---
title: "WASM as a Kubernetes Sidecar: Lightweight Security Proxies and Policy Enforcement"
description: "WASM sidecars in Kubernetes offer smaller attack surface than language-runtime sidecars — no shell, no package manager, no OS CVEs beyond the runtime itself. This guide covers WASM-based admission webhooks, policy sidecars, traffic inspection with wasm-filter, and security properties compared to traditional sidecar proxies."
slug: wasm-kubernetes-sidecar-security
date: 2026-05-07
lastmod: 2026-05-07
category: wasm
tags:
  - wasm
  - kubernetes
  - sidecar
  - proxy-security
  - policy-enforcement
personas:
  - security-engineer
  - platform-engineer
article_number: 585
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/wasm/wasm-kubernetes-sidecar-security/
---

# WASM as a Kubernetes Sidecar: Lightweight Security Proxies and Policy Enforcement

## The Problem With Traditional Sidecars

The sidecar pattern is foundational to Kubernetes security architecture. Envoy proxy sidecars enforce mTLS, observability agents collect spans, policy sidecars validate egress — all running as co-located containers that share the Pod's network namespace. The pattern works. The attack surface that ships with it is less well understood.

A typical Envoy sidecar running as an OCI container image carries:

- A Linux userspace including glibc, musl, or equivalent
- A shell (often `/bin/sh` or `/bin/bash`) present in debug builds
- An apt or apk package manager left in the layer cache
- A process tree visible to adjacent containers in the Pod
- Kernel syscall surface exposed through the container's Linux namespace
- CVE exposure in every OS package, even those never executed

When that sidecar container is compromised — via a memory corruption bug in Envoy, a misconfigured RBAC binding that lets an attacker exec into it, or a supply-chain substitution in the base image — the attacker lands in a full Linux environment. They have a shell, a network interface shared with the application container, access to the Pod's service account token mounted at `/var/run/secrets/kubernetes.io/serviceaccount/`, and the ability to run arbitrary binaries by writing to `/tmp`.

WASM sidecars do not carry that surface. A WASM module executing inside a runtime (Wasmtime, WasmEdge, WAMR) has no shell, no filesystem unless explicitly granted, no arbitrary syscall access, and no ability to spawn processes. If the module's logic is compromised, the blast radius is bounded by what the WASM runtime's host function interface exposes — a narrow, auditable set of capabilities defined at deployment time.

This article covers the security architecture of WASM sidecars: where they outperform language-runtime containers, where they introduce new constraints, and how to deploy them correctly in production Kubernetes clusters.

## WASM Sidecars vs Language-Runtime Sidecars

The comparison is not WASM vs. native code; it is WASM vs. a full container image carrying a language runtime, OS packages, and the implicit privileges of a Linux process.

**Shell access.** A container-based sidecar, even one running a Go binary with `FROM scratch`, often has a shell available in its build layers or in debug variants. A WASM module has no concept of a shell. The module's execution is limited to the functions it exports and the host functions the runtime grants. An attacker who can influence the module's behavior cannot exec a shell because there is no exec syscall available.

**Package manager artifacts.** Container base images built on Debian, Alpine, or Ubuntu leave package manager databases and occasionally the package manager binaries themselves in the final image. These are vectors for post-exploitation (downloading tools, reading cached credentials). A WASM OCI artifact contains only the `.wasm` binary and its component metadata. There is no package database, no cached apt state, no `/etc/passwd`.

**OS-level CVEs.** A container sidecar is affected by glibc CVEs, kernel module vulnerabilities accessible from userspace, and exploit chains through Linux capabilities granted to the container (NET_ADMIN is common for network-adjacent sidecars). WASM runtime CVEs exist — Wasmtime and WasmEdge both have CVE histories — but they are confined to the WASM execution engine, not the full Linux OS package surface. A single runtime binary replaces dozens of OS packages as the attack surface.

**Deterministic resource accounting.** Container CPU limits are enforced by cgroup quotas, which allow burst usage and do not prevent a container from starving neighbors within the burst window. WASM runtimes support fuel metering: a fixed number of instructions the module may execute before the runtime halts it. This is deterministic and not bypassable from within the module. For a sidecar handling request-path logic, fuel metering provides a hard wall against runaway computation that cgroup quotas do not.

**Privilege escalation surface.** A compromised container sidecar can attempt privilege escalation through Linux kernel exploits, SUID binaries left in the image, or capabilities granted by the PodSpec. A WASM module runs in a single-threaded execution context (absent WASM threads) with no OS privilege concepts. There is no setuid, no capability set to manipulate, no ptrace. The module cannot escalate within the WASM sandbox.

The trade-off: WASM sidecars require an explicit host function interface for everything they need to do. They cannot open TCP connections, read environment variables, or emit logs without the runtime exposing those operations. This limits flexibility compared to a general-purpose container but is the source of the security advantage.

## WASM-Based Envoy Filters as Security Sidecars

Envoy's proxy-wasm ABI is the most production-mature WASM sidecar integration in Kubernetes. Istio, Kuma, and Gloo all support loading WASM plugins into the Envoy sidecar at runtime. These plugins run in the Envoy worker thread, in-process but memory-isolated via WASM's linear memory model.

The proxy-wasm ABI exposes a defined set of host functions: read and modify HTTP headers, read the request body, dispatch async HTTP calls, set properties, emit metrics. Plugins cannot call arbitrary libc functions. The ABI surface is the security boundary.

**HTTP authentication sidecar.** A WASM filter that implements header-based authentication:

```rust
// proxy-wasm-rust-sdk
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

struct AuthFilter;

impl HttpContext for AuthFilter {
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        let token = self.get_http_request_header("x-api-key");
        match token {
            Some(t) if validate_token(&t) => Action::Continue,
            _ => {
                self.send_http_response(401, vec![], Some(b"Unauthorized"));
                Action::Pause
            }
        }
    }
}
```

The filter has no access to the underlying socket, the TLS certificate chain, other in-flight requests, or Envoy's internal state beyond what the ABI exposes. If this WASM module is compromised, the attacker can block or pass HTTP requests and emit metrics — not pivot to the host or read unrelated traffic.

**Rate limiting sidecar.** WASM filters can implement per-IP or per-token rate limiting using the shared data API, which provides a key-value store scoped to the Envoy instance:

```rust
fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
    let client_ip = self.get_http_request_header("x-forwarded-for")
        .unwrap_or_default();
    let key = format!("rate:{}", client_ip);
    
    let (count, cas) = self.get_shared_data(&key)
        .unwrap_or((Some(b"0".to_vec()), None));
    
    let current: u64 = std::str::from_utf8(&count.unwrap_or_default())
        .ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    
    if current >= RATE_LIMIT {
        self.send_http_response(429, vec![], Some(b"Rate limit exceeded"));
        return Action::Pause;
    }
    
    let _ = self.set_shared_data(&key, Some((current + 1).to_string().as_bytes()), cas);
    Action::Continue
}
```

**Header injection detection.** A WASM sidecar can scan incoming headers for injection patterns — CRLF sequences, oversized values, HTTP request smuggling markers — before the request reaches the application. This moves the detection into the network layer without requiring changes to application code.

Deploy as a `WasmPlugin` resource in Istio 1.22+:

```yaml
apiVersion: extensions.istio.io/v1alpha1
kind: WasmPlugin
metadata:
  name: header-injection-detector
  namespace: production
spec:
  selector:
    matchLabels:
      app: payment-service
  url: oci://registry.example.com/security/header-detector:v1.2.3@sha256:abcdef...
  phase: AUTHN
  pluginConfig:
    max_header_value_bytes: 4096
    crlf_check: true
  vmConfig:
    env:
    - name: LOG_LEVEL
      value: warn
```

The `sha256` digest pin on the OCI reference is mandatory for security-critical filters. Tag-only references allow registry-side substitution.

## SpinKube: Running WASM Natively in Kubernetes

SpinKube is the integration project for running Fermyon Spin applications natively in Kubernetes, using `containerd-shim-spin` as the OCI runtime shim. Unlike Envoy WASM filters (which run inside an existing proxy process), SpinKube replaces the container runtime for designated Pods. The WASM module is the workload; there is no container OS image underneath.

The architecture: a `RuntimeClass` named `wasmtime-spin` is registered in the cluster. Pods that specify this RuntimeClass are intercepted by the `containerd-shim-spin` process rather than `runc`. The shim starts a Spin runtime, loads the WASM OCI artifact, and maps WASI capabilities from the PodSpec into the Spin application manifest.

For sidecar use cases, SpinKube Pods make effective policy enforcement containers:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-with-wasm-policy-sidecar
spec:
  runtimeClassName: wasmtime-spin
  containers:
  - name: application
    image: registry.example.com/app:v2.1.0
  - name: policy-enforcer
    image: registry.example.com/security/policy-sidecar:v0.8.1@sha256:deadbeef...
    resources:
      requests:
        memory: "16Mi"
        cpu: "50m"
      limits:
        memory: "64Mi"
        cpu: "200m"
```

The `policy-enforcer` container image contains only the WASM binary. The shim enforces the Pod's resource limits via the Wasmtime epoch interrupt mechanism: when the allocated CPU budget is consumed, the runtime interrupts execution rather than allowing unbounded CPU consumption.

Security properties specific to SpinKube sidecars:

- No shell in the container image. The OCI image is a WASM component plus a minimal manifest; `kubectl exec` into the container fails because there is no process to exec into.
- WASI capabilities are granted per-component in the Spin manifest, not inherited from the host OS. Network access requires explicit `allowed_outbound_hosts` configuration.
- The containerd shim itself runs as a separate process with a restricted privilege set, not as a privileged container.

## WASM Admission Webhooks

Kubernetes admission webhooks are small HTTP services that intercept API server requests and allow or deny them based on policy. Traditional admission webhooks run as Deployments with Go or Python runtimes, full container images, and Kubernetes service accounts. WASM admission webhooks run the same HTTP handler logic in a WASM runtime with a much smaller footprint.

Kubewardenuses WASM for all its policies. Each Kubewarden policy is a `.wasm` module that receives a JSON-serialized `AdmissionRequest` and returns an `AdmissionResponse`. The policy has no access to the cluster API, no service account, and no filesystem. It evaluates the request payload in a pure-function style.

A Kubewarden policy that enforces image digest pinning:

```rust
use kubewarden_policy_sdk::prelude::*;

#[no_mangle]
pub extern "C" fn validate(payload: *const u8, payload_len: usize) -> *const u8 {
    let req: ValidationRequest<Settings> = 
        serde_json::from_slice(unsafe { 
            std::slice::from_raw_parts(payload, payload_len) 
        }).unwrap();
    
    let pod_spec = req.request.object.spec.unwrap();
    
    for container in &pod_spec.containers {
        if !container.image.contains('@') {
            return rejection(
                &format!("Container {} must use digest-pinned image", container.name)
            );
        }
    }
    acceptance()
}
```

Deploy as a `ClusterAdmissionPolicy`:

```yaml
apiVersion: policies.kubewarden.io/v1
kind: ClusterAdmissionPolicy
metadata:
  name: require-image-digest
spec:
  module: registry.example.com/policies/require-digest:v1.0.0@sha256:cafebabe...
  rules:
  - apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
    operations: ["CREATE", "UPDATE"]
  mutating: false
  settings: {}
```

The policy binary runs in Wasmtime inside the Kubewarden controller. It evaluates in microseconds with no network calls, no Kubernetes API access, and no ambient credentials. A compromised policy binary can only affect admission decisions for the resource types it is registered against — it cannot enumerate cluster state or escalate to the controller's service account.

## Security Properties of WASM Sidecars

**Immutability after load.** Once a WASM module is loaded by the runtime, its code section is immutable. The module cannot patch its own instructions, load additional code, or JIT-compile arbitrary payloads. This is a meaningful difference from native code sidecars, where the executable can write to executable memory if `W^X` is not enforced.

**Memory safety by construction.** WASM's linear memory model prevents buffer overflows from reaching outside the module's allocated memory. A WASM sidecar with a buffer overflow in its parsing logic cannot corrupt adjacent process memory, overwrite function pointers, or jump to attacker-controlled code outside the module. The overflow is contained within the 32-bit linear address space of that module instance.

**No privilege escalation via shell.** The most common post-exploitation step after gaining code execution in a sidecar is spawning a shell. WASM provides no mechanism for this. There is no `execve` host function in the standard WASI API. A module that wants to execute another process would need the runtime to explicitly expose that capability, which production deployments do not do.

**Deterministic behavior.** WASM execution is formally specified. Given the same inputs and the same linear memory state, a WASM module produces the same outputs. This enables fuzzing and formal verification approaches that are impractical for general-purpose native binaries. Security-critical sidecar logic — token validation, policy evaluation, header inspection — benefits from this property.

## Resource Limits for WASM Sidecars

Apply Kubernetes resource requests and limits to WASM sidecar containers as you would for any container. The kubelet enforces these at the cgroup level for containerd-shim-based workloads. For Envoy WASM plugins, configure limits at the `WasmPlugin` level separately.

For SpinKube and runwasi-based WASM sidecars:

```yaml
resources:
  requests:
    memory: "8Mi"
    cpu: "10m"
  limits:
    memory: "32Mi"
    cpu: "100m"
```

WASM sidecars are genuinely small. A Rust-compiled WASM module for header inspection or token validation typically uses 2–8 MB of memory at runtime, versus 50–150 MB for a minimal Go or Envoy sidecar container. The smaller footprint means tighter limits that more accurately reflect expected usage.

At the runtime level, configure fuel limits for Wasmtime-based sidecars. Fuel metering stops execution after a fixed number of Wasm instructions regardless of wall-clock time. This prevents pathological inputs from causing the sidecar to consume CPU until the cgroup limit kicks in:

```toml
# wasmtime configuration for the containerd shim
[runtime]
fuel = 100_000_000   # 100 million instructions per invocation
max_memory_size = "32MiB"
epoch_interruption = true
epoch_deadline_ms = 100
```

For Envoy WASM plugins, set per-plugin VM memory limits in the `WasmPlugin` spec:

```yaml
vmConfig:
  runtime: v8
  nailgunPoolSize: 0
  # Memory cap: Envoy will terminate the plugin VM if it exceeds this
  # (Envoy 1.30+ via per-vm memory limit annotation)
  resources:
    requests:
      memory: "4Mi"
    limits:
      memory: "16Mi"
```

## Supply Chain Security for WASM Sidecar Images

WASM OCI artifacts follow the same distribution model as container images but with different media types. Supply chain controls must be applied explicitly; tooling that scans container images for OS CVEs does not automatically apply to WASM OCI artifacts.

**Sign all WASM OCI artifacts with Sigstore/cosign:**

```bash
# Sign after build
cosign sign --key cosign.key \
  registry.example.com/security/header-detector:v1.2.3

# Verify before deployment (in CI/CD pipeline)
cosign verify --key cosign.pub \
  registry.example.com/security/header-detector:v1.2.3@sha256:abcdef...
```

**Pin references to digest in all manifests.** Tag references allow registry-side content replacement without triggering Kubernetes image pull policy re-evaluation. Every WASM sidecar reference in a `WasmPlugin`, `ClusterAdmissionPolicy`, or Pod manifest must include the `@sha256:` digest suffix.

**Enforce signature verification in the admission webhook.** Kubewarden ships a built-in policy (`verify-image-signatures`) that checks cosign signatures before admitting Pods or WasmPlugin resources. Enable it for all namespaces that load WASM sidecars.

**SBOM for WASM artifacts.** Generate a Software Bill of Materials for WASM builds using `wasm-pack` or `cargo-component`. The SBOM captures the Rust crate dependency tree and their versions, enabling CVE scanning against the build-time dependency graph rather than a runtime OS package list:

```bash
cargo cyclonedx --format json --output sbom.json
cosign attach sbom --sbom sbom.json \
  registry.example.com/security/header-detector:v1.2.3
```

## Observability from WASM Sidecars via WASI HTTP

Observability is the most commonly cited limitation of WASM sidecars compared to traditional containers. A Go sidecar can open a gRPC channel, use the OpenTelemetry SDK, and export spans to a collector. WASM modules cannot open sockets natively.

The WASI HTTP proposal (stabilized in WASI Preview 2) changes this. A WASM sidecar built to the WASI HTTP interface can make outbound HTTP calls — including to an OTLP HTTP endpoint — using the host's networking stack. The call is mediated by the runtime, which enforces the allowed_outbound_hosts policy before transmitting.

Emit OpenTelemetry spans from a Rust WASM sidecar using the `opentelemetry-otlp` crate compiled to `wasm32-wasip2`:

```rust
use opentelemetry::trace::{Tracer, TracerProvider};
use opentelemetry_otlp::WithExportConfig;

async fn init_tracer() -> opentelemetry_sdk::trace::Tracer {
    opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .http()
                .with_endpoint("http://otel-collector.monitoring:4318")
        )
        .install_batch(opentelemetry_sdk::runtime::WasiThreads)
        .unwrap()
        .tracer("wasm-policy-sidecar")
}
```

For Envoy WASM plugins, use the proxy-wasm metrics API to emit counters and histograms that Envoy aggregates and exposes on its metrics endpoint:

```rust
let blocked_requests = self.define_metric(
    MetricType::Counter,
    "wasm_sidecar.blocked_requests_total",
);
self.increment_metric(blocked_requests, 1);
```

Prometheus scrapes these from Envoy's `/stats/prometheus` endpoint alongside all other Envoy metrics. No separate exporter process is required.

For structured log output, WASM modules write to WASI stdout, which the containerd shim captures and forwards to the node's logging infrastructure (Fluent Bit, Promtail, Vector) using the same log collection path as container stdout. Add structured JSON output at the application level and parse it in the log aggregator:

```rust
eprintln!(r#"{{"level":"warn","event":"policy_violation","reason":"{}","request_id":"{}"}}"#,
    reason, request_id);
```

## Threat Model Summary

| Threat | Traditional Container Sidecar | WASM Sidecar |
|--------|------------------------------|--------------|
| Shell access post-compromise | Available if image contains shell | Not available — no exec syscall |
| Package manager artifacts | Present in most base images | Not present — WASM binary only |
| OS CVE surface | Full OS userspace | Runtime CVEs only (Wasmtime, WasmEdge) |
| Privilege escalation | Possible via SUID, capabilities, kernel exploits | Not possible — no privilege concepts in WASM |
| Memory safety | Depends on language (C/C++ risky) | Guaranteed by WASM linear memory model |
| Supply chain attack surface | Base image + app + all layers | WASM binary + runtime |
| Resource limit enforcement | cgroup quotas (soft enforcement) | Fuel metering (deterministic instruction count) |
| Observability integration | Full SDK support | WASI HTTP + proxy-wasm metrics API |

## Key Decisions

Use WASM Envoy filters (via `WasmPlugin`) for security logic that lives in the request path: authentication, rate limiting, header inspection, JWT validation. This integrates with existing Istio/Envoy infrastructure without adding new Pods.

Use Kubewarden WASM policies for admission control. The architecture eliminates the ambient-credential risk of traditional webhook Deployments.

Use SpinKube for standalone security sidecar workloads that need their own lifecycle separate from the application — policy evaluators, credential rotators, audit log forwarders — where the complete absence of a shell is a compliance requirement.

In all cases: pin OCI references to digest, sign WASM artifacts with cosign, attach SBOMs, and configure fuel/memory limits at the runtime level in addition to Kubernetes resource limits. The WASM security model provides strong defaults, but supply-chain hygiene and runtime configuration are still operator responsibilities.
