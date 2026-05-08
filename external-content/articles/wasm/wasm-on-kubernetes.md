---
title: "WASM Workloads on Kubernetes: runwasi, Spin, and the Threat Model Shift from OCI Containers"
description: "WASM on Kubernetes via runwasi and containerd shims runs alongside containers but with a different escape surface, different RBAC implications, and different supply-chain controls."
slug: "wasm-on-kubernetes"
date: 2026-04-27
lastmod: 2026-04-27
category: "wasm"
tags: ["wasm", "kubernetes", "runwasi", "spin", "wasmcloud", "containerd"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 178
difficulty: "advanced"
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/wasm/wasm-on-kubernetes/index.html"
---

# WASM Workloads on Kubernetes: runwasi, Spin, and the Threat Model Shift from OCI Containers

## Problem

WebAssembly workloads now run on Kubernetes the same way containers do: a Pod manifest, an OCI image, scheduling by the kubelet. The mechanism underneath is different — `runwasi` (a containerd shim that hosts a WASM runtime instead of `runc`), or `kwasm-operator` for nodes that need WASM runtime injection — but from the user-API perspective the workload looks like any other Pod with a special `RuntimeClass`.

The threat model is not the same. WASM workloads share the kubelet, the cluster network, the secret store, and the image-distribution pipeline with regular containers, but they bring different escape surfaces, different isolation guarantees, and different supply-chain shape:

- **No Linux namespaces.** A WASM module is not a container; it is a sandboxed binary running inside the shim's host process. Pod-level controls that depend on Linux namespaces (PID, IPC, mount, hostNetwork toggles) do not apply or apply differently.
- **No seccomp / AppArmor surface.** Pod `securityContext` fields that enforce kernel-level filters are no-ops for WASM modules — there are no syscalls to filter, only host-call imports.
- **WASI capability handover happens at runtime mount.** Filesystem access for a WASM workload is not via Pod volume mounts but via the WASI `preopened_dir` mechanism the shim configures.
- **Resource limits use a different accounting layer.** Pod `resources.limits.cpu` translates to runtime fuel/epoch budget, not cgroup CPU quotas.
- **Image format is the same OCI registry but content is `application/vnd.wasm.config.v0+json`.** Admission controllers that check image labels miss WASM-specific identifiers unless they look for the alternate media type.

Mainstream by 2026: Spin (Fermyon), wasmCloud, and the `containerd-shim-spin` are stable, included in many CNCF distributions, and run real production workloads. The hardening story has caught up but is not the same as the container hardening story.

This article covers `RuntimeClass` setup, Pod-level configuration that does and does not apply to WASM, NetworkPolicy at the Pod boundary, image attestation for WASM, and the operational gaps to monitor.

**Target systems:** Kubernetes 1.28+, containerd 1.7+ with `runwasi` shim (`containerd-shim-spin-v2`, `containerd-shim-wasmtime-v1`, `containerd-shim-wasmedge-v1`), or `kwasm-operator` for node-level WASM runtime installation. Compatible with Spin 2.0+, wasmCloud 1.0+, and standalone Wasmtime/WasmEdge runtimes.

## Threat Model

- **Adversary 1 — Untrusted WASM module:** an attacker uploads a `.wasm` artifact and convinces the platform to schedule it. They want to escape the WASM sandbox to access the kubelet, host filesystem, or other tenants.
- **Adversary 2 — Compromised WASM build pipeline:** a previously-trusted module containing malicious imports introduced through dependency or supply-chain compromise.
- **Adversary 3 — Cross-runtime lateral movement:** an attacker has compromised a container Pod and uses its position on the cluster network to attack co-resident WASM Pods (or vice versa).
- **Adversary 4 — Misconfigured RBAC granting WASM Pods cluster-API access:** a WASM workload with a default ServiceAccount has the same kubernetes-api access as any other Pod and can call `pods.get`, list secrets in its namespace, etc.
- **Access level:** Adversary 1 has module-upload permission. Adversary 2 has prior trust. Adversary 3 has Pod-level execution somewhere. Adversary 4 has ServiceAccount token access from inside the WASM Pod.
- **Objective:** Escape the WASM sandbox to host or kubelet; pivot through the cluster network; abuse over-permissioned ServiceAccount tokens to pivot to other namespaces.
- **Blast radius:** Without hardening: WASM Pods inherit the cluster's default ServiceAccount and unrestricted egress; a sandbox-escape exploit means kubelet-level access. With hardening: NetworkPolicy bounds egress, ServiceAccount tokens are disabled, runtime resource limits enforce fairness, and image attestation blocks unsigned modules at admission time.

## Configuration

### Step 1: Install the WASM Runtime via RuntimeClass

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: wasmtime
handler: wasmtime
scheduling:
  nodeSelector:
    workload-type: wasm
```

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: spin
handler: spin
scheduling:
  nodeSelector:
    workload-type: wasm
```

The `handler` corresponds to the containerd shim (`containerd-shim-wasmtime-v1`, `containerd-shim-spin-v2`). Each node hosting WASM workloads needs the shim installed. Use `kwasm-operator` to automate:

```yaml
# Deploy kwasm-operator and label nodes for WASM.
kubectl label node worker-1 kwasm.sh/kwasm-node=true
kubectl label node worker-2 kwasm.sh/kwasm-node=true
```

Restrict WASM nodes to known workloads using taints + tolerations so a misconfigured Pod cannot accidentally schedule on a WASM node:

```yaml
# Taint the wasm-pool nodes.
kubectl taint nodes worker-1 worker-2 \
  workload-type=wasm:NoSchedule
```

### Step 2: Pod Spec for a WASM Workload

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: wasm-app
  namespace: wasm-tenant-payments
  labels:
    app: payments-api
    runtime: wasm
spec:
  runtimeClassName: wasmtime
  serviceAccountName: wasm-app
  automountServiceAccountToken: false   # WASM Pods rarely need API access
  tolerations:
    - key: workload-type
      operator: Equal
      value: wasm
      effect: NoSchedule
  containers:
    - name: app
      image: ghcr.io/myorg/payments@sha256:abc123...   # OCI artifact with .wasm payload
      command: ["/payments.wasm"]
      env:
        - name: TENANT_ID
          value: payments
      ports:
        - containerPort: 8080
          name: http
      resources:
        # CPU and memory limits translate to runtime fuel and memory caps.
        # The shim consults these when configuring Wasmtime/WasmEdge.
        requests:
          cpu: 100m
          memory: 64Mi
        limits:
          cpu: 500m
          memory: 256Mi
      # Most securityContext fields are no-ops for WASM. These are the ones
      # that still apply at the shim/container level.
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        readOnlyRootFilesystem: true
      volumeMounts:
        - name: workdir
          mountPath: /work
        - name: assets
          mountPath: /assets
          readOnly: true
  volumes:
    - name: workdir
      emptyDir:
        sizeLimit: 64Mi
    - name: assets
      configMap:
        name: payments-assets
```

Notes that matter for security:

- `automountServiceAccountToken: false` is critical. WASM workloads usually do not need Kubernetes API access; defaulting to mounting a token grants whatever the namespace's default ServiceAccount permissions allow.
- `securityContext.privileged`, `capabilities`, `seccompProfile`, `procMount` — all no-ops for WASM. Setting them does no harm but provides no protection.
- Volume mounts are translated by the shim into WASI `preopened_dir` calls. The path inside the volume is the path the WASM module sees.
- `command` points to the WASM module's entrypoint. `args` are passed as WASI command-line arguments.

### Step 3: NetworkPolicy at the Pod Boundary

WASM workloads sit on the same Pod network as containers. NetworkPolicy applies the same way:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: wasm-payments-egress
  namespace: wasm-tenant-payments
spec:
  podSelector:
    matchLabels:
      app: payments-api
      runtime: wasm
  policyTypes:
    - Egress
  egress:
    # Allow outbound to the database service only.
    - to:
        - namespaceSelector:
            matchLabels:
              name: data
          podSelector:
            matchLabels:
              app: postgres
      ports:
        - protocol: TCP
          port: 5432
    # Allow DNS.
    - to:
        - namespaceSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
```

Combined with WASI socket allowlists at the runtime layer (Wasmtime / WasmEdge configuration), NetworkPolicy provides defense in depth. The runtime layer rejects connections the WASM module attempts to make to disallowed destinations; NetworkPolicy rejects them again at the Pod boundary.

### Step 4: Admission Control for WASM Image Verification

WASM modules in OCI registries use a media type distinct from container images: `application/vnd.wasm.config.v0+json`. Admission policies that gate container images by signature need a parallel rule for WASM artifacts.

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: wasm-image-must-be-signed
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
  validations:
    - expression: >
        !has(object.spec.runtimeClassName) ||
        !(object.spec.runtimeClassName in ["wasmtime", "spin", "wasmcloud", "wasmedge"]) ||
        object.spec.containers.all(c,
          c.image.startsWith("ghcr.io/myorg/wasm/") ||
          c.image.startsWith("registry.example.com/wasm/"))
      message: "WASM workloads must use images from the approved WASM registry namespace"
```

Pair with cosign-based verification via the cosigned admission controller or Kyverno's `verifyImages` rule, configured with a `type: oci` for WASM artifacts:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-wasm-signatures
spec:
  validationFailureAction: Enforce
  webhookTimeoutSeconds: 30
  rules:
    - name: verify-wasm
      match:
        resources:
          kinds: [Pod]
      preconditions:
        all:
          - key: "{{request.object.spec.runtimeClassName || ''}}"
            operator: AnyIn
            value: ["wasmtime", "spin", "wasmcloud"]
      verifyImages:
        - imageReferences:
            - "ghcr.io/myorg/wasm/*"
          attestors:
            - entries:
                - keys:
                    publicKeys: |-
                      -----BEGIN PUBLIC KEY-----
                      ...
                      -----END PUBLIC KEY-----
```

### Step 5: Observability for WASM Workloads

Standard Kubernetes metrics (CPU, memory) reflect the shim host process, not the WASM module's own resource use. Wire the runtime's telemetry into Prometheus:

```yaml
# Spin includes OTel telemetry for module execution.
apiVersion: spinkube.dev/v1alpha1
kind: SpinApp
metadata:
  name: payments-api
spec:
  runtime: wasmtime
  observability:
    otel:
      endpoint: http://otel-collector.observability:4317
      attributes:
        - tenant: payments
        - app: payments-api
```

Track:

```
wasm_module_invocations_total{tenant, module}    counter
wasm_module_duration_seconds                      histogram
wasm_module_traps_total{kind}                     counter
wasm_module_memory_pages                          gauge
wasm_module_fuel_consumed                         histogram
```

Alert on `wasm_module_traps_total{kind=~"epoch_deadline|fuel_exhausted|memory_grow"}` spikes — these are the abuse signals.

### Step 6: Cross-Runtime Network Boundaries

A cluster running both containers and WASM Pods needs explicit policy at the boundary. A compromised container reaching a WASM Pod (or vice versa) on the same node should not be possible by default.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-cross-runtime
  namespace: wasm-tenant-payments
spec:
  podSelector:
    matchLabels:
      runtime: wasm
  policyTypes:
    - Ingress
  ingress:
    # Only allow ingress from other WASM Pods or known gateways.
    - from:
        - podSelector:
            matchLabels:
              runtime: wasm
        - namespaceSelector:
            matchLabels:
              name: gateway-system
```

For node-level isolation, schedule WASM workloads on a dedicated node pool (the `workload-type=wasm` taint above) and apply node-level firewall rules at the host:

```bash
# On worker nodes hosting WASM workloads.
nft add rule inet filter input \
  iifname "cni0" oifname "cni0" \
  ip daddr <wasm-pod-cidr> ip saddr != <wasm-pod-cidr> drop
```

## Expected Behaviour

| Signal | Containers | WASM Pods (hardened) |
|--------|-----------|------------------------|
| Pod start cold | 50ms-2s container creation | <100ms (no namespace setup, no rootfs unpack) |
| `securityContext.capabilities` | Enforced via Linux capabilities | Ignored (no kernel-level controls) |
| `seccompProfile` | Enforced | Ignored |
| Memory enforcement | cgroup `memory.max` | Runtime memory ceiling via `set_static_memory_maximum_size` |
| CPU enforcement | cgroup CPU quota | Runtime fuel/epoch budget |
| Network isolation | NetworkPolicy | NetworkPolicy + WASI socket allowlist |
| ServiceAccount token mount | Default-on | Should be default-off for WASM Pods |
| OCI media-type expectations | `application/vnd.docker.image.rootfs.*` | `application/vnd.wasm.*` |

Verify a WASM Pod is correctly using the WASM runtime:

```bash
kubectl exec -n wasm-tenant-payments wasm-app -- ps -ef
# Output is from the shim host process, not a Linux container init.

# On the node, check the shim:
crictl ps --label "io.kubernetes.pod.name=wasm-app" -v
# RUNTIME: io.containerd.spin.v2

# Confirm no SA token is mounted.
kubectl exec -n wasm-tenant-payments wasm-app -- ls /var/run/secrets/kubernetes.io
# (no such file or directory)
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Dedicated WASM node pool | Isolated host kernel attack surface | Underutilization if WASM workload count is small | Use a small node pool with HPA on the shim's CPU usage. |
| `automountServiceAccountToken: false` default | WASM Pods cannot accidentally use API permissions | Workloads that legitimately need API access must opt in | Provide a "k8s-aware" WASM template that enables the token + scoped Role. |
| WASI capability translation from volume mounts | Familiar Pod spec UX | Volumes that work for containers may map awkwardly to WASI | Document the mapping; reject volume types that have no WASI equivalent (hostPath should never appear on WASM Pods). |
| Image attestation for WASM | Same supply-chain assurances as containers | Tooling adoption (cosign, Kyverno) needs WASM-specific config | Use shared admission policies that match by `runtimeClassName`. |
| Cross-runtime NetworkPolicy | Bounds blast radius from container compromises | More NetworkPolicy resources to maintain | Default-deny, then allowlist explicitly per service. |
| Runtime telemetry | Observability into module-level resource use | Extra OTel pipeline for WASM-specific metrics | Reuse the cluster's existing OTel Collector. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Shim missing on a WASM-tagged node | Pod stuck in `ContainerCreating` with `failed to find runtime handler` | `kubectl describe pod` shows the error | Run `kwasm-operator` reconcile, or manually install the shim binary (`/usr/local/bin/containerd-shim-spin-v2`). |
| Shim crash | Pods on the node go to `Error` simultaneously | Node logs show shim panic | The shim is the equivalent of `runc`. A bug in the shim is a node-level event. Restart containerd; investigate the shim version. |
| WASI capability mismatch | WASM module fails with `wasi:filesystem` error trying to access a Pod volume | Pod logs show "permission denied" on a path that exists | Check the shim's volume-to-WASI mapping. Some shims (older `containerd-shim-spin-v1`) have known mapping bugs; upgrade to current. |
| ServiceAccount token mount accidental | A WASM Pod has Kubernetes API access without intent | `kubectl exec ls /var/run/secrets/kubernetes.io` shows token | Always set `automountServiceAccountToken: false` for WASM Pods. Enforce via VAP. |
| WASM module signature missing in registry | Pod fails admission | Kyverno or cosigned admission webhook denies the create | Sign the module before pushing. Use the same CI pipeline that signs container images, with the cosign WASM-specific subcommand. |
| Resource limits ignored | WASM module exceeds Pod CPU/memory; node OOM | Standard Kubernetes resource events | Verify the shim version supports limit translation. Some early shims silently ignored Pod limits. |
| Container Pod attacks WASM Pod via cluster network | A compromised container exfiltrates from a WASM Pod | NetworkPolicy violation logs (Cilium/Calico) | Tighten cross-runtime NetworkPolicy. WASM and container Pods should default-deny on ingress and only allow from known sources. |

## When to Consider a Managed Alternative

Self-hosted WASM-on-Kubernetes requires shim distribution, RuntimeClass management, image admission, and cross-runtime policy maintenance (4-10 hours/month for a multi-tenant cluster).

- **[Fermyon Cloud](https://www.fermyon.com/cloud):** managed Spin platform with built-in tenant isolation and image attestation.
- **[Cosmonic](https://cosmonic.com/):** managed wasmCloud with capability-based tenancy.

## Related Articles

- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [WASI Preview 2 Capability-Based Security](/articles/wasm/wasi-preview-2-capabilities/)
- [OCI WASM Module Signing and Verification](/articles/wasm/wasm-oci-signing/)
- [Network Policies for Zero-Trust Kubernetes Networking](/articles/kubernetes/kubernetes-network-policies/)
- [ValidatingAdmissionPolicy with CEL](/articles/kubernetes/validating-admission-policy-cel/)
