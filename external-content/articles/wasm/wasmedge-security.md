---
title: "WasmEdge Security: Sandboxing AI Inference, Plugins, and Serverless Functions"
description: "WasmEdge runs AI inference workloads, plugins, and serverless functions inside a WASM sandbox. Securing the runtime requires capability-based access control, plugin isolation, socket permission limits, and supply chain verification of the modules being executed."
slug: "wasmedge-security"
date: 2026-04-30
lastmod: 2026-04-30
category: "wasm"
tags: ["wasmedge", "wasm", "sandbox", "ai-inference", "serverless", "capability"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 278
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/wasm/wasmedge-security/index.html"
---

# WasmEdge Security: Sandboxing AI Inference, Plugins, and Serverless Functions

## Problem

WasmEdge is a high-performance WebAssembly runtime optimised for edge, serverless, and AI workloads. Its plugin architecture supports WASI-NN (Neural Network API) for running models like LLaMA, Whisper, and Stable Diffusion inside a WASM sandbox, and WASI-Socket for networking. This makes WasmEdge a useful execution environment for untrusted or semi-trusted code: third-party functions, user-provided models, or externally-sourced WASM modules.

The WebAssembly sandbox provides a default-deny capability model — a module cannot access the filesystem, network, or host environment unless capabilities are explicitly granted. However, misconfigured WasmEdge deployments routinely grant more capability than needed:

- **Overpermissive WASI preopen directories.** Granting `--dir /:/ ` (full filesystem access) is common in examples and persists into production. A malicious WASM module can read `/etc/passwd`, environment variables, and mounted secrets.
- **WASI-Socket without restriction.** Enabling WASI-Socket without restricting permitted addresses allows a WASM module to make outbound connections to arbitrary hosts — data exfiltration from the sandbox.
- **Unverified WASM modules.** The `.wasm` binary being executed is not verified against a known-good hash or signature. A supply chain attack that replaces the WASM module is not detected.
- **AI model weight exposure.** WASI-NN loads model weights from the host filesystem. If the preopen directory includes the model weight path, and the module is malicious, it can exfiltrate the model weights.
- **Plugin loading without verification.** WasmEdge plugins (native `.so` files) run outside the WASM sandbox. A malicious or compromised plugin has full host access. Plugin provenance is often not checked.
- **Resource limits absent.** A WASM module that enters an infinite loop or allocates unbounded memory can exhaust host resources. Without per-execution resource limits, a single runaway module affects all co-located workloads.

**Target systems:** WasmEdge 0.13+ (WASI-NN GA, WasiSocket); WASI-NN with llama.cpp, Whisper.cpp, and GGML backends; WasmEdge in Kubernetes via containerd-shim-wasmEdge; serverless platforms using WasmEdge (Fermyon Spin on WasmEdge, Knative + WasmEdge).

## Threat Model

- **Adversary 1 — Malicious WASM module via supply chain:** An attacker compromises the registry or build pipeline that produces `.wasm` artefacts. The replacement module is executed by WasmEdge with the same capabilities as the original — filesystem access, network, WASI-NN access.
- **Adversary 2 — Sandbox escape via overpermissive capabilities:** A WASM module is granted filesystem access it doesn't need (e.g., `--dir /:/`). The module reads host secrets, environment variables, or other tenants' data mounted on the same host.
- **Adversary 3 — Network exfiltration via WASI-Socket:** A malicious WASM module uses WASI-Socket to exfiltrate data to an attacker-controlled endpoint. Without socket restrictions, any outbound connection is permitted from inside the sandbox.
- **Adversary 4 — AI model weight exfiltration:** A WASM module executing inference has read access to the model weight directory. The module exfiltrates weights (which may be proprietary) over WASI-Socket.
- **Adversary 5 — Plugin compromise:** A native plugin loaded by WasmEdge is compromised or malicious. Plugins execute outside the WASM sandbox with full host process permissions — complete host compromise.
- **Adversary 6 — Resource exhaustion:** A tenant or attacker submits a WASM module that allocates all available memory or enters an infinite loop, causing OOM kills or CPU starvation for other tenants.
- **Access level:** Adversaries 1 and 5 require supply chain access. Adversaries 2, 3, and 4 exploit misconfiguration and only need to run code on the platform. Adversary 6 is a denial-of-service requiring only function submission access.
- **Objective:** Exfiltrate data or model weights, achieve host access via plugin, deny service to other tenants.
- **Blast radius:** An overpermissive capability grant exposes all filesystem content visible to the WasmEdge process. A compromised plugin has host process access. Resource exhaustion affects all co-located WASM workloads.

## Configuration

### Step 1: Minimal Capability Grants

WasmEdge capabilities are granted at execution time. Deny all by default and add only what the specific module requires:

```bash
# BAD: Full filesystem access — do not use in production.
wasmedge --dir /:/ module.wasm

# GOOD: Only the specific directories the module needs.
# For a function that reads from /data/input and writes to /data/output:
wasmedge \
  --dir /data/input:/data/input:readonly \
  --dir /data/output:/data/output \
  module.wasm

# For AI inference with WASI-NN: only the model weight directory, readonly.
wasmedge \
  --dir /models/llama:/models/llama:readonly \
  --env NN_PRELOAD="default:GGML:AUTO:/models/llama/llama-2-7b.gguf" \
  --wasi-nn-preload default:GGML:AUTO:/models/llama/llama-2-7b.gguf \
  inference.wasm

# No network access by default.
# WASI-Socket requires --allow-af-inet or --allow-af-inet6 to enable.
# Grant only if the module explicitly requires outbound network access.
```

Capability matrix — grant only the row relevant to each module:

| Module Type | `--dir` | WASI-Socket | WASI-NN | `--env` |
|-------------|---------|-------------|---------|---------|
| Pure compute | None | No | No | No |
| File transformer | Input+output only, readonly input | No | No | No |
| AI inference (local) | Model dir readonly | No | Yes | Model path only |
| Webhook handler | None | Specific IPs only | No | Config only |
| Multi-tenant function | Per-tenant tmpdir | No | No | Tenant ID only |

### Step 2: WASI-Socket Restrictions

If a module requires network access, restrict permitted addresses using WasmEdge's socket capability controls:

```rust
// In Rust: use the wasmedge-wasi-helper or wasi-sdk socket bindings.
// The host controls which addresses are reachable — application code cannot
// open sockets to addresses not in the allow-list.

// Host-side: WasmEdge 0.13+ supports TCP/UDP address restrictions via
// the --allow-ip flag or via configuration file.
```

```toml
# wasmedge-config.toml — capability configuration file.
[wasi]
# Restrict socket access to specific addresses.
allowed_socket_addresses = [
  "10.0.1.50:8080",        # Internal inference gateway only.
  "10.0.1.51:8080",        # Fallback inference node.
]
# Block all other socket connections.
allow_all_socket_addresses = false

[resource_limits]
memory_pages_max = 65536   # 4 GiB (65536 * 64KiB pages) maximum per execution.
fuel_limit = 10000000000   # Instruction count limit (prevents infinite loops).
```

```bash
# Use the config file at execution time.
wasmedge --config wasmedge-config.toml module.wasm
```

### Step 3: Verify WASM Module Integrity

Never execute unverified WASM modules. Verify the module against a known-good digest or a Sigstore signature before execution:

```bash
# Generate SHA-256 digest at build time and store in a trusted location.
sha256sum inference.wasm > inference.wasm.sha256
# Store inference.wasm.sha256 in a separate trusted path, not alongside the WASM.

# At execution time, verify before running.
verify_and_run() {
  local MODULE=$1
  local EXPECTED_SHA256=$2

  ACTUAL=$(sha256sum "$MODULE" | awk '{print $1}')
  if [ "$ACTUAL" != "$EXPECTED_SHA256" ]; then
    echo "INTEGRITY CHECK FAILED: $MODULE"
    echo "Expected: $EXPECTED_SHA256"
    echo "Actual:   $ACTUAL"
    exit 1
  fi
  wasmedge --config /etc/wasmedge/config.toml "$MODULE"
}

verify_and_run inference.wasm "$(cat /etc/wasmedge/inference.wasm.sha256)"
```

For supply chain provenance, use Sigstore:

```bash
# Sign the WASM module at build time (CI pipeline).
cosign sign-blob \
  --key cosign.key \
  --bundle inference.wasm.bundle \
  inference.wasm

# Verify signature before execution.
cosign verify-blob \
  --key cosign.pub \
  --bundle inference.wasm.bundle \
  inference.wasm || { echo "Signature verification failed"; exit 1; }
```

### Step 4: Plugin Security

WasmEdge plugins are native shared libraries that extend the runtime. They execute outside the sandbox. Manage plugins with the same care as host binaries:

```bash
# List installed plugins.
wasmedge --list-plugins

# Verify plugin integrity.
sha256sum /usr/local/lib/wasmedge/*.so | sort > /etc/wasmedge/plugin-manifest.sha256
# At startup or before execution:
sha256sum --check /etc/wasmedge/plugin-manifest.sha256 || { 
  echo "Plugin integrity check failed"; 
  exit 1; 
}

# Use only plugins from the official WasmEdge release.
# Do not load community or third-party plugins without source review.
# Plugin directory should be read-only at runtime.
chmod 444 /usr/local/lib/wasmedge/*.so
chown root:root /usr/local/lib/wasmedge/*.so
```

Restrict which plugins load in the configuration:

```toml
# wasmedge-config.toml
[plugins]
# Allowlist: only load specific plugins by exact path.
allowed_plugins = [
  "/usr/local/lib/wasmedge/libwasmedgePluginWasiNN.so",
]
# All other plugins are rejected even if present on disk.
```

### Step 5: Resource Limits

Enforce per-execution memory and instruction limits to prevent resource exhaustion:

```toml
# wasmedge-config.toml
[resource_limits]
# Memory: 64KiB pages. 16384 pages = 1 GiB.
memory_pages_max = 16384

# Fuel: instruction counter. Execution halts when fuel exhausted.
# 1e10 instructions ≈ several seconds of computation — tune per workload.
fuel_limit = 10000000000

# Execution timeout (seconds). Enforced at the host level.
# Combine with OS-level timeout (timeout(1) or systemd-run --timeout).
```

```bash
# Enforce wall-clock timeout in addition to instruction limit.
timeout 30 wasmedge \
  --config /etc/wasmedge/config.toml \
  inference.wasm
# Exits with code 124 if timeout exceeded.

# In Kubernetes: set resource limits on the pod.
# containerd-shim-wasmedge respects pod resource limits.
```

```yaml
# kubernetes/wasmedge-pod.yaml
apiVersion: v1
kind: Pod
spec:
  runtimeClassName: wasmedge   # Uses containerd-shim-wasmedge.
  containers:
    - name: inference
      image: ghcr.io/example/inference:sha256-abc123
      resources:
        limits:
          memory: "1Gi"
          cpu: "2"
        requests:
          memory: "512Mi"
          cpu: "500m"
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
```

### Step 6: Multi-Tenant Isolation

When running WASM modules from multiple tenants on the same host, enforce per-tenant isolation:

```python
# wasmedge_runner.py — multi-tenant execution controller.
import subprocess
import tempfile
import os
from pathlib import Path

def run_tenant_module(
    tenant_id: str,
    wasm_path: str,
    expected_sha256: str,
    input_data: bytes,
) -> bytes:
    # 1. Verify module integrity.
    import hashlib
    actual = hashlib.sha256(Path(wasm_path).read_bytes()).hexdigest()
    if actual != expected_sha256:
        raise ValueError(f"Integrity check failed for {wasm_path}")

    # 2. Create per-tenant tmpdir — no shared state between tenants.
    with tempfile.TemporaryDirectory(prefix=f"tenant-{tenant_id}-") as tmpdir:
        input_path = Path(tmpdir) / "input"
        output_path = Path(tmpdir) / "output"
        input_path.write_bytes(input_data)

        # 3. Run WasmEdge with minimal permissions.
        result = subprocess.run(
            [
                "wasmedge",
                "--config", "/etc/wasmedge/config.toml",
                "--dir", f"{tmpdir}:{tmpdir}",   # Only tenant tmpdir.
                "--env", f"TENANT_ID={tenant_id}",
                wasm_path,
            ],
            capture_output=True,
            timeout=30,          # Wall-clock timeout.
            check=False,
        )

        if result.returncode != 0:
            raise RuntimeError(f"WASM execution failed: {result.stderr.decode()}")

        return output_path.read_bytes() if output_path.exists() else b""
```

### Step 7: Containerd RuntimeClass for Kubernetes

Use the official WasmEdge containerd shim for Kubernetes workloads:

```bash
# Install containerd-shim-wasmedge on nodes.
apt-get install wasmedge-containerd-shim

# Configure containerd runtime.
cat >> /etc/containerd/config.toml << 'EOF'
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.wasmedge]
  runtime_type = "io.containerd.wasmedge.v1"
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.wasmedge.options]
    ConfigPath = "/etc/wasmedge/config.toml"
EOF

systemctl restart containerd
```

```yaml
# kubernetes/runtimeclass-wasmedge.yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: wasmedge
handler: wasmedge
scheduling:
  nodeSelector:
    wasmedge: "true"      # Only schedule on nodes with the shim installed.
  tolerations:
    - key: "wasmedge"
      operator: "Exists"
      effect: "NoSchedule"
```

Apply Kyverno policy to enforce WasmEdge pods use restricted security contexts:

```yaml
# kyverno/wasmedge-security-policy.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: wasmedge-security-policy
spec:
  validationFailureAction: Enforce
  rules:
    - name: require-non-root
      match:
        any:
          - resources:
              kinds: ["Pod"]
              selector:
                matchLabels:
                  runtime: "wasmedge"
      validate:
        message: "WasmEdge pods must run as non-root."
        pattern:
          spec:
            containers:
              - securityContext:
                  runAsNonRoot: true
                  readOnlyRootFilesystem: true
                  allowPrivilegeEscalation: false
```

### Step 8: Telemetry

```
wasmedge_executions_total{tenant, module, status}              counter
wasmedge_execution_duration_seconds{tenant, module}            histogram
wasmedge_memory_pages_used{tenant, module}                     gauge
wasmedge_fuel_consumed{tenant, module}                         counter
wasmedge_integrity_check_failures_total{module}                counter
wasmedge_socket_connections_total{tenant, destination}         counter
wasmedge_plugin_load_total{plugin, status}                     counter
wasmedge_resource_limit_exceeded_total{tenant, limit_type}     counter
```

Alert on:

- `wasmedge_integrity_check_failures_total` non-zero — a WASM module failed verification; do not execute; investigate the module source.
- `wasmedge_resource_limit_exceeded_total` — a module hit its memory or fuel limit; may indicate a runaway computation or deliberate resource exhaustion.
- `wasmedge_socket_connections_total` with unexpected `destination` — a module attempted a connection to an address not in the allow-list; investigate for data exfiltration.
- `wasmedge_plugin_load_total{status="failed"}` — a plugin failed its integrity check or was not on the allowlist; investigate before restarting the runtime.
- `wasmedge_execution_duration_seconds` P99 spikes — a module is taking significantly longer than baseline; combined with resource limit monitoring, indicates possible abuse.

## Expected Behaviour

| Signal | Unconfigured WasmEdge | Hardened WasmEdge |
|--------|----------------------|-------------------|
| Malicious module reads host `/etc` | Succeeds if `--dir /:/` granted | Blocked: only permitted directories accessible |
| Module exfiltrates data over network | Succeeds if WASI-Socket enabled | Blocked: only specific IPs permitted, or socket disabled |
| Tampered WASM module executed | Executed without detection | Integrity check fails; execution aborted |
| AI model weights exfiltrated | Readable if model dir in preopen | Model dir mounted readonly; socket disabled for inference module |
| Compromised plugin loaded | Loads and executes with host access | Plugin allowlist blocks non-approved plugins; hash check at load |
| Runaway module exhausts host memory | OOM kill affects all tenants | Fuel and memory limits halt the module; other modules unaffected |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Minimal capability grants | Strong sandbox; limits exfiltration | Requires knowing exact capability needs per module | Document capability requirements at module build time |
| Socket address allowlist | Prevents arbitrary outbound connections | Must update allowlist when upstream endpoints change | Manage via configuration file; allowlist changes require review |
| Module integrity verification | Detects supply chain tampering | Build pipeline must produce and distribute hashes/signatures | Integrate with Sigstore via CI; use OCI artifact signing |
| Plugin allowlist | Prevents loading malicious plugins | Restricts extending the runtime | Only add plugins after code review; pin to specific versions |
| Resource limits | Prevents exhaustion; enables multi-tenancy | Must be tuned per workload; too-low fuel limit breaks valid modules | Profile execution in staging; set fuel at 10× observed maximum |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Integrity check blocks legitimate update | Module fails verification after CI update | `wasmedge_integrity_check_failures_total` alert; execution blocked | Update the expected hash alongside the module in the deployment pipeline |
| Fuel limit too low for large model | Inference fails with `FuelExhausted` error | Execution failure logs; `wasmedge_resource_limit_exceeded_total` | Increase fuel limit; profile the model's instruction count in staging |
| WASI-Socket allowlist missing required endpoint | Module fails to connect to upstream API | Execution logs show connection refused; `wasmedge_socket_connections_total` shows drop | Add endpoint to allowlist; review why module needs the connection |
| Plugin integrity check fails after host update | WasmEdge refuses to load plugin | `wasmedge_plugin_load_total{status="failed"}` | Regenerate plugin manifest after planned update; alert on unplanned changes |
| Memory limit OOM on large batch | Module killed mid-inference; partial output | `wasmedge_resource_limit_exceeded_total{limit_type="memory"}` | Increase memory limit or split batch; add input size validation upstream |

## Related Articles

- [WASM Component Model Security](/articles/wasm/wasm-component-model-security/)
- [Spin Framework Security](/articles/wasm/spin-framework-security/)
- [WasmCloud Security](/articles/wasm/wasmcloud-security/)
- [Kyverno Policy Development and Testing](/articles/kubernetes/kyverno-policy-development/)
- [RuntimeClass: gVisor and Kata Containers](/articles/kubernetes/runtimeclass-gvisor-kata/)
- [Sigstore Keyless Signing](/articles/cicd/sigstore-keyless-signing/)
