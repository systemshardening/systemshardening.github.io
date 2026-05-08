---
title: "Kubernetes RuntimeClass: gVisor and Kata Containers for Production Workload Isolation"
description: "RuntimeClass lets you select a sandboxed container runtime per workload. gVisor intercepts syscalls in userspace; Kata Containers run workloads in lightweight VMs. Each changes the threat model."
slug: "runtimeclass-gvisor-kata"
date: 2026-04-29
lastmod: 2026-04-29
category: "kubernetes"
tags: ["runtimeclass", "gvisor", "kata-containers", "sandboxing", "isolation"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 240
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/kubernetes/runtimeclass-gvisor-kata/index.html"
---

# Kubernetes RuntimeClass: gVisor and Kata Containers for Production Workload Isolation

## Problem

Standard container isolation relies on Linux namespaces and cgroups. The container shares the host kernel: every syscall made by the container is handled by the same kernel that manages the rest of the node. A container escape vulnerability in the kernel, or a kernel exploit reachable from within the container, compromises the entire node.

The attack surface of the Linux kernel visible from within a container is substantial — hundreds of syscalls, many with complex parsing logic that has historically contained exploits (CVE-2022-0185, CVE-2022-2639, CVE-2023-0266, and others). Seccomp profiles reduce the visible syscall surface, but they require maintaining per-workload allowlists and still expose the real kernel to the calls they permit.

Sandboxed runtimes change the isolation model:

- **gVisor (runsc):** A user-space kernel written in Go. Container syscalls are intercepted by gVisor's Sentry component, which implements a large portion of the Linux syscall ABI in userspace. Host kernel exposure is reduced to a small surface of host syscalls that gVisor's Sentry itself makes. A kernel exploit in the container must first break out of gVisor's Sentry — a separate isolation boundary.
- **Kata Containers:** Container workloads run inside lightweight virtual machines (QEMU micro-vm or Cloud Hypervisor) with their own guest kernel. The container's syscalls are handled by the guest kernel; the hypervisor call surface is the isolation boundary. A full kernel exploit within the container escapes only the guest kernel, not the host.

The specific gaps in clusters without sandboxed runtimes:

- Multi-tenant clusters running workloads from different trust levels (first-party + third-party) with identical kernel isolation.
- Workloads executing untrusted user-provided code (function platforms, CI runners, ML inference) with direct kernel exposure.
- No per-workload isolation policy — all pods on a node have the same escape risk.
- Incident response after a container escape is complicated by shared kernel state.

**Target systems:** Kubernetes 1.28+ (RuntimeClass stable); gVisor 20240101+ (containerd-shim-runsc); Kata Containers 3.3+ (kata-deploy DaemonSet); node OS: Ubuntu 22.04 or RHEL 9 with KVM enabled.

## Threat Model

- **Adversary 1 — Kernel exploit from within a container:** An attacker running code inside a standard container exploits a kernel vulnerability (use-after-free, type confusion) reachable via a syscall permitted by the container's seccomp profile. They gain a root shell on the host node.
- **Adversary 2 — Cross-tenant escape in multi-tenant cluster:** A tenant in a shared Kubernetes cluster exploits a container runtime or kernel vulnerability to escape their pod and access other tenants' data on the same node.
- **Adversary 3 — Untrusted code execution in a function platform:** A user submits a malicious function payload that exploits the container runtime. Without sandbox isolation, this compromises the node.
- **Adversary 4 — gVisor escape:** An attacker finds a vulnerability in gVisor's Sentry (Go, approximately 200k lines). They escape gVisor's userspace kernel but still face the host kernel — a second isolation boundary.
- **Adversary 5 — Hypervisor escape (Kata):** An attacker exploits the Kata guest kernel and then attacks the hypervisor (QEMU/Cloud Hypervisor). Hypervisor CVEs exist but are fewer and more complex than kernel CVEs.
- **Access level:** All adversaries have container-level code execution (user or root within the container).
- **Objective:** Escape the container boundary and access the host kernel, other containers, or the Kubernetes API.
- **Blast radius:** Standard runtime: container escape = node compromise. gVisor: container escape requires breaking gVisor Sentry first. Kata: requires breaking hypervisor. In both cases, the isolation boundary is significantly stronger than namespaces alone.

## Configuration

### Step 1: Install gVisor on Nodes

```bash
# On each node: install the runsc binary.
curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /usr/share/keyrings/gvisor.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor.gpg] \
  https://storage.googleapis.com/gvisor/releases release main" \
  | tee /etc/apt/sources.list.d/gvisor.list
apt update && apt install -y runsc

# Configure containerd to use runsc as a runtime handler.
cat >> /etc/containerd/config.toml <<'EOF'
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc.options]
  TypeUrl = "io.containerd.runsc.v1.options"
  ConfigPath = "/etc/containerd/runsc.toml"
EOF

# gVisor configuration.
cat > /etc/containerd/runsc.toml <<'EOF'
[runsc_config]
  platform = "kvm"          # Use KVM for hardware-accelerated isolation (preferred).
                             # "ptrace" is a fallback where KVM is unavailable.
  network = "host"          # Or "sandbox" for full network namespace isolation.
  file-access = "exclusive"  # Exclusive file access for stronger isolation.
  overlay = false
  debug = false
  strace = false
EOF

systemctl restart containerd
```

Verify:

```bash
# Test gVisor is working.
ctr image pull docker.io/library/alpine:latest
ctr run --runtime io.containerd.runsc.v1 --rm docker.io/library/alpine:latest test uname -r
# Output shows gVisor's kernel version, not the host kernel.
```

### Step 2: Install Kata Containers on Nodes

```bash
# Deploy Kata via the kata-deploy DaemonSet (installs on all nodes automatically).
kubectl apply -f https://raw.githubusercontent.com/kata-containers/kata-containers/main/tools/packaging/kata-deploy/kata-deploy/base/kata-deploy.yaml

# Wait for kata-deploy to complete on all nodes.
kubectl -n kube-system wait --timeout=300s \
  --for=condition=Ready \
  -l name=kata-deploy \
  pod

# Verify containerd was patched with Kata handlers.
kubectl -n kube-system exec -it \
  $(kubectl -n kube-system get pod -l name=kata-deploy -o jsonpath='{.items[0].metadata.name}') \
  -- kata-runtime check
```

kata-deploy adds the following runtime handlers to containerd on each node:
- `kata-qemu`: QEMU micro-vm (widest compatibility)
- `kata-clh`: Cloud Hypervisor (lower overhead, Linux-only)
- `kata-fc`: Firecracker (lowest overhead; limited device support)

### Step 3: Create RuntimeClass Resources

```yaml
# runtimeclass-gvisor.yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
overhead:
  podFixed:
    memory: "100Mi"    # gVisor Sentry memory overhead per pod.
    cpu: "50m"
scheduling:
  nodeSelector:
    sandbox.io/runtime: gvisor   # Only schedule on nodes with runsc installed.
  tolerations:
    - key: sandbox.io/runtime
      operator: Equal
      value: gvisor
      effect: NoSchedule
---
# runtimeclass-kata.yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: kata-qemu
handler: kata-qemu
overhead:
  podFixed:
    memory: "512Mi"    # Guest kernel + QEMU overhead per pod.
    cpu: "250m"
scheduling:
  nodeSelector:
    sandbox.io/runtime: kata
  tolerations:
    - key: sandbox.io/runtime
      operator: Equal
      value: kata
      effect: NoSchedule
```

Label nodes:

```bash
# Label nodes with gVisor support.
kubectl label node gvisor-node-1 sandbox.io/runtime=gvisor
kubectl taint node gvisor-node-1 sandbox.io/runtime=gvisor:NoSchedule

# Label nodes with Kata support (requires nested virt or bare-metal KVM).
kubectl label node kata-node-1 sandbox.io/runtime=kata
kubectl taint node kata-node-1 sandbox.io/runtime=kata:NoSchedule
```

### Step 4: Assign RuntimeClass to Workloads

```yaml
# Untrusted workload using gVisor.
apiVersion: v1
kind: Pod
metadata:
  name: untrusted-function
  namespace: functions
spec:
  runtimeClassName: gvisor   # Key line.
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: function
      image: user-provided-function:latest
      resources:
        limits:
          memory: 256Mi
          cpu: 500m
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: [ALL]
```

```yaml
# High-isolation workload using Kata.
apiVersion: v1
kind: Pod
metadata:
  name: sensitive-ml-inference
  namespace: ml
spec:
  runtimeClassName: kata-qemu   # Lightweight VM isolation.
  containers:
    - name: inference
      image: ml-model-server:v1.2.3
      resources:
        requests:
          memory: 2Gi
          cpu: 2
        limits:
          memory: 4Gi
          cpu: 4
```

### Step 5: Enforce RuntimeClass with Kyverno

Prevent sensitive namespaces from running with the default (insecure) runtime:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-sandbox-runtime
spec:
  validationFailureAction: Enforce
  rules:
    - name: require-gvisor-or-kata
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [functions, untrusted, ml-inference]
      validate:
        message: "Pods in this namespace must use a sandboxed RuntimeClass (gvisor or kata-qemu)."
        pattern:
          spec:
            runtimeClassName: "gvisor | kata-qemu | kata-clh | kata-fc"
```

For namespaces where the standard runtime is acceptable, explicitly document the decision:

```yaml
# For first-party trusted workloads, no runtimeClassName needed.
# For third-party or user-provided code: require sandbox.
```

### Step 6: gVisor Performance Tuning

gVisor's performance overhead varies by workload type:

| Workload type | gVisor overhead | Notes |
|--------------|----------------|-------|
| CPU-bound (ML, compression) | 2–5% | Near-native; no syscall overhead |
| Network-intensive | 10–20% | gVisor's netstack is userspace; overhead vs kernel networking |
| Syscall-heavy (databases, file servers) | 20–100%+ | Each syscall transitions to Sentry; not suitable for databases |
| Memory-intensive | 5–10% | Page fault handling via Sentry |

For network-intensive workloads, configure gVisor to use the host network stack:

```toml
# /etc/containerd/runsc.toml
[runsc_config]
  network = "host"         # Use host kernel network stack for lower overhead.
  platform = "kvm"         # KVM platform for hardware isolation.
```

For syscall-heavy workloads that cannot accept gVisor overhead, use Kata instead:

```bash
# Kata's guest kernel handles syscalls natively; overhead is mainly VM startup
# (which is amortized for long-running pods).
# Typical Kata overhead: 5-15% for steady-state workloads.
```

### Step 7: Verify Isolation

Confirm that gVisor and Kata pods are not running with the host kernel:

```bash
# In a gVisor pod: the kernel version should show gVisor, not the host kernel.
kubectl exec -n functions untrusted-function -- uname -r
# Output: 4.4.0 (gVisor's synthetic kernel version; not the real host kernel)

# In a Kata pod: the kernel is a minimal guest kernel.
kubectl exec -n ml sensitive-ml-inference -- uname -r
# Output: 6.1.x-kata (the Kata guest kernel)

# Confirm the host kernel version (on the node directly).
uname -r
# Output: 6.8.x (the real host kernel; different from what pods see)
```

Test that a syscall unavailable to gVisor fails:

```bash
# perf_event_open is not implemented in gVisor (intentionally).
kubectl exec -n functions untrusted-function -- \
  python3 -c "import ctypes; ctypes.CDLL(None).perf_event_open(None, 0, -1, -1, 0)"
# Expected: OSError: [Errno 38] Function not implemented (ENOSYS from gVisor)
```

### Step 8: Telemetry

```
kubelet_running_pods{runtime_handler}                  gauge
container_runtime_operations_total{operation_type}    counter
gvisor_sandbox_count                                   gauge
gvisor_syscall_count{syscall}                          counter
kata_vm_count                                          gauge
kata_vm_startup_seconds                                histogram
runtimeclass_admission_failure_total{namespace}        counter
```

Alert on:

- `runtimeclass_admission_failure_total` non-zero — a pod was rejected because it didn't specify a required RuntimeClass; investigate the deploying workload.
- `kata_vm_count` mismatch vs expected pod count — a pod may have fallen back to the default runtime.
- gVisor Sentry crash (`runsc` process dies) — pod continues but with fallback behavior; detect via `kubelet_running_pods` count drop.

## Expected Behaviour

| Signal | Standard runtime | gVisor | Kata Containers |
|--------|-----------------|--------|-----------------|
| Host kernel syscall surface | Full | ~50 syscalls (Sentry's host surface) | Hypervisor call surface only |
| Container `uname -r` | Host kernel version | gVisor synthetic version | Kata guest kernel version |
| Kernel exploit from container | Host kernel exposed | Sentry must be broken first | Guest kernel must be exploited; then hypervisor |
| Syscall-heavy workload overhead | Baseline | 20–100%+ | 5–15% |
| VM startup time | <1s | N/A (no VM) | 100–500ms |
| GPU passthrough | Supported | Limited | Supported (Kata with VFIO) |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| gVisor isolation | Strong syscall interception; lightweight | Syscall-heavy workloads see high overhead; not all syscalls implemented | Profile workload before deploying; use Kata for syscall-heavy workloads. |
| Kata isolation | Near-native performance; real kernel | VM startup latency; higher memory overhead per pod | Use for long-running workloads; pre-warm VMs for latency-sensitive paths. |
| RuntimeClass + Kyverno enforcement | Policy prevents unsafe defaults | Breaks workloads that don't declare RuntimeClass | Roll out per namespace; audit before enforcement. |
| Node labeling + tainting | Ensures sandboxed pods land on capable nodes | Reduces scheduling flexibility; requires more node types | Use separate node pools per runtime type; resize pools with cluster autoscaler. |
| KVM platform for gVisor | Hardware-accelerated; stronger isolation | Requires KVM access on the node (nested virt in clouds) | Most major cloud providers support nested virt on specific instance types. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| runsc not installed on node | Pod stays in Pending; `RuntimeClass not found` event | Pod events; kubelet log | Install runsc on the node; or remove the node taint to reschedule elsewhere. |
| KVM unavailable on node | gVisor falls back to ptrace platform (weaker) | `runsc` logs show `platform: ptrace`; check `/dev/kvm` exists | Enable nested virtualization on the instance; or use a bare-metal node. |
| Kata VM startup timeout | Pod stuck in ContainerCreating | Pod events: `failed to start sandbox`; kata-runtime logs | Check QEMU binary and guest kernel are installed; verify KVM access. |
| Unsupported syscall in gVisor | Application crashes with ENOSYS | Application error logs; `runsc` debug logs show unimplemented syscall | File a gVisor issue if the syscall is reasonable; or switch the workload to Kata. |
| RuntimeClass overhead miscounted | OOM on node due to underestimated overhead | Node memory pressure; pod OOM kills | Increase `overhead.podFixed.memory` in the RuntimeClass spec. |
| Pod scheduled to wrong node type | Pod fails; node doesn't have the runtime handler | Pod events: `handler not found` | Fix node selector in RuntimeClass or pod spec; verify node labels match. |

## Related Articles

- [Pod Security Context and Seccomp Profiles](/articles/kubernetes/seccomp-profiles/)
- [Kubernetes Node Hardening](/articles/kubernetes/node-hardening/)
- [Confidential Containers: Encrypted Workloads in Kubernetes](/articles/kubernetes/confidential-containers/)
- [Multi-Tenancy Hardening in Kubernetes](/articles/kubernetes/multi-tenancy-hardening/)
- [Linux Capability Hardening](/articles/linux/linux-capability-hardening/)
