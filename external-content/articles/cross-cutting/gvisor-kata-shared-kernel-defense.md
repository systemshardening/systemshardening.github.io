---
title: "gVisor and Kata Containers: What the Shared Kernel Problem Forced the Industry to Build"
description: "CVE-2019-5736 (runc), CVE-2022-0847 (Dirty Pipe), and CVE-2022-1015 (Netfilter) each demonstrated that containers sharing a Linux kernel cannot be isolated by Linux itself. gVisor reimplements kernel syscalls in userspace; Kata Containers runs each pod in a separate microVM. Both exist because the threat model changed."
slug: gvisor-kata-shared-kernel-defense
date: 2026-05-08
lastmod: 2026-05-08
category: cross-cutting
tags:
  - gvisor
  - kata-containers
  - kernel
  - container-escape
  - runtime-security
personas:
  - platform-engineer
  - security-engineer
article_number: 663
difficulty: Intermediate
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/cross-cutting/gvisor-kata-shared-kernel-defense/
---

# gVisor and Kata Containers: What the Shared Kernel Problem Forced the Industry to Build

## The Problem

The container security model has a single foundational assumption that every container escape CVE exploits: all containers on a host share one Linux kernel, and that kernel's correctness is the only thing standing between a container process and the host.

The timeline of failures is instructive.

**2016: Dirty COW (CVE-2016-5195).** A race condition in `mmap` copy-on-write handling allowed unprivileged processes to write to read-only memory mappings. Any unprivileged process inside a container — with no elevated capabilities, no seccomp bypass, nothing — could escalate to root on the host by racing a write to `/proc/self/mem` against the COW implementation. The bug had been present in the kernel since 2.6.22 (2007). It took nine years to find and nine seconds to exploit once a PoC existed. The fix landed in 4.8.3. The lesson: a kernel bug that has existed for years is not theoretical; it is latent.

**2019: runc CVE-2019-5736.** Disclosed on February 11, 2019, by Adam Iwaniuk and Borys Popławski. A malicious container could overwrite the host runc binary on disk by abusing `/proc/self/exe` symlink resolution during the brief window when runc's child process joined the container's PID namespace. The attacker needed only one thing: the ability to exec into a container they controlled. Any user with `kubectl exec` permission to a pod they owned met that bar. Every container runtime that used runc — Docker before 18.09.2, containerd before 1.2.4, CRI-O before 1.11.8, and therefore every Kubernetes cluster running those versions — was affected. The patch was runc 1.0-rc6, released the same day. Kubernetes clusters that did not patch within days of disclosure were exposed: every exec into a user-controlled pod was a root-on-host primitive. The full technical breakdown of this vulnerability is in [runc CVE-2019-5736: Overwriting the Container Runtime from Inside a Container](/articles/kubernetes/runc-container-escape-cve-2019-5736/).

**2022: Dirty Pipe (CVE-2022-0847).** Disclosed March 7, 2022, by Max Kellermann. A pipe buffer initialisation bug introduced in kernel 5.8 left `PIPE_BUF_FLAG_CAN_MERGE` set on buffer entries populated via `splice()` from file-backed pages. A subsequent write to the pipe merged data directly into the page cache, bypassing all VFS permission checks. No race condition. No capabilities required. Any unprivileged process in a container running kernels 5.8 through 5.16.10 could overwrite arbitrary bytes in any file-backed read-only mapping — including `/etc/passwd`, SUID binaries, and container layer files in the host's overlay filesystem. Inside a container, this translated immediately to host filesystem write access with no containment boundary. The full mechanism is documented in [Dirty Pipe (CVE-2022-0847): Writing to Read-Only Files Inside Containers](/articles/linux/dirty-pipe-container-escape/).

**2022: Netfilter CVE-2022-1015.** An out-of-bounds write in the `nft_validate_register_store()` path of the nftables subsystem. The bug was reachable from unprivileged user namespaces — which are enabled by default on Ubuntu and many other distributions. A container process with `CAP_NET_ADMIN` scoped to a user namespace (which Kubernetes grants to containers that request it, and which can sometimes be obtained through namespace creation) could trigger the OOB write to escalate to kernel context and execute arbitrary code as root on the host. The mechanism is covered in detail in [Netfilter Container Escape CVE-2022-1015](/articles/network/netfilter-container-escape-cve-2022-1015/).

The pattern across all four CVEs is identical: the container process reaches a code path in the shared kernel, that code path has a bug, and the result is host compromise. The isolation mechanism — namespaces, cgroups, seccomp, capabilities — never enters the picture. Namespaces partition the kernel's view of resources. They do not partition the kernel's code. A bug in `splice()` is reachable from any process that can call `splice()`, regardless of what mount namespace it is in.

This is the shared kernel problem stated precisely. You cannot use Linux to isolate processes from Linux.

The industry responded with two architectural approaches that both reject the premise.

### gVisor: A Userspace Kernel

Google shipped gVisor in 2018 and open-sourced it as `runsc` — an OCI-compatible runtime that replaces runc. The architecture is a clean break: instead of letting container processes make Linux syscalls directly to the host kernel, gVisor places a component called the **Sentry** between the container and the host.

The Sentry is a Go process that implements the Linux syscall ABI in userspace. When a container process calls `splice()`, the call is intercepted by a ptrace-based or KVM-based intercept mechanism (depending on the platform) before it reaches the host kernel. The Sentry handles the call: it executes its own Go implementation of `splice()`, using a small set of host kernel operations to accomplish the underlying work. The container process never makes a `splice()` call against the host kernel; it makes the call against the Sentry's userspace implementation.

The host syscall reduction is dramatic. A standard Linux process has access to roughly 400 syscalls on x86-64. Under gVisor, the Sentry makes approximately 50 host syscalls to implement the full container syscall surface. The container process's calls never reach the host kernel at all.

The consequence for CVE-2022-0847 is exact: the Dirty Pipe bug is in the host kernel's pipe buffer implementation. The Sentry has its own pipe buffer implementation, in Go, in userspace. The `PIPE_BUF_FLAG_CAN_MERGE` initialisation bug does not exist in the Sentry's code. A container process running under gVisor calling `splice()` reaches the Sentry's Go implementation, not the host kernel's C implementation. The CVE is not present in the attack surface.

For CVE-2019-5736, the analysis is different but the conclusion is the same. The runc vulnerability exists because runc itself executes in the host kernel context while transitioning into container namespaces. Under gVisor, there is no runc. The Sentry manages the container's lifecycle without the exec-into-container namespace-join dance that made CVE-2019-5736 possible. The attack vector does not exist.

### Kata Containers: A VM Per Pod

The OpenStack Foundation merged Intel's Clear Containers project with Hyper's runV in 2019 to produce Kata Containers. The architecture is different from gVisor's: rather than reimplementing the kernel, Kata gives each pod its own kernel.

When Kubernetes schedules a pod with runtimeClass `kata-containers`, Kata launches a lightweight VM — using QEMU, Cloud Hypervisor, or Firecracker as the VMM — and runs the container processes inside that VM's Linux kernel. The host kernel is not involved in processing the container's syscalls. The container calls `splice()` inside the guest kernel. The guest kernel runs entirely within a hardware virtualisation boundary enforced by VT-x or AMD-V. The host kernel's attack surface is no longer the Linux syscall ABI — it is the hypervisor interface.

CVE-2022-0847 under Kata: the guest kernel may be affected if it is running an unpatched 5.8–5.16.10 kernel (you need to patch the guest kernel too — it is a real kernel). But the host kernel is not touched by the container process at all. A successful Dirty Pipe exploit inside a Kata pod damages the guest VM's filesystem. The host filesystem is behind a hardware virtualisation boundary that requires a separate hypervisor escape to cross.

CVE-2019-5736 under Kata: entirely irrelevant. There is no runc binary that joins the container's PID namespace from the host side. The container init process runs inside the VM from boot. There is no exec path that crosses the host/guest boundary in the way runc's namespace join does.

The remaining attack surface with Kata is the VMM itself. QEMU has a long history of device emulation CVEs (CVE-2019-6778, CVE-2020-29130, among many others). Firecracker has a dramatically smaller attack surface — four virtio devices, written in Rust — but is not without issues; [Firecracker VMM Attack Surface](/articles/cross-cutting/firecracker-vmm-attack-surface/) covers a 2026 OOB write in Firecracker's virtio PCI transport. The threat model shifts from "kernel CVEs are exploitable by any container" to "hypervisor CVEs are required to cross the VM boundary" — a significantly smaller and better-defined attack surface.

## Threat Model

**Standard runc containers.** Every kernel CVE is potential attack surface. The kernel processes every syscall from every container. A container process with the right primitive — the right sequence of calls, or the right race condition, or the right object spray — can trigger a kernel bug. The attacker needs to find or weaponise a kernel CVE and have a container that can execute the exploit. On a busy multi-tenant cluster, dozens of workloads are exercising different kernel code paths simultaneously. CVE-2022-0847 required zero capabilities and no race condition; a container running an unpatched kernel had no mechanism to prevent a process inside it from escalating to host root.

**gVisor.** The host kernel's attack surface is the ~50 syscalls the Sentry makes on behalf of container operations. A container process cannot reach a host kernel CVE through the normal syscall path — the Sentry handles it. To reach the host kernel, the attacker must first compromise the Sentry: find a bug in the Sentry's Go syscall implementation that allows escaping from the Sentry's userspace context to the host. The Sentry is written in memory-safe Go, code-reviewed, and the subject of ongoing security audits. gVisor-specific vulnerabilities have been found — CVE-2020-10890 was a sandbox escape via a bug in gVisor's socket handling, and CVE-2021-22555 (a Linux kernel heap buffer overflow in netfilter) had a gVisor-specific variant because the Sentry implements its own netfilter handling. The attack surface is smaller and better-controlled than the full Linux kernel, but is not zero. gVisor does not protect against vulnerabilities in the Sentry itself.

**Kata Containers.** The host kernel is not in the direct attack path from the container process. To reach the host kernel, the attacker must: (1) compromise the container with code execution, (2) find a vulnerability in the guest kernel to escape the container within the VM, (3) find a VMM or hypervisor vulnerability to escape the VM boundary. Steps 2 and 3 each require a separate exploit. The class of vulnerabilities required at step 3 (VMM/hypervisor CVEs) is distinct from Linux kernel syscall CVEs and represents a much smaller and more focused attack surface. Remaining risks: guest kernel CVEs (same class as runc vulnerabilities, but now scoped to the guest VM — an attacker who escapes the container within the guest has guest-root but not host-root); VMM CVEs (QEMU CVEs, Firecracker CVEs); hardware microarchitectural vulnerabilities that can cross VM boundaries (Spectre variants, L1TF on certain Intel SKUs).

**Side-by-side comparison.**

| Threat | runc | gVisor | Kata (Firecracker) |
|---|---|---|---|
| Linux kernel syscall CVE | Directly exploitable | Not reachable from container syscall path | Guest kernel only; host protected by VM boundary |
| Container runtime CVE (runc) | Direct attack vector | No runc in the execution path | No runc in the execution path |
| Privilege escalation with CAP_NET_ADMIN | Exploitable if kernel has netfilter bug | Sentry handles netfilter; host unexposed | Guest only |
| Hypervisor/VMM CVE | Not applicable | Not applicable | Primary remaining attack surface |
| Sentry-specific bug | Not applicable | Primary remaining attack surface | Not applicable |
| Workload compatibility | Full Linux syscall ABI | ~380 syscalls implemented; some gaps | Full Linux kernel in guest; near-complete compatibility |

## Hardening Configuration

### 1. Install gVisor on Containerd Nodes

On each node where gVisor workloads will run, install the `runsc` binary and configure containerd to use it as a runtime handler.

```bash
# Install runsc from the official gVisor APT repository
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
  | sudo tee /etc/apt/sources.list.d/gvisor.list
sudo apt-get update && sudo apt-get install -y runsc

# Verify installation
runsc --version
```

Add the `runsc` handler to containerd's configuration at `/etc/containerd/config.toml`:

```toml
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc.options]
  TypeUrl = "io.containerd.runsc.v1.options"
  ConfigPath = "/etc/containerd/runsc.toml"
```

```toml
# /etc/containerd/runsc.toml
# Use the KVM platform where hardware virtualisation is available;
# fall back to ptrace on VMs that don't support nested KVM.
[runsc_config]
  platform = "kvm"
  debug = false
  debug-log = "/var/log/runsc/"
  strace = false
```

Restart containerd: `sudo systemctl restart containerd`.

### 2. gVisor RuntimeClass

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
scheduling:
  nodeClassification:
    tolerations:
    - key: runtime
      operator: Equal
      value: gvisor
      effect: NoSchedule
---
apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: payments
spec:
  runtimeClassName: gvisor
  containers:
  - name: app
    image: myapp:latest
    resources:
      requests:
        cpu: "250m"
        memory: "256Mi"
```

Verify gVisor is active from inside the pod:

```bash
# The /proc/version file reports the gVisor version, not the host kernel version.
# On a standard runc pod you would see the host kernel; under gVisor you see this:
kubectl exec -n payments app -- cat /proc/version
# Linux version 4.4.0 #1 SMP Sun Jan 10 15:06:54 PST 2016 (gVisor)

# The gVisor sandbox process is visible on the node:
# ps aux | grep runsc
# The sandbox intercepts syscalls — dmesg inside the pod is the Sentry's log, not the host dmesg.
kubectl exec -n payments app -- dmesg | grep -i gvisor
```

The `/proc/version` output is a reliable runtime check: if it reports `gVisor`, the pod is running under the Sentry. If it reports the actual host kernel version, the pod is using runc.

### 3. Install Kata Containers with kata-deploy

On Kubernetes clusters, kata-deploy handles the installation of Kata binaries and RuntimeClass objects across nodes:

```bash
# Deploy kata-deploy to install Kata on all nodes
kubectl apply -f https://raw.githubusercontent.com/kata-containers/kata-containers/main/tools/packaging/kata-deploy/kata-deploy/base/kata-deploy.yaml

# kata-deploy creates RuntimeClass objects for each VMM variant:
# kata-qemu    — QEMU VMM, full device emulation, highest compatibility
# kata-clh     — Cloud Hypervisor VMM, reduced attack surface vs QEMU
# kata-fc      — Firecracker VMM, minimal device set, lowest overhead
kubectl get runtimeclass
```

To configure Firecracker explicitly as the Kata VMM (lowest overhead, ~125ms pod start vs ~500ms for QEMU):

```yaml
# /opt/kata/share/defaults/kata-containers/configuration-fc.toml
[hypervisor.firecracker]
  path = "/opt/kata/bin/firecracker"
  kernel = "/opt/kata/share/kata-containers/vmlinux-5.15.63-96"
  image = "/opt/kata/share/kata-containers/kata-containers.img"
  default_vcpus = 1
  default_maxvcpus = 4
  default_memory = 256
  # Disable block device hotplug — reduces attack surface
  block_device_driver = "virtio-blk"
  # Use vsock for agent communication
  use_vsock = true
```

### 4. Kata Containers RuntimeClass

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: kata-containers
handler: kata-fc
scheduling:
  nodeClassification:
    tolerations:
    - key: runtime
      operator: Equal
      value: kata
      effect: NoSchedule
---
apiVersion: v1
kind: Pod
metadata:
  name: payment-processor
  namespace: payments
spec:
  runtimeClassName: kata-containers
  containers:
  - name: payment-processor
    image: payment-processor:v2.1.0
    resources:
      # Account for VM overhead: Kata's guest kernel + agent consumes ~128Mi baseline
      requests:
        cpu: "500m"
        memory: "512Mi"
      limits:
        cpu: "2"
        memory: "2Gi"
```

Verify Kata isolation from inside the pod:

```bash
# The kernel version reported is the guest kernel, not the host kernel
kubectl exec -n payments payment-processor -- uname -r
# 5.15.63-96 (the Kata guest kernel, not the host kernel)

# The process tree is minimal — the container sees only its own processes
kubectl exec -n payments payment-processor -- ps aux
# No host processes visible; VM boundary is enforced

# From the node, the Kata sandbox appears as a firecracker process:
# ps aux | grep firecracker
# /opt/kata/bin/firecracker --config-file /run/kata-containers/...
```

### 5. OPA/Kyverno Policy: Require Secure RuntimeClass for Sensitive Namespaces

Specifying a `runtimeClassName` in a pod spec is optional. A workload that omits it defaults to the cluster's default runtime — typically runc. Without admission control enforcement, pods in regulated namespaces can silently fall through to runc by omitting the field. Enforce it:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-secure-runtime
  annotations:
    policies.kyverno.io/title: Require Secure RuntimeClass for Regulated Namespaces
    policies.kyverno.io/description: >-
      Pods in regulated namespaces must use gvisor or kata-containers to prevent
      shared-kernel escape via kernel CVEs. Pods that omit runtimeClassName fall
      back to runc and are rejected.
spec:
  validationFailureAction: Enforce
  background: true
  rules:
  - name: check-runtimeclass
    match:
      any:
      - resources:
          kinds: [Pod]
          namespaces:
          - payments
          - secrets
          - regulated
          - pci-scope
    validate:
      message: >-
        Pods in regulated namespaces must specify runtimeClassName: gvisor,
        kata-containers, kata-qemu, or kata-fc. Omitting runtimeClassName falls
        back to runc, which shares the host kernel.
      pattern:
        spec:
          runtimeClassName: "gvisor | kata-containers | kata-qemu | kata-clh | kata-fc"
```

Apply and test the policy:

```bash
# Attempt to create a pod without runtimeClassName in the payments namespace — should be rejected
kubectl run test --image=nginx -n payments
# Error from server: admission webhook "kyverno-resource-validating-webhook-cfg.kyverno.svc" denied the request:
# Pods in regulated namespaces must specify runtimeClassName: gvisor, kata-containers...

# Confirm the policy is enforced in background mode for existing pods
kubectl get policyreport -n payments
```

### 6. Node Pool Segregation

Kata nodes require hardware virtualisation support (VT-x or AMD-V) and the appropriate VMM binaries. On cloud providers, this means bare-metal instances or instances where nested virtualisation is enabled (AWS `metal` instance types, GCP C2 with nested KVM, Azure `Dv3` with nested virtualisation). Not every node needs Kata; taint and tolerate to avoid scheduling standard workloads onto more expensive nodes:

```bash
# Taint dedicated Kata nodes so only pods with the toleration land on them
kubectl taint nodes kata-node-1 kata-node-2 runtime=kata:NoSchedule

# Label for affinity rules
kubectl label nodes kata-node-1 kata-node-2 runtime-class=kata
```

```yaml
# Pod spec with explicit Kata node placement
spec:
  runtimeClassName: kata-containers
  tolerations:
  - key: runtime
    operator: Equal
    value: kata
    effect: NoSchedule
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
        - matchExpressions:
          - key: runtime-class
            operator: In
            values: [kata]
```

Similarly for gVisor nodes — gVisor can run on standard instances without hardware virtualisation (using the ptrace platform, with higher overhead), but is most effective with KVM access on nodes. Separate the node pools to control cost and scheduling.

### 7. Performance Benchmarking Baselines

Before enforcing secure runtimes in production, benchmark your actual workloads. Published numbers for common scenarios:

**gVisor overhead.** Syscall-light workloads (web servers with low syscall rate): 2–10% CPU overhead. The Sentry adds a context switch per syscall; for workloads that make thousands of syscalls per second (databases, high-throughput I/O), overhead reaches 2–3x. The Sentry's Netstack (userspace TCP/IP implementation) adds latency relative to the host kernel's network stack — approximately 10–30% network throughput reduction for latency-sensitive workloads.

```bash
# Measure syscall rate inside a container to predict gVisor overhead
strace -c -p $(pgrep -f myapp) -- sleep 30 2>&1 | grep total
# If syscall rate is >10k/sec, measure gVisor overhead explicitly before deploying.

# Simple latency comparison: run against runc, then gVisor
kubectl run bench-runc --image=nginx --overrides='{"spec":{"runtimeClassName":""}}' -n test
kubectl run bench-gvisor --image=nginx --overrides='{"spec":{"runtimeClassName":"gvisor"}}' -n test
# Compare p99 response latency with a sustained load test.
```

**Kata Containers overhead.** Pod start latency: Firecracker ~125ms, Cloud Hypervisor ~200ms, QEMU ~500ms (measured from kubelet pod creation event to container ready). This is largely fixed overhead — cold start time to boot the guest kernel. Steady-state CPU overhead for most workloads: 1–5%. Memory overhead: each Kata VM allocates memory for its guest kernel and kata-agent process, a baseline of approximately 128–256 MB per pod depending on configuration.

```bash
# Measure pod start latency for each runtime
for runtime in "" gvisor kata-fc kata-qemu; do
  start=$(date +%s%3N)
  kubectl run perf-test-${runtime:-runc} \
    --image=alpine \
    --restart=Never \
    --overrides="{\"spec\":{\"runtimeClassName\":\"${runtime}\"}}" \
    -- sleep 1 -n test
  kubectl wait --for=condition=Ready pod/perf-test-${runtime:-runc} -n test --timeout=60s
  echo "${runtime:-runc}: $(($(date +%s%3N) - start))ms to Ready"
  kubectl delete pod perf-test-${runtime:-runc} -n test
done
```

## Expected Behaviour

After deploying a gVisor RuntimeClass and scheduling a pod with `runtimeClassName: gvisor`, `kubectl describe pod` shows:

```
Runtime Class Name:  gvisor
...
Events:
  Type    Reason          Age   From               Message
  ----    ------          ----  ----                -------
  Normal  Scheduled       3s    default-scheduler  Successfully assigned payments/app to node-1
  Normal  Pulled          2s    kubelet            Container image "myapp:latest" already present on machine
  Normal  Created         2s    kubelet            Created container app
  Normal  Started         2s    kubelet            Started container app
```

The `Runtime Class Name: gvisor` field confirms the RuntimeClass resolved. On the node, the sandbox appears as:

```
$ ps aux | grep runsc
root     12345  0.3  0.1  runsc-sandbox --id=<sandbox-id> --root=/var/run/containerd/runsc ...
```

Inside the pod, the kernel reported by `/proc/version` is the gVisor sentinel string, not the host kernel:

```
$ kubectl exec payments/app -- cat /proc/version
Linux version 4.4.0 #1 SMP Sun Jan 10 15:06:54 PST 2016 (gVisor)
```

This is the most reliable runtime check. An application that reads `/proc/version` and sees an actual kernel version string is running under runc regardless of what the Kubernetes spec claims — it means the RuntimeClass was not found, the node handler was not configured, or containerd fell back to the default runtime.

For a Kata Containers pod, `kubectl describe pod` shows `Runtime Class Name: kata-containers`, and inside the pod:

```
$ kubectl exec payments/payment-processor -- uname -r
5.15.63-96
$ kubectl exec payments/payment-processor -- cat /proc/cpuinfo | grep -c processor
1
```

The guest kernel version differs from the host kernel version. The processor count reflects the vCPU count configured in the Kata VMM config, not the host's physical CPU count — another reliable indicator of VM isolation.

## Trade-offs

**gVisor compatibility.** gVisor does not implement every Linux syscall. As of 2026, approximately 380 of the ~400 x86-64 syscalls are implemented, but coverage is not uniform — newer syscalls added in recent kernel versions may be absent, and `io_uring` support is partial. Applications that rely on direct device access, unusual ptrace behaviour (debuggers, profilers), or specific network socket options may fail or behave incorrectly under gVisor. Check the [gVisor compatibility guide](https://gvisor.dev/docs/user_guide/compatibility/) before deploying any workload. Databases that rely on high-throughput I/O (PostgreSQL with many concurrent connections, Redis with pipeline-heavy workloads) experience significant overhead from the Sentry's syscall interposition. GPU workloads are not supported in standard gVisor — the Sentry does not implement GPU driver interfaces.

**gVisor networking.** The Sentry includes Netstack, a complete userspace TCP/IP implementation written in Go. Netstack is correct and well-tested, but imposes overhead compared to the host kernel's network stack. For workloads where network throughput is the bottleneck, measure this explicitly. gVisor can be configured to use a passthrough network mode (`hostnet`) that bypasses Netstack for external traffic at the cost of reduced isolation — a deliberate trade-off that removes part of gVisor's network stack isolation.

**Kata hardware requirements.** Kata requires hardware virtualisation. On bare metal nodes this is universally available. On cloud VMs, nested virtualisation must be enabled: AWS supports this on Nitro-based instances but requires bare-metal instance types for full KVM performance; GCP supports nested KVM on N1/C2 instances with explicit enablement; Azure supports it on Dv3/Ev3 and later series. Not all managed Kubernetes offerings expose nested virtualisation to node VMs — EKS on standard instances, GKE Standard, and AKS with non-nested VMs cannot run Kata without bare-metal nodes. This is a significant operational constraint: Kata is not a drop-in change on a standard cloud-managed cluster.

**Kata resource overhead.** Each Kata pod carries the overhead of a running VM: guest kernel memory, kata-agent process, and VMM process on the host. For Firecracker, this baseline is approximately 128–256 MB of memory per pod. A cluster running 500 pods with Kata carries 64–128 GB of overhead memory that would not exist with runc. Plan node pool sizing accordingly.

**Debugging under secure runtimes.** `strace` inside a gVisor pod does not produce standard ptrace output — the Sentry intercepts ptrace. `perf` inside a Kata pod profiles the guest kernel, not the host kernel. Some APM tools inject LD_PRELOAD hooks that interact strangely with gVisor's loader implementation. Verify that your observability stack works correctly in each runtime before relying on it for production debugging.

## Failure Modes

**Not enforcing RuntimeClass via admission control.** A RuntimeClass in the cluster and a deployment guide telling developers to use it is not enforcement. A developer who omits `runtimeClassName` from their pod spec gets runc — silently, without any warning. Every pod in your regulated namespaces that reaches production without a RuntimeClass field is running on the shared kernel. The Kyverno policy in section 3 above (or an equivalent OPA Gatekeeper constraint) is mandatory, not optional. Audit existing pods for compliance:

```bash
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.metadata.namespace | test("payments|secrets|regulated|pci-scope")) |
  select(.spec.runtimeClassName == null or .spec.runtimeClassName == "") |
  "\(.metadata.namespace)/\(.metadata.name): runtimeClassName not set (running runc)"'
```

**Assuming gVisor is invulnerable.** gVisor has its own CVEs. CVE-2020-10890 was a sandbox escape via a socket handling bug in the Sentry. CVE-2021-22555's netfilter variant affected gVisor's netfilter implementation. Treat gVisor like any other security-critical component: subscribe to gVisor's security advisories, patch on a defined SLA, and do not treat "running gVisor" as a substitute for patching the host kernel. The host kernel still runs; host processes still use it; a host kernel exploit that doesn't go through container syscalls is unaffected by gVisor entirely.

**Not testing workload compatibility before enforcement.** Enforcing a secure RuntimeClass via admission control without first testing workloads against gVisor or Kata will result in production outages. Applications that use syscalls not yet implemented in gVisor will fail at startup with `ENOSYS`. Applications that rely on `/dev/` devices not present in the Kata guest will fail. Run a compatibility test in a lower environment before enforcing: deploy the workload with the target RuntimeClass, exercise all code paths, check for `ENOSYS` errors or unexpected crashes. Build this into your deployment pipeline as a gate.

**Using QEMU-based Kata on cloud VMs without nested virtualisation.** QEMU requires hardware virtualisation to create VMs. On a cloud VM that does not support nested virtualisation (most standard instance types), QEMU falls back to TCG software emulation. TCG Kata is not a security isolation mechanism — it is a software emulation with no VM boundary enforcement. The fallback is silent: the pod starts, looks correct, and provides no isolation. Always verify that KVM is available on Kata nodes:

```bash
# On each candidate Kata node, confirm KVM module is loaded and accessible
kubectl debug node/kata-node-1 -it --image=alpine -- sh -c 'ls /dev/kvm && echo KVM available'
# If this returns "No such file or directory", Kata on this node provides no VM isolation.
```

**Skipping the guest kernel patch cycle.** Kata does not eliminate the need to patch kernels — it means you now maintain two kernels per node type: the host kernel and the Kata guest kernel bundled in the Kata container images. Guest kernel updates ship as new Kata container image releases. Pin Kata to a specific version, yes, but also establish a cadence for updating to new Kata releases that include guest kernel patches. A Kata cluster running a 2022 guest kernel against 2026 CVEs provides VM isolation but not guest kernel safety.

## Related Articles

- [Dirty Pipe (CVE-2022-0847): Writing to Read-Only Files Inside Containers](/articles/linux/dirty-pipe-container-escape/)
- [runc CVE-2019-5736: Overwriting the Container Runtime from Inside a Container](/articles/kubernetes/runc-container-escape-cve-2019-5736/)
- [Netfilter Container Escape CVE-2022-1015](/articles/network/netfilter-container-escape-cve-2022-1015/)
- [Firecracker VMM Attack Surface](/articles/cross-cutting/firecracker-vmm-attack-surface/)
- [Complete Kubernetes Hardening](/articles/cross-cutting/complete-kubernetes-hardening/)
