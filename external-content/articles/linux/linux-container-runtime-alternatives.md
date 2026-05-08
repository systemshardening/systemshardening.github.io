---
title: "Container Runtime Security: gVisor, Kata Containers, and crun Beyond runc"
description: "runc's seccomp filters help, but a single unfiltered syscall can still hand an attacker the host kernel. This article explains when and how to deploy gVisor, Kata Containers, and crun to enforce stronger isolation boundaries for high-risk workloads."
slug: linux-container-runtime-alternatives
date: 2026-05-07
lastmod: 2026-05-07
category: linux
tags:
  - container-runtime
  - gvisor
  - kata-containers
  - sandboxing
  - isolation
personas:
  - security-engineer
  - platform-engineer
article_number: 482
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/linux/linux-container-runtime-alternatives/
---

# Container Runtime Security: gVisor, Kata Containers, and crun Beyond runc

## The Problem

Every container running under the default runc runtime shares the host kernel. The namespace and cgroup layer hides resources from the container process, but the process communicates with the kernel directly via syscalls. Seccomp BPF filters reduce the attack surface by blocking syscalls the container does not need — a typical Docker default profile blocks around 44 of the ~350+ available syscalls. That still leaves more than 300 syscalls reachable, each of which is a potential exploitation path.

This matters concretely:

- `CVE-2022-0847` (Dirty Pipe) was exploited through the `splice` syscall, which is in the Docker default seccomp allowlist.
- `CVE-2019-5736` (runc overwrite) exploited the `/proc/self/exe` path — no syscall filter blocked it because the attacker operated within the process execution model.
- `CVE-2024-21626` (runc working directory) exploited a file descriptor leak during container startup, before any seccomp filter took effect.

The root cause is architectural: when the container process and the host share a kernel, a logic flaw in the kernel becomes a container escape. Syscall filtering does not prevent exploitation of the syscalls that remain in the allowlist. It is a reduction of attack surface, not elimination of the attack vector.

For most workloads — internal services, well-understood applications, trusted code — runc with a hardened seccomp profile, AppArmor/SELinux, and a non-root user is the right trade-off. Overhead is minimal and the security posture is acceptable.

For high-risk workloads — untrusted code execution, multi-tenant platforms, AI inference with user-supplied inputs, CI job runners, ingress processing of arbitrary network traffic — the shared-kernel model is not acceptable and an alternative runtime is warranted.

This article covers three alternatives and how to choose between them.

## runc's Security Model: What It Gives You and Where It Stops

runc is the OCI reference runtime. When containerd or Docker creates a container, it calls runc to fork the container process into a set of Linux namespaces (pid, net, mnt, uts, ipc, user) and place it under a cgroup. The container process then runs with:

- **Capabilities**: a reduced capability set (typically the Docker default drops `NET_ADMIN`, `SYS_PTRACE`, `SYS_MODULE`, and about 25 others)
- **Seccomp BPF**: a syscall allowlist enforced by the kernel
- **AppArmor or SELinux**: mandatory access control on file and network operations

The enforcement boundary is the kernel. Every syscall from the container process goes to the same kernel that serves the host. When you apply a seccomp filter, the kernel evaluates the BPF program on each syscall before dispatching it. If the filter allows the syscall, it runs at full privilege in the kernel. A kernel vulnerability in that handler is exploitable by the container process.

```bash
# Inspect the default Docker seccomp profile allowlist
docker run --rm -it ubuntu:24.04 bash -c "cat /proc/$$/status | grep Seccomp"
# Seccomp: 2  (2 = filter mode active)

# Count blocked syscalls in Docker's default profile
curl -s https://raw.githubusercontent.com/moby/moby/master/profiles/seccomp/default.json \
  | jq '[.syscalls[] | select(.action == "SCMP_ACT_ALLOW")] | length'
# ~340 allowed — the filter blocks ~44 syscalls

# View kernel attack surface from within a container
strace -c -f sleep 60 &
# Every unique syscall here is a potential kernel exploitation path
```

The practical implication: runc is excellent when you trust the code running inside the container. For untrusted code, you need a different isolation primitive.

## gVisor (runsc): A User-Space Kernel

[gVisor](https://gvisor.dev) intercepts syscalls from the container process before they reach the host kernel. The Sentry — gVisor's core component — is a user-space process that implements a substantial subset of the Linux kernel API. Container processes make syscalls; those syscalls are caught by gVisor and either handled entirely in user space or forwarded to the host kernel through a minimal, audited interface.

### Architecture: Sentry and Gofer

The Sentry handles most Linux syscalls (network, process management, signals, futexes) in Go code running as an unprivileged user-space process. File system operations go through the Gofer, a separate process that mediates all host filesystem access over a 9P protocol connection. The container process never touches the host filesystem directly.

```
Container Process
      |
      | syscall
      v
   [ Sentry - user-space Linux kernel implementation ]
      |              |
      | host FS ops  | select kernel syscalls (~100 total surface)
      v              v
   [ Gofer ]    [ Host Kernel ]
      |
      | 9P
      v
   [ Host Filesystem ]
```

The Sentry exposes roughly 240 syscalls to container processes. Of those, about 100 result in a call to the host kernel; the rest are handled entirely within the Sentry. The host kernel attack surface from a gVisor container is a small, audited interface — not the full syscall table.

### Platform: KVM vs ptrace

gVisor supports two execution platforms:

**ptrace platform**: Uses `ptrace` to intercept syscalls. Available on any Linux host without hardware virtualisation. Carries significant performance overhead — each syscall from the container involves a ptrace stop/resume cycle. Suitable for development environments or workloads where syscall frequency is low.

**KVM platform**: Runs the Sentry inside a VM using KVM hardware virtualisation. Much lower overhead than ptrace because syscall interception is handled by the hypervisor in hardware (VMEXIT). Requires KVM access on the host — works on bare metal and most cloud VM types (GCP n2, AWS metal instances, Azure DCsv3). This is the production deployment mode.

```bash
# Verify KVM availability for gVisor
ls -la /dev/kvm
# Must exist and be accessible to the containerd process

# Check CPU virtualisation extensions
grep -E 'vmx|svm' /proc/cpuinfo | head -1
# vmx = Intel VT-x, svm = AMD-V
```

### Configuring gVisor with containerd

Install the runsc binary and configure containerd to use it as a runtime handler:

```bash
# Install runsc (gVisor runtime binary)
RUNSC_VERSION="20240930.0"
curl -fsSL "https://storage.googleapis.com/gvisor/releases/release/${RUNSC_VERSION}/x86_64/runsc" \
  -o /usr/local/bin/runsc
curl -fsSL "https://storage.googleapis.com/gvisor/releases/release/${RUNSC_VERSION}/x86_64/runsc.sha512" \
  | sha512sum --check
chmod 755 /usr/local/bin/runsc

# Install the containerd shim
curl -fsSL "https://storage.googleapis.com/gvisor/releases/release/${RUNSC_VERSION}/x86_64/containerd-shim-runsc-v1" \
  -o /usr/local/bin/containerd-shim-runsc-v1
chmod 755 /usr/local/bin/containerd-shim-runsc-v1
```

Configure containerd to register the gVisor runtime handler:

```toml
# /etc/containerd/config.toml
version = 2

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc.options]
  TypeUrl = "io.containerd.runsc.v1.options"
  # Use KVM platform for production
  ConfigPath = "/etc/containerd/runsc.toml"
```

```toml
# /etc/containerd/runsc.toml
[runsc_config]
  platform = "kvm"
  network = "sandbox"
  debug-log = "/var/log/runsc/%ID%/"
```

```bash
systemctl restart containerd

# Test: run a container with gVisor
docker run --runtime=runsc --rm ubuntu:24.04 uname -r
# Returns gVisor's kernel version string, not the host kernel version
# e.g.: 4.4.0 #1 SMP Sun Jan 10 15:06:54 PST 2010 (gVisor fake version)
```

### Performance Characteristics

gVisor adds latency on syscall-heavy workloads. Benchmarks from the gVisor team and independent sources show:

| Workload type | runc overhead | gVisor (KVM) overhead | Notes |
|---|---|---|---|
| CPU-bound (no I/O) | baseline | +1-3% | Sentry handles few host syscalls |
| Network throughput (TCP bulk) | baseline | +10-20% | Network stack in user space |
| Syscall-heavy (forks, stats) | baseline | +2-5x | Each syscall has Sentry cost |
| File I/O (random small reads) | baseline | +2-10x | Gofer adds round-trip overhead |

For AI inference, REST API servers, or batch processing workloads, the overhead is acceptable. For database engines with high-frequency small I/O or applications that make thousands of syscalls per second, benchmark first.

## Kata Containers: VM-Isolated Containers

[Kata Containers](https://katacontainers.io) takes a different approach: instead of intercepting syscalls in user space, Kata wraps each container (or pod) in a lightweight virtual machine. The container process runs inside a VM with its own kernel. A kernel exploit inside the container only compromises the guest kernel — not the host.

### Architecture

```
Pod / Container Group
       |
  [ kata-agent ] (runs inside VM)
       |
  [ Guest Kernel ] (lightweight, hardened)
       |
  [ Hypervisor: QEMU / Cloud Hypervisor / Firecracker ]
       |
  [ Host Kernel ]
```

The `kata-agent` runs as PID 1 inside the guest VM, receives instructions from the Kata Containers runtime shim on the host over a vsock channel, and creates the container processes inside the VM using runc or crun. The container appears normal from the application's perspective — its filesystem is mounted via virtio-fs or device pass-through, its network is presented via a veth pair bridged through virtio-net.

### Hypervisor Backends

Kata supports three hypervisor backends, each with different trade-offs:

**QEMU (default)**: Full-featured, best compatibility, highest overhead. Boot time ~300-500ms, memory footprint ~200MB per pod overhead. Suitable when compatibility and feature completeness are the priority.

**Cloud Hypervisor (ch)**: Purpose-built for cloud workloads. Written in Rust. Faster boot (~150ms), lower overhead (~130MB). Good balance of security and performance for production deployments.

**Firecracker**: AWS's VMM, designed for serverless workloads. Fastest boot (<125ms in ideal conditions), smallest memory footprint (~50MB overhead), but limited device support (no PCI, no USB). Best for function-as-a-service or CI environments with many short-lived containers.

### Configuring Kata with containerd

```bash
# Install Kata Containers from official release
KATA_VERSION="3.6.0"
curl -fsSL "https://github.com/kata-containers/kata-containers/releases/download/${KATA_VERSION}/kata-static-${KATA_VERSION}-amd64.tar.xz" \
  -o kata-static.tar.xz
tar -xf kata-static.tar.xz -C /opt
# Binaries land in /opt/kata/bin/

# Add kata symlinks to PATH
ln -sf /opt/kata/bin/containerd-shim-kata-v2 /usr/local/bin/containerd-shim-kata-v2
ln -sf /opt/kata/bin/kata-runtime /usr/local/bin/kata-runtime

# Verify hardware virtualisation
kata-runtime check
# Must report: System is capable of running Kata Containers
```

```toml
# /etc/containerd/config.toml — add Kata runtime handlers
version = 2

# Kata with QEMU
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata-qemu]
  runtime_type = "io.containerd.kata.v2"
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata-qemu.options]
    ConfigPath = "/opt/kata/share/defaults/kata-containers/configuration-qemu.toml"

# Kata with Cloud Hypervisor (preferred for production)
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata-clh]
  runtime_type = "io.containerd.kata.v2"
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata-clh.options]
    ConfigPath = "/opt/kata/share/defaults/kata-containers/configuration-clh.toml"

# Kata with Firecracker
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata-fc]
  runtime_type = "io.containerd.kata.v2"
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata-fc.options]
    ConfigPath = "/opt/kata/share/defaults/kata-containers/configuration-fc.toml"
```

```toml
# /opt/kata/share/defaults/kata-containers/configuration-clh.toml (key excerpt)
[hypervisor.clh]
  path = "/opt/kata/bin/cloud-hypervisor"
  kernel = "/opt/kata/share/kata-containers/vmlinux-confidential.container"
  image = "/opt/kata/share/kata-containers/kata-containers.img"
  # Disable unnecessary devices
  disable_vhost_net = false
  virtio_fs_daemon = "/opt/kata/libexec/virtiofsd"
  # Memory for the VM (add to your container memory request)
  default_memory = 2048
  # Enable confidential computing if hardware supports it
  confidential_guest = false
```

```bash
systemctl restart containerd

# Test Kata isolation — guest kernel differs from host
docker run --runtime=kata-clh --rm ubuntu:24.04 uname -r
# Returns the Kata guest kernel version: e.g., 6.1.62-container
# Different from host kernel
```

## crun: A Leaner OCI Runtime

[crun](https://github.com/containers/crun) is a C implementation of the OCI container runtime spec, developed by Red Hat as an alternative to runc (written in Go). It is not a sandbox or a VM-based runtime — its security posture is comparable to runc. The value proposition is different: lower overhead, smaller codebase, and native cgroup v2 support.

### Why crun Matters for Security

A smaller codebase means a smaller attack surface in the runtime itself. runc is approximately 70,000 lines of Go across its dependencies; crun's core is approximately 7,000 lines of C. Fewer lines mean fewer places for bugs. The runtime executes as a privileged process during container setup, so vulnerabilities in the runtime binary itself (like CVE-2019-5736) are serious — crun's reduced size is a genuine security benefit.

crun added cgroup v2 support before runc and handles the unified hierarchy more cleanly. On systems using cgroup v2 exclusively (Ubuntu 22.04+, RHEL 9, Fedora 31+), crun is the better choice at the runtime level.

```bash
# Install crun
apt-get install -y crun       # Ubuntu 22.04+
dnf install -y crun           # RHEL 9 / Fedora

# Or build from source for the latest version
git clone https://github.com/containers/crun
cd crun && ./autogen.sh && ./configure && make -j$(nproc)
cp crun /usr/local/bin/crun

# Verify crun capabilities
crun --version
# crun version 1.15
# commit: ...
# spec: 1.0.0
# +SYSTEMD +SELINUX +APPARMOR +CAP +SECCOMP +EBPF +CRIU +YAJL
```

```toml
# /etc/containerd/config.toml — replace runc with crun
version = 2

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
    BinaryName = "/usr/local/bin/crun"
    # crun is a drop-in replacement; all runc options apply
    SystemdCgroup = true
```

Podman uses crun as its default runtime on RHEL/Fedora. The switch from runc to crun is transparent to the container workload.

## Kubernetes RuntimeClass: Mixing Runtimes in a Cluster

Kubernetes RuntimeClass lets you assign different OCI runtimes to different pods. Sensitive pods get gVisor or Kata; trusted workloads stay on runc or crun. The selection is made at the pod level in the pod spec.

### RuntimeClass Configuration

First, ensure the node's containerd config registers all handlers (as shown above). Then create RuntimeClass objects in Kubernetes:

```yaml
# runtimeclasses.yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
scheduling:
  nodeSelector:
    runtime.kubernetes.io/gvisor: "true"
---
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: kata-clh
handler: kata-clh
scheduling:
  nodeSelector:
    runtime.kubernetes.io/kata: "true"
  tolerations:
    - key: kata
      operator: Exists
      effect: NoSchedule
overhead:
  podFixed:
    memory: "130Mi"   # Kata VM overhead — factored into scheduling
    cpu: "250m"
---
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: crun
handler: crun
```

```bash
kubectl apply -f runtimeclasses.yaml

# Label nodes that have gVisor installed
kubectl label node worker-01 runtime.kubernetes.io/gvisor=true

# Label nodes that have Kata + KVM
kubectl label node worker-02 runtime.kubernetes.io/kata=true
```

### Selecting a RuntimeClass in a Pod

```yaml
# untrusted-workload.yaml
apiVersion: v1
kind: Pod
metadata:
  name: user-code-runner
  namespace: tenant-sandbox
spec:
  runtimeClassName: gvisor       # All containers in this pod use gVisor
  containers:
    - name: runner
      image: python:3.12-slim
      command: ["python", "-c", "import sys; exec(sys.stdin.read())"]
      resources:
        limits:
          memory: "512Mi"
          cpu: "500m"
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
```

```yaml
# ci-job.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: build-job
spec:
  template:
    spec:
      runtimeClassName: kata-clh   # Build jobs get VM isolation
      containers:
        - name: builder
          image: ubuntu:24.04
          command: ["/bin/bash", "-c", "make all"]
          securityContext:
            runAsNonRoot: false    # Build often needs root — VM provides isolation
```

### Enforcing RuntimeClass with OPA / Kyverno

Allow-listing is not enough — you need to prevent workloads from omitting `runtimeClassName` in sensitive namespaces:

```yaml
# kyverno-policy-require-runtime.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-sandbox-runtime
spec:
  validationFailureAction: Enforce
  rules:
    - name: check-runtimeclass
      match:
        resources:
          kinds: [Pod]
          namespaces:
            - tenant-*
            - ci-*
      validate:
        message: "Pods in tenant and CI namespaces must specify runtimeClassName: gvisor or kata-clh"
        pattern:
          spec:
            runtimeClassName: "gvisor | kata-clh"
```

## Workload Assignment: Which Runtime for Which Pod

Not all workloads justify the overhead of gVisor or Kata. Use this decision matrix:

| Workload | Trust Level | Recommended Runtime | Rationale |
|---|---|---|---|
| Internal microservice | High | runc / crun | Trusted code, low risk, performance matters |
| Third-party container from external registry | Medium | gVisor | Reduced supply-chain risk |
| AI inference with user-supplied inputs | Low | gVisor | Prompt injection → code execution path |
| CI job runner (user-submitted build jobs) | Untrusted | Kata Containers | Build jobs need root; VM isolates the host |
| Ingress/proxy container | Medium-High | gVisor | Directly processes attacker-controlled network data |
| Multi-tenant function execution | Untrusted | gVisor or Kata | Each tenant's code is untrusted |
| Database (PostgreSQL, MySQL) | High | crun | Trusted, syscall-heavy — crun gives marginal improvement |
| Kubernetes system pods (coredns, kube-proxy) | High | runc / crun | Trusted, perf-sensitive |

### AI/ML Workload Consideration

LLM serving endpoints process user-supplied prompts. A successful prompt injection that leads to arbitrary code execution hits the container boundary. For public-facing inference endpoints, gVisor's user-space kernel means that a container escape attempt via a kernel CVE fails — the guest kernel is gVisor's Sentry, not the host kernel. Deploy inference containers with `runtimeClassName: gvisor` and KVM platform.

## Security Testing: Isolating the Difference

The following test demonstrates the isolation boundary concretely. It uses a known container information disclosure technique — reading the host's `/proc` filesystem — not an active exploit, to avoid legal issues with reproduction.

```bash
# Test 1: runc — host kernel visible from container
docker run --rm ubuntu:24.04 cat /proc/version
# Linux version 6.8.0-41-generic (buildd@...) (gcc version 13.2.0...) #41-Ubuntu...
# MATCHES host kernel exactly

# Test 2: gVisor — Sentry kernel visible, not host
docker run --runtime=runsc --rm ubuntu:24.04 cat /proc/version
# Linux version 4.4.0 #1 SMP Sun Jan 10 15:06:54 PST 2010
# gVisor's fake kernel version — host kernel is not visible

# Test 3: Kata — guest kernel visible
docker run --runtime=kata-clh --rm ubuntu:24.04 cat /proc/version
# Linux version 6.1.62-container (kata@...) ...
# Guest kernel version — different from host

# Test the syscall surface
# runc: all host syscalls available
docker run --rm ubuntu:24.04 strace -c ls / 2>&1 | tail -5

# gVisor: Sentry intercepts; host syscall count is tiny
docker run --runtime=runsc --rm ubuntu:24.04 strace -c ls / 2>&1 | tail -5
# Note: strace may not work inside gVisor — it relies on ptrace which gVisor restricts
# This is itself a security feature

# Escape attempt: exploit /proc/sysrq-trigger (requires SYS_ADMIN but demonstrates boundary)
docker run --rm --privileged ubuntu:24.04 sh -c "echo h > /proc/sysrq-trigger" 2>&1
# Under runc --privileged: succeeds, affects host kernel
# Under gVisor: fails — Sentry's /proc is virtual, not host's /proc
docker run --runtime=runsc --privileged ubuntu:24.04 sh -c "echo h > /proc/sysrq-trigger" 2>&1
# write /proc/sysrq-trigger: operation not permitted (gVisor blocks this)
```

The `--privileged` flag behaves differently across runtimes. Under runc, `--privileged` gives the container nearly full host kernel access. Under gVisor, `--privileged` grants more capabilities within gVisor's user-space kernel but cannot reach the real host kernel. This is the isolation guarantee.

## 2025-2026 Developments

### gVisor: Improved Network Stack and Systrap Platform

The gVisor team shipped a new **Systrap** platform in 2024-2025 as an alternative to ptrace. Systrap uses seccomp to trap syscalls into the Sentry without requiring ptrace, reducing context-switch overhead by 30-40% on syscall-heavy workloads. On hosts without KVM, Systrap is now recommended over ptrace.

gVisor's network stack (`netstack`) gained significant improvements in 2024-2025:
- RACK-TLP (Recent ACKnowledgement - Tail Loss Probe) for better TCP loss recovery
- UDP-GRO (Generic Receive Offload) reducing CPU overhead for high-throughput UDP
- IPv6 extension header support

Enable Systrap in the gVisor config:

```toml
# /etc/containerd/runsc.toml
[runsc_config]
  platform = "systrap"    # New: systrap instead of ptrace for non-KVM hosts
  network = "sandbox"
```

### Kata 3.x: Dragonball VMM and Confidential Containers

Kata Containers 3.x introduced **Dragonball**, a Rust-based VMM developed by Alibaba Cloud. It provides:
- Sub-100ms VM boot times
- Purpose-built for container workloads (no legacy device emulation)
- ~40MB memory overhead per pod (vs ~200MB for QEMU)
- Full integration with Kata's virtio-fs for shared filesystem access

```toml
# configuration-dragonball.toml (Kata 3.x)
[hypervisor.dragonball]
  path = "/opt/kata/bin/dragonball"
  kernel = "/opt/kata/share/kata-containers/vmlinux.container"
  default_memory = 512
  enable_iothreads = true
```

Kata 3.x also deepened **Confidential Containers** support (CoCo), running the guest VM inside a hardware Trusted Execution Environment using AMD SEV-SNP or Intel TDX. This protects container memory from the hypervisor and host OS — relevant for regulated data processing where even the platform operator should not read workload memory.

```bash
# Check for SEV-SNP support (AMD)
dmesg | grep -i sev
# [    0.000000] SEV-SNP: initialized

# Check for TDX support (Intel)
dmesg | grep -i tdx
# [    0.000000] tdx: TDX module: attributes 0x0, vendor_id 0x8086
```

## Choosing the Right Runtime

The decision is not binary between runc and an alternative — it is a tiered model:

1. **Default runtime**: crun on cgroup v2 hosts, runc elsewhere. Smallest runtime codebase, full OCI compatibility, no overhead.

2. **Reduced kernel attack surface**: gVisor (KVM or Systrap platform) for workloads that process untrusted input or run untrusted code but are not expected to need root access or unusual kernel features. Expected overhead 5-20% depending on syscall frequency.

3. **Full VM isolation**: Kata Containers for workloads that legitimately need elevated privileges (build systems, legacy applications requiring root, workloads with unknown syscall profiles), multi-tenant environments, or regulated workloads requiring TEE support. Expected overhead 130-200MB per pod + 100-300ms startup latency.

4. **Layer them**: RuntimeClass lets you apply different runtimes per namespace or per workload type in the same cluster. There is no requirement to choose one runtime for all workloads.

The combination of gVisor for untrusted-input processing and Kata for privileged or CI workloads, alongside runc/crun for trusted services, provides defence-in-depth at the runtime layer without requiring architectural changes to applications.

## References

- [gVisor documentation: Platforms](https://gvisor.dev/docs/architecture_guide/platforms/)
- [Kata Containers architecture overview](https://katacontainers.io/learn/)
- [OCI Runtime Specification](https://github.com/opencontainers/runtime-spec)
- [Kubernetes RuntimeClass documentation](https://kubernetes.io/docs/concepts/containers/runtime-class/)
- [crun GitHub repository](https://github.com/containers/crun)
- [CVE-2024-21626: runc working directory escape](https://nvd.nist.gov/vuln/detail/CVE-2024-21626)
- [Kata Containers 3.x Dragonball VMM](https://github.com/kata-containers/kata-containers/blob/main/docs/hypervisors.md)
- [gVisor Systrap platform](https://gvisor.dev/blog/2023/04/28/systrap-release/)
