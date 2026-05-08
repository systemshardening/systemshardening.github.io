---
title: "AI Red Teams and Container Security: What the Benchmarks Mean for Architecture"
description: "The UK AISI SandboxEscapeBench and Anthropic Red Team's 500+ findings invalidate 'minimal containers are secure.' AI scales vulnerability discovery beyond what hardening can keep pace with. Understand what the benchmarks measured and which architectural responses genuinely reduce AI-automated escape probability."
slug: ai-red-team-container-security
date: 2026-05-07
lastmod: 2026-05-07
category: ai-landscape
tags:
  - ai-red-team
  - container-security
  - vulnerability-discovery
  - gvisor
  - threat-model
personas:
  - security-engineer
  - platform-engineer
article_number: 460
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/ai-landscape/ai-red-team-container-security/
---

# AI Red Teams and Container Security: What the Benchmarks Mean for Architecture

## The Problem

Two independent research programmes produced findings in 2025–2026 that expose a structural flaw in how container security has been justified. The flaw is not in any specific hardening step. It is in the foundational assumption that motivates most hardening: that reducing the attack surface to a minimal container meaningfully reduces the probability of exploitation.

The first programme: Anthropic's Red Team, using systematic AI-assisted code analysis, found over 500 validated high-severity vulnerabilities — including exploitable bugs in codebases that had passed years of human code review and standard SAST tooling. These were not trivially detectable issues. Many were logic flaws, implicit trust relationships, and subtle memory errors that evaded detection precisely because human reviewers were the primary filter. AI-assisted analysis applied at scale broke through that filter.

The second programme: the UK AI Security Institute's SandboxEscapeBench tested Claude Opus 4.5 and GPT-5 against a structured set of container escape scenarios. The headline result was approximately 50% success across all scenarios. But the more operationally significant result was the breakdown by configuration: 100% success against exposed Docker sockets (`/var/run/docker.sock` mounted into a container) and 100% success against privileged containers (`securityContext.privileged: true`). These are configurations that security teams have documented as dangerous for years. What changed is not the knowledge — it is the attacker.

The standard argument for minimal containers is that reducing the number of binaries, libraries, and services in a container reduces the total number of exploitable vulnerabilities. A container running a single Go binary on a distroless base has fewer CVEs than a container running a full Ubuntu stack with Python, curl, and a package manager. That argument is correct as far as it goes. The problem is what it ignores: the shared kernel.

A minimal container running on a standard Linux kernel still shares that kernel with every other container on the node. The Linux kernel visible from within a container — even a well-hardened container — exposes hundreds of syscalls backed by millions of lines of code with a documented history of high-severity CVEs. If an attacker using AI-assisted tooling can discover new vulnerabilities in existing kernel subsystems at the rate Anthropic's Red Team found them in application code, then the gap between a "minimal" container and an "insecure" container as measured against kernel attack surface is near-zero. Both containers sit above the same target.

The implication is architectural. Security that focuses on what runs inside a container addresses a narrowing portion of the actual risk. The remaining and growing portion is the kernel and runtime layer underneath — and that portion is not addressable by optimising Dockerfiles.

## Threat Model

Framing AI offensive capability as a binary — "AI can escape containers" or "AI cannot" — produces the wrong response. The capability is better understood as three progressive levels, each requiring a different class of architectural response.

**Level 1 — Commodity AI:** An attacker with access to publicly available LLM APIs uses security-focused prompts to enumerate container escape vectors and attempt known CVE exploits. This maps to what SandboxEscapeBench actually measured. At this level, the AI does not discover new vulnerabilities. It applies known techniques, chains known exploits, and does so with the systematic thoroughness and speed that distinguishes it from human attackers. Success rate against misconfigured containers: approximately 50% overall, 100% against exposed Docker sockets and privileged containers, near-zero against well-hardened containers with no excess capabilities and a restrictive seccomp profile.

**Level 2 — Capable AI red team:** An attacker uses systematic AI-assisted code analysis to discover previously undisclosed vulnerabilities in container runtime or kernel code. This maps to what Anthropic's Red Team demonstrated is possible when AI is applied to source code at scale. At this level, success against hardened containers becomes possible — not because the hardening was done incorrectly, but because the AI found a vulnerability in code that the hardening never reached. A container with no excess capabilities, a locked-down seccomp profile, and a restricted Pod Security Standard is still running on a kernel with subsystems reachable from that container. A 0-day in one of those subsystems — discovered by AI in hours rather than human researchers in months — produces an exploit path through an otherwise well-hardened surface.

**Level 3 — State-level AI capability:** AI-assisted offensive research applied at the scale of a well-resourced programme, discovering dozens of previously unknown vulnerabilities per target codebase. At this level, software-only container isolation is insufficient. The kernel, the container runtime, and the VM boundary all contain code. Given enough AI-assisted analysis, vulnerabilities are found. The only architectural response that remains structurally sound at this level eliminates the shared code boundary entirely — hardware-level isolation that removes the shared kernel from the threat model rather than hardening it.

The practical question for most organisations is not "which level is real?" All three are. The question is which level represents the threat to a given workload, and therefore which class of architectural response is warranted.

## Hardening Configuration

### Eliminating Level 1 Success: Close the 100% Escape Vectors

SandboxEscapeBench's 100% escape results are not edge cases that can be tolerated. They represent configurations where any Level 1 attacker achieves full host compromise with certainty. These must be removed before any other hardening step is meaningful.

Audit for exposed Docker sockets and privileged containers:

```bash
kubectl get pods -A -o json | jq '
  .items[] |
  select(.spec.volumes[]?.hostPath.path == "/var/run/docker.sock") |
  {namespace: .metadata.namespace, name: .metadata.name, pod: .metadata.name}
'
```

```bash
kubectl get pods -A -o json | jq '
  .items[] |
  select(.spec.containers[].securityContext.privileged == true) |
  {namespace: .metadata.namespace, name: .metadata.name}
'
```

Block both permanently via Kyverno:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: block-level1-escape-vectors
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: block-privileged-containers
      match:
        any:
          - resources:
              kinds: [Pod]
      validate:
        message: "Privileged containers are not permitted."
        pattern:
          spec:
            containers:
              - securityContext:
                  privileged: "false | nil"
    - name: block-docker-socket-mount
      match:
        any:
          - resources:
              kinds: [Pod]
      validate:
        message: "Mounting the Docker socket is not permitted."
        deny:
          conditions:
            any:
              - key: "{{ request.object.spec.volumes[].hostPath.path | contains(@, '/var/run/docker.sock') }}"
                operator: Equals
                value: true
    - name: block-host-pid-namespace
      match:
        any:
          - resources:
              kinds: [Pod]
      validate:
        message: "hostPID is not permitted."
        pattern:
          spec:
            hostPID: "false | nil"
    - name: block-host-network-namespace
      match:
        any:
          - resources:
              kinds: [Pod]
      validate:
        message: "hostNetwork is not permitted outside system namespaces."
        pattern:
          spec:
            hostNetwork: "false | nil"
```

Apply Pod Security Standards at `restricted` to every application namespace:

```bash
kubectl label namespace production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/enforce-version=latest
```

Strip capabilities to empty and require `allowPrivilegeEscalation: false` on every container:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: hardened-workload
spec:
  containers:
    - name: app
      image: registry.example.com/app:v1.0.0
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        runAsUser: 1000
        capabilities:
          drop:
            - ALL
        seccompProfile:
          type: RuntimeDefault
```

After these controls, SandboxEscapeBench's Level 1 AI finds no 100% escape vector and succeeds at the baseline ~50% rate only against residual misconfigurations. When those are removed, success rate at Level 1 drops to near-zero.

### Reducing Level 1 Success Further: Hardware Sandboxing

The residual ~50% escape rate in SandboxEscapeBench came from known Linux kernel CVEs exploitable within a container. gVisor and Kata Containers change what "the kernel" means from the container's perspective.

gVisor interposes a user-space kernel (Sentry, written in Go) between the container and the host kernel. Container syscalls reach gVisor's Sentry, not the host kernel. A Level 1 AI attempting known kernel CVEs discovers that the expected syscall paths either do not exist in gVisor's implementation or behave differently. CVEs specific to `nf_tables`, `overlayfs`, `FUSE`, or complex netlink socket handling produce ENOSYS or safe-rejection responses from gVisor rather than exploitable kernel code paths.

Kata Containers takes a different approach: each pod runs inside a lightweight VM with its own guest kernel. The host kernel is behind a hypervisor boundary. A Level 1 AI enumerating kernel CVEs against the guest kernel finds a much smaller, purpose-built kernel (rather than a full Linux distribution kernel) and cannot reach the host kernel without first defeating the hypervisor — a significantly higher bar than a container escape.

Install gVisor on nodes and configure containerd:

```bash
curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /usr/share/keyrings/gvisor.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor.gpg] \
  https://storage.googleapis.com/gvisor/releases release main" \
  | tee /etc/apt/sources.list.d/gvisor.list
apt update && apt install -y runsc
```

```bash
cat >> /etc/containerd/config.toml << 'EOF'
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc.options]
  TypeUrl = "io.containerd.runsc.v1.options"
  ConfigPath = "/etc/containerd/runsc.toml"
EOF
systemctl restart containerd
```

Create RuntimeClass resources for both runtimes:

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
overhead:
  podFixed:
    memory: "100Mi"
    cpu: "50m"
scheduling:
  nodeSelector:
    sandbox.io/runtime: gvisor
---
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: kata-qemu
handler: kata-qemu
overhead:
  podFixed:
    memory: "512Mi"
    cpu: "250m"
scheduling:
  nodeSelector:
    sandbox.io/runtime: kata
```

Apply gVisor to untrusted workloads:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: untrusted-inference
  namespace: ml-untrusted
spec:
  runtimeClassName: gvisor
  containers:
    - name: inference
      image: registry.example.com/inference:v2.1.0
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop:
            - ALL
```

Enforce `runtimeClassName` on sensitive namespaces via Kyverno so that workloads cannot silently fall back to the unprotected default runtime:

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
              namespaces: [ml-untrusted, functions, third-party]
      validate:
        message: "Pods in this namespace must use a sandboxed RuntimeClass."
        pattern:
          spec:
            runtimeClassName: "gvisor | kata-qemu | kata-clh | kata-fc"
```

### Addressing Level 2: Architectural CVE Class Elimination

Level 2 capability — AI-assisted 0-day discovery — cannot be addressed by applying known CVE mitigations faster. By definition, 0-days are not in CVE databases. Incremental hardening of existing code cannot keep pace with AI that finds new vulnerabilities in that code faster than patches ship.

The architectural response is different: eliminate the code that would be exploited, not harden it. This is the core insight in the Edera/Xen model of hypervisor security and in the broader argument for structured capability reduction.

Specific kernel subsystems that have produced high-severity container escape CVEs and that can be removed from the container-accessible surface:

- `nf_tables`: netfilter's nftables subsystem. CVE-2023-32233, CVE-2024-1086, and multiple others enabled privilege escalation from within containers. Most containerised applications do not need direct `nf_tables` access. Network policies at the cluster level (Cilium, Calico) operate at a different layer and do not require `nf_tables` to be accessible from workload namespaces.
- `overlayfs` with user namespaces: the `OverlayFS` filesystem in user namespace context has produced repeated escape paths. Restricting `clone(CLONE_NEWUSER)` in combination with a tight seccomp profile that denies `mount` eliminates this attack surface.
- Complex device emulation: MMIO emulation, virtio backends, and similar device emulation code in hypervisors has historically been a source of escapes (CVE-2026-5747-class). Message-passing architectures between VM guest and host eliminate device emulation code entirely.

Restrict `clone(CLONE_NEWUSER)` and `mount` via seccomp:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: restricted-seccomp-profile
  namespace: kube-system
data:
  profile.json: |
    {
      "defaultAction": "SCMP_ACT_ERRNO",
      "syscalls": [
        {
          "names": [
            "read", "write", "open", "close", "stat", "fstat", "lstat",
            "poll", "lseek", "mmap", "mprotect", "munmap", "brk",
            "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl",
            "pread64", "pwrite64", "readv", "writev", "access", "pipe",
            "select", "sched_yield", "mremap", "msync", "mincore", "madvise",
            "shmget", "shmat", "shmctl", "dup", "dup2", "pause", "nanosleep",
            "getitimer", "alarm", "setitimer", "getpid", "sendfile", "socket",
            "connect", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg",
            "shutdown", "bind", "listen", "getsockname", "getpeername",
            "socketpair", "setsockopt", "getsockopt", "clone", "fork", "vfork",
            "execve", "exit", "wait4", "kill", "uname", "fcntl", "flock",
            "fsync", "fdatasync", "truncate", "ftruncate", "getdents", "getcwd",
            "chdir", "rename", "mkdir", "rmdir", "creat", "link", "unlink",
            "symlink", "readlink", "chmod", "fchmod", "chown", "fchown",
            "lchown", "umask", "gettimeofday", "getrlimit", "getrusage",
            "sysinfo", "times", "getuid", "getgid", "setuid", "setgid",
            "geteuid", "getegid", "setpgid", "getppid", "getpgrp", "setsid",
            "setreuid", "setregid", "getgroups", "setgroups", "setresuid",
            "getresuid", "setresgid", "getresgid", "getpgid", "setfsuid",
            "setfsgid", "getsid", "capget", "capset", "rt_sigpending",
            "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend",
            "sigaltstack", "utime", "mknod", "statfs", "fstatfs", "prctl",
            "arch_prctl", "setrlimit", "sync", "gettid", "readahead", "futex",
            "sched_setaffinity", "sched_getaffinity", "set_thread_area",
            "get_thread_area", "exit_group", "set_tid_address", "openat",
            "mkdirat", "mknodat", "fchownat", "fstatat64", "unlinkat",
            "renameat", "linkat", "symlinkat", "readlinkat", "fchmodat",
            "faccessat", "pselect6", "ppoll", "set_robust_list",
            "get_robust_list", "splice", "tee", "sync_file_range", "vmsplice",
            "fallocate", "eventfd2", "epoll_create1", "dup3", "pipe2",
            "inotify_init1", "accept4", "signalfd4", "timerfd_create",
            "timerfd_settime", "timerfd_gettime", "epoll_wait", "epoll_ctl",
            "epoll_pwait", "recvmmsg", "sendmmsg", "getcpu", "clock_gettime",
            "clock_getres", "clock_nanosleep", "getrandom"
          ],
          "action": "SCMP_ACT_ALLOW"
        },
        {
          "names": ["clone"],
          "action": "SCMP_ACT_ALLOW",
          "args": [
            {
              "index": 0,
              "value": 2114060288,
              "valueTwo": 2114060288,
              "op": "SCMP_CMP_MASKED_EQ"
            }
          ]
        }
      ]
    }
```

The `clone` entry permits thread creation (`CLONE_THREAD`, `CLONE_VM`, `CLONE_SIGHAND`) while blocking `CLONE_NEWUSER` (0x10000000). Without user namespace creation, the overlayfs + user namespace escape chain has no entry point.

Apply this profile to workloads:

```yaml
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: restricted-seccomp-profile/profile.json
```

For the device emulation class specifically: if your architecture uses Kata Containers with QEMU, consider migrating to Cloud Hypervisor or Firecracker as the VMM backend. Both have significantly smaller device emulation codebases than QEMU. Firecracker has no device emulation at all for device types outside its intentionally minimal model. CVE-2026-5747-class vulnerabilities in MMIO emulation code have zero attack surface in Firecracker because that code does not exist.

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: kata-firecracker
handler: kata-fc
overhead:
  podFixed:
    memory: "256Mi"
    cpu: "100m"
scheduling:
  nodeSelector:
    sandbox.io/runtime: kata-fc
```

### Threat Modelling for Level 3

Level 3 — AI-assisted offensive research applied at state-level scale, discovering dozens of 0-days per target — is a realistic threat for a narrow set of organisations: critical national infrastructure, high-value financial systems, and organisations that are plausible targets for nation-state offensive programmes.

For this level, honest assessment: software-only isolation is not a sufficient architectural response. Every container runtime, every hypervisor, and every kernel contains code. At sufficient scale of AI-assisted analysis, vulnerabilities are found. The only architectural model that remains structurally sound is one that eliminates the shared software boundary from the threat model.

Two approaches that do this:

**Type-1 hypervisor without VMM:** A Type-1 hypervisor (bare-metal, no host operating system) with no virtual machine manager running on the host eliminates the VMM as an attack surface. Xen with a minimal control domain, or a custom microhypervisor, presents significantly less code to AI-assisted analysis than a QEMU-based Kata stack on a general-purpose Linux host. The attack surface is the hypervisor itself — which, at ~100,000 lines of code in minimal configurations, is three orders of magnitude smaller than the Linux kernel.

**Confidential computing / TEE:** AMD SEV-SNP, Intel TDX, and ARM CCA provide hardware-enforced memory encryption and attestation. A workload running in a TEE cannot have its memory read or modified by the host — including by a compromised hypervisor. This addresses a different threat model (host compromise rather than container escape) but for Level 3 threats they are complementary: the TEE prevents an attacker who has achieved host-level code execution from reading the confidential workload's memory.

The operational threshold for Level 3 infrastructure investment is high. Before investing in Type-1 hypervisor infrastructure, establish that:

1. Your threat model includes nation-state actors or equivalently resourced adversaries.
2. The data processed by the workloads justifies the operational complexity.
3. Level 1 and Level 2 architectural responses are already implemented and verified.

For most organisations, Level 2 architectural responses — hardware sandboxing plus kernel subsystem elimination — represent the appropriate ceiling of investment.

### Continuous AI-Assisted Red Teaming as a Defence

The same capability that makes AI dangerous as an offensive tool makes it useful for defensive validation. An AI escape agent run against your own container configurations in a controlled lab environment produces signal that traditional penetration testing does not: the same systematic, tireless enumeration that a real attacker would apply.

A container escape testing stage in CI provides ongoing verification that hardening controls are in place and effective:

```yaml
name: Container Escape Red Team
on:
  schedule:
    - cron: '0 2 * * 1'
  workflow_dispatch:

jobs:
  escape-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Provision test cluster
        run: |
          kind create cluster --name escape-test --config test/kind-config.yaml
          kubectl apply -f test/hardened-workload-under-test.yaml
          kubectl wait --for=condition=Ready pod/target-workload --timeout=120s

      - name: Run escape attempt suite
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY_REDTEAM }}
        run: |
          python test/escape_agent.py \
            --target-namespace default \
            --target-pod target-workload \
            --max-attempts 50 \
            --timeout 300 \
            --report escape-report-${{ github.sha }}.json

      - name: Assert no escape achieved
        run: |
          python test/assert_no_escape.py \
            --report escape-report-${{ github.sha }}.json \
            --fail-on-any-escape

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: escape-report
          path: escape-report-*.json

      - name: Teardown test cluster
        if: always()
        run: kind delete cluster --name escape-test
```

The escape agent runs against the test cluster using a structured set of known escape techniques — Docker socket enumeration, capability abuse, kernel CVE application, namespace confusion — and records every attempt and result. The `assert_no_escape.py` step fails CI if any technique succeeded, triggering investigation before the configuration reaches production.

This is not a substitute for architectural controls. A CI gate that validates your gVisor RuntimeClass is enforced and your seccomp profile is applied provides confidence that the controls are in place. It does not validate that gVisor itself contains no 0-day — that is the Level 2 and Level 3 problem, which requires architectural elimination rather than validation testing.

## Expected Behaviour After Hardening

Against Level 1 AI: all 100% escape vectors — exposed Docker sockets, privileged containers, host namespace sharing — are absent. Kyverno policies reject any future introduction of those configurations at admission time. gVisor RuntimeClass is enforced on untrusted workload namespaces. A Level 1 AI agent running SandboxEscapeBench's test suite against a container in this configuration finds no Docker socket to mount, no privileged flag to exploit, a seccomp profile blocking the syscall paths for known kernel CVEs, and gVisor's user-space kernel returning ENOSYS on the syscalls those CVEs depend on. Escape success rate drops from approximately 50% to near-zero on commodity attack tooling.

Against Level 2 AI: the architecture eliminates device emulation code (Firecracker VMM or Type-1 hypervisor), restricts `CLONE_NEWUSER` via seccomp (removing the overlayfs + user namespace escape chain), and presents gVisor's ~200,000-line Go kernel rather than the multi-million-line Linux kernel as the software target. A new 0-day discovered by AI in an `nf_tables` subsystem that no longer exists in the attack-accessible kernel surface has no viable exploit path. The eliminated code is not hardened — it is absent.

Against Level 3 AI (where applicable): confidential compute (AMD SEV-SNP, Intel TDX) ensures that a compromised host cannot read workload memory. Type-1 hypervisor deployment reduces the software-layer attack surface to the hypervisor code base, which is significantly smaller than the full Linux kernel stack.

## Trade-offs and Operational Considerations

gVisor imposes measurable overhead on syscall-heavy workloads. The overhead is near-zero for CPU-bound workloads, 10–20% for network-intensive workloads using gVisor's netstack, and can exceed 50% for workloads that issue high syscall volumes (databases, file servers). Profile workloads before requiring gVisor cluster-wide. For syscall-heavy workloads that cannot accept gVisor overhead, Kata Containers presents a real kernel in a VM — the overhead is primarily VM startup time (100–500ms, amortised for long-running pods) and steady-state overhead of 5–15%.

Eliminating `nf_tables` and `overlayfs` from the container-accessible kernel surface requires cross-cutting coordination with the network layer and the node configuration. The seccomp profile that blocks `CLONE_NEWUSER` must be applied consistently — a pod that bypasses the profile by specifying `seccompProfile: Unconfined` defeats the control. Enforce via PSS restricted (which requires a non-Unconfined seccomp profile) and verify with Kyverno.

Level 3 threat modelling requires an honest assessment of your actual threat profile. Most organisations do not face nation-state AI offensive capability directed at their container workloads. Investing in Type-1 hypervisor infrastructure and confidential computing for workloads that do not require that level of protection is operationally expensive and may not be recoverable in improved security posture for the actual threats you face. Be explicit about threat levels in your threat model documentation before making architectural decisions.

The continuous AI red team CI pipeline requires a dedicated API key with budget controls, a fully isolated test cluster that cannot reach production systems, and a maintained library of escape techniques. The value is proportional to the coverage of that technique library — a test suite that checks only the 100% escape vectors provides limited signal if those are already eliminated by policy.

## Failure Modes

**gVisor deployed but `hostNetwork: true` pods bypass it:** A pod with `hostNetwork: true` uses the host network stack directly, not gVisor's netstack. Network-layer kernel CVEs remain exploitable from that pod. gVisor provides no protection for host-network workloads because the syscalls for network operations go to the real host kernel. Block `hostNetwork: true` via Kyverno policy — it is also one of SandboxEscapeBench's high-escape-probability configurations.

**AI red team testing run at deployment and not repeated:** Container runtime and kernel updates add new attack surface continuously. A test that validated your configuration against gVisor 20240101's implementation does not validate it against a new kernel version that added a subsystem gVisor now exposes differently. Schedule the CI escape-test job at minimum weekly, and trigger it on any node OS update or container runtime version change. A passing test at deployment provides zero confidence about the state of the system six months later.

**Architectural hardening focuses on the container layer while the orchestration plane remains unprotected:** SandboxEscapeBench tested container escapes. An AI attacker who determines that container escape is difficult will pivot to the Kubernetes API server, etcd, or admission webhook infrastructure. A well-hardened container layer with an API server accessible without authentication or with weak RBAC provides a trivial alternative path to cluster control. Architectural decisions about container isolation must be matched by equally rigorous hardening of the control plane. The container security model is only as strong as the weakest path to cluster-admin.

**Seccomp profile applied inconsistently across pod controllers:** A Kyverno policy that matches on `Pod` resources catches directly submitted pods but not pods created by Deployments, StatefulSets, or DaemonSets if those are submitted before the policy was in place. Audit existing workloads for seccomp profile compliance before and after policy implementation. PSS restricted ensures a non-Unconfined profile but does not enforce the specific profile you need for `CLONE_NEWUSER` blocking — that requires the custom Localhost profile to be explicitly specified.

## Related Articles

- [Kubernetes LLM Escape Hardening](/articles/kubernetes/kubernetes-llm-escape-hardening/)
- [RuntimeClass gVisor Kata](/articles/kubernetes/runtimeclass-gvisor-kata/)
- [AI Vulnerability Discovery](/articles/ai-landscape/ai-vulnerability-discovery/)
- [Firecracker VMM Attack Surface](/articles/cross-cutting/firecracker-vmm-attack-surface/)
- [Linux Unprivileged Namespace Restriction](/articles/linux/linux-unprivileged-namespace-restriction/)
