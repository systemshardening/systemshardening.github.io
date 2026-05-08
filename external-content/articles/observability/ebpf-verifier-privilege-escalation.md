---
title: "eBPF Verifier Bugs: Privilege Escalation from Container Observability Tools"
description: "CVE-2021-3490 (ALU32 bounds bypass) and CVE-2022-23222 (pointer arithmetic escape) both allowed unprivileged eBPF programs to achieve kernel write primitives. Observability tools like Falco, Tetragon, and Pixie that load eBPF programs into the kernel expand the attack surface — a compromised tool or malicious pod with BPF privileges can escalate to host root."
slug: ebpf-verifier-privilege-escalation
date: 2026-05-08
lastmod: 2026-05-08
category: observability
tags:
  - ebpf
  - cve
  - privilege-escalation
  - kernel
  - container-escape
personas:
  - security-engineer
  - platform-engineer
article_number: 661
difficulty: Advanced
estimated_reading_time: 14
published: true
layout: article.njk
permalink: /articles/observability/ebpf-verifier-privilege-escalation/
---

# eBPF Verifier Bugs: Privilege Escalation from Container Observability Tools

## The Problem

eBPF's security model rests on a single load-bearing component: the verifier. Before any eBPF program executes, the kernel's verifier performs a static analysis pass over every instruction, constructing an abstract state machine that tracks the type and value bounds of every register at each program point. If the verifier accepts a program, the kernel's contract is that the program cannot access memory outside the explicitly permitted regions, cannot dereference arbitrary pointers, and will always terminate. This guarantee is what allows operators to safely load observability programs into the kernel at runtime. It is also the guarantee that CVE-2021-3490 and CVE-2022-23222 violated — not at the theoretical level, but in exploitable, root-achieving ways.

**CVE-2021-3490** was discovered by Manfred Paul and demonstrated at Pwn2Own 2021. The eBPF ISA operates on 64-bit registers but also supports 32-bit sub-register arithmetic (ALU32 operations). The verifier maintains two parallel bounds representations for each register: a 64-bit tracking state and a 32-bit tracking state. ALU32 arithmetic was supposed to keep both representations in sync. It did not. When an ALU32 operation produced a value that fit in 32 bits, the verifier correctly bounded the 32-bit representation but failed to tighten the 64-bit representation correspondingly. An attacker could craft a sequence of ALU32 operations that produced a register value the verifier believed was bounded — for example, within the range `[0, map_value_size - 1]` — but whose 64-bit representation the verifier had left with a much wider, or entirely unbounded, range. When that register was then used as an offset for a map value pointer access, the verifier approved the access because the 32-bit bounds appeared safe. At runtime, the 64-bit register value was used for the actual memory access, and it could be attacker-controlled anywhere in kernel memory. This gave an out-of-bounds read and write primitive. The write primitive was sufficient to overwrite a kernel function pointer and achieve code execution at ring 0. Affected kernel range: 5.7 through 5.11. Fix landed in 5.11.15 and backports.

**CVE-2022-23222** was discovered by tr3e. The verifier's type system tracks whether a register holds a scalar value, a pointer to a map value, a pointer to the stack, a pointer to a BPF context structure, or several other typed variants. The `PTR_TO_MEM` type (used for pointers returned from certain helper calls and for ringbuf reservations) was subject to a bounds-propagation failure when arithmetic operations were performed on it in combination with specific map lookup patterns. In certain code sequences, the verifier's abstract state for the register's type was corrupted from `PTR_TO_MEM` to `SCALAR_VALUE` or vice versa after arithmetic. The consequence: the verifier permitted pointer arithmetic that it should have rejected, and the resulting pointer could, at runtime, dereference an arbitrary kernel virtual address. Like CVE-2021-3490, this produced a read/write primitive directly convertible to a privilege escalation via function pointer overwrite or `modprobe_path` overwrite. Affected: Linux 5.15 and earlier, specifically 5.15.x before 5.15.19, 5.10.x before 5.10.96, and 5.16.x before 5.16.5.

**How the bpf() syscall and verifier work.** When a process calls `bpf(BPF_PROG_LOAD, &attr, sizeof(attr))`, the kernel copies the program's bytecode from userspace and runs it through the verifier before any instruction executes. The verifier performs a depth-first traversal of every possible execution path (bounded by the 1 million instruction limit introduced in 5.2). At each instruction, it maintains a `bpf_reg_state` for each of the 11 registers: the register's type (`SCALAR_VALUE`, `PTR_TO_MAP_VALUE`, `PTR_TO_CTX`, etc.), signed and unsigned minimum and maximum values, and a tnum (tracked number) representing which bits are known constants and which are unknown. Memory accesses are approved only when the verifier can prove, using these abstract bounds, that the access offset into a permitted region is within the region's size. The entire security guarantee depends on the abstract bounds being a sound over-approximation of the concrete runtime values. When they are not — when the runtime value can escape the range the verifier computed — the security guarantee collapses entirely.

**The exploitation pattern.** Once an out-of-bounds write primitive exists in an eBPF program, the standard exploitation path against Linux kernels applies with minimal modification. The attacker's eBPF program, which has already passed verification and is executing in the kernel context, performs a heap spray to locate a predictable kernel object (an `sk_buff`, a `file` structure, or an `inode` depending on the specific exploit) adjacent to the exploitable map value region. Using the OOB write primitive, it overwrites a function pointer within that object — `sk_buff->destructor`, a `file_operations` entry, or in many published exploits the global `modprobe_path` string. Overwriting `modprobe_path` requires only a kernel data write, no function pointer corruption: the string `/sbin/modprobe` is replaced with an attacker-controlled path, and a subsequent `request_module()` call (triggered by attempting to load a kernel module or by the `socket()` syscall with an unknown protocol family) causes the kernel to execute the attacker's binary as root with `__request_module`'s privileges. Published PoC exploits for both CVE-2021-3490 and CVE-2022-23222 use this pattern and produce a root shell in under two seconds on affected kernels.

**The Kubernetes observability threat surface.** Every major Kubernetes observability tool that uses eBPF runs as a DaemonSet — one pod per node, with host kernel access. Falco loads eBPF probes to intercept syscalls. Tetragon (Cilium's runtime security project) loads eBPF programs that trace kernel functions. Pixie loads eBPF programs for application performance tracing. Hubble and Cilium itself load eBPF programs for network flow visibility and network policy enforcement. All of these run with `CAP_BPF` (on kernels ≥ 5.8) or `CAP_SYS_ADMIN` (on older kernels where `CAP_BPF` does not exist). A compromised DaemonSet image is not just a container escape — the malicious eBPF program it loads executes kernel code directly on the host, bypassing every namespace boundary and seccomp profile simultaneously. The analogy to the Trivy action compromise is exact: the supply chain attack loads an eBPF program instead of exfiltrating secrets, and the DaemonSet's kernel privilege replaces the CI job's secret access. The blast radius is host root on every node in the cluster running that DaemonSet.

## Threat Model

**Compromised observability tool image.** An attacker who gains write access to the container registry or CI/CD pipeline for Falco, Tetragon, or Pixie can inject a malicious eBPF program into the tool's image. When the DaemonSet rolls out the new image (automatically, as most clusters do), the pod loads the malicious eBPF program into the host kernel with whatever privileges the DaemonSet's ServiceAccount holds. On kernels within the vulnerable range for CVE-2021-3490 or CVE-2022-23222, this produces immediate root on the node. On patched kernels, the malicious program can still instrument all syscalls and network activity on the node — every process, every container, all traffic — without requiring root separately. The DaemonSet's design guarantees the widest possible deployment footprint.

**Pod with CAP_BPF exploiting a verifier bug.** Any pod that a developer has granted `CAP_BPF` — either explicitly for a custom monitoring use case, or inadvertently via a broad `CAP_SYS_ADMIN` grant — can call `bpf(BPF_PROG_LOAD, ...)` directly. On a kernel within the CVE-2022-23222 range (5.15.x before 5.15.19 is very common in clusters that froze on Ubuntu 22.04 LTS's 5.15 kernel), the pod escalates to host root in under two seconds, reads all secrets and credentials from the node's filesystem and process memory, and exits. No persistent artifact remains on the node unless the attacker places one explicitly.

**Unprivileged user creating pods.** In RBAC configurations where developers can create pods in their own namespaces, an attacker with valid cluster credentials can create a pod with `securityContext.capabilities.add: ["CAP_BPF"]` in the pod spec, unless an admission controller explicitly blocks this. Once the pod starts, the escalation path above applies. Many clusters restrict this via PodSecurity admission at the `restricted` level, but clusters still running PSP (deprecated in 1.21, removed in 1.25) or using permissive PSA baselines are fully exposed.

**eBPF map data exfiltration.** Even without exploiting a verifier bug, an observability tool that has been compromised can read the eBPF maps populated by other eBPF programs on the same node. Falco's syscall ring buffer contains a continuous trace of every syscall made by every container on the node: file opens, network connections, process executions, and their arguments. A malicious Falco image that simply forwards this data to an external endpoint — rather than processing it locally — exfiltrates a complete audit trail of all pod activity, including environment variables passed to exec calls, paths of files accessed by other pods, and network connection metadata. This requires no kernel vulnerability: the DaemonSet's existing, legitimate privileges suffice.

**Heterogeneous node pools and kernel version lag.** Kubernetes node pools are routinely not all on the same kernel version. Managed Kubernetes services (EKS, GKE, AKS) allow mixing node groups with different OS images and kernel versions. A cluster may have some nodes on Ubuntu 22.04 (5.15.x kernel) and others on Ubuntu 24.04 (6.8.x kernel). CVE-2022-23222 affects the 5.15.x range; an attacker who can schedule a workload on the older node group retains the exploitation path even after the newer nodes are patched. Kernel version heterogeneity within a cluster means the effective security boundary is determined by the oldest kernel in the pool, not the newest.

**Lateral movement after node compromise.** Host root on a Kubernetes node gives complete access to every container running on that node via `crictl exec`, the kubelet API on localhost, and direct filesystem access to container overlay mounts. It also gives access to the node's kubelet credentials (the client certificate in `/var/lib/kubelet/pki/`), which can be used against the Kubernetes API server with the node's RBAC permissions — typically including `get` on pods and `update` on node status. On GKE and EKS, the node's service account token or IAM role credentials give cloud API access. The privilege escalation chain from eBPF verifier bug to cloud account access is: exploit verifier → host root → steal kubelet certificate → enumerate cluster → steal cloud credentials from node metadata API → cloud account takeover.

## Hardening Configuration

### 1. Restrict BPF Syscall Access at the Kernel Level

The sysctl `kernel.unprivileged_bpf_disabled` controls whether the `bpf()` syscall is accessible to processes without `CAP_BPF` or `CAP_SYS_ADMIN`:

```bash
# Check current state
sysctl kernel.unprivileged_bpf_disabled
# kernel.unprivileged_bpf_disabled = 0  ← unsafe default on many distributions

# Disable unprivileged BPF access
sysctl -w kernel.unprivileged_bpf_disabled=1
```

Make this persistent across reboots by writing to a sysctl drop-in:

```bash
cat > /etc/sysctl.d/99-bpf-hardening.conf << 'EOF'
# Require CAP_BPF or CAP_SYS_ADMIN to load eBPF programs or create maps.
# This does not prevent DaemonSet observability tools from functioning —
# they run with CAP_BPF explicitly — but it closes the unprivileged
# exploitation path for CVE-2021-3490 and CVE-2022-23222.
kernel.unprivileged_bpf_disabled = 1

# Restrict perf_event_open to reduce information disclosure to unprivileged users.
# Some eBPF exploit paths use perf events as an oracle.
kernel.perf_event_paranoid = 3
EOF

sysctl --system
```

Verify that the setting survived a node restart and that it is consistent across all nodes. In a Kubernetes cluster, use a DaemonSet that runs on node startup to assert the value — a misconfigured node that was added to the pool without the sysctl applied represents the attack surface:

```bash
# On each node, or as a DaemonSet init container
sysctl kernel.unprivileged_bpf_disabled | grep -q 'kernel.unprivileged_bpf_disabled = 1' \
  || { echo "FAIL: BPF not restricted on $(hostname)"; exit 1; }
```

Note: setting `kernel.unprivileged_bpf_disabled = 2` (available since 5.13) is irreversible at runtime — even root cannot set it back to 0 without a reboot. This is appropriate for production nodes where you never expect to change BPF policy dynamically.

### 2. Seccomp Profile Blocking bpf() Syscall

Block the `bpf()` syscall (syscall number 321 on x86-64) in all pods that do not require it. Create a seccomp profile that drops only the BPF syscall while allowing everything else:

```json
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
  "syscalls": [
    {
      "names": ["bpf"],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1
    }
  ]
}
```

Save this to `/var/lib/kubelet/seccomp/profiles/block-bpf.json` on each node. Apply it via `RuntimeClass`:

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: no-bpf
handler: runc
scheduling:
  nodeSelector:
    kubernetes.io/os: linux
overhead:
  podFixed:
    memory: "0"
    cpu: "0"
---
apiVersion: v1
kind: Pod
metadata:
  name: application-pod
spec:
  runtimeClassName: no-bpf
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/block-bpf.json
  containers:
  - name: app
    image: my-app:latest
```

For the monitoring namespace where Falco or Tetragon runs, use a permissive seccomp profile (or `RuntimeDefault`) and rely on the Kyverno capability restriction in the next section to enforce that only the monitoring namespace can hold `CAP_BPF`. Do not apply `block-bpf.json` to the monitoring namespace — the observability tools need the syscall.

### 3. Kyverno ClusterPolicy: Restrict CAP_BPF Grants

No pod outside the `monitoring` namespace should be able to request `CAP_BPF` or `CAP_SYS_ADMIN`. Enforce this at admission:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-cap-bpf
  annotations:
    policies.kyverno.io/title: Restrict CAP_BPF and CAP_SYS_ADMIN
    policies.kyverno.io/description: >-
      Prevents pods outside the monitoring namespace from requesting CAP_BPF
      or CAP_SYS_ADMIN. These capabilities allow loading eBPF programs and are
      required attack prerequisites for CVE-2021-3490 and CVE-2022-23222.
spec:
  validationFailureAction: Enforce
  background: true
  rules:
  - name: deny-cap-bpf-outside-monitoring
    match:
      any:
      - resources:
          kinds: ["Pod"]
    exclude:
      any:
      - resources:
          namespaces: ["monitoring", "kube-system"]
    validate:
      message: >-
        CAP_BPF and CAP_SYS_ADMIN are restricted to the monitoring and
        kube-system namespaces. Pod {{ request.object.metadata.name }} in
        namespace {{ request.object.metadata.namespace }} requested a
        prohibited capability.
      deny:
        conditions:
          any:
          - key: "CAP_BPF"
            operator: AnyIn
            value: "{{ request.object.spec.containers[].securityContext.capabilities.add[] }}"
          - key: "CAP_SYS_ADMIN"
            operator: AnyIn
            value: "{{ request.object.spec.containers[].securityContext.capabilities.add[] }}"
          - key: "CAP_BPF"
            operator: AnyIn
            value: "{{ request.object.spec.initContainers[].securityContext.capabilities.add[] }}"
          - key: "CAP_SYS_ADMIN"
            operator: AnyIn
            value: "{{ request.object.spec.initContainers[].securityContext.capabilities.add[] }}"
```

This policy enforces at admission time. Back it up with a second rule that audits existing pods (the `background: true` setting enables this):

```yaml
  - name: audit-privileged-pods
    match:
      any:
      - resources:
          kinds: ["Pod"]
    exclude:
      any:
      - resources:
          namespaces: ["monitoring", "kube-system"]
    validate:
      message: "Pod {{ request.object.metadata.name }} runs as privileged — review required."
      pattern:
        spec:
          containers:
          - =(securityContext):
              =(privileged): false
```

### 4. Image Signature Verification for Observability Tools

A supply chain attack on an observability DaemonSet image is the highest-impact delivery vector — the pod already has `CAP_BPF` and runs on every node. Enforce cryptographic signature verification before any image in the `monitoring` namespace is admitted.

Verify the Falco image signature manually using cosign:

```bash
cosign verify \
  --certificate-identity-regexp="https://github.com/falcosecurity/falco/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  falcosecurity/falco:0.39.2

# Expected output:
# Verification for index.docker.io/falcosecurity/falco:0.39.2 --
# The following checks were performed on each of these signatures:
#   - The cosign claims were validated
#   - Existence of the claims in the transparency log was verified offline
#   - The code-signing certificate claims were validated
```

Enforce signature verification at admission using the Sigstore Policy Controller:

```yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: monitoring-namespace-signed-images
spec:
  images:
  - glob: "falcosecurity/**"
  - glob: "quay.io/cilium/**"
  - glob: "docker.io/cilium/**"
  authorities:
  - keyless:
      url: https://fulcio.sigstore.dev
      identities:
      - issuerRegExp: "https://token.actions.githubusercontent.com"
        subjectRegExp: "https://github.com/falcosecurity/.*"
  - keyless:
      url: https://fulcio.sigstore.dev
      identities:
      - issuerRegExp: "https://token.actions.githubusercontent.com"
        subjectRegExp: "https://github.com/cilium/.*"
```

Apply Policy Controller to the monitoring namespace specifically:

```bash
# Label the monitoring namespace for Policy Controller enforcement
kubectl label namespace monitoring policy.sigstore.dev/include=true

# Verify the label is present before deploying any DaemonSet
kubectl get namespace monitoring -o jsonpath='{.metadata.labels}'
```

Without signature enforcement, a registry credential compromise is sufficient to inject a malicious Tetragon image that will be scheduled on every node in the cluster — the DaemonSet controller will roll it out automatically on the next image pull.

### 5. Kernel Patch Tracking Across Node Pools

Maintain a script that maps running kernel versions against known-vulnerable ranges. Run this as a CronJob or as part of your node compliance check:

```bash
#!/bin/bash
# check-kernel-ebpf-cves.sh
# Checks the running kernel version against eBPF verifier CVE vulnerable ranges.
# Exit code 0 = clean, 1 = vulnerable

KERNEL_FULL=$(uname -r)
# Extract major.minor.patch as integers
KERNEL_MAJOR=$(echo "$KERNEL_FULL" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_FULL" | cut -d. -f2)
KERNEL_PATCH=$(echo "$KERNEL_FULL" | cut -d. -f3 | cut -d- -f1)

echo "Node: $(hostname)"
echo "Kernel: $KERNEL_FULL (${KERNEL_MAJOR}.${KERNEL_MINOR}.${KERNEL_PATCH})"

VULNERABLE=0

# CVE-2021-3490: ALU32 bounds bypass. Affects 5.7.0 - 5.11.14
if [[ "$KERNEL_MAJOR" -eq 5 ]]; then
  if [[ "$KERNEL_MINOR" -ge 7 && "$KERNEL_MINOR" -le 10 ]]; then
    echo "VULNERABLE: CVE-2021-3490 (5.7-5.10.x series, all patch levels)"
    VULNERABLE=1
  elif [[ "$KERNEL_MINOR" -eq 11 && "$KERNEL_PATCH" -lt 15 ]]; then
    echo "VULNERABLE: CVE-2021-3490 (5.11.x < 5.11.15)"
    VULNERABLE=1
  fi
fi

# CVE-2022-23222: PTR_TO_MEM type confusion.
# Affects: 5.16.x < 5.16.5, 5.15.x < 5.15.19, 5.10.x < 5.10.96
if [[ "$KERNEL_MAJOR" -eq 5 ]]; then
  if [[ "$KERNEL_MINOR" -eq 16 && "$KERNEL_PATCH" -lt 5 ]]; then
    echo "VULNERABLE: CVE-2022-23222 (5.16.x < 5.16.5)"
    VULNERABLE=1
  elif [[ "$KERNEL_MINOR" -eq 15 && "$KERNEL_PATCH" -lt 19 ]]; then
    echo "VULNERABLE: CVE-2022-23222 (5.15.x < 5.15.19)"
    VULNERABLE=1
  elif [[ "$KERNEL_MINOR" -eq 10 && "$KERNEL_PATCH" -lt 96 ]]; then
    echo "VULNERABLE: CVE-2022-23222 (5.10.x < 5.10.96)"
    VULNERABLE=1
  fi
fi

# CVE-2023-2163: incorrect pruning of dead code allowing out-of-bounds access.
# Affects: 6.0.x - 6.2.x before 6.2.16, 6.3.x before 6.3.3
if [[ "$KERNEL_MAJOR" -eq 6 ]]; then
  if [[ "$KERNEL_MINOR" -ge 0 && "$KERNEL_MINOR" -le 1 ]]; then
    echo "VULNERABLE: CVE-2023-2163 (6.0-6.1.x — check distro backport status)"
    VULNERABLE=1
  elif [[ "$KERNEL_MINOR" -eq 2 && "$KERNEL_PATCH" -lt 16 ]]; then
    echo "VULNERABLE: CVE-2023-2163 (6.2.x < 6.2.16)"
    VULNERABLE=1
  elif [[ "$KERNEL_MINOR" -eq 3 && "$KERNEL_PATCH" -lt 3 ]]; then
    echo "VULNERABLE: CVE-2023-2163 (6.3.x < 6.3.3)"
    VULNERABLE=1
  fi
fi

# CVE-2023-39191: insufficient validation of dynamic pointers in certain helper calls.
# Affects: kernels before 6.2 (depends on CONFIG_BPF_JIT_ALWAYS_ON and architecture)
if [[ "$KERNEL_MAJOR" -lt 6 ]] || [[ "$KERNEL_MAJOR" -eq 6 && "$KERNEL_MINOR" -lt 2 ]]; then
  echo "POTENTIALLY VULNERABLE: CVE-2023-39191 (< 6.2 — verify distro backport)"
  # Not setting VULNERABLE=1 here because distro kernels frequently backport fixes;
  # treat as informational and check your distro's security tracker
fi

if [[ "$VULNERABLE" -eq 0 ]]; then
  echo "No known eBPF verifier CVEs detected at this kernel version."
fi

exit $VULNERABLE
```

Deploy this as a Kubernetes CronJob that runs on every node via a DaemonSet or cluster-wide node scanning approach:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: ebpf-kernel-cve-check
  namespace: monitoring
spec:
  schedule: "0 6 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          hostPID: true
          tolerations:
          - operator: Exists
          nodeSelector:
            kubernetes.io/os: linux
          containers:
          - name: kernel-check
            image: alpine:3.20
            command: ["/bin/sh", "-c"]
            args:
            - |
              KERNEL=$(uname -r)
              echo "kernel_version{node=\"$NODE_NAME\"} 1" >> /dev/null
              # Inline the check script or mount it from a ConfigMap
            env:
            - name: NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
            securityContext:
              readOnlyRootFilesystem: true
              allowPrivilegeEscalation: false
          restartPolicy: OnFailure
```

### 6. eBPF Program Audit Logging

Maintain an inventory of expected eBPF programs loaded on each node. Unexpected programs indicate either a misconfigured workload or active exploitation:

```bash
# List all loaded eBPF programs with metadata
bpftool prog list --json | jq -r '.[] | [.id, .type, .name, (.loaded_at | todate)] | @tsv'

# Expected output on a Falco node:
# 42    tracepoint    sys_enter_openat    2026-05-08T06:00:12Z
# 43    tracepoint    sys_exit_openat     2026-05-08T06:00:12Z
# 44    tracepoint    sys_enter_execve    2026-05-08T06:00:12Z
# ...

# List eBPF maps and their sizes — unexpectedly large maps may indicate data staging
bpftool map list --json | jq -r '.[] | [.id, .type, .name, .bytes_memlock] | @tsv'
```

Create a Falco rule (meta-alerting: Falco detecting Falco misuse) to alert on unexpected `bpf()` syscall callers:

```yaml
- rule: Unexpected BPF Program Load
  desc: >
    A process outside the expected observability namespace loaded an eBPF program.
    This may indicate exploitation of a verifier vulnerability or an unauthorized
    monitoring tool.
  condition: >
    syscall.type = bpf
    and syscall.args[0] = BPF_PROG_LOAD
    and not proc.name in (falco, tetragon, cilium-agent, hubble-relay, pixie_agent)
    and not container.image.repository in (falcosecurity/falco, quay.io/cilium/cilium)
  output: >
    Unexpected BPF program load (user=%user.name command=%proc.cmdline
    pid=%proc.pid container=%container.name image=%container.image.repository
    ns=%k8s.ns.name)
  priority: CRITICAL
  tags: [ebpf, privilege-escalation, container-escape]
```

Establish a baseline of expected programs and export it as a ConfigMap for comparison:

```bash
# Snapshot current programs on a known-clean node
bpftool prog list --json | jq '[.[] | {id, type, name, tag}]' \
  > /etc/ebpf-baseline-$(date +%Y%m%d).json

# Compare current state to baseline in a monitoring loop
bpftool prog list --json | jq '[.[] | {type, name, tag}] | sort_by(.tag)' \
  > /tmp/current.json

diff <(jq 'sort_by(.tag)' /etc/ebpf-baseline-*.json) /tmp/current.json \
  && echo "eBPF program inventory unchanged" \
  || echo "ALERT: eBPF program inventory changed — investigate"
```

## Expected Behaviour

On a correctly hardened cluster, the following outputs represent baseline normal state.

`bpftool prog list` on a Falco-only node produces programs exclusively from Falco's expected syscall tracepoints, with consistent `loaded_at` timestamps corresponding to the DaemonSet rollout time. No programs are loaded by `pid` values that are not the Falco process:

```
42: tracepoint  name sys_enter_open  tag 2a4b8c1d3e5f6a7b  gpl
    loaded_at 2026-05-08T06:00:12+0000  uid 0
    xlated 504B  jited 312B  memlock 4096B  map_ids 1,2
    pids falco(1847)
```

When a pod without `CAP_BPF` attempts to call `bpf(BPF_PROG_LOAD, ...)`, the kernel returns `EPERM` immediately. In the audit log (`/var/log/audit/audit.log` with `auditd`, or `journalctl -k` on systems using systemd journal):

```
type=SYSCALL msg=audit(1746684312.042:8834): arch=c000003e syscall=321
success=no exit=-1 a0=5 a1=7ffd8a4c2030 a2=80 a3=0 items=0
ppid=12345 pid=12346 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000
fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=42
comm="exploit_poc" exe="/tmp/exploit" key="bpf_syscall"
```

A Kyverno policy violation when a pod requests `CAP_BPF` outside the `monitoring` namespace:

```
Error from server: error when creating "bad-pod.yaml": admission webhook
"validate.kyverno.svc-fail" denied the request:

resource Pod/default/debug-bpf was blocked due to the following policies

restrict-cap-bpf:
  deny-cap-bpf-outside-monitoring: CAP_BPF and CAP_SYS_ADMIN are restricted
  to the monitoring and kube-system namespaces. Pod debug-bpf in namespace
  default requested a prohibited capability.
```

## Trade-offs

**Blocking CAP_BPF affects Cilium CNI.** Cilium uses eBPF for its entire data plane: network policy enforcement, service load balancing, and pod-to-pod routing. Restricting `CAP_BPF` in `kube-system` — where Cilium runs — breaks the CNI entirely. The Kyverno policy above exempts `kube-system` from the capability restriction. If your threat model requires restricting `kube-system` further, the alternative is switching to a non-eBPF CNI (Flannel, Calico in iptables mode) which trades observability capability for a reduced kernel attack surface. There is no configuration that simultaneously uses Cilium and prevents all pods with `CAP_BPF` from running.

**Falco kernel module mode as an alternative.** Falco supports a kernel module driver (`falco.ko`) as an alternative to its eBPF probe. The kernel module does not go through the eBPF verifier — it executes directly as kernel code. This removes the verifier bug attack surface for Falco specifically, but introduces a different risk: a compromised Falco image with kernel module mode active is arbitrary kernel code execution by design, with no verifier as a limiting factor. The kernel module approach is not a security improvement; it trades one risk category for another. Falco's eBPF modern probe (using `libbpf` and CO-RE) is generally preferable because it does get verifier scrutiny, and the verifier bugs in question have all been patched upstream.

**`kernel.unprivileged_bpf_disabled=1` breaks bcc tools.** The `bcc` toolkit (including `tcptop`, `execsnoop`, `profile`, and dozens of others) relies on loading eBPF programs without privilege elevation. Developers who use these tools for performance analysis from their own workstations will find them broken after setting this sysctl. This is an acceptable trade-off on production nodes. On development machines or bastion hosts where engineers need `bcc` access, consider a namespace with a service account that has `CAP_BPF` bound to a specific user group, rather than relaxing the system-wide sysctl. Alternatively, `bpftrace` works with the sysctl set when invoked with `sudo`.

**Requiring signed images for DaemonSets adds CI/CD pipeline complexity.** Enforcement of Sigstore signatures via Policy Controller means every Falco, Tetragon, and Cilium image must be signed before admission. Upstream projects sign their release images, but if your organisation builds custom forks or internal configurations of these tools, you must add signing to your image build pipeline. The `cosign sign` step in CI adds approximately 30 seconds to an image build. Failing to sign correctly means the DaemonSet cannot update on a monitored node — a monitoring outage rather than a security incident, but operationally disruptive. Build the signing step into your CI template for all observability tooling before enabling policy enforcement in production.

## Failure Modes

**Trusting the eBPF verifier as a complete security boundary.** The eBPF verifier has had exploitable bugs in every major kernel version since eBPF became generally available. CVE-2021-3490 (5.7–5.11), CVE-2022-23222 (≤5.15.18), CVE-2023-2163 (6.0–6.3.2), CVE-2023-39191 (< 6.2) — these are not isolated incidents. They are a recurring pattern indicating that the verifier, despite its formal verification ambitions, is a complex piece of software with its own attack surface. Treat the verifier as a defence-in-depth component, not as the sole barrier between a pod and ring 0. Layer `CAP_BPF` restrictions, seccomp profiles, image signature enforcement, and kernel patching on top of it.

**Not scanning DaemonSet images as rigorously as application images.** Security teams routinely apply strict scanning and admission policies to application workloads while treating infrastructure DaemonSets as trusted. Falco, Tetragon, and Cilium images have base operating systems, libraries, and Go runtimes — all of which carry CVEs. More importantly, their privileged position in the cluster makes them a higher-value supply chain target than most application images. Apply at minimum the same scanning policies (Trivy in CI, image signature verification at admission) to observability DaemonSets as to production application images. Given their elevated privileges, consider applying stricter policies.

**Assuming observability tools are "read-only."** The phrase "read-only kernel access" is commonly applied to eBPF observability tools in architecture documentation. It is incorrect. eBPF programs of type `BPF_PROG_TYPE_KPROBE` can write to kernel function arguments via the `bpf_probe_write_user()` helper. eBPF programs with access to `BPF_MAP_TYPE_HASH` or `BPF_MAP_TYPE_ARRAY` maps pinned in the BPF virtual filesystem can be updated by any process with `CAP_BPF` and file read access to the pin path. Most critically: a verifier vulnerability converts any eBPF program into an arbitrary write primitive regardless of its declared program type. Do not architect defences on the assumption that a compromised observability tool is constrained to reading data.

**Not tracking kernel versions across heterogeneous node pools.** The `kubectl get nodes -o wide` output shows the kernel version for every node in the cluster. A heterogeneous node pool — EKS node groups on different AMIs, spot instances that came up on an older image before the current image was available, preemptible nodes from GKE that returned from preemption running a stale kernel — creates a subset of nodes that remain vulnerable after the primary node group is patched. Run the kernel CVE check script above as a CronJob on every node and alert on any output that includes `VULNERABLE:`. The longest-running node in a cluster is frequently the one that missed the patch that all newer nodes have.
