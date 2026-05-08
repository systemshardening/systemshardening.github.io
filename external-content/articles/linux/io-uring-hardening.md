---
title: "io_uring Security and Hardening: Disabling, Restricting, and Auditing a Bypass-Prone Syscall Interface"
description: "io_uring gives userspace a submission queue that sidesteps the normal syscall path. It has produced a steady stream of kernel CVEs and routinely bypasses seccomp."
slug: "io-uring-hardening"
date: 2026-04-24
lastmod: 2026-04-24
category: "linux"
tags: ["io_uring", "kernel", "seccomp", "sandboxing", "linux", "container-security"]
personas: ["systems-engineer", "platform-engineer", "security-engineer"]
article_number: 163
difficulty: "advanced"
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/linux/io-uring-hardening/index.html"
---

# io_uring Security and Hardening: Disabling, Restricting, and Auditing a Bypass-Prone Syscall Interface

## Problem

io_uring is a high-performance asynchronous I/O interface introduced in Linux 5.1. Instead of issuing one syscall per operation, a process sets up shared memory ring buffers with the kernel and submits I/O operations by writing submission queue entries (SQEs). The kernel processes them in the background and posts completions to a separate ring.

For database engines, proxies, and network dataplanes this is a meaningful throughput win. It is also one of the hardest kernel subsystems to reason about from a security perspective, for three reasons:

- **io_uring bypasses seccomp for the queued operations.** A seccomp filter intercepts syscalls. io_uring submits work through shared memory ring buffers; the individual operations (`IORING_OP_OPENAT`, `IORING_OP_READ`, `IORING_OP_SENDMSG`, etc.) are not seccomp-filterable on most kernels. A sandbox that blocks `openat` at the syscall level does not block `IORING_OP_OPENAT`.
- **The attack surface is large and evolving.** Since 2019, io_uring has accumulated over 100 CVEs, including use-after-free, type confusion, and privilege escalation bugs. Google's kCTF rewarded multiple critical io_uring exploits in 2023–2024. ChromeOS and Android disabled the interface for unprivileged processes. Docker Desktop disables it by default. Major distros restrict it for containers.
- **Workloads rarely need it.** Most production services perform I/O through glibc, Go's runtime, or managed runtimes that do not use io_uring. You pay the kernel attack surface cost even when no process benefits.

This article covers four complementary controls: disabling io_uring globally, restricting it per-container via seccomp, constraining which opcodes a process can submit, and auditing io_uring usage across a fleet.

**Target systems:** Linux kernel 5.15+ (the `io_uring_disabled` sysctl arrived in 6.6, with backports in RHEL 9.4 and Ubuntu 24.04). Kubernetes 1.28+ for the container-level controls.

## Threat Model

- **Adversary:** Attacker with code execution inside an unprivileged process — compromised application container, malicious userspace process on a shared host, or code executing under a seccomp sandbox (browser renderer, document converter, CI runner).
- **Access level:** Unprivileged user namespace or container, typically with a seccomp filter and minimal Linux capabilities.
- **Objective:** Reach vulnerable kernel code paths to achieve privilege escalation, read kernel memory (heap leak, KASLR bypass), or escape the sandbox.
- **Blast radius:** A successful io_uring kernel exploit grants root on the host. On a Kubernetes node this means access to every pod's secrets, the kubelet credentials, and in cloud environments the instance metadata credentials. The standard kernel-exploit blast radius applies: one compromised pod becomes one compromised node.
- **What this does not defend against:** root-equivalent processes that can legitimately use io_uring (database engines running as their service user with required capabilities). The controls here target unprivileged workloads that do not need the interface.

## Configuration

### Option 1: Disable io_uring Globally

The cleanest control. Refuse any attempt to call `io_uring_setup` at the kernel level. Since 6.6 (backported to RHEL 9.4 and Ubuntu 24.04), a dedicated sysctl exists:

```ini
# /etc/sysctl.d/60-io-uring.conf
# Disable io_uring for all processes.
# 0 = allowed (default)
# 1 = disabled for unprivileged processes (CAP_SYS_ADMIN still allowed)
# 2 = disabled for everyone, including root
kernel.io_uring_disabled = 2
```

Apply and verify:

```bash
sudo sysctl -p /etc/sysctl.d/60-io-uring.conf
cat /proc/sys/kernel/io_uring_disabled
# 2

# Verify: an unprivileged io_uring_setup call should now return ENOSYS or EPERM.
strace -e io_uring_setup -f -- ./io_uring_test_program
# io_uring_setup(8, {...}) = -1 EPERM (Operation not permitted)
```

Set `kernel.io_uring_disabled = 1` instead if one specific daemon legitimately uses io_uring and you want to allow it as root. Use `2` when no process on the host needs it.

For older kernels (5.15–6.5) without the sysctl, disable at boot via the kernel command line. Append to `GRUB_CMDLINE_LINUX` in `/etc/default/grub`:

```
io_uring.disabled=1
```

Rebuild grub and reboot:

```bash
sudo update-grub   # Debian/Ubuntu
sudo grub2-mkconfig -o /boot/grub2/grub.cfg   # RHEL/Rocky
sudo reboot
```

### Option 2: Block io_uring_setup via Seccomp

When you cannot disable io_uring host-wide (because one service needs it), block it for everything else via seccomp. The three io_uring syscalls are `io_uring_setup` (425), `io_uring_enter` (426), and `io_uring_register` (427).

For containers, extend the runtime's default seccomp profile. The Docker and containerd default profiles already block these syscalls unless `CAP_SYS_ADMIN` is granted. Verify your runtime version:

```bash
# Check that io_uring is in the blocked list for unprivileged containers.
docker run --rm alpine:3 sh -c \
  'apk add -q strace && strace -e io_uring_setup sh -c "true"' 2>&1 | \
  grep io_uring_setup
# io_uring_setup(...) = -1 EPERM (Operation not permitted)
```

For Kubernetes, use the `RuntimeDefault` seccomp profile on every pod:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: myapp:1.0
```

For a custom seccomp profile that adds io_uring to an existing allow-list, deny the three syscalls explicitly:

```json
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "syscalls": [
    {
      "names": ["io_uring_setup", "io_uring_enter", "io_uring_register"],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 38
    }
  ]
}
```

`errnoRet: 38` returns `ENOSYS`, which signals to the application that the syscall is unimplemented. Most runtimes (glibc, Rust's tokio with `io-uring` feature, Go's experimental io_uring support) fall back to synchronous I/O when they see `ENOSYS`. Returning `EPERM` instead is more truthful but causes some applications to abort.

### Option 3: Restrict Which Opcodes a Process Can Submit

If a service legitimately uses io_uring for file I/O but should never open new files or make network calls through it, constrain the opcodes via `io_uring_register` with `IORING_REGISTER_RESTRICTIONS` (available since kernel 5.10). This is set once during initialization and cannot be loosened afterwards.

```c
// restrict_io_uring.c
// Allow only IORING_OP_READ and IORING_OP_WRITE on pre-registered fds.
#include <liburing.h>

struct io_uring_restriction res[3] = {
    {
        .opcode = IORING_RESTRICTION_REGISTER_OP,
        .register_op = IORING_REGISTER_FILES,
    },
    {
        .opcode = IORING_RESTRICTION_SQE_OP,
        .sqe_op = IORING_OP_READ,
    },
    {
        .opcode = IORING_RESTRICTION_SQE_OP,
        .sqe_op = IORING_OP_WRITE,
    },
};

io_uring_register_restrictions(&ring, res, 3);
io_uring_enable_rings(&ring);
```

With this in place, a compromised process that controls submission queue entries cannot submit `IORING_OP_OPENAT`, `IORING_OP_CONNECT`, or any other opcode — the kernel rejects them before execution. Applies only when the service itself sets up the restrictions. For third-party software that uses io_uring, Options 1 or 2 are the only reliable controls.

### Option 4: Audit io_uring Usage Across the Fleet

Before disabling io_uring, measure who uses it. auditd records syscall invocations; eBPF lets you record per-opcode submissions without modifying applications.

Audit rule (auditd):

```bash
# /etc/audit/rules.d/io-uring.rules
-a always,exit -F arch=b64 -S io_uring_setup -k io_uring_usage
-a always,exit -F arch=b64 -S io_uring_register -k io_uring_usage
```

Reload and query:

```bash
sudo augenrules --load
sudo ausearch -k io_uring_usage --start today | \
  awk '/comm=/ {for (i=1;i<=NF;i++) if ($i ~ /^comm=/) print $i}' | \
  sort -u
```

For opcode-level visibility, use bpftrace:

```bash
sudo bpftrace -e '
tracepoint:io_uring:io_uring_submit_sqe {
  @opcodes[comm, args->opcode] = count();
}
interval:s:30 { print(@opcodes); clear(@opcodes); }
'
```

Expected output: a frequency table of (process, opcode) pairs. Anything unexpected — a web service submitting `IORING_OP_OPENAT` to `/etc/shadow`, a sidecar issuing `IORING_OP_CONNECT` to a public IP — warrants investigation.

## Expected Behaviour

After applying `io_uring_disabled = 2`:

| Signal | Before | After |
|--------|--------|-------|
| `io_uring_setup()` | Returns valid ring fd | Returns `EPERM` for all users |
| Processes using io_uring | Work normally | Fall back to synchronous I/O or fail at startup |
| Kernel attack surface | io_uring code paths reachable from any process | io_uring code paths unreachable; exploit attempts fail at syscall entry |
| `cat /proc/sys/kernel/io_uring_disabled` | `0` | `2` |
| Benchmark throughput | High for io_uring-aware apps | Unchanged for apps using read/write/epoll; degraded for io_uring-native apps |

After seccomp-level blocking (Option 2):

- Containers with `RuntimeDefault` profile receive `EPERM` for `io_uring_setup`.
- Privileged containers (with `CAP_SYS_ADMIN`) still have access — use Option 1 to block them too.
- Applications fall back to synchronous I/O if they handle the error; abort at startup if they do not.

## Trade-offs

| Control | Security Benefit | Cost | Mitigation |
|---------|------------------|------|------------|
| `io_uring_disabled = 2` | Removes the entire subsystem from the kernel attack surface | Any process that needs io_uring fails. Measure first via auditd/bpftrace. | Whitelist via `= 1` and run the exempt service as a user with `CAP_SYS_ADMIN`. |
| Seccomp block in containers | Blocks unprivileged containers without touching the host kernel | Does not protect against root-in-container (CAP_SYS_ADMIN bypasses the block). Containers with the capability can still exploit. | Combine with `allowPrivilegeEscalation: false`, drop all capabilities, and use unprivileged user namespaces. |
| `IORING_REGISTER_RESTRICTIONS` | Fine-grained opcode allowlist enforced by the kernel | Requires source-code modification. Cannot be applied to third-party binaries. | Use for in-house services. Fall back to seccomp for everything else. |
| Performance impact of disabling | N/A | Throughput loss of 10-40% for io_uring-native workloads (benchmarked on Redis with async replication, FoundationDB, ScyllaDB). | Keep io_uring enabled (via `= 1`) on hosts dedicated to those databases; disable on general application nodes. |
| Auditing via bpftrace | Visibility into which processes use io_uring before you disable it | eBPF programs consume CPU (~1-3% on loaded systems) and require `CAP_BPF` to run. | Run audits on a representative sample of nodes for 24-48 hours; do not leave bpftrace running continuously. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Legitimate service depends on io_uring | Service fails with `io_uring_setup: Operation not permitted` or crashes at startup | systemd logs `Failed to start`, application logs mention io_uring initialization failure | Identify the service via audit logs. Either allow it via `io_uring_disabled = 1` and run it with the needed capability, or reconfigure the service to use synchronous I/O (most have a config flag). |
| Seccomp block returns wrong errno | Application aborts instead of falling back | Application logs show unexpected termination on io_uring_setup | Change seccomp rule from `errnoRet: 1` (EPERM) to `errnoRet: 38` (ENOSYS). Most runtimes handle ENOSYS gracefully. |
| Setting reverts after reboot | `/proc/sys/kernel/io_uring_disabled` back to `0` | Audit rules show io_uring_setup calls succeeding again | Ensure the sysctl config file is in `/etc/sysctl.d/` (persistent) rather than set via `sysctl -w` (runtime only). Verify with `sudo sysctl -a | grep io_uring_disabled` after reboot. |
| Container runtime upgrade removes io_uring from default seccomp profile | New containers can call io_uring_setup successfully | `ausearch -k io_uring_usage` shows new processes using the interface after an upgrade | Pin your seccomp profile as a `Localhost` profile under `/var/lib/kubelet/seccomp/profiles/` and reference it explicitly in pod specs. Do not depend on `RuntimeDefault` alone. |
| Exploit in io_uring code despite restrictions | Kernel panic, unexpected privilege escalation | Node abruptly reboots; security scanner flags new root processes | Keep kernels current. CVEs in io_uring are patched quickly by upstream and distros. Subscribe to your distro's security advisory list. Disabling (Option 1) is the only reliable mitigation until patches land. |
| IORING_REGISTER_RESTRICTIONS bypass via opcode not covered | A legal opcode ends up doing something unexpected | Audit logs show unusual file access by the restricted process | Review the opcode list before each kernel upgrade. New opcodes (e.g., `IORING_OP_FTRUNCATE` added in 6.5, `IORING_OP_BIND`/`LISTEN` added in 6.11) appear regularly and must be added to deny restrictions. |

## Related Articles

- [Hardening the Linux Kernel Attack Surface with sysctl and Boot Parameters](/articles/linux/sysctl-kernel-hardening/)
- [seccomp Profiles for Kubernetes Workloads](/articles/kubernetes/seccomp-profiles/)
- [Hardening the Linux Audit Framework: auditd Rules, auditctl, and ausearch](/articles/linux/auditd-deep-dive/)
- [eBPF Runtime Security with Tetragon](/articles/observability/ebpf-tetragon/)
