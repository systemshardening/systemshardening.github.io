---
title: "Seccomp-BPF for Non-Container Workloads: Syscall Filtering for System Services"
description: "Seccomp-BPF restricts which syscalls a process can make. Applied to system daemons and services outside containers, it reduces the kernel attack surface exploitable from a compromised service."
slug: "seccomp-bpf-non-container"
date: 2026-04-30
lastmod: 2026-04-30
category: "linux"
tags: ["seccomp", "bpf", "syscall", "systemd", "hardening"]
personas: ["security-engineer", "platform-engineer", "systems-engineer"]
article_number: 255
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/linux/seccomp-bpf-non-container/index.html"
---

# Seccomp-BPF for Non-Container Workloads: Syscall Filtering for System Services

## Problem

Every Linux process has access to hundreds of syscalls. A web server needs `read`, `write`, `accept`, `send`, `recv`, and a handful of others. It does not need `ptrace`, `mount`, `kexec_load`, `create_module`, or `perf_event_open`. Yet without seccomp, every syscall is available to the process — and to any attacker who achieves code execution within it.

Seccomp-BPF (seccomp mode 2) allows each process to install a BPF filter that the kernel evaluates for every syscall. If the filter returns `SECCOMP_RET_KILL`, the process is terminated; `SECCOMP_RET_ERRNO` returns a specific error; `SECCOMP_RET_ALLOW` lets the syscall proceed. The filter runs in-kernel, before the syscall executes — an attacker cannot bypass it from userspace.

In the container world, seccomp profiles are well-established (Docker's default profile, Kubernetes `seccompProfile` field). For system services running directly on Linux hosts — nginx, PostgreSQL, OpenSSH, Prometheus node-exporter, custom daemons — seccomp is rarely applied.

Specific gaps in unmanaged services:

- Services compiled with no seccomp filter; full syscall table available on compromise.
- systemd units with no `SystemCallFilter=` directive, despite systemd's built-in seccomp support since version 198.
- No tooling to audit which syscalls a service actually uses at runtime.
- Profile development is manual and error-prone; one wrong exclusion breaks the service.
- No alerting when a service makes an unusual syscall (pre-filter, audit mode).

**Target systems:** Linux kernel 3.17+ (seccomp-BPF stable); systemd 198+ (`SystemCallFilter`, `SystemCallArchitectures`); libseccomp 2.5+ (C/Go/Python library for profile generation); strace 6.0+, seccomp-tools for auditing.

## Threat Model

- **Adversary 1 — RCE in a service daemon:** An attacker achieves code execution in nginx via a memory corruption vulnerability. Without seccomp, they call `execve` to spawn a shell, `mmap` + `mprotect` to make shellcode executable, or `ptrace` to attach to another process. With a strict seccomp filter, those syscalls return `EPERM` and the exploit chain fails.
- **Adversary 2 — Syscall-level privilege escalation:** A known kernel vulnerability (e.g., a `perf_event_open` or `userfaultfd` exploit) requires calling a specific syscall from userspace. If that syscall is blocked in the service's filter, the exploit is not reachable.
- **Adversary 3 — Container escape via host service:** A containerised workload achieves RCE in a host-level service (e.g., through a shared Unix socket). Without seccomp on the host service, the attacker uses it as a proxy to call privileged syscalls.
- **Adversary 4 — Time-of-check to time-of-use via seccomp bypass:** An attacker attempts to use `seccomp` itself to install a permissive filter (child processes can add more restrictive filters, not less restrictive ones — `SECCOMP_FILTER_FLAG_TSYNC` propagates filters but cannot remove them). The `no_new_privs` bit prevents child processes from gaining privileges.
- **Access level:** Adversaries 1–3 have process-level code execution in the targeted service. Adversary 4 has process-level execution and attempts syscall-level escalation.
- **Objective:** Escape the service's privilege context, pivot to the host, execute arbitrary code outside the service's intended scope.
- **Blast radius:** Without seccomp, RCE in a service = access to the full Linux syscall table = many escalation paths. With a strict profile, the attacker is limited to syscalls the service legitimately uses — typically no `execve`, no `ptrace`, no `mount`.

## Configuration

### Step 1: Audit Syscalls with strace

Before writing a profile, record which syscalls the service actually makes at runtime:

```bash
# Trace a running service by PID.
strace -p $(pgrep -f nginx) -f -e trace=all -o /tmp/nginx-syscalls.txt &
# Exercise the service: run typical workloads, startup, reload.
# Stop after a representative window.
kill %1

# Extract the unique syscall names.
grep -oP '(?<=^|\n)\w+(?=\()' /tmp/nginx-syscalls.txt | sort -u

# Or attach to all processes in a systemd service cgroup.
systemctl show nginx --property=MainPID --value | xargs -I{} strace -p {} -f \
  -e trace=all 2>/tmp/nginx-strace.txt &
# ... run workloads ...
kill %1
grep -oP '^\w+(?=\()' /tmp/nginx-strace.txt | sort -u > /tmp/nginx-allowed-syscalls.txt
```

Use `seccomp-tools` for more targeted analysis:

```bash
# Install seccomp-tools (Ruby gem).
gem install seccomp-tools

# If the service already has a seccomp filter, dump it.
seccomp-tools dump -p $(pgrep nginx)

# Disassemble a raw BPF filter.
seccomp-tools disasm /tmp/filter.bpf
```

### Step 2: Generate a Profile with libseccomp

Use `libseccomp` to build a profile programmatically rather than writing raw BPF:

```c
/* nginx-seccomp.c — generate a seccomp profile for nginx worker processes */
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    scmp_filter_ctx ctx;

    /* Default action: kill the process on any unlisted syscall. */
    ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
    if (!ctx) { perror("seccomp_init"); return 1; }

    /* Allow each syscall nginx workers legitimately need. */
    const int allowed[] = {
        SCMP_SYS(read), SCMP_SYS(write), SCMP_SYS(writev),
        SCMP_SYS(open), SCMP_SYS(openat), SCMP_SYS(close),
        SCMP_SYS(stat), SCMP_SYS(fstat), SCMP_SYS(lstat),
        SCMP_SYS(poll), SCMP_SYS(select), SCMP_SYS(epoll_wait),
        SCMP_SYS(epoll_ctl), SCMP_SYS(epoll_create1),
        SCMP_SYS(accept4), SCMP_SYS(accept),
        SCMP_SYS(recv), SCMP_SYS(recvfrom), SCMP_SYS(recvmsg),
        SCMP_SYS(send), SCMP_SYS(sendto), SCMP_SYS(sendmsg),
        SCMP_SYS(socket), SCMP_SYS(connect), SCMP_SYS(bind),
        SCMP_SYS(listen), SCMP_SYS(getsockopt), SCMP_SYS(setsockopt),
        SCMP_SYS(mmap), SCMP_SYS(mprotect), SCMP_SYS(munmap),
        SCMP_SYS(brk), SCMP_SYS(mremap),
        SCMP_SYS(futex), SCMP_SYS(nanosleep),
        SCMP_SYS(getpid), SCMP_SYS(getuid), SCMP_SYS(geteuid),
        SCMP_SYS(getgid), SCMP_SYS(getegid),
        SCMP_SYS(setuid), SCMP_SYS(setgid),   /* for worker process drop */
        SCMP_SYS(prctl),                        /* for no_new_privs */
        SCMP_SYS(exit), SCMP_SYS(exit_group),
        SCMP_SYS(rt_sigaction), SCMP_SYS(rt_sigreturn),
        SCMP_SYS(rt_sigprocmask), SCMP_SYS(sigaltstack),
        SCMP_SYS(getcwd), SCMP_SYS(chdir),
        SCMP_SYS(ioctl),
        /* Explicitly NOT included: execve, ptrace, mount, kexec_load */
    };

    for (size_t i = 0; i < sizeof(allowed)/sizeof(allowed[0]); i++) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, allowed[i], 0) < 0) {
            fprintf(stderr, "Failed to add rule for syscall %d\n", allowed[i]);
            seccomp_release(ctx);
            return 1;
        }
    }

    /* Export as BPF binary for use with systemd or a loader. */
    FILE *f = fopen("/etc/seccomp/nginx-worker.bpf", "wb");
    seccomp_export_bpf(ctx, fileno(f));
    fclose(f);

    seccomp_release(ctx);
    return 0;
}
```

```bash
gcc -o gen-nginx-seccomp nginx-seccomp.c -lseccomp
./gen-nginx-seccomp
# Produces /etc/seccomp/nginx-worker.bpf
```

For quick profile generation from a strace output, use `oci-seccomp-bpf-hook` in audit mode or the `sysexit` tracer approach:

```bash
# Generate a profile from strace output automatically.
cat /tmp/nginx-allowed-syscalls.txt | while read syscall; do
  echo "  - $syscall"
done > /etc/seccomp/nginx-syscalls.yaml
```

### Step 3: Apply via systemd SystemCallFilter

systemd's `SystemCallFilter=` applies a seccomp filter to the service without modifying the service binary:

```ini
# /etc/systemd/system/nginx.service.d/seccomp.conf
[Service]
# Lock to the native syscall ABI (prevents 32-bit syscall bypass on 64-bit kernels).
SystemCallArchitectures=native

# Allow only the listed syscall groups.
# Systemd provides named groups (@network-io, @file-system, @basic-io, etc.)
SystemCallFilter=@system-service
SystemCallFilter=@network-io
SystemCallFilter=@file-system

# Additionally block specific high-risk syscalls that the groups include.
SystemCallFilter=~@debug          # Blocks ptrace, perf_event_open, etc.
SystemCallFilter=~@mount          # Blocks mount, umount2, pivot_root.
SystemCallFilter=~@module         # Blocks init_module, delete_module.
SystemCallFilter=~@reboot         # Blocks reboot, kexec_load.
SystemCallFilter=~@privileged     # Blocks chown, setuid to other UIDs beyond own drop.
SystemCallFilter=~@raw-io         # Blocks iopl, ioperm, direct I/O.
SystemCallFilter=~@cpu-emulation  # Blocks modify_ldt, vm86.
SystemCallFilter=~@obsolete       # Blocks _sysctl, create_module, etc.

# Kill the process (not just the syscall) on violation.
SystemCallErrorNumber=EPERM       # Return EPERM instead of killing (less disruptive for debugging).
                                  # Change to ~kill once stable.
```

```bash
systemctl daemon-reload
systemctl restart nginx

# Test that nginx still works.
curl -s -o /dev/null -w '%{http_code}' http://localhost/
# Expected: 200

# Check if any syscalls are being blocked (EPERM mode).
journalctl -u nginx --since "1 minute ago" | grep -i seccomp
dmesg | grep -i seccomp
```

The systemd syscall groups (prefixed `@`) are maintained and updated with each systemd release, covering well-known categories without requiring manual syscall enumeration. View available groups:

```bash
systemd-analyze syscall-filter
# Lists all available @ groups and their member syscalls.
```

### Step 4: Apply Directly in Code with libseccomp (Go)

For custom daemons, apply the filter from within the process itself:

```go
package main

import (
    "log"
    libseccomp "github.com/seccomp/libseccomp-golang"
)

func installSeccompFilter() error {
    // Default action: kill the process.
    filter, err := libseccomp.NewFilter(libseccomp.ActKillProcess)
    if err != nil {
        return err
    }
    defer filter.Release()

    // Add allowed syscalls.
    allowed := []string{
        "read", "write", "close", "fstat", "mmap", "mprotect", "munmap",
        "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
        "poll", "lseek", "pread64", "pwrite64", "readv", "writev",
        "access", "pipe", "select", "sched_yield", "mremap", "msync",
        "mincore", "madvise", "dup", "dup2", "pause", "nanosleep",
        "getitimer", "alarm", "setitimer", "getpid", "socket",
        "connect", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg",
        "bind", "listen", "getsockname", "getpeername", "getsockopt",
        "setsockopt", "clone", "fork", "vfork", "execve",  // execve needed for startup only
        "exit", "exit_group", "futex", "epoll_create", "epoll_ctl", "epoll_wait",
        "openat", "newfstatat", "getdents64", "fcntl",
        "getuid", "geteuid", "getgid", "getegid",
        "set_robust_list", "get_robust_list", "prctl",
        "arch_prctl", "setrlimit", "getrlimit", "sigaltstack",
    }

    for _, sc := range allowed {
        syscallID, err := libseccomp.GetSyscallFromName(sc)
        if err != nil {
            return fmt.Errorf("unknown syscall %s: %w", sc, err)
        }
        if err := filter.AddRule(syscallID, libseccomp.ActAllow); err != nil {
            return fmt.Errorf("add rule %s: %w", sc, err)
        }
    }

    // Load the filter into the kernel.
    return filter.Load()
}

func main() {
    // Install the filter early — before accepting connections.
    if err := installSeccompFilter(); err != nil {
        log.Fatalf("seccomp filter install failed: %v", err)
    }
    // ... start serving ...
}
```

For processes that need to drop `execve` after startup (most daemons):

```go
// After startup is complete (workers forked, sockets bound), tighten the filter.
func tightenFilterPostStartup() error {
    filter, _ := libseccomp.NewFilter(libseccomp.ActKillProcess)
    // Same as above but WITHOUT execve.
    // This second filter is additive — cannot loosen existing restrictions.
    return filter.Load()
}
```

### Step 5: Audit Mode Before Enforcement

Start with `SCMP_ACT_LOG` (kernel 4.14+) to log violations without killing the process:

```ini
# systemd audit mode — log violations but don't kill.
[Service]
SystemCallFilter=@system-service @network-io @file-system
SystemCallFilter=~@debug ~@mount ~@module ~@reboot
SystemCallErrorNumber=EPERM   # Return error; don't kill.
```

Monitor for blocked syscalls:

```bash
# Watch auditd for seccomp events.
auditctl -a always,exit -F arch=b64 -S all -F key=seccomp-audit
ausearch -k seccomp-audit --start today | grep SECCOMP | awk '{print $NF}' | sort | uniq -c

# Or watch the kernel log directly.
dmesg -w | grep -i seccomp
# Format: audit: type=1326 audit(timestamp:serial): auid=... syscall=X ...
```

For each blocked syscall, decide: add to the allowlist (it's legitimate), or confirm it's blocked correctly (it's an exploit attempt). After a week with no unexpected blocks, switch to enforcement.

### Step 6: Architecture Pinning

On 64-bit kernels, 32-bit syscalls have different numbers. An attacker can bypass a 64-bit filter by using 32-bit compatibility syscalls. Pin to native:

```ini
# systemd.
SystemCallArchitectures=native

# Or in libseccomp: set architecture explicitly.
```

```c
/* In libseccomp C: */
seccomp_arch_remove(ctx, SCMP_ARCH_X86);      /* Remove 32-bit x86 */
seccomp_arch_remove(ctx, SCMP_ARCH_X32);      /* Remove x32 ABI */
/* Keep only SCMP_ARCH_X86_64 (the default) */
```

### Step 7: Telemetry

```
seccomp_violation_total{service, syscall}         counter
seccomp_filter_installed_total{service}           counter
seccomp_audit_events_total{service}               counter
service_syscall_count{service, syscall}           counter (from audit mode)
```

Alert on:

- `seccomp_violation_total` non-zero for a production service in enforcement mode — either a bug in the profile (service regression) or an active exploit attempt. Treat as high priority until root-caused.
- Any syscall from the `@debug` or `@module` groups appearing in audit logs for a production service — these are never expected from normal operation.

## Expected Behaviour

| Signal | No seccomp | Audit mode | Enforcement mode |
|--------|-----------|------------|-----------------|
| `execve` from compromised nginx | Succeeds — shell spawned | Logged; process continues | Process killed immediately |
| `ptrace` attach to other process | Succeeds | Logged | Process killed |
| Service functionality | Normal | Normal | Normal (if profile is correct) |
| Kernel exploit via `perf_event_open` | Reachable | Logged | Blocked; syscall returns `EPERM` |
| Profile bug: missing required syscall | N/A | Service logs error; continues | Service fails to start or errors at runtime |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| `SystemCallFilter` in systemd | No code changes required | systemd groups are coarse; may allow more than needed | Combine groups with explicit `~@debug` exclusions for precision. |
| `SCMP_ACT_KILL_PROCESS` | Immediate termination on violation | Profile bugs crash the service | Start with `EPERM` mode; move to kill after validation. |
| Architecture pinning | Closes 32-bit ABI bypass | Some services need compatibility mode | Almost no production service needs 32-bit compat; enable unless you've confirmed a dependency. |
| libseccomp in-process | Tightest possible control; no intermediary | Service code must call the API; compile-time dependency | Wrap in a thin init function; add to supervisor process. |
| Audit-first deployment | Safe discovery of required syscalls | Delay before enforcement; two deployment phases | Worth the delay; rushing to enforcement with an incomplete profile breaks the service. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Missing syscall in profile | Service fails at startup or on specific operation | `SECCOMP` audit events; service error logs | Add the missing syscall to the allowlist; reload. |
| Profile applied before process finishes setup | Startup fails (e.g., `execve` needed for fork-exec) | Immediate crash on service start | Allow `execve` in the startup phase; add a second tighter filter post-fork. |
| 32-bit compat syscall blocked unexpectedly | Java or older binary fails | Application errors; audit log shows 32-bit syscall | Identify which binary needs compat; either add it to allowlist or recompile as native 64-bit. |
| Kernel version mismatch | `SCMP_ACT_KILL_PROCESS` not available on old kernels | Service refuses to start | Fall back to `SCMP_ACT_KILL` (kills thread, not process) on kernels < 4.14. |
| Profile not applied after package update | Service binary updated; wrapper not re-applied | Audit shows no seccomp events | Tie profile application to the service unit; it reapplies on every restart automatically with systemd. |

## Related Articles

- [Pod Security Context and Seccomp Profiles](/articles/kubernetes/seccomp-profiles/)
- [Linux Capability Hardening](/articles/linux/linux-capability-hardening/)
- [AppArmor Profile Development and Enforcement](/articles/linux/apparmor/)
- [eBPF LSM: Runtime Policy Enforcement](/articles/linux/ebpf-lsm/)
- [systemd Unit Hardening](/articles/linux/systemd-unit-hardening/)
