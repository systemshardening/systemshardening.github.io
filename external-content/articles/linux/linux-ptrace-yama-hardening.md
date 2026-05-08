---
title: "Linux ptrace Security and YAMA LSM Hardening"
description: "ptrace is a privilege-escalation primitive hiding in plain sight. YAMA LSM, PR_SET_DUMPABLE, seccomp, and eBPF auditing close the attack surface in production and container environments."
slug: linux-ptrace-yama-hardening
date: 2026-05-07
lastmod: 2026-05-07
category: linux
tags:
  - ptrace
  - yama
  - lsm
  - process-security
  - memory-inspection
personas:
  - security-engineer
  - platform-engineer
article_number: 473
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/linux/linux-ptrace-yama-hardening/
---

# Linux ptrace Security and YAMA LSM Hardening

## The Problem

`ptrace(2)` is a debugging syscall. It is also one of the most dangerous primitives in the Linux kernel: any process that can attach to another can read and write its entire address space, forge its syscalls, and inject arbitrary code into it. The system call was designed in a world where "processes belonging to the same user" were equivalent in trust. That assumption has not held for decades.

On a modern system, the same UID runs a browser, an SSH agent, a credential manager, a cloud CLI, a secret vault daemon, and a dozen other processes — each holding different secrets. Default kernel policy (`ptrace_scope=0`) allows any of them to attach to any other. A single compromised process in that UID space can exfiltrate everything.

The attack surface is not theoretical:

- **ssh-agent credential theft:** An attacker with code execution in the user's session can attach to ssh-agent, walk its memory, and extract private keys — without touching the filesystem.
- **gpg-agent / pass:** Same pattern. The decrypted secret lives in memory; ptrace reaches it.
- **Browser credential stores:** Chromium, Firefox, Electron-based apps keep session tokens and saved passwords in heap memory. Ptrace reads them.
- **Cloud CLIs:** AWS/GCP/Azure CLI processes cache short-lived credentials in memory. The process credential is often more valuable than the stored credential file.
- **Container escapes:** If a container shares a PID namespace with the host, an attacker inside the container can ptrace host processes if the scope is not restricted.

The mitigations — YAMA LSM, `PR_SET_DUMPABLE`, seccomp BPF, and eBPF-based auditd — each defend a different layer. None is sufficient alone.

---

## ptrace as an Attack Primitive

### The Core Capability

`PTRACE_ATTACH` stops a target process and grants the tracer full read/write access to the target's:

- Virtual memory (`PTRACE_PEEKDATA`, `PTRACE_POKEDATA`)
- Registers (`PTRACE_GETREGS`, `PTRACE_SETREGS`)
- Signal delivery
- Syscall arguments and return values

A minimal credential extractor is fewer than 60 lines of C:

```c
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    pid_t target = atoi(argv[1]);
    long word;

    if (ptrace(PTRACE_ATTACH, target, NULL, NULL) < 0) {
        perror("ptrace attach");
        return 1;
    }
    waitpid(target, NULL, 0);

    /* Read 64 bytes from the target's stack pointer */
    unsigned long sp;
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, target, NULL, &regs);
    sp = regs.rsp;

    for (int i = 0; i < 8; i++) {
        word = ptrace(PTRACE_PEEKDATA, target, (void *)(sp + i * 8), NULL);
        printf("%016lx ", word);
    }

    ptrace(PTRACE_DETACH, target, NULL, NULL);
    return 0;
}
```

Real-world tools like `mimipenguin`, `gcore`, and `proc_maps_reader` use the same mechanism against known offsets in ssh-agent's heap.

### /proc/PID/mem: The Higher-Bandwidth Route

`/proc/PID/mem` provides a file interface to process address space. Reading it requires `PTRACE_ATTACH` permission (same access control as ptrace itself), but throughput is much higher — `read(2)` on `/proc/PID/mem` is faster than byte-at-a-time `PTRACE_PEEKDATA`.

The canonical attack:

```bash
# Attach, then read the entire heap in one call
pid=$(pgrep ssh-agent)
# Stop the target
kill -STOP $pid
# Read from /proc/PID/maps to find heap range
grep heap /proc/$pid/maps
# e.g.: 55a2b3c00000-55a2b3e00000 rw-p ...

# Read the heap directly
dd if=/proc/$pid/mem bs=1 skip=$((0x55a2b3c00000)) count=$((0x200000)) 2>/dev/null | \
  strings | grep -E 'OPENSSH|ecdsa|rsa'
kill -CONT $pid
```

This works on a default `ptrace_scope=0` system for any process owned by the same UID. The file descriptor check on `/proc/PID/mem` calls `ptrace_may_access()` in the kernel — the same function gated by YAMA.

### Code Injection via ptrace

`PTRACE_POKEDATA` allows writing to the target's memory. Combined with `PTRACE_SETREGS` to redirect the instruction pointer, this is full shellcode injection:

```c
/* Write shellcode into target's .text segment and redirect RIP */
for (int i = 0; i < shellcode_len / 8; i++) {
    ptrace(PTRACE_POKEDATA, target,
           (void *)(target_addr + i * 8),
           *(long *)(shellcode + i * 8));
}
regs.rip = target_addr;
ptrace(PTRACE_SETREGS, target, NULL, &regs);
ptrace(PTRACE_CONT, target, NULL, NULL);
```

This is the mechanism behind process hollowing, reflective library injection, and the `dlinject` family of tools.

---

## YAMA LSM: Restricting ptrace Scope

YAMA is a Linux Security Module focused entirely on restricting ptrace. It ships in every major distribution and is controlled via a single sysctl: `kernel.yama.ptrace_scope`.

### The Four Scope Levels

**Scope 0 — Classic (no restriction)**

Any process can ptrace any other process owned by the same UID. Root can ptrace anything. This is the historical Unix behavior and the default on many distributions.

```bash
sysctl kernel.yama.ptrace_scope
# kernel.yama.ptrace_scope = 0
```

**Scope 1 — Restricted (parent-only)**

A process can only be ptraced by:
- Its direct parent
- Processes it has explicitly designated via `PR_SET_PTRACER`
- Root (CAP_SYS_PTRACE)

This is the correct setting for most production systems. `gdb ./program` works because the shell (parent) spawns the target. `strace -p <pid>` of an unrelated process does not, unless root or PR_SET_PTRACER is used.

```bash
sysctl -w kernel.yama.ptrace_scope=1
```

**Scope 2 — Admin-only**

Only processes with `CAP_SYS_PTRACE` can use ptrace. No ordinary user can debug anything, regardless of ownership.

```bash
sysctl -w kernel.yama.ptrace_scope=2
```

**Scope 3 — Fully disabled**

ptrace is disabled system-wide. Not even root can use it without rebooting with a different scope. This value is sticky until reboot when set via sysctl at runtime.

```bash
sysctl -w kernel.yama.ptrace_scope=3
```

To make it persistent:

```bash
# /etc/sysctl.d/99-yama.conf
kernel.yama.ptrace_scope = 1
```

For high-security systems running no interactive debugging workloads:

```bash
# /etc/sysctl.d/99-yama.conf
kernel.yama.ptrace_scope = 2
```

### Trade-offs by Environment

| Environment | Recommended scope | Rationale |
|---|---|---|
| Production servers (no debugger) | 2 | No interactive debugging; admin-only for emergency use |
| Kubernetes worker nodes | 1 | kubelet and container runtimes need parent-child ptrace |
| Developer workstations | 1 | gdb/strace work for parent-spawned targets |
| Security-critical hosts (HSMs, secret brokers) | 3 | No debugging, ever |
| CI/CD runners | 1 | Build tools that use strace/ltrace for reproducibility |

### PR_SET_PTRACER: Opt-In Debugger Allowlisting

Under scope 1, a process can grant a specific other process permission to attach via `prctl(PR_SET_PTRACER, pid, ...)`. This is the correct mechanism to allow, for example, a dedicated debug helper to attach to a service without running as root:

```c
#include <sys/prctl.h>

/* Allow the process with PID 'debugger_pid' to attach to us */
prctl(PR_SET_PTRACER, debugger_pid, 0, 0, 0);

/* Allow any process to attach (USE WITH EXTREME CAUTION) */
prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
```

In practice, `PR_SET_PTRACER_ANY` is used by test frameworks that spawn tracers. In production, pass the specific PID of the authorized debugger process and revoke it by setting `PR_SET_PTRACER` back to 0 after the debugging session.

---

## PR_SET_DUMPABLE: Protecting Secrets from Core Dumps

Core dumps can expose the same information as ptrace. A crashed ssh-agent produces a core file containing all in-memory private keys. `PR_SET_DUMPABLE` controls both core dump behavior and — critically — ptrace access.

```c
#include <sys/prctl.h>

/* Disable core dumps and ptrace attach for this process */
prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
```

When `PR_SET_DUMPABLE` is 0:
- The kernel will not write a core file on crash.
- `/proc/PID/mem`, `/proc/PID/maps`, and `/proc/PID/environ` become inaccessible to non-root.
- `PTRACE_ATTACH` is denied (via `ptrace_may_access()`) even from same-UID processes.

This is the correct setting for any process that holds key material, session tokens, or credentials. OpenSSH 8.2+ sets this by default. If you maintain a daemon that handles secrets:

```c
/* Called at startup, before handling any secrets */
if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
    err(1, "prctl PR_SET_DUMPABLE");
}
```

Note the interaction with YAMA: `PR_SET_DUMPABLE=0` is enforced independently of `ptrace_scope`. Even at scope 0, a process that set itself non-dumpable cannot be attached to by a same-UID peer — only by root.

**Interaction with setuid/setgid:** The kernel automatically sets `dumpable=0` when a process executes a setuid or setgid binary. This is why `/proc/self/mem` access restrictions tighten for setuid processes even without explicit `prctl` calls.

---

## Seccomp and ptrace: Blocking the Syscall Entirely

For processes that will never issue ptrace (the vast majority of production workloads), seccomp BPF provides the hardest restriction: remove the syscall from the process's callable surface entirely.

A minimal seccomp filter that blocks ptrace:

```c
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

static void block_ptrace(void) {
    struct sock_filter filter[] = {
        /* Load syscall number */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),
        /* Kill process if syscall is ptrace */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ptrace, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
}
```

Use `SECCOMP_RET_ERRNO` with `EPERM` instead of `SECCOMP_RET_KILL_PROCESS` if the process must not crash on an unexpected ptrace call (e.g., some JVM runtimes probe for ptrace availability at startup).

### Container and Kubernetes Defaults

**Docker/containerd default seccomp profile:** Docker's default seccomp profile (as of 2024) does NOT block `ptrace`. The `ptrace` syscall is allowed by default. This is intentional — Go runtime, Java debuggers, and strace-based diagnostics use it — but it means containers are not protected unless you supply a custom profile.

Check your container's effective profile:

```bash
# Show the effective seccomp profile for a running container
docker inspect <container> --format '{{.HostConfig.SecurityOpt}}'
```

To apply a restrictive profile that blocks ptrace in Docker:

```bash
docker run --security-opt seccomp=/path/to/no-ptrace-seccomp.json ...
```

A minimal `no-ptrace-seccomp.json` (based on the Docker default with ptrace removed):

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [
    {
      "names": ["ptrace"],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1
    }
  ]
}
```

In practice, start from Docker's default profile and remove `ptrace` from the allowlist rather than building from scratch.

**Kubernetes seccomp annotations:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: hardened-app
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/no-ptrace.json
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
```

The `RuntimeDefault` seccomp profile (equivalent to Docker's default) does not block ptrace. Use `Localhost` with a custom profile if you need that guarantee.

**PID namespace isolation:** In Kubernetes, the default is for each Pod to have its own PID namespace. With `shareProcessNamespace: true`, containers in a Pod share a PID namespace — and ptrace restrictions between those containers now depend on YAMA scope and UID alignment, not namespace isolation. Avoid `shareProcessNamespace: true` unless the use case requires it.

---

## Linux 5.14+ Syscall User Dispatch

Linux 5.14 introduced Syscall User Dispatch (SUD), a mechanism that lets a process redirect specific syscall ranges to a userspace signal handler rather than the kernel. This is used by compatibility layers (Wine, Steam Proton) to intercept Windows syscalls.

The security interaction with ptrace: SUD handlers run in userspace and can inspect syscall arguments before they reach the kernel. A malicious library linked into a process could install a SUD handler that intercepts `read(2)` calls on `/proc/PID/mem` paths and logs or exfiltrates the data. The defense is the same as for other injection vectors — integrity of the process's own address space.

From a defensive perspective, SUD's relevance is that it does not bypass YAMA or seccomp: a process still needs `PTRACE_ATTACH` permission to open `/proc/PID/mem`, and seccomp still gates the `ptrace` syscall before dispatch reaches the kernel. SUD runs after seccomp in the syscall path. However, SUD can be used by a compromised process to intercept syscalls being made by its own threads, which is a lateral movement vector within a multi-threaded process if the attacker has written code into one thread via ptrace.

---

## Detecting ptrace Attacks with auditd and eBPF

### auditd: Syscall-Level Auditing

Audit rules to detect ptrace attach attempts:

```bash
# /etc/audit/rules.d/99-ptrace.rules

# Alert on all ptrace PTRACE_ATTACH and PTRACE_TRACEME calls
-a always,exit -F arch=b64 -S ptrace -F a0=0x10 -k ptrace_attach
-a always,exit -F arch=b64 -S ptrace -F a0=0x0  -k ptrace_traceme
-a always,exit -F arch=b32 -S ptrace -F a0=0x10 -k ptrace_attach
-a always,exit -F arch=b32 -S ptrace -F a0=0x0  -k ptrace_traceme

# Watch for /proc/*/mem opens
-a always,exit -F arch=b64 -S openat -F path=/proc -k proc_mem_open
```

Where `a0=0x10` is `PTRACE_ATTACH` (decimal 16) and `a0=0x0` is `PTRACE_TRACEME`. Load the rules:

```bash
augenrules --load
systemctl restart auditd
```

Query ptrace events:

```bash
ausearch -k ptrace_attach --start today | aureport -i
```

A spike in `ptrace_attach` events against a specific PID (e.g., `ssh-agent`, `gnome-keyring-daemon`, `gpg-agent`) is a strong indicator of credential theft activity.

### eBPF: Per-Process Attach Monitoring

For production systems where auditd overhead is a concern, an eBPF kprobe on `security_ptrace_check` fires at the YAMA decision point:

```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct event {
    u32 tracer_pid;
    u32 target_pid;
    u32 tracer_uid;
    char tracer_comm[16];
    char target_comm[16];
};

struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 20); } events SEC(".maps");

SEC("lsm/ptrace_access_check")
int BPF_PROG(ptrace_access_check, struct task_struct *child, unsigned int mode) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->tracer_pid = bpf_get_current_pid_tgid() >> 32;
    e->target_pid = child->tgid;
    e->tracer_uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(e->tracer_comm, sizeof(e->tracer_comm));
    bpf_probe_read_kernel_str(e->target_comm, sizeof(e->target_comm), child->comm);

    bpf_ringbuf_submit(e, 0);
    return 0; /* observe only, return 0 to continue */
}

char LICENSE[] SEC("license") = "GPL";
```

This attaches to the `ptrace_access_check` LSM hook — the same hook YAMA uses — so it fires on every ptrace permission check regardless of whether YAMA allows or denies. Return a non-zero value from the BPF program to deny the attach (combining eBPF LSM enforcement with observability).

Integrate with Falco or a custom alerting pipeline by reading from the ring buffer and emitting to your SIEM.

---

## Hardening Checklist

**Kernel sysctl (apply in /etc/sysctl.d/99-yama.conf):**

```bash
# Restrict ptrace to parent-child relationships only
kernel.yama.ptrace_scope = 1

# On high-security nodes with no debugging requirement
kernel.yama.ptrace_scope = 2
```

Verify the setting survived boot:

```bash
sysctl kernel.yama.ptrace_scope
cat /proc/sys/kernel/yama/ptrace_scope
```

**For daemons handling credentials — in service code:**

```c
/* Early in main(), before any key material is loaded */
prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
```

Or via systemd unit:

```ini
[Service]
# Equivalent to PR_SET_DUMPABLE=0
LimitCORE=0
# Additional ptrace restriction (requires systemd 247+)
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
```

Note: `LimitCORE=0` prevents core dumps but does not set `PR_SET_DUMPABLE` — ptrace restriction requires the `prctl` call or `NoNewPrivileges=yes` combined with YAMA scope ≥ 1.

**For containers:**

```bash
# Explicitly deny ptrace in container seccomp profile
# Do not rely on Docker default — it allows ptrace
docker run \
  --security-opt no-new-privileges \
  --security-opt seccomp=./no-ptrace.json \
  myimage:latest
```

**For Kubernetes:**

```yaml
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: no-ptrace.json
  containers:
  - securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
```

**For audit:**

```bash
# Install ptrace audit rules
augenrules --load

# Verify YAMA is loaded and active
grep -r yama /sys/kernel/security/
ls /sys/module/yama/
```

---

## What YAMA Does Not Protect

- **Root bypass:** `CAP_SYS_PTRACE` bypasses YAMA entirely at all scope levels below 3. Any process with this capability can ptrace anything. Audit `CAP_SYS_PTRACE` grants aggressively; it should never appear in production container security contexts.
- **Same process:** Scope has no meaning within a process. A compromised thread can read the stack of other threads directly via shared memory. Compartmentalize secrets across processes, not threads.
- **Kernel exploits:** Kernel vulnerabilities bypass all LSMs. YAMA is a userspace-facing protection. Defense-in-depth via kernel lockdown mode, signed modules, and live patching is required at the layer below.
- **Ambient authority:** If the attacker already has root or is the parent process, scope 1 provides no protection. Scope 2 is the minimum for protecting against root-equivalent-but-not-root scenarios.
- **Process injection via non-ptrace paths:** `/proc/PID/fd`, shared memory segments, and UNIX socket credential passing are separate attack surfaces not covered by YAMA. `PR_SET_DUMPABLE=0` protects `/proc/PID/mem` and `/proc/PID/maps` independently of YAMA scope.

---

## Summary

The default ptrace behavior on Linux grants full memory read/write access between processes of the same UID. In any multi-process environment — desktop sessions, Kubernetes pods sharing a PID namespace, containers — this is an unacceptable trust boundary.

The layered defense:

1. **YAMA `ptrace_scope=1`** on every production system. `ptrace_scope=2` on systems with no debugging requirement.
2. **`PR_SET_DUMPABLE=0`** in every daemon that handles key material or credentials.
3. **Seccomp BPF blocking `ptrace`** in containers and sandboxed processes that have no debugging requirement.
4. **Custom Kubernetes seccomp profiles** — do not assume `RuntimeDefault` blocks ptrace.
5. **auditd or eBPF LSM hooks** to detect and alert on ptrace attach attempts against sensitive processes.
6. **Audit `CAP_SYS_PTRACE` grants** — any process holding this capability renders YAMA scope ineffective.

ptrace is not a deprecated syscall. It remains the primary mechanism for debuggers, profilers, strace, and a significant fraction of security tooling. The goal is not to remove it but to restrict it to authorized parent-child relationships and to ensure that processes holding secrets have explicitly withdrawn their consent to being inspected.
