---
title: "WASM and seccomp: Host-Side Syscall Filtering for Runtime Defence in Depth"
description: "The WASM sandbox prevents direct syscalls — but the runtime process still needs OS access, and a sandbox escape leads to unrestricted syscall access. Applying a seccomp profile to the WASM runtime process limits the blast radius of runtime vulnerabilities, complementing the WASM sandbox with a kernel-level enforcement layer."
slug: wasm-seccomp-syscall-filtering
date: 2026-05-07
lastmod: 2026-05-07
category: wasm
tags:
  - wasm
  - seccomp
  - syscall-filtering
  - defence-in-depth
  - sandbox-hardening
personas:
  - security-engineer
  - platform-engineer
article_number: 592
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/wasm/wasm-seccomp-syscall-filtering/
---

# WASM and seccomp: Host-Side Syscall Filtering for Runtime Defence in Depth

## Problem

The WebAssembly sandbox is a strong isolation primitive. A WASM module cannot call `open(2)` or `socket(2)` directly — it has no ambient authority and no direct path to kernel APIs. All host interaction flows through explicitly imported WASI host functions, and the runtime mediates every call.

That description is accurate when the sandbox holds. When it does not, the situation changes completely.

The runtime process — `wasmtime`, `wasmedge`, a Spin worker thread, a containerd-shim-spin container — runs with the full syscall access of a normal Linux process. A runtime vulnerability that gives an attacker code execution inside the runtime process hands them unrestricted access to every syscall the process can make. `ptrace`. `mount`. `perf_event_open`. `clone` with new namespaces. Whatever the runtime user can do, the attacker can now do.

Sandbox escapes in JIT compilers and complex runtimes are not theoretical. Wasmtime has published CVEs for miscompilation-class bugs that allowed a WASM module to overwrite host memory outside its linear memory region. WasmEdge has seen heap corruption in its AOT path. No runtime with a JIT or AOT compiler is immune to memory corruption bugs; no memory corruption bug in a sufficiently capable runtime is immune to exploit.

This is where seccomp-bpf enters. Seccomp is a kernel-level syscall filter. A BPF program attached to the process via `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)` intercepts every syscall before the kernel executes it, evaluates a set of rules, and either allows, rejects with `ENOSYS`/`EPERM`, or kills the thread. The filter runs entirely in the kernel; the runtime process cannot disable it.

The value proposition is straightforward: even if an attacker escapes the WASM sandbox and achieves code execution in the runtime process, they cannot call `ptrace`, `mount`, `init_module`, `perf_event_open`, or any other high-value syscall that the runtime itself has no need to make. The blast radius of a runtime compromise is constrained by the set of syscalls actually required for the workload — typically a few dozen rather than the ~400 available on a modern Linux kernel.

This article covers how to profile Wasmtime's syscall usage, build a minimal seccomp profile, apply it programmatically in Rust and via Kubernetes `seccompProfile`, combine it with namespace isolation, and test profiles without breaking WASM execution.

**Target systems:** Linux x86-64 and arm64; Wasmtime 22+ as the primary runtime; WasmEdge 0.14+ for comparison; Kubernetes 1.29+ for the Kubernetes section; SpinKube and containerd-shim-spin for OCI WASM containers.

## Threat Model

- **Adversary 1 — WASM sandbox escape:** a module containing a payload designed to trigger a JIT compiler or validator bug, gaining code execution in the runtime process. Objective: escalate from WASM sandbox to full host process privilege.
- **Adversary 2 — Supply chain compromise:** a trusted module silently modified to include exploit code targeting a known but unpatched runtime CVE. The attacker hopes the runtime is not seccomp-protected.
- **Adversary 3 — Privileged syscall abuse post-escape:** after escaping the WASM sandbox, an attacker uses `ptrace` to attach to other processes, `mount` to bind-mount the host filesystem into a namespace, or `perf_event_open` to leak kernel memory (Spectre-class attacks).
- **Access level:** All adversaries have code execution within the WASM module. Adversary 1 and 2 have also achieved runtime-process-level code execution. Adversary 3 is operating with runtime-process UID.
- **Objective:** Container escape, lateral movement, host data exfiltration, kernel memory disclosure, loading kernel modules.
- **Blast radius without seccomp:** Full syscall access at the runtime process's UID. Containers or pods without a seccomp profile have no kernel-level syscall restriction beyond DAC permissions.
- **Blast radius with minimal seccomp:** Constrained to the ~30-50 syscalls Wasmtime actually needs. `ptrace`, `mount`, `init_module`, `kexec_load`, `perf_event_open`, `clone3` with CLONE_NEWUSER, and `unshare` are blocked. A post-escape attacker cannot perform the most impactful follow-on actions.

Seccomp does not prevent the sandbox escape itself. It limits what an attacker can do after a successful escape. Combined with namespaces, read-only root filesystem, and no-new-privileges, it forms a layered enforcement stack with no single bypass path.

## Profiling Wasmtime's Syscall Usage

Before building a profile, you need to know which syscalls Wasmtime actually makes. The set varies by workload type, feature flags, and WASI capability grants. There are two practical approaches: `strace` and `perf record`.

### Using strace

```bash
strace -f -e trace=all -o /tmp/wasmtime-trace.txt \
  wasmtime run --dir /tmp --dir /var/lib/wasm \
  /path/to/workload.wasm -- arg1 arg2
```

The `-f` flag follows child threads, which is important because Wasmtime creates threads for its async executor and epoch-interrupt thread. Extract the unique syscall names:

```bash
grep -oP 'syscall\(\K[A-Z_a-z0-9]+|^\w+(?=\()' /tmp/wasmtime-trace.txt \
  | sort -u
```

Or more precisely, since strace output lines have the syscall name at the start:

```bash
awk -F'(' '{print $1}' /tmp/wasmtime-trace.txt \
  | sed 's/^[0-9 ]*//;s/^\[pid [0-9]*\] //' \
  | grep -v '^---\|^+++\|^<\|^$' \
  | sort -u
```

### Using perf

For production-like profiling under load, `perf` is preferable because it has much lower overhead:

```bash
perf stat -e 'syscalls:sys_enter_*' \
  -- wasmtime run /path/to/workload.wasm 2>&1 \
  | grep -v ' 0 ' \
  | sort -rn -k1
```

This emits a count per syscall name. Focus on syscalls that actually fire; a count of zero means Wasmtime's code path on this workload never reached that syscall.

### Wasmtime's Typical Syscall Set

After profiling a Wasmtime worker handling HTTP requests via WASI HTTP (Spin workloads), the stable syscall set is approximately:

| Category | Syscalls |
|----------|----------|
| Memory management | `mmap`, `munmap`, `mprotect`, `madvise`, `brk` |
| Thread/sync | `futex`, `clone`, `set_robust_list`, `rseq`, `sched_getaffinity` |
| I/O | `read`, `write`, `pread64`, `pwrite64`, `readv`, `writev` |
| File descriptors | `close`, `dup`, `dup2`, `fcntl`, `ioctl` |
| File system (if WASI fs enabled) | `openat`, `fstat`, `newfstatat`, `getdents64`, `lseek`, `unlinkat`, `renameat2`, `mkdirat` |
| Signals | `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `rt_sigsuspend` |
| Process info | `getpid`, `gettid`, `getuid`, `getgid`, `uname` |
| Time | `clock_gettime`, `clock_nanosleep`, `nanosleep` |
| Networking (if WASI sockets enabled) | `socket`, `connect`, `bind`, `listen`, `accept4`, `getsockopt`, `setsockopt`, `sendmsg`, `recvmsg`, `shutdown`, `poll`, `epoll_create1`, `epoll_ctl`, `epoll_wait` |
| Misc | `getrandom`, `exit_group`, `exit`, `arch_prctl`, `prctl` |

Notable absences: `ptrace`, `mount`, `umount2`, `init_module`, `finit_module`, `delete_module`, `kexec_load`, `kexec_file_load`, `perf_event_open`, `setuid`, `setgid`, `setns`, `unshare`.

## Building a Minimal seccomp Profile for Wasmtime

### seccomp-bpf Profile Format

Linux seccomp profiles can be written in BPF bytecode directly, but in practice they are generated from a higher-level specification. The two common paths are:

1. **libseccomp** (C library), used by most container runtimes.
2. **seccompiler** (Rust crate, maintained by the Firecracker team), used by Wasmtime's own Firecracker integration and suitable for embedding in Rust runtimes.

For a standalone Rust embedder, `seccompiler` is the idiomatic choice:

```toml
# Cargo.toml
[dependencies]
seccompiler = "0.4"
```

### Allowlist Profile in Rust

The following profile is appropriate for a Wasmtime process handling CPU-bound WASM workloads with no outbound network. Extend the allowlist if WASI sockets are enabled.

```rust
// seccomp_profile.rs
use seccompiler::{
    BpfProgram, SeccompAction, SeccompFilter,
    SeccompRule, SeccompCmpArgLen, SeccompCmpOp,
};
use std::collections::BTreeMap;

/// Build a minimal seccomp allowlist for a Wasmtime worker process.
/// Denied syscalls will cause SIGSYS (kills the thread).
pub fn build_wasmtime_filter() -> anyhow::Result<BpfProgram> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // Helper: allow a syscall unconditionally.
    macro_rules! allow {
        ($nr:expr) => {
            rules.insert($nr, vec![]);
        };
    }

    // Memory management
    allow!(libc::SYS_mmap);
    allow!(libc::SYS_munmap);
    allow!(libc::SYS_mprotect);
    allow!(libc::SYS_madvise);
    allow!(libc::SYS_brk);
    allow!(libc::SYS_mremap);

    // Thread and synchronisation
    allow!(libc::SYS_futex);
    allow!(libc::SYS_clone);
    allow!(libc::SYS_clone3);
    allow!(libc::SYS_set_robust_list);
    allow!(libc::SYS_rseq);
    allow!(libc::SYS_sched_getaffinity);
    allow!(libc::SYS_sched_yield);

    // Basic I/O
    allow!(libc::SYS_read);
    allow!(libc::SYS_write);
    allow!(libc::SYS_pread64);
    allow!(libc::SYS_pwrite64);
    allow!(libc::SYS_readv);
    allow!(libc::SYS_writev);
    allow!(libc::SYS_close);
    allow!(libc::SYS_dup);
    allow!(libc::SYS_dup2);
    allow!(libc::SYS_dup3);

    // File descriptor management
    allow!(libc::SYS_fcntl);
    allow!(libc::SYS_ioctl);
    allow!(libc::SYS_pipe2);
    allow!(libc::SYS_eventfd2);
    allow!(libc::SYS_timerfd_create);
    allow!(libc::SYS_timerfd_settime);

    // Filesystem (WASI fs path; remove if not using wasi:filesystem)
    allow!(libc::SYS_openat);
    allow!(libc::SYS_fstat);
    allow!(libc::SYS_newfstatat);
    allow!(libc::SYS_statx);
    allow!(libc::SYS_getdents64);
    allow!(libc::SYS_lseek);
    allow!(libc::SYS_unlinkat);
    allow!(libc::SYS_renameat2);
    allow!(libc::SYS_mkdirat);
    allow!(libc::SYS_readlinkat);
    allow!(libc::SYS_ftruncate);
    allow!(libc::SYS_fallocate);
    allow!(libc::SYS_fsync);
    allow!(libc::SYS_fdatasync);

    // Signals
    allow!(libc::SYS_rt_sigaction);
    allow!(libc::SYS_rt_sigprocmask);
    allow!(libc::SYS_rt_sigreturn);
    allow!(libc::SYS_rt_sigsuspend);

    // Process info (read-only; safe)
    allow!(libc::SYS_getpid);
    allow!(libc::SYS_gettid);
    allow!(libc::SYS_getuid);
    allow!(libc::SYS_geteuid);
    allow!(libc::SYS_getgid);
    allow!(libc::SYS_getegid);
    allow!(libc::SYS_uname);
    allow!(libc::SYS_getcwd);

    // Time
    allow!(libc::SYS_clock_gettime);
    allow!(libc::SYS_clock_nanosleep);
    allow!(libc::SYS_nanosleep);
    allow!(libc::SYS_gettimeofday);

    // Epoll / poll for async I/O
    allow!(libc::SYS_epoll_create1);
    allow!(libc::SYS_epoll_ctl);
    allow!(libc::SYS_epoll_wait);
    allow!(libc::SYS_poll);
    allow!(libc::SYS_ppoll);
    allow!(libc::SYS_select);
    allow!(libc::SYS_pselect6);

    // Entropy
    allow!(libc::SYS_getrandom);

    // Process exit
    allow!(libc::SYS_exit);
    allow!(libc::SYS_exit_group);

    // Architecture setup (called by glibc startup)
    allow!(libc::SYS_arch_prctl);

    // prctl: allow only specific operations
    // PR_SET_NAME=15, PR_GET_NAME=16, PR_SET_DUMPABLE=4, PR_GET_DUMPABLE=3
    // Block PR_SET_SECCOMP (disabling this filter) and PR_SET_MM (memory map manipulation).
    rules.insert(libc::SYS_prctl, vec![
        SeccompRule::new(vec![
            seccompiler::SeccompCondition::new(
                0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, libc::PR_SET_NAME as u64,
            )?,
        ])?,
        SeccompRule::new(vec![
            seccompiler::SeccompCondition::new(
                0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, libc::PR_GET_NAME as u64,
            )?,
        ])?,
        SeccompRule::new(vec![
            seccompiler::SeccompCondition::new(
                0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, libc::PR_SET_DUMPABLE as u64,
            )?,
        ])?,
        SeccompRule::new(vec![
            seccompiler::SeccompCondition::new(
                0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, libc::PR_GET_DUMPABLE as u64,
            )?,
        ])?,
    ]);

    // Explicitly NOT allowed (blocked by default action):
    // ptrace, mount, umount2, init_module, finit_module, delete_module,
    // kexec_load, kexec_file_load, perf_event_open, setuid, setgid,
    // setns, unshare, pivot_root, chroot, swapon, swapoff,
    // settimeofday, adjtimex, clock_adjtime, syslog, reboot,
    // acct, sysfs, nfsservctl, ioperm, iopl, create_module,
    // query_module, bdflush, stime, vhangup, modify_ldt, vm86old.

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::KillThread,  // default: kill thread on unknown syscall
        SeccompAction::Allow,       // action on allowlisted syscalls
        std::env::consts::ARCH.try_into()?,
    )?;

    Ok(seccompiler::compile_filter(filter)?)
}
```

### Applying the Filter with prctl

The filter must be applied before the runtime begins executing untrusted code. For a Rust embedder, apply it in the worker thread after spawning but before instantiating the first module:

```rust
// worker_thread.rs
use seccompiler::apply_filter;

fn worker_main(wasm_bytes: Vec<u8>, config: WorkerConfig) -> anyhow::Result<()> {
    // No-new-privileges must be set before seccomp in most configurations.
    // This prevents setuid binaries from regaining privileges.
    unsafe {
        let ret = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        anyhow::ensure!(ret == 0, "PR_SET_NO_NEW_PRIVS failed: {}", std::io::Error::last_os_error());
    }

    // Install the seccomp filter. After this point, any blocked syscall
    // kills the calling thread. The engine, store, and instance are created
    // after the filter is in place.
    let filter = build_wasmtime_filter()?;
    apply_filter(&filter)?;

    // Now safe to create the engine and instantiate modules.
    let engine = Engine::new(&make_config())?;
    let mut store = Store::new(&engine, ());
    store.set_fuel(10_000_000)?;

    let module = Module::new(&engine, &wasm_bytes)?;
    let instance = Instance::new(&mut store, &module, &[])?;
    let run_fn = instance.get_typed_func::<(), ()>(&mut store, "run")?;
    run_fn.call(&mut store, ())?;

    Ok(())
}
```

The ordering matters: `PR_SET_NO_NEW_PRIVS` before `PR_SET_SECCOMP`. Without `no_new_privs`, unprivileged processes cannot install strict seccomp filters in some configurations. The engine and store are created after the filter is installed, so even Wasmtime's initialisation code (JIT compiler setup, signal handler installation) runs under the filter. Any unexpected syscall during initialisation will surface immediately in testing, rather than being discovered at runtime under exploitation conditions.

### Adding WASI Network Syscalls

If the workload uses `wasi:sockets`, extend the allowlist:

```rust
// Append to rules in build_wasmtime_filter() before building the filter.
allow!(libc::SYS_socket);
allow!(libc::SYS_connect);
allow!(libc::SYS_bind);
allow!(libc::SYS_listen);
allow!(libc::SYS_accept4);
allow!(libc::SYS_getsockopt);
allow!(libc::SYS_setsockopt);
allow!(libc::SYS_getsockname);
allow!(libc::SYS_getpeername);
allow!(libc::SYS_sendmsg);
allow!(libc::SYS_recvmsg);
allow!(libc::SYS_sendto);
allow!(libc::SYS_recvfrom);
allow!(libc::SYS_shutdown);
```

Do not add network syscalls speculatively. Each addition widens the post-escape attack surface. Profile the actual workload: if the module never calls `wasi:sockets`, Wasmtime never reaches those syscalls, and they should be absent from the allowlist.

## Docker's Default seccomp Profile and WASM

Docker ships a default seccomp profile that blocks roughly 50 high-risk syscalls while allowing the rest. The relevant blocked syscalls for WASM runtime defence include: `ptrace`, `kexec_load`, `kexec_file_load`, `init_module`, `finit_module`, `delete_module`, `mount`, `umount2`, `pivot_root`, `syslog`, `acct`, `settimeofday`, `adjtimex`, `reboot`, `swapon`, `swapoff`, `nfsservctl`, `setdomainname`, `sethostname`, `perf_event_open`, `create_module`, `query_module`, and a number of obsolete or rarely-used calls.

The Docker default profile is a reasonable baseline for WASM containers. It covers the most impactful kernel-exploitation primitives. However, it is permissive by design — it blocks ~50 calls but allows ~350. For WASM workloads, a purpose-built allowlist (permitting only the ~40-50 syscalls Wasmtime actually needs) is significantly tighter.

Running a Wasmtime container under Docker's default profile:

```bash
# Default seccomp is applied automatically; this is explicit.
docker run --security-opt seccomp=/etc/docker/seccomp/default.json \
  --user 65534:65534 \
  --read-only \
  --cap-drop ALL \
  wasmtime-worker:latest wasmtime run /app/module.wasm
```

To use a custom allowlist profile:

```bash
docker run --security-opt seccomp=/etc/docker/seccomp/wasmtime-allowlist.json \
  --user 65534:65534 \
  --read-only \
  --cap-drop ALL \
  wasmtime-worker:latest wasmtime run /app/module.wasm
```

The JSON format for Docker seccomp profiles is defined by the OCI Runtime Spec. An allowlist-style Docker profile for Wasmtime looks like:

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "defaultErrnoRet": 38,
  "syscalls": [
    {
      "names": [
        "mmap", "munmap", "mprotect", "madvise", "brk", "mremap",
        "futex", "clone", "clone3", "set_robust_list", "rseq",
        "sched_getaffinity", "sched_yield",
        "read", "write", "pread64", "pwrite64", "readv", "writev",
        "close", "dup", "dup2", "dup3", "fcntl", "ioctl",
        "pipe2", "eventfd2",
        "openat", "fstat", "newfstatat", "statx", "getdents64", "lseek",
        "unlinkat", "renameat2", "mkdirat", "readlinkat", "ftruncate",
        "fallocate", "fsync", "fdatasync",
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "rt_sigsuspend",
        "getpid", "gettid", "getuid", "geteuid", "getgid", "getegid",
        "uname", "getcwd",
        "clock_gettime", "clock_nanosleep", "nanosleep", "gettimeofday",
        "epoll_create1", "epoll_ctl", "epoll_wait", "poll", "ppoll",
        "select", "pselect6",
        "getrandom",
        "exit", "exit_group",
        "arch_prctl",
        "prctl"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

`SCMP_ACT_ERRNO` with `errnoRet: 38` (ENOSYS) is preferable to `SCMP_ACT_KILL` during initial rollout — a blocked syscall returns an error rather than killing the process, making it easier to detect missed allowlist entries in logs before switching to a hard kill policy.

## Kubernetes seccompProfile for WASM Workloads

Kubernetes supports seccomp profiles at the pod and container level via the `securityContext.seccompProfile` field. For SpinKube or any workload using containerd-shim-spin, the profile applies to the entire shim process that hosts the Spin application.

### Kubernetes Built-in Profiles

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: spin-worker
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault     # Use the container runtime's default profile.
  containers:
    - name: spin-app
      image: ghcr.io/your-org/spin-app:v1.0.0
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        runAsUser: 65534
        capabilities:
          drop: ["ALL"]
```

`RuntimeDefault` maps to containerd's default seccomp profile, which is equivalent to Docker's default profile. For WASM workloads, this is the minimum acceptable level. It blocks `ptrace`, `mount`, and the most dangerous kernel interfaces.

### Custom Profiles via Localhost

For a tighter allowlist, store the profile JSON on the node under `/var/lib/kubelet/seccomp/` and reference it:

```bash
# On each node (or via DaemonSet):
mkdir -p /var/lib/kubelet/seccomp/wasm
cp wasmtime-allowlist.json /var/lib/kubelet/seccomp/wasm/wasmtime-allowlist.json
```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: spin-worker
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: wasm/wasmtime-allowlist.json
  containers:
    - name: spin-app
      image: ghcr.io/your-org/spin-app:v1.0.0
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        runAsUser: 65534
        capabilities:
          drop: ["ALL"]
```

### SpinKube and containerd-shim-spin

When using SpinKube, the shim process (`containerd-shim-spin`) is the Wasmtime host. The `seccompProfile` applied to the pod covers the shim. Profile the shim process specifically — it has slightly different initialisation syscalls compared to the standalone `wasmtime` CLI. In particular, containerd-shim-spin opens Unix domain sockets for containerd communication and uses `sendmsg`/`recvmsg` for the shim protocol; these must be in the allowlist.

The SpinKube `SpinApp` CRD propagates `securityContext` to the underlying pod:

```yaml
apiVersion: core.spinoperator.dev/v1alpha1
kind: SpinApp
metadata:
  name: my-spin-app
spec:
  image: ghcr.io/your-org/spin-app:v1.0.0
  replicas: 3
  executor: containerd-shim-spin
  podTemplateSpec:
    spec:
      securityContext:
        seccompProfile:
          type: Localhost
          localhostProfile: wasm/wasmtime-allowlist.json
      containers:
        - name: spin-app
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            capabilities:
              drop: ["ALL"]
```

## Combining seccomp with Namespaces for WASM Workloads

seccomp operates on the process's syscall numbers; namespaces restrict the resources visible to the process. They are complementary: seccomp says "you cannot call `mount`", namespaces say "even if you could, there is no useful filesystem to mount". Used together, they eliminate different attack paths:

| Control | What it prevents |
|---------|-----------------|
| seccomp allowlist | Blocked syscalls cannot be called at all — no kernel code is executed for them. |
| User namespaces (disabled) | Prevents `unshare(CLONE_NEWUSER)` from creating a new user namespace that grants apparent root inside the namespace. |
| Mount namespace | The WASM process cannot `mount` over sensitive paths even if it somehow calls `mount` (blocked by seccomp anyway). |
| Network namespace | Limits which network interfaces are visible; combined with seccomp blocking `socket`, eliminates network side channels. |
| PID namespace | Limits which processes are visible to the WASM runtime and any escape payload. |

A production WASM worker pod should combine:

```yaml
securityContext:
  seccompProfile:
    type: Localhost
    localhostProfile: wasm/wasmtime-allowlist.json
  # Host namespaces must be false (the defaults):
  hostPID: false
  hostIPC: false
  hostNetwork: false
  runAsNonRoot: true
  runAsUser: 65534
  fsGroup: 65534
```

With `no_new_privs` set in the container's security context (`allowPrivilegeEscalation: false`), the container cannot gain privileges even through setuid executables that might exist in the image. This is also required for seccomp to function correctly — without it, a setuid binary could execute in an elevated context that circumvents the filter.

## Testing seccomp Profiles Without Breaking WASM Execution

Deploying an overly restrictive profile breaks the runtime. The development cycle is: audit → allow → test → tighten → repeat.

### Phase 1: Audit Mode with SCMP_ACT_LOG

Before enforcing the filter, use logging to observe which syscalls fire without blocking them. This requires kernel 4.14+ and audit daemon support:

```json
{
  "defaultAction": "SCMP_ACT_LOG",
  "syscalls": []
}
```

Apply this to the container and run the full workload. Inspect the audit log:

```bash
ausearch -m SECCOMP | grep -oP 'syscall=\K[0-9]+' \
  | xargs -I{} python3 -c "import ctypes; \
      syscall_name = ctypes.CDLL('libseccomp.so.2').seccomp_syscall_resolve_num_arch; \
      print(syscall_name({}))"
```

Or use `scmp_sys_resolver` from the libseccomp package:

```bash
ausearch -m SECCOMP | grep -oP 'syscall=\K[0-9]+' \
  | sort -u \
  | while read n; do scmp_sys_resolver "$n"; done
```

### Phase 2: Warn Mode (SCMP_ACT_ERRNO, watch for ENOSYS)

Switch the default action to `SCMP_ACT_ERRNO` and run the workload. Any blocked syscall returns `ENOSYS` instead of killing the process. Grep the application logs and the system journal for ENOSYS:

```bash
journalctl -u your-wasm-service | grep -i 'enosys\|function not implemented\|SIGSYS'
```

A well-behaved runtime will surface blocked syscalls as error returns rather than silently failing. Wasmtime itself logs unexpected errors at the `error` level. Any `ENOSYS` that surfaces here indicates a syscall that needs to be added to the allowlist.

### Phase 3: Kill Mode (SCMP_ACT_KILL or SCMP_ACT_KILL_PROCESS)

Once the workload runs cleanly under ERRNO mode, switch to kill. `SCMP_ACT_KILL_PROCESS` is preferred over `SCMP_ACT_KILL_THREAD` — it kills the entire process on a blocked syscall, preventing a thread from continuing after an attempted violation.

```bash
# Functional test: the workload must complete correctly.
docker run --security-opt seccomp=wasmtime-allowlist.json \
  wasmtime-worker:latest wasmtime run /app/module.wasm -- test-input
echo "Exit code: $?"  # Must be 0.

# Negative test: a syscall that must be blocked.
docker run --security-opt seccomp=wasmtime-allowlist.json \
  wasmtime-worker:latest \
  bash -c 'strace -e ptrace ls 2>&1 | grep -i "operation not permitted\|killed"'
```

### Automated Profile Validation with oci-seccomp-bpf-hook

The `oci-seccomp-bpf-hook` OCI hook intercepts container execution and uses eBPF to record all syscalls made during a container run, then emits a seccomp profile. This is the lowest-friction approach for generating accurate profiles:

```bash
# Install the hook
dnf install oci-seccomp-bpf-hook  # Fedora/RHEL
# or
apt-get install golang-github-containers-common  # Debian/Ubuntu (packaged differently)

# Run the container with the recorder hook
podman run \
  --annotation io.containers.trace-syscall=of:/tmp/wasmtime-profile.json \
  wasmtime-worker:latest \
  wasmtime run /app/module.wasm -- full-workload-input

# The generated profile is in /tmp/wasmtime-profile.json.
# Review it, then convert to allowlist style and tighten.
```

The generated profile will be an allowlist of exactly the syscalls observed. Do a manual review pass to remove any surprising entries and add comments justifying each allowed syscall. The profile is a security-relevant artefact — it should be reviewed and version-controlled alongside the container image.

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| seccomp allowlist vs. denylist | Allowlist dramatically smaller attack surface; new dangerous syscalls are blocked by default | Higher maintenance burden; runtime upgrades may require profile updates | Pin Wasmtime version; test profile compatibility in CI before upgrading |
| SCMP_ACT_KILL_PROCESS | Immediate containment on blocked syscall | Harder to diagnose; process disappears without a log entry | Use SCMP_ACT_LOG or ERRNO in staging; KILL in production; alert on SIGSYS in container runtime logs |
| Profile per workload type | Tighter profiles per use case (fs-only, network-only, CPU-only) | Operational complexity; more profiles to maintain | Use a base profile and extend per workload type with documented additions |
| Early filter installation (before engine init) | Maximum coverage; even JIT init code is filtered | May block syscalls used only during startup | Profile the startup path specifically; add startup-only syscalls if necessary, or accept slightly wider profile |
| Kubernetes Localhost profiles | Full control over allowed syscall set | Profile must be present on every node | Distribute via DaemonSet ConfigMap sync or node provisioning tooling |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Missing syscall in allowlist | Wasmtime worker killed silently or returns ENOSYS on an operation | Container exits unexpectedly; `journalctl` shows SIGSYS; workload returns errors | Audit with `SCMP_ACT_LOG` first; add the missing syscall to the profile |
| Wasmtime version update adds new syscall | Workers start crashing after image update | Deployment rollout fails; container crash-loops | Pin Wasmtime version; run profile compatibility test in CI as a required check |
| Profile not applied to all containers in pod | Sidecar or init container runs unfiltered | Security audit: `cat /proc/<pid>/status \| grep Seccomp` should show `2` (filter mode) | Apply `seccompProfile` at the pod level, not only the container level |
| `no_new_privs` not set | `setuid` binaries in the image can execute with elevated context bypassing seccomp | Check `allowPrivilegeEscalation: false` in security context | Always set `allowPrivilegeEscalation: false`; verify with admission webhook |
| Profile stored only on some nodes | Pod fails to schedule on nodes missing the profile | Pods stuck in `Pending` with `seccomp profile not found` event | DaemonSet to distribute profiles; or use OCI Image-embedded profiles (Kubernetes 1.32+ alpha) |
| Audit logging generates excessive volume | Node audit log fills up | Disk pressure on nodes running WASM with SCMP_ACT_LOG | Use SCMP_ACT_LOG only in staging; switch to SCMP_ACT_ERRNO and KILL in production |

## Related Articles

- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [WASM Isolation vs Container Isolation](/articles/wasm/wasm-isolation-vs-container-isolation/)
- [WASM Workloads on Kubernetes](/articles/wasm/wasm-on-kubernetes/)
- [WASI Preview 2 Capability-Based Security](/articles/wasm/wasi-preview-2-capabilities/)
- [Wasmtime Aarch64 Sandbox Escape](/articles/wasm/wasmtime-aarch64-sandbox-escape/)
