---
title: "Landlock LSM: Unprivileged Kernel Sandboxing for Production Linux Applications"
description: "Landlock lets an unprivileged process restrict its own filesystem and network access at the kernel level. AppArmor without root, seccomp with semantics."
slug: "landlock-lsm"
date: 2026-04-27
lastmod: 2026-04-27
category: "linux"
tags: ["landlock", "lsm", "sandboxing", "kernel", "linux", "application-security"]
personas: ["systems-engineer", "security-engineer", "platform-engineer"]
article_number: 170
difficulty: "advanced"
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/linux/landlock-lsm/index.html"
---

# Landlock LSM: Unprivileged Kernel Sandboxing for Production Linux Applications

## Problem

Linux has had application sandboxing for two decades. Every existing option requires either privilege or trust:

- **AppArmor and SELinux** — global policies set by the system administrator. Useful for distros and infra teams, but applications cannot ship their own profiles or restrict themselves at runtime without root.
- **seccomp-bpf** — the application can restrict its own syscalls, but only at the syscall layer. Filters cannot express "this process can read `/var/lib/app` but not `/etc/shadow`," because both involve the same `openat(2)` syscall. Path-based access decisions need information seccomp does not have.
- **chroot / mount namespaces / pivot_root** — require `CAP_SYS_ADMIN` or unprivileged user namespaces (which are themselves a class of privilege-escalation surface).
- **gVisor / Firecracker / Kata** — strong isolation but heavy operational footprint; container-runtime, not in-process.

Landlock fills the missing position: an unprivileged, in-process, path- and network-aware sandbox that the application itself defines. A web framework, build tool, or data parser can declare "I will only read these directories, write to these directories, and connect to these ports" and the kernel enforces it for the rest of the process's lifetime — without root, without setuid helpers, without escaping a container runtime.

Stable since Linux 5.13 (June 2021), Landlock has matured through several ABI versions:

- **ABI 1 (5.13):** filesystem read/write/execute restrictions.
- **ABI 2 (5.19):** `LANDLOCK_ACCESS_FS_REFER` (rename / link across hierarchies).
- **ABI 3 (6.2):** `LANDLOCK_ACCESS_FS_TRUNCATE`.
- **ABI 4 (6.7):** network restrictions — `LANDLOCK_ACCESS_NET_BIND_TCP` and `LANDLOCK_ACCESS_NET_CONNECT_TCP`.
- **ABI 5 (6.10):** `LANDLOCK_ACCESS_FS_IOCTL_DEV` for device ioctls.
- **ABI 6 (6.12):** `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` and `LANDLOCK_SCOPE_SIGNAL` to restrict abstract-socket connections and signal delivery.

The specific gaps Landlock closes that nothing else does:

- A single multi-tenant binary (a build runner, a document converter, a code interpreter) can sandbox each request differently, with no namespace setup, no privileged helper, and no fork overhead beyond a few syscalls.
- Library code can sandbox itself before it parses untrusted input, even when the application embedding it forgot to do so.
- Existing applications can be sandboxed by a small wrapper without touching their source. The kernel enforces the policy from process startup.

This article covers the Landlock API, integration patterns for application code, the wrapper approach for unmodified binaries, and the defensive trade-offs versus seccomp and namespace-based isolation.

**Target systems:** Linux kernel 6.7+ for full ABI coverage including network restrictions. Most distributions in 2026 ship 6.6+ (Ubuntu 24.04 ships 6.8, RHEL 10 ships 6.12).

## Threat Model

- **Adversary:** Attacker who has gained code execution inside an application via memory-corruption RCE, deserialization, command injection in a sub-process, or via execution of untrusted user-supplied content (a sandboxed code interpreter, a document parser).
- **Access level:** The application's own UID. No additional Linux capabilities. No control over the host's mount namespaces or seccomp profile.
- **Objective:** Read sensitive files outside the application's working set (`/etc/shadow`, `/proc/self/environ` of other processes, application secrets), write to system locations to gain persistence, connect to external networks for command-and-control or exfiltration.
- **Blast radius:** Without Landlock, the attacker has the full filesystem and network reachable by the application's UID. With Landlock applied, the attacker is restricted to the policy the application declared at startup. The kernel enforces the policy regardless of subsequent syscalls, fork/exec, or library trickery.
- **What Landlock does not protect against:** kernel-level vulnerabilities (a kernel exploit bypasses every LSM), processes that legitimately have `CAP_SYS_ADMIN` (the `LANDLOCK_RESTRICT_SELF_LOG_*` flag does not gate this), or attacks that operate entirely within the policy's allowlist (an SSRF that connects to an allowlisted backend port can still abuse the backend).

## Configuration

### Pattern 1: Application Self-Sandbox (Modify the Source)

For applications under your control, call Landlock during initialization, before any untrusted input is processed.

A minimal C example that restricts the process to read-only access on `/usr` and read-write on `/var/lib/app`:

```c
// landlock_sandbox.c
// Apply a minimal Landlock policy: read-only /usr, read-write /var/lib/app,
// connect TCP only to 127.0.0.1:5432 (database). No other filesystem or
// network access permitted.
#include <linux/landlock.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#ifndef landlock_create_ruleset
static inline int landlock_create_ruleset(
    const struct landlock_ruleset_attr *const attr,
    const size_t size, const __u32 flags) {
    return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif
#ifndef landlock_add_rule
static inline int landlock_add_rule(const int ruleset_fd,
    const enum landlock_rule_type rule_type,
    const void *const rule_attr, const __u32 flags) {
    return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr, flags);
}
#endif
#ifndef landlock_restrict_self
static inline int landlock_restrict_self(const int ruleset_fd, const __u32 flags) {
    return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

#define ALL_FS_ACCESS ( \
    LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE | \
    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | \
    LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE | \
    LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR | \
    LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK | \
    LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
    LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER | \
    LANDLOCK_ACCESS_FS_TRUNCATE | LANDLOCK_ACCESS_FS_IOCTL_DEV)

#define READ_ONLY_FS ( \
    LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | \
    LANDLOCK_ACCESS_FS_READ_DIR)

#define READ_WRITE_FS ( \
    READ_ONLY_FS | LANDLOCK_ACCESS_FS_WRITE_FILE | \
    LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE | \
    LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG | \
    LANDLOCK_ACCESS_FS_TRUNCATE)

static int allow_path(int rs, const char *path, __u64 access) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) return -1;
    struct landlock_path_beneath_attr pb = {
        .allowed_access = access,
        .parent_fd = fd,
    };
    int rc = landlock_add_rule(rs, LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
    close(fd);
    return rc;
}

static int allow_tcp(int rs, __u16 port) {
    struct landlock_net_port_attr np = {
        .allowed_access = LANDLOCK_ACCESS_NET_CONNECT_TCP,
        .port = port,
    };
    return landlock_add_rule(rs, LANDLOCK_RULE_NET_PORT, &np, 0);
}

int sandbox_self(void) {
    struct landlock_ruleset_attr attr = {
        .handled_access_fs = ALL_FS_ACCESS,
        .handled_access_net =
            LANDLOCK_ACCESS_NET_CONNECT_TCP | LANDLOCK_ACCESS_NET_BIND_TCP,
    };
    int rs = landlock_create_ruleset(&attr, sizeof(attr), 0);
    if (rs < 0) {
        perror("landlock_create_ruleset");
        return -1;
    }

    if (allow_path(rs, "/usr", READ_ONLY_FS) < 0) goto fail;
    if (allow_path(rs, "/etc/ssl/certs", READ_ONLY_FS) < 0) goto fail;
    if (allow_path(rs, "/var/lib/app", READ_WRITE_FS) < 0) goto fail;
    if (allow_path(rs, "/var/log/app", READ_WRITE_FS) < 0) goto fail;
    if (allow_tcp(rs, 5432) < 0) goto fail;   /* postgres */
    if (allow_tcp(rs, 53) < 0) goto fail;     /* dns */

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) goto fail;
    if (landlock_restrict_self(rs, 0) < 0) goto fail;

    close(rs);
    return 0;
fail:
    close(rs);
    return -1;
}

int main(int argc, char **argv) {
    if (sandbox_self() < 0) {
        fprintf(stderr, "sandbox setup failed: %s\n", strerror(errno));
        return 1;
    }
    /* Application code runs under Landlock from here. */
    execvp(argv[1], &argv[1]);
    perror("execvp");
    return 1;
}
```

Notes that matter for security:

- `PR_SET_NO_NEW_PRIVS` is required before `landlock_restrict_self`. Without it, a setuid binary would still gain privileges across exec.
- The `handled_access_*` fields declare which access classes the policy controls. Anything not declared is unrestricted (legacy behavior preserved).
- Landlock rules are additive across ruleset stacks. A child process inheriting the policy can only further restrict, never relax.
- Unknown access bits are silently ignored on older kernels. Build the policy by querying the kernel's supported ABI:

```c
int abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
```

Then mask off bits not supported by `abi` to avoid construction errors on older kernels.

### Pattern 2: Wrap an Existing Binary

For binaries you cannot modify (vendored services, shell pipelines, third-party tools), use the [`landlock-rs`](https://github.com/landlock-lsm/rust-landlock) `landlock-cli` wrapper or roll your own:

```bash
# /usr/local/bin/sandboxed-tool
#!/bin/sh
# Wrap `tool` with a Landlock policy before exec.
exec /usr/local/bin/landlock-runner \
  --ro /usr \
  --ro /etc/ssl/certs \
  --rw /var/lib/tool \
  --rw /tmp \
  --connect-tcp 443 \
  -- /usr/local/bin/tool "$@"
```

`landlock-runner` is a small executable that calls the syscalls above and execs into the target. systemd v254+ has direct integration:

```ini
# /etc/systemd/system/myapp.service
[Service]
ExecStart=/usr/local/bin/myapp
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/myapp /var/log/myapp
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
# Landlock-specific (systemd v254+ converts these to Landlock rules where supported).
SocketBindAllow=ipv4:tcp:8080
SocketBindAllow=ipv6:tcp:8080
```

systemd applies AppArmor + seccomp + Landlock based on which the kernel supports, falling back gracefully on older systems.

### Pattern 3: Per-Request Sandboxing Inside a Server

For a long-running server that handles untrusted requests (a markdown renderer, a shell-out command runner, a code interpreter), use Landlock in the per-request fork/exec:

```c
pid_t handle_request(const struct request *req) {
    pid_t pid = fork();
    if (pid != 0) return pid;

    /* In child. Construct a per-request policy. */
    struct landlock_ruleset_attr attr = {
        .handled_access_fs = READ_WRITE_FS,
        .handled_access_net = LANDLOCK_ACCESS_NET_CONNECT_TCP,
    };
    int rs = landlock_create_ruleset(&attr, sizeof(attr), 0);
    /* Allow only this request's working directory. */
    char workdir[PATH_MAX];
    snprintf(workdir, sizeof(workdir),
             "/var/lib/app/jobs/%s", req->job_id);
    allow_path(rs, workdir, READ_WRITE_FS);
    allow_path(rs, "/usr", READ_ONLY_FS);
    /* No network at all for this request. handled_access_net is set, no rules added. */

    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    landlock_restrict_self(rs, 0);
    close(rs);

    execve(req->command, req->argv, req->envp);
    _exit(127);
}
```

Each request gets its own bounded view. A compromised request cannot read another request's working directory because the kernel rejects the `openat`.

## Expected Behaviour

| Signal | Without Landlock | With Landlock |
|--------|------------------|---------------|
| `cat /etc/shadow` from inside the app | Allowed if the app's UID has read access | `EACCES` regardless of UID |
| `connect()` to attacker IP:443 | Allowed | `EACCES` unless port 443 is in allowed list |
| `unlink()` outside allowed paths | Allowed | `EACCES` |
| `fork() + execve()` of a child | Inherits unrestricted | Child inherits the same Landlock policy |
| Re-checking the policy at runtime | N/A | `/proc/self/status` shows `Seccomp` and (since 6.4) Landlock domain count |

Verify the policy is applied:

```bash
# Confirm the process has a Landlock domain.
grep -E "^(Landlock|NoNewPrivs)" /proc/$(pgrep -n myapp)/status
# Landlock_Restrict_Self: 1
# NoNewPrivs:             1
```

```bash
# Negative test — should fail with EACCES.
sudo -u app strace -f -e openat -- /usr/bin/sandboxed-tool cat /etc/shadow 2>&1 | \
  grep shadow
# openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = -1 EACCES (Permission denied)
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Application self-sandbox | Defense-in-depth without infrastructure changes | Source code modifications required | Centralize the sandbox call in a startup-bootstrap library used across services. |
| Wrapper approach | Sandboxes unmodified binaries | Adds a fork+exec hop on startup | Pre-fork in long-running daemons; the cost is one-time. |
| Path-based allowlist | Fine-grained, kernel-enforced | Mounting changes (a new bind mount, a moved log directory) silently break | Treat the policy as part of the deployment manifest; CI test that the application starts under the policy after every change. |
| Network port restrictions | Blocks exfiltration via unexpected ports | DNS over UDP is not currently restricted (Landlock targets TCP first) | Combine with seccomp filters on `socket(AF_INET, SOCK_DGRAM, ...)` to gate UDP, or use NetworkPolicy at the container/cluster level. |
| Layered with seccomp | Two independent kernel mechanisms | Two policies to maintain | Generate both from a shared YAML manifest; reduces drift. |
| Older kernel support | Graceful no-op on unsupported kernels | A 5.10 kernel silently runs unsandboxed | Refuse to start on kernels older than your minimum supported version (5.13 for FS, 6.7 for net). Log the ABI version on startup. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Path moved during deploy without policy update | Application errors with `EACCES`/`ENOENT` after deploy | Application logs show `permission denied` for paths the policy does not cover | Update `allow_path` calls; redeploy. Treat the sandbox manifest as part of the configuration set. |
| Library uses syscall path you did not consider | Specific feature breaks (TLS handshake fails because `/etc/ssl/certs` was missed) | Targeted feature error; not a global crash | Add the path to the allowlist. Use `strace -e openat,connect` against an unsanitized binary to discover paths. |
| Older kernel silently no-op | False sense of security on legacy hosts | `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` returns < expected | Refuse to start; alert deployment automation. The application should not boot under a stale kernel for security-critical sandboxing. |
| Child process inherits restrictive policy unexpectedly | A subprocess (e.g., a debugger, a side-utility) cannot access a path it needs | The subprocess errors; parent runs fine | Decide whether the subprocess needs a different policy (use a separate Landlock domain in a wrapper) or whether the parent's allowlist should expand. |
| Setuid helper escapes the sandbox | A setuid binary called by the application gains privileges | Unexpected privilege escalation in audit logs | `PR_SET_NO_NEW_PRIVS` must be set before `landlock_restrict_self`. The example above does so; verify in your wrapper. |
| Operator misreads `EACCES` as a permission bug | Time wasted toggling UNIX file permissions | `chmod` and `chown` produce no change in behavior | `dmesg \| grep audit: \| grep landlock` shows the rejection — Linux audits Landlock denials when `auditd` is configured. |

## When Seccomp, AppArmor, or Containers Are Better Fits

Landlock is not a universal replacement.

- **Pure syscall filtering with no path semantics:** seccomp is more efficient and well-supported.
- **System-wide policy administered by the operator:** AppArmor or SELinux. Landlock is for self-restriction.
- **Strong isolation across mutually-distrusting tenants:** containers with user namespaces, gVisor, or Firecracker. Landlock is in-process; a kernel exploit defeats it.
- **Mandatory enforcement that the application cannot disable:** AppArmor/SELinux. A compromised application cannot un-Landlock itself, but the operator wants enforcement that survives application bugs.

Use Landlock for *applications opting into safer behavior* — the layer that complements, not replaces, the operator's controls.

## Related Articles

- [Hardening the Linux Kernel Attack Surface with sysctl and Boot Parameters](/articles/linux/sysctl-kernel-hardening/)
- [seccomp Profiles for Kubernetes Workloads](/articles/kubernetes/seccomp-profiles/)
- [AppArmor Profiles for Application Hardening](/articles/linux/apparmor/)
- [SELinux for Production Systems](/articles/linux/selinux/)
- [io_uring Security and Hardening](/articles/linux/io-uring-hardening/)
