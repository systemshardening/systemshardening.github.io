---
title: "Linux User Namespace Security: Attack Surface Reduction and Safe Delegation"
description: "Unprivileged user namespaces underpin rootless containers but have enabled dozens of kernel privilege escalation CVEs. Knowing when to restrict them, how to delegate safely, and how to monitor their use is essential."
slug: "linux-user-namespace-security"
date: 2026-04-30
lastmod: 2026-04-30
category: "linux"
tags: ["user-namespaces", "namespaces", "kernel", "containers", "privilege-escalation"]
personas: ["security-engineer", "platform-engineer", "systems-engineer"]
article_number: 271
difficulty: "advanced"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/linux/linux-user-namespace-security/index.html"
---

# Linux User Namespace Security: Attack Surface Reduction and Safe Delegation

## Problem

User namespaces allow an unprivileged process to appear as root within an isolated namespace, mapping its UID/GID to real UIDs outside the namespace. This enables rootless containers (Podman, rootless Docker, rootless Buildah) without requiring a setuid helper binary.

The security trade-off is significant. User namespaces expose a large portion of the kernel's namespace and capability code to unprivileged processes — code that was previously only reachable by root. Since user namespaces were enabled by default in Linux 3.8, they have been the enabling primitive for dozens of kernel privilege escalation CVEs:

- CVE-2022-0185: heap overflow in `legacy_parse_param()` reachable via user namespaces.
- CVE-2022-25636: out-of-bounds write in `nft_fwd_dup_netdev_offload()` — requires `CAP_NET_ADMIN` in a user namespace.
- CVE-2023-0386: FUSE ovlfs SUID privilege escalation via user namespaces.
- CVE-2021-3493: overlayfs privilege escalation via user namespaces (Ubuntu-specific, but demonstrates the pattern).

The pattern: an attacker with unprivileged local access creates a user namespace, gaining capabilities within it, then exploits a kernel vulnerability in the namespace-related code paths that require those capabilities. Without user namespaces, these code paths are unreachable from unprivileged processes.

Specific gaps in unmanaged systems:

- Unprivileged user namespace creation enabled globally (`kernel.unprivileged_userns_clone=1`).
- No monitoring of user namespace creation events; attacker reconnaissance goes undetected.
- Rootless containers used on nodes where rootless is unnecessary (e.g., server infrastructure that doesn't run developer tooling).
- No seccomp profile applied to processes that create user namespaces; post-namespace syscalls are unrestricted.

**Target systems:** Linux kernel 5.12+; Ubuntu 22.04+ (has `kernel.unprivileged_userns_clone` sysctl); RHEL 9+ (`user.max_user_namespaces`); systemd 252+ (delegate user namespace creation to specific services); Podman 4.x (rootless containers with user namespaces).

## Threat Model

- **Adversary 1 — Unprivileged kernel exploit via user namespace:** An attacker with a local shell (e.g., via a web application RCE running as `www-data`) creates a user namespace, gaining `CAP_NET_ADMIN` within it, and exploits a kernel vulnerability in the netfilter or network stack that requires that capability.
- **Adversary 2 — Container escape via overlayfs in user namespace:** A compromised container uses `unshare -Ur` to create a new user namespace, then exploits an overlayfs or FUSE vulnerability reachable from within the namespace to escape the container.
- **Adversary 3 — Rootless container abuse:** A developer running rootless Podman/Docker on a workstation has user namespaces enabled. An attacker with local code execution uses the user namespace capability to reach kernel code paths they couldn't otherwise access.
- **Adversary 4 — UID mapping manipulation:** A process creates a user namespace with a crafted UID mapping that produces unexpected UID 0 in the parent namespace during filesystem operations (historical pattern in overlayfs CVEs).
- **Access level:** All adversaries have unprivileged local code execution (no root required).
- **Objective:** Escalate from unprivileged user to root on the host; escape a container.
- **Blast radius:** With unprivileged user namespaces enabled globally, every kernel CVE in the user namespace code paths is exploitable by any local user. Restricting creation to root reduces the attack surface to processes that already have elevated privilege.

## Configuration

### Step 1: Audit Current User Namespace State

```bash
# Check if unprivileged user namespace creation is enabled.
sysctl kernel.unprivileged_userns_clone
# 1 = enabled (Ubuntu default); 0 = disabled

# Check the maximum number of user namespaces per user.
sysctl user.max_user_namespaces
# 0 = disabled; large number = enabled

# List currently existing user namespaces.
lsns -t user
# Shows all user namespaces and the processes using them.

# Count user namespace creation events in the last hour (if auditd enabled).
ausearch -sc unshare --start recent | grep -c "syscall=unshare"

# List processes running inside user namespaces.
ps -eo pid,user,args --no-headers | while read pid user args; do
  ns=$(readlink /proc/$pid/ns/user 2>/dev/null)
  init_ns=$(readlink /proc/1/ns/user 2>/dev/null)
  if [[ -n "$ns" && "$ns" != "$init_ns" ]]; then
    echo "PID $pid ($user): $args [in user namespace: $ns]"
  fi
done
```

### Step 2: Restrict Unprivileged User Namespace Creation

On systems that don't require rootless containers (most production servers), disable unprivileged user namespace creation:

```bash
# Ubuntu/Debian: disable unprivileged user namespace creation.
sysctl -w kernel.unprivileged_userns_clone=0

# Make permanent.
echo "kernel.unprivileged_userns_clone=0" >> /etc/sysctl.d/99-user-namespace-security.conf
sysctl --system

# RHEL/CentOS: use user.max_user_namespaces.
sysctl -w user.max_user_namespaces=0
echo "user.max_user_namespaces=0" >> /etc/sysctl.d/99-user-namespace-security.conf

# Verify.
sysctl kernel.unprivileged_userns_clone
# Expected: kernel.unprivileged_userns_clone = 0

# Test that unprivileged creation is blocked.
sudo -u nobody unshare -Ur /bin/bash -c "whoami"
# Expected: unshare: unshare failed: Operation not permitted
```

Impact assessment before disabling: identify which workloads use user namespaces:

```bash
# Check if any services require user namespaces.
# Rootless Podman/Docker will break.
systemctl list-units --type=service | while read unit _; do
  if systemctl show "$unit" -p ExecStart 2>/dev/null | grep -q "podman\|docker\|buildah\|rootless"; then
    echo "User namespace dependency: $unit"
  fi
done

# Check running processes in user namespaces.
lsns -t user -o PID,COMMAND 2>/dev/null | tail -n +2 | awk '{print $2}' | sort -u
```

### Step 3: Delegate User Namespace Creation to Specific Services

Rather than globally disabling or enabling, systemd can grant user namespace creation to specific services while keeping it disabled for others:

```ini
# /etc/systemd/system/rootless-builder.service
[Service]
# Allow this service to create user namespaces even if globally disabled.
# Available in systemd 252+ and kernels with LSM namespace support.
AmbientCapabilities=CAP_SYS_ADMIN
CapabilityBoundingSet=CAP_SYS_ADMIN
# Or: use UserNamespacePermission (systemd 256+).
# UserNamespacePermission=yes

User=builder
Group=builder

ExecStart=/usr/local/bin/rootless-build.sh
```

For Podman specifically, use `newuidmap` and `newgidmap` setuid helpers rather than global user namespace enablement:

```bash
# These setuid helpers allow specific UID mapping without user namespaces.
# They require /etc/subuid and /etc/subgid entries for the user.
ls -la /usr/bin/newuidmap /usr/bin/newgidmap
# Should be -rwsr-xr-x (setuid root)

# Configure /etc/subuid and /etc/subgid for the builder user.
echo "builder:100000:65536" >> /etc/subuid
echo "builder:100000:65536" >> /etc/subgid

# Rootless Podman works without global user namespace enablement
# when newuidmap/newgidmap are present and /etc/subuid is configured.
sudo -u builder podman run --rm alpine whoami
# Should work without kernel.unprivileged_userns_clone=1.
```

### Step 4: Seccomp Profile for Processes Using User Namespaces

If user namespaces must remain enabled, restrict what the namespaced process can do with seccomp:

```json
// seccomp-user-ns.json — restrict syscalls available after user namespace creation.
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": [
        "unshare",
        "clone",
        "clone3",
        "setuid",
        "setgid",
        "setgroups",
        "newuidmap",
        "newgidmap"
      ],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "names": [
        "mount",
        "umount2",
        "pivot_root"
      ],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1
    },
    {
      "names": [
        "ptrace"
      ],
      "action": "SCMP_ACT_ERRNO"
    }
  ]
}
```

Apply via systemd:

```ini
[Service]
SystemCallFilter=~@mount @reboot @module @privileged
# Even if the process creates a user namespace, these syscalls remain blocked.
```

### Step 5: AppArmor Policy Restricting User Namespace Creation

On Ubuntu, AppArmor can restrict user namespace creation to specific binaries:

```
# /etc/apparmor.d/restrict-user-namespaces
# Block all user namespace creation except from specific trusted binaries.

profile restrict-user-namespaces flags=(attach_disconnected) {
  # Default: deny user namespace creation.
  deny userns,

  # Allow specific trusted processes to create user namespaces.
  ^/usr/bin/podman {
    userns,
    # Additional rules for podman...
  }

  ^/usr/bin/buildah {
    userns,
    # Additional rules for buildah...
  }
}
```

```bash
# Load the AppArmor profile.
apparmor_parser -r /etc/apparmor.d/restrict-user-namespaces

# Verify it's enforcing.
aa-status | grep restrict-user-namespaces
```

Ubuntu 23.10+ supports `kernel.apparmor_restrict_unprivileged_userns`:

```bash
# Restrict user namespace creation via AppArmor (Ubuntu 23.10+).
sysctl -w kernel.apparmor_restrict_unprivileged_userns=1
echo "kernel.apparmor_restrict_unprivileged_userns=1" >> /etc/sysctl.d/99-userns.conf
```

### Step 6: Audit User Namespace Creation with auditd

```bash
# /etc/audit/rules.d/user-namespaces.rules
# Audit all unshare syscalls (used to create user namespaces).
-a always,exit -F arch=b64 -S unshare -F a0&0x10000000 -k user_ns_create
# 0x10000000 = CLONE_NEWUSER flag

# Audit clone syscalls with CLONE_NEWUSER.
-a always,exit -F arch=b64 -S clone -F a0&0x10000000 -k user_ns_create_clone

# Alert on user namespace creation from unexpected users.
auditctl -a always,exit -F arch=b64 -S unshare \
  -F uid!=0 -F uid!=1000 \   # Not root, not the known builder user.
  -k unexpected_user_ns
```

Real-time monitoring:

```bash
# Watch for user namespace creation events.
ausearch -k user_ns_create -i --start today | grep -v "^----" | \
  awk '/type=SYSCALL/ {print}' | grep -v "auid=0"
# Shows non-root user namespace creation events.
```

### Step 7: Telemetry

```
linux_user_namespace_create_total{uid, process}              counter
linux_user_namespace_current_count                           gauge
linux_user_namespace_creation_denied_total{uid, process}     counter
auditd_user_ns_event_total{uid, syscall}                     counter
```

Alert on:

- `linux_user_namespace_create_total` from unexpected UIDs — a non-builder user creating namespaces deserves inspection.
- `linux_user_namespace_current_count` growing unbounded — a process may be creating namespaces without cleaning up (resource exhaustion or exploit attempt).
- Any user namespace creation on a system where `kernel.unprivileged_userns_clone=0` — this indicates a privilege escalation (only root can create them when disabled).

## Expected Behaviour

| Signal | Unrestricted user namespaces | Restricted configuration |
|--------|------------------------------|--------------------------|
| Unprivileged kernel CVE via user namespace | Exploitable by any local user | Blocked; `unshare` returns `EPERM` |
| Rootless Podman (authorised service) | Works | Works (newuidmap/newgidmap or explicit service delegation) |
| `unshare -Ur` from a web shell | Creates namespace; exploit proceeds | Blocked by `kernel.unprivileged_userns_clone=0` |
| User namespace creation audit trail | None | auditd records all creation events with UID and binary |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| `unprivileged_userns_clone=0` | Eliminates the class of user-namespace-enabled kernel exploits | Breaks rootless containers globally | Identify which services need rootless; use newuidmap/newgidmap pattern or service-level delegation. |
| AppArmor restriction | Per-binary policy; rootless works for approved binaries | AppArmor profile maintenance | AppArmor userns restriction is well-supported on Ubuntu; maintain profiles alongside binary updates. |
| Seccomp on namespaced processes | Post-namespace syscall restriction | Must profile each application | Start with a permissive seccomp, add restrictions based on strace output. |
| Audit user namespace creation | Visibility into all namespace events | Audit log volume | Rate-limit audit events; alert on unexpected sources only. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Disabling breaks a CI tool | CI pipeline fails: `unshare: Operation not permitted` | CI failure; `linux_user_namespace_creation_denied_total` rises | Identify the tool; enable for its service user or use newuidmap approach. |
| AppArmor profile denies legitimate binary | Process fails unexpectedly | AppArmor DENIED log entry | Add the binary to the AppArmor profile; reload. |
| User namespace count limit reached | New namespace creation fails; containers don't start | `ENOSPC` on `unshare`; container start errors | Increase `user.max_user_namespaces`; or investigate leak. |
| Audit log flood from high-frequency namespace creation | Log pipeline overwhelmed | Log volume metrics | Rate-limit audit rule with `-F key=user_ns_create -F rate_limit=10` or audit namespaced aggregation. |

## Related Articles

- [Linux Capability Hardening](/articles/linux/linux-capability-hardening/)
- [Seccomp-BPF for Non-Container Workloads](/articles/linux/seccomp-bpf-non-container/)
- [eBPF LSM: Runtime Policy Enforcement](/articles/linux/ebpf-lsm/)
- [Kernel Module Hardening](/articles/linux/kernel-module-hardening/)
- [RuntimeClass: gVisor and Kata Containers](/articles/kubernetes/runtimeclass-gvisor-kata/)
