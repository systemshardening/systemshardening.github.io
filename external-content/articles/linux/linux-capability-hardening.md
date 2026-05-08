---
title: "Linux Capability Hardening: Dropping Privileges from Daemons and Services"
description: "Ambient capabilities, CapDrop in systemd units, auditing capability use with auditd and bpftrace. Least-privilege for services that run as root by legacy necessity."
slug: "linux-capability-hardening"
date: 2026-04-29
lastmod: 2026-04-29
category: "linux"
tags: ["capabilities", "linux", "systemd", "privilege", "hardening"]
personas: ["security-engineer", "platform-engineer", "systems-engineer"]
article_number: 231
difficulty: "intermediate"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/linux/linux-capability-hardening/index.html"
---

# Linux Capability Hardening: Dropping Privileges from Daemons and Services

## Problem

Historically, root was binary: you either had all privileges or none. Linux capabilities split root into 38 discrete permissions — `CAP_NET_BIND_SERVICE`, `CAP_SYS_PTRACE`, `CAP_KILL`, and 35 others — so a process can hold exactly the subset it needs.

In practice, most services still run with the full root capability set. The pattern: a daemon was written to run as root (because it needed to bind port 80, or write to `/proc`), nobody ever removed the extra capabilities it wasn't using, and it now holds `CAP_SYS_ADMIN`, `CAP_NET_RAW`, `CAP_DAC_OVERRIDE`, and 20 others it will never call. If that daemon is compromised, the attacker inherits all of them.

The specific failure modes in unmanaged deployments:

- Services in systemd units with no `CapabilityBoundingSet=` directive, running with a bounding set of all capabilities.
- Container workloads inheriting the Docker / containerd default set (which includes `CAP_NET_RAW`, `CAP_CHOWN`, `CAP_SETUID`, `CAP_SETGID`, `CAP_SYS_CHROOT`, and others rarely needed by application code).
- Binaries with file capabilities (`setcap`) that are world-readable and executable — any local user can exec them.
- No audit trail of capability use; a compromised service escalating via `CAP_SYS_ADMIN` would go undetected.
- Ambient capabilities misunderstood: non-root child processes can inherit capabilities without a setuid binary, but this is rarely scoped correctly.

The hardening goal is the capability analog of least-privilege: enumerate exactly which capabilities each service requires, drop everything else at the bounding set level, and alert when capabilities outside the expected set are exercised.

**Target systems:** Linux kernel 5.8+ (ambient capabilities stable); systemd 230+ (full `CapabilityBoundingSet=`, `AmbientCapabilities=`, `SecureBits=` support); containerd 1.7+ and Docker 24+.

## Threat Model

- **Adversary 1 — RCE in an over-privileged daemon:** A web application server runs as root with all capabilities. An attacker achieves RCE via a web vulnerability. With `CAP_NET_RAW` they can sniff traffic; with `CAP_SYS_PTRACE` they can attach to any process; with `CAP_SYS_ADMIN` they can mount filesystems and escape namespaces.
- **Adversary 2 — File capability abuse:** A binary has `CAP_NET_BIND_SERVICE` set via `setcap`. An attacker who achieves local code execution can exec that binary, inherit the capability, and bind a listener on a privileged port to intercept traffic.
- **Adversary 3 — Ambient capability escalation:** An application grants ambient capabilities to child processes during a privileged operation. A compromised child process retains those capabilities across exec boundaries unexpectedly.
- **Adversary 4 — Container breakout via `CAP_SYS_ADMIN`:** A container workload retains `CAP_SYS_ADMIN`. The attacker mounts the host filesystem, writes a cron job, escapes.
- **Access level:** Adversary 1 requires application-level RCE. Adversaries 2 and 3 require local shell access. Adversary 4 has container-level execution.
- **Objective:** Escalate from application/container scope to host or other-user scope.
- **Blast radius:** With a full capability set, an RCE is nearly equivalent to an unrestricted root shell. With a minimal capability set, RCE is contained to what the service legitimately does — typically no privilege escalation path remains.

## Configuration

### Step 1: Audit Current Capability Sets

Before dropping anything, establish what each service actually holds and uses.

```bash
# List capabilities for a running process by PID.
grep -E '^Cap' /proc/$(pgrep nginx)/status

# Decode hex capability masks.
capsh --decode=00000000a80425fb

# List all processes with non-empty capability sets.
ps -eo pid,comm,cap_eff --no-headers | awk '$3 != "0000000000000000"'

# Find binaries with file capabilities set.
find / -xdev -not -path '/proc/*' -not -path '/sys/*' \
  -executable -type f 2>/dev/null \
  | xargs -P4 getcap 2>/dev/null
```

The five capability sets per-process:

| Set | Meaning |
|-----|---------|
| `CapInh` | Inheritable — can pass across exec if file also has it |
| `CapPrm` | Permitted — upper bound of effective |
| `CapEff` | Effective — what the kernel checks |
| `CapBnd` | Bounding — hard ceiling; cannot be added back once dropped |
| `CapAmb` | Ambient — inherited by unprivileged children |

The goal: drive `CapBnd` to the minimum, `CapEff` to only what's in active use, `CapAmb` to zero unless explicitly needed.

### Step 2: Identify Required Capabilities

For each service, determine the minimum required set. Common patterns:

| Service type | Typically needed | Can drop |
|-------------|-----------------|---------|
| Web server (nginx, Apache) | `CAP_NET_BIND_SERVICE` (if binding <1024), `CAP_SETUID`, `CAP_SETGID` (for worker process drop) | Everything else |
| Container runtime | `CAP_SETUID`, `CAP_SETGID`, `CAP_MKNOD`, `CAP_SYS_CHROOT`, `CAP_CHOWN`, `CAP_FSETID`, `CAP_FOWNER`, `CAP_SETFCAP`, `CAP_NET_BIND_SERVICE` | `CAP_SYS_ADMIN`, `CAP_NET_RAW`, `CAP_SYS_PTRACE` |
| Database (PostgreSQL) | `CAP_NET_BIND_SERVICE` if port <1024; usually none (runs on 5432) | All, especially `CAP_SYS_ADMIN` |
| DNS resolver (unbound) | `CAP_NET_BIND_SERVICE` (port 53) | Everything else |
| Network packet capture | `CAP_NET_RAW`, `CAP_NET_ADMIN` | All others |
| Custom app listening >1024 | None | All |

Use `strace` to confirm at runtime:

```bash
strace -e trace=process,network -f -p $(pgrep nginx) 2>&1 | grep -E 'capset|prctl.*CAP'
```

Or audit via kernel with `auditd`:

```bash
auditctl -a always,exit -F arch=b64 -S capset -k cap_changes
ausearch -k cap_changes --start today | aureport --summary
```

### Step 3: Harden systemd Service Units

systemd exposes capability controls natively. Add to the `[Service]` section:

```ini
[Service]
# Drop the bounding set to exactly what the service needs.
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID

# Prevent acquiring new capabilities via setuid/setcap exec within the service.
NoNewPrivileges=yes

# If the service runs as a non-root user but needs specific capabilities,
# grant them as ambient capabilities (kernel 4.3+).
User=www-data
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Secure bits: keep caps locked to this unit; prevent inheritance to children.
# SECBIT_NOROOT | SECBIT_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED
SecureBits=keep-caps-locked no-setuid-fixup-locked noroot noroot-locked
```

A minimal hardened nginx unit looks like:

```ini
[Unit]
Description=nginx HTTP server
After=network.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t
ExecStart=/usr/sbin/nginx
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s QUIT $MAINPID

# Capability hardening.
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_CHOWN
NoNewPrivileges=yes

# Additional systemd sandboxing (complements capability drops).
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/nginx /var/run /var/cache/nginx

[Install]
WantedBy=multi-user.target
```

Reload and verify:

```bash
systemctl daemon-reload
systemctl restart nginx
# Confirm the effective caps.
grep CapEff /proc/$(pgrep -f 'nginx: master')/status | xargs capsh --decode=
```

### Step 4: Drop Capabilities in Container Workloads

Docker / containerd accept per-container capability configuration.

**Docker run:**

```bash
# Drop all capabilities then add only what's needed.
docker run --cap-drop ALL \
           --cap-add NET_BIND_SERVICE \
           --security-opt no-new-privileges:true \
           nginx:alpine
```

**Kubernetes Pod spec:**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  containers:
    - name: nginx
      image: nginx:alpine
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
          add:
            - NET_BIND_SERVICE
```

**Enforce via Kyverno policy:**

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-drop-all-capabilities
spec:
  validationFailureAction: Enforce
  rules:
    - name: drop-all-caps
      match:
        any:
          - resources:
              kinds: [Pod]
      validate:
        message: "Containers must drop ALL capabilities."
        pattern:
          spec:
            containers:
              - securityContext:
                  capabilities:
                    drop:
                      - ALL
```

### Step 5: Remove or Scope File Capabilities

File capabilities persist on the binary across all invocations. Audit and minimize:

```bash
# Remove all file capabilities from a binary that no longer needs them.
setcap -r /usr/bin/ping

# Add only what's needed (ping needs CAP_NET_RAW for ICMP).
setcap cap_net_raw+ep /usr/bin/ping

# Verify.
getcap /usr/bin/ping
# Output: /usr/bin/ping = cap_net_raw+ep
```

For system binaries, prefer running as a dedicated low-privilege user with ambient caps in systemd rather than file caps. File caps are sticky to the binary on disk — anyone who can exec the file gains the capability.

Restrict file capability binaries from being world-executable where not needed:

```bash
# Change ping to only be executable by the 'netadmin' group.
chgrp netadmin /usr/bin/ping
chmod 750 /usr/bin/ping
```

### Step 6: Audit Capability Use with bpftrace

To confirm which capabilities a service actually calls (not just holds), trace `cap_capable` kernel calls:

```bash
# Trace all capability checks by process name.
bpftrace -e '
  kprobe:cap_capable {
    printf("%s(%d) cap=%d ret=%d\n", comm, pid, arg2, retval);
  }
' | grep nginx
```

Or use the pre-built BCC tool:

```bash
# capsnoop: print every capability check in real time.
/usr/share/bcc/tools/capable -K
```

This reveals which capabilities the process actually queries at runtime (not just what it holds). Common findings:

- nginx queries `CAP_NET_BIND_SERVICE` once at startup when binding port 80; never queries it again.
- PostgreSQL checks `CAP_SYS_NICE` during startup on some distributions even if it doesn't need it; can be dropped after verification.
- Java applications often check `CAP_SYS_ADMIN` during JVM startup; usually succeeds without it.

### Step 7: Audit Capability Changes with auditd

Detect runtime capability escalation attempts:

```bash
# /etc/audit/rules.d/capabilities.rules
-a always,exit -F arch=b64 -S capset -k capability_change
-a always,exit -F arch=b64 -S prctl -F a0=0x16 -k set_secbits
-w /proc/sys/kernel/cap_last_cap -p w -k cap_boundary_change
```

Alert pattern: a service's process calling `capset` to expand its own capability set is an indicator of exploit activity. Legitimate services set capabilities once (at start, via systemd) and never call `capset` again.

### Step 8: Verify with capsh

After hardening, confirm the resulting process has the expected capability set:

```bash
# Show capabilities of current shell.
capsh --print

# Show capabilities for a specific process.
PID=$(pgrep -f 'nginx: master')
for cap in CapInh CapPrm CapEff CapBnd CapAmb; do
  val=$(grep "^$cap:" /proc/$PID/status | awk '{print $2}')
  echo "$cap: $(capsh --decode=$val)"
done
```

Expected output for a hardened nginx master:

```
CapInh: =
CapPrm: cap_chown,cap_setgid,cap_setuid,cap_net_bind_service
CapEff: cap_chown,cap_setgid,cap_setuid,cap_net_bind_service
CapBnd: cap_chown,cap_setgid,cap_setuid,cap_net_bind_service
CapAmb: =
```

Nothing outside the four declared capabilities appears in the bounding set.

## Expected Behaviour

| Signal | Before hardening | After hardening |
|--------|-----------------|-----------------|
| `CapBnd` for nginx master | All 38 capabilities | `cap_net_bind_service`, `cap_setuid`, `cap_setgid`, `cap_chown` only |
| RCE blast radius | Full root capability set available | Limited to the 4 declared capabilities |
| `CAP_SYS_ADMIN` available to nginx | Yes | No — not in bounding set |
| `CAP_NET_RAW` available to nginx | Yes | No |
| `capset` syscall at runtime | Allowed | Blocked by `NoNewPrivileges=yes` |
| Container default cap set | ~14 Docker-default capabilities | 0 or 1 (explicit add-back only) |

Verify the bounding set shrank:

```bash
grep CapBnd /proc/$(pgrep -f 'nginx: master')/status
# Before: CapBnd: 000001ffffffffff   (all caps)
# After:  CapBnd: 00000000000020e0   (net_bind_service + setuid + setgid + chown)
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Reduced bounding set | Eliminates post-exploit escalation paths via dropped caps | Some services fail to start if a required cap was not identified | Test with `strace` and `bpftrace` before production; gradually tighten. |
| `NoNewPrivileges=yes` | Prevents setuid/setcap binaries from escalating within the service | Breaks services that intentionally exec setuid children (e.g., `su`, `sudo` in init scripts) | Redesign those init scripts; use dedicated systemd units per privilege level. |
| File cap removal from ping/traceroute | Reduces local escalation surface | Breaks tools for non-root users | Wrap in a `ping`-capable group with ambient caps in a wrapper unit. |
| Ambient capabilities | Non-root process can have caps without setuid binary | Ambient caps persist across exec; a child that execs a setuid binary may unexpectedly combine them | Pair with `SecureBits=noroot` to prevent cap re-inheritance via setuid. |
| Kyverno enforcement in k8s | Prevents misconfigured pods from launching | Breaks workloads that haven't been updated | Audit mode first (`audit` vs `enforce`); roll out per namespace. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Required cap not in bounding set | Service fails at startup with `EPERM` on a syscall | `journalctl -u <service>` shows permission denied; `strace` at restart shows which syscall | Add the cap to `CapabilityBoundingSet=`; reload. |
| `NoNewPrivileges` breaks init script | Init script calls `sudo` or another setuid binary; fails silently or with permission error | Service fails post-start exec; check `ExecStartPost` logs | Replace setuid calls in init scripts with explicit systemd unit ordering or systemd-run. |
| Ambient cap leaks to untrusted child | Child process has unexpected capabilities | `bpftrace cap_capable` shows child calling cap checks that should be absent | Audit ambient cap grants; add `SecureBits=noroot-locked` to the parent unit. |
| Pod fails Kyverno admission | Pod cannot schedule; admission webhook rejects | Kubernetes event: `Policy drop-all-caps: validation failed` | Add `capabilities.drop: [ALL]` and explicit `add` to the pod spec. |
| File cap on writable binary | Attacker writes malicious binary at file-cap-path and gains caps | Periodic `find / -xdev -executable | xargs getcap` scan finds unexpected entries | Remove unexpected file caps immediately; audit how binary was replaced. |
| bpftrace shows cap never used | A capability in the set is never queried at runtime | Trace shows no calls to `cap_capable` for a specific cap | Remove it from the bounding set; it's dead weight. |

## Related Articles

- [SELinux Policy for Production Services](/articles/linux/selinux/)
- [AppArmor Profile Development and Enforcement](/articles/linux/apparmor/)
- [Landlock LSM: Filesystem Sandboxing in Linux](/articles/linux/landlock-lsm/)
- [systemd Unit Hardening](/articles/linux/systemd-unit-hardening/)
- [Pod Security Context and Seccomp Profiles](/articles/kubernetes/seccomp-profiles/)
