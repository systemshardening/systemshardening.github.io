---
title: "Linux Core Dump Security Hardening"
description: "Core dumps write a full copy of process memory to disk — including TLS private keys, passwords, session tokens, and cryptographic material. This guide covers disabling core dumps globally and per-service, locking down systemd-coredump, hardening kernel core_pattern, using PR_SET_DUMPABLE, controlling fs.suid_dumpable, and auditing core dump creation with auditd."
slug: linux-core-dump-hardening
date: 2026-05-07
lastmod: 2026-05-07
category: linux
tags:
  - core-dumps
  - memory-security
  - systemd-coredump
  - information-disclosure
  - ulimit
personas:
  - security-engineer
  - platform-engineer
article_number: 486
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/linux/linux-core-dump-hardening/
---

# Linux Core Dump Security Hardening

## The Problem

When a process terminates abnormally — segmentation fault, assertion failure, unhandled signal — the kernel's default behaviour is to write the entire contents of the process's virtual address space to disk. The resulting core file is a faithful snapshot of everything the process held in memory at the moment of death: heap allocations, stack frames, mmapped files, and every byte of every open memory region.

For developers debugging a crash, that completeness is the point. For a production security posture, it is a liability. A single core file from a web server or secrets manager can contain:

- **TLS private keys** — if the process loaded a private key for certificate signing or mTLS, the key material sits in a heap allocation. The core file contains it verbatim.
- **Cleartext passwords and connection strings** — database drivers, message queue clients, and configuration loaders typically hold credentials in memory long after initial authentication.
- **Session tokens and JWTs** — web application processes accumulate tokens across active sessions. A core from a busy application server can expose tokens for every currently-logged-in user.
- **Cryptographic keying material** — HMAC signing keys, symmetric encryption keys, master seeds for key derivation — anything the process loaded for cryptographic operations is present in the dump.
- **In-flight request data** — for services proxying or processing sensitive payloads, a core can expose the contents of requests that were being handled at crash time.

The core file is written with permissions `0400` owned by the user who ran the process, or to a path determined by `/proc/sys/kernel/core_pattern`. On a multi-user system, or any system where an attacker has read access to the core directory, the file becomes a ready-made credential dump. Even on single-user systems, a core file provides an attacker who has gained local access with a durable, offline-analysable copy of process memory — a far richer target than a running process they need to stay attached to.

The threat is not theoretical. Vulnerability researchers and incident response teams routinely recover private keys, session tokens, and plaintext credentials from production core files left on compromised hosts.

**Target systems:** Ubuntu 22.04/24.04 LTS, Debian 12, RHEL 9 / Rocky Linux 9, systemd 249+.

## Threat Model

- **Adversary:** Attacker with local read access to the system — via a web shell, compromised service account, or post-initial-access lateral movement — who is trying to escalate privileges or harvest credentials without further exploiting the running application.
- **Core dump discovery vectors:** Predictable paths (`/var/crash/`, `/tmp/`, `core` in the working directory), systemd journal metadata leaking paths, or access to `/var/lib/systemd/coredump/` on a system where permissions are misconfigured.
- **Exfiltration risk:** Core files are self-contained. A single `scp` or HTTP POST exfiltrates days of credential material without touching the live process.
- **Scope of this guide:** Prevention-first (disable where not needed), access control (restrict where legitimate), detection (alert on unexpected dumps).

---

## Disabling Core Dumps Globally

The highest-confidence approach is to disable core dumps system-wide. Most production servers have no operational need to produce core dumps — crash debugging is done in staging or with live debugging tools like `gdb --pid`.

### PAM / limits.conf

The `pam_limits` module enforces resource limits at login session creation. Setting `core` to `0` prevents any shell session — interactive or service-spawned — from creating core files:

```bash
# /etc/security/limits.conf
# Disable core dumps for all users
*    hard    core    0
*    soft    core    0

# Also target root explicitly
root hard    core    0
root soft    core    0
```

Verify the file is being read by your PAM stack:

```bash
grep pam_limits /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive 2>/dev/null
# Expected: session required pam_limits.so  (or similar)
```

Hard limits prevent users from raising the soft limit beyond the hard cap. Setting both to `0` removes all escape hatches short of root overriding the limit explicitly.

### /etc/profile.d/ for Login Shells

For shells that do not go through PAM (cron jobs started by init, older init systems), add a `ulimit` call to the global shell profile:

```bash
# /etc/profile.d/disable-coredumps.sh
# Disable core dumps in all login shell sessions
ulimit -c 0
```

```bash
chmod 644 /etc/profile.d/disable-coredumps.sh
```

This is belt-and-suspenders: PAM limits cover interactive logins and most service sessions; the profile script covers shells that load `/etc/profile` but bypass PAM.

### systemd system.conf and user.conf

systemd manages the resource limits for all services it supervises. The global default is set in `/etc/systemd/system.conf`:

```ini
# /etc/systemd/system.conf
[Manager]
DefaultLimitCORE=0
```

For user-session services managed by the user systemd instance:

```ini
# /etc/systemd/user.conf
[Manager]
DefaultLimitCORE=0
```

After editing, reload the daemon configuration (note: this takes effect for new units; existing running services need a restart to inherit the new limit):

```bash
systemctl daemon-reexec
```

Verify the global default is applied to a running service:

```bash
systemctl show --property=LimitCORE some-service.service
# Expected: LimitCORE=0
```

### sysctl fs.suid_dumpable

The `fs.suid_dumpable` sysctl controls whether setuid, setgid, and file-capability binaries can produce core dumps. This is separate from `RLIMIT_CORE` — it is a system-wide policy knob.

```bash
# 0 (default on hardened systems): no core dumps from setuid/setgid processes
# 1: core dumps permitted — DANGEROUS, core files may be owned by root but
#    written to a user-writable directory
# 2: core dumps only when core_pattern is an absolute path or pipe handler
#    (systemd-coredump mode); files are owned by root with mode 0600

# Hardened default: disable setuid core dumps entirely
# /etc/sysctl.d/50-coredump.conf
fs.suid_dumpable = 0
```

Apply immediately:

```bash
sysctl -w fs.suid_dumpable=0
```

`fs.suid_dumpable = 1` is the most dangerous value. A setuid binary (e.g., `sudo`, `passwd`) that crashes while running as root will write a core file owned by root to whatever directory `core_pattern` resolves to — potentially a world-readable directory like `/tmp`. With `suid_dumpable=2` and a coredump handler in place, this risk is mitigated but not eliminated.

---

## Per-Service Core Dump Control in systemd

Global defaults are a good baseline, but some services genuinely need crash dumps for debugging — a canary environment, a staging service, or a specific daemon you are actively debugging. systemd lets you override per unit without touching global policy.

### LimitCORE in Service Units

```ini
# /etc/systemd/system/my-service.service
[Service]
# Disable core dumps for this specific service
LimitCORE=0
```

To allow dumps only for a specific service while keeping the global default at 0:

```ini
[Service]
# Allow unlimited core dumps for this service (debugging environment only)
LimitCORE=infinity
```

After editing:

```bash
systemctl daemon-reload
systemctl restart my-service.service
```

Verify the limit took effect:

```bash
# Find the main PID
PID=$(systemctl show -p MainPID --value my-service.service)
# Check limits for that PID
grep -i core /proc/$PID/limits
# Expected: Max core file size          0                    0                    bytes
```

### ProtectSystem and PrivateMemory

For sensitive services, consider additional systemd sandboxing options that work alongside `LimitCORE=0` to reduce the blast radius of any crash-derived information disclosure:

```ini
[Service]
LimitCORE=0
# Make /usr, /boot, /etc read-only from the service's perspective
ProtectSystem=strict
# Mount a private /tmp
PrivateTmp=true
# Restrict address families (reduces surface for network-based exploitation)
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
# Prevent privilege escalation
NoNewPrivileges=true
```

These do not directly prevent core dumps but reduce what secrets are accessible in memory in the first place, limiting the value of any core file that is produced.

---

## Hardening systemd-coredump

On modern systemd systems, `/proc/sys/kernel/core_pattern` is typically set to a pipe handler:

```bash
cat /proc/sys/kernel/core_pattern
# On a stock Ubuntu/Debian system:
# |/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h
```

This hands all core dumps to `systemd-coredump`, which stores them in `/var/lib/systemd/coredump/` (optionally compressed) and writes metadata to the journal. The central collection is better than scattered per-process core files, but it requires explicit configuration to be safe.

### /etc/systemd/coredump.conf

```ini
# /etc/systemd/coredump.conf

[Coredump]
# Storage=none: discard all core dumps immediately after capture (recommended
# for production systems that have no debugging requirement)
Storage=none

# Storage=journal: store compressed core in the journal (volume-limited)
# Storage=external: store compressed core in /var/lib/systemd/coredump/

# If you must retain cores, use journal storage with size limits:
# Storage=journal
# Compress=yes
# ProcessSizeMax=2G
# ExternalSizeMax=2G
# MaxUse=8G
# KeepFree=1G
```

After editing:

```bash
systemctl daemon-reload
# Verify configuration loaded
coredumpctl --no-pager list 2>/dev/null | head -5
```

**`Storage=none` is the correct choice for production.** It means `systemd-coredump` captures the dump, logs the crash metadata (executable path, PID, signal, timestamp) to the journal for incident response, but immediately discards the memory image. You retain crash visibility without the credential exposure risk.

### Permissions on the Coredump Store

If `Storage=external` or `Storage=journal` is in use, verify the storage directory is locked down:

```bash
ls -la /var/lib/systemd/coredump/
# Expected: drwx--x--- 2 root systemd-coredump 4096 ...

# Check that non-root users cannot reach the coredump directory
sudo -u nobody ls /var/lib/systemd/coredump/ 2>&1
# Expected: Permission denied

# Enumerate stored cores (requires coredump group or root)
coredumpctl list
```

The `systemd-coredump` group has read access to stored cores. Audit group membership:

```bash
getent group systemd-coredump
# Only authorised debugging personnel should be members
```

---

## /proc/sys/kernel/core_pattern Security

The `core_pattern` kernel parameter determines where core dumps are written and in what format. It is a frequent source of subtle security issues.

### Pipe Handler Syntax and Trust Boundary

When `core_pattern` starts with `|`, the kernel executes the specified program as root with the core dump piped to its stdin. This is a powerful escalation point if the handler binary is writable or the path can be manipulated:

```bash
# Safe: absolute path to a root-owned, non-writable binary
cat /proc/sys/kernel/core_pattern
# |/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h

# Verify the handler binary is root-owned and not writable by others
stat $(cat /proc/sys/kernel/core_pattern | sed 's/|//;s/ .*//')
# Expected: Uid: 0/root, permissions 0755 or more restrictive
```

A world-writable handler binary would allow any local user to replace it with a script that runs as root on the next crash — a trivial privilege escalation.

### Path-Based core_pattern Risks

If `core_pattern` writes to a path rather than a pipe, directory traversal in the pattern specifiers can create files in unexpected locations:

```bash
# Vulnerable pattern (do not use):
# core_%e_%p
# The %e specifier is the executable name — if an attacker can control the
# process name (e.g., via argv[0] manipulation), they influence the filename.

# Predictable-path risk:
# core  (relative path — core written to process's cwd, which may be /tmp or
#        another world-writable directory)

# Safe options for production:
# 1. Absolute path to a root-owned, mode 700 directory:
#    /var/crash/core.%e.%p.%t
# 2. Pipe to a controlled handler:
#    |/usr/local/sbin/coredump-handler %P %u %e
# 3. Discard entirely (pipe to /bin/false or set RLIMIT_CORE=0):
#    |/bin/false
```

Setting `core_pattern` to discard:

```bash
# Write to /dev/null equivalent — no core file written
echo '|/bin/false' > /proc/sys/kernel/core_pattern

# Persist via sysctl (kernel.core_pattern is a string, not a number)
# /etc/sysctl.d/50-coredump.conf
kernel.core_pattern = |/bin/false
```

Note: `sysctl -w` and `/etc/sysctl.d/` work for `kernel.core_pattern`, but some distributions reset it during systemd startup when `systemd-coredump` is installed. Verify after boot:

```bash
cat /proc/sys/kernel/core_pattern
```

If systemd-coredump resets your value, configure it through `coredump.conf` rather than fighting the sysctl.

---

## PR_SET_DUMPABLE: Per-Process Control

Applications handling sensitive material can opt themselves out of core dump generation at the process level using the `prctl(2)` system call with `PR_SET_DUMPABLE`.

### C/C++ Application Hardening

```c
#include <sys/prctl.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    /* Disable core dumps for this process.
     * 0 = not dumpable; 1 = dumpable (default); 2 = dumpable to root only
     * Setting to 0 also prevents /proc/<pid>/mem and /proc/<pid>/maps from
     * being accessible to other users — a secondary security benefit. */
    if (prctl(PR_SET_DUMPABLE, 0) != 0) {
        perror("prctl(PR_SET_DUMPABLE, 0)");
        /* Non-fatal: log and continue rather than aborting startup */
    }

    /* Load secrets, start listeners, etc. */
    return 0;
}
```

`PR_SET_DUMPABLE` affects not just core dumps but also:

- **`/proc/<pid>/mem` access** — other processes (including debuggers) cannot read the process's memory via the procfs interface.
- **`/proc/<pid>/maps` visibility** — the memory map is hidden from non-root users.
- **ptrace attachment** — combined with `PR_SET_DUMPABLE=0`, a process is significantly harder to introspect from userspace.

Call `prctl(PR_SET_DUMPABLE, 0)` as early as possible in the process lifecycle — before loading any secrets — to ensure the protection is in place before sensitive material enters memory.

Verify the current dumpable state of a running process:

```bash
PID=12345
cat /proc/$PID/status | grep CoreDumping
# CoreDumping: 0  means dumps disabled
# CoreDumping: 1  means dumps enabled
```

### Interaction with setuid/setgid

The kernel automatically clears the dumpable flag when a process executes a setuid or setgid binary (unless `fs.suid_dumpable` overrides this). This means:

- A non-root process running `sudo` or `su` will not produce a core dump by default.
- A root process that calls `setuid(non_root_uid)` will have its dumpable flag cleared until `prctl(PR_SET_DUMPABLE, 1)` is called — important for daemons that drop privileges at startup and then need ptrace debugging.

### Go, Java, and Python Equivalents

Not all runtime environments expose `prctl` directly, but most provide a path to it:

```go
// Go: use syscall.RawSyscall
package main

import (
    "fmt"
    "syscall"
)

func disableCoreDump() error {
    // prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
    _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, 1, 0, 0)
    if errno != 0 {
        return fmt.Errorf("prctl PR_SET_DUMPABLE: %w", errno)
    }
    return nil
}
```

```python
# Python: use ctypes to call prctl
import ctypes
import ctypes.util

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

PR_SET_DUMPABLE = 4
NOT_DUMPABLE = 0

result = libc.prctl(PR_SET_DUMPABLE, NOT_DUMPABLE, 0, 0, 0)
if result != 0:
    raise OSError(ctypes.get_errno(), "prctl(PR_SET_DUMPABLE, 0) failed")
```

For Java processes (JVM), there is no standard API — the JVM does not expose `prctl`. The workaround is to wrap the JVM invocation in a C launcher that calls `prctl` before `execve`, or to rely on `LimitCORE=0` in the systemd unit (which is the more practical approach for JVM services).

---

## Protecting Legitimate Core Dumps

In non-production environments where core dumps are needed for crash analysis, configure storage and access controls to minimise exposure.

### Directory Permissions

```bash
# Dedicated core dump directory, writable only by root
install -d -m 0700 -o root -g root /var/crash/cores

# Set core_pattern to write there
# /etc/sysctl.d/50-coredump.conf
kernel.core_pattern = /var/crash/cores/core.%e.%p.%t
```

Individual core files should be mode `0400` (owner read-only). The kernel honours the process umask when writing core files. Set the umask to `0177` for services that produce debugging dumps:

```ini
# /etc/systemd/system/debug-service.service
[Service]
UMask=0177
LimitCORE=infinity
```

### ACL-Based Access for Debugging Teams

For environments where multiple engineers need core access without all having root:

```bash
# Create a debugging group
groupadd coredump-access

# Set ACL on the cores directory
setfacl -m g:coredump-access:rx /var/crash/cores
# Individual core files inherit the ACL via default ACL:
setfacl -dm g:coredump-access:r /var/crash/cores

# Add engineers to the group
usermod -aG coredump-access engineer1
```

### Encrypted Core Storage

For compliance environments where core dumps must be retained but the secrets exposure risk must be contained, encrypt the storage volume:

```bash
# Option 1: LUKS-encrypted partition for core storage
cryptsetup luksFormat /dev/sdX
cryptsetup luksOpen /dev/sdX coredumps
mkfs.ext4 /dev/mapper/coredumps
mount /dev/mapper/coredumps /var/crash/cores

# Option 2: Use systemd-coredump with Storage=external and encrypt
# the /var/lib/systemd/coredump/ filesystem via LUKS or fscrypt
```

For `systemd-coredump` with journal storage, cores are compressed with zstd by default. This reduces exfiltration risk from a bulk copy of the journal but does not encrypt the content — anyone with journal read access can decompress and analyse the dump.

---

## Auditing Core Dump Creation

Disabling core dumps prevents the credential exposure, but monitoring when core dumps are attempted — or actually produced — provides early warning of crashes that may indicate exploitation attempts (memory corruption bugs, crash-based denial-of-service).

### auditd Rules for Core Dump Events

```bash
# /etc/audit/rules.d/50-coredump.rules

# Watch for changes to core_pattern (tampering with dump destination)
-w /proc/sys/kernel/core_pattern -p w -k coredump_pattern_change

# Watch the systemd-coredump configuration file
-w /etc/systemd/coredump.conf -p w -k coredump_config_change

# Watch the coredump storage directory for new files
-w /var/lib/systemd/coredump/ -p wxa -k coredump_file_created

# Audit prctl calls that modify dumpable state
# (syscall 157 = prctl on x86-64)
-a always,exit -F arch=b64 -S prctl -F a0=4 -k prctl_set_dumpable
```

Load and verify rules:

```bash
augenrules --load
auditctl -l | grep -E 'coredump|prctl'
```

### Parsing auditd Events

When a core dump is created via the pipe handler, look for `COREDUMP` type records in the audit log:

```bash
# Search for core dump events
ausearch -k coredump_file_created --start today --interpret

# Alternatively, via journalctl for systemd-coredump events
journalctl -t systemd-coredump --since "24 hours ago" -o json \
  | jq '{time: .COREDUMP_TIMESTAMP, exe: .COREDUMP_EXE, uid: .COREDUMP_UID, sig: .COREDUMP_SIGNAL}'
```

### Alerting on Unexpected Core Files

For environments where core dumps should never be produced (you set `Storage=none`), alert on any `systemd-coredump` journal entry — each one represents a process crash that warrants investigation:

```bash
# Systemd unit to alert on coredump journal entries
# /etc/systemd/system/coredump-alert.service
[Unit]
Description=Alert on core dump events
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/coredump-alert.sh

[Install]
WantedBy=multi-user.target
```

```bash
# /usr/local/bin/coredump-alert.sh
#!/bin/bash
# Send an alert for each coredump journal entry in the last 5 minutes
journalctl -t systemd-coredump --since "5 minutes ago" --no-pager -o json \
  | while read -r line; do
    EXE=$(echo "$line" | jq -r '.COREDUMP_EXE // "unknown"')
    PID=$(echo "$line" | jq -r '.COREDUMP_PID // "unknown"')
    SIG=$(echo "$line" | jq -r '.COREDUMP_SIGNAL // "unknown"')
    logger -p security.warning -t coredump-alert \
      "Core dump: exe=${EXE} pid=${PID} signal=${SIG}"
    # Extend here to POST to a SIEM webhook or send a PagerDuty alert
  done
```

Trigger this script periodically via a systemd timer or cron:

```bash
# /etc/cron.d/coredump-alert
*/5 * * * * root /usr/local/bin/coredump-alert.sh
```

---

## Complete Hardening Checklist

Apply these settings on every production Linux system. Verify each one after deployment and after kernel or systemd upgrades, which can reset some values.

```bash
#!/bin/bash
# core-dump-hardening-check.sh — verify core dump hardening posture

PASS=0; FAIL=0; WARN=0

check() {
    local label="$1" result="$2" expected="$3"
    if [ "$result" = "$expected" ]; then
        echo "PASS: $label"
        ((PASS++))
    else
        echo "FAIL: $label (got: '$result', want: '$expected')"
        ((FAIL++))
    fi
}

# 1. Global hard limit via limits.conf
HARD_CORE=$(grep -E '^\*\s+hard\s+core' /etc/security/limits.conf \
  | awk '{print $4}' | head -1)
check "limits.conf hard core = 0" "$HARD_CORE" "0"

# 2. sysctl fs.suid_dumpable
SUID_DUMP=$(sysctl -n fs.suid_dumpable)
check "fs.suid_dumpable = 0" "$SUID_DUMP" "0"

# 3. systemd DefaultLimitCORE
DEFAULT_CORE=$(grep -E '^\s*DefaultLimitCORE' /etc/systemd/system.conf \
  | cut -d= -f2 | tr -d ' ')
check "systemd DefaultLimitCORE = 0" "$DEFAULT_CORE" "0"

# 4. coredump.conf Storage=none
STORAGE=$(grep -E '^\s*Storage' /etc/systemd/coredump.conf \
  | cut -d= -f2 | tr -d ' ')
check "coredump.conf Storage = none" "$STORAGE" "none"

# 5. core_pattern safe (pipe to false or absolute path)
PATTERN=$(cat /proc/sys/kernel/core_pattern)
if echo "$PATTERN" | grep -qE '^\|'; then
    HANDLER=$(echo "$PATTERN" | sed 's/^|//;s/ .*//')
    if [ -O "$HANDLER" ] && [ ! -w "$HANDLER" ] && \
       [ "$(stat -c %u "$HANDLER")" = "0" ]; then
        echo "PASS: core_pattern pipe handler is root-owned non-writable"
        ((PASS++))
    else
        echo "WARN: core_pattern handler $HANDLER — verify ownership/permissions"
        ((WARN++))
    fi
else
    echo "WARN: core_pattern uses path '$PATTERN' — verify directory permissions"
    ((WARN++))
fi

# 6. profile.d script present
if [ -f /etc/profile.d/disable-coredumps.sh ]; then
    echo "PASS: /etc/profile.d/disable-coredumps.sh present"
    ((PASS++))
else
    echo "WARN: /etc/profile.d/disable-coredumps.sh not found"
    ((WARN++))
fi

# 7. auditd watching coredump directory
if auditctl -l 2>/dev/null | grep -q coredump; then
    echo "PASS: auditd rules for coredump events present"
    ((PASS++))
else
    echo "WARN: no auditd rules for coredump events"
    ((WARN++))
fi

echo ""
echo "Results: ${PASS} PASS, ${FAIL} FAIL, ${WARN} WARN"
[ "$FAIL" -gt 0 ] && exit 1 || exit 0
```

---

## Summary

Core dump hardening is a depth-of-defence control that is easy to implement and rarely done correctly. The attack surface is straightforward: a process crash on a production system creates a file containing every secret the process held. The mitigations are layered but complementary:

- **Disable globally first.** Set `DefaultLimitCORE=0` in `/etc/systemd/system.conf`, enforce it in `/etc/security/limits.conf`, and add a `/etc/profile.d/` fallback. This eliminates the risk on systems with no crash-debugging requirement.
- **Lock down setuid processes.** `fs.suid_dumpable=0` ensures that even if per-process limits are misconfigured, privileged binaries cannot expose their memory.
- **Configure systemd-coredump defensively.** `Storage=none` discards the memory image while preserving crash metadata in the journal. You retain operational visibility without credential exposure.
- **Harden the core_pattern.** Verify the pipe handler is root-owned and non-writable. Never use a relative path pattern on a production system.
- **Call `prctl(PR_SET_DUMPABLE, 0)` in sensitive daemons.** This is the last line of defence when a service bypasses system-level limits or when a misconfiguration temporarily enables dumps. It also hardens procfs access to the process.
- **Audit and alert.** Use auditd to detect tampering with `core_pattern` and `coredump.conf`, and alert on journal entries from `systemd-coredump` — every crash is a signal that warrants investigation, regardless of whether the dump was stored.

The combined effect is that a process crash on a hardened production system generates a journal entry with metadata (executable, PID, signal, timestamp) and nothing else. Engineers retain enough information to detect, triage, and reproduce the crash in a controlled environment, while the production system does not accumulate files containing TLS keys, passwords, and session tokens in directories that could be read by a local attacker.
