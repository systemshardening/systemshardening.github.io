---
title: "Linux File Immutability with chattr: Protecting Critical System Files Against Root Compromise"
description: "chattr +i sets a filesystem-level immutable flag that blocks writes, deletes, renames, and hard links — even for root. Learn how to protect /etc/passwd, SSH config, and log files, automate attribute enforcement at boot, and integrate with auditd and IMA/EVM."
slug: linux-file-immutability-chattr
date: 2026-05-07
lastmod: 2026-05-07
category: linux
tags:
  - chattr
  - file-immutability
  - extended-attributes
  - tamper-prevention
  - intrusion-detection
personas:
  - security-engineer
  - sysadmin
article_number: 485
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/linux/linux-file-immutability-chattr/
---

# Linux File Immutability with chattr: Protecting Critical System Files Against Root Compromise

## The Problem

Unix permission bits protect files from unprivileged users. Root bypasses all of them. A compromised process running as root — through a kernel exploit, a SUID binary bug, or a misconfigured sudo rule — can modify `/etc/passwd` to add a backdoor account, overwrite `/etc/sudoers` to grant unrestricted access, or replace the SSH `authorized_keys` for every user on the system. File permissions are not a defense against a root shell.

The `chattr` immutable flag operates below Unix permissions. It is enforced by the filesystem driver, not by the VFS permission layer, and requires a separate kernel capability (`CAP_LINUX_IMMUTABLE`) to clear. An attacker with a root shell does not automatically have `CAP_LINUX_IMMUTABLE` in a properly confined environment. Even in an unconfined root shell, the immutable flag forces the attacker to make a noisy, auditable call to `chattr -i` before modifying any protected file — buying detection time and leaving evidence.

This is not a complete defense against a determined attacker with unrestricted kernel access. It is a layer: one that is trivially configured, has near-zero performance overhead, and meaningfully raises the cost of stealthy persistence on a compromised system.

**Target systems:** Any Linux with ext2/ext3/ext4, XFS (partial), btrfs (partial). The `e2fsprogs` package provides `chattr` and `lsattr`. The immutable flag is well-established; the kernel interface has been stable since Linux 2.0.

## Threat Model

- **Adversary 1 — Root shell via application exploit:** A web application, database, or container breakout grants an attacker a root process. They attempt to modify `/etc/passwd`, `/etc/shadow`, or `/etc/cron.d/` to establish persistence.
- **Adversary 2 — Privileged lateral movement:** An attacker already has root on one host and is modifying SSH configs or cron jobs to pivot to additional hosts or maintain access after the initial foothold is patched.
- **Adversary 3 — Insider threat:** A privileged operator with root access makes unauthorized changes to authentication configuration outside of change management.
- **Access level:** Full root on the running system. No physical access to the disk, no ability to reboot and modify kernel boot parameters (assumed enforced by GRUB password and UEFI Secure Boot — see [GRUB Boot Hardening](/articles/linux/grub-boot-hardening/) and [UEFI Secure Boot](/articles/linux/linux-uefi-secure-boot-db/)).
- **Objective:** Persistent access via modified authentication files, backdoor accounts, or unauthorized cron jobs.
- **Blast radius without chattr:** Silent modification of any file on the system; changes may go undetected until the next integrity scan (AIDE, Tripwire) which could be hours later.
- **Blast radius with chattr:** Any modification attempt on a protected file is refused with `EPERM`. The attacker must first call `chattr -i`, which is auditable via auditd `FS_SETATTR` rules.

## The +i Flag: Filesystem-Level Immutability

The immutable flag (`+i`) is a filesystem-level attribute stored in the inode, separate from Unix permission bits and POSIX ACLs. When set, the kernel's filesystem driver refuses all of the following operations on the file — regardless of the caller's UID or capability set:

- **Write:** `O_WRONLY` and `O_RDWR` opens fail with `EPERM`.
- **Truncation:** `truncate(2)` and `ftruncate(2)` fail.
- **Deletion:** `unlink(2)` fails; the file cannot be removed.
- **Rename:** `rename(2)` fails; the file cannot be moved.
- **Hard link creation:** `link(2)` fails; no new hard links can point to the inode.
- **Attribute modification:** `chown(2)`, `chmod(2)`, and `setxattr(2)` fail. The inode's metadata is frozen along with its data.
- **Append:** Unlike the `+a` flag, `+i` blocks appending as well as overwriting.

The check happens inside the filesystem driver, not in the VFS layer. This is critical: it means that even a process bypassing normal VFS permission checks (e.g., via a `CAP_DAC_OVERRIDE` capability) will still be blocked — the filesystem driver enforces `CAP_LINUX_IMMUTABLE` specifically.

Clearing the `+i` flag requires `CAP_LINUX_IMMUTABLE`. In a default unconfined root shell, root has all capabilities, so an attacker with full root can clear the flag. The defense value is therefore:

1. **Confinement:** If the compromised process runs in a capability-restricted environment (container with dropped capabilities, SELinux domain without the `chattr` permission, systemd service with `AmbientCapabilities=` restricting the set), `CAP_LINUX_IMMUTABLE` is unavailable and the flag cannot be cleared.
2. **Detection:** Even for unconfined root, every `chattr -i` call is a detectable event. Without the flag, silent modification leaves no audit trail.
3. **Defense in depth:** Combined with auditd, IMA/EVM, and rate-limiting on privilege escalation paths, the window for undetected tampering is reduced to seconds.

### Setting and Checking Flags

```bash
# Set the immutable flag on a single file.
sudo chattr +i /etc/passwd

# Set the immutable flag on multiple files at once.
sudo chattr +i /etc/passwd /etc/shadow /etc/group /etc/gshadow

# Remove the immutable flag (requires CAP_LINUX_IMMUTABLE).
sudo chattr -i /etc/passwd

# Check flags on a file — lsattr is the read counterpart to chattr.
lsattr /etc/passwd
# Output: ----i---------e------- /etc/passwd
# The 'i' in position 5 indicates the immutable flag.
# The 'e' indicates extent-mapped (normal for ext4; ignore it).

# Check all files in a directory (non-recursive).
lsattr /etc/

# Recursive check — useful for auditing an entire directory tree.
lsattr -R /etc/ssh/

# Check a specific set of sensitive files.
lsattr /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config
```

The output format from `lsattr` is a 22-character flag string followed by the filename. Each position corresponds to a specific attribute; the relevant ones are:

| Position | Flag | Meaning |
|----------|------|---------|
| 5        | `i`  | Immutable |
| 6        | `a`  | Append-only |
| 1        | `s`  | Secure deletion (zero on delete) |
| 2        | `u`  | Undeletable (data preserved after unlink) |
| 16       | `e`  | Extents (normal ext4 internal flag) |

### Recursive Application

```bash
# Make all files under /etc/cron.d/ immutable.
# -R applies recursively. Directories themselves also get +i,
# which prevents creating new files inside them.
sudo chattr -R +i /etc/cron.d/

# CAUTION: setting +i on a directory prevents file creation inside it.
# This is useful for locking down cron.d but will break package manager
# operations that write new cron jobs to that path.
# See the "Package Manager Workflow" section below.

# Check that it applied correctly.
lsattr -R /etc/cron.d/
```

## The +a Flag: Append-Only for Log Files

The append-only flag (`+a`) allows a file to be opened for appending but not for overwriting or deletion. It is the correct flag for log files: a logging daemon can write new lines, but an attacker cannot truncate the log to erase evidence.

```bash
# Mark a log file append-only.
sudo chattr +a /var/log/auth.log
sudo chattr +a /var/log/syslog

# Confirm the flag.
lsattr /var/log/auth.log
# Output: -----a--------e------- /var/log/auth.log

# An append-only file accepts appended writes...
echo "test entry" | sudo tee -a /var/log/auth.log   # succeeds

# ...but not truncation or overwriting.
sudo truncate -s 0 /var/log/auth.log     # EPERM
sudo tee /var/log/auth.log < /dev/null   # EPERM (O_WRONLY without O_APPEND)
```

Key operational considerations for `+a`:

- **Log rotation:** Standard `logrotate` with `copytruncate` will fail because it truncates the original. Use the `create` method instead (rename + create new file). However, `rename(2)` also fails on `+a` files that are hardlinked in certain configurations — test your rotation configuration before deploying.
- **journald:** systemd-journald writes to its own binary journal format and does not use `+a` on individual log files. For journald log protection, use `chattr +i` on completed archived journals or rely on remote log shipping.
- **rsyslog/syslog-ng:** These daemons open log files with `O_WRONLY|O_APPEND`, which is compatible with `+a`. Set the flag after the daemon starts and has opened its files, or after confirming the daemon uses `O_APPEND`.

## Files to Protect

A practical baseline for most Linux servers:

```bash
# Authentication and authorization.
sudo chattr +i \
  /etc/passwd \
  /etc/shadow \
  /etc/group \
  /etc/gshadow \
  /etc/sudoers \
  /etc/sudoers.d/

# SSH configuration.
sudo chattr +i \
  /etc/ssh/sshd_config \
  /etc/ssh/ssh_config

# PAM configuration (controls authentication stack).
sudo chattr +i \
  /etc/pam.d/common-auth \
  /etc/pam.d/common-account \
  /etc/pam.d/sshd \
  /etc/pam.d/sudo \
  /etc/pam.d/su

# Scheduled tasks.
sudo chattr +i \
  /etc/crontab \
  /etc/cron.d/ \
  /etc/cron.daily/ \
  /etc/cron.weekly/ \
  /etc/cron.monthly/

# System initialization (prevents persistent backdoors via rc.local or init).
sudo chattr +i /etc/rc.local

# Log files (append-only, not fully immutable).
sudo chattr +a \
  /var/log/auth.log \
  /var/log/secure \
  /var/log/syslog
```

**Do not** set `+i` on:

- `/etc/hosts`, `/etc/resolv.conf`, `/etc/hostname` — these legitimately change on reconfiguration and often on DHCP lease renewal.
- `/etc/motd`, `/etc/issue` — minor but legitimate updates are normal.
- Any file managed by a configuration management system (Ansible, Puppet, Chef) unless you build the unset/reset cycle into the playbook.
- The entirety of `/etc/` recursively without testing — many tools write to `/etc/` as part of normal operation.

## What +i Does NOT Protect Against

Understanding the limitations is as important as understanding the capability:

**Remounting with different options:** If an attacker can reboot the system and modify kernel boot parameters (e.g., by booting from external media or editing GRUB), they can mount the filesystem offline and modify files directly, bypassing the kernel's attribute enforcement entirely. Mitigations: GRUB password, UEFI Secure Boot with locked boot order, LUKS full-disk encryption with TPM sealing (see [LUKS TPM2 Sealing](/articles/linux/luks-tpm2-sealing/)).

**Parent directory deletion:** `chattr +i` on a file prevents deletion of that file, but it does not prevent deletion of the parent directory if the directory itself is not also marked immutable. If `/etc/cron.d/` is not `+i`, an attacker can delete the directory and recreate it with different contents. Always set `+i` on both the directory and its files.

**Bind mounts and overlays:** An attacker with sufficient privileges can create a bind mount that shadows an immutable file with a different file at the same path. The original file remains immutable but the shadow file is served to processes using the overlaid path. Mitigation: restrict `CAP_SYS_ADMIN` in containers and service units; audit new mount operations via auditd.

**Memory-only attacks:** `chattr +i` has no effect on what happens in memory. An attacker can modify the in-memory contents of a running process (e.g., patch `sshd`'s running binary in memory via `/proc/<pid>/mem`) without touching the on-disk file. This is a different attack class requiring a different defense (runtime integrity, process isolation).

**Race conditions in tools:** Some tools check for the immutable flag, temporarily remove it, perform their operation, then re-set it. If an attacker has a race window during that interval, they can write to the file. This is rare in practice but relevant for automated scripts.

**Kernel exploits:** An attacker with a kernel-level exploit (ring-0 code execution) can disable filesystem attribute enforcement entirely. `chattr +i` is a userspace-enforced kernel feature — it does not survive kernel compromise.

## Combination with IMA/EVM

`chattr +i` and IMA/EVM are complementary, not redundant:

| Protection | chattr +i | IMA/EVM |
|---|---|---|
| Prevents writes | Yes | No (detects after the fact) |
| Works without TPM | Yes | Partial (no remote attestation) |
| Survives kernel exploit | No | No |
| Detects offline tampering | No | Yes (EVM HMAC check at boot) |
| Covers execution-time hash | No | Yes (IMA measures at exec) |
| Scope | Named files | All executed files per policy |

The practical combination:

1. Use `chattr +i` on specific high-value configuration files to prevent runtime modification.
2. Use IMA appraisal (with `security.ima` xattrs) to verify that protected binaries have not been replaced between boots.
3. Use EVM to protect IMA's xattrs themselves from offline modification.

```bash
# After setting chattr +i on critical files,
# generate IMA signatures for them so IMA appraisal can verify them at exec.
# (Requires evmctl from the ima-evm-utils package.)
sudo evmctl ima_sign --key /etc/keys/ima-signing.pem /etc/ssh/sshd_config
sudo evmctl ima_sign --key /etc/keys/ima-signing.pem /etc/sudoers

# Verify IMA signature on a file.
sudo evmctl ima_verify /etc/sudoers
```

See [Linux IMA/EVM: Kernel-Level File Integrity Measurement](/articles/linux/linux-ima-evm/) for full IMA/EVM configuration.

## Automating at Boot

Manually setting `chattr +i` is fragile — a reboot, package update, or disk replacement loses the flags. The flags must be re-applied automatically after boot.

### Systemd Oneshot Service (Recommended)

```ini
# /etc/systemd/system/file-immutability.service
[Unit]
Description=Set filesystem immutability flags on critical system files
DefaultDependencies=no
After=local-fs.target
Before=sysinit.target network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/set-immutable-flags.sh

[Install]
WantedBy=sysinit.target
```

```bash
# /usr/local/sbin/set-immutable-flags.sh
#!/bin/bash
set -euo pipefail

IMMUTABLE_FILES=(
  /etc/passwd
  /etc/shadow
  /etc/group
  /etc/gshadow
  /etc/sudoers
  /etc/ssh/sshd_config
  /etc/pam.d/sshd
  /etc/pam.d/sudo
  /etc/pam.d/su
  /etc/crontab
  /etc/rc.local
)

IMMUTABLE_DIRS=(
  /etc/sudoers.d
  /etc/cron.d
  /etc/cron.daily
  /etc/cron.weekly
  /etc/cron.monthly
)

APPEND_ONLY_FILES=(
  /var/log/auth.log
  /var/log/syslog
)

log() { logger -t file-immutability "$*"; }

for f in "${IMMUTABLE_FILES[@]}"; do
  if [[ -f "$f" ]]; then
    chattr +i "$f" && log "Set +i on $f" || log "WARNING: failed to set +i on $f"
  else
    log "WARNING: $f not found, skipping"
  fi
done

for d in "${IMMUTABLE_DIRS[@]}"; do
  if [[ -d "$d" ]]; then
    # Set +i on directory itself AND all files within it.
    chattr +i "$d"
    find "$d" -maxdepth 1 -type f -exec chattr +i {} \;
    log "Set +i on $d and contents"
  fi
done

for f in "${APPEND_ONLY_FILES[@]}"; do
  if [[ -f "$f" ]]; then
    chattr +a "$f" && log "Set +a on $f" || log "WARNING: failed to set +a on $f"
  fi
done
```

```bash
# Install and enable the service.
sudo chmod 750 /usr/local/sbin/set-immutable-flags.sh
sudo chown root:root /usr/local/sbin/set-immutable-flags.sh
sudo systemctl daemon-reload
sudo systemctl enable --now file-immutability.service

# Verify it ran successfully.
sudo systemctl status file-immutability.service
```

The service runs before `sysinit.target`, which means it executes before most daemons start but after the local filesystem is mounted read-write. The `DefaultDependencies=no` prevents circular ordering dependencies during early boot.

### /etc/rc.local Approach

```bash
# /etc/rc.local — simpler but less controllable than systemd.
# Runs late in boot, after all other services.
#!/bin/bash
chattr +i /etc/passwd /etc/shadow /etc/group /etc/sudoers
chattr +i /etc/ssh/sshd_config
chattr +a /var/log/auth.log /var/log/syslog
exit 0
```

`rc.local` runs later in the boot sequence than the systemd oneshot approach, leaving a window between filesystem mount and immutability being set. Prefer the systemd service for production systems.

## Package Manager Workflow

APT and DNF write directly to files in `/etc/` and `/usr/` as part of package installation and upgrade. If those files are immutable, the update will fail:

```
dpkg: error processing package openssh-server (--configure):
 cannot open '/etc/ssh/sshd_config' for writing: Operation not permitted
```

The correct workflow is:

```bash
# 1. Remove immutability before updating.
sudo chattr -i /etc/ssh/sshd_config /etc/pam.d/sshd

# 2. Perform the update.
sudo apt-get install --only-upgrade openssh-server

# 3. Review changes made by the package (important!).
sudo diff /etc/ssh/sshd_config /etc/ssh/sshd_config.dpkg-new 2>/dev/null || true

# 4. Re-apply immutability.
sudo chattr +i /etc/ssh/sshd_config /etc/pam.d/sshd
```

For automated updates (unattended-upgrades, dnf-automatic), the update wrapper must handle this lifecycle. An example pre/post hook for `unattended-upgrades`:

```bash
# /etc/apt/apt.conf.d/98-chattr-hooks
DPkg::Pre-Invoke  { "/usr/local/sbin/chattr-remove-for-update.sh"; };
DPkg::Post-Invoke { "/usr/local/sbin/chattr-restore-after-update.sh"; };
```

```bash
# /usr/local/sbin/chattr-remove-for-update.sh
#!/bin/bash
# Strip immutability from files that package managers may update.
# Called before every dpkg invocation.
MANAGED_BY_PACKAGES=(
  /etc/ssh/sshd_config
  /etc/pam.d/sshd
  /etc/pam.d/sudo
  /etc/sudoers
)
for f in "${MANAGED_BY_PACKAGES[@]}"; do
  [[ -f "$f" ]] && chattr -i "$f"
done
```

```bash
# /usr/local/sbin/chattr-restore-after-update.sh
#!/bin/bash
# Re-apply immutability after dpkg completes.
MANAGED_BY_PACKAGES=(
  /etc/ssh/sshd_config
  /etc/pam.d/sshd
  /etc/pam.d/sudo
  /etc/sudoers
)
for f in "${MANAGED_BY_PACKAGES[@]}"; do
  [[ -f "$f" ]] && chattr +i "$f"
done
```

This approach has a race window: between the pre-invoke hook removing immutability and the post-invoke hook re-applying it, the files are unprotected. For high-security environments, disable unattended upgrades and perform all updates manually with explicit chattr transitions.

## Detecting Tampering

### Auditing Expected Immutable Files

Run periodic checks to verify that expected files still have the immutable flag set. A missing flag indicates either a failed boot service or an attacker who removed it:

```bash
#!/bin/bash
# /usr/local/sbin/audit-immutability.sh
# Run via cron or systemd timer. Exits non-zero if any expected flag is missing.

EXPECTED_IMMUTABLE=(
  /etc/passwd
  /etc/shadow
  /etc/sudoers
  /etc/ssh/sshd_config
  /etc/crontab
)

FAIL=0
for f in "${EXPECTED_IMMUTABLE[@]}"; do
  flags=$(lsattr "$f" 2>/dev/null | awk '{print $1}')
  if [[ "$flags" != *i* ]]; then
    echo "ALERT: $f is missing the immutable flag (flags: ${flags:-not found})" >&2
    FAIL=1
  fi
done

exit "$FAIL"
```

```bash
# Install as a systemd timer for hourly checks.
# /etc/systemd/system/audit-immutability.service
[Unit]
Description=Audit filesystem immutability flags

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/audit-immutability.sh
```

```ini
# /etc/systemd/system/audit-immutability.timer
[Unit]
Description=Hourly immutability audit

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
```

### auditd Rules for chattr Calls

Any call to `chattr` that modifies filesystem attributes is detectable via auditd. The `chattr` command uses the `ioctl(2)` syscall with `FS_IOC_SETFLAGS` to change inode flags:

```bash
# /etc/audit/rules.d/immutability.rules

# Watch for chattr being executed on sensitive paths.
# chattr uses ioctl with FS_IOC_SETFLAGS; detect by watching the binary
# and the target paths for attribute changes.
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr \
  -F dir=/etc -F key=etc-xattr-change

# Watch for ioctl calls that could correspond to chattr operations.
# arch=b64 covers both native 64-bit and 32-bit compat syscalls.
-a always,exit -F arch=b64 -S ioctl \
  -F path=/usr/bin/chattr -F key=chattr-exec

# Audit writes to critical files — catches editors, dd, and other
# direct writes that don't go through a syscall chattr watches.
-w /etc/passwd -p wa -k passwd-change
-w /etc/shadow -p wa -k shadow-change
-w /etc/sudoers -p wa -k sudoers-change
-w /etc/ssh/sshd_config -p wa -k sshd-config-change
-w /etc/crontab -p wa -k crontab-change
-w /etc/cron.d/ -p wa -k crond-change

# Load rules: sudo augenrules --load
```

With these rules in place, any attempt to modify a protected file generates an audit event. Even if the attack succeeds (because the file was temporarily unprotected), the audit log records the event:

```bash
# Search for attempts to modify passwd.
sudo ausearch -k passwd-change --interpret

# Search for chattr executions.
sudo ausearch -k chattr-exec --interpret

# Show all recent EPERM errors on watched paths (failed modification attempts).
sudo ausearch -k passwd-change -sv no --interpret | grep -A5 'EPERM\|EACCES'
```

See [Linux Audit Framework Deep Dive](/articles/linux/auditd-deep-dive/) for full auditd configuration.

## dm-verity vs chattr: When to Use Each

These two mechanisms address different parts of the integrity problem:

| Dimension | chattr +i | dm-verity |
|---|---|---|
| Scope | Individual files, runtime | Entire block device, read-only |
| Granularity | Per-file, selective | All blocks on a partition |
| Writable filesystem | Yes | No (root must be read-only) |
| Survives reboot with modified file | Yes (flag persists in inode) | Yes (block-level hash tree) |
| Bypassed by root (unconfined) | Yes (chattr -i then modify) | No (Merkle root is signed) |
| Operational complexity | Low | High (image builds, A/B partitions) |
| Suitable for /etc changes | Yes (selective immutability) | No (entire partition is read-only) |
| Suitable for immutable OS image | No | Yes |
| Package updates | Manual unset/reset cycle | Full image rebuild |

**Use chattr +i when:**

- You need selective, per-file protection on an otherwise writable filesystem.
- The system runs a conventional Linux distribution where `/etc/` is legitimately writable most of the time.
- You want defense-in-depth around a specific set of files (authentication, SSH, cron) without restructuring the OS.
- Operational simplicity is a constraint.

**Use dm-verity when:**

- You are building an immutable OS image (appliance, container host, edge device).
- You need cryptographic proof that the running system matches a known-good image.
- You are doing remote attestation and need TPM measurements tied to block-level integrity.
- The threat model includes persistent rootkits that survive reboots.

For most production servers running conventional distributions, chattr provides the right trade-off: meaningful protection against the most common persistence techniques, with manageable operational overhead. For high-assurance systems where the threat model includes sophisticated persistent adversaries, dm-verity is the appropriate foundation — with chattr adding defense-in-depth for writable data partitions on top.

## Filesystem Compatibility

`chattr` and `lsattr` from `e2fsprogs` work on:

- **ext2/ext3/ext4:** Full support. All flags work as documented.
- **XFS:** The immutable flag (`+i`) is supported. Append-only (`+a`) is supported. Some other flags are ignored.
- **btrfs:** The immutable flag is supported. Note that btrfs subvolumes can be snapshotted; a snapshot of an immutable file is itself immutable.
- **tmpfs:** The immutable flag is **not** supported. `/tmp` and `/run` are typically tmpfs.
- **overlayfs (container overlay):** The lower layer attributes are honored; the upper layer typically does not propagate `+i` from the lower layer. Do not rely on `chattr +i` for files on overlayfs mount points.
- **NFS:** NFS v4 has limited support; behavior depends on the server's filesystem. Do not rely on `chattr +i` over NFS.

Always verify with `lsattr` after setting flags, especially on less-common filesystems.

## Summary

`chattr +i` is a low-cost, high-signal control. Set it on files where modification is almost never legitimate at runtime: password files, SSH config, sudoers, PAM configuration, and cron tables. Set `+a` on log files to prevent evidence destruction. Automate enforcement via a systemd oneshot service that runs before `sysinit.target`. Pair with auditd rules to detect `chattr -i` calls, creating an audit trail for any attempt to clear the protection.

The flag is not a silver bullet — a fully unconfined root can clear it, and a kernel exploit bypasses it entirely. Its value is in the detection layer it creates and in the effectiveness it has against the most common case: a compromised application process that has escalated to root via a single CVE, lacks `CAP_LINUX_IMMUTABLE` in its capability set, and cannot easily establish persistence against immutable authentication files.

Pair this control with [Linux IMA/EVM](/articles/linux/linux-ima-evm/) for kernel-level measurement of executed files, [auditd](/articles/linux/auditd-deep-dive/) for syscall-level audit coverage, and [dm-verity](/articles/linux/dm-verity/) when the threat model justifies a fully immutable root filesystem.
