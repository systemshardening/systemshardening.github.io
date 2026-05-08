---
title: "Linux Rootkit Detection: rkhunter, Kernel Module Auditing, and Integrity Verification"
description: "Rootkits hide attacker presence by modifying kernel structures, replacing system binaries, and intercepting syscalls. Detecting them requires integrity baselines taken before compromise, kernel module auditing, and tools that operate below the rootkit's hook level."
slug: "rootkit-detection"
date: 2026-05-01
lastmod: 2026-05-01
category: "linux"
tags: ["rootkit", "rkhunter", "integrity", "kernel-modules", "linux-hardening", "forensics"]
personas: ["security-engineer", "platform-engineer", "sre"]
article_number: 287
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/linux/rootkit-detection/index.html"
---

# Linux Rootkit Detection: rkhunter, Kernel Module Auditing, and Integrity Verification

## Problem

A rootkit is software that gives an attacker persistent, hidden access to a compromised system. Linux rootkits work by modifying the kernel's view of the system: hooking syscalls, hiding files and processes from `/proc`, replacing common utilities (`ls`, `ps`, `netstat`), or loading a kernel module that intercepts all security-relevant operations.

The fundamental challenge of rootkit detection is that the tools used for detection run in the same environment the rootkit controls. A rootkit that hooks `getdents64` (directory listing) can hide its own files from `ls`, `find`, and any tool that calls those syscalls. A rootkit that hooks `read` can modify the output of file reads in memory before returning results. Running detection tools from inside a compromised system is inherently unreliable.

Effective rootkit detection requires:

- **Pre-compromise baselines.** Cryptographic hashes of critical binaries, kernel modules, and configuration files taken before compromise — stored off-host — are the only reliable way to detect binary replacement.
- **Out-of-band verification.** Booting from a trusted read-only medium (live USB, rescue instance) bypasses kernel-level hooks. Mounting the compromised disk and scanning from a clean kernel eliminates hook interference.
- **Kernel module inventory.** Legitimate systems have a known set of kernel modules. Unexpected modules — especially those not in the distro package — are a strong indicator of compromise.
- **Multiple detection approaches.** No single tool catches all rootkits. Combining file integrity (IMA/rkhunter), kernel module auditing, network connection verification, and behavioral indicators provides defence-in-depth.

**Target systems:** Ubuntu 22.04+, RHEL 9+, Debian 12+; rkhunter 1.4.6+; Linux IMA (Integrity Measurement Architecture); auditd; systemd; kernel module signing (CONFIG_MODULE_SIG_FORCE).

## Threat Model

- **Adversary 1 — User-space rootkit (binary replacement):** An attacker with root access replaces system binaries (`/bin/ps`, `/bin/ls`, `/sbin/netstat`) with trojaned versions that hide the attacker's processes and network connections. Standard system tools appear to show a clean system.
- **Adversary 2 — Kernel module rootkit (LKM):** An attacker loads a malicious kernel module (LKM) that hooks syscall table entries. The module intercepts `getdents64` to hide files, `kill` to protect attacker processes, and `connect` to hide network connections — all invisibly to user-space tools.
- **Adversary 3 — eBPF rootkit:** An attacker with CAP_BPF loads a malicious eBPF program that hooks tracepoints and kprobes to intercept and modify syscall return values. Unlike LKM rootkits, eBPF rootkits do not appear in `lsmod` output.
- **Adversary 4 — Preload rootkit:** An attacker adds a malicious shared library to `/etc/ld.so.preload`. The library intercepts libc functions (`readdir`, `fopen`, `popen`) in all user-space processes, hiding files and processes.
- **Adversary 5 — Bootkit:** An attacker modifies the bootloader (GRUB) or boot sector to load malicious code before the kernel. The malicious code patches the kernel as it loads, establishing hooks before any security tooling initialises.
- **Access level:** All adversaries have already achieved root. Rootkit detection is the post-compromise detection phase.
- **Objective:** Maintain persistent, hidden access; hide malware, network connections, and exfiltration activity.
- **Blast radius:** An undetected rootkit gives an attacker ongoing access to the host. Duration of access may be months or years before detection.

## Configuration

### Step 1: Pre-Compromise Baseline (Do This Before Incidents)

The most important rootkit detection control is a baseline taken before compromise:

```bash
#!/bin/bash
# /usr/local/sbin/create-integrity-baseline.sh
# Run immediately after provisioning a new host. Store output off-host.

set -euo pipefail
BASELINE_DIR="/var/lib/integrity-baseline"
BASELINE_DATE=$(date +%Y%m%d-%H%M%S)
BASELINE_FILE="${BASELINE_DIR}/baseline-${BASELINE_DATE}.sha256"

mkdir -p "$BASELINE_DIR"

# Hash critical binaries and libraries.
find \
  /bin /sbin /usr/bin /usr/sbin \
  /lib /lib64 /usr/lib /usr/lib64 \
  /boot \
  /etc/passwd /etc/shadow /etc/sudoers /etc/sudoers.d \
  /etc/ld.so.preload /etc/ld.so.conf.d \
  -type f 2>/dev/null | \
  sort | \
  xargs sha256sum > "$BASELINE_FILE"

# Record loaded kernel modules.
lsmod | sort > "${BASELINE_DIR}/modules-${BASELINE_DATE}.txt"

# Record active network connections.
ss -tlnup > "${BASELINE_DIR}/connections-${BASELINE_DATE}.txt"

# Record running processes.
ps auxf > "${BASELINE_DIR}/processes-${BASELINE_DATE}.txt"

# Record SUID/SGID files.
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort \
  > "${BASELINE_DIR}/setuid-${BASELINE_DATE}.txt"

# Sign the baseline with a GPG key (private key stored off-host).
gpg --detach-sign --armor "$BASELINE_FILE"

echo "Baseline created: $BASELINE_FILE"
echo "IMPORTANT: Copy $BASELINE_DIR to off-host secure storage immediately."
```

Ship the baseline to immutable storage immediately:

```bash
# Ship to S3 with Object Lock (cannot be modified or deleted).
aws s3 cp "$BASELINE_DIR/" \
  "s3://security-baselines-${ACCOUNT_ID}/${HOSTNAME}/" \
  --recursive \
  --storage-class COMPLIANCE  # Object Lock COMPLIANCE mode.
```

### Step 2: rkhunter Installation and Configuration

```bash
# Install rkhunter.
apt-get install rkhunter   # Ubuntu/Debian.
dnf install rkhunter       # RHEL/Rocky.

# Update the rootkit database.
rkhunter --update

# Build initial file properties database (run on a known-clean system).
rkhunter --propupd

# Verify the propupd database was created.
ls -la /var/lib/rkhunter/db/rkhunter.dat
```

```bash
# /etc/rkhunter.conf — key configuration options.

# Update mirrors.
UPDATE_MIRRORS=1
MIRRORS_MODE=0

# Enable all tests.
DISABLE_TESTS=""

# Allowlist known-good SUID files.
ALLOWHIDDENDIR=/dev/.udev
ALLOWHIDDENFILE=/dev/.initramfs

# Script allowlist — packages that legitimately install scripts in sensitive paths.
SCRIPTWHITELIST=/usr/bin/groups
SCRIPTWHITELIST=/usr/bin/ldd

# Allowlist expected preloaded libraries (none expected; any entry here is suspicious).
# ALLOWPROCDELFILE=

# Send alerts to syslog.
USE_SYSLOG=authpriv.warning

# Rotate log.
APPEND_LOG=0

# Lock file.
LOCKDIR=/var/lock

# Hash command used for file properties.
HASH_CMD=sha256sum
HASH_FLD_IDX=1
```

```bash
# Run a full check.
rkhunter --check --skip-keypress 2>&1 | tee /var/log/rkhunter-$(date +%Y%m%d).log

# Check exit code: 0 = clean, 1 = warnings, 2 = errors.
echo "Exit code: $?"

# Automated daily check via cron.
cat > /etc/cron.daily/rkhunter << 'EOF'
#!/bin/bash
rkhunter --cronjob --update --quiet
EXIT=$?
if [ $EXIT -ne 0 ]; then
  logger -p security.alert -t rkhunter "rkhunter scan returned exit code $EXIT"
fi
EOF
chmod +x /etc/cron.daily/rkhunter
```

### Step 3: Kernel Module Auditing

Legitimate systems have a known set of kernel modules. Audit for unexpected additions:

```bash
#!/bin/bash
# /usr/local/sbin/audit-kernel-modules.sh

KNOWN_MODULES_FILE="/var/lib/integrity-baseline/modules-known.txt"
CURRENT_MODULES=$(lsmod | awk 'NR>1 {print $1}' | sort)

if [ ! -f "$KNOWN_MODULES_FILE" ]; then
  echo "No baseline found. Creating from current state."
  echo "$CURRENT_MODULES" > "$KNOWN_MODULES_FILE"
  exit 0
fi

KNOWN_MODULES=$(cat "$KNOWN_MODULES_FILE")

# Find modules present now but not in baseline.
UNEXPECTED=$(comm -13 <(echo "$KNOWN_MODULES") <(echo "$CURRENT_MODULES"))

if [ -n "$UNEXPECTED" ]; then
  MSG="ALERT: Unexpected kernel modules loaded: $UNEXPECTED"
  logger -p security.alert -t kernel-module-audit "$MSG"
  echo "$MSG"
  # Investigate each unexpected module.
  for mod in $UNEXPECTED; do
    modinfo "$mod" 2>&1 || echo "modinfo failed for $mod (may be hidden)"
    echo "Loaded by: $(cat /proc/modules | grep "^$mod " || echo 'not in /proc/modules')"
  done
fi

# Enforce kernel module signing (already-running check).
# A signed-only kernel rejects unsigned modules at load time.
cat /proc/sys/kernel/modules_disabled    # 1 = no new modules can load.
```

Enforce signed modules only (prevents loading unsigned LKM rootkits):

```bash
# /etc/sysctl.d/50-module-hardening.conf
# Require signed kernel modules.
# kernel.modules_disabled = 1   # After all legitimate modules loaded — prevents all future loads.

# Check module signing enforcement at boot.
grep CONFIG_MODULE_SIG_FORCE /boot/config-$(uname -r)
# CONFIG_MODULE_SIG_FORCE=y means unsigned modules are rejected at load.
```

```bash
# Lock down module loading after boot (if all required modules are loaded).
echo 1 > /proc/sys/kernel/modules_disabled
# Persist via sysctl.d (after verifying all required modules are loaded at boot).
# WARNING: This is irreversible until reboot. Verify all required modules load at boot first.
```

### Step 4: eBPF Rootkit Detection

eBPF rootkits do not appear in `lsmod` but use the bpf() syscall. Detect them via BPF program enumeration:

```bash
# List all loaded BPF programs.
bpftool prog list

# Expected output on a clean system: only programs from known system daemons.
# Unexpected programs — especially those attached to kprobes/tracepoints — warrant investigation.

# Check BPF programs attached to sensitive hooks.
bpftool prog list | grep -E "kprobe|tracepoint|cgroup"

# List BPF maps (rootkits use maps to store state).
bpftool map list

# Check which processes own BPF programs.
bpftool prog list --json | python3 -c "
import json, sys
progs = json.load(sys.stdin)
for p in progs:
    pid = p.get('pids', [{}])[0].get('pid', 'unknown')
    name = p.get('pids', [{}])[0].get('comm', 'unknown')
    print(f\"PID {pid} ({name}): {p['type']} id={p['id']}\")
"
```

Restrict BPF program loading via seccomp/capabilities:

```bash
# /etc/sysctl.d/50-bpf-hardening.conf
# Restrict unprivileged BPF (requires CAP_BPF for any BPF operation).
kernel.unprivileged_bpf_disabled = 1

# Restrict perf events (used by some eBPF rootkits for initial access).
kernel.perf_event_paranoid = 3
```

### Step 5: ld.so.preload Detection

A preload rootkit injects a library into every process:

```bash
# Check for unexpected preloaded libraries.
check_preload() {
  local PRELOAD_FILE="/etc/ld.so.preload"
  
  if [ -f "$PRELOAD_FILE" ]; then
    CONTENT=$(cat "$PRELOAD_FILE")
    if [ -n "$CONTENT" ]; then
      logger -p security.alert -t preload-check \
        "ALERT: /etc/ld.so.preload is non-empty: $CONTENT"
      echo "SUSPICIOUS: /etc/ld.so.preload contains: $CONTENT"
    fi
  fi

  # Check for hidden preload files.
  # Some rootkits use /etc/.preload or similar hidden paths.
  find /etc -name "*.preload" -o -name ".ld*" 2>/dev/null | while read -r f; do
    echo "SUSPICIOUS: found $f"
    cat "$f"
  done
}

check_preload
```

### Step 6: Out-of-Band Verification

When a rootkit is suspected, mount the system from a clean environment:

```bash
# Mount the potentially compromised disk from a rescue/live environment.
# Boot from a live USB or a forensic image.

# Identify the suspicious disk.
lsblk
fdisk -l /dev/sda

# Mount read-only to prevent modification.
mount -o ro /dev/sda2 /mnt/suspect

# Run rkhunter against the mounted root (bypasses hooks).
rkhunter --rootdir /mnt/suspect --check --skip-keypress

# Compare against the off-host baseline.
# Download baseline from S3.
aws s3 cp "s3://security-baselines/${HOSTNAME}/baseline-latest.sha256" /tmp/baseline.sha256

# Verify against mounted filesystem.
sha256sum --check /tmp/baseline.sha256 --quiet 2>&1 | grep -v "OK$"
# Any lines without "OK" indicate modified files.

# Check for hidden files (bypass kernel hooks by using the clean kernel).
find /mnt/suspect -name ".*" -not -name ".." -not -name "." 2>/dev/null | \
  grep -vE "^/mnt/suspect/(home|root|var/cache|var/log|etc/\\.)" | \
  head -50
```

### Step 7: auditd Rules for Rootkit Indicator Detection

```bash
# /etc/audit/rules.d/40-rootkit-indicators.rules

# Monitor /etc/ld.so.preload modifications.
-w /etc/ld.so.preload -p wa -k rootkit_preload

# Monitor kernel module loading.
-a always,exit -F arch=b64 -S init_module,finit_module -k module_load
-a always,exit -F arch=b64 -S delete_module -k module_unload

# Monitor syscall table modifications (on x86_64, syscall table is at a known address).
# Kernel self-protection (KSPP) makes this harder; audit attempts.
-a always,exit -F arch=b64 -S ptrace -k ptrace_use

# Monitor BPF program loading.
-a always,exit -F arch=b64 -S bpf -k bpf_prog_load

# Monitor writes to /boot (bootkit detection).
-w /boot -p wa -k boot_modification

# Monitor changes to kernel parameters.
-w /etc/sysctl.conf -p wa -k sysctl_change
-w /etc/sysctl.d -p wa -k sysctl_change

# Monitor /proc/sys/kernel modifications.
-w /proc/sys/kernel/modules_disabled -p wa -k modules_lockdown
```

### Step 8: Telemetry

```
rootkit_scan_result{host, tool, status}              gauge (0=clean,1=warning,2=error)
rootkit_unexpected_modules_total{host, module}       counter
rootkit_preload_non_empty{host}                      gauge (1=suspicious)
rootkit_suid_changes_total{host, file}               counter
rootkit_binary_hash_mismatches_total{host, binary}   counter
bpf_programs_loaded{host, type, comm}                gauge
rootkit_scan_last_run_timestamp{host}                gauge
```

Alert on:

- `rootkit_scan_result` > 0 — rkhunter detected warnings or errors; review the full scan log immediately.
- `rootkit_unexpected_modules_total` non-zero — a kernel module not in the baseline is loaded; immediate investigation required.
- `rootkit_preload_non_empty` == 1 — `/etc/ld.so.preload` is non-empty; high-confidence rootkit indicator.
- `rootkit_binary_hash_mismatches_total` non-zero — a critical system binary has been replaced; treat as confirmed compromise.
- `bpf_programs_loaded` with unexpected `comm` — a BPF program loaded by an unexpected process; investigate for eBPF rootkit.
- No `rootkit_scan_last_run_timestamp` update in 25 hours — scheduled scan failed to run.

## Expected Behaviour

| Signal | No detection | Rootkit detection in place |
|--------|-------------|---------------------------|
| Binary replacement | Trojaned `ps` hides attacker processes | Hash mismatch detected against baseline |
| LKM rootkit loaded | Invisible to standard tools | Kernel module audit detects unexpected module |
| ld.so.preload injection | Every process loads malicious library | preload check alerts immediately |
| eBPF rootkit | Not visible in lsmod | bpftool enumeration shows unexpected program |
| Out-of-band scan | Not performed | Rescue boot bypasses hooks; clean-kernel scan reveals hidden files |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Off-host baseline | Reliable comparison; rootkit cannot modify it | Must be created before compromise | Automate baseline creation in provisioning pipeline; store in immutable S3 |
| `modules_disabled = 1` | Prevents LKM rootkit loading after boot | Cannot load any new modules until reboot | Load all required modules at boot via initramfs; then lock |
| rkhunter daily scan | Automated detection | Some rootkits can evade rkhunter | Use multiple tools; combine with IMA for kernel-level verification |
| `kernel.unprivileged_bpf_disabled = 1` | Prevents unprivileged eBPF rootkits | Breaks some observability tools (perf, BCC) | Run observability tools with CAP_BPF explicitly; systemd service capability grants |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Baseline not created before compromise | Cannot reliably detect binary replacement | No hash comparison possible | Use package manager to verify (rpm -V / debsums) as a fallback |
| rkhunter propupd run after compromise | Baseline includes compromised state | Future scans show clean (false negative) | Verify propupd was run on a clean system; compare with package manager hashes |
| Kernel module signing not enforced | Unsigned LKM can load | Unexpected module appears in audit | Enable CONFIG_MODULE_SIG_FORCE; requires reboot with appropriate kernel config |
| Rootkit hides from rkhunter | No alert despite compromise | Only out-of-band scan detects | Treat any anomalous behaviour (unexplained network traffic, CPU usage) as trigger for OOB scan |
| Out-of-band scan inconclusive | Rootkit modifies disk to evade | Forensic analysis of disk image | Take forensic image first; analyse in isolated environment |

## Related Articles

- [Linux IMA and EVM](/articles/linux/linux-ima-evm/)
- [Linux Auditd Deep Dive](/articles/linux/auditd-deep-dive/)
- [eBPF LSM](/articles/linux/ebpf-lsm/)
- [dm-verity for Root Filesystem Integrity](/articles/linux/dm-verity/)
- [Forensic Readiness](/articles/observability/forensic-readiness/)
- [Kernel Module Hardening](/articles/linux/kernel-module-hardening/)
