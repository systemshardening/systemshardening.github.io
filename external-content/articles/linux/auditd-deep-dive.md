---
title: "Linux Audit Framework Deep Dive: auditd Rules, auditctl, and ausearch for Security Monitoring"
description: "auditd is the kernel-level audit system on Linux, it captures syscalls, file access, user commands, and privilege changes that no userspace tool can..."
slug: "auditd-deep-dive"
date: 2026-03-08
lastmod: 2026-03-08
category: "linux"
tags: ["auditd", "audit", "linux", "monitoring", "compliance", "forensics"]
personas: ["security-engineer", "systems-engineer"]
article_number: 10
difficulty: "intermediate"
estimated_reading_time: 16
provider_bridges:
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
premium_pack: "auditd-rule-collection"
published: true
layout: article.njk
permalink: "/articles/linux/auditd-deep-dive/index.html"
---

# Linux Audit Framework Deep Dive: [auditd](https://github.com/linux-audit/audit-userspace) Rules, auditctl, and ausearch for Security Monitoring

## Problem

auditd is the kernel-level audit system on Linux, it captures syscalls, file access, user commands, and privilege changes that no userspace tool can see. But raw audit output is cryptic (multi-line records with numeric syscall codes and hex-encoded arguments), rule ordering affects performance, and most teams either log too much (performance impact, storage costs) or too little (miss critical security events).

This article covers rule design, performance-optimised ordering, investigation with `ausearch` and `aureport`, and integration with log shippers for centralized monitoring. For the full pipeline from auditd to centralized storage, see [Building a Security Audit Log Pipeline That Scales: auditd to Elasticsearch](/articles/observability/audit-log-pipeline/)(/articles/observability/audit-log-pipeline/).

**Target systems:** Ubuntu 24.04 LTS, RHEL 9, any Linux with auditd.

## Threat Model

- **Adversary:** Any attacker operating on Linux hosts. Audit logs detect privilege escalation, unauthorized file access, user creation, suspicious process execution, and kernel module loading.

## Configuration

### Rule Design

```bash
# /etc/audit/rules.d/hardening.rules
# Security-relevant audit rules.
# Applied with: sudo augenrules --load

# === Exclusions (performance) - put FIRST ===
# Exclude high-volume, low-value event types
-a always,exclude -F msgtype=CWD
-a always,exclude -F msgtype=EOE
-a always,exclude -F msgtype=PROCTITLE

# === File Integrity Monitoring ===
# Sensitive files: monitor reads and writes
-w /etc/shadow -p rwa -k shadow_access
-w /etc/passwd -p rwa -k passwd_access
-w /etc/group -p rwa -k group_access
-w /etc/sudoers -p rwa -k sudoers_access
-w /etc/sudoers.d -p rwa -k sudoers_access
-w /etc/ssh/sshd_config -p rwa -k sshd_config
-w /root/.ssh -p rwa -k root_ssh_keys

# Cron configuration
-w /etc/crontab -p rwa -k cron_access
-w /etc/cron.d -p rwa -k cron_access
-w /var/spool/cron -p rwa -k cron_access

# === User and Group Changes ===
-w /usr/sbin/useradd -p x -k user_modification
-w /usr/sbin/userdel -p x -k user_modification
-w /usr/sbin/usermod -p x -k user_modification
-w /usr/sbin/groupadd -p x -k group_modification
-w /usr/sbin/groupmod -p x -k group_modification

# === Privilege Escalation ===
# Monitor commands run with elevated privileges (euid=0 but auid!=0)
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k privilege_escalation

# Monitor su and sudo usage
-w /usr/bin/su -p x -k su_usage
-w /usr/bin/sudo -p x -k sudo_usage

# === Process Execution by Users ===
# Log all commands run by real users (auid >= 1000)
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=4294967295 -k user_command

# === Kernel Module Loading ===
-a always,exit -F arch=b64 -S init_module -S finit_module -k module_load
-a always,exit -F arch=b64 -S delete_module -k module_unload

# === Network: Outbound Connections (Optional - High Volume) ===
# Uncomment for high-security environments. Generates significant volume.
# -a always,exit -F arch=b64 -S connect -F a2!=110 -k network_connect

# === Make Rules Immutable (Optional) ===
# After testing: uncomment to prevent rule changes at runtime.
# Requires reboot to modify rules.
# -e 2
```

### auditd.conf Tuning

```ini
# /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log
log_format = ENRICHED
# ENRICHED adds readable names alongside numeric IDs

max_log_file = 50
num_logs = 10
max_log_file_action = rotate

# Backlog limit: kernel buffer size for audit events
# Default 8192 is too low for busy systems
backlog_limit = 32768
# If backlog fills: events are lost (or system halts, depending on failure_mode)

# Space management
space_left = 100
space_left_action = email
admin_space_left = 50
admin_space_left_action = halt
# 'halt' stops the system when disk is full (security > availability)
# Use 'syslog' if availability is more important than audit completeness

# Write frequency (higher = more I/O, less data loss on crash)
freq = 50

# Dispatcher for real-time log shipping
dispatcher = /sbin/audispd
```

### Investigation with ausearch

```bash
# Search by key (the -k tag in rules)
sudo ausearch -k shadow_access --format text
# Shows all accesses to /etc/shadow with human-readable format

# Search by time range
sudo ausearch -ts today -k privilege_escalation
sudo ausearch -ts '2026-04-22 10:00:00' -te '2026-04-22 11:00:00'

# Search by user
sudo ausearch -ua alice
# All events associated with user alice

# Search by syscall (process execution)
sudo ausearch -sc execve -ts recent

# Search by file path
sudo ausearch -f /etc/shadow

# Generate summary reports
sudo aureport --summary
sudo aureport --auth --summary     # Authentication summary
sudo aureport --login --summary    # Login summary
sudo aureport --file --summary     # File access summary
sudo aureport --key --summary      # Events by key
```

### Compliance Mappings

| CIS Control | auditd Rule Key | Rule |
|-------------|----------------|------|
| 4.1.3. Log login/logout events | `logins` | `-w /var/log/faillog -p wa -k logins` |
| 4.1.4. Log session initiation | `session` | `-w /var/run/utmp -p wa -k session` |
| 4.1.6. Log file permission changes | `perm_mod` | `-a always,exit -S chmod -S fchmod -k perm_mod` |
| 4.1.8. Log successful file access | `access` | `-a always,exit -S open -S openat -F exit=-EACCES -k access` |
| 4.1.11. Log privileged commands | `privilege_escalation` | As above, execve with euid=0 |
| 4.1.14. Log user/group changes | `user_modification` | As above, useradd/userdel/usermod |
| 4.1.17. Log kernel module loading | `module_load` | As above, init_module/finit_module |

## Expected Behaviour

- `auditctl -l` shows all rules active
- `auditctl -s` shows `lost = 0` (no events dropped)
- `ausearch -k shadow_access` returns results when /etc/shadow is accessed
- `aureport --key --summary` shows event counts per rule key
- Audit logs rotate automatically (50MB × 10 files = 500MB max local storage)

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Process execution logging (execve) | 1-5GB/day on busy hosts | Storage costs; auditd CPU overhead (1-3%) | Log only user commands (auid >= 1000), not system processes. |
| `backlog_limit = 32768` | Uses ~256KB kernel memory | Negligible on modern systems | Monitor `auditctl -s` lost counter. Increase if events are being lost. |
| Immutable rules (`-e 2`) | Rules cannot be changed at runtime | Requires reboot to update rules | Enable only after thorough testing. Keep the option to reboot quickly. |
| `admin_space_left_action = halt` | System halts when disk is full (preserves audit integrity) | System downtime | Use 'syslog' for availability-first environments. Ship logs off-host to prevent local disk fill. |
| ENRICHED log format | Larger log files (human-readable names added) | 20-30% more disk space per event | Worth it for readability. Or: use RAW format and decode at query time. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| auditd buffer overflow | `auditctl -s` shows `lost > 0` | Monitor lost counter via [Prometheus](https://prometheus.io) textfile exporter | Increase `backlog_limit`. Reduce rule scope on busy hosts. |
| Disk full | auditd stops logging (or system halts if configured) | Disk usage alerts; `space_left_action` triggers | Rotate logs. Ship to external storage. Increase disk. |
| Rules too broad | High CPU from auditd; system performance degradation | `top` shows auditd using >5% CPU; system latency increases | Narrow rules. Remove high-volume rules (network_connect, all file access). |
| Immutable rules prevent emergency change | Need to add/modify rules but `-e 2` is set | `auditctl -e` returns "Audit configuration is locked" | Reboot the system. Modify rules in `/etc/audit/rules.d/`. Reboot applies new rules. |

## When to Consider a Managed Alternative

Audit log volume grows to 1-5GB/host/day. Centralized querying requires a log pipeline ([Building a Security Audit Log Pipeline That Scales: auditd to Elasticsearch](/articles/observability/audit-log-pipeline/)).

- **[Grafana Cloud](https://grafana.com/cloud) or [Axiom](https://axiom.co):** Centralized audit log storage with query capability.
- **[Sysdig](https://sysdig.com):** Host-level security monitoring with built-in audit analysis, replacing the need to build custom audit log pipelines.

**Premium content pack:** auditd rule collection. rule sets for CIS Level 1, CIS Level 2, SOC 2, and NIST 800-53 AU controls. Includes compliance mapping tables and `aureport` analysis scripts.


## Related Articles

- [Hardening the Linux Kernel Attack Surface with sysctl and Boot Parameters](/articles/linux/sysctl-kernel-hardening/)
- [systemd Unit Hardening: ProtectSystem, PrivateTmp, and the Full Sandbox Toolkit](/articles/linux/systemd-unit-hardening/)
- [Cgroup v2 Resource Isolation: Preventing Resource Exhaustion Attacks on Shared Systems](/articles/linux/cgroup-resource-isolation/)
- [Kernel Module Hardening: Blacklisting, Signing, and Preventing Runtime Loading](/articles/linux/kernel-module-hardening/)
- [Automated OS Hardening with Ansible: A Production-Ready Playbook Collection](/articles/linux/ansible-os-hardening/)
