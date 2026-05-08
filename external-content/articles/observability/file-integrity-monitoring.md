---
title: "File Integrity Monitoring with Falco and AIDE: Detecting Unauthorized File Changes"
description: "Deploy a layered file integrity monitoring strategy using AIDE for baseline integrity checks and Falco for real-time detection. Covers AIDE configuration, database initialization, scheduled checks, SIEM integration, Falco fanotify rules for /etc/ and /usr/bin/ writes, combining both tools, Wazuh syscheck as a managed alternative, and handling legitimate change windows."
slug: file-integrity-monitoring
date: 2026-05-07
lastmod: 2026-05-07
category: observability
tags:
  - file-integrity-monitoring
  - aide
  - falco
  - fim
  - host-security
personas:
  - security-engineer
  - platform-engineer
article_number: 560
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/observability/file-integrity-monitoring/
---

# File Integrity Monitoring with Falco and AIDE: Detecting Unauthorized File Changes

## Problem

File integrity monitoring (FIM) is a mandatory control in PCI DSS 11.5.2 and appears in CIS Controls v8 Control 3.3 (data integrity). Every major compliance framework that governs Linux infrastructure requires it, yet implementations frequently fail in one of two ways: they are either too slow to catch active attacks (a nightly AIDE run misses a webshell that was placed and used within the same hour) or too noisy to act on (Falco alerting on every configuration management run produces fatigue that leads to the alerts being ignored).

The threat is concrete. FIM is the primary mechanism for detecting:

- **Rootkit installation**: rootkits replace `/usr/bin/ps`, `/usr/bin/ls`, `/sbin/netstat`, or kernel modules with trojanized versions. A binary replacement is invisible to a running system but is caught immediately by a hash comparison against a known-good baseline.
- **Webshell creation**: a web server vulnerability that results in an attacker writing a PHP or JSP shell to `/var/www/html/` is a FIM event. The file is new, its hash has no entry in the baseline, and Falco sees the `open` syscall with `O_CREAT` the moment it is written.
- **Binary replacement / supply chain staging**: an attacker who has obtained a foothold and wants persistence may replace `/usr/local/bin/some-tool` with a backdoored version. The file modification time, size, and sha256 hash all change.
- **Configuration tampering**: changes to `/etc/sudoers`, `/etc/crontab`, `/etc/pam.d/sshd`, or `/etc/ssh/sshd_config` are a reliable indicator of privilege escalation or persistence.

This article builds a layered FIM strategy: AIDE for scheduled baseline integrity verification (catch anything that slipped through over a period), Falco for real-time detection (alert within seconds of a change), and Wazuh syscheck as a managed alternative for teams already running Wazuh. It also covers the operationally critical question of how to handle legitimate changes without generating noise that erodes trust in the alerts.

**Target systems:** Ubuntu 22.04 / Debian 12 / RHEL 9 with AIDE 0.17+. Falco 0.39+. Wazuh Agent 4.7+.

## Threat Model

- **Adversary:** An attacker who has achieved initial access via an application vulnerability, credential theft, or supply chain compromise and is attempting to establish persistence, escalate privileges, or hide their presence.
- **Detection objective:** Detect file system changes to system binaries, configuration files, and web directories that are inconsistent with known-good baselines or that occur outside of authorized change windows.
- **Blind spots:** FIM does not detect purely in-memory attacks. It does not detect reads of sensitive files (only modifications and creations). AIDE specifically does not detect attacks that occur and are cleaned up between two successive database scans. Address the cleanup-between-scans gap with Falco's real-time coverage.

## Configuration

### AIDE: Baseline Integrity Verification

AIDE (Advanced Intrusion Detection Environment) maintains a database of file attributes and compares the live filesystem against that snapshot on demand. It is the authoritative answer to "has anything changed since we last knew this system was clean?"

#### Installing AIDE

```bash
# Debian / Ubuntu
apt-get install -y aide aide-common

# RHEL / Rocky / AlmaLinux
dnf install -y aide
```

#### Configuring /etc/aide.conf

The default `aide.conf` is usable but monitors too broadly (it includes `/proc` and `/sys` on some distributions, generating enormous false-positive output) and uses attribute groups that are not specific enough to distinguish meaningful changes from routine noise.

A production-hardened configuration:

```
# /etc/aide.conf
# Database paths. Use a read-only location for the reference database
# once initialized; the new database written by --check should be compared
# before being promoted to the reference.
database=file:/var/lib/aide/aide.db.gz
database_out=file:/var/lib/aide/aide.db.new.gz
database_new=file:/var/lib/aide/aide.db.new.gz

# Logging: write a report file in addition to stdout.
report_url=file:/var/log/aide/aide.log
report_url=stdout

# Gzip the database (reduces size on large filesystems).
gzip_dbout=yes

# Attribute group definitions.
# CRITICAL: for binaries and libraries — full cryptographic verification.
CRITICAL = sha256+sha512+size+ftype+inode+uid+gid+p+mtime+ctime

# CONFIG: for configuration files — track permission and ownership changes
# in addition to content changes.
CONFIG = sha256+size+ftype+uid+gid+p+mtime+ctime

# LOG: for log files — track only inode and size, not content (logs grow).
LOG = size+ftype+inode

# PERMS: for directories — ownership and permissions only.
PERMS = ftype+uid+gid+p

# Critical system binaries and libraries
/bin        CRITICAL
/sbin       CRITICAL
/usr/bin    CRITICAL
/usr/sbin   CRITICAL
/usr/lib    CRITICAL
/usr/lib64  CRITICAL
/lib        CRITICAL
/lib64      CRITICAL
/usr/local/bin  CRITICAL
/usr/local/sbin CRITICAL

# Kernel and boot
/boot       CRITICAL
/vmlinuz    CRITICAL
/initrd.img CRITICAL

# System configuration
/etc        CONFIG
!/etc/mtab                  # Changes at boot/mount time — exclude.
!/etc/adjtime               # Changes on NTP sync — exclude.
!/etc/lvm/archive           # LVM state, volatile — exclude.
!/etc/lvm/backup            # LVM state, volatile — exclude.

# PAM and authentication configuration (separate high-priority group)
/etc/pam.d  CRITICAL
/etc/sudoers    CRITICAL
/etc/sudoers.d  CRITICAL
/etc/ssh/sshd_config    CRITICAL
/etc/passwd     CRITICAL
/etc/shadow     CRITICAL
/etc/group      CRITICAL
/etc/gshadow    CRITICAL

# Cron
/etc/cron.d     CONFIG
/etc/cron.daily CONFIG
/etc/cron.weekly    CONFIG
/etc/cron.monthly   CONFIG
/etc/crontab    CRITICAL

# Web directories (webshell detection)
/var/www    CRITICAL
/srv/www    CRITICAL
/usr/share/nginx/html   CRITICAL

# Systemd units (persistence via service installation)
/lib/systemd/system     CONFIG
/etc/systemd/system     CONFIG
/usr/lib/systemd/system CONFIG

# Kernel modules (rootkit detection)
/lib/modules    CRITICAL
/usr/lib/modules    CRITICAL

# Volatile directories — exclude entirely.
!/proc
!/sys
!/dev
!/run
!/tmp
!/var/tmp
!/var/run
!/var/lock
!/var/cache/apt
!/var/cache/yum
!/var/cache/dnf
!/var/log           # Use the LOG group for specific log files only.
!/var/lib/aide      # The AIDE database directory itself.
!/var/spool/mail
!/var/spool/cron
```

Key exclusion rationale:

- `/proc`, `/sys`, `/dev`: pseudo-filesystems with no persistent inodes. Including them causes thousands of false positives on every check.
- `/var/run`, `/tmp`, `/var/tmp`: volatile by design. Monitoring these generates noise on every daemon restart and temp file creation.
- `/var/cache/apt` and package manager caches: these change on every `apt-get update`. If you want to monitor installed package binaries, monitor `/usr/bin` (the install destination) instead.

#### Initialising the Database

The initial database must be created on a known-clean system. Initializing AIDE on a system that is already compromised creates a tampered baseline.

```bash
# Initialize the AIDE database. This scans the entire filesystem
# according to /etc/aide.conf and writes the reference database.
# This operation takes 5–20 minutes depending on filesystem size.
aide --init

# On Debian/Ubuntu the binary may be named aide.wrapper:
aide.wrapper --init

# The database is written to database_out path (/var/lib/aide/aide.db.new.gz).
# Promote it to the reference database:
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# Verify the database was written correctly:
ls -lh /var/lib/aide/aide.db.gz
```

**Protect the reference database.** If an attacker can overwrite `/var/lib/aide/aide.db.gz`, they can update the baseline to include their modifications and defeat AIDE entirely. Store a copy of the initialized database:

- On a read-only network share (NFS export with `ro` mount option).
- In an artifact registry (push the `.gz` to a container registry or S3 bucket with object lock enabled).
- On a dedicated bastion host that the monitored system cannot write to.

#### Running Scheduled Checks via systemd Timer

Do not use cron for AIDE checks. Use systemd timers for reliable execution, logging, and on-failure alerting.

```ini
# /etc/systemd/system/aide-check.service
[Unit]
Description=AIDE File Integrity Check
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/aide --check
# Store the report in a dated file for historical comparison.
StandardOutput=append:/var/log/aide/aide-%Y%m%d.log
StandardError=append:/var/log/aide/aide-%Y%m%d.log
# Alert on failure (non-zero exit = changes detected).
OnFailure=aide-alert.service
```

```ini
# /etc/systemd/system/aide-check.timer
[Unit]
Description=Run AIDE file integrity check every 6 hours

[Timer]
# Run 10 minutes after boot, then every 6 hours.
OnBootSec=10min
OnUnitActiveSec=6h
# Randomize by up to 5 minutes to spread load across a fleet.
RandomizedDelaySec=5min
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
systemctl daemon-reload
systemctl enable --now aide-check.timer

# Verify the timer is scheduled:
systemctl list-timers aide-check.timer
```

#### Parsing AIDE Output and Integrating with a SIEM

AIDE exits with code 0 if no changes are detected, 1 if changes are found, and 2+ for configuration or database errors. The report format is human-readable but needs parsing for SIEM ingestion.

A minimal alerting service that ships AIDE output to a webhook or SIEM:

```bash
#!/bin/bash
# /usr/local/bin/aide-alert.sh
# Called by aide-alert.service on non-zero AIDE exit.

REPORT_FILE="/var/log/aide/aide-$(date +%Y%m%d).log"
HOSTNAME="$(hostname -f)"
WEBHOOK_URL="${AIDE_WEBHOOK_URL:-}"   # Set in environment or /etc/environment

# Parse the AIDE summary lines: Added/Removed/Changed counts.
SUMMARY=$(grep -E "^(Added|Removed|Changed|Total)" "$REPORT_FILE" | tr '\n' ' ')

# Extract changed file paths for SIEM enrichment.
CHANGED_FILES=$(grep -E "^(f|d|l)[+-]" "$REPORT_FILE" | awk '{print $NF}' | head -50)

# Build a JSON payload for the SIEM webhook.
PAYLOAD=$(jq -n \
  --arg host "$HOSTNAME" \
  --arg summary "$SUMMARY" \
  --arg files "$CHANGED_FILES" \
  --arg report "$REPORT_FILE" \
  --arg ts "$(date -Iseconds)" \
  '{
    source: "aide",
    host: $host,
    timestamp: $ts,
    summary: $summary,
    changed_files: ($files | split("\n")),
    report_path: $report,
    severity: "high"
  }'
)

# Ship to SIEM webhook if configured.
if [[ -n "$WEBHOOK_URL" ]]; then
  curl -s -X POST "$WEBHOOK_URL" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD"
fi

# Always write to syslog so the local log aggregation pipeline picks it up.
logger -t aide-fim -p security.warning "AIDE detected filesystem changes: $SUMMARY"
```

For environments using Filebeat or Fluentd, configure them to tail `/var/log/aide/` and apply a multiline codec to reassemble AIDE's report format before forwarding to Elasticsearch or Splunk.

### Falco: Real-Time FIM

AIDE catches changes between scans. Falco catches them the moment they happen. The key difference is detection latency: a 6-hour AIDE cycle means a webshell could be active for up to 6 hours before detection. Falco detects the `open()` call that creates the file within milliseconds.

Falco uses Linux's fanotify interface (wrapped in its eBPF probe) to intercept file system events at the syscall level. The relevant events for FIM are `open` / `openat` / `openat2` with write flags, `rename`, `unlink`, and `chmod` / `chown`.

#### Falco FIM Rules for System Directories

```yaml
# /etc/falco/rules.d/fim-rules.yaml
# File Integrity Monitoring rules for system directories.
# Designed to complement AIDE: catch changes in real time, not just at scan time.

# --- Macro definitions ---

# File write flags: O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND.
# Any open with one of these flags on a sensitive path is an FIM event.
- macro: file_write_or_create
  condition: >
    evt.type in (open, openat, openat2)
    and evt.dir = <
    and (
      evt.arg.flags contains O_WRONLY
      or evt.arg.flags contains O_RDWR
      or evt.arg.flags contains O_CREAT
      or evt.arg.flags contains O_TRUNC
    )

# Known-legitimate writers to /etc: configuration management and package managers.
# Extend this list to match your environment's configuration management tooling.
- macro: known_etc_writers
  condition: >
    proc.name in (
      dpkg, dpkg-reconfigure, apt-get, apt, dnf, yum, rpm,
      puppet, chef-client, ansible-playbook, ansible,
      cfn-init, cloud-init,
      authconfig, authselect, update-ca-certificates,
      adduser, useradd, usermod, groupadd, passwd, chage,
      sshd, pam-auth-update, ldconfig
    )
    or proc.pname in (
      dpkg, apt-get, apt, dnf, yum, rpm
    )

# Known-legitimate writers to system binary directories.
- macro: known_bin_writers
  condition: >
    proc.name in (
      dpkg, apt-get, apt, dnf, yum, rpm,
      make, install, ldconfig, update-alternatives,
      puppet, chef-client, ansible-playbook
    )
    or proc.pname in (
      dpkg, apt-get, apt, dnf, yum, rpm
    )

# Maintenance window suppression macro.
# Set the FIM_MAINTENANCE_WINDOW environment variable on the Falco process
# (or use a Falco plugin-managed list) to suppress alerts during authorized changes.
# This example checks for a sentinel file created by your change management system.
- macro: maintenance_window_active
  condition: >
    proc.env[FIM_MAINTENANCE_WINDOW] = "true"

# --- Rules ---

# Detect writes to /etc/
- rule: Write to /etc/ Directory
  desc: >
    A file in /etc/ was opened for writing or created. Changes to /etc/ can
    indicate configuration tampering, credential theft preparation (modifying
    /etc/passwd or /etc/sudoers), or persistence via cron or PAM modification.
    Legitimate changes should occur only during package installs or authorized
    configuration management runs.
  condition: >
    file_write_or_create
    and fd.name startswith /etc/
    and not fd.name in (/etc/mtab, /etc/adjtime, /etc/.pwd.lock, /etc/resolv.conf)
    and not fd.name glob "/etc/lvm/*"
    and not fd.name glob "/etc/network/run/*"
    and not known_etc_writers
    and not maintenance_window_active
  output: >
    Write to /etc/ (file=%fd.name flags=%evt.arg.flags
    proc=%proc.name pid=%proc.pid parent=%proc.pname
    user=%user.name uid=%user.uid
    container=%container.id image=%container.image.repository)
  priority: WARNING
  tags: [fim, host_security, mitre_persistence, mitre_defense_evasion]

# Detect writes to system binary directories — the primary rootkit installation signal.
- rule: Write to System Binary Directory
  desc: >
    A file in /usr/bin/, /usr/sbin/, /bin/, /sbin/, or /usr/local/bin/ was
    written or created. Changes to these directories outside of package manager
    operations indicate binary replacement — the mechanism by which rootkits
    replace system tools (ps, ls, netstat) with trojanized versions.
  condition: >
    file_write_or_create
    and (
      fd.name startswith /usr/bin/
      or fd.name startswith /usr/sbin/
      or fd.name startswith /bin/
      or fd.name startswith /sbin/
      or fd.name startswith /usr/local/bin/
      or fd.name startswith /usr/local/sbin/
    )
    and not known_bin_writers
    and not maintenance_window_active
  output: >
    Write to system binary directory
    (file=%fd.name flags=%evt.arg.flags
    proc=%proc.name pid=%proc.pid parent=%proc.pname
    cmdline=%proc.cmdline user=%user.name uid=%user.uid
    container=%container.id image=%container.image.repository)
  priority: ERROR
  tags: [fim, rootkit, host_security, mitre_persistence, mitre_defense_evasion]

# Detect writes to kernel module directories — the rootkit kernel module signal.
- rule: Write to Kernel Module Directory
  desc: >
    A file in /lib/modules/ or /usr/lib/modules/ was written or created.
    Kernel rootkits install loadable kernel modules (LKMs) that hook syscalls
    to hide processes, files, and network connections. Writing to the modules
    directory is a high-confidence rootkit installation indicator.
  condition: >
    file_write_or_create
    and (
      fd.name startswith /lib/modules/
      or fd.name startswith /usr/lib/modules/
    )
    and not known_bin_writers
    and not maintenance_window_active
  output: >
    Write to kernel module directory
    (file=%fd.name proc=%proc.name pid=%proc.pid
    parent=%proc.pname cmdline=%proc.cmdline
    user=%user.name uid=%user.uid)
  priority: CRITICAL
  tags: [fim, rootkit, kernel, mitre_persistence]

# Detect writes to web directories — the webshell creation signal.
- rule: File Created in Web Directory
  desc: >
    A new file was created in a web server document root (/var/www/, /srv/www/,
    /usr/share/nginx/html/). Webshells are the most common post-exploitation
    persistence mechanism on web servers. Any unexpected file creation in the
    document root — especially .php, .jsp, .asp, or .py files — should trigger
    immediate investigation.
  condition: >
    file_write_or_create
    and evt.arg.flags contains O_CREAT
    and (
      fd.name startswith /var/www/
      or fd.name startswith /srv/www/
      or fd.name startswith /usr/share/nginx/html/
    )
    and not proc.name in (nginx, apache2, httpd, php-fpm, rsync, scp, sftp-server)
    and not maintenance_window_active
  output: >
    File created in web directory
    (file=%fd.name proc=%proc.name pid=%proc.pid
    parent=%proc.pname cmdline=%proc.cmdline
    user=%user.name uid=%user.uid)
  priority: ERROR
  tags: [fim, webshell, host_security, mitre_persistence]

# Detect writes to systemd unit directories — the service-based persistence signal.
- rule: Write to Systemd Unit Directory
  desc: >
    A file in /etc/systemd/system/, /lib/systemd/system/, or
    /usr/lib/systemd/system/ was written. Installing a malicious systemd service
    is a reliable persistence mechanism that survives reboots and runs as root.
  condition: >
    file_write_or_create
    and (
      fd.name startswith /etc/systemd/system/
      or fd.name startswith /lib/systemd/system/
      or fd.name startswith /usr/lib/systemd/system/
    )
    and not known_bin_writers
    and not maintenance_window_active
  output: >
    Write to systemd unit directory
    (file=%fd.name proc=%proc.name pid=%proc.pid
    parent=%proc.pname cmdline=%proc.cmdline
    user=%user.name uid=%user.uid)
  priority: WARNING
  tags: [fim, persistence, host_security, mitre_persistence]

# Detect chmod/chown operations on /etc/ and binary dirs — setuid bit planting.
- rule: Suspicious chmod on Critical Path
  desc: >
    chmod or fchmod was called on a file in /etc/, /usr/bin/, or /sbin/.
    Attackers plant setuid binaries to create a persistent privilege escalation
    path that survives reboots without requiring a writable rootkit file.
  condition: >
    evt.type in (chmod, fchmod, fchmodat)
    and evt.dir = <
    and (
      fd.name startswith /etc/
      or fd.name startswith /usr/bin/
      or fd.name startswith /usr/sbin/
      or fd.name startswith /bin/
      or fd.name startswith /sbin/
    )
    and not known_bin_writers
    and not known_etc_writers
    and not maintenance_window_active
  output: >
    Suspicious chmod on critical path
    (file=%fd.name mode=%evt.arg.mode
    proc=%proc.name pid=%proc.pid user=%user.name uid=%user.uid)
  priority: WARNING
  tags: [fim, privilege_escalation, mitre_privilege_escalation]
```

### Combining AIDE and Falco: Layered Detection Strategy

Neither tool alone provides complete coverage. The correct architecture uses both:

| Scenario | AIDE | Falco |
|---|---|---|
| Binary replaced while system was offline | Catches on next check | Does not apply |
| Webshell created during business hours | Catches on next scan (up to 6h delay) | Catches within seconds |
| Change made and cleaned up between scans | Misses entirely | Catches both creation and deletion |
| Attacker modifies AIDE database | Blind | Detects write to `/var/lib/aide/` |
| Compliance evidence of file integrity | Full historical report | Real-time alert log |

Add a Falco rule to detect tampering with the AIDE database itself — this is the highest-priority FIM event because it indicates an attacker is attempting to defeat the baseline mechanism:

```yaml
# Detect writes to the AIDE database — database tampering signal.
- rule: Write to AIDE Database
  desc: >
    The AIDE integrity database was written by a process other than aide itself.
    Writing to /var/lib/aide/ outside of an authorized aide --init or aide --update
    operation indicates an attempt to defeat file integrity monitoring by updating
    the baseline to include malicious changes.
  condition: >
    file_write_or_create
    and fd.name startswith /var/lib/aide/
    and not proc.name in (aide, aide.wrapper)
  output: >
    AIDE database tampered
    (file=%fd.name proc=%proc.name pid=%proc.pid
    parent=%proc.pname cmdline=%proc.cmdline
    user=%user.name uid=%user.uid)
  priority: CRITICAL
  tags: [fim, defense_evasion, mitre_defense_evasion]
```

### Wazuh FIM: Managed Alternative

Teams already operating Wazuh can use the built-in `syscheck` module instead of maintaining separate AIDE and Falco FIM configurations. Wazuh syscheck provides scheduled and real-time FIM from a single agent, with results stored in the Wazuh indexer and queryable from the Wazuh dashboard.

#### Wazuh syscheck Configuration

```xml
<!-- /var/ossec/etc/ossec.conf — syscheck section -->
<syscheck>
  <!-- Real-time monitoring uses inotify/fanotify.
       Directories marked realtime="yes" alert within seconds of a change.
       Directories without realtime use the scheduled scan (frequency). -->

  <!-- Scan frequency: every 6 hours (21600 seconds). -->
  <frequency>21600</frequency>

  <!-- Alert on first scan (report new files found at startup). -->
  <alert_new_files>yes</alert_new_files>

  <!-- Auto-ignore: suppress repeated alerts on the same file.
       Set to no in high-security environments to ensure every change alerts. -->
  <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>

  <!-- System binaries: real-time + full hash verification. -->
  <directories realtime="yes" check_all="yes" report_changes="yes">/bin</directories>
  <directories realtime="yes" check_all="yes" report_changes="yes">/sbin</directories>
  <directories realtime="yes" check_all="yes" report_changes="yes">/usr/bin</directories>
  <directories realtime="yes" check_all="yes" report_changes="yes">/usr/sbin</directories>
  <directories realtime="yes" check_all="yes" report_changes="yes">/usr/local/bin</directories>

  <!-- System configuration: real-time. -->
  <directories realtime="yes" check_all="yes" report_changes="yes">/etc</directories>

  <!-- Web directories: real-time with diff reporting. -->
  <directories realtime="yes" check_all="yes" report_changes="yes">/var/www</directories>
  <directories realtime="yes" check_all="yes" report_changes="yes">/srv/www</directories>

  <!-- Systemd: scheduled only (changes here are infrequent). -->
  <directories check_all="yes">/etc/systemd/system</directories>
  <directories check_all="yes">/lib/systemd/system</directories>

  <!-- Kernel modules. -->
  <directories check_all="yes">/lib/modules</directories>

  <!-- Ignore volatile paths. -->
  <ignore>/etc/mtab</ignore>
  <ignore>/etc/adjtime</ignore>
  <ignore type="sregex">/etc/lvm/</ignore>
  <ignore>/var/run</ignore>
  <ignore>/tmp</ignore>
  <ignore>/var/tmp</ignore>
  <ignore>/var/log</ignore>
  <ignore>/var/lib/aide</ignore>

  <!-- Scan Windows hosts if mixed environment. -->
  <!-- <windows_registry>HKEY_LOCAL_MACHINE\Software</windows_registry> -->
</syscheck>
```

The `realtime="yes"` attribute instructs the Wazuh agent to use `inotify` (Linux) or `ReadDirectoryChangesW` (Windows) for immediate notification rather than waiting for the next scheduled scan. Use `realtime="yes"` for `/etc`, `/bin`, `/usr/bin`, and web directories. Reserve the scheduled-only mode for less critical paths where the 6-hour latency is acceptable.

Wazuh generates rule 550 (file modified), 554 (new file), and 553 (file deleted) alerts from syscheck events. Map these to a Wazuh SIEM dashboard with a filter for `rule.groups: syscheck` and `rule.level >= 7` to surface only high-confidence FIM alerts.

### Handling Legitimate Changes: Change Management Integration

The operationally hardest problem in FIM is distinguishing malicious changes from legitimate ones. Every package install, configuration management run, and application deployment triggers FIM alerts. Without a change management integration, FIM alert fatigue is guaranteed.

**Strategy 1: Maintenance window suppression via a sentinel file.**

Create and remove a sentinel file that Falco checks before alerting. Your change management system (Ansible, Terraform, a deployment pipeline) creates the sentinel at the start of a change window and removes it on completion.

```bash
# At the start of a maintenance window:
touch /run/fim-maintenance-active

# At the end of a maintenance window:
rm -f /run/fim-maintenance-active
```

Update the Falco macro:

```yaml
- macro: maintenance_window_active
  condition: >
    fd.name = /run/fim-maintenance-active
    and evt.type in (open, openat, openat2)
```

More robustly, use a Falco-readable environment variable or a Falco list that is updated via the Falco API:

```bash
# Falco 0.37+ supports the Falco API for dynamic list updates.
# Set a "suppressed hosts" list before a deployment:
curl -s -X PUT http://localhost:8765/api/rules/lists/suppressed_hosts \
  -H "Content-Type: application/json" \
  -d '{"items": ["prod-web-01.example.com"]}'
```

**Strategy 2: Expected-change correlation in the SIEM.**

Forward both your change management system's activity log (from your CMDB, Ansible Tower/AWX job history, or Terraform Cloud run log) and your Falco/AIDE alerts to the same SIEM. Write a correlation rule that suppresses an FIM alert if a corresponding authorized change record exists for the same host and file path within a 30-minute window.

```
# Elasticsearch correlation query (run as a SIEM alert suppression rule):
{
  "query": {
    "bool": {
      "must": [
        {"term": {"event.dataset": "aide_fim"}},
        {"term": {"host.name": "{{ alert.host }}"}},
        {"range": {"@timestamp": {"gte": "now-30m"}}}
      ],
      "must_not": [
        {"exists": {"field": "change_ticket_id"}}  # Set by CMDB enrichment
      ]
    }
  }
}
```

**Strategy 3: AIDE --check after every authorized change.**

After each package install or configuration management run, immediately trigger an AIDE check and promote the new database as the updated baseline. This shrinks the window during which AIDE is "stale" and reduces false positives on the next scheduled check.

```bash
# Post-deployment hook (run after ansible-playbook or apt-get):
aide --update
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
logger -t aide-fim -p security.info "AIDE database updated after authorized deployment"
```

### Container FIM: Immutable Root Filesystems as a Stronger Alternative

For containerized workloads, the strongest FIM posture is preventing file system writes at the container runtime level rather than detecting them after the fact. An immutable root filesystem makes the entire FIM problem for containers moot: if no writes are possible, there are no changes to detect.

```yaml
# Kubernetes Pod spec: immutable root filesystem
spec:
  containers:
  - name: app
    image: your-registry/app:v1.2.3
    securityContext:
      readOnlyRootFilesystem: true    # Mount the container root as read-only.
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      runAsUser: 10001
    # Mount writable volumes only for directories that genuinely need writes.
    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: cache
      mountPath: /app/cache
  volumes:
  - name: tmp
    emptyDir: {}
  - name: cache
    emptyDir: {}
```

With `readOnlyRootFilesystem: true`, any attempt to write to `/etc/`, `/usr/bin/`, or any other directory not explicitly mounted as a writable volume will return `EROFS` (read-only file system) and the syscall will fail. No FIM rule fires because the write is denied at the kernel level before any data is written.

Enforce `readOnlyRootFilesystem: true` across all production containers using an OPA/Gatekeeper constraint or a Kyverno policy:

```yaml
# Kyverno policy: require read-only root filesystem on all pods.
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-readonly-root-filesystem
spec:
  validationFailureAction: Enforce
  rules:
  - name: check-readonly-rootfs
    match:
      resources:
        kinds: [Pod]
    validate:
      message: "Containers must use readOnlyRootFilesystem: true"
      pattern:
        spec:
          containers:
          - securityContext:
              readOnlyRootFilesystem: true
```

For containers that cannot run with a fully immutable root filesystem (legacy applications that write to `/etc/` or `/var/`), Falco FIM rules remain the right detection layer. The Falco rules defined above work equally for host and container contexts — the `container.id` and `k8s.pod.name` fields in the output identify which container generated the FIM event.

## Verification

After deploying AIDE and the Falco FIM rules, verify the full detection pipeline:

```bash
# 1. Verify AIDE detects a test change.
echo "test" >> /etc/hosts
aide --check 2>&1 | grep -E "(Changed|hosts)"
# Should show /etc/hosts as a changed file.
# Restore:
sed -i '/^test$/d' /etc/hosts

# 2. Verify Falco detects a write to /usr/bin/ in real time.
# In one terminal, watch Falco logs:
journalctl -u falco -f

# In another terminal, trigger the rule:
touch /usr/bin/test-fim-$(date +%s)   # This requires root.
# Falco should log a "Write to system binary directory" alert within 1-2 seconds.
# Clean up:
rm -f /usr/bin/test-fim-*

# 3. Verify the AIDE database tampering rule fires.
touch /var/lib/aide/aide-tamper-test
# Falco should log a "Write to AIDE database" CRITICAL alert.
rm -f /var/lib/aide/aide-tamper-test

# 4. Verify the systemd timer is scheduled.
systemctl list-timers aide-check.timer
# Expected output: Next trigger time within 6 hours of last trigger.

# 5. Verify SIEM receives AIDE alerts.
logger -t aide-fim -p security.warning "Test AIDE alert for SIEM pipeline verification"
# Check your SIEM for the test log entry within 60 seconds.

# 6. For Wazuh: verify syscheck real-time is active.
/var/ossec/bin/agent_control -i 001 | grep "syscheck"
# Should show "Last scan" time and "Real-time monitoring: enabled"
```

## Key Points

- AIDE and Falco are complementary, not redundant: AIDE catches changes between scans (including offline changes), Falco catches changes in real time but misses anything that happens before Falco starts or after it stops.
- Initialize the AIDE database only on a known-clean system. An AIDE database initialized post-compromise is a liability, not a control.
- Store a copy of the AIDE reference database outside the monitored system — on a read-only share or object storage with versioning. A writable database on the same host can be tampered.
- Exclude volatile paths (`/proc`, `/sys`, `/dev`, `/run`, `/tmp`, `/var/tmp`) from both AIDE and Falco FIM rules. Monitoring these paths generates noise that leads to alert fatigue without producing actionable intelligence.
- The highest-priority FIM alert is a write to the AIDE database itself. An attacker updating the FIM baseline is defeating the entire detection layer; treat this as a CRITICAL incident.
- Falco's `maintenance_window_active` macro is the primary knob for suppressing FIM noise during authorized deployments. Integrate it with your change management system rather than disabling Falco rules during maintenance.
- For containers, `readOnlyRootFilesystem: true` is a stronger control than FIM: it prevents writes entirely rather than detecting them. Enforce it via a Kyverno or OPA policy at admission time.
- Wazuh `syscheck` with `realtime="yes"` provides combined scheduled and real-time FIM in a single agent, suitable for teams already operating Wazuh who do not want to maintain separate AIDE and Falco configurations.
- PCI DSS 11.5.2 requires alerting "on unauthorized modifications to critical system files, configuration files, or content files." Both AIDE (via the alerting service) and Falco (via Falcosidekick) satisfy this requirement; document which tool covers which file paths in your compliance evidence.
