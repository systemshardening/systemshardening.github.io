---
title: "Linux Disk Quota Security: Preventing Storage-Based Denial of Service"
description: "A full /var/log stops syslog cold, a full /tmp crashes services that assume writes succeed, and a full /home triggers cascading auth failures. Disk quotas are the enforcement layer that prevents these outcomes."
slug: linux-disk-quota-security
date: 2026-05-07
lastmod: 2026-05-07
category: linux
tags:
  - disk-quotas
  - dos-prevention
  - resource-limits
  - multi-tenant
  - filesystem-security
personas:
  - security-engineer
  - sysadmin
article_number: 488
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/linux/linux-disk-quota-security/
---

# Linux Disk Quota Security: Preventing Storage-Based Denial of Service

## The Problem

Storage exhaustion is one of the most reliable ways to break a Linux system without exploiting a single CVE. Unlike CPU or memory pressure, which degrade service gracefully before the system fails, filesystem fullness is binary: the filesystem hits 100% capacity and every write returns `ENOSPC`. The cascade is fast and wide.

Consider what happens when `/var/log` fills:

- `syslog`, `journald`, and `auditd` stop writing. You lose the audit trail at exactly the moment you need it — either because a misconfigured log rotation stopped running, or because an attacker deliberately flooded a writable log file to suppress evidence.
- Services that write to `/var/log` directly fail on their next write. Some handle `ENOSPC` gracefully; many do not.

When `/tmp` fills:

- Any program that relies on `tmpfs` writes for intermediate state — compilers, package managers, IPC socket creation, `mkstemp()` usage in OpenSSL — fails mid-operation. A partial package install can leave package manager databases inconsistent.
- Services restart and fail immediately because they cannot write pid files, sockets, or lock files to `/tmp`.

When `/home` fills on a shared system:

- Users cannot write `.Xauthority`, which prevents graphical login.
- SSH cannot write known hosts or control sockets, breaking multiplexed sessions.
- Bash cannot write `.bash_history`, but more critically, applications writing config or cache files to the home directory fail with unhandled errors.
- PAM modules that create session state under `/home` on first login may fail, blocking authentication entirely.

These failures can be caused by misconfiguration (a service writing unbounded logs, a developer's runaway build filling their home directory) or by a deliberate attack. An attacker with write access to any writable path — even as an unprivileged user — can write a large file to exhaust the filesystem and force a denial of service on every other service sharing that partition. On a shared hosting system or multi-tenant server, one user can take down the entire host.

Disk quotas are the enforcement layer. They cap how much storage a user, group, or directory tree can consume, hard-stopping the fill before it becomes a system-wide outage.

## Linux Quota Types

Linux supports three quota granularities:

**User quotas** (`usrquota`) limit the total disk usage attributed to a UID. Every file's block count and inode count is charged to its owner. A user who owns 10 GB of files counts 10 GB against their quota regardless of which directory those files live in.

**Group quotas** (`grpquota`) apply the same accounting at the GID level. Useful for shared project directories where multiple users contribute files but the project should not exceed a storage budget.

**Project quotas** (`prjquota`) track all blocks and inodes within a directory tree, regardless of which user owns the files. A project ID is assigned to a directory and all files within it inherit that project ID. This is the right model for `/var/log`, `/srv/app-data`, or any directory tree you want to cap independently of user identity. XFS has supported project quotas natively since the filesystem's origin. ext4 gained project quota support in kernel 4.5.

## Enabling Quotas on ext4

For ext4 filesystems, quotas are enabled through mount options in `/etc/fstab`.

```bash
# /etc/fstab
# Add usrquota,grpquota mount options to the target filesystem
UUID=<uuid>  /home  ext4  defaults,usrquota,grpquota  0  2

# For project quotas on ext4 (kernel 4.5+ and e2fsprogs 1.43+)
UUID=<uuid>  /var/log  ext4  defaults,prjquota  0  2
```

For project quotas on ext4, enable the project quota feature on the filesystem first:

```bash
# Filesystem must be unmounted or remounted read-only
sudo tune2fs -O project,quota /dev/sda2

# Verify the feature is set
sudo tune2fs -l /dev/sda2 | grep features
# should include: project, quota
```

After modifying `/etc/fstab`, remount or reboot, then initialise the quota database:

```bash
# Scan the filesystem and build initial quota database files
sudo quotacheck -cugm /home

# This creates /home/aquota.user and /home/aquota.group

# Enable quota enforcement
sudo quotaon /home

# Verify quotas are active
sudo quotaon -p /home
# /dev/sda3 [/home]: user quotas turned on
# /dev/sda3 [/home]: group quotas turned on
```

## Setting Hard and Soft Limits

Quota limits come in two types with meaningfully different semantics:

**Soft limit:** A threshold the user may exceed temporarily. Exceeding the soft limit starts a grace period (default: 7 days). If the user is still over the soft limit when the grace period expires, the soft limit becomes enforced as a hard limit until usage drops below it.

**Hard limit:** An absolute ceiling. Writes that would push usage above the hard limit are rejected with `ENOSPC` immediately. The hard limit cannot be exceeded even momentarily.

The split between soft and hard limits is useful for legitimate users who occasionally need more space (a developer running a large build) but who should not permanently consume excess storage. For security-critical directories like `/var/log`, consider setting soft and hard limits identically to eliminate the grace window entirely.

Use `edquota` to set limits interactively:

```bash
# Edit quotas for user 'deploy'
sudo edquota -u deploy
# Opens in $EDITOR:
# Disk quotas for user deploy (uid 1001):
#   Filesystem  blocks   soft    hard  inodes  soft  hard
#   /dev/sda3   204800   0       0     1200    0     0
#
# Set limits (values in 1KB blocks):
#   Filesystem  blocks   soft      hard      inodes  soft  hard
#   /dev/sda3   204800   2097152   2621440   1200    50000 60000
# soft: 2 GB, hard: 2.5 GB; soft inode: 50k, hard inode: 60k
```

For scripted provisioning, use `setquota` directly:

```bash
# setquota -u <user> <soft-blocks> <hard-blocks> <soft-inodes> <hard-inodes> <filesystem>
# Block values in 1KB units; 1 GB = 1048576

sudo setquota -u deploy 2097152 2621440 50000 60000 /home
sudo setquota -u ci-runner 5242880 6291456 100000 120000 /home

# Set a grace period of 24 hours (instead of default 7 days)
sudo setquota -t 86400 86400 /home
```

Apply the same limits to a new user template with `edquota -p` (prototype):

```bash
# Set limits on a template user, then clone to others
sudo edquota -u template-user
sudo edquota -p template-user alice bob carol
```

View current usage and limits:

```bash
# Summary of all users with quotas on /home
sudo repquota -s /home

# Per-user output (human-readable sizes)
sudo quota -s -u deploy

# Report across all quota-enabled filesystems
sudo repquota -s -a
```

Sample `repquota` output:

```
*** Report for user quotas on device /dev/sda3
Block grace time: 24:00:00; Inode grace time: 24:00:00
                        Block limits                File limits
User            used    soft    hard  grace    used  soft  hard  grace
----------------------------------------------------------------------
deploy    --  204800 2097152 2621440          1200 50000 60000
ci-runner --  819200 5242880 6291456          8400 100000 120000
```

The `--` in the grace column means the user is within their soft limit. A `+` means they are over it.

## XFS Project Quotas for Directory Trees

XFS project quotas are the most precise tool for capping directory trees independent of user ownership. On XFS, project quota management uses `xfs_quota` and two configuration files.

Define projects in `/etc/projects` (project ID to directory mapping) and `/etc/projid` (project ID to name mapping):

```bash
# /etc/projects
# Format: <project-id>:<path>
10:/var/log
11:/home
12:/srv/app-data
13:/tmp

# /etc/projid
# Format: <project-name>:<project-id>
varlog:10
home:11
appdata:12
tmp:13
```

Enable the project quota mount option in `/etc/fstab`:

```bash
UUID=<uuid>  /  xfs  defaults,prjquota  0  0
```

After remounting, initialise each project:

```bash
# Initialise project: assigns the project ID to the directory inode
sudo xfs_quota -x -c 'project -s varlog' /
sudo xfs_quota -x -c 'project -s home' /
sudo xfs_quota -x -c 'project -s appdata' /
sudo xfs_quota -x -c 'project -s tmp' /
```

Set limits:

```bash
# xfs_quota limit syntax: bsoft/bhard for block limits, isoft/ihard for inode limits
# Units: m (megabytes), g (gigabytes)

# /var/log capped at 4 GB hard, 3.5 GB soft
sudo xfs_quota -x -c 'limit -p bsoft=3584m bhard=4096m varlog' /

# /home capped at 100 GB total across all users
sudo xfs_quota -x -c 'limit -p bsoft=96g bhard=100g home' /

# /srv/app-data: 50 GB
sudo xfs_quota -x -c 'limit -p bsoft=48g bhard=50g appdata' /

# /tmp: 2 GB
sudo xfs_quota -x -c 'limit -p bsoft=1792m bhard=2048m tmp' /
```

Check project usage:

```bash
# Report all project quotas
sudo xfs_quota -x -c 'report -ph' /

# Detailed report for a specific project
sudo xfs_quota -x -c 'quota -ph varlog' /
```

Sample output:

```
Project quota on / (/dev/sda1)
                               Blocks
Project ID       Used       Soft       Hard    Warn/Grace
---------- --------------------------------------------------
varlog         1.2G       3.5G       4.0G     00 [--------]
home           42G        96G       100G      00 [--------]
appdata        8.1G       48G        50G      00 [--------]
tmp            256M      1.8G        2.0G     00 [--------]
```

## Tmpfs Size Limits

Tmpfs filesystems backed by RAM (and swap) have no on-disk quota tooling, but they have their own size limit mechanism. Without an explicit `size=` parameter, tmpfs defaults to 50% of total RAM — which means a process writing to `/tmp` can exhaust half your system's memory.

Constrain tmpfs mounts explicitly in `/etc/fstab`:

```bash
# /etc/fstab tmpfs entries with explicit size limits
tmpfs  /tmp          tmpfs  defaults,size=2g,mode=1777,nosuid,noexec,nodev  0  0
tmpfs  /run          tmpfs  defaults,size=256m,mode=0755,nosuid,noexec,nodev  0  0
tmpfs  /dev/shm      tmpfs  defaults,size=1g,nosuid,noexec,nodev  0  0
```

For a running system, resize without unmounting:

```bash
sudo mount -o remount,size=2g /tmp
```

Verify current tmpfs sizes:

```bash
df -h --output=source,size,used,avail,pcent,target -t tmpfs
```

## cgroup v2 IO Limits: A Complementary Layer

Disk quotas control *how much* data can be stored. cgroup v2 IO limits control *how fast* it can be written. Both are needed for full storage DoS prevention: a quota prevents a user from filling a filesystem, while an IO weight limit prevents a runaway process from saturating disk bandwidth and starving other processes even when there is still free space.

```bash
# Check IO statistics for a systemd service
systemd-cgtop

# Set IO bandwidth limits in a systemd service override
# /etc/systemd/system/log-importer.service.d/io-limits.conf
```

```ini
[Service]
# Absolute write bandwidth cap on /dev/sda (find device with lsblk)
IOWriteBandwidthMax=/dev/sda 50M

# Relative IO weight (default 100; lower = lower priority)
IOWeight=20
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart log-importer.service

# Verify the limits are applied to the cgroup
cat /sys/fs/cgroup/system.slice/log-importer.service/io.max
# 8:0 rbps=max wbps=52428800 riops=max wiops=max
```

For interactive inspection:

```bash
# Watch per-cgroup IO rates in real time
systemd-cgtop -d 1
```

## Monitoring and Alerting

Quota enforcement silently blocks writes once a hard limit is reached. Users may not understand why their writes are failing. Build alerting before limits are hit.

A simple script to alert when users approach their hard limit:

```bash
#!/bin/bash
# /usr/local/bin/quota-alert.sh
# Run via cron every 15 minutes

THRESHOLD=85  # percent of hard limit
ALERT_CMD="logger -p auth.warning -t quota-alert"

# Parse repquota output for users over threshold
repquota -a 2>/dev/null | awk -v threshold="$THRESHOLD" '
/^\// { next }          # skip header lines with filesystem paths
/^---/ { next }         # skip separator
NF < 8 { next }         # skip incomplete lines
{
    user=$1
    used=$2
    hard=$4
    if (hard > 0 && used > 0) {
        pct = (used * 100) / hard
        if (pct >= threshold) {
            printf "user=%s used=%dKB hard=%dKB pct=%.0f%%\n", user, used, hard, pct
        }
    }
}' | while read -r line; do
    $ALERT_CMD "Quota threshold exceeded: $line"
done
```

```bash
# /etc/cron.d/quota-monitor
*/15 * * * * root /usr/local/bin/quota-alert.sh
```

For XFS project quotas, parse `xfs_quota` report output similarly:

```bash
#!/bin/bash
# Check XFS project quota usage
sudo xfs_quota -x -c 'report -pbn' / | awk '
NR > 2 && NF >= 4 {
    project=$1; used=$2; hard=$4
    if (hard > 0 && used > 0) {
        pct = (used * 100) / hard
        if (pct >= 85) {
            printf "WARNING: project=%s at %.0f%% of quota (%d/%d blocks)\n",
                project, pct, used, hard
        }
    }
}'
```

Integrate quota metrics into your observability stack. The `node_exporter` for [Prometheus](https://prometheus.io) does not expose quota data by default, but the [textfile collector](https://github.com/prometheus/node_exporter#textfile-collector) can ingest the output of a quota scraping script written to `/var/lib/node_exporter/textfile_collector/`:

```bash
#!/bin/bash
# /usr/local/bin/quota-metrics.sh
# Outputs Prometheus text format for node_exporter textfile collector

echo "# HELP disk_quota_used_bytes Disk quota used by user"
echo "# TYPE disk_quota_used_bytes gauge"

repquota -a 2>/dev/null | awk '
/^\// { fs=$1 }
NF >= 8 && $1 !~ /^[-#]/ && $1 != "Block" {
    user=$1; used=$2*1024; hard=$4*1024
    if (hard > 0) {
        printf "disk_quota_used_bytes{user=\"%s\",filesystem=\"%s\"} %d\n", user, fs, used
        printf "disk_quota_hard_bytes{user=\"%s\",filesystem=\"%s\"} %d\n", user, fs, hard
    }
}'
```

## Container and Kubernetes Disk Limits

Container runtimes use XFS project quotas under the hood for per-container disk limits when using the overlay2 storage driver on XFS.

Docker exposes this through the `--storage-opt` flag:

```bash
# Limit a container's writable layer to 10 GB
docker run --storage-opt size=10g nginx:alpine

# Verify the limit
docker inspect <container-id> | jq '.[0].HostConfig.StorageOpt'
```

For this to work, the Docker data directory (`/var/lib/docker`) must be on an XFS filesystem with `prjquota` enabled in the mount options. Docker assigns a project ID to each container's overlay directory and enforces the limit via the XFS quota mechanism.

In [Kubernetes](https://kubernetes.io), per-pod ephemeral storage limits are enforced by the kubelet and also rely on XFS project quotas (or filesystem usage polling as a fallback):

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
    - name: app
      image: app:latest
      resources:
        requests:
          ephemeral-storage: "1Gi"
        limits:
          ephemeral-storage: "5Gi"
```

The kubelet evicts pods that exceed their ephemeral storage limit. Without setting `ephemeral-storage` limits, a container writing to its writable layer or to an `emptyDir` volume can fill the node's disk, causing the node to enter a `DiskPressure` condition and triggering eviction of other pods.

Enable XFS project quota-based enforcement in kubelet (faster and more accurate than polling):

```yaml
# kubelet configuration
featureGates:
  LocalStorageCapacityIsolationFSQuotaMonitoring: true
```

For `emptyDir` volumes backed by tmpfs, set a `sizeLimit`:

```yaml
volumes:
  - name: scratch
    emptyDir:
      medium: Memory
      sizeLimit: 256Mi
```

## Expected Behaviour After Configuration

- Writing past a hard limit returns `ENOSPC` immediately. The affected user or process cannot write more data. Other users on the same filesystem are unaffected.
- Writing past a soft limit succeeds, but the grace timer starts. `quota -s -u <user>` shows the grace time remaining.
- XFS project quota enforcement prevents any process — regardless of UID — from writing past the project hard limit for a capped directory tree.
- `repquota -s -a` shows all users with quotas, their current usage, and whether they are in grace.
- `df -h` still shows free space on the filesystem because the quota is per-entity, not a reservation. The filesystem itself may have free blocks that the quota holder cannot use.
- Tmpfs mounts with `size=` reject writes past their size limit, preventing RAM exhaustion from a process writing to `/tmp` or `/dev/shm`.
- Docker containers with `--storage-opt size=` are evicted if their writable layer exceeds the limit; the limit appears in `docker inspect`.
- Kubernetes pods exceeding `ephemeral-storage` limits are evicted by the kubelet, and the event is visible in `kubectl describe pod`.

## Trade-offs

| Control | Benefit | Cost | Mitigation |
|---------|---------|------|------------|
| User/group quotas | Prevents single user from filling a shared filesystem | Accounting overhead on every write; inode count and block count charged to UID/GID | Negligible on modern hardware. Use `aquota.user` with journaling (`journaldata=ordered`) for consistency. |
| XFS project quotas | Caps directory trees regardless of who owns the files; used by container runtimes | Requires XFS with `prjquota` mount option; project IDs must be managed; adding directories to a project requires `xfs_quota -x -c 'project -s'` re-run | Automate project setup with a configuration management tool. Run project init in provisioning scripts. |
| Soft limits with grace | Gives legitimate users temporary headroom | A user near their hard limit can stay over the soft limit for days if grace period is long | Set identical soft and hard limits for security-critical directories. Shorten global grace period with `setquota -t`. |
| Tmpfs `size=` | Prevents RAM exhaustion from `/tmp` and `/dev/shm` writes | Setting size too low breaks programs that need large temporary files (e.g., video processing, large builds) | Set size conservatively (2 GB for `/tmp` is appropriate for most servers), and document the limit. Provide an overflow path (`/var/tmp` on disk) for processes that need more. |

## Related Articles

- [Cgroup v2 Resource Isolation: Preventing Resource Exhaustion Attacks on Shared Systems](/articles/linux/cgroup-resource-isolation/)
- [Filesystem Mount Options That Matter: noexec, nosuid, nodev, and Beyond](/articles/linux/filesystem-mount-options/)
- [Linux Audit Framework Deep Dive: auditd Rules, auditctl, and ausearch for Security Monitoring](/articles/linux/auditd-deep-dive/)
- [systemd Unit Hardening: ProtectSystem, PrivateTmp, and the Full Sandbox Toolkit](/articles/linux/systemd-unit-hardening/)
- [Hardening the Linux Kernel Attack Surface with sysctl and Boot Parameters](/articles/linux/sysctl-kernel-hardening/)
