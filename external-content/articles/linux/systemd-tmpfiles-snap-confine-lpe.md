---
title: "systemd-tmpfiles and snap-confine Race Condition: CVE-2026-3888 on Ubuntu"
description: "CVE-2026-3888 exploits a race between snap-confine and systemd-tmpfiles to escalate privileges to root on Ubuntu LTS. Understand the timing window, patch snapd, and harden /tmp handling to close this class of tmpfiles race vulnerabilities."
slug: systemd-tmpfiles-snap-confine-lpe
date: 2026-05-07
lastmod: 2026-05-07
category: linux
tags:
  - ubuntu
  - snapd
  - privilege-escalation
  - race-condition
  - cve
personas:
  - platform-engineer
  - security-engineer
article_number: 447
difficulty: Advanced
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/linux/systemd-tmpfiles-snap-confine-lpe/
---

# systemd-tmpfiles and snap-confine Race Condition: CVE-2026-3888 on Ubuntu

## The Problem

CVE-2026-3888 is a local privilege escalation vulnerability that arises from the interaction between two separately correct components: `snap-confine` and `systemd-tmpfiles`. Neither component contains a bug in isolation — the vulnerability exists entirely in the temporal gap between their operations on a shared path in `/tmp`. It was disclosed in March–April 2026 with a CVSS base score of 8.4, affecting Ubuntu 20.04 LTS, 22.04 LTS, and 24.04 LTS wherever `snapd` is installed.

`snap-confine` is the setuid-root binary responsible for constructing the execution environment for snap applications. When a snap is launched, `snap-confine` creates a private, per-snap working directory under a predictable path in `/tmp` — specifically `/tmp/snap.XXXXXX`, where the suffix is derived deterministically from the snap name rather than generated randomly. This directory is used by `snap-confine` during the setup phase of snap execution, and because `snap-confine` carries the setuid root bit, it performs all directory operations as the root user regardless of which unprivileged user launched the snap.

`systemd-tmpfiles` is the system service responsible for managing the lifecycle of temporary files and directories. It is driven by rules in `/usr/lib/tmpfiles.d/` and `/etc/tmpfiles.d/`, and it runs at boot and on a periodic timer — typically `systemd-tmpfiles-clean.timer`, which fires once per day. Its job is to remove stale entries from `/tmp` based on age and access timestamp criteria. On a default Ubuntu system, directories in `/tmp` that have not been accessed within a configurable window (the `d` rule age, defaulting to 10 days) are removed and, if the rule specifies it, recreated as root-owned directories with defined permissions.

The race window emerges from this sequence. After a snap package is installed, the per-snap `/tmp/snap.XXXXXX` directory is created and used when the snap first runs. If the snap is not launched again within the cleanup window — a period that corresponds to 10 to 30 days depending on system uptime patterns and the `systemd-tmpfiles-clean.timer` schedule — `systemd-tmpfiles` removes the directory. On some Ubuntu configurations the tmpfiles rule then recreates the directory path as a root-owned, world-writable placeholder before `snap-confine` can claim it. The window between the old directory being removed and `snap-confine` recreating it on the next snap launch is where the exploit lives.

An unprivileged attacker who monitors `/tmp` for the removal of `/tmp/snap.XXXXXX` — straightforwardly accomplished with `inotifywait` — can immediately place a symlink at `/tmp/snap.XXXXXX` pointing to an attacker-chosen target before `snap-confine` runs again. When the user or a scheduled process next launches the snap, `snap-confine` runs as root, attempts to set up its working environment at `/tmp/snap.XXXXXX`, and follows the symlink. Because the path resolution in the vulnerable code path does not verify that the directory is root-owned and was not substituted between the creation and use phases, `snap-confine` operates on the symlink target. The result is that `snap-confine` performs privileged directory operations — `mkdir`, `chown`, `chmod`, `bind mount` setup — on an attacker-controlled path, which translates to an arbitrary file write as root.

Escalating from arbitrary root file write to full root access is mechanical: overwriting `/etc/passwd` to add a passwordless root account, writing a cron job to `/etc/cron.d/`, or modifying `/etc/sudoers`. The full chain from symlink placement to interactive root shell is achievable in a single triggered snap launch.

What makes this class of vulnerability particularly difficult to detect in production is that no individual component is misbehaving. `snap-confine` is correctly setting up a snap environment. `systemd-tmpfiles` is correctly enforcing the cleanup policy it was configured with. A security audit of either component in isolation would not surface the vulnerability. Intrusion detection rules focused on individual system call sequences produce no signal because all operations are individually legitimate. The vulnerability only becomes visible when the interaction between the two components, and the timing of that interaction relative to unprivileged observer processes, is analysed holistically. This is the defining characteristic of this class of tmpfiles race combined with a setuid binary: the attack surface is the composition, not the components.

## Threat Model

The direct threat is a local unprivileged attacker with a shell on the target Ubuntu system. This includes developer accounts, CI runner service accounts, containerised processes that have access to the host's `/tmp` namespace, and any process with `inotify` access to the filesystem. The attack requires no prior privilege, no kernel exploit, and no custom kernel module.

Exploitation has three phases. In the reconnaissance phase, the attacker establishes that `snapd` is installed and identifies which snap packages are present with predictable `/tmp` directory names. This is entirely unprivileged: `snap list` is readable by any local user, and the naming convention for snap directories in `/tmp` is documented in the `snapd` source. In the monitoring phase, the attacker starts an `inotifywait` process on `/tmp` watching for `IN_DELETE` events matching the target snap directory name. This phase requires waiting for the natural cleanup interval — 10 to 30 days — unless the attacker can trigger cleanup earlier by interacting with `systemd-tmpfiles` in a way that is still possible from an unprivileged context on some configurations. In the exploitation phase, the attacker races to create the symlink after the directory is removed and before `snap-confine` recreates it; with a sufficiently fast reaction (achievable with a shell script sleeping in an `inotifywait` loop), the race window is wide enough to win reliably.

The highest-exposure populations are:

- **Ubuntu-based GitHub Actions runners** — hosted and self-hosted runners on Ubuntu 20.04, 22.04, and 24.04 have `snapd` installed by default. Any pipeline running untrusted code — pull request pipelines from external contributors, for example — has access to a local shell and can exploit this vulnerability. The CI runner service account is the typical unprivileged starting point.
- **Ubuntu LTS cloud instances** — the vast majority of Ubuntu compute instances in AWS, GCP, and Azure run one of the three affected LTS releases. Cloud-optimised Ubuntu images ship `snapd` pre-installed. An attacker who achieves RCE on an application running on the instance can pivot to root via this vulnerability without a kernel exploit.
- **Container hosts with shared `/tmp`** — container configurations that mount the host's `/tmp` into the container, or runtime configurations that do not give the container a private `/tmp` mount namespace, expose `snap-confine`'s working directory to processes inside the container. A process inside such a container can win the race and escalate to root on the host.
- **Multi-user developer workstations and laptops** — Ubuntu desktop systems running snaps are affected. An attacker with a low-privilege local account (guest account, shared account for automated testing) can escalate on any system where the snap application is used infrequently enough to trigger the cleanup window.

The impact of successful exploitation is full root compromise of the host operating system. This includes reading all data on the system, modifying or destroying data, installing persistent backdoors, and pivoting to other systems reachable from the host.

## Hardening Configuration

### Step 1: Patch snapd

The primary and mandatory remediation is patching `snapd` to the version containing the fix. The patch adds an ownership verification step inside `snap-confine`: before using the directory at the expected path, `snap-confine` now verifies that the directory is owned by root and has not been replaced with a symlink or a directory owned by any other user. A symlink placed by an unprivileged attacker fails this check and causes `snap-confine` to abort the snap launch with an error rather than following the attacker-controlled path.

```bash
apt-get update
apt-get upgrade snapd
```

After upgrading, confirm the installed version:

```bash
snap version
```

The patched `snapd` version for each Ubuntu release is documented in the USN advisory for CVE-2026-3888. Cross-reference the installed version against the advisory before concluding that patching is complete.

Verify the `snap-confine` binary itself has been replaced, not only the `snapd` daemon package. In some upgrade scenarios, the `snap-confine` binary at `/usr/lib/snapd/snap-confine` can be cached or left at a previous version if the snap core snap is not refreshed:

```bash
dpkg -l snapd
/usr/lib/snapd/snap-confine --version
```

If the version strings differ or the `snap-confine` binary predates the patch, force a refresh:

```bash
snap refresh core
```

### Step 2: Harden `/tmp` with `nosuid` Mount Option

Mounting `/tmp` with `nosuid` prevents any setuid binary located inside `/tmp` from executing with elevated privileges. This does not prevent the symlink attack described in CVE-2026-3888 itself — `snap-confine` lives at `/usr/lib/snapd/snap-confine`, not inside `/tmp` — but it removes a class of post-exploitation options that rely on dropping a setuid binary into `/tmp` as a persistence mechanism.

Add the `nosuid` and `noexec` options to the `/tmp` mount in `/etc/fstab`:

```conf
tmpfs /tmp tmpfs defaults,nosuid,noexec,nodev,size=2G 0 0
```

If `/tmp` is already mounted as `tmpfs`, remount without rebooting:

```bash
mount -o remount,nosuid,noexec,nodev /tmp
```

Reload systemd's view of the mount configuration:

```bash
systemctl daemon-reload
```

Verify the mount options are active:

```bash
findmnt /tmp
```

The output should include `nosuid` and `noexec` in the OPTIONS column.

### Step 3: Enable `PrivateTmp` for Snap Services

systemd's `PrivateTmp=true` directive gives a service unit an isolated `/tmp` and `/var/tmp` mount namespace. Processes inside the unit see a private `/tmp` that is not shared with the rest of the system. If `snap-confine` operates within a systemd service unit with `PrivateTmp=true`, the attacker-controlled symlink in the host's `/tmp` is invisible to `snap-confine`, because `snap-confine` and the snapped application see a different `/tmp` entirely.

Verify whether the systemd unit for a snap application has `PrivateTmp` set:

```bash
systemctl cat snap.<snapname>.service | grep PrivateTmp
```

If `PrivateTmp=true` is absent, add an override:

```bash
systemctl edit snap.<snapname>.service
```

In the override file:

```conf
[Service]
PrivateTmp=true
```

Reload and restart:

```bash
systemctl daemon-reload
systemctl restart snap.<snapname>.service
```

Note that `PrivateTmp=true` only applies to snaps managed as systemd services. Snap applications launched interactively from a shell do not run within a systemd unit context and do not inherit this isolation. The patch in Step 1 remains the only complete fix for snap applications launched from the CLI.

### Step 4: Monitor `/tmp` for Unprivileged Symlink Creation

auditd can detect the moment an attacker places a symlink in `/tmp`. The `symlinkat` and `symlink` syscalls in `/tmp` by a non-root user are a strong signal of either the exploit in progress or a precursor to it.

Add the following rules to `/etc/audit/rules.d/99-tmp-symlink.rules`:

```conf
-a always,exit -F arch=b64 -S symlink -F dir=/tmp -F auid!=0 -k tmp_symlink
-a always,exit -F arch=b64 -S symlinkat -F dir=/tmp -F auid!=0 -k tmp_symlink
-a always,exit -F arch=b32 -S symlink -F dir=/tmp -F auid!=0 -k tmp_symlink
-a always,exit -F arch=b32 -S symlinkat -F dir=/tmp -F auid!=0 -k tmp_symlink
```

Load the rules immediately:

```bash
augenrules --load
```

Verify the rules are active:

```bash
auditctl -l | grep tmp_symlink
```

Query for matching events:

```bash
ausearch -k tmp_symlink --interpret
```

For a more targeted rule that generates lower volume by restricting the watch to snap directories specifically:

```conf
-a always,exit -F arch=b64 -S symlink -F dir=/tmp -F name_regex=snap\..* -F auid!=0 -k snap_symlink_race
-a always,exit -F arch=b64 -S symlinkat -F dir=/tmp -F name_regex=snap\..* -F auid!=0 -k snap_symlink_race
```

Configure alerting in your SIEM or log management platform to page on events with the `snap_symlink_race` key. The race window is short; real-time alerting is more useful than batch review.

### Step 5: Remove snapd on Systems That Do Not Require It

On servers, CI runners, and container hosts where no snap application is functionally required, the safest course is to remove `snapd` entirely. This eliminates `snap-confine`, the tmpfiles interaction, and all future snap-related attack surface.

```bash
apt-get purge snapd
rm -rf /snap /var/snap /var/lib/snapd /var/cache/snapd
```

Verify the removal is complete:

```bash
which snap
dpkg -l snapd
```

Both commands should return no results. Confirm that no services attempt to restart `snapd`:

```bash
systemctl list-units --state=failed | grep snap
```

## Expected Behaviour After Hardening

After patching `snapd`, an attacker who successfully places a symlink at `/tmp/snap.XXXXXX` before a snap launch will see the launch fail rather than the privilege escalation succeed. `snap-confine` performs the ownership check, determines that the path is a symlink or is owned by a non-root user, logs an error, and exits without following the symlink. The snap launch returns an error to the calling process, which is the correct and safe failure mode.

The audit rule for symlink creation in `/tmp` generates a record immediately on the syscall. A successful exploitation attempt looks like:

```
type=SYSCALL msg=audit(1746316800.441:5120): arch=c000003e syscall=88 success=yes exit=0 \
  a0=ffffff9c a1=7ffd1a3e2010 a2=ffffff9c a3=7ffd1a3e2030 items=2 ppid=4412 pid=4413 \
  auid=1001 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 \
  fsgid=1001 tty=pts0 ses=12 comm="exploit" exe="/home/attacker/exploit" key="tmp_symlink"
type=PATH msg=audit(1746316800.441:5120): item=1 name="/tmp/snap.firefox" inode=0 \
  dev=00:00 mode=0120777 ouid=1001 ogid=1001 rdev=00:00 nametype=CREATE
```

Syscall 88 is `symlink` on x86-64. The `nametype=CREATE` and `mode=0120777` (symlink mode) confirm a symlink was created. The `auid=1001` field identifies the unprivileged user. This record appears in the audit log before `snap-confine` is ever invoked, giving defenders a detection opportunity even if the patch has not yet been applied.

## Trade-offs and Operational Considerations

Purging `snapd` is the cleanest hardening option but has scope implications that vary by environment. Ubuntu cloud images use `snap` for several pre-installed tools: `cloud-init` may be distributed as a snap on some image configurations, and the `lxd` snap provides LXD container support. Audit snap usage before purging:

```bash
snap list
```

Review the output and confirm that no installed snap is providing a service that the system depends on. If `lxd` is delivered as a snap, migrating to the `apt` package or a Debian-native alternative is necessary before purging `snapd`.

The `PrivateTmp=true` mitigation for snap services can conflict with snap applications that intentionally share state via `/tmp` between multiple components. Some snaps use `/tmp` as an IPC channel between the snap's own processes or between the snap and external host processes. Adding `PrivateTmp=true` to such a snap's service unit will break that IPC. Test snap functionality after adding the override before deploying to production, and document which snap services had the override added so future debugging is not confused by the isolated `/tmp`.

The auditd `/tmp` symlink monitoring rules will generate notable volume on developer machines where users frequently create symlinks in `/tmp` for legitimate purposes — build systems, temporary link farms, development tool caches. The `auid!=0` filter already excludes root-created symlinks, but on machines with active developer users, the remaining volume may be high. Apply additional `uid` filters to exclude known service accounts and developer accounts that have been audited as low-risk:

```conf
-a always,exit -F arch=b64 -S symlink -F dir=/tmp -F auid!=0 -F uid!=deploy -F uid!=buildbot -k tmp_symlink
```

On production servers where non-root symlinks in `/tmp` should be extremely rare, the unfiltered rule is appropriate and any match warrants immediate investigation.

## Failure Modes

**snapd upgraded but `snap-confine` not updated.** The `snapd` Debian package and the `snap-confine` binary are versioned together, but `snap-confine` can remain at a previous version if the `core` or `core20`/`core22` snap is not refreshed after the package upgrade. `dpkg -l snapd` showing the patched version does not guarantee that the running `snap-confine` binary incorporates the fix. Always follow the package upgrade with `snap refresh core` and verify `/usr/lib/snapd/snap-confine --version` matches expectations.

**`PrivateTmp=true` does not apply to CLI-launched snaps.** The `PrivateTmp=true` override in a snap's systemd service unit only isolates `/tmp` for that service unit's invocation. When a user runs `snap run firefox` from a terminal, `snap-confine` executes in the calling user's process context, not within the service unit. The service unit `PrivateTmp` setting has no effect on this invocation. The patch remains the only complete fix for CLI-launched snaps.

**Audit rule monitoring `/tmp` globally but with excessive volume.** The broad `-F dir=/tmp` filter captures all symlinks in `/tmp`, which on busy systems can flood the audit log and cause important events to be dropped if the audit backlog limit is exceeded. If audit log volume from the `/tmp` rules is causing drops (visible in `auditctl -s` as nonzero `lost` count), replace the broad rule with a more specific path filter:

```conf
-w /tmp -p x -k tmp_watch
```

Or reduce to watching only symlink creation on paths matching the `snap.` prefix using a `name_regex` filter as shown in Step 4. Verify the `lost` counter remains zero after applying the rule:

```bash
auditctl -s | grep lost
```

**Container host exposure with shared `/tmp`.** If the container runtime mounts the host `/tmp` into the container and the snap application runs on the host, the container's filesystem namespace overlaps with `snap-confine`'s working path. After patching `snapd` on the host, confirm the container's `/tmp` view does not shadow the host `/tmp` in a way that allows the container to see and manipulate snap directory paths. Containers with `--mount type=tmpfs,dst=/tmp` get their own isolated `/tmp` and are not exposed; containers without an explicit `/tmp` mount that inherit the host mount namespace are exposed.

## Related Articles

- [Linux LPE Defence in Depth](/articles/linux/linux-lpe-defence-in-depth/)
- [Linux algif_aead Privilege Escalation](/articles/linux/linux-algif-aead-privilege-escalation/)
- [Systemd Unit Hardening](/articles/linux/systemd-unit-hardening/)
- [Auditd Deep Dive](/articles/linux/auditd-deep-dive/)
- [Filesystem Mount Options](/articles/linux/filesystem-mount-options/)
