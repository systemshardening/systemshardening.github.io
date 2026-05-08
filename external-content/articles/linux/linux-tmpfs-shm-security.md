---
title: "Linux tmpfs and POSIX Shared Memory Security Hardening"
description: "tmpfs filesystems — /tmp, /dev/shm, /run — are writable in-memory surfaces used daily for payload staging and IPC abuse. This article covers mount hardening, systemd PrivateTmp isolation, size limits, abstract UNIX sockets, and managing application exceptions."
slug: linux-tmpfs-shm-security
date: 2026-05-07
lastmod: 2026-05-07
category: linux
tags:
  - tmpfs
  - shared-memory
  - posix-shm
  - mount-hardening
  - noexec
personas:
  - security-engineer
  - platform-engineer
article_number: 474
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/linux/linux-tmpfs-shm-security/
---

# Linux tmpfs and POSIX Shared Memory Security Hardening

## The Problem

Three world-writable filesystems are present on nearly every Linux system and are almost always left with their default permissive mount options: `/tmp`, `/dev/shm`, and `/run`. All three are backed by tmpfs — a virtual filesystem stored entirely in RAM with no persistent backing store. Because they are writable by all users and because their contents live in memory rather than on disk, they are a recurring staging ground for post-exploitation activity.

The concrete problems:

- `/dev/shm` is executable by default. An attacker who achieves RCE on a web application can write shellcode or a compiled ELF binary to `/dev/shm`, `mmap` it with `PROT_EXEC`, and execute it without touching the disk. The OverlayFS local privilege escalation pair CVE-2023-2640 / CVE-2023-32629 — known as GameOver(lay) — specifically used `/dev/shm` as the staging area on Ubuntu systems. The attack writes a crafted executable to `/dev/shm`, uses OverlayFS to expose it with inflated permissions, and escalates to root.
- `/tmp` is executable by default and sticky-bit world-writable. Exploits dropped to `/tmp` run directly. The sticky bit prevents deletion by non-owners but does nothing to prevent execution.
- POSIX shared memory objects created via `shm_open(3)` reside in `/dev/shm` as regular files. An attacker who can write to `/dev/shm` and `mmap` the file with `PROT_EXEC` has an in-memory execution primitive that bypasses signature-based detection looking at the filesystem.
- Abstract UNIX domain sockets (those with a null byte at the start of the name) bind to the kernel's abstract socket namespace, which has no filesystem representation and no inode-level permissions. Any process in the same network namespace can connect to an abstract socket regardless of DAC permissions. Services communicating through abstract sockets are invisible to tools that only walk `/var/run`.
- A process that can write arbitrarily to a world-writable tmpfs can exhaust the host's available RAM and swap, causing an out-of-memory event that can be weaponised into a denial-of-service condition.

None of these problems require kernel exploits. They are reliably exploitable by any unprivileged process on a default-configured system.

**Target systems:** Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, Debian 12, RHEL 9 / Rocky Linux 9.

## Threat Model

- **Adversary:** Attacker with unprivileged code execution on the host — a compromised web application, a malicious container escaping to the host, or a CI job running untrusted code.
- **Access level:** Unprivileged local user with the ability to write files to world-writable directories and create POSIX shared memory objects.
- **Objectives:**
  - Stage and execute payloads in memory without writing to persistent storage, evading endpoint agents that monitor disk activity.
  - Abuse `shm_open` / `mmap` to create executable mappings from `/dev/shm` for privilege escalation.
  - Exhaust RAM via unbounded tmpfs writes to trigger OOM and disrupt services.
  - Race another process on a TOCTOU-vulnerable path in `/tmp` to substitute a file with a symlink, redirecting a privileged write to an attacker-chosen target.
  - Communicate covertly with a malicious process via an abstract UNIX socket that bypasses filesystem-permission inspection.
- **Blast radius:** Successful privilege escalation from one compromised service affects all workloads on the host. On a Kubernetes node, host root grants access to all pod secrets and kubelet credentials.

## Mount Hardening Options

Three mount flags apply to tmpfs and block the most commonly exploited default behaviours:

| Flag | Effect | Notes |
|------|--------|-------|
| `noexec` | The kernel refuses `execve` and `mmap(PROT_EXEC)` against files on this filesystem | Most important on `/dev/shm` and `/tmp` |
| `nosuid` | `setuid` and `setgid` bits on executables are ignored | Prevents a setuid binary dropped to `/tmp` from escalating |
| `nodev` | Block and character device files cannot be opened by path | Prevents raw disk access through device nodes in `/tmp` |

These flags interact with the kernel at the VFS layer, not at userspace. They are enforced on every `mmap` and `execve` call against files on the affected filesystem — there is no userspace bypass available to an unprivileged process.

### /etc/fstab Hardening

If `/tmp` and `/dev/shm` are not listed in `/etc/fstab`, add them. If they are already listed, update the options column. The `size=` limit is critical — without it a single unprivileged process can `dd if=/dev/zero` into `/tmp` until the system OOMs.

```conf
# /etc/fstab

# /tmp: in-memory, 2 GiB cap, no execution, no setuid, no devices
tmpfs   /tmp     tmpfs  defaults,noexec,nosuid,nodev,size=2G   0 0

# /dev/shm: POSIX shared memory — most payloads are staged here
tmpfs   /dev/shm tmpfs  defaults,noexec,nosuid,nodev,size=512M 0 0

# /run: PID files and sockets — execution not needed here
tmpfs   /run     tmpfs  defaults,noexec,nosuid,nodev,size=256M,mode=755 0 0

# /var/tmp: persists across reboots, same risk profile as /tmp
# If /var/tmp is a separate ext4/xfs partition, use the same options:
/dev/sda5 /var/tmp ext4  defaults,noexec,nosuid,nodev           0 2
```

Apply without rebooting:

```bash
sudo mount -o remount,noexec,nosuid,nodev,size=2G     /tmp
sudo mount -o remount,noexec,nosuid,nodev,size=512M   /dev/shm
sudo mount -o remount,noexec,nosuid,nodev              /run

# Verify — OPTIONS column must contain noexec,nosuid,nodev
findmnt -o TARGET,OPTIONS /tmp /dev/shm /run
```

### Systemd Mount Units

Systemd generates mount units from `/etc/fstab`, but you can also write drop-in overrides for the units it generates automatically. The unit names are derived from the mount point path by replacing `/` with `-` and appending `.mount`.

```bash
# The generated unit name for /dev/shm
systemctl cat dev-shm.mount

# Override: harden options without replacing the full unit
sudo mkdir -p /etc/systemd/system/dev-shm.mount.d/
```

```ini
# /etc/systemd/system/dev-shm.mount.d/hardened.conf
[Mount]
Options=defaults,noexec,nosuid,nodev,size=512M
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart dev-shm.mount
systemctl show dev-shm.mount --property=Options
```

The same pattern applies to `tmp.mount` and `run.mount`. Systemd ships default units for all three — override rather than replace to survive package upgrades.

## /dev/shm and POSIX Shared Memory Exploitation

POSIX shared memory is created with `shm_open(3)` (equivalent to `open(2)` on a file under `/dev/shm`) and mapped into a process's address space with `mmap(2)`. On a default system with an executable `/dev/shm`, this sequence gives an attacker in-memory code execution:

```c
// Attacker primitive: write shellcode to /dev/shm and execute it
int fd = shm_open("/payload", O_RDWR | O_CREAT, 0700);
ftruncate(fd, shellcode_len);
void *p = mmap(NULL, shellcode_len,
               PROT_READ | PROT_WRITE | PROT_EXEC,
               MAP_SHARED, fd, 0);
memcpy(p, shellcode, shellcode_len);
((void(*)())p)();   // jump to shellcode
```

With `noexec` on `/dev/shm`, the `mmap` call with `PROT_EXEC` returns `EACCES`. The payload is written to disk but cannot be made executable by mapping it from the file descriptor — the kernel enforces this at the `do_mmap` path regardless of the calling process's capabilities.

The GameOver(lay) CVE pair (CVE-2023-2640 / CVE-2023-32629) relied on this exact primitive: a crafted executable was written to `/dev/shm`, then OverlayFS tricks were used to expose it with elevated SUID permissions through a user namespace. Systems with `noexec` on `/dev/shm` broke a prerequisite of the exploit chain before the OverlayFS layer was even reached.

Check the current state before hardening:

```bash
# Confirm /dev/shm is executable (bad: exec in output means no noexec)
findmnt -n -o OPTIONS /dev/shm | tr ',' '\n' | grep -E '^(no)?exec'

# List POSIX shared memory objects currently open on the system
ls -la /dev/shm/

# Check which processes have /dev/shm mappings with EXEC permissions
grep -r ' r-xp .*/dev/shm/' /proc/*/maps 2>/dev/null
```

## tmpfs Size Limits

Without a `size=` option, tmpfs expands to fill all available RAM and swap. An unprivileged process can perform a RAM exhaustion attack:

```bash
# Unprivileged DoS — fills /tmp until OOM killer fires
dd if=/dev/zero of=/tmp/bomb bs=1M   # runs until OOM or disk quota
```

The `size=` mount option caps the total space the tmpfs instance can use. Setting `size=2G` on `/tmp` limits the blast radius to 2 GiB regardless of how much RAM the host has. Choose sizes based on your observed peak usage:

```bash
# Check current tmpfs usage across all mounts
df -h --type=tmpfs

# Identify largest consumers in /tmp right now
du -sh /tmp/* 2>/dev/null | sort -rh | head -20
```

For `/dev/shm`, the relevant question is how large legitimate POSIX shared memory segments get. PostgreSQL, for example, creates a shared memory segment sized to `shared_buffers`. Check running allocations:

```bash
# Show named POSIX shm objects and sizes
ls -lah /dev/shm/

# For anonymous huge shared memory (used by databases), check /proc/sysvipc
ipcs -m
```

Set the `size=` limit to 2–3× the observed peak rather than a hard minimum — applications that legitimately use shared memory will fail with `ENOSPC` if the limit is too tight, and the failure mode is often opaque.

## /tmp Sticky Bit and TOCTOU Risks

The `/tmp` sticky bit (`chmod +t /tmp`, mode 1777) prevents users from deleting each other's files. It does not prevent TOCTOU (time-of-check-to-time-of-use) attacks against programs that create predictable filenames in `/tmp`.

The canonical pattern: a privileged process checks whether `/tmp/workfile` exists, creates it if not, then writes sensitive data to it. An attacker who wins the race between the check and the create can place a symlink at `/tmp/workfile` pointing to `/etc/passwd`. The privileged process then writes to the symlink target.

Verify the sticky bit is set (it should be by default, but confirm after hardening):

```bash
stat /tmp | grep -i access
# Expected: Access: (1777/drwxrwxrwt)
```

For newly written code, use `O_TMPFILE` or `mkstemp(3)` which create files atomically with a unique name, bypassing the race:

```bash
# Safe temporary file creation (shell)
tmpfile=$(mktemp /tmp/app.XXXXXXXXXX)
# Kernel-side: open(2) with O_TMPFILE | O_RDWR on Linux 3.11+
```

The sticky bit cannot prevent all TOCTOU races — it only prevents deletion. The correct defence is `PrivateTmp=yes` in systemd units, which removes the shared namespace entirely.

## Systemd PrivateTmp Isolation

`PrivateTmp=yes` in a systemd service unit mounts a private, service-specific tmpfs over `/tmp` and `/var/tmp` within the service's mount namespace. The service sees an empty, fresh `/tmp` that is invisible to all other processes on the host, including other services. No other process can read, write, or race on the service's temporary files.

```ini
# /etc/systemd/system/myapp.service
[Unit]
Description=My Application

[Service]
ExecStart=/usr/bin/myapp
PrivateTmp=yes        # isolated /tmp and /var/tmp
PrivateDevices=yes    # no device files
NoNewPrivileges=yes   # no setuid escalation
ProtectSystem=strict  # / and /usr read-only
ProtectHome=yes       # /home, /root, /run/user read-only

[Install]
WantedBy=multi-user.target
```

Apply and verify:

```bash
sudo systemctl daemon-reload
sudo systemctl restart myapp

# Confirm the private mount is active
systemctl show myapp.service --property=PrivateTmp
# Expected: PrivateTmp=yes

# Check from inside the service namespace
nsenter -t $(systemctl show -p MainPID --value myapp.service) -m \
    findmnt /tmp
# The source should show 'tmpfs' with a unique kernel ID different from
# the host's /tmp mount
```

`PrivateTmp=yes` also resolves the application-exec exception problem: if a service legitimately needs to execute binaries from its own `/tmp` (JVM class extraction, Python native extension loading), you can mount the private `/tmp` with `exec` without opening the host's global `/tmp` to execution:

```ini
[Service]
PrivateTmp=yes
# The private tmpfs defaults to exec. No host-wide /tmp exec needed.
```

Note that `PrivateTmp=yes` applies only to processes started by the unit. Shell sessions, `su` invocations, and `systemd-run --user` processes all use the host's `/tmp`. The host-level `noexec` mount options remain essential.

## Abstract UNIX Socket Namespace

Abstract UNIX domain sockets are identified by a pathname where the first byte is a null character. They bind to the kernel's abstract socket namespace rather than the filesystem. Because there is no filesystem inode, there are no permission bits — any process in the same network namespace can connect to an abstract socket by name.

This creates a monitoring blind spot: filesystem-based auditing tools, tools that walk `/var/run`, and tools that check socket file permissions are all ineffective against abstract sockets. Processes can communicate covertly over abstract sockets without leaving any filesystem artefact.

Enumerate abstract sockets currently in use:

```bash
# /proc/net/unix — all UNIX domain sockets; abstract sockets have @ prefix
# in the ss output (the @ is ss's rendering of the leading null byte)
ss -xlp | grep '@'

# Raw /proc view — abstract names appear with \0 prefix (shown as empty path start)
cat /proc/net/unix | awk '$NF ~ /^@/ { print $NF, $(NF-1) }' | sort

# With socket state and owning process
ss -xlnp state listening | head -40
```

A socket name starting with `@` in `ss` output or with a blank leading field in `/proc/net/unix` is abstract. Legitimate abstract sockets include D-Bus (`@/tmp/dbus-...`), X11 (`@/tmp/.X11-unix/X0`), and some GNOME and systemd IPC paths.

Audit unfamiliar entries:

```bash
# Find PID owning an abstract socket (if ss shows the inode)
ss -xlp | grep '@myapp-secret'
# Output includes pid=NNNN; cross-reference with:
ls -la /proc/NNNN/exe
cat /proc/NNNN/cmdline | tr '\0' ' '
```

Add auditd rules to detect processes binding to new abstract sockets on servers where the set of expected abstract sockets is stable:

```conf
# /etc/audit/rules.d/80-abstract-sockets.rules
# Detect bind() calls on AF_UNIX sockets — abstract socket creation
# syscall 49 is bind(2) on x86-64
-a always,exit -F arch=b64 -S bind -F a0!=0 -k unix_socket_bind
```

Restrict containers from accessing the host abstract socket namespace by placing them in a separate network namespace (`--network=none` or a dedicated CNI network in Kubernetes). Abstract sockets are scoped to the network namespace — a container with its own network namespace cannot reach abstract sockets bound in the host namespace.

## Application Impact: exec in /tmp Exceptions

Several legitimate workloads require execution from tmpfs paths. The correct response is per-service exception management, not globally relaxing `/tmp` to `exec`.

Common cases:

| Application | Behaviour | Solution |
|-------------|-----------|----------|
| JVM (HotSpot, GraalVM) | Extracts JIT-compiled native code and JVM shared libraries to a temp directory, then `dlopen`s them | Set `-Djava.io.tmpdir=/var/lib/jvm-work` on an exec-capable bind mount, or use `PrivateTmp=yes` |
| Python (ctypes, cffi) | Compiles C extensions to `tempfile.gettempdir()` — defaults to `/tmp` | Set `TMPDIR` in the systemd unit to an exec-capable path |
| Node.js (node-gyp, some native addons) | Extracts `.node` shared objects during startup | Set `npm_config_cache` and `TMPDIR` to an exec-capable directory |
| Ansible (on the managed node) | Copies and executes Python modules via `/tmp` or `~/.ansible/tmp` | Set `remote_tmp` in `ansible.cfg` to a path on a filesystem with `exec`, or use `ansible_remote_tmp=/var/ansible-tmp` on a dedicated ext4 mount |
| Chrome/Chromium headless | Uses `/dev/shm` for renderer sandbox; fails with `--disable-dev-shm-usage` absent | Pass `--disable-dev-shm-usage --no-sandbox` or mount a larger `/dev/shm` without `noexec` for the browser service only |
| PostgreSQL (older builds) | Uses System V shared memory (`SYSV`) not POSIX shm; unaffected by `/dev/shm` options | No exception needed for modern PostgreSQL (≥9.3) which uses POSIX shm read-only |

Detection — identify which processes are actively executing from tmpfs mounts:

```bash
#!/bin/bash
# find-tmpfs-exec.sh
# Report processes with exec mappings into tmpfs-backed paths

for pid_dir in /proc/[0-9]*/maps; do
    pid=$(echo "$pid_dir" | grep -oP '(?<=/proc/)\d+')
    [ -r "$pid_dir" ] || continue
    if grep -q ' r-xp .*/tmp\|/dev/shm\|/run/' "$pid_dir" 2>/dev/null; then
        comm=$(cat /proc/"$pid"/comm 2>/dev/null)
        echo "PID $pid ($comm): exec mapping in tmpfs path"
        grep ' r-xp .*/tmp\|/dev/shm\|/run/' "$pid_dir"
    fi
done
```

For each identified process, create a dedicated exec-capable directory and redirect that application's tmpdir there:

```bash
# Create an exec-capable tmpdir for a specific service
sudo mkdir -p /var/lib/myapp/tmp
sudo chown myapp:myapp /var/lib/myapp/tmp
```

```ini
# /etc/systemd/system/myapp.service
[Service]
Environment=TMPDIR=/var/lib/myapp/tmp
PrivateTmp=no   # disabled because we manage our own tmpdir
```

Mount `/var/lib/myapp/tmp` as a separate tmpfs with only `nosuid,nodev` (allowing exec) and a tight size limit:

```conf
# /etc/fstab — per-service exec-capable tmpfs
tmpfs  /var/lib/myapp/tmp  tmpfs  defaults,nosuid,nodev,size=512M,uid=myapp,gid=myapp,mode=700  0 0
```

This grants exec capability to exactly one service on exactly one mount point, leaving `/tmp` and `/dev/shm` fully hardened for everything else.

## Verification

A single script to validate the expected state after hardening:

```bash
#!/bin/bash
# verify-tmpfs-hardening.sh

FAIL=0

check() {
    local label="$1" mp="$2" flag="$3"
    if findmnt -n -o OPTIONS "$mp" 2>/dev/null | grep -qw "$flag"; then
        printf "OK   %-20s has %s\n" "$mp" "$flag"
    else
        printf "FAIL %-20s missing %s\n" "$mp" "$flag"
        FAIL=1
    fi
}

check_size() {
    local mp="$1"
    local size
    size=$(findmnt -n -o OPTIONS "$mp" 2>/dev/null | grep -oP 'size=\K[^,]+')
    if [ -n "$size" ]; then
        printf "OK   %-20s size limit: %s\n" "$mp" "$size"
    else
        printf "WARN %-20s no size= limit set\n" "$mp"
    fi
}

echo "=== Mount flags ==="
for mp in /tmp /dev/shm /run; do
    check "$mp" "$mp" noexec
    check "$mp" "$mp" nosuid
    check "$mp" "$mp" nodev
    check_size "$mp"
done

echo ""
echo "=== Sticky bit ==="
stat_out=$(stat -c '%a' /tmp)
if [[ "$stat_out" =~ ^1 ]]; then
    echo "OK   /tmp has sticky bit (mode: $stat_out)"
else
    echo "FAIL /tmp missing sticky bit (mode: $stat_out)"
    FAIL=1
fi

echo ""
echo "=== Active exec mappings in tmpfs paths ==="
found=0
for maps in /proc/[0-9]*/maps; do
    pid=$(echo "$maps" | grep -oP '(?<=/proc/)\d+')
    [ -r "$maps" ] || continue
    if grep -qE ' r-xp .+(/tmp|/dev/shm|/run)/' "$maps" 2>/dev/null; then
        comm=$(cat /proc/"$pid"/comm 2>/dev/null)
        echo "WARN PID $pid ($comm) has exec mapping in tmpfs path"
        found=1
    fi
done
[ "$found" -eq 0 ] && echo "OK   No exec mappings found in /tmp, /dev/shm, /run"

echo ""
if [ "$FAIL" -eq 0 ]; then
    echo "ALL CHECKS PASSED"
    exit 0
else
    echo "SOME CHECKS FAILED"
    exit 1
fi
```

## Trade-offs

| Change | What breaks | Workaround |
|--------|-------------|------------|
| `noexec` on `/tmp` | JVM JIT cache extraction, Python native extension compilation, Ansible remote modules | Redirect `TMPDIR` per service; use `PrivateTmp=yes` with exec-capable private tmpfs |
| `noexec` on `/dev/shm` | Chrome headless renderer, some older memcached builds that self-modify | Pass `--disable-dev-shm-usage` to Chrome; upgrade memcached; isolate with a per-service exec-capable tmpfs |
| `size=` limits on `/tmp` | Large package extractions (`dpkg`, `rpm` unpacking multi-GB installers) | Temporarily `mount -o remount,size=8G /tmp` before the operation, remount back after |
| `size=` on `/dev/shm` | PostgreSQL with large `shared_buffers` may fail to allocate its shared segment | Set `size=` to 1.5× PostgreSQL `shared_buffers`; or redirect PostgreSQL to a dedicated POSIX shm mount |
| `PrivateTmp=yes` | Services that use `/tmp` as an IPC channel between separate processes | Move IPC to `/run` sockets (also tmpfs, namespaced per-service by `RuntimeDirectory=`) |

## Failure Modes

**`fstab` syntax error causes boot failure.** Always run `sudo mount -a` after editing `/etc/fstab` to validate syntax before the next reboot. A failed `/dev/shm` mount on boot drops systemd into degraded state; `/tmp` failure can cause early-boot services to crash before the emergency shell is available.

**Remount without `size=` removes the size cap.** `mount -o remount,exec /tmp` strips options that are not explicitly re-stated only on kernels older than 5.8. On current kernels, options not mentioned in a remount are preserved. Verify with `findmnt` after every remount:

```bash
findmnt -n -o OPTIONS /tmp
```

**`PrivateTmp=yes` hides files from tools running as root outside the namespace.** `strace`, `lsof`, and `ls /tmp` run from a root shell on the host will not see files created by a service with `PrivateTmp=yes` because those tools operate in the host mount namespace. Use `nsenter` to inspect the service's namespace:

```bash
nsenter -t "$(systemctl show -p MainPID --value myapp.service)" --mount \
    ls /tmp
```

**Abstract socket monitoring creates high-volume audit logs.** The `bind` syscall fires on every socket creation. On busy application servers, filter to `AF_UNIX` specifically and scope to non-root processes:

```conf
-a always,exit -F arch=b64 -S bind -F a0=1 -F auid!=unset -F auid!=0 -k abstract_socket
```

(`a0=1` matches `AF_UNIX = 1`).

## Related Articles

- [Filesystem Mount Options That Matter](/articles/linux/filesystem-mount-options/)
- [Systemd Unit Hardening](/articles/linux/systemd-unit-hardening/)
- [systemd-tmpfiles and snap-confine Race Condition](/articles/linux/systemd-tmpfiles-snap-confine-lpe/)
- [Linux Capability Hardening](/articles/linux/linux-capability-hardening/)
- [Auditd Deep Dive](/articles/linux/auditd-deep-dive/)
