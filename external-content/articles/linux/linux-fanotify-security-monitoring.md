---
title: "Linux fanotify for Real-Time Filesystem Security Monitoring"
description: "fanotify gives your security daemon filesystem-wide visibility and the ability to block file operations before they complete. This article covers permission events, FAN_MARK_FILESYSTEM, path resolution with FAN_REPORT_DFID_NAME, and how fanotify fits alongside auditd and eBPF."
slug: linux-fanotify-security-monitoring
date: 2026-05-07
lastmod: 2026-05-07
category: linux
tags:
  - fanotify
  - inotify
  - file-integrity
  - intrusion-detection
  - ebpf
personas:
  - security-engineer
  - platform-engineer
article_number: 472
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/linux/linux-fanotify-security-monitoring/
---

# Linux fanotify for Real-Time Filesystem Security Monitoring

## The Problem

Every anti-malware scanner, DLP agent, and file-integrity monitor on Linux needs the same thing: a reliable stream of "this process just opened / wrote / executed this file" events, delivered fast enough to block the operation if needed.

`inotify` is the historical answer and it falls short in four concrete ways:

1. **Per-inode watches.** You must explicitly call `inotify_add_watch()` for every directory you care about. Monitoring `/usr` means watching hundreds of directories and updating the watch list every time a subdirectory is created. Race conditions between directory creation and watch installation are real.
2. **No path in events.** `inotify` returns a watch descriptor and a filename component. Reconstructing the full path requires mapping watch descriptors back to directories you're already tracking — a bookkeeping problem, not a kernel feature.
3. **No blocking.** `inotify` is notification-only. By the time your daemon processes `IN_CLOSE_WRITE`, the bytes are already on disk. You cannot intercept and deny the operation.
4. **No process identity.** `inotify` events carry no PID. You can't tell which process triggered the event without racing to correlate `/proc` state.

`fanotify` (Linux 2.6.37, significantly extended through 5.x) was designed to fix all of these. It is the API that RHEL's `fapolicyd`, ClamAV's on-access scanner, and most commercial endpoint protection agents on Linux use under the hood.

## inotify vs fanotify: What Actually Changes

| Capability | inotify | fanotify |
|---|---|---|
| Scope | Per-directory watch | Per-mount or per-filesystem |
| Path in event | No (watch descriptor + filename component) | Yes (with `FAN_REPORT_DFID_NAME`, kernel 5.1+) |
| PID in event | No | Yes |
| Blocking mode | No | Yes (`FAN_CLASS_CONTENT`, `FAN_CLASS_PRE_CONTENT`) |
| Permission decisions | No | Yes (`FAN_OPEN_PERM`, `FAN_ACCESS_PERM`) |
| Binary execution events | No | Yes (`FAN_OPEN_EXEC_PERM`) |
| Kernel version | 2.6.13 | 2.6.37 (full features: 5.1+) |

The `FAN_CLASS_*` hierarchy controls what your daemon can do with events:

- `FAN_CLASS_NOTIF` — notification only, no blocking. Equivalent to an enriched `inotify`.
- `FAN_CLASS_CONTENT` — can intercept file reads/opens. Used by on-access virus scanners.
- `FAN_CLASS_PRE_CONTENT` — can intercept partial-write events. Used by hierarchical storage managers, but also useful for DLP on write interception.

Only one process can hold `FAN_CLASS_PRE_CONTENT` per mount. Multiple processes can hold `FAN_CLASS_CONTENT` and `FAN_CLASS_NOTIF` simultaneously — they queue independently.

## Filesystem-Wide Marks: FAN_MARK_FILESYSTEM

The most important operational improvement over `inotify` is `FAN_MARK_FILESYSTEM`. Instead of walking a directory tree and adding individual watches, a single `fanotify_mark()` call covers everything under a mount point:

```c
int fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK, O_RDONLY | O_LARGEFILE);

// Watch the entire filesystem containing /usr
fanotify_mark(fan_fd,
    FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
    FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM | FAN_CLOSE_WRITE,
    AT_FDCWD, "/usr");
```

The `FAN_MARK_FILESYSTEM` flag requires `CAP_SYS_ADMIN`. This is intentional: a filesystem-wide mark intercepts every open on the mount, including operations by root. The kernel will not let unprivileged processes install such a broad net.

Marks are additive. You can layer:

```c
// Also watch /etc for config mutations
fanotify_mark(fan_fd,
    FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
    FAN_CLOSE_WRITE | FAN_MOVED_TO,
    AT_FDCWD, "/etc");
```

To exclude noisy paths from a filesystem-wide mark use `FAN_MARK_IGNORED_MASK`:

```c
// Suppress events for /var/log (high-volume writes, low-value for this use case)
fanotify_mark(fan_fd,
    FAN_MARK_ADD | FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORED_SURV_MODIFY,
    FAN_CLOSE_WRITE,
    AT_FDCWD, "/var/log");
```

## Permission Events: FAN_OPEN_PERM and FAN_ACCESS_PERM

Permission events are the blocking primitive. When the kernel delivers a `FAN_OPEN_PERM` event, the opening process is suspended in the kernel waiting for your daemon to write a response. Until you respond, the `open()` syscall does not return.

This is the mechanism anti-malware scanners use: the file open is held, the scanner reads the file descriptor from the event, scans it, then writes allow or deny back to the fanotify fd.

The response is a `struct fanotify_response`:

```c
struct fanotify_response response = {
    .fd  = event->fd,
    .response = FAN_ALLOW,   // or FAN_DENY
};
write(fan_fd, &response, sizeof(response));
```

`FAN_DENY` causes the syscall in the triggering process to return `EPERM`. The file is never opened from the process's perspective.

**Key events for security monitoring:**

| Event flag | Triggered when | Blocking? |
|---|---|---|
| `FAN_OPEN_PERM` | Any `open()` / `openat()` | Yes |
| `FAN_ACCESS_PERM` | `read()` on a watched inode | Yes |
| `FAN_OPEN_EXEC_PERM` | `execve()` of a watched file | Yes |
| `FAN_CLOSE_WRITE` | File closed after write | No (notification) |
| `FAN_MOVED_TO` | File renamed/moved into watched path | No |
| `FAN_CREATE` | File created in watched directory | No |
| `FAN_DELETE` | File deleted | No |

`FAN_OPEN_EXEC_PERM` deserves special attention. It fires when the kernel is about to execute the file — after the `execve()` is called but before the new process image is loaded. Your daemon can deny execution of files that fail a hash check, aren't in an allowlist, or were written by an untrusted process. This is the foundation of application allowlisting on Linux without LSM policy.

## Getting File Paths: FAN_REPORT_DFID_NAME (Linux 5.1+)

Before kernel 5.1, fanotify events gave you an open file descriptor to the affected file. You could read the file, but mapping it back to a path required `readlink(/proc/self/fd/<n>)` — fragile if the file was deleted between the event and your read, and wrong if it was hardlinked under multiple paths.

Linux 5.1 introduced `FAN_REPORT_DFID_NAME`. Pass it to `fanotify_init()` and events include:

- A `file_handle` identifying the directory containing the file
- The filename component as a null-terminated string appended to the event structure

```c
int fan_fd = fanotify_init(
    FAN_CLASS_NOTIF | FAN_REPORT_DFID_NAME | FAN_CLOEXEC | FAN_NONBLOCK,
    O_RDONLY | O_LARGEFILE
);
```

Reading events with `FAN_REPORT_DFID_NAME` requires walking a variable-length structure. Each event is followed by a `fanotify_event_info_fid` header, then the `file_handle`, then the filename:

```c
struct fanotify_event_metadata *meta;
struct fanotify_event_info_fid *fid;
char buf[4096];
ssize_t n;

while ((n = read(fan_fd, buf, sizeof(buf))) > 0) {
    meta = (struct fanotify_event_metadata *)buf;
    while (FAN_EVENT_OK(meta, n)) {
        if (meta->mask & FAN_EVENTS_BITS) {
            fid = (struct fanotify_event_info_fid *)(meta + 1);
            struct file_handle *fh = (struct file_handle *)fid->handle;

            // Filename is after the variable-length file_handle
            char *fname = (char *)fh->f_handle + fh->handle_bytes;

            // Open the directory by handle to get a real fd
            int dir_fd = open_by_handle_at(AT_FDCWD, fh, O_RDONLY);
            if (dir_fd >= 0) {
                // Now we have: dir_fd + fname = the full file
                // You can openat(dir_fd, fname, ...) to read it
                // or readlink /proc/self/fd/<dir_fd> + "/" + fname for the path
                close(dir_fd);
            }
        }
        if (meta->fd != FAN_NOFD)
            close(meta->fd);   // Always close the event fd
        meta = FAN_EVENT_NEXT(meta, n);
    }
}
```

`open_by_handle_at()` requires `CAP_DAC_READ_SEARCH`. On kernels before 5.1, fall back to `readlink(/proc/self/fd/<event_fd>)` but accept that deleted-file races exist.

Linux 5.9 added `FAN_REPORT_PIDFD` — instead of a PID that may be recycled, events carry a pidfd that remains valid until you close it. This eliminates TOCTOU races when correlating event PIDs to process metadata.

## Practical C Skeleton: Init, Mark, Read, Respond

A minimal but production-shaped fanotify daemon has four layers:

```c
#define _GNU_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#define EVENT_BUF_LEN (10 * (sizeof(struct fanotify_event_metadata) + NAME_MAX + 1))

static int fan_fd;

static void send_response(int event_fd, uint32_t response_type) {
    struct fanotify_response resp = {
        .fd       = event_fd,
        .response = response_type,
    };
    if (write(fan_fd, &resp, sizeof(resp)) < 0)
        perror("fanotify response write");
    close(event_fd);
}

static int is_trusted_write(pid_t pid) {
    // Placeholder: read /proc/<pid>/exe, check against allowlist
    // In production: use pidfd_open + /proc/self/fdinfo for race-safe check
    return 0;
}

int main(void) {
    fan_fd = fanotify_init(
        FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK | FAN_REPORT_PIDFD,
        O_RDONLY | O_LARGEFILE | O_CLOEXEC
    );
    if (fan_fd < 0) { perror("fanotify_init"); return 1; }

    // Block execution of anything written to /usr on this filesystem
    if (fanotify_mark(fan_fd,
            FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
            FAN_OPEN_EXEC_PERM | FAN_CLOSE_WRITE,
            AT_FDCWD, "/usr") < 0) {
        perror("fanotify_mark /usr"); return 1;
    }

    // Alert on /etc writes (config tampering)
    if (fanotify_mark(fan_fd,
            FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
            FAN_CLOSE_WRITE | FAN_MOVED_TO,
            AT_FDCWD, "/etc") < 0) {
        perror("fanotify_mark /etc"); return 1;
    }

    char buf[EVENT_BUF_LEN] __attribute__((aligned(8)));
    for (;;) {
        ssize_t n = read(fan_fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EAGAIN) continue;   // non-blocking, no events
            perror("fanotify read"); break;
        }

        struct fanotify_event_metadata *ev =
            (struct fanotify_event_metadata *)buf;

        while (FAN_EVENT_OK(ev, n)) {
            if (ev->vers != FANOTIFY_METADATA_VERSION) {
                fprintf(stderr, "kernel/userspace version mismatch\n");
                goto done;
            }

            pid_t pid = ev->pid;
            char exe[PATH_MAX];
            snprintf(exe, sizeof(exe), "/proc/%d/exe", pid);
            char target[PATH_MAX];
            ssize_t l = readlink(exe, target, sizeof(target) - 1);
            if (l > 0) target[l] = '\0';
            else snprintf(target, sizeof(target), "<unknown>");

            if (ev->mask & FAN_OPEN_EXEC_PERM) {
                // Check if the binary is in our allowlist
                // For demo: deny anything in /usr/local/bin not signed
                fprintf(stderr, "[EXEC] pid=%d exe=%s\n", pid, target);
                // Real check: verify HMAC or check inode against known-good db
                send_response(ev->fd, FAN_ALLOW);
                ev->fd = FAN_NOFD;   // already closed by send_response
            }

            if (ev->mask & FAN_CLOSE_WRITE) {
                char path[PATH_MAX];
                if (ev->fd != FAN_NOFD) {
                    snprintf(exe, sizeof(exe), "/proc/self/fd/%d", ev->fd);
                    ssize_t pl = readlink(exe, path, sizeof(path) - 1);
                    if (pl > 0) path[pl] = '\0';
                    else snprintf(path, sizeof(path), "<unknown>");
                }
                fprintf(stderr, "[WRITE] pid=%d path=%s\n", pid, path);
                // Emit to SIEM here (syslog, structured JSON to stdout, etc.)
            }

            if (ev->fd != FAN_NOFD) close(ev->fd);
            ev = FAN_EVENT_NEXT(ev, n);
        }
    }

done:
    close(fan_fd);
    return 0;
}
```

Compile with:

```bash
gcc -O2 -Wall -o fan_monitor fan_monitor.c
# Requires CAP_SYS_ADMIN to run; on a non-root user:
sudo setcap cap_sys_admin,cap_dac_read_search+eip ./fan_monitor
```

## Security Monitoring Use Cases

### Detecting Unauthorized Binary Writes to /usr/bin and /lib

An attacker who achieves RCE will frequently try to persist by dropping a binary into a standard search-path directory. A `FAN_CLOSE_WRITE | FAN_MARK_FILESYSTEM` mark on `/usr` with `FAN_CLOSE_WRITE` catches the write after the file is closed — the full content is committed. Cross-reference the writing PID against a list of blessed package-manager processes (dpkg, rpm, dnf). Any other writer is anomalous.

```bash
# Verify your mark is active
cat /proc/<fan_pid>/fdinfo/<fan_fd>
# Output includes: fanotify flags, event queue size, inode table size
```

### Alerting on /etc/passwd Writes

`/etc/passwd` writes indicate account creation or modification. With `FAN_CLOSE_WRITE` on `/etc`:

```c
if (strstr(path, "/etc/passwd") || strstr(path, "/etc/shadow")) {
    alert_siem("CREDENTIAL_FILE_MODIFIED", pid, path);
}
```

Combine with the writing process's cmdline and parent PID to distinguish `useradd` (expected) from a web process writing directly to `/etc/shadow` (critical alert).

### Blocking Execution of Files Written by Untrusted Processes

This is the "write-then-exec" attack pattern: download a payload, write it to `/tmp`, `chmod +x`, execute. With `FAN_OPEN_EXEC_PERM` on the filesystem:

1. On `FAN_CLOSE_WRITE`: record `(inode, device, sha256)` → `writer_pid_exe` in a hash map.
2. On `FAN_OPEN_EXEC_PERM`: look up the inode in the hash map. If the writer was not a trusted package manager, respond `FAN_DENY`.

This requires tracking inodes across events, handling hardlinks (same inode, multiple paths), and expiring old entries. The inode + device pair is your stable identity — not the path, which can be renamed under you.

### Application Allowlisting Without LSM

`fapolicyd` (used in RHEL/Fedora) implements exactly this pattern: a fanotify `FAN_OPEN_EXEC_PERM` daemon that checks executing binaries against a hash database. No SELinux policy required, no kernel module, just a daemon with `CAP_SYS_ADMIN`. The commercial equivalent is SentinelOne, CrowdStrike Falcon, and Carbon Black's kernel components — all built on the same fanotify primitives on Linux.

## fanotify vs auditd: When to Use Each

These tools are not alternatives — they serve fundamentally different purposes and you should run both.

| Concern | fanotify | auditd |
|---|---|---|
| Real-time blocking | Yes — holds the syscall | No — post-fact notification |
| Full syscall coverage | No — filesystem events only | Yes — all syscalls, netfilter, user space |
| PID/process metadata | Yes | Yes |
| Compliance logging (PCI, HIPAA) | Not designed for this | Yes — tamper-evident audit trail |
| User/UID context | Via /proc correlation | Native in audit record |
| Network events | No | Yes (via audit rules) |
| Kernel version dependency | 5.1+ for full features | All kernels |
| Performance at scale | High (in-kernel filtering) | Moderate (rule ordering critical) |

**Rule of thumb:** Use fanotify when you need to block. Use auditd when you need a forensic record. For SOC workflows, pipe fanotify alerts to your SIEM alongside auditd logs — fanotify tells you what was stopped, auditd tells you everything that happened around it.

A common architecture layers them:

```
fanotify daemon  →  blocks exec of unknown binaries, alerts on /etc writes
auditd           →  logs all execves, setuid calls, network connects, cron changes
SIEM             →  correlates both streams
```

## eBPF as Complement: Where fanotify Falls Short

fanotify operates at the VFS layer — it sees file operations, not the full syscall context around them. Two gaps where eBPF fills in:

**1. Syscall argument granularity.** fanotify tells you a file was opened. An eBPF `kprobe` on `do_sys_open` or an LSM hook on `security_file_open` can capture the full `open()` flags, the calling process's capability set, the cgroup, and the network namespace — context fanotify doesn't surface.

**2. Memory-mapped execution.** `mmap(PROT_EXEC)` on a file doesn't trigger `FAN_OPEN_EXEC_PERM`. Shellcode loaded via `mmap` is invisible to fanotify. eBPF LSM hooks on `security_mmap_file` catch this. This is a genuine blind spot: attackers loading shellcode via `mmap` from a writable+executable anonymous mapping bypass fanotify entirely, though an eBPF LSM hook on `security_mmap_addr` can catch anonymous executable mappings.

**3. Container namespaces.** A `FAN_MARK_FILESYSTEM` mark placed from the host covers all containers sharing that filesystem. eBPF programs can carry namespace context in their map keys, enabling per-container policy without the host-wide blast radius of a fanotify mark.

For a full treatment of eBPF LSM hooks, see [eBPF-LSM (lsm_bpf): Kernel Security Policy as Hot-Loadable BPF Programs](/articles/linux/ebpf-lsm/).

## Performance Considerations

### Event Queue Sizing

The kernel fanotify queue defaults to 16,384 events. On a busy system, the queue can fill before your daemon drains it. A full queue causes the kernel to either drop events (notification mode) or block the triggering process (permission mode). Check queue depth:

```bash
cat /proc/sys/fs/fanotify/max_queued_events   # default 16384
# Raise it for high-throughput systems:
sysctl -w fs.fanotify.max_queued_events=65536
```

Monitor queue saturation:

```bash
# Events dropped due to queue overflow appear in kernel log
dmesg | grep fanotify
```

### Avoiding Deadlocks in Permission Event Handlers

The cardinal rule: **your permission event handler must never open a file on a filesystem it is monitoring with a permission event mark.** If your handler calls `open("/usr/lib/libcrypto.so")` to initialize OpenSSL, and `/usr/lib` is marked with `FAN_OPEN_PERM`, your daemon will generate an event it needs to respond to, while it's blocked waiting to respond to a different event. Deadlock.

Practical mitigations:

1. **Pre-load all libraries before installing marks.** Call `dlopen()` and resolve all symbols before the first `fanotify_mark()`.
2. **Use a separate thread for I/O.** The event-reading thread writes events to an internal queue; a pool of worker threads handles the scanning and responds. Workers must use `O_PATH` opens or work via the event's own fd.
3. **Exclude your daemon's PID.** In the event loop, check `ev->pid == getpid()` and immediately `FAN_ALLOW` those events. Kernel 5.0+ supports `FAN_MARK_ONLYDIR` and ignore masks, but self-generated events are the most common deadlock vector.
4. **Set response timeouts.** If your scanner can stall (network lookup, heavy I/O), use a watchdog thread that sends `FAN_ALLOW` for events that haven't been responded to within N milliseconds. A stalled scanner should fail open (allow), not hang the system.

### Thread Pool Architecture

```
main thread:  read(fan_fd, buf) → dispatch to work queue
worker pool:  dequeue event → scan → write response to fan_fd
              (all workers share fan_fd for writes — this is safe)
```

Worker count should be tuned to your scan latency, not your core count. If a scan takes 50ms on average and you want to handle 100 concurrent opens, you need ~5 workers minimum. Profile with `perf stat` on the scanner process and watch for `read` saturation on `fan_fd`.

## Operational Runbook

```bash
# Verify fanotify support in running kernel
grep -r CONFIG_FANOTIFY /boot/config-$(uname -r)
# CONFIG_FANOTIFY=y
# CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y  ← required for FAN_OPEN_PERM

# Check active fanotify file descriptors system-wide
find /proc -name fdinfo -type d 2>/dev/null | xargs grep -l fanotify 2>/dev/null

# List marks on a fanotify fd (replace PID and FD)
cat /proc/<pid>/fdinfo/<fd>

# Adjust system-wide limits
sysctl fs.fanotify.max_user_marks    # default 8192 per user
sysctl fs.fanotify.max_user_instances  # default 128 per user
sysctl fs.fanotify.max_queued_events   # default 16384
```

## What This Doesn't Cover

- **NFS and FUSE mounts.** fanotify marks on NFS mounts are local-only: you monitor operations from this host, not remote writes. For distributed filesystem integrity, you need agents on each node or a centralized audit service.
- **Overlayfs (container layers).** Writes to the container layer may not surface the host path as expected. Test your marks against your container runtime before relying on them.
- **Audit trail durability.** fanotify is a live stream, not a log. If your daemon crashes, events during the outage are gone. For compliance use cases, fanotify should feed a durable sink (auditd, a structured log file, a SIEM). It is not a replacement for auditd's tamper-evident ring buffer.

fanotify is the right primitive when you need real-time filesystem visibility with blocking capability, and you understand its scope: it covers VFS operations on local filesystems, but not the full syscall surface, container namespaces, or memory-mapped execution. Used alongside auditd and eBPF, it forms a complete picture of filesystem activity on a production Linux host.
