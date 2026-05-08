---
title: "Linux Page-Cache and splice() Security"
description: "Harden Linux systems against page-cache write primitives exploited by CVE-2026-31431 (Copy Fail) and related AF_ALG/splice attack chains, with kernel config controls and patch-gap monitoring."
slug: linux-page-cache-splice-security
date: 2026-05-02
lastmod: 2026-05-02
category: linux
tags: ["page-cache", "splice", "af-alg", "cve-2026-31431", "kernel", "lpe", "crypto-api"]
personas: ["systems-engineer", "security-engineer", "platform-engineer"]
article_number: 351
difficulty: advanced
estimated_reading_time: 17
published: true
layout: article.njk
permalink: "/articles/linux/linux-page-cache-splice-security/index.html"
---

# Linux Page-Cache and splice() Security

## Problem

The Linux page-cache is the kernel's unified memory-backed store for file content. When a file is read, the kernel fetches its pages from disk into physical memory and caches them. All subsequent reads for that file — by any process on the system — are served from those same physical pages. When two processes open the same file, they share the same underlying page-cache pages. A write to a page-cache page by one process is therefore immediately visible to every other process mapping that file. This is not a bug; it is a fundamental design property that enables efficient shared libraries, copy-on-write fork semantics, and coherent memory-mapped I/O.

The `splice()` system call is designed for zero-copy data movement between file descriptors and kernel-managed pipes. Where a normal `read()` + `write()` pair copies data from kernel space to userspace and back, `splice()` keeps data inside the kernel, moving page-cache pages into a pipe's page list by transferring ownership of the underlying `struct page` reference. The calling process ends up holding a pipe buffer that refers directly to the page-cache page — the same physical page that backs the on-disk file. Under normal operation this reference is read-only: the pipe is a read reference, and the page remains write-protected to userspace. The security guarantee depends entirely on the kernel never granting a writable reference to a page-cache page belonging to a file the caller does not own with write permission.

CVE-2026-31431, disclosed on April 29, 2026 under the name "Copy Fail," breaks that guarantee through a chain involving the AF_ALG interface. AF_ALG is the kernel's userspace-accessible crypto API: processes create an `AF_ALG` socket (domain 38), bind it to a named algorithm such as `skcipher` or `aead`, and pass plaintext through `sendmsg()` for in-kernel encryption or authentication. An optimization introduced in 2017 via kernel commit `72548b093ee3` allowed the AF_ALG receive path to accept page-cache pages placed into writable scatter/gather (SG) lists for in-place crypto operations — avoiding a copy by operating on the source page directly. The intent was performance. The consequence was that a local unprivileged user could chain AF_ALG `sendmsg()` with `splice()` to obtain a writable reference to an arbitrary page-cache page.

The exploit path is concrete. An attacker `splice()`s a page from a setuid binary — `/usr/bin/su` is the canonical target — into a pipe. The pipe buffer now holds a reference to that page. The attacker then opens an AF_ALG `aead` or `skcipher` socket, binds it to an algorithm, and passes the pipe buffer as the source for an in-place crypto operation via `sendmsg()` with `MSG_MORE`. The kernel, following the 2017 optimization, marks that page writable in the SG list and hands it to the crypto engine. Before the crypto operation completes, the attacker uses a second `write()` to the pipe — which the kernel fulfills by writing into the now-writable page-cache page. The result is an arbitrary 4-byte write to the page backing `/usr/bin/su` without holding write permission to the file. Redirecting the first instruction of `main()` to a shellcode stub is sufficient for privilege escalation to root. CVSS 7.8, local, no capabilities required. The fix commit `a664bf3d603d` was merged into Linus's tree on April 1, 2026.

CVE-2026-31431 is not a novel class of bug. It is the latest instance of a recurring pattern in which the kernel's page-cache can be made writable by unprivileged users through subtle API interactions. Dirty Cow (CVE-2016-5195) exploited a race condition in the copy-on-write handler for memory-mapped files, allowing an unprivileged write to a read-only mapping. Dirty Pipe (CVE-2022-0847) exploited missing `PIPE_BUF_FLAG_CAN_MERGE` initialization in the pipe buffer, allowing a splice-then-write pattern that overwrote arbitrary page-cache pages — a near-identical mechanism to Copy Fail. The attack surface is structural: the kernel's performance optimizations routinely trade page-cache isolation for throughput, and each such trade is a potential write primitive. Setuid binaries are always the primary target because they are world-readable (so any process can `splice()` them), owned by root, and executed with elevated privilege.

A further complication is the stable-queue patch-gap. When a security fix lands in Linus's mainline tree, it does not immediately appear in distribution packages. The stable-kernel team backports the fix to maintained branches — in this case the 6.18.22 backport carried commit hash `fafe0fa2995a0f7073c1c358d7d3145bcc9aedd8` and the 6.19.12 backport carried `ce42ee423e58dffa5ec03524054c9d8bfd4f6237` — but these commits appeared in the `stable-rc` queue at `git.kernel.org` before any major distribution had shipped a patched binary package. The coordinated disclosure date of April 29, 2026 — 28 days after the mainline fix — is the formal window, but the actual window for a skilled attacker monitoring `git.kernel.org` began on April 1. CERT-EU published advisory 2026-005 on April 29; Sysdig published technical analysis the same day. Between April 1 and April 29, the fix, the changed files, and the commit message were all publicly visible to anyone watching `crypto/algif_aead.c` and `crypto/algif_skcipher.c`.

**Target systems:** Linux kernel versions ≤ 6.18.21 and ≤ 6.19.11 (unpatched). Distribution exposure: Ubuntu 24.04 LTS with kernel versions before the 6.8.x patched series; RHEL 10 kernels before the backport landed; Debian 13 with unpatched kernel packages. Any multi-tenant system — shared hosting, CI runners, container clusters where AF_ALG sockets are accessible inside pods — is in scope.

## Threat Model

1. **Local unprivileged user on a multi-tenant host.** Shared hosting provider, university HPC cluster, or CI build runner where multiple users share a kernel. The user runs the AF_ALG + splice chain against `/usr/bin/su`, achieves a writable page-cache reference, overwrites 4 bytes of the binary's mapped text, executes it, and gets a root shell. No capabilities required. No files written to disk. The write is entirely in-memory and leaves no filesystem artifact.

2. **Container workload with AF_ALG access.** AF_ALG socket creation does not require `CAP_SYS_ADMIN` by default. An attacker with code execution inside a container that lacks a seccomp profile blocking AF_ALG can attempt the same chain. If the container shares the host kernel's page-cache (which all containers do, absent filesystem namespacing for the binary in question), the attack succeeds. The container-to-host page-cache sharing is not optional: it is how the kernel works.

3. **Patch-gap attacker monitoring kernel.org.** A skilled adversary subscribes to commits touching `crypto/algif_aead.c`, `crypto/algif_skcipher.c`, `mm/splice.c`, and `mm/filemap.c`. On April 1, they observe commit `a664bf3d603d` with a message referencing removal of page-writability from the AF_ALG SG path. They read the diff, identify the write primitive, write a proof-of-concept, and have 28 days to deploy it against unpatched systems before the coordinated disclosure date triggers vendor patching. This is the canonical silent-fix exploitation pattern and it requires no vulnerability research — only kernel commit monitoring.

4. **Chained exploit combining page-cache write with an info-leak.** The page-cache write primitive from CVE-2026-31431 is most powerful when combined with a kernel address space layout randomization (KASLR) bypass. An attacker first exploits a separate info-leak vulnerability (a timing side-channel, a speculative execution leak, or an uninitialized kernel memory read) to locate the target binary's page-cache pages in the kernel virtual address space, then applies the write primitive at a precise offset. Chained exploits of this type have been demonstrated for both Dirty Cow and Dirty Pipe; the same pattern applies here.

**Blast radius.** Root on the host. On a Kubernetes node, root means access to all pod secrets mounted as volumes, the kubelet's client certificate, and cloud provider instance metadata credentials (AWS IMDSv1/v2 without hop-limit hardening, GCP metadata server). A single compromised CI runner can exfiltrate all repository secrets injected as environment variables. Container escape follows directly because root on the host can read and write all cgroup, namespace, and mount namespaces.

## Configuration / Implementation

### Immediate Mitigation: Restrict AF_ALG Sockets

The most targeted control short of patching is preventing unprivileged processes from creating AF_ALG sockets at all. AF_ALG is domain 38 (`AF_ALG`) with socket type `SOCK_SEQPACKET` (type 5). A seccomp filter can block this combination without affecting any other socket call.

Seccomp profile entry (JSON, libseccomp / Docker / Kubernetes format):

```json
{
  "syscalls": [
    {
      "names": ["socket"],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1,
      "args": [
        {
          "index": 0,
          "value": 38,
          "op": "SCMP_CMP_EQ"
        }
      ]
    }
  ]
}
```

This instructs the kernel to return `EPERM` when any process covered by this seccomp profile calls `socket()` with the first argument (domain) equal to 38. All other `socket()` calls — TCP, UDP, Unix domain, Netlink — are unaffected.

Verify the block is active:

```bash
# As the target user (should fail with EPERM after applying the profile)
python3 -c "import socket; socket.socket(38, 5, 0)"
```

A patched or protected system returns:
```
OSError: [Errno 1] Operation not permitted
```

An unprotected system returns no error and creates the socket.

For systems that cannot apply per-process seccomp profiles immediately, a coarser control is disabling unprivileged user namespaces, which limits several AF_ALG exploit chains:

```ini
# /etc/sysctl.d/60-userns.conf
kernel.unprivileged_userfaultfd = 0
kernel.unprivileged_bpf_disabled = 1
```

Apply immediately without reboot:

```bash
sudo sysctl -p /etc/sysctl.d/60-userns.conf
```

These do not block CVE-2026-31431 directly — AF_ALG does not require user namespaces — but they reduce the adjacent attack surface used in chained exploits.

### Kernel Patching Procedure

The definitive fix is applying the patched kernel. Check the running version and determine whether the fix is present:

```bash
# Check running kernel version
uname -r

# Check whether AF_ALG AEAD is compiled in (a pre-condition for the vulnerability)
zcat /proc/config.gz | grep CONFIG_CRYPTO_USER_API_AEAD
```

If `CONFIG_CRYPTO_USER_API_AEAD=y`, the code path exists. If the kernel version is ≤ 6.18.21 or ≤ 6.19.11, it is unpatched.

Find the patched package on Debian/Ubuntu:

```bash
apt-cache policy linux-image-generic
# Look for version strings incorporating 6.8.x or later with Ubuntu security suffix
apt-cache changelog linux-image-$(uname -r) | grep -i "CVE-2026-31431"
```

Find the patched package on RHEL/Fedora:

```bash
dnf updateinfo list CVE-2026-31431
dnf update --advisory CVE-2026-31431
```

After installing the patched kernel, verify the fix is active by checking for the corrected behavior in `algif_aead.c`. If `kpatch` or `livepatch` is available, apply the live patch first to close the window before the next maintenance reboot:

```bash
# RHEL: check available live patches
subscription-manager repos --list | grep livepatch
dnf install kpatch-patch

# Ubuntu: canonical livepatch
canonical-livepatch status
canonical-livepatch enable <TOKEN>
```

Priority patching applies to: any host with interactive shell access for non-root users, any CI system where job workloads run as an unprivileged UID under a shared kernel, any container host where seccomp is not enforced on all pods.

### Monitoring kernel.org for Silent Fixes

The 28-day patch gap between mainline commit and coordinated disclosure is the window in which defenders are blind if they rely only on CVE feeds. Monitoring upstream kernel commits directly closes that gap.

Create a cron job that checks for new commits to the relevant files:

```bash
#!/bin/bash
# /usr/local/bin/kernel-watch.sh
# Run daily. Requires a local mirror or use git ls-remote.

REPO="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
WATCH_FILES=(
  "crypto/algif_aead.c"
  "crypto/algif_skcipher.c"
  "mm/splice.c"
  "mm/filemap.c"
  "fs/pipe.c"
)
LAST_SEEN_FILE="/var/lib/kernel-watch/last-seen-commit"

CURRENT_HEAD=$(git ls-remote "$REPO" HEAD | awk '{print $1}')
LAST_SEEN=$(cat "$LAST_SEEN_FILE" 2>/dev/null || echo "")

if [ "$CURRENT_HEAD" = "$LAST_SEEN" ]; then
  exit 0
fi

# Clone or fetch into a shallow local mirror
MIRROR="/var/lib/kernel-watch/linux.git"
if [ ! -d "$MIRROR" ]; then
  git clone --bare --depth=50 "$REPO" "$MIRROR"
else
  git -C "$MIRROR" fetch --depth=50 origin HEAD:HEAD 2>/dev/null
fi

for FILE in "${WATCH_FILES[@]}"; do
  HITS=$(git -C "$MIRROR" log --oneline HEAD~50..HEAD -- "$FILE" 2>/dev/null)
  if [ -n "$HITS" ]; then
    echo "KERNEL WATCH ALERT: new commits to $FILE"
    echo "$HITS"
    # Send to your alerting channel: mail, Slack webhook, PagerDuty, etc.
    echo "$HITS" | mail -s "kernel-watch: $FILE changed" security@example.com
  fi
done

echo "$CURRENT_HEAD" > "$LAST_SEEN_FILE"
```

Install as a daily cron:

```bash
sudo install -m 755 /usr/local/bin/kernel-watch.sh /usr/local/bin/kernel-watch.sh
echo "0 6 * * * root /usr/local/bin/kernel-watch.sh" | sudo tee /etc/cron.d/kernel-watch
```

Additionally, cross-reference mainline commits against the kernel security advisory list:

```bash
# Check the kernel security advisories page
curl -s https://kernel.org/pub/linux/kernel/projects/security/ | grep -i "2026"
```

Subscribe to the `linux-kernel-announce` mailing list for stable release announcements:

```
List: linux-kernel-announce@vger.kernel.org
Subscribe: https://vger.kernel.org/majordomo-info.html
```

Also subscribe to CERT-EU, CISA KEV, and distro security announcement lists (`ubuntu-security-announce@lists.ubuntu.com`, `rhsa-announce@redhat.com`) so that when coordinated disclosure happens, patching automation can trigger immediately rather than waiting for the next maintenance window.

### Reducing the AF_ALG Attack Surface Long-Term

The cleanest mitigation for servers that do not use userspace kernel crypto is to disable AF_ALG entirely at kernel build time:

```
# In kernel .config or defconfig fragment:
CONFIG_CRYPTO_USER_API_AEAD=n
CONFIG_CRYPTO_USER_API_SKCIPHER=n
CONFIG_CRYPTO_USER_API_HASH=n
CONFIG_CRYPTO_USER_API_RNG=n
```

Verify that AF_ALG algorithm types are absent from the running kernel:

```bash
cat /proc/crypto | grep -A3 "aead"
# Should return nothing if CONFIG_CRYPTO_USER_API_AEAD=n
```

Custom kernel builds are required for this approach and are appropriate for appliance-style deployments, hardened cloud images, and OCI base images where the kernel build is owned. General-purpose distributions ship with `CONFIG_CRYPTO_USER_API_AEAD=y` because some userspace cryptographic libraries (OpenSSL engine via AF_ALG backend, `libkcapi`) rely on it.

On systems where a custom kernel build is not feasible but AF_ALG is confirmed unused, the runtime module can be blocked:

```bash
# /etc/modprobe.d/blacklist-af-alg.conf
blacklist algif_aead
blacklist algif_skcipher
blacklist algif_hash
install algif_aead /bin/false
install algif_skcipher /bin/false
```

Apply and rebuild the initramfs:

```bash
sudo update-initramfs -u    # Debian/Ubuntu
sudo dracut --force          # RHEL/Fedora
```

### Container Hardening Against This Class

Containers share the host kernel's page-cache. A container workload that can create an AF_ALG socket and call `splice()` can attempt the same chain as a local user, with the same result if the kernel is unpatched.

Apply the seccomp profile shown in the earlier section to all container runtimes. For Kubernetes, reference the profile via a `SeccompProfile` object and reference it in the pod's `securityContext`:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: hardened-workload
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/block-af-alg.json
    runAsNonRoot: true
    runAsUser: 65534
  containers:
    - name: app
      image: example/app:latest
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
```

For Docker:

```bash
docker run \
  --security-opt seccomp=/etc/docker/seccomp/block-af-alg.json \
  --user 65534:65534 \
  --cap-drop ALL \
  --read-only \
  example/app:latest
```

AppArmor profiles can add a network-level control, though AF_ALG is not a network socket in the traditional sense:

```
# AppArmor addition to container profile
deny network af_alg,
```

Rootless containers reduce blast radius: if the exploit succeeds inside a rootless container, the attacker gains the container user's UID on the host — still a container escape, but not immediately root on the host without a further LPE step.

### Detecting Exploitation Attempts

Audit rules that fire on AF_ALG socket creation by non-root users:

```bash
# Install audit rule (survives reboot when added to /etc/audit/rules.d/)
sudo auditctl -a always,exit \
  -F arch=b64 \
  -S socket \
  -F a0=38 \
  -F uid!=0 \
  -k af_alg_socket

# Persist across reboots
cat << 'EOF' | sudo tee /etc/audit/rules.d/af-alg.rules
-a always,exit -F arch=b64 -S socket -F a0=38 -F uid!=0 -k af_alg_socket
EOF
sudo augenrules --load
```

Query the audit log for hits:

```bash
ausearch -k af_alg_socket --start today
```

Falco rule for runtime detection in Kubernetes environments:

```yaml
- rule: AF_ALG socket created by non-root
  desc: Detects creation of AF_ALG (domain 38) sockets by non-root users, a prerequisite for CVE-2026-31431 exploitation
  condition: >
    syscall.type = socket
    and evt.arg.domain = 38
    and user.uid != 0
    and not proc.name in (trusted_af_alg_users)
  output: >
    AF_ALG socket opened by non-root process
    (user=%user.name uid=%user.uid pid=%proc.pid comm=%proc.name
    container=%container.id image=%container.image.repository)
  priority: WARNING
  tags: [lpe, cve-2026-31431, af-alg, page-cache]
```

Additionally, monitor for unexpected writes to `setuid` binary inodes via inotify or eBPF:

```bash
# inotifywait on setuid binaries (lightweight but not kernel-bypass proof)
inotifywait -m -e modify /usr/bin/su /usr/bin/sudo /usr/bin/passwd \
  --format '%T %w %e' --timefmt '%Y-%m-%dT%H:%M:%S' 2>&1 | \
  logger -t setuid-watch -p security.warning
```

An eBPF-based approach via `bpftrace` can detect the `splice()` + AF_ALG pattern:

```bash
bpftrace -e '
tracepoint:syscalls:sys_enter_splice
/ uid != 0 /
{
  printf("splice by uid=%d pid=%d comm=%s\n", uid, pid, comm);
}'
```

## Expected Behaviour

| Signal | Unpatched kernel | Patched + hardened |
|---|---|---|
| AF_ALG socket created by unprivileged user | Succeeds silently; `socket(38, 5, 0)` returns a valid fd | Returns `EPERM` (seccomp block) or kernel returns `ENOSYS` if `algif_aead` module absent |
| `splice()` of setuid binary page into pipe | Succeeds; pipe buffer holds page-cache page reference | Succeeds (splice itself is not blocked), but subsequent AF_ALG writable SG path is patched out — write primitive unavailable |
| Write to `/usr/bin/su` page-cache via AF_ALG chain | Succeeds on kernel ≤ 6.18.21/6.19.11; file on disk unmodified but in-memory copy overwritten | Fails; kernel enforces page write-protection on the SG list path after commit `a664bf3d603d` |
| Container attempting AF_ALG socket | Succeeds if no seccomp profile enforced | Returns `EPERM` when pod seccomp profile includes AF_ALG block |
| Patch-gap detection via kernel.org monitoring | No alert; 28-day blind window | `kernel-watch.sh` cron fires within 24 hours of commit `a664bf3d603d`; security team notified April 2, 2026 |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Disable AF_ALG via `CONFIG_CRYPTO_USER_API_AEAD=n` | Eliminates the entire attack surface class; no AF_ALG code reachable from userspace | Requires custom kernel build; breaks userspace applications using `libkcapi` or OpenSSL's AF_ALG engine for hardware crypto offload | Audit whether any production service uses AF_ALG (`strace -e socket` or `ss -f alg`); disable only on confirmed-clean systems |
| Seccomp `socket` block for AF_ALG (domain 38) | Targeted; blocks only AF_ALG creation; no kernel rebuild; deployable immediately via container runtime or systemd unit | Breaks any legitimate process inside the same seccomp scope that uses in-kernel crypto (rare on servers, more common on desktop) | Apply at container granularity, not system-wide; whitelist known AF_ALG users by cgroup or UID |
| Module blacklisting (`algif_aead`, `algif_skcipher`) | No kernel rebuild required; blocks runtime module load | Module may already be loaded at boot; blacklisting does not unload a loaded module; does not help on kernels with modules compiled in | Pair with initramfs rebuild; check `lsmod | grep algif` post-boot to confirm not loaded |
| Live patching via `kpatch` / `canonical-livepatch` | Closes the vulnerability without a reboot; zero downtime | Not available on all distributions; livepatch subscription required (RHEL); Canonical Livepatch requires Ubuntu Pro; patch coverage lags mainline by days to weeks | Use live patching as a bridge, not a permanent solution; schedule a full kernel update within one maintenance window |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Seccomp AF_ALG block breaks legitimate application | Application fails at startup or during crypto operations with `EACCES` or `EPERM`; logs show `socket: Operation not permitted` | Check `strace -e socket <app>` for `socket(AF_ALG, ...)` calls; review application documentation for AF_ALG dependency | Identify the specific process needing AF_ALG; move it to a separate seccomp profile that permits domain 38; or configure the application to use a software crypto path instead |
| Kernel update breaks a hardware driver (e.g., crypto accelerator) | System fails to boot or driver module fails to load after kernel upgrade; `dmesg` shows module initialization errors | Check `journalctl -b -1` and `dmesg | grep -i "error\|fail"` immediately after reboot | Boot to previous kernel via GRUB (`Advanced options`); pin the previous kernel version with `apt-mark hold linux-image-<version>` or `dnf versionlock`; report regression to distro |
| kpatch live patch conflicts with a loaded module | `kpatch load` reports `ERROR: patch conflicts with loaded module`; live patch not applied | Run `kpatch status`; check `dmesg` for `kpatch:` messages | Unload the conflicting module if it is not in use (`modprobe -r <module>`); if module is required, schedule a reboot to the patched kernel instead of relying on live patch |
| Audit rule `af_alg_socket` floods log with false positives | `/var/log/audit/audit.log` grows rapidly; `auditd` disk I/O spikes; alerting system pages on volume | `ausearch -k af_alg_socket | wc -l` over a 5-minute window; identify the generating UID and process with `ausearch -k af_alg_socket -i` | Add a UID exclusion for the legitimate process: `auditctl -a always,exit -F arch=b64 -S socket -F a0=38 -F uid!=0 -F uid!=[legitimate_uid] -k af_alg_socket`; remove the original rule |

## Related Articles

- [Linux Memory Protections](/articles/linux/linux-memory-protections/)
- [Linux Capability Hardening](/articles/linux/linux-capability-hardening/)
- [seccomp-bpf for Non-Container Workloads](/articles/linux/seccomp-bpf-non-container/)
- [Kernel Module Hardening](/articles/linux/kernel-module-hardening/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
