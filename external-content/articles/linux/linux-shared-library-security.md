---
title: "Linux Shared Library Security: LD_PRELOAD Attacks, Library Hijacking, and Hardened Linking"
description: "LD_PRELOAD lets any unprivileged user inject arbitrary code into every dynamically linked process they spawn. This article covers the full attack surface — PRELOAD hooks, library path hijacking, /etc/ld.so.preload persistence — and the structural defenses: AT_SECURE clearing, IMA/EVM measurement, dm-verity on /usr, and auditd detection rules."
slug: linux-shared-library-security
date: 2026-05-07
lastmod: 2026-05-07
category: linux
tags:
  - ld-preload
  - shared-libraries
  - dynamic-linking
  - library-hijacking
  - supply-chain
personas:
  - security-engineer
  - platform-engineer
article_number: 487
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/linux/linux-shared-library-security/
---

# Linux Shared Library Security: LD_PRELOAD Attacks, Library Hijacking, and Hardened Linking

## The Problem

Every dynamically linked process on Linux carries an implicit trust relationship with the runtime linker (`ld-linux-x86-64.so.2` or `ld-linux.so.2`). When the kernel hands control to a new ELF binary, the linker runs first — before `main()`, before any application code — and walks a resolution chain: `LD_PRELOAD` environment variable, `/etc/ld.so.preload`, `RPATH`/`RUNPATH` in the binary, `LD_LIBRARY_PATH`, `/etc/ld.so.cache`, then the default library paths (`/lib`, `/usr/lib`, etc.). An attacker who controls any link in that chain can inject a shared object into every process the victim spawns.

The attack surface is wide:

- A developer with `LD_PRELOAD=/tmp/evil.so` set in their shell injects code into every subprocess, including sudo, ssh-agent, and any credential-handling tool.
- A compromised build artifact drops a malicious `.so` file and a `LD_LIBRARY_PATH` entry in a shell profile, silently intercepting subsequent process calls.
- An attacker who achieves a one-time root write appends to `/etc/ld.so.preload` to gain code execution in every dynamically linked process on the host — a persistent, stealthy rootkit primitive.
- A supply-chain compromise replaces `/usr/lib/libssl.so.3` with an instrumented version that exfiltrates TLS session keys before passing through to the real implementation.

Unlike many attacks that require a specific vulnerability, LD_PRELOAD abuse exploits a documented, intended feature of the Linux runtime linker. The defense is not a patch — it is configuration, measurement, and detection.

**Target systems:** Ubuntu 22.04/24.04 LTS, Debian 12, RHEL 9 / Rocky Linux 9, kernel 5.15+.

## Threat Model

- **Adversary 1 — Unprivileged local user:** sets `LD_PRELOAD` to hook libc functions in subprocesses, intercepting credentials, bypassing audit logging, or exfiltrating data.
- **Adversary 2 — Compromised application:** writes a malicious library to a world-writable path and manipulates `LD_LIBRARY_PATH` or `RPATH` in a subsequent invocation.
- **Adversary 3 — Attacker with transient root:** achieves root for a moment (e.g., via a short-lived CVE), writes to `/etc/ld.so.preload`, then loses root — but retains code execution in every future process.
- **Adversary 4 — Supply-chain compromise:** replaces a package-managed shared library on disk with an instrumented version that passes through all calls while logging sensitive data.
- **Access level:** Ranges from unprivileged user (Adversary 1 and 2) to brief root (Adversary 3) to package-distribution compromise (Adversary 4).
- **Objective:** Credential theft, audit evasion, privilege escalation, persistent code execution.
- **Blast radius:** Without mitigations, a single `LD_PRELOAD` entry or a modified system library affects every dynamically linked process on the host, including security tooling.

## How LD_PRELOAD Hooking Works

The runtime linker resolves shared library symbols at process startup. If `LD_PRELOAD` names a shared object, that object is loaded before all others in the dependency chain. Any symbol it exports shadows the same-named symbol in later libraries — including libc.

A minimal credential-intercepting hook looks like this:

```c
/* hook_open.c — intercepts open(2) calls, logs paths to /tmp/.exfil */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef int (*orig_open_t)(const char *pathname, int flags, ...);

int open(const char *pathname, int flags, ...) {
    orig_open_t orig = (orig_open_t)dlsym(RTLD_NEXT, "open");

    /* Log every file path opened — catches SSH key reads, /etc/shadow, etc. */
    FILE *log = fopen("/tmp/.exfil", "a");
    if (log) {
        fprintf(log, "open: %s (pid %d)\n", pathname, getpid());
        fclose(log);
    }

    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode_t mode = va_arg(args, mode_t);
        va_end(args);
        return orig(pathname, flags, mode);
    }
    return orig(pathname, flags);
}
```

```bash
# Build the hook library
gcc -shared -fPIC -o /tmp/hook_open.so hook_open.c -ldl

# Inject into any process the attacker spawns as the same user
LD_PRELOAD=/tmp/hook_open.so ssh user@target
# Every file open() call inside ssh now logs to /tmp/.exfil
# — including reads of ~/.ssh/id_rsa and known_hosts
```

The same technique hooks `connect()` to intercept network connections, `read()` to capture data from file descriptors, `write()` to exfiltrate outbound data, and `getpwnam()`/`pam_authenticate()` to steal cleartext passwords as they pass through PAM.

A more sophisticated hook intercepts `read()` on file descriptor 0 (stdin) to capture every character typed at a password prompt — indistinguishable from a legitimate read from the application's perspective.

## Library Path Hijacking Beyond LD_PRELOAD

`LD_PRELOAD` is the most direct vector, but the full resolution chain offers multiple hijack points.

### LD_LIBRARY_PATH Manipulation

`LD_LIBRARY_PATH` prepends directories to the library search path. An attacker who writes a malicious `libssl.so.3` to `/tmp/evil/` and sets `LD_LIBRARY_PATH=/tmp/evil` intercepts all TLS operations in any process launched from that shell:

```bash
mkdir -p /tmp/evil
# Drop a trojanised libssl.so.3 that logs session keys before delegating
cp /usr/lib/x86_64-linux-gnu/libssl.so.3 /tmp/evil/libssl.so.3
# (in practice, modify the copy to add hooks)
export LD_LIBRARY_PATH=/tmp/evil
curl https://internal-api.corp.example/v1/secrets  # intercepts TLS
```

### RPATH and RUNPATH Injection

`RPATH` and `RUNPATH` are baked into the ELF binary itself, set at link time. A `$ORIGIN`-relative `RPATH` is common in redistributed applications that bundle their own libraries:

```bash
# Inspect RPATH/RUNPATH of a binary
readelf -d /usr/bin/python3 | grep -E 'RPATH|RUNPATH'
# Legitimate: (empty, or /usr/lib/python3.12)

# A compromised binary might have:
#   RPATH: $ORIGIN/../lib:/tmp
# Any .so in /tmp can be loaded as a dependency
```

The distinction between `RPATH` and `RUNPATH` matters for defense: `RPATH` takes precedence over `LD_LIBRARY_PATH`, while `RUNPATH` does not. Binaries with writable `RPATH` directories are a higher risk than those with `RUNPATH`.

### ldconfig and /etc/ld.so.conf.d Abuse

`ldconfig` regenerates `/etc/ld.so.cache` from the paths in `/etc/ld.so.conf` and `/etc/ld.so.conf.d/*.conf`. An attacker with write access to any `ld.so.conf.d` fragment, or to any directory listed therein, can cause a legitimate library path to resolve to an attacker-controlled directory:

```bash
# Check ownership of ld.so.conf.d entries
ls -la /etc/ld.so.conf.d/
# Any world-writable .conf file is a hijack path

# Check what directories are in the cache
ldconfig -v 2>/dev/null | grep '^/'
# Look for unexpected writable directories
find $(ldconfig -v 2>/dev/null | grep '^/' | cut -d: -f1) \
    -maxdepth 0 -writable 2>/dev/null
```

## /etc/ld.so.preload: The Rootkit Persistence Primitive

`/etc/ld.so.preload` is the system-wide equivalent of `LD_PRELOAD`: every shared object listed there is loaded into every dynamically linked process on the system, regardless of which user spawned it. This makes it the preferred persistence mechanism for Linux userspace rootkits.

A canonical rootkit entry:

```bash
# Written by attacker after brief root access:
echo '/lib/x86_64-linux-gnu/.cache/libaudit-helper.so' > /etc/ld.so.preload
# The library name mimics a legitimate audit helper.
# It hides files, intercepts getdents64(), and reports back to C2.
```

Unlike a cron job or systemd unit, this entry survives in a file that most administrators never inspect. The malicious library runs before `ls`, before `ps`, before audit tools — it can hide its own presence from the very tools used to detect it.

Detection requires either reading `/etc/ld.so.preload` directly (before hooking takes effect in that shell session) or using a kernel-level mechanism that cannot be intercepted by userspace:

```bash
# Check for unexpected entries — run this before any shells that might be hooked
cat /etc/ld.so.preload
# Expected: empty or absent on most hardened systems
# Any entry here demands immediate investigation

# auditd rule to alert on writes to /etc/ld.so.preload
# Add to /etc/audit/rules.d/hardening.rules:
-w /etc/ld.so.preload -p wa -k ld_so_preload_write
```

## The AT_SECURE Mechanism: What It Protects and What It Does Not

The linker clears `LD_PRELOAD`, `LD_LIBRARY_PATH`, and related environment variables when a process's effective UID or GID differs from its real UID or GID — the `AT_SECURE` auxiliary vector entry that the kernel sets for setuid/setgid binaries.

```c
/* From glibc's elf/rtld.c — simplified */
if (__libc_enable_secure) {
    /* AT_SECURE is set: clear all LD_ variables */
    unsetenv("LD_PRELOAD");
    unsetenv("LD_LIBRARY_PATH");
    unsetenv("LD_AUDIT");
    /* ... */
}
```

This is the critical protection for privilege escalation: `LD_PRELOAD` does not apply to `sudo`, `su`, `passwd`, or any setuid binary. An unprivileged user cannot use `LD_PRELOAD` to inject code that runs with elevated privileges.

**What AT_SECURE does not protect:**

- Non-setuid binaries run by the same user. `LD_PRELOAD` fully applies.
- Processes spawned by services running as a non-root unprivileged user (e.g., a web server running as `www-data`). If the attacker compromises that user, `LD_PRELOAD` affects all subprocesses.
- `/etc/ld.so.preload` — this is honoured even for setuid binaries when the file is present. An entry in `/etc/ld.so.preload` is loaded into `sudo`. This is by design (for system-wide audit shims), which makes it the most dangerous persistence vector.

## Detecting LD_PRELOAD Abuse at Runtime

### Checking /proc/PID/maps

Every loaded shared object appears in `/proc/PID/maps`. Comparing the actual loaded libraries against a known-good baseline reveals injected libraries:

```bash
#!/bin/bash
# check-loaded-libs.sh — detect unexpected shared objects in running processes
# Usage: ./check-loaded-libs.sh [pid]
# Without a PID, checks all processes.

KNOWN_GOOD_DIRS=("/usr/lib" "/usr/lib/x86_64-linux-gnu" "/lib" "/lib/x86_64-linux-gnu")

check_pid() {
    local pid=$1
    local comm
    comm=$(cat /proc/"$pid"/comm 2>/dev/null) || return

    while IFS= read -r line; do
        # Extract the mapped path (last field)
        local path
        path=$(awk '{print $6}' <<< "$line")
        [[ "$path" =~ \.so ]] || continue
        [[ -z "$path" ]] && continue

        # Check if it lives under a known-good library directory
        local trusted=false
        for dir in "${KNOWN_GOOD_DIRS[@]}"; do
            if [[ "$path" == "$dir"/* ]]; then
                trusted=true
                break
            fi
        done

        if [[ "$trusted" == false ]]; then
            echo "ALERT: pid=$pid comm=$comm unexpected library: $path"
        fi
    done < /proc/"$pid"/maps 2>/dev/null
}

if [[ -n "$1" ]]; then
    check_pid "$1"
else
    for piddir in /proc/[0-9]*/; do
        check_pid "$(basename "$piddir")"
    done
fi
```

```bash
# Run against all processes — look for libraries outside /usr/lib
sudo ./check-loaded-libs.sh 2>/dev/null | grep ALERT

# Spot-check a specific process
sudo ./check-loaded-libs.sh $(pgrep sshd | head -1)

# Quick one-liner: list all unique library paths loaded across all processes
sudo find /proc -maxdepth 3 -name maps -readable \
    -exec grep '\.so' {} \; 2>/dev/null \
    | awk '{print $6}' | sort -u \
    | grep -v '^/usr/lib\|^/lib\|^/usr/share\|^$'
```

### auditd Rules for Library Injection Detection

```bash
# /etc/audit/rules.d/library-security.rules

# Alert on writes to /etc/ld.so.preload
-w /etc/ld.so.preload -p wa -k ld_so_preload_write

# Alert on modifications to ldconfig configuration
-w /etc/ld.so.conf -p wa -k ldconfig_modification
-w /etc/ld.so.conf.d/ -p wa -k ldconfig_modification

# Alert on execve calls with LD_PRELOAD in the environment
# (requires auditd with execve environment logging — performance cost)
-a always,exit -F arch=b64 -S execve -k exec_with_preload

# Alert on writes to standard library directories
-w /usr/lib/x86_64-linux-gnu/ -p wa -k lib_write
-w /lib/x86_64-linux-gnu/ -p wa -k lib_write
```

```bash
# Reload rules
augenrules --load

# Search for LD_PRELOAD-related audit events
ausearch -k ld_so_preload_write --start today
ausearch -k ldconfig_modification --start today
```

## Library Signature Verification: The Gap

Windows has Authenticode for DLL signing, with kernel enforcement at load time. Linux has no equivalent built into the kernel or glibc. The runtime linker loads any readable ELF shared object without verifying its origin, hash, or signature. This is the fundamental gap.

### IMA/EVM for Library Measurement

Linux IMA (Integrity Measurement Architecture) and EVM (Extended Verification Module) fill part of this gap. IMA can measure files before they are read — including shared libraries — and enforce a policy that rejects files whose hash does not match an appraisal value:

```bash
# /etc/ima/ima-policy — measure and appraise shared libraries
# Measure all .so files read by any process
measure func=FILE_MMAP mask=MAY_EXEC

# Appraise (enforce) shared library loads — requires IMA keys in kernel keyring
appraise func=FILE_MMAP mask=MAY_EXEC appraise_type=imasig

# Appraise executables
appraise func=BPRM_CHECK mask=MAY_EXEC appraise_type=imasig
```

```bash
# Sign a shared library with the IMA key
evmctl ima_sign --key /etc/keys/ima-signing-key.pem \
    /usr/lib/x86_64-linux-gnu/libssl.so.3

# Verify the signature
evmctl ima_verify /usr/lib/x86_64-linux-gnu/libssl.so.3

# Check IMA measurement log
cat /sys/kernel/security/ima/ascii_runtime_measurements | grep libssl
```

IMA appraisal enforces that a shared library carries a valid signature before the kernel maps it into process address space. A replaced library without a valid signature causes the `mmap()` call to fail with `EACCES` — the process terminates rather than running a trojanised library.

### dm-verity on /usr

The most robust protection against library replacement is making the filesystem that contains libraries read-only at the block level. `dm-verity` on `/usr` means no file in that partition can be modified without the next reboot detecting a Merkle-tree mismatch:

```bash
# Mount /usr from a verified block device (setup done at image build time)
# In /etc/fstab or a systemd mount unit:
/dev/mapper/usr-verity  /usr  ext4  ro,nodev,nosuid  0 0

# The dm-verity device is created by:
veritysetup create usr-verity /dev/sda3 /dev/sda4 <root-hash>
# where sda3 is the /usr partition and sda4 holds the hash tree

# Verify the root hash at any time without remounting:
veritysetup verify /dev/sda3 /dev/sda4 <expected-root-hash>
```

With dm-verity on `/usr`, an attacker with transient root cannot persistently replace `/usr/lib/libssl.so.3` — the write would fail on a read-only filesystem, and any offline modification would be detected at the next boot.

## Hardening the Library Configuration

### Lock Down /etc/ld.so.preload

On systems that do not need a system-wide preload shim (almost all production systems), `/etc/ld.so.preload` should not exist. If it must exist, restrict write access:

```bash
# Remove it if unused
sudo rm -f /etc/ld.so.preload

# If it must exist (e.g., for a system-wide audit hook), make it immutable
sudo chattr +i /etc/ld.so.preload
# chattr +i prevents modification even by root, unless the immutable flag is cleared first.
# Combined with auditd monitoring of chattr calls, this provides both protection and detection.

# Monitor chattr calls on critical files
# Add to /etc/audit/rules.d/hardening.rules:
-a always,exit -F arch=b64 -S ioctl -F a1=0x40206601 -k chattr_immutable
```

### Secure /etc/ld.so.conf.d

Every file under `/etc/ld.so.conf.d/` must be owned by root and non-world-writable:

```bash
# Audit ld.so.conf.d ownership and permissions
find /etc/ld.so.conf.d/ -not -user root -o -perm /022 | \
    while read f; do echo "INSECURE: $f"; ls -la "$f"; done

# Fix permissions
sudo chown root:root /etc/ld.so.conf.d/*.conf
sudo chmod 644 /etc/ld.so.conf.d/*.conf

# Check that no listed directory is world-writable
grep -r '' /etc/ld.so.conf.d/ /etc/ld.so.conf 2>/dev/null | \
    grep -v '^#' | awk -F: '{print $2}' | sort -u | \
    xargs -I{} find {} -maxdepth 0 -writable 2>/dev/null
```

### Mount Options to Limit Library Injection

```bash
# /etc/fstab hardening for directories users can write to:

# Home directories: nosuid prevents setuid binaries, noexec prevents direct execution.
# noexec does NOT prevent LD_PRELOAD from loading .so files — shared objects are
# mapped, not exec'd. But nosuid ensures that if a user writes a setuid binary
# to their home directory, it gains no privilege.
/dev/sda5   /home   ext4   defaults,nosuid,nodev   0 2

# /tmp: nosuid,nodev,noexec. noexec prevents execve of binaries in /tmp,
# which forces attackers to use LD_PRELOAD instead of direct execution.
tmpfs   /tmp   tmpfs   defaults,nosuid,nodev,noexec,size=2G   0 0

# /var/tmp: same as /tmp
/dev/sda6   /var/tmp   ext4   defaults,nosuid,nodev,noexec   0 2
```

Note: `noexec` on `/tmp` does not prevent `LD_PRELOAD=/tmp/evil.so`. The linker uses `mmap(MAP_EXEC)`, not `execve()`. The kernel honours `noexec` for `execve()` but not for `mmap()` with `PROT_EXEC`. This is a commonly misunderstood limitation.

To prevent mmap-based execution from noexec mounts requires a custom LSM policy (SELinux, AppArmor, or a BPF-LSM hook). SELinux with targeted policy will deny `mmap(PROT_EXEC)` from noexec-mounted paths if the file context is not executable:

```bash
# SELinux: check if a file has executable context
ls -Z /tmp/evil.so
# Untrusted file will have: unconfined_u:object_r:user_tmp_t:s0
# user_tmp_t does not have execmod permission — mmap with PROT_EXEC is denied
# when SELinux is enforcing

# Verify SELinux is enforcing
getenforce  # Should output: Enforcing
```

## Static Linking for Security-Critical Binaries

For security-critical tooling — integrity checkers, audit log shippers, incident response tools — static linking eliminates the dynamic linker attack surface entirely. A statically linked binary carries all its dependencies inside the ELF file; there is no runtime linker walk, no `LD_PRELOAD`, no library path resolution.

```bash
# Compile a security tool as a fully static binary
gcc -static -o aide-static aide.c -lcrypto -lssl
# Verify: no dynamic dependencies
ldd aide-static
# Output: not a dynamic executable

# Go tools are statically linked by default (CGO_ENABLED=0):
CGO_ENABLED=0 GOOS=linux go build -o /usr/local/bin/log-shipper ./cmd/log-shipper
ldd /usr/local/bin/log-shipper
# Output: not a dynamic executable
```

Trade-offs to consider:

| Factor | Static | Dynamic |
|--------|--------|---------|
| LD_PRELOAD attack surface | None | Full |
| Library update propagation | Requires rebuild and redeploy | Automatic with `apt upgrade` / `dnf upgrade` |
| Binary size | Larger (all deps embedded) | Smaller |
| ASLR effectiveness | Slightly reduced (larger text segment) | Normal |
| CVE response time | Slower (rebuild cycle) | Faster (library update only) |
| Rootkit injection via library | Not possible | Possible |

For an integrity-checking tool that must run reliably even on a compromised system, static linking is the correct choice. For a general application that benefits from OS-level TLS library updates (e.g., OpenSSL CVE patches applied via `apt upgrade`), dynamic linking with library signing and dm-verity is the better model.

## Container Security: Library Integrity in OCI Images

Container images layer the filesystem; the base layer typically contains the OS shared libraries. A compromised base image is equivalent to a host with trojanised system libraries.

```dockerfile
# Use a minimal, known-good base image with a pinned digest
# Pinning to a digest prevents a tag from being updated to a malicious image
FROM debian:12-slim@sha256:1234abcd...  AS base

# Copy only necessary libraries rather than including the full package set
# Reduces the library attack surface inside the container
RUN apt-get install -y --no-install-recommends libssl3 libcurl4
```

```yaml
# Kubernetes: read-only root filesystem prevents /etc/ld.so.preload modification
# and prevents any runtime library injection to the filesystem
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: registry.corp.example/app:v1.2.3@sha256:abcd1234...
    securityContext:
      readOnlyRootFilesystem: true    # Prevents /etc/ld.so.preload writes
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      seccompProfile:
        type: RuntimeDefault
    volumeMounts:
    # Mount writable state dirs explicitly — not the root
    - name: app-data
      mountPath: /var/lib/app
```

With `readOnlyRootFilesystem: true`, an attacker who achieves code execution inside the container cannot write to `/etc/ld.so.preload` or replace any file in `/usr/lib`. The container's library state is frozen at image build time.

For defence in depth, use image scanning with a tool that verifies library content against the package manifest:

```bash
# Scan a container image for library tampering and CVEs
trivy image --ignore-unfixed \
    --severity HIGH,CRITICAL \
    registry.corp.example/app:v1.2.3

# Verify that the image's library checksums match the dpkg/rpm database
# (run inside a container spawned from the image)
dpkg --verify 2>&1 | grep -v '^$'  # Empty output means no deviations
rpm -Va 2>&1 | grep -v '^$'        # Same for RPM-based systems
```

## Comprehensive Hardening Checklist

```bash
# 1. Verify /etc/ld.so.preload is absent or empty
[[ -s /etc/ld.so.preload ]] && echo "WARNING: /etc/ld.so.preload is non-empty" \
    && cat /etc/ld.so.preload || echo "OK: /etc/ld.so.preload is absent or empty"

# 2. Check ld.so.conf.d for insecure permissions
find /etc/ld.so.conf.d/ \( -not -user root \) -o -perm /022 2>/dev/null \
    | grep . && echo "FAIL: insecure ld.so.conf.d entries above" || echo "OK"

# 3. Check for world-writable directories in the library search path
ldconfig -v 2>/dev/null | grep '^/' | cut -d: -f1 | sort -u | \
    xargs -I{} find {} -maxdepth 0 -writable 2>/dev/null | \
    grep . && echo "FAIL: writable library dirs above" || echo "OK"

# 4. Verify auditd rule for /etc/ld.so.preload writes
auditctl -l | grep ld.so.preload && echo "OK: audit rule present" \
    || echo "FAIL: no audit rule for /etc/ld.so.preload"

# 5. Check for unexpected libraries loaded in running processes
find /proc -maxdepth 3 -name maps -readable 2>/dev/null \
    -exec grep '\.so' {} \; 2>/dev/null \
    | awk '{print $6}' | sort -u \
    | grep -Ev '^(/usr/lib|/lib|/usr/share|)' \
    | grep . && echo "REVIEW: unexpected library paths above" || echo "OK"

# 6. Verify IMA policy is active (if using IMA)
cat /sys/kernel/security/ima/policy 2>/dev/null | grep -c appraise \
    && echo "OK: IMA appraisal rules active" \
    || echo "INFO: IMA appraisal not configured"

# 7. Check SELinux enforcing mode
getenforce 2>/dev/null | grep -q Enforcing \
    && echo "OK: SELinux enforcing" \
    || echo "WARN: SELinux not enforcing"
```

## Key Mitigations Summary

| Threat | Mitigation | Strength |
|--------|-----------|----------|
| `LD_PRELOAD` into setuid binaries | AT_SECURE clearing in glibc (automatic) | Strong — no config needed |
| `LD_PRELOAD` into user processes | SELinux/AppArmor policy; noexec mounts | Moderate — policy-dependent |
| `/etc/ld.so.preload` persistence | Remove file; `chattr +i`; auditd monitoring | Strong with all three layers |
| Library replacement on disk | dm-verity on `/usr`; IMA/EVM appraisal | Strong — block-level enforcement |
| Library path hijacking | Fix ld.so.conf.d ownership; audit writable paths | Moderate — requires ongoing auditing |
| Supply-chain library swap | Pinned image digests; `dpkg --verify`; Trivy | Moderate — detection-focused |
| Injection into security tooling | Static linking of critical tools | Strong — eliminates attack surface |

The `LD_PRELOAD` attack surface cannot be fully eliminated on a system that uses dynamic linking — it is intrinsic to how the ELF runtime works. The correct posture is layered: AT_SECURE for setuid escalation paths, IMA/EVM or dm-verity for library integrity on disk, auditd for detection of `/etc/ld.so.preload` modifications, and static linking for the handful of tools that must be trusted even on a potentially compromised host.
