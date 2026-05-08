---
title: "Hardening Linux Kernel Information Exposure Through sysfs, debugfs, and procfs"
description: "Linux virtual filesystems expose kernel memory addresses, hardware state, and process details by default. Harden /proc, /sys, and debugfs to eliminate information leakage that attackers exploit for KASLR bypass, process enumeration, and side-channel attacks."
slug: linux-sysfs-debugfs-hardening
date: 2026-05-07
lastmod: 2026-05-07
category: linux
tags:
  - sysfs
  - debugfs
  - procfs
  - kernel-hardening
  - information-disclosure
personas:
  - security-engineer
  - platform-engineer
article_number: 479
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/linux/linux-sysfs-debugfs-hardening/
---

# Hardening Linux Kernel Information Exposure Through sysfs, debugfs, and procfs

## The Problem

The Linux kernel maintains a set of virtual filesystems — `/proc`, `/sys`, and `/sys/kernel/debug` — whose sole purpose is to make kernel internals visible to userspace. On a fresh install, these interfaces export a remarkable amount of data: the virtual and physical addresses of every kernel symbol, the layout of kernel memory, live hardware register state, process credentials for every user on the system, raw kernel memory through a character device, EFI variable contents, and profiling data for every CPU event counter.

This is not a bug. These interfaces exist for legitimate purposes: diagnostics, observability, hardware enumeration, performance profiling, and container runtimes that rely on per-process metadata. The problem is that the defaults are far too permissive for production systems where the threat model includes unprivileged local users, containerized workloads that may be partially compromised, and post-exploitation phases of attacks that have already obtained a low-privilege foothold.

What an attacker gains from these interfaces:

- **KASLR bypass:** Kernel Address Space Layout Randomization is a first-line mitigation against kernel exploits. `/proc/kallsyms` exports the runtime addresses of every kernel symbol. With one read, an unprivileged user on a default system can defeat KASLR entirely, converting an otherwise unexploitable kernel bug into a reliable exploit. `/proc/kcore` provides direct read access to kernel memory as an ELF core dump. Both are readable to root by default, and `kallsyms` is often readable by all users.
- **Process enumeration:** `/proc` contains a numbered directory for every running process. Each directory includes the process's command line, environment variables, file descriptor targets, memory maps, and credentials. An attacker can enumerate all running processes, identify security tooling, find credential material in environment variables, and map the privilege structure of the host.
- **Hardware state leakage:** `/sys/kernel/debug` exposes kernel data structures, device register dumps, and subsystem state that was never intended for production consumption. The `perf_event` subsystem provides CPU performance counters that are a known side-channel for extracting secrets from other processes or from kernel execution.
- **EFI variable tampering:** `/sys/firmware/efi/vars` allows reading and writing EFI NVRAM variables from a running OS. A compromised process with sufficient privilege can modify Secure Boot keys, boot order, or firmware settings.

**Target systems:** Linux kernel 5.8+ (for `hidepid=invisible`), Ubuntu 22.04+, Debian 12, RHEL 9, kernel 5.15+ for most sysctl knobs. Many settings apply to 4.x kernels as well.

## Threat Model

- **Adversary 1 — Unprivileged local attacker:** an attacker with a shell through a compromised application, a stolen SSH key, or a container escape that landed them in the host namespace without privilege. Their immediate goal is information gathering: kernel version, KASLR offsets, other processes, credential material.
- **Adversary 2 — Post-exploitation staging:** an attacker who has already escalated to root or obtained a high-privilege service account and is preparing a persistent implant. They need kernel symbol addresses, memory layout, and hardware state to write a reliable exploit payload or rootkit.
- **Adversary 3 — Side-channel attacker:** an attacker in an adjacent container or VM who uses CPU performance counters or kernel profiling interfaces to extract cryptographic material or observe memory access patterns in a victim process.
- **Access level:** Primarily unprivileged local users and processes. Some scenarios assume CAP_SYS_ADMIN or root within a non-privileged user namespace.
- **Objective:** KASLR bypass, process enumeration, credential extraction from environment variables, exploit development, persistent kernel-level foothold, and side-channel attacks against cryptographic operations.

## /proc Hardening

### hidepid: Hiding Other Users' Processes

By default, any user can list `/proc` and read metadata about every other user's processes. The `hidepid` mount option changes this.

Available values:

- `hidepid=0` (default): All processes visible to all users.
- `hidepid=1`: Process directories exist, but `/proc/<pid>` contents are only accessible to the owning user or root.
- `hidepid=2` (or `hidepid=invisible` on 5.8+): Process directories for other users are not visible at all. `ls /proc` only shows the current user's pids plus numeric pids owned by root.
- `hidepid=invisible`: Kernel 5.8+ alias for `hidepid=2`, considered cleaner.

Remount `/proc` with the strongest option:

```bash
# Check current mount options
findmnt -n -o OPTIONS /proc

# Remount immediately (not persistent)
mount -o remount,hidepid=invisible,gid=proc /proc
```

The `gid=proc` parameter designates a group whose members are exempt from hidepid restrictions — useful for monitoring daemons (prometheus node-exporter, ps-based tools) that need to enumerate all processes without running as root.

```bash
# Create the proc group if it doesn't exist
groupadd -r proc

# Add monitoring user to the proc group
usermod -aG proc prometheus
```

Make it persistent in `/etc/fstab`:

```
proc /proc proc defaults,nosuid,nodev,noexec,hidepid=invisible,gid=proc 0 0
```

The `subset=pid` option (5.8+) goes further: it restricts `/proc` to only the process-related directories, hiding filesystem-global kernel information like `/proc/kcore`, `/proc/kallsyms`, `/proc/modules`, and `/proc/net`. This is the strongest general-purpose option:

```
proc /proc proc defaults,nosuid,nodev,noexec,hidepid=invisible,gid=proc,subset=pid 0 0
```

Note that `subset=pid` will break tools that read `/proc/net`, `/proc/sys`, `/proc/meminfo`, `/proc/cpuinfo`, and similar. Test thoroughly before applying to production.

**Impact on observability tooling:** `ps`, `top`, `htop`, `pgrep`, and any tool that reads `/proc` to enumerate processes will only show the current user's processes. Root is unaffected. The `proc` group bypass covers monitoring agents. `lsns`, `ss -p`, and `/proc/net/tcp` visibility may also be affected depending on kernel version and namespace configuration.

### Protecting /proc/kcore and /proc/kallsyms

`/proc/kcore` presents the live kernel's virtual address space as an ELF core file. On a 64-bit system this is typically over 100 TB in apparent size (the full kernel virtual address space), though only resident pages are actually readable. It is restricted to root by default, but root-readable is not the same as safe.

`/proc/kallsyms` exports the name and runtime virtual address of every exported kernel symbol. This is the primary mechanism for defeating KASLR. The permissions are `0444` by default — world-readable.

The `kptr_restrict` sysctl controls whether kernel pointers are printed in kernel interfaces:

| Value | Behavior |
|-------|----------|
| `0` | No restriction. All pointers printed as-is. |
| `1` | Kernel pointers hashed/zeroed for unprivileged users; visible to root and CAP_SYSLOG. |
| `2` | Kernel pointers zeroed for all users including root. |

Set the strictest value:

```bash
# Apply immediately
sysctl -w kernel.kptr_restrict=2

# Verify
cat /proc/sys/kernel/kptr_restrict
```

With `kptr_restrict=2`, `/proc/kallsyms` still exists but all addresses are replaced with zeros:

```
0000000000000000 T ksys_read
0000000000000000 T ksys_write
```

Persist in `/etc/sysctl.d/90-kernel-hardening.conf`:

```ini
# Kernel pointer restriction
kernel.kptr_restrict = 2
```

`dmesg_restrict` controls whether unprivileged users can read the kernel ring buffer via `dmesg(1)`:

```ini
# Prevent unprivileged dmesg access
kernel.dmesg_restrict = 1
```

The kernel ring buffer routinely contains physical addresses, device initialization data with hardware addresses, and occasionally pointer values that appear in driver error messages. With `dmesg_restrict=1`, only users with `CAP_SYS_ADMIN` or `CAP_SYSLOG` can read `dmesg` output. Without it, leaked addresses from driver messages provide a reliable KASLR bypass even when `kptr_restrict=2` is set.

## debugfs

`/sys/kernel/debug` is mounted as `debugfs` and exposes raw kernel internal state: device register dumps, subsystem-specific counters, RCU statistics, tracing configuration, and in-kernel data structures formatted for human consumption. This interface was designed for kernel developers and driver authors, not for production systems.

Examples of what lives under debugfs:

- `/sys/kernel/debug/gpio` — GPIO line states and controller configuration
- `/sys/kernel/debug/regmap/` — Hardware register contents by device
- `/sys/kernel/debug/tracing/` — Ftrace configuration and ring buffers
- `/sys/kernel/debug/bdi/` — Backing device writeback statistics
- `/sys/kernel/debug/sched/` — Scheduler internals
- `/sys/kernel/debug/kprobes/` — Registered kprobe locations and hit counts (kernel address disclosure)

### Detecting and Removing debugfs

```bash
# Check whether debugfs is mounted
findmnt -t debugfs
mount | grep debugfs

# Check if any processes have files open under debugfs
lsof | grep /sys/kernel/debug 2>/dev/null
```

Unmount immediately:

```bash
umount /sys/kernel/debug
```

Prevent it from mounting at boot. In `/etc/fstab`, do not include a `debugfs` entry. If your distribution includes one, remove or comment it out.

To block debugfs from being mounted at all, add to `/etc/modprobe.d/hardening.conf`:

```
install debugfs /bin/true
```

This prevents the `debugfs` kernel module from loading, which prevents any mount of the filesystem type.

If some tooling requires debugfs (certain ftrace-based profilers, some hardware debugging tools), restrict permissions instead of unmounting:

```bash
# Remove all world and group read permissions
chmod 700 /sys/kernel/debug
chmod 700 /sys/kernel/debug/*
```

A systemd service override can lock this down at boot:

```ini
# /etc/systemd/system/restrict-debugfs.service
[Unit]
Description=Restrict debugfs permissions
After=local-fs.target
ConditionPathExists=/sys/kernel/debug

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/chmod 700 /sys/kernel/debug

[Install]
WantedBy=multi-user.target
```

## perf_event_paranoid

The `perf_event` subsystem exposes CPU performance counters to userspace. These counters are the foundation for side-channel attacks including:

- **Flush+Reload / Prime+Probe:** Cache timing attacks that can extract AES keys, RSA private keys, and other cryptographic material from co-located processes.
- **Spectre variant exploitation:** Several Spectre variants require precise access to cycle-accurate timing, which perf provides.
- **Cross-VM and cross-container information leakage** when the host kernel has not been patched for all speculative execution vulnerabilities.

The `perf_event_paranoid` sysctl controls access:

| Value | Who Can Profile |
|-------|----------------|
| `-1` | No restrictions. All perf features available to all users. |
| `0` | Unprivileged users can profile their own processes; no CPU-level or system-wide profiling. |
| `1` | Unprivileged users can profile their own processes with user-space-only events. Kernel profiling requires `CAP_SYS_ADMIN`. |
| `2` | Only users with `CAP_SYS_ADMIN` can use perf. (Default on some distros.) |
| `3` | `perf_event_open(2)` requires `CAP_PERFMON` (5.8+) or `CAP_SYS_ADMIN`. No unprivileged access. |

```ini
# /etc/sysctl.d/90-kernel-hardening.conf
kernel.perf_event_paranoid = 3
```

This disables unprivileged performance counter access entirely. The impact is that non-root developers cannot run `perf stat` on their own programs. For a production server, this is the correct setting. For a developer workstation, `perf_event_paranoid=2` is a reasonable compromise.

## Unprivileged BPF

Extended BPF (eBPF) is a powerful kernel execution environment. The ability for unprivileged users to load BPF programs represents a substantial kernel attack surface:

- BPF programs run in the kernel with access to kernel data structures, memory, and hardware.
- The BPF verifier has had multiple bypasses that allowed privilege escalation from unprivileged BPF program loading (CVE-2021-3490, CVE-2022-23222, CVE-2021-31440, and others).
- Unprivileged BPF programs can be used for side-channel attacks, probing kernel memory layouts, and as primitives in kernel exploit chains.

```ini
# Disable unprivileged BPF entirely
kernel.unprivileged_bpf_disabled = 1
```

With this set, `bpf(2)` syscalls from unprivileged users are rejected. Only processes with `CAP_BPF` (5.8+) or `CAP_SYS_ADMIN` can load BPF programs. This does not affect system-level monitoring tools (Cilium, Falco, bpftrace) that run as root or with explicit capabilities, but it prevents containerized workloads from using BPF as an attack surface.

Also disable unprivileged user namespaces if your workload does not require them, since user namespaces grant a path to BPF and other privileged operations:

```ini
kernel.unprivileged_userns_clone = 0
```

Note: `unprivileged_userns_clone` is a Debian/Ubuntu-specific knob. On upstream kernels and RHEL, user namespace restrictions are configured differently.

## /sys/kernel/security and securityfs

`securityfs` is mounted at `/sys/kernel/security` and exposes interfaces for Linux Security Modules: IMA (Integrity Measurement Architecture) measurements, AppArmor policy, SELinux AVC statistics, and similar.

The IMA measurement log at `/sys/kernel/security/ima/ascii_runtime_measurements` contains hashes of every measured file. While this is not directly exploitable, it leaks information about what software is running on the system. The AppArmor and SELinux interfaces expose policy details.

Verify what is exposed:

```bash
ls -la /sys/kernel/security/
ls -la /sys/kernel/security/ima/ 2>/dev/null
```

`securityfs` is not straightforward to unmount since LSMs may require it. Restrict access to specific directories:

```bash
# Restrict IMA measurement log to root
chmod 600 /sys/kernel/security/ima/ascii_runtime_measurements
chmod 600 /sys/kernel/security/ima/binary_runtime_measurements
```

For IMA, policy should explicitly restrict which measurements are exposed and to whom. A separate article covers IMA/EVM policy construction.

## /sys/firmware/efi/vars

On UEFI systems, `/sys/firmware/efi/vars` (legacy) and `/sys/firmware/efi/efivars` (current) provide read/write access to EFI NVRAM variables from the running OS.

The risks:

- A compromised root process can modify Secure Boot policy keys (PK, KEK, db, dbx).
- An attacker can add or modify boot entries to cause the system to boot a different image.
- EFI variables are persistent across reboots; a modified variable survives a full OS reinstall.
- Some firmware bugs make the NVRAM writable even to non-root users via certain interfaces.

Check what is mounted:

```bash
findmnt /sys/firmware/efi/efivars
ls -la /sys/firmware/efi/efivars/ | head -20
```

The `efi_vars` module can be blocked if EFI variable writes from the OS are not needed:

```
# /etc/modprobe.d/hardening.conf
install efi_pstore /bin/true
```

For systems where EFI variable access is required (e.g., for bootloader updates), mount `efivars` read-only:

```bash
mount -o remount,ro /sys/firmware/efi/efivars
```

Add to `/etc/fstab`:

```
efivarfs /sys/firmware/efi/efivars efivarfs ro,nosuid,nodev,noexec 0 0
```

Note that mounting efivars read-only will break `fwupdmgr` and similar firmware update tools. Unmount read-only and remount read-write when performing firmware updates, then return to read-only.

## Systemd Unit Hardening

When deploying services, systemd's security directives can apply these restrictions at the per-service level without modifying global system settings. This is appropriate for multi-tenant hosts where you need full system visibility for operators but want individual services isolated from kernel internals.

Key directives:

- **`ProtectKernelTunables=yes`**: Mounts `/proc/sys`, `/sys`, `/sys/fs/bpf`, and similar locations read-only for the service. Prevents the service from modifying any sysctl or sysfs value.
- **`ProtectKernelLogs=yes`**: Makes the kernel ring buffer inaccessible to the service (`CAP_SYSLOG` is removed, and `/dev/kmsg` is blocked).
- **`ProtectProc=invisible`**: Applies `hidepid=invisible` scoped to the service's mount namespace. Other processes are not visible in `/proc` for this service.
- **`ProcSubset=pid`**: Applies `subset=pid` to `/proc` for this service, hiding non-process kernel information.

Example service unit:

```ini
[Service]
User=appuser
Group=appgroup

# Kernel interface hardening
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectProc=invisible
ProcSubset=pid

# Additional isolation
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes

# Only the capabilities actually needed
CapabilityBoundingSet=
AmbientCapabilities=
```

Verify the effective security score:

```bash
systemd-analyze security your-service.service
```

`ProtectKernelTunables` in particular closes a common gap in containerized services that run as root: without it, the service can write arbitrary sysctls via `/proc/sys`, modify `/sys/kernel/debug` entries, or change kernel parameters that affect security enforcement.

## Consolidated sysctl Configuration

Apply all sysctl-based hardening in a single drop-in file:

```ini
# /etc/sysctl.d/90-kernel-hardening.conf
#
# Kernel information exposure hardening
# Review each setting against your workload requirements before applying.

# Restrict kernel pointer exposure in /proc and dmesg
kernel.kptr_restrict = 2

# Prevent unprivileged dmesg access
kernel.dmesg_restrict = 1

# Restrict perf_event to CAP_PERFMON / CAP_SYS_ADMIN only
kernel.perf_event_paranoid = 3

# Disable unprivileged BPF program loading
kernel.unprivileged_bpf_disabled = 1

# Disable unprivileged user namespace creation (Debian/Ubuntu)
# kernel.unprivileged_userns_clone = 0

# Restrict ptrace to parent processes only
kernel.yama.ptrace_scope = 1
```

Apply immediately:

```bash
sysctl --system
# Verify
sysctl kernel.kptr_restrict kernel.dmesg_restrict kernel.perf_event_paranoid kernel.unprivileged_bpf_disabled
```

## Verification

After applying changes, verify the restrictions are effective:

```bash
# Test kptr_restrict - all addresses should be zeros
grep -m 5 " T " /proc/kallsyms

# Test dmesg_restrict - should fail for non-root
su -s /bin/bash nobody -c "dmesg" 2>&1

# Test hidepid - non-root should not see root processes
su -s /bin/bash nobody -c "ls /proc | grep -E '^[0-9]+$' | wc -l"

# Verify debugfs is not mounted
findmnt -t debugfs && echo "WARNING: debugfs is mounted" || echo "OK: debugfs not mounted"

# Verify perf_event_paranoid
cat /proc/sys/kernel/perf_event_paranoid

# Check EFI vars mount options
findmnt /sys/firmware/efi/efivars | grep -o 'ro\|rw'

# Audit open files under kernel debug interfaces
ls -la /sys/kernel/debug 2>/dev/null && echo "WARNING: debugfs accessible" || echo "OK"
```

For automated verification in CI/CD pipelines or infrastructure scanning, the Center for Internet Security (CIS) benchmarks for Linux define specific expected values for these sysctls. Tools like `oscap` (OpenSCAP) can check compliance against CIS Level 2 profiles:

```bash
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis_server_l2 \
  --results results.xml \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-xccdf.xml
```

## Compatibility Notes

These settings have real operational implications:

| Setting | What It Breaks | Mitigation |
|---------|----------------|------------|
| `hidepid=invisible` | `ps aux`, `htop` for non-root users | Add monitoring users to `proc` group |
| `subset=pid` | `/proc/net`, `/proc/meminfo`, `/proc/sys` visibility | Use `gid=proc` exemption; test all tools |
| `kptr_restrict=2` | Some debugging tools that need kernel addresses | Drop to 1 for troubleshooting |
| `dmesg_restrict=1` | User-initiated `dmesg` without sudo | `sudo dmesg` or CAP_SYSLOG grant |
| `perf_event_paranoid=3` | `perf stat`, flame graphs for non-root | Grant `CAP_PERFMON` to specific users |
| `unprivileged_bpf_disabled=1` | Rootless containers using BPF, some observability agents | Grant `CAP_BPF` to specific services |
| debugfs unmounted | ftrace-based profilers, `trace-cmd`, some hardware debug | Remount temporarily for diagnostics |
| efivars read-only | `fwupdmgr`, bootloader updates | Remount read-write during update windows |

The settings in this article harden a default Linux installation against a class of information disclosure attacks that are frequently underestimated. KASLR bypass through `/proc/kallsyms` has been demonstrated as a component in real exploit chains. Process enumeration through an open `/proc` is a standard step in post-exploitation frameworks. Unprivileged BPF loading has produced a steady stream of privilege escalation CVEs. None of these require exotic conditions — they require only that the attacker has a shell.

Apply `kptr_restrict=2`, `dmesg_restrict=1`, `perf_event_paranoid=3`, and `unprivileged_bpf_disabled=1` as baseline requirements. Apply `hidepid=invisible` for any multi-user system or host running untrusted container workloads. Unmount debugfs unless actively required. The operational cost is low; the reduction in kernel attack surface is significant.
