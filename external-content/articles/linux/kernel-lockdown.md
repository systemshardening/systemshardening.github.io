---
title: "Kernel Lockdown Mode: Blocking Root from Modifying the Running Kernel"
description: "Lockdown mode separates root from kernel. integrity blocks code modification; confidentiality also blocks reads. Cheap, broad, underused."
slug: "kernel-lockdown"
date: 2026-04-27
lastmod: 2026-04-27
category: "linux"
tags: ["kernel-lockdown", "secure-boot", "linux", "kernel", "hardening"]
personas: ["systems-engineer", "security-engineer", "platform-engineer"]
article_number: 191
difficulty: "intermediate"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/linux/kernel-lockdown/index.html"
---

# Kernel Lockdown Mode: Blocking Root from Modifying the Running Kernel

## Problem

Root traditionally has unrestricted access to the running kernel: load and unload modules, write to `/dev/mem` and `/dev/kmem`, change MSRs (`wrmsr`), boot a different kernel via `kexec_load`, dump the kernel's memory through `/proc/kcore`, set custom ACPI tables, and mutate kernel data structures via the `bpf()` syscall in subtle ways. Each of these is a path from compromised root to a permanent foothold that survives reboot, defeats integrity measurement, or evades runtime detection.

Lockdown is a Linux Security Module (`lockdown` LSM, mainline since 5.4) that severs this implicit privilege. With lockdown active, even `uid=0` cannot perform a defined set of operations that would let it modify or expose the running kernel. The control was originally motivated by Secure Boot — a Secure-Boot-verified kernel must not let userspace replace it at runtime — but lockdown is useful well beyond Secure Boot deployments.

Two modes:

- **`lockdown=integrity`** — blocks operations that modify the running kernel image.
- **`lockdown=confidentiality`** — blocks `integrity` operations *plus* operations that read kernel memory.

Despite being available for years, lockdown is off by default on most non-Secure-Boot installations. The specific gaps in a default configuration:

- `insmod`/`modprobe` of unsigned kernel modules succeeds for root.
- `kexec_file_load(2)` and `kexec_load(2)` permit booting a different kernel image without a reboot — a perfect persistence mechanism that survives runtime forensics.
- `/dev/mem`, `/dev/kmem`, and `/dev/port` allow direct hardware-state manipulation.
- `/proc/kcore`, `/proc/vmcore`, and `/sys/kernel/debug/*` expose kernel memory.
- `wrmsr` to performance-monitoring MSRs lets code disable mitigations like SMEP, SMAP, NX.
- `iopl(2)`, `ioperm(2)`, raw PCI access via `/sys/bus/pci/.../config`.

This article covers enabling lockdown via boot parameter and at runtime, the difference between the two modes, integration with Secure Boot and signed modules, audit logging, and the practical applications that lockdown breaks (so you can plan for them).

**Target systems:** Linux kernel 5.4+ with `CONFIG_SECURITY_LOCKDOWN_LSM=y`. Most distros (Ubuntu 20.04+, RHEL 8+, Fedora 32+, Debian 11+) ship lockdown built in. Activation differs.

## Threat Model

- **Adversary 1 — Compromised root:** an attacker has gained root through a privilege-escalation exploit, a credential leak, or a misconfiguration. They want to install a persistent, kernel-resident foothold that survives reboot or hides from runtime monitoring.
- **Adversary 2 — Malicious kernel module:** an attacker convinces an admin (or automation) to load a kernel module — third-party driver, "monitoring agent" — that contains a rootkit or escalation payload.
- **Adversary 3 — Kernel memory exfiltration:** an attacker with root reads kernel memory (via `/proc/kcore`, `kexec` snapshots, or `/dev/mem`) to extract secrets — TLS session keys, full-disk-encryption keys, KASLR offsets enabling further exploitation.
- **Adversary 4 — kexec persistence:** attacker uses `kexec_load` to boot a modified kernel that pretends to be the original, evading boot-integrity attestation.
- **Access level:** All adversaries have root inside the OS. Some have CAP_SYS_MODULE / CAP_SYS_ADMIN, all have at least standard root.
- **Objective:** Persistent foothold across reboots; evasion of EDR/IDS that runs in userspace; extraction of secrets resident in kernel memory.
- **Blast radius:** Without lockdown, root translates directly to "permanent kernel control." With lockdown, root is bounded to userspace; a kernel exploit becomes the only path to kernel-level persistence, and even that path is harder if the kernel image must remain Secure-Boot-validated.

## Configuration

### Step 1: Choose a Mode and Enable at Boot

Append to the kernel command line via `/etc/default/grub`:

```
GRUB_CMDLINE_LINUX="... lockdown=confidentiality"
```

Rebuild grub config and reboot:

```bash
sudo update-grub                         # Debian / Ubuntu
sudo grub2-mkconfig -o /boot/grub2/grub.cfg   # RHEL / Rocky
sudo reboot
```

Verify:

```bash
cat /sys/kernel/security/lockdown
# none [integrity] confidentiality
# (active mode is in brackets)
```

For most production servers without specific debugging or kernel-tracing requirements, **`confidentiality` is the recommendation**. Reserve `integrity` for hosts where you genuinely need to read kernel memory at runtime (deep debugging, security-research environments).

### Step 2: Tighten Lockdown at Runtime

Lockdown can be raised but not lowered without a reboot. From `none` you can switch to `integrity` or `confidentiality`; from `integrity` you can switch to `confidentiality`; never the reverse.

```bash
echo confidentiality | sudo tee /sys/kernel/security/lockdown
cat /sys/kernel/security/lockdown
# none integrity [confidentiality]
```

This is useful when you cannot reboot immediately but want to apply lockdown to an already-running system. Add to your hardening playbook to run early in boot via systemd:

```ini
# /etc/systemd/system/lockdown-at-boot.service
[Unit]
Description=Raise kernel lockdown to confidentiality
DefaultDependencies=no
After=local-fs.target
Before=basic.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo confidentiality > /sys/kernel/security/lockdown'
RemainAfterExit=yes

[Install]
WantedBy=basic.target
```

Combined with the boot-parameter approach: the boot parameter sets lockdown before any userspace runs (smallest exposure window); the systemd unit is a defense in case the parameter was missed during a kernel upgrade.

### Step 3: Combine With Signed Module Loading

Lockdown by itself blocks unsigned module loading. To allow specific signed modules, configure module signing.

Generate a signing key (one-time):

```bash
sudo openssl req -new -x509 -newkey rsa:4096 -keyout /etc/kernel/signing.key \
  -outform DER -out /etc/kernel/signing.x509 -days 365 -nodes \
  -subj "/CN=Production module signing/"

sudo chmod 600 /etc/kernel/signing.key
```

Sign a module:

```bash
sudo /usr/src/linux-headers-$(uname -r)/scripts/sign-file \
  sha256 /etc/kernel/signing.key /etc/kernel/signing.x509 \
  ./mymodule.ko
```

Enroll the public certificate in the kernel's trusted keyring (requires Secure Boot or an existing trust path):

```bash
# Append to /etc/kernel-img.conf or distro-specific cert location.
sudo mokutil --import /etc/kernel/signing.x509
sudo reboot
# Confirm enrollment in the MOK manager during boot.
```

Verify a signed module loads under lockdown:

```bash
sudo insmod ./mymodule.ko
# Should succeed if signed and the cert is trusted.
sudo insmod ./unsigned.ko
# insmod: ERROR: could not insert module: Permission denied (lockdown blocks)
```

### Step 4: Audit What Lockdown Blocks

Every lockdown denial generates a kernel audit message. Forward to your audit pipeline:

```bash
# /etc/audit/rules.d/lockdown.rules
-a always,exit -F arch=b64 -F a0=0 -S init_module -S finit_module
-a always,exit -F arch=b64 -S kexec_load -S kexec_file_load
-w /dev/mem -p rwa -k mem_access
-w /dev/kmem -p rwa -k kmem_access
-w /proc/kcore -p r -k kcore_read
```

Reload audit rules and watch for denials:

```bash
sudo augenrules --load
sudo journalctl -k | grep -E "lockdown|denied" | head -20
# kernel: Lockdown: insmod: unsigned module loading is restricted; see man kernel_lockdown.7
```

In production: every lockdown denial line should be either a known operator action (signed module load) or an alert-worthy event.

### Step 5: Plan for Tooling That Lockdown Breaks

Lockdown breaks legitimate workflows. Inventory and adapt before flipping the switch.

| Tool / operation | Why it breaks under `confidentiality` | Workaround |
|------------------|---------------------------------------|------------|
| `kdump` (crash dumps via `kexec`) | `kexec_load` blocked | Use `pstore` (firmware-resident crash log) or accept that you cannot capture in-kernel crash dumps post-deploy |
| `perf` with kernel tracing | Some `perf_event_open` flags blocked | Run `perf record` with `--user-callchains` only; for kernel-mode, lower lockdown to `integrity` temporarily on a debug node |
| `eBPF` programs that read kernel memory | `bpf_probe_read_kernel` restricted in confidentiality | Use `bpf_probe_read_user` for user-space data; for kernel-side data, use exposed structures rather than direct kernel memory reads |
| `bpftrace` | Same eBPF restrictions | Stick to `tracepoint:` and `kprobe:` events that don't need kernel-memory reads; for security observability, use Tetragon or Falco instead |
| Hibernation (`systemctl hibernate`) | Writing the kernel image to disk constitutes leaking | Disable hibernation: `sudo systemctl mask hibernate.target` |
| Direct hardware access (radio drivers, custom DSP cards) | `/dev/mem`, `iopl`, `ioperm` blocked | Move drivers in-kernel with proper module signing |
| `crash` debugger | Reads `/proc/kcore` | Use only on dev/staging hosts with lockdown disabled |

For Kubernetes nodes specifically: kdump is rarely useful in production (workload restart is faster than crash analysis). eBPF-based security observability (Tetragon) works under lockdown because it uses the kernel's structured BPF helpers, not direct memory reads.

## Expected Behaviour

| Operation | Without lockdown | `lockdown=integrity` | `lockdown=confidentiality` |
|-----------|-------------------|----------------------|----------------------------|
| `insmod unsigned.ko` | succeeds | blocked | blocked |
| `insmod signed.ko` (cert in keyring) | succeeds | succeeds | succeeds |
| `kexec_load` | succeeds | blocked | blocked |
| Write to `/dev/mem` | succeeds | blocked | blocked |
| Read `/proc/kcore` | succeeds | succeeds | blocked |
| `wrmsr` to debug-control MSRs | succeeds | blocked | blocked |
| `bpf_probe_read_kernel` | succeeds | mostly succeeds | blocked |
| Hibernation | succeeds | succeeds | blocked |
| Reading kernel symbols `/proc/kallsyms` | succeeds | succeeds | blocked (returns zeroes) |

Verify lockdown is active:

```bash
cat /sys/kernel/security/lockdown
# none integrity [confidentiality]

# Negative test: attempt a blocked operation and confirm it fails.
sudo insmod /tmp/test_unsigned.ko 2>&1
# insmod: ERROR: could not insert module: Operation not permitted
sudo dmesg | tail -1
# kernel: Lockdown: insmod: unsigned module loading is restricted...
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| `confidentiality` over `integrity` | Closes kernel-memory-read paths | Some debug tooling broken | Reserve a small fleet of debug hosts at `integrity` for ad-hoc forensics. |
| Module signing requirement | Ensures only trusted modules load | Operational overhead — every third-party module must be signed | Bake module-signing into kernel-package build pipelines. Most distros sign their stock modules already. |
| `kexec` blocked | Eliminates a major persistence vector | Cannot live-patch kernels without `kpatch` / `livepatch` | Use Canonical Livepatch / Ksplice / `kpatch` for security-critical kernel patches without reboot. |
| `kdump` broken | No post-mortem kernel core dumps | Crash analysis harder | Use `pstore` and structured panic logging; for many production crashes, application-level data is more useful than kernel core. |
| eBPF restrictions | Direct kernel-memory reads blocked | Some advanced bpftrace scripts won't work | Most production eBPF programs don't need raw kernel-memory reads; the structured helpers handle common cases. |
| Hibernation blocked | Eliminates encrypted-memory-to-disk leak | Servers cannot hibernate | Servers shouldn't hibernate anyway. Disable hibernation systemd target. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Required module not signed after distro upgrade | Boot fails or feature broken (e.g., out-of-tree network driver missing) | dmesg shows lockdown denial for the module | Sign the module against the trusted key; re-deploy. Test in staging before propagating distro upgrades to production. |
| Lockdown disabled accidentally during kernel package upgrade | New kernel boots without `lockdown=` parameter | `cat /sys/kernel/security/lockdown` shows `[none]` | Verify `/etc/default/grub` retains the parameter; some distro upgrades reset it. The systemd-unit fallback in Step 2 catches this. |
| Audit floods with lockdown denials | Audit log grows unbounded | `journalctl -k | grep -c lockdown` rises sharply | Some legitimate tool is repeatedly hitting a lockdown rule. Identify and either fix the tool, sign its needed components, or carve a per-host exception. |
| Hibernation-disabled state breaks laptops | Laptop developers cannot suspend | Reports of failed hibernate from non-server hosts | Apply lockdown selectively. Lockdown is for servers and workstations under engineering control; not for general user laptops where hibernate is expected. |
| Customer escalation: tool requires `/proc/kcore` | Specific tool documented as requiring kernel-memory access fails | Vendor support reports lockdown errors | Move that workload to a non-lockdown debug host; do not lower lockdown on production fleet. |
| Module signed with rotated key | Production module rejected after key rotation | Kernel logs show certificate validation failure | Phase key rotation: enroll new cert alongside old, re-sign all modules with new key, reboot to switch to new key, then remove old. |

## Related Articles

- [Hardening the Linux Kernel Attack Surface with sysctl and Boot Parameters](/articles/linux/sysctl-kernel-hardening/)
- [GRUB Boot Hardening for Production Linux Systems](/articles/linux/grub-boot-hardening/)
- [Linux Kernel Module Loading: Restricting What Loads on Your System](/articles/linux/kernel-module-hardening/)
- [io_uring Security and Hardening](/articles/linux/io-uring-hardening/)
- [Landlock LSM: Unprivileged Kernel Sandboxing](/articles/linux/landlock-lsm/)
