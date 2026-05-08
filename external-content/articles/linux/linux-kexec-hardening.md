---
title: "Linux kexec Hardening: Signed Kernel Loading and Lockdown Integration"
description: "Restrict and authenticate kexec on production Linux: signed kexec_file_load, lockdown mode interactions, kdump isolation, and detection of kexec abuse."
slug: "linux-kexec-hardening"
date: 2026-05-08
lastmod: 2026-05-08
category: "linux"
tags: ["kexec", "kernel", "lockdown", "secure-boot", "kdump", "linux"]
personas: ["systems-engineer", "security-engineer", "platform-engineer"]
article_number: 649
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/linux/linux-kexec-hardening/index.html"
---

# Linux kexec Hardening: Signed Kernel Loading and Lockdown Integration

## Problem

`kexec` lets a privileged process load a new kernel image into memory and jump to it without going through firmware. It exists for two legitimate reasons: fast reboots on large servers, and `kdump` capture of crashed kernels for post-mortem analysis. From an attacker's perspective it is also one of the cleanest ways to defeat almost every host integrity control on a Linux system. A successful `kexec_load(2)` replaces the running kernel with code of the attacker's choosing, bypassing IMA, EVM, AppArmor, SELinux, eBPF LSM, and any process-level monitoring. The new kernel can be unsigned, lockdown can be cleared, and the audit subsystem inherits whatever rules the new image dictates.

Two syscalls are involved. The legacy `kexec_load(2)` accepts an in-memory image with no integrity checks at all — root with `CAP_SYS_BOOT` can stage arbitrary bytes. The newer `kexec_file_load(2)` (introduced in 3.17) takes file descriptors and runs the kernel's own signature verification path. On distributions with `CONFIG_KEXEC_BZIMAGE_VERIFY_SIG=y` plus `CONFIG_KEXEC_VERIFY_SIG=y`, `kexec_file_load` will reject any kernel that is not signed by a key in the platform `.builtin_trusted_keys` (or `.secondary_trusted_keys`) keyring. The legacy syscall does no such checking and is still enabled by default on most stock kernels, including RHEL 9, Ubuntu 24.04 LTS, and the upstream long-term tree.

The threat is not theoretical. Several rootkit families and at least two nation-state implants observed in 2024–2025 used `kexec_load` to swap out the running kernel post-exploitation, sidestepping endpoint detection that was only inspecting the booted kernel's modules. The `kexec` path is also a common evasion when an attacker has obtained `CAP_SYS_BOOT` via a misconfigured container or a privilege-escalation chain that does not yield full UID 0.

Mitigation has three moving parts that interact non-trivially: (a) lockdown mode, which gates which syscalls are usable at all, (b) Secure Boot, which controls which keys can sign the new kernel, and (c) the IMA / measured-boot stack, which records what got loaded. Most operators enable Secure Boot and stop there; the result is a system where Secure Boot is verifying the boot chain and `kexec_load` is happily blowing past it at runtime.

Target systems: Linux 5.15+ (RHEL 9.x, Ubuntu 22.04/24.04 LTS, Debian 12, SUSE 15 SP5), x86_64 and arm64 with UEFI Secure Boot enabled.

## Threat Model

1. **Local root attacker with CAP_SYS_BOOT.** Goal: load an unsigned kernel that disables host-based monitoring and persists across reboot via UEFI variable manipulation. Attack surface: legacy `kexec_load(2)`.
2. **Container escape with a leaked CAP_SYS_BOOT capability.** Misconfigured pods or privileged containers occasionally retain `CAP_SYS_BOOT`. Goal: pivot from container to host kernel replacement.
3. **Supply-chain compromise of `kexec-tools` or initramfs hooks.** Goal: replace the userspace kexec binary so even a "clean reboot" loads attacker-controlled code via the kdump path.
4. **Insider with maintenance-window access.** Goal: stage a backdoored kernel during scheduled patching, leveraging the fact that operators frequently disable lockdown for kdump testing.

Without hardening, any of these gives the attacker arbitrary kernel-mode code execution that survives until firmware-level reboot and may persist beyond it. With kexec locked to signed images plus lockdown in `confidentiality` mode, adversary 1 and 2 are reduced to needing a code-signing-key compromise, and adversaries 3 and 4 leave measurable IMA/audit trails.

## Configuration / Implementation

### Step 1 — Confirm what your kernel allows today

```bash
# Is lockdown active, and at what level?
cat /sys/kernel/security/lockdown
# Expected after hardening: [confidentiality]   (none integrity confidentiality)

# Does the kernel support signed kexec_file_load?
grep -E 'CONFIG_KEXEC|CONFIG_KEXEC_FILE|VERIFY_SIG' /boot/config-$(uname -r)
```

You want to see:

```
CONFIG_KEXEC=y
CONFIG_KEXEC_FILE=y
CONFIG_KEXEC_SIG=y
CONFIG_KEXEC_SIG_FORCE=y      # or compensated for via lockdown
CONFIG_KEXEC_BZIMAGE_VERIFY_SIG=y
```

`KEXEC_SIG_FORCE=y` makes the kernel reject *any* unsigned image via `kexec_file_load`, regardless of lockdown state. Without it, signature checking only kicks in when lockdown is at integrity or higher.

### Step 2 — Engage kernel lockdown

Lockdown disables the legacy `kexec_load(2)` entirely and forces all kexec calls through the file-based, signature-checked path. The simplest activation is via the kernel command line:

```bash
# /etc/default/grub
GRUB_CMDLINE_LINUX="... lockdown=confidentiality"
```

Then:

```bash
sudo update-grub          # Debian/Ubuntu
sudo grub2-mkconfig -o /boot/grub2/grub.cfg   # RHEL/SUSE
```

On Secure Boot systems the kernel auto-engages `lockdown=integrity` when SB is enabled — that is enough to block legacy kexec_load, but `confidentiality` is the recommended target for production hosts because it also blocks `/dev/mem`, `/dev/kmem`, and several debugfs leak paths that an attacker could otherwise use to recover signing keys or live-patch the kernel.

Verify after reboot:

```bash
dmesg | grep -i lockdown
# [    0.000000] Kernel is locked down from command line; see man kernel_lockdown.7
cat /sys/kernel/security/lockdown
# none integrity [confidentiality]
```

### Step 3 — Constrain CAP_SYS_BOOT

Even with lockdown, `CAP_SYS_BOOT` allows `reboot(2)` and the still-permitted `kexec_file_load`. Audit which units actually need it:

```bash
# Find services granted CAP_SYS_BOOT explicitly.
systemctl show '*' --property=CapabilityBoundingSet 2>/dev/null \
  | grep -B1 cap_sys_boot
```

Almost nothing legitimate outside `systemd-shutdown`, `kdump.service`, and an HA fencing agent needs it. For everything else:

```ini
# /etc/systemd/system/<unit>.d/override.conf
[Service]
CapabilityBoundingSet=~CAP_SYS_BOOT
AmbientCapabilities=
NoNewPrivileges=yes
```

### Step 4 — Sign your kdump / staged kernel

`kdump` is the most common reason teams disable kexec hardening: the captured kernel is by default unsigned, so `kexec_file_load` rejects it under `KEXEC_SIG_FORCE`. The fix is to use the same signed kernel as the running system (which is what `kexec-tools` ≥ 2.0.26 does by default with `--reuse-cmdline`):

```bash
# /etc/sysconfig/kdump  (RHEL) or /etc/default/kdump-tools (Debian)
KDUMP_KEXEC_ARGS="-s --reuse-cmdline"   # -s forces kexec_file_load
KEXEC_ARGS="-s"
```

Confirm the signed path is being used:

```bash
sudo kexec -s -p /boot/vmlinuz-$(uname -r) \
  --initrd=/boot/initrd.img-$(uname -r) \
  --reuse-cmdline
sudo kexec -p -u   # unload after testing
dmesg | tail -5
# kexec_core: Starting new kernel
# (or, if signature-check failed:) kexec_file_load: Image not signed
```

### Step 5 — Lock down /sys/kernel/kexec_* knobs

```bash
# /etc/sysctl.d/90-kexec.conf
kernel.kexec_load_disabled = 1
```

`kexec_load_disabled=1` is a one-way switch: once set, *both* kexec syscalls are disabled until reboot. Combined with `KEXEC_SIG_FORCE`, this is belt-and-braces — useful on hosts that never need kdump (e.g., stateless workers behind a load balancer) where you take the dump-loss tradeoff for the strongest guarantee.

For systems that do need kdump, leave `kexec_load_disabled=0` but rely on lockdown + signature enforcement.

### Step 6 — Add an IMA measurement rule for kexec

```bash
# /etc/ima/ima-policy
measure func=KEXEC_KERNEL_CHECK
measure func=KEXEC_INITRAMFS_CHECK
appraise func=KEXEC_KERNEL_CHECK appraise_type=imasig
appraise func=KEXEC_INITRAMFS_CHECK appraise_type=imasig
```

This causes any kexec'd kernel and initramfs to be hashed into the IMA measurement log (and, if you use a TPM, extended into PCR 10) before execution. SIEM ingest of `/sys/kernel/security/ima/ascii_runtime_measurements` then gives you a signed audit trail of every kernel that has ever run on the host.

### Step 7 — Audit rule for kexec syscalls

```
# /etc/audit/rules.d/50-kexec.rules
-a always,exit -F arch=b64 -S kexec_load -S kexec_file_load -k kexec
-a always,exit -F arch=b64 -S init_module -S finit_module -F auid!=-1 -k modload
```

Every kexec call now produces an `audit.log` event tagged `kexec` with the calling UID, command, and the file descriptor. In a hardened environment kexec calls are rare and easily alertable.

## Expected Behaviour

| Signal | Before hardening | After hardening |
|--------|------------------|-----------------|
| `kexec_load(2)` from root | Loads any bytes; jumps to new kernel | `EPERM` (lockdown blocks) |
| `kexec_file_load` of unsigned kernel | Loads silently | `-EKEYREJECTED`; dmesg `Image not signed` |
| `/dev/mem` read | Allowed for root | `EPERM` under `confidentiality` |
| Audit `kexec` key entries | Absent | One entry per kexec attempt |
| IMA measurement log | No KEXEC_KERNEL_CHECK rows | Hash + path of each kexec'd image |
| TPM PCR 10 | Static post-boot | Extended on each kexec |

Verification snippet:

```bash
# This must fail under hardening.
sudo perl -e 'syscall(246, 0, 0, 0, 0)' 2>&1   # 246 = kexec_load on x86_64
# Operation not permitted

# This must succeed (signed) and fail (unsigned).
sudo kexec -s -l /boot/vmlinuz-$(uname -r) --initrd=/boot/initrd.img-$(uname -r) --reuse-cmdline
sudo kexec -s -l /tmp/unsigned-vmlinuz --initrd=/tmp/initrd --reuse-cmdline
# kexec_file_load failed: Required key not available
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| `lockdown=confidentiality` | Closes /dev/mem, kprobes, BPF tracing leaks | Breaks some debugging tools (perf with raw tracepoints, kgdb) | Keep a separate non-prod kernel with lockdown=none for kernel debugging |
| `KEXEC_SIG_FORCE=y` | Blocks unsigned kexec even outside lockdown | Custom-built kernels need re-signing for upgrades | Wire kernel signing into the build pipeline, mirror Secure Boot keys |
| `kexec_load_disabled=1` | Strongest possible block | No kdump capture possible | Reserve for hosts where dump capture is not required (e.g., immutable workers) |
| IMA appraise on kexec | Cryptographic audit trail | IMA policy authoring is fiddly; bad rules brick systems | Roll out in `measure`-only mode first, wait two weeks, then add `appraise` |
| CapabilityBoundingSet trimming | Eliminates whole classes of caller | Some HA agents legitimately need CAP_SYS_BOOT | Whitelist by unit, audit changes via systemd unit drop-in review |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| kdump fails post-hardening | `kdump.service` failed; no vmcore captured on crash | `systemctl status kdump`; `journalctl -u kdump-tools` shows `Required key not available` | Switch kdump to `-s --reuse-cmdline`; ensure running kernel is signed |
| Lockdown breaks vendor monitoring agent | Agent reports BPF attach failure | `dmesg \| grep "Lockdown:"` | Update agent to use ring-buffer perf events instead of kprobe blobs; or pin host to `integrity` not `confidentiality` |
| Signed kernel boots but kexec rejects same image | `kexec_file_load: Required key not available` | dmesg shows mismatch between `.builtin_trusted_keys` and signing CA | Re-sign kernel with the in-kernel CA; `keyctl list %:.builtin_trusted_keys` |
| Audit volume explodes | auditd backpressure, lost events | `aureport -k kexec` shows >100/day | Investigate — legitimate kexec rate is <1/day per host; high counts indicate misconfigured monitoring agents |
| Boot loop after `kexec_load_disabled=1` plus broken initramfs | Recovery via kdump impossible | Console-only | Boot rescue kernel from firmware menu; sysctl is reset on reboot |

## When to Consider a Managed Alternative

- Confidential-VM offerings on AWS Nitro, Azure Confidential VMs, and GCP Confidential Space lock down the guest kernel boundary as part of the platform; kexec attacks at the guest level still matter for in-VM tenants but the blast radius shrinks.
- Talos Linux ships with an immutable, signed kernel and disables kexec entirely — appropriate for Kubernetes worker fleets where you control the OS.
- ChromeOS and Bottlerocket apply similar lockdown defaults out of the box.

## Related Articles

- [UEFI Secure Boot DB Management](/articles/linux/linux-uefi-secure-boot-db/)
- [Linux IMA / EVM Configuration](/articles/linux/linux-ima-evm/)
- [Kernel Lockdown Mode](/articles/linux/kernel-lockdown/)
- [Linux Capability Hardening](/articles/linux/linux-capability-hardening/)
- [UKI Secure Boot Hardening](/articles/linux/uki-secure-boot-hardening/)
