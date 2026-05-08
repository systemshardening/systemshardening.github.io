---
title: "Unified Kernel Image and Measured Boot Hardening"
description: "Harden Linux boot integrity with Unified Kernel Images, systemd-boot, and TPM2 PCR policy binding to replace legacy GRUB+LUKS measured-boot flows."
slug: uki-secure-boot-hardening
date: 2026-05-01
lastmod: 2026-05-01
category: linux
tags: ["uki", "secure-boot", "measured-boot", "tpm2", "systemd-boot", "ima", "pcr"]
personas: ["systems-engineer", "security-engineer", "platform-engineer"]
article_number: 319
difficulty: advanced
estimated_reading_time: 17
published: true
layout: article.njk
permalink: "/articles/linux/uki-secure-boot-hardening/index.html"
---

# Unified Kernel Image and Measured Boot Hardening

## Problem

Legacy Linux boot stacks combine at least three independently managed artifacts: the kernel binary, the initramfs, and the kernel command line. Each must be independently verified for a meaningful secure boot chain, but UEFI Secure Boot only natively verifies PE-format binaries. The initramfs is a cpio archive loaded by the bootloader without any cryptographic verification step in the UEFI firmware. An attacker with write access to `/boot` can swap out the initramfs entirely and the UEFI firmware will never detect the modification, even with Secure Boot enabled and enforced.

GRUB2's history compounds this problem. The BootHole vulnerability class (CVE-2020-10713 and related) demonstrated that GRUB2's own binary could be exploited to bypass Secure Boot validation before the kernel loads. Subsequent patches required coordinated revocation of previously signed bootloaders across every distribution, a process that took years and produced significant breakage. Every link in the chain — shim, GRUB2 binary, GRUB2 modules — expands the attack surface that must be audited and kept current.

Signing the kernel command line is a problem legacy stacks solve inconsistently or not at all. GRUB reads `grub.cfg` at boot, and while some configurations wrap that file in a GPG-signed blob, most deployments do not. An attacker who can modify `grub.cfg` can inject `init=/bin/bash`, disable kernel lockdown, or redirect the root device without invalidating any Secure Boot signature. The kernel sees these parameters as authoritative once the bootloader passes control.

TPM2-based LUKS2 auto-unlock deepens the dependency on the full boot stack being stable. When you seal a disk encryption key to a set of Platform Configuration Registers (PCRs), any change to a measured component causes PCR values to diverge from the policy, and the TPM refuses to release the key. This is the intended behavior, but in practice it means every kernel update requires re-sealing the key before reboot or the system fails to decrypt its root volume and drops to an emergency shell. Automating the re-seal before the old kernel is removed and after the new one is installed, but before the first reboot, is fragile without tooling explicitly designed for it.

The Unified Kernel Image format addresses all three problems simultaneously. A UKI is a single PE/COFF binary that embeds the kernel, the initramfs, the kernel command line, `os-release`, and optionally a splash image as named PE sections. The entire binary is signed with one Authenticode signature. UEFI firmware validates the signature before executing anything. The initramfs can no longer be swapped independently, the command line is part of the signed object, and the single signed artifact produces a stable, predictable measurement in TPM2 PCR 11. When `systemd-cryptenroll` binds a LUKS2 volume key to PCR 11, updating the kernel means building a new UKI, signing it, and enrolling the new PCR policy — a single atomic operation rather than a sequence of fragile steps.

The systemd project has driven UKI adoption through `ukify` (the build tool), `systemd-boot` (a minimal UEFI bootloader that requires no shim in most configurations), and `systemd-cryptenroll` (the TPM2 enrollment tool). Distribution support has followed.

**Target systems:** Fedora 38+, Ubuntu 24.04+, RHEL 10 / CentOS Stream 10, Debian 13 (trixie), systemd ≥ 253.

## Threat Model

**Adversary 1 — Evil Maid with physical access.** An attacker gains brief unsupervised physical access to the machine. They boot from external media, mount the EFI System Partition, and replace the initramfs or inject a malicious entry into `grub.cfg`. On a legacy stack, this succeeds silently. On a UKI stack with Secure Boot enforcing Custom Mode keys, any binary not signed by the enrolled Platform Key is rejected by firmware before execution. The initramfs cannot be replaced independently because it is embedded in the signed UKI.

**Adversary 2 — Supply chain attacker with repository write access.** An attacker compromises a package repository mirror or the build pipeline for a distribution kernel package. They inject a backdoored kernel or initramfs. On a legacy stack with automatic updates enabled, this reaches production on the next `apt upgrade` or `dnf update`. On a UKI stack using `sbctl` or a hardware-backed signing key, the malicious artifact lacks a valid Secure Boot signature and fails to boot. Distribution-signed UKIs extend this protection to the full image including the initramfs.

**Adversary 3 — Insider with bootloader configuration write access.** A privileged but non-root operator or a compromised automation account has write access to `/boot/efi` but not the signing key. They attempt to modify `loader/entries/*.conf` to change the kernel command line, disable `lockdown=integrity`, or redirect the root device. On a legacy GRUB stack this succeeds. On a UKI stack the command line is embedded in the signed binary; the loader entry's `options` line is ignored by `systemd-boot` when a UKI is in use, because the UKI's embedded command line takes precedence.

Without UKI and measured boot, a successful attack on any of these vectors produces no persistent forensic signal. The attacker achieves code execution at kernel or initramfs level before any userspace integrity monitoring starts. IMA/EVM logs, auditd, and EDR agents are all bypassed. With UKI and TPM2 PCR policy binding, the disk encryption key is inaccessible unless the complete boot stack matches the policy at enrollment time. A tampered boot stack fails to unseal the volume key, preventing access to the encrypted root filesystem entirely. The blast radius is contained: the attacker cannot read encrypted data, cannot pivot to persistent access through the filesystem, and the tamper is detectable through PCR log inspection.

## Configuration / Implementation

### Building a UKI with ukify

Install the tooling:

```bash
apt install systemd-ukify sbctl binutils
```

Identify the kernel, initramfs, and command line for the UKI:

```bash
KERNEL=/boot/vmlinuz-6.8.0-51-generic
INITRD=/boot/initrd.img-6.8.0-51-generic
CMDLINE="root=/dev/mapper/root ro quiet splash lsm=lockdown,yama,apparmor,bpf lockdown=integrity"
```

Build the UKI:

```bash
ukify build \
  --linux="${KERNEL}" \
  --initrd="${INITRD}" \
  --cmdline="${CMDLINE}" \
  --os-release=/etc/os-release \
  --output=/boot/efi/EFI/Linux/linux-6.8.0-51-generic.efi
```

Sign the UKI with `sbctl` after key enrollment (see next section):

```bash
sbctl sign /boot/efi/EFI/Linux/linux-6.8.0-51-generic.efi
```

To embed a splash image and a devicetree blob for ARM targets:

```bash
ukify build \
  --linux="${KERNEL}" \
  --initrd="${INITRD}" \
  --cmdline="${CMDLINE}" \
  --os-release=/etc/os-release \
  --splash=/usr/share/plymouth/themes/bgrt/bgrt-fallback.png \
  --output=/boot/efi/EFI/Linux/linux-6.8.0-51-generic.efi
```

For environments using `pesign` with an HSM-backed signing certificate instead of `sbctl`:

```bash
pesign \
  --sign \
  --in=/boot/efi/EFI/Linux/linux-6.8.0-51-generic.efi \
  --out=/boot/efi/EFI/Linux/linux-6.8.0-51-generic.efi \
  --certificate="CN=Secure Boot Signing" \
  --nss-token="HSM Token" \
  --certdir=/etc/pki/pesign \
  --overwrite
```

Verify the embedded sections of the produced UKI:

```bash
objdump -h /boot/efi/EFI/Linux/linux-6.8.0-51-generic.efi | grep -E '\.linux|\.initrd|\.cmdline|\.osrel'
```

### Enrolling Keys into UEFI

Generate Platform Key, Key Exchange Key, and Signature Database key material:

```bash
sbctl create-keys
```

Keys are written to `/usr/share/secureboot/keys/`. Enroll them into UEFI firmware in Setup Mode:

```bash
sbctl enroll-keys --microsoft
```

The `--microsoft` flag includes Microsoft's third-party CA in the Signature Database, which is required to boot option ROMs and some external hardware firmware. Omit it on systems where you control all signed binaries and have no need for Microsoft-signed drivers.

Verify enrollment status:

```bash
sbctl status
```

After enrollment, put the firmware back into User Mode (not Setup Mode) and enable Secure Boot enforcement. On most systems this happens automatically when keys are enrolled, but verify in firmware settings.

Sign all existing EFI binaries on the system before rebooting:

```bash
sbctl sign-all
sbctl verify
```

### systemd-boot Installation and Configuration

Install systemd-boot to the EFI System Partition:

```bash
bootctl install
```

Configure the bootloader timeout and default entry in `/boot/efi/loader/loader.conf`:

```ini
timeout 3
default @saved
console-mode auto
editor no
```

Setting `editor no` prevents interactive kernel command-line modification at the boot menu, which would otherwise allow bypassing the signed command line embedded in the UKI. UKIs discovered under `/boot/efi/EFI/Linux/` are automatically enumerated by systemd-boot; no explicit loader entry is required for them.

Verify bootloader installation:

```bash
bootctl status
```

Update the bootloader binary itself whenever systemd is updated:

```bash
bootctl update
sbctl sign /boot/efi/EFI/systemd/systemd-bootx64.efi
sbctl sign /boot/efi/EFI/BOOT/BOOTX64.EFI
```

### TPM2 PCR Policy Binding with systemd-cryptenroll

Select the PCRs to bind based on what each one measures:

| PCR | What it measures |
|-----|-----------------|
| 0   | UEFI firmware code and data |
| 7   | Secure Boot state and policy |
| 11  | UKI hash (set by systemd-boot from the PE image hash) |
| 12  | Kernel command line passed by bootloader (redundant when using UKI) |
| 14  | Shim MOK database (only relevant with shim) |

For a UKI stack, binding to PCRs 0+7+11 covers firmware integrity, Secure Boot enforcement state, and the exact UKI that was booted. Binding PCR 0 means a firmware update requires re-enrollment; whether this is acceptable depends on the update frequency and operational model.

Format the LUKS2 volume if not already done, then enroll the TPM2 token:

```bash
systemd-cryptenroll \
  --tpm2-device=auto \
  --tpm2-pcrs=0+7+11 \
  /dev/sda3
```

If PCR 0 binding causes too many firmware-update re-enrollments, drop it:

```bash
systemd-cryptenroll \
  --tpm2-device=auto \
  --tpm2-pcrs=7+11 \
  /dev/sda3
```

Update `/etc/crypttab` to activate the volume using the TPM2 token:

```
root  /dev/sda3  -  tpm2-device=auto
```

Verify the enrolled token:

```bash
cryptsetup luksDump /dev/sda3 | grep -A 10 "Tokens:"
```

To wipe a previously enrolled token and re-enroll after a UKI update:

```bash
systemd-cryptenroll --wipe-slot=tpm2 /dev/sda3
systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7+11 /dev/sda3
```

For production systems, maintain a recovery passphrase in a separate LUKS keyslot stored in a secrets manager:

```bash
systemd-cryptenroll --password /dev/sda3
```

### Automating UKI Rebuild on Kernel Updates

The `kernel-install` framework invokes plugins from `/usr/lib/kernel/install.d/` and `/etc/kernel/install.d/` on every kernel install or removal. Create a plugin to build and sign a UKI whenever a new kernel lands:

```bash
cat > /etc/kernel/install.d/90-uki-sign.install << 'EOF'
#!/bin/bash
set -euo pipefail

COMMAND="$1"
KERNEL_VERSION="$2"
BOOT_DIR_ABS="$3"
KERNEL_IMAGE="$4"

if [[ "$COMMAND" != "add" ]]; then
    exit 0
fi

INITRD="${BOOT_DIR_ABS}/initrd"
CMDLINE="/etc/kernel/cmdline"
OUTPUT="/boot/efi/EFI/Linux/linux-${KERNEL_VERSION}.efi"

ukify build \
    --linux="${KERNEL_IMAGE}" \
    --initrd="${INITRD}" \
    --cmdline="${CMDLINE}" \
    --os-release=/etc/os-release \
    --output="${OUTPUT}"

sbctl sign "${OUTPUT}"
EOF

chmod +x /etc/kernel/install.d/90-uki-sign.install
```

Store the kernel command line in `/etc/kernel/cmdline` so the plugin can read it:

```
root=/dev/mapper/root ro quiet lsm=lockdown,yama,apparmor,bpf lockdown=integrity
```

For systems using `dracut`, set UKI output in `/etc/dracut.conf.d/uki.conf`:

```
uefi="yes"
uefi_stub="/usr/lib/systemd/boot/efi/linuxx64.efi.stub"
kernel_cmdline="root=/dev/mapper/root ro quiet lockdown=integrity"
```

For `mkinitcpio` on Arch-based systems, add `uki` to the `PRESETS` array in `/etc/mkinitcpio.d/linux.preset`:

```bash
ALL_config="/etc/mkinitcpio.conf"
ALL_kver="/boot/vmlinuz-linux"
PRESETS=('default' 'uki')
default_image="/boot/initramfs-linux.img"
uki_uki="/boot/efi/EFI/Linux/arch-linux.efi"
uki_cmdline="/etc/kernel/cmdline"
```

After a kernel update hook runs, re-enroll the TPM2 token to the new PCR 11 value before rebooting. Automate this with a systemd oneshot service triggered by the kernel-install hook:

```bash
cat > /etc/systemd/system/tpm2-reenroll.service << 'EOF'
[Unit]
Description=Re-enroll TPM2 LUKS token after UKI update
After=local-fs.target
ConditionPathExists=/run/uki-updated

[Service]
Type=oneshot
ExecStart=/usr/bin/systemd-cryptenroll --wipe-slot=tpm2 /dev/sda3
ExecStart=/usr/bin/systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7+11 /dev/sda3
ExecStartPost=/bin/rm -f /run/uki-updated
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl enable tpm2-reenroll.service
```

### Verifying PCR Values

Read current PCR values from the TPM2:

```bash
tpm2_pcrread sha256:0,7,11
```

Predict the PCR 11 value for a specific UKI before booting it:

```bash
systemd-measure calculate \
  --linux=/boot/efi/EFI/Linux/linux-6.8.0-51-generic.efi \
  --pcr-bank=sha256 \
  --pcr=11
```

Compare the predicted value against the current TPM state to confirm the running UKI matches expectations:

```bash
systemd-measure verify \
  --linux=/boot/efi/EFI/Linux/linux-6.8.0-51-generic.efi
```

Inspect the full TPM2 event log for the boot session to audit what contributed to each PCR:

```bash
journalctl -b --grep="TPM" | head -50
tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements
```

### IMA Integration

When IMA is active, boot with `ima_policy=tcb` in the kernel command line embedded in the UKI to enforce kernel module signing verification and file measurement. Because the command line is part of the signed UKI, this policy cannot be removed without rebuilding and re-signing the image:

```
root=/dev/mapper/root ro quiet lockdown=integrity ima_policy=tcb ima_hash=sha256
```

Verify IMA is measuring files after boot:

```bash
cat /sys/kernel/security/ima/ascii_runtime_measurements | head -20
```

## Expected Behaviour

| Signal | Before (legacy GRUB) | After (UKI + measured boot) |
|--------|---------------------|-----------------------------|
| initramfs replaced on disk | No detection; tampered initramfs boots normally | Secure Boot rejects UKI signature mismatch; system refuses to boot |
| Kernel command line modified in grub.cfg | Modified cmdline takes effect on next boot | Embedded cmdline in signed UKI takes precedence; loader entry `options` line ignored |
| LUKS auto-unlock after kernel update | TPM policy sealed to old PCR values fails; manual passphrase required | New UKI triggers re-enrollment hook; TPM2 policy updated before first reboot |
| UEFI Secure Boot disabled in firmware | No runtime detection | PCR 7 diverges from enrollment-time value; TPM refuses to release volume key |
| Boot from external unsigned media | Succeeds if no UEFI password set | Rejected by Secure Boot; unsigned bootloaders cannot execute |
| Firmware update applied | Legacy GRUB continues to boot; no attestation | PCR 0 diverges (if bound); requires re-enrollment or pre-authorized firmware update policy |
| IMA policy tampered via cmdline injection | Policy change takes effect if cmdline is writable | cmdline is part of signed UKI; IMA policy cannot be changed without re-signing |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Vendor kernel vs custom kernel | Distro handles UKI signing; no key management needed | Custom kernel builds require in-house signing infrastructure | Use `sbctl` with machine-local keys for custom builds; distribute public key via configuration management |
| Dual-boot with Windows | Minimal; Secure Boot Custom Mode can coexist with Windows if Microsoft CA is included | UEFI key enrollment is complex; wrong mode wipes Windows boot entries | Use `sbctl enroll-keys --microsoft`; test in VM before production enrollment |
| TPM2 availability on VMs | Full protection when vTPM is present (AWS Nitro, Azure Gen2, GCP Confidential) | Many legacy VM configurations lack vTPM or present TPM 1.2 only | Verify with `tpm2_getcap properties-fixed`; fall back to passphrase-only LUKS on unsupported VMs |
| Recovery workflow complexity | Compromised boot stack is reliably blocked | Firmware update, Secure Boot key loss, or failed hook leaves system unbootable | Pre-provision recovery passphrase in LUKS slot 0; store in secrets manager; document recovery runbook |
| UKI build time in update hook | Signing is atomic; no partial-update boot risk | UKI build adds 10–30 seconds to every kernel update | Acceptable overhead for security gain; parallelize initramfs generation if needed |
| Single signed artifact | Simpler audit trail; one signature covers kernel+initrd+cmdline | Larger EFI binary; some firmware has EFI partition size or file-count limits | Ensure EFI partition ≥ 512 MB; monitor partition usage as part of capacity planning |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| PCR mismatch after firmware update | System prompts for LUKS passphrase at boot instead of auto-unlocking | `tpm2_pcrread sha256:0` shows value different from enrollment-time log | Boot with recovery passphrase; run `systemd-cryptenroll --wipe-slot=tpm2 /dev/sda3` then re-enroll; if PCR 0 is frequently changing, drop it from the PCR set |
| Lost UEFI Secure Boot keys (`sbctl` keys deleted) | New UKIs cannot be signed; system boots unsigned UKI only if Secure Boot temporarily disabled | `sbctl status` shows no keys enrolled; `sbctl verify` reports unsigned binaries | Restore keys from backup (keep `/usr/share/secureboot/keys/` in encrypted backup); if unrecoverable, boot recovery media, disable Secure Boot temporarily, regenerate keys, re-enroll |
| UKI build failure in kernel update hook | New kernel installed but no bootable UKI created; system boots previous kernel or drops to firmware menu | `journalctl -b -1 -u kernel-install` shows build error; `/boot/efi/EFI/Linux/` missing new entry | Fix build error (missing initrd, invalid cmdline path); manually run `ukify build` and `sbctl sign`; verify with `bootctl list` |
| Secure Boot disabled accidentally in firmware | TPM PCR 7 changes; volume key unsealing fails | System requests LUKS passphrase at boot; `tpm2_pcrread sha256:7` differs from expected | Re-enable Secure Boot in firmware settings; if PCR 7 value now matches enrollment, TPM auto-unlock resumes; otherwise re-enroll |
| EFI partition full | `kernel-install` hook succeeds but `ukify` cannot write UKI; kernel update partially applied | `df /boot/efi` shows 100% usage; hook log shows write error | Remove old UKI entries with `bootctl unlink` or manual deletion; increase EFI partition size if structurally possible; set up monitoring alert at 80% EFI partition usage |
| TPM2 lockout triggered by repeated failed unseals | TPM enters lockout mode; no further unsealing attempts succeed until timeout expires | `tpm2_getcap properties-variable | grep lockout` shows lockout counter incremented | Wait for lockout timer to expire (default: 2 hours after 32 failed attempts); boot with recovery passphrase; investigate why PCR values diverged |

## Related Articles

- [GRUB Boot Hardening](/articles/linux/grub-boot-hardening/)
- [LUKS2 TPM2 Sealing](/articles/linux/luks-tpm2-sealing/)
- [dm-verity Root Filesystem Integrity](/articles/linux/dm-verity/)
- [Kernel Lockdown Mode](/articles/linux/kernel-lockdown/)
- [Artifact Integrity in CI/CD Pipelines](/articles/cicd/artifact-integrity/)
