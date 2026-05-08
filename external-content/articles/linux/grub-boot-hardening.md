---
title: "Hardening GRUB and the Boot Process: Secure Boot, Boot Passwords, and Tamper Detection"
description: "Without boot security, an attacker with physical access or console access (BMC, IPMI, cloud serial console) to a Linux system can."
slug: "grub-boot-hardening"
date: 2026-03-23
lastmod: 2026-03-23
category: "linux"
tags: ["grub", "secure-boot", "uefi", "tpm", "boot-hardening", "linux"]
personas: ["systems-engineer", "security-engineer"]
article_number: 11
difficulty: "advanced"
estimated_reading_time: 14
provider_bridges:
  - name: "Civo"
    id: 22
    category: "managed-kubernetes"
  - name: "DigitalOcean"
    id: 21
    category: "managed-kubernetes"
published: true
layout: article.njk
permalink: "/articles/linux/grub-boot-hardening/index.html"
---

# Hardening GRUB and the Boot Process: Secure Boot, Boot Passwords, and Tamper Detection

## Problem

Without boot security, an attacker with physical access or console access (BMC, IPMI, cloud serial console) to a Linux system can:

- Edit GRUB boot parameters to add `init=/bin/bash`, dropping directly to a root shell without any authentication.
- Boot into single-user mode or recovery mode, which on many distributions gives a root shell with no password prompt.
- Replace the kernel or initramfs with a trojaned version that captures credentials or installs a rootkit before the operating system starts.
- Load unsigned kernel modules that bypass all runtime security controls.

These attacks bypass every hardening measure applied at the operating system level. Disk encryption (LUKS), [SELinux](https://github.com/SELinuxProject/selinux), [AppArmor](https://apparmor.net), firewall rules, and sysctl settings are all irrelevant if the attacker can change what boots.

Boot hardening is primarily relevant for bare metal servers and virtual machines where you control the boot process. For containers, the boot chain is the host's concern. For managed cloud instances, the provider handles boot integrity.

**Target systems:** Ubuntu 24.04 LTS, Debian 12, RHEL 9 / Rocky Linux 9 on bare metal or VMs with UEFI firmware.

## Threat Model

- **Adversary:** Attacker with physical access to the server (data centre breach, stolen laptop, decommissioned hardware), or remote access to the management interface (compromised BMC/IPMI/iDRAC credentials, cloud serial console).
- **Access level:** Console access sufficient to interact with the bootloader.
- **Objective:** Gain root access by modifying boot parameters, replace the kernel with a malicious version, or install a bootkit that persists across OS reinstalls.
- **Blast radius:** Complete host compromise. A trojaned kernel or bootkit has full control over the system, including the ability to hide itself from runtime detection tools.

## Configuration

### UEFI Secure Boot

Secure Boot ensures that only signed bootloaders, kernels, and kernel modules can execute during the boot process. The UEFI firmware verifies each component's signature before allowing it to run.

Check Secure Boot status:

```bash
# Check if Secure Boot is enabled
mokutil --sb-state
# Expected output: "SecureBoot enabled"

# List enrolled keys
mokutil --list-enrolled
```

On Ubuntu and Debian, Secure Boot works out of the box with the distribution-signed kernel and GRUB. The chain of trust is: Microsoft UEFI CA signs Canonical's shim, which signs GRUB, which verifies the kernel signature.

**Enrolling custom keys** (for organisations that want to control the trust chain):

```bash
# Generate your own Secure Boot keys
openssl req -new -x509 -newkey rsa:2048 -keyout MOK.priv -outform DER \
    -out MOK.der -nodes -days 36500 -subj "/CN=My Organisation Secure Boot/"

# Enroll the key (requires reboot and physical/console confirmation)
sudo mokutil --import MOK.der
# You will be prompted to set a one-time password.
# On next reboot, the MOK manager will ask for this password to confirm enrollment.

sudo systemctl reboot
# At the blue MOK manager screen: Enroll MOK -> Continue -> Enter password -> Reboot
```

### GRUB Password Protection

A GRUB password prevents unauthorized users from editing boot parameters or selecting alternative boot entries.

Generate a password hash:

```bash
grub-mkpasswd-pbkdf2
# Enter password: (use a strong, unique password)
# Reenter password:
# Output: PBKDF2 hash of your password is grub.pbkdf2.sha512.10000.HASH...
```

Create the GRUB configuration:

```bash
# /etc/grub.d/40_custom - add after the existing comments

set superusers="admin"
password_pbkdf2 admin grub.pbkdf2.sha512.10000.YOUR_HASH_HERE
```

To allow the default boot entry to start without a password (only require the password for editing):

```bash
# /etc/grub.d/10_linux - find the menuentry line and add --unrestricted
# On Ubuntu/Debian, edit /etc/grub.d/10_linux:
# Change: menuentry '...' --class gnu-linux ...
# To:     menuentry '...' --class gnu-linux --unrestricted ...
```

A simpler approach on Ubuntu/Debian is to create `/etc/grub.d/01_password`:

```bash
#!/bin/sh
cat << 'EOF'
set superusers="admin"
password_pbkdf2 admin grub.pbkdf2.sha512.10000.YOUR_HASH_HERE
EOF
```

```bash
sudo chmod 755 /etc/grub.d/01_password
sudo update-grub
```

After this, pressing `e` to edit a boot entry at the GRUB menu requires the password. The default entry still boots automatically after the timeout.

### Kernel Module Signing Enforcement

Secure Boot alone verifies the kernel, but modules loaded after boot may not be signed. Enforce module signature verification:

```bash
# Check current kernel module signing configuration
grep CONFIG_MODULE_SIG /boot/config-$(uname -r)
# Expected:
# CONFIG_MODULE_SIG=y
# CONFIG_MODULE_SIG_FORCE=y (if enforced)
```

To sign custom modules (required when `CONFIG_MODULE_SIG_FORCE=y`):

```bash
# Sign a module with your MOK key
/usr/src/linux-headers-$(uname -r)/scripts/sign-file \
    sha256 MOK.priv MOK.der /path/to/module.ko

# Verify the signature
modinfo /path/to/module.ko | grep sig
```

On RHEL 9 and Rocky Linux 9, the kernel enforces module signatures by default when Secure Boot is enabled. On Ubuntu, you may need to configure this explicitly by adding `module.sig_enforce=1` to the kernel command line:

```bash
# /etc/default/grub
GRUB_CMDLINE_LINUX="$EXISTING_VALUES module.sig_enforce=1"
```

```bash
sudo update-grub
```

### Boot Integrity with TPM 2.0

The Trusted Platform Module (TPM) can measure each component of the boot process and store those measurements in Platform Configuration Registers (PCRs). You can then verify at runtime that the boot chain has not been tampered with.

Check TPM availability:

```bash
# Check for TPM device
ls -la /dev/tpm*
# Expected: /dev/tpm0 and /dev/tpmrm0

# Check TPM version
cat /sys/class/tpm/tpm0/tpm_version_major
# Expected: 2

# Read PCR values
tpm2_pcrread sha256:0,1,2,3,4,5,6,7
```

PCR reference for boot integrity:

| PCR | Measures |
|-----|----------|
| 0 | UEFI firmware code |
| 1 | UEFI firmware configuration |
| 2 | Option ROMs |
| 4 | Bootloader (GRUB) |
| 5 | Bootloader configuration (grub.cfg) |
| 7 | Secure Boot state |
| 8 | Kernel command line |
| 9 | Kernel and initramfs |

Bind LUKS disk encryption to TPM PCR values so the disk only unlocks if the boot chain is unmodified:

```bash
# Bind LUKS to TPM PCRs 0,2,4,7 (firmware, option ROMs, bootloader, Secure Boot state)
sudo systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0+2+4+7 /dev/sda2

# Test: the system should boot and decrypt automatically if the boot chain is intact.
# If any measured component changes, decryption fails and you must enter the recovery key.
```

### Protecting GRUB Configuration Files

Restrict access to GRUB configuration to prevent non-root users from reading password hashes or modifying boot parameters:

```bash
# Restrict GRUB configuration file permissions
sudo chmod 600 /boot/grub/grub.cfg
sudo chmod 700 /boot/grub
sudo chmod 600 /etc/grub.d/*

# On RHEL/Rocky:
sudo chmod 600 /boot/grub2/grub.cfg
```

## Expected Behaviour

After applying boot hardening:

- `mokutil --sb-state` returns "SecureBoot enabled"
- Pressing `e` at the GRUB menu prompts for the superuser password before allowing edits
- The default boot entry starts automatically without requiring a password (if `--unrestricted` is set)
- `dmesg | grep "Secure boot"` shows "Secure boot enabled"
- Attempting to load an unsigned kernel module fails: `modprobe unsigned_module` returns "Required key not available"
- `tpm2_pcrread` shows non-zero values in boot-related PCRs
- Kernel updates signed by the distribution install and boot normally
- The system decrypts LUKS volumes automatically when the boot chain is unmodified (if TPM-bound)

## Trade-offs

| Control | Benefit | Cost | Mitigation |
|---------|---------|------|------------|
| Secure Boot | Prevents unsigned code from running during boot | Blocks unsigned kernel modules (NVIDIA proprietary, ZFS DKMS, VirtualBox) | Sign third-party modules with your MOK key. Or use `mokutil --disable-validation` (reduces security). |
| GRUB password | Prevents unauthorized boot parameter modification | Every non-default boot action (recovery mode, kernel selection) requires the password. Lost password requires rescue media. | Store the GRUB password hash in your configuration management system. Use `--unrestricted` on the default entry. |
| Module signature enforcement | Prevents loading of malicious or tampered modules | DKMS modules must be signed after every kernel update. Adds complexity to the kernel update process. | Automate signing with a post-kernel-install hook. On Ubuntu, the `dkms` package handles this when MOK is enrolled. |
| TPM-bound LUKS | Disk only decrypts if boot chain is unmodified | Firmware updates, GRUB updates, or kernel updates change PCR values, breaking automatic decryption until you re-enroll. | Always keep a recovery key accessible. Re-enroll TPM after planned updates: `systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto /dev/sda2`. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Secure Boot blocks kernel update | System will not boot after `apt upgrade` installs a new kernel | UEFI firmware shows "Security Violation" or boots to the previous kernel | Boot from rescue media. Enroll the new kernel's signing key with `mokutil --import`. Or temporarily disable Secure Boot in UEFI settings to boot and fix. |
| GRUB password lost | Cannot edit boot parameters or enter recovery mode | GRUB prompts for a password that no one knows | Boot from USB/CD rescue media. Mount the root filesystem. Edit `/etc/grub.d/` to remove or reset the password. Run `update-grub` from chroot. |
| TPM PCR mismatch after update | LUKS automatic decryption fails; system prompts for recovery key on boot | Boot hangs at "Please enter passphrase for disk" | Enter the LUKS recovery key manually. After booting, re-enroll TPM with updated PCR values. |
| Unsigned module needed urgently | Critical driver (network, storage) cannot be loaded because module signing is enforced | `modprobe` fails with "Required key not available"; hardware not functional | Temporarily add `module.sig_enforce=0` to kernel parameters at GRUB (requires GRUB password). Sign the module, then re-enable enforcement. |
| DKMS module not signed after kernel update | Third-party module (NVIDIA, ZFS) fails to load after kernel update | `dkms status` shows module built but not signed; `modprobe` fails | Run `sign-file` manually on the built module. Add signing to the DKMS post-build hook to prevent recurrence. |

## When to Consider a Managed Alternative

**Transition point:** Boot security matters most on bare metal servers and self-managed VMs. It is irrelevant for containers, and it is handled by the provider on managed cloud instances.

**What managed providers handle:**

Cloud providers (AWS, GCP, Azure) offer trusted launch VMs with measured boot, vTPM, and Secure Boot enabled by default. The provider manages the firmware, bootloader integrity, and boot measurement. You do not need to configure GRUB passwords or TPM enrollment on these instances.

Managed [Kubernetes](https://kubernetes.io) providers ([Civo](https://www.civo.com), [DigitalOcean](https://www.digitalocean.com), [Vultr](https://www.vultr.com), [Linode](https://www.linode.com)) handle node boot integrity entirely. The node images are built with Secure Boot support, and you never interact with the bootloader on these nodes.

**What you still control:** On self-managed bare metal or VMs, boot hardening is your responsibility. This article covers that scenario. If you are running containers on managed infrastructure, focus your hardening effort on container images, runtime security, and network policies instead.

**When boot hardening still matters:** Compliance frameworks (PCI DSS, NIST 800-53) require boot integrity controls regardless of deployment model. If you are audited, you need to demonstrate that either you have implemented boot hardening (bare metal/VMs) or your provider handles it (managed infrastructure with documentation of their controls).
