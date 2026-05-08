---
title: "UEFI Secure Boot Deep Dive: DB/DBX, Shim, MOK, and Custom Key Enrolment"
description: "Master the UEFI Secure Boot trust chain from firmware key databases through shim and MOK to the kernel. Learn to inspect DB/DBX, enrol custom keys, remove Microsoft CA, detect bypasses, and understand BootGuard and firmware update signing."
slug: linux-uefi-secure-boot-db
date: 2026-05-07
lastmod: 2026-05-07
category: linux
tags:
  - secure-boot
  - uefi
  - firmware-security
  - shim
  - mok
personas:
  - security-engineer
  - platform-engineer
article_number: 476
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/linux/linux-uefi-secure-boot-db/
---

# UEFI Secure Boot Deep Dive: DB/DBX, Shim, MOK, and Custom Key Enrolment

## The Problem

Most Linux servers run with Secure Boot "enabled" in a superficial sense: the firmware checks for a valid signature on the bootloader, finds it signed by Microsoft's third-party CA, and proceeds. But that framing hides several layers of problems.

**Microsoft's CA is in your trust chain.** The firmware trusts the bootloader because it trusts a certificate issued by Microsoft. Every distribution's shim binary is signed by Microsoft. If Microsoft's signing infrastructure were compromised — or if Microsoft signed a malicious shim under legal or regulatory pressure — your "Secure Boot" would chain-of-trust its way to executing attacker-controlled code. This is not hypothetical: the Secure Boot ecosystem saw exactly this class of issue with BootHole (CVE-2020-10713), where a bug in GRUB's configuration parser could be exploited via a legitimately signed GRUB binary, requiring Microsoft to push DBX revocations across the fleet.

**The shim-MOK extension expands the attack surface.** Shim adds a Machine Owner Key database that is user-manageable from inside Linux. MOK was designed for kernel module signing and out-of-tree drivers. In practice, MOK keys enrolled by package managers or administrators often have no expiry and grant the same trust as DB keys for purposes of bootloader chain verification. An attacker who achieves root once can enrol a malicious MOK key that persists across reinstalls.

**UEFI variables are writable from the OS.** On most systems in Setup Mode or before a Platform Key is enrolled, UEFI authenticated variables can be modified by root without any out-of-band confirmation. Even with a PK enrolled, the variable update protocol is complex enough that implementation bugs have allowed bypass. LogoFAIL (2023) demonstrated that parsers for UEFI logo images — loaded before any signature check — contained exploitable vulnerabilities in dozens of firmwares.

**Measured boot and verified boot are distinct.** Many engineers treat "TPM PCR values are set" as equivalent to "the system is secure." Measured boot records what was loaded; it does not prevent loading. Only verified boot (with enforcement) prevents execution of unsigned code. The gap between "we measure things" and "we refuse to boot unsigned things" is where most production systems live.

This article covers the full trust chain at the firmware and bootloader layer: what lives in DB and DBX, how shim and MOK work, how to replace the Microsoft CA with your own keys, how Intel Boot Guard ties firmware signing to hardware fuses, how firmware updates are signed and verified, and how to detect when any of this has been subverted.

**Target systems:** x86_64 systems with UEFI firmware; Ubuntu 22.04+/24.04+, Fedora 38+, RHEL 9+, Debian 12+.

## The UEFI Secure Boot Trust Chain

The chain from power-on to userspace has eight distinct links, each of which can be subverted independently.

```
[CPU reset vector]
       ↓
[UEFI firmware] — verified by Intel Boot Guard (if enabled) against BootGuard ACM
       ↓
[UEFI DB] — PK → KEK → DB: firmware verifies shim.efi against DB
       ↓
[shim.efi] — signed by Microsoft 3rd Party UEFI CA; verifies next stage against DB or MOK
       ↓
[grub.efi / systemd-boot.efi] — signed by distro key (in DB or trusted by shim)
       ↓
[kernel (vmlinuz)] — signed; verified by GRUB or directly by shim/firmware
       ↓
[initramfs] — NOT verified by UEFI; only by UKI embedding or IMA
       ↓
[userspace]
```

Subversion opportunities:

- **Firmware level:** UEFI rootkits (e.g., CosmicStrand, BlackLotus) install at firmware level or in the UEFI System Partition to survive OS reinstall. Boot Guard addresses this if provisioned.
- **DB/DBX level:** Enrolling a malicious key into DB, or failing to push DBX revocations, allows a signed-but-revoked bootloader to execute.
- **Shim level:** A vulnerability in shim's parsing code (BootHole affected shim's trust delegation to GRUB) can allow bypass before the kernel boots.
- **MOK level:** An attacker who achieves root can enrol a persistent MOK key, making future malicious binaries trusted.
- **Kernel level:** An unsigned or incorrectly signed kernel is the most common configuration error; many distros default to trusting distro keys that include both DB and MOK paths.
- **Initramfs level:** Without UKI, the initramfs is not covered by any UEFI signature. See the UKI article for the mitigation.

## UEFI DB and DBX: The Key Databases

The UEFI firmware maintains four authenticated variables that constitute the Secure Boot key hierarchy:

| Variable | Purpose |
|----------|---------|
| PK (Platform Key) | Single key owned by the platform/OEM; authorises KEK updates |
| KEK (Key Exchange Key) | Authorises updates to DB and DBX |
| DB (Signature Database) | Allowed signatures and hashes; firmware accepts EFI binaries matching these |
| DBX (Forbidden Signature Database) | Revoked signatures and hashes; firmware rejects EFI binaries matching these |

A system in **Setup Mode** has no PK enrolled — any authenticated variable can be written without signature verification. A system in **User Mode** has a PK enrolled and all subsequent updates to KEK, DB, and DBX must be signed by the appropriate key.

### Inspecting DB and DBX

```bash
# Install efitools
apt install efitools
# or
dnf install efitools

# Read current DB contents (allowed signatures)
efi-readvar -v db

# Read DBX (revoked signatures/hashes)
efi-readvar -v dbx

# Read KEK
efi-readvar -v KEK

# Read PK
efi-readvar -v PK

# Check Secure Boot state and mode
bootctl status | grep -E 'Secure Boot|Setup Mode'

# Alternative: mokutil for a quick human-readable summary
mokutil --sb-state
```

The DB on a typical Ubuntu or Fedora system contains:
- **Microsoft Corporation UEFI CA 2011** — signs third-party EFI binaries (including distro shims)
- **Microsoft Windows Production PCA 2011** — signs Windows bootloaders
- Optionally, a distribution-specific key (Canonical, Red Hat)

The DBX is a growing list of SHA-256 hashes of revoked bootloader binaries. Microsoft publishes periodic DBX updates via Windows Update and via `https://uefi.org/revocationlistfile`. A system with an outdated DBX may boot a shim or GRUB binary known to be exploitable.

### Checking and Updating DBX

```bash
# Download the latest UEFI revocation list
curl -O https://uefi.org/revocationlistfile

# Inspect the current DBX size (number of entries)
efi-readvar -v dbx | grep -c 'sha256'

# Apply a DBX update (requires authenticated variable write permission)
# Usually handled by fwupd — see firmware update section
fwupdmgr refresh
fwupdmgr update

# Manual DBX update with efi-updatevar (requires KEK private key)
efi-updatevar -a -f dbx_update.auth dbx
```

DBX updates are the primary mechanism for Secure Boot revocation. Without prompt DBX updates, a compromised or vulnerable signed binary remains executable on the system even after the compromise is publicly known.

## Shim and MOK

### How Shim Works

Shim is a minimal EFI binary signed by Microsoft's third-party CA. Its job is to perform a second stage of signature verification using keys that the Linux distribution manages independently of Microsoft:

1. Firmware loads `shim.efi`, verifying it against DB (finds the Microsoft CA).
2. Shim loads `MokManager.efi` or `grub.efi`, verifying the next stage against: DB (firmware's database), MOK (Machine Owner Key database stored in a UEFI variable), and the shim vendor certificate (compiled into shim at build time).
3. GRUB or systemd-boot then loads the kernel, which is again verified.

### MOK Enrolment Workflow

The Machine Owner Key database allows administrators to enrol custom signing keys without modifying the firmware-level DB. This is the intended path for out-of-tree kernel modules (e.g., proprietary GPU drivers, VirtualBox modules).

```bash
# Generate a MOK key pair
openssl req -new -x509 -newkey rsa:4096 \
  -keyout /etc/pki/mok/mok.key \
  -out /etc/pki/mok/mok.crt \
  -days 3650 \
  -subj "/CN=Local MOK Key $(hostname)/" \
  -nodes

# Convert to DER format for enrolment
openssl x509 -in /etc/pki/mok/mok.crt \
  -outform DER \
  -out /etc/pki/mok/mok.der

# Request enrolment — this queues the key for next-boot confirmation
mokutil --import /etc/pki/mok/mok.der
# You will be prompted to set a one-time password used at next boot

# At next boot, the MokManager EFI application presents the key for confirmation.
# The administrator must physically confirm (or have console access) and enter the password.

# After enrolment, verify the key is present
mokutil --list-enrolled
```

The physical confirmation step is Secure Boot's defence against a remote attacker enrolling a MOK key via a root shell. Without it, MOK enrolment would be trivially abused to make any binary trusted.

### MOK as a Bypass Risk

The MOK database significantly weakens the Secure Boot guarantees for production servers. Key risks:

- **Persistent access:** A root-level attacker can queue a MOK enrolment. If the server reboots unattended (e.g., after a kernel panic), and no human is monitoring the console, MokManager may auto-enrol or the timeout may default to confirming the enrolment depending on firmware and shim configuration.
- **No expiry enforcement:** MOK keys have no built-in expiry mechanism. Keys enrolled for driver signing often persist for years.
- **Broad trust scope:** A MOK key enrolled for module signing is also trusted by shim for EFI binary verification on some distributions.

For production servers where no out-of-tree kernel modules are needed, consider disabling MOK entirely:

```bash
# Disable MOK processing in shim (requires shim recompilation or vendor option)
# On supported systems, instruct mokutil to disable MOK
mokutil --disable-validation

# Verify MOK validation status
mokutil --sb-state
```

For environments requiring the tightest guarantees, replace shim entirely with a custom PK/KEK/DB hierarchy — see the next section.

## Custom Secure Boot with Your Own Keys

Replacing the Microsoft CA from your trust chain eliminates an entire class of supply-chain risk. This is the right choice for air-gapped systems, high-assurance servers, and any environment that can control every binary that boots.

### Generating PK, KEK, and DB Keys

```bash
# Working directory for key material
mkdir -p /etc/secureboot/keys
cd /etc/secureboot/keys

# Generate a GUID for this platform
GUID=$(python3 -c 'import uuid; print(uuid.uuid4())')
echo "$GUID" > platform_guid.txt

# Platform Key (PK) — one key, kept offline after enrolment
openssl req -new -x509 -newkey rsa:4096 \
  -keyout PK.key -out PK.crt \
  -days 7300 -subj "/CN=Platform Key $(hostname)/" -nodes

# Key Exchange Key (KEK) — authorises DB/DBX updates
openssl req -new -x509 -newkey rsa:4096 \
  -keyout KEK.key -out KEK.crt \
  -days 7300 -subj "/CN=Key Exchange Key $(hostname)/" -nodes

# DB key — used to sign EFI binaries
openssl req -new -x509 -newkey rsa:4096 \
  -keyout DB.key -out DB.crt \
  -days 3650 -subj "/CN=Secure Boot DB $(hostname)/" -nodes

# Convert to DER
for k in PK KEK DB; do
  openssl x509 -in ${k}.crt -outform DER -out ${k}.der
done
```

### Creating Authenticated Variable Payloads

UEFI authenticated variables require the new value to be signed by the authorising key. The `efitools` package provides `sign-efi-sig-list` for this:

```bash
# Convert certificates to EFI signature lists
cert-to-efi-sig-list -g "$GUID" PK.crt PK.esl
cert-to-efi-sig-list -g "$GUID" KEK.crt KEK.esl
cert-to-efi-sig-list -g "$GUID" DB.crt DB.esl

# Sign the KEK list with PK (KEK update must be signed by PK)
sign-efi-sig-list -g "$GUID" -k PK.key -c PK.crt KEK KEK.esl KEK.auth

# Sign the DB list with KEK (DB update must be signed by KEK)
sign-efi-sig-list -g "$GUID" -k KEK.key -c KEK.crt db DB.esl DB.auth

# Sign the PK with itself (self-signed; transitions system from Setup to User Mode)
sign-efi-sig-list -g "$GUID" -k PK.key -c PK.crt PK PK.esl PK.auth
```

### Enrolling Keys

**Method 1: efi-updatevar (requires Setup Mode or existing key authority)**

```bash
# System must be in Setup Mode (no PK enrolled) for this method
# Or you must present the existing authorising key

# Enrol DB first (before PK, while still in Setup Mode)
efi-updatevar -e -f DB.auth db

# Enrol KEK
efi-updatevar -e -f KEK.auth KEK

# Enrol PK last — this exits Setup Mode; no further unauthenticated writes
efi-updatevar -f PK.auth PK

# Verify
efi-readvar -v PK
efi-readvar -v KEK
efi-readvar -v db
```

**Method 2: KeyTool EFI application (interactive, at firmware level)**

`efitools` ships a `KeyTool.efi` binary that runs as a UEFI application. Copy it to the ESP and boot it directly from the firmware's boot menu. This approach works even if the Linux kernel cannot write UEFI variables (some firmwares lock variable access in User Mode).

**Method 3: sbctl (recommended for desktop/workstation)**

`sbctl` provides a higher-level interface and integrates with `systemd-boot`:

```bash
apt install sbctl
# or
dnf install sbctl

# Create keys (stored in /usr/share/secureboot/keys/)
sbctl create-keys

# Enrol keys (--microsoft to also include Microsoft CA; omit for full custom)
sbctl enroll-keys
# WARNING: omitting --microsoft removes the Microsoft CA from DB.
# Only do this if you can sign every binary that boots on this system.

# Verify enrolment status
sbctl status

# Sign your bootloader and kernel
sbctl sign /boot/efi/EFI/BOOT/BOOTX64.EFI
sbctl sign /boot/efi/EFI/ubuntu/shimx64.efi
sbctl sign /boot/vmlinuz-6.8.0-51-generic

# List all signed files (sbctl maintains a database for re-signing after updates)
sbctl list-files
```

### Signing Binaries with the DB Key

Every EFI binary in the boot path must be signed with the DB key:

```bash
# Sign with sbsign (from sbsigntool)
sbsign --key DB.key --cert DB.crt \
  --output /boot/efi/EFI/ubuntu/grubx64.efi.signed \
  /boot/efi/EFI/ubuntu/grubx64.efi

# Verify a signature
sbverify --cert DB.crt /boot/efi/EFI/ubuntu/grubx64.efi.signed

# Check what certificate signed an EFI binary
sbverify --list /boot/efi/EFI/ubuntu/shimx64.efi
```

Set up automatic re-signing on kernel updates using a pacman hook, dpkg trigger, or dracut plugin as appropriate for your distribution. Without this, a kernel update produces an unsigned binary that Secure Boot will reject on next boot.

## UEFI BootGuard and Intel Boot Guard

UEFI Secure Boot verifies software after the firmware is loaded. It says nothing about whether the firmware itself has been tampered with. Intel Boot Guard addresses the firmware layer.

### Verified Boot vs Measured Boot

**Intel Boot Guard Verified Boot:** The CPU's Authenticated Code Module (ACM) — immutable silicon-level code — verifies the Initial Boot Block (IBB, the first block of the UEFI firmware image) against a public key hash fused into non-volatile storage (eFUSEs). If the IBB hash doesn't match, the system halts. The fuse values are written at manufacturing time and are permanent.

**Intel Boot Guard Measured Boot:** The ACM measures the IBB and extends a TPM PCR (typically PCR0) with the result. This records what firmware ran but does not prevent unverified firmware from executing.

**The implication:** Verified Boot requires that the OEM provision the correct eFUSE values at manufacturing. A system without Boot Guard provisioned — or with Boot Guard in measurement-only mode — can have its firmware replaced by a UEFI rootkit that persists across OS reinstall, Secure Boot re-enrolment, and disk wipe.

```bash
# Check if Boot Guard is provisioned (requires MSR access)
# PCR0 value reflects the firmware measurement
tpm2_pcrread sha256:0

# A value of 0000...0000 indicates TPM has not been extended (Boot Guard not active or pre-boot)
# A non-zero value indicates a firmware measurement occurred

# Intel TXT / Boot Guard status via txt-stat (tboot package)
apt install tboot
txt-stat | grep -E 'BIOS|Boot Guard|IBB'

# Check firmware security properties via fwupdmgr
fwupdmgr security
# Look for: "UEFI Platform Key", "Intel Boot Guard", "BIOS Write Protect"
```

Boot Guard is provisioned by the OEM or ODM and cannot be enabled by the end user after manufacturing. When purchasing servers for high-assurance environments, explicitly verify Boot Guard provisioning status with the vendor.

## Firmware Update Security

Firmware updates are a privileged operation that can bypass all software-level security controls. A compromised firmware update delivers a UEFI rootkit that survives OS reinstall.

### fwupd and LVFS

The Linux Vendor Firmware Service (LVFS) is the distribution mechanism for firmware updates on Linux. `fwupd` is the client.

```bash
# Refresh metadata from LVFS
fwupdmgr refresh

# List devices with available updates
fwupdmgr get-updates

# Apply updates (downloads, verifies, stages for application at next boot)
fwupdmgr update

# Check security posture of all firmware components
fwupdmgr security --force

# Verify a specific firmware file before applying
fwupdmgr verify-update
```

Every firmware update distributed through LVFS is signed with the vendor's key, and `fwupd` verifies the signature and the metadata chain before staging the update. The metadata itself is signed with a key whose certificate is shipped with `fwupd`, preventing MITM substitution of a malicious firmware image for a legitimate one.

### Capsule Update Signing

UEFI firmware updates are distributed as UEFI Capsule files. A capsule contains the firmware image and an EFI signature. The UEFI firmware (not the OS) applies the capsule at next boot after the OS stages it to an EFI variable or EFI System Partition location.

```bash
# Inspect a firmware capsule (if you have one as a .cab file from LVFS)
# Extract the .cab
gcab -x firmware-update.cab

# View capsule metadata
fwupdtool get-details firmware.bin

# Verify the capsule signature chain manually
# LVFS uses a two-tier PKI: root CA → vendor signing certificate → firmware capsule
# The certificate chain is embedded in the .cab metadata
fwupdtool verify firmware.bin
```

The critical security property: `fwupd` checks the firmware hash against what LVFS reports before staging. An attacker who can modify the firmware file on disk between download and staging will have the hash check fail. The capsule itself carries an Authenticode-style signature verified by the UEFI firmware during application.

### High-Assurance Firmware Update Controls

For production environments:

```bash
# Lock firmware writes at the OS level via kernel sysctl
# This prevents direct UEFI variable writes (requires kernel 5.9+)
cat /sys/firmware/efi/efivars/

# Enable firmware write protection via fwupd policy
# /etc/fwupd/daemon.conf
grep -E 'OnlyTrusted|EnumerateAllDevices' /etc/fwupd/daemon.conf

# Audit firmware update history
journalctl -u fwupd --since "7 days ago" | grep -E 'update|apply|verify'
```

## UEFI Variable Security

UEFI authenticated variables underpin all Secure Boot configuration. Their security model has several subtleties that affect production systems.

### Setup Mode vs User Mode

```bash
# Check current mode
efi-readvar -v PK
# Empty output = Setup Mode (no PK, variable writes unrestricted)
# Non-empty = User Mode (PK enrolled, writes require authentication)

# Alternative
bootctl status | grep "Setup Mode"
# "Setup Mode: no" means User Mode (secure)
```

In Setup Mode, any process with root access can modify PK, KEK, DB, and DBX without presenting a signed payload. This is the intended mode during initial provisioning but represents a complete Secure Boot bypass if a system is left in this state.

### UEFI Variable Abuse from the OS

Even in User Mode, UEFI variables present attack surface:

```bash
# UEFI variables are exposed via efivars filesystem
ls /sys/firmware/efi/efivars/ | wc -l

# Boot order can be manipulated by root (no authentication required for BootOrder)
efibootmgr -v

# An attacker can add a boot entry pointing to a malicious EFI binary on removable media
# or on the ESP, then reorder to make it boot first — bypassing Secure Boot if the
# binary is on a path shim would verify, or if the firmware is in a permissive mode

# Restrict UEFI variable access at the kernel level (kernel lockdown integrity mode)
cat /sys/kernel/security/lockdown
# "integrity" or "confidentiality" mode restricts raw EFI variable writes
```

The kernel's `lockdown=integrity` mode (see the kernel lockdown article) prevents direct writes to EFI variables from userspace, requiring all updates to go through authenticated kernel interfaces. Combine lockdown with Secure Boot enforcement for defence in depth.

### Protecting Against Runtime Variable Attacks

```bash
# Enable kernel lockdown via boot parameter (or Secure Boot auto-activation)
# Add to kernel command line:
# lockdown=integrity

# On Secure Boot systems, lockdown=integrity is often auto-enabled
# Confirm:
cat /sys/kernel/security/lockdown
# Expected: [integrity] confidentiality  (integrity is active)

# Verify Secure Boot auto-triggers lockdown
dmesg | grep -i lockdown
# Expected: "lockdown: Secure Boot enabled; integrity locked down"
```

## Detecting Secure Boot Bypass

### Runtime Checks

```bash
# Primary status check
bootctl status
# Key fields: "Secure Boot: enabled (user)", "Setup Mode: no", "Measured UKI: yes"

# Kernel perspective
dmesg | grep -i "secure boot"
dmesg | grep -i "lockdown"
# Expected: "Secure Boot enabled", "UEFI Secure Boot in enabled"

# Check if the running kernel is Secure Boot aware
cat /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c | xxd
# Byte 4 (after 4-byte attributes header) = 1 means Secure Boot enabled

# Quick check via mokutil
mokutil --sb-state
# "SecureBoot enabled" = enforcement active
# "SecureBoot disabled" = not enforced

# Check MOK list for unexpected keys
mokutil --list-enrolled
```

### TPM Event Log Analysis

The TPM event log records every measurement made during boot. Comparing it to expected values detects modification of any measured component.

```bash
# Install tpm2-tools
apt install tpm2-tools

# Read TPM PCR values
tpm2_pcrread

# PCR0: firmware code (Boot Guard measurement)
# PCR1: firmware configuration / NVRAM
# PCR2: option ROM code
# PCR3: option ROM configuration
# PCR4: MBR / bootloader
# PCR5: partition table / GPT
# PCR7: Secure Boot state (DB, DBX, KEK, PK values and Secure Boot enabled status)

# Read the full event log
tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements

# PCR7 is the critical one for Secure Boot: it records all DB/DBX/KEK/PK changes
# and the Secure Boot enabled state at boot time
tpm2_pcrread sha256:7

# Check if the Secure Boot state matches expectation
# A value of 0000...0000 in PCR7 indicates Secure Boot was not measured
# (potential bypass or legacy BIOS mode)
```

### Detecting DBX Freshness

An outdated DBX is a known Secure Boot bypass vector:

```bash
# Count DBX entries
efi-readvar -v dbx | grep -c sha256

# Compare against UEFI.org published count
# As of early 2026, a properly updated DBX should have 200+ entries

# fwupdmgr reports DBX update status
fwupdmgr security | grep -i "dbx\|revocation"

# Check for BootHole-related GRUB revocations in DBX
# The BootHole patches added hashes for vulnerable GRUB binaries
efi-readvar -v dbx | grep -A2 "sha256" | head -40
```

### Checking for Suspicious MOK Entries

```bash
# List all enrolled MOK keys with details
mokutil --list-enrolled | grep -E 'Subject|Issuer|Valid|Fingerprint'

# Identify keys not from your distribution or your own PKI
# Red flags: unknown CNs, keys with no expiry, keys from unexpected organizations

# Check MokListTrusted — if enabled, MOK keys get DB-level trust
mokutil --list-trusted

# Detect if MOK validation has been disabled
mokutil --sb-state | grep -i "mok"
```

## BootHole and LogoFAIL: Recent UEFI CVEs

### BootHole (CVE-2020-10713 and Related)

BootHole was a family of vulnerabilities in GRUB2 allowing an attacker with access to `grub.cfg` (or `grubenv`) to exploit memory corruption bugs in GRUB's configuration and filesystem parsers — all of which execute after UEFI Secure Boot has verified the GRUB binary, but before the kernel loads.

The implication: a legitimately signed GRUB binary could be exploited to execute arbitrary code, bypassing Secure Boot entirely. The fix required:

1. Patching GRUB2
2. Revoking previously signed vulnerable GRUB binaries via DBX
3. Revoking vulnerable shim binaries
4. Coordinating distribution-level shim re-signing through Microsoft

The coordinated response took over a year and required DBX updates to be pushed to every Secure Boot system in the world. Systems that did not receive the DBX update remain vulnerable to an attacker with a pre-patch GRUB binary.

```bash
# Verify your GRUB version is post-BootHole
grub-install --version
# Patched versions: GRUB 2.06+ with distribution backports

# Check that BootHole-related hashes are in your DBX
# The vulnerable GRUB binaries have known SHA-256 hashes
# fwupdmgr applies the DBX update that includes them
fwupdmgr get-updates | grep -i "dbx\|revocation"
```

The primary mitigation beyond patching is migrating to Unified Kernel Images (UKIs), which embed the kernel command line in the signed binary and reduce GRUB's attack surface to nearly zero. The UKI article covers this migration.

### LogoFAIL (CVE-2023-40238 and Related)

LogoFAIL (disclosed December 2023) was a set of vulnerabilities in UEFI image parser code — specifically the parsers used to display OEM splash logos during POST. These parsers run before any Secure Boot verification and before any OS code executes.

The attack vector: a malicious image file placed on the EFI System Partition (no signature required for logo files) could exploit an overflow or logic bug in the BMP, JPEG, or GIF parser embedded in the firmware, achieving arbitrary code execution at firmware level. This code executes before the UEFI Secure Boot check, before Boot Guard (which only measures the IBB, not the logo parser), and before TPM measurements of the boot path.

Mitigations:

```bash
# Verify your firmware has been updated post-LogoFAIL
fwupdmgr get-updates
fwupdmgr security | grep -E 'BIOS|Firmware'

# Check CVE fix status for your firmware vendor
# Dell: DSN-2023-17, HP: HPSBHF03861, Lenovo: LEN-140336

# Reduce ESP exposure: limit who can write to the EFI System Partition
# The ESP is typically mounted at /boot/efi
systemctl list-units | grep "boot-efi"

# Restrict ESP write access (breaks automatic updates — evaluate trade-off)
mount -o remount,ro /boot/efi

# For automated environments: mount ESP read-only in /etc/fstab
# and only remount rw during kernel/bootloader updates
grep 'boot/efi' /etc/fstab
# Add: vfat  ro  (after testing that your update tooling handles it)
```

The structural defence against LogoFAIL-class attacks is Intel Boot Guard with Verified Boot provisioned — the IBB is measured against hardware-fused values before any firmware code runs, including logo parsers. If the firmware image is modified to include a malicious logo parser payload, the IBB hash changes, Boot Guard detects the mismatch, and the system halts.

## Summary

| Control | What It Protects | Required Action |
|---------|-----------------|-----------------|
| DB/DBX maintenance | Revoked bootloaders won't execute | Run `fwupdmgr update` regularly; verify DBX entry count |
| Custom PK/KEK/DB | Remove Microsoft CA from trust chain | Generate keys, enrol with `sbctl` or `efi-updatevar` |
| MOK hygiene | Prevent persistent attacker key enrolment | Audit `mokutil --list-enrolled`; disable MOK if not needed |
| Boot Guard (Verified) | Firmware-level rootkit prevention | Verify at hardware purchase; cannot be provisioned post-manufacture |
| fwupd/LVFS | Signed firmware updates only | Enable `fwupdmgr` as a regular maintenance step |
| Kernel lockdown=integrity | Restrict runtime UEFI variable writes | Add to kernel command line; verify via `/sys/kernel/security/lockdown` |
| TPM PCR7 monitoring | Detect Secure Boot state changes | Read PCR7 at baseline; alert on deviation |
| UKI migration | Remove GRUB attack surface (BootHole class) | See uki-secure-boot-hardening article |

The most common gap in production systems is the combination of an outdated DBX (no revocations applied) with MOK keys enrolled by automation that have never been audited. Fixing these two issues — keeping DBX current via `fwupdmgr` and auditing MOK contents quarterly — provides significant improvement without requiring any key hierarchy changes.

Full custom key enrolment (removing the Microsoft CA) is the right choice for new deployments and air-gapped systems, but carries an operational cost: every kernel update, every bootloader update, and every EFI tool that touches the ESP must be re-signed. Build this into the update pipeline from the start rather than retrofitting it.
