---
title: "LUKS Disk Encryption with TPM2 Sealing: Measured Boot and Network-Bound Unlock"
description: "Sealing LUKS keys to TPM2 PCRs means the disk only unlocks on hardware in the expected boot state. Clevis and tang add network-bound decryption for server fleets without manual passphrase entry."
slug: "luks-tpm2-sealing"
date: 2026-04-30
lastmod: 2026-04-30
category: "linux"
tags: ["luks", "tpm2", "disk-encryption", "clevis", "tang"]
personas: ["security-engineer", "platform-engineer", "systems-engineer"]
article_number: 247
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/linux/luks-tpm2-sealing/index.html"
---

# LUKS Disk Encryption with TPM2 Sealing: Measured Boot and Network-Bound Disk Encryption

## Problem

LUKS (Linux Unified Key Setup) encrypts block devices at rest. Without key management, LUKS is often deployed with a static passphrase that must be entered at boot — impractical for server fleets — or with a keyfile stored on the same disk, which defeats the purpose.

The structural gap: a stolen disk with a static passphrase or an unprotected keyfile can be decrypted offline by an attacker with physical access. Cloud instances with unencrypted root volumes expose all data if the underlying storage is accessed by the cloud provider, a hypervisor vulnerability, or a physical disk extraction.

Two complementary solutions address this:

- **TPM2 sealing:** The LUKS decryption key is sealed to the system's TPM and bound to specific PCR values (firmware measurements, secure boot state, kernel cmdline). The TPM releases the key only if the measured boot state matches the sealed policy. A disk moved to a different machine, or booted with a modified kernel, will not have the key released.
- **Network-bound disk encryption (NBDE) with clevis/tang:** The LUKS key is derived from a response from a tang server on the internal network. Encryption is transparent at boot as long as the server can reach tang. A stolen disk cannot decrypt without tang access. Tang holds no secret — it performs a one-way cryptographic operation (McEliece/ECIES) that requires the disk's embedded key fragment plus tang's response.

The specific gaps in unmanaged deployments:

- Root volumes unencrypted on cloud VMs; snapshot or disk-export = plaintext data.
- LUKS with static passphrase stored in the IPMI/BMC console; accessible to anyone with BMC access.
- Keyfiles stored in `/boot` unencrypted; if `/boot` is unencrypted, the keyfile is accessible.
- No measurement of boot state; a tampered kernel still unlocks the disk.
- Manual passphrase entry required on reboot; fleet operators skip encryption to avoid operational burden.

**Target systems:** Linux kernel 5.17+ (TPM2 PCR policy with `systemd-cryptenroll`); systemd 251+ (`systemd-cryptsetup` with TPM2 support); clevis 18+ and tang 14+ (NBDE); RHEL 9, Ubuntu 22.04+.

## Threat Model

- **Adversary 1 — Physical disk extraction:** An attacker removes the disk from a server (physically or via cloud snapshot). Without encryption, all data is immediately accessible. With LUKS+TPM sealing, the disk cannot be decrypted without the TPM that sealed the key — and the TPM requires the correct boot state.
- **Adversary 2 — Cold boot attack:** A system is powered off and the disk is cloned before the RAM state dissipates. Without encryption, the attacker analyses the disk directly. With LUKS, the disk contents are ciphertext without the key.
- **Adversary 3 — Tampered boot chain:** An attacker modifies the kernel or initramfs to include a backdoor, expecting the disk to auto-unlock. TPM PCR binding includes PCR4 (bootloader) and PCR9 (initramfs); a modified initramfs changes the PCR values, causing the TPM to refuse to release the key.
- **Adversary 4 — Tang server compromise:** An attacker compromises the tang server on the internal network. Tang holds no client secrets — only its own key pair. Compromise allows an attacker to decrypt a stolen disk only if they also have the disk's embedded key fragment. Tang key rotation limits the window.
- **Adversary 5 — Replay attack against tang:** An attacker captures a valid tang response and replays it to unlock a disk. Tang's protocol (José/JWK) is replay-resistant; each unlock uses a fresh ephemeral key exchange.
- **Access level:** Adversary 1 has physical or hypervisor-level access. Adversary 2 has physical access during power-off window. Adversary 3 has bootloader write access. Adversary 4 has network access to tang. Adversary 5 has network MITM capability.
- **Objective:** Decrypt disk contents offline, access sensitive data after hardware theft, persist through reboots with modified bootloader.
- **Blast radius:** Unencrypted disk: all data immediately accessible. LUKS+TPM sealing: disk is encrypted; key requires the specific TPM in the correct boot state to release. LUKS+tang: disk is encrypted; key requires tang server access on the internal network.

## Configuration

### Step 1: Set Up LUKS on the Root Partition

For new systems, encrypt during OS installation. For existing systems, `cryptsetup-reencrypt` performs in-place re-encryption:

```bash
# Check LUKS status on an existing volume.
cryptsetup status /dev/mapper/root
cryptsetup luksDump /dev/sda2

# In-place encryption of an existing unencrypted partition (requires backup first).
cryptsetup reencrypt --encrypt --reduce-device-size 32S /dev/sda2

# Or: standard LUKS2 format on a new partition.
cryptsetup luksFormat \
  --type luks2 \
  --cipher aes-xts-plain64 \
  --key-size 512 \
  --hash sha256 \
  --pbkdf argon2id \
  /dev/sda2
```

LUKS2 with Argon2id key derivation is the current best practice (LUKS1 used PBKDF2 which is GPU-acceleratable).

### Step 2: Enroll a TPM2 Key with systemd-cryptenroll

`systemd-cryptenroll` manages LUKS2 keyslots and integrates with the TPM2 via the kernel's TPM stack:

```bash
# List current keyslots.
systemd-cryptenroll /dev/sda2 --list

# Enroll a TPM2 key bound to PCRs 0, 2, 4, 7, 9.
systemd-cryptenroll /dev/sda2 \
  --tpm2-device=auto \
  --tpm2-pcrs="0+2+4+7+9"

# PCR meanings:
# 0  = Core root of trust (UEFI firmware)
# 2  = Extended or pluggable executable code
# 4  = Boot loader code and configuration
# 7  = Secure boot state
# 9  = Grub configuration / kernel cmdline (if using systemd-boot)
```

The `--tpm2-pcrs` selection is the key policy decision:

| PCR set | Protects against | Risk |
|---------|-----------------|------|
| `7` only | Secure boot bypass | Allows kernel/initramfs changes as long as secure boot is on |
| `0+7` | Firmware + secure boot | Moderate; firmware updates break the seal |
| `0+2+4+7+9` | Firmware + bootloader + secure boot + cmdline | Strict; any boot change requires re-sealing |
| `0+4+7` | Common balanced choice | Firmware updates break; kernel updates don't (if PCR9 excluded) |

After enrollment, verify the TPM2 keyslot was created:

```bash
cryptsetup luksDump /dev/sda2 | grep -A5 "Token "
# Should show a systemd-tpm2 token in keyslot.
```

### Step 3: Configure /etc/crypttab for Automatic Unlock

```bash
# /etc/crypttab
# <name>        <device>    <keyfile>  <options>
root-crypt      /dev/sda2   none       tpm2-device=auto,tpm2-pcrs=0+2+4+7+9

# The "none" keyfile means: use the TPM2 token automatically.
# At boot, systemd-cryptsetup queries the TPM; if PCRs match, LUKS opens.
```

Update initramfs to include the TPM2 tools:

```bash
# Debian/Ubuntu.
apt install tpm2-tools clevis-luks clevis-initramfs
update-initramfs -u -k all

# RHEL/Fedora.
dnf install tpm2-tools clevis-luks clevis-dracut
dracut --force
```

### Step 4: Network-Bound Disk Encryption with Tang (Server Fleets)

TPM sealing requires each machine to have a TPM and bind to its specific hardware. For homogeneous server fleets where hardware replacement is common, NBDE with clevis/tang is more operationally flexible.

**Set up tang server (on a dedicated, highly available internal host):**

```bash
# Install tang.
apt install tang

# Start tang service.
systemctl enable --now tangd.socket

# Display tang server thumbprint (used when binding clients).
tang-show-keys
# Output: <base64url-thumbprint>

# Tang keys are in /var/db/tang/.
# Rotate keys periodically (old keys can be archived for decryption of old disks).
tangd-keygen /var/db/tang/ rotate
```

Tang should run on at least two servers in separate AZs; clients bind to both.

**Bind a LUKS volume to tang:**

```bash
# Install clevis.
apt install clevis-luks clevis-initramfs

# Bind LUKS to a tang server.
clevis luks bind -d /dev/sda2 tang \
  '{"url":"http://tang.internal:7500","thp":"<tang-thumbprint>"}'

# Bind to a second tang server for HA (clevis SSS — secret sharing).
# The disk unlocks if either tang server is available.
clevis luks bind -d /dev/sda2 sss \
  '{
    "t": 1,
    "pins": {
      "tang": [
        {"url":"http://tang1.internal:7500","thp":"<tang1-thumbprint>"},
        {"url":"http://tang2.internal:7500","thp":"<tang2-thumbprint>"}
      ]
    }
  }'

# Update initramfs to include clevis.
update-initramfs -u -k all
```

**Combine TPM2 and tang for defence in depth:**

```bash
# Unlock if EITHER TPM PCRs match OR tang responds (SSS with t=1).
clevis luks bind -d /dev/sda2 sss \
  '{
    "t": 1,
    "pins": {
      "tpm2": {"pcr_ids":"0,2,4,7"},
      "tang": {"url":"http://tang.internal:7500","thp":"<thumbprint>"}
    }
  }'
```

This policy: the disk unlocks automatically at boot if the TPM measurement matches (bare-metal, trusted boot chain) OR if tang is reachable (cloud instance in trusted network). If the server is stolen and booted outside the network, neither condition is met.

### Step 5: PCR Policy Updates After Kernel Upgrades

When the kernel or bootloader is updated, PCR values change. The TPM will refuse to release the old sealed key. Before updating, re-seal the key to the new expected PCR values:

```bash
# Predict new PCR values after a kernel update (systemd 253+).
systemd-pcrlock predict --pcr=4,9

# Re-enroll with predicted values before rebooting into the new kernel.
systemd-cryptenroll /dev/sda2 \
  --wipe-slot=tpm2 \
  --tpm2-device=auto \
  --tpm2-pcrs="0+4+7+9" \
  --tpm2-with-pin=no

# Alternatively: use systemd-pcrlock to create a signed policy that
# pre-authorises specific future PCR states.
systemd-pcrlock make-policy \
  --pcr=7+11+12+13+14+15 \
  --certificate=/etc/pcrlock/tpm2-key.crt \
  --private-key=/etc/pcrlock/tpm2-key.key
```

Automate pre-sealing as part of the package upgrade hook:

```bash
# /etc/kernel/postinst.d/00-reseal-tpm
#!/bin/bash
set -e
NEW_VERSION="$1"
echo "Re-sealing TPM key for kernel $NEW_VERSION"
systemd-cryptenroll /dev/sda2 --wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrs="0+4+7"
```

### Step 6: Recovery Key Management

Always keep a recovery keyslot for emergency access (hardware failure, TPM reset, tang server outage):

```bash
# Add a recovery passphrase keyslot.
systemd-cryptenroll /dev/sda2 --password

# Or generate a recovery key (random, high-entropy).
systemd-cryptenroll /dev/sda2 --recovery-key
# Output: recovery key (store in a secrets manager, not on the system).

# Store the recovery key in Vault.
vault kv put secret/recovery/$(hostname)/luks \
  recovery_key="$(systemd-cryptenroll /dev/sda2 --recovery-key 2>&1 | grep 'Recovery key')"
```

For clevis-bound volumes, the recovery passphrase allows manual unlock when tang is unreachable and the TPM doesn't match:

```bash
# Emergency manual unlock.
cryptsetup luksOpen /dev/sda2 root-crypt
# Enter recovery passphrase when prompted.
```

### Step 7: Verify the Configuration

```bash
# Confirm TPM2 token is present.
cryptsetup luksDump /dev/sda2 | grep -i tpm

# Test unlock without rebooting (using the TPM token directly).
systemd-cryptsetup attach root-crypt /dev/sda2 - tpm2-device=auto

# Verify the disk unlocks at boot by checking the current PCR state matches policy.
tpm2_policypcr -Q -l sha256:0,2,4,7,9 -L /tmp/expected.pcr
# Compare with: tpm2_readpcr -g sha256 -l 0,2,4,7,9

# For tang-bound volumes: test clevis unlock.
clevis luks unlock -d /dev/sda2
```

### Step 8: Telemetry

```
luks_volume_encrypted_total{host}                        gauge
luks_tpm2_unlock_success_total{host}                     counter
luks_tpm2_unlock_failure_total{host, reason}             counter
luks_tang_unlock_success_total{host, tang_server}        counter
luks_tang_unlock_failure_total{host, tang_server}        counter
tang_server_up{instance}                                 gauge
luks_recovery_key_used_total{host}                       counter
```

Alert on:

- `luks_tpm2_unlock_failure_total` non-zero — TPM seal broken; PCR mismatch suggests unexpected boot change; investigate the host.
- `luks_tang_unlock_failure_total` — tang server unreachable; check network connectivity and tang server health.
- `luks_recovery_key_used_total` non-zero — a recovery key was used to unlock a disk; requires explanation and audit.
- `tang_server_up` == 0 — tang server down; NBDE clients cannot auto-unlock on reboot until restored.

## Expected Behaviour

| Signal | No encryption | LUKS only (passphrase) | LUKS + TPM2 sealing | LUKS + tang NBDE |
|--------|--------------|----------------------|---------------------|-----------------|
| Stolen disk | All data readable | Brute-force passphrase | Disk unusable without the sealing TPM | Disk unusable without tang access |
| Modified boot chain | N/A | Unlocks normally | TPM refuses to release key (PCR mismatch) | Unlocks normally (tang doesn't check boot state) |
| Server reboot (unattended) | No action needed | Requires passphrase entry | Fully automatic | Fully automatic if tang reachable |
| Firmware update | N/A | No impact | Re-seal required before reboot | No impact |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| TPM PCR sealing | Disk tied to specific hardware + boot state | Kernel/firmware updates require re-sealing | Automate re-sealing in package post-install hooks; use `systemd-pcrlock`. |
| Tang NBDE | No per-machine binding; works for fleet rotation | Tang server is a network dependency at boot | Run tang on 2+ servers across AZs; SSS policy allows either to succeed. |
| Combined TPM + tang | Two independent unlock paths | Increased complexity | SSS t=1 means either path suffices; complexity is in setup, not operation. |
| LUKS2 with Argon2id | GPU-resistant key derivation | Slower passphrase unlock (~2s vs <0.5s for PBKDF2) | Irrelevant for automated unlock (TPM/tang); only affects manual passphrase entry. |
| Recovery key in Vault | Emergency access preserved | Recovery key is a secret requiring Vault access | Vault HA; store recovery key print in a physical safe as last resort. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| PCR mismatch after kernel update | System boots to initramfs rescue shell; LUKS won't open | Boot failure; console shows TPM seal error | Boot from recovery media; enter recovery passphrase; re-seal to new PCRs. |
| Tang server unreachable at boot | System waits for tang; eventually falls back to passphrase | Boot timeout; clevis error in journal | Restore tang server; or enter recovery passphrase manually to boot. |
| TPM reset or replacement | TPM2 keyslot unusable; disk won't auto-unlock | `luks_tpm2_unlock_failure_total` alert | Re-enroll TPM2 keyslot with the new TPM (requires recovery passphrase first). |
| Tang key rotation breaks existing bindings | NBDE unlock fails; clevis cannot derive LUKS key | `luks_tang_unlock_failure_total` alert | Keep old tang key online during transition; rebind all clients before retiring old key. |
| Recovery key not stored before disaster | System unbootable; no way to recover LUKS | Data loss | Enforce recovery key storage in Vault as part of provisioning automation. |
| initramfs missing clevis/tpm2 tools | System boots without LUKS auto-unlock; falls back to passphrase | Manual passphrase required at boot | Regenerate initramfs with correct packages; `update-initramfs -u`. |

## Related Articles

- [Linux IMA/EVM: Kernel-Level File Integrity Measurement](/articles/linux/linux-ima-evm/)
- [dm-verity: Block-Level Integrity for Read-Only Partitions](/articles/linux/dm-verity/)
- [GRUB Boot Hardening](/articles/linux/grub-boot-hardening/)
- [Kernel Lockdown and Module Hardening](/articles/linux/kernel-lockdown/)
- [Hardware Security Module Integration](/articles/cross-cutting/hsm-key-management/)
