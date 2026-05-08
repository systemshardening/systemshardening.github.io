---
title: "Linux IMA/EVM: Kernel-Level File Integrity Measurement and Appraisal"
description: "IMA measures every executed file and mmap'd library at the kernel level. EVM protects extended attributes from tampering. Together they detect supply chain compromise before code runs."
slug: "linux-ima-evm"
date: 2026-04-29
lastmod: 2026-04-29
category: "linux"
tags: ["ima", "evm", "integrity", "kernel", "supply-chain"]
personas: ["security-engineer", "platform-engineer", "systems-engineer"]
article_number: 239
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/linux/linux-ima-evm/index.html"
---

# Linux IMA/EVM: Kernel-Level File Integrity Measurement and Appraisal

## Problem

dm-verity provides block-level integrity for read-only partitions — excellent for immutable root filesystems but inapplicable to writable data directories, dynamically installed packages, or systems where files legitimately change. AppArmor and SELinux control what a process can access but do not verify the content of the files it accesses.

The Integrity Measurement Architecture (IMA) fills this gap. It operates at the kernel level, measuring every file before execution or mmap, recording the hash in a tamper-evident log and optionally refusing to run files whose hash doesn't match a stored reference. The Extended Verification Module (EVM) protects IMA's stored metadata (security.ima xattr) against offline tampering by binding it to a kernel HMAC or asymmetric signature.

The combined threat IMA/EVM addresses: a supply chain attacker who replaces a binary on a writable filesystem between installation and execution. Without IMA, the replacement is invisible until the attacker's code runs. With IMA appraisal enabled, the kernel refuses to execute the modified binary — the hash doesn't match the stored measurement.

Specific gaps in systems without IMA/EVM:

- No kernel-enforced record of which files were executed during a run.
- A compromised package manager can replace binaries; there is no pre-exec check.
- TPM-based remote attestation (via PCR10) cannot include executed-file hashes without IMA populating them.
- Security audits rely on userspace integrity checkers (AIDE, Tripwire) that run periodically, not at exec time.

The IMA measurement log feeds directly into TPM PCR10, enabling remote attestation: a verifier can cryptographically confirm which files the system executed since boot.

**Target systems:** Linux kernel 5.12+ (IMA-modsig, appraisal with signatures); systems with TPM 2.0 for remote attestation; RHEL 9+, Ubuntu 22.04+ (IMA enabled in default kernel, disabled by default in policy).

## Threat Model

- **Adversary 1 — Supply chain binary replacement:** An attacker who compromises a package repository or build pipeline replaces a production binary. The system installs and runs it. Without IMA appraisal, execution proceeds silently.
- **Adversary 2 — Privileged persistence:** A root-privileged attacker replaces a system binary (e.g., `/usr/sbin/sshd`) with a backdoored version. The system continues to run the modified binary across reboots. IMA appraisal blocks the exec; the measurement log captures the event.
- **Adversary 3 — Offline filesystem tampering:** An attacker with physical or hypervisor-level access mounts the filesystem offline and modifies files. EVM's HMAC binding detects the modification at next boot when the kernel checks the xattr against the HMAC key sealed to the TPM.
- **Adversary 4 — xattr spoofing:** An attacker modifies `security.ima` to match the hash of a malicious binary. Without EVM, this succeeds. EVM's HMAC or RSA signature over the xattr and inode metadata detects the forgery.
- **Access level:** Adversary 1 has package repository write access. Adversaries 2 and 3 have root or physical access. Adversary 4 has root access on the target system.
- **Objective:** Execute unauthorized code, persist across reboots, evade detection.
- **Blast radius:** Without IMA/EVM, binary replacement is silent and persistent. With appraisal: unauthorized binaries are refused at exec time; the event is logged. Remote attestation allows external systems to verify the integrity state.

## Configuration

### Step 1: Verify Kernel Support

```bash
# Confirm IMA is compiled in.
grep -E 'CONFIG_IMA|CONFIG_EVM' /boot/config-$(uname -r)
# Expected: CONFIG_IMA=y, CONFIG_EVM=y, CONFIG_IMA_APPRAISE=y

# Check the current IMA policy.
cat /sys/kernel/security/ima/policy

# View the current measurement log (first 10 entries).
head -10 /sys/kernel/security/ima/ascii_runtime_measurements
# Format: PCR-index hash-algorithm:hash filename
```

If IMA is not compiled in, install the kernel package with IMA support (RHEL: default since 7; Ubuntu: enabled since 20.04 with `CONFIG_IMA=y`).

### Step 2: Boot Parameters

Enable IMA and EVM via kernel command line:

```bash
# /etc/default/grub
GRUB_CMDLINE_LINUX="... ima_policy=tcb ima_hash=sha256 evm=fix"

# Explanation:
# ima_policy=tcb   — "Trusted Computing Base" policy: measure all executables,
#                    kernel modules, and firmware.
# ima_hash=sha256  — Use SHA-256 for measurements (SHA-1 default is too weak).
# evm=fix          — Allow EVM HMACs to be calculated on first boot (setup mode).
#                    Change to evm=enforce after initial labeling.

sudo update-grub
sudo reboot
```

After reboot, confirm IMA is active:

```bash
cat /sys/kernel/security/ima/policy
# Should show the tcb policy rules.

wc -l /sys/kernel/security/ima/ascii_runtime_measurements
# Should show growing count of measurements.
```

### Step 3: Custom IMA Policy

The `tcb` built-in policy is a starting point. For production, write a custom policy that measures exactly what matters and avoids excessive measurement of high-frequency files:

```bash
# /etc/ima/ima-policy (loaded at boot via initramfs or directly)

# Don't measure pseudo-filesystems.
dont_measure fsmagic=0x9fa0      # proc
dont_measure fsmagic=0x62656572  # sysfs
dont_measure fsmagic=0x64626720  # debugfs
dont_measure fsmagic=0xabc5      # tmpfs
dont_measure fsmagic=0x1cd1      # devtmpfs
dont_measure fsmagic=0x72b6      # jffs2

# Don't measure files already protected by dm-verity.
dont_measure obj_type=dm_verity_t

# Measure all executables.
measure func=BPRM_CHECK mask=MAY_EXEC

# Measure kernel modules.
measure func=MODULE_CHECK

# Measure firmware.
measure func=FIRMWARE_CHECK

# Measure all mmap'd files (catches shared libraries).
measure func=MMAP_CHECK mask=MAY_EXEC

# Appraise executables: refuse to run if hash doesn't match stored xattr.
appraise func=BPRM_CHECK appraise_type=imasig

# Appraise kernel modules.
appraise func=MODULE_CHECK appraise_type=imasig

# Log all appraisal failures (don't enforce yet — use audit mode first).
# Change appraise to enforce after validating.
```

Load the custom policy:

```bash
# During initramfs (preferred): place policy file at /etc/ima/ima-policy
# and configure initramfs to load it before root is mounted.

# At runtime (for testing):
echo 0 > /sys/kernel/security/ima/policy
cat /etc/ima/ima-policy > /sys/kernel/security/ima/policy
# Note: runtime policy can only be appended, not replaced; reboot to reset.
```

### Step 4: Sign Files with IMA Signatures

IMA appraisal with `imasig` requires each file to have a valid IMA signature stored in its `security.ima` xattr. Sign using `evmctl`:

```bash
# Install ima-evm-utils.
apt install ima-evm-utils    # Debian/Ubuntu
dnf install ima-evm-utils    # RHEL/Fedora

# Generate a signing key pair (offline, air-gapped is ideal).
openssl genrsa -out ima-signing-key.pem 4096
openssl req -new -x509 -key ima-signing-key.pem \
  -out ima-signing-cert.pem -days 3650 \
  -subj "/CN=IMA Signing Key"

# Load the public key into the kernel's IMA keyring.
keyctl padd asymmetric "" %keyring:.ima < ima-signing-cert.pem

# Sign all executables on the system.
evmctl sign --imasig --key ima-signing-key.pem \
  --hashalgo sha256 \
  /usr/bin/bash

# Sign an entire directory tree.
find /usr/bin /usr/sbin /usr/lib -type f -executable \
  | xargs -P4 evmctl sign --imasig --key ima-signing-key.pem --hashalgo sha256

# Verify a signature.
evmctl verify --imasig /usr/bin/bash
# Output: /usr/bin/bash: verification is OK
```

Integrate signing into the package build pipeline:

```bash
# Post-install hook for RPM (spec file).
%post
find %{buildroot}/usr/bin %{buildroot}/usr/sbin -type f -executable \
  | xargs evmctl sign --imasig --key /etc/ima/signing-key.pem --hashalgo sha256
```

### Step 5: Configure EVM

EVM protects the `security.ima` xattr (and other security xattrs) against tampering. It uses either a kernel HMAC keyed from a TPM-sealed master key, or an RSA signature.

```bash
# Create the EVM HMAC master key (derive from TPM or use a kernel keyring key).
# Option A: Random key stored in kernel keyring.
keyctl add encrypted evm-key "new default 32" @u

# Option B: TPM-sealed key (requires TPM 2.0 and tpm2-tools).
tpm2_createprimary -C e -G rsa -c primary.ctx
tpm2_create -G hmac -u evm.pub -r evm.priv \
  -C primary.ctx \
  -L "pcr:sha256:0,7"   # Seal to PCRs 0 (firmware) and 7 (secure boot state).
tpm2_load -C primary.ctx -u evm.pub -r evm.priv -c evm.ctx
tpm2_evictcontrol -C o -c evm.ctx 0x81000001

# Enable EVM with the loaded key.
echo 1 > /sys/kernel/security/evm
```

Once EVM is enabled in enforce mode, any modification to `security.ima` or other security xattrs without the HMAC key causes the file to fail appraisal.

### Step 6: Remote Attestation via TPM PCR10

IMA extends TPM PCR10 with each file measurement. A remote verifier can request a TPM quote and verify the measurement log:

```bash
# On the attested system: generate a TPM quote covering PCR10.
tpm2_quote \
  --key-context attestation-key.ctx \
  --pcr-list sha256:10 \
  --message nonce.bin \
  --signature quote.sig \
  --pcrs quote.pcrs \
  --qualification nonce.bin

# Send quote.sig, quote.pcrs, and the IMA measurement log to the verifier.
scp quote.sig quote.pcrs /sys/kernel/security/ima/binary_runtime_measurements \
  verifier.internal:/var/attestation/$(hostname)/
```

On the verifier:

```bash
# Verify the TPM quote signature.
tpm2_checkquote \
  --public attestation-key.pub \
  --message nonce.bin \
  --signature quote.sig \
  --pcrs quote.pcrs \
  --qualification nonce.bin

# Replay the IMA log and verify PCR10 matches the quote.
ima-log-parser binary_runtime_measurements | verify_against_pcr10 quote.pcrs
```

If any measured file was tampered with since boot, the replayed log hash won't match PCR10 — the attestation fails.

### Step 7: Audit Mode Before Enforcement

Run IMA appraisal in audit mode before enforcing to identify unsigned files:

```bash
# Policy: appraise (log failures) but don't enforce (don't block exec).
appraise func=BPRM_CHECK appraise_type=imasig audit

# Watch kernel log for appraisal failures.
dmesg | grep -i "ima:"
# Output: ima: appraise integrity appraisal error: /usr/bin/some-binary
```

Audit mode reveals every file that would be blocked if enforcement were enabled. Use this to complete the signing corpus before switching to enforce.

### Step 8: Telemetry

```
ima_measurement_count                              gauge
ima_appraisal_failure_total{file, reason}          counter
ima_policy_violations_total                        counter
evm_appraisal_failure_total{file}                  counter
tpm_pcr10_extended_total                           counter
```

Alert on:

- `ima_appraisal_failure_total` non-zero in enforce mode — an unsigned or tampered file was executed (or attempted).
- `evm_appraisal_failure_total` non-zero — a security xattr was tampered with offline.
- Remote attestation failure — PCR10 mismatch; the system's execution history differs from the expected policy.

## Expected Behaviour

| Signal | Without IMA/EVM | With IMA/EVM enforce |
|--------|----------------|---------------------|
| Replaced binary executed | Runs silently | Blocked at exec; `EACCES` returned to caller |
| Tampered `security.ima` xattr | Not detected | EVM HMAC mismatch; file blocked |
| Remote attestation coverage | PCR0–7 only (firmware, secure boot) | PCR10 includes every executed file hash |
| Package backdoor detection | Next AIDE scan (hours/days later) | Exec blocked immediately; kernel log entry |
| Measurement log | None | Append-only log in `/sys/kernel/security/ima/` |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Appraisal enforcement | Pre-exec integrity check | All executables must be signed; unsigned binaries fail | Audit mode first; integrate signing into build pipeline before enforcing. |
| SHA-256 measurements | Collision-resistant | ~5% performance overhead on exec-heavy workloads | Acceptable for most workloads; exclude high-frequency pseudo-files from policy. |
| EVM HMAC key in TPM | Key survives reboot but not physical extraction | TPM setup complexity | Use TPM2 tools; seal to PCRs for measured boot integration. |
| Custom policy | Precise coverage | Policy mistakes block legitimate binaries | Test in VM; use audit mode; keep a recovery console path unsigned (or separately signed). |
| Remote attestation | Cryptographic proof of execution history | Requires attestation infrastructure | Start with local audit log; add remote attestation as a second phase. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| File not signed before enforce mode | Binary fails to execute; application crashes | `ima: appraisal error` in dmesg; app error | Boot with `ima_appraise=fix` to allow re-signing; sign the file; re-enable enforce. |
| EVM key not loaded at boot | All appraisals fail; system may be unbootable | Early boot errors; `evm: HMAC data not found` | Boot from rescue media; load key; fix initramfs to load key before root mount. |
| TPM PCR10 mismatch in attestation | Attestation server rejects the host | Attestation logs show PCR mismatch | Investigate IMA log for unexpected measurements; identify the added/changed file. |
| Package update invalidates signatures | Updated binary fails appraisal | Post-update appraisal errors | Re-sign updated files as part of package post-install hook. |
| Policy too broad: measures tmpfs | Performance degradation; log fills fast | High `ima_measurement_count`; IO load spike | Add `dont_measure fsmagic=0xabc5` (tmpfs) to policy. |
| IMA xattr lost after filesystem repair | Files lose `security.ima`; fail appraisal | Widespread appraisal failures after fsck | Re-sign all files; document that fsck may clear xattrs. |

## Related Articles

- [dm-verity: Block-Level Integrity for Read-Only Partitions](/articles/linux/dm-verity/)
- [Kernel Lockdown and Module Hardening](/articles/linux/kernel-lockdown/)
- [Linux Capability Hardening](/articles/linux/linux-capability-hardening/)
- [Reproducible WASM Builds and SBOM Generation](/articles/wasm/reproducible-wasm-builds/)
- [SLSA Provenance and Build Integrity](/articles/cicd/slsa-provenance/)
