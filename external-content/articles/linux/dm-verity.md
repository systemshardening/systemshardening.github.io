---
title: "dm-verity and dm-integrity: Tamper-Evident Block-Level Roots for Production Linux"
description: "dm-verity gives you a read-only root that fails to mount if a single block is tampered with. dm-integrity adds runtime checksumming. Together: immutable, evidence-bearing systems."
slug: "dm-verity"
date: 2026-04-29
lastmod: 2026-04-29
category: "linux"
tags: ["dm-verity", "dm-integrity", "linux", "immutable", "boot-integrity"]
personas: ["systems-engineer", "security-engineer", "platform-engineer"]
article_number: 207
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/linux/dm-verity/index.html"
---

# dm-verity and dm-integrity: Tamper-Evident Block-Level Roots for Production Linux

## Problem

Filesystem-level integrity (auditd, AIDE, Tripwire) is too late. A check that runs after boot has already let a malicious binary execute; a check that runs hourly has minutes-to-hours of attacker dwell time. The right boundary for system-image integrity is the kernel's block layer — every read of a block is verified before the bytes reach userspace.

`dm-verity` provides this: a Merkle-tree-backed verification layer that sits between the block device and the filesystem. Each block read is verified against a hash; any mismatch causes I/O to fail. The Merkle root is signed at image-build time with a known key.

`dm-integrity` is the writable counterpart: per-block checksums for read-write filesystems, detecting bit-rot or physical tampering on disk. Combined with dm-crypt, dm-integrity provides authenticated encryption (AEAD) at the block level.

By 2026, immutable Linux distributions have made these mainstream:

- **Fedora CoreOS / Flatcar / Talos** ship with dm-verity-protected root partitions. Boot fails if root is tampered with.
- **Bottlerocket** (AWS) and **Container OS** (GCP) use dm-verity for the system partition.
- **ChromeOS** has used dm-verity for the rootfs for over a decade.
- **Android** uses dm-verity for `system` and `vendor` partitions; dm-integrity for `userdata` (encrypted).

Yet the typical Ubuntu / RHEL production server still has a writable, unsigned root. A compromised process with root privileges modifies any system binary; the next reboot uses the modified binary. dm-verity is the structural defense.

The specific gaps in a default Linux server image:

- Root filesystem is read-write; binaries can be replaced at runtime.
- No cryptographic measurement of the running system; integrity-checking tools (auditd, AIDE) operate on userspace files after boot.
- File integrity monitoring (FIM) catches changes after the fact, not during write.
- Persistent rootkits survive reboot because root is mutable.
- Read-only `chattr +i` is bypassed by anyone with `CAP_LINUX_IMMUTABLE`.

This article covers building dm-verity-protected root images, signing and verifying the Merkle root, deploying dm-integrity for writable partitions, the systemd integration via `systemd-veritysetup`, and the operational changes (where state goes when the root is read-only).

**Target systems:** Linux kernel 5.4+ (dm-verity `forward_error_correction` in 5.10+, dm-integrity AEAD in 5.16+); Fedora CoreOS, Talos Linux, Bottlerocket, custom immutable distros built on Buildroot or systemd-mkosi.

## Threat Model

- **Adversary 1 — Persistent rootkit:** an attacker with root modifies system binaries (`sshd`, `systemd`, `bash`) to install backdoors that survive reboot.
- **Adversary 2 — Disk-level tampering:** physical access to the disk; attacker modifies file contents while the host is offline.
- **Adversary 3 — Supply-chain image tampering:** the system image is replaced in transit between the build server and the deploy target.
- **Adversary 4 — Bit-rot:** silent data corruption from disk degradation, cosmic rays, controller bugs. Not adversarial but indistinguishable from tampering.
- **Access level:** Adversary 1 has root on the running system. Adversary 2 has physical disk access. Adversary 3 has man-in-the-middle on the image-distribution path. Adversary 4 has none.
- **Objective:** Persistent foothold via modified system binaries; undetectable data corruption.
- **Blast radius:** Without dm-verity, a single root compromise persists indefinitely. With dm-verity, the next reboot fails to mount root if any block has been modified — the rootkit can't survive a reboot, and persistence is forced into writable state directories which are clearly demarcated.

## Configuration

### Step 1: Build a Verity-Protected Image

Build the root filesystem, generate the Merkle hash tree, and sign the root hash.

```bash
# Build the root filesystem (any standard tool: debootstrap, mkosi, buildroot).
mkdir -p /tmp/rootfs
debootstrap stable /tmp/rootfs http://deb.debian.org/debian/

# Convert to a fixed-size ext4 image, immutable.
truncate -s 2G /tmp/root.img
mkfs.ext4 -F /tmp/root.img
mount -o loop /tmp/root.img /mnt
cp -a /tmp/rootfs/* /mnt/
umount /mnt

# Generate the verity hash tree.
veritysetup format /tmp/root.img /tmp/root.verity > /tmp/verity.info
# Outputs:
#   UUID: ...
#   Hash type: 1
#   Data blocks: 524288
#   Data block size: 4096
#   Hash block size: 4096
#   Hash algorithm: sha256
#   Salt: a8...
#   Root hash: 4f7c2e3d... (this is the key value)
```

The root hash is a 32-byte SHA-256 of the entire Merkle tree's root. Any modification to any data block changes a leaf hash; that propagates up and changes the root hash.

Sign the root hash:

```bash
# Sign with the build-server's signing key.
ROOT_HASH=$(grep "Root hash" /tmp/verity.info | awk '{print $3}')
echo -n "$ROOT_HASH" | openssl dgst -sha256 -sign /etc/build-keys/verity.key \
  -out /tmp/root-hash.sig
```

Distribute three artifacts: `root.img` (data), `root.verity` (Merkle tree), `root-hash.sig` (signature over the root hash).

### Step 2: Boot With Verity Activated

The bootloader passes the root hash to the kernel, which sets up the dm-verity device before mounting root.

```bash
# /boot/loader/entries/00-verity.conf (systemd-boot example).
title   Production OS (verity)
linux   /vmlinuz
initrd  /initrd.img
options root=/dev/mapper/root-verity \
        verity.usrhash=4f7c2e3d... \
        verity.usr=PARTLABEL=root \
        verity.usrhashpart=PARTLABEL=verity \
        ro
```

`systemd-veritysetup-generator` reads the kernel command-line, sets up the dm-verity device, and mounts it as the root.

For GRUB:

```
GRUB_CMDLINE_LINUX="systemd.verity_root_data=PARTUUID=... systemd.verity_root_hash=PARTUUID=... verity.usrhash=4f7c2e3d... ro"
```

The `ro` flag is critical: dm-verity supports read-only mounts only.

Verify at runtime:

```bash
# Confirm dm-verity is active on root.
sudo dmsetup table root-verity
# 0 524288 verity 1 /dev/sda3 /dev/sda4 4096 4096 524288 1 sha256
#   4f7c2e3d... a8b9c0d1...

# Read /proc/mounts.
mount | grep " on / "
# /dev/mapper/root-verity on / type ext4 (ro,relatime)

# Tampering with root after boot fails the read.
# (Cannot easily simulate without taking the system down; see Step 4 verification.)
```

### Step 3: Writable State With dm-integrity + dm-crypt

A read-only root needs writable space for logs, application state, configuration. Mount these on dm-integrity-protected partitions:

```bash
# Format with integrity (HMAC + AES-GCM for authenticated encryption).
sudo cryptsetup luksFormat --type luks2 \
  --integrity hmac-sha256 \
  --cipher aes-xts-plain64 \
  --key-size 512 \
  /dev/sda5

sudo cryptsetup open /dev/sda5 var-state \
  --key-file /etc/keys/var-state.key

# Format ext4 on the protected device.
sudo mkfs.ext4 /dev/mapper/var-state
sudo mount /dev/mapper/var-state /var/state
```

The kernel verifies HMAC on every read; tampering returns `EILSEQ` to userspace. Combined with the immutable root, the system has clear separation: read-only verified system, write-enabled but tamper-evident state.

Update `/etc/fstab` to mount writable partitions on boot. Application data (`/var/lib/<app>`) goes to dm-integrity volumes; session state, caches, sockets go to tmpfs.

### Step 4: Failure Behavior on Tampering

A simulated tamper (in a test environment) on a verity-protected device causes:

```bash
# DON'T do this on production. Test environment only.
sudo dd if=/dev/zero of=/dev/sda3 bs=4096 count=1 seek=100 conv=notrunc

# On next read of the affected block:
cat /verified-file
# I/O error.

# dmesg shows:
# [12345.678] device-mapper: verity: 8:3: data block 100 is corrupted
```

The kernel returns I/O error; userspace cannot read the modified block. Production: the kernel-panic-on-corruption mode (`error_behavior=panic`) is one of three configurable behaviors; choose based on workload sensitivity.

### Step 5: Update Flow

dm-verity-protected systems require a build-then-deploy update flow, not in-place package upgrades. The pattern:

```
[Build new image with new packages]
  -> [Generate new Merkle root + sign]
  -> [Distribute new root.img, verity, signature]
  -> [Bootloader updates entries to point at new image]
  -> [Reboot to apply]
  -> [Old image kept for one boot cycle for rollback]
```

Tools: `systemd-sysupdate` (handles the dual-image swap), Bottlerocket's update operator, Talos's machine-config CRD, Flatcar's update_engine.

```yaml
# systemd-sysupdate transfer config.
[Source]
Type=url-file
Path=https://updates.example.com/talos-%v.raw.xz
MatchPattern=talos_@v.raw.xz

[Target]
Type=partition
Path=auto
MatchPattern=talos_%v
PartitionType=root-x86-64-verity
ReadOnly=1
```

Sysupdate downloads, verifies the signature, writes to the inactive partition, swaps the boot reference, and reboots. Two-image roll-forward / roll-back is automatic.

### Step 6: Audit and Telemetry

Track integrity events:

```
verity_io_error_total{partition}             counter
verity_corruption_detected_total{block_num}  counter
integrity_decryption_failure_total           counter
integrity_data_block_failures_total          counter
boot_verity_root_hash_mismatch_total          counter
```

For ongoing monitoring:

```bash
# Read kernel ringbuffer for verity / integrity messages.
journalctl -k | grep -iE "dm-verity|dm-integrity|verity:"
```

Alert on any verity error — they should be zero in normal operation. Even a single error indicates either tampering or hardware failure; both warrant immediate investigation.

### Step 7: Image Provenance

Sign images with cosign / SLSA provenance, the same as container images. Tie the Merkle root hash to a build attestation:

```bash
cosign attest --yes --predicate provenance.json --type slsaprovenance \
  --certificate-identity 'https://github.com/myorg/build-images/.github/workflows/build.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/myorg/talos-image:v1.7.0
```

The deployment pipeline verifies the cosign signature, the SLSA provenance, AND the dm-verity Merkle root. Three independent gates.

## Expected Behaviour

| Signal | Standard mutable root | dm-verity-protected root |
|--------|------------------------|----------------------------|
| Modify `/usr/bin/sshd` after boot | Succeeds; persists across reboot | I/O error to write attempt; root is `ro` |
| Disk-level tamper while offline | Modification persists | Boot fails: `verity root hash mismatch` |
| Bit-rot in system files | Silent corruption | Read fails; OS reports the block |
| Update flow | `apt upgrade` in place | New signed image; reboot to apply |
| Persistent rootkit | Survives reboot | Cannot survive — read-only root forces persistence to known-writable directories which are themselves dm-integrity-protected |

Verify the integrity story:

```bash
# Confirm root is read-only.
mount | grep " on / "
# /dev/mapper/root-verity on / type ext4 (ro,relatime)

# Confirm dm-verity is active.
sudo dmsetup table | grep verity
# root-verity: 0 524288 verity ...

# Try to write — should fail.
sudo touch /etc/test-rw
# touch: cannot touch '/etc/test-rw': Read-only file system
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Read-only root | Defeats persistent rootkits | In-place package upgrades not possible | Use immutable update flow (sysupdate); design state to live on writable partitions explicitly. |
| Merkle-tree storage | Tamper detection | ~1% storage overhead for the hash tree | Negligible; hash partition can be on the same disk. |
| dm-integrity for state | Authenticated encryption per block | ~5-15% performance overhead vs raw block device | Acceptable for application state; not for high-throughput scratch space (use tmpfs). |
| Per-image signing | Provenance from build to boot | Build pipeline complexity | Standard now; cosign integrates well. |
| Update reboot required | Atomicity guaranteed | Higher MTTR for security patches | Use systemd-sysupdate's dual-partition flow; reboot-required time bounded to one reboot. |
| Rollback to previous image | Recovery from bad updates | Two partitions of disk space | Accepted cost; the previous image is one update cycle away. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Verity root hash mismatch on boot | Boot fails with verity error | Console output: "data block N is corrupted" | Investigate the disk for failure or tampering; re-flash the image. The system fails closed — exactly the desired behavior. |
| Application expects writable /etc | App fails with permission errors | Application logs show write failures to /etc paths | Move config to a writable overlay (using systemd's `ConfigurationDirectory` or symlinks to /var/state/<app>/conf). |
| dm-integrity corruption | Reads fail on the protected partition | dmesg: integrity checksum failure | Disk is degrading or has been tampered with; replace and restore from backup. |
| Out-of-date kernel command line | Kernel can't find verity-data partition | systemd-veritysetup-generator fails | Verify kernel cmdline; for systemd-boot, regenerate via `bootctl install`; for GRUB, regenerate via `update-grub`. |
| Hash partition lost / corrupted | Cannot mount root | Boot loops or panics | Use the alternate (rollback) image; investigate. The hash partition is small and could be backed up separately. |
| Update signature mismatch | Sysupdate refuses to apply | systemd-sysupdate logs show signature error | Verify the signing key matches; trust roots may have been rotated. Investigate update server compromise. |
| Forgot writable mount for state | Application data lost across reboot | App restart shows empty state | Configure `/etc/fstab` to mount writable partition on boot before any service that needs state. |

## Related Articles

- [GRUB Boot Hardening for Production Linux Systems](/articles/linux/grub-boot-hardening/)
- [Kernel Lockdown Mode](/articles/linux/kernel-lockdown/)
- [Hardening the Linux Kernel Attack Surface with sysctl](/articles/linux/sysctl-kernel-hardening/)
- [Linux Audit Framework Deep Dive](/articles/linux/auditd-deep-dive/)
- [FIDO2 SSH with sk-* Keys](/articles/linux/fido2-ssh/)
