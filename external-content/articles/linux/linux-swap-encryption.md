---
title: "Linux Encrypted Swap: Protecting In-Memory Secrets from Disk Exposure"
description: "Unencrypted swap exposes cryptographic keys, session tokens, and database results to cold-boot attacks and forensic analysis. This guide covers volatile random-key swap, persistent LUKS swap for hibernation, zram as a swap alternative, and verification tooling for production systems."
slug: linux-swap-encryption
date: 2026-05-07
lastmod: 2026-05-07
category: linux
tags:
  - swap-encryption
  - dm-crypt
  - luks
  - memory-security
  - cold-boot
personas:
  - security-engineer
  - platform-engineer
article_number: 484
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/linux/linux-swap-encryption/
---

# Linux Encrypted Swap: Protecting In-Memory Secrets from Disk Exposure

## The Problem

RAM is volatile. When the kernel runs low on memory, it pages process memory out to disk — the swap partition or swapfile. Most production Linux systems have swap enabled. Most production Linux systems do not encrypt swap.

The consequence: any data that passes through a process's memory can silently land on disk. Cryptographic private keys held by an SSH agent, TLS session secrets in an nginx worker, OAuth tokens in a web application, bcrypt hashes returned by a database query, plaintext passwords momentarily resident while being validated — all are candidates for swap eviction. Once written to disk, those secrets persist until the swap blocks are overwritten by new swap pages.

Cold-boot attacks exploit this directly. An attacker who obtains physical access to a machine — or to a cloud disk snapshot, a VM image, or a storage backup — can analyse the swap partition with standard forensic tools. Unlike RAM, which loses state within seconds to minutes after power-off, disk-resident swap is stable indefinitely. The kernel does not zero swap pages before writing them; it does not zero swap pages when the process that wrote them exits.

The specific exposure scenarios:

- **OpenSSL/GnuTLS private keys** paged out during high-memory-pressure events on TLS termination hosts. The key material is plaintext in the swap page — no memory locking (`mlock`) means no protection from eviction.
- **Database query results** containing PII, credentials, or regulated data written to swap during sort operations or hash joins.
- **Secrets manager payloads** fetched by application processes; if the process is not explicitly pinning the memory region, the kernel can evict it.
- **Container workloads** that inherit the host swap device without awareness that their heap is potentially disk-persistent.
- **Hibernation images** (`/sys/power/state = disk`) which serialise the entire system RAM to the swap partition. An unencrypted swap partition means hibernation produces an unencrypted memory dump on disk.

The fix is conceptually simple: encrypt the swap block device before the kernel writes to it. The dm-crypt layer handles block-level encryption transparently — the kernel writes encrypted ciphertext to the disk, reads ciphertext back, decrypts in memory. Two distinct deployment patterns cover the two main use cases.

## Volatile (Random-Key) Swap Encryption

For systems that do not use hibernation, the correct approach is ephemeral random-key encryption. On every boot, a fresh random key is generated from `/dev/urandom` or a hardware RNG. The swap device is encrypted with that key, and the key is never written to disk. On the next boot, a new key is generated; the previous swap ciphertext is permanently unreadable — not because it was wiped, but because the key is gone.

This approach requires no key management infrastructure. There is no key to protect, rotate, or back up. The trade-off is that swap contents are irrecoverably lost across reboots — which is precisely what you want for swap.

### /etc/crypttab configuration

`/etc/crypttab` describes dm-crypt mappings that `systemd-cryptsetup` or the traditional `cryptdisks` init scripts set up at boot.

```conf
# /etc/crypttab
# <name>       <device>           <keyfile>   <options>
cryptswap      /dev/sda2          /dev/urandom  swap,cipher=aes-xts-plain64,size=256
```

Field-by-field:

- `cryptswap` — the name of the device mapper target that will appear as `/dev/mapper/cryptswap`.
- `/dev/sda2` — the raw block device to encrypt. Adjust to your actual swap partition. Never use a swap file path here; this must be a block device.
- `/dev/urandom` — instructs `cryptsetup` to generate a random key at open time. On kernels 4.8+ and hardware with an HWRNG, you can substitute `/dev/hwrng` for hardware-generated entropy. Do not use a passphrase or a keyfile path for volatile swap — that defeats the purpose.
- `swap` — marks this as a swap device; `mkswap` is run automatically on the plaintext side after the dm-crypt layer opens. This overwrites any residual signature on the device.
- `cipher=aes-xts-plain64,size=256` — AES-256 in XTS mode, the standard for disk encryption. `plain64` is the IV generator; it is appropriate for swap (sequential block numbers, no need for the more complex `essiv`). `size=256` is the key size in bits.

If you want to be explicit about the hash (used only for passphrase-based key derivation; irrelevant for random-key swap but required by older tools):

```conf
cryptswap  /dev/sda2  /dev/urandom  swap,cipher=aes-xts-plain64,size=256,hash=sha256
```

### /etc/fstab swap entry

After `crypttab` defines the mapping, `fstab` mounts it as swap:

```conf
# /etc/fstab
/dev/mapper/cryptswap  none  swap  sw,pri=-2  0  0
```

The `pri=-2` sets swap priority below any zram devices (described below) if both are in use. Do not use `UUID=` for the encrypted swap device — the UUID changes on every boot because `mkswap` is run fresh each time the random key opens the volume.

### Applying changes without reboot

```bash
# Disable current swap
sudo swapoff -a

# If the cryptswap mapping already exists, close it
sudo cryptsetup close cryptswap

# Re-open with random key per crypttab
sudo cryptdisks_start cryptswap   # Debian/Ubuntu
# or
sudo systemctl start systemd-cryptsetup@cryptswap.service  # systemd distros

# Enable the new encrypted swap
sudo swapon /dev/mapper/cryptswap
```

## Persistent LUKS-Encrypted Swap

Volatile random-key swap cannot support hibernation. Suspend-to-disk writes the entire system RAM to the swap partition and reads it back on the next boot. If the key used to encrypt swap does not persist across the power cycle, the hibernation image is unreadable and the resume fails (typically a kernel panic or corrupted resume).

For hibernation, swap must be encrypted with a key that survives power-off. This means a proper LUKS container with a stored key.

```bash
# Create a LUKS2 container on the swap partition
sudo cryptsetup luksFormat --type luks2 \
  --cipher aes-xts-plain64 \
  --key-size 512 \
  --hash sha512 \
  --pbkdf argon2id \
  /dev/sda2

# Add a keyfile for unattended unlock (store this securely)
sudo dd if=/dev/urandom of=/etc/cryptsetup-keys.d/swap.key bs=64 count=1
sudo chmod 600 /etc/cryptsetup-keys.d/swap.key
sudo cryptsetup luksAddKey /dev/sda2 /etc/cryptsetup-keys.d/swap.key

# Open the LUKS container
sudo cryptsetup luksOpen /dev/sda2 cryptswap --key-file /etc/cryptsetup-keys.d/swap.key

# Format the plaintext device as swap
sudo mkswap /dev/mapper/cryptswap
```

`/etc/crypttab` for persistent LUKS swap:

```conf
# /etc/crypttab — persistent LUKS swap (hibernation-capable)
cryptswap  /dev/sda2  /etc/cryptsetup-keys.d/swap.key  luks,discard
```

Note the `luks` option instead of `swap` — `luks` tells `cryptdisks` / `systemd-cryptsetup` to use LUKS metadata for key slot lookup rather than generating a random key. The `discard` option passes TRIM commands through to the underlying device; omit it if you want to prevent storage-layer metadata leakage (TRIM reveals which blocks are free/used, which can leak information about swap usage patterns).

The keyfile (`/etc/cryptsetup-keys.d/swap.key`) must be protected. On a system where the root filesystem is itself encrypted (LUKS+TPM2), the keyfile is protected by the root volume encryption. If root is unencrypted, the keyfile sitting on root disk provides no real protection against physical access — the attacker reads the keyfile and decrypts swap directly.

### Hibernation with LUKS+TPM2 sealed keys

The production-grade approach combines LUKS swap with TPM2-sealed key management. The swap LUKS key is enrolled into the TPM's sealed key slots via `systemd-cryptenroll`:

```bash
# Enroll TPM2 with PCR binding (PCR 0,1,7 = firmware+config+secureboot)
sudo systemd-cryptenroll \
  --tpm2-device=auto \
  --tpm2-pcrs=0+1+7 \
  /dev/sda2
```

With this configuration the swap partition auto-unlocks at boot only if the system is in the expected measured boot state — firmware unmodified, Secure Boot enabled, bootloader unmodified. A stolen disk, or a disk booted with a tampered kernel, will not have the TPM release the key. See the [LUKS TPM2 sealing article](/articles/linux/luks-tpm2-sealing/) for the full implementation including clevis/tang for server fleet deployments where TPM sealing alone is insufficient.

For hibernation resume to work, the kernel initramfs must contain the cryptsetup hooks to open the LUKS swap device before the resume image is loaded. On Debian/Ubuntu:

```bash
sudo update-initramfs -u -k all
```

Verify the `resume` and `cryptroot`/`cryptsetup` hooks are included:

```bash
lsinitramfs /boot/initrd.img-$(uname -r) | grep -E 'cryptsetup|resume'
```

## zram: Compressed In-RAM Swap

If hibernation is not required and the goal is to avoid paging secrets to disk entirely, `zram` provides a compelling alternative. zram creates a block device backed by a compressed pool in RAM itself — swap goes to zram, zram compresses it and stores the result in kernel memory. Nothing ever reaches disk.

The security properties are straightforward: zram swap has the same confidentiality boundary as the rest of RAM. There is no disk exposure surface. Cold-boot attacks against disk do not apply (though RAM cold-boot attacks, which require physical presence within seconds of power-off with supercooled RAM, remain theoretically possible).

### systemd-zram-generator

`systemd-zram-generator` is the standard way to configure zram on systemd systems (Fedora 33+, Ubuntu 22.04+, most modern distros):

```bash
sudo apt install systemd-zram-generator   # Debian/Ubuntu
sudo dnf install systemd-zram-generator   # Fedora/RHEL
```

Configuration in `/etc/systemd/zram-generator.conf`:

```ini
# /etc/systemd/zram-generator.conf
[zram0]
zram-size = min(ram / 2, 8192)
compression-algorithm = zstd
swap-priority = 100
```

- `zram-size` — maximum size of the zram device. `min(ram / 2, 8192)` caps at 8 GiB but uses half of RAM on smaller systems. Tune based on your working set.
- `compression-algorithm = zstd` — zstd is the best-in-class default; provides higher compression ratios than lzo with better performance than lz4 on modern CPUs.
- `swap-priority = 100` — higher priority than disk swap (typically set to `-1` or `-2`) means the kernel fills zram first.

Apply immediately:

```bash
sudo systemctl daemon-reload
sudo systemctl start /dev/zram0
sudo swapon --show
```

You can run zram and encrypted disk swap simultaneously: zram absorbs normal memory pressure, and the encrypted disk swap handles severe overcommit scenarios. Assign priorities accordingly (`zram` at `100`, encrypted disk swap at `10`).

## Disabling Swap Entirely

For high-security, memory-rich workloads where protecting secrets is paramount and OOM behaviour is acceptable, disabling swap entirely eliminates the disk exposure surface:

```bash
# Disable swap for the current session
sudo swapoff -a

# Verify
cat /proc/swaps
```

To make this permanent, comment out all swap lines in `/etc/fstab` and remove (or comment out) swap entries in `/etc/crypttab`.

The kernel tunable `vm.swappiness` controls the kernel's willingness to swap. Setting it to `0` does not disable swap — it tells the kernel to avoid swapping unless absolutely necessary (memory pressure is extreme). Setting it to `1` on kernels 3.5+ means swap only when the system is very close to OOM. Neither is equivalent to `swapoff`.

```bash
# Minimise (but not eliminate) swapping — persistent via sysctl.d
echo 'vm.swappiness = 1' | sudo tee /etc/sysctl.d/99-noswap.conf
sudo sysctl -p /etc/sysctl.d/99-noswap.conf
```

The OOM consequences of disabling swap entirely: when physical RAM is exhausted, the OOM killer terminates processes rather than paging them out. On a host with adequate RAM for its workload this is not a problem in practice. For workloads that have bursty memory demand (large sort operations, model inference, batch ETL), disabling swap increases the probability of OOM kills during peak demand. Size RAM conservatively if you intend to disable swap.

For Kubernetes nodes, `kubelet` historically required swap to be disabled (`--fail-swap-on=true`). From Kubernetes 1.28, swap support is available as a beta feature with `NodeSwap` feature gate. If running encrypted swap on a Kubernetes node, ensure the kubelet swap configuration is explicitly set rather than relying on defaults.

## Verifying Swap Is Encrypted

After configuring encrypted swap, verify the setup is correct before relying on it.

### Check active swap devices

```bash
cat /proc/swaps
```

Expected output when encrypted swap is active:

```
Filename                Type        Size      Used  Priority
/dev/dm-2               partition   8388604   0     -2
```

The device name `dm-N` confirms swap is on a device mapper target (dm-crypt). A raw device name like `/dev/sda2` in this output indicates unencrypted swap.

### Inspect the device mapper target

```bash
sudo dmsetup info cryptswap
```

```
Name:              cryptswap
State:             ACTIVE
Read Ahead:        256
Tables present:    LIVE
Open count:        1
Event number:      0
Major, minor:      253, 2
Number of targets: 1
UUID:              CRYPT-PLAIN-cryptswap
```

The `CRYPT-PLAIN` UUID prefix confirms this is a dm-crypt device in plain mode (volatile random-key). A LUKS device would show `CRYPT-LUKS2-<uuid>`.

### Check cryptsetup status

```bash
sudo cryptsetup status cryptswap
```

```
/dev/mapper/cryptswap is active.
  type:    PLAIN
  cipher:  aes-xts-plain64
  keysize: 256 bits
  key location: dm-crypt
  device:  /dev/sda2
  sector size:  512
  offset:  0 sectors
  size:    16777216 sectors
  mode:    read/write
```

Verify `cipher` and `keysize` match your `crypttab` configuration. The `key location: dm-crypt` for PLAIN mode confirms the key is held in kernel memory and not stored on disk.

For LUKS swap:

```bash
sudo cryptsetup luksDump /dev/sda2
```

This shows the LUKS header, key slots, and cipher parameters. Verify the cipher, key size, and PBKDF match your intended configuration.

### Confirm no plaintext swap metadata on disk

After enabling encrypted swap, the raw partition should contain no recognisable swap signature:

```bash
sudo file -s /dev/sda2
```

On a properly configured volatile-encrypted swap device, this returns `data` (unrecognised binary). If it returns `Linux/i386 swap file`, the device mapper is not active and the kernel is writing to raw unencrypted swap.

## Container and VM Considerations

Container runtimes (Docker, containerd, CRI-O) do not manage swap directly. Containers inherit the host's swap configuration. A container process whose memory is swapped out will have that memory encrypted if and only if the host has encrypted swap. The container has no visibility into this; it cannot make its own swap encrypted if the host does not.

The operational consequence: encrypting swap is a host-level responsibility. Container security policies that include memory protection requirements must verify the host swap configuration, not the container configuration.

For VM workloads on hypervisors, the hypervisor may offer its own swap (ballooning, host swap) that is independent of the guest's swap configuration. Guest-level swap encryption protects guest memory paged to the guest's virtual disk, but does not protect memory that the hypervisor has moved to host swap. On KVM with virtio-balloon, the balloon driver reclaims guest physical pages for the host; those pages contain guest memory contents. Full protection requires either:

1. Disabling memory ballooning for security-sensitive VMs, or
2. Hardware-level VM memory encryption (AMD SEV, Intel TDX) which encrypts guest RAM from the hypervisor's perspective.

For cloud VMs (AWS EC2, GCP Compute Engine, Azure VMs), the host hypervisor swap is not guest-accessible or guest-configurable. The relevant defence is encrypting the guest's own virtual disk (EBS encryption, Cloud Disk encryption), which ensures that if the cloud provider's physical storage is accessed, the swap partition on the encrypted virtual disk is not readable.

## Summary

| Scenario | Recommended configuration |
|---|---|
| No hibernation, simplest setup | `/etc/crypttab` with `/dev/urandom`, volatile key |
| No hibernation, minimal disk exposure | zram (`systemd-zram-generator`) |
| Hibernation required | LUKS2 swap + keyfile; LUKS+TPM2 sealing for production |
| Maximum security, RAM-rich host | `swapoff -a`, `vm.swappiness=1` as fallback |
| Kubernetes node | Host-level encrypted swap or zram; set kubelet swap policy explicitly |

Unencrypted swap is a silent data exfiltration path that most hardening checklists miss. The fix is low-effort: a two-line `crypttab` entry and a `fstab` update. For systems where disk exposure must be eliminated entirely, zram moves swap into RAM. For systems with hibernation requirements, LUKS with TPM2-sealed keys provides encrypted persistent swap without manual passphrase entry at boot.

Verify after every configuration change with `cryptsetup status`, `dmsetup info`, and `file -s` against the raw device. Automated compliance checks should assert that no device listed in `/proc/swaps` maps to a non-dm-crypt block device.
