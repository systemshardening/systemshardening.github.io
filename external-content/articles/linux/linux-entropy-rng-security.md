---
title: "Linux Entropy and RNG Security: Hardening Randomness from Boot to Application"
description: "Weak entropy means predictable secrets. This guide covers Linux RNG architecture, boot-time starvation in VMs, RDRAND/TPM seeding, LRNG, and auditing entropy health for production systems."
slug: linux-entropy-rng-security
date: 2026-05-07
lastmod: 2026-05-07
category: linux
tags:
  - entropy
  - rng
  - cryptography
  - getrandom
  - tpm
personas:
  - security-engineer
  - platform-engineer
article_number: 469
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/linux/linux-entropy-rng-security/
---

# Linux Entropy and RNG Security: Hardening Randomness from Boot to Application

## The Problem

Cryptographic security collapses when the underlying randomness is predictable. Every TLS session key, every ECDH ephemeral, every RSA key generation, every ASLR offset — all of it descends from the kernel's random number generator. When that generator is seeded with low-quality entropy, an attacker who can guess or partially reconstruct the seed gains the ability to predict output: session tokens, private keys, nonces.

This isn't a theoretical concern. The 2012 "Mining Your Ps and Qs" paper found that 0.2% of TLS public keys on the public internet shared prime factors — the direct result of RSA key generation on freshly booted systems with insufficient entropy. In embedded Linux and cloud VM deployments this risk is substantially higher: a VM cloned from a template or a container launched from an image may start with a nearly identical kernel state, meaning hundreds of instances generate cryptographic material from near-identical initial conditions.

Three concrete failure modes deserve attention:

1. **Boot-time starvation** — the entropy pool has not yet accumulated sufficient noise at the moment a key is generated. Cloud instances, containers, and embedded devices are particularly susceptible. The kernel may block or return low-quality output before interrupts, disk I/O, and network events have seeded the pool.

2. **Clone entropy collision** — VM snapshots and container images freeze the RNG state at image creation time. If a pool state or seed file is preserved in the image, every instance spawned from that image starts with the same internal state until divergence occurs.

3. **RDRAND trust overextension** — older kernel configurations allowed RDRAND output to bypass the kernel entropy pool entirely. Hardware RNGs can be backdoored or faulty; the 2019 debate about AMD RDRAND produced concrete evidence of firmware bugs returning constant values. Exclusive reliance on hardware RNG removes the defense-in-depth the kernel pool provides.

Understanding the Linux RNG architecture is the prerequisite for fixing all three.

## Linux RNG Architecture

### The Entropy Pool

The kernel maintains a single entropy pool backed by a ChaCha20-based CSPRNG. Hardware event interrupts — keystrokes, disk completions, network packet arrival timing, USB events — contribute timing jitter that feeds the pool's input. The pool is not a simple accumulator: it uses a cryptographic mixing function (currently BLAKE2s for input hashing since kernel 5.17) to fold new entropy into the existing state.

The critical distinction: **entropy estimation** (how many bits of unpredictable input have been mixed in) is separate from **output generation** (how many pseudorandom bytes are produced). Once the pool is considered seeded — a threshold of 256 bits of estimated entropy — the ChaCha20 CSPRNG can produce output indefinitely with cryptographic security guarantees, even if no further entropy is added.

### /dev/random vs /dev/urandom: The Pre-5.6 World

Before kernel 5.6, these two interfaces had meaningfully different behavior:

- **`/dev/random`** — blocked if the kernel's entropy estimate dropped below a threshold. Intended for "high-security" uses. In practice, this caused applications to hang indefinitely waiting for entropy, was frequently misunderstood, and the blocking was not actually a strong security guarantee given that the CSPRNG output was already cryptographically strong once initially seeded.
- **`/dev/urandom`** — never blocked, returned CSPRNG output. Technically could return output before the pool was fully seeded at early boot, but in practice was the correct choice for almost all applications.

This split created enormous developer confusion. Countless programs used `/dev/random` out of perceived safety, introduced random hangs, and gained no real security benefit.

### The 2020 Unification (Kernel 5.6)

Kernel 5.6 merged `/dev/random` and `/dev/urandom` behavior: both now use the same CSPRNG pool, and both block only until the pool is initially seeded (the one-time wait at early boot). After initial seeding, `/dev/random` no longer blocks based on entropy estimates. The distinction between the two interfaces is now essentially vestigial for most purposes.

```bash
# On a modern (5.6+) kernel, these produce equivalent output and behavior:
dd if=/dev/random  bs=32 count=1 2>/dev/null | xxd
dd if=/dev/urandom bs=32 count=1 2>/dev/null | xxd
```

### The getrandom() Syscall

`getrandom(2)`, introduced in kernel 3.17, is the correct modern interface for applications. It avoids file descriptor overhead and race conditions around `/dev/random` and `/dev/urandom`:

```c
#include <sys/random.h>

// Block until pool is seeded, then return 32 cryptographic bytes
unsigned char buf[32];
ssize_t ret = getrandom(buf, sizeof(buf), 0);
if (ret < 0) {
    perror("getrandom");
    exit(1);
}

// Non-blocking variant: returns EAGAIN if pool not yet seeded
ret = getrandom(buf, sizeof(buf), GRND_NONBLOCK);
if (ret == -1 && errno == EAGAIN) {
    // Pool not yet seeded — handle gracefully, do NOT fall back to
    // a weak source. Either wait, abort, or use GRND_INSECURE only
    // if you truly accept unseeded output (almost never correct).
    fprintf(stderr, "RNG not yet seeded\n");
    exit(1);
}
```

In Python, the `secrets` module uses `getrandom()` on Linux:

```python
import secrets

# Correct: uses getrandom() internally
token = secrets.token_bytes(32)
key   = secrets.token_hex(32)

# Also correct on modern systems (reads /dev/urandom)
import os
raw = os.urandom(32)
```

**Never use `random.random()` or `random.SystemRandom` for security-sensitive material.** `random.random()` is a Mersenne Twister — not cryptographically secure. `random.SystemRandom` wraps `os.urandom()` which is acceptable, but `secrets` is the canonical choice since Python 3.6.

## Boot-Time Entropy Starvation

### Why VMs and Containers Are Different

On physical hardware, the kernel accumulates entropy from interrupt timing throughout the boot process: BIOS/UEFI events, disk controller interrupts, USB enumeration, NIC initialization. By the time the first user-space daemon starts, several hundred bits of entropy have typically been mixed in.

VMs and containers eliminate or reduce most of these entropy sources:

- Hypervisors serialize interrupts; the "noise" in timing is dramatically reduced or absent.
- Container init doesn't go through a full hardware boot sequence.
- Cloned VM images may inherit a saved seed file (if `/var/lib/systemd/random-seed` or `/var/lib/urandom/random-seed` was present at snapshot time) — every clone starts from identical state.

The practical consequence: an application that generates a TLS key within seconds of a container starting may do so before `getrandom()` has blocked long enough for the pool to accumulate 256 bits of estimated entropy. On pre-5.6 kernels, `/dev/urandom` would happily return output in this state; on 5.17+ kernels, improvements to early-boot entropy gathering reduce (but do not eliminate) this window.

### Kernel 5.17+ Early Boot Improvements

Kernel 5.17 introduced significant changes to early-boot RNG seeding:

- RDRAND/RDSEED is now mixed into the pool at the earliest possible point in `init/main.c`, before most subsystems start.
- The pool's internal state is hashed with the boot ID, timestamp, and CPU ID to ensure per-boot uniqueness even on cloned images.
- The `crng_init` state machine was restructured: the pool reaches `CRNG_EARLY` (enough for non-blocking output) faster on systems with hardware RNG.

Check your kernel's seeding state:

```bash
# 0 = not seeded, 1 = early seeded, 2 = fully seeded
cat /proc/sys/kernel/random/entropy_avail
# On 5.17+, the kernel also logs crng init:
dmesg | grep -i 'crng\|random:'
```

## RDRAND and RDSEED: Hardware RNG

Intel introduced RDRAND in Ivy Bridge (2012); AMD followed in Zen (2017). RDSEED provides raw entropy from the hardware source; RDRAND provides CSPRNG output seeded from it.

### The 2019 AMD RDRAND Controversy

In 2019, a kernel commit briefly changed Linux to use RDRAND as the *sole* source for the RNG on systems where it was available. Linus Torvalds reverted this, stating explicitly that RDRAND should be *mixed* with other entropy, not trusted exclusively. The concerns:

1. **Backdoor risk** — a hardware vendor could theoretically produce deterministic or correlated output without detection.
2. **Firmware bugs** — AMD Ryzen systems with certain AGESA firmware versions returned a constant value (`0xFFFFFFFF`) from RDRAND, a confirmed bug that would have catastrophically weakened any system trusting it exclusively.
3. **Transparency** — RDRAND's internal state is not inspectable; mixing it with kernel-collected entropy ensures that even a compromised RDRAND cannot compromise the pool if the attacker doesn't also control the other entropy inputs.

Current kernel behavior (post-revert): RDRAND output is XORed into the entropy pool as one input among several. It contributes to seeding speed but cannot override other inputs.

```bash
# Verify RDRAND is available on your CPU
grep -w rdrand /proc/cpuinfo | head -1

# The kernel logs RDRAND usage during boot:
dmesg | grep -i rdrand
```

### Disabling RDRAND (Paranoid Configuration)

If you operate in a high-assurance environment where hardware RNG trust is unacceptable:

```bash
# Kernel command line — disables RDRAND usage in the kernel RNG
nordrand
```

This forces the kernel to rely entirely on interrupt-based entropy collection, which may extend the boot-time seeding window significantly on VMs.

## TPM as Entropy Source

TPMs (Trusted Platform Modules) expose a hardware RNG that is architecturally separate from RDRAND and provides an independent entropy source. TPM 2.0 is standard on modern x86 systems and is mandatory for Windows 11, meaning it's available on most contemporary hardware.

### Adding TPM Entropy at Boot

The `tpm2-tools` package provides `tpm2_getrandom`, which reads bytes directly from the TPM's RNG. Used at boot via a systemd service, this seeds the kernel pool before critical daemons start:

```bash
# Install tpm2-tools
apt install tpm2-tools          # Debian/Ubuntu
dnf install tpm2-tools          # RHEL/Fedora

# Read 32 bytes from TPM RNG and write to kernel entropy pool
tpm2_getrandom 32 | dd of=/dev/random bs=32 count=1

# More robust: write using rngd's built-in TPM support
apt install rng-tools-debian
# /etc/default/rng-tools-debian:
# HRNGDEVICE=/dev/tpm0
```

A minimal systemd unit to seed from TPM at early boot:

```ini
# /etc/systemd/system/tpm-seed.service
[Unit]
Description=Seed kernel RNG from TPM2
DefaultDependencies=no
Before=sysinit.target
After=dev-tpm0.device
ConditionPathExists=/dev/tpm0

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'tpm2_getrandom 64 | dd of=/dev/random bs=64 count=1 iflag=fullblock'
RemainAfterExit=yes

[Install]
WantedBy=sysinit.target
```

```bash
systemctl enable tpm-seed.service
```

### tpm-crng-test

The `tpm-crng-test` utility (part of some distributions' `rng-tools` packages) runs NIST SP 800-22 statistical tests against TPM output before trusting it for pool seeding. This guards against TPM RNG implementation defects:

```bash
# Test TPM RNG quality (may take several seconds)
tpm2_getrandom 4096 | rngtest -c 1000
```

## LRNG: The Linux Random Number Generator Proposal

The LRNG patchset (maintained by Stephan Müller, periodically submitted for upstream inclusion) proposes replacing the legacy RNG with a more modular design. Key differences:

- **Entropy source multiplexing** — pluggable entropy sources (interrupts, RDRAND, TPM, Jitter entropy) with independent accounting per source. The legacy implementation mixes all sources into a single pool with a single estimate.
- **Jitter entropy** — the LRNG includes an integrated CPU execution jitter entropy source (based on `jitterentropy`) that measures CPU cache timing variations — effective even in virtualized environments with no hardware RNG.
- **FIPS 140-3 alignment** — the LRNG's design maps more cleanly to the FIPS 140-3 approved DRBG constructions (AES-CTR-DRBG, HMAC-DRBG) rather than the custom ChaCha20-based design in the upstream kernel.
- **Per-NUMA node pools** — reduces lock contention on large NUMA systems.

As of 2026, LRNG has not been merged upstream but is available as an out-of-tree patch or via security-focused distributions. For most production use, the upstream kernel's improvements since 5.17 are sufficient unless FIPS 140-3 certification is required.

## VM-Specific Hardening

### virtio-rng

KVM/QEMU and other hypervisors supporting the VirtIO specification provide `virtio-rng`, a paravirtualized RNG device that passes entropy from the host kernel's pool to the guest:

```bash
# Verify virtio-rng is loaded in the guest
lsmod | grep virtio_rng
# Should show: virtio_rng

# QEMU command line to attach virtio-rng device
# -object rng-random,id=rng0,filename=/dev/urandom \
# -device virtio-rng-pci,rng=rng0

# The kernel will log when it receives entropy from virtio-rng:
dmesg | grep -i virtio
```

For libvirt-managed VMs, add to the domain XML:

```xml
<devices>
  <rng model="virtio">
    <backend model="random">/dev/urandom</backend>
  </rng>
</devices>
```

### AWS Nitro RNG

AWS Nitro-based instances expose a hardware RNG through the `nsm` (Nitro Security Module) driver. The `amazon-ssm-agent` or the `nitro-enclaves` SDK can feed this into the kernel pool. Nitro instances also inject entropy into the guest via the standard paravirt RNG channel:

```bash
# On Nitro instances, check for the entropy device
ls -la /dev/hwrng
cat /sys/devices/virtual/misc/hw_random/rng_current

# rngd reads from /dev/hwrng and feeds the kernel pool
systemctl status rngd
```

### GCP vTPM Seeding

Google Cloud Platform instances with Shielded VM enabled include a vTPM. The GCP image includes a systemd service that seeds the kernel at boot from the vTPM:

```bash
# On GCP Shielded VMs:
systemctl status google-startup-scripts
dmesg | grep -i 'tpm\|random'

# Manual vTPM seed (if not already configured):
tpm2_getrandom 32 | dd of=/dev/random bs=32 count=1
```

For any cloud environment where you cannot verify the hypervisor's entropy delivery, the safe baseline is: install `rng-tools`, enable `rngd`, and add a boot-time TPM or virtio-rng seed if either is available.

## Auditing Entropy Health

### Kernel Entropy Accounting

```bash
# Current entropy pool estimate (bits). Pre-5.6: should be >100 at steady state.
# Post-5.6: this value is less meaningful but still watchable.
cat /proc/sys/kernel/random/entropy_avail

# Pool size in bits (fixed, typically 4096)
cat /proc/sys/kernel/random/poolsize

# UUID generated from /dev/urandom — useful for testing
cat /proc/sys/kernel/random/uuid

# Watch entropy available in real time
watch -n1 cat /proc/sys/kernel/random/entropy_avail
```

### rngtest: FIPS Statistical Tests

`rngtest` (from `rng-tools`) runs the FIPS 140-2 statistical tests against a stream of bytes. Use it to validate your RNG sources:

```bash
apt install rng-tools

# Test /dev/urandom output quality (1000 blocks of 20000 bits each)
cat /dev/urandom | rngtest -c 1000

# Expected output on a healthy system:
# rngtest: bits received from input: 20000000
# rngtest: FIPS 140-2 successes: 1000
# rngtest: FIPS 140-2 failures: 0
# Any failures indicate a serious problem with the entropy source.

# Test hardware RNG directly
cat /dev/hwrng | rngtest -c 1000
```

### Monitoring Entropy Starvation

For production systems, alert on prolonged periods of low `entropy_avail`. A Prometheus alerting rule using the `node_exporter`:

```yaml
# node_exporter exports kernel_random_entropy_available_bits
groups:
  - name: entropy
    rules:
      - alert: LowKernelEntropy
        expr: node_random_entropy_available < 200
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Low kernel entropy on {{ $labels.instance }}"
          description: >
            Kernel entropy pool at {{ $value }} bits for 5+ minutes.
            Cryptographic operations may block or use low-quality randomness.
            Check rngd, virtio-rng, and TPM seeding.
```

On kernels 5.6+, sustained low entropy is less immediately dangerous (the CSPRNG output is still cryptographically strong once initially seeded), but it warrants investigation as it may indicate that rngd or hardware RNG sources have failed.

### Checking the Seeded State

```bash
# Linux 5.17+ exposes the seeded flag:
cat /proc/sys/kernel/random/uuid   # Forces pool to be read; will block until seeded

# Kernel log shows seeding events:
dmesg | grep 'random: crng'
# crng init done            — pool fully seeded
# random: fast init done    — early seed complete (5.17+)
```

## Application Guidance

The rules for application developers are straightforward, and the common mistakes are avoidable:

**Use `getrandom(0)` or `/dev/urandom`, never `/dev/random`.**

On modern kernels, `/dev/random` no longer provides stronger guarantees — it simply blocks until the initial seeding is complete, which `getrandom(0)` does as well. Using `/dev/random` in daemons or services can cause indefinite hangs at boot, particularly in container environments.

**Handle `GRND_NONBLOCK` correctly.**

```c
// If you use GRND_NONBLOCK, you MUST handle EAGAIN
ssize_t ret = getrandom(buf, 32, GRND_NONBLOCK);
if (ret == -1) {
    if (errno == EAGAIN) {
        // Pool not seeded yet. Do NOT fall back to a weaker source.
        // Block on getrandom(buf, 32, 0) instead, or fail with an error.
        // Applications that generate keys during early boot should use
        // getrandom(0) and accept the block.
        ret = getrandom(buf, 32, 0);  // block until seeded
    }
    if (ret == -1) { perror("getrandom"); exit(1); }
}
```

**Never seed application-level PRNGs from a fixed value, timestamp, or PID.** Any seeding must come from `getrandom()` or `/dev/urandom`. In particular:

```python
# Wrong: trivially predictable
import random
random.seed(int(time.time()))
token = random.getrandbits(128)

# Wrong: Mersenne Twister is not a CSPRNG
import random
token = random.getrandbits(128)

# Correct
import secrets
token = secrets.token_bytes(16)
```

**Do not copy seed files into VM/container images.** The file `/var/lib/systemd/random-seed` (systemd) or `/var/lib/urandom/random-seed` (SysV) preserves entropy across reboots on physical machines. This is beneficial on bare metal but dangerous in images: every instance spawned from an image containing this file starts with the same seed until divergence occurs. Ensure seed files are excluded from image builds or are regenerated on first boot.

**Key generation at boot.** If your service generates a long-term key on first startup (common in orchestration: etcd peer certs, Vault unseal keys, Kubernetes service account keys), ensure it waits until the pool is seeded:

```bash
# Shell: wait for pool to be seeded before generating keys
# On Linux 5.6+ kernels, reading from /dev/urandom already does this.
# For older kernels:
until [ "$(cat /proc/sys/kernel/random/entropy_avail)" -gt 200 ]; do
    sleep 0.1
done
generate_keys
```

Or, use `systemd-random-seed` (enabled by default in modern systemd) which restores saved entropy from a previous boot and ensures sufficient entropy is available before most services start — provided the seed file was not baked into an image.

## Hardening Checklist

```
[ ] Kernel >= 5.17 for improved early-boot seeding
[ ] virtio-rng attached to all KVM/QEMU VMs
[ ] rngd installed and enabled on all VM instances
[ ] TPM available and tpm-seed.service or equivalent configured
[ ] RDRAND not used exclusively (verify: dmesg | grep rdrand)
[ ] Seed files excluded from VM/container image builds
[ ] Applications use getrandom(0) or /dev/urandom — not /dev/random
[ ] entropy_avail monitoring configured in Prometheus/Grafana
[ ] rngtest passes on /dev/urandom and /dev/hwrng (if present)
[ ] Container init waits for pool seeding before cryptographic first-use
```
