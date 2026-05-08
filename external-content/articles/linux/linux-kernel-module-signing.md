---
title: "Linux Kernel Module Signing and Verification"
description: "Unsigned kernel modules are a primary rootkit vector. This guide covers the full module signing infrastructure: CONFIG_MODULE_SIG_FORCE, sign-file, DKMS auto-signing, MOK enrollment, and detecting unsigned modules at runtime."
slug: linux-kernel-module-signing
date: 2026-05-07
lastmod: 2026-05-07
category: linux
tags:
  - kernel-modules
  - module-signing
  - secure-boot
  - kernel-hardening
  - rootkit-prevention
personas:
  - security-engineer
  - platform-engineer
article_number: 483
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/linux/linux-kernel-module-signing/
---

# Linux Kernel Module Signing and Verification

## The Problem

A kernel module is not an application. It is compiled code that executes at ring 0, with the same privileges as the kernel itself. When a module loads, it can register new syscall handlers, intercept existing ones, allocate kernel memory, walk arbitrary kernel data structures, and install hooks that run invisibly before any LSM policy evaluation. There is no boundary, no seccomp filter, no namespace limit that applies to code running at this privilege level. A malicious `.ko` file is not malware running on the operating system — it *is* the operating system.

This is precisely why unsigned module loading remains one of the most reliable rootkit installation paths on unprotected Linux systems:

1. An attacker gains root through any means — credential theft, a container escape, a local privilege escalation CVE.
2. They compile a kernel module (or deliver a pre-compiled one matching the target kernel version from the `uname -r` output they can read without privileges).
3. `insmod malicious.ko` — and the rootkit is resident in the kernel, hiding processes, intercepting syscalls, creating a covert command channel.

Without module signing enforcement, this attack works on any kernel. The only defence is ensuring that `insmod` and `modprobe` refuse to load modules that were not signed by a key the kernel trusts. That is what this article covers.

**Target systems:** Ubuntu 22.04/24.04 LTS, Debian 12, RHEL 9 / Rocky Linux 9. Kernel 5.4+. Most of the configuration applies identically across distributions.

## Threat Model

- **Adversary 1 — Root-level attacker:** Has gained `uid=0` through any escalation path. Wants to install a persistent, kernel-resident backdoor that survives service restarts, hides from userspace monitoring tools, and persists until the next reboot (or longer, with a suitable hook). Without module signing enforcement, this requires only `insmod`.
- **Adversary 2 — Supply chain attacker:** Has compromised a package repository, a build pipeline, or an OCI image layer. Delivers a malicious `.ko` file that gets loaded automatically by a legitimate service (e.g., a falsely-named DKMS package).
- **Adversary 3 — Insider:** A privileged operator loads a "monitoring module" that is actually exfiltrating data or creating a covert channel. Without signature audit trails, there is no artefact proving what was loaded.
- **Access level:** All adversaries have root. Some have physical access.
- **Objective:** Persistent kernel-resident code that evades userspace detection, survives LSM enforcement, and can intercept, hide, or exfiltrate data.
- **Blast radius:** Complete, permanent host compromise. Kernel code that survives a `ps`, a `netstat`, an `auditd` query, and a file integrity check is undetectable without specialised kernel-level forensics.

## Kernel Module Signing Infrastructure

### How the Kernel Verifies Signatures

When a kernel is built with `CONFIG_MODULE_SIG=y`, the build system generates an asymmetric key pair. The private key is used at build time to sign all in-tree modules. The corresponding X.509 certificate (the public key) is embedded directly into the kernel image itself, compiled into the `.rodata` section — it is not a file on disk that an attacker can replace.

At module load time (`insmod`, `modprobe`, `finit_module(2)`), the kernel:

1. Reads the signature appended to the end of the `.ko` file.
2. Identifies the signing certificate by key ID.
3. Looks up the certificate in the kernel's trusted keyring (`/proc/keys`, specifically the `.builtin_trusted_keys` and `.secondary_trusted_keys` keyrings).
4. Verifies the signature over the module contents using the public key.
5. Either permits or denies the load based on the signature result and the enforcement mode.

The signing key pair generated at distro build time is per-kernel-version and is typically discarded after the build — the distro vendor does not retain the private key, making it impossible for an attacker who compromises a live system to re-sign a malicious module as if it were a vendor module.

Check what certificates are trusted by the running kernel:

```bash
# List the kernel's built-in trusted keys
sudo keyctl list %:.builtin_trusted_keys

# List secondary trusted keys (where MOK-enrolled certs appear)
sudo keyctl list %:.secondary_trusted_keys

# Check all keyrings for module signing keys
sudo cat /proc/keys | grep -E "asymmetric|module"
```

### Compile-Time Configuration: What Distros Actually Enable

The relevant kernel config options and their meanings:

```bash
# Check the current kernel's compile-time module signing config
grep -E "CONFIG_MODULE_SIG" /boot/config-$(uname -r)
```

| Config Option | Effect |
|---|---|
| `CONFIG_MODULE_SIG=y` | Build the signing infrastructure. Modules can be signed and signatures will be checked, but unsigned modules still load. |
| `CONFIG_MODULE_SIG_ALL=y` | Sign all in-tree modules at build time using the auto-generated key. |
| `CONFIG_MODULE_SIG_FORCE=y` | Reject any module without a valid, trusted signature. Unsigned modules fail with `EKEYREJECTED`. |
| `CONFIG_MODULE_SIG_SHA256=y` | Use SHA-256 for the signature hash (recommended). |
| `CONFIG_MODULE_SIG_KEY="certs/signing_key.pem"` | Path to the auto-generated key used to sign in-tree modules. |

On **Ubuntu 22.04/24.04**, the stock kernel ships with `CONFIG_MODULE_SIG=y` and `CONFIG_MODULE_SIG_ALL=y` but **not** `CONFIG_MODULE_SIG_FORCE=y`. Unsigned modules load with a warning logged to dmesg. When Secure Boot is active, however, Ubuntu's bootloader chain configures the kernel to behave as if `CONFIG_MODULE_SIG_FORCE=y` were set — the `lockdown=integrity` mode is applied automatically, which includes refusing unsigned modules.

On **RHEL 9 / Rocky Linux 9**, the same pattern applies. Secure Boot enforces module signing; non-Secure-Boot installs warn but permit unsigned loads.

The consequence: **on any system without Secure Boot, unsigned module loading succeeds by default**, even with signing infrastructure present. Hardening requires explicit enforcement regardless of Secure Boot state.

## Enforcement Boot Parameters

Two boot parameters control how the kernel treats unsigned modules at runtime, independent of the compile-time `CONFIG_MODULE_SIG_FORCE` setting:

### `module.sig_enforce=1`

Forces signature enforcement at runtime. Equivalent to having compiled with `CONFIG_MODULE_SIG_FORCE=y`. Any module without a valid signature from a trusted key is rejected.

```bash
# Add to /etc/default/grub:
GRUB_CMDLINE_LINUX="... module.sig_enforce=1"

# Rebuild grub config
sudo update-grub                                    # Ubuntu/Debian
sudo grub2-mkconfig -o /boot/grub2/grub.cfg        # RHEL/Rocky

# Verify after reboot
cat /sys/module/module/parameters/sig_enforce
# 1
```

### `modules_disabled` — Hard Lock After Boot

A complementary control: once `kernel.modules_disabled` is set to `1`, no further modules can be loaded regardless of signature status. This is a one-way ratchet — it cannot be cleared without a reboot.

```bash
# Set after all required modules are loaded (cannot be reversed until reboot)
echo 1 | sudo tee /proc/sys/kernel/modules_disabled

# Verify
cat /proc/sys/kernel/modules_disabled
# 1

# Any subsequent modprobe fails:
sudo modprobe nbd 2>&1
# modprobe: ERROR: could not insert 'nbd': Operation not permitted
```

This is the appropriate endpoint for hardened production systems: boot, load required modules, sign the manifest, then lock the door.

## Signing Out-of-Tree Modules

### The `sign-file` Utility

The Linux kernel source ships a `sign-file` tool that performs the PKCS#7 signature operation over a `.ko` file and appends the result. On Debian-based systems it is available in the `linux-headers` package:

```bash
ls /usr/src/linux-headers-$(uname -r)/scripts/sign-file
```

Usage:

```bash
sign-file <hash-algo> <key-file> <cert-file> <module-file> [<dest-file>]
```

### Generating a Custom Signing Key

For out-of-tree modules (DKMS drivers, custom modules), you need your own signing key pair. The key is typically called a Machine Owner Key (MOK) in the context of Secure Boot enrollment.

```bash
# Create a directory to hold the key material
sudo mkdir -p /etc/kernel/mok
sudo chmod 700 /etc/kernel/mok

# Generate the key pair: 4096-bit RSA, self-signed X.509 certificate
sudo openssl req -new -x509 -newkey rsa:4096 \
  -keyout /etc/kernel/mok/mok.priv \
  -outform DER \
  -out /etc/kernel/mok/mok.der \
  -days 3650 \
  -nodes \
  -subj "/CN=$(hostname -s) DKMS module signing key/"

# Restrict access to the private key — only root reads it
sudo chmod 600 /etc/kernel/mok/mok.priv
sudo chmod 644 /etc/kernel/mok/mok.der

# Verify the certificate
openssl x509 -in /etc/kernel/mok/mok.der -inform DER -text -noout | \
  grep -E "Subject:|Not After|Public Key"
```

### Signing a Module Manually

```bash
# Sign a specific .ko file in place
sudo /usr/src/linux-headers-$(uname -r)/scripts/sign-file \
  sha256 \
  /etc/kernel/mok/mok.priv \
  /etc/kernel/mok/mok.der \
  /path/to/your/module.ko

# Verify the signature was appended
modinfo /path/to/your/module.ko | grep -E "^sig"
# sig_id:         PKCS#7
# signer:         hostname DKMS module signing key
# sig_key:        XX:XX:XX:...
# sig_hashalgo:   sha256
# signature:      ...
```

## DKMS and Automatic Module Signing

DKMS (Dynamic Kernel Module Support) rebuilds out-of-tree modules whenever a new kernel is installed. Without automatic signing configured, every kernel update produces an unsigned module that will fail to load under `sig_enforce=1` — often discovered in production when the system reboots onto the new kernel.

### Configuring `/etc/dkms/framework.conf`

DKMS supports post-build signing via configuration in `/etc/dkms/framework.conf`. The relevant variables:

```bash
# /etc/dkms/framework.conf additions for automatic module signing

# Path to the sign-file script for the current kernel
# (DKMS expands $kernelver automatically)
sign_tool="/usr/src/linux-headers-${kernelver}/scripts/sign-file"

# Hash algorithm to use for signing
sign_algo="sha256"

# Private key for signing
mok_signing_key="/etc/kernel/mok/mok.priv"

# Public certificate for signing
mok_certificate="/etc/kernel/mok/mok.der"
```

With this configuration, DKMS calls `sign-file` automatically after rebuilding a module for a new kernel. Verify it works:

```bash
# Force a DKMS rebuild for a specific module/kernel combination
sudo dkms build -m <module-name> -v <version> -k $(uname -r)

# Check the built module is signed
modinfo /var/lib/dkms/<module-name>/<version>/$(uname -r)/x86_64/module/<name>.ko \
  | grep signer
# signer: hostname DKMS module signing key
```

### Per-Module DKMS Signing Override

Individual DKMS modules can specify signing configuration in their `dkms.conf`:

```bash
# /usr/src/<module>-<version>/dkms.conf
PACKAGE_NAME="my-driver"
PACKAGE_VERSION="1.0"
BUILT_MODULE_NAME[0]="my_driver"
DEST_MODULE_LOCATION[0]="/updates"
AUTOINSTALL="yes"

# Signing configuration (overrides framework.conf for this module)
SIGN_TOOL="/usr/src/linux-headers-${kernelver}/scripts/sign-file"
SIGN_ALGO="sha256"
SIGN_KEY="/etc/kernel/mok/mok.priv"
SIGN_CERT="/etc/kernel/mok/mok.der"
```

## Enrolling Custom Certificates in MOK

Signing a module is not sufficient on its own. The kernel must also trust the certificate used to sign it. On systems with Secure Boot, the UEFI firmware's Secure Boot chain controls which keys are trusted at the kernel level. To add a custom signing certificate, it must be enrolled in the Machine Owner Key (MOK) database.

`mokutil` is the userspace tool for this, shipping as part of the `mokutil` package on all major distros.

```bash
# Import the custom signing certificate into the MOK enrollment queue
sudo mokutil --import /etc/kernel/mok/mok.der

# mokutil will prompt for a one-time enrollment password.
# This password is presented during the next boot in the MOK manager.
# Choose something you can type at the console; you won't need it again.

# Reboot — during boot, the UEFI MOK manager (shim) will appear
# asking to confirm enrollment of the new key.
sudo reboot
```

During reboot, the UEFI shim (the `shim.efi` bootloader component) presents a blue MOK Management screen. Select "Enroll MOK", confirm with the password set above, and the certificate is added to the MOK database persisted in UEFI NVRAM.

After enrollment, verify the kernel sees the certificate as trusted:

```bash
# The MOK database is made available to the kernel as secondary trusted keys
sudo keyctl list %:.secondary_trusted_keys | grep -A1 "DKMS\|$(hostname -s)"

# Or check via mokutil
mokutil --list-enrolled | grep "Subject:"
```

On systems **without Secure Boot** (non-UEFI or Secure Boot disabled), MOK enrollment via the UEFI manager is unavailable. In this case, the certificate can be added directly to the kernel's secondary keyring if `CONFIG_SECONDARY_TRUSTED_KEYRING=y`:

```bash
# Non-Secure-Boot path: add cert directly to running kernel's secondary keyring
# (survives until next reboot; must be re-added or embedded in initramfs)
sudo keyctl padd asymmetric "" %:.secondary_trusted_keys < /etc/kernel/mok/mok.der
```

For persistent enrollment without Secure Boot, the certificate must be embedded in the initramfs or compiled into the kernel with `CONFIG_SYSTEM_TRUSTED_KEYS`.

## Lockdown Mode and Module Signing Interaction

Kernel lockdown mode (the `lockdown` LSM, available since kernel 5.4) interacts directly with module signing in a way that is important to understand:

- `lockdown=integrity` (or higher): unsigned module loading is explicitly blocked, regardless of whether `CONFIG_MODULE_SIG_FORCE` is set at compile time or `module.sig_enforce=1` is set at runtime. This is the Secure Boot enforcement path — when Secure Boot is active and the bootloader establishes `lockdown=integrity`, the kernel refuses unsigned modules as part of its integrity guarantee.
- Without lockdown: `module.sig_enforce=1` is needed to block unsigned loads.

The recommendation for hardened systems:

```bash
# Both parameters together: lockdown blocks unsigned modules AND
# sig_enforce provides defence-in-depth if lockdown is somehow bypassed
GRUB_CMDLINE_LINUX="... lockdown=integrity module.sig_enforce=1"
```

Check the current lockdown state:

```bash
cat /sys/kernel/security/lockdown
# none [integrity] confidentiality   (active mode in brackets)

# A quick functional test: attempt to load an unsigned module
# Compile a trivial module:
cat > /tmp/test_mod.c << 'EOF'
#include <linux/module.h>
MODULE_LICENSE("GPL");
static int __init test_init(void) { return 0; }
static void __exit test_exit(void) {}
module_init(test_init);
module_exit(test_exit);
EOF
# Build and try to load (should fail under sig_enforce or lockdown):
# sudo insmod /tmp/test_mod.ko 2>&1
# insmod: ERROR: could not insert module /tmp/test_mod.ko: Required key not available
```

## Verifying Module Signatures

### Using `modinfo`

```bash
# Check signature information for a loaded or on-disk module
modinfo /lib/modules/$(uname -r)/kernel/drivers/net/tun.ko.zst | grep -E "^sig|^filename"
# filename:       /lib/modules/6.8.0-58-generic/kernel/drivers/net/tun.ko.zst
# sig_id:         PKCS#7
# signer:         Canonical Ltd. Secure Boot Signing (2024)
# sig_key:        XX:XX:XX:XX:...
# sig_hashalgo:   sha256
# signature:      ...

# For a module signed with your own key:
modinfo /path/to/mymodule.ko | grep signer
# signer:         myhostname DKMS module signing key
```

### Checking Loaded Modules via `/sys/module`

```bash
# For each loaded module, sysfs exposes some metadata
# The srcversion is a hash of the module source, useful for tracking
ls /sys/module/tun/
# coresize  holders  initsize  initstate  notes  parameters  refcnt  sections  srcversion  taint  uevent

cat /sys/module/tun/srcversion
# A1B2C3D4E5F6...

# taint flags on the module — important for unsigned detection
cat /sys/module/tun/taint
# (empty = no taints)

# The kernel's overall taint state
cat /proc/sys/kernel/tainted
# 0 = clean
# Bit 13 (value 8192) set = unsigned module was loaded
```

The kernel sets taint bit 13 (`TAINT_UNSIGNED_MODULE`) whenever an unsigned module is loaded. A non-zero `tainted` value after masking for this bit means an unsigned module was loaded at some point since boot.

## Detection: Auditing Loaded Modules

### Checking for Unsigned Modules at Runtime

```bash
#!/bin/bash
# detect-unsigned-modules.sh
# Reports any loaded kernel module that lacks a valid signature.
# Run as root. Exits 1 if unsigned modules are found.

UNSIGNED=0

while read -r modname _rest; do
  modpath=$(modinfo -n "$modname" 2>/dev/null)
  if [[ -z "$modpath" ]]; then
    continue
  fi

  # modinfo exits non-zero and prints nothing for sig fields if unsigned
  signer=$(modinfo "$modpath" 2>/dev/null | awk '/^signer:/{print $2}')
  if [[ -z "$signer" ]]; then
    echo "UNSIGNED: $modname ($modpath)"
    UNSIGNED=$((UNSIGNED + 1))
  fi
done < <(lsmod | tail -n +2)

# Also check kernel taint for unsigned module bit
tainted=$(cat /proc/sys/kernel/tainted)
if (( (tainted & 8192) != 0 )); then
  echo "WARNING: kernel taint bit 13 (TAINT_UNSIGNED_MODULE) is set"
fi

if [[ $UNSIGNED -gt 0 ]]; then
  echo "Total unsigned modules: $UNSIGNED"
  exit 1
fi

echo "All loaded modules are signed."
exit 0
```

```bash
sudo bash detect-unsigned-modules.sh
```

### Continuous Auditing with auditd

```bash
# /etc/audit/rules.d/module-signing.rules
# Log all module load attempts (init_module and finit_module syscalls)
-a always,exit -F arch=b64 -S init_module -S finit_module -k module_load
-a always,exit -F arch=b32 -S init_module -S finit_module -k module_load

# Log module unload attempts
-a always,exit -F arch=b64 -S delete_module -k module_unload
-a always,exit -F arch=b32 -S delete_module -k module_unload
```

```bash
sudo augenrules --load

# Query module load events
sudo ausearch -k module_load -ts today | aureport -f -i

# Watch for signature verification failures in kernel log
sudo journalctl -k --since today | grep -E "module verification failed|Required key not available|PKCS#7"
```

Every module load that fails signature verification produces a kernel log line. Under `sig_enforce=1`, these are hard failures that prevent the load. Without enforcement, they are warnings — but still auditable.

### Comparing Against a Known-Good Baseline

On immutable or predictable infrastructure, compare the loaded module set against a baseline captured at build time:

```bash
# Capture baseline (run once on a known-good system)
lsmod | awk 'NR>1 {print $1}' | sort > /etc/security/module-baseline.txt

# Check at runtime (can be run from a cron job or systemd timer)
lsmod | awk 'NR>1 {print $1}' | sort > /tmp/current-modules.txt
diff /etc/security/module-baseline.txt /tmp/current-modules.txt
# Lines preceded by > are modules loaded that were not in the baseline
# Lines preceded by < are expected modules that are now missing
```

## Expected Behaviour

After full enforcement is configured:

```bash
# Confirm sig_enforce is active
cat /sys/module/module/parameters/sig_enforce
# 1

# Confirm lockdown is active
cat /sys/kernel/security/lockdown
# none [integrity] confidentiality

# Unsigned module load must be rejected
sudo insmod /tmp/unsigned_test.ko 2>&1
# insmod: ERROR: could not insert module /tmp/unsigned_test.ko: Required key not available
sudo dmesg | tail -3
# kernel: unsigned_test: module verification failed: signature and/or required key missing - tainting kernel

# Signed module load must succeed
sudo modinfo /var/lib/dkms/my-driver/1.0/$(uname -r)/x86_64/module/my_driver.ko | grep signer
# signer: myhostname DKMS module signing key
sudo insmod /var/lib/dkms/my-driver/1.0/$(uname -r)/x86_64/module/my_driver.ko
# (no output = success)

# Kernel taint should be zero after only signed loads
cat /proc/sys/kernel/tainted
# 0
```

## Trade-offs

| Control | Benefit | Cost | Mitigation |
|---|---|---|---|
| `module.sig_enforce=1` | Hard blocks unsigned module rootkit installation | Out-of-tree modules (NVIDIA, ZFS, VirtualBox) must be signed before loading | Automate signing in DKMS framework.conf; sign modules in CI before packaging |
| `CONFIG_MODULE_SIG_FORCE=y` at build | Signing enforcement baked into the kernel binary, not bypassable by boot parameter manipulation | Requires a custom kernel build | Use boot-parameter enforcement on stock distro kernels; reserve compile-time enforcement for custom appliance images |
| MOK enrollment via UEFI | Ties trusted signing keys to UEFI NVRAM, which requires physical access to modify | Requires a console session at reboot to confirm enrollment | Automate MOK enrollment pre-deployment; on cloud instances, most hypervisors do not support Secure Boot MOK management — use secondary keyring instead |
| `modules_disabled=1` after boot | No new modules can load, signed or unsigned, once the lock is set | Hot-plug hardware does not get drivers; adding network interfaces requires a reboot | Only appropriate for servers with a fixed hardware profile. Pre-load all needed modules before setting the lock. |
| `lockdown=integrity` | Enforces unsigned module rejection as part of broader kernel integrity guarantee | Breaks kdump, some debug tools, and eBPF memory reads | See the [Kernel Lockdown Mode](/articles/linux/kernel-lockdown/) article for the full compatibility matrix |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| DKMS module not signed after kernel update | Out-of-tree driver fails to load after kernel upgrade | `dmesg` shows "module verification failed"; `dkms status` shows build succeeded but `modinfo` shows no signer | Run `sign-file` manually on the built `.ko`; fix `framework.conf` to auto-sign future builds |
| MOK certificate not enrolled after reboot | Signed module rejected with "Required key not available" | `keyctl list %:.secondary_trusted_keys` does not show your certificate CN | Re-run `mokutil --import`; reboot and confirm enrollment in the MOK manager during boot |
| `sig_enforce=1` boot parameter lost after distro kernel upgrade | New kernel boots without enforcement; `cat /sys/module/module/parameters/sig_enforce` shows `0` | Monitoring script sees parameter absent | Some distro kernel upgrades regenerate GRUB config. Audit `/etc/default/grub` after every kernel package update. Use the systemd unit approach as a defence-in-depth layer. |
| Signing key expires | Module signing fails in CI pipeline; deployed modules rejected at runtime | CI pipeline error on `sign-file`; kernel log shows certificate expired | Generate a new key pair, re-enroll in MOK, re-sign all DKMS modules, roll out with kernel-package update cycle |
| Private key compromised | An attacker can sign malicious modules as trusted | No automated runtime detection (signature checks pass) | Revoke the certificate via `mokutil --delete`, remove from secondary keyring, re-deploy with a new key. Consider OCSP or CRL if operating at scale. |
| modules_disabled set before needed modules load | System boots but lacks network, storage, or other hardware drivers | Emergency shell at boot; `dmesg` shows missing drivers | Reboot, edit GRUB to set `init=/bin/bash`, disable the `lock-modules.service`, fix module pre-loading order |

## Related Articles

- [Kernel Lockdown Mode: Blocking Root from Modifying the Running Kernel](/articles/linux/kernel-lockdown/)
- [Linux Kernel Module Loading: Restricting What Loads on Your System](/articles/linux/kernel-module-hardening/)
- [GRUB Boot Hardening for Production Linux Systems](/articles/linux/grub-boot-hardening/)
- [dm-verity: Block-Level Integrity Verification for Read-Only Filesystems](/articles/linux/dm-verity/)
- [auditd Deep Dive: Kernel-Level Event Logging for Security Operations](/articles/linux/auditd-deep-dive/)
