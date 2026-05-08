---
title: "Kernel Module Hardening: Blacklisting, Signing, and Preventing Runtime Loading"
description: "The Linux kernel loads modules on demand. When a process requests a capability that is not built into the running kernel (a filesystem type, a..."
slug: "kernel-module-hardening"
date: 2026-01-28
lastmod: 2026-01-28
category: "linux"
tags: ["kernel-modules", "modprobe", "module-signing", "hardening", "linux"]
personas: ["systems-engineer", "security-engineer"]
article_number: 14
difficulty: "intermediate"
estimated_reading_time: 13
provider_bridges:
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
published: true
layout: article.njk
permalink: "/articles/linux/kernel-module-hardening/index.html"
---

# Kernel Module Hardening: Blacklisting, Signing, and Preventing Runtime Loading

## Problem

The Linux kernel loads modules on demand. When a process requests a capability that is not built into the running kernel (a filesystem type, a network protocol, a hardware driver), the kernel automatically loads the corresponding module. This is convenient, but it means the kernel attack surface extends far beyond what is actually in use:

- USB storage modules (`usb-storage`, `uas`) allow data exfiltration via physical access. On a server, USB storage is almost never legitimate.
- Firewire and Thunderbolt modules (`firewire-core`, `thunderbolt`) enable DMA attacks where a physically connected device can read and write arbitrary host memory.
- Unused filesystem modules (`cramfs`, `freevxfs`, `jffs2`, `hfs`, `hfsplus`, `udf`) have had multiple privilege escalation vulnerabilities. If the module is loaded, a malicious filesystem image can trigger kernel code that has not been audited for the current threat landscape.
- Network protocol modules (`sctp`, `dccp`, `tipc`, `rds`) expand the network attack surface. If a protocol module is loaded, the host accepts traffic for that protocol even if no application uses it.
- Bluetooth modules create an entire wireless attack surface on servers that have no Bluetooth hardware or use case.

Every loaded module is kernel code running with full privileges. A vulnerability in any loaded module is a direct path to kernel compromise. The principle of least privilege demands that only modules required for the host's function should be loadable.

**Target systems:** Ubuntu 24.04 LTS, Debian 12, RHEL 9 / Rocky Linux 9, kernel 5.15+.

## Threat Model

- **Adversary:** Attacker with local unprivileged access (compromised application, SSH with stolen credentials) attempting to trigger kernel module loading to exploit a vulnerability in the module code. Or: attacker with physical access using Firewire/Thunderbolt DMA attacks or USB-based exploits.
- **Access level:** Unprivileged local user (for triggering auto-load of vulnerable modules), or physical access (for DMA and USB attacks).
- **Objective:** Privilege escalation through a kernel module vulnerability, data exfiltration via USB storage, or direct memory access via Firewire/Thunderbolt.
- **Blast radius:** Complete host compromise. Kernel module vulnerabilities give the attacker ring-0 access.

## Configuration

### Blacklisting Unnecessary Modules

The `blacklist` directive in modprobe prevents automatic loading but still allows manual loading with `modprobe`. The `install <module> /bin/true` pattern prevents loading entirely by redirecting the load request to a no-op command.

Create `/etc/modprobe.d/blacklist-hardening.conf`:

```bash
# /etc/modprobe.d/blacklist-hardening.conf
# Prevent loading of unnecessary kernel modules
# Using "install /bin/true" instead of "blacklist" because blacklist
# only prevents auto-loading, not explicit loading.

# --- USB storage ---
# Prevents USB mass storage devices from being usable.
# Remove these lines if the host legitimately uses USB storage.
install usb-storage /bin/true
install uas /bin/true

# --- Firewire ---
# Firewire allows DMA (Direct Memory Access) from connected devices.
# A malicious Firewire device can read/write host memory directly.
install firewire-core /bin/true
install firewire-ohci /bin/true
install firewire-sbp2 /bin/true

# --- Thunderbolt ---
# Thunderbolt also allows DMA. Relevant for laptops and workstations
# that might be connected to untrusted docking stations.
install thunderbolt /bin/true

# --- Bluetooth ---
# No legitimate use case for Bluetooth on servers.
install bluetooth /bin/true
install btusb /bin/true

# --- Unused filesystems ---
# These filesystem modules have had CVEs and are rarely needed on servers.
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true

# --- Uncommon network protocols ---
# These protocols are rarely used and have had vulnerabilities.
# Only blacklist if your applications do not use these protocols.
install sctp /bin/true
install dccp /bin/true
install tipc /bin/true
install rds /bin/true

# --- Misc ---
# vivid: virtual video test driver, has had privilege escalation CVEs
install vivid /bin/true
```

After creating the file, regenerate the initramfs to ensure blacklists are honoured during early boot:

```bash
# Ubuntu/Debian
sudo update-initramfs -u

# RHEL/Rocky
sudo dracut --force
```

### Verifying Blacklists Are Active

```bash
# Attempt to load a blacklisted module
sudo modprobe usb-storage
# Expected: no error, but the module is NOT loaded (redirected to /bin/true)

# Verify the module is not loaded
lsmod | grep usb_storage
# Expected: no output

# Check what happens when the module is requested
modprobe -n -v usb-storage
# Expected output: install /bin/true

# List all currently loaded modules
lsmod | wc -l
# Compare before and after blacklisting to see the reduction
```

### Kernel Module Signing

Module signing ensures that only modules signed with a trusted key can be loaded. This prevents an attacker with root access from loading a malicious module.

Check current signing configuration:

```bash
# Check if module signing is enabled
grep CONFIG_MODULE_SIG /boot/config-$(uname -r)
# CONFIG_MODULE_SIG=y           (signing infrastructure enabled)
# CONFIG_MODULE_SIG_FORCE=y     (only signed modules can load - if set)

# Check if Secure Boot is enforcing module signatures
mokutil --sb-state
```

When `CONFIG_MODULE_SIG_FORCE` is set (or when Secure Boot is active and the kernel enforces it), only modules signed with a key enrolled in the kernel's keyring can be loaded.

Sign a custom module with your Machine Owner Key:

```bash
# Generate a signing key (if you don't have one from Secure Boot setup)
openssl req -new -x509 -newkey rsa:2048 -keyout signing_key.priv \
    -outform DER -out signing_key.der -nodes -days 36500 \
    -subj "/CN=Module Signing Key/"

# Sign a module
/usr/src/linux-headers-$(uname -r)/scripts/sign-file \
    sha256 signing_key.priv signing_key.der /path/to/module.ko

# Verify the signature
modinfo /path/to/module.ko | grep "^sig"
# sig_id: ...
# signer: Module Signing Key
# sig_key: ...
```

### Preventing All Runtime Module Loading

The most aggressive hardening option is to prevent any module from loading after boot. This is done with a sysctl that, once set, cannot be unset without rebooting:

```bash
# WARNING: This is irreversible until reboot.
# Once set, NO modules can be loaded, including legitimate drivers.
# All required modules must already be loaded before setting this.

# Set via sysctl (takes effect immediately, cannot be reversed)
echo 1 | sudo tee /proc/sys/kernel/modules_disabled
```

To apply this automatically after boot, create a [systemd](https://systemd.io) service that runs after all other services have started:

```ini
# /etc/systemd/system/lock-modules.service
[Unit]
Description=Disable kernel module loading after boot
After=multi-user.target
# Run after all normal services have started and loaded their modules

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo 1 > /proc/sys/kernel/modules_disabled'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable lock-modules.service
```

**Do not set `kernel.modules_disabled=1` in `/etc/sysctl.conf`.** If you do, it takes effect during early boot before many drivers have loaded, potentially making the system unbootable (no network, no storage, no display).

### Monitoring for Unexpected Module Loads

Use [auditd](https://github.com/linux-audit/audit-userspace) to log every module load attempt:

```bash
# /etc/audit/rules.d/modules.rules
# Log all module load attempts
-a always,exit -F arch=b64 -S init_module -S finit_module -k module_load
-a always,exit -F arch=b32 -S init_module -S finit_module -k module_load

# Log module unload attempts
-a always,exit -F arch=b64 -S delete_module -k module_unload
-a always,exit -F arch=b32 -S delete_module -k module_unload
```

```bash
# Reload audit rules
sudo augenrules --load

# Search for module load events
sudo ausearch -k module_load -ts recent
```

### Quick Reference: Modules to Blacklist by Server Role

| Server Role | Safe to Blacklist |
|-------------|------------------|
| Web server | usb-storage, firewire-*, thunderbolt, bluetooth, all unused filesystems, sctp, dccp, tipc, rds, vivid |
| Database server | Same as web server |
| [Kubernetes](https://kubernetes.io) node | Same as web server, but check if any CNI plugin needs sctp |
| File server (NFS/Samba) | firewire-*, thunderbolt, bluetooth, dccp, tipc, rds, vivid. Keep filesystem modules as needed. |
| Laptop/workstation | firewire-*, cramfs, freevxfs, jffs2, sctp, dccp, tipc, rds, vivid. Keep USB, Bluetooth, Thunderbolt if needed. |

## Expected Behaviour

After applying module blacklists:

- `modprobe usb-storage` silently succeeds (redirected to `/bin/true`) but the module is not loaded
- `lsmod | grep usb_storage` returns no output
- `modprobe -n -v cramfs` shows `install /bin/true`
- Plugging in a USB drive on a server produces no `/dev/sd*` device (the driver is not loaded)
- All system services start normally (SSH, web server, database, container runtime)
- `ausearch -k module_load` shows audit entries for any module load attempts
- After `modules_disabled=1` is set, any `modprobe` call returns "Operation not permitted"

## Trade-offs

| Control | Benefit | Cost | Mitigation |
|---------|---------|------|------------|
| Blacklisting USB storage | Prevents USB-based data exfiltration and USB exploit delivery | Cannot use USB drives for data transfer or backup | Use network-based transfer methods. For emergency recovery, boot from rescue media where the blacklist is not active. |
| Blacklisting Firewire/Thunderbolt | Prevents DMA attacks from connected devices | Cannot use Thunderbolt docks, displays, or storage on the affected host | Only relevant for servers. Workstations and laptops may need Thunderbolt. |
| Blacklisting filesystem modules | Reduces kernel attack surface from rarely-used filesystem code | Cannot mount media formatted with those filesystems | If you need to read a UDF disc or HFS+ drive, temporarily load the module: remove the blacklist line, load the module, use it, and re-blacklist. |
| `modules_disabled=1` | No new kernel code can be loaded after boot, even by root | Any driver or module needed after the lock point cannot be loaded. Hot-plugging new hardware will not work. Adding a new network interface requires a reboot. | Ensure all needed modules are loaded before the lock. Test thoroughly. Only use on servers with stable, known hardware configurations. |
| Module signing enforcement | Only trusted modules can load | Third-party modules (NVIDIA, ZFS, VirtualBox) must be signed. DKMS modules need re-signing after every kernel update. | Automate signing with post-kernel-install hooks. Use the MOK (Machine Owner Key) enrollment process. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Blacklisted module needed by application | Hardware device does not work. Application that depends on a kernel feature fails to start. | `dmesg` shows the module was requested but not loaded. Application logs show device-related errors. | Remove the specific `install /bin/true` line from the blacklist file. Run `sudo depmod -a` and then `sudo modprobe <module>`. |
| `modules_disabled=1` set too early | System partially boots but lacks network, storage, or display drivers | System is unresponsive or drops to emergency shell. Console shows missing driver messages. | Reboot. Edit the GRUB boot parameters to add `init=/bin/bash` (requires GRUB password if set). Remove or disable the `lock-modules.service`. Reboot normally. |
| Unsigned module rejected by signing enforcement | `modprobe` fails with "Required key not available" | `dmesg` shows "module verification failed: signature and/or required key missing" | Sign the module with your MOK key using `sign-file`. If urgent, temporarily boot with `module.sig_enforce=0` (reduces security). |
| DKMS module not signed after kernel update | Third-party driver (NVIDIA GPU, ZFS) stops working after kernel update | `dkms status` shows module built but not loaded. `modinfo` shows no signature. | Run `sign-file` on the DKMS-built module. Add automatic signing to your DKMS configuration or a post-kernel-install hook script. |
| Audit log volume from module monitoring | auditd fills disk with module load events during boot | `/var/log/audit/audit.log` grows rapidly. `aureport` shows thousands of module_load events at boot time. | The boot-time volume is normal. Set `max_log_file` and `max_log_file_action` in `auditd.conf` to manage rotation. The steady-state volume after boot should be near zero. |

## When to Consider a Managed Alternative

**Transition point:** Kernel module management is primarily relevant for bare metal servers and self-managed VMs. If your workloads run in containers on managed infrastructure, the provider handles the node kernel configuration.

**What managed providers handle:**

Managed Kubernetes providers configure node kernels with appropriate module sets for container workloads. You do not need to manage module blacklists on nodes you do not control.

Runtime security platforms ([Sysdig](https://sysdig.com), [Falco](https://falco.org)) detect unexpected module loads at runtime. If a module that should not be loaded appears on a host, these tools generate an alert. This is particularly useful for detecting rootkit installation, which often involves loading a custom kernel module.

**What you still control:** On self-managed infrastructure, module blacklisting and signing are your responsibility. The configurations in this article are directly applicable to bare metal servers, self-managed VMs, and Kubernetes nodes that you provision yourself.

**Automation path:** For fleet-wide module hardening, use the blacklist configuration from this article in your configuration management tool. The [Ansible](https://www.ansible.com) playbook for kernel module lockdown applies the blacklist, regenerates the initramfs, and verifies that blacklisted modules cannot be loaded, all with a staged rollout to prevent fleet-wide breakage from an overly aggressive blacklist.


## Related Articles

- [Hardening the Linux Kernel Attack Surface with sysctl and Boot Parameters](/articles/linux/sysctl-kernel-hardening/)
- [systemd Unit Hardening: ProtectSystem, PrivateTmp, and the Full Sandbox Toolkit](/articles/linux/systemd-unit-hardening/)
- [Filesystem Mount Options That Matter: noexec, nosuid, nodev, and Beyond](/articles/linux/filesystem-mount-options/)
- [Hardening /proc and /sys: Restricting Kernel Information Disclosure](/articles/linux/proc-sys-hardening/)
- [Time Synchronization Security: Hardening NTP and Chrony Against Manipulation](/articles/linux/time-sync-security/)
