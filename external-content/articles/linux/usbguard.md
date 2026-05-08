---
title: "USBGuard: USB Device Authorization on Production Linux Hosts"
description: "USB devices are a peripheral attack surface most servers ignore. USBGuard provides allowlist-based authorization, blocking BadUSB and malicious-cable threats."
slug: "usbguard"
date: 2026-04-29
lastmod: 2026-04-29
category: "linux"
tags: ["usbguard", "usb", "linux", "device-control", "badusb"]
personas: ["systems-engineer", "security-engineer", "platform-engineer"]
article_number: 223
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/linux/usbguard/index.html"
---

# USBGuard: USB Device Authorization on Production Linux Hosts

## Problem

Most production Linux hosts default-trust every USB device. The kernel sees a new device, asks the bus to enumerate it, then loads any driver that matches the device's claimed VID/PID. A malicious USB device — BadUSB-class HID injectors, mass-storage devices that auto-mount, ethernet adapters that spoof DHCP — can attack a host within seconds of being plugged in.

Server fleets aren't immune just because they're in datacenters. Threat scenarios:

- **Insider plugging in a USB stick** to exfiltrate data or deliver malware.
- **Janitor/cleaner with physical access** plugging in a "lost" drive.
- **Vendor technicians performing maintenance** with potentially-compromised tools.
- **Malicious hardware in supply chain** — replacement components with USB connections.
- **HID-injection attacks** (Rubber Ducky, Bash Bunny) that type commands faster than humans can react.

The kernel-level defense is USBGuard: a userspace daemon that intercepts USB device authorization requests and applies an allowlist policy before the kernel binds the device. Authorized devices work normally; unauthorized devices stay unauthorized — drivers don't load, mount events don't fire, HID inputs don't reach the console.

By 2026 USBGuard ships in most distributions (Ubuntu, RHEL, Debian, Fedora, Arch). Production adoption is uneven; the typical reaction is "we have physical security, we don't need it." Physical security defends against opportunistic attackers; USBGuard defends against sophisticated and trusted-but-compromised actors.

The specific gaps in default Linux:

- New USB devices auto-authorize and bind to drivers.
- USB mass-storage devices auto-mount via udisks2 or systemd.
- HID devices (keyboards, mice) immediately accept input.
- Network interfaces brought up by USB ethernet/WiFi adapters appear automatically.
- Audit log of USB events exists but is not gated.

This article covers USBGuard installation, policy design (deny-by-default with allowlisted device IDs / serial numbers), integration with udev and systemd, audit logging, and the operational patterns for laptops vs. servers vs. specialized devices (KVM-attached USB-passthrough, USB-printer servers).

**Target systems:** USBGuard 1.1+, Linux kernel with `CONFIG_USB`, systemd-based distros. Compatible with Ubuntu 22.04+, RHEL 9+, Debian 12+, Fedora 38+.

## Threat Model

- **Adversary 1 — Physical access attacker (drop attack):** plugs in a USB device while no one is watching. Wants the device to execute or exfiltrate without triggering alerts.
- **Adversary 2 — Insider with maintenance access:** has legitimate physical access; uses USB to exfiltrate data or deploy malware.
- **Adversary 3 — Compromised cable:** USB-C cable with embedded electronics (O.MG cable) types commands or hijacks data.
- **Adversary 4 — Replacement-component attacker:** a piece of hardware that comes with USB connections (KVM extender, replacement keyboard) is malicious.
- **Adversary 5 — HID injection:** plug-in device pretending to be a keyboard, types commands faster than humans react.
- **Access level:** all adversaries have physical-access capability for a brief window. None have prior credentials.
- **Objective:** Execute commands on the host; mount filesystems for read/write; capture HID input; extract host data.
- **Blast radius:** Without USBGuard, plugging in a malicious device equals immediate code execution at root or user level. With USBGuard, device cannot authorize without explicit allowlist match; alerts fire on attempts.

## Configuration

### Step 1: Install and Initial Setup

```bash
# Debian / Ubuntu.
sudo apt install usbguard

# RHEL / Rocky.
sudo dnf install usbguard

# Generate initial policy from currently-attached devices (the "trusted" baseline).
sudo usbguard generate-policy > /etc/usbguard/rules.conf
sudo chmod 600 /etc/usbguard/rules.conf

# Start the daemon.
sudo systemctl enable --now usbguard
```

The generated policy contains explicit `allow id ...` rules for every currently-attached device (keyboards, root hubs, internal devices). Inspect:

```bash
sudo cat /etc/usbguard/rules.conf
# allow id 1d6b:0002 serial "0000:00:14.0" name "xHCI Host Controller" ...
# allow id 04f2:b7c8 serial "" name "USB2.0 HD UVC WebCam" ...
# allow id 8087:0024 serial "" name "Integrated Hub" ...
```

Each rule pins on USB vendor ID + product ID, optionally serial number, optionally device name. Internal devices (root hubs, integrated peripherals) are typically pinned by serial.

### Step 2: Set Default Policy

The `RuleSet` config decides what happens to unmatched devices. The hard mode for production:

```ini
# /etc/usbguard/usbguard-daemon.conf
RuleFolder=/etc/usbguard/rules.d/
RuleFile=/etc/usbguard/rules.conf
ImplicitPolicyTarget=block
PresentDevicePolicy=apply-policy
PresentControllerPolicy=keep
InsertedDevicePolicy=apply-policy
RestoreControllerDeviceState=false
DeviceManagerBackend=uevent
IPCAllowedUsers=root
IPCAllowedGroups=plugdev
IPCAccessControlFiles=/etc/usbguard/IPCAccessControl.d/
DeviceRulesWithPort=false
AuthorizedDefault=none
```

`ImplicitPolicyTarget=block` defaults to denying everything not explicitly allowed. `AuthorizedDefault=none` ensures even the kernel default authorization is overridden.

For a more lenient initial deployment (allow-by-default with logging while you build the allowlist):

```ini
ImplicitPolicyTarget=allow   # less safe; use only during baseline-building
```

Run in `allow` mode for 1-2 weeks while building the explicit allowlist; switch to `block`.

### Step 3: Server-Specific Policy

For servers in datacenters, the typical legitimate USB devices are:

- iLO / BMC USB ports (out-of-band management).
- KVM-over-USB switches.
- The internal disk's USB-attached management interface (rare).

```ini
# /etc/usbguard/rules.conf for a typical server.

# Allow internal root hubs (always).
allow id 1d6b:0002 with-interface 09:*:*  # USB 2.0 hub
allow id 1d6b:0003 with-interface 09:*:*  # USB 3.0 hub

# Allow specific iLO management.
allow id 03f0:7029 name "HP iLO Virtual USB" with-interface { 03:00:00 08:06:50 }

# Block everything else.
block id *:* with-interface { 03:01:01 }   # explicitly block HID keyboards
block id *:* with-interface { 03:01:02 }   # block HID mice
block id *:* with-interface { 08:*:* }     # block mass storage
block id *:* with-interface { 02:02:00 }   # block USB-CDC modems
```

Servers should never need a USB keyboard or mouse plugged in during normal operation. Block at this layer; allow only via explicit operator action (covered below).

### Step 4: Operator-Workstation Policy

Workstations / laptops have legitimate USB use. The pattern: allow specific known devices by serial, ask for explicit authorization on new devices.

```ini
# Trusted: my company's allowlisted YubiKey, by serial.
allow id 1050:0407 serial "1234567" name "YubiKey 5 NFC"

# Block everything else; manual authorize via usbguard CLI.
```

Operator inserts a new device:

```bash
sudo usbguard list-devices
# 19: block id 1050:0407 serial "8901234" name "YubiKey 5 NFC" ...

# Manually authorize for this session only.
sudo usbguard allow-device 19

# Or persistently.
sudo usbguard allow-device --permanent 19
```

For more frictionless UX, USBGuard ships a Qt UI applet that pops up on insert.

### Step 5: Per-Interface Allowlisting (HID Mitigation)

The strongest BadUSB mitigation: allow-list at the USB interface level rather than device level. A device claims to be a flash drive (interface class 08 mass storage) but secretly also has interface class 03 (HID keyboard). With device-level allow:

```
allow id 0781:5530 name "Cruzer Glide"
```

The whole device is authorized — including the secret keyboard interface.

With interface-level allow:

```
allow id 0781:5530 with-interface 08:06:50   # only the mass-storage interface
```

The device's secret keyboard interface remains blocked. The mass-storage interface works. This is the structural defense against BadUSB-class attacks.

For the kernel to enforce per-interface authorization, ensure:

```bash
echo '0' | sudo tee /sys/bus/usb/drivers/usb/authorized_default
```

(USBGuard handles this automatically when configured correctly.)

### Step 6: Auditing and Alerts

USBGuard logs every event:

```bash
sudo journalctl -u usbguard -f
# usbguard[1234]: USB device blocked: id=0781:5530 serial=12345 hash=...
```

Forward to your SIEM. Detection rules:

- New device blocked from a specific source — alert (possible drop-in attack).
- New device allowed by serial without explicit authorization — alert (rule too broad).
- Manual `usbguard allow-device` invoked — log; review correlation with operational tickets.

For per-host alerting:

```yaml
# Falco rule (or your-detection-engine equivalent).
- rule: USB device blocked on production server
  desc: USBGuard blocked an unexpected USB device
  condition: process_name=usbguard and event.payload contains "blocked"
  output: "USBGuard blocked device %device_id on %hostname (severity: medium)"
  priority: WARNING
  tags: [usb, physical-attack]
```

### Step 7: Centralized Policy Distribution

For fleets, distribute USBGuard policy via configuration management (Ansible, Salt, Puppet):

```yaml
# Ansible role excerpt.
- name: Install USBGuard
  apt:
    name: usbguard
    state: present

- name: Deploy USBGuard policy
  template:
    src: usbguard-rules.conf.j2
    dest: /etc/usbguard/rules.conf
    owner: root
    mode: '0600'
  notify: restart usbguard

- name: Set USBGuard daemon config
  template:
    src: usbguard-daemon.conf.j2
    dest: /etc/usbguard/usbguard-daemon.conf
  notify: restart usbguard
```

Different host classes (servers, workstations, build machines) get different policies via Ansible host vars or per-host inventory groups.

### Step 8: KVM / Out-of-Band Considerations

USB-passthrough KVM systems present USB devices that the host treats as locally-attached. Some servers expose iLO/BMC's "virtual media" as USB. The policy must allowlist these by their specific VID/PID:

```ini
# HP iLO virtual media.
allow id 03f0:7029 name "HP iLO Virtual USB"

# Dell iDRAC virtual media.
allow id 0413:6122 name "Dell iDRAC Virtual USB"

# KVM-over-IP devices' emulated USB.
allow id 18ba:0018 name "Aten KVM USB Composite"
```

Test before deploying widely; out-of-band tools may use multiple VID/PIDs across firmware versions.

## Expected Behaviour

| Signal | Without USBGuard | With USBGuard |
|--------|--------------------|----------------|
| Plug in USB stick | Auto-mount; auto-authorize | Blocked; log entry; alert |
| BadUSB HID-injection device | Types commands at console | Keyboard interface blocked; mass-storage allowed if it claims to be one |
| O.MG cable | Captures keystrokes / types commands | Cable's HID interface blocked |
| Vendor-spoofed USB ethernet | Auto-loads; brings up interface | Blocked unless explicitly allowed |
| Plug in operator's authorized YubiKey | Works | Works (allowlisted by serial) |
| Audit trail | None / kernel log only | Structured per-event log with disposition |

Verify the protection holds:

```bash
# Plug in an unknown USB device.
sudo journalctl -u usbguard -n 5
# usbguard[1234]: USB device blocked: id=09da:0018 serial="..." name="..."

# Confirm the device is not authorized.
ls /dev/disk/by-id/usb-* 2>/dev/null
# (no output if mass storage was blocked)
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Block-by-default policy | Strongest default | Operators frustrated by friction | Per-host-class policies; lab / workstation more permissive than production. |
| Per-interface allowlisting | Defeats BadUSB | More complex policy syntax | Use the `with-interface` clause for sensitive devices. |
| Serial-number allowlist | Specific to known good devices | Replacing devices requires policy update | Standardize on specific device models; enrolled per ID. |
| Permanent vs. session authorization | Session-only is safer | UX friction for operators | UI applet for workstation use; CLI for servers. |
| Centralized policy distribution | Fleet uniformity | Configuration management overhead | Standard pattern; reuse existing CM. |
| Audit pipeline integration | Full visibility | Log volume | Modest; one event per insertion. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Policy too restrictive | Legitimate device blocked | Operator reports; usbguard log shows block | Add device to policy; for server fleet, distribute via CM. |
| iLO / BMC virtual media blocked | Out-of-band rescue fails | Cannot mount ISO via virtual media | Allow specific iLO/BMC virtual-USB IDs explicitly; test before fleet rollout. |
| Operator bypasses with `allow-device` for non-emergency | Drift toward looser policy | Audit log shows manual authorizations | Quarterly review of `allow-device` usage; tighten policy to legitimate cases. |
| Internal device misidentified, blocked | Server hangs at boot waiting for blocked device | Console logs / iLO console | Boot to single-user; disable usbguard (`systemctl mask usbguard`); fix policy; re-enable. |
| HID-injection in time window before usbguard active | Brief window during boot when USB is auto-authorized | Hard to detect once damage done | Use `usb-storage` and `hid-generic` driver blacklisting at initramfs; only allow via usbguard after start. |
| Daemon crash | New devices unauthorized; existing keep state | systemd / log monitoring | systemd auto-restarts; verify with monitoring. |
| Policy rules out-of-date as devices change | Blocks legitimate replacement device | Operator reports | Tag policy with last-updated date; review on hardware refresh. |

## Related Articles

- [GRUB Boot Hardening for Production Linux Systems](/articles/linux/grub-boot-hardening/)
- [Kernel Lockdown Mode](/articles/linux/kernel-lockdown/)
- [eBPF-LSM (lsm_bpf)](/articles/linux/ebpf-lsm/)
- [Hardening the Linux Kernel Attack Surface with sysctl](/articles/linux/sysctl-kernel-hardening/)
- [auditd Deep Dive](/articles/linux/auditd-deep-dive/)
