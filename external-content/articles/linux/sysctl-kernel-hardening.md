---
title: "Hardening the Linux Kernel Attack Surface with sysctl and Boot Parameters"
description: "Linux kernels ship with defaults optimised for compatibility, not security. On a stock Ubuntu 24.04 or RHEL 9 installation."
slug: "sysctl-kernel-hardening"
date: 2026-04-08
lastmod: 2026-04-08
category: "linux"
tags: ["sysctl", "kernel", "hardening", "linux", "network-stack", "memory-protection"]
personas: ["systems-engineer", "sre"]
article_number: 1
difficulty: "intermediate"
estimated_reading_time: 18
provider_bridges:
  - name: "Civo"
    id: 22
    category: "managed-kubernetes"
  - name: "DigitalOcean"
    id: 21
    category: "managed-kubernetes"
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
premium_pack: "ansible-hardening-playbooks"
published: true
layout: article.njk
permalink: "/articles/linux/sysctl-kernel-hardening/index.html"
---

# Hardening the Linux Kernel Attack Surface with sysctl and Boot Parameters

## Problem

Linux kernels ship with defaults optimised for compatibility, not security. On a stock Ubuntu 24.04 or RHEL 9 installation:

- The network stack accepts ICMP redirects, allowing an attacker on the same network segment to reroute traffic through a host they control.
- Source routing is enabled, letting an attacker specify the path a packet takes through the network, bypassing firewall rules.
- SYN flood protections are enabled by default on most modern distributions, but other network hardening parameters are not.
- Kernel pointers are exposed to unprivileged users through `/proc/kallsyms`, providing the exact memory layout needed to bypass KASLR.
- `dmesg` is readable by all users, leaking kernel addresses, hardware details, and driver information useful for targeted exploitation.
- Memory protections like `init_on_alloc` and `init_on_free` are disabled, leaving freed memory contents accessible to subsequent allocations.

These defaults persist in production because administrators either do not know which parameters to change, fear breaking running services, or cannot find a single reference that covers the settings, their costs, and their failure modes in one place.

This article is that reference.

**Target systems:** Ubuntu 24.04 LTS, Debian 12, RHEL 9 / Rocky Linux 9, and any kernel 5.15+.

## Threat Model

- **Adversary:** Network-adjacent attacker who can send packets to the host (e.g., shared VPC, compromised neighbour), or unprivileged local user with shell access via a compromised application (e.g., RCE in a web service, compromised dependency).
- **Access level:** Network access to exposed services, or unprivileged shell on the host.
- **Objective:** Reconnaissance (kernel pointer leaks for KASLR bypass, hardware fingerprinting via `dmesg`), network manipulation (SYN floods, IP spoofing, ICMP redirect for traffic interception), or privilege escalation (leveraging weak memory protections, exploiting use-after-free bugs with uninitialised memory).
- **Blast radius:** Single host compromise. On [Kubernetes](https://kubernetes.io) nodes, a compromised host means access to all pods on that node, kubelet credentials, and potentially the ability to move laterally to other nodes.

## Configuration

### Network Stack Hardening

These settings harden the IPv4 and IPv6 network stack against spoofing, redirect attacks, and flood-based denial of service.

Create `/etc/sysctl.d/60-net-hardening.conf`:

```ini
# /etc/sysctl.d/60-net-hardening.conf
# Network stack hardening for production systems
# Target: Ubuntu 24.04 LTS, RHEL 9, Debian 12, kernel 5.15+

# --- IPv4: Anti-spoofing ---
# Strict reverse path filtering. Drops packets where the source address
# would not be routable back through the interface they arrived on.
# Use =2 (loose mode) only if this host has asymmetric routing.
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# --- IPv4: Disable source routing ---
# Source-routed packets let the sender specify the route, bypassing
# your network topology and potentially your firewall rules.
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# --- IPv4: ICMP redirect prevention ---
# Accepting redirects allows a network neighbour to change your routing table.
# Sending redirects can leak your routing topology.
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# --- IPv4: Logging and flood protection ---
# Log packets with impossible source addresses (spoofed, martian).
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# SYN flood protection. Enabled by default on most modern kernels,
# but set explicitly to ensure it is not disabled.
net.ipv4.tcp_syncookies = 1

# TCP timestamps are REQUIRED for SYN cookies to work. Many hardening
# guides incorrectly recommend disabling timestamps. Do not disable them.
net.ipv4.tcp_timestamps = 1

# Ignore ICMP echo requests sent to broadcast addresses (Smurf attack prevention).
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses.
net.ipv4.icmp_ignore_bogus_error_responses = 1

# --- IPv6: Hardening ---
# Disable ICMP redirects for IPv6.
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable IPv6 source routing.
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Disable Router Advertisement acceptance on servers.
# WARNING: Only set this on hosts with static IPv6 configuration.
# Hosts relying on SLAAC for IPv6 addressing will lose connectivity.
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
```

**Why `tcp_timestamps = 1` must stay enabled:** A common misconception in older hardening guides is that TCP timestamps leak uptime information and should be disabled. This is wrong for two reasons: (1) The information leakage is minimal and easily obtained through other means. (2) SYN cookies (`tcp_syncookies`) require TCP timestamps to function. Disabling timestamps disables your SYN flood protection. Keep timestamps enabled.

### Memory and Kernel Protections

These settings restrict access to kernel internals and harden memory management against exploitation.

Create `/etc/sysctl.d/60-kernel-hardening.conf`:

```ini
# /etc/sysctl.d/60-kernel-hardening.conf
# Kernel memory and information disclosure protections
# Target: Ubuntu 24.04 LTS, RHEL 9, Debian 12, kernel 5.15+

# --- Address Space Layout Randomisation ---
# 2 = full randomisation (stack, VDSO, shared libraries, mmap, heap).
# This is the default on most modern kernels. Set explicitly to prevent regression.
kernel.randomize_va_space = 2

# --- Kernel pointer restriction ---
# 0 = pointers visible to all users (default on some distros)
# 1 = pointers hidden from non-privileged users
# 2 = pointers hidden from all users including root
# Use 2 for production. Use 1 if monitoring tools need kernel pointers.
kernel.kptr_restrict = 2

# --- Restrict dmesg access ---
# Prevents unprivileged users from reading kernel ring buffer.
# dmesg contains kernel addresses, hardware info, and driver details.
kernel.dmesg_restrict = 1

# --- Restrict perf_event access ---
# 3 = disallow all perf event access for unprivileged users.
# Perf events can be used for side-channel attacks (Spectre variants).
kernel.perf_event_paranoid = 3

# --- Restrict ptrace ---
# 0 = any process can ptrace any other (dangerous)
# 1 = only parent processes can ptrace children (default on Ubuntu)
# 2 = only processes with CAP_SYS_PTRACE can ptrace
# 3 = no process can ptrace (breaks debuggers entirely)
# Use 1 for production. Use 2 if no debugging is needed on this host.
kernel.yama.ptrace_scope = 1

# --- Disable unprivileged BPF ---
# Prevents unprivileged users from loading BPF programs.
# BPF can be used for kernel exploitation. Privileged BPF (root, CAP_BPF)
# is still available for tools like tcpdump and container runtimes.
# WARNING: Test with your container runtime. Some older versions of
# containerd/CRI-O use unprivileged BPF. Modern versions (containerd 1.7+,
# CRI-O 1.28+) work with this set to 1.
kernel.unprivileged_bpf_disabled = 1

# --- Harden BPF JIT ---
# When BPF JIT is enabled, harden the compiled code against
# JIT spraying attacks.
net.core.bpf_jit_harden = 2

# --- Disable kexec ---
# Prevents loading a new kernel at runtime. An attacker with root
# could use kexec to load a kernel without your security settings.
kernel.kexec_load_disabled = 1

# --- Restrict userfaultfd ---
# userfaultfd is used in kernel exploitation (race condition stabilisation).
# 1 = only privileged users can create userfaultfd.
vm.unprivileged_userfaultfd = 0
```

### Filesystem Protections

Create `/etc/sysctl.d/60-fs-hardening.conf`:

```ini
# /etc/sysctl.d/60-fs-hardening.conf
# Filesystem protections against link-based attacks
# Target: Ubuntu 24.04 LTS, RHEL 9, Debian 12, kernel 5.15+

# Prevent hardlink creation to files the user does not own.
# Mitigates hardlink-based privilege escalation in world-writable directories.
fs.protected_hardlinks = 1

# Prevent symlink following in world-writable sticky directories
# unless the owner of the symlink matches the owner of the directory
# or the target. Mitigates symlink attacks in /tmp.
fs.protected_symlinks = 1

# Restrict FIFO and regular file creation in world-writable sticky
# directories to prevent data spoofing attacks.
# 2 = also applies when the directory owner does not own the existing file.
fs.protected_fifos = 2
fs.protected_regular = 2

# Prevent core dumps from setuid programs.
# Core dumps from privileged programs can contain sensitive data.
fs.suid_dumpable = 0
```

### Boot Parameters

These kernel command-line parameters must be set in the bootloader (GRUB) and require a reboot to take effect.

Edit `/etc/default/grub` and add parameters to `GRUB_CMDLINE_LINUX`:

```bash
# Add these to the existing GRUB_CMDLINE_LINUX value in /etc/default/grub.
# Do not replace the existing value - append to it.

GRUB_CMDLINE_LINUX="$EXISTING_VALUES init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 slab_nomerge vsyscall=none lockdown=confidentiality"
```

Parameter reference:

| Parameter | What it does | Performance impact |
|-----------|-------------|-------------------|
| `init_on_alloc=1` | Zeroes memory on allocation, preventing data leaks from freed objects | 1-3% throughput reduction on allocation-heavy workloads |
| `init_on_free=1` | Zeroes memory on free, preventing use-after-free data leaks | 3-5% additional overhead. Skip on latency-sensitive systems |
| `page_alloc.shuffle=1` | Randomises page allocator freelists, making heap layout unpredictable | Negligible |
| `slab_nomerge` | Prevents merging of slab caches with similar object sizes, reducing cross-cache exploitation | 5-15% increased memory usage |
| `vsyscall=none` | Disables the legacy vsyscall page, which is a known exploitation target | None. Breaks very old binaries (pre-glibc 2.14, circa 2011) |
| `lockdown=confidentiality` | Prevents root from reading kernel memory, loading unsigned modules, accessing /dev/mem, and using kexec | Blocks: NVIDIA unsigned drivers, hibernation, some BPF operations |

Apply the GRUB changes:

```bash
# On Debian/Ubuntu:
sudo update-grub

# On RHEL/Rocky:
sudo grub2-mkconfig -o /boot/grub2/grub.cfg

# Reboot to apply boot parameters:
sudo systemctl reboot
```

**About `lockdown=confidentiality`:** This is the most impactful boot parameter. It prevents even root from accessing raw kernel memory, loading unsigned modules, or using kexec. If you use unsigned kernel modules (NVIDIA proprietary drivers, ZFS DKMS), use `lockdown=integrity` instead (weaker but allows unsigned modules) or sign your modules. Test this in staging before production.

### Applying and Persisting sysctl Settings

Apply all sysctl settings immediately without rebooting:

```bash
# Apply all settings from /etc/sysctl.d/
sudo sysctl --system

# Output will show each setting being applied:
# * Applying /etc/sysctl.d/60-net-hardening.conf ...
# * Applying /etc/sysctl.d/60-kernel-hardening.conf ...
# * Applying /etc/sysctl.d/60-fs-hardening.conf ...
```

**File naming convention:** Files in `/etc/sysctl.d/` are applied in lexicographic order. Using the `60-` prefix ensures our hardening runs after distribution defaults (usually `10-` or `20-`) but before any application-specific tuning (`90-` or `99-`). This allows application-specific overrides to take precedence.

### Verification Script

Save as `/usr/local/bin/verify-sysctl-hardening.sh`:

```bash
#!/bin/bash
# Verify sysctl hardening settings are active.
# Exit code 0 = all settings correct. Exit code 1 = one or more settings wrong.

FAIL=0

check() {
    local key="$1"
    local expected="$2"
    local actual
    actual=$(sysctl -n "$key" 2>/dev/null)
    if [ "$actual" != "$expected" ]; then
        echo "FAIL: $key = $actual (expected $expected)"
        FAIL=1
    else
        echo "OK:   $key = $actual"
    fi
}

echo "=== Network Stack ==="
check net.ipv4.conf.all.rp_filter 1
check net.ipv4.conf.all.accept_source_route 0
check net.ipv4.conf.all.accept_redirects 0
check net.ipv4.conf.all.send_redirects 0
check net.ipv4.conf.all.log_martians 1
check net.ipv4.tcp_syncookies 1
check net.ipv4.tcp_timestamps 1
check net.ipv4.icmp_echo_ignore_broadcasts 1
check net.ipv6.conf.all.accept_redirects 0
check net.ipv6.conf.all.accept_ra 0

echo ""
echo "=== Kernel Protections ==="
check kernel.randomize_va_space 2
check kernel.kptr_restrict 2
check kernel.dmesg_restrict 1
check kernel.perf_event_paranoid 3
check kernel.yama.ptrace_scope 1
check kernel.unprivileged_bpf_disabled 1
check net.core.bpf_jit_harden 2
check kernel.kexec_load_disabled 1
check vm.unprivileged_userfaultfd 0

echo ""
echo "=== Filesystem ==="
check fs.protected_hardlinks 1
check fs.protected_symlinks 1
check fs.protected_fifos 2
check fs.protected_regular 2
check fs.suid_dumpable 0

echo ""
echo "=== Boot Parameters ==="
for param in init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 slab_nomerge vsyscall=none; do
    if grep -q "$param" /proc/cmdline; then
        echo "OK:   boot param $param present"
    else
        echo "FAIL: boot param $param missing from /proc/cmdline"
        FAIL=1
    fi
done

echo ""
if [ $FAIL -eq 0 ]; then
    echo "ALL CHECKS PASSED"
    exit 0
else
    echo "SOME CHECKS FAILED"
    exit 1
fi
```

```bash
sudo chmod +x /usr/local/bin/verify-sysctl-hardening.sh
sudo verify-sysctl-hardening.sh
```

## Expected Behaviour

After applying all sysctl settings and rebooting with the new boot parameters:

- `sudo verify-sysctl-hardening.sh` returns exit code 0 with all checks passing
- `cat /proc/kallsyms` as a non-root user shows all addresses as `0000000000000000`
- `dmesg` as a non-root user returns `dmesg: read kernel buffer failed: Operation not permitted`
- `cat /proc/cmdline` shows all boot parameters present
- `sysctl -a 2>/dev/null | grep rp_filter` confirms strict mode on all interfaces
- Network services (web server, database, SSH) function normally
- Container workloads ([Docker](https://www.docker.com), containerd, CRI-O with version 1.7+/1.28+) start and run without errors

**Testing network hardening** (requires a second host on the same network):

```bash
# From another host, attempt to send a spoofed packet:
sudo hping3 -S -a 192.0.2.1 -p 80 TARGET_IP
# Expected: packet is dropped (rp_filter). No response from target.

# Attempt a SYN flood:
sudo hping3 -S --flood -p 80 TARGET_IP
# Expected: SYN cookies activate. Legitimate connections still succeed.
# Check with: netstat -s | grep "SYNs to LISTEN"
```

## Trade-offs

| Setting | Performance Impact | Compatibility Risk | Recommendation |
|---------|-------------------|-------------------|----------------|
| `init_on_alloc=1` | 1-3% throughput reduction on allocation-heavy workloads (benchmarked with `sysbench memory`) | None known | Enable everywhere. The overhead is negligible for most workloads. |
| `init_on_free=1` | 3-5% additional overhead on top of `init_on_alloc` | None known | Enable on security-critical systems. Skip on latency-sensitive workloads (real-time processing, high-frequency trading). |
| `slab_nomerge` | 5-15% increased kernel memory usage | None known | Enable on security-critical systems. Skip on memory-constrained hosts (<2GB RAM). |
| `lockdown=confidentiality` | None | Blocks unsigned module loading (NVIDIA, ZFS DKMS), hibernation, `/dev/mem` access, some BPF operations | Use `lockdown=integrity` if you need unsigned modules. Test in staging first. |
| `kernel.unprivileged_bpf_disabled=1` | None | Older container runtimes (containerd <1.7, CRI-O <1.28) may use unprivileged BPF | Test with your container runtime before applying. Modern runtimes are fine. |
| `net.ipv6.conf.all.accept_ra=0` | None | Hosts using SLAAC for IPv6 addressing will lose IPv6 connectivity | Only set on hosts with static IPv6 configuration. |
| `rp_filter=1` (strict) | None | Breaks asymmetric routing (traffic enters on one interface, would exit on another) | Use `rp_filter=2` (loose mode) only on interfaces with known asymmetric routing. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| `rp_filter=1` breaks asymmetric routing | Legitimate traffic dropped on multi-homed hosts | `dmesg` shows `martian source` logs with valid source IPs; monitoring shows packet loss on specific interfaces | Set `rp_filter=2` on the affected interface only: `sysctl net.ipv4.conf.eth1.rp_filter=2` |
| `lockdown=confidentiality` blocks NVIDIA driver | `modprobe nvidia` fails; GPU not available | `dmesg` shows `Lockdown: modprobe: unsigned module loading is restricted`; `nvidia-smi` returns error | Option 1: Sign the module (`scripts/sign-file`). Option 2: Use `lockdown=integrity`. Option 3: Remove `lockdown` from boot params and reboot |
| `unprivileged_bpf_disabled=1` breaks container runtime | containerd or CRI-O fails to start or pods fail to schedule | Container runtime logs show BPF-related permission errors; `journalctl -u containerd` shows `EPERM` | Set `kernel.unprivileged_bpf_disabled=0` and restart the runtime. Upgrade the runtime to a version that uses privileged BPF. |
| `accept_ra=0` breaks IPv6 connectivity | IPv6 stops working on hosts using SLAAC | `ip -6 route show` shows no default route; IPv6 connections fail | Set `net.ipv6.conf.<interface>.accept_ra=1` on interfaces needing SLAAC. Better: migrate to static IPv6 configuration. |
| `init_on_free=1` causes latency regression | P99 latency increases 3-5% on allocation-heavy workloads | Application latency metrics increase after reboot; `perf stat` shows increased page zeroing time | Remove `init_on_free=1` from boot params. Keep `init_on_alloc=1` (lower overhead, still valuable). Reboot. |
| sysctl settings reset after reboot | Settings revert to defaults | `verify-sysctl-hardening.sh` reports failures after reboot | Check that files exist in `/etc/sysctl.d/` and are not overridden by later files. Run `sysctl --system` and check output for conflicts. |

## When to Consider a Managed Alternative

**Transition point:** When you are managing sysctl consistency across more than 10-20 hosts and spending more than 2 hours per month verifying compliance or investigating drift.

**What managed providers handle:**

Managed Kubernetes providers ([Civo](https://www.civo.com), [DigitalOcean](https://www.digitalocean.com), [Vultr](https://www.vultr.com), [Linode](https://www.linode.com)) configure node-level kernel parameters as part of their node images. When you run workloads on managed Kubernetes, you do not manage sysctl on the underlying nodes. The provider handles kernel hardening, patching, and configuration consistency across all nodes in your cluster.

Runtime security platforms ([Sysdig](https://sysdig.com) and [Aqua](https://www.aquasec.com)) can verify sysctl compliance across a fleet of hosts and alert on configuration drift. If a host's sysctl settings change (manually, through a package update, or through a configuration management error), the platform detects the deviation and alerts.

**What you still control:** Application-level sysctl tuning remains your responsibility even on managed infrastructure. Settings like `net.core.somaxconn` (maximum socket backlog for high-connection workloads) or `vm.max_map_count` (required by [Elasticsearch](https://www.elastic.co/elasticsearch)) are workload-specific and set at the pod level using init containers or security context capabilities.

**Automation path:** For self-managed infrastructure, use the verification script from this article in a cron job or CI pipeline. For fleet-wide application, see [Automated OS Hardening with Ansible](/articles/linux/ansible-os-hardening/) ([Automated OS Hardening with Ansible: A Production-Ready Playbook Collection](/articles/linux/ansible-os-hardening/)) for a production-ready playbook that applies these settings across all hosts with staged rollout and canary verification.
