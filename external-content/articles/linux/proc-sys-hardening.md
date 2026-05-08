---
title: "Hardening /proc and /sys: Restricting Kernel Information Disclosure"
description: "/proc and /sys are virtual filesystems that expose kernel internals, hardware details, and process information to userspace."
slug: "proc-sys-hardening"
date: 2026-03-11
lastmod: 2026-03-11
category: "linux"
tags: ["proc", "sysfs", "hidepid", "kernel", "information-disclosure", "hardening", "linux"]
personas: ["systems-engineer", "security-engineer"]
article_number: 16
difficulty: "intermediate"
estimated_reading_time: 13
provider_bridges:
  - name: "Civo"
    id: 22
    category: "managed-kubernetes"
  - name: "DigitalOcean"
    id: 21
    category: "managed-kubernetes"
published: true
layout: article.njk
permalink: "/articles/linux/proc-sys-hardening/index.html"
---

# Hardening /proc and /sys: Restricting Kernel Information Disclosure

## Problem

`/proc` and `/sys` are virtual filesystems that expose kernel internals, hardware details, and process information to userspace. On a stock Linux system, every unprivileged user can read:

- `/proc/kallsyms` -- the addresses of every symbol in the running kernel. With this data, an attacker can bypass KASLR (Kernel Address Space Layout Randomisation) and precisely target kernel exploitation.
- `/proc/kcore` -- a virtual file representing the physical memory of the system. Root can read the full contents of RAM through this file, including encryption keys, credentials, and other secrets.
- `/proc/[pid]/` directories for every process on the system. Any user can see the command-line arguments, environment variables (which often contain secrets), memory maps, and file descriptors of every other user's processes.
- `/sys/kernel/` files that expose kernel configuration details, security module state, and hardware topology useful for fingerprinting.
- `/proc/sysrq-trigger` -- the magic SysRq interface that can reboot the machine, kill all processes, or dump memory, accessible to root without authentication.

These information leaks are prerequisites for most local privilege escalation attacks. The attacker first reads `/proc` to learn the kernel's memory layout, identify running services, and find processes with interesting credentials, then uses that information to craft a targeted exploit.

**Target systems:** Ubuntu 24.04 LTS, Debian 12, RHEL 9 / Rocky Linux 9, kernel 5.15+.

## Threat Model

- **Adversary:** Unprivileged local user with shell access (compromised web application, stolen SSH credentials, container escape into the host namespace).
- **Access level:** Unprivileged shell on the host, or a container with the host's `/proc` mounted (misconfigured container or privileged mode).
- **Objective:** Reconnaissance (kernel addresses for KASLR bypass, process enumeration, credential harvesting from environment variables), or direct system manipulation via `/proc/sysrq-trigger`.
- **Blast radius:** Information gathered from `/proc` and `/sys` enables further attacks (privilege escalation, targeted exploitation). If `/proc/sysrq-trigger` is accessible, immediate denial of service or data exfiltration is possible.

## Configuration

### Hiding Process Information with hidepid

The `hidepid` mount option on `/proc` controls which processes are visible to unprivileged users:

| Value | Effect |
|-------|--------|
| `hidepid=0` | Default. All users can read all `/proc/[pid]/` directories. |
| `hidepid=1` | Users can see all `/proc/[pid]/` entries but cannot access `/proc/[pid]/cmdline`, `/proc/[pid]/status`, etc. for other users' processes. |
| `hidepid=2` | Users can only see their own processes in `/proc`. Other users' PID directories are invisible. |
| `hidepid=invisible` | Same as `hidepid=2` on kernels 5.8+. Clearer naming. |

Apply `hidepid=2` via `/etc/fstab`:

```bash
# /etc/fstab - add or modify the /proc mount line
proc    /proc    proc    defaults,hidepid=2,gid=proc    0    0
```

The `gid=proc` option allows members of the `proc` group to see all processes. This is essential for monitoring agents and tools that need full process visibility.

```bash
# Create the proc group if it doesn't exist
sudo groupadd -r proc 2>/dev/null

# Add monitoring users to the proc group
sudo usermod -aG proc prometheus
sudo usermod -aG proc node_exporter
sudo usermod -aG proc zabbix

# Apply immediately without rebooting
sudo mount -o remount,hidepid=2,gid=proc /proc
```

Verify:

```bash
# As root - should see all processes
ps aux | wc -l

# As an unprivileged user - should see only their own processes
su - testuser -c "ps aux | wc -l"
# Expected: far fewer processes than root sees
```

### Restricting Kernel Pointer Exposure

Kernel pointers in `/proc/kallsyms` are the primary target for KASLR bypass. Restrict them with `kptr_restrict`:

```ini
# /etc/sysctl.d/60-proc-hardening.conf

# Hide kernel pointers from all users (even root)
# 0 = visible to all (insecure default on some distros)
# 1 = hidden from unprivileged users, visible to root
# 2 = hidden from all users including root
kernel.kptr_restrict = 2

# Restrict access to dmesg (kernel ring buffer)
# Contains kernel addresses, hardware details, driver information
kernel.dmesg_restrict = 1

# Restrict perf_event access to prevent side-channel attacks
kernel.perf_event_paranoid = 3

# Disable the SysRq magic key (prevents reboot/crash via /proc/sysrq-trigger)
# 0 = disable all SysRq functions
# 1 = enable all SysRq functions (insecure)
# 176 = allow only sync and remount-ro (useful for emergency recovery)
kernel.sysrq = 0
```

Apply:

```bash
sudo sysctl --system
```

### Restricting /proc/kcore

`/proc/kcore` provides a raw view of physical memory. While only root can read it by default, a compromised root account (through sudo misconfiguration or a container escape to host namespaces) can dump the entire contents of RAM:

```bash
# Check current permissions
ls -la /proc/kcore
# -r-------- 1 root root ... /proc/kcore (readable by root only by default)
```

On systems with Secure Boot and `lockdown=confidentiality`, access to `/proc/kcore` is blocked even for root. If you cannot use lockdown mode, restrict access with an [AppArmor](https://apparmor.net) or [SELinux](https://github.com/SELinuxProject/selinux) policy.

AppArmor (Ubuntu/Debian):

```bash
# /etc/apparmor.d/proc-kcore
profile proc-kcore /proc/kcore {
    deny /proc/kcore r,
}
```

### Hardening /sys Filesystem Access

The `/sys` filesystem exposes kernel configuration, device information, and security module interfaces. Key paths to restrict:

```bash
# Restrict access to security module interfaces
sudo chmod 700 /sys/kernel/security 2>/dev/null

# Restrict access to kernel debug interface
sudo chmod 700 /sys/kernel/debug 2>/dev/null
```

For persistent restrictions, create a [systemd](https://systemd.io) tmpfiles rule:

```ini
# /etc/tmpfiles.d/sys-hardening.conf
# Restrict /sys/kernel/security to root only
z /sys/kernel/security 0700 root root -
z /sys/kernel/debug 0700 root root -
```

```bash
sudo systemd-tmpfiles --create
```

### Container Runtime procfs Masking

Container runtimes mask certain `/proc` and `/sys` paths to prevent containers from accessing sensitive host information. However, the specific paths masked differ between runtimes.

Paths masked by default in [containerd](https://containerd.io) and [CRI-O](https://cri-o.io):

| Path | Why it is masked |
|------|-----------------|
| `/proc/acpi` | Hardware ACPI tables (host fingerprinting) |
| `/proc/kcore` | Physical memory access |
| `/proc/keys` | Kernel keyring (encryption keys) |
| `/proc/latency_stats` | Kernel scheduling information |
| `/proc/sched_debug` | Scheduler debug output |
| `/proc/scsi` | SCSI device information |
| `/proc/timer_list` | Kernel timer information |
| `/proc/timer_stats` | Timer statistics |
| `/sys/firmware` | Firmware tables (host fingerprinting) |

Verify container procfs masking:

```bash
# From inside a container, these should return "Permission denied" or show empty/fake data
docker run --rm alpine cat /proc/kcore
# Expected: "Permission denied"

docker run --rm alpine cat /proc/acpi/wakeup
# Expected: "Permission denied" or "No such file or directory"
```

If you run containers with `--privileged`, all procfs masking is disabled. Never use `--privileged` in production. Instead, grant specific capabilities:

```yaml
# Kubernetes security context - restrictive defaults
securityContext:
  privileged: false
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
  procMount: Default  # Uses the runtime's default masking
```

### Verification Script

```bash
#!/bin/bash
# verify-proc-hardening.sh

FAIL=0

check_sysctl() {
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

echo "=== sysctl Settings ==="
check_sysctl kernel.kptr_restrict 2
check_sysctl kernel.dmesg_restrict 1
check_sysctl kernel.perf_event_paranoid 3
check_sysctl kernel.sysrq 0

echo ""
echo "=== /proc Mount Options ==="
if findmnt -n -o OPTIONS /proc | grep -q "hidepid=2\|hidepid=invisible"; then
    echo "OK:   /proc mounted with hidepid=2 or hidepid=invisible"
else
    echo "FAIL: /proc not mounted with hidepid"
    FAIL=1
fi

echo ""
echo "=== Kernel Pointer Exposure ==="
KALLSYMS=$(cat /proc/kallsyms 2>/dev/null | head -1)
if echo "$KALLSYMS" | grep -q "^0000000000000000"; then
    echo "OK:   /proc/kallsyms addresses are zeroed"
else
    echo "FAIL: /proc/kallsyms exposes kernel addresses"
    FAIL=1
fi

echo ""
echo "=== dmesg Access ==="
if dmesg 2>&1 | grep -q "Operation not permitted"; then
    echo "OK:   dmesg restricted for unprivileged users"
else
    echo "INFO: Run this check as a non-root user to verify dmesg restriction"
fi

echo ""
if [ $FAIL -eq 0 ]; then
    echo "ALL CHECKS PASSED"
    exit 0
else
    echo "SOME CHECKS FAILED"
    exit 1
fi
```

## Expected Behaviour

After applying `/proc` and `/sys` hardening:

- `cat /proc/kallsyms` as a non-root user shows all addresses as `0000000000000000`
- `cat /proc/kallsyms` as root also shows zeroed addresses (with `kptr_restrict=2`)
- `dmesg` as a non-root user returns "Operation not permitted"
- `ps aux` as a non-root user shows only that user's processes (with `hidepid=2`)
- `echo b > /proc/sysrq-trigger` as root does nothing (with `sysrq=0`)
- Monitoring agents in the `proc` group can still see all processes and collect metrics
- Container processes cannot read `/proc/kcore`, `/proc/keys`, or `/proc/acpi`
- System services (SSH, web servers, databases) function normally
- `systemd-cgtop`, `htop` (as root), and `top` (as root) display all processes correctly

## Trade-offs

| Control | Benefit | Cost | Mitigation |
|---------|---------|------|------------|
| `hidepid=2` | Users cannot see other users' processes, preventing enumeration of running services and command-line secrets | `ps aux` as non-root shows only own processes. Some tools that expect full process visibility break. | Add monitoring and admin users to the `proc` group via the `gid=proc` mount option. |
| `kptr_restrict=2` | Kernel addresses hidden from everyone, including root. Prevents KASLR bypass even after root compromise. | Root cannot debug kernel issues that require symbol addresses. `perf` and `bpftrace` cannot resolve kernel symbols. | Use `kptr_restrict=1` if root needs kernel symbols for debugging. On dedicated development/debugging hosts, keep at 0. |
| `sysrq=0` | Prevents abuse of the SysRq interface for denial of service or data exfiltration | Cannot use SysRq for emergency recovery (sync, remount-ro, reboot) | Set `sysrq=176` to allow only safe SysRq functions (sync and remount-ro). Useful for emergency situations on physical hardware. |
| `dmesg_restrict=1` | Prevents unprivileged access to kernel ring buffer (addresses, hardware info, driver details) | Users cannot run `dmesg` for troubleshooting | Grant `CAP_SYSLOG` to specific debugging users or tools. Or use `journalctl -k` with appropriate journal permissions. |
| Container procfs masking | Containers cannot access sensitive host kernel information | Some monitoring containers need access to host `/proc` paths | Mount specific host paths read-only into monitoring containers instead of disabling procfs masking entirely. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Monitoring agent cannot read `/proc` | Metrics collection stops. Dashboards show gaps. Alerts fire for missing metrics. | [Prometheus](https://prometheus.io) scrape errors. Agent logs show "permission denied" on `/proc` paths. | Add the monitoring agent's user to the `proc` group: `usermod -aG proc <agent_user>`. Restart the agent. |
| `hidepid=2` breaks application that reads other processes | Application fails with "no such file or directory" when reading `/proc/<pid>` of another process | Application error logs reference `/proc` paths. `strace` shows `ENOENT` or `EACCES` on `/proc/[pid]/` access. | Add the application user to the `proc` group. Or run the application with `CAP_SYS_PTRACE` capability (grants `/proc` access). |
| `kptr_restrict=2` breaks debugging tools | `perf report` shows unresolved symbols. `bpftrace` cannot map kernel addresses to function names. | Debugging output shows hex addresses instead of symbol names. | Temporarily set `sysctl kernel.kptr_restrict=1` for the debugging session. Reset to 2 when done. |
| `sysrq=0` prevents emergency recovery | Cannot use Alt+SysRq+S (sync) or Alt+SysRq+B (reboot) on a hung system | System is hung and the only option is a hard power cycle | Set `sysrq=176` instead of 0 to allow sync and remount-ro. For remote systems, use IPMI/BMC for emergency reboot. |
| Container runs with `--privileged` bypassing all masking | Container can read all `/proc` and `/sys` paths, including kernel memory | Kubernetes audit log shows privileged container creation. Pod security admission rejects the pod (if PSA is enforced). | Never use `--privileged`. Use Kubernetes Pod Security Admission (or a policy engine) to reject privileged containers at the admission level. |

## When to Consider a Managed Alternative

**Transition point:** When you run containers at scale and need consistent procfs masking across multiple container runtimes and runtime versions, or when container runtime upgrades change the default masking behaviour and you need to verify compliance after each update.

**What managed providers handle:**

Managed Kubernetes providers ([Civo](https://www.civo.com), [DigitalOcean](https://www.digitalocean.com), [Vultr](https://www.vultr.com), [Linode](https://www.linode.com)) configure container runtimes with appropriate procfs masking on their node images. The provider handles the runtime configuration and ensures that containers cannot access sensitive host paths by default. When the provider upgrades the container runtime, they verify that masking policies are maintained.

[Falco](https://falco.org) (open source) and [Sysdig](https://sysdig.com) detect suspicious access patterns to `/proc` and `/sys` paths at runtime. If a container attempts to read `/proc/kcore` or access a masked path, these tools generate an alert. This provides detection even if a masking configuration is accidentally weakened.

**What you still control:** Host-level `/proc` hardening (`hidepid`, `kptr_restrict`, `dmesg_restrict`) is your responsibility on self-managed infrastructure. Pod security contexts and admission policies that prevent privileged containers are your responsibility on any Kubernetes deployment, including managed clusters.

**Automation path:** For self-managed infrastructure, apply the sysctl and fstab configurations from this article through your configuration management tool. Run the verification script on a schedule to detect drift. For Kubernetes, enforce Pod Security Standards at the namespace level to prevent containers from running with elevated procfs access.


## Related Articles

- [Hardening the Linux Kernel Attack Surface with sysctl and Boot Parameters](/articles/linux/sysctl-kernel-hardening/)
- [Filesystem Mount Options That Matter: noexec, nosuid, nodev, and Beyond](/articles/linux/filesystem-mount-options/)
- [Hardening GRUB and the Boot Process: Secure Boot, Boot Passwords, and Tamper Detection](/articles/linux/grub-boot-hardening/)
- [systemd Unit Hardening: ProtectSystem, PrivateTmp, and the Full Sandbox Toolkit](/articles/linux/systemd-unit-hardening/)
- [Kernel Module Hardening: Blacklisting, Signing, and Preventing Runtime Loading](/articles/linux/kernel-module-hardening/)
