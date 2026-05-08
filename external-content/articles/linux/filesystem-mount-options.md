---
title: "Filesystem Mount Options That Matter: noexec, nosuid, nodev, and Beyond"
description: "Default Linux installations mount most filesystems with permissive options. On a stock Ubuntu 24.04 or RHEL 9 system:"
slug: "filesystem-mount-options"
date: 2026-01-08
lastmod: 2026-01-08
category: "linux"
tags: ["mount-options", "filesystem", "noexec", "nosuid", "nodev", "hardening", "linux"]
personas: ["systems-engineer", "sre"]
article_number: 5
difficulty: "intermediate"
estimated_reading_time: 14
provider_bridges:
  - name: "Civo"
    id: 22
    category: "managed-kubernetes"
  - name: "DigitalOcean"
    id: 21
    category: "managed-kubernetes"
premium_pack: "ansible-hardening-playbooks"
published: true
layout: article.njk
permalink: "/articles/linux/filesystem-mount-options/index.html"
---

# Filesystem Mount Options That Matter: noexec, nosuid, nodev, and Beyond

## Problem

Default Linux installations mount most filesystems with permissive options. On a stock Ubuntu 24.04 or RHEL 9 system:

- `/tmp` allows executable binaries. An attacker who lands a shell through a web application can download a privilege escalation exploit to `/tmp` and execute it directly.
- `/dev/shm` (shared memory) allows execution. Multiple real-world exploits use shared memory as a staging area because it is world-writable and executable by default.
- `/home` allows setuid binaries. A compromised user account can place a setuid-root binary in their home directory if the underlying filesystem permits it.
- `/var` allows device files. While unlikely to be exploited in isolation, allowing device file creation on data partitions violates the principle of least privilege.

Mount options are one of the cheapest hardening controls available. They require no additional software, have near-zero performance impact, and prevent entire classes of attacks. Yet most production systems run with the defaults because administrators either do not know which options to apply where, or fear breaking running applications.

**Target systems:** Ubuntu 24.04 LTS, Debian 12, RHEL 9 / Rocky Linux 9, and any system using ext4, xfs, or tmpfs.

## Threat Model

- **Adversary:** Attacker who has gained unprivileged shell access through a compromised application (web shell, RCE in a dependency, stolen SSH credentials) and is attempting to escalate privileges or establish persistence.
- **Access level:** Unprivileged local user with write access to world-writable directories (`/tmp`, `/var/tmp`, `/dev/shm`).
- **Objective:** Execute downloaded exploit binaries, create setuid binaries for privilege escalation, or create device files to access raw block devices.
- **Blast radius:** Single host. On shared systems or [Kubernetes](https://kubernetes.io) nodes, a successful privilege escalation from one compromised service affects all other workloads on the same host.

## Configuration

### Mount Options Reference

Each option restricts a specific capability on the mounted filesystem:

| Option | Effect | Use case |
|--------|--------|----------|
| `noexec` | Prevents execution of any binaries on the filesystem | Directories that should contain only data: `/tmp`, `/var/tmp`, `/dev/shm` |
| `nosuid` | Ignores setuid and setgid bits on binaries | Every partition except `/` and `/usr` (where system binaries with setuid live) |
| `nodev` | Prevents interpretation of block/character device files | Every partition except `/` and `/dev` |
| `ro` | Mounts the filesystem read-only | `/boot` (after kernel updates, remount rw temporarily) |

### /etc/fstab Configuration

Apply mount options by editing `/etc/fstab`. The following examples assume separate partitions or tmpfs mounts for each path. If `/tmp` is not a separate partition, you can use a bind mount or tmpfs.

```bash
# /etc/fstab - hardened mount options
# <filesystem>  <mount point>  <type>  <options>                        <dump>  <pass>

# /tmp - tmpfs with restrictive options
# Size limits /tmp to 2G to prevent a single process from filling all RAM.
tmpfs           /tmp           tmpfs   defaults,noexec,nosuid,nodev,size=2G  0  0

# /var/tmp - bind mount from /tmp (shares the same restrictions)
# Or if /var/tmp is a separate partition:
/dev/sda5       /var/tmp       ext4    defaults,noexec,nosuid,nodev     0  2

# /dev/shm - shared memory (already tmpfs, add restrictions)
tmpfs           /dev/shm       tmpfs   defaults,noexec,nosuid,nodev     0  0

# /home - user directories (no setuid, no device files)
/dev/sda3       /home          ext4    defaults,nosuid,nodev            0  2

# /var - system data (no setuid, no device files)
/dev/sda4       /var           ext4    defaults,nosuid,nodev            0  2

# /var/log - logs (no execution, no setuid, no device files)
/dev/sda6       /var/log       ext4    defaults,noexec,nosuid,nodev     0  2

# /boot - kernel and bootloader (read-only after boot)
/dev/sda1       /boot          ext4    defaults,nosuid,nodev,ro         0  2
```

**If `/tmp` is not a separate partition,** use a tmpfs mount (shown above) or a bind mount:

```bash
# Create a dedicated directory and bind-mount it as /tmp
sudo mkdir -p /mnt/tmp-storage
# In /etc/fstab:
/mnt/tmp-storage  /tmp  none  bind,noexec,nosuid,nodev  0  0
```

### Applying Changes Without Rebooting

```bash
# Remount /tmp with new options (if already mounted)
sudo mount -o remount,noexec,nosuid,nodev /tmp

# Remount /dev/shm
sudo mount -o remount,noexec,nosuid,nodev /dev/shm

# Remount /home
sudo mount -o remount,nosuid,nodev /home

# Verify the changes took effect
findmnt -o TARGET,OPTIONS /tmp /dev/shm /home
```

### Container Overlay Filesystem Hardening

[Docker](https://www.docker.com) and [containerd](https://containerd.io) mount overlay filesystems for each container. By default, these overlays inherit permissive options from the underlying storage driver.

For Docker, configure mount propagation in the [systemd](https://systemd.io) service:

```ini
# /etc/systemd/system/docker.service.d/mount-flags.conf
[Service]
MountFlags=slave
```

For containerd, restrict mount propagation in the runtime configuration:

```toml
# /etc/containerd/config.toml
[plugins."io.containerd.grpc.v1.cri"]
  [plugins."io.containerd.grpc.v1.cri".containerd]
    [plugins."io.containerd.grpc.v1.cri".containerd.runtimes]
      [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
        [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
          # Prevent container mounts from propagating to the host
          SystemdCgroup = true
```

In Kubernetes pod specifications, set `mountPropagation` explicitly to prevent containers from affecting host mounts:

```yaml
volumeMounts:
  - name: data
    mountPath: /data
    mountPropagation: None  # Default, but set explicitly
```

### Verification

```bash
#!/bin/bash
# verify-mount-options.sh - Check that hardened mount options are active

FAIL=0

check_mount() {
    local mount_point="$1"
    local expected_option="$2"
    
    if findmnt -n -o OPTIONS "$mount_point" 2>/dev/null | grep -q "$expected_option"; then
        echo "OK:   $mount_point has $expected_option"
    else
        echo "FAIL: $mount_point missing $expected_option"
        FAIL=1
    fi
}

echo "=== /tmp ==="
check_mount /tmp noexec
check_mount /tmp nosuid
check_mount /tmp nodev

echo "=== /dev/shm ==="
check_mount /dev/shm noexec
check_mount /dev/shm nosuid
check_mount /dev/shm nodev

echo "=== /home ==="
check_mount /home nosuid
check_mount /home nodev

echo "=== /var ==="
check_mount /var nosuid
check_mount /var nodev

echo ""
if [ $FAIL -eq 0 ]; then
    echo "ALL MOUNT OPTION CHECKS PASSED"
    exit 0
else
    echo "SOME CHECKS FAILED"
    exit 1
fi
```

## Expected Behaviour

After applying the mount options and either remounting or rebooting:

- `findmnt -o TARGET,OPTIONS /tmp` shows `noexec,nosuid,nodev` in the options
- Attempting to execute a binary from `/tmp` fails: `cp /bin/ls /tmp/ls && /tmp/ls` returns `bash: /tmp/ls: Permission denied`
- Attempting to execute from `/dev/shm` fails the same way
- Setuid bits on binaries in `/home` are silently ignored by the kernel
- System services (SSH, web servers, databases) continue to function normally
- Package managers (`apt`, `dnf`) continue to work because they execute from `/usr`
- Container workloads start and run without errors (overlay mounts are separate from host mount restrictions)

## Trade-offs

| Option | Affected Path | What Breaks | Workaround |
|--------|--------------|-------------|------------|
| `noexec` on `/tmp` | `/tmp` | Java applications that extract and execute JARs from `/tmp`. Some installers (Oracle Database, some game servers) that write executables to `/tmp`. Build tools that compile in `/tmp`. | Set `TMPDIR` to an exec-capable directory for the specific application. Or use systemd `PrivateTmp=yes` which gives the service its own `/tmp` with exec capability. |
| `noexec` on `/var/tmp` | `/var/tmp` | `dpkg` post-install scripts that execute from `/var/tmp`. Some backup tools (Veeam agent). | Temporarily remount: `sudo mount -o remount,exec /var/tmp`, run the operation, remount with `noexec`. |
| `noexec` on `/dev/shm` | `/dev/shm` | Some builds of Chrome/Chromium (headless mode). Older versions of [PostgreSQL](https://www.postgresql.org) that use shared memory executables. | For Chrome, pass `--disable-dev-shm-usage`. For PostgreSQL, this is fixed in modern versions. |
| `nosuid` on `/home` | `/home` | Developers using `sudo`-like tools built from source in their home directory. Custom setuid utilities (rare in production). | Move setuid binaries to `/usr/local/bin`. |
| `ro` on `/boot` | `/boot` | Kernel updates fail because `/boot` is read-only. | Remount before updating: `sudo mount -o remount,rw /boot && sudo apt upgrade && sudo mount -o remount,ro /boot`. |

The most common breakage is Java on `noexec /tmp`. The `PrivateTmp` solution is preferred because it keeps the security benefit for all other processes while allowing the specific service to execute from its private tmp namespace.

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Application writes executable to `/tmp` with `noexec` | Application returns vague error ("exec format error" or "permission denied") with no indication that mount options are the cause | `strace` on the failing process shows `EACCES` on an `execve` call in `/tmp` | Set `TMPDIR=/var/lib/appname/tmp` in the application's systemd unit, or use `PrivateTmp=yes` |
| `fstab` syntax error | System fails to mount one or more filesystems on boot, potentially dropping to emergency mode | System boots to emergency shell; `journalctl -b` shows mount failures | Boot from rescue media, fix `/etc/fstab`. Always run `sudo mount -a` after editing fstab to catch errors before rebooting. |
| Missing partition for separate mount | Boot fails because fstab references a partition that does not exist | Emergency mode on boot; `mount -a` fails with "special device not found" | Remove or comment out the fstab entry. Use tmpfs or bind mounts instead of dedicated partitions. |
| Container overlay ignores host mount options | Containers can execute binaries even though host `/tmp` has `noexec` | Container processes successfully execute binaries in paths that should be restricted | Container overlay mounts are separate from the host filesystem. Restrict container capabilities using security contexts (`readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`) instead. |

## When to Consider a Managed Alternative

**Transition point:** When you manage more than 10 hosts and need consistent mount option enforcement across all of them, or when container overlay filesystem options vary by runtime version and a single misconfigured node could allow privilege escalation.

**What managed providers handle:**

Managed Kubernetes providers ([Civo](https://www.civo.com), [DigitalOcean](https://www.digitalocean.com), [Vultr](https://www.vultr.com), [Linode](https://www.linode.com)) configure node filesystem layout and mount options as part of their node images. You do not manage `/etc/fstab` on nodes you do not control.

Compliance scanning tools ([Aqua](https://www.aquasec.com), [Snyk](https://snyk.io) IaC scanning) can audit mount options across your fleet and flag hosts where `/tmp` is missing `noexec` or `/dev/shm` is missing `nosuid`. This is more reliable than manual verification when host counts grow.

**What you still control:** Even on managed infrastructure, container-level filesystem restrictions are your responsibility. Set `readOnlyRootFilesystem: true` and `allowPrivilegeEscalation: false` in your Kubernetes security contexts. These controls complement host-level mount options.

**Automation path:** For self-managed infrastructure, use the verification script from this article in a configuration management tool or CI pipeline. For fleet-wide enforcement, the [Ansible](https://www.ansible.com) playbook pack applies these mount options across all hosts with pre-flight checks that detect and skip hosts where a separate partition does not exist.
