---
title: "systemd Unit Hardening: ProtectSystem, PrivateTmp, and the Full Sandbox Toolkit"
description: "systemd provides over 30 security-relevant directives for sandboxing services, yet the vast majority of unit files (including those shipped by..."
slug: "systemd-unit-hardening"
date: 2026-01-17
lastmod: 2026-01-17
category: "linux"
tags: ["systemd", "sandboxing", "hardening", "linux", "capabilities", "seccomp"]
personas: ["systems-engineer", "devops-engineer"]
article_number: 2
difficulty: "intermediate"
estimated_reading_time: 20
provider_bridges:
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
  - name: "Aqua"
    id: 123
    category: "runtime-security"
premium_pack: "systemd-hardening-overrides"
published: true
layout: article.njk
permalink: "/articles/linux/systemd-unit-hardening/index.html"
---

# [systemd](https://systemd.io) Unit Hardening: ProtectSystem, PrivateTmp, and the Full Sandbox Toolkit

## Problem

systemd provides over 30 security-relevant directives for sandboxing services, yet the vast majority of unit files (including those shipped by upstream packages) use none of them. A default [NGINX](https://nginx.org) unit file runs with full filesystem access, all Linux capabilities, no syscall filtering, and the ability to see every process on the host. A compromised service running in this configuration has effectively the same access as the user it runs as, with no containment.

The result: a remote code execution vulnerability in your web server gives the attacker read access to `/etc/shadow`, the ability to write to any path the service user can write, visibility into every running process, and the ability to make arbitrary network connections, all before any privilege escalation.

systemd can prevent all of this. The directives are built into every modern Linux distribution. They require no additional software. They are applied per-service with drop-in files that survive package upgrades. And they can be tested non-destructively using `systemd-analyze security`.

The gap: engineers do not know which directives to apply for which service type, what each directive actually restricts, or what breaks when the sandbox is too tight.

**Target systems:** Any Linux distribution using systemd (Ubuntu 20.04+, Debian 11+, RHEL 8+, Rocky 8+, Fedora 38+).

## Threat Model

- **Adversary:** Attacker with code execution inside a service, achieved through RCE vulnerability, compromised dependency, or supply chain attack targeting the application running under systemd.
- **Access level:** Runs as the service user. Often `www-data` for web servers, `postgres` for databases, or `root` for poorly configured legacy services.
- **Objective:** Read sensitive files (`/etc/shadow`, SSH keys, database credentials). Write to arbitrary paths (web shells, cron jobs, SSH authorized_keys). Pivot to other services on the host. Escalate to root.
- **Blast radius:** Without sandboxing, full host compromise as the service user, with trivial escalation paths if running as root. With sandboxing, contained to the service's declared filesystem paths, capabilities, and syscalls.

## Configuration

### Assessing Current Security Posture

Before hardening, check how exposed your services currently are:

```bash
# Score every service on the system (0 = fully hardened, 10 = fully exposed).
systemd-analyze security

# Example output:
# UNIT                           EXPOSURE PREDICATE HAPPY
# nginx.service                      9.6 UNSAFE    😨
# postgresql.service                 9.2 UNSAFE    😨
# sshd.service                       9.6 UNSAFE    😨
# redis-server.service               9.6 UNSAFE    😨

# Score a specific service with detailed breakdown:
systemd-analyze security nginx.service
```

The detailed output shows every security directive and whether it is active. A score above 7.0 means the service has almost no sandboxing.

### Filesystem Isolation

These directives restrict what the service can see and write on the filesystem.

Create a drop-in override file (survives package upgrades):

```bash
sudo systemctl edit nginx.service
```

This opens an editor for `/etc/systemd/system/nginx.service.d/override.conf`. Add:

```ini
[Service]
# --- Filesystem isolation ---

# Make the entire filesystem read-only, except for /dev, /proc, /sys,
# and paths explicitly listed in ReadWritePaths.
# 'strict' = everything read-only. 'full' = /etc is also read-only.
# 'yes' = /usr and /boot are read-only, /etc is writable.
ProtectSystem=strict

# Give the service its own /tmp and /var/tmp that no other service can see.
# Files in the private /tmp are deleted when the service stops.
PrivateTmp=yes

# Hide /home, /root, and /run/user from the service entirely.
# These directories appear empty inside the service's namespace.
ProtectHome=yes

# Explicitly allow writes only to the paths this service needs.
# NGINX needs to write to its log directory and PID file.
ReadWritePaths=/var/log/nginx /run/nginx

# Make /proc/sys, /sys, and kernel tunables read-only.
# Prevents the service from modifying sysctl values or kernel parameters.
ProtectKernelTunables=yes

# Prevent the service from loading kernel modules.
ProtectKernelModules=yes

# Hide kernel log ring buffer from the service.
ProtectKernelLogs=yes

# Make control groups read-only (service cannot modify its own cgroup).
ProtectControlGroups=yes

# Prevent the service from creating device nodes.
PrivateDevices=yes

# Prevent the service from changing the system clock.
ProtectClock=yes

# Prevent the service from setting the hostname.
ProtectHostname=yes
```

### Capability Restriction

Linux capabilities provide fine-grained root privileges. Most services need zero or one capability.

```ini
[Service]
# --- Capability restriction ---

# Drop ALL capabilities. Then add back only what the service needs.
CapabilityBoundingSet=
AmbientCapabilities=

# NGINX needs CAP_NET_BIND_SERVICE to bind to ports 80 and 443.
# If NGINX runs on ports >1024 (behind a load balancer), even this
# is unnecessary and CapabilityBoundingSet can stay empty.
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Prevent the service from gaining NEW privileges through setuid,
# setgid, or filesystem capabilities on executed binaries.
NoNewPrivileges=yes
```

**Common capabilities by service type:**

| Service Type | Required Capabilities | Notes |
|-------------|----------------------|-------|
| Web server (port 80/443) | `CAP_NET_BIND_SERVICE` | Not needed if behind a reverse proxy on port >1024 |
| Web server (port >1024) | (none) | Drop all capabilities |
| Database ([PostgreSQL](https://www.postgresql.org), [Redis](https://redis.io)) | (none) | Runs on high port by default |
| Worker/queue consumer | (none) | No special privileges needed |
| Log shipper | `CAP_DAC_READ_SEARCH` | Only if reading other users' log files |
| Network tool (tcpdump) | `CAP_NET_RAW` | Only for packet capture tools |

### Syscall Filtering

Restrict which kernel syscalls the service can invoke. This is the systemd equivalent of seccomp.

```ini
[Service]
# --- Syscall filtering ---

# Allow only the syscall groups needed by this service.
# @system-service covers the basics: file I/O, networking, memory management.
# This blocks: mount, reboot, kexec, module loading, raw I/O, clock setting.
SystemCallFilter=@system-service

# Return EPERM (not SIGSYS) when a blocked syscall is attempted.
# EPERM causes a graceful error. SIGSYS kills the process.
SystemCallErrorNumber=EPERM

# Lock down syscall filtering so the process cannot change its own filter.
LockPersonality=yes

# Restrict the set of address families the service can use.
# Most services need only IPv4, IPv6, and Unix sockets.
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# Prevent the service from creating new namespaces.
# Namespace creation is used in container escape exploits.
RestrictNamespaces=yes

# Restrict real-time scheduling (prevents priority manipulation DoS).
RestrictRealtime=yes

# Restrict access to the SUID/SGID bits on files.
RestrictSUIDSGID=yes
```

### Network Isolation

For services that should not make any network connections (e.g., a batch processor that reads from a local queue file):

```ini
[Service]
# --- Network isolation (for services with no network needs) ---

# Give the service its own network namespace with only a loopback device.
# The service cannot see or use any real network interfaces.
PrivateNetwork=yes
```

For services that need network but should be restricted to specific address families:

```ini
[Service]
# Only allow IPv4, IPv6, and Unix sockets (no raw, netlink, packet).
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# Alternatively, block ALL network except Unix sockets:
# RestrictAddressFamilies=AF_UNIX
# Useful for services that communicate only via socket files.
```

### User and Group Isolation

```ini
[Service]
# --- User isolation ---

# Run as a non-root user (if not already configured in the unit file).
User=www-data
Group=www-data

# DynamicUser creates a transient user for this service.
# The user exists only while the service runs. No persistent UID.
# Cannot be used with services that need persistent file ownership.
# DynamicUser=yes

# Hide other users' processes. The service only sees its own processes.
ProtectProc=invisible

# Hide process information from other services.
ProcSubset=pid
```

### Complete Hardened Override for NGINX

Combining all directives into a single drop-in:

```ini
# /etc/systemd/system/nginx.service.d/hardening.conf
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ReadWritePaths=/var/log/nginx /run/nginx /var/cache/nginx
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=
NoNewPrivileges=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
ProtectProc=invisible
ProcSubset=pid
```

```bash
# Reload systemd and restart the service:
sudo systemctl daemon-reload
sudo systemctl restart nginx

# Verify the service is running:
sudo systemctl status nginx
# Expected: active (running)

# Check the new security score:
systemd-analyze security nginx.service
# Expected: score drops from ~9.6 to ~2.0-3.5
```

### Hardened Overrides for Other Common Services

**PostgreSQL:**

```ini
# /etc/systemd/system/postgresql@.service.d/hardening.conf
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ReadWritePaths=/var/lib/postgresql /var/log/postgresql /run/postgresql
CapabilityBoundingSet=
NoNewPrivileges=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
```

**Redis:**

```ini
# /etc/systemd/system/redis-server.service.d/hardening.conf
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ReadWritePaths=/var/lib/redis /var/log/redis /run/redis
CapabilityBoundingSet=
NoNewPrivileges=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
```

**Node Exporter ([Prometheus](https://prometheus.io)):**

```ini
# /etc/systemd/system/node_exporter.service.d/hardening.conf
[Service]
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ReadWritePaths=
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
NoNewPrivileges=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
```

Note: Node Exporter needs `CAP_DAC_READ_SEARCH` to read `/proc` and `/sys` metrics, and `AF_NETLINK` for network interface stats.

### Testing Procedure

Always test hardening changes before applying to production:

```bash
# 1. Apply the override
sudo systemctl edit nginx.service  # paste the override
sudo systemctl daemon-reload

# 2. Restart and check status
sudo systemctl restart nginx
sudo systemctl status nginx
# If the service fails to start: check the journal for the specific error.
sudo journalctl -u nginx.service -n 20 --no-pager

# 3. Run functional tests
curl -s -o /dev/null -w "%{http_code}" http://localhost/
# Expected: 200 (or your expected response code)

# 4. Check the security score
systemd-analyze security nginx.service
# Expected: significant improvement from baseline

# 5. If it breaks: remove the override and restart
sudo rm /etc/systemd/system/nginx.service.d/hardening.conf
sudo systemctl daemon-reload
sudo systemctl restart nginx
```

## Expected Behaviour

After applying hardened overrides:

- `systemd-analyze security <service>` scores drop from ~9.6 (UNSAFE) to ~2.0-3.5 (OK/MEDIUM)
- Services start successfully and pass all functional tests
- `ProtectSystem=strict` prevents the service from writing outside declared `ReadWritePaths`
- `PrivateTmp=yes` gives each service its own `/tmp`, files in one service's `/tmp` are invisible to other services
- `CapabilityBoundingSet=` drops all capabilities, the service cannot bind to privileged ports, raw sockets, or change file ownership
- `SystemCallFilter=@system-service` blocks mount, reboot, kexec, module loading, and other dangerous syscalls
- `NoNewPrivileges=yes` prevents setuid binaries from escalating privileges even if the service can execute them

## Trade-offs

| Directive | Impact | Risk | Mitigation |
|-----------|--------|------|------------|
| `ProtectSystem=strict` | All writes outside `ReadWritePaths` fail with EROFS | Service fails to write logs, PID files, or data if paths not listed | Audit write paths with `strace -e write` before hardening. Add all required paths to `ReadWritePaths`. |
| `PrivateTmp=yes` | Services cannot share files via `/tmp` | Breaks services that use `/tmp` for inter-process communication | Use `BindPaths` to share specific directories between services instead of `/tmp`. |
| `SystemCallFilter=@system-service` | Blocks unusual syscalls | Application updates may use syscalls not in the group | Test after every application update. Add specific syscalls with `SystemCallFilter=@system-service madvise io_uring_setup` if needed. |
| `CapabilityBoundingSet=` (empty) | Service cannot bind to ports <1024 | Web servers on port 80/443 fail to start | Add `CAP_NET_BIND_SERVICE` for port <1024. Or run behind a reverse proxy on a high port. |
| `PrivateNetwork=yes` | Complete network isolation | Service cannot make any network connections | Only use for services with zero network needs (batch processors, local-only workers). |
| `DynamicUser=yes` | No persistent UID; data ownership changes on restart | Breaks services that need to own persistent files | Use `User=`/`Group=` with static UIDs instead. `DynamicUser` works for stateless services only. |
| `ProtectProc=invisible` | Service cannot see other processes | Monitoring tools that enumerate processes will see only their own | Use `ProtectProc=default` for monitoring agents. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| `ReadWritePaths` missing required path | Service crashes on write; EROFS error in journal | `journalctl -u <service>` shows "Read-only file system" | Add the missing path to `ReadWritePaths`. Reload and restart. |
| `SystemCallFilter` blocks required syscall | Service segfaults or returns EPERM on specific operation | `journalctl` shows `seccomp` audit entries; `dmesg` shows blocked syscall name and number | Add the specific syscall to the filter: `SystemCallFilter=@system-service <syscall_name>`. |
| `CapabilityBoundingSet` missing required cap | Service fails to bind port or access restricted resource | Service logs show "Permission denied" for specific operation | Add the required capability. Check the table above for common service requirements. |
| `PrivateTmp` breaks shared temp files | Service A can't find files written by Service B in /tmp | Application logs show "File not found" for paths in /tmp | Use `BindPaths=/shared:/tmp` to share a specific directory. Or move shared files to a non-tmp location. |
| Override breaks on package upgrade | New service features fail because the override is too restrictive | Service misbehaves after `apt upgrade`; new features return errors | Review systemd overrides after package upgrades. Run `systemd-analyze security` to check for new requirements. |

## When to Consider a Managed Alternative

**Transition point:** When maintaining custom systemd overrides across 20+ services and 2+ distributions becomes operational toil (4-8 hours/month), or when the team is moving workloads to containers where application-level sandboxing (seccomp, [AppArmor](https://apparmor.net), capabilities) is handled at the container runtime and orchestration layer.

**What managed providers handle:**

Managed [Kubernetes](https://kubernetes.io) providers (Civo #22, DigitalOcean #21, Vultr #12, Linode #13) abstract service management entirely. Workloads run in containers with their own isolation mechanisms (seccomp profiles, security contexts, network policies). The underlying systemd unit files for kubelet and [containerd](https://containerd.io) are managed by the provider.

Runtime security platforms ([Sysdig](https://sysdig.com) and [Aqua](https://www.aquasec.com)) can audit systemd unit hardening compliance across a fleet and alert on drift. They verify that overrides are in place and that security scores meet your threshold.

**What you still control:** For services that run directly on hosts (not in containers) (SSH, databases, monitoring agents) systemd hardening remains your responsibility and this article's guidance applies directly.

**Premium content pack:** Pre-built systemd hardening override files for 15 common services (nginx, postgresql, redis, mysql, node_exporter, prometheus, grafana, elasticsearch, haproxy, chronyd, unbound, fail2ban, certbot, docker, containerd), tested on Ubuntu 24.04 LTS and RHEL 9, with per-service documentation of required `ReadWritePaths` and capabilities.


## Related Articles

- [Hardening the Linux Kernel Attack Surface with sysctl and Boot Parameters](/articles/linux/sysctl-kernel-hardening/)
- [Cgroup v2 Resource Isolation: Preventing Resource Exhaustion Attacks on Shared Systems](/articles/linux/cgroup-resource-isolation/)
- [Kernel Module Hardening: Blacklisting, Signing, and Preventing Runtime Loading](/articles/linux/kernel-module-hardening/)
- [SELinux in Production: Writing Custom Policies Without Losing Your Mind](/articles/linux/selinux/)
- [AppArmor Profiles for Custom Applications: From Complain Mode to Enforce](/articles/linux/apparmor/)
