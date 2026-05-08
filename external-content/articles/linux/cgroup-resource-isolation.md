---
title: "Cgroup v2 Resource Isolation: Preventing Resource Exhaustion Attacks on Shared Systems"
description: "Without resource limits, a single service, container, or compromised process can consume all available CPU, memory, I/O bandwidth, or PIDs on a host."
slug: "cgroup-resource-isolation"
date: 2026-02-21
lastmod: 2026-02-21
category: "linux"
tags: ["cgroups", "resource-isolation", "systemd", "containers", "linux", "denial-of-service"]
personas: ["systems-engineer", "platform-engineer"]
article_number: 12
difficulty: "intermediate"
estimated_reading_time: 15
provider_bridges:
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
  - name: "Civo"
    id: 22
    category: "managed-kubernetes"
published: true
layout: article.njk
permalink: "/articles/linux/cgroup-resource-isolation/index.html"
---

# Cgroup v2 Resource Isolation: Preventing Resource Exhaustion Attacks on Shared Systems

## Problem

Without resource limits, a single service, container, or compromised process can consume all available CPU, memory, I/O bandwidth, or PIDs on a host. This denies service to every other workload on the same machine:

- A fork bomb (`:(){ :|:& };:`) creates processes exponentially until the system runs out of PIDs and becomes unresponsive.
- A memory leak in one service triggers the kernel OOM killer, which may kill a different, healthy service that happens to be the largest consumer.
- A runaway log rotation or backup job saturates disk I/O, causing database queries on the same host to time out.
- A cryptocurrency miner deployed through a compromised dependency pins all CPU cores at 100%, starving legitimate workloads.

Cgroup v2 (the unified cgroup hierarchy) is the mechanism Linux provides to enforce per-service and per-container resource limits. It is built into the kernel and managed through [systemd](https://systemd.io) on modern distributions. Most teams do not configure limits until after an incident, because profiling workloads to set correct limits takes effort.

**Target systems:** Ubuntu 24.04 LTS, Debian 12, RHEL 9 / Rocky Linux 9, any system running systemd 252+ with kernel 5.15+.

## Threat Model

- **Adversary:** Compromised service performing resource exhaustion (either intentionally by an attacker, or unintentionally through a bug or misconfiguration). Or: an unprivileged local user running a fork bomb or memory-consuming process.
- **Access level:** Any process running on the host, including containerized workloads.
- **Objective:** Denial of service to other workloads on the same host. Force the OOM killer to terminate critical services. Saturate I/O to cause cascading timeouts.
- **Blast radius:** All services on the host. Without resource isolation, one workload's resource consumption affects every other workload sharing the same kernel.

## Configuration

### Verify Cgroup v2 is Active

```bash
# Check cgroup version
stat -fc %T /sys/fs/cgroup
# Expected output: "cgroup2fs" (cgroup v2)
# If output is "tmpfs", you are on cgroup v1

# Verify systemd is using the unified hierarchy
cat /proc/cmdline | grep -o 'systemd.unified_cgroup_hierarchy=[0-9]'
# Expected: systemd.unified_cgroup_hierarchy=1 (or absent, which defaults to v2 on modern distros)
```

If you are still on cgroup v1, migrate by adding the kernel parameter:

```bash
# /etc/default/grub
GRUB_CMDLINE_LINUX="$EXISTING_VALUES systemd.unified_cgroup_hierarchy=1"
```

```bash
sudo update-grub && sudo systemctl reboot
```

### systemd Slice Configuration

systemd organises services into slices. Configure resource limits per slice to isolate categories of workloads.

Create a slice for web-facing services:

```ini
# /etc/systemd/system/web.slice
[Slice]
Description=Web Services Slice

# CPU: relative weight (1-10000, default 100)
# This slice gets 4x the CPU of a default slice when there is contention.
# When CPU is idle, there is no restriction.
CPUWeight=400

# Memory: hard limit. OOM killer activates if this is exceeded.
MemoryMax=4G

# Memory: high watermark. The kernel reclaims memory aggressively above this.
# Processes are not killed but are slowed by reclaim pressure.
MemoryHigh=3G

# I/O: relative weight (1-10000, default 100)
IOWeight=200

# PIDs: maximum number of tasks (processes + threads)
TasksMax=4096
```

Assign a service to the slice:

```ini
# /etc/systemd/system/myapp.service.d/resources.conf
[Service]
Slice=web.slice

# Per-service limits within the slice
MemoryMax=2G
MemoryHigh=1536M
CPUQuota=200%
TasksMax=512
```

Create a slice for background/batch work:

```ini
# /etc/systemd/system/batch.slice
[Slice]
Description=Batch Processing Slice
CPUWeight=50
MemoryMax=2G
MemoryHigh=1536M
IOWeight=50
TasksMax=1024
```

Apply the changes:

```bash
sudo systemctl daemon-reload

# Move a running service to the new slice
sudo systemctl set-property myapp.service Slice=web.slice

# Verify cgroup placement
systemd-cgls
```

### Preventing Fork Bombs with PID Limits

The most effective fork bomb defence is a PID limit. Without one, a fork bomb will exhaust the system-wide PID space (default: 32768 on most systems).

```ini
# /etc/systemd/system/user-.slice.d/pid-limit.conf
[Slice]
# Limit each user session to 512 tasks
TasksMax=512
```

For the system-wide default:

```ini
# /etc/systemd/system.conf.d/pid-limits.conf
[Manager]
DefaultTasksMax=4096
```

Test the fork bomb defence:

```bash
# As an unprivileged user with the PID limit applied:
:(){ :|:& };:
# Expected: the fork bomb hits the TasksMax limit quickly.
# The user's session becomes slow but other services are unaffected.
# Check with: systemctl status user-1000.slice
```

### Container Runtime Cgroup Settings

For [containerd](https://containerd.io), configure default resource limits:

```toml
# /etc/containerd/config.toml
[plugins."io.containerd.cri.v1.runtime"]
  [plugins."io.containerd.cri.v1.runtime".containerd]
    [plugins."io.containerd.cri.v1.runtime".containerd.runtimes]
      [plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runc]
        [plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runc.options]
          SystemdCgroup = true
```

`SystemdCgroup = true` ensures containerd uses the systemd cgroup driver, which places containers in the systemd hierarchy and makes them visible to `systemd-cgtop` and `systemctl` tooling.

### [Kubernetes](https://kubernetes.io) Resource Limits

In Kubernetes, resource limits map to cgroup constraints on the node:

```yaml
# Pod specification with resource limits
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  containers:
    - name: app
      image: myapp:v1.2.3
      resources:
        requests:
          memory: "256Mi"
          cpu: "250m"
        limits:
          memory: "512Mi"
          cpu: "1000m"
```

Enforce defaults across a namespace with a LimitRange:

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: production
spec:
  limits:
    - default:
        memory: "512Mi"
        cpu: "500m"
      defaultRequest:
        memory: "128Mi"
        cpu: "100m"
      max:
        memory: "4Gi"
        cpu: "4000m"
      type: Container
```

### Monitoring with systemd-cgtop

```bash
# Real-time cgroup resource usage (like top, but for cgroups)
systemd-cgtop

# Check a specific slice
systemctl status web.slice
# Shows: CPU, memory, and task count for the slice and all services in it

# Check cgroup limits for a service
systemctl show myapp.service | grep -E 'Memory|CPU|Tasks'
# MemoryMax=2147483648
# CPUQuota=200%
# TasksMax=512
```

### Detecting Cgroup Escapes

Monitor for processes running outside expected cgroup hierarchies:

```bash
#!/bin/bash
# detect-cgroup-escape.sh
# Alert if any non-kernel process is in the root cgroup

for pid in /proc/[0-9]*; do
    pid_num=$(basename "$pid")
    cgroup=$(cat "$pid/cgroup" 2>/dev/null)
    
    # Processes in the root cgroup (0::/) should only be kernel threads
    if echo "$cgroup" | grep -q "^0::/$" ; then
        name=$(cat "$pid/comm" 2>/dev/null)
        # Kernel threads have PPID 2 (kthreadd)
        ppid=$(awk '/^PPid:/{print $2}' "$pid/status" 2>/dev/null)
        if [ "$ppid" != "2" ] && [ "$ppid" != "0" ]; then
            echo "WARNING: Process $pid_num ($name) is in root cgroup"
        fi
    fi
done
```

## Expected Behaviour

After configuring cgroup v2 resource limits:

- `stat -fc %T /sys/fs/cgroup` returns `cgroup2fs`
- `systemd-cgtop` shows resource usage broken down by slice and service
- A service exceeding its `MemoryMax` is killed by the OOM killer within the cgroup (not the system-wide OOM killer)
- A fork bomb in a user session hits `TasksMax` and new `fork()` calls return `EAGAIN` instead of creating new processes
- CPU-bound processes in a low-weight slice are throttled when high-weight slices need CPU
- I/O-bound batch jobs do not starve latency-sensitive web services
- Container resource limits appear as cgroup constraints under `/sys/fs/cgroup/system.slice/`
- Other services on the host continue operating normally during a resource exhaustion event in an isolated slice

## Trade-offs

| Control | Benefit | Cost | Mitigation |
|---------|---------|------|------------|
| CPU limits (CPUQuota) | Prevents CPU starvation | Causes throttling and latency spikes during CPU contention even if other CPUs are idle. CFS bandwidth throttling can add up to 5ms per scheduling period. | Use CPUWeight (relative) instead of CPUQuota (absolute) when possible. CPUWeight only restricts when there is contention. |
| Memory limits (MemoryMax) | Prevents one service from consuming all RAM | Triggers OOM kill when the limit is hit. If the limit is too low, the service restarts repeatedly. | Set MemoryHigh to 75% of MemoryMax. This applies memory pressure (reclaim) before the hard kill. Profile workloads for 1-2 weeks before setting final limits. |
| PID limits (TasksMax) | Prevents fork bombs and runaway thread creation | Applications with large thread pools (Java, Go with many goroutines) may hit the limit under normal load. | Profile the application's peak task count and set TasksMax to 2x that value. Monitor `tasks_current` via systemd or [Prometheus](https://prometheus.io). |
| I/O limits (IOWeight) | Prevents I/O starvation | Batch jobs take longer to complete when I/O-sensitive services need bandwidth. | Use IOWeight (relative) for fairness. Use IOReadBandwidthMax/IOWriteBandwidthMax only when you need a hard ceiling. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| MemoryMax too low | Service is OOM-killed repeatedly, enters a restart loop | `journalctl -u myapp.service` shows "Out of memory" and rapid restart/stop cycles; `systemctl status` shows "oom-kill" | Increase MemoryMax. Check `memory.peak` in the cgroup to find the actual peak usage: `cat /sys/fs/cgroup/web.slice/myapp.service/memory.peak` |
| CPUQuota too restrictive | Service responds slowly, request timeouts increase | Application latency metrics spike. `systemd-cgtop` shows the service at 100% of its quota while the host has idle CPU. | Switch from CPUQuota to CPUWeight, or increase the quota. CPUWeight is almost always the better choice for production services. |
| TasksMax hit during normal operation | Application fails to create new threads or processes | Application logs show "Resource temporarily unavailable" or "Cannot allocate memory" (misleading). `systemctl show myapp.service -p TasksCurrent` shows current equals max. | Increase TasksMax. Profile the application to understand its thread/process model. |
| Cgroup v1/v2 mismatch | Container runtime fails to start or cannot apply limits | containerd/[Docker](https://www.docker.com) logs show "cgroup driver mismatch" or "failed to create cgroup" | Ensure both the kernel and the container runtime use the same cgroup version. Set `SystemdCgroup = true` in containerd config and `systemd.unified_cgroup_hierarchy=1` in boot params. |
| OOM killer targets wrong process | The OOM killer in a cgroup kills a critical subprocess instead of the one consuming the most memory | Post-mortem shows the wrong process was killed. `dmesg` shows OOM details. | Set `OOMPolicy=kill` in the systemd service to kill the entire service instead of individual processes. Use `oom_score_adj` to prioritize which processes survive. |

## When to Consider a Managed Alternative

**Transition point:** When you are fine-tuning cgroup limits per workload across more than 10 services, spending 2-4 hours profiling each service, and need to maintain those limits as workload patterns change.

**What managed providers handle:**

Managed Kubernetes providers ([Civo](https://www.civo.com), [DigitalOcean](https://www.digitalocean.com), [Vultr](https://www.vultr.com), [Linode](https://www.linode.com)) enforce resource isolation at the platform level. Kubernetes resource requests and limits translate to cgroup v2 constraints on the node, and the kubelet handles the cgroup hierarchy. You define resource requirements in your pod specs, and the platform handles the low-level enforcement.

Runtime security platforms ([Sysdig](https://sysdig.com)) monitor for resource abuse patterns and cgroup escape attempts. They can detect when a process breaks out of its expected cgroup hierarchy, when resource consumption patterns indicate cryptomining, or when a fork bomb is in progress.

**What you still control:** Even on managed Kubernetes, you must set resource requests and limits in your pod specifications. The platform enforces them, but you define the values. Use Kubernetes LimitRange and ResourceQuota objects to set namespace-level defaults and ceilings so that no team can deploy without resource limits.

**Automation path:** For self-managed hosts, start with the systemd slice configuration in this article. Profile workloads for 1-2 weeks using `systemd-cgtop` and `memory.peak` readings before setting hard limits. For fleet-wide enforcement, integrate resource limit verification into your configuration management tool.


## Related Articles

- [systemd Unit Hardening: ProtectSystem, PrivateTmp, and the Full Sandbox Toolkit](/articles/linux/systemd-unit-hardening/)
- [Hardening the Linux Kernel Attack Surface with sysctl and Boot Parameters](/articles/linux/sysctl-kernel-hardening/)
- [Filesystem Mount Options That Matter: noexec, nosuid, nodev, and Beyond](/articles/linux/filesystem-mount-options/)
- [Linux Audit Framework Deep Dive: auditd Rules, auditctl, and ausearch for Security Monitoring](/articles/linux/auditd-deep-dive/)
- [Hardening GRUB and the Boot Process: Secure Boot, Boot Passwords, and Tamper Detection](/articles/linux/grub-boot-hardening/)
