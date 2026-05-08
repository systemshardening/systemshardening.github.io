---
title: "AppArmor Profiles for Custom Applications: From Complain Mode to Enforce"
description: "AppArmor is the default mandatory access control system on Ubuntu and Debian. It restricts applications to specific file paths, capabilities, and..."
slug: "apparmor"
date: 2026-01-18
lastmod: 2026-01-18
category: "linux"
tags: ["apparmor", "mac", "hardening", "ubuntu", "profiles", "confinement"]
personas: ["systems-engineer", "platform-engineer"]
article_number: 4
difficulty: "intermediate"
estimated_reading_time: 14
provider_bridges:
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
  - name: "Aqua"
    id: 123
    category: "runtime-security"
premium_pack: "apparmor-profile-collection"
published: true
layout: article.njk
permalink: "/articles/linux/apparmor/index.html"
---

# [AppArmor](https://apparmor.net) Profiles for Custom Applications: From Complain Mode to Enforce

## Problem

AppArmor is the default mandatory access control system on Ubuntu and Debian. It restricts applications to specific file paths, capabilities, and network access. Most applications (including custom ones) run without an AppArmor profile, meaning they have unrestricted access to anything the Unix user can reach.

Creating custom profiles requires iterative profiling that can break applications if done carelessly. The workflow (complain → observe → refine → enforce) takes 4-8 hours per application but provides confinement that survives application compromises.

**Target systems:** Ubuntu 24.04 LTS, Debian 12+. AppArmor is also available in [Kubernetes](https://kubernetes.io) via pod annotations.

## Threat Model

- **Adversary:** Attacker with code execution inside a service. AppArmor confines the compromised service to specific paths and capabilities regardless of Unix permissions.

## Configuration

### Generating an Initial Profile

```bash
# Install AppArmor utilities
sudo apt install apparmor-utils

# Generate a profile for a custom application
sudo aa-genprof /opt/myapp/bin/myapp
# This starts the application in complain mode and monitors for access requests.
# Follow the interactive prompts to allow/deny each access.

# Alternative: generate from existing log data
sudo aa-logprof
# Reads AppArmor logs and suggests profile additions.
```

### Manual Profile Writing

```
# /etc/apparmor.d/opt.myapp.bin.myapp
# AppArmor profile for custom web application

#include <tunables/global>

/opt/myapp/bin/myapp {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  # Binary itself
  /opt/myapp/bin/myapp mr,

  # Configuration files (read-only)
  /opt/myapp/config/ r,
  /opt/myapp/config/** r,

  # Data directory (read-write)
  /opt/myapp/data/ rw,
  /opt/myapp/data/** rw,

  # Log files (write, append, create)
  /var/log/myapp/ rw,
  /var/log/myapp/** w,

  # Temporary files
  /tmp/myapp-* rw,

  # Shared libraries
  /usr/lib/** mr,
  /lib/** mr,

  # Network: allow TCP on port 8080
  network inet stream,
  network inet6 stream,

  # DNS resolution
  /etc/resolv.conf r,
  /etc/nsswitch.conf r,
  /etc/hosts r,

  # Deny everything else implicitly
  # AppArmor denies any access not explicitly allowed.
}
```

### Complain → Enforce Workflow

```bash
# Step 1: Load profile in complain mode (log but don't block)
sudo apparmor_parser -r -C /etc/apparmor.d/opt.myapp.bin.myapp
sudo aa-complain /opt/myapp/bin/myapp

# Step 2: Exercise the application (1-2 weeks of normal usage)
# All denied accesses are logged but allowed.

# Step 3: Review denials and update profile
sudo aa-logprof
# Interactive: for each denial, choose Allow, Deny, or Glob.

# Step 4: Switch to enforce mode
sudo aa-enforce /opt/myapp/bin/myapp

# Step 5: Monitor for violations
sudo dmesg | grep apparmor
# Look for DENIED entries - these indicate the profile is too restrictive.
```

### Kubernetes Integration

```yaml
# Pod with AppArmor profile
apiVersion: v1
kind: Pod
metadata:
  name: myapp
  annotations:
    container.apparmor.security.beta.kubernetes.io/myapp: localhost/myapp-profile
spec:
  containers:
    - name: myapp
      image: registry.example.com/myapp:v1
```

```bash
# Load the profile on all nodes:
# Deploy via DaemonSet that copies profiles to each node
kubectl apply -f - <<'EOF'
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: apparmor-loader
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: apparmor-loader
  template:
    metadata:
      labels:
        app: apparmor-loader
    spec:
      containers:
        - name: apparmor-loader
          image: registry.example.com/apparmor-loader:v1
          command: ["sh", "-c", "cp /profiles/* /etc/apparmor.d/ && apparmor_parser -r /etc/apparmor.d/myapp-profile && sleep infinity"]
          volumeMounts:
            - name: apparmor-dir
              mountPath: /etc/apparmor.d
            - name: profiles
              mountPath: /profiles
      volumes:
        - name: apparmor-dir
          hostPath:
            path: /etc/apparmor.d
        - name: profiles
          configMap:
            name: apparmor-profiles
EOF
```

### Monitoring Violations

```bash
# Check for AppArmor denials in kernel log
sudo dmesg | grep "apparmor=\"DENIED\""

# Parse denials for monitoring
sudo journalctl -k | grep "apparmor=\"DENIED\"" | \
  awk '{for(i=1;i<=NF;i++) if($i ~ /profile=|operation=|name=/) print $i}'

# Prometheus: export AppArmor denial count via node_exporter textfile
echo "apparmor_denied_total $(dmesg | grep -c 'apparmor=\"DENIED\"')" > \
  /var/lib/node_exporter/apparmor.prom
```

## Expected Behaviour

- `aa-status` shows the application profile in enforce mode
- `dmesg | grep apparmor` shows zero DENIED entries during normal operation
- Application runs normally with full functionality
- Any access outside the profile is blocked and logged

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Complain mode (1-2 weeks) | No security enforcement during learning | Attacks during complain mode are unconfined | Use complain mode in staging, not production. Switch to enforce before production deployment. |
| Path-based profiles | Easy to write and understand | New file paths from application updates break the profile | Update profiles as part of the deployment pipeline. Test in complain mode after updates. |
| Kubernetes AppArmor | Per-container confinement | Profile must be loaded on every node | DaemonSet-based profile loader ensures all nodes have the profile. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Profile too restrictive | Application crashes or returns errors | `dmesg` shows DENIED entries; application logs show "Permission denied" | Switch to complain mode. Identify missing paths. Update profile. Re-enforce. |
| Profile not loaded on node | Pod fails to start with AppArmor error | `kubectl describe pod` shows AppArmor profile not found | Verify DaemonSet-based profile loader. Check profile exists on the node. |
| Application update adds new paths | Feature breaks after update (profile blocks new file access) | DENIED entries in dmesg after application update | Update profile to include new paths. Test in complain mode first. |

## When to Consider a Managed Alternative

Profile creation takes 4-8 hours per application. Maintaining profiles across application updates requires ongoing effort.

- **[Sysdig](https://sysdig.com) and [Aqua](https://www.aquasec.com):** Provide automated profile generation from observed behaviour. Managed runtime enforcement handles MAC-equivalent confinement for containers.
- **Managed Kubernetes:** Providers handle node-level AppArmor. Container workloads use seccomp and capabilities ([Hardening a Complete Kubernetes Platform: From Cluster Bootstrap to Production-Ready](/articles/cross-cutting/complete-kubernetes-hardening/)) which are simpler to manage.

**Premium content pack:** AppArmor profile collection for common applications (nginx, postgresql, redis, node, python, go) with Kubernetes deployment configurations and a profile update workflow guide.


## Related Articles

- [SELinux in Production: Writing Custom Policies Without Losing Your Mind](/articles/linux/selinux/)
- [systemd Unit Hardening: ProtectSystem, PrivateTmp, and the Full Sandbox Toolkit](/articles/linux/systemd-unit-hardening/)
- [Automated OS Hardening with Ansible: A Production-Ready Playbook Collection](/articles/linux/ansible-os-hardening/)
- [Hardening the Linux Kernel Attack Surface with sysctl and Boot Parameters](/articles/linux/sysctl-kernel-hardening/)
- [Kernel Module Hardening: Blacklisting, Signing, and Preventing Runtime Loading](/articles/linux/kernel-module-hardening/)
