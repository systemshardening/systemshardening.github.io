---
title: "SELinux in Production: Writing Custom Policies Without Losing Your Mind"
description: "SELinux is the most powerful mandatory access control system on Linux, and the most disabled. The result: services have no MAC confinement."
slug: "selinux"
date: 2026-02-21
lastmod: 2026-02-21
category: "linux"
tags: ["selinux", "mac", "hardening", "rhel", "policy", "audit2allow"]
personas: ["systems-engineer", "security-engineer"]
article_number: 3
difficulty: "advanced"
estimated_reading_time: 18
provider_bridges:
  - name: "Aqua"
    id: 123
    category: "runtime-security"
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
premium_pack: "selinux-policy-collection"
published: true
layout: article.njk
permalink: "/articles/linux/selinux/index.html"
---

# [SELinux](https://github.com/SELinuxProject/selinux) in Production: Writing Custom Policies Without Losing Your Mind

## Problem

SELinux is the most powerful mandatory access control system on Linux, and the most disabled. The majority of RHEL/Rocky/Fedora systems in production run with `setenforce 0` (permissive mode, effectively disabled) because custom policy writing is painful. The result: services have no MAC confinement. A compromised web server running without SELinux can read any file the web server user can access, write to any writable path, and make arbitrary network connections.

SELinux in enforcing mode confines each service to exactly the files, ports, and capabilities it needs. A compromised confined service cannot access files outside its policy, cannot bind to unexpected ports, and cannot execute unexpected binaries.

The gap: engineers do not know how to write targeted policies for custom applications, how to troubleshoot AVC denials without disabling SELinux, or how to test policies in CI before production.

**Target systems:** RHEL 9, Rocky Linux 9, Fedora 38+. SELinux is also available on Debian/Ubuntu but is not the default MAC ([AppArmor](https://apparmor.net) is, see [AppArmor Profiles for Custom Applications: From Complain Mode to Enforce](/articles/linux/apparmor/)).

## Threat Model

- **Adversary:** Attacker with code execution inside a service. SELinux limits what the compromised service can access regardless of the service's Unix user permissions.
- **Blast radius:** Without SELinux, full access as the service user (often extensive). With SELinux, confined to the service's type enforcement policy (read-only access to specific files, specific ports, no shell execution).

## Configuration

### Verifying and Enabling SELinux

```bash
# Check current SELinux status
getenforce
# Expected: Enforcing (if already enabled)
# If Permissive or Disabled: enable it

sestatus
# SELinux status:                 enabled
# Current mode:                   enforcing
# Policy:                         targeted

# If disabled: edit /etc/selinux/config
# SELINUX=enforcing
# Reboot required after changing from disabled to enforcing.

# To transition safely: set to permissive first, reboot, check for AVC denials,
# then switch to enforcing:
sudo setenforce 0  # Permissive (logs denials but doesn't block)
# Fix all AVC denials, then:
sudo setenforce 1  # Enforcing
```

### Understanding AVC Denials

When SELinux blocks an action, it logs an AVC (Access [Vector](https://vector.dev) Cache) denial:

```bash
# View recent AVC denials
sudo ausearch -m AVC -ts recent

# Example denial:
# type=AVC msg=audit(1713830400.123:456): avc:  denied  { read } for
#   pid=12345 comm="nginx" name="custom.conf" dev="vda1" ino=67890
#   scontext=system_u:system_r:httpd_t:s0
#   tcontext=system_u:object_r:etc_t:s0
#   tclass=file permissive=0

# Translation: nginx (running as httpd_t) tried to read custom.conf
# (labelled as etc_t), and was denied because httpd_t cannot read etc_t files.
```

```bash
# Use sealert for human-readable analysis (install setroubleshoot):
sudo dnf install setroubleshoot-server
sudo sealert -a /var/log/audit/audit.log

# Output explains the denial and suggests fixes.
```

### Creating Custom Policies with audit2allow

The standard workflow for custom applications:

```bash
# Step 1: Run the application in permissive mode to collect all denials
sudo setenforce 0
systemctl restart myapp

# Step 2: Exercise all application functionality (API calls, file access, etc.)
# Generate realistic traffic that exercises all code paths.

# Step 3: Generate a policy module from the denials
sudo ausearch -m AVC -ts today | audit2allow -M myapp_policy

# This creates:
# myapp_policy.te  - Type Enforcement source
# myapp_policy.pp  - Compiled policy module

# Step 4: Review the .te file before installing
cat myapp_policy.te
# Look for overly broad permissions. audit2allow often generates
# broader permissions than needed. Refine manually if possible.

# Step 5: Install the policy module
sudo semodule -i myapp_policy.pp

# Step 6: Return to enforcing mode
sudo setenforce 1

# Step 7: Test the application again - all functionality should work
# If new denials appear: repeat the process, adding to the policy.
```

**Warning about `audit2allow -M`:** This tool generates the minimum policy to allow all observed denials. It may be overly permissive if the application was exercised with too-broad permissions. Always review the `.te` file manually.

### Writing Type Enforcement Policies Manually

For more control than `audit2allow` provides:

```
# myapp.te - Type Enforcement policy for a custom web application

policy_module(myapp, 1.0.0)

# Declare types
type myapp_t;         # Process type
type myapp_exec_t;    # Executable type
type myapp_data_t;    # Data directory type
type myapp_log_t;     # Log file type

# Domain transition: when myapp_exec_t is executed, the process becomes myapp_t
init_daemon_domain(myapp_t, myapp_exec_t)

# File contexts
require {
    type httpd_port_t;
    type node_t;
}

# Allow the process to:
# - Read its own config files
allow myapp_t myapp_data_t:file { read open getattr };
allow myapp_t myapp_data_t:dir { search getattr };

# - Write to its log directory
allow myapp_t myapp_log_t:file { write create append open getattr };
allow myapp_t myapp_log_t:dir { write add_name search getattr };

# - Bind to HTTP ports (80, 443)
allow myapp_t httpd_port_t:tcp_socket { name_bind };

# - Make outbound TCP connections
allow myapp_t node_t:tcp_socket { node_bind };

# - Read /etc/resolv.conf for DNS
allow myapp_t etc_t:file { read open getattr };
```

```bash
# File context definitions
# myapp.fc - assign SELinux labels to application files
/opt/myapp(/.*)?                gen_context(system_u:object_r:myapp_data_t,s0)
/opt/myapp/bin/myapp            gen_context(system_u:object_r:myapp_exec_t,s0)
/var/log/myapp(/.*)?            gen_context(system_u:object_r:myapp_log_t,s0)
```

```bash
# Compile and install
make -f /usr/share/selinux/devel/Makefile myapp.pp
sudo semodule -i myapp.pp

# Apply file contexts
sudo restorecon -Rv /opt/myapp /var/log/myapp

# Verify labels
ls -lZ /opt/myapp/bin/myapp
# -rwxr-xr-x. root root system_u:object_r:myapp_exec_t:s0 /opt/myapp/bin/myapp
```

### CI Pipeline for SELinux Policy Testing

```yaml
# .github/workflows/selinux-test.yml
name: SELinux Policy Test
on: [push, pull_request]

jobs:
  test-policy:
    runs-on: ubuntu-latest
    container:
      image: rockylinux:9
      options: --privileged  # Required for SELinux testing
    steps:
      - uses: actions/checkout@v4

      - name: Install SELinux development tools
        run: |
          dnf install -y selinux-policy-devel policycoreutils

      - name: Compile policy
        run: |
          make -f /usr/share/selinux/devel/Makefile myapp.pp

      - name: Validate policy syntax
        run: |
          semodule -l | grep myapp || semodule -i myapp.pp
          sesearch -A -s myapp_t | head -20
          # Verify expected permissions are present
          sesearch -A -s myapp_t -t myapp_data_t -c file | grep -q "read"
          echo "OK: myapp_t can read myapp_data_t files"
```

### SELinux vs AppArmor

| Feature | SELinux | AppArmor |
|---------|---------|----------|
| Default on | RHEL, Rocky, Fedora | Ubuntu, Debian, SUSE |
| Policy model | Type enforcement (label-based) | Path-based profiles |
| Granularity | Very fine (per-type, per-class, per-permission) | Medium (per-path, per-capability) |
| Learning curve | Steep (requires understanding types, contexts, transitions) | Moderate (path-based is more intuitive) |
| [Kubernetes](https://kubernetes.io) integration | Supported (SELinux contexts in SecurityContext) | Supported (AppArmor annotations) |
| Custom policy creation | 8-16 hours for first policy; 2-4 hours after experience | 4-8 hours for first profile; 1-2 hours after experience |
| Recommendation | Use on RHEL/Rocky systems | Use on Ubuntu/Debian systems |

## Expected Behaviour

- `getenforce` returns `Enforcing` on all production hosts
- Custom applications run with targeted SELinux policies
- `ausearch -m AVC` shows zero denials during normal operation
- Policy modules versioned in Git and deployed via CI/CD
- New application deployments include SELinux policy as part of the deployment

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Enforcing mode globally | Services confined to their type policy | Application breaks if policy is missing or incomplete | Start with permissive mode. Test thoroughly. Switch to enforcing per-service. |
| Custom policies via audit2allow | Quick policy generation from observed behaviour | Overly broad if exercised with too-wide scope | Review generated `.te` file manually. Narrow permissions where possible. |
| Manual type enforcement policies | Most precise confinement | 8-16 hours per application for initial policy | Use audit2allow for the first pass, then refine manually for critical services. |
| CI testing of policies | Catches syntax errors before deployment | Cannot fully test runtime behaviour in CI (no real syscall enforcement) | Supplement CI testing with staging environment testing in enforcing mode. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Missing policy for application | Application fails with "Permission denied" in enforcing mode | `ausearch -m AVC` shows denials for the application's type | Generate policy with `audit2allow`. Install. Restart application. |
| Policy too restrictive | Application works in permissive but fails in enforcing | AVC denials in audit log when switching to enforcing | Add the missing permissions to the policy. Recompile. Install. Restart. |
| File context not applied | Files have wrong SELinux labels; access denied | `ls -lZ` shows unexpected context (e.g., `unlabeled_t`) | `restorecon -Rv /path/to/files` to apply correct contexts. |
| Policy conflict after package update | Package update installs a policy that conflicts with custom policy | Application breaks after `dnf update`; AVC denials appear | Audit the conflict: `semodule -l` to list all modules. Adjust custom policy to work with the updated package policy. |

## When to Consider a Managed Alternative

Custom SELinux policy maintenance requires 8-16 hours per application for initial development and 2-4 hours per application update that changes file access or network patterns.

- **[Aqua](https://www.aquasec.com) and [Sysdig](https://sysdig.com):** Managed runtime enforcement that abstracts MAC policy complexity. These platforms provide container-level confinement that achieves similar goals to SELinux with less operational burden.
- **Managed Kubernetes:** K8s providers handle node-level SELinux configuration. Workload-level security is handled through seccomp, capabilities, and container security contexts.

For teams on RHEL/Rocky: invest in SELinux for critical services (web servers, databases, SSH). Use `audit2allow` as a starting point, refine manually for the highest-risk services.

**Premium content pack:** SELinux policy collection. pre-built policies for common services (nginx, postgresql, redis, custom Go/Python/Node applications) with file contexts, CI testing templates, and a troubleshooting guide.


## Related Articles

- [AppArmor Profiles for Custom Applications: From Complain Mode to Enforce](/articles/linux/apparmor/)
- [systemd Unit Hardening: ProtectSystem, PrivateTmp, and the Full Sandbox Toolkit](/articles/linux/systemd-unit-hardening/)
- [Automated OS Hardening with Ansible: A Production-Ready Playbook Collection](/articles/linux/ansible-os-hardening/)
- [Hardening the Linux Kernel Attack Surface with sysctl and Boot Parameters](/articles/linux/sysctl-kernel-hardening/)
- [Kernel Module Hardening: Blacklisting, Signing, and Preventing Runtime Loading](/articles/linux/kernel-module-hardening/)
