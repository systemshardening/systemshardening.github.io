---
title: "Automated OS Hardening with Ansible: A Production-Ready Playbook Collection"
description: "Manual OS hardening does not scale. The sysctl settings from Hardening the Linux Kernel Attack Surface with sysctl and Boot..."
slug: "ansible-os-hardening"
date: 2026-02-12
lastmod: 2026-02-12
category: "linux"
tags: ["ansible", "automation", "hardening", "cis-benchmark", "compliance", "molecule"]
personas: ["devops-engineer", "systems-engineer"]
article_number: 15
difficulty: "intermediate"
estimated_reading_time: 22
provider_bridges:
  - name: "Aqua"
    id: 123
    category: "runtime-security"
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
premium_pack: "ansible-hardening-playbooks"
published: true
layout: article.njk
permalink: "/articles/linux/ansible-os-hardening/index.html"
---

# Automated OS Hardening with [Ansible](https://www.ansible.com): A Production-Ready Playbook Collection

## Problem

Manual OS hardening does not scale. The sysctl settings from [Hardening the Linux Kernel Attack Surface with sysctl and Boot Parameters](/articles/linux/sysctl-kernel-hardening/)(/articles/linux/sysctl-kernel-hardening/), the [systemd](https://systemd.io) overrides from [systemd Unit Hardening: ProtectSystem, PrivateTmp, and the Full Sandbox Toolkit](/articles/linux/systemd-unit-hardening/)(/articles/linux/systemd-unit-hardening/), the SSH configuration from [SSH Hardening Beyond the Basics: Certificate Authentication, Jump Hosts, and Logging](/articles/linux/ssh-hardening/)(/articles/linux/ssh-hardening/), applying these across 10, 50, or 200 hosts by hand is error-prone, time-consuming, and impossible to verify consistently.

The specific problems:

- **Configuration drift.** A host hardened 6 months ago may have had settings reverted by a package update, a troubleshooting session, or a configuration management conflict. Without automated verification, you do not know which hosts are hardened and which have drifted.
- **Inconsistent application.** Different engineers apply different subsets of hardening settings. Server A has sysctl hardened but not systemd. Server B has SSH hardened but not filesystem mount options. There is no single source of truth.
- **Testing gap.** Hardening settings that work on a web server break a database server. Without per-role configuration and testing, every new hardening push is a gamble.
- **Compliance verification.** Answering "are all our hosts CIS Level 1 compliant?" requires logging into each host and running checks, or, more realistically, it means nobody checks.

Ansible solves all four problems: declarative state management, idempotent application, role-based configuration, and automated verification. This article provides a production-ready playbook architecture that implements CIS Benchmark-level hardening for Ubuntu 24.04 LTS and RHEL 9, with per-role customisation, [Molecule](https://ansible.readthedocs.io/projects/molecule/) testing, and staged rollout.

**Target systems:** Ubuntu 24.04 LTS, RHEL 9 / Rocky Linux 9. Ansible 2.15+. Molecule for testing.

## Threat Model

- **Adversary:** Any attacker exploiting unhardened defaults across a fleet. The threat is not a specific attack technique; it is the inconsistent security posture that creates gaps attackers can find and exploit.
- **Blast radius:** Without automation, some hosts are hardened, some are not, and you do not know which. An attacker who scans your fleet will find the unhardened hosts. With automation, every host in the fleet has the same baseline, verified by CI.

## Configuration

### Playbook Repository Structure

```
ansible-hardening/
├── inventory/
│   ├── production/
│   │   ├── hosts.yml
│   │   └── group_vars/
│   │       ├── all.yml           # Defaults for all hosts
│   │       ├── webservers.yml    # Web server overrides
│   │       ├── databases.yml     # Database overrides
│   │       └── kubernetes.yml    # K8s node overrides
│   └── staging/
│       └── hosts.yml
├── roles/
│   ├── base/                     # Applied to ALL hosts
│   │   ├── tasks/
│   │   │   ├── main.yml
│   │   │   ├── sysctl.yml
│   │   │   ├── systemd.yml
│   │   │   ├── ssh.yml
│   │   │   ├── filesystem.yml
│   │   │   ├── kernel-modules.yml
│   │   │   ├── auditd.yml
│   │   │   └── packages.yml
│   │   ├── templates/
│   │   │   ├── sysctl-hardening.conf.j2
│   │   │   ├── sshd_config.j2
│   │   │   └── audit.rules.j2
│   │   ├── handlers/
│   │   │   └── main.yml
│   │   └── defaults/
│   │       └── main.yml
│   ├── webserver/                # Additional hardening for web servers
│   ├── database/                 # Additional hardening for databases
│   └── kubernetes-node/          # Additional hardening for K8s nodes
├── site.yml                      # Main playbook
├── molecule/
│   └── default/
│       ├── molecule.yml
│       ├── converge.yml
│       └── verify.yml
└── requirements.yml
```

### Inventory Configuration

```yaml
# inventory/production/hosts.yml
all:
  children:
    webservers:
      hosts:
        web-01.example.com:
        web-02.example.com:
    databases:
      hosts:
        db-01.example.com:
    kubernetes:
      hosts:
        k8s-node-01.example.com:
        k8s-node-02.example.com:
        k8s-node-03.example.com:
```

```yaml
# inventory/production/group_vars/all.yml
# Defaults applied to every host. Override per group as needed.

# sysctl hardening
hardening_sysctl_rp_filter: 1
hardening_sysctl_accept_source_route: 0
hardening_sysctl_accept_redirects: 0
hardening_sysctl_tcp_syncookies: 1
hardening_sysctl_kptr_restrict: 2
hardening_sysctl_dmesg_restrict: 1
hardening_sysctl_unprivileged_bpf_disabled: 1

# SSH hardening
hardening_ssh_permit_root_login: "no"
hardening_ssh_password_auth: "no"
hardening_ssh_max_auth_tries: 3
hardening_ssh_max_startups: "10:30:60"
hardening_ssh_allow_tcp_forwarding: "no"
hardening_ssh_x11_forwarding: "no"
hardening_ssh_allow_agent_forwarding: "no"

# Filesystem
hardening_tmp_noexec: true
hardening_tmp_nosuid: true
hardening_tmp_nodev: true

# Packages to remove
hardening_packages_remove:
  - telnet
  - rsh-client
  - talk
```

```yaml
# inventory/production/group_vars/databases.yml
# Database servers need some settings adjusted.

# PostgreSQL needs more shared memory
hardening_sysctl_shmmax: 2147483648

# Database servers may need TCP forwarding for replication
hardening_ssh_allow_tcp_forwarding: "local"
```

### Base Role - sysctl Task

```yaml
# roles/base/tasks/sysctl.yml
---
- name: Deploy network hardening sysctl config
  ansible.builtin.template:
    src: sysctl-hardening.conf.j2
    dest: /etc/sysctl.d/60-hardening.conf
    owner: root
    group: root
    mode: '0644'
  notify: reload sysctl
  tags: [sysctl, network]

- name: Apply sysctl settings immediately
  ansible.builtin.command: sysctl --system
  changed_when: false
  tags: [sysctl]

- name: Verify critical sysctl settings
  ansible.builtin.command: "sysctl -n {{ item.key }}"
  register: sysctl_check
  failed_when: sysctl_check.stdout | trim != item.value | string
  changed_when: false
  loop:
    - { key: "net.ipv4.conf.all.rp_filter", value: "{{ hardening_sysctl_rp_filter }}" }
    - { key: "net.ipv4.conf.all.accept_source_route", value: "{{ hardening_sysctl_accept_source_route }}" }
    - { key: "net.ipv4.conf.all.accept_redirects", value: "{{ hardening_sysctl_accept_redirects }}" }
    - { key: "net.ipv4.tcp_syncookies", value: "{{ hardening_sysctl_tcp_syncookies }}" }
    - { key: "kernel.kptr_restrict", value: "{{ hardening_sysctl_kptr_restrict }}" }
    - { key: "kernel.dmesg_restrict", value: "{{ hardening_sysctl_dmesg_restrict }}" }
  tags: [sysctl, verify]
```

```jinja2
{# roles/base/templates/sysctl-hardening.conf.j2 #}
# Managed by Ansible - do not edit manually.
# Source: ansible-hardening/roles/base/templates/sysctl-hardening.conf.j2

# Network stack hardening
net.ipv4.conf.all.rp_filter = {{ hardening_sysctl_rp_filter }}
net.ipv4.conf.default.rp_filter = {{ hardening_sysctl_rp_filter }}
net.ipv4.conf.all.accept_source_route = {{ hardening_sysctl_accept_source_route }}
net.ipv4.conf.default.accept_source_route = {{ hardening_sysctl_accept_source_route }}
net.ipv4.conf.all.accept_redirects = {{ hardening_sysctl_accept_redirects }}
net.ipv4.conf.default.accept_redirects = {{ hardening_sysctl_accept_redirects }}
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.tcp_syncookies = {{ hardening_sysctl_tcp_syncookies }}
net.ipv4.tcp_timestamps = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Kernel protections
kernel.randomize_va_space = 2
kernel.kptr_restrict = {{ hardening_sysctl_kptr_restrict }}
kernel.dmesg_restrict = {{ hardening_sysctl_dmesg_restrict }}
kernel.perf_event_paranoid = 3
kernel.yama.ptrace_scope = 1
kernel.unprivileged_bpf_disabled = {{ hardening_sysctl_unprivileged_bpf_disabled }}
net.core.bpf_jit_harden = 2
kernel.kexec_load_disabled = 1

# Filesystem
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0

{% if hardening_sysctl_shmmax is defined %}
# Database overrides
kernel.shmmax = {{ hardening_sysctl_shmmax }}
{% endif %}
```

### Base Role - SSH Task

```yaml
# roles/base/tasks/ssh.yml
---
- name: Deploy hardened sshd_config
  ansible.builtin.template:
    src: sshd_config.j2
    dest: /etc/ssh/sshd_config
    owner: root
    group: root
    mode: '0600'
    validate: '/usr/sbin/sshd -t -f %s'
  notify: restart sshd
  tags: [ssh]

- name: Verify sshd configuration is valid
  ansible.builtin.command: /usr/sbin/sshd -t
  changed_when: false
  tags: [ssh, verify]
```

### Main Playbook

```yaml
# site.yml
---
- name: Apply base hardening to all hosts
  hosts: all
  become: true
  roles:
    - base
  tags: [base]

- name: Apply web server hardening
  hosts: webservers
  become: true
  roles:
    - webserver
  tags: [webserver]

- name: Apply database hardening
  hosts: databases
  become: true
  roles:
    - database
  tags: [database]

- name: Apply Kubernetes node hardening
  hosts: kubernetes
  become: true
  roles:
    - kubernetes-node
  tags: [kubernetes]
```

### Molecule Testing

```yaml
# molecule/default/molecule.yml
---
dependency:
  name: galaxy
driver:
  name: docker
platforms:
  - name: ubuntu-2404
    image: ubuntu:24.04
    privileged: true
    command: /lib/systemd/systemd
    volumes:
      - /sys/fs/cgroup:/sys/fs/cgroup:rw
    tmpfs:
      - /run
      - /tmp
  - name: rhel-9
    image: rockylinux:9
    privileged: true
    command: /lib/systemd/systemd
    volumes:
      - /sys/fs/cgroup:/sys/fs/cgroup:rw
    tmpfs:
      - /run
      - /tmp
provisioner:
  name: ansible
  playbooks:
    converge: converge.yml
    verify: verify.yml
verifier:
  name: ansible
```

```yaml
# molecule/default/verify.yml
---
- name: Verify hardening
  hosts: all
  become: true
  tasks:
    - name: Check sysctl rp_filter
      ansible.builtin.command: sysctl -n net.ipv4.conf.all.rp_filter
      register: rp_filter
      failed_when: rp_filter.stdout | trim != "1"
      changed_when: false

    - name: Check kernel pointer restriction
      ansible.builtin.command: sysctl -n kernel.kptr_restrict
      register: kptr
      failed_when: kptr.stdout | trim != "2"
      changed_when: false

    - name: Check sshd config is valid
      ansible.builtin.command: /usr/sbin/sshd -t
      changed_when: false

    - name: Verify sshd password auth is disabled
      ansible.builtin.command: grep -E "^PasswordAuthentication no" /etc/ssh/sshd_config
      changed_when: false

    - name: Check unneeded packages are removed
      ansible.builtin.package:
        name: telnet
        state: absent
      check_mode: true
      register: telnet_check
      failed_when: telnet_check.changed
```

```bash
# Run Molecule tests locally:
cd ansible-hardening
molecule test

# Expected output:
# --> Test matrix
# --> Dependency
# --> Create
# --> Converge
# --> Idempotence   ← Re-runs playbook; expects zero changes
# --> Verify        ← Runs verification playbook
# --> Destroy

# All stages should pass. Idempotence is critical -
# it proves the playbook can be safely re-run.
```

### Staged Rollout

Never apply hardening to your entire fleet at once. Use a canary strategy:

```bash
# Stage 1: Apply to a single canary host
ansible-playbook site.yml -i inventory/production -l web-01.example.com --diff

# Verify the canary host is healthy:
# - Check application health endpoint
# - Check monitoring dashboards for anomalies
# - Wait 30 minutes

# Stage 2: Apply to 25% of each group
ansible-playbook site.yml -i inventory/production --limit '~web-0[1-2]|~db-01|~k8s-node-01' --diff

# Wait 1 hour. Verify.

# Stage 3: Apply to all hosts
ansible-playbook site.yml -i inventory/production --diff
```

### Drift Detection

Schedule regular compliance checks to detect configuration drift:

```bash
# Run the playbook in check mode (dry-run) - reports what WOULD change:
ansible-playbook site.yml -i inventory/production --check --diff

# If the output shows zero changes: fleet is in compliance.
# If changes are reported: a host has drifted.

# Automate this as a cron job or CI pipeline:
# 0 6 * * * ansible-playbook site.yml --check --diff 2>&1 | mail -s "Hardening drift report" security@example.com
```

For [Prometheus](https://prometheus.io)-based monitoring:

```bash
# Export drift check results as a Prometheus metric:
# Create a textfile exporter gauge:
echo "hardening_drift_detected $(ansible-playbook site.yml --check --diff 2>&1 | grep -c 'changed=')" \
  > /var/lib/node_exporter/hardening_drift.prom
```

## Expected Behaviour

After setting up and running the playbook:

- `ansible-playbook site.yml` applies all hardening across the fleet idempotently
- Re-running produces zero changes (idempotent)
- `molecule test` passes on both Ubuntu 24.04 and RHEL 9
- Canary host rollout catches breaking changes before fleet-wide application
- Drift detection (scheduled `--check --diff`) reports zero changes when fleet is compliant
- Each server role (web, database, K8s node) has appropriate hardening with role-specific overrides
- New hosts added to inventory are automatically hardened on the next playbook run

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| CIS Level 1 baseline (not Level 2) | Level 2 adds 20+ additional controls with higher breakage risk | Some compliance frameworks require Level 2 | Start with Level 1. Add Level 2 controls incrementally after testing each one. |
| Ansible over Salt/Puppet | Broadest adoption, lowest learning curve, agentless | Salt is faster for event-driven remediation; Puppet better for very large fleets (>1000 hosts) | Ansible is the right choice for most teams. Migrate later if needed. |
| Molecule [Docker](https://www.docker.com) testing | Fast (2-3 minutes), runs in CI | Docker doesn't perfectly replicate bare-metal sysctl behaviour | Supplement with a staging VM for sysctl-specific tests. Docker catches 90% of issues. |
| Template-based configs | Configuration is generated from variables; one source of truth | Template errors can produce invalid configs | Validation steps in tasks (`sshd -t`, `sysctl --system`) catch template errors before they take effect. |
| Staged rollout (canary → 25% → 100%) | Catches breaking changes before fleet-wide impact | Slower than full fleet deployment | The time cost (1-2 hours for staged rollout) is negligible compared to the recovery cost of a fleet-wide breakage. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Playbook locks out SSH | Cannot SSH after hardening run | Lose SSH access; console access required | Include SSH connectivity test as the LAST task in the playbook. If it fails, the override is rolled back before the connection drops. Always test from a second SSH session. |
| sysctl change breaks application | Application fails after sysctl hardening | Application monitoring shows errors; canary host catches this | Canary deployment limits blast radius. Override the specific sysctl in the host's group_vars. Re-run playbook. |
| Template syntax error | `sshd_config` or `sysctl.conf` is invalid | `validate` parameter on template task catches this; task fails before deploying invalid config | Fix the template. The `validate` parameter ensures the old config stays in place until the new one passes validation. |
| Molecule passes but production fails | Hardening works in Docker but breaks on real hardware | Production monitoring detects failure; canary strategy limits blast radius | Fix playbook; add the failing scenario to Molecule tests. Supplement Docker testing with staging VM tests for hardware-specific settings. |
| Drift detected after package upgrade | `apt upgrade` resets an sshd_config setting to default | Drift detection (scheduled `--check --diff`) reports changes | Re-run the playbook. The drift is automatically remediated. Investigate which package caused the reset. |
| Role-specific override missing | Database server breaks because sysctl is too restrictive | Database monitoring shows performance degradation or errors; canary catches this | Add the necessary override to the database group_vars. Re-run playbook. |

## When to Consider a Managed Alternative

**Transition point:** Maintaining hardening playbooks across 2+ OS versions and 3+ server roles requires 4-8 hours per month. When the maintenance burden exceeds this, or when the team is moving to containers and managed Kubernetes where host-level hardening is abstracted away.

**What managed providers handle:**

- **Managed Kubernetes** (Civo #22, DigitalOcean #21), Node OS hardening is the provider's responsibility. You do not run Ansible against managed K8s nodes.
- **[Aqua](https://www.aquasec.com) and [Sysdig](https://sysdig.com):** Verify compliance across a fleet and alert on drift. They do not remediate (Ansible does that), but they provide the monitoring layer that detects when remediation is needed.
- **[Chef InSpec](https://www.chef.io/products/chef-inspec):** Compliance verification. Use [InSpec](https://www.chef.io/products/chef-inspec) as the verifier in your Ansible workflow: Ansible remediates, InSpec verifies.

**What you still control:** For any hosts you manage directly (bare metal, VMs, self-managed K8s nodes), Ansible hardening remains your responsibility. This playbook collection applies directly to those hosts.

**Premium content pack:** The complete Ansible playbook collection. roles for base, webserver, database, kubernetes-node, with tested templates for all configurations covered in Articles #1, #2, #5, #7, #8, and #10. Tested with Molecule on Ubuntu 24.04 LTS and RHEL 9. Includes CI pipeline configuration for automated drift detection.


## Related Articles

- [systemd Unit Hardening: ProtectSystem, PrivateTmp, and the Full Sandbox Toolkit](/articles/linux/systemd-unit-hardening/)
- [SELinux in Production: Writing Custom Policies Without Losing Your Mind](/articles/linux/selinux/)
- [AppArmor Profiles for Custom Applications: From Complain Mode to Enforce](/articles/linux/apparmor/)
- [Hardening the Linux Kernel Attack Surface with sysctl and Boot Parameters](/articles/linux/sysctl-kernel-hardening/)
- [Linux Audit Framework Deep Dive: auditd Rules, auditctl, and ausearch for Security Monitoring](/articles/linux/auditd-deep-dive/)
