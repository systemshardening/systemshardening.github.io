---
title: "Hardening Baseline Automation: Enforcing and Verifying Security Configuration at Scale"
description: "Manual hardening checklists don't scale beyond a few dozen systems. Automated baselines codify security configuration as policy, enforce it at provisioning, detect drift in production, and generate compliance evidence. This guide covers CIS Benchmark automation with Ansible, InSpec/OSQuery for continuous compliance, and cloud-native configuration enforcement."
slug: hardening-baseline-automation
date: 2026-05-07
lastmod: 2026-05-07
category: cross-cutting
tags:
  - hardening-baseline
  - cis-benchmarks
  - compliance-automation
  - ansible
  - configuration-management
personas:
  - security-engineer
  - platform-engineer
article_number: 623
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/cross-cutting/hardening-baseline-automation/
---

# Hardening Baseline Automation: Enforcing and Verifying Security Configuration at Scale

## Problem

Manual hardening checklists fail in three distinct ways. First, they are not reproducible: two engineers following the same 200-step document will produce subtly different configurations. A sysctl value applied interactively may not persist across a reboot if the engineer forgot to write it to `/etc/sysctl.d/`. A firewall rule added via `ufw allow` that should have been `ufw allow proto tcp from 10.0.0.0/8`. Second, manual checklists leave no machine-readable audit trail. When an auditor asks "which systems have kernel address space layout randomisation enabled?", the honest answer is "we think all of them, but we cannot prove it without checking each one". Third, hardening applied manually drifts. A package upgrade reverts a sysctl setting. A developer opens a port for debugging and forgets to close it. An incident responder disables SELinux to narrow down a problem and it stays disabled. Six months after the initial hardening sprint, the actual configuration no longer matches the documented baseline.

At ten systems, manual hardening is annoying. At a hundred systems, it is a compliance liability. At a thousand systems, it is impossible.

The solution is to codify the baseline as machine-executable policy: Ansible roles that apply settings idempotently, Packer that bakes hardened images so new instances start already compliant, InSpec profiles that verify every control, OpenSCAP for Red Hat-family Linux, and osquery for lightweight continuous monitoring. Cloud providers have native equivalents. The output of this system is both a hardened fleet and a continuous stream of compliance evidence.

## Threat Model

- **Adversary:** Configuration drift as an attack surface. An attacker who gains initial access to a system is significantly more constrained on a system with AppArmor profiles enforced, kernel hardening sysctl values in place, unnecessary services removed, and filesystem mount options set to `noexec`. A drifted system silently restores those attack paths.
- **Objective:** Every system in the fleet should pass the same baseline checks at all times, not just immediately after provisioning.
- **Blast radius:** Without automated drift detection, a single misconfigured system can persist in that state for months. With automated baselines, drift is detected within hours and either auto-remediated or alerted within a defined SLA.

## Configuration

### Choosing a CIS Benchmark Level

The [Center for Internet Security](https://www.cisecurity.org) publishes benchmarks for Linux, Windows, Kubernetes, Docker, cloud services, and more. Each benchmark has two levels.

**Level 1** covers configurations that improve security without significantly impacting functionality or requiring significant operational change. This is the right starting point for most production systems. It covers items like disabling unused network protocols, enforcing SSH configuration, removing unnecessary packages, and setting filesystem mount options.

**Level 2** adds defence-in-depth controls that may impact usability or require more significant operational adjustment — things like mandatory access controls (SELinux/AppArmor), audit subsystem configuration, and strict kernel parameters. Apply Level 2 to systems that handle sensitive data or are internet-facing.

For Kubernetes, CIS provides a separate benchmark covering API server flags, kubelet configuration, etcd encryption, and RBAC. [kube-bench](https://aquasecurity.github.io/kube-bench/) automates this check and is covered in the [Compliance-as-Code](/articles/cross-cutting/compliance-as-code/) article. This article focuses on the host OS baseline.

### Ansible for Hardening Automation

[Ansible](https://www.ansible.com) is the most widely used tool for applying hardening baselines to Linux systems. Roles are idempotent by design: running the same role twice produces the same result. The [ansible-lockdown](https://github.com/ansible-lockdown) project maintains CIS-aligned roles for RHEL, Ubuntu, and Windows.

```yaml
# requirements.yml — install the CIS Ubuntu 24.04 role
collections:
  - name: ansible.posix
    version: ">=1.5.0"

roles:
  - name: UBUNTU24-CIS
    src: https://github.com/ansible-lockdown/UBUNTU24-CIS
    version: main
```

```bash
ansible-galaxy install -r requirements.yml
```

```yaml
# playbook-harden-linux.yml
---
- name: Apply CIS Level 1 hardening baseline
  hosts: all
  become: true
  vars:
    # CIS Level 1 only — set to 2 for Level 2 controls
    ubuntu24cis_level_1: true
    ubuntu24cis_level_2: false

    # Section 1: Initial Setup
    ubuntu24cis_section1: true
    ubuntu24cis_section2: true   # Services
    ubuntu24cis_section3: true   # Network Configuration
    ubuntu24cis_section4: true   # Host-Based Firewall
    ubuntu24cis_section5: true   # Access, Authentication, Authorization
    ubuntu24cis_section6: true   # Logging and Auditing
    ubuntu24cis_section7: true   # System Maintenance

    # Skip controls that conflict with your environment
    # Example: skip IPv6 disablement if you use IPv6
    ubuntu24cis_ipv6_required: true

    # SSH hardening (override defaults as needed)
    ubuntu24cis_sshd:
      PermitRootLogin: "no"
      PasswordAuthentication: "no"
      MaxAuthTries: 3
      ClientAliveInterval: 300
      ClientAliveCountMax: 0
      X11Forwarding: "no"
      AllowTcpForwarding: "no"
      Banner: /etc/issue.net

  roles:
    - UBUNTU24-CIS
```

```bash
# Apply hardening to all production hosts
ansible-playbook -i inventory/production playbook-harden-linux.yml \
  --check  # Dry-run first to see what would change

# Apply for real
ansible-playbook -i inventory/production playbook-harden-linux.yml

# Apply to a single host for testing
ansible-playbook -i inventory/production playbook-harden-linux.yml \
  --limit "web-prod-01.example.com"
```

Custom controls that the CIS role does not cover should be written as separate Ansible tasks. Keep these in a `site-hardening` role alongside the CIS role so they are versioned and peer-reviewed like any other infrastructure code.

```yaml
# roles/site-hardening/tasks/sysctl.yml
---
- name: Apply site-specific kernel hardening
  ansible.posix.sysctl:
    name: "{{ item.key }}"
    value: "{{ item.value }}"
    state: present
    sysctl_file: /etc/sysctl.d/99-site-hardening.conf
    reload: true
  loop:
    - { key: "kernel.unprivileged_bpf_disabled", value: "1" }
    - { key: "net.core.bpf_jit_harden", value: "2" }
    - { key: "kernel.yama.ptrace_scope", value: "2" }
    - { key: "vm.unprivileged_userfaultfd", value: "0" }

- name: Disable core dumps for setuid programs
  ansible.posix.sysctl:
    name: fs.suid_dumpable
    value: "0"
    sysctl_file: /etc/sysctl.d/99-site-hardening.conf
    reload: true
```

### Packer for Immutable Hardened Base Images

Hardening at provisioning time with Ansible still leaves a window: a new instance is running an unhardened base AMI until Ansible completes. For immutable infrastructure patterns, the better approach is to bake the hardened configuration into the base image using [Packer](https://www.packer.io). Every instance launched from that AMI starts hardened with zero lag.

```hcl
# hardened-ubuntu.pkr.hcl
packer {
  required_plugins {
    amazon = {
      version = ">= 1.3.0"
      source  = "github.com/hashicorp/amazon"
    }
    ansible = {
      version = ">= 1.1.0"
      source  = "github.com/hashicorp/ansible"
    }
  }
}

variable "aws_region" {
  default = "eu-west-1"
}

variable "base_ami" {
  description = "Ubuntu 24.04 LTS base AMI"
  default     = "ami-0e9085a8d461c2d01"
}

source "amazon-ebs" "hardened-ubuntu" {
  region        = var.aws_region
  source_ami    = var.base_ami
  instance_type = "t3.small"
  ssh_username  = "ubuntu"

  ami_name        = "hardened-ubuntu-24-04-cis-l1-{{timestamp}}"
  ami_description = "Ubuntu 24.04 LTS with CIS Level 1 baseline applied"

  tags = {
    Name          = "hardened-ubuntu-24-04-cis-l1"
    CIS_Level     = "1"
    Baseline_Date = "{{timestamp}}"
    Managed_By    = "packer"
  }

  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = 20
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }
}

build {
  sources = ["source.amazon-ebs.hardened-ubuntu"]

  # Apply Ansible hardening baseline
  provisioner "ansible" {
    playbook_file = "./playbook-harden-linux.yml"
    user          = "ubuntu"
    extra_arguments = [
      "--extra-vars", "ansible_python_interpreter=/usr/bin/python3"
    ]
  }

  # Run InSpec to verify the image passes the baseline before publishing
  provisioner "shell-local" {
    command = <<-EOT
      inspec exec ./inspec-profiles/cis-ubuntu-24 \
        -t ssh://ubuntu@${build.Host} \
        -i ${build.SSHPrivateKey} \
        --reporter json:/tmp/packer-inspec-results.json cli
      FAIL=$(jq '[.profiles[].controls[].results[] | select(.status == "failed")] | length' /tmp/packer-inspec-results.json)
      if [ "$FAIL" -gt 0 ]; then
        echo "BASELINE VERIFICATION FAILED: $FAIL controls failed. Not publishing AMI."
        exit 1
      fi
      echo "All CIS controls passed. AMI is ready to publish."
    EOT
  }

  # Capture build metadata
  post-processor "manifest" {
    output     = "packer-manifest.json"
    strip_path = true
  }
}
```

```bash
# Build the hardened AMI (runs Ansible, runs InSpec, publishes only if all checks pass)
packer build hardened-ubuntu.pkr.hcl

# The output AMI ID is in packer-manifest.json
AMI_ID=$(jq -r '.builds[-1].artifact_id' packer-manifest.json | cut -d':' -f2)
echo "Hardened AMI: $AMI_ID"
```

Pin all auto-scaling groups and launch templates to the latest hardened AMI. When a new baseline is required (a new CIS version, a new OS patch level, a new site control), rebuild the AMI through the pipeline and roll out the new AMI via an ASG rolling update.

### Chef InSpec for Continuous Compliance Verification

Packer bakes the baseline in; InSpec verifies it continuously in production. [InSpec](https://www.chef.io/products/chef-inspec) profiles are collections of controls that express expected system state as code. A control reads the system, compares it against the expected value, and reports pass or fail.

```ruby
# inspec-profiles/cis-ubuntu-24/controls/sysctl.rb
# CIS Ubuntu 24.04 Level 1 — Section 3: Network Configuration

control 'cis-3.3.1-ipv4-forwarding' do
  impact 1.0
  title 'Ensure IP forwarding is disabled'
  desc 'Hosts that are not routers should not forward packets.'
  tag cis: '3.3.1'
  tag remediation: 'https://systemshardening.com/articles/linux/sysctl-kernel-hardening/'

  describe kernel_parameter('net.ipv4.ip_forward') do
    its('value') { should eq 0 }
  end
end

control 'cis-3.3.2-packet-redirect' do
  impact 1.0
  title 'Ensure packet redirect sending is disabled'
  tag cis: '3.3.2'

  describe kernel_parameter('net.ipv4.conf.all.send_redirects') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv4.conf.default.send_redirects') do
    its('value') { should eq 0 }
  end
end

control 'cis-3.3.4-bogus-icmp' do
  impact 0.5
  title 'Ensure suspicious packets are logged'
  tag cis: '3.3.4'

  describe kernel_parameter('net.ipv4.conf.all.log_martians') do
    its('value') { should eq 1 }
  end
end

control 'cis-5.2-ssh-hardening' do
  impact 1.0
  title 'Ensure SSH is configured securely'
  tag cis: '5.2'
  tag remediation: 'https://systemshardening.com/articles/linux/ssh-hardening/'

  describe sshd_config do
    its('PermitRootLogin')        { should eq 'no' }
    its('PasswordAuthentication') { should eq 'no' }
    its('MaxAuthTries')           { should cmp <= 4 }
    its('X11Forwarding')          { should eq 'no' }
    its('AllowTcpForwarding')     { should eq 'no' }
    its('ClientAliveInterval')    { should cmp <= 300 }
    its('LoginGraceTime')         { should cmp <= 60 }
  end
end

control 'cis-1.1-filesystem-mounts' do
  impact 1.0
  title 'Ensure nodev/nosuid/noexec on removable and temporary filesystems'
  tag cis: '1.1'

  describe mount('/tmp') do
    it { should be_mounted }
    its('options') { should include 'nodev' }
    its('options') { should include 'nosuid' }
    its('options') { should include 'noexec' }
  end

  describe mount('/dev/shm') do
    it { should be_mounted }
    its('options') { should include 'nodev' }
    its('options') { should include 'nosuid' }
    its('options') { should include 'noexec' }
  end
end
```

```bash
# Run InSpec against a local system
inspec exec ./inspec-profiles/cis-ubuntu-24 \
  --reporter json:/var/log/inspec/compliance-$(date +%Y%m%d).json \
              html:/var/log/inspec/compliance-$(date +%Y%m%d).html \
              cli

# Run InSpec against a remote system over SSH
inspec exec ./inspec-profiles/cis-ubuntu-24 \
  -t ssh://inspec@web-prod-01.example.com \
  --reporter json:/tmp/inspec-web-prod-01.json cli

# Parse results summary
jq '{
  pass: [.profiles[].controls[].results[] | select(.status == "passed")] | length,
  fail: [.profiles[].controls[].results[] | select(.status == "failed")] | length,
  skip: [.profiles[].controls[].results[] | select(.status == "skipped")] | length
}' /tmp/inspec-web-prod-01.json
```

The JSON report can be shipped to a SIEM or aggregated into the hardening scorecard. The HTML report is audit-ready: it shows pass/fail for every control, the control description, the expected value, and the actual observed value for failures.

### OpenSCAP for Red Hat-Family Linux

On RHEL, Rocky Linux, and AlmaLinux, [OpenSCAP](https://www.open-scap.org) is the native compliance scanner. It reads XCCDF (Extensible Configuration Checklist Description Format) profiles from the `scap-security-guide` package and can both scan and remediate.

```bash
# Install OpenSCAP and the security guide
dnf install -y openscap-scanner scap-security-guide

# List available profiles for RHEL 9
oscap info /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml | grep -A2 "Profile"

# Run a CIS Level 1 scan and generate an HTML report
oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis_server_l1 \
  --results /tmp/oscap-results.xml \
  --report /tmp/oscap-report.html \
  --fetch-remote-resources \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml

# Generate an Ansible remediation playbook for failed controls
oscap xccdf generate fix \
  --profile xccdf_org.ssgproject.content_profile_cis_server_l1 \
  --fix-type ansible \
  --output /tmp/oscap-remediation.yml \
  /tmp/oscap-results.xml

# Apply the auto-generated remediation
ansible-playbook -i localhost, -c local /tmp/oscap-remediation.yml
```

OpenSCAP integrates with Red Hat Satellite and Ansible Automation Platform for fleet-wide scanning. Results stored in Satellite provide a per-host compliance history that satisfies auditor requests for historical evidence.

### osquery for Lightweight Continuous Compliance

[osquery](https://osquery.io) exposes the operating system as a SQL-queryable database. It runs as a daemon (`osqueryd`) and executes scheduled queries, storing results locally or shipping them to a fleet management server ([Fleet](https://fleetdm.com) or [Kolide](https://www.kolide.com)). Unlike InSpec, which you run periodically, osquery runs continuously with near-real-time visibility.

```sql
-- osquery scheduled queries for hardening baseline
-- Place in /etc/osquery/osquery.conf

{
  "options": {
    "config_plugin": "filesystem",
    "logger_plugin": "filesystem",
    "logger_path": "/var/log/osquery",
    "schedule_splay_percent": 10
  },
  "schedule": {
    "sysctl_hardening": {
      "query": "SELECT name, current_value, config_value FROM system_controls WHERE name IN ('net.ipv4.ip_forward', 'net.ipv4.conf.all.rp_filter', 'net.ipv4.conf.all.accept_redirects', 'net.ipv4.tcp_syncookies', 'kernel.kptr_restrict', 'kernel.dmesg_restrict', 'kernel.randomize_va_space', 'kernel.unprivileged_bpf_disabled') AND current_value != '0' AND name IN ('net.ipv4.ip_forward', 'net.ipv4.conf.all.accept_redirects');",
      "interval": 300,
      "description": "Check that packet forwarding and ICMP redirects are disabled"
    },
    "world_writable_dirs": {
      "query": "SELECT path, mode, uid FROM file WHERE path IN ('/tmp', '/var/tmp', '/dev/shm') AND (mode LIKE '%2%' OR mode LIKE '%7%');",
      "interval": 600,
      "description": "Detect sticky bit missing on world-writable directories"
    },
    "suid_binaries_unexpected": {
      "query": "SELECT path, username, mode FROM file JOIN users USING (uid) WHERE type = 'regular' AND (mode LIKE '%u+s%' OR mode LIKE '%4%') AND path NOT IN (SELECT path FROM file WHERE path LIKE '/usr/bin/%' OR path LIKE '/usr/sbin/%');",
      "interval": 3600,
      "description": "Detect unexpected SUID binaries outside standard paths"
    },
    "ssh_authorized_keys": {
      "query": "SELECT authorized_keys.uid, users.username, authorized_keys.key, authorized_keys.key_file FROM authorized_keys JOIN users USING (uid);",
      "interval": 3600,
      "description": "Inventory all SSH authorized keys"
    },
    "listening_ports_baseline": {
      "query": "SELECT pid, port, protocol, address, processes.name FROM listening_ports JOIN processes USING (pid) WHERE port NOT IN (22, 443, 80) AND address != '127.0.0.1';",
      "interval": 300,
      "description": "Detect services listening on unexpected ports"
    },
    "cron_baseline": {
      "query": "SELECT command, path FROM crontab WHERE command NOT LIKE '/usr/sbin/%' AND command NOT LIKE '/usr/bin/%' AND command NOT LIKE '/opt/company/%';",
      "interval": 3600,
      "description": "Detect unexpected cron entries outside approved paths"
    }
  }
}
```

Differential queries are the key osquery capability for drift detection. By setting `"removed": true` on a scheduled query, osquery reports only rows that have appeared or disappeared since the last execution, producing a change event rather than a full snapshot. A new SUID binary, a new listening port, or a new cron entry all produce an immediate alert rather than requiring a diff of two large JSON files.

### Detecting and Alerting on Drift

The combination of Ansible (enforce), Packer (bake), InSpec/OpenSCAP (verify periodically), and osquery (monitor continuously) creates overlapping detection layers. Drift alerts should be actionable and specific.

```yaml
# prometheus-drift-alerts.yaml
# Feed InSpec results into Prometheus via node_exporter textfile collector
groups:
  - name: hardening-baseline-drift
    rules:
      - alert: HardeningBaselineDrift
        expr: hardening_inspec_failed_controls > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "{{ $labels.host }} has {{ $value }} failed CIS controls"
          description: "Hardening baseline drift detected. Run InSpec with --reporter html to identify failures. Apply Ansible remediation playbook."
          runbook: "https://wiki.example.com/runbooks/hardening-drift"

      - alert: HardeningBaselineCriticalDrift
        expr: hardening_inspec_failed_controls{impact="1.0"} > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Critical hardening control failed on {{ $labels.host }}"
          description: "A CIS Level 1 critical control (impact 1.0) has failed. Immediate investigation required."

      - alert: SysctlValueChanged
        expr: changes(hardening_sysctl_value[1h]) > 0
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "Kernel parameter changed on {{ $labels.host }}: {{ $labels.parameter }}"
          description: "A monitored sysctl value changed. This may indicate a package update reversion or manual change. Verify with: sysctl {{ $labels.parameter }}"
```

```bash
#!/bin/bash
# collect-inspec-metrics.sh
# Run after each InSpec scan to update Prometheus textfile metrics
set -euo pipefail

RESULTS_FILE="${1:-/var/log/inspec/compliance-latest.json}"
METRICS_FILE="/var/lib/node_exporter/textfile_collector/hardening.prom"

HOSTNAME=$(hostname -f)

PASS=$(jq '[.profiles[].controls[].results[] | select(.status == "passed")] | length' "$RESULTS_FILE")
FAIL=$(jq '[.profiles[].controls[].results[] | select(.status == "failed")] | length' "$RESULTS_FILE")
SKIP=$(jq '[.profiles[].controls[].results[] | select(.status == "skipped")] | length' "$RESULTS_FILE")
TOTAL=$((PASS + FAIL))
SCORE=$([ "$TOTAL" -gt 0 ] && echo "scale=2; $PASS / $TOTAL * 100" | bc || echo "0")

cat > "$METRICS_FILE" <<PROM
# HELP hardening_inspec_passed_controls Number of CIS controls passing
# TYPE hardening_inspec_passed_controls gauge
hardening_inspec_passed_controls{host="${HOSTNAME}"} ${PASS}
# HELP hardening_inspec_failed_controls Number of CIS controls failing
# TYPE hardening_inspec_failed_controls gauge
hardening_inspec_failed_controls{host="${HOSTNAME}"} ${FAIL}
# HELP hardening_inspec_score Compliance score as percentage
# TYPE hardening_inspec_score gauge
hardening_inspec_score{host="${HOSTNAME}"} ${SCORE}
# HELP hardening_inspec_last_run_timestamp Unix timestamp of last InSpec run
# TYPE hardening_inspec_last_run_timestamp gauge
hardening_inspec_last_run_timestamp{host="${HOSTNAME}"} $(date +%s)
PROM

echo "Metrics written: ${PASS} passed, ${FAIL} failed, score ${SCORE}%"
```

### Cloud-Native Compliance Enforcement

Cloud providers offer native equivalents that are often simpler to operate than self-hosted tooling and produce results that auditors already recognise.

**AWS Config** evaluates resource configuration against rules and can aggregate results across accounts and regions.

```json
{
  "ConfigRuleName": "cis-benchmark-ec2-imdsv2",
  "Description": "CIS AWS Foundations 2.6.1 — Ensure IMDSv2 is required on EC2 instances",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "EC2_IMDSV2_REQUIRED"
  },
  "Scope": {
    "ComplianceResourceTypes": ["AWS::EC2::Instance"]
  }
}
```

```bash
# Enable CIS AWS Foundations conformance pack (includes ~50 rules)
aws configservice put-conformance-pack \
  --conformance-pack-name "cis-aws-foundations-level1" \
  --template-s3-uri "s3://aws-config-conformance-packs-${AWS_REGION}/AWSConfigConformsPack-CISBenchmark.yaml" \
  --delivery-s3-bucket "my-config-results-bucket"

# Query compliance status across all rules
aws configservice describe-compliance-by-config-rule \
  --query 'ComplianceByConfigRules[?Compliance.ComplianceType==`NON_COMPLIANT`]' \
  --output table
```

**GCP Security Command Center** (with Security Health Analytics enabled) continuously evaluates GCP resources against CIS Google Cloud Foundations benchmarks. Findings are surfaced in the SCC console and can be exported to Cloud Logging or Pub/Sub for downstream alerting.

**Azure Policy** applies and enforces Azure Security Benchmark controls. The CIS Microsoft Azure Foundations initiative is available as a built-in policy set.

```bash
# Apply the CIS Azure Foundations initiative to a subscription
az policy assignment create \
  --name "cis-azure-foundations" \
  --display-name "CIS Microsoft Azure Foundations Benchmark v2.0" \
  --scope "/subscriptions/${SUBSCRIPTION_ID}" \
  --policy-set-definition "06f19060-9e68-4070-92ca-f15cc126059e" \
  --enforcement-mode Default
```

### Generating Compliance Evidence for Auditors

Automated baselines produce machine-readable output. The last step is converting that output into the evidence auditors need.

```bash
#!/bin/bash
# generate-compliance-evidence.sh
# Produce an audit package: HTML report + JSON data + summary CSV
set -euo pipefail

DATE=$(date +%Y-%m-%d)
EVIDENCE_DIR="/var/log/compliance/evidence-${DATE}"
mkdir -p "$EVIDENCE_DIR"

# Run InSpec and generate both HTML and JSON
inspec exec ./inspec-profiles/cis-ubuntu-24 \
  --reporter html:"${EVIDENCE_DIR}/compliance-report.html" \
             json:"${EVIDENCE_DIR}/compliance-data.json" \
             cli

# Generate summary CSV for spreadsheet-loving auditors
echo "control_id,title,status,impact,cis_ref" > "${EVIDENCE_DIR}/summary.csv"
jq -r '.profiles[].controls[] |
  .id as $id |
  .title as $title |
  .impact as $impact |
  (.tags.cis // "N/A") as $cis |
  .results[] |
  [$id, $title, .status, ($impact | tostring), $cis] |
  @csv' "${EVIDENCE_DIR}/compliance-data.json" >> "${EVIDENCE_DIR}/summary.csv"

# Count results
PASS=$(jq '[.profiles[].controls[].results[] | select(.status == "passed")] | length' "${EVIDENCE_DIR}/compliance-data.json")
FAIL=$(jq '[.profiles[].controls[].results[] | select(.status == "failed")] | length' "${EVIDENCE_DIR}/compliance-data.json")
TOTAL=$((PASS + FAIL))
SCORE=$(echo "scale=1; $PASS / $TOTAL * 100" | bc)

# Write a cover page text file
cat > "${EVIDENCE_DIR}/README.txt" <<EOF
Compliance Evidence Package
System: $(hostname -f)
Date: ${DATE}
Framework: CIS Ubuntu 24.04 LTS Benchmark Level 1
Assessed by: InSpec $(inspec version)
Controls passed: ${PASS}
Controls failed: ${FAIL}
Compliance score: ${SCORE}%

Files:
  compliance-report.html  — Human-readable HTML report (share with auditors)
  compliance-data.json    — Machine-readable results (for SIEM/dashboards)
  summary.csv             — Control-by-control CSV (for spreadsheet review)
EOF

echo "Evidence package written to: ${EVIDENCE_DIR}"
echo "Score: ${SCORE}% (${PASS}/${TOTAL} controls passing)"
```

Schedule this script weekly via cron and archive the evidence packages to object storage. When an auditor requests evidence that controls were operating during a specific period, retrieve the evidence package for that week. The HTML report shows the date, the system, the profile version, and pass/fail for every control — no manual data collection required.

## Expected Behaviour

- All new instances (EC2, GCP Compute, bare metal) launch from a Packer-built hardened base image that already passes CIS Level 1
- Ansible playbooks apply and maintain the hardening baseline idempotently; running the playbook is safe at any time
- InSpec profiles run on a daily schedule against all production systems; results feed into Prometheus via the textfile collector
- Compliance score for each host is visible in the hardening scorecard dashboard
- Any host scoring below 90% triggers a warning alert; any critical-impact (1.0) control failure triggers an immediate alert
- osquery runs continuously on all hosts, reporting drift within 5 minutes of a monitored sysctl or file permission change
- Weekly evidence packages are archived to S3 (or equivalent) for 12 months, satisfying auditor requests for historical compliance evidence
- Cloud-native conformance packs (AWS Config, GCP SCC, Azure Policy) run continuously alongside host-level checks, providing coverage for cloud resource configuration

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| CIS Level 1 as baseline | Broad applicability; minimal operational disruption | Some controls may not match your architecture (e.g. disabling IPv6 when you use it) | Maintain a documented exception list. Each exception requires a compensating control and periodic review. |
| Packer-baked images | All new instances start hardened; no provisioning lag | Image rebuild pipeline takes 20-30 minutes; teams may use old images during the rebuild window | Pin launch templates to image IDs via Terraform. Require image refresh on a defined schedule (e.g. monthly). |
| Ansible for drift remediation | Drift is auto-corrected on the next playbook run | Auto-remediation could revert intentional emergency changes made by an operator | Alert on drift before remediating. Use a review window (e.g. 4 hours) before auto-remediation applies. |
| InSpec daily scans | Compliance status is at most 24 hours stale | Day-long window between drift and detection | Layer osquery continuous monitoring to catch high-priority changes immediately. InSpec provides deep verification; osquery provides rapid detection. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Ansible role not idempotent | Second run changes state or fails | CI test: run role twice in a row; second run should report zero changes | Fix tasks that are not idempotent. Use `changed_when: false` for read-only tasks. Validate with `--diff`. |
| Packer build succeeds but InSpec gate is skipped | Unhardened AMI is published | InSpec gate not in pipeline; no check on published AMI | Add InSpec as a blocking `shell-local` post-provisioner step. Fail the build if any critical control fails. |
| osquery daemon stops running | No continuous compliance events | Missing heartbeat metric from osquery; osquery `last_seen` goes stale in Fleet | Alert on osquery daemon absence. Include `osqueryd` in systemd watchdog or monit supervision. |
| InSpec profile outdated for new OS version | False passes on controls that no longer apply to updated OS | Controls pass on OS version the profile was not written for | Pin InSpec profiles to OS major versions. Test profiles against new OS in CI before rolling out. |

## When to Consider a Managed Alternative

Maintaining InSpec profiles, Ansible roles, and Packer pipelines across multiple OS families and CIS benchmark versions is significant ongoing work. The CIS benchmark itself publishes new versions, and OS vendors release new major versions, each requiring profile updates.

- **[Wiz](https://www.wiz.io):** Cloud-native CSPM with CIS benchmark coverage for cloud resources and Kubernetes. Continuous scanning with no agent required.
- **[Prisma Cloud](https://www.paloaltonetworks.com/prisma/cloud):** Full lifecycle compliance — image scanning, runtime compliance, cloud configuration. CIS, NIST, PCI-DSS, HIPAA profiles built in.
- **[Qualys VMDR](https://www.qualys.com/apps/vulnerability-management-detection-response/):** Agent-based continuous assessment with CIS benchmark profiles and auto-remediation scripts.
- **[Anchore Enterprise](https://anchore.com):** CIS benchmark checks baked into the container image build pipeline, before images are pushed to registry.

Use managed alternatives when engineering bandwidth is the constraint. Use the open-source approach covered here when you need full control over profile content, want to avoid vendor lock-in, or need to customise controls beyond what managed platforms offer.

## Related Articles

- [Compliance-as-Code: Mapping CIS Benchmarks to Automated Checks with InSpec and Kube-bench](/articles/cross-cutting/compliance-as-code/)
- [The Hardening Scorecard: Measuring and Tracking Security Posture](/articles/cross-cutting/hardening-scorecard/)
- [Security Hardening for Small Teams: Prioritising Controls When You Cannot Do Everything](/articles/cross-cutting/hardening-small-teams/)
- [Cloud Security Posture Management: Detecting and Remediating Cloud Misconfigurations](/articles/cross-cutting/cloud-security-posture-management/)
- [Incident Response Hardening Playbook: From Detection to Post-Mortem](/articles/cross-cutting/incident-response-hardening-playbook/)
