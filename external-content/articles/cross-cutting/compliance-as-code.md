---
title: "Compliance-as-Code: Mapping CIS Benchmarks to Automated Checks with InSpec and Kube-bench"
description: "Manual compliance audits are point-in-time snapshots that are outdated before the report is written."
slug: "compliance-as-code"
date: 2026-03-28
lastmod: 2026-03-28
category: "cross-cutting"
tags: ["compliance", "cis", "inspec", "kube-bench", "automation", "soc2"]
personas: ["security-engineer", "devops-engineer"]
article_number: 94
difficulty: "intermediate"
estimated_reading_time: 16
provider_bridges:
  - name: "Aqua"
    id: 123
    category: "runtime-security"
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
  - name: "Vanta"
    id: 169
    category: "compliance"
  - name: "Drata"
    id: 170
    category: "compliance"
premium_pack: "compliance-profile-collection"
published: true
layout: article.njk
permalink: "/articles/cross-cutting/compliance-as-code/index.html"
---

# Compliance-as-Code: Mapping CIS Benchmarks to Automated Checks with [InSpec](https://www.chef.io/products/chef-inspec) and Kube-bench

## Problem

Manual compliance audits are point-in-time snapshots that are outdated before the report is written. Between audits, compliance drift goes undetected, a sysctl setting reverted by a package update, an RBAC binding added for troubleshooting and never removed, a network policy deleted during incident response. CIS Benchmarks and SOC 2 controls can be automated, providing continuous verification instead of periodic spot checks.

## Threat Model

- **Adversary:** Compliance drift, the gap between documented security posture and actual configuration. This is not a human adversary but an entropy problem: systems drift from their hardened state over time.

## Configuration

### Chef InSpec for Linux CIS Benchmark

```bash
# Install InSpec
curl https://omnitruck.chef.io/install.sh | sudo bash -s -- -P inspec

# Run CIS Level 1 benchmark against a host
inspec exec https://github.com/dev-sec/linux-baseline \
  --reporter json:/tmp/inspec-results.json cli

# Output: pass/fail for each CIS control
# Example:
#   ✔  os-01: Trusted hosts login
#   ✔  os-02: Check owner and permissions for /etc/shadow
#   ✗  sysctl-01: IPv4 Forwarding (expected 0, got 1)
```

### Custom InSpec Profile

```ruby
# controls/sysctl_hardening.rb
# Custom InSpec controls matching Article #1 sysctl settings

control 'sysctl-01' do
  impact 1.0
  title 'Network stack hardening'
  desc 'Verify sysctl hardening settings from systemshardening.com Article #1'

  describe kernel_parameter('net.ipv4.conf.all.rp_filter') do
    its('value') { should eq 1 }
  end

  describe kernel_parameter('net.ipv4.conf.all.accept_source_route') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv4.conf.all.accept_redirects') do
    its('value') { should eq 0 }
  end

  describe kernel_parameter('net.ipv4.tcp_syncookies') do
    its('value') { should eq 1 }
  end

  describe kernel_parameter('kernel.kptr_restrict') do
    its('value') { should eq 2 }
  end

  describe kernel_parameter('kernel.dmesg_restrict') do
    its('value') { should eq 1 }
  end
end

control 'ssh-01' do
  impact 1.0
  title 'SSH hardening'
  desc 'Verify SSH hardening from systemshardening.com Article #7'

  describe sshd_config do
    its('PermitRootLogin') { should eq 'no' }
    its('PasswordAuthentication') { should eq 'no' }
    its('MaxAuthTries') { should cmp <= 3 }
    its('X11Forwarding') { should eq 'no' }
    its('AllowTcpForwarding') { should eq 'no' }
  end
end
```

### [kube-bench](https://aquasecurity.github.io/kube-bench/) for [Kubernetes](https://kubernetes.io) CIS Benchmark

```bash
# Run kube-bench as a Kubernetes Job
kubectl apply -f - <<'EOF'
apiVersion: batch/v1
kind: Job
metadata:
  name: kube-bench
  namespace: default
spec:
  template:
    spec:
      hostPID: true
      containers:
        - name: kube-bench
          image: aquasec/kube-bench:latest
          command: ["kube-bench", "run", "--json"]
          volumeMounts:
            - name: var-lib-kubelet
              mountPath: /var/lib/kubelet
              readOnly: true
            - name: etc-kubernetes
              mountPath: /etc/kubernetes
              readOnly: true
      restartPolicy: Never
      volumes:
        - name: var-lib-kubelet
          hostPath:
            path: /var/lib/kubelet
        - name: etc-kubernetes
          hostPath:
            path: /etc/kubernetes
EOF

# Get results:
kubectl logs job/kube-bench | jq '.Controls[].tests[].results[] | select(.status == "FAIL")'
```

### CI/CD Integration

```yaml
# .github/workflows/compliance.yml
name: Compliance Check
on:
  push:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 06:00 UTC

jobs:
  linux-compliance:
    runs-on: self-hosted  # Must run on the target host
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Run InSpec CIS benchmark
        run: |
          inspec exec ./inspec-profiles/linux-hardening \
            --reporter json:inspec-results.json cli
          # Parse results for Prometheus
          PASS=$(jq '[.profiles[].controls[].results[] | select(.status == "passed")] | length' inspec-results.json)
          FAIL=$(jq '[.profiles[].controls[].results[] | select(.status == "failed")] | length' inspec-results.json)
          TOTAL=$((PASS + FAIL))
          SCORE=$(echo "scale=2; $PASS / $TOTAL * 100" | bc)
          echo "compliance_score{host=\"$(hostname)\",framework=\"cis\"} $SCORE" > /var/lib/node_exporter/compliance.prom
          echo "Compliance score: $SCORE% ($PASS/$TOTAL passed)"

      - name: Fail if score below threshold
        run: |
          SCORE=$(jq -r '.statistics.duration' inspec-results.json)
          FAIL_COUNT=$(jq '[.profiles[].controls[].results[] | select(.status == "failed")] | length' inspec-results.json)
          if [ "$FAIL_COUNT" -gt 5 ]; then
            echo "COMPLIANCE FAILURE: $FAIL_COUNT controls failed"
            exit 1
          fi
```

### Audit-Ready Reporting

```bash
# Generate HTML report for auditors:
inspec exec ./inspec-profiles/linux-hardening \
  --reporter html:compliance-report.html json:compliance-data.json

# The HTML report includes:
# - Pass/fail status for each control
# - Control descriptions and remediation guidance
# - Timestamp and target host
# - Overall compliance score

# For Grafana dashboard:
# Export compliance score as a Prometheus metric (see CI workflow above)
# Dashboard panel: single-stat showing compliance percentage per host
```

### Mapping Controls to Remediation

Each failed InSpec control links to the corresponding systemshardening.com article:

```ruby
control 'sysctl-01' do
  impact 1.0
  title 'Network stack hardening'
  desc 'Verify sysctl hardening settings'
  tag remediation: 'https://systemshardening.com/articles/linux/sysctl-kernel-hardening/'
  tag cis: '3.3.1'
  tag ansible_tag: 'sysctl'

  # ... checks ...
end
```

## Expected Behaviour

- InSpec CIS benchmark runs weekly; compliance score tracked in Prometheus
- kube-bench CIS score > 90% for Kubernetes clusters
- Failed controls generate alerts; each failure links to a remediation article
- Compliance reports available for auditors on demand (HTML + JSON)
- Compliance drift detected within 1 week (scheduled scans)

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Weekly compliance scans | Drift detected within 7 days | Week-long gap between drift and detection | Increase frequency to daily for critical systems. |
| InSpec on production hosts | Scans read system state; no writes | InSpec requires elevated access (root or sudo) | Run InSpec with a dedicated read-only service account. |
| Automated remediation ([Ansible](https://www.ansible.com)) | Drift auto-fixed | Auto-remediation could revert intentional changes | Alert on drift first. Auto-remediate only for critical controls after review period. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| InSpec profile outdated | Controls don't match current OS version | New OS features not checked; false passes | Update profiles when OS is upgraded. Pin profiles to OS version. |
| kube-bench version mismatch | Checks for wrong K8s version | Results show controls that don't apply | Pin kube-bench version to match cluster version. |
| Compliance score drops after upgrade | Package update reverted hardening setting | Scheduled compliance scan shows regression | Run compliance scan after every `apt upgrade` / `dnf update`. Link to Ansible remediation. |

## When to Consider a Managed Alternative

Maintaining compliance profiles across OS and K8s versions is ongoing work. Generating audit-ready reports requires formatting and aggregation.

- **[Aqua](https://www.aquasec.com):** Compliance scanning with managed profiles. CIS, NIST, PCI-DSS, HIPAA built-in.
- **[Sysdig](https://sysdig.com):** Continuous compliance monitoring. Maps [Falco](https://falco.org) detections to compliance frameworks.
- **[Vanta](https://www.vanta.com) / [Drata](https://drata.com) / [Secureframe](https://secureframe.com):** Full compliance automation platforms for SOC 2, ISO 27001. Automated evidence collection, continuous monitoring, and auditor-ready reports. Use when customers or investors require formal certification.

**Premium content pack:** Compliance profile collection. InSpec profiles for CIS Level 1/2 (Ubuntu 24.04, RHEL 9), kube-bench custom checks, compliance dashboard Grafana JSON, and control-to-article remediation mappings.


## Related Articles

- [The Hardening Scorecard: Measuring and Tracking Security Posture](/articles/cross-cutting/hardening-scorecard/)
- [Incident Response Hardening Playbook: From Detection to Post-Mortem](/articles/cross-cutting/incident-response-hardening-playbook/)
- [Zero Trust Networking: Identity-Based Access Beyond Perimeter Security](/articles/cross-cutting/zero-trust-networking/)
- [Hardening a Complete Kubernetes Platform: From Cluster Bootstrap to Production-Ready](/articles/cross-cutting/complete-kubernetes-hardening/)
- [Security Hardening for Small Teams: Prioritising Controls When You Cannot Do Everything](/articles/cross-cutting/hardening-small-teams/)
