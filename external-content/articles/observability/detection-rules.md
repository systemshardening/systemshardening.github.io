---
title: "Building Detection Rules That Don't Cry Wolf: Alert Design for Security Events"
description: "Security detection that generates 50+ false positives per day is worse than no detection, it trains the team to ignore alerts."
slug: "detection-rules"
date: 2026-01-23
lastmod: 2026-01-23
category: "observability"
tags: ["alerting", "detection", "false-positives", "correlation", "prometheus", "falco"]
personas: ["security-engineer", "sre"]
article_number: 67
difficulty: "advanced"
estimated_reading_time: 18
provider_bridges:
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
  - name: "Panther"
    id: 127
    category: "runtime-security"
premium_pack: "security-alert-rules"
published: true
layout: article.njk
permalink: "/articles/observability/detection-rules/index.html"
---

# Building Detection Rules That Don't Cry Wolf: Alert Design for Security Events

## Problem

Security detection that generates 50+ false positives per day is worse than no detection, it trains the team to ignore alerts. Most detection rules are written for theoretical attacks without calibration against real traffic patterns. The result: alert fatigue that masks genuine incidents.

The core challenge: reducing false positives WITHOUT missing real attacks. Every detection rule sits on a spectrum, tighter thresholds catch more attacks but generate more noise. The engineering discipline is finding the right point on that spectrum for each rule, and using correlation to increase confidence without increasing noise.

**Target systems:** [Prometheus](https://prometheus.io) + Alertmanager, [Falco](https://falco.org), and any SIEM/alerting platform.

## Threat Model

- **Adversary:** Alert fatigue is the adversary's ally. An attacker who operates while the security team is ignoring noisy alerts has unlimited dwell time.

## Configuration

### Baseline Establishment (30-Day Learning Period)

Before writing detection rules, establish what "normal" looks like:

```yaml
# Prometheus recording rules: capture baselines for key security signals.
groups:
  - name: security-baselines
    interval: 5m
    rules:
      # Auth failure baseline: average failures per source per 5-minute window
      - record: security:auth_failures:avg_rate5m_7d
        expr: avg_over_time(rate(auth_failures_total{result="failure"}[5m])[7d:5m])

      # API error baseline: average 4xx rate per service
      - record: security:api_errors:avg_rate5m_7d
        expr: avg_over_time(rate(http_requests_total{code=~"4.."}[5m])[7d:5m])

      # Process execution baseline: unique binaries per container image over 7 days
      - record: security:process_count:count_7d
        expr: count by (container_image) (count_over_time(container_processes_total[7d]))

      # Network destination baseline: unique destinations per source workload
      - record: security:network_destinations:count_7d
        expr: count by (source_workload, destination_workload) (
          rate(hubble_flows_processed_total{verdict="FORWARDED"}[7d]) > 0
        )
```

### Brute Force Detection (Low False Positive)

```yaml
# Alert: auth failure rate exceeds 5x the 7-day average from a single source.
# Using a multiplier of the baseline instead of a static threshold adapts
# to environments with different normal failure rates.
- alert: BruteForceDetected
  expr: >
    rate(auth_failures_total{result="failure"}[5m])
    > 5 * security:auth_failures:avg_rate5m_7d
    and rate(auth_failures_total{result="failure"}[5m]) > 0.1
  for: 2m
  labels:
    severity: warning
    detection_type: brute_force
  annotations:
    summary: "Brute force: {{ $labels.source_ip }} against {{ $labels.service }}"
    description: "Current rate: {{ $value | humanize }}/sec (5x above baseline)"
    runbook_url: "https://systemshardening.com/runbooks/brute-force"
    false_positive_notes: |
      Common FP sources: password rotation scripts, misconfigured service accounts,
      mobile apps with expired cached credentials. Check if the source IP matches
      a known internal service before escalating.
```

**Why `> 5 * baseline AND > 0.1`:** The AND clause prevents alerts when the baseline is near zero (a single failure would be "infinitely above baseline"). The absolute floor of 0.1/sec (6 failures per minute) filters out normal occasional failures.

### Unusual Process Execution (Medium False Positive - Needs Tuning)

```yaml
# Falco rule: process not seen in 30-day baseline for this container image.
- rule: Process Not In Baseline
  desc: A process was executed that has not been seen in this container image in 30 days.
  condition: >
    spawned_process
    and container
    and not (proc.name, container.image.repository) in (baseline_process_list)
  output: >
    Process not in baseline
    (binary=%proc.name image=%container.image.repository
     container=%container.name namespace=%k8s.ns.name)
  priority: NOTICE
  tags: [behavioural, baseline]

# The baseline_process_list is generated from 30 days of observation.
# Update weekly via a cron job that queries Prometheus:
# SELECT DISTINCT binary_name, container_image
# FROM process_execution_logs
# WHERE timestamp > now() - interval '30 days'
```

**Tuning this rule:** Start at NOTICE priority (not WARNING). Review all NOTICE alerts for 2 weeks. Promote true positives to WARNING. Add exceptions for known-good processes that appear occasionally (cron jobs, init processes, health checks).

### Data Exfiltration Detection

```yaml
# Alert: outbound data volume 10x above 7-day average for a specific service.
- alert: PossibleDataExfiltration
  expr: >
    rate(container_network_transmit_bytes_total[1h])
    > 10 * avg_over_time(rate(container_network_transmit_bytes_total[1h])[7d:1h])
    and rate(container_network_transmit_bytes_total[1h]) > 1048576
  for: 15m
  labels:
    severity: warning
    detection_type: exfiltration
  annotations:
    summary: "{{ $labels.pod }} sending 10x normal egress ({{ $value | humanize }}B/sec)"
    false_positive_notes: |
      Common FP sources: backup jobs, log shipping spikes, database replication
      catch-up after maintenance, deployment of large container images.
      Check if a backup or migration is scheduled before escalating.
```

### DNS Tunnelling Detection

```yaml
# Alert: DNS query rate from a single pod exceeds normal patterns.
# DNS tunnelling generates 100-1000x more DNS queries than normal applications.
- alert: PossibleDNSTunnelling
  expr: >
    sum by (source_pod) (
      rate(coredns_dns_requests_total[5m])
    ) > 10
  for: 10m
  labels:
    severity: warning
    detection_type: dns_tunnelling
  annotations:
    summary: "High DNS query rate from {{ $labels.source_pod }}: {{ $value | humanize }}/sec"
    runbook_url: "https://systemshardening.com/runbooks/dns-tunnelling"
    false_positive_notes: |
      Common FP sources: service discovery (consul, etcd), DNS-based load balancing,
      applications with short DNS TTLs. Check the queried domains, tunnelling
      queries target a single domain with very long subdomain labels.
```

### Alert Correlation (Multi-Signal High Confidence)

Single anomalies are low-confidence. Multiple anomalies from the same source in the same time window are high-confidence:

```yaml
# High-confidence composite alert: process anomaly AND network anomaly
# from the same pod within 10 minutes.
- alert: CorrelatedCompromiseIndicator
  expr: >
    (count by (namespace, pod) (
      ALERTS{alertname="ProcessNotInBaseline", alertstate="firing"}
    ) > 0)
    and on (namespace, pod)
    (count by (namespace, pod) (
      ALERTS{alertname=~"PossibleDataExfiltration|NewNetworkDestination", alertstate="firing"}
    ) > 0)
  labels:
    severity: critical
    detection_type: correlated
  annotations:
    summary: "CORRELATED: {{ $labels.pod }} has process AND network anomalies"
    description: |
      HIGH CONFIDENCE. This pod exhibits:
      1. Unexpected process execution (not in 30-day baseline)
      2. Anomalous network behaviour (exfiltration or new destination)
      IMMEDIATE ACTION: Quarantine the pod. Begin investigation.
    runbook_url: "https://systemshardening.com/runbooks/compromised-pod"
```

### Deployment Window Suppression

```yaml
# Inhibit behavioural alerts during rolling deployments.
# ArgoCD sync events trigger a 15-minute suppression window.
inhibit_rules:
  - source_match:
      alertname: DeploymentInProgress
    target_match_re:
      detection_type: "baseline|behavioural"
    equal: ['namespace']
```

```yaml
# Recording rule: track deployment activity per namespace
- record: deployment:in_progress
  expr: changes(argocd_app_sync_total[15m]) > 0

# Alert that serves as the suppression source
- alert: DeploymentInProgress
  expr: deployment:in_progress > 0
  labels:
    severity: info
```

### Alert Quality Metrics

Track detection quality over time:

```yaml
# Record alert outcomes for quality measurement
# (requires manual tagging of alerts as TP/FP after investigation)

# Dashboard metrics:
# - False positive rate: FP alerts / total alerts per week
# - Mean time to detect (MTTD): time from first anomaly to alert
# - Mean time to investigate (MTTI): time from alert to triage decision
# - Alert-to-incident ratio: alerts that became incidents / total alerts
```

### Runbook Links in Every Alert

Every alert MUST include a `runbook_url` annotation:

```yaml
annotations:
  runbook_url: "https://systemshardening.com/runbooks/brute-force"
  # Runbook covers:
  # 1. Triage: is this a real attack or a known FP source?
  # 2. Investigation: what to check (logs, metrics, context)
  # 3. Escalation: when to page, when to create an incident
  # 4. Response: containment actions for confirmed attacks
  # 5. Known FP patterns: common false positive sources
```

## Expected Behaviour

- False positive rate below 5 per day after 30-day tuning period
- True positive detection for brute force, lateral movement, and data exfiltration
- Correlated alerts (multi-signal) reduce page volume by 60-80% vs uncorrelated
- Deployment-window suppression eliminates 90% of deployment-related false positives
- Every alert includes a runbook link and false positive notes
- Alert quality metrics tracked weekly

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| Baseline-relative thresholds (5x average) | Adapts to each environment's normal | Noisy environments have high baselines; attacks may hide within | Add absolute floor thresholds (AND clause) to catch attacks in noisy environments. |
| 30-day baseline period | No behavioural detection for new workloads | Attackers may target new workloads | Use strict allowlists (not baselines) for new workloads during learning period. |
| Correlation (require 2+ signals) | Much fewer false positives | Slower detection for single-vector attacks | Keep individual alerts at NOTICE/WARNING; only escalate correlated alerts to CRITICAL. |
| Deployment suppression (15 min) | Eliminates deployment noise | Attacker could time attack to deployment window | Keep window minimal. Alert on unexpected deployments (manual, outside CI). |
| `false_positive_notes` in annotations | Reduces investigation time per alert | Notes may become outdated | Review and update notes after every FP investigation. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Threshold too sensitive | 50+ alerts per day; team ignores all alerts | Weekly alert quality review shows >80% FP rate | Increase multiplier (5x → 10x). Add absolute floor. Review top alert generators. |
| Threshold too loose | Real attack goes undetected | Post-incident review reveals alert did not fire | Lower threshold. Add correlation rules that combine weak signals. |
| Baseline drift | Gradually increasing FP rate over weeks | Alert volume trending upward without corresponding incidents | Re-baseline monthly. Exclude deployment windows from baseline calculation. |
| Suppression too broad | Real attack during deployment goes undetected | Post-incident: attack occurred during suppression window | Narrow suppression to specific alert types only. Never suppress critical alerts. |
| Runbook missing or outdated | On-call engineer doesn't know how to investigate | Investigation time exceeds SLA; engineer escalates without triage | Require runbook link in every alert rule. Review runbooks after every incident. |

## When to Consider a Managed Alternative

Self-managed detection rules require ongoing tuning (4-8 hours/month) and baseline maintenance.

- **[Sysdig](https://sysdig.com):** Managed detection rules updated for emerging attack techniques. ML-powered anomaly detection. Multi-cluster baseline aggregation.
- **[Panther](https://panther.com):** Detection-as-code SIEM with Python rules. Cross-signal correlation engine.
- **[Grafana Cloud](https://grafana.com/cloud):** Unified alerting across metrics and logs. ML-powered anomaly alerting in [Grafana](https://grafana.com) Cloud.

**Premium content pack:** Security alert rule library. 30+ tested Prometheus alert rules and Falco rules for auth, RBAC, network, process, and exfiltration detection. Each rule includes baseline recording rules, correlation patterns, runbook templates, and false positive documentation.


## Related Articles

- [Crypto Mining Detection: CPU Patterns, Network Signatures, and Automated Response](/articles/observability/crypto-mining-detection/)
- [Security-Relevant Prometheus Metrics: What to Collect, How to Alert, When to Page](/articles/observability/prometheus-security-metrics/)
- [Lateral Movement Detection: Network Patterns, Authentication Anomalies, and Alert Correlation](/articles/observability/lateral-movement-detection/)
- [eBPF-Based Security Monitoring: Tetragon for Process, Network, and File Observability](/articles/observability/ebpf-tetragon/)
- [Incident Response Runbooks: Structured Procedures for Common Security Events](/articles/observability/incident-response-runbooks/)
