---
title: "The Hardening Scorecard: Measuring and Tracking Security Posture"
description: "\"Are we more secure than last month?\" is a question most teams cannot answer. Security tools produce individual outputs: kube-bench returns a CIS score..."
slug: "hardening-scorecard"
date: 2026-04-10
lastmod: 2026-04-10
category: "cross-cutting"
tags: ["metrics", "scorecard", "cis-benchmark", "compliance", "grafana", "security-posture"]
personas: ["security-engineer", "sre"]
article_number: 99
difficulty: "intermediate"
estimated_reading_time: 14
provider_bridges:
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
  - name: "Vanta"
    id: 169
    category: "compliance"
  - name: "Drata"
    id: 170
    category: "compliance"
premium_pack: "grafana-scorecard-dashboard-pack"
published: true
layout: article.njk
permalink: "/articles/cross-cutting/hardening-scorecard/index.html"
---

# The Hardening Scorecard: Measuring and Tracking Security Posture

## Problem

"Are we more secure than last month?" is a question most teams cannot answer. Security tools produce individual outputs: [kube-bench](https://aquasecurity.github.io/kube-bench/) returns a CIS score, [Trivy](https://trivy.dev) lists CVEs, network policy audits show coverage percentages. But nobody correlates these signals into a single view. Without aggregated measurement, hardening work is driven by gut feeling and audit pressure rather than data.

The absence of measurement creates two problems. First, teams cannot prioritise: if you do not know which area is weakest, you invest effort randomly. Second, leadership visibility is zero. The engineering team knows they "did some security work" but cannot quantify progress. When budget or headcount discussions happen, the security team has no data to demonstrate improvement or justify further investment.

A hardening scorecard aggregates signals from existing tools into a single dashboard with trend lines, category scores, and threshold alerts. It does not replace individual tools. It makes their outputs actionable.

**Target systems:** [Kubernetes](https://kubernetes.io) clusters (kube-bench, Trivy, network policy audit). Linux hosts ([InSpec](https://www.chef.io/products/chef-inspec), [Lynis](https://cisofy.com/lynis/)). CI/CD pipelines (vulnerability scan results). [Prometheus](https://prometheus.io) and [Grafana](https://grafana.com) for metric storage and visualisation.

## Threat Model

- **Adversary:** Not a specific attacker. The threat is unmeasured risk. Hardening controls that degrade silently (certificate expires, network policy removed, new namespace without RBAC) create gaps that are only discovered during an incident or audit.
- **Objective:** The scorecard detects security posture degradation before an attacker exploits it. A declining CIS benchmark score, a rising CVE count, or a namespace without network policies are all signals that something changed.
- **Blast radius:** An unmeasured security gap has unlimited blast radius because nobody knows it exists. The scorecard limits blast radius by making gaps visible within hours of their appearance.

## Configuration

### Define Hardening Metrics

```yaml
# hardening-metrics-definition.yaml
# Document what you measure, how, and what the target is
metrics:
  - name: cis_benchmark_score
    source: kube-bench
    target: ">= 90%"
    frequency: daily
    description: "CIS Kubernetes Benchmark pass rate"

  - name: critical_cve_count
    source: trivy
    target: "0"
    frequency: "every CI build + daily scheduled scan"
    description: "Number of critical CVEs in running container images"

  - name: high_cve_count
    source: trivy
    target: "<= 10"
    frequency: "every CI build + daily scheduled scan"
    description: "Number of high severity CVEs in running container images"

  - name: network_policy_coverage
    source: "kubectl audit script"
    target: "100%"
    frequency: hourly
    description: "Percentage of namespaces with default-deny network policy"

  - name: rbac_least_privilege
    source: "rbac-audit script"
    target: "0 cluster-admin bindings outside kube-system"
    frequency: daily
    description: "Number of ClusterRoleBindings using cluster-admin"

  - name: certificate_expiry_min_days
    source: cert-manager
    target: ">= 14 days"
    frequency: hourly
    description: "Minimum days until any certificate expires"

  - name: secret_age_max_days
    source: vault
    target: "<= 90 days"
    frequency: daily
    description: "Maximum age of any secret in Vault"

  - name: pss_compliance
    source: "pod-security audit"
    target: "100% restricted or baseline"
    frequency: hourly
    description: "Percentage of namespaces with Pod Security Standards enforced"
```

### Automated Collection

```bash
#!/bin/bash
# collect-hardening-metrics.sh
# Run as a CronJob in the monitoring namespace
set -euo pipefail

PUSHGATEWAY="http://prometheus-pushgateway.monitoring:9091"

# 1. CIS Benchmark Score (kube-bench)
TOTAL=$(kube-bench run --json 2>/dev/null | jq '.Totals.total_pass + .Totals.total_fail + .Totals.total_warn')
PASS=$(kube-bench run --json 2>/dev/null | jq '.Totals.total_pass')
SCORE=$(echo "scale=2; ${PASS} / ${TOTAL} * 100" | bc)

cat <<METRICS | curl -s --data-binary @- "${PUSHGATEWAY}/metrics/job/hardening-scorecard"
# HELP hardening_cis_score CIS Kubernetes Benchmark pass percentage
# TYPE hardening_cis_score gauge
hardening_cis_score ${SCORE}
# HELP hardening_cis_pass CIS checks passed
# TYPE hardening_cis_pass gauge
hardening_cis_pass ${PASS}
# HELP hardening_cis_total CIS checks total
# TYPE hardening_cis_total gauge
hardening_cis_total ${TOTAL}
METRICS

# 2. CVE Counts (Trivy scanning running images)
CRITICAL_CVES=0
HIGH_CVES=0
for IMAGE in $(kubectl get pods -A -o jsonpath='{.items[*].spec.containers[*].image}' | tr ' ' '\n' | sort -u); do
  RESULT=$(trivy image --quiet --format json --severity CRITICAL,HIGH "${IMAGE}" 2>/dev/null || echo '{"Results":[]}')
  CRITICAL_CVES=$((CRITICAL_CVES + $(echo "${RESULT}" | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length')))
  HIGH_CVES=$((HIGH_CVES + $(echo "${RESULT}" | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH")] | length')))
done

cat <<METRICS | curl -s --data-binary @- "${PUSHGATEWAY}/metrics/job/hardening-scorecard"
# HELP hardening_critical_cves Critical CVEs in running images
# TYPE hardening_critical_cves gauge
hardening_critical_cves ${CRITICAL_CVES}
# HELP hardening_high_cves High severity CVEs in running images
# TYPE hardening_high_cves gauge
hardening_high_cves ${HIGH_CVES}
METRICS

# 3. Network Policy Coverage
TOTAL_NS=$(kubectl get ns --no-headers | wc -l)
NS_WITH_POLICY=$(kubectl get networkpolicy -A --no-headers 2>/dev/null | awk '{print $1}' | sort -u | wc -l)
COVERAGE=$(echo "scale=2; ${NS_WITH_POLICY} / ${TOTAL_NS} * 100" | bc)

cat <<METRICS | curl -s --data-binary @- "${PUSHGATEWAY}/metrics/job/hardening-scorecard"
# HELP hardening_netpol_coverage Percentage of namespaces with network policies
# TYPE hardening_netpol_coverage gauge
hardening_netpol_coverage ${COVERAGE}
METRICS

# 4. RBAC Audit
CLUSTER_ADMIN_BINDINGS=$(kubectl get clusterrolebindings -o json | \
  jq '[.items[] | select(.roleRef.name=="cluster-admin") | select(.metadata.namespace != "kube-system")] | length')

cat <<METRICS | curl -s --data-binary @- "${PUSHGATEWAY}/metrics/job/hardening-scorecard"
# HELP hardening_cluster_admin_bindings Non-system cluster-admin bindings
# TYPE hardening_cluster_admin_bindings gauge
hardening_cluster_admin_bindings ${CLUSTER_ADMIN_BINDINGS}
METRICS

# 5. Certificate Expiry
MIN_DAYS=$(kubectl get certificates -A -o json | \
  jq '[.items[].status.notAfter | fromdateiso8601 - now | . / 86400 | floor] | min // 9999')

cat <<METRICS | curl -s --data-binary @- "${PUSHGATEWAY}/metrics/job/hardening-scorecard"
# HELP hardening_cert_min_days_remaining Minimum days until certificate expiry
# TYPE hardening_cert_min_days_remaining gauge
hardening_cert_min_days_remaining ${MIN_DAYS}
METRICS

echo "Hardening metrics collection complete."
```

```yaml
# cronjob-hardening-metrics.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: hardening-metrics
  namespace: monitoring
spec:
  schedule: "0 */6 * * *"  # Every 6 hours
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: hardening-metrics
          containers:
            - name: collector
              image: registry.example.com/hardening-metrics:v1
              command: ["/bin/bash", "/scripts/collect-hardening-metrics.sh"]
              volumeMounts:
                - name: scripts
                  mountPath: /scripts
          restartPolicy: OnFailure
          volumes:
            - name: scripts
              configMap:
                name: hardening-metrics-scripts
```

### Scorecard Alerts

```yaml
# prometheus-scorecard-alerts.yaml
groups:
  - name: hardening-scorecard
    rules:
      - alert: CISScoreDegraded
        expr: hardening_cis_score < 85
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "CIS Benchmark score dropped below 85% (current: {{ $value }}%)"
          runbook: "Run kube-bench to identify failing checks. Compare with previous report to find regressions."

      - alert: CriticalCVEsDetected
        expr: hardening_critical_cves > 0
        for: 15m
        labels:
          severity: critical
        annotations:
          summary: "{{ $value }} critical CVEs in running container images"
          runbook: "Run trivy scan to identify affected images. Prioritise patching."

      - alert: NetworkPolicyCoverageGap
        expr: hardening_netpol_coverage < 100
        for: 30m
        labels:
          severity: warning
        annotations:
          summary: "Network policy coverage at {{ $value }}%. Not all namespaces have policies."
          runbook: "List namespaces without network policies. Apply default-deny policy to each."

      - alert: ClusterAdminOveruse
        expr: hardening_cluster_admin_bindings > 0
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "{{ $value }} cluster-admin bindings outside kube-system"
          runbook: "Review each binding. Replace with least-privilege roles."

      - alert: CertificateExpiringSoon
        expr: hardening_cert_min_days_remaining < 14
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "Certificate expiring in {{ $value }} days"

      - alert: HardeningScoreDropped
        expr: >
          hardening_cis_score < avg_over_time(hardening_cis_score[7d]) - 5
        for: 6h
        labels:
          severity: warning
        annotations:
          summary: "CIS score dropped more than 5 points from 7-day average"
          description: "A significant regression in hardening posture was detected. Investigate recent changes."
```

### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "Hardening Scorecard",
    "panels": [
      {
        "title": "Overall CIS Score",
        "type": "gauge",
        "targets": [{"expr": "hardening_cis_score"}],
        "fieldConfig": {
          "defaults": {
            "thresholds": {
              "steps": [
                {"color": "red", "value": 0},
                {"color": "yellow", "value": 70},
                {"color": "green", "value": 90}
              ]
            },
            "unit": "percent",
            "max": 100
          }
        }
      },
      {
        "title": "Critical CVEs",
        "type": "stat",
        "targets": [{"expr": "hardening_critical_cves"}],
        "fieldConfig": {
          "defaults": {
            "thresholds": {
              "steps": [
                {"color": "green", "value": 0},
                {"color": "red", "value": 1}
              ]
            }
          }
        }
      },
      {
        "title": "Network Policy Coverage",
        "type": "gauge",
        "targets": [{"expr": "hardening_netpol_coverage"}],
        "fieldConfig": {
          "defaults": {
            "thresholds": {
              "steps": [
                {"color": "red", "value": 0},
                {"color": "yellow", "value": 80},
                {"color": "green", "value": 100}
              ]
            },
            "unit": "percent"
          }
        }
      },
      {
        "title": "CIS Score Trend (30 days)",
        "type": "timeseries",
        "targets": [{"expr": "hardening_cis_score", "legendFormat": "CIS Score"}]
      },
      {
        "title": "CVE Trend (30 days)",
        "type": "timeseries",
        "targets": [
          {"expr": "hardening_critical_cves", "legendFormat": "Critical"},
          {"expr": "hardening_high_cves", "legendFormat": "High"}
        ]
      }
    ]
  }
}
```

## Expected Behaviour

- Hardening metrics are collected every 6 hours and pushed to Prometheus
- Grafana dashboard shows current scores, trend lines, and threshold indicators
- CIS benchmark score above 90% (green), 70-90% (yellow), below 70% (red)
- Critical CVE count at zero (green), any non-zero triggers critical alert
- Network policy coverage at 100% (all namespaces have at least one policy)
- Score regressions (5+ point drop from 7-day average) trigger investigation alerts
- Monthly trend reports are generated from dashboard data for leadership review

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| 6-hour collection interval | Balance between freshness and resource usage | CVE introduced between scans is undetected for up to 6 hours | CI pipeline scans catch CVEs at build time. Scheduled scans catch CVEs in running images. |
| Pushgateway for metrics | Simple integration with batch jobs | Pushgateway is a single point of failure for scorecard metrics | Run Pushgateway with persistent storage. Missing push triggers its own alert. |
| Single aggregated score | Easy to understand for leadership | Aggregation hides detail (90% CIS score could mean very different things) | Dashboard provides drill-down from aggregate to individual check failures. Never report only the number. |
| kube-bench + Trivy as data sources | Open-source, no licensing cost | Tool-specific: kube-bench covers CIS only, Trivy covers CVEs only | Add data sources over time. The scorecard framework is extensible. Start with two sources, add more as the programme matures. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Metrics collection job fails | Stale data in dashboard; score does not update | CronJob failure alert; Pushgateway last push timestamp is old | Check CronJob logs. Common causes: kube-bench binary not found, Trivy DB update failed, RBAC insufficient. |
| Score improves artificially | Metric shows improvement without actual hardening | Manual review reveals metric changed due to fewer total checks (denominator decreased) | Track both pass count and total count. Alert on significant denominator changes. |
| Dashboard not reviewed | Scorecard exists but nobody looks at it | No meeting or review process references the dashboard | Schedule monthly security review meeting with dashboard as the first agenda item. |
| Alert fatigue from scorecard | Team ignores scorecard alerts because there are too many | Alert acknowledgement rate drops; open alerts accumulate | Reduce to high-value alerts only (critical CVEs, score regression). Informational metrics stay in dashboard, not alerts. |

## When to Consider a Managed Alternative

[Grafana Cloud](https://grafana.com/cloud) for managed dashboards with team sharing, eliminating Prometheus and Grafana infrastructure management. [Sysdig](https://sysdig.com) for built-in compliance scoring with CIS benchmark automation and runtime visibility. [Vanta](https://www.vanta.com) and [Drata](https://drata.com) for automated compliance scoring that maps directly to SOC 2, ISO 27001, and other frameworks, useful when the scorecard's audience is auditors rather than engineers.

**Premium content pack:** Grafana scorecard dashboard pack. Pre-built Grafana JSON dashboards, metric collection CronJob manifests, Prometheus alert rules for posture degradation, and executive summary report template.


## Related Articles

- [Compliance-as-Code: Mapping CIS Benchmarks to Automated Checks with InSpec and Kube-bench](/articles/cross-cutting/compliance-as-code/)
- [Incident Response Hardening Playbook: From Detection to Post-Mortem](/articles/cross-cutting/incident-response-hardening-playbook/)
- [Multi-Cloud Hardening: Consistent Security Posture Across Providers](/articles/cross-cutting/multi-cloud-hardening/)
- [Hardening a Complete Kubernetes Platform: From Cluster Bootstrap to Production-Ready](/articles/cross-cutting/complete-kubernetes-hardening/)
- [Security Hardening for Small Teams: Prioritising Controls When You Cannot Do Everything](/articles/cross-cutting/hardening-small-teams/)
