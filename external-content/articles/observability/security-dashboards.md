---
title: "Security Dashboards That Engineers Actually Use: Grafana Designs for Hardening Verification"
description: "Most security dashboards are vanity metrics, total alerts this month, pie charts of vulnerability severity, traffic heatmaps that look impressive but."
slug: "security-dashboards"
date: 2026-04-13
lastmod: 2026-04-13
category: "observability"
tags: ["grafana", "dashboards", "security-monitoring", "visualization", "sli"]
personas: ["sre", "security-engineer"]
article_number: 74
difficulty: "intermediate"
estimated_reading_time: 14
provider_bridges:
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
premium_pack: "grafana-security-dashboards"
published: true
layout: article.njk
permalink: "/articles/observability/security-dashboards/index.html"
---

# Security Dashboards That Engineers Actually Use: [Grafana](https://grafana.com) Designs for Hardening Verification

## Problem

Most security dashboards are vanity metrics, total alerts this month, pie charts of vulnerability severity, traffic heatmaps that look impressive but answer no actionable question. Engineers glance at them once and never return. The result: security state is invisible until something breaks.

Effective security dashboards answer one question: **are my security controls working right now?** Each panel has an associated action, green means "nothing to do," red means "fix this today."

## Threat Model

- **Adversary:** Invisible security degradation. A network policy that was deleted. A certificate that is expiring. A seccomp profile that was removed during a deployment. A [Falco](https://falco.org) rule that stopped matching. Without dashboards, these regressions go unnoticed until the next audit or incident.

## Configuration

### Dashboard Design Principles

1. **Answer a question, not display a metric.** Every panel answers: "Is X working?" not "What is the value of Y?"
2. **Red/amber/green status over raw numbers.** A single-stat panel showing "3 pods without network policy" is more useful than a time-series graph of policy counts.
3. **Action link on every panel.** Red panel → link to the runbook or the article that fixes the issue.
4. **No vanity metrics.** Remove panels that nobody acts on. If a panel has been green for 6 months and nobody has ever clicked on it, delete it.

### Panel 1: Network Policy Coverage

```json
{
  "title": "Pods Without Network Policy",
  "type": "stat",
  "description": "Number of pods in production namespaces with no matching network policy. Should be 0.",
  "targets": [{
    "expr": "count(kube_pod_info{namespace=~'production|staging'}) - count(kube_pod_info{namespace=~'production|staging'} * on(namespace) group_left kube_networkpolicy_spec_pod_selector)",
    "legendFormat": "Unprotected pods"
  }],
  "thresholds": {
    "steps": [
      {"value": 0, "color": "green"},
      {"value": 1, "color": "red"}
    ]
  },
  "links": [{
    "title": "Fix: Apply network policies",
    "url": "/articles/kubernetes/network-policies/"
  }]
}
```

### Panel 2: Pod Security Standard Compliance

```json
{
  "title": "Namespaces Without PSS Enforcement",
  "type": "stat",
  "targets": [{
    "expr": "count(kube_namespace_labels{label_pod_security_kubernetes_io_enforce=''} or kube_namespace_labels unless kube_namespace_labels{label_pod_security_kubernetes_io_enforce!=''})",
    "legendFormat": "Non-enforcing namespaces"
  }],
  "thresholds": {
    "steps": [
      {"value": 0, "color": "green"},
      {"value": 1, "color": "yellow"},
      {"value": 3, "color": "red"}
    ]
  }
}
```

### Panel 3: Certificate Health

```json
{
  "title": "Certificates Expiring Within 30 Days",
  "type": "stat",
  "targets": [{
    "expr": "count(certmanager_certificate_expiration_timestamp_seconds - time() < 30 * 24 * 3600)",
    "legendFormat": "Expiring soon"
  }],
  "thresholds": {
    "steps": [
      {"value": 0, "color": "green"},
      {"value": 1, "color": "yellow"},
      {"value": 3, "color": "red"}
    ]
  },
  "links": [{
    "title": "Fix: Certificate monitoring",
    "url": "/articles/observability/certificate-expiry/"
  }]
}
```

### Panel 4: RBAC Health

```json
{
  "title": "ClusterRoleBindings with cluster-admin",
  "type": "stat",
  "description": "Number of ClusterRoleBindings granting cluster-admin. Should be minimal (kube-system only).",
  "targets": [{
    "expr": "count(kube_clusterrolebinding_info{clusterrole='cluster-admin'})",
    "legendFormat": "cluster-admin bindings"
  }],
  "thresholds": {
    "steps": [
      {"value": 0, "color": "green"},
      {"value": 3, "color": "yellow"},
      {"value": 5, "color": "red"}
    ]
  }
}
```

### Panel 5: Vulnerability Status

```json
{
  "title": "Images with Critical CVEs in Production",
  "type": "stat",
  "targets": [{
    "expr": "count(trivy_vulnerability_id{severity='CRITICAL', namespace=~'production|staging'})",
    "legendFormat": "Critical CVEs"
  }],
  "thresholds": {
    "steps": [
      {"value": 0, "color": "green"},
      {"value": 1, "color": "red"}
    ]
  }
}
```

### Panel 6: Falco Alert Rate

```json
{
  "title": "Falco Alerts (24h)",
  "type": "timeseries",
  "description": "Alert rate by priority. Spikes indicate potential security events.",
  "targets": [
    {"expr": "sum by (priority) (rate(falco_events_total[1h]))", "legendFormat": "{{ priority }}"}
  ],
  "fieldConfig": {
    "overrides": [
      {"matcher": {"id": "byName", "options": "Critical"}, "properties": [{"id": "color", "value": "red"}]},
      {"matcher": {"id": "byName", "options": "Warning"}, "properties": [{"id": "color", "value": "orange"}]}
    ]
  }
}
```

### Panel 7: Seccomp Coverage

```json
{
  "title": "Pods Without Seccomp Profile",
  "type": "stat",
  "targets": [{
    "expr": "count(kube_pod_container_info{namespace=~'production|staging'}) - count(kube_pod_container_info{namespace=~'production|staging'} * on(pod, namespace) group_left kube_pod_annotations{annotation_seccomp_security_alpha_kubernetes_io_pod!=''})",
    "legendFormat": "No seccomp"
  }],
  "thresholds": {
    "steps": [
      {"value": 0, "color": "green"},
      {"value": 1, "color": "yellow"},
      {"value": 5, "color": "red"}
    ]
  }
}
```

### Complete Dashboard JSON

The full Grafana dashboard JSON (all 7 panels + variables for namespace/cluster filtering) is available in the premium content pack. To import:

```bash
# Import via Grafana API:
curl -X POST -H "Authorization: Bearer $GRAFANA_TOKEN" \
  -H "Content-Type: application/json" \
  -d @security-dashboard.json \
  "$GRAFANA_URL/api/dashboards/db"
```

### Dashboard Refresh and Variables

```json
{
  "refresh": "30s",
  "templating": {
    "list": [
      {
        "name": "namespace",
        "type": "query",
        "query": "label_values(kube_namespace_labels, namespace)",
        "multi": true,
        "includeAll": true
      },
      {
        "name": "cluster",
        "type": "query",
        "query": "label_values(kube_node_info, cluster)",
        "multi": false
      }
    ]
  }
}
```

## Expected Behaviour

- Dashboard loads in under 3 seconds
- All panels show current state with red/amber/green thresholds
- Zero unprotected pods (network policy panel green)
- Zero namespaces without PSS enforcement
- Zero certificates expiring within 7 days
- Minimal cluster-admin bindings (kube-system only)
- Zero critical CVEs in production images
- Falco alert rate stable and within tuned baseline

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| 30-second auto-refresh | Always current; uses Grafana resources | Unnecessary load for dashboards not actively viewed | Use auto-refresh only on actively-displayed dashboards. Disable for dashboards viewed occasionally. |
| Red/amber/green thresholds | Clear actionability | Threshold values need tuning per environment | Start with conservative thresholds. Adjust based on what's achievable for your environment. |
| Action links on panels | Engineers can fix issues directly from the dashboard | Links to articles may become stale | Verify links in quarterly dashboard review. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| [Prometheus](https://prometheus.io) scrape missing | Panel shows "No data" | Panel-level "no data" state visible; data source health check | Fix ServiceMonitor for the missing metric source. |
| Threshold too sensitive | Panel always red; team ignores it | Panel has been red for 30+ days with no action taken | Adjust threshold to reflect achievable state. A dashboard that is always red is useless. |
| Metric renamed after upgrade | Panel query returns zero results | Panel shows zero or "no data" after Prometheus/[Kubernetes](https://kubernetes.io) upgrade | Update PromQL query to use the new metric name. |

## When to Consider a Managed Alternative

Self-managed Grafana requires persistent storage, user management, OIDC integration, and backup. [Grafana Cloud](https://grafana.com/cloud) provides managed Grafana with team access, cross-cluster dashboards, and built-in alerting. The free tier (3 users, 10K metrics) covers small teams.

**Primary premium content pack:** Importable Grafana JSON dashboard for all hardening categories, network policies, PSS, certificates, RBAC, vulnerabilities, Falco, seccomp. Variables for namespace and cluster filtering. Pre-configured thresholds with action links to systemshardening.com articles.


## Related Articles

- [Security-Relevant Prometheus Metrics: What to Collect, How to Alert, When to Page](/articles/observability/prometheus-security-metrics/)
- [Building a Security Audit Log Pipeline That Scales: auditd to Elasticsearch](/articles/observability/audit-log-pipeline/)
- [Kubernetes Audit Log Pipeline Design: From API Server to SIEM](/articles/observability/k8s-audit-log-design/)
- [OpenTelemetry for Security: Distributed Tracing of Authentication and Authorization Flows](/articles/observability/otel-security-tracing/)
- [Lateral Movement Detection: Network Patterns, Authentication Anomalies, and Alert Correlation](/articles/observability/lateral-movement-detection/)
