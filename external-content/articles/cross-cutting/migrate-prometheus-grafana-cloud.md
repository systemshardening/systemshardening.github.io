---
title: "Migrating from Self-Hosted Prometheus to Grafana Cloud: Preserving Dashboards, Alerts, and History"
description: "Self-hosted Prometheus consumes 500GB+ storage within 6 months for a 20-node Kubernetes cluster."
slug: "migrate-prometheus-grafana-cloud"
date: 2026-02-21
lastmod: 2026-02-21
category: "cross-cutting"
tags: ["prometheus", "grafana-cloud", "migration", "observability", "remote-write"]
personas: ["sre", "platform-engineer"]
article_number: 90
difficulty: "intermediate"
estimated_reading_time: 16
provider_bridges:
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
  - name: "Axiom"
    id: 112
    category: "observability"
  - name: "Chronosphere"
    id: 116
    category: "observability"
premium_pack: "observability-migration-toolkit"
published: true
layout: article.njk
permalink: "/articles/cross-cutting/migrate-prometheus-grafana-cloud/index.html"
---

# Migrating from Self-Hosted [Prometheus](https://prometheus.io) to [Grafana](https://grafana.com) Cloud: Preserving Dashboards, Alerts, and History

## Problem

Self-hosted Prometheus consumes 500GB+ storage within 6 months for a 20-node [Kubernetes](https://kubernetes.io) cluster. HA requires Thanos or Cortex, significant operational complexity. Cross-cluster aggregation needs federation or remote write. Grafana needs persistent storage, user management, and backup. The total operational cost of self-managed observability typically exceeds the cost of a managed backend.

But migration must preserve dashboards, alert rules, and recording rules without a detection gap. Moving from one observability backend to another is like replacing the engines on a plane in flight.

## Threat Model

- **Adversary:** Not direct, the threat is losing security monitoring during the migration window. If your security alert rules stop functioning during migration, attackers have a detection gap to exploit.

## Configuration

### Phase 1: Remote Write (Parallel Running)

Configure Prometheus to send metrics to both local storage and Grafana Cloud simultaneously:

```yaml
# prometheus.yml - add remote_write section
remote_write:
  - url: "https://prometheus-prod-01-eu-west-0.grafana.net/api/prom/push"
    basic_auth:
      username: "${GRAFANA_CLOUD_PROMETHEUS_USER}"
      password: "${GRAFANA_CLOUD_API_KEY}"
    queue_config:
      max_samples_per_send: 5000
      max_shards: 10
      capacity: 10000
    write_relabel_configs:
      # Optional: filter which metrics are sent to reduce costs
      - source_labels: [__name__]
        regex: "go_.*"
        action: drop
```

```bash
# Apply the config
kubectl rollout restart statefulset prometheus-server -n monitoring

# Verify remote write is working:
# Check Prometheus targets page: http://prometheus:9090/targets
# Check Grafana Cloud: Explore → select Prometheus data source → run a query

# Monitor remote write health:
# prometheus_remote_storage_succeeded_samples_total should increase
# prometheus_remote_storage_failed_samples_total should stay at 0
```

### Phase 2: Dashboard Migration

```bash
# Export all Grafana dashboards as JSON
# Using the Grafana API:
GRAFANA_URL="http://grafana.monitoring.svc:3000"
GRAFANA_TOKEN="your-api-token"

# List all dashboards
curl -s -H "Authorization: Bearer $GRAFANA_TOKEN" \
  "$GRAFANA_URL/api/search?type=dash-db" | jq -r '.[].uid' > dashboard-uids.txt

# Export each dashboard
mkdir -p dashboards-export
while read uid; do
  curl -s -H "Authorization: Bearer $GRAFANA_TOKEN" \
    "$GRAFANA_URL/api/dashboards/uid/$uid" | jq '.dashboard' > "dashboards-export/$uid.json"
  echo "Exported: $uid"
done < dashboard-uids.txt

# Import to Grafana Cloud
CLOUD_URL="https://your-org.grafana.net"
CLOUD_TOKEN="your-cloud-api-token"

for f in dashboards-export/*.json; do
  # Wrap in the import format
  jq '{dashboard: ., overwrite: true}' "$f" | \
    curl -s -X POST -H "Authorization: Bearer $CLOUD_TOKEN" \
    -H "Content-Type: application/json" \
    -d @- "$CLOUD_URL/api/dashboards/db"
  echo "Imported: $f"
done
```

**Data source references:** After import, dashboards reference the old data source. Update to the Grafana Cloud Prometheus data source:

```bash
# In each imported dashboard JSON, replace the datasource reference:
# Old: {"type": "prometheus", "uid": "local-prometheus"}
# New: {"type": "prometheus", "uid": "grafanacloud-prom"}

for f in dashboards-export/*.json; do
  sed -i 's/"uid": "local-prometheus"/"uid": "grafanacloud-prom"/g' "$f"
done
# Re-import the updated dashboards
```

### Phase 3: Alert Rule Migration

```bash
# Export PrometheusRule resources
kubectl get prometheusrules --all-namespaces -o yaml > prometheus-rules-export.yaml

# Convert to Grafana Cloud alerting format.
# Grafana Cloud uses Grafana Alerting (not Alertmanager directly).
# The PromQL expressions are compatible - only the wrapping format changes.
```

For each PrometheusRule, create a corresponding Grafana Cloud alert rule:

```yaml
# Grafana Cloud alert rule (created via API or UI)
# Each PrometheusRule group becomes a Grafana alerting rule group.
{
  "name": "security-auth-alerts",
  "interval": "30s",
  "rules": [
    {
      "grafana_alert": {
        "title": "BruteForceDetected",
        "condition": "A",
        "data": [
          {
            "refId": "A",
            "queryType": "",
            "relativeTimeRange": {"from": 300, "to": 0},
            "datasourceUid": "grafanacloud-prom",
            "model": {
              "expr": "sum by (source_ip, service) (rate(auth_failures_total{result=\"failure\"}[5m])) > 0.5",
              "intervalMs": 30000,
              "maxDataPoints": 43200
            }
          }
        ],
        "for": "2m",
        "labels": {"severity": "warning"},
        "annotations": {
          "summary": "Possible brute force detected"
        }
      }
    }
  ]
}
```

### Phase 4: Verification

```bash
# Run for 24-48 hours with both systems active.
# Compare key metrics between self-hosted and Grafana Cloud:

# On self-hosted Prometheus:
curl -s "http://prometheus:9090/api/v1/query?query=up" | jq '.data.result | length'

# On Grafana Cloud (using the Grafana Cloud Prometheus API):
curl -s -u "$USER:$API_KEY" \
  "https://prometheus-prod-01-eu-west-0.grafana.net/api/prom/api/v1/query?query=up" | \
  jq '.data.result | length'

# Both should return the same count.
# Check security-specific metrics:
# - auth_failures_total
# - apiserver_authorization_decisions_total
# - certmanager_certificate_expiration_timestamp_seconds
# - cilium_drop_count_total
```

### Phase 5: Cut Over and Decommission

```bash
# After 24-48 hours of verified parallel running:

# 1. Update all alert notification channels to point to Grafana Cloud OnCall (#178)
# 2. Disable alerts on the self-hosted Prometheus (set all rules to inactive)
# 3. Remove the self-hosted Grafana from DNS/bookmarks
# 4. Keep self-hosted Prometheus running for 7 more days (historical queries)
# 5. After 7 days: decommission self-hosted Prometheus and Grafana

# The remote_write configuration stays - Prometheus continues to scrape
# and ship metrics to Grafana Cloud. The local storage can be reduced
# to minimal retention (2h for write-ahead log only).
```

### Cost Estimation

```bash
# Calculate your Grafana Cloud cost based on current Prometheus usage:

# Count active time series:
curl -s "http://prometheus:9090/api/v1/label/__name__/values" | jq '.data | length'
# This is the number of metric names. Multiply by average labels per metric
# to get active series count.

# Or use the TSDB stats:
curl -s "http://prometheus:9090/api/v1/status/tsdb" | jq '.data.seriesCountByMetricName[:10]'

# Grafana Cloud pricing (as of 2026):
# Free: 10,000 active series, 50GB logs, 50GB traces
# Pro: $8/1000 active series/month + $0.50/GB logs
#
# Example: 50,000 active series = ~$400/month on Grafana Cloud
# vs. engineering time to manage self-hosted: $800-3,200/month
```

## Expected Behaviour

- All metrics flowing to Grafana Cloud via remote write within 1 hour of configuration
- All dashboards imported and rendering identically to self-hosted Grafana
- All alert rules firing with the same thresholds and conditions
- No detection gap during the parallel running period
- Self-hosted Prometheus can be decommissioned after 7-day parallel running

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| Parallel running (both active) | Double metric storage cost during migration (7-14 days) | Double the cost is temporary | Migration period is short. The cost is negligible compared to the long-term savings. |
| Accept historical data loss | No migration of Thanos/Prometheus historical data | Lose trend data; security baselines need re-establishment | Accept 30-day baseline gap. Historical data is still accessible on self-hosted during the transition period. |
| Remote write to Grafana Cloud | Prometheus becomes a collection agent, not a storage backend | Dependency on Grafana Cloud availability | Prometheus local storage provides a buffer. If Grafana Cloud is unreachable, metrics buffer locally and ship when connection restores. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Remote write fails | Metrics not arriving in Grafana Cloud | `prometheus_remote_storage_failed_samples_total` increases; Grafana Cloud shows no data | Check credentials, endpoint URL, network egress from Prometheus namespace. Prometheus buffers locally. metrics ship when connection restores. |
| Dashboard variable mismatch | Imported dashboards show "No data" | Visual comparison during parallel running reveals blank panels | Update data source UIDs and variable queries to match Grafana Cloud Prometheus data source. |
| Alert rule PromQL incompatible | Alerts don't fire in Grafana Cloud | Test each alert rule; Grafana Alerting shows rule error | Minor PromQL syntax differences between Prometheus and Grafana Cloud. Adjust as needed. most queries work unchanged. |
| Cost exceeds estimate | Grafana Cloud bill higher than expected | Invoice exceeds budget | Use `write_relabel_configs` to drop high-cardinality, low-value metrics before shipping. Review `seriesCountByMetricName` for optimization targets. |

## When to Consider a Managed Alternative

**This article IS the managed alternative.** Direct affiliate path to [Grafana Cloud](https://grafana.com/cloud).

**Alternatives:**
- **[Axiom](https://axiom.co):** 500GB/month free, unlimited retention, serverless query. Better for teams that want to ingest everything (metrics + logs + traces) without worrying about cardinality or retention costs.
- **[Chronosphere](https://chronosphere.io):** Built for high-cardinality environments with cost control. For teams where cardinality is the primary scaling challenge.
- **[VictoriaMetrics](https://victoriametrics.com):** Self-hosted but lower resource usage than Prometheus. Extends the self-hosted stage before needing managed.
- **[SigNoz](https://signoz.io):** [OpenTelemetry](https://opentelemetry.io)-native unified observability. For teams migrating to OTel.

**Sponsored guide opportunity:** Grafana Labs sponsors a deep-dive on Grafana Cloud migration specific to security monitoring use cases.

**Premium content pack:** Observability migration toolkit. export scripts, dashboard conversion tools, alert rule migration templates, cost estimation calculator, and verification scripts for Grafana Cloud, Axiom, and Chronosphere.


## Related Articles

- [Security Infrastructure Disaster Recovery: Vault, PKI, and SIEM Failover](/articles/cross-cutting/security-infra-disaster-recovery/)
- [Multi-Cloud Hardening: Consistent Security Posture Across Providers](/articles/cross-cutting/multi-cloud-hardening/)
- [Migrating from Self-Managed Kubernetes to a Managed Provider Without Losing Your Security Posture](/articles/cross-cutting/migrate-to-managed-k8s/)
- [Hardening a Complete Kubernetes Platform: From Cluster Bootstrap to Production-Ready](/articles/cross-cutting/complete-kubernetes-hardening/)
- [Security Hardening for Small Teams: Prioritising Controls When You Cannot Do Everything](/articles/cross-cutting/hardening-small-teams/)
