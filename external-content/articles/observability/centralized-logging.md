---
title: "Centralized Logging Architecture for Security: Fluentd, Vector, and Loki Compared"
description: "Self-managed log infrastructure is one of the highest operational costs for small-to-medium teams."
slug: "centralized-logging"
date: 2026-01-16
lastmod: 2026-01-16
category: "observability"
tags: ["logging", "fluentd", "vector", "loki", "elasticsearch", "architecture"]
personas: ["sre", "security-engineer"]
article_number: 72
difficulty: "intermediate"
estimated_reading_time: 20
provider_bridges:
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
  - name: "Axiom"
    id: 112
    category: "observability"
  - name: "Better Stack"
    id: 113
    category: "observability"
premium_pack: "logging-pipeline-configs"
published: true
layout: article.njk
permalink: "/articles/observability/centralized-logging/index.html"
---

# Centralized Logging Architecture for Security: [Fluentd](https://www.fluentd.org), [Vector](https://vector.dev), and [Loki](https://grafana.com/oss/loki/) Compared

## Problem

Self-managed log infrastructure is one of the highest operational costs for small-to-medium teams. The choice of collector (Fluentd vs Vector vs Promtail) and backend (Loki vs [Elasticsearch](https://www.elastic.co/elasticsearch) vs OpenObserve) determines your query capability, operational burden, and cost for years. Choosing wrong is expensive to reverse, log pipelines are deeply integrated into every service.

For security use cases specifically, the requirements are: full-text search across log content (not just labels), sub-10-second query latency for 30-day windows, structured log support (JSON, key-value), retention management (30 days hot, 12 months archival), and integration with alerting (fire alerts from log queries).

## Threat Model

- **Adversary:** Any attacker. Centralized logs are the foundation of all security investigation and detection. Without them, you are blind.

## Configuration

### Collector Comparison

| Feature | Vector | Fluentd | Promtail |
|---------|--------|---------|----------|
| Language | Rust | Ruby + C | Go |
| Memory usage (idle) | 15-30MB | 50-100MB | 20-40MB |
| Throughput | 10-50K events/sec/core | 5-20K events/sec/core | 5-15K events/sec/core |
| Configuration | YAML/TOML | Ruby DSL | YAML |
| Transform capability | VRL (powerful) | Filters (plugin-based) | Pipeline stages (limited) |
| Buffer/retry | Built-in disk buffer | Plugin-based (buffered output) | WAL-based |
| [Kubernetes](https://kubernetes.io) support | Native | Via fluent-bit/fluentd | Native (Loki only) |
| Best for | New deployments, performance | Existing ecosystems, plugin breadth | Loki-only deployments |

**Recommendation:** Vector for new deployments (fastest, lowest memory, most flexible transforms). Fluentd only if you have an existing Fluentd ecosystem with custom plugins. Promtail only if you are committed to Loki as the only backend.

### Backend Comparison

| Feature | Loki | Elasticsearch | [OpenObserve](https://openobserve.ai) | [Quickwit](https://quickwit.io) |
|---------|------|---------------|-------------------|-----------------|
| Query language | LogQL (label-based) | KQL / Lucene (full-text) | SQL + full-text | Tantivy (full-text) |
| Full-text search | Limited (filter expressions) | Yes (inverted index) | Yes | Yes |
| Storage cost (per GB/month) | $0.01-0.03 (S3) | $0.10-0.50 (local SSD) | $0.01-0.03 (S3) | $0.01-0.03 (S3) |
| Operational complexity | Low (stateless queriers) | High (cluster management) | Medium | Low |
| Retention management | Built-in compactor | ILM policies (complex) | Built-in | Built-in |
| Security query suitability | Good for label-based (namespace, pod, severity) | Best (full-text across all fields) | Good | Good |

**Recommendation for security:**
- If you need full-text search across log content: Elasticsearch or OpenObserve
- If label-based queries (namespace, pod, app, severity) are sufficient: Loki (5-10x cheaper)
- For most teams: start with Loki (cost-effective), supplement with Elasticsearch only for security investigation queries

### Loki Deployment with Vector

```yaml
# vector-daemonset.yaml - collect logs from all pods
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: vector
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: vector
  template:
    metadata:
      labels:
        app: vector
    spec:
      serviceAccountName: vector
      containers:
        - name: vector
          image: timberio/vector:0.40.0-debian
          volumeMounts:
            - name: config
              mountPath: /etc/vector
            - name: varlog
              mountPath: /var/log
              readOnly: true
            - name: varlogpods
              mountPath: /var/log/pods
              readOnly: true
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 256Mi
      volumes:
        - name: config
          configMap:
            name: vector-config
        - name: varlog
          hostPath:
            path: /var/log
        - name: varlogpods
          hostPath:
            path: /var/log/pods
```

```yaml
# vector-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: vector-config
  namespace: monitoring
data:
  vector.yaml: |
    sources:
      kubernetes_logs:
        type: kubernetes_logs
        auto_partial_merge: true

    transforms:
      parse_json:
        type: remap
        inputs: [kubernetes_logs]
        source: |
          # Parse JSON log lines (most applications log structured JSON)
          parsed, err = parse_json(.message)
          if err == null {
            . = merge(., parsed)
          }
          # Add security-relevant labels
          .security_source = .kubernetes.pod_namespace + "/" + .kubernetes.pod_name

      filter_security:
        type: filter
        inputs: [parse_json]
        condition:
          type: vrl
          source: |
            # Keep all logs from security-relevant namespaces
            # and any log containing security-relevant keywords
            includes(["production", "kube-system", "falco", "monitoring"], .kubernetes.pod_namespace) ||
            match!(.message, r'(?i)(error|fail|denied|unauthorized|forbidden|CVE|exploit)')

    sinks:
      loki:
        type: loki
        inputs: [filter_security]
        endpoint: "http://loki.monitoring:3100"
        labels:
          namespace: "{{ kubernetes.pod_namespace }}"
          pod: "{{ kubernetes.pod_name }}"
          container: "{{ kubernetes.container_name }}"
          app: "{{ kubernetes.pod_labels.app }}"
          severity: "{{ level }}"
        encoding:
          codec: json
```

### Log Parsing and Enrichment

```yaml
# Vector transform for structured security log enrichment
transforms:
  enrich_security:
    type: remap
    inputs: [parse_json]
    source: |
      # Classify log severity for security
      if match!(.message, r'(?i)(critical|emergency|fatal)') {
        .security_severity = "critical"
      } else if match!(.message, r'(?i)(error|fail|denied|unauthorized)') {
        .security_severity = "high"
      } else if match!(.message, r'(?i)(warn|deprecat)') {
        .security_severity = "medium"
      } else {
        .security_severity = "low"
      }

      # Extract common security fields
      .source_ip = parse_regex!(.message, r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})').ip ?? null
      .user = parse_regex!(.message, r'user[= ]+(?P<user>\S+)').user ?? null
```

### Retention Policies

```yaml
# Loki retention configuration (loki-config.yaml)
limits_config:
  retention_period: 720h  # 30 days for queryable hot storage

compactor:
  working_directory: /data/loki/compactor
  retention_enabled: true
  retention_delete_delay: 2h
  delete_request_store: s3

# For 12-month archival: ship a copy to immutable S3 (see Article #65)
```

### Security Alerting from Logs

```yaml
# Loki alerting rules (via Grafana or Loki ruler)
groups:
  - name: security-log-alerts
    rules:
      - alert: AuthenticationFailureSpike
        expr: >
          sum(rate({namespace="production"} |= "authentication failed" [5m])) > 0.5
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Authentication failure spike in production"

      - alert: UnauthorizedAPIAccess
        expr: >
          sum(rate({namespace="production"} |~ "403|Forbidden|Unauthorized" [5m])) > 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Elevated 403/Unauthorized responses in production"

      - alert: SuspiciousCommandExecution
        expr: >
          count_over_time({source="auditd"} |= "exec" |~ "curl|wget|nc|ncat|python.*-c|perl.*-e" [5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "Suspicious command execution detected in audit logs"
```

## Expected Behaviour

- All cluster logs centralized within 30 seconds of generation
- Security queries return results within 5 seconds for 30-day window
- No log loss under sustained load (verified with canary log entries)
- Retention policies manage 30-day hot and 12-month archival automatically
- Security alerts fire from log queries within 2 minutes of the event
- Vector DaemonSet consumes <256MB memory per node

## Trade-offs

| Backend | Monthly Cost (20-node cluster) | Query Capability | Ops Effort |
|---------|-------------------------------|-----------------|------------|
| Loki (self-managed) | $50-100 (S3 storage) | Label-based; limited full-text | Low (stateless, S3-backed) |
| Elasticsearch (self-managed) | $200-500 (SSD storage + compute) | Full-text search, aggregations | High (cluster management, ILM) |
| [OpenObserve](https://openobserve.ai) (self-managed) | $50-100 (S3 storage) | Full-text + SQL | Medium (simpler than ES) |
| [Grafana Cloud](https://grafana.com/cloud) Loki | $0-200 (usage-based) | Same as self-managed Loki | Zero (fully managed) |
| [Axiom](https://axiom.co) | $0-100 (500GB free) | Full-text, serverless | Zero (fully managed) |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Vector DaemonSet not running on node | Logs from that node not collected | DaemonSet pod count < node count; log gap detection alert | Check tolerations. Fix resource limits. Ensure Vector pod can schedule on all nodes. |
| Loki ingestion rate exceeded | Logs rejected with 429; Vector retries | Loki metrics show `429 rate_limited`; Vector shows delivery retries | Scale Loki ingesters. Or: increase rate limits in `limits_config`. |
| Elasticsearch cluster red | Log ingestion stops; queries fail | ES cluster health API shows red; [Prometheus](https://prometheus.io) ES exporter alerts | Fix shard allocation. Add nodes. Or: migrate to managed backend. |
| Log parsing fails | Structured fields missing; queries return no results | Dashboard panels show "no data" for structured fields; raw `.message` still present | Fix VRL parsing in Vector transform. Test with `vector tap` for live debugging. |
| Retention not applied | Storage grows unbounded; disk fills | Disk usage alerts; Loki compactor metrics show no deletions | Check compactor configuration. Verify `retention_enabled: true`. Check compactor pod is running. |

## When to Consider a Managed Alternative

**This is the strongest observability conversion article.** Self-managed Elasticsearch is a full-time job past 20 hosts. Even Loki, while simpler, requires capacity planning, storage management, and version upgrades.

- **[Grafana Cloud](https://grafana.com/cloud):** Managed Loki. Start free (50GB logs/month). Native Grafana integration. The most natural migration from self-hosted Loki.
- **[Axiom](https://axiom.co):** 500GB/month free. Serverless query. Zero cluster management. Full-text search (unlike Loki). Best for teams that want to ingest everything without worrying about backend operations.
- **[Better Stack](https://betterstack.com):** Logging + uptime monitoring + incident management in one. Managed. For teams wanting a single vendor for log-related concerns.
- **[SigNoz](https://signoz.io):** [OpenTelemetry](https://opentelemetry.io)-native. Unified logs + metrics + traces. For teams migrating to OTel.

**Premium content pack:** Logging pipeline configurations. Vector DaemonSet manifests for Kubernetes, Vector configs for Loki/Elasticsearch/Axiom backends, log parsing transforms for common application frameworks, Loki alerting rules for security events, and retention policy templates.


## Related Articles

- [Building a Security Audit Log Pipeline That Scales: auditd to Elasticsearch](/articles/observability/audit-log-pipeline/)
- [Kubernetes Audit Log Pipeline Design: From API Server to SIEM](/articles/observability/k8s-audit-log-design/)
- [OpenTelemetry for Security: Distributed Tracing of Authentication and Authorization Flows](/articles/observability/otel-security-tracing/)
- [Incident Response Runbooks: Structured Procedures for Common Security Events](/articles/observability/incident-response-runbooks/)
- [Lateral Movement Detection: Network Patterns, Authentication Anomalies, and Alert Correlation](/articles/observability/lateral-movement-detection/)
