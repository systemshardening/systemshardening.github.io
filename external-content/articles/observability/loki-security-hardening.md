---
title: "Loki Security Hardening: Authentication, Tenant Isolation, and Log Tampering Prevention"
description: "Loki aggregates logs from all services. Without authentication, anyone who reaches the Loki endpoint reads all logs. Multi-tenancy requires strict tenant isolation, rate limiting per tenant, and append-only storage to prevent log tampering."
slug: "loki-security-hardening"
date: 2026-05-01
lastmod: 2026-05-01
category: "observability"
tags: ["loki", "logging", "authentication", "multi-tenancy", "log-security"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 291
difficulty: "intermediate"
estimated_reading_time: 12
published: true
layout: article.njk
permalink: "/articles/observability/loki-security-hardening/index.html"
---

# Loki Security Hardening: Authentication, Tenant Isolation, and Log Tampering Prevention

## Problem

Loki is a horizontally scalable log aggregation system. Its pull-based label model and integration with Grafana make it the default log backend for Kubernetes-native stacks. The same properties that make it operationally convenient create security risks:

- **No built-in authentication.** Loki's default configuration accepts all requests without authentication. Any process that can reach the Loki HTTP port (3100) can push logs under any tenant ID and query any tenant's logs. This is by design for single-tenant deployments but is actively dangerous when Loki is exposed within a multi-team cluster.
- **Tenant ID spoofing.** Loki's multi-tenancy model relies on the `X-Scope-OrgID` HTTP header to identify the tenant. Without authentication and authorisation, any Promtail agent or application can set this header to any value — including another tenant's ID — and read or write to that tenant's log stream.
- **Log injection via unvalidated labels.** Loki stores logs indexed by labels. Labels come from Promtail's configuration, which sources them from Kubernetes pod annotations, node labels, and log stream metadata. An attacker who can set a pod annotation can inject arbitrary labels into the log stream, potentially poisoning label-based alert queries.
- **No log integrity protection.** Loki is an append-only system by design, but its storage backend (S3, GCS, filesystem) may allow deletion or modification if the storage access controls are not configured correctly. A compromised Loki instance or storage credential can retroactively delete log evidence.
- **Ruler (alert) rule injection.** Loki's ruler component evaluates LogQL alert rules. A user with access to create ruler rules can query any tenant's logs (if multi-tenancy is bypassed) or execute expensive queries that exhaust Loki's query frontend resources.

**Target systems:** Loki 3.x (microservices and single-binary modes); Promtail 3.x; Grafana Alloy as Loki client; S3/GCS object storage backends; Kubernetes namespace-based multi-tenancy.

## Threat Model

- **Adversary 1 — Unauthenticated log read:** An attacker who reaches the Loki HTTP endpoint queries all logs using `{job=~".+"}`. Without authentication, they read all log streams — including logs containing credentials, PII, and security events.
- **Adversary 2 — Cross-tenant log access (tenant ID spoofing):** A developer's application sets `X-Scope-OrgID: payments` in its Loki push requests, accessing the payments team's log namespace. Without server-side tenant authorisation, this succeeds.
- **Adversary 3 — Log poisoning via label injection:** An attacker who can annotate a pod sets `loki.example.com/stream` to a value that matches a critical alert rule's label selector, injecting synthetic log events that trigger false security alerts — or suppress legitimate ones by flooding the alert query.
- **Adversary 4 — Log deletion from storage:** An attacker who obtains S3 credentials for the Loki storage bucket deletes log chunks, destroying forensic evidence of their previous activity.
- **Adversary 5 — Resource exhaustion via expensive queries:** A user with query access submits an unbounded LogQL query (`{job=~".+"} |= ""` over a 30-day range). The query exhausts Loki's querier memory, causing OOM and service disruption for all tenants.
- **Access level:** Adversaries 1 and 5 need network access to Loki. Adversary 2 needs the ability to push logs. Adversary 3 needs pod annotation access. Adversary 4 needs storage credentials.
- **Objective:** Extract sensitive log data, inject false log evidence, destroy audit trail, deny log service.
- **Blast radius:** Full log read access exposes all application logs across all teams — a significant data breach if logs contain PII, credentials, or security event data.

## Configuration

### Step 1: Authentication via Reverse Proxy

Loki does not implement authentication natively. Enforce it at the gateway layer:

```yaml
# nginx reverse proxy in front of Loki — OAuth2 Proxy for SSO.
# docker-compose or Kubernetes deployment.

# nginx.conf for Loki gateway.
upstream loki {
    server loki:3100;
}

server {
    listen 443 ssl;
    server_name loki.internal.example.com;

    ssl_certificate     /etc/ssl/loki.crt;
    ssl_certificate_key /etc/ssl/loki.key;

    # Require authentication via OAuth2 Proxy sidecar.
    location / {
        auth_request /oauth2/auth;
        error_page 401 = /oauth2/sign_in;

        auth_request_set $user $upstream_http_x_auth_request_user;
        auth_request_set $groups $upstream_http_x_auth_request_groups;

        proxy_set_header X-Auth-Request-User $user;
        proxy_set_header X-Auth-Request-Groups $groups;

        # Set tenant ID from authenticated user's group.
        # This prevents spoofing — the tenant is set by auth, not by the client.
        proxy_set_header X-Scope-OrgID $user;

        proxy_pass http://loki;
    }

    location /oauth2/ {
        proxy_pass http://oauth2-proxy:4180;
    }
}
```

For Kubernetes, use a dedicated auth gateway:

```yaml
# Grafana Enterprise or Grafana Cloud provides built-in auth for Loki.
# For self-hosted, use the Loki gateway with HTTP basic auth or mTLS.
apiVersion: v1
kind: ConfigMap
metadata:
  name: loki-gateway-config
  namespace: monitoring
data:
  nginx.conf: |
    http {
      upstream loki {
        server loki-read:3100;
      }

      upstream loki-write {
        server loki-write:3100;
      }

      server {
        listen 80;

        location = /loki/api/v1/push {
          # Write endpoint: authenticated Promtail agents only.
          # mTLS: require client certificate.
          proxy_pass http://loki-write;
          proxy_set_header X-Scope-OrgID $http_x_scope_orgid;
        }

        location /loki/api/ {
          # Read endpoint: authenticated users only.
          auth_basic "Loki";
          auth_basic_user_file /etc/nginx/htpasswd;
          proxy_pass http://loki;
        }
      }
    }
```

### Step 2: Multi-Tenant Configuration

```yaml
# loki-config.yaml — multi-tenancy configuration.
auth_enabled: true   # CRITICAL: enables X-Scope-OrgID header enforcement.
                     # Without this, all logs are stored under tenant "fake".

server:
  http_listen_port: 3100
  grpc_listen_port: 9095
  # Bind to localhost only — gateway handles external access.
  http_listen_address: 127.0.0.1
  grpc_listen_address: 127.0.0.1

# Tenant-level limits — prevent one tenant from consuming all resources.
limits_config:
  # Per-tenant ingestion limits.
  ingestion_rate_mb: 10           # 10 MB/s per tenant.
  ingestion_burst_size_mb: 20     # Burst up to 20 MB.
  max_streams_per_user: 10000     # Max active streams per tenant.
  max_line_size: 256kb            # Max log line size.

  # Per-tenant query limits.
  max_query_length: 12h           # Max time range for a query.
  max_query_parallelism: 8        # Max parallel sub-queries per tenant.
  max_entries_limit_per_query: 50000  # Max log entries returned per query.
  query_timeout: 300s             # Kill queries running over 5 minutes.
  max_cache_freshness_per_query: 10m

  # Retention per tenant (configurable per tenant via per-tenant overrides).
  retention_period: 720h          # 30 days default.

# Per-tenant overrides — security team gets longer retention.
# overrides.yaml (separate file, reloaded without restart).
overrides:
  security-team:
    retention_period: 8760h       # 1 year for security logs.
    max_query_length: 720h        # Allow longer historical queries.
  payments:
    ingestion_rate_mb: 50         # Higher limit for high-volume service.
```

### Step 3: Promtail Security

```yaml
# promtail-config.yaml — harden log collection agent.
server:
  http_listen_port: 9080
  # Bind to localhost; don't expose Promtail HTTP on host interface.
  http_listen_address: 127.0.0.1

clients:
  - url: https://loki-gateway.monitoring:443/loki/api/v1/push
    tenant_id: "${TENANT_ID}"   # Set from environment; not from log metadata.
    # mTLS: authenticate Promtail to the Loki gateway.
    tls_config:
      cert_file: /etc/promtail/client.crt
      key_file: /etc/promtail/client.key
      ca_file: /etc/promtail/ca.crt
    # Backoff and retry.
    backoff_config:
      max_retries: 10
      min_period: 500ms
      max_period: 5m

scrape_configs:
  - job_name: kubernetes-pods
    kubernetes_sd_configs:
      - role: pod
    pipeline_stages:
      # Scrub PII before shipping.
      - replace:
          expression: '(\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b)'
          replace: '[CARD-REDACTED]'
      - replace:
          expression: '(\b\d{3}-\d{2}-\d{4}\b)'
          replace: '[SSN-REDACTED]'
      # Drop logs from known-noisy, low-value sources.
      - drop:
          source: "job"
          value: "kube-system/coredns"
          drop_counter_reason: "coredns-filtered"

    # Label allowlist — only allow specific pod labels as Loki labels.
    # Prevents label injection via arbitrary pod annotations.
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app]
        target_label: app
      - source_labels: [__meta_kubernetes_namespace]
        target_label: namespace
      - source_labels: [__meta_kubernetes_pod_container_name]
        target_label: container
      # DO NOT include: __meta_kubernetes_pod_annotation_* without explicit allowlist.
      # Pod annotations are attacker-controlled if they can annotate pods.
```

### Step 4: Storage Backend Security

```bash
# S3 backend: prevent log deletion.
# S3 Object Lock — COMPLIANCE mode prevents deletion even by root.
aws s3api create-bucket \
  --bucket loki-logs-prod \
  --region us-east-1 \
  --object-lock-enabled-for-bucket

aws s3api put-object-lock-configuration \
  --bucket loki-logs-prod \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "COMPLIANCE",
        "Days": 30
      }
    }
  }'

# IAM policy for Loki: write and read, but no delete.
aws iam put-role-policy \
  --role-name loki-service-role \
  --policy-name loki-s3-access \
  --policy-document '{
    "Statement": [{
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::loki-logs-prod",
        "arn:aws:s3:::loki-logs-prod/*"
      ]
    }]
  }'
# Absent: s3:DeleteObject — Loki cannot delete its own logs.
```

```yaml
# loki-config.yaml — S3 storage configuration.
storage_config:
  aws:
    s3: "s3://loki-logs-prod"
    region: us-east-1
    sse_encryption: true         # SSE-KMS.
    s3forcepathstyle: true
    http_config:
      idle_conn_timeout: 90s
      response_header_timeout: 0

  # Chunk store.
  boltdb_shipper:
    active_index_directory: /var/loki/index
    cache_location: /var/loki/cache
    shared_store: s3
```

### Step 5: Ruler Security (Alert Rules)

```yaml
# Restrict who can create ruler rules.
# Ruler rules can query all logs in the tenant — treat as privileged access.

# loki-config.yaml
ruler:
  storage:
    type: s3
    s3:
      bucketnames: loki-ruler-prod
  rule_path: /tmp/loki/rules
  enable_api: true
  enable_alertmanager_v2: true

# Ruler API access: only allow platform team to create/modify rules.
# Enforce via the reverse proxy:
# location /loki/api/v1/rules {
#   # Only allow platform team (from auth header group).
#   if ($http_x_auth_request_groups !~ "platform-team") {
#     return 403;
#   }
#   proxy_pass http://loki;
# }
```

### Step 6: Log Integrity Verification

```bash
#!/bin/bash
# verify-log-integrity.sh — detect gaps or deletions in log streams.

TENANT="security-team"
START=$(date -u --date="24 hours ago" +%s%N)
END=$(date -u +%s%N)

# Query Loki for log count in the past 24 hours.
LOG_COUNT=$(curl -s \
  -H "X-Scope-OrgID: $TENANT" \
  -G "https://loki.internal/loki/api/v1/query" \
  --data-urlencode "query=count_over_time({job=\"security-events\"}[24h])" \
  --data-urlencode "time=$END" | \
  jq -r '.data.result[0].value[1] // "0"')

echo "Security event log count (24h): $LOG_COUNT"

# Compare with expected baseline.
EXPECTED_MINIMUM=1000
if [ "$LOG_COUNT" -lt "$EXPECTED_MINIMUM" ]; then
  logger -p security.alert -t loki-integrity \
    "ALERT: Security log count $LOG_COUNT below minimum $EXPECTED_MINIMUM"
fi
```

### Step 7: Kubernetes Deployment Security

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: loki
  namespace: monitoring
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: loki
          image: grafana/loki:3.0.0@sha256:abc123
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            limits:
              cpu: "4"
              memory: "8Gi"
            requests:
              cpu: "500m"
              memory: "1Gi"
          volumeMounts:
            - name: config
              mountPath: /etc/loki
              readOnly: true
            - name: data
              mountPath: /var/loki
```

### Step 8: Telemetry

```
loki_ingester_streams_created_total{tenant}                    counter
loki_request_duration_seconds{route, tenant, status_code}      histogram
loki_ingestion_rate_bytes{tenant}                              gauge
loki_query_length_hours{tenant}                                histogram
loki_tenant_storage_bytes{tenant}                              gauge
loki_ruler_rules_total{tenant}                                 gauge
loki_rejected_samples_total{tenant, reason}                    counter
```

Alert on:

- `loki_rejected_samples_total{reason="rate_limit_exceeded"}` — a tenant is hitting ingestion rate limits; may indicate a logging misconfiguration or a denial-of-service attempt.
- Unexpected `loki_tenant_storage_bytes` decrease — log chunks may have been deleted; investigate S3 access logs.
- `loki_query_length_hours` P99 > query_timeout — queries timing out; either increase timeout or investigate expensive query patterns.
- Security log count drops below baseline (via integrity check script) — logs may have been deleted or the shipping pipeline is broken.
- Any `DELETE` API calls to S3 loki bucket (via CloudTrail) — should never happen given IAM policy.

## Expected Behaviour

| Signal | Default Loki (no auth) | Hardened Loki |
|--------|----------------------|---------------|
| Anonymous log query | All logs readable | 401; authentication required |
| Tenant ID spoofing | Any client sets any tenant | Gateway enforces tenant from authenticated identity |
| Log deletion from S3 | Possible with default IAM | Object Lock prevents deletion; IAM blocks DeleteObject |
| Expensive query exhausts querier | No per-tenant limits | max_query_length and query_timeout kill runaway queries |
| Pod annotation label injection | Arbitrary labels added to log stream | Label allowlist in Promtail relabel config |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| auth_enabled = true | Tenant isolation enforced server-side | All clients must send X-Scope-OrgID | Set consistently in Promtail config; enforce in gateway |
| S3 Object Lock (COMPLIANCE) | Logs cannot be deleted | Cannot delete even erroneous data until retention expires | Test retention policy; use shorter window if needed |
| Per-tenant query limits | Prevents resource exhaustion | Legitimate historical queries may time out | Increase limit for specific tenants via overrides |
| mTLS for Promtail-to-Loki | Authenticates log shipper | Certificate management for each Promtail instance | cert-manager automates per-node certificates |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| auth_enabled misconfiguration | All logs stored under "fake" tenant | Unexpected `{orgID="fake"}` label in queries | Enable auth_enabled; all historical data under "fake" is not migrated |
| Rate limit too low | Legitimate high-volume service loses logs | `loki_rejected_samples_total` alert | Increase rate limit for specific tenant via overrides.yaml |
| Promtail certificate expiry | Logs stop shipping; cert error | `loki_ingestion_rate_bytes` drops to 0 for tenant | cert-manager auto-renewal; alert at 14 days remaining |
| Query frontend OOM from expensive query | Query service crashes; all queries fail | Query latency spike then 503 | Reduce max_query_parallelism; add memory limit to query frontend |
| S3 backend outage | Log ingestion buffer fills; eventual write failure | Loki error logs; ingestion rate alert | Loki buffers in WAL; writes complete once S3 recovers |

## Related Articles

- [Grafana Security Hardening](/articles/observability/grafana-security-hardening/)
- [Audit Log Pipeline](/articles/observability/audit-log-pipeline/)
- [Log Integrity](/articles/observability/log-integrity/)
- [OpenTelemetry PII Leakage Prevention](/articles/observability/otel-pii-leakage/)
- [OpenTelemetry Collector Hardening](/articles/observability/otel-collector-hardening/)
