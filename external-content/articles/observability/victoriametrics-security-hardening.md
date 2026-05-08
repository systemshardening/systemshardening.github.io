---
title: "VictoriaMetrics Security Hardening: Authentication, TLS, Tenant Isolation, and Data Protection"
description: "VictoriaMetrics is a high-performance Prometheus-compatible TSDB with no built-in authentication. Without vmauth, anyone who reaches any component endpoint reads or writes all metrics. This guide hardens every layer: vmauth proxy authentication, per-component TLS, vmgateway JWT tenant isolation, vmagent credential management, deleteRange API access control, and backup encryption."
slug: victoriametrics-security-hardening
date: 2026-05-07
lastmod: 2026-05-07
category: observability
tags:
  - victoriametrics
  - prometheus
  - metrics-security
  - authentication
  - multi-tenancy
personas:
  - security-engineer
  - platform-engineer
article_number: 552
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/observability/victoriametrics-security-hardening/
---

# VictoriaMetrics Security Hardening: Authentication, TLS, Tenant Isolation, and Data Protection

## Problem

VictoriaMetrics is a drop-in Prometheus-compatible time-series database designed for high ingestion throughput and low memory consumption. Its cluster mode separates write (vminsert), read (vmselect), and storage (vmstorage) concerns across independently scalable components. Its single-node binary is a common replacement for Prometheus in resource-constrained environments. Both modes share a structural security problem: there is no built-in authentication.

The default VictoriaMetrics deployment accepts all read and write requests without any authentication challenge. An unauthenticated attacker who reaches the vmselect HTTP port (8481) can execute arbitrary MetricsQL queries against all stored data. An attacker who reaches vminsert (8480) can inject arbitrary metrics — poisoning dashboards, triggering false alerts, and introducing cardinality explosions that exhaust storage. vmstorage (8482) exposes its native binary protocol without TLS, so intra-cluster traffic between vminsert/vmselect and vmstorage carries metric data in plaintext.

Additional risks compound the authentication gap:

- **No tenant enforcement at the query layer.** VictoriaMetrics cluster mode uses URL-based tenancy (`/insert/0/` and `/select/0/`) where `0` is the tenant ID. Any client can change the path segment to query a different tenant's metrics. Without a proxy that enforces tenant routing from authenticated identity, URL-based tenancy is a naming convention, not a security boundary.
- **deleteRange API has no access control.** The HTTP API at `/api/v1/admin/tsdb/delete_series` permanently deletes metric series matching a selector. In a default deployment, any client that can reach vmselect's HTTP port can delete metric data — including security-relevant telemetry — without authentication.
- **vmagent scrape credentials may be stored in plaintext.** vmagent, VictoriaMetrics's scrape agent, stores scrape target credentials in its configuration file. If that file is not protected appropriately, or if the vmagent HTTP API is exposed, credentials for scrape targets leak.
- **Metric labels can contain PII.** Labels are freeform. Any label with high cardinality and sensitive values — user IDs, email addresses, session tokens embedded in URL path labels — constitutes both a privacy risk and a cardinality bomb that degrades performance.
- **Backups to object storage default to unencrypted.** vmbackup transfers metric data snapshots to S3 or GCS. Without explicit encryption configuration, backup objects are stored in plaintext.

**Target systems:** VictoriaMetrics v1.100+ single-node and cluster mode; vmagent v1.100+; vmauth v1.100+; vmgateway v1.100+; vmbackup v1.100+; Kubernetes deployments via victoria-metrics-k8s-stack Helm chart.

## Threat Model

- **Adversary 1 — Unauthenticated metric read:** An attacker who reaches the vmselect HTTP port executes `{__name__=~".+"}` and enumerates all stored metric series, including series whose labels contain internal service names, user identifiers, or API endpoint paths. No authentication is required in the default configuration.
- **Adversary 2 — Cross-tenant query via URL manipulation:** A developer in team A changes the tenant path segment in a MetricsQL query URL from `/select/1/` to `/select/2/` and reads team B's metrics. Without vmauth enforcing tenant routing from authenticated identity, this URL substitution succeeds.
- **Adversary 3 — Metric injection via vminsert:** An attacker sends crafted Prometheus remote-write traffic to vminsert, injecting metrics that match existing series names with modified values. Alert thresholds tied to those series fire or are suppressed based on attacker-controlled data. The attacker can also inject series with high-cardinality label combinations that exhaust vmstorage memory.
- **Adversary 4 — deleteRange data destruction:** An attacker who reaches vmselect's admin API calls `DELETE /api/v1/admin/tsdb/delete_series?match[]=job="security-events"`, permanently destroying security event telemetry without authentication. The deletion covers historical data, removing forensic evidence of prior activity.
- **Adversary 5 — gRPC/native protocol interception:** An attacker with network access to the intra-cluster network captures plaintext vminsert-to-vmstorage or vmselect-to-vmstorage traffic, reconstructing metric series and label sets from the wire. In Kubernetes, a compromised pod with `NET_ADMIN` or network packet capture capability achieves this.
- **Adversary 6 — Backup data exfiltration:** An attacker obtains read access to the S3 bucket used by vmbackup and downloads metric snapshot objects containing months of production telemetry, including label-embedded PII.
- **Access level:** Adversaries 1–4 need network access to HTTP ports. Adversary 5 needs pod-level network access in the cluster. Adversary 6 needs S3 credentials or a misconfigured bucket ACL.
- **Objective:** Extract sensitive metric data, inject false telemetry, destroy audit trail, deny monitoring service.
- **Blast radius:** Full metric read exposes infrastructure topology, request rates, error patterns, and any PII embedded in labels across all services and all tenants stored in VictoriaMetrics.

## Configuration

### Step 1: vmauth as Authentication Proxy

vmauth is VictoriaMetrics's official authentication and routing proxy. Deploy it as the sole external-facing entry point for all read and write traffic. All vminsert and vmselect ports should be unreachable from outside the cluster directly — only vmauth should be reachable.

```yaml
# vmauth-config.yaml — authentication and per-tenant routing.
users:
  # Basic auth user for vmagent remote write — insert only.
  - username: "vmagent-writer"
    password: "${VMAGENT_WRITER_PASSWORD}"   # Loaded from environment.
    url_prefix:
      - "http://vminsert:8480/insert/0/prometheus/api/v1/write"
    # Restrict to write path only — cannot read.

  # Bearer token for Grafana — select only, restricted to tenant 0.
  - bearer_token: "${GRAFANA_BEARER_TOKEN}"
    url_prefix:
      - "http://vmselect:8481/select/0/prometheus"
    # Grafana datasource uses this token; cannot write or access other tenants.

  # Per-tenant routing: team A's token routes to tenant 1.
  - bearer_token: "${TEAM_A_BEARER_TOKEN}"
    url_prefix:
      - "http://vmselect:8481/select/1/prometheus"
    # Team A can only query their own tenant data.

  # Per-tenant routing: team B's token routes to tenant 2.
  - bearer_token: "${TEAM_B_BEARER_TOKEN}"
    url_prefix:
      - "http://vmselect:8481/select/2/prometheus"

  # Admin user: access to all tenants and admin APIs.
  # Requires separate, tightly controlled credential.
  - username: "admin"
    password: "${VM_ADMIN_PASSWORD}"
    url_prefix:
      - "http://vmselect:8481"
      - "http://vminsert:8480"
```

Deploy vmauth as a Kubernetes Deployment with the config mounted from a Secret (not a ConfigMap — the config contains credentials):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vmauth
  namespace: monitoring
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: vmauth
          image: victoriametrics/vmauth:v1.100.0
          args:
            - "-auth.config=/etc/vmauth/config.yaml"
            - "-tls"
            - "-tlsCertFile=/etc/vmauth/tls/tls.crt"
            - "-tlsKeyFile=/etc/vmauth/tls/tls.key"
          ports:
            - containerPort: 8427   # HTTPS with -tls flag.
          volumeMounts:
            - name: vmauth-config
              mountPath: /etc/vmauth
              readOnly: true
            - name: tls
              mountPath: /etc/vmauth/tls
              readOnly: true
      volumes:
        - name: vmauth-config
          secret:
            secretName: vmauth-config   # Not ConfigMap — contains credentials.
        - name: tls
          secret:
            secretName: vmauth-tls
```

For Kubernetes Ingress, terminate TLS at the Ingress controller and forward to vmauth over HTTPS internally:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: vmauth
  namespace: monitoring
  annotations:
    nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    # Restrict source IPs to internal networks only.
    nginx.ingress.kubernetes.io/whitelist-source-range: "10.0.0.0/8,172.16.0.0/12"
spec:
  tls:
    - hosts: ["metrics.internal.example.com"]
      secretName: vmauth-ingress-tls
  rules:
    - host: metrics.internal.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: vmauth
                port:
                  number: 8427
```

### Step 2: TLS for All Component Communication

Enable TLS on every VictoriaMetrics component. In cluster mode, all internal communication — vminsert to vmstorage, vmselect to vmstorage — must be encrypted.

**vmstorage with TLS:**

```bash
# vmstorage startup flags — enable TLS for vminsert and vmselect connections.
/usr/bin/vmstorage \
  -storageDataPath=/var/lib/victoriametrics \
  -vminsertAddr=:8400 \
  -vmselectAddr=:8401 \
  # TLS for vminsert connections.
  -tls \
  -tlsCertFile=/etc/victoriametrics/tls/tls.crt \
  -tlsKeyFile=/etc/victoriametrics/tls/tls.key \
  # Require client certificate from vminsert and vmselect (mutual TLS).
  -mtls \
  -mtlsAllowedCACerts=/etc/victoriametrics/tls/ca.crt
```

**vminsert connecting to vmstorage with TLS:**

```bash
/usr/bin/vminsert \
  -storageNode=vmstorage-0.vmstorage:8400,vmstorage-1.vmstorage:8400 \
  # TLS for connections to vmstorage.
  -storageNodeTLS \
  -storageNodeTLSCertFile=/etc/victoriametrics/tls/tls.crt \
  -storageNodeTLSKeyFile=/etc/victoriametrics/tls/tls.key \
  -storageNodeTLSCAFile=/etc/victoriametrics/tls/ca.crt \
  # Mutual TLS: vminsert presents its client certificate to vmstorage.
  -storageNodeTLSInsecureSkipVerify=false
```

**vmselect connecting to vmstorage with TLS:**

```bash
/usr/bin/vmselect \
  -storageNode=vmstorage-0.vmstorage:8401,vmstorage-1.vmstorage:8401 \
  -storageNodeTLS \
  -storageNodeTLSCertFile=/etc/victoriametrics/tls/tls.crt \
  -storageNodeTLSKeyFile=/etc/victoriametrics/tls/tls.key \
  -storageNodeTLSCAFile=/etc/victoriametrics/tls/ca.crt \
  -storageNodeTLSInsecureSkipVerify=false
```

Use cert-manager to issue certificates from an internal CA, with 90-day validity and automatic renewal at 30 days remaining. VictoriaMetrics reads TLS certificates from disk on each connection, so rotation does not require a restart.

### Step 3: vmgateway for JWT-Based Tenant Access Control

vmgateway provides per-request JWT validation and tenant enforcement for the query path. It validates a JWT on every request, extracts the tenant claim from the token, and enforces that the request only accesses that tenant's data — regardless of what the client puts in the URL path.

```yaml
# vmgateway startup flags.
/usr/bin/vmgateway \
  -clusterMode \
  -read.url=http://vmselect:8481 \
  -write.url=http://vminsert:8480 \
  # JWT validation: verify tokens with this public key.
  -auth.publicKeyPath=/etc/vmgateway/jwt-public.pem \
  # Extract tenant ID from JWT claim "vm_access.tenant_id".
  -enable.auth \
  -tls \
  -tlsCertFile=/etc/vmgateway/tls/tls.crt \
  -tlsKeyFile=/etc/vmgateway/tls/tls.key
```

The JWT payload structure for a tenant-scoped token:

```json
{
  "sub": "grafana-team-payments",
  "iat": 1746662400,
  "exp": 1746748800,
  "vm_access": {
    "tenant_id": {
      "account_id": 1,
      "project_id": 0
    },
    "mode": 1
  }
}
```

`mode: 1` grants read access only. `mode: 2` grants write access. `mode: 3` grants read and write. vmgateway enforces these modes: a token with `mode: 1` issued to a Grafana service account cannot write metrics regardless of the HTTP endpoint it calls.

Issue short-lived JWTs (1 hour expiry) from your identity provider or from a vmgateway-compatible token issuer. Do not issue long-lived static tokens for production workloads.

### Step 4: Protecting the deleteRange API

The deleteRange API permanently removes metric series. It must only be callable by authorised operators, not by Grafana, vmagent, or application services.

At the vmauth routing layer, route delete requests only for an explicit admin credential:

```yaml
# vmauth-config.yaml — admin-only routing for delete operations.
users:
  # All regular users: explicitly block access to the delete endpoint.
  - bearer_token: "${GRAFANA_BEARER_TOKEN}"
    url_prefix:
      - "http://vmselect:8481/select/0/prometheus"
    # url_map can be used to block specific paths:
    url_map:
      - src_paths:
          - "/api/v1/admin/tsdb/delete_series.*"
        action: deny
      - src_paths:
          - ".*"
        url_prefix: "http://vmselect:8481/select/0/prometheus"

  # Admin-only: access to delete endpoint requires separate admin token.
  - bearer_token: "${VM_ADMIN_DELETE_TOKEN}"
    url_prefix:
      - "http://vmselect:8481"
```

At the network layer, enforce this with a Kubernetes NetworkPolicy that blocks direct access to vmselect port 8481 from all pods except vmauth:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vmselect-restrict
  namespace: monitoring
spec:
  podSelector:
    matchLabels:
      app: vmselect
  policyTypes:
    - Ingress
  ingress:
    # Only vmauth can reach vmselect directly.
    - from:
        - podSelector:
            matchLabels:
              app: vmauth
      ports:
        - port: 8481
```

Log all calls to the delete endpoint. Alert on any delete API call — it should be rare and always deliberate:

```yaml
# Alertmanager rule: alert on any deleteRange call (detected via vmauth access logs).
groups:
  - name: victoriametrics-admin
    rules:
      - alert: VictoriaMetricsDeleteSeriesCall
        expr: increase(vmauth_requests_total{path=~".*delete_series.*"}[5m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "MetricSeries delete API called — verify this is authorised"
```

### Step 5: vmagent Security

vmagent scrapes Prometheus-format targets and forwards to VictoriaMetrics. Its configuration file contains scrape credentials for targets that require authentication.

```yaml
# vmagent-config.yaml — credential security.
scrape_configs:
  - job_name: "kubernetes-pods"
    kubernetes_sd_configs:
      - role: pod
    # TLS for scraping HTTPS targets.
    tls_config:
      ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
      insecure_skip_verify: false

  - job_name: "internal-api-metrics"
    static_configs:
      - targets: ["api.internal:8443"]
    scheme: https
    tls_config:
      ca_file: /etc/vmagent/certs/internal-ca.crt
    # Use credentials_file, not inline credentials.
    # The file is mounted from a Kubernetes Secret.
    authorization:
      type: Bearer
      credentials_file: /var/run/secrets/vmagent/api-bearer-token
    # Relabeling: drop sensitive labels before forwarding to VictoriaMetrics.
    metric_relabel_configs:
      # Drop user_id label — high cardinality, likely contains PII.
      - action: labeldrop
        regex: "user_id|session_id|request_id"
      # Redact path segments that contain tokens or IDs.
      - source_labels: [path]
        regex: '/api/v1/users/([^/]+)(.*)'
        replacement: '/api/v1/users/REDACTED$2'
        target_label: path
        action: replace

remote_write:
  - url: "https://vmauth.monitoring.svc.cluster.local:8427/insert/0/prometheus/api/v1/write"
    tls_config:
      ca_file: /etc/vmagent/certs/vmauth-ca.crt
    bearer_token_file: /var/run/secrets/vmagent/vmauth-writer-token
    queue_config:
      max_samples_per_send: 10000
      max_shards: 8
```

Restrict vmagent's own HTTP API. The vmagent HTTP interface (port 8429) exposes the configuration, active scrape targets, and the ability to reload configuration. Never expose it outside the monitoring namespace:

```bash
# vmagent startup flags.
/usr/bin/vmagent \
  -promscrape.config=/etc/vmagent/config.yaml \
  -remoteWrite.url=https://vmauth.monitoring.svc.cluster.local:8427/insert/0/prometheus/api/v1/write \
  -remoteWrite.bearerTokenFile=/var/run/secrets/vmagent/vmauth-writer-token \
  -remoteWrite.tlsCAFile=/etc/vmagent/certs/vmauth-ca.crt \
  # Bind HTTP interface to localhost only — not accessible from other pods.
  -httpListenAddr=127.0.0.1:8429 \
  # Enable basic auth on the local HTTP interface for any local access.
  -httpAuth.username=admin \
  -httpAuth.password="${VMAGENT_HTTP_PASSWORD}"
```

### Step 6: Cluster Mode Network Isolation

In cluster mode, separate each component tier onto distinct network segments with explicit NetworkPolicies. No component should be reachable from application namespaces directly:

```yaml
# vmstorage-networkpolicy.yaml — only vminsert and vmselect can reach vmstorage.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vmstorage-isolation
  namespace: monitoring
spec:
  podSelector:
    matchLabels:
      app: vmstorage
  policyTypes:
    - Ingress
    - Egress
  ingress:
    # vminsert on port 8400.
    - from:
        - podSelector:
            matchLabels:
              app: vminsert
      ports:
        - port: 8400
    # vmselect on port 8401.
    - from:
        - podSelector:
            matchLabels:
              app: vmselect
      ports:
        - port: 8401
  egress:
    # vmstorage only needs to make outbound connections for replication.
    - to:
        - podSelector:
            matchLabels:
              app: vmstorage
      ports:
        - port: 8400
        - port: 8401
```

For vminsert and vmselect, deny all ingress from application namespaces and only allow ingress from vmauth:

```yaml
# vminsert-networkpolicy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vminsert-isolation
  namespace: monitoring
spec:
  podSelector:
    matchLabels:
      app: vminsert
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: vmauth
      ports:
        - port: 8480
```

### Step 7: Preventing Label Cardinality and PII Leakage

High cardinality labels are both a performance problem and a PII risk. Each unique label combination creates a new time series. Labels that include user-identifying values — email addresses, usernames, session tokens — grow unboundedly, consume significant vmstorage memory, and constitute personal data stored in the metrics system.

Enforce cardinality limits at the vmstorage and vminsert level to stop cardinality explosions before they exhaust resources:

```bash
# vmstorage: limit new series creation rate and total unique timeseries.
/usr/bin/vmstorage \
  -storage.maxDailySeries=5000000 \     # Alert if a tenant exceeds this daily.
  -storage.maxHourlySeries=1000000      # Throttle burst cardinality growth.
```

```bash
# vminsert: limit per-label value count.
/usr/bin/vminsert \
  -maxLabelsPerTimeseries=40 \          # Drop series with more than 40 labels.
  -maxLabelValueLen=1024                # Truncate label values exceeding 1 KB.
```

At vmagent, apply relabeling to drop or redact sensitive labels before they reach VictoriaMetrics:

```yaml
# Global relabeling applied to all scraped metrics.
# Place in vmagent-config.yaml under scrape_configs defaults or as
# metric_relabel_configs on each job.
metric_relabel_configs:
  # Drop any label matching PII patterns.
  - action: labeldrop
    regex: "(user_id|email|username|session_token|api_key|password|secret)"

  # Redact URL path labels containing identifiers.
  - source_labels: [url, http_url, request_uri]
    regex: '(.*)/([0-9a-f]{8,}|[0-9]+)(.*)'
    replacement: '$1/REDACTED$3'
    target_label: url
    action: replace

  # Drop high-cardinality trace/span IDs.
  - action: labeldrop
    regex: "(trace_id|span_id|request_id|correlation_id)"
```

Audit cardinality weekly using MetricsQL:

```promql
# Top 20 metrics by unique series count — investigate any with unexpectedly
# high counts for potential PII label leakage.
topk(20, count by (__name__)({__name__=~".+"}))
```

Alert when a single metric exceeds a cardinality threshold:

```yaml
- alert: HighCardinalityMetric
  expr: count by (__name__)(count by (__name__, instance)({__name__=~".+"})) > 50000
  for: 10m
  labels:
    severity: warning
  annotations:
    summary: "Metric {{ $labels.__name__ }} has > 50k unique series — investigate for PII labels"
```

### Step 8: vmbackup to S3 with Encryption

vmbackup snapshots vmstorage data to S3 (or GCS, Azure Blob). Configure encryption and least-privilege IAM to protect backup data at rest.

```bash
# vmbackup: backup with SSE-KMS encryption.
/usr/bin/vmbackup \
  -storageDataPath=/var/lib/victoriametrics \
  -dst=s3://victoriametrics-backups-prod/daily \
  # SSE-KMS: encrypt with a customer-managed KMS key.
  -s3StorageClass=STANDARD_IA \
  -s3SSECustomerAlgorithm=aws:kms \
  -s3SSEKMSKeyID=arn:aws:kms:us-east-1:123456789012:key/mrk-abc123 \
  # Credentials via IAM role for service accounts (IRSA) — no static keys.
  -s3ForcePathStyle=false
```

Apply least-privilege IAM for the vmbackup service account. vmbackup needs PutObject but not DeleteObject (retention management should be handled by S3 lifecycle rules, not by vmbackup itself):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "VmbackupWrite",
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:ListBucket",
        "s3:AbortMultipartUpload",
        "s3:ListBucketMultipartUploads"
      ],
      "Resource": [
        "arn:aws:s3:::victoriametrics-backups-prod",
        "arn:aws:s3:::victoriametrics-backups-prod/*"
      ]
    },
    {
      "Sid": "KmsDecryptForRestore",
      "Effect": "Allow",
      "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/mrk-abc123"
    }
  ]
}
```

Enable S3 Block Public Access at both the bucket and account level. Enable access logging on the backup bucket to detect any unexpected GetObject calls that might indicate backup data exfiltration.

### Step 9: Rate Limiting and Resource Protection

Without per-tenant rate limits, a single tenant can exhaust vmstorage's query resources — either accidentally through an expensive dashboard or intentionally as a denial-of-service. The `-search.maxUniqueTimeseries` flag is the primary guard against query-induced resource exhaustion:

```bash
# vmselect: resource protection flags.
/usr/bin/vmselect \
  -storageNode=vmstorage-0.vmstorage:8401,vmstorage-1.vmstorage:8401 \
  # Maximum unique time series a single query can access.
  # Queries exceeding this are rejected with an error.
  -search.maxUniqueTimeseries=500000 \
  # Maximum time range a query can cover (prevents full-history table scans).
  -search.maxQueryDuration=60s \
  # Maximum number of concurrent queries from all users combined.
  -search.maxConcurrentRequests=16 \
  # Maximum bytes allowed per query result.
  -search.maxBytesPerQuery=1073741824 \   # 1 GB
  # Maximum lookback window — prevents unlimited step ranges.
  -search.maxLookback=168h                # 7 days
```

For per-tenant enforcement, vmgateway applies rate limits per JWT-authenticated tenant. Configure limits in the vmgateway startup flags or via its configuration file:

```bash
/usr/bin/vmgateway \
  -clusterMode \
  -read.url=http://vmselect:8481 \
  -write.url=http://vminsert:8480 \
  -auth.publicKeyPath=/etc/vmgateway/jwt-public.pem \
  -enable.auth \
  # Per-tenant ingestion rate limit (default applies if JWT has no specific limit).
  -ratelimit.config=/etc/vmgateway/ratelimit.yaml
```

```yaml
# vmgateway ratelimit.yaml — per-tenant limits.
rateLimits:
  # Default limit applies to any tenant not listed explicitly.
  - type: queries
    value: 100
    resolution: minute
  - type: writes
    value: 100000
    resolution: minute
  # Payments team has higher write budget.
  - tenantID:
      accountID: 1
    type: writes
    value: 1000000
    resolution: minute
```

### Step 10: Telemetry

```
vm_http_requests_total{path, code}                     counter
vm_rows_inserted_total{type}                           counter
vm_new_timeseries_created_total{type}                  counter
vm_cache_size_bytes{type}                              gauge
vmauth_requests_total{username, path, code}            counter
vmauth_request_duration_seconds{path}                  histogram
vmgateway_access_denied_total{tenant}                  counter
vmbackup_uptime_seconds                                gauge
```

Alert on:

- `vm_new_timeseries_created_total` rate spike — sudden increase in new series creation is a cardinality explosion indicator; investigate for PII labels or a misconfigured application.
- `vmauth_requests_total{code="401"}` rate spike — failed authentication attempts; may indicate credential stuffing or a rotated token that was not updated in all consumers.
- `vmgateway_access_denied_total` non-zero — a tenant exceeded its rate limit or attempted to access a path its JWT does not permit; investigate for cross-tenant probing.
- `vmauth_requests_total{path=~".*delete_series.*"}` non-zero — any deleteRange call should be alerted and reviewed.
- vmstorage disk fill rate: `vm_data_size_bytes` growth rate exceeding expected baseline may indicate a cardinality explosion consuming storage.

## Expected Behaviour

| Signal | Default VictoriaMetrics | Hardened VictoriaMetrics |
|--------|------------------------|--------------------------|
| Anonymous MetricsQL query | All metrics readable without credentials | 401 from vmauth; credentials required |
| Cross-tenant query via URL manipulation | Path change gives access to any tenant | vmgateway enforces tenant from JWT claim; URL tenant segment ignored |
| deleteRange API call without auth | Metrics permanently deleted; no record | vmauth denies; NetworkPolicy blocks direct access; alert fires |
| vminsert-to-vmstorage traffic | Plaintext native protocol | Mutual TLS; certificate required on both ends |
| High-cardinality PII label series | Stored indefinitely; unbounded growth | Relabeling drops PII labels; maxLabelsPerTimeseries limits cardinality |
| Backup data in S3 | Plaintext objects | SSE-KMS encrypted; IAM restricts access; no public ACL |
| Single tenant exhausting query resources | Unlimited concurrent queries | -search.maxUniqueTimeseries and vmgateway per-tenant rate limits |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| vmauth as sole entry point | Single authentication boundary; all access logged | Single point of failure; vmauth outage stops all metric access | Deploy vmauth as Deployment with 2+ replicas; include health checks in Kubernetes readiness probe |
| Mutual TLS for vmstorage | Prevents rogue vminsert/vmselect from connecting | Certificate management for all component pods | cert-manager automates issuance and rotation; mount as volume; VictoriaMetrics reloads without restart |
| JWT tokens via vmgateway | Short-lived tokens; per-tenant enforcement | Token issuance infrastructure required; applications must refresh tokens | Issue tokens from existing OIDC provider; use 1-hour expiry with client-side refresh |
| deleteRange blocked to non-admins | Prevents accidental or malicious metric deletion | Legitimate data deletion (GDPR erasure) requires admin credential | Document admin credential access procedure; use separate delete token stored in secrets manager |
| Label PII relabeling | Prevents PII in metrics; reduces cardinality | May drop labels that dashboards currently depend on | Audit existing dashboards before applying relabeling; coordinate with team owners |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| vmauth certificate expiry | All metric access fails with TLS errors | vmauth_requests_total drops to 0; Grafana datasource errors | cert-manager auto-renewal; alert at 14 days remaining on certificate expiry |
| vmgateway JWT public key mismatch | All authenticated requests return 401 | vmgateway_access_denied_total spike across all tenants | Verify JWT issuer public key matches vmgateway's configured key; redeploy with corrected key path |
| vmstorage mutual TLS client cert expiry | vminsert/vmselect cannot connect to vmstorage; write and read fail | vm_rows_inserted_total drops to 0; vmselect returns errors | Rotate vmstorage client certificates; rolling restart vminsert and vmselect |
| Rate limit misconfigured too low | Legitimate Grafana dashboards return query errors | vmgateway rate limit denials for production tenant | Increase rate limit in vmgateway ratelimit.yaml; reload config without restart |
| vmbackup IAM permission denied | Backup fails silently; RPO at risk | vmbackup exits non-zero; alert on backup age exceeding SLA | Review IAM role policy; ensure PutObject and KMS GenerateDataKey are permitted |
| PII relabeling drops required label | Dashboard shows "No data" for affected metric | Grafana panel errors; increase in "no data" panel count | Roll back relabeling rule; audit label usage before re-applying with correct regex |

## Related Articles

- [Thanos and Prometheus Multi-Tenancy Security](/articles/observability/thanos-prometheus-multitenancy-security/)
- [Prometheus Remote Write and Config Endpoint Security](/articles/observability/prometheus-remote-write-security/)
- [Grafana Security Hardening](/articles/observability/grafana-security-hardening/)
- [OpenTelemetry PII Leakage Prevention](/articles/observability/otel-pii-leakage/)
- [Alertmanager Security Hardening](/articles/observability/alertmanager-security/)
