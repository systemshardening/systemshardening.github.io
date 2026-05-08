---
title: "Securing Distributed Tracing Infrastructure: Grafana Tempo and Jaeger"
description: "Distributed traces are a security liability by default — they accumulate request parameters, user IDs, internal service URLs, and raw SQL across every hop of every request. This guide hardens the full tracing stack: PII scrubbing before storage, Tempo authentication and multi-tenancy, S3 backend encryption, Jaeger access control, OTLP endpoint authentication, and the right-to-erasure problem in append-only trace storage."
slug: tempo-jaeger-tracing-security
date: 2026-05-07
lastmod: 2026-05-07
category: observability
tags:
  - tempo
  - jaeger
  - distributed-tracing
  - trace-privacy
  - opentelemetry
personas:
  - security-engineer
  - platform-engineer
article_number: 558
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/observability/tempo-jaeger-tracing-security/
---

# Securing Distributed Tracing Infrastructure: Grafana Tempo and Jaeger

## Problem

Distributed tracing infrastructure exists to help engineering teams understand the runtime behaviour of production systems. In doing that job, traces accumulate a cross-cutting view of every request that flows through your architecture: HTTP URLs with query strings, internal service addresses, database queries, user-facing identifiers, authentication headers, and exception payloads. Each of those categories is a potential data class that should never exist in an observability store — but which lands there routinely when tracing infrastructure is deployed without a security-first configuration.

The trace backend is an unusual kind of security liability. Unlike a database with obvious access controls, tracing backends are frequently treated as infrastructure plumbing: deployed with permissive defaults, accessible to any developer with a cluster login, and retained for months. The combination of rich, queryable data and minimal access controls makes the Jaeger UI or Tempo query endpoint a quiet exfiltration target. An analyst with five minutes and a browser can map your internal service graph, extract query parameters that contain user emails, and find SQL spans that reveal your schema — without triggering a single security alert.

This guide covers the infrastructure-level security controls for Grafana Tempo and Jaeger: what data should be stripped before it reaches storage, how each component's authentication and authorisation is configured, how storage is secured at rest, and how multi-tenant isolation is enforced. SDK-level PII scrubbing and OTel Collector redaction processors are covered in companion articles; this article focuses on the tracing infrastructure itself.

**Target systems:** Grafana Tempo 2.4+; Jaeger 1.55+ (all-in-one and distributed); OpenTelemetry Collector contrib 0.100+ as the collection pipeline; Kubernetes as the deployment environment; S3-compatible object storage.

## Threat Model

- **Adversary 1 — Developer exfiltrating PII through the Jaeger UI:** A developer with internal network access opens the Jaeger query UI (no authentication configured) and searches for traces on the `/api/users` endpoint. The span attributes include `http.target: /api/users/alice@example.com` and `db.statement: SELECT * FROM users WHERE email = 'alice@example.com'`. Within minutes they have a list of user emails and the database schema. No vulnerability was exploited — just default configuration.
- **Adversary 2 — Compromised developer credential reads Tempo storage:** An attacker obtains a developer's AWS credentials via a phishing or supply-chain compromise. The Tempo S3 bucket has no additional bucket policy — any authenticated IAM identity in the account can read it. The attacker downloads raw trace blocks, which are gzip-compressed but unencrypted. The blocks contain trace data covering months of production traffic, including PII-bearing span attributes.
- **Adversary 3 — Cross-tenant trace correlation in a multi-tenant cluster:** Two product teams share a Tempo instance. Team A is permitted to query their own traces. The Tempo API endpoint is authenticated but has no tenant-enforcement — callers can specify any `X-Scope-OrgID` value. Team A queries Team B's tenant ID and reads their internal service graph, request rates, and error patterns.
- **Adversary 4 — Trace injection via unauthenticated OTLP endpoint:** The OTel Collector's OTLP gRPC port is exposed cluster-wide without authentication. A compromised pod sends forged spans that attribute errors to a legitimate service, creating fabricated incident evidence in Jaeger. The forged traces survive for the full retention period and appear during a post-incident review.
- **Adversary 5 — Right-to-erasure violation discovered in audit:** A GDPR audit finds that user email addresses are embedded in Tempo trace blocks. The legal team requests deletion of all traces containing a specific user's data. Tempo's append-only block storage cannot selectively delete individual span attributes — the only option is to delete the entire block, which destroys unrelated production telemetry.
- **Access level:** Adversaries 1 and 3 have internal read access. Adversary 2 has stolen cloud credentials. Adversary 4 has compromised pod-level access. Adversary 5 is an institutional consequence of missing scrubbing controls.
- **Objective:** Extract PII and internal architecture intelligence; forge forensic evidence; trigger compliance violations.

## Configuration

### Step 1: PII Prevention at the OpenTelemetry Collector

The single most important security control for tracing infrastructure is ensuring that sensitive data never reaches the backend. Retroactive deletion is not reliably possible in append-only object stores. The OTel Collector's `transform` and `redaction` processors form the scrubbing layer between applications and Tempo or Jaeger.

```yaml
# otelcol-contrib-config.yaml — span attribute scrubbing before backend export.
processors:
  # Redaction processor: block specific attribute keys and value patterns.
  redaction/pii:
    allow_all_keys: true
    # Block-list: these keys are always deleted from spans.
    blocked_keys:
      - "http.request.header.authorization"
      - "http.request.header.cookie"
      - "http.response.header.set-cookie"
      - "http.request.header.x-api-key"
      - "http.request.header.x-auth-token"
    # Value pattern block-list: any attribute whose value matches
    # these patterns has the matching text replaced with [REDACTED].
    blocked_values:
      - "(?i)Bearer\\s+[A-Za-z0-9\\-._~+/]+=*"          # Bearer tokens.
      - "\\b\\d{3}-\\d{2}-\\d{4}\\b"                      # US SSNs.
      - "\\b(?:\\d[ -]*?){13,16}\\b"                       # Card numbers.
      - "sk-[A-Za-z0-9]{32,}"                              # OpenAI-style API keys.
    summary: silent

  # Transform processor: additional pattern-based scrubbing for structured fields.
  transform/scrub-urls:
    trace_statements:
      - context: span
        statements:
          # Redact email addresses embedded in URL paths and query strings.
          - replace_pattern(attributes["http.url"],
              "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
              "[EMAIL-REDACTED]")
          - replace_pattern(attributes["http.target"],
              "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
              "[EMAIL-REDACTED]")
          # Redact string literal values in SQL statements.
          # Keeps query structure for debugging; removes parameter values.
          - replace_pattern(attributes["db.statement"],
              "'[^']*'", "'?'")
          - replace_pattern(attributes["db.statement"],
              "= [0-9]{4,}", "= ?")

  # Hash user identifiers rather than dropping them entirely.
  # A hashed user ID is non-reversible but still allows grouping
  # traces by user for debugging without storing the raw ID.
  transform/hash-user-ids:
    trace_statements:
      - context: span
        statements:
          # SHA-256 hash of user.id attribute if present.
          - set(attributes["user.id"],
              SHA256(attributes["user.id"]))
            where attributes["user.id"] != nil

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors:
        - redaction/pii
        - transform/scrub-urls
        - transform/hash-user-ids
        - tail_sampling
        - batch
      exporters: [otlphttp/tempo]
```

**Why hashing beats deletion for user IDs:** Hashing with SHA-256 preserves the ability to correlate traces for a given user during an incident investigation — you can compute the hash of a known user ID and query for it — while preventing the raw identifier from being stored. Deletion prevents all cross-trace correlation.

### Step 2: OTLP Ingestion Endpoint Authentication

The OTLP gRPC and HTTP endpoints that receive spans from application services should require authentication. An unauthenticated OTLP endpoint accepts spans from any process in the cluster, enabling trace injection attacks.

```yaml
# otelcol-contrib-config.yaml — authenticated OTLP receiver.
extensions:
  # OIDC authenticator: validate JWT bearer tokens.
  # Services use their Kubernetes service account OIDC tokens as credentials.
  oidc:
    issuer_url: https://kubernetes.default.svc.cluster.local
    audience: otel-collector
    attribute: sub   # Extract service identity from subject claim.

receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
        auth:
          authenticator: oidc
      http:
        endpoint: 0.0.0.0:4318
        auth:
          authenticator: oidc
        # TLS for HTTP OTLP.
        tls:
          cert_file: /etc/otel/tls/tls.crt
          key_file: /etc/otel/tls/tls.key
          min_version: "1.2"

service:
  extensions: [oidc]
  pipelines:
    traces:
      receivers: [otlp]
      processors: [redaction/pii, transform/scrub-urls, batch]
      exporters: [otlphttp/tempo]
```

Services obtain tokens using the Kubernetes service account token API. The OIDC authenticator validates the token signature against the cluster's JWKS endpoint and rejects any request that does not carry a valid token for the configured audience.

If OIDC is not available in your environment, a static bearer token shared via Kubernetes Secret is a minimal improvement over no authentication, though it provides weaker guarantees:

```yaml
extensions:
  bearertokenauth:
    tokens_file: /etc/otel/tokens.txt   # One token per line.
```

Supplement authentication with a NetworkPolicy that restricts which pods can reach the OTLP port:

```yaml
# NetworkPolicy: pods send traces to the collector; nothing else connects.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: otel-collector-otlp-ingress
  namespace: tracing
spec:
  podSelector:
    matchLabels:
      app: otel-collector
  policyTypes:
    - Ingress
  ingress:
    # Application pods in the apps namespace may send traces.
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: apps
      ports:
        - port: 4317
          protocol: TCP
        - port: 4318
          protocol: TCP
    # Block all other inbound except Prometheus scraping.
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
      ports:
        - port: 8888
          protocol: TCP
```

### Step 3: Grafana Tempo Authentication and Multi-Tenancy

Tempo exposes an HTTP API that accepts trace queries and ingestion. By default the API is unauthenticated. In a production deployment Tempo sits behind an authenticating reverse proxy.

**OAuth2-proxy for Tempo query access:**

```yaml
# Tempo deployment with OAuth2-proxy sidecar.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tempo
  namespace: tracing
spec:
  template:
    spec:
      containers:
        - name: tempo
          image: grafana/tempo:2.4.0
          args:
            - -config.file=/etc/tempo/tempo.yaml
          ports:
            - name: http
              containerPort: 3200
            - name: grpc
              containerPort: 9095

        - name: oauth2-proxy
          image: quay.io/oauth2-proxy/oauth2-proxy:v7.6.0
          args:
            - --upstream=http://localhost:3200
            - --http-address=0.0.0.0:4180
            - --provider=oidc
            - --oidc-issuer-url=https://company.okta.com/oauth2/default
            - --client-id=$(OIDC_CLIENT_ID)
            - --client-secret=$(OIDC_CLIENT_SECRET)
            - --cookie-secret=$(COOKIE_SECRET)
            - --email-domain=example.com
            # Only users in the observability group may read traces.
            - --allowed-group=observability-platform
            - --skip-provider-button=true
          ports:
            - containerPort: 4180
          envFrom:
            - secretRef:
                name: oauth2-proxy-credentials
```

Expose only the OAuth2-proxy port through the Service and Ingress. Tempo's native HTTP port must not be directly accessible from outside the pod.

**Multi-tenancy with X-Scope-OrgID enforcement:**

Tempo's multi-tenancy model uses the `X-Scope-OrgID` header to route trace data and queries to per-tenant storage partitions. The tenant ID must be injected and validated by the authentication gateway — callers must not be able to specify arbitrary tenant IDs.

```yaml
# tempo.yaml — multi-tenancy configuration.
multitenancy_enabled: true

# Tempo enforces that requests carry the X-Scope-OrgID header.
# The authentication gateway is responsible for setting this header
# to the verified tenant ID from the OIDC token claims.
# Example: oauth2-proxy passes the user's group as the org ID.

limits_config:
  # Per-tenant trace ingestion rate limit.
  ingestion_rate_limit_bytes: 15000000     # 15 MB/s per tenant.
  ingestion_burst_size_bytes: 20000000     # 20 MB burst.
  # Per-tenant query parallelism limit.
  max_search_duration: 168h

# Distributor: multi-tenant aware ingestion.
distributor:
  receivers:
    otlp:
      protocols:
        grpc:
          endpoint: 0.0.0.0:4317
        http:
          endpoint: 0.0.0.0:4318
```

An authentication proxy that correctly injects `X-Scope-OrgID` prevents Adversary 3 (cross-tenant trace correlation). The proxy reads the tenant identity from the validated OIDC token and sets the header — the caller never controls the tenant scope of their query.

### Step 4: Tempo Storage Security (S3 Backend)

Tempo stores trace data as compressed blocks in object storage. Without additional controls, the bucket is a readable archive of all traces for the entire retention period.

```yaml
# tempo.yaml — S3 backend with encryption and access restrictions.
storage:
  trace:
    backend: s3
    s3:
      bucket: tempo-traces-prod
      endpoint: s3.amazonaws.com
      region: us-east-1
      # Server-side encryption with a customer-managed KMS key.
      # Separate KMS key per tenant in a multi-tenant deployment.
      sse_type: KMS
      sse_kms_key_id: arn:aws:kms:us-east-1:123456789012:key/mrk-abc123

    wal:
      path: /var/tempo/wal
```

Enforce bucket-level controls separately from application configuration. The bucket policy must enforce encryption in transit and block public access:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyNonTLS",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::tempo-traces-prod",
        "arn:aws:s3:::tempo-traces-prod/*"
      ],
      "Condition": {
        "Bool": {"aws:SecureTransport": "false"}
      }
    },
    {
      "Sid": "DenyNonEncryptedPuts",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::tempo-traces-prod/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": "aws:kms"
        }
      }
    },
    {
      "Sid": "AllowTempoServiceRole",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/tempo-service-role"
      },
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::tempo-traces-prod",
        "arn:aws:s3:::tempo-traces-prod/*"
      ]
    }
  ]
}
```

S3 Block Public Access settings must be enabled at both the bucket and account level:

```bash
# Enforce block-public-access on the bucket.
aws s3api put-public-access-block \
  --bucket tempo-traces-prod \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,\
    BlockPublicPolicy=true,RestrictPublicBuckets=true
```

Use a dedicated IAM role for Tempo with minimal permissions. The role should have no access to other buckets and no IAM permissions of its own. In an EKS environment, bind the role to the Tempo service account using IRSA:

```yaml
# ServiceAccount annotation for IRSA.
apiVersion: v1
kind: ServiceAccount
metadata:
  name: tempo
  namespace: tracing
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/tempo-service-role
```

### Step 5: Jaeger Security Configuration

Jaeger's collector, query service, and storage backend each present separate attack surfaces.

**Jaeger Collector authentication:** The Jaeger Collector accepts spans over gRPC or HTTP. In a pipeline where the OTel Collector forwards to Jaeger (rather than Tempo), the Jaeger Collector should not be directly reachable by application pods. Route all span ingestion through the OTel Collector, which handles authentication as described in Step 2. The Jaeger Collector is then a cluster-internal receiver that only the OTel Collector communicates with:

```yaml
# NetworkPolicy: only the OTel Collector may send spans to Jaeger Collector.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: jaeger-collector-ingress
  namespace: tracing
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: jaeger
      app.kubernetes.io/component: collector
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: otel-collector
      ports:
        - port: 14250   # Jaeger gRPC.
          protocol: TCP
        - port: 14268   # Jaeger HTTP (Thrift).
          protocol: TCP
    # No other ingress sources permitted.
```

**Jaeger Query service behind an authenticating proxy:** The Jaeger Query HTTP API and UI must not be exposed without authentication:

```yaml
# Jaeger Query Deployment with OAuth2-proxy sidecar.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: jaeger-query
  namespace: tracing
spec:
  template:
    spec:
      containers:
        - name: jaeger-query
          image: jaegertracing/jaeger-query:1.55.0
          args:
            - --query.base-path=/jaeger
            # Disable the in-process HTTP server for the health check;
            # health should be served on a non-public port.
            - --admin.http.host-port=:14269
          ports:
            - name: query-http
              containerPort: 16686

        - name: oauth2-proxy
          image: quay.io/oauth2-proxy/oauth2-proxy:v7.6.0
          args:
            - --upstream=http://localhost:16686
            - --http-address=0.0.0.0:4180
            - --provider=oidc
            - --oidc-issuer-url=https://company.okta.com/oauth2/default
            - --client-id=$(OIDC_CLIENT_ID)
            - --client-secret=$(OIDC_CLIENT_SECRET)
            - --cookie-secret=$(COOKIE_SECRET)
            - --email-domain=example.com
            - --allowed-group=observability-platform
            - --skip-provider-button=true
          ports:
            - containerPort: 4180
```

```yaml
# Ingress: route to oauth2-proxy port, not Jaeger native port.
# Restrict by source IP to internal networks only.
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: jaeger-query
  namespace: tracing
  annotations:
    nginx.ingress.kubernetes.io/whitelist-source-range: "10.0.0.0/8,172.16.0.0/12"
spec:
  ingressClassName: nginx
  rules:
    - host: jaeger.internal.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: jaeger-query
                port:
                  number: 4180   # OAuth2-proxy port.
  tls:
    - hosts:
        - jaeger.internal.example.com
      secretName: jaeger-tls
```

Jaeger's query API does not natively support tenant isolation. In a multi-tenant deployment, either run one Jaeger instance per tenant or use Tempo (which does support multi-tenancy via the `X-Scope-OrgID` model) and access Jaeger traces through Grafana's unified Tempo datasource.

### Step 6: Tail-Based Sampling to Preserve Security-Relevant Traces

Tail-based sampling makes sampling decisions after the full trace has been assembled. This ensures that security-relevant traces — authentication failures, slow requests that may indicate timing attacks, requests to sensitive endpoints — are always retained, while high-volume benign traffic is sampled aggressively.

```yaml
# OTel Collector: tail sampling before export to Tempo/Jaeger.
processors:
  tail_sampling:
    decision_wait: 15s       # Wait 15 seconds for all spans to arrive.
    num_traces: 50000        # Maximum in-flight traces before forced eviction.
    expected_new_traces_per_sec: 1000

    policies:
      # Retain all error traces unconditionally.
      - name: retain-errors
        type: status_code
        status_code:
          status_codes: [ERROR]

      # Retain slow traces (>2s) — may indicate timing attacks or abuse.
      - name: retain-slow
        type: latency
        latency:
          threshold_ms: 2000

      # Retain traces touching authentication endpoints.
      - name: retain-auth
        type: string_attribute
        string_attribute:
          key: http.target
          values: ["/auth/", "/login", "/token", "/oauth", "/api/keys"]
          enabled_regex_matching: true
          invert_match: false

      # Retain traces with suspicious attribute patterns.
      # A span attribute set by security middleware when anomalies are detected.
      - name: retain-security-flagged
        type: string_attribute
        string_attribute:
          key: security.event
          values: [".*"]
          enabled_regex_matching: true

      # Sample 0.5% of remaining healthy fast traces.
      - name: sample-baseline
        type: probabilistic
        probabilistic:
          sampling_percentage: 0.5
```

The sampling configuration above ensures that the traces most likely to be needed during incident response are always retained, while the storage cost of baseline healthy traffic is reduced by 99.5%.

### Step 7: Trace Data Retention and the Right-to-Erasure Problem

Append-only object storage creates a compliance challenge for GDPR and similar right-to-erasure obligations. Tempo writes trace data as immutable compressed blocks; individual span attributes cannot be deleted without deleting the entire block.

The practical answer is prevention, not remediation: if PII never enters trace storage, there is no erasure obligation to fulfill. The scrubbing pipeline in Step 1 is therefore not optional from a compliance perspective.

Configure Tempo's compactor for automatic block deletion after the retention period:

```yaml
# tempo.yaml — compactor retention.
compactor:
  compaction:
    # Delete blocks older than this duration.
    block_retention: 168h    # 7 days for standard traces.
    # For environments with stricter retention requirements, reduce to 72h or 48h.
    # Compliance traces (if needed for audit) should go to a separate pipeline
    # with different retention — not to the same Tempo instance as operational traces.

    # Compacted blocks (post-merge) also respect retention.
    compacted_block_retention: 1h
```

For environments with per-user deletion obligations, enforce a data minimisation policy at ingestion time:

1. No raw user identifiers in span attributes — hash at the Collector (Step 1).
2. No PII in `http.url`, `http.target`, or `db.statement` — scrub at the Collector (Step 1).
3. Short retention (7 days or less) for operational traces containing any user-correlated data.
4. If a user makes an erasure request, verify that the scrubbing pipeline was active during their usage period. If it was, there is no raw PII to delete.

For situations where a misconfigured service emitted PII before the scrubbing pipeline was deployed, the only mitigation in Tempo is to delete the affected blocks. Identify the time range of the misconfigured period and use the Tempo API to force-compact and delete those blocks:

```bash
# Identify blocks covering the affected time range.
curl -s http://tempo.tracing.svc:3200/api/search/tags \
  | jq '.tagNames[]'

# List blocks in the compactor's object storage path.
aws s3 ls s3://tempo-traces-prod/ --recursive \
  | grep "^2026-03-"   # Affected month.

# Delete specific blocks (irreversible — test first).
# Tempo will re-read the block list from object storage on restart.
aws s3 rm s3://tempo-traces-prod/tenant-id/block-uuid/ --recursive
```

### Step 8: Cross-Tenant Trace Correlation Risks in Service Mesh Environments

In a service mesh (Istio, Linkerd), every pod-to-pod request generates a span. When requests cross tenant namespace boundaries — a shared API gateway calling into tenant-specific services, for example — the trace spans those boundaries. The resulting trace contains spans from services belonging to different tenants.

This creates a cross-tenant information disclosure path: if Tenant A's service makes a call to the shared gateway, the trace may contain spans from the gateway that reveal information about requests from Tenant B if they share the same trace ID propagation context.

Controls:

```yaml
# Istio: terminate trace context at namespace boundaries.
# Use a VirtualService to strip trace headers on cross-namespace traffic.
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: gateway-ingress-tenant-a
  namespace: tenant-a
spec:
  hosts:
    - shared-gateway.platform.svc.cluster.local
  http:
    - headers:
        request:
          remove:
            - traceparent    # W3C Trace Context.
            - tracestate
            - x-b3-traceid   # B3 propagation.
            - x-b3-spanid
            - x-b3-sampled
      route:
        - destination:
            host: shared-gateway.platform.svc.cluster.local
```

Removing trace context headers at the tenant boundary causes the gateway to start a new trace for each cross-boundary request. The gateway's trace and the tenant's trace are no longer linked, preventing correlation.

In Tempo's multi-tenant model, assign the OTel Collector or sidecar to a specific tenant ID so that spans from Tenant A's services are stored under Tenant A's partition only. The shared gateway should write its spans to the platform tenant partition, not to any specific tenant.

## Expected Behaviour

| Signal | Default deployment | Hardened deployment |
|--------|-------------------|---------------------|
| Email address in `http.target` span | Stored verbatim in Tempo/Jaeger | Replaced with `[EMAIL-REDACTED]` at Collector |
| SQL parameter values in `db.statement` | Full values stored | Replaced with `?` placeholders at Collector |
| Jaeger UI access | No authentication | SSO login required; group membership enforced |
| Tempo query for another tenant's traces | Possible with any `X-Scope-OrgID` | Tenant ID injected by auth proxy; caller cannot override |
| Tempo S3 blocks | Unencrypted; accessible to IAM principals in account | KMS-encrypted; access limited to Tempo service role |
| OTLP endpoint accepts spans from any pod | Yes — unauthenticated | JWT authentication required; network policy restricts source pods |
| Cross-namespace trace correlation | Full traces cross tenant boundaries | Trace context headers stripped at tenant boundary |
| Traces retained after retention period | Indefinitely (no retention configured) | Compactor deletes blocks after 7 days |

## Telemetry

```
# Scrubbing pipeline effectiveness.
otelcol_processor_redaction_processed_spans_total{processor}    counter
otelcol_processor_redaction_masked_attributes_total{processor}  counter

# Tempo backend health.
tempo_ingester_traces_created_total{tenant}                     counter
tempo_compactor_blocks_deleted_total                            counter
tempo_storage_bytes_used_total{tenant}                          gauge

# Authentication events.
oauth2_proxy_requests_total{status}                             counter
oauth2_proxy_authentication_failures_total                      counter

# Sampling decisions.
otelcol_processor_tail_sampling_sampling_decision_timer_bucket  histogram
otelcol_processor_tail_sampling_count_traces_sampled_total      counter
```

Alert on:

- `tempo_storage_bytes_used_total` growing past retention threshold — compaction may not be running, traces accumulating beyond policy.
- `oauth2_proxy_authentication_failures_total` spike — potential brute-force against the trace query UI.
- `otelcol_processor_redaction_masked_attributes_total` drops to zero — scrubbing pipeline may be misconfigured or bypassed.
- Any direct access to Tempo or Jaeger native ports (port 3200 or 16686) from outside the pod — OAuth2-proxy may have been bypassed.

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Hashed user IDs | Supports cross-trace correlation without storing raw PII | Hash is one-way; operators must compute the hash to query by user | Store the hash-to-user mapping in a separate, access-controlled lookup table for incident investigation |
| Short retention (7 days) | Limits PII exposure window; reduces erasure complexity | Historical trace analysis beyond 7 days is not possible | Archive anonymised aggregates (RED metrics, error counts, latency percentiles) to Prometheus long-term storage |
| Tenant-boundary trace context stripping | Prevents cross-tenant correlation via shared gateway | Breaks distributed trace continuity across boundaries | Generate a synthetic correlation ID that is shared without being a W3C trace context header; used for operational correlation only |
| Per-tenant KMS key | Breach of one tenant's key does not expose other tenants | Higher KMS key management overhead | Use AWS KMS multi-region keys for DR; automate key rotation via Terraform |
| Tail sampling for security-critical traces | Error and auth traces always retained | Requires sufficient Collector memory to buffer in-flight traces | Size Collector memory to `num_traces × average_trace_size_bytes`; monitor OOM events |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Scrubbing processor misconfigured | PII appears in stored traces | Nightly scan of sampled spans for PII patterns; alert on any match | Fix Collector config; existing affected blocks cannot be retroactively scrubbed — delete if retention policy allows |
| OAuth2-proxy credential rotation failure | Jaeger/Tempo UI inaccessible; 401 errors | oauth2-proxy health check failure; alert on 5xx rate | Rotate the `OIDC_CLIENT_SECRET` and restart the proxy pod; automate rotation with an External Secrets Operator pattern |
| Tempo compactor not running | Storage grows past retention period | `tempo_compactor_blocks_deleted_total` at zero for >24h | Restart compactor pod; verify object storage permissions for the service role include `s3:DeleteObject` |
| OTLP JWT expiry | Application spans rejected; trace coverage drops to zero | `otelcol_receiver_refused_spans_total` spike; alert on spike | Rotate the service account token; verify the Kubernetes token automounting is enabled and not near the 24h expiry |
| Cross-tenant trace pollution | Tenant A can query Tenant B's spans | Test query using wrong tenant ID from authenticated session; should return 403 | Verify auth proxy correctly extracts and sets `X-Scope-OrgID` from the validated OIDC claim; do not allow callers to set this header directly |
| KMS key revoked or deleted | Tempo cannot read or write blocks | Tempo errors on all block operations; storage completely unavailable | Restore key from KMS backup; use key aliases to enable transparent rotation without changing Tempo config |

## Related Articles

- [OpenTelemetry Collector Hardening](/articles/observability/otel-collector-hardening/)
- [OpenTelemetry PII Leakage Prevention](/articles/observability/otel-pii-leakage/)
- [OpenTelemetry Tail-Based Sampling for Security-Critical Traces](/articles/observability/otel-tail-sampling-security/)
- [Distributed Tracing Security: Span Data Scrubbing](/articles/observability/distributed-tracing-security/)
- [Grafana Security Hardening](/articles/observability/grafana-security-hardening/)
- [Securing Multi-Tenant Prometheus with Thanos](/articles/observability/thanos-prometheus-multitenancy-security/)
