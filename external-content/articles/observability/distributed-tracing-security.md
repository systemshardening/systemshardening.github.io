---
title: "Distributed Tracing Security: Jaeger, Tempo, and Sensitive Span Data Scrubbing"
description: "Distributed traces capture the full execution path of a request across services — including HTTP headers, query parameters, and error payloads that may contain PII, authentication tokens, or internal system details. Securing the tracing pipeline requires data scrubbing at collection, access controls on trace storage, and sampling policies that limit exposure."
slug: "distributed-tracing-security"
date: 2026-05-01
lastmod: 2026-05-01
category: "observability"
tags: ["jaeger", "tempo", "tracing", "opentelemetry", "pii", "span-scrubbing"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 315
difficulty: "intermediate"
estimated_reading_time: 12
published: true
layout: article.njk
permalink: "/articles/observability/distributed-tracing-security/index.html"
---

# Distributed Tracing Security: Jaeger, Tempo, and Sensitive Span Data Scrubbing

## Problem

Distributed tracing captures the full execution graph of requests flowing through a system. A trace for a user login request may include the HTTP request URL, headers (potentially including `Authorization` or session cookies), query parameters (potentially including email or username), database queries, and error messages with stack traces. This data is invaluable for debugging and performance analysis — and a significant security and compliance risk if not handled carefully.

Common problems:

- **Authentication tokens in trace attributes.** OpenTelemetry auto-instrumentation captures HTTP request headers as span attributes by default. If `Authorization: Bearer <token>` is captured and stored in Jaeger or Tempo, anyone with trace read access has access to valid user tokens.
- **PII in URL paths and query parameters.** URLs like `/api/users/alice@example.com/profile` or `/search?email=alice@example.com` are captured as `http.url` or `http.target` span attributes. Traces become a PII database.
- **Database queries with sensitive values.** SQL spans often capture the full query text including parameter values if the instrumentation library is misconfigured. `SELECT * FROM users WHERE password = 'plaintext'` appearing in a trace span is a significant security event.
- **Traces accessible without authentication.** Jaeger's UI and API, and Tempo's HTTP API, may be deployed without authentication — accessible to any user in the cluster or on the internal network. All traces, including those with the above data, are readable.
- **Trace IDs in user-facing error messages.** Exposing trace IDs to end users allows them to look up their own traces in the tracing backend — revealing internal service architecture, database query patterns, and other system internals.
- **No retention policy on trace storage.** Traces accumulate indefinitely. A trace from six months ago containing a valid session token in a span attribute is still readable.

**Target systems:** Jaeger 1.55+ (all-in-one and distributed); Grafana Tempo 2.4+; OpenTelemetry Collector as the tracing pipeline; OTLP protocol; Kubernetes-deployed tracing infrastructure.

## Threat Model

- **Adversary 1 — Session token extraction from traces:** A developer with access to the Jaeger UI queries traces for the `/api/login` endpoint. They find span attributes containing `Authorization: Bearer sk-prod-abc123`. They use the token to authenticate as the user whose request was traced.
- **Adversary 2 — PII exfiltration from trace database:** An attacker with read access to the Tempo object storage backend downloads trace data. The traces contain email addresses, phone numbers, and user IDs in span attributes, constituting a GDPR-reportable data breach.
- **Adversary 3 — Internal architecture reconnaissance via traces:** An analyst with Jaeger UI access maps the full internal service graph by querying traces across all services. They identify internal endpoints, database schemas from query spans, and service dependency patterns — intelligence for a subsequent attack.
- **Adversary 4 — Trace injection for false evidence:** An attacker injects forged trace data into the tracing pipeline (via an unauthenticated OTLP endpoint), creating fake spans that implicate legitimate services in activity they did not perform.
- **Adversary 5 — SQL injection via span attribute logging:** The tracing library logs the full SQL query including parameters. An attacker who can read traces sees that parameter binding is not used: `WHERE username='alice'` — confirming the application is vulnerable to SQL injection.
- **Access level:** Adversaries 1 and 3 have internal read access. Adversary 2 needs backend storage access. Adversary 4 needs access to the OTLP ingestion endpoint. Adversary 5 needs trace read access.
- **Objective:** Extract credentials and PII from traces; map internal architecture; inject false audit evidence.
- **Blast radius:** Unscrubbable traces in a system processing authentication requests expose every session token captured during the retention period.

## Configuration

### Step 1: OpenTelemetry Collector Scrubbing Pipeline

The OTel Collector is the right place to scrub sensitive data — centrally, before it reaches the backend:

```yaml
# otel-collector-config.yaml — span attribute scrubbing.
processors:
  # Transform processor: redact sensitive span attributes.
  transform/scrub-sensitive:
    trace_statements:
      - context: span
        statements:
          # Redact Authorization header.
          - set(attributes["http.request.header.authorization"], "[REDACTED]")
            where attributes["http.request.header.authorization"] != nil

          # Redact Cookie header.
          - set(attributes["http.request.header.cookie"], "[REDACTED]")
            where attributes["http.request.header.cookie"] != nil

          # Redact Set-Cookie response header.
          - set(attributes["http.response.header.set-cookie"], "[REDACTED]")
            where attributes["http.response.header.set-cookie"] != nil

          # Scrub common PII patterns from URL attributes.
          # Redact email addresses in http.url and http.target.
          - replace_pattern(attributes["http.url"],
              "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
              "[EMAIL-REDACTED]")
          - replace_pattern(attributes["http.target"],
              "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
              "[EMAIL-REDACTED]")

          # Redact db.statement parameter values (keep query structure, not values).
          # This replaces quoted string values in SQL.
          - replace_pattern(attributes["db.statement"],
              "'[^']*'",
              "'[REDACTED]'")
          # Replace numeric parameters.
          - replace_pattern(attributes["db.statement"],
              "= [0-9]+",
              "= [REDACTED]")

  # Attribute filter: drop entire attributes that should never be in traces.
  attributes/drop-sensitive:
    actions:
      - key: "http.request.header.x-api-key"
        action: delete
      - key: "http.request.header.x-auth-token"
        action: delete
      - key: "exception.message"
        action: update
        # Keep exception type; scrub message (may contain PII).
        # Use transform processor for regex scrubbing on exception messages.

  # Tail sampling: only keep traces that are interesting.
  tail_sampling:
    decision_wait: 10s
    policies:
      # Always keep error traces.
      - name: errors
        type: status_code
        status_code: {status_codes: [ERROR]}
      # Always keep slow traces (>1s).
      - name: slow
        type: latency
        latency: {threshold_ms: 1000}
      # Sample 1% of successful fast traces.
      - name: sample-successful
        type: probabilistic
        probabilistic: {sampling_percentage: 1}

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors:
        [transform/scrub-sensitive, attributes/drop-sensitive, tail_sampling]
      exporters: [otlphttp/tempo]
```

### Step 2: Jaeger Authentication and Access Control

```yaml
# Jaeger with OAuth2 Proxy for SSO-gated access.
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
          ports:
            - containerPort: 16686  # UI/API.

        # OAuth2 Proxy sidecar: enforce SSO.
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
            - --skip-provider-button=true
          ports:
            - containerPort: 4180
```

```yaml
# Expose Jaeger only through authenticated proxy.
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: jaeger
  namespace: tracing
  annotations:
    nginx.ingress.kubernetes.io/whitelist-source-range: "10.0.0.0/8"
spec:
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
                  number: 4180   # OAuth2 Proxy port, not Jaeger direct.
```

### Step 3: Grafana Tempo Security

```yaml
# tempo-config.yaml — authentication for Tempo HTTP API.
http_api_prefix: ""
server:
  http_listen_port: 3200
  grpc_listen_port: 9095

# Multi-tenant: require tenant ID in headers.
multitenancy_enabled: true
# Clients must send X-Scope-OrgID header.
# Access control enforced by authentication gateway.

# Storage: S3 with encryption.
storage:
  trace:
    backend: s3
    s3:
      bucket: tempo-traces-prod
      endpoint: s3.amazonaws.com
      region: us-east-1
      sse_type: KMS                         # Server-side encryption with KMS.
      sse_kms_key_id: arn:aws:kms:...:key/...

# Retention: delete traces older than 7 days.
compactor:
  compaction:
    block_retention: 168h   # 7 days.
```

### Step 4: OTLP Endpoint Authentication

The OTLP endpoint that receives traces from applications should require authentication:

```yaml
# OTel Collector: require authenticated OTLP submissions.
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
        auth:
          authenticator: bearertoken   # Require Bearer token from services.
      http:
        endpoint: 0.0.0.0:4318
        auth:
          authenticator: bearertoken

extensions:
  bearertoken:
    scheme: Bearer
    # Tokens are validated against this JWKS endpoint.
    # Services authenticate using their Kubernetes service account OIDC token.
    jwks_file: /etc/otel/jwks.json

service:
  extensions: [bearertoken]
```

```yaml
# NetworkPolicy: only allow pods to reach OTel Collector on OTLP port.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: otel-collector-access
  namespace: tracing
spec:
  podSelector:
    matchLabels:
      app: otel-collector
  policyTypes:
    - Ingress
  ingress:
    # All pods can send traces (OTLP).
    - ports:
        - port: 4317
          protocol: TCP
        - port: 4318
          protocol: TCP
    # Prometheus can scrape metrics.
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
      ports:
        - port: 8888
```

### Step 5: Instrumentation Library Configuration

Configure the OTel SDK in applications to avoid capturing sensitive data at the source:

```python
# Python: configure OTel to sanitise HTTP headers before exporting.
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry import trace

# Exclude sensitive headers from automatic capture.
FastAPIInstrumentor.instrument_app(
    app,
    tracer_provider=tracer_provider,
    excluded_urls=".*/(health|ready|metrics)",  # Don't trace health checks.
    http_capture_headers_server_request=[
        # ALLOWLIST: only capture these headers; block all others.
        "content-type",
        "x-request-id",
        "user-agent",
        # NOT: authorization, cookie, x-api-key.
    ],
    http_capture_headers_server_response=[
        "content-type",
        # NOT: set-cookie.
    ],
)
```

```go
// Go: configure HTTP span capture to exclude sensitive headers.
import (
    "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
    semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

handler := otelhttp.NewHandler(mux, "server",
    otelhttp.WithSpanOptions(
        // Do not record request body or response body.
        trace.WithAttributes(),
    ),
    // Custom filter: don't start spans for health check endpoints.
    otelhttp.WithFilter(func(r *http.Request) bool {
        return r.URL.Path != "/health" && r.URL.Path != "/ready"
    }),
)
```

### Step 6: Trace ID Handling

```python
# Never expose trace IDs in user-facing error responses.
# BAD: returning trace ID allows users to query internal traces.
@app.exception_handler(Exception)
async def generic_error_handler(request, exc):
    trace_id = trace.get_current_span().get_span_context().trace_id
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            # "trace_id": f"{trace_id:032x}"  # Do NOT expose.
        }
    )

# GOOD: return a support reference (opaque to the user; maps to trace in internal tooling).
import secrets
@app.exception_handler(Exception)
async def generic_error_handler(request, exc):
    support_ref = secrets.token_hex(8)   # Opaque reference.
    # Map support_ref to trace_id in structured log (not in response).
    logger.error("internal_error", support_ref=support_ref, exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "reference": support_ref}
    )
```

### Step 7: Retention and Deletion Policy

```bash
# Tempo: configure compactor for automatic deletion after retention period.
# tempo-config.yaml
compactor:
  compaction:
    block_retention: 168h    # 7 days for standard traces.
    # Compliance: some regulated environments require 0-day retention for PII traces.

# For GDPR right-to-erasure: traces containing user PII cannot be individually deleted
# from Tempo (it's append-only compressed blocks).
# Architecture requirement: do NOT store PII in traces — scrub at collection time.
# This is why the scrubbing pipeline in Step 1 is non-optional.
```

### Step 8: Telemetry

```
otel_collector_spans_received_total{service, status}           counter
otel_collector_spans_dropped_total{reason}                     counter
otel_collector_pii_redactions_total{attribute, pattern}        counter
tempo_query_duration_seconds{status}                           histogram
tempo_storage_bytes{tenant}                                    gauge
jaeger_query_requests_total{result, type}                      counter
tracing_sensitive_attribute_count{service, attribute}          gauge  # Should be 0.
```

Alert on:

- `tracing_sensitive_attribute_count` non-zero — a service is emitting sensitive attributes that the scrubbing pipeline missed; investigate instrumentation configuration.
- `otel_collector_spans_dropped_total` non-zero — the scrubbing pipeline is dropping spans due to errors; check collector logs.
- Unauthenticated access to Jaeger/Tempo API (from audit log) — someone bypassed the OAuth2 proxy.
- Trace storage exceeding retention threshold — compaction may be failing; traces are accumulating.

## Expected Behaviour

| Signal | Unscrubbbed tracing | Scrubbbed tracing |
|--------|--------------------|--------------------|
| Authorization header in span | Token visible in Jaeger UI | Header replaced with [REDACTED] in collector |
| Email address in URL | PII stored in trace backend | Email replaced with [EMAIL-REDACTED] |
| SQL query with parameter values | Full query values in span | Parameter values replaced with [REDACTED] |
| Unauthenticated Jaeger access | Any internal user reads all traces | SSO required; only members of allowed group |
| Trace ID in error response | Users can query their own traces | Support reference instead; trace ID not exposed |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Aggressive span scrubbing | PII never reaches trace backend | Debugging becomes harder (less context) | Keep sanitised exception types; add structured non-PII context to spans |
| Tail sampling (1%) | Reduces storage; limits PII exposure | Miss some errors in the 99% | Always-sample errors and slow traces; sample healthy fast traces |
| OTel Collector authentication | Prevents trace injection | Services must obtain and present tokens | Use Kubernetes service account OIDC tokens; no additional management |
| Short retention (7 days) | Limits PII exposure window | Historical analysis limited | Archive anonymised aggregates (counts, latencies) for long-term analysis |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Scrubbing transform misconfigured | Sensitive attributes still appear in traces | Periodic audit of sample traces for PII | Fix transform configuration; old traces cannot be retroactively scrubbed |
| OAuth2 proxy certificate expired | Jaeger UI inaccessible | Proxy TLS error; cert expiry alert | Renew certificate; cert-manager handles this automatically |
| Collector drops spans under load | Trace coverage gaps during traffic spikes | `otel_collector_spans_dropped_total` spike | Increase collector resources; add horizontal scaling |
| Tempo retention not enforced | Old traces accumulate | Storage size growing past retention period | Restart compactor; verify compaction configuration |

## Related Articles

- [OpenTelemetry Collector Hardening](/articles/observability/otel-collector-hardening/)
- [OpenTelemetry PII Leakage Prevention](/articles/observability/otel-pii-leakage/)
- [Loki Security Hardening](/articles/observability/loki-security-hardening/)
- [Grafana Security Hardening](/articles/observability/grafana-security-hardening/)
- [Application Security Logging](/articles/observability/application-security-logging/)
