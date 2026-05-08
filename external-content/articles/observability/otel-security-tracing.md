---
title: "OpenTelemetry for Security: Distributed Tracing of Authentication and Authorization Flows"
description: "Distributed tracing is standard for performance debugging, but almost no team uses it for security."
slug: "otel-security-tracing"
date: 2026-04-09
lastmod: 2026-04-09
category: "observability"
tags: ["opentelemetry", "tracing", "authentication", "security-monitoring", "observability"]
personas: ["sre", "security-engineer"]
article_number: 68
difficulty: "advanced"
estimated_reading_time: 16
provider_bridges:
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
  - name: "Axiom"
    id: 112
    category: "observability"
  - name: "SigNoz"
    id: 117
    category: "observability"
premium_pack: "otel-security-dashboards"
published: true
layout: article.njk
permalink: "/articles/observability/otel-security-tracing/index.html"
---

# [OpenTelemetry](https://opentelemetry.io) for Security: Distributed Tracing of Authentication and Authorization Flows

## Problem

Distributed tracing is standard for performance debugging, but almost no team uses it for security. Authentication flows that span multiple services (identity provider to API gateway to backend to database) are invisible without end-to-end tracing. When a credential stuffing attack hits your login endpoint, you see elevated error rates in metrics, but you cannot trace a single malicious request through every hop it touches.

The specific gaps:

- **Auth failures are logged, not traced.** A failed login generates a log line. But you cannot see which downstream services were contacted during the failed attempt, how long each step took, or whether the request triggered any side effects.
- **Latency anomalies in auth flows go unnoticed.** Brute force attacks cause elevated P99 latency on auth endpoints. Without tracing, you cannot distinguish between a slow database query and 10,000 concurrent credential stuffing requests.
- **Authorization decisions are scattered.** A user requests access to a resource. The API gateway checks the JWT, the backend checks RBAC, the database checks row-level security. If any step fails, the context is lost. You see a 403 but not which authorization layer rejected the request or why.
- **Cross-service correlation requires trace context.** When a suspicious request hits service A and you want to see what happened in service B, you need a trace ID that propagates across service boundaries. Without OTel instrumentation, each service is an island.

This article instruments auth flows with OpenTelemetry spans, configures the OTel Collector for security-relevant span filtering, and builds detection rules from trace data.

**Target systems:** Any application instrumented with OpenTelemetry SDK (Go, Python, Java, Node.js). OTel Collector for pipeline processing. [Prometheus](https://prometheus.io) and [Grafana](https://grafana.com) for derived metrics.

## Threat Model

- **Adversary:** An attacker performing credential stuffing, brute force, or session hijacking against authentication endpoints. They may also exploit authorization bypass vulnerabilities to access resources they should not reach.
- **Blast radius:** Without auth flow tracing, you detect attacks only through aggregate metrics (elevated error rates) with no request-level visibility. Investigation requires correlating logs across 3-5 services manually. With tracing, a single trace ID shows the complete attack path through every service hop.

## Configuration

### Instrumenting Auth Flows with OTel Spans

Add security-relevant attributes to authentication and authorization spans:

```python
# Python example using OpenTelemetry SDK.
# Instrument the login handler to create a span with security attributes.
from opentelemetry import trace
from opentelemetry.trace import StatusCode

tracer = trace.get_tracer("auth-service")

def login_handler(request):
    with tracer.start_as_current_span("auth.login") as span:
        # Tag every auth span with security-relevant attributes.
        span.set_attribute("auth.method", "password")
        span.set_attribute("auth.username", request.username)
        span.set_attribute("net.peer.ip", request.client_ip)
        span.set_attribute("auth.user_agent", request.headers.get("User-Agent", ""))

        # Token validation as a child span.
        with tracer.start_as_current_span("auth.token_validate") as token_span:
            token = validate_credentials(request.username, request.password)
            if token is None:
                span.set_attribute("auth.result", "failure")
                span.set_attribute("auth.failure_reason", "invalid_credentials")
                span.set_status(StatusCode.ERROR, "Authentication failed")
                return Response(status=401)
            token_span.set_attribute("auth.token_type", "jwt")

        # Permission check as another child span.
        with tracer.start_as_current_span("auth.permission_check") as perm_span:
            permissions = check_permissions(token.user_id, request.resource)
            perm_span.set_attribute("auth.permissions_granted", len(permissions))
            perm_span.set_attribute("auth.resource", request.resource)

        span.set_attribute("auth.result", "success")
        return Response(status=200, body={"token": token.value})
```

```go
// Go example: authorization middleware with OTel spans.
func AuthorizationMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        ctx, span := tracer.Start(r.Context(), "auth.authorize",
            trace.WithAttributes(
                attribute.String("auth.method", "bearer"),
                attribute.String("net.peer.ip", r.RemoteAddr),
                attribute.String("http.target", r.URL.Path),
            ),
        )
        defer span.End()

        claims, err := validateJWT(r.Header.Get("Authorization"))
        if err != nil {
            span.SetAttributes(
                attribute.String("auth.result", "failure"),
                attribute.String("auth.failure_reason", err.Error()),
            )
            span.SetStatus(codes.Error, "Authorization failed")
            http.Error(w, "Unauthorized", 401)
            return
        }

        span.SetAttributes(
            attribute.String("auth.result", "success"),
            attribute.String("auth.subject", claims.Subject),
            attribute.StringSlice("auth.roles", claims.Roles),
        )
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

### OTel Collector Configuration

Filter and process security-relevant spans before export:

```yaml
# otel-collector-config.yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

processors:
  # Filter: keep only auth-related spans for the security pipeline.
  filter/security:
    spans:
      include:
        match_type: regexp
        span_names:
          - "auth\\..*"
          - ".*login.*"
          - ".*authorize.*"
          - ".*permission.*"

  # Add cluster metadata to all spans.
  resource:
    attributes:
      - key: k8s.cluster.name
        value: "production"
        action: upsert

  # Generate metrics from span data (RED metrics for auth flows).
  spanmetrics:
    metrics_exporter: prometheus
    dimensions:
      - name: auth.result
      - name: auth.method
      - name: auth.failure_reason
      - name: net.peer.ip
    histogram:
      explicit:
        boundaries: [10ms, 50ms, 100ms, 250ms, 500ms, 1s, 5s]

  # Tail sampling: keep 100% of failed auth traces, 10% of successful.
  tail_sampling:
    decision_wait: 10s
    policies:
      - name: auth-failures-always
        type: string_attribute
        string_attribute:
          key: auth.result
          values: ["failure"]
      - name: high-latency-auth
        type: latency
        latency:
          threshold_ms: 1000
      - name: sample-success
        type: probabilistic
        probabilistic:
          sampling_percentage: 10

exporters:
  otlp/tempo:
    endpoint: "tempo.monitoring:4317"
    tls:
      insecure: false
      ca_file: /etc/ssl/certs/ca.pem

  prometheus:
    endpoint: "0.0.0.0:8889"
    namespace: "otel_security"

service:
  pipelines:
    traces/security:
      receivers: [otlp]
      processors: [filter/security, resource, tail_sampling]
      exporters: [otlp/tempo]
    metrics/security:
      receivers: [otlp]
      processors: [filter/security, spanmetrics]
      exporters: [prometheus]
```

### Detection Rules from Trace-Derived Metrics

The spanmetrics processor generates Prometheus metrics from auth spans:

```yaml
# Prometheus alerting rules based on OTel-derived auth metrics.
groups:
  - name: otel-auth-security
    rules:
      # Brute force detection: auth failure rate from a single IP.
      - alert: BruteForceFromTraces
        expr: >
          sum by (net_peer_ip) (
            rate(otel_security_calls_total{
              span_name=~"auth\\.login",
              auth_result="failure"
            }[5m])
          ) > 0.5
        for: 2m
        labels:
          severity: warning
          detection_type: brute_force
        annotations:
          summary: >
            Brute force detected from {{ $labels.net_peer_ip }}:
            {{ $value | humanize }} failed auths/sec
          runbook_url: "https://systemshardening.com/runbooks/brute-force"

      # Auth latency anomaly: P99 > 2x baseline indicates load from attack.
      - alert: AuthLatencyAnomaly
        expr: >
          histogram_quantile(0.99,
            rate(otel_security_duration_bucket{
              span_name=~"auth\\..*"
            }[5m])
          ) > 2 * histogram_quantile(0.99,
            avg_over_time(
              rate(otel_security_duration_bucket{
                span_name=~"auth\\..*"
              }[5m])[7d:5m]
            )
          )
        for: 5m
        labels:
          severity: warning
          detection_type: auth_anomaly
        annotations:
          summary: "Auth P99 latency is 2x above baseline: {{ $value | humanizeDuration }}"

      # Credential stuffing: many unique usernames failing from same IP range.
      - alert: CredentialStuffing
        expr: >
          count by (net_peer_ip) (
            count by (net_peer_ip, auth_username) (
              rate(otel_security_calls_total{
                auth_result="failure"
              }[10m]) > 0
            )
          ) > 20
        for: 5m
        labels:
          severity: critical
          detection_type: credential_stuffing
        annotations:
          summary: >
            Credential stuffing: {{ $labels.net_peer_ip }} tried
            {{ $value }} unique usernames in 10 minutes

      # Authorization bypass attempt: successful auth followed by
      # excessive 403 responses (probing for accessible resources).
      - alert: AuthorizationProbing
        expr: >
          sum by (auth_subject) (
            rate(otel_security_calls_total{
              span_name="auth.authorize",
              auth_result="failure"
            }[10m])
          ) > 0.1
          and
          sum by (auth_subject) (
            rate(otel_security_calls_total{
              span_name="auth.authorize",
              auth_result="success"
            }[10m])
          ) > 0
        for: 5m
        labels:
          severity: warning
          detection_type: authz_probing
        annotations:
          summary: >
            Authorization probing: {{ $labels.auth_subject }}
            is authenticated but hitting excessive 403s
```

### Security Dashboard Queries

```promql
# Grafana dashboard panels for auth security.

# Panel 1: Auth failure rate by source IP (top 10).
topk(10,
  sum by (net_peer_ip) (
    rate(otel_security_calls_total{auth_result="failure"}[5m])
  )
)

# Panel 2: Auth success/failure ratio over time.
sum(rate(otel_security_calls_total{auth_result="success"}[5m]))
/
sum(rate(otel_security_calls_total[5m]))

# Panel 3: P99 auth latency by span name.
histogram_quantile(0.99,
  sum by (le, span_name) (
    rate(otel_security_duration_bucket[5m])
  )
)

# Panel 4: Unique usernames per source IP (credential stuffing indicator).
count by (net_peer_ip) (
  count by (net_peer_ip, auth_username) (
    otel_security_calls_total{auth_result="failure"}
  )
)
```

## Expected Behaviour

- Every authentication attempt (success and failure) produces a trace with security attributes
- Authorization decisions are visible as child spans within the request trace
- Failed auth traces retained at 100%; successful auth traces sampled at 10%
- Brute force attacks detected within 2 minutes via trace-derived metrics
- Credential stuffing (many unique usernames from one source) detected within 5 minutes
- Auth P99 latency anomalies (2x above baseline) trigger alerts within 5 minutes
- Trace IDs in log entries enable single-click pivot from alert to full request trace

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| Tail sampling (100% failures, 10% success) | 90% storage reduction for auth traces | May miss slow-burn attacks that succeed on each attempt | Keep 100% of traces with unusual attributes (new user-agent, new geo). Sample only routine successes. |
| Spanmetrics processor for Prometheus export | Enables alerting without querying trace backend | High-cardinality attributes (username, IP) cause metric explosion | Limit dimensions to IP and result. Use trace queries for username-level investigation. |
| Security-only filter in Collector | Reduces trace pipeline volume by 80-90% | Non-auth security events (data access, admin actions) not traced | Add additional span name patterns as security instrumentation grows. |
| Username in span attributes | Enables per-user attack analysis | PII in trace data may violate data retention policies | Hash usernames before setting span attribute if PII compliance requires it. Set TTL on trace storage. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| OTel Collector down | No new traces or metrics; alerts stop firing | `up{job="otel-collector"}` goes to 0 | Deploy Collector as a DaemonSet or with replicas. SDKs buffer spans locally during outage. |
| Tail sampling drops attack traces | Investigation finds no trace for a known attack timestamp | Post-incident: search for trace ID from logs, trace not found in backend | Increase decision_wait. Add explicit keep policy for high-severity attributes. |
| Spanmetrics cardinality explosion | Prometheus OOM or slow queries; Collector memory spikes | Collector memory usage exceeds 80%; Prometheus scrape duration increases | Remove high-cardinality dimensions (username). Aggregate IPs to /24 subnets. |
| Trace context not propagated | Auth spans appear as separate traces per service, not connected | Traces show single-span roots instead of multi-service chains | Verify W3C Trace Context headers propagated through load balancers and API gateways. Check SDK auto-instrumentation configuration. |
| SDK instrumentation missing in one service | Gap in trace chain; auth flow incomplete | Trace visualization shows a missing hop between services | Audit all services in the auth path for OTel SDK initialization. Use auto-instrumentation agents where manual instrumentation is missing. |

## When to Consider a Managed Alternative

Self-managed OTel security tracing requires Collector deployment, SDK instrumentation across all auth services, span storage backend, and metric pipeline maintenance (6-10 hours/month).

- **[Grafana Cloud](https://grafana.com/cloud):** Managed Tempo for traces, Mimir for metrics, [Loki](https://grafana.com/oss/loki/) for logs. Unified view across all three signals. Native OTel Collector support with managed scaling.
- **[Axiom](https://axiom.co):** Unified observability platform. Traces, metrics, and logs in one backend. Native OTel ingestion. No cardinality limits on trace attributes.
- **[SigNoz](https://signoz.io):** OTel-native observability platform. Built specifically for OpenTelemetry data. Integrated trace-to-metric derivation without separate spanmetrics configuration.

**Premium content pack:** OTel security dashboard collection. Pre-built Grafana dashboards for auth flow analysis, brute force detection, and credential stuffing visualization. Includes OTel Collector configs and SDK instrumentation examples for Go, Python, Java, and Node.js.


## Related Articles

- [Building a Security Audit Log Pipeline That Scales: auditd to Elasticsearch](/articles/observability/audit-log-pipeline/)
- [Kubernetes Audit Log Pipeline Design: From API Server to SIEM](/articles/observability/k8s-audit-log-design/)
- [Security Dashboards That Engineers Actually Use: Grafana Designs for Hardening Verification](/articles/observability/security-dashboards/)
- [Centralized Logging Architecture for Security: Fluentd, Vector, and Loki Compared](/articles/observability/centralized-logging/)
- [Lateral Movement Detection: Network Patterns, Authentication Anomalies, and Alert Correlation](/articles/observability/lateral-movement-detection/)
