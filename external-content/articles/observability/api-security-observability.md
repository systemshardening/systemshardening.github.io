---
title: "API Traffic Security Observability: Monitoring API Behaviour for Security Threats"
description: "API gateways aggregate traffic statistics, but security threats live in per-caller behaviour over time: brute-force patterns across auth failures, scanning behaviour in parameter variation, data dump signatures in response sizes. This article builds a security observability layer on top of API traffic using OpenTelemetry, Prometheus, and Elasticsearch to surface what gateway dashboards hide."
slug: api-security-observability
date: 2026-05-07
lastmod: 2026-05-07
category: observability
tags:
  - api-security
  - api-monitoring
  - rate-limiting
  - anomaly-detection
  - opentelemetry
personas:
  - security-engineer
  - platform-engineer
article_number: 548
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/observability/api-security-observability/
---

# API Traffic Security Observability: Monitoring API Behaviour for Security Threats

## Problem

An API gateway publishes excellent aggregate metrics: total request volume, p99 latency, 4xx rates, upstream health. What it does not show is that a single authenticated API key is responsible for 94% of this hour's 401 responses, that one client has sequentially varied the `account_id` parameter through 8,000 values in the past ten minutes, or that the `GET /export` endpoint returned 2.3 GB to one caller in a burst that lasted four minutes before stopping.

The distinction matters. Aggregate gateway metrics are operational signals — they tell you the system is degraded. Per-caller behavioural signals are security signals — they tell you someone is probing, enumerating, or exfiltrating. A gateway dashboard will not fire a page when a legitimate API key starts doing something illegitimate. Security observability has to be built on top of the operational layer, not instead of it.

Common blind spots:

- **Authentication failure attribution.** `http_requests_total{status="401"}` tells you your 401 rate is elevated. It does not tell you which API key, IP, or user is responsible. Brute-force and credential-stuffing activity is invisible without per-client attribution.
- **Request pattern analysis.** Scanning behaviour — an attacker systematically iterating through resource IDs or parameter values — looks like normal traffic in aggregate. The signal is the sequential pattern within a caller's session, not the overall volume.
- **Response size distribution.** A single large response from `GET /reports` may be normal. Three hundred consecutive large responses from the same API key in a two-minute window is a data exfiltration pattern. Aggregate response byte metrics lose the per-caller temporal correlation.
- **Error rate per endpoint.** An attacker probing for SQL injection will generate a burst of 500 responses from a specific endpoint. Aggregate error rate masks which endpoint and which caller.
- **API key rotation anomalies.** When an API key is rotated, the new key often exhibits identical behavioural fingerprints to the old one immediately — same request patterns, same endpoints, same timing — because the operator is the same. A compromised key rotation, by contrast, shows different behavioural fingerprints.

**Target systems:** APIs fronted by Nginx, Envoy, or an API gateway (Kong, AWS API Gateway); applications instrumented with OpenTelemetry SDKs; Prometheus for metrics; Elasticsearch for log-based detection; distributed tracing backends (Jaeger, Grafana Tempo).

## Threat Model

- **Adversary 1 — Credential brute-force via API:** An attacker iterates through username and password combinations against `POST /auth/login` at 20 requests per second from a rotating IP pool. Each IP sends only 15 requests — below a naive per-IP threshold. Per-endpoint 401 rate analysis detects the burst; per-client attribution is masked by IP rotation, so the detection must be endpoint-level.
- **Adversary 2 — IDOR enumeration:** An authenticated attacker uses their valid API key to iterate `GET /users/{id}` from id=1 to id=100,000. Each request is authorised. The signal is sequential parameter variation from a single credential, not authentication failure.
- **Adversary 3 — Data exfiltration via large export endpoint:** A compromised API key calls `GET /data/export?format=full` repeatedly during a maintenance window. Total response bytes from that key in one hour exceed 10 GB. The anomaly is response volume per authenticated identity, not request count.
- **Adversary 4 — Injection probing:** An attacker sends a burst of malformed requests to `POST /query` with varying payload structures, looking for SQL or NoSQL injection responses. The signal is error rate spike on a specific endpoint combined with unusual request body sizes.
- **Adversary 5 — API key abuse after rotation:** A developer's API key is compromised and rotated. The attacker has the old key and immediately requests a new key using a stolen refresh token. The new key shows identical behavioural patterns to the compromised key within minutes of issuance — behaviour that the legitimate developer would not exhibit (they are unaware of the compromise).
- **Access level:** Adversaries 1 and 4 are unauthenticated. Adversaries 2, 3, and 5 are authenticated with valid credentials.
- **Objective:** Credential access, data exfiltration, injection vulnerabilities, privilege escalation.
- **Blast radius:** Undetected IDOR enumeration exposes the full user database. Undetected export exfiltration means a complete data dump; detection after the fact has no remediation.

## Configuration

### Step 1: OpenTelemetry Span Attributes for Security Telemetry

Standard OTel HTTP instrumentation captures method, URL, and status code. Security telemetry requires additional per-request attributes that enable per-caller aggregation.

```python
# Python/FastAPI: enrich spans with security-relevant attributes.
from opentelemetry import trace
from opentelemetry.semconv.trace import SpanAttributes
import time

tracer = trace.get_tracer(__name__)

async def api_security_middleware(request: Request, call_next):
    span = trace.get_current_span()

    # Auth identity — the caller, not the user being acted on.
    api_key_id = request.headers.get("X-API-Key-ID", "anonymous")
    authenticated_user = getattr(request.state, "user_id", None)
    auth_method = request.headers.get("X-Auth-Method", "none")

    # Request sizing.
    content_length = request.headers.get("Content-Length", "0")

    span.set_attributes({
        # Caller identity — critical for per-client aggregation.
        "api.key.id": api_key_id,               # Opaque key ID, not the key itself.
        "auth.user.id": authenticated_user or "unauthenticated",
        "auth.method": auth_method,              # bearer, api_key, basic, none.

        # Request shape — used for scanning detection.
        "http.request.body.size": int(content_length),
        "api.endpoint.template": request.scope.get("route", {}).path,
        # /users/{id} not /users/12345 — normalised for aggregation.
    })

    start = time.monotonic()
    response = await call_next(request)
    duration_ms = (time.monotonic() - start) * 1000

    # Post-response attributes.
    span.set_attributes({
        "http.response.body.size": int(response.headers.get("Content-Length", "0")),
        "auth.result": "success" if response.status_code < 400 else (
            "auth_failure" if response.status_code in (401, 403) else "error"
        ),
        "api.request.duration_ms": duration_ms,
    })

    return response
```

```go
// Go: equivalent span enrichment for gin/echo handlers.
func SecuritySpanMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        span := trace.SpanFromContext(c.Request.Context())

        apiKeyID := c.GetHeader("X-API-Key-ID")
        if apiKeyID == "" {
            apiKeyID = "anonymous"
        }

        span.SetAttributes(
            attribute.String("api.key.id", apiKeyID),
            attribute.String("auth.user.id", c.GetString("user_id")),
            attribute.String("api.endpoint.template", c.FullPath()),
            attribute.Int("http.request.body.size", int(c.Request.ContentLength)),
        )

        c.Next()

        span.SetAttributes(
            attribute.Int("http.response.status_code", c.Writer.Status()),
            attribute.Int("http.response.body.size", c.Writer.Size()),
            attribute.String("auth.result", authResult(c.Writer.Status())),
        )
    }
}
```

### Step 2: Nginx and Envoy Security Log Fields

Structured access logs are the highest-volume security data source. These fields must be present for log-based detection.

```nginx
# nginx.conf — structured JSON access log with security fields.
log_format security_json escape=json
  '{'
    '"timestamp":"$time_iso8601",'
    '"remote_addr":"$remote_addr",'
    '"method":"$request_method",'
    '"uri":"$uri",'                          # Normalised URI, not full request.
    '"status":$status,'
    '"request_length":$request_length,'
    '"bytes_sent":$bytes_sent,'
    '"body_bytes_sent":$body_bytes_sent,'
    '"upstream_response_time":"$upstream_response_time",'
    '"http_x_api_key_id":"$http_x_api_key_id",'    # API key ID (not key value).
    '"http_x_forwarded_for":"$http_x_forwarded_for",'
    '"http_user_agent":"$http_user_agent",'
    '"request_time":$request_time'
  '}';

access_log /var/log/nginx/api_access.log security_json;
```

```yaml
# Envoy: access log with security fields via JSON formatter.
access_log:
  - name: envoy.access_loggers.stdout
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
      log_format:
        json_format:
          timestamp: "%START_TIME%"
          method: "%REQ(:METHOD)%"
          path: "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%"
          response_code: "%RESPONSE_CODE%"
          # Response bytes — key for data exfiltration detection.
          bytes_sent: "%BYTES_SENT%"
          bytes_received: "%BYTES_RECEIVED%"
          # Upstream timing — abnormal upstream latency signals heavy queries.
          upstream_response_time: "%RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)%"
          # Caller identity.
          api_key_id: "%REQ(X-API-KEY-ID)%"
          authenticated_user: "%DYNAMIC_METADATA(envoy.filters.http.jwt_authn:sub)%"
          request_id: "%REQ(X-REQUEST-ID)%"
```

### Step 3: Prometheus Security SLIs for API Traffic

These recording rules and alerts provide the per-caller metrics that aggregate gateway dashboards omit.

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: api-security-slis
  namespace: monitoring
spec:
  groups:
    - name: api_security
      interval: 30s
      rules:

        # Recording rule: auth failure rate per API key (brute-force signal).
        - record: security:api_auth_failures:rate5m
          expr: >
            sum by (api_key_id, endpoint_template) (
              rate(http_requests_total{
                auth_result=~"auth_failure"
              }[5m])
            )

        # Alert: single API key generating high 401/403 rate (credential abuse).
        - alert: APIKeyHighAuthFailureRate
          expr: security:api_auth_failures:rate5m > 0.2
          for: 3m
          labels:
            severity: warning
          annotations:
            summary: "API key {{ $labels.api_key_id }} generating high auth failures on {{ $labels.endpoint_template }}"
            description: "{{ $value | humanize }} auth failures/sec. Investigate key misuse or brute-force."
            runbook_url: "https://systemshardening.com/runbooks/api-key-auth-failure"

        # Alert: unusual request volume per authenticated user (enumeration signal).
        - alert: APIKeyAbnormalRequestVolume
          expr: >
            (
              rate(http_requests_total[5m]) by (api_key_id)
            )
            >
            5 * (
              avg_over_time(rate(http_requests_total[5m]) by (api_key_id)[1d:5m])
            )
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "API key {{ $labels.api_key_id }} request volume is 5x above its 24h baseline"
            description: "Current rate: {{ $value | humanize }}/sec. Check for scanning or automation abuse."

        # Recording rule: response bytes per caller (data exfiltration signal).
        - record: security:api_response_bytes:rate5m
          expr: >
            sum by (api_key_id, endpoint_template) (
              rate(http_response_bytes_total[5m])
            )

        # Alert: single key transferring abnormal response volume.
        - alert: APIKeyHighResponseVolume
          expr: security:api_response_bytes:rate5m > 10e6   # >10 MB/s from one key.
          for: 2m
          labels:
            severity: critical
          annotations:
            summary: "API key {{ $labels.api_key_id }} transferring >10 MB/s from {{ $labels.endpoint_template }}"
            description: "Possible data exfiltration. Rate: {{ $value | humanize }} bytes/sec."

        # Alert: error rate spike on specific endpoint (injection probing).
        - alert: APIEndpointErrorSpike
          expr: >
            rate(http_requests_total{status=~"5.."}[5m]) by (endpoint_template)
            > 3 * avg_over_time(
              rate(http_requests_total{status=~"5.."}[5m]) by (endpoint_template)[24h:5m]
            )
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "Error rate spike on {{ $labels.endpoint_template }}"
            description: "Current 5xx rate is 3x above 24h baseline. Check for injection probing."
```

### Step 4: Elasticsearch Detection Rules for Per-Caller Behaviour

Prometheus aggregates by label cardinality constraints. Elasticsearch handles arbitrary per-caller queries. These scripted metric queries implement the detection rules that Prometheus cannot.

```json
// Elasticsearch: scripted metric for per-user 401/403 rate over 5 minutes.
// POST /api-access-logs-*/_search
{
  "size": 0,
  "query": {
    "range": {
      "timestamp": { "gte": "now-5m" }
    }
  },
  "aggs": {
    "per_api_key": {
      "terms": {
        "field": "http_x_api_key_id.keyword",
        "size": 1000,
        "min_doc_count": 5
      },
      "aggs": {
        "auth_failures": {
          "filter": {
            "terms": { "status": [401, 403] }
          }
        },
        "auth_failure_rate": {
          "bucket_script": {
            "buckets_path": {
              "failures": "auth_failures._count",
              "total": "_count"
            },
            "script": "params.failures / params.total"
          }
        },
        "high_failure_rate_flag": {
          "bucket_selector": {
            "buckets_path": {
              "rate": "auth_failure_rate"
            },
            "script": "params.rate > 0.5"   // Flag keys where >50% of requests fail auth.
          }
        }
      }
    }
  }
}
```

```json
// Elasticsearch: scanning detection via parameter variation analysis.
// Detects sequential numeric parameter iteration (IDOR enumeration).
// POST /api-access-logs-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        { "range": { "timestamp": { "gte": "now-10m" } } },
        { "term": { "status": 200 } }
      ]
    }
  },
  "aggs": {
    "per_api_key": {
      "terms": {
        "field": "http_x_api_key_id.keyword",
        "size": 500
      },
      "aggs": {
        "unique_uris": {
          "cardinality": {
            "field": "uri.keyword"
          }
        },
        "request_count": {
          "value_count": {
            "field": "uri.keyword"
          }
        },
        "high_cardinality_scanner": {
          "bucket_selector": {
            "buckets_path": {
              "unique": "unique_uris",
              "total": "request_count"
            },
            // High unique URI ratio + volume = parameter scanning.
            "script": "params.unique > 500 && (params.unique / params.total) > 0.8"
          }
        }
      }
    }
  }
}
```

```python
# Python: Elasticsearch Watcher alert — trigger on scanning behaviour.
# Deploy as a Watcher job running every 10 minutes.
watcher_body = {
    "trigger": {
        "schedule": {"interval": "10m"}
    },
    "input": {
        "search": {
            "request": {
                "indices": ["api-access-logs-*"],
                "body": {
                    # Insert the scanning detection query from above.
                }
            }
        }
    },
    "condition": {
        # Fire if any bucket survives the bucket_selector (scanner detected).
        "compare": {
            "ctx.payload.aggregations.per_api_key.buckets": {
                "not_eq": []
            }
        }
    },
    "actions": {
        "notify_security": {
            "webhook": {
                "method": "POST",
                "url": "https://security-alerting.internal/api/alert",
                "body": '{"type": "api_scanning", "keys": "{{ctx.payload.aggregations.per_api_key.buckets}}"}'
            }
        }
    }
}
```

### Step 5: Distributed Tracing for Multi-Service Attack Path Reconstruction

When an attacker pivots through multiple services, individual service logs show fragments of the attack. Distributed traces show the full path with timing and attribution.

```python
# Add security context to trace propagation so cross-service attack paths
# can be reconstructed from a single trace ID.

from opentelemetry.baggage import set_baggage
from opentelemetry.propagate import inject

def propagate_security_context(headers: dict, request_context: dict) -> dict:
    """Inject security context into outbound headers for downstream attribution."""
    # Propagate caller identity across service boundaries.
    # Downstream services see the original API key, not the calling service.
    ctx = set_baggage("api.key.id", request_context.get("api_key_id", ""))
    ctx = set_baggage("auth.user.id", request_context.get("user_id", ""), context=ctx)
    # Original client IP (before load balancer).
    ctx = set_baggage("client.original_ip", request_context.get("real_ip", ""), context=ctx)

    inject(headers, context=ctx)
    return headers
```

```yaml
# OTel Collector: extract baggage attributes into span attributes for backend storage.
# This makes security context queryable in Jaeger/Tempo.
processors:
  transform/security-context:
    trace_statements:
      - context: span
        statements:
          # Promote baggage to span attributes for queryability.
          - set(attributes["api.key.id"], baggage["api.key.id"])
            where baggage["api.key.id"] != nil
          - set(attributes["auth.user.id"], baggage["auth.user.id"])
            where baggage["auth.user.id"] != nil
          - set(attributes["client.original_ip"], baggage["client.original_ip"])
            where baggage["client.original_ip"] != nil

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [transform/security-context, batch]
      exporters: [otlphttp/tempo]
```

To reconstruct an attack path across services, query Tempo by the `api.key.id` attribute:

```bash
# Tempo TraceQL: find all traces from a suspicious API key across all services.
# This reconstructs the full attack path even when services are unaware of each other.
{span.api.key.id = "key-suspicious-abc123"}
| select(span.service.name, span.http.method, span.http.target,
         span.auth.result, span.http.response.body.size)
```

### Step 6: API Key Rotation Anomaly Detection

After a legitimate rotation, the new key exhibits a warm-up period: the operator reconnects, re-authenticates, and resumes their normal usage pattern over minutes to hours. A compromised key rotation shows the attacker's pattern immediately on the new key.

```python
# Behavioural fingerprinting for API key rotation detection.
# Run as a scheduled job (every 15 minutes) comparing new keys against baselines.

import json
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta

es = Elasticsearch("https://elasticsearch.internal:9200")

def get_key_behaviour_fingerprint(api_key_id: str, window_minutes: int = 15) -> dict:
    """Compute a behavioural fingerprint for an API key over a recent window."""
    result = es.search(
        index="api-access-logs-*",
        body={
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"http_x_api_key_id.keyword": api_key_id}},
                        {"range": {"timestamp": {"gte": f"now-{window_minutes}m"}}}
                    ]
                }
            },
            "aggs": {
                "top_endpoints": {
                    "terms": {"field": "uri.keyword", "size": 10}
                },
                "avg_request_size": {"avg": {"field": "request_length"}},
                "avg_response_size": {"avg": {"field": "bytes_sent"}},
                "unique_ips": {"cardinality": {"field": "remote_addr.keyword"}},
                # Request timing distribution — unique per operator.
                "request_intervals": {
                    "percentiles": {
                        "field": "request_time",
                        "percents": [50, 90, 99]
                    }
                }
            }
        }
    )

    aggs = result["aggregations"]
    return {
        "top_endpoints": [b["key"] for b in aggs["top_endpoints"]["buckets"]],
        "avg_request_size": aggs["avg_request_size"]["value"],
        "avg_response_size": aggs["avg_response_size"]["value"],
        "unique_ips": aggs["unique_ips"]["value"],
        "p50_interval": aggs["request_intervals"]["values"]["50.0"],
    }


def detect_rotation_anomaly(old_key_id: str, new_key_id: str) -> bool:
    """
    Return True if the new key exhibits suspicious behavioural similarity
    to the old key immediately after rotation.

    Legitimate: new key has zero traffic for minutes, then gradual warm-up.
    Suspicious: new key immediately shows same fingerprint as old key.
    """
    new_fp = get_key_behaviour_fingerprint(new_key_id, window_minutes=15)

    if new_fp["unique_ips"] == 0:
        return False  # New key not yet in use — normal.

    old_fp = get_key_behaviour_fingerprint(old_key_id, window_minutes=60)

    # Check if new key is hitting same endpoints immediately.
    endpoint_overlap = len(
        set(new_fp["top_endpoints"]) & set(old_fp["top_endpoints"])
    ) / max(len(old_fp["top_endpoints"]), 1)

    # Immediate high overlap on a brand-new key is suspicious.
    if endpoint_overlap > 0.8 and new_fp["unique_ips"] > 1:
        return True  # Flag for investigation.

    return False
```

### Step 7: Security Observability Telemetry

```
# Metrics to expose from the security observability layer.

# Per-caller request and failure rates.
http_requests_total{api_key_id, endpoint_template, status, auth_result}     counter
http_response_bytes_total{api_key_id, endpoint_template}                    counter
auth_failures_total{api_key_id, endpoint_template, failure_type}            counter

# Scanning detection metrics (emitted by detection job).
api_scanning_events_total{api_key_id, detection_method}                     counter
api_rotation_anomalies_total{new_key_id, old_key_id}                        counter

# Instrumentation health.
otel_spans_without_key_id_total{service}                                    counter  # Should be 0.
api_log_fields_missing_total{field, service}                                counter  # Should be 0.
```

Alert on:

- `auth_failures_total` rate per `api_key_id` exceeding 0.2/sec for 3 minutes — single key generating auth failures; investigate brute-force or misconfigured client.
- `http_response_bytes_total` rate per `api_key_id` exceeding 10 MB/s for 2 minutes — possible data exfiltration; revoke key pending investigation.
- `api_scanning_events_total` increment — scanning behaviour detected; correlate with `api_key_id` and review recent traces.
- `otel_spans_without_key_id_total` non-zero — a service is not injecting caller identity into spans; security observability blind spot.

## Expected Behaviour

| Signal | Without security observability | With security observability |
|--------|-------------------------------|----------------------------|
| Brute-force against `/auth/login` | 401 rate spike in gateway dashboard; no attribution | Alert fires within 3 min with `api_key_id` or IP attribution |
| IDOR enumeration via valid key | Normal 200 traffic in gateway metrics | Elasticsearch scanner alert: high URI cardinality from one key |
| Data exfiltration via export endpoint | Elevated bytes_sent in aggregate | `APIKeyHighResponseVolume` alert with `api_key_id` |
| Injection probing on `/query` | 5xx spike — no endpoint specificity | `APIEndpointErrorSpike` alert with endpoint template |
| Compromised key used after rotation | No signal — valid key, valid requests | Rotation anomaly detection flags immediate endpoint overlap |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Per-`api_key_id` Prometheus labels | Enables per-caller alerting | High cardinality — can OOM Prometheus at scale | Use recording rules to pre-aggregate; cap label cardinality with relabelling; use VictoriaMetrics or Thanos for high-cardinality environments |
| Span enrichment with `api.key.id` | Full attack path reconstruction in traces | Slightly higher span payload size | Key IDs are short opaque strings; overhead is negligible |
| Elasticsearch scripted metrics | Arbitrary per-caller queries | Higher query latency than Prometheus; requires Elasticsearch | Run on a schedule (every 10 min), not real-time; use for detection, not dashboards |
| Behavioural fingerprinting | Detects compromised rotation | Requires baseline history; false positives during legitimate usage changes | Gate on minimum traffic threshold; flag for human review, not automated block |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Services not injecting `api_key_id` into spans | Security alerts have no caller attribution; all show "anonymous" | `otel_spans_without_key_id_total` non-zero | Fix middleware instrumentation in affected services; verify with test request |
| Prometheus cardinality explosion from per-key labels | Prometheus OOM; slow queries; scrape target down | Prometheus memory growth; `up == 0` for prometheus | Aggregate key labels to key prefix or tier; drop high-cardinality labels in relabelling |
| Elasticsearch index lag under load | Scanning detection delayed beyond attack window | Elasticsearch indexing latency rising; watcher execution delayed | Increase Elasticsearch indexing buffer; reduce watcher query scope; add dedicated index for security logs |
| Rotation anomaly job produces false positives | Security team alert fatigue from legitimate key rotations | High `api_rotation_anomalies_total` rate during known rotation events | Add suppression window during planned rotations; tune endpoint overlap threshold per key tier |
| Access log fields missing from Nginx/Envoy | `api_log_fields_missing_total` non-zero; log-based detection blind | Periodic log field validation job; metric alert | Update log format configuration; redeploy; verify with sample log analysis |

## Related Articles

- [Distributed Tracing Security: Jaeger, Tempo, and Sensitive Span Data Scrubbing](/articles/observability/distributed-tracing-security/)
- [Security-Relevant Prometheus Metrics: What to Collect, How to Alert, When to Page](/articles/observability/prometheus-security-metrics/)
- [OpenTelemetry Collector Hardening](/articles/observability/otel-collector-hardening/)
- [Application Security Logging](/articles/observability/application-security-logging/)
- [Detection Rules: Alert Design for Security Events](/articles/observability/detection-rules/)
