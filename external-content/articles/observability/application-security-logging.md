---
title: "Application Security Logging: Structured Events, PII Redaction, and SIEM Integration"
description: "Application logs are the primary source of authentication, authorisation, and API activity signals. Most applications log too little for security, or too much PII. Structured security events fix both."
slug: "application-security-logging"
date: 2026-04-30
lastmod: 2026-04-30
category: "observability"
tags: ["logging", "siem", "pii", "security-events", "structured-logging"]
personas: ["security-engineer", "sre", "platform-engineer"]
article_number: 259
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/observability/application-security-logging/index.html"
---

# Application Security Logging: Structured Events, PII Redaction, and SIEM Integration

## Problem

Application logs are the record of what your system did, to whom, and with what result. In a security incident, they answer: which account was accessed, when did the attacker authenticate, what data did they read, and which API calls preceded the breach.

Most application logging is built for debugging, not security:

- **Authentication events log the wrong fields.** A successful login logs `"User logged in"` with no username, IP, or session ID. A failed login logs nothing, or logs the attempted username in plaintext — useful for debugging, but not for SIEM correlation.
- **Authorisation decisions are unlogged.** When a user is denied access to a resource, the event is silently dropped. An attacker probing access controls leaves no trace.
- **PII leaks into logs.** Request bodies containing credit card numbers, SSNs, or passwords are logged verbatim. These logs are stored in SIEM systems, S3 buckets, and shipped to third-party log aggregators — each an exposure point.
- **No correlation ID across services.** A user action that touches five microservices produces five unconnected log entries. Reconstructing the full request path during an incident requires hours of manual correlation.
- **Log levels swallow security events.** Security-relevant events (auth failures, privilege escalation, data exports) are logged at DEBUG or INFO and purged after 7 days. The attacker's activity is gone before the investigation starts.

**Target systems:** Any application producing logs; structuring applies equally to Go, Python, Node.js, Java; SIEM targets: Elasticsearch/OpenSearch, Splunk, Google Chronicle, Datadog. Specific examples use Go's `slog`, Python's `structlog`, and OpenTelemetry log exporter.

## Threat Model

- **Adversary 1 — Credential stuffing:** An attacker attempts thousands of username/password combinations against the login endpoint. Without per-IP failed-auth logging, the attack is invisible until accounts are compromised.
- **Adversary 2 — IDOR (Insecure Direct Object Reference):** An attacker increments a user ID in API calls to read other users' data. Without logging which user ID was accessed alongside the requesting user ID, the probe is undetectable in logs.
- **Adversary 3 — Privilege escalation:** An attacker with a low-privilege account calls an admin API endpoint. Without logging the denied authorisation decision with the caller's identity, the probe is invisible.
- **Adversary 4 — Data exfiltration:** An attacker with legitimate API access exports large volumes of records. Without logging response sizes and record counts, bulk export is indistinguishable from normal usage.
- **Adversary 5 — Log injection:** An attacker submits input containing newlines or JSON-breaking characters to manipulate structured log output and forge false entries. Structured logging with proper escaping prevents this.
- **Access level:** Adversaries 1 and 2 have API access. Adversary 3 has authenticated user access. Adversary 4 has legitimate but over-scoped API access. Adversary 5 controls input to a logged field.
- **Objective:** Exfiltrate data without detection, probe access controls without generating alerts, cover tracks by manipulating logs.
- **Blast radius:** Without security-grade application logging, an attacker has a wide window to probe, escalate, and exfiltrate with no trace in the logs. With structured security events, every significant action creates an auditable record correlated to a session and user identity.

## Configuration

### Step 1: Define the Security Event Schema

Agree on a schema for all security-relevant events before writing any code. Every event must carry:

```json
{
  "timestamp": "2026-04-30T12:34:56.789Z",
  "level": "INFO",
  "event_type": "auth.login.success",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "span_id": "00f067aa0ba902b7",
  "service": "payments-api",
  "version": "v2.3.1",
  "user_id": "usr_abc123",
  "session_id": "sess_xyz789",
  "ip": "203.0.113.42",
  "user_agent": "Mozilla/5.0 ...",
  "result": "success",
  "duration_ms": 45
}
```

Event type taxonomy (use dot-separated hierarchical names for SIEM filtering):

```
auth.login.success
auth.login.failure
auth.logout
auth.mfa.challenge.success
auth.mfa.challenge.failure
auth.password.reset.requested
auth.session.expired

authz.access.granted
authz.access.denied
authz.role.assigned
authz.role.removed

data.read           # record count and resource type
data.write
data.delete
data.export         # bulk operations; include record count

api.rate_limit.exceeded
api.input.validation.failure

admin.user.created
admin.user.suspended
admin.config.changed
```

### Step 2: Instrument Authentication Events (Go/slog)

```go
package security

import (
    "context"
    "log/slog"
    "net/http"
    "time"
)

type SecurityLogger struct {
    logger *slog.Logger
}

func (s *SecurityLogger) LogAuthEvent(ctx context.Context, r *http.Request, eventType string, attrs ...slog.Attr) {
    args := []any{
        slog.String("event_type", eventType),
        slog.String("trace_id", traceIDFromContext(ctx)),
        slog.String("span_id", spanIDFromContext(ctx)),
        slog.String("ip", clientIP(r)),
        slog.String("user_agent", r.Header.Get("User-Agent")),
        slog.String("method", r.Method),
        slog.String("path", r.URL.Path),
        slog.Time("timestamp", time.Now().UTC()),
    }
    for _, a := range attrs {
        args = append(args, a)
    }
    // Always use WARN or higher for security events; they must survive log retention filters.
    s.logger.LogAttrs(ctx, slog.LevelWarn, "security_event", args...)
}

// Usage in auth handler:
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
    start := time.Now()
    username := r.FormValue("username")   // Validated; not logged directly.
    userID, err := h.authenticate(r)

    if err != nil {
        h.security.LogAuthEvent(r.Context(), r, "auth.login.failure",
            slog.String("result", "failure"),
            slog.String("reason", classifyAuthError(err)),   // "invalid_password", "account_locked", etc.
            slog.String("user_id_hash", hashUserID(username)),   // Hashed, not plaintext.
            slog.Duration("duration", time.Since(start)),
        )
        // Return generic error to client; specific reason only in logs.
        http.Error(w, "Authentication failed", http.StatusUnauthorized)
        return
    }

    h.security.LogAuthEvent(r.Context(), r, "auth.login.success",
        slog.String("result", "success"),
        slog.String("user_id", userID),
        slog.String("session_id", sessionID),
        slog.Duration("duration", time.Since(start)),
    )
}
```

### Step 3: Instrument Authorisation Events (Python/structlog)

```python
import structlog
import functools
from typing import Callable

security_log = structlog.get_logger("security")

def require_permission(permission: str):
    """Decorator that logs authorisation decisions for every protected endpoint."""
    def decorator(fn: Callable):
        @functools.wraps(fn)
        def wrapper(request, *args, **kwargs):
            user = request.user
            resource_id = kwargs.get("id") or kwargs.get("resource_id")

            if not user.has_permission(permission):
                security_log.warning(
                    "authz.access.denied",
                    user_id=user.id,
                    permission=permission,
                    resource_id=resource_id,
                    resource_type=fn.__name__,
                    ip=get_client_ip(request),
                    trace_id=request.headers.get("X-Trace-ID"),
                    result="denied",
                )
                raise PermissionDenied()

            result = fn(request, *args, **kwargs)

            security_log.info(
                "authz.access.granted",
                user_id=user.id,
                permission=permission,
                resource_id=resource_id,
                resource_type=fn.__name__,
                trace_id=request.headers.get("X-Trace-ID"),
                result="granted",
            )
            return result
        return wrapper
    return decorator

# Usage:
@require_permission("payments:read")
def get_payment(request, payment_id: str):
    payment = Payment.objects.get(id=payment_id, owner=request.user)
    security_log.info(
        "data.read",
        user_id=request.user.id,
        resource_type="payment",
        resource_id=payment_id,
        record_count=1,
        trace_id=request.headers.get("X-Trace-ID"),
    )
    return payment
```

Log bulk data access with record counts (detects exfiltration):

```python
def export_payments(request):
    queryset = Payment.objects.filter(owner=request.user)
    count = queryset.count()

    security_log.warning(
        "data.export",
        user_id=request.user.id,
        resource_type="payment",
        record_count=count,
        filter_params=safe_filter_repr(request.GET),   # Sanitised, not raw query string.
        trace_id=request.headers.get("X-Trace-ID"),
        result="success" if count <= MAX_EXPORT else "blocked",
    )

    if count > MAX_EXPORT:
        raise PermissionDenied("Export limit exceeded")

    return queryset
```

### Step 4: PII Redaction Before Logging

Never log raw PII. Redact at the point of log creation, not post-hoc:

```python
import hashlib, re

CARD_PATTERN = re.compile(r'\b(?:\d{4}[\s-]?){3}\d{4}\b')
SSN_PATTERN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

def redact_pii(value: str) -> str:
    """Replace known PII patterns with redaction markers."""
    value = CARD_PATTERN.sub('[CARD_REDACTED]', value)
    value = SSN_PATTERN.sub('[SSN_REDACTED]', value)
    value = EMAIL_PATTERN.sub('[EMAIL_REDACTED]', value)
    return value

def hash_user_identifier(identifier: str, salt: str) -> str:
    """Pseudonymise user identifiers for logging. Same input always produces
    the same hash — sufficient for correlation without storing plaintext."""
    return hashlib.sha256(f"{salt}:{identifier}".encode()).hexdigest()[:16]

# structlog processor to automatically redact PII from all log messages.
def pii_redact_processor(logger, method, event_dict):
    for key in ["message", "error", "query", "input"]:
        if key in event_dict and isinstance(event_dict[key], str):
            event_dict[key] = redact_pii(event_dict[key])
    return event_dict

structlog.configure(
    processors=[
        pii_redact_processor,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
```

Fields that must never be logged in plaintext:

- Passwords or password hashes
- Full credit card numbers (last 4 digits only)
- SSNs, national ID numbers
- Full email addresses (use hashed version for correlation)
- API keys and tokens (log key ID, not value)
- Authentication cookies or session tokens

### Step 5: Correlation IDs Across Microservices

Every request must carry a trace ID that flows through all service calls:

```go
// Middleware: inject a trace ID on every incoming request if not present.
func TraceMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        traceID := r.Header.Get("X-Trace-ID")
        if traceID == "" {
            traceID = generateTraceID()
        }
        // Forward to downstream services.
        r.Header.Set("X-Trace-ID", traceID)
        // Add to context for log extraction.
        ctx := context.WithValue(r.Context(), traceIDKey, traceID)
        // Add to response so clients can reference it.
        w.Header().Set("X-Trace-ID", traceID)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

Use OpenTelemetry trace context (W3C `traceparent` header) for interoperability:

```go
import "go.opentelemetry.io/otel/propagation"

// Extract trace context from incoming request.
ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
// Inject into outgoing requests to downstream services.
otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))
```

### Step 6: Ship to SIEM with Retention Tiers

Security events must be retained longer than debug logs:

```yaml
# Filebeat/Vector pipeline: separate security events from debug logs.
vector:
  sources:
    app_logs:
      type: file
      include: ["/var/log/app/*.json"]

  transforms:
    security_events:
      type: filter
      inputs: [app_logs]
      condition: .level == "WARN" || .level == "ERROR" || .event_type != null

    debug_logs:
      type: filter
      inputs: [app_logs]
      condition: .level == "DEBUG" || .level == "INFO"

  sinks:
    siem:
      type: elasticsearch
      inputs: [security_events]
      endpoint: https://siem.internal:9200
      index: security-events-%Y.%m.%d
      # Retention: 365 days via ILM.

    debug_store:
      type: s3
      inputs: [debug_logs]
      bucket: app-debug-logs
      # Retention: 14 days via S3 lifecycle.
```

Set minimum log level for security events to `WARN` so they survive log-level filtering:

```go
// Security events always log at WARN regardless of the application's log level setting.
s.logger.LogAttrs(ctx, slog.LevelWarn, "security_event", ...)
```

### Step 7: SIEM Alert Rules

With structured events in the SIEM, write precise alert queries:

```
# Elasticsearch: credential stuffing detection.
# Alert if more than 10 auth.login.failure events from the same IP in 5 minutes.
{
  "query": {
    "bool": {
      "must": [
        {"term": {"event_type": "auth.login.failure"}},
        {"range": {"@timestamp": {"gte": "now-5m"}}}
      ]
    }
  },
  "aggs": {
    "by_ip": {
      "terms": {"field": "ip", "min_doc_count": 10}
    }
  }
}

# IDOR probe: one user reading many different users' resources.
# Alert if user X reads > 50 distinct resource IDs belonging to other users.
{
  "query": {
    "bool": {
      "must": [
        {"term": {"event_type": "data.read"}},
        {"range": {"@timestamp": {"gte": "now-1h"}}}
      ],
      "must_not": [
        {"term": {"user_id": "${resource_owner_id}"}}
      ]
    }
  },
  "aggs": {
    "by_user": {"terms": {"field": "user_id", "min_doc_count": 50}}
  }
}
```

### Step 8: Telemetry

```
security_event_total{event_type, result, service}           counter
security_event_pii_redacted_total{field, service}           counter
auth_failure_rate{ip, user_id_hash}                         gauge
authz_denial_rate{user_id, resource_type}                   gauge
data_export_record_count{user_id}                           histogram
log_correlation_gap_total{service}                          counter (events missing trace_id)
```

Alert on:

- `auth_failure_rate` per IP > 10/5min — credential stuffing.
- `authz_denial_rate` per user > 5/min — access control probing.
- `data_export_record_count` > threshold — bulk exfiltration candidate.
- `log_correlation_gap_total` > 0 — events missing trace IDs; correlation gaps in incident investigation.

## Expected Behaviour

| Signal | Unstructured debug logs | Structured security logging |
|--------|------------------------|----------------------------|
| Failed login | `ERROR login failed` (no IP, no user) | JSON event with IP, user hash, reason, duration |
| Authorisation denial | Not logged | `authz.access.denied` with user, resource, permission |
| Bulk data export | Not distinguishable | `data.export` with record count; alert if > threshold |
| PII in request body | Logged verbatim | Redacted before reaching log sink |
| Cross-service correlation | Not possible | Trace ID follows request through all services |
| SIEM retention | Mixed with debug (short retention) | Security events on 365-day retention tier |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| WARN level for security events | Survive log-level filtering | More noise in WARN logs | Filter SIEM on `event_type` field rather than log level for precision. |
| Structured JSON logging | Machine-parseable; SIEM-ready | Larger log volume than text | Compress at sink; structured logs compress well (repeated field names). |
| PII redaction at source | No PII reaches log sinks | May lose some debugging context | Use pseudonymised hash for correlation; store raw only in encrypted audit store if needed. |
| Trace ID propagation | Full request lineage | Requires middleware in every service | Add once to HTTP middleware and gRPC interceptor; flows automatically thereafter. |
| Record count in data.read logs | Enables exfiltration detection | Slightly more work per data access | Add to data access abstraction layer once; applies to all callers. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Security events dropped at WARN level filter | Auth failures invisible in SIEM | `security_event_total` drops; SIEM shows no auth events | Check log pipeline log-level configuration; ensure WARN and above flows to SIEM. |
| PII redaction regex too narrow | New PII format reaches logs | Periodic PII scan of log sample | Expand regex patterns; add test cases for new PII formats. |
| Trace ID missing from downstream service | Correlation gaps in investigation | `log_correlation_gap_total` counter rises | Add propagation middleware to the service that's dropping trace IDs. |
| Log injection via unescaped user input | Forged log entries in SIEM | Suspicious JSON-breaking characters in log fields | Use JSON logger (not string interpolation); JSON escapes automatically. |
| SIEM ingestion lag | Security events arrive > 5 minutes late | SIEM ingest lag metric | Check Vector/Filebeat pipeline throughput; scale ingestion workers. |
| Bulk export not logged due to streaming | Large exports bypass record count logging | No `data.export` events despite high data volume | Log count before streaming; or log a checkpoint every N records. |

## Related Articles

- [Audit Log Pipeline Design](/articles/observability/audit-log-pipeline/)
- [OpenTelemetry PII Leakage Prevention](/articles/observability/otel-pii-leakage/)
- [OpenTelemetry Security Tracing](/articles/observability/otel-security-tracing/)
- [SIEM Cost Optimisation](/articles/observability/siem-cost-optimization/)
- [Detection Rules and Sigma Correlation](/articles/observability/detection-rules/)
