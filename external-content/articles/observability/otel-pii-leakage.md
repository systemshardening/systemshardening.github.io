---
title: "OpenTelemetry PII Leakage: Stopping Sensitive Data in Span Attributes, Baggage, and Logs"
description: "OTel traces capture authorization headers, URL params, internal IDs, and database query strings by default. Without redaction, your traces are an exfiltration target."
slug: "otel-pii-leakage"
date: 2026-04-27
lastmod: 2026-04-27
category: "observability"
tags: ["opentelemetry", "pii", "redaction", "tracing", "baggage", "compliance"]
personas: ["sre", "security-engineer", "platform-engineer"]
article_number: 176
difficulty: "intermediate"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/observability/otel-pii-leakage/index.html"
---

# OpenTelemetry PII Leakage: Stopping Sensitive Data in Span Attributes, Baggage, and Logs

## Problem

OpenTelemetry instrumentation, when applied with the default auto-instrumentation libraries, produces telemetry that is more sensitive than most teams realize. The defaults are operational (capture useful diagnostic data) rather than privacy-safe.

Consider what a typical request emits, end to end:

- **HTTP server span** — full URL including query string, request headers including `Authorization`, `Cookie`, `X-Api-Key`, `User-Agent`, `X-Forwarded-For`. Some libraries truncate `Authorization` to "Bearer ..." and some do not.
- **Outgoing HTTP client span** — full URL of the third-party service including any tokens passed as URL parameters, request body if instrumented at the body-buffering layer.
- **Database client span** — the full SQL statement including bound parameters, especially for ORMs that interpolate values into the statement string before sending.
- **Cache client span (Redis, Memcached)** — keys and values for `GET`/`SET` commands.
- **Message queue span (Kafka, SQS, NATS)** — message payloads if a body-attribute extractor is enabled.
- **Custom application spans** — whatever the developer chose to record, often including user IDs, tenant IDs, full document bodies, JWT contents.
- **Baggage** — application-supplied context that propagates across all downstream services. Once written, it travels through every subsequent service in the request chain and lands in every downstream span.
- **Logs (via OTel logs SDK)** — application log lines as-is, including the things developers write at INFO level: customer email, transaction details, raw error payloads.

Once this data reaches your observability backend, it sits in cold storage for the retention period (often 30-180 days), accessible to anyone with read access to the trace store. SOC 2, GDPR, HIPAA, PCI-DSS, and most internal data-classification policies do not contemplate "trace data" as a separate category. It inherits the access controls of whatever indexes it.

The specific gaps in a default OTel deployment:

- HTTP auto-instrumentation captures `Authorization` header values verbatim unless explicitly stripped.
- DB instrumentation captures the SQL statement post-interpolation, leaking parameter values.
- Application code calls `span.set_attribute("user.email", current_user.email)` because the example in the OTel docs does so.
- Baggage written by an upstream gateway propagates as span attributes on every downstream service.
- Log capture sends application logs without any pattern-based redaction.
- Backend exporters (Jaeger, Tempo, Datadog, Splunk Observability) receive the data unchanged and index it for query.

This article covers SDK-level attribute filtering, Collector-level redaction processors, baggage scoping, and database / HTTP / log specific patterns. The goal is bounded sensitive-data exposure even when developers add new instrumentation tomorrow.

**Target systems:** OpenTelemetry SDK (any language with the standard processors API), OpenTelemetry Collector v0.96+, observability backends that store trace data (Jaeger, Tempo, Datadog APM, Splunk Observability, New Relic, Honeycomb, Lightstep).

## Threat Model

- **Adversary 1 — Curious insider:** employee with read access to the observability backend (developers, SREs, on-call) who searches for or stumbles across customer data.
- **Adversary 2 — Compromised observability backend:** stolen credentials or compromised SaaS observability vendor exposing the trace store to an attacker who never had legitimate access.
- **Adversary 3 — Compliance auditor finding regulated data outside its sanctioned location:** GDPR, HIPAA, PCI-DSS auditors find PII/PHI/PAN in a system not classified for it.
- **Adversary 4 — Subpoena / legal discovery:** lawful process compels disclosure of operational logs and traces; sensitive data ends up in legal records.
- **Access level:** Adversary 1 has standard observability access. Adversary 2 has temporary access via stolen credentials. Adversary 3 has audit access. Adversary 4 has process power, no technical compromise.
- **Objective:** Read sensitive data that should never have been in the trace store. Establish that regulated data was stored without proper controls, triggering breach disclosure.
- **Blast radius:** Once data is in the trace store, it is in every backup, every export pipeline, every downstream BI tool that reads from it. Removing it after the fact is hard — backends often do not support retroactive deletion of attribute values, only entire spans or time ranges.

## Configuration

### Layer 1: SDK-Level Span Processor for Header Redaction

The earliest place to redact is in the SDK before the span ever leaves the application. Use a custom `SpanProcessor` (or use the SDK's `attribute_value_length_limit` and library-specific config).

Python:

```python
# instrumentation.py
# Span processor that scrubs sensitive attributes before export.
from opentelemetry.sdk.trace import SpanProcessor, Span
import re

SENSITIVE_KEYS = {
    "http.request.header.authorization",
    "http.request.header.cookie",
    "http.request.header.x-api-key",
    "http.response.header.set-cookie",
    "user.email", "user.phone", "user.ssn",
    "db.statement.parameters",
    "messaging.payload",
}

PATTERNS = [
    (re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*"), "Bearer [redacted]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[ssn-redacted]"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), "[email-redacted]"),
    (re.compile(r"\b(?:\d[ -]*?){13,16}\b"), "[card-redacted]"),
    (re.compile(r"sk-[A-Za-z0-9]{32,}"), "[apikey-redacted]"),
]

class RedactionSpanProcessor(SpanProcessor):
    def on_start(self, span: Span, parent_context=None): pass
    def on_end(self, span: Span):
        attrs = span._attributes if hasattr(span, "_attributes") else {}
        for key in list(attrs.keys()):
            if key in SENSITIVE_KEYS:
                attrs[key] = "[redacted]"
            elif isinstance(attrs[key], str):
                value = attrs[key]
                for pat, replacement in PATTERNS:
                    value = pat.sub(replacement, value)
                attrs[key] = value
    def shutdown(self): pass
    def force_flush(self, timeout_millis=30000): return True

# Wire up at SDK initialization:
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
provider = TracerProvider()
provider.add_span_processor(RedactionSpanProcessor())
provider.add_span_processor(BatchSpanProcessor(otlp_exporter))
trace.set_tracer_provider(provider)
```

The redaction processor runs *before* the batch exporter, so attribute scrubbing happens before any network egress.

### Layer 2: Collector-Level Redaction Processor

A second line of defense at the OpenTelemetry Collector. Even if a service's SDK is misconfigured, the Collector strips the same attributes before they reach the backend.

```yaml
# otel-collector-config.yaml
processors:
  redaction:
    allow_all_keys: true
    blocked_values:
      - "(?i)Bearer\\s+[A-Za-z0-9\\-._~+/]+=*"
      - "\\b\\d{3}-\\d{2}-\\d{4}\\b"   # SSN
      - "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b"   # email
      - "sk-[A-Za-z0-9]{32,}"   # API keys
      - "\\b(?:\\d[ -]*?){13,16}\\b"   # credit cards
    summary: silent
    blocked_keys:
      - "http.request.header.authorization"
      - "http.request.header.cookie"
      - "http.request.header.x-api-key"
      - "http.response.header.set-cookie"

  attributes/scrub-sql:
    actions:
      - key: db.statement
        pattern: "(?i)(password|secret|token)\\s*=\\s*'[^']*'"
        action: update
        from_attribute: ""

  filter/drop_baggage:
    spans:
      exclude:
        match_type: regexp
        attributes:
          - key: baggage.*

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors:
        - redaction
        - attributes/scrub-sql
        - filter/drop_baggage
        - memory_limiter
        - batch
      exporters: [otlphttp]
```

The Collector's `redaction` processor (available since v0.81) supports both key-level blocklists and value-pattern matching. Combine with `attributes/scrub-sql` for finer-grained SQL redaction.

### Layer 3: Database Statement Redaction

ORMs and DB drivers vary in how they expose query parameters. The safest pattern is to disable raw-statement capture and rely on the parameterized form:

```python
# SQLAlchemy + OTel: capture only the SQL template, not the bound values.
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
SQLAlchemyInstrumentor().instrument(
    enable_commenter=True,
    commenter_options={"db_driver": True, "opentelemetry_values": False},
)

# Configure to capture statements but with parameters stripped.
# DB span 'db.statement' will be: "SELECT * FROM users WHERE email = ?"
# Not: "SELECT * FROM users WHERE email = 'alice@example.com'"
```

For drivers that do not support template-only capture, replace `db.statement` at the SDK level:

```python
# Custom span processor for DB-specific scrubbing.
class DbRedactor(SpanProcessor):
    def on_end(self, span):
        attrs = span._attributes if hasattr(span, "_attributes") else {}
        if "db.statement" in attrs:
            stmt = attrs["db.statement"]
            # Replace string literals.
            stmt = re.sub(r"'([^']*)'", "'?'", stmt)
            # Replace numeric literals beyond the obvious "1" / "0" cases.
            stmt = re.sub(r"\b\d{4,}\b", "?", stmt)
            attrs["db.statement"] = stmt
```

### Layer 4: Baggage Scoping

Baggage propagates across services. Without controls, anything written to baggage at the gateway becomes a span attribute on every downstream service.

Limit which baggage keys propagate:

```python
# Use a custom Propagator that only allows known-safe keys.
from opentelemetry.baggage.propagation import W3CBaggagePropagator
from opentelemetry import baggage, context

ALLOWED_BAGGAGE_KEYS = {"request.id", "tenant.id", "trace.sampling.priority"}

class FilteredBaggagePropagator(W3CBaggagePropagator):
    def extract(self, carrier, context_=None, getter=None):
        ctx = super().extract(carrier, context_, getter)
        for key in list(baggage.get_all(ctx).keys()):
            if key not in ALLOWED_BAGGAGE_KEYS:
                ctx = baggage.remove_baggage(key, ctx)
        return ctx

# Set as the global propagator.
from opentelemetry.propagate import set_global_textmap
set_global_textmap(FilteredBaggagePropagator())
```

Crucially, do not write user PII into baggage. A common antipattern: writing `user.email` to baggage at the API gateway "for debugging." It now lives in every downstream service's traces.

### Layer 5: Log Body Redaction

OTel logs SDK ships log records to the same backend as traces. Apply the same patterns to log records:

```yaml
# Collector config for log redaction.
processors:
  transform/redact_logs:
    log_statements:
      - context: log
        statements:
          - replace_pattern(body, "Bearer\\s+[A-Za-z0-9\\-._~+/]+=*", "Bearer [redacted]")
          - replace_pattern(body, "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b", "[email-redacted]")
          - replace_pattern(body, "sk-[A-Za-z0-9]{32,}", "[apikey-redacted]")
```

For application code, prefer structured logging that separates the field from its value:

```python
# Bad — full message field becomes the log body.
logger.info(f"User {user.email} logged in from {request.client.host}")

# Better — structured. Sensitive fields are individually classified
# and individually redactable.
logger.info("user_login", user_id=user.id, source_ip=request.client.host)
```

### Layer 6: Sample-Based Verification

Active checks that the redaction works. Periodically replay a subset of indexed spans against your sensitive-data patterns:

```python
# verify_redaction.py
# Run nightly. Query the trace backend for spans, scan attribute values,
# emit metrics on any matching pattern.
import re

def scan_span(span):
    findings = []
    for key, value in span.get("attributes", {}).items():
        if not isinstance(value, str):
            continue
        for pattern_name, pat in [
            ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
            ("ssn", r"\b\d{3}-\d{2}-\d{4}\b"),
            ("bearer", r"Bearer\s+[A-Za-z0-9\-._~+/]+=*"),
            ("card", r"\b(?:\d[ -]*?){13,16}\b"),
        ]:
            if re.search(pat, value):
                findings.append((pattern_name, span["service.name"], key))
    return findings

# Pseudocode for backend query:
spans = backend.query(time_range="last 1h", limit=10000)
findings = []
for s in spans:
    findings.extend(scan_span(s))

# Emit Prometheus metric for any finding.
for pattern, service, key in findings:
    pii_leak_total.labels(pattern=pattern, service=service, attr=key).inc()
```

Alert on any non-zero finding count. The leak should be investigated and patched at the source.

## Expected Behaviour

| Signal | Default OTel | Hardened |
|--------|--------------|----------|
| `Authorization` header in HTTP server span | Captured verbatim | `[redacted]` at SDK |
| `db.statement` for parameterized query | Includes literal values | Includes only `?` placeholders |
| Email address in span attribute | Captured | Replaced with `[email-redacted]` |
| Baggage carrying `user.email` | Propagated and recorded as span attribute on every downstream service | Stripped at propagation extraction; never reaches downstream |
| Application log line containing API key | Indexed verbatim in log backend | Replaced with `[apikey-redacted]` at SDK or Collector |
| Verification scan over indexed spans | Pattern matches present | Matches near-zero; alerts on any finding |
| Backend storage volume | Baseline | -10 to -30% (redacted strings are shorter than originals on average) |

Operate on metrics:

```
otel_redaction_attribute_replacements_total{key, pattern}    counter
otel_redaction_log_replacements_total{pattern}              counter
otel_pii_scan_findings_total{pattern, service}              counter (post-redaction)
otel_baggage_filtered_keys_total{key}                        counter
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| SDK-level redaction | Earliest interception; no sensitive data leaves the application process | Per-language implementation; new SDKs may miss the patterns | Implement in a shared internal library distributed to all services. |
| Collector-level redaction | Defense in depth; catches misconfigured SDKs | Adds Collector CPU cost (~5-15% per redaction processor on busy pipelines) | Run redaction in the gateway tier of the Collector, not on every node, to amortize cost. |
| DB statement template-only | Major source of leakage closed | Loses some debugging visibility (cannot see exact query that ran) | Keep parameterized template + bound values in a separate secure log if needed for incident response. |
| Baggage scoping | Prevents propagation of sensitive context | Some legitimate use cases for cross-service context need refactoring | Maintain an allowlist of baggage keys; require security review to add new entries. |
| Log redaction | Same protection extended to OTel logs | False positives may redact non-sensitive content (e.g., a "@example.com" mentioned in a stack trace) | Tune patterns over time; alert when redaction rates change suddenly. |
| Sample-based verification | Catches leaks the redactors miss | Adds ongoing operational burden | Schedule the scan once per day; cost is one query per day plus pattern-matching CPU. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| New service deployed without redaction processor | New service's spans contain unredacted data | Verification scan finds matches localized to the new service | Mandate the redaction library as part of the platform service template; CI check that the processor is registered. |
| Library update changes attribute names | Block list misses new key (e.g., `http.request.authorization` becomes `http.req.auth.value`) | Verification scan finds matches in unfamiliar attribute keys | Use prefix-based block list (`http.request.header.*`) rather than exact-match. |
| Redaction processor regex too greedy | Legitimate trace content masked, debugging hard | Operators report missing data in spans where it should be present | Tighten the pattern; add unit tests that exercise both positive and negative cases. |
| Sensitive data in custom attribute | A developer adds `span.set_attribute("user.password_hash", h)` | Verification scan flags the new attribute name | Add `*.password*`, `*.token*`, `*.secret*` to the global block prefix list. Code review catches in PR; linting flags `set_attribute` calls with sensitive-looking keys. |
| Backend indexes redacted data inconsistently | Some spans show `[redacted]`, others show original — caused by mixed deploy state | Backend query shows partial redaction across the same service | Trigger a fleet-wide redeploy; verify all services run the latest SDK + Collector configuration. |
| Existing data already in backend | Historical spans contain sensitive data; redaction does not retroactively clean them | Backend audit returns matches in older time ranges | Most backends do not support retroactive attribute deletion. Options: shorten retention, delete entire affected spans (if vendor supports), or accept and monitor. The forward-looking redaction prevents new accumulation. |
| Compliance auditor finds redacted data anyway | Auditor questions whether redaction is sufficient under their interpretation | Audit report flags trace-store contents | Document the redaction patterns and retention policy; demonstrate the verification process; consult counsel on whether the redacted form qualifies as anonymization. |

## Related Articles

- [Securing the OpenTelemetry Collector](/articles/observability/otel-collector-hardening/)
- [OpenTelemetry Collector Pipelines: Sampling, Routing, and Resilience](/articles/observability/otel-collector-pipelines/)
- [OpenTelemetry for Security: Distributed Tracing of Authentication and Authorization Flows](/articles/observability/otel-security-tracing/)
- [Centralized Logging Architecture for Security](/articles/observability/centralized-logging/)
- [Building a Security Audit Log Pipeline That Scales](/articles/observability/audit-log-pipeline/)
