---
title: "OpenTelemetry Collector Pipelines: Securing Receivers, Processors, and Exporters"
description: "An OTel Collector pipeline with default settings forwards every attribute, header, and trace to your backend with no filtering or authentication."
slug: "otel-collector-pipelines"
date: 2026-04-08
lastmod: 2026-04-08
category: "observability"
tags: ["opentelemetry", "otel-collector", "receivers", "exporters", "processors", "pipelines"]
personas: ["sre", "platform-engineer", "security-engineer"]
article_number: 142
difficulty: "intermediate"
estimated_reading_time: 18
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
premium_pack: "otel-hardened-pipeline-configs"
published: true
layout: article.njk
permalink: "/articles/observability/otel-collector-pipelines/index.html"
---

# [OpenTelemetry](https://opentelemetry.io) Collector Pipelines: Securing Receivers, Processors, and Exporters

## Problem

The [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/) is a vendor-neutral proxy that receives, processes, and exports telemetry data. Out of the box, it accepts data from any source without authentication, forwards every attribute (including sensitive fields like `db.statement`, `http.request.header.authorization`, and user IP addresses) with no filtering, and ships it all to your backend over plaintext connections.

The specific gaps in a default Collector deployment:

- **Receivers accept unauthenticated traffic.** The OTLP gRPC and HTTP receivers bind to `0.0.0.0` and accept data from any client. An attacker on your network can inject fabricated spans, pollute metrics, or flood the Collector to cause resource exhaustion.
- **Sensitive attributes pass through unfiltered.** Application instrumentation captures SQL queries in `db.statement`, authorization headers in `http.request.header.authorization`, email addresses in user attributes, and IP addresses in `net.peer.ip`. All of these reach your observability backend and become searchable by anyone with dashboard access.
- **Exporters send data in plaintext.** Without explicit TLS configuration, telemetry travels unencrypted between the Collector and your backend. Credentials embedded in exporter configs sit in plaintext YAML files.
- **A single pipeline mixes signal types and tenants.** Traces, metrics, and logs share the same pipeline by default. One noisy service can starve telemetry from critical systems, and there is no isolation between teams or environments.

This article configures every stage of the Collector pipeline for authenticated ingestion, data sanitization, and encrypted export.

**Target systems:** [OpenTelemetry Collector Contrib](https://github.com/open-telemetry/opentelemetry-collector-contrib) v0.100+. Kubernetes or VM deployments. Any OTLP-compatible backend ([Grafana Cloud](https://grafana.com/products/cloud/), [Axiom](https://axiom.co/), [SigNoz](https://signoz.io/)).

## Threat Model

- **Adversary:** An attacker with network access to the Collector's receiver ports, or an insider with read access to the observability backend who should not see PII, credentials, or raw SQL queries. Also considers denial-of-service through telemetry flooding.
- **Blast radius:** Without pipeline hardening, the Collector becomes a data exfiltration path. Sensitive attributes in traces and logs are searchable in your backend. Unauthenticated receivers allow telemetry injection. Plaintext exports expose data in transit. With hardened pipelines, receivers reject unauthorized sources, processors strip sensitive fields before export, and exporters use TLS with proper credential management.

## Configuration

### Receivers: Authenticated Ingestion

Lock down each receiver to accept only authenticated, authorized traffic.

**OTLP gRPC/HTTP receiver with bearer token authentication:**

```yaml
# otel-collector-config.yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
        tls:
          cert_file: /etc/otel/certs/collector.crt
          key_file: /etc/otel/certs/collector.key
          client_ca_file: /etc/otel/certs/ca.crt
        auth:
          authenticator: bearertokenauth
      http:
        endpoint: 0.0.0.0:4318
        tls:
          cert_file: /etc/otel/certs/collector.crt
          key_file: /etc/otel/certs/collector.key
        auth:
          authenticator: bearertokenauth

extensions:
  bearertokenauth:
    # Token read from environment variable, never hardcoded.
    token: ${env:OTEL_RECEIVER_AUTH_TOKEN}
```

**Prometheus receiver with TLS scraping:**

```yaml
receivers:
  prometheus:
    config:
      scrape_configs:
        - job_name: "secure-targets"
          scheme: https
          tls_config:
            ca_file: /etc/otel/certs/ca.crt
            cert_file: /etc/otel/certs/client.crt
            key_file: /etc/otel/certs/client.key
            insecure_skip_verify: false
          static_configs:
            - targets: ["app-server:9090"]
```

**Filelog receiver with restricted paths:**

```yaml
receivers:
  filelog:
    include:
      # Explicit allowlist. Never use /var/log/*.
      - /var/log/app/application.log
      - /var/log/app/access.log
    exclude:
      - /var/log/app/*.gz
    # Prevent symlink traversal.
    include_file_name: true
    include_file_path: true
    max_log_size: 1MiB
```

### Processors: Data Sanitization and Resource Protection

Processors run in the order they appear in the pipeline definition. Order matters: filter first (reduce volume), then sanitize (strip sensitive data), then limit resources, then batch.

**Remove sensitive attributes:**

```yaml
processors:
  # Strip fields that should never reach the backend.
  attributes/remove-sensitive:
    actions:
      - key: db.statement
        action: delete
      - key: http.request.header.authorization
        action: delete
      - key: http.request.header.cookie
        action: delete
      - key: http.request.header.set-cookie
        action: delete
      - key: enduser.credential
        action: delete
```

**PII scrubbing with the transform processor:**

```yaml
processors:
  transform/scrub-pii:
    trace_statements:
      - context: span
        statements:
          # Replace email addresses with [REDACTED_EMAIL].
          - replace_pattern(attributes["user.email"],
              "([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+)",
              "[REDACTED_EMAIL]")
          # Mask IP addresses to /24 subnet.
          - replace_pattern(attributes["net.peer.ip"],
              "(\\d+\\.\\d+\\.\\d+)\\.\\d+",
              "$$1.0")
    log_statements:
      - context: log
        statements:
          - replace_pattern(body,
              "([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+)",
              "[REDACTED_EMAIL]")
```

**Filter out noisy telemetry:**

```yaml
processors:
  # Drop health check spans that add volume but no value.
  filter/drop-noise:
    error_mode: ignore
    traces:
      span:
        - 'attributes["http.target"] == "/healthz"'
        - 'attributes["http.target"] == "/readyz"'
        - 'attributes["http.target"] == "/livez"'
        - 'name == "HTTP GET /favicon.ico"'
    metrics:
      metric:
        # Drop go runtime metrics from non-production services.
        - 'IsMatch(name, "go_.*") and resource.attributes["deployment.environment"] != "production"'
```

**Memory limiter to prevent OOM:**

```yaml
processors:
  memory_limiter:
    # Hard limit: reject data when memory hits this threshold.
    limit_mib: 512
    # Soft limit: start refusing data before hitting the hard limit.
    spike_limit_mib: 128
    check_interval: 5s
```

**Batch processor for throughput vs. latency:**

```yaml
processors:
  batch:
    # Send a batch when either condition is met.
    send_batch_size: 1024
    # Maximum wait before sending a partial batch.
    timeout: 5s
    # Upper bound to prevent huge allocations.
    send_batch_max_size: 2048
```

For latency-sensitive pipelines (security alerting), reduce `timeout` to `1s` and `send_batch_size` to `256`. For high-throughput, cost-optimized pipelines, increase `timeout` to `10s` and `send_batch_size` to `8192`.

**Tail sampling for security-focused retention:**

```yaml
processors:
  tail_sampling:
    decision_wait: 10s
    num_traces: 100000
    policies:
      # Keep 100% of error spans. Every failure is worth investigating.
      - name: errors-always
        type: status_code
        status_code:
          status_codes:
            - ERROR
      # Keep 100% of high-latency traces (potential abuse or attack).
      - name: slow-traces
        type: latency
        latency:
          threshold_ms: 5000
      # Keep 100% of traces with auth failures.
      - name: auth-failures
        type: string_attribute
        string_attribute:
          key: auth.result
          values: ["failure"]
      # Sample 10% of successful traces.
      - name: success-sampling
        type: probabilistic
        probabilistic:
          sampling_percentage: 10
```

### Exporters: Encrypted Delivery with Credential Management

**OTLP exporter with TLS and bearer token:**

```yaml
exporters:
  otlp/backend:
    endpoint: "otel-backend.example.com:4317"
    tls:
      cert_file: /etc/otel/certs/client.crt
      key_file: /etc/otel/certs/client.key
      ca_file: /etc/otel/certs/ca.crt
    headers:
      Authorization: "Bearer ${env:OTEL_EXPORTER_AUTH_TOKEN}"
    retry_on_failure:
      enabled: true
      initial_interval: 5s
      max_interval: 30s
      max_elapsed_time: 300s
    sending_queue:
      enabled: true
      num_consumers: 10
      queue_size: 5000
      storage: file_storage/queue
```

**Prometheus remote write with basic auth:**

```yaml
exporters:
  prometheusremotewrite:
    endpoint: "https://prometheus.example.com/api/v1/write"
    tls:
      ca_file: /etc/otel/certs/ca.crt
      insecure_skip_verify: false
    auth:
      authenticator: basicauth/prom

extensions:
  basicauth/prom:
    client_auth:
      username: ${env:PROM_REMOTE_WRITE_USER}
      password: ${env:PROM_REMOTE_WRITE_PASSWORD}
```

**Credential management in Kubernetes:**

Never put secrets in the Collector config file. Mount them from Kubernetes Secrets as environment variables or files:

```yaml
# Kubernetes Deployment snippet for the Collector.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: otel-collector
spec:
  template:
    spec:
      containers:
        - name: otel-collector
          env:
            - name: OTEL_RECEIVER_AUTH_TOKEN
              valueFrom:
                secretKeyRef:
                  name: otel-secrets
                  key: receiver-token
            - name: OTEL_EXPORTER_AUTH_TOKEN
              valueFrom:
                secretKeyRef:
                  name: otel-secrets
                  key: exporter-token
            - name: PROM_REMOTE_WRITE_USER
              valueFrom:
                secretKeyRef:
                  name: otel-secrets
                  key: prom-user
            - name: PROM_REMOTE_WRITE_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: otel-secrets
                  key: prom-password
          volumeMounts:
            - name: otel-certs
              mountPath: /etc/otel/certs
              readOnly: true
      volumes:
        - name: otel-certs
          secret:
            secretName: otel-tls-certs
```

### Pipeline Isolation and Multi-Tenant Routing

Separate pipelines prevent one signal type from starving another. The routing connector directs data to different exporters based on attributes:

```yaml
connectors:
  routing:
    table:
      - statement: route() where resource.attributes["tenant"] == "team-a"
        pipelines: [traces/team-a]
      - statement: route() where resource.attributes["tenant"] == "team-b"
        pipelines: [traces/team-b]
    default_pipelines: [traces/default]

service:
  extensions: [bearertokenauth, basicauth/prom, file_storage/queue]

  pipelines:
    # Traces pipeline: full security processing.
    traces:
      receivers: [otlp]
      processors:
        - memory_limiter
        - filter/drop-noise
        - attributes/remove-sensitive
        - transform/scrub-pii
        - tail_sampling
        - batch
      exporters: [routing]

    traces/team-a:
      receivers: [routing]
      exporters: [otlp/team-a-backend]

    traces/team-b:
      receivers: [routing]
      exporters: [otlp/team-b-backend]

    traces/default:
      receivers: [routing]
      exporters: [otlp/backend]

    # Metrics pipeline: separate processing chain.
    metrics:
      receivers: [otlp, prometheus]
      processors:
        - memory_limiter
        - filter/drop-noise
        - attributes/remove-sensitive
        - batch
      exporters: [prometheusremotewrite]

    # Logs pipeline: aggressive PII scrubbing.
    logs:
      receivers: [otlp, filelog]
      processors:
        - memory_limiter
        - attributes/remove-sensitive
        - transform/scrub-pii
        - batch
      exporters: [otlp/backend]
```

## Expected Behaviour

After deploying the hardened pipeline:

- **Unauthenticated OTLP requests return an error.** Any client sending data without a valid bearer token receives a gRPC `UNAUTHENTICATED` status or HTTP 401. The Collector logs the rejection.
- **Sensitive attributes never reach the backend.** Query your backend for `db.statement`, `http.request.header.authorization`, or `enduser.credential` attributes and get zero results. Email addresses appear as `[REDACTED_EMAIL]` and IP addresses are masked to `/24`.
- **Health check spans are absent from storage.** Traces for `/healthz`, `/readyz`, and `/livez` are dropped before export. This reduces trace storage volume by 20-60% in typical Kubernetes deployments.
- **Error and security-relevant traces are always retained.** The tail sampling policy keeps 100% of error spans and auth failures. Only successful, low-latency traces are sampled down to 10%.
- **Memory stays bounded.** The `memory_limiter` processor rejects data before the Collector process hits its memory ceiling. You see `dropped_data` metrics increase during traffic spikes rather than OOM kills.
- **Tenant data stays isolated.** Team A's traces route to Team A's backend. No cross-tenant data leakage.

Verify with: `otelcol validate --config=/etc/otel/otel-collector-config.yaml` to catch config errors before deployment.

## Trade-offs

| Decision | Benefit | Cost |
|---|---|---|
| Bearer token on receivers | Blocks unauthorized ingestion | Every SDK and agent needs the token configured; token rotation requires coordinated rollout |
| Deleting `db.statement` | Eliminates SQL injection exposure in backend | Developers lose the ability to debug slow queries from trace data; they must use separate database monitoring tools |
| PII regex scrubbing | Prevents email and IP leakage | Regex is not exhaustive; novel PII formats may slip through; adds 2-5ms per span at the processor stage |
| Tail sampling at 10% for success | Reduces storage costs by up to 90% for successful traces | Rare non-error issues in sampled-out traces become invisible; debugging intermittent problems gets harder |
| Separate pipelines per signal | One noisy signal cannot starve another | More complex config to maintain; each pipeline needs its own processor chain |
| Memory limiter at 512 MiB | Prevents OOM kills | Data is dropped during sustained spikes rather than queued; you may lose telemetry during incidents (exactly when you need it most) |
| Routing connector for multi-tenancy | Data isolation between teams | Adds a hop in the pipeline; requires consistent `tenant` attribute on all incoming data |

## Failure Modes

**Symptom: Collector restarts with OOM despite memory_limiter.**
The `memory_limiter` must be the **first** processor in every pipeline. If batch or transform processors run before it, they can allocate memory before the limiter has a chance to refuse data. Check the processor order in your pipeline definition.

**Symptom: Tail sampling drops all traces.**
The `decision_wait` parameter must be long enough for all spans in a trace to arrive. If your services have high latency, spans arrive after the decision window closes, and the sampler drops incomplete traces. Increase `decision_wait` from 10s to 30s for services with P99 latency above 5 seconds. Monitor the `otelcol_processor_tail_sampling_sampling_trace_dropped_too_early` metric.

**Symptom: Bearer token auth rejects all traffic after rotation.**
Token rotation requires updating both the Collector config (via the `OTEL_RECEIVER_AUTH_TOKEN` environment variable) and every SDK client simultaneously. Use a transition period where the Collector accepts both old and new tokens. The `bearertokenauth` extension supports a single token, so for zero-downtime rotation, place an authenticating reverse proxy (Envoy, nginx) in front of the Collector and handle token validation there.

**Symptom: Transform processor regex does not match.**
OTTL regex syntax uses Go's `regexp` package, which does not support lookaheads or lookbehinds. Test patterns with `go test` or a Go regex playground before deploying. Escaped backslashes in YAML require double escaping (`\\d` for `\d`).

**Symptom: Routing connector sends everything to default pipeline.**
The `resource.attributes["tenant"]` must be set by the application or by a resource processor before the routing connector. If the attribute is missing, all data falls through to `default_pipelines`. Add a resource processor that sets a default tenant for untagged data, and alert on the `otelcol_connector_routing_default_route` metric.

## When to Consider a Managed Alternative

Self-hosted Collector pipelines give you full control over data processing, but they come with operational cost: certificate rotation, token management, scaling, and processor tuning. Consider a managed alternative when:

- Your team does not have dedicated SRE capacity to maintain the Collector fleet.
- You need SOC 2 or HIPAA compliance for telemetry data and want the vendor to handle encryption at rest and audit logging.
- Multi-region deployments make self-hosted Collector topology complex.

[Grafana Cloud](https://grafana.com/products/cloud/) provides a managed OTLP endpoint with built-in authentication. [Axiom](https://axiom.co/) offers native OTLP ingestion with automatic PII detection. [SigNoz](https://signoz.io/) runs an OTel Collector internally but manages the infrastructure for you.

Even with a managed backend, running a local Collector as a gateway for PII scrubbing and sampling before data leaves your network is a common hybrid pattern.

## Related Articles

- [OpenTelemetry Collector Hardening](/articles/observability/otel-collector-hardening/) - Base Collector security configuration including network exposure, extension security, and binary verification.
- [OpenTelemetry for Security Tracing](/articles/observability/otel-security-tracing/) - Instrumenting authentication and authorization flows with OTel spans and building detection rules from trace data.
- [Prometheus Security Metrics](/articles/observability/prometheus-security-metrics/) - Collecting and alerting on security-relevant metrics with Prometheus, complementing the trace and log pipelines configured here.
- [Centralized Logging](/articles/observability/centralized-logging/) - Designing a centralized log pipeline with integrity guarantees, covering the log signal that flows through the Collector's log pipeline.
- [Audit Log Pipeline](/articles/observability/audit-log-pipeline/) - Building a tamper-evident audit log pipeline for compliance, which can use the OTel Collector as a transport layer.
