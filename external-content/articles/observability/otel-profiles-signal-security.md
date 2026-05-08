---
title: "OpenTelemetry Profiles Signal Security: PII Leakage, Access Control, and Symbolisation Pipelines"
description: "OTel Profiles is the fourth signal alongside traces, metrics, and logs — stable as of 2025 and now flowing through the OTel Collector by default. Stack frames carry function names, file paths, and sometimes full SQL or cleartext URLs. Hardening guide for collector pipelines and storage."
slug: "otel-profiles-signal-security"
date: 2026-05-08
lastmod: 2026-05-08
category: "observability"
tags: ["opentelemetry", "profiles", "continuous-profiling", "pii", "ebpf", "pyroscope"]
personas: ["security-engineer", "sre", "platform-engineer"]
article_number: 661
difficulty: "intermediate"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/observability/otel-profiles-signal-security/index.html"
---

# OpenTelemetry Profiles Signal Security: PII Leakage, Access Control, and Symbolisation Pipelines

## Problem

OpenTelemetry's Profiles signal stabilised in 2025 and is now the canonical wire format for continuous-profiling data alongside traces, metrics, and logs. The OTel Collector ships a `profilesreceiver` and `profilesexporter`, vendors (Grafana Pyroscope, Polar Signals, Elastic Universal Profiling, Datadog) accept profiles in OTel format, and language SDKs (Go, Java, Python, .NET) emit them out of the box. The signal carries call-stack samples — `(timestamp, frame[], duration)` tuples — sampled at intervals from the running process.

The trouble is that what counts as a "frame" is more sensitive than most operators realise. A frame contains a function name, a source file path, a line number, and on some runtimes the actual frame arguments or local-variable names. In aggregate over millions of samples per service per minute, profiles disclose:

- **Source tree layout** of a private codebase (file paths, package names, internal class hierarchies).
- **Database access patterns** — Java JDBC stacks frequently contain the prepared-statement SQL as a frame attribute on some collectors; Go stacks include the table-name argument when functions are inlined; Python frames sometimes carry the full URL on `requests.get`.
- **User identifiers** when frame attributes leak `userId=42` arguments captured by the profiler.
- **Cryptographic primitives in use** — the frame names alone reveal which TLS curve, AEAD, or KEM you are running.
- **Cleartext authorization headers** in rare cases when a profiler captures argument values for HTTP middleware.

This is not a hypothetical: in 2025 multiple post-incident reviews from large SaaS providers documented profile data being the leakage vector that exposed customer record IDs, internal microservice paths, and even short cleartext auth tokens captured as Java-stack frame arguments. The signal is sensitive in a way logs and metrics are not, and the existing OTel-Collector defaults are tuned for completeness, not for redaction.

This article covers what to redact at the collector, how to scope access controls and storage, and how to wire symbolisation (the conversion of raw memory addresses to function names) into a pipeline that does not give the symbol-resolver service unbounded access to your binaries and debug info.

Target systems: OpenTelemetry Collector 0.115+ (with `profilesreceiver`/`profilesexporter`), Pyroscope 1.10+ or Polar Signals Cloud agents, language SDKs with Profiles support, and storage backends accepting OTLP profiles.

## Threat Model

1. **Tenant-A profile data leaking to tenant-B** in a multi-tenant collector: misrouting based on a bad `service.namespace` causes profiles to be exported to the wrong backend.
2. **PII or secret leakage via frame names/arguments** to a third-party APM vendor or a long-retention internal store.
3. **Adversary with read access to profile storage** reconstructing internal architecture (which microservices call which, which crypto library is in use, which database driver and version) to plan a targeted attack.
4. **Compromised symbolisation service** with read access to debug info and source paths gaining a sweeping view of every binary the org runs.
5. **Adversary tampering with a profile in transit** to suppress evidence of malicious activity (e.g., a cryptominer's stack samples) before they reach the SOC.

Without redaction or scoping, all five succeed. With the controls below, 1 is bounded by collector tenant isolation; 2 is bounded by frame-name redaction and argument stripping; 3 is bounded by storage ACLs and aggregation lag; 4 is bounded by symbol-server scope and signed debug info; 5 is bounded by signed-profile attestations.

## Configuration / Implementation

### Step 1 — Confirm Profiles signal is actually enabled

```bash
# Collector version + extension:
otelcol --version
otelcol components | grep profiles
# Want: profilesreceiver, profilesexporter, batchprocessor (with profiles)

# SDK side, Go example:
go list -m go.opentelemetry.io/otel/sdk/profile
# Need >= v0.4.0
```

### Step 2 — Strip risky frame attributes at the SDK

The closest control surface is the SDK itself. For Java's async-profiler-based exporter:

```java
// Application bootstrap.
SdkProfilerProvider provider = SdkProfilerProvider.builder()
    .addProcessor(BatchSpanProcessor.builder(otlpExporter).build())
    .setSampler(Samplers.cpu(99))               // 99 Hz CPU profiling
    .setFrameAttributeFilter(FrameAttributeFilter.builder()
        .denyKeys("sql", "url", "http.url",
                  "thread.name",                // contains tenant-id in our app
                  "frame.locals.*")
        .build())
    .setStackDepthLimit(48)                     // truncate deep stacks
    .build();
```

For the Go SDK:

```go
provider := profile.NewProvider(
    profile.WithFrameRedactor(func(f profile.Frame) profile.Frame {
        // Drop locals, redact paths starting with internal modules.
        f.Locals = nil
        if strings.HasPrefix(f.File, "/build/internal/") {
            f.File = "<redacted-internal>"
        }
        return f
    }),
    profile.WithExporter(otlp.NewExporter(otlp.WithGRPC(endpoint))),
)
```

The SDK is the *only* place to remove frame attributes that contain caller-passed argument values; once they reach the collector they have already crossed a trust boundary.

### Step 3 — Collector-side redaction and scoping

Many language SDKs do not yet support frame-attribute filters. The collector becomes the second line of defence:

```yaml
# /etc/otelcol/profiles-pipeline.yaml
receivers:
  otlp/profiles:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
        tls:
          cert_file: /etc/otelcol/tls/server.crt
          key_file:  /etc/otelcol/tls/server.key
          client_ca_file: /etc/otelcol/tls/clients-ca.crt
        auth:
          authenticator: oidc

processors:
  redaction/profiles:
    profiles:
      drop_frame_attributes:
        - sql
        - url
        - http.url
        - http.request.header.authorization
        - frame.args.*
        - frame.locals.*
      hash_frame_attributes:
        - "rpc.peer.address"
        - "user.id"
      replace_path_prefix:
        - "/home/builder/repo/internal" -> "/internal"
        - "/private-modules"             -> "/m"
      strip_kernel_addresses: true        # drop frames where module is "[kernel]"
      drop_function_name_patterns:
        - "checkAuthToken.*"               # internal naming hint we do not want exposed
        - ".*ssn.*"
  attributes/tenant:
    actions:
      - key: tenant_id
        action: extract
        from_context: auth.subject
        regex: "^tenant-([a-z0-9]+)$"
        to_attributes: ["tenant"]
  routing/tenant:
    from_attribute: tenant
    table:
      - value: tenant-finance
        exporters: [otlp/finance-store]
      - value: tenant-marketing
        exporters: [otlp/marketing-store]

exporters:
  otlp/finance-store:
    endpoint: profile-finance.observability.svc:4317
    tls: { insecure: false, ca_file: /etc/otelcol/tls/store-ca.crt }
  otlp/marketing-store:
    endpoint: profile-marketing.observability.svc:4317
    tls: { insecure: false, ca_file: /etc/otelcol/tls/store-ca.crt }

service:
  pipelines:
    profiles:
      receivers: [otlp/profiles]
      processors: [redaction/profiles, attributes/tenant, routing/tenant]
      exporters: [otlp/finance-store, otlp/marketing-store]
```

`drop_frame_attributes` removes attribute keys that commonly leak sensitive data. `hash_frame_attributes` replaces values with a deterministic SHA-256 (truncated) so cardinality is preserved for analytics without revealing the original. `strip_kernel_addresses` drops frames inside kernel space — useful because raw kernel addresses are KASLR-leakable.

### Step 4 — Tenant-isolated symbolisation

Profile samples are typically captured as raw program counters and symbolised later. The symbol-resolver service is therefore one of the highest-trust components in the pipeline; it needs read access to every binary and its debug info. Two patterns:

**Co-located symbolisation**: each tenant runs its own symboliser scoped to its own binaries. Privacy-preserving but adds operational cost.

**Shared symboliser with attestation**: a single symboliser service, but every binary entry is signed by a build-time signer and the symboliser refuses to resolve any binary that does not carry a current attestation.

```yaml
# Parca-Agent / Polar Signals example with attestation.
symboliser:
  mode: shared
  binary_store:
    type: oci
    registry: registry.example.com/debug-binaries
    require_signature: true                # cosign verify with org root
    signature_policy: /etc/symboliser/policy.yaml
  cache:
    size_mb: 4096
    eviction: lru
  acl:
    # Only approved tenants may resolve a binary.
    rules:
      - binary_pattern: "registry.example.com/debug-binaries/finance/*"
        allowed_tenants: [tenant-finance]
      - binary_pattern: "registry.example.com/debug-binaries/shared/*"
        allowed_tenants: ["*"]
```

Without an ACL, a tenant with profile-read access can supply addresses from any binary and get symbols back, effectively reading parts of other tenants' source layouts.

### Step 5 — Sample-rate, retention, and aggregation

PII risk decreases monotonically with both reduced sample rate and shorter retention. The trade-off is signal quality.

```yaml
processors:
  probabilistic_sampler/profiles:
    sampling_percentage: 25            # keep 25% of profile samples
  filter/lowfreq_only:
    profiles:
      sample_match:
        # Drop very-low-count frames where reidentification risk is highest.
        min_sample_count: 5
```

Storage retention should be tiered: hot 7d (queryable, full fidelity), warm 30d (downsampled to 5-second buckets, frame attributes stripped), cold 1y (only function-name aggregates).

### Step 6 — Authentication and access control on the read path

Profile-store query APIs (Pyroscope, Polar Signals, Grafana profile data source) must enforce per-tenant scoping at the API gateway:

```yaml
# Pyroscope auth-proxy snippet.
auth:
  type: oidc
  issuer: https://idp.example.com
  client_id: pyroscope
  required_scopes: [profiles.read]
tenant_extraction:
  source: jwt_claim
  claim: tenant
header_required: X-Scope-OrgID
```

`X-Scope-OrgID` is Pyroscope's tenant-scoping header; setting it on each request and forbidding clients from sending arbitrary values (the auth proxy must derive it from the JWT, not trust the header) is the difference between a multi-tenant store and a multi-tenant exfil opportunity.

### Step 7 — Detection of unusual profile traffic

Two detection rules pay for themselves:

```yaml
# Loki/Promtail-style alert for profile receiver.
groups:
  - name: profiles-security
    rules:
      - alert: ProfilesUnexpectedFrameAttribute
        expr: |
          rate(otelcol_processor_redaction_dropped_frame_attributes_total
            {key=~"http.request.header.authorization|frame.args.*"}[5m]) > 0
        for: 10m
        labels: { severity: high }
        annotations:
          description: |
            Application is emitting frame attributes that should never appear.
            Indicates SDK misconfiguration or instrumentation regression.
      - alert: ProfilesTenantRoutingMismatch
        expr: |
          increase(otelcol_processor_routing_unmatched_total
            {pipeline="profiles"}[15m]) > 0
        labels: { severity: high }
```

Either alert is suspicious enough to warrant blocking exports until human review.

## Expected Behaviour

| Signal | Before this hardening | After |
|---|---|---|
| SDK-emitted frame `args/locals` | Sent to collector | Stripped at SDK or collector |
| SQL-bearing JDBC frame | Stored, queryable as text | Hashed or dropped |
| Authorization-header frame attribute | Stored in plaintext | Dropped at collector |
| Cross-tenant routing of profiles | Possible via misroute | Bounded by `routing/tenant` processor |
| Symboliser access to other tenant binaries | Implicit | Denied by ACL |
| Long retention of full-fidelity profiles | Default | Tiered: 7d full → 30d warm → 1y aggregates |
| Profile read API tenancy | Trust client `X-Scope-OrgID` | Derived from authenticated JWT |
| Anomalous frame-attribute traffic | Silent | Alerted, optionally exports paused |

Verification snippet:

```bash
# Send a deliberately PII-tainted profile and confirm it is redacted.
otlp-debug-cli send-profile \
  --frame-attribute "sql=SELECT * FROM users WHERE ssn='123-45-6789'" \
  --frame-attribute "user.id=42" \
  --endpoint collector.example.com:4317 \
  --tls --cert client.crt --key client.key

# Check the downstream store does not contain the SSN string.
pyroscope-cli query --tenant tenant-finance \
  --query 'sql=~".*ssn.*"' --window 5m
# Expect: empty result.

# Check the user.id value is hashed (cardinality preserved, value is opaque).
pyroscope-cli query --tenant tenant-finance \
  --query 'user.id!=""' --window 5m | jq '.frames[].user_id'
# Expect: 64-hex-char hash strings, not "42".
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| SDK-side redaction | Prevents data leaving the host | Each SDK has different APIs | Standardise on a thin wrapper per language |
| Collector-side redaction | Centralised policy enforcement | Adds processor stages, ~5% throughput | Separate profiles pipeline from traces |
| Tenant-routed export | Strong cross-tenant boundary | More exporters to maintain | Generate config from tenant inventory |
| Symboliser ACL | Prevents binary disclosure | Cache misses on cross-tenant queries | Pre-warm cache per tenant |
| Sample-rate reduction | Less PII, smaller storage | Less detail in flame graphs | Higher rate in dev, lower in prod |
| Tiered retention | Reduced exposure window | Older comparisons less precise | Keep aggregates indefinitely; drop raw early |
| Anomaly alerting on redaction events | Catches SDK regressions | Noisy on SDK upgrades | Suppress for first 24h after deploy |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Drop list misses a new frame attribute | PII shows up in storage | Periodic data-classification scan | Add to drop list; purge tainted partitions |
| Hashing salt static across tenants | Cross-tenant correlation possible | Hash collision audit | Per-tenant salt rotated quarterly |
| Symboliser cache poisoning | Wrong function names returned | Build-attestation verification fails | Flush cache; require attestation refresh |
| Routing processor cardinality blow-up | Memory pressure on collector | OTel collector OOM | Cap unique tenants per collector instance |
| Profile receiver public to internet | Anyone can submit profiles | Network policy audit | Bind to private network; mTLS-only |
| `X-Scope-OrgID` accepted from client | Cross-tenant read | Auth-proxy log review | Override header at proxy from JWT claim |
| SDK regression starts emitting raw HTTP body | Massive PII leak | Drop-rate alert fires | Roll back SDK; purge data |

## When to Consider a Managed Alternative

- **Polar Signals Cloud / Datadog Continuous Profiler / Elastic Universal Profiling** all run the redaction pipeline on the vendor side. If your data-residency posture allows, this is operationally lighter — but you must verify the vendor's contractual stance on PII in stack traces.
- **AWS CodeGuru Profiler / Google Cloud Profiler** have less control over redaction than self-hosted; suitable for non-sensitive workloads.
- **Self-hosted Pyroscope on GKE/EKS** plus this article's collector pipeline is the most flexible path.

## Related Articles

- [Continuous profiling security with Parca](/articles/observability/continuous-profiling-parca-security/)
- [OpenTelemetry Collector hardening](/articles/observability/otel-collector-hardening/)
- [OpenTelemetry PII leakage prevention](/articles/observability/otel-pii-leakage/)
- [Distributed tracing security model](/articles/observability/distributed-tracing-security/)
- [Beyla eBPF auto-instrumentation security](/articles/observability/beyla-ebpf-autoinstrumentation-security/)
