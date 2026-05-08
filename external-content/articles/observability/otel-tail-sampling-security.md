---
title: "OpenTelemetry Tail-Based Sampling for Security-Critical Traces"
description: "Configure OpenTelemetry Collector tail-based sampling to guarantee retention of security-relevant spans while controlling volume, and track OTel Collector CVEs from public PRs."
slug: otel-tail-sampling-security
date: 2026-05-02
lastmod: 2026-05-02
category: observability
tags: ["opentelemetry", "tail-sampling", "tracing", "otel-collector", "security-traces", "sampling"]
personas: ["sre", "security-engineer", "platform-engineer"]
article_number: 339
difficulty: intermediate
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/observability/otel-tail-sampling-security/index.html"
---

# OpenTelemetry Tail-Based Sampling for Security-Critical Traces

## Problem

Sampling is the mechanism by which a tracing system decides which traces to store and which to discard. At any meaningful production scale, retaining every trace is cost-prohibitive: a service handling ten thousand requests per second could generate tens of gigabytes of trace data per minute. The standard answer is sampling — but the details of when and how the sampling decision is made determine whether your tracing infrastructure is useful for security purposes at all.

Head-based sampling makes the keep-or-drop decision at the moment a trace starts. The most common implementation is probabilistic: flip a weighted coin and keep 1% or 5% of traces. Every SDK and collector that participates in that trace propagates the sampling decision in the `traceparent` header, so all spans in a kept trace are consistently stored, and all spans in a dropped trace are consistently discarded. The implementation is simple, memory-efficient, and predictable. The security problem is fundamental: the decision is made before a single span attribute has been observed. At the moment the coin is flipped, you do not know whether this trace will become an authentication failure, contain a database injection attempt, or be the only forensic record of a privilege escalation.

At 1% head-based sampling, 99 out of every 100 traces are discarded before they are observed. If your authentication service processes ten thousand login attempts during a credential stuffing attack, approximately nine thousand nine hundred of those traces are dropped. The Jaeger or Tempo instance that your incident response team queries the following morning will have, on average, one hundred traces of that attack — and those hundred are selected at random, not selected for their forensic value. The specific traces that contain `auth.result: denied` with unusual geographic attributes, unusual user-agent strings, or high request frequency from a single IP have the same 1% chance of retention as a benign successful login.

Tail-based sampling defers the decision until the full trace has been assembled. The OTel Collector's `tailsampling` processor buffers incoming spans, waits for a configurable `decision_wait` period, then evaluates the complete trace against a set of policies before deciding to keep or drop it. Because the decision is made on observed data rather than statistical chance, the policies can be precise: retain any trace where any span has `http.status_code >= 400`, retain any trace containing a span with `auth.result: denied`, retain any trace where the duration exceeds five seconds (a potential timing attack signal), retain any trace touching a specific resource path. Benign successful requests can still be sampled probabilistically at low rates, while security-relevant traces are guaranteed retention regardless of their volume.

The OTel Collector contrib repository that ships the `tailsampling` processor is a fast-moving project with weekly releases, and its release discipline for security issues does not match the pace of fixes. Memory-related bugs in the tail sampling processor — including a memory leak under high-cardinality trace IDs where the processor's in-flight trace map grew unboundedly until the Collector was OOM-killed — have been merged as ordinary code changes with titles like "fix memory leak in tailsampling processor" without a CVE or advisory. Similarly, the file-based exporter in the contrib repository had a path traversal fix merged as a routine maintenance PR. The vulnerability is visible in the diff to any reader watching the repository; the operational disclosure is not. A second class of correctness issue is more directly security-relevant: the `tailsampling` processor has had bugs where traces that arrived split across two `decision_wait` windows were given an incorrect sampling decision — sometimes retained when they should have been dropped, sometimes dropped when they should have been retained. The second case means your policy says "retain all auth failures" but a trace arriving near the window boundary may be silently dropped.

To track security-relevant changes without waiting for a CVE that may never arrive: subscribe to GitHub releases for both `open-telemetry/opentelemetry-collector` and `open-telemetry/opentelemetry-collector-contrib`; watch pull requests with the `processor/tailsampling` label; configure Dependabot or Renovate to open bump PRs when the Collector image version changes; and scan each CHANGELOG entry for the keywords `fix memory`, `fix path`, `bounds check`, `overflow`, and `leak`. This is the practical substitute for a formal advisory process that does not exist for this component.

Target systems: OTel Collector Contrib 0.100+, Jaeger 1.55+, Grafana Tempo 2.4+.

## Threat Model

1. **Attacker exploiting authentication bypass.** An attacker discovers an authentication bypass in the API gateway and issues several thousand unauthenticated requests over a thirty-minute window. With 1% head-based sampling, approximately thirty traces are retained — selected randomly. The traces that contain `http.status_code: 403`, `auth.bypass: true`, or unusual header patterns are statistically indistinguishable from retained traces and may not appear in the retained set at all. When the incident response team opens Jaeger, there is no trace evidence of the attack pattern, only normal-looking traffic.

2. **Insider performing low-and-slow data exfiltration.** An insider queries the database in small batches at irregular intervals over several weeks. Each individual span looks unremarkable: a `db.operation: SELECT`, a normal row count, a sub-second duration. Only a complete trace that combines the database span, the specific query parameters, the calling user identity, and the upstream HTTP context reveals the exfiltration pattern. With head-based sampling, the majority of these traces are dropped before any span is retained. Tail sampling with a policy matching the specific table name or the user identity preserves the complete forensic record.

3. **Patch-gap exploitation of the Collector itself.** A security fix for a memory exhaustion bug in the `tailsampling` processor is merged to `open-telemetry/opentelemetry-collector-contrib`. The PR is publicly visible in the repository for two weeks before the next collector release. An attacker monitoring the repo for such disclosures reads the diff, understands the trigger condition (high-cardinality trace IDs exceeding the in-flight map size), and begins sending crafted traces with randomized trace IDs at high volume. The Collector's memory grows until it is OOM-killed. While the Collector is down, all traces — including active security-critical traces — are dropped. Because no CVE was filed, no automated scanner flagged the risk, and the team has not yet upgraded.

4. **OTel Collector compromise via plugin or receiver vulnerability.** The OTel Collector occupies a privileged position in the observability architecture: it receives spans from every service, has network access to every trace backend, and may have credentials for exporters. A vulnerability in a contrib receiver — such as the Prometheus receiver, the OTLP/HTTP receiver, or a third-party extension — that allows remote code execution or credential extraction has blast radius equivalent to compromising the entire trace pipeline. An attacker with access to the Collector process can exfiltrate all traces including sensitive span attributes, inject false traces to mislead incident response, or pivot to backend systems using stored exporter credentials.

The common thread across these scenarios is that the Collector's central position and the opacity of sampling decisions both amplify risk. Tail sampling with auditable policies reduces the first two risks by guaranteeing forensic trace retention. Aggressive patch management and Collector hardening address the second two by treating the Collector as a security-critical component rather than infrastructure plumbing.

## Configuration / Implementation

### Tail Sampling Processor Basics

The `tailsampling` processor ships with `otelcol-contrib`, not the core distribution. The Collector pipeline buffers spans from all receivers, holds them for `decision_wait` seconds, then evaluates policies against the assembled trace.

```yaml
# otelcol-contrib config: processors section
processors:
  tail_sampling:
    # Wait this long after receiving the first span of a trace
    # before making the sampling decision. Must exceed your
    # longest legitimate trace duration.
    decision_wait: 10s
    # Maximum number of traces to hold in the decision buffer.
    # Exceeding this causes the oldest traces to be dropped.
    num_traces: 100000
    # Used to pre-size internal maps. Set to your expected
    # new-trace rate in traces per second.
    expected_new_traces_per_sec: 1000
    policies:
      - name: always-sample-errors
        type: status_code
        status_code:
          status_codes: [ERROR, UNSET]
```

The pipeline order must place `tail_sampling` before exporters and after receivers:

```yaml
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, tail_sampling, batch]
      exporters: [otlp/tempo]
```

`memory_limiter` must precede `tail_sampling` to prevent the in-flight trace buffer from exhausting all available memory when cardinality spikes.

### Security-Focused Sampling Policies

The `tailsampling` processor evaluates policies in order and uses the first matching policy's decision. Combine `or` and `and` composite policies to express security-first retention logic.

```yaml
processors:
  tail_sampling:
    decision_wait: 10s
    num_traces: 100000
    expected_new_traces_per_sec: 1000
    policies:

      # Policy 1: Always retain traces with any HTTP error status.
      # Catches 4xx client errors (auth failures, not-found probes)
      # and 5xx server errors (crashes, overloads, exploit attempts).
      - name: retain-http-errors
        type: status_code
        status_code:
          status_codes: [ERROR, UNSET]

      # Policy 2: Always retain traces containing auth denial spans.
      # Requires your services to set auth.result on the relevant span.
      - name: retain-auth-failures
        type: string_attribute
        string_attribute:
          key: auth.result
          values: ["denied", "failed", "unauthorized"]
          enabled_regex_matching: false

      # Policy 3: Retain high-latency traces.
      # Requests exceeding 5s may indicate timing-based attacks,
      # lock contention exploits, or algorithmic complexity attacks.
      - name: retain-high-latency
        type: latency
        latency:
          threshold_ms: 5000

      # Policy 4: Retain traces from a watchlist of user IDs.
      # Useful when an investigation has identified specific principals.
      - name: retain-watchlist-users
        type: string_attribute
        string_attribute:
          key: enduser.id
          values: ["suspect-user-1", "suspect-user-2"]
          enabled_regex_matching: true
          # Regex form for wildcard matching:
          # values: ["compromised-account-.*", "external-contractor-.*"]

      # Policy 5: Retain any trace touching sensitive database operations.
      # Tag your DB spans with db.operation to enable this.
      - name: retain-dangerous-db-ops
        type: string_attribute
        string_attribute:
          key: db.operation
          values: ["DROP", "TRUNCATE", "ALTER", "GRANT", "REVOKE"]
          enabled_regex_matching: false

      # Policy 6: Composite — retain traces matching ANY security signal.
      # This acts as a catch-all combining the above via OR logic.
      # Note: individual named policies above already fire first;
      # this composite is useful when embedding in a broader policy tree.
      - name: security-composite
        type: composite
        composite:
          max_total_spans_per_second: 5000
          policy_order:
            - retain-http-errors
            - retain-auth-failures
            - retain-high-latency
          rate_allocation:
            - policy: retain-http-errors
              percent: 100
            - policy: retain-auth-failures
              percent: 100
            - policy: retain-high-latency
              percent: 100

      # Policy 7: Probabilistic fallback for non-security traces.
      # Drop 99% of traces that did not match any security policy.
      # Place this LAST so security policies take priority.
      - name: probabilistic-fallback
        type: probabilistic
        probabilistic:
          sampling_percentage: 1
```

### Load Shedding Under High Volume

Under a volumetric attack, the `tail_sampling` processor may receive trace IDs at a rate that exceeds `num_traces`. When the buffer is full, the oldest in-flight traces are evicted without a sampling decision, which means they are dropped. Configure the `memory_limiter` processor upstream to apply backpressure before the tail sampler saturates, and set `num_traces` conservatively high while monitoring actual usage.

```yaml
processors:
  memory_limiter:
    # Refuse incoming data when heap reaches 80% of limit.
    # Collector should be deployed with a container memory limit set.
    limit_mib: 3072
    spike_limit_mib: 512
    check_interval: 5s
```

Set the container/pod memory limit above `limit_mib` to give the Collector headroom for non-trace memory. A Kubernetes resource spec:

```yaml
resources:
  requests:
    memory: "2Gi"
    cpu: "500m"
  limits:
    memory: "4Gi"
    cpu: "2"
```

### Monitoring Collector Resource Usage

The `tailsampling` processor exposes Prometheus metrics that indicate whether policies are functioning correctly. Alert on these rather than discovering failures during an incident.

```yaml
# Collector config: enable Prometheus metrics scraping
service:
  telemetry:
    metrics:
      address: "0.0.0.0:8888"
      level: detailed
```

Key metrics:

- `otelcol_processor_tail_sampling_count_traces_sampled` — total traces kept by each named policy. A sudden drop in `retain-auth-failures` matches while your authentication service is under attack should be alarming.
- `otelcol_processor_tail_sampling_global_count_traces_sampled` — total traces that reached a sampling decision. If this drops while `otelcol_receiver_accepted_spans` stays high, traces are being evicted from the buffer before a decision is made.
- `otelcol_processor_tail_sampling_sampling_decision_histogram` — latency of sampling decisions. Spikes indicate buffer pressure.
- `otelcol_processor_dropped_spans` — spans dropped due to backpressure or errors anywhere in the pipeline.

Prometheus alerting rules:

```yaml
groups:
  - name: otel-tail-sampling
    rules:

      - alert: TailSamplingTracesEvictedBeforeDecision
        expr: |
          increase(otelcol_processor_tail_sampling_global_count_traces_sampled[5m]) /
          increase(otelcol_receiver_accepted_spans[5m]) < 0.5
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "OTel Collector tail sampling: traces evicted before decision"
          description: >
            More than 50% of incoming spans are not reaching a sampling decision.
            The tail sampling buffer may be undersized or decision_wait is too long.

      - alert: TailSamplingAuthFailurePolicyInactive
        expr: |
          increase(otelcol_processor_tail_sampling_count_traces_sampled{policy="retain-auth-failures"}[15m]) == 0
        for: 30m
        labels:
          severity: info
        annotations:
          summary: "Auth failure sampling policy has matched no traces"
          description: >
            The retain-auth-failures tail sampling policy has not matched any traces
            in the last 30 minutes. Verify auth.result span attributes are being set.

      - alert: OTelCollectorMemoryPressure
        expr: |
          otelcol_process_memory_rss / (3072 * 1024 * 1024) > 0.85
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "OTel Collector memory above 85% of limit"
          description: >
            Collector RSS exceeds 85% of the configured memory_limiter threshold.
            Tail sampling buffer may be overrun. Check for cardinality spike.
```

### Tracking OTel Collector Security Issues

Because the OTel Collector contrib project does not consistently publish CVEs for security-adjacent fixes, proactive monitoring of the repository is the practical alternative.

Query open pull requests labeled `processor/tailsampling` using the GitHub API:

```bash
gh api repos/open-telemetry/opentelemetry-collector-contrib/pulls \
  --jq '.[] | select(
    (.labels // []) | map(.name) | contains(["processor/tailsampling"])
  ) | {number: .number, title: .title, url: .html_url}'
```

Scan CHANGELOG entries for security-adjacent language after each release:

```bash
# After upgrading the Collector image, diff the CHANGELOG
curl -s https://raw.githubusercontent.com/open-telemetry/opentelemetry-collector-contrib/main/CHANGELOG.md \
  | grep -iE "(fix memory|fix path|bounds check|overflow|leak|traversal|injection)" \
  | head -40
```

Configure Dependabot to open automatic bump PRs when the Collector image is updated. In `.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: docker
    directory: "/deploy/otelcol"
    schedule:
      interval: weekly
    labels:
      - "security"
      - "dependencies"
    commit-message:
      prefix: "chore(otel)"
```

Subscribe to GitHub release notifications for both repositories:

- https://github.com/open-telemetry/opentelemetry-collector/releases
- https://github.com/open-telemetry/opentelemetry-collector-contrib/releases

Use the GitHub watch feature (Watch > Custom > Releases) to receive email notifications without subscribing to all repository activity.

### Securing the Collector Itself

The Collector's privileged position justifies hardening it as a security-critical service.

```yaml
# otelcol-contrib config: TLS and authentication on OTLP receiver
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: "0.0.0.0:4317"
        tls:
          cert_file: /etc/otelcol/tls/tls.crt
          key_file: /etc/otelcol/tls/tls.key
          client_ca_file: /etc/otelcol/tls/ca.crt
        auth:
          authenticator: oidc
      http:
        endpoint: "0.0.0.0:4318"
        tls:
          cert_file: /etc/otelcol/tls/tls.crt
          key_file: /etc/otelcol/tls/tls.key

extensions:
  oidc:
    issuer_url: https://auth.internal/
    audience: otelcol

service:
  extensions: [oidc]
```

Kubernetes NetworkPolicy restricting Collector ingress to known namespaces:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: otelcol-ingress
  namespace: observability
spec:
  podSelector:
    matchLabels:
      app: otelcol
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              otel-instrumented: "true"
      ports:
        - port: 4317
          protocol: TCP
        - port: 4318
          protocol: TCP
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: observability
      ports:
        - port: 3200  # Grafana Tempo
          protocol: TCP
```

Run the Collector with minimal Linux capabilities in the pod security context:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
  readOnlyRootFilesystem: true
  seccompProfile:
    type: RuntimeDefault
```

## Expected Behaviour

| Signal | Head Sampling at 1% | Tail Sampling with Security Policies |
|---|---|---|
| Auth failure trace retention rate | ~1% (statistically random) | ~100% (explicit retain policy) |
| Forensic trace availability 1 hour post-incident | 1–5 traces from a 500-trace attack | All 500 traces retained |
| Collector memory under cardinality attack (high trace ID randomisation) | Not applicable — spans dropped at SDK | In-flight buffer grows; OOM if `memory_limiter` not configured |
| Security span drop rate (error, denied, anomalous) | 99% dropped, statistically indistinguishable | <1% dropped (only buffer eviction edge cases) |
| Benign successful request retention | 1% retained | ~1% retained (probabilistic fallback policy) |
| Collector CPU overhead | Minimal — no policy evaluation | Moderate — policy evaluation per assembled trace |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Tail sampling memory | All traces available for policy evaluation | Collector holds spans for `decision_wait` seconds; 100,000 in-flight traces at 1 KB average = ~100 MB minimum, more under attack | Set `num_traces` and `memory_limiter` based on measured cardinality; deploy Collector with explicit memory limits |
| Increased Collector CPU | Accurate, policy-driven retention | Policy evaluation runs per trace at decision time; complex composite policies multiply cost | Benchmark with production trace cardinality; scale Collector horizontally using a load-balancing exporter |
| Sampling decision latency | Complete traces available at decision time | Adds `decision_wait` (e.g., 10s) to the pipeline before traces reach the backend | `decision_wait` does not affect application latency — it is Collector-internal; configure backends to show "pending" traces |
| Policy maintenance | Precise security-relevant retention | Policies require ongoing maintenance as services evolve; a stale policy silently fails to match | Test policies in staging with synthetic security-relevant spans; alert on zero-match policies (see alerting rules above) |
| Split-trace risk | Mostly handled by Collector internals | Traces spanning multiple `decision_wait` windows may receive incorrect decisions in older Collector versions | Run Collector Contrib 0.100+ where split-trace handling was improved; monitor `sampling_decision_histogram` for decision-time outliers |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| `decision_wait` too short | Traces appear incomplete in Jaeger or Tempo; long-running spans missing from retained traces | `otelcol_processor_tail_sampling_sampling_decision_histogram` shows decisions before all spans arrive; trace completeness drops in backend | Increase `decision_wait` to exceed the 99th percentile of trace duration in your system; query `max(trace_duration_seconds)` in your backend |
| Collector OOM from in-flight trace buffer | Collector pod OOM-killed; all in-flight traces dropped; gap in trace coverage during restart | Kubernetes OOMKilled events; `otelcol_process_memory_rss` alert fires; gap in `otelcol_processor_tail_sampling_global_count_traces_sampled` | Reduce `num_traces`; lower `decision_wait`; increase Collector memory limit; add `memory_limiter` upstream of `tail_sampling` in the pipeline |
| Policy misconfiguration silently drops security-critical traces | Auth failure traces absent from backend despite known auth failures occurring | Zero-match alert on `retain-auth-failures` policy fires; cross-reference application auth failure logs against trace backend | Add synthetic test spans with known attributes to staging; validate policy match rate in pre-production before deploying policy changes |
| Collector version with tailsampling correctness bug | Security-critical traces randomly absent even with correct policy configuration; no error logged | No direct metric — requires comparing application-level error counts against retained trace counts for the same window | Monitor the `open-telemetry/opentelemetry-collector-contrib` CHANGELOG for tailsampling fixes; upgrade to a version where the bug is fixed; use Dependabot to stay current |

## Related Articles

- [OTel Collector Hardening](/articles/observability/otel-collector-hardening/)
- [OTel Collector Pipelines](/articles/observability/otel-collector-pipelines/)
- [Distributed Tracing Security](/articles/observability/distributed-tracing-security/)
- [Forensic Readiness](/articles/observability/forensic-readiness/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
