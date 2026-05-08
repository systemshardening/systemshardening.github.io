---
title: "OpenTelemetry Language SDK Security"
description: "Harden OpenTelemetry language SDKs against CVE-2026-40182 unbounded memory DoS in the OTLP exporter and CVE-2026-40891 gRPC trailer parsing DoS—and track silent fixes in fast-moving SDK releases."
slug: otel-sdk-security
date: 2026-05-03
lastmod: 2026-05-03
category: observability
tags: ["opentelemetry", "otel-sdk", "cve-2026-40182", "cve-2026-40891", "otlp", "grpc", "dos"]
personas: ["sre", "security-engineer", "platform-engineer"]
article_number: 387
difficulty: intermediate
estimated_reading_time: 15
published: true
layout: article.njk
permalink: "/articles/observability/otel-sdk-security/index.html"
---

# OpenTelemetry Language SDK Security

## Problem

The OTel Collector and the OTel language SDKs address different parts of the observability pipeline, and they present different security surfaces. The OTel Collector is a standalone process — a separate binary that receives telemetry from applications and routes it to backends. Its compromise or crash affects observability, but the applications themselves keep running. OTel language SDKs (`opentelemetry-dotnet`, `opentelemetry-java`, `opentelemetry-python`, `opentelemetry-go`, `opentelemetry-js`) are embedded directly in application code. They run in the same process as the application. A vulnerability that causes the SDK to allocate unbounded memory, enter an infinite loop, or panic does not take down a sidecar — it takes down the production service.

**CVE-2026-40182** (2026, Medium severity) is an unbounded memory allocation vulnerability in the OpenTelemetry .NET SDK's OTLP HTTP exporter. When the OTLP receiver returned a non-200 HTTP status code — a common scenario during backend downtime, misconfiguration, or network partition — the exporter read the entire HTTP response body without applying any size limit. An attacker who controls the OTLP endpoint, or who can perform a man-in-the-middle attack on the OTLP connection, can return a response body of arbitrary size (tens of gigabytes). The application process allocates the full response body into memory and crashes with an out-of-memory error. The affected range is `opentelemetry-dotnet` versions 1.13.1 up to but not including 1.15.2. The fix in v1.15.2 introduces a hard cap on the response body read size.

**CVE-2026-40891** (2026, Medium severity) is a denial-of-service vulnerability in the same SDK's handling of gRPC `grpc-status-details-bin` trailers in the OTLP/gRPC exporter. The OTel .NET SDK uses gRPC as an alternative transport for OTLP export. When parsing gRPC trailers received from a malicious or compromised OTLP receiver, certain crafted trailer values triggered an infinite loop (or excessive CPU spin) in the trailer parsing code. The result is 100% CPU consumption in the application process, rendering the service unresponsive. Both CVEs affect the same version range (1.13.1 to before 1.15.2) and are fixed together in v1.15.2.

The in-process attack surface is the critical distinction here. When an OTel SDK bug is triggered, the failure is not "observability is temporarily unavailable" — it is "the application is down." A production API service that exports traces or metrics to an OTLP endpoint which begins returning malformed or oversized error responses (due to a collector misconfiguration, a collector upgrade gone wrong, or an attacker controlling the collector endpoint) will crash due to the SDK bug. The outage is caused by observability infrastructure, but it presents as an application outage. Worse, because the SDK crash eliminates telemetry export, diagnosing the outage from inside the OTel pipeline is impossible — operators lose visibility precisely when they need it most.

The OpenTelemetry project spans multiple language repositories (`open-telemetry/opentelemetry-dotnet`, `open-telemetry/opentelemetry-java`, `open-telemetry/opentelemetry-python-contrib`, `open-telemetry/opentelemetry-go`, `open-telemetry/opentelemetry-js`), each maintained by different teams with varying security process maturity. CVE-2026-40182 and CVE-2026-40891 were fixed in `opentelemetry-dotnet` v1.15.2, but the release notes for that version described the changes as "bug fix in OTLP error response handling" and "fix gRPC trailer parsing" — not as security fixes. The CVEs were assigned and published to GitHub Security Advisories several days after the release. This gap matters operationally: organisations using Dependabot or Renovate to manage the `OpenTelemetry.*` NuGet packages would receive an auto-PR titled "Update OpenTelemetry.Exporter.OpenTelemetryProtocol to 1.15.2" with no security annotation, no urgency signal, and no mention of remote memory exhaustion. The same pattern has appeared in `opentelemetry-java`, where OTLP exporter fixes have been shipped under the label "performance improvement" before CVE assignment. Tracking this requires monitoring release changelogs, watching diffs in OTLP exporter files, and querying the GitHub Security Advisory API directly.

The practical toolchain for staying ahead of silent fixes: query `gh api repos/open-telemetry/opentelemetry-dotnet/security/advisories --jq '.[].summary'` in CI; watch the `src/OpenTelemetry.Exporter.OpenTelemetryProtocol/` directory for changes across releases; run `dotnet list package --vulnerable --include-transitive`, `pip-audit`, `npm audit`, `govulncheck ./...` against the SDK packages in every language your organisation uses; configure Renovate with `vulnerabilityAlerts.enabled = true` so that once a CVE is assigned, the resulting PR is promoted to a security update with higher priority.

**Target systems:** opentelemetry-dotnet 1.13.1–1.15.1 (CVE-2026-40182/40891); any application embedding an OTel SDK and exporting to an OTLP endpoint that may return errors.

## Threat Model

1. **CVE-2026-40182 — OTLP endpoint MITM DoS**: An attacker performs a man-in-the-middle attack on the OTLP/HTTP export path — via DNS poisoning of the collector's hostname, BGP hijack of the collector's IP, or compromise of a load balancer or Envoy sidecar that proxies OTLP traffic. The attacker intercepts the application's OTLP export request and returns a 503 response with a multi-gigabyte body. The application's OTel OTLP exporter (running in-process) allocates the full response into heap memory and crashes with OOM. The application outage coincides with observability failure, since the OTel SDK is no longer exporting. The attacker achieves a production outage and eliminates the traces that would have captured the attack.

2. **CVE-2026-40891 — gRPC trailer infinite loop**: The attacker controls or compromises the OTel Collector that receives the application's OTLP/gRPC telemetry. Rather than crashing the collector, the attacker reconfigures or patches it to return a malformed `grpc-status-details-bin` trailer in response to export requests. The SDK's trailer parsing enters an infinite loop; the application's CPU pegs at 100% and the service stops handling requests. This is particularly dangerous in Kubernetes: the readiness probe fails, the pod is marked unready, and traffic is routed to remaining pods — which are also all connecting to the same compromised collector and also fail. A single compromised collector can cascade to a complete cluster-wide outage.

3. **Silent fix exploitation**: An attacker reads the v1.15.2 release notes, notes the description "fix OTLP error response handling," and examines the diff in `OpenTelemetryProtocolExporterHttpEventSource.cs`. The root cause is clear before a CVE is assigned. The attacker identifies OTel Collector instances that are configured to return errors (401 Unauthorized for misconfigured auth tokens, 429 Too Many Requests under load) and scans for applications using SDK versions prior to 1.15.2. Because these applications are already triggering the error path in normal operations, the attacker knows the memory allocation path is live. Targeted 503 responses cause controlled OOM crashes timed to coincide with high traffic periods.

4. **Observability infrastructure as an attack pivot**: During an active security incident, an attacker who has already compromised the OTel Collector reconfigures it to return malformed responses to all connected applications. This triggers CVE-2026-40182 or CVE-2026-40891 simultaneously across the monitored fleet, crashing all applications at once and eliminating the trace and metric data that the incident response team is relying on. The attacker uses the OTel infrastructure — the system that should aid incident response — as the weapon to impede it.

The blast radius of these vulnerabilities scales with OTel SDK adoption. An organisation that has fully instrumented its microservices with OTel and exports via OTLP to a central collector has created a single dependency that, if manipulated, can crash every service simultaneously. Patching is necessary but not sufficient: the OTLP connection path itself must be secured with TLS (to prevent MITM exploitation of CVE-2026-40182) and the collector must be protected as a critical infrastructure component (to prevent the compromised-collector scenario that enables CVE-2026-40891 and the incident-response pivot). Network policy must restrict which pods can even reach the collector, limiting the attacker's ability to probe the OTLP path.

## Configuration / Implementation

### Upgrading OTel SDKs

The primary remediation for CVE-2026-40182 and CVE-2026-40891 is upgrading to `opentelemetry-dotnet` v1.15.2 or later. For other language SDKs, check the respective repositories for OTLP exporter fixes in the release notes and apply the latest stable release.

**.NET** — update the OTLP exporter package directly:

```bash
dotnet add package OpenTelemetry.Exporter.OpenTelemetryProtocol --version 1.15.2
dotnet add package OpenTelemetry.Extensions.Hosting --version 1.15.2

# Verify the installed version
dotnet list package | grep OpenTelemetry
```

**Java** — update the BOM version in Maven `pom.xml`:

```xml
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>io.opentelemetry</groupId>
      <artifactId>opentelemetry-bom</artifactId>
      <version>1.40.0</version>
      <type>pom</type>
      <scope>import</scope>
    </dependency>
  </dependencies>
</dependencyManagement>
```

Or in Gradle `build.gradle.kts`:

```kotlin
implementation(platform("io.opentelemetry:opentelemetry-bom:1.40.0"))
implementation("io.opentelemetry:opentelemetry-exporter-otlp")
```

**Python** — pin the exporter to a version without known CVEs:

```bash
pip install "opentelemetry-exporter-otlp-proto-http>=1.25.0" \
            "opentelemetry-exporter-otlp-proto-grpc>=1.25.0"

# Verify installed versions
pip show opentelemetry-exporter-otlp-proto-http | grep Version
```

**Go** — update to the latest stable module version:

```bash
go get go.opentelemetry.io/otel@latest
go get go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc@latest
go get go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp@latest
go mod tidy
```

**Node.js** — update via npm or yarn:

```bash
npm update @opentelemetry/exporter-trace-otlp-http \
           @opentelemetry/exporter-trace-otlp-grpc \
           @opentelemetry/exporter-metrics-otlp-http

# Check for remaining vulnerabilities
npm audit --omit=dev
```

### Response Body Size Limits and Circuit Breakers

Even on patched SDK versions, defence-in-depth requires limiting the blast radius if a future OTLP exporter vulnerability emerges. In .NET, set a conservative timeout on the OTLP exporter so that slow or oversized responses are abandoned:

```csharp
using OpenTelemetry.Exporter;

builder.Services.AddOpenTelemetry()
    .WithTracing(tracing =>
    {
        tracing.AddOtlpExporter(options =>
        {
            options.Endpoint = new Uri(
                Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT")
                ?? "http://otel-collector.monitoring.svc.cluster.local:4318");
            options.Protocol = OtlpExportProtocol.HttpProtobuf;
            // Hard timeout: abandon export if response takes > 5 seconds
            options.TimeoutMilliseconds = 5000;
        });
    });
```

Wrap OTel SDK initialisation with a circuit breaker (using Polly in .NET) so that repeated SDK failures do not cascade to application startup failure:

```csharp
using Polly;
using Polly.CircuitBreaker;

var otelCircuitBreaker = Policy
    .Handle<Exception>()
    .CircuitBreakerAsync(
        exceptionsAllowedBeforeBreaking: 5,
        durationOfBreak: TimeSpan.FromSeconds(30),
        onBreak: (ex, duration) =>
            logger.LogWarning("OTel SDK circuit breaker open for {Duration}s: {Message}",
                duration.TotalSeconds, ex.Message),
        onReset: () => logger.LogInformation("OTel SDK circuit breaker reset")
    );

try
{
    await otelCircuitBreaker.ExecuteAsync(() =>
        tracer.StartActiveSpan("operation", out _));
}
catch (BrokenCircuitException)
{
    // OTel is unavailable — application continues without telemetry
}
```

This pattern ensures that OTel SDK failures degrade to "no observability" rather than "application unavailable."

### OTLP Connection Security (TLS)

Unencrypted OTLP/HTTP (port 4318) and OTLP/gRPC (port 4317) are the default in many deployments, which makes MITM attacks (the primary exploitation vector for CVE-2026-40182) straightforward on any network segment where the attacker has a position. Enforcing TLS on the OTLP path eliminates this attack surface.

Configure OTLP exporters for TLS using environment variables (all OTel SDKs honour these):

```bash
# Use HTTPS endpoint for OTLP/HTTP
export OTEL_EXPORTER_OTLP_ENDPOINT="https://otel-collector.monitoring.svc.cluster.local:4318"

# For OTLP/gRPC with TLS (port 4317 with TLS)
export OTEL_EXPORTER_OTLP_ENDPOINT="https://otel-collector.monitoring.svc.cluster.local:4317"

# Mutual TLS: client certificate for application pod identity
export OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE="/var/run/secrets/otel/tls.crt"
export OTEL_EXPORTER_OTLP_CLIENT_KEY="/var/run/secrets/otel/tls.key"

# CA certificate if using a private PKI
export OTEL_EXPORTER_OTLP_CERTIFICATE="/var/run/secrets/otel/ca.crt"
```

In Kubernetes, mount the certificates from a Secret managed by cert-manager:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-application
spec:
  template:
    spec:
      containers:
        - name: app
          env:
            - name: OTEL_EXPORTER_OTLP_ENDPOINT
              value: "https://otel-collector.monitoring.svc.cluster.local:4318"
            - name: OTEL_EXPORTER_OTLP_CERTIFICATE
              value: "/var/run/secrets/otel-ca/ca.crt"
            - name: OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE
              value: "/var/run/secrets/otel-mtls/tls.crt"
            - name: OTEL_EXPORTER_OTLP_CLIENT_KEY
              value: "/var/run/secrets/otel-mtls/tls.key"
          volumeMounts:
            - name: otel-ca
              mountPath: /var/run/secrets/otel-ca
              readOnly: true
            - name: otel-mtls
              mountPath: /var/run/secrets/otel-mtls
              readOnly: true
      volumes:
        - name: otel-ca
          secret:
            secretName: otel-collector-ca
        - name: otel-mtls
          secret:
            secretName: my-application-otel-client-cert
```

The OTel Collector's OTLP receiver must be configured to require TLS and (if using mTLS) to validate client certificates. Add to the collector's `config.yaml`:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: "0.0.0.0:4318"
        tls:
          cert_file: /etc/otel/tls/tls.crt
          key_file: /etc/otel/tls/tls.key
          client_ca_file: /etc/otel/tls/ca.crt
      grpc:
        endpoint: "0.0.0.0:4317"
        tls:
          cert_file: /etc/otel/tls/tls.crt
          key_file: /etc/otel/tls/tls.key
          client_ca_file: /etc/otel/tls/ca.crt
```

### OTel Collector Endpoint Hardening

Restricting which pods can reach the OTLP receiver limits an attacker's ability to probe the collector with crafted responses and limits the blast radius if the collector is compromised.

Apply a Kubernetes NetworkPolicy that allows OTLP traffic only from instrumented application pods:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: otel-collector-ingress
  namespace: monitoring
spec:
  podSelector:
    matchLabels:
      app: otel-collector
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              otel-instrumented: "true"
        - podSelector:
            matchLabels:
              otel-export: "enabled"
      ports:
        - protocol: TCP
          port: 4317
        - protocol: TCP
          port: 4318
```

Label namespaces and pods that are permitted to send telemetry:

```bash
kubectl label namespace production otel-instrumented=true
kubectl label pods -l app=my-service otel-export=enabled -n production
```

The OTel Collector must not be reachable from the internet or from development namespaces. Monitor the collector's connection logs for unexpected source IPs — unexpected connections may indicate a compromised pod or an attacker probing the OTLP path.

### SDK Vulnerability Scanning in CI

Add OTel SDK vulnerability scanning as a required step in every language's CI pipeline. A vulnerability in the SDK can be silently introduced by a transitive dependency update, not just a direct SDK version bump.

**.NET** (add to CI pipeline, e.g., GitHub Actions):

```yaml
- name: Check for vulnerable NuGet packages
  run: |
    dotnet list package --vulnerable --include-transitive 2>&1 | tee vuln-report.txt
    if grep -q "has known vulnerabilities" vuln-report.txt; then
      echo "Vulnerable packages detected — failing build"
      cat vuln-report.txt
      exit 1
    fi
```

**Python**:

```yaml
- name: Audit Python dependencies for CVEs
  run: |
    pip install pip-audit
    pip-audit --requirement requirements.txt \
              --output-format json \
              --output pip-audit-report.json
    # Fail if any opentelemetry package has a known CVE
    jq -e '[.[] | select(.name | test("opentelemetry"))] | length == 0' \
       pip-audit-report.json
```

**Go**:

```yaml
- name: Run govulncheck
  run: |
    go install golang.org/x/vuln/cmd/govulncheck@latest
    govulncheck ./...
```

**Java** (OWASP Dependency Check via Maven):

```yaml
- name: OWASP Dependency Check
  run: |
    mvn org.owasp:dependency-check-maven:check \
      -DfailBuildOnCVSS=7 \
      -Dformat=JSON \
      -DoutputDirectory=target/dependency-check
```

**Node.js**:

```yaml
- name: npm audit for OTel packages
  run: |
    npm audit --omit=dev --json | \
      jq -e '[.vulnerabilities | to_entries[] |
              select(.key | test("opentelemetry"))] | length == 0'
```

### Monitoring OTel SDK Releases for Security Fixes

Because security fixes are often shipped as "bug fixes" before CVE assignment, monitor release changelogs for security-relevant terms:

```bash
# Query recent opentelemetry-dotnet releases for security-relevant content
gh api repos/open-telemetry/opentelemetry-dotnet/releases \
  --jq '.[0:10] | .[] |
    select(.body |
      test("security|CVE|fix.*otlp|fix.*grpc|fix.*exporter|memory|oom|infinite loop";
           "i")) |
    {tag: .tag_name, published: .published_at, summary: (.body | split("\n")[0])}'

# List current security advisories for the .NET SDK
gh api repos/open-telemetry/opentelemetry-dotnet/security/advisories \
  --jq '.[].summary'

# Watch the OTLP exporter directory for changes between versions
gh api repos/open-telemetry/opentelemetry-dotnet/commits \
  --field path="src/OpenTelemetry.Exporter.OpenTelemetryProtocol" \
  --jq '.[0:5] | .[] | {sha: .sha[0:8], message: .commit.message, date: .commit.author.date}'
```

Add the GitHub Advisory API query as a scheduled CI job that runs daily and opens an issue or sends a Slack alert when new advisories appear:

```yaml
# .github/workflows/otel-advisory-monitor.yaml
name: OTel Security Advisory Monitor
on:
  schedule:
    - cron: "0 8 * * *"
  workflow_dispatch: {}

jobs:
  check-advisories:
    runs-on: ubuntu-latest
    steps:
      - name: Check opentelemetry-dotnet advisories
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          gh api repos/open-telemetry/opentelemetry-dotnet/security/advisories \
            --jq '.[] | select(.state == "published") |
              {ghsa: .ghsa_id, summary: .summary, severity: .severity,
               published: .published_at}' > advisories.json
          cat advisories.json

      - name: Fail if high/critical advisories exist
        run: |
          HIGH=$(jq -r '[.[] | select(.severity == "high" or .severity == "critical")] | length' advisories.json)
          if [ "$HIGH" -gt 0 ]; then
            echo "High/critical OTel advisories found — review required"
            exit 1
          fi
```

Configure Renovate with vulnerability alert promotion so that once a CVE is assigned to an OTel package, the resulting PR is labelled as a security update and assigned higher priority:

```json
{
  "packageRules": [
    {
      "matchPackagePatterns": ["^OpenTelemetry", "^opentelemetry"],
      "matchUpdateTypes": ["patch", "minor"],
      "automerge": false,
      "labels": ["otel-sdk", "dependencies"],
      "reviewers": ["@platform-team"]
    }
  ],
  "vulnerabilityAlerts": {
    "enabled": true,
    "labels": ["security", "otel-sdk"],
    "assignees": ["@security-team"]
  }
}
```

## Expected Behaviour

| Signal | Vulnerable OTel SDK (pre-1.15.2) | Patched + TLS + CI Scanning |
|---|---|---|
| OTLP endpoint returns large error response body (503 + multi-GB body) | Application process allocates full response body, crashes with OOM; pod restarts; no traces captured during outage | Response read abandoned after timeout; export marked failed; application continues running; error logged and metric incremented |
| OTLP/gRPC receiver returns malformed `grpc-status-details-bin` trailer | Application thread enters infinite parsing loop; CPU pegs at 100%; readiness probe fails; pod evicted from load balancing | Trailer parsed safely with v1.15.2 fix; export returns error; retry backoff applied; application continues handling requests |
| MITM on unencrypted OTLP/HTTP connection | Attacker can inject arbitrary response body; CVE-2026-40182 fully exploitable | TLS prevents MITM interception; mTLS additionally verifies collector identity; injected responses rejected at TLS layer |
| `dotnet list package --vulnerable` run in CI | Command returns CVE-2026-40182 and CVE-2026-40891 for installed SDK version; CI pass/fail depends on whether step is configured | CI step detects vulnerability, fails build, and blocks deployment; engineer receives notification with CVE details and fix version |
| OTel SDK crash during active security incident | Loss of all trace/metric telemetry at the moment it is needed most; incident response team blind; crash causation unclear | Circuit breaker degrades gracefully to no-telemetry mode; application stays up; historical telemetry from pre-crash period available in backend |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| OTLP TLS (HTTP and gRPC) | Eliminates MITM exploitation of CVE-2026-40182; authenticates the collector to the SDK | Certificate provisioning and rotation overhead; cert-manager or equivalent required; TLS handshake latency on each connection | Use cert-manager with short-lived certs (24–48 h) and automatic rotation; benchmark OTLP/gRPC with TLS to confirm latency is within budget (typically <1 ms per export batch) |
| Response body size limit / timeout | Prevents unbounded memory allocation even against future exporter vulnerabilities; defence-in-depth beyond patch | A very slow but legitimate collector response (e.g., under heavy load) may be abandoned, causing export failures and gaps in telemetry | Set timeout conservatively but not aggressively (5–10 s); monitor export failure rate; alert if failure rate exceeds 1% |
| SDK upgrade (1.13.x → 1.15.2) | Fixes both CVEs; reduces exploitable attack surface | Minor version bumps in OTel SDKs can include API changes (attribute key renames, exporter option restructuring); integration tests may fail | Pin to a specific patch version in CI; run integration tests against the new SDK version in a staging environment before rolling out; review the full changelog for breaking changes |
| Circuit breaker around OTel SDK | Ensures application availability survives OTel SDK failures; breaks the dependency chain between observability and uptime | Adds code complexity; requires correct tuning of thresholds and break duration; failed-open means silent telemetry loss | Start with conservative thresholds (5 failures in 30 s, 30 s break); log circuit state changes at WARN level; add a `otel.circuit_breaker.state` metric if possible so the circuit breaker itself is observable |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| OTLP TLS certificate mismatch after rotation | All application OTLP exports fail silently (TLS handshake error logged but not alerted); traces and metrics stop appearing in backends; application health unaffected | Alert on OTel exporter error rate > 1% for > 5 minutes; monitor `otelcol_exporter_send_failed_spans_total` on the collector side (no incoming data); cert expiry alert 7 days before expiry | Roll back to previous certificate version in the Kubernetes Secret; trigger cert-manager re-issuance; validate OTLP connectivity with `grpcurl` or `curl` against the collector endpoint |
| Circuit breaker trips permanently on transient collector error | OTel SDK circuit breaker opens during a brief collector restart; half-open probe fails (collector still restarting); breaker stays open indefinitely; application runs without telemetry permanently | Alert if circuit breaker remains open > 5 minutes (log-based alert on "OTel SDK circuit breaker open" message); monitor absence of new traces in backend for > 10 minutes | Restart application pod to reset circuit breaker state; or implement a manual reset endpoint in the health API; increase break duration to allow collector more time to recover before probe |
| SDK minor version upgrade breaks existing instrumentation API | `AddOtlpExporter` constructor signature changes between 1.13 and 1.15; application fails to build; instrumentation attributes renamed, breaking existing dashboards | Build failure caught in CI before deployment; dashboard alert on missing metric labels post-deployment | Pin to exact version in package lock file; update application code to match new API; remap renamed attributes in the OTel Collector processor config to maintain dashboard compatibility |
| Renovate auto-PR for OTel SDK introduces breaking change merged without review | Breaking SDK change deployed to production; instrumentation stops working or application startup fails; Renovate bypassed manual review | Require at least one approval on all Renovate PRs for `OpenTelemetry.*` packages; smoke test OTel connectivity in staging as a required CI check | Revert the Renovate PR; pin the package to the previous known-good version; schedule a manual upgrade with testing |

## Related Articles

- [OTel Collector Hardening](/articles/observability/otel-collector-hardening/)
- [OTel Collector Pipelines](/articles/observability/otel-collector-pipelines/)
- [Prometheus Remote Write Security](/articles/observability/prometheus-remote-write-security/)
- [Distributed Tracing Security](/articles/observability/distributed-tracing-security/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
