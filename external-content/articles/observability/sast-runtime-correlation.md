---
title: "Correlating SAST Findings with Runtime Behaviour: Prioritising Reachable Vulnerabilities"
description: "SAST tools report thousands of findings — but most are in code paths that are never executed in production. Correlating static findings with runtime traces, error rates, and WAF telemetry identifies which vulnerabilities are in hot code paths, which are reachable from the internet, and which can be de-prioritised. This guide builds a SAST-to-runtime correlation pipeline using OpenTelemetry, distributed tracing, and SARIF metadata."
slug: sast-runtime-correlation
date: 2026-05-08
lastmod: 2026-05-08
category: observability
tags:
  - sast
  - runtime-analysis
  - vulnerability-prioritisation
  - opentelemetry
  - code-scanning
personas:
  - security-engineer
  - security-analyst
article_number: 645
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/observability/sast-runtime-correlation/
---

# Correlating SAST Findings with Runtime Behaviour: Prioritising Reachable Vulnerabilities

## Problem

Static Application Security Testing (SAST) tools are noisy by design. A single scan of a medium-to-large codebase using tools like Semgrep, CodeQL, or Checkmarx routinely produces hundreds or thousands of findings. For a team of four security engineers, this volume is unmanageable. Most findings will sit in a backlog for months, occasionally reviewed in bulk triage sessions that amount to educated guessing about which problems are real.

The core issue is that SAST operates on code as text. It does not know which functions are called in production, which endpoints are exposed to the public internet, which parameters accept user-controlled data, or which code paths have never been executed since the service was deployed. It reports what could go wrong, not what is going wrong or is likely to go wrong.

Three categories of SAST noise dominate large codebases:

**Dead code vulnerabilities.** Functions flagged for injection vulnerabilities that are never invoked — legacy code, feature-flagged paths that have been disabled for years, internal utilities that were replaced but not deleted. SAST has no way to distinguish these from active code paths without knowing the runtime call graph.

**Test code findings.** Many SAST configurations scan test fixtures by default. Test code frequently contains intentionally weak crypto, hardcoded credentials for local development, and patterns that would be dangerous in production. These findings pollute the backlog and train teams to ignore findings, which is the worst possible outcome.

**Low-traffic code paths.** A SQL injection in a database administration endpoint called twice a month by a single internal user behind a VPN is categorically different from a SQL injection in the main product search API handling 50,000 requests per hour from anonymous users. SAST assigns them the same severity.

The reachability gap is the specific failure mode this article addresses. A SAST tool reports that `UserService.findByEmail()` performs unsafe string concatenation in a SQL query. That is a valid static finding. But the relevant questions for prioritisation are:

- Is `findByEmail()` ever called in production? If so, how often?
- Is it reachable from the internet, or only from authenticated internal services?
- Is the parameter that reaches the unsafe concatenation actually user-controlled, or is it always a validated internal identifier?
- Is there a WAF rule that would block the most obvious exploitation patterns?

None of these questions can be answered by static analysis alone. Runtime observability data — distributed traces, WAF logs, error rates, function call counts — can answer all of them.

## Threat Model

**Security debt accumulation from triage paralysis.** A security team that cannot distinguish critical reachable vulnerabilities from theoretical low-risk ones will develop predictable failure patterns. Triage meetings focus on recently-discovered high-severity findings regardless of reachability. Older findings are de-prioritised simply because they are old. Remediation effort concentrates on whatever developers happen to notice or whatever was flagged in the most recent sprint. Real risk is not reduced; backlog is. The organisation accumulates security debt in code paths that are genuinely dangerous while spending cycles on findings that pose near-zero risk.

**Exploitation of an apparently low-priority finding.** The inverse failure mode: a SAST tool flags an injection vulnerability as medium severity because it is in a utility function with limited context about how that function is called. The security team de-prioritises it based on the static severity score. What static analysis missed is that the utility function is called from three hot API endpoints that are directly accessible from the internet and receive thousands of requests per minute. An attacker conducting routine scanning discovers the vulnerability; the organisation had data to deprioritise it and acted on incomplete information.

**False de-prioritisation through coverage gaps.** If the runtime correlation pipeline is not instrumented comprehensively, a code path that is active but not traced will appear to be inactive. A finding correlated against tracing data that shows zero calls could be a genuine dead-code finding or a critical code path with no OpenTelemetry instrumentation. Acting on the former conclusion without verifying the latter creates a systematic blind spot.

## Configuration and Implementation

### SARIF Enrichment with Runtime Metadata

SARIF (Static Analysis Results Interchange Format) is the standard output format for SAST tools. It is JSON, versioned at schema 2.1.0, and supports custom properties at the result level. Enriching SARIF findings with runtime metadata keeps the vulnerability record, the static finding, and the runtime context in a single artifact.

A minimal SARIF result object looks like:

```json
{
  "ruleId": "sql-injection",
  "level": "error",
  "message": { "text": "Unsanitised input passed to SQL query" },
  "locations": [{
    "physicalLocation": {
      "artifactLocation": { "uri": "src/services/user_service.py" },
      "region": { "startLine": 142, "startColumn": 12 }
    },
    "logicalLocations": [{
      "name": "UserService.findByEmail",
      "kind": "function"
    }]
  }]
}
```

The `properties` field on a SARIF result accepts arbitrary key-value pairs. Enriched runtime properties to add:

```json
{
  "properties": {
    "runtimeCallCount": 18432,
    "callsPerDay": 614,
    "lastObservedInTrace": "2026-05-06T14:22:11Z",
    "publiclyReachable": true,
    "wafCoverage": "partial",
    "reachabilityScore": 87,
    "traceQueryUrl": "https://tempo.internal/explore?expr=..."
  }
}
```

The following Python script queries a Tempo/Jaeger backend and enriches a SARIF file with this data:

```python
import json
import requests
from datetime import datetime, timedelta

TEMPO_URL = "http://tempo.monitoring.svc:3100"
SARIF_INPUT = "scan-results.sarif"
SARIF_OUTPUT = "scan-results-enriched.sarif"
LOOKBACK_DAYS = 30

def query_function_call_count(filepath: str, function_name: str) -> dict:
    """Query Tempo for spans matching this function in the last LOOKBACK_DAYS days."""
    since = (datetime.utcnow() - timedelta(days=LOOKBACK_DAYS)).isoformat() + "Z"
    
    # Tempo TraceQL query: find spans with matching code attributes
    query = (
        f'{{span.code.filepath=~".*{filepath.split("/")[-1]}" '
        f'&& span.code.function="{function_name}"}}'
    )
    resp = requests.get(
        f"{TEMPO_URL}/api/search",
        params={"q": query, "start": since, "limit": 1000},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    
    traces = data.get("traces", [])
    span_count = sum(t.get("spanSet", {}).get("matched", 0) for t in traces)
    last_seen = None
    if traces:
        last_seen = max(
            t.get("startTimeUnixNano", "0") for t in traces
        )
        last_seen = datetime.utcfromtimestamp(
            int(last_seen) / 1e9
        ).isoformat() + "Z"
    
    return {
        "runtimeCallCount": span_count,
        "callsPerDay": round(span_count / LOOKBACK_DAYS, 1),
        "lastObservedInTrace": last_seen,
    }

def enrich_sarif(sarif_path: str, output_path: str):
    with open(sarif_path) as f:
        sarif = json.load(f)

    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                logical = loc.get("logicalLocations", [{}])[0]
                
                filepath = phys.get("artifactLocation", {}).get("uri", "")
                function_name = logical.get("name", "")
                
                if not filepath or not function_name:
                    continue
                
                runtime_data = query_function_call_count(filepath, function_name)
                
                props = result.setdefault("properties", {})
                props.update(runtime_data)
                props["reachabilityScore"] = compute_reachability_score(
                    result, runtime_data
                )

    with open(output_path, "w") as f:
        json.dump(sarif, f, indent=2)
    print(f"Enriched SARIF written to {output_path}")

if __name__ == "__main__":
    enrich_sarif(SARIF_INPUT, SARIF_OUTPUT)
```

### Extracting Code Path Data from Distributed Traces

OpenTelemetry defines semantic conventions for code-level span attributes. When auto-instrumentation or manual instrumentation is configured to capture stack frames, spans include:

- `code.function` — the function or method name, e.g. `UserService.findByEmail`
- `code.filepath` — relative or absolute path to the source file
- `code.lineno` — line number within the file
- `code.namespace` — class or module containing the function

These attributes are not captured by default in most auto-instrumentation libraries because of the performance cost of stack inspection. They must be enabled explicitly. In Python, using the OpenTelemetry SDK:

```python
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider

tracer = trace.get_tracer(__name__)

def find_by_email(email: str):
    with tracer.start_as_current_span(
        "UserService.findByEmail",
        attributes={
            "code.function": "find_by_email",
            "code.filepath": "src/services/user_service.py",
            "code.lineno": 142,
            "code.namespace": "UserService",
        }
    ) as span:
        # function body
        pass
```

For Elasticsearch-backed trace storage, the following query finds all traces containing the target function in the last 30 days:

```json
GET traces-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "term": { "Span.attributes.code.function": "find_by_email" } },
        { "term": { "Span.attributes.code.filepath": "src/services/user_service.py" } },
        { "range": { "@timestamp": { "gte": "now-30d" } } }
      ]
    }
  },
  "aggs": {
    "call_count": { "value_count": { "field": "Span.spanId" } },
    "last_seen": { "max": { "field": "@timestamp" } }
  },
  "size": 0
}
```

The aggregation returns `call_count.value` (total span count in 30 days) and `last_seen.value_as_string` (ISO timestamp of the most recent call). These two values feed directly into the SARIF enrichment script.

### WAF Log Correlation

WAF telemetry provides the strongest signal for confirming that a vulnerable code path is reachable from the public internet. If a WAF rule is blocking requests targeting a parameter that a SAST tool flagged for injection, the finding is not just reachable — exploitation is being actively attempted.

For AWS WAF, log entries are delivered to S3 or CloudWatch Logs in JSON format. A relevant log entry for a blocked SQL injection attempt:

```json
{
  "timestamp": 1746700800000,
  "action": "BLOCK",
  "httpRequest": {
    "uri": "/api/users/search",
    "args": "email=admin%27+OR+1%3D1--",
    "httpMethod": "GET"
  },
  "terminatingRuleId": "AWSManagedRulesSQLiRuleSet",
  "ruleGroupList": [...]
}
```

Matching WAF block events to SAST findings requires mapping the WAF's `uri` field to the function that handles that route, which in turn must match the `locations` in the SARIF finding. This mapping is built from the application's routing table — in Flask, for example, `app.url_map` can be serialised to a JSON file during the build process, creating a static route-to-function mapping that the enrichment script uses.

Prometheus metric for WAF blocks per endpoint, suitable for Grafana alerting:

```yaml
# prometheus-waf-exporter configuration
rules:
  - record: waf_blocks_per_endpoint_total
    expr: sum by (uri, rule_id) (aws_waf_blocked_requests_total)
```

A SAST finding whose associated endpoint shows `waf_blocks_per_endpoint_total > 0` in the last 7 days receives a `publiclyReachable: true` flag and a significant reachability score boost.

### Building a Vulnerability Reachability Score

The reachability score combines five dimensions into a single 0–100 value:

| Dimension | Description | Max Weight |
|---|---|---|
| Static severity | CVSS base score normalised to 0–100 | 30 |
| Call frequency | Log-scaled calls per day in production | 25 |
| Public reachability | Boolean: is the endpoint internet-accessible | 20 |
| WAF coverage | Does an active WAF rule cover the exploitation pattern | 15 |
| Recency | How recently was the code path observed | 10 |

```python
import math
from dataclasses import dataclass
from typing import Optional

@dataclass
class SASTFinding:
    cvss_score: float          # 0.0–10.0
    calls_per_day: float       # from distributed traces
    publicly_reachable: bool   # from WAF/network topology data
    waf_blocks_last_7d: int    # WAF block count for this endpoint
    days_since_last_trace: Optional[int]  # None if never observed

def compute_reachability_score(finding: SASTFinding) -> int:
    # Static severity (0–30)
    severity_score = (finding.cvss_score / 10.0) * 30

    # Call frequency: log scale, 0 calls = 0 points, 10k+/day = 25 points
    if finding.calls_per_day <= 0:
        frequency_score = 0.0
    else:
        frequency_score = min(25.0, (math.log10(finding.calls_per_day + 1) / 4.0) * 25)

    # Public reachability (0 or 20)
    reachability_score = 20.0 if finding.publicly_reachable else 0.0

    # WAF coverage: presence of WAF blocks confirms reachability;
    # absence of WAF rule on a public endpoint is a risk multiplier
    if finding.waf_blocks_last_7d > 0:
        waf_score = 15.0  # confirmed exploitation attempts
    elif finding.publicly_reachable:
        waf_score = 10.0  # reachable but WAF not blocking (gap)
    else:
        waf_score = 0.0

    # Recency (0–10): never traced = 0, traced within 1 day = 10
    if finding.days_since_last_trace is None:
        recency_score = 0.0
    else:
        recency_score = max(0.0, 10.0 - (finding.days_since_last_trace / 30.0) * 10)

    total = severity_score + frequency_score + reachability_score + waf_score + recency_score
    return round(min(100.0, total))
```

A critical SQL injection (CVSS 9.0) in a function called 5,000 times per day from the internet with active WAF block events scores approximately 94/100 — immediate action required. The same SQL injection in a function with zero calls in 30 days, no WAF events, and not on a public endpoint scores approximately 27/100 — defer.

### Integration with GitHub Code Scanning

GitHub Code Scanning accepts SARIF files via the REST API and displays findings as alerts in the Security tab. The same API supports updating alert states and adding comments, enabling automated feedback loops.

After enriching a SARIF file, resubmit it to update displayed severity:

```bash
# Upload enriched SARIF to GitHub Code Scanning
gh api \
  --method POST \
  -H "Accept: application/vnd.github+json" \
  /repos/{owner}/{repo}/code-scanning/sarifs \
  --field commit_sha="$(git rev-parse HEAD)" \
  --field ref="refs/heads/main" \
  --field sarif="$(gzip -c scan-results-enriched.sarif | base64 -w0)" \
  --field tool_name="semgrep-with-runtime-context"
```

To add runtime context comments to existing alerts and auto-close confirmed dead-code findings:

```python
import os
import requests

GH_TOKEN = os.environ["GITHUB_TOKEN"]
REPO = "org/repo"
HEADERS = {
    "Authorization": f"Bearer {GH_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

def update_alert_with_runtime_data(alert_number: int, finding: dict):
    calls_per_day = finding["properties"].get("callsPerDay", 0)
    score = finding["properties"].get("reachabilityScore", 0)
    last_seen = finding["properties"].get("lastObservedInTrace", "never")
    
    # Add a comment with runtime context
    comment_body = (
        f"**Runtime Reachability Analysis**\n\n"
        f"- Calls per day (30-day average): `{calls_per_day}`\n"
        f"- Last observed in production trace: `{last_seen}`\n"
        f"- Publicly reachable: `{finding['properties'].get('publiclyReachable', False)}`\n"
        f"- WAF coverage: `{finding['properties'].get('wafCoverage', 'unknown')}`\n"
        f"- **Reachability score: {score}/100**\n\n"
        f"Score threshold: 70+ = immediate action, 30–69 = scheduled, <30 = defer."
    )
    
    # GitHub Code Scanning API does not support alert comments directly;
    # post to the associated PR or issue thread instead.
    # Auto-dismiss findings that have never been observed in 90+ days:
    days_since = finding["properties"].get("daysSinceLastTrace")
    if days_since is not None and days_since > 90 and not finding["properties"].get("publiclyReachable"):
        requests.patch(
            f"https://api.github.com/repos/{REPO}/code-scanning/alerts/{alert_number}",
            headers=HEADERS,
            json={
                "state": "dismissed",
                "dismissed_reason": "won't fix",
                "dismissed_comment": (
                    f"Automatically dismissed: code path not observed in production "
                    f"traces for {days_since} days and not on a publicly reachable endpoint. "
                    f"Reachability score: {score}/100."
                ),
            },
        )
```

The 90-day threshold for auto-dismissal should be treated as a policy decision, not a technical default. Teams should start with manual review of proposed auto-dismissals before enabling automated closure.

### Dashboard: SAST Findings by Runtime Risk

A Grafana dashboard backed by the enriched SARIF data — loaded into a time-series database or a JSON datasource — visualises the full finding population on a scatter plot with static CVSS severity on one axis and runtime calls-per-day on the other. Four quadrants define action categories:

- **Top-right (high severity, high call frequency):** Immediate action. These are the findings where exploitation is both easy and high-impact, and where the vulnerable code is demonstrably active.
- **Top-left (high severity, low call frequency):** Scheduled remediation. The vulnerability is serious but exposure is limited. Remediate within the current quarter.
- **Bottom-right (low severity, high call frequency):** Assess for chaining. Low severity individually but the code is active and reachable. Evaluate whether findings in this quadrant can be chained with others.
- **Bottom-left (low severity, low call frequency):** Defer indefinitely. Revisit if the code path's call frequency increases.

The dashboard should also show:

- Count of findings auto-dismissed as never-observed vs. manually triaged
- WAF block rate trend for endpoints with open SAST findings
- Coverage ratio: instrumented functions as a percentage of all functions with SAST findings

### Coverage Gaps

The most dangerous failure mode is systematic under-coverage in distributed tracing leading to false de-prioritisation. Specific coverage gaps to audit:

**Batch jobs and scheduled tasks.** A Kubernetes CronJob running a data export function once per day will produce spans only during its execution window. A 30-day lookback query run outside that window will find some calls; a 1-day lookback will find zero. Enrich SARIF for batch job code paths with a separate data source — job execution logs or a dedicated metrics counter — rather than relying on trace volume.

**Application startup code.** Initialisation functions run once at startup and may never appear in traces from normal request handling. Injection vulnerabilities in configuration loading or database connection setup may be just as dangerous as vulnerabilities in request handlers, but will show zero runtime calls after the first deployment.

**Error handlers and exception paths.** Code paths that only execute when an exception is thrown may show very low trace volume under normal conditions. A vulnerability in an exception handler that fires when authentication fails may be precisely the vulnerability an attacker would trigger.

**Distinguishing "never called" from "called but not instrumented".** Before treating zero-call SAST findings as safe to defer, cross-reference against a function-level instrumentation coverage map. If `UserService.findByEmail` has no traces but also has no OpenTelemetry spans anywhere in its call stack, the absence of trace data says nothing about whether it is called in production.

## Expected Behaviour

| SAST Finding Type | Runtime Correlation Signal | Priority Adjustment |
|---|---|---|
| SQL injection in API handler | 15,000 calls/day, publicly reachable, WAF partial | Critical — immediate fix |
| XSS in admin template renderer | 200 calls/day, requires admin auth, no WAF | High — schedule this sprint |
| Path traversal in file export | 0 calls in 60 days, internal only | Low — defer, mark for review |
| Command injection in legacy CLI tool | 0 calls in 90 days, no network exposure | Dismiss — not reachable |
| Insecure deserialisation in message consumer | 500 calls/day, internal service only | Medium — next quarter |
| Hardcoded credential in test fixture | Test code, never deployed | Dismiss — test artifact |
| SSRF in webhook handler | 50 calls/day, publicly reachable, no WAF | High — active risk, no mitigating control |
| Weak crypto in session token generation | 20,000 calls/day, publicly reachable | Critical — active cryptographic exposure |

## Trade-offs

**Trace storage cost.** Storing function-level span attributes (`code.function`, `code.filepath`, `code.lineno`) on every span increases trace payload size. At high request volumes, enabling code-level attributes across all services may increase trace storage costs by 20–40%. Selective instrumentation — enabling code-level attributes only on services with open SAST findings — balances cost against coverage.

**Instrumentation coverage gaps.** Reachability scoring is only as reliable as the tracing coverage it is based on. A team that scores its instrumentation coverage at 60% and acts on zero-call findings as confirmed dead code is operating on a significant false-premises risk. Coverage gaps in tracing must be tracked as a security metric, not just an observability gap.

**False de-prioritisation risk.** Never-called today does not mean never-exploitable. A dormant code path that is activated by a new feature, a configuration change, or a dependency update can move from zero-calls to critical-path in a single deployment. Enriched SARIF findings dismissed as unreachable should be flagged for re-evaluation on any code change that touches the same file or module. A CI hook that re-runs reachability scoring for findings in modified files costs minimal CI time and closes the stale-dismissal gap.

**Dependency on tracing infrastructure reliability.** If the correlation pipeline depends on Tempo or Jaeger being available, a tracing outage creates a window during which new SAST findings cannot be enriched. The enrichment script should fail open — producing SARIF output with `reachabilityScore: null` rather than failing the pipeline — and alerts on missing enrichment data should be treated as a signal to investigate tracing availability.

## Failure Modes

**Tracing coverage gaps causing silent de-prioritisation.** The most consequential failure mode. A critical code path with no instrumentation produces zero trace hits, which the enrichment script reads as "never called," which results in a score of 27/100 and a deferred finding. Mitigation: instrument a coverage completeness metric (`instrumented_functions / total_functions_with_sast_findings`) and alert when it falls below a threshold. Do not auto-dismiss findings in uninstrumented code paths.

**SARIF format changes breaking the enrichment pipeline.** SARIF 2.1.0 has been stable, but tool-specific extensions and schema deviations are common. Semgrep, CodeQL, and Checkmarx each emit SARIF with slightly different structures for logical locations and custom properties. The enrichment script should validate input SARIF structure before processing and fail with a schema error rather than silently producing a partially-enriched output file.

**Code path matching failures from minification or obfuscation.** In compiled or transpiled languages (Go, TypeScript compiled to JavaScript, Java compiled to JVM bytecode), the `code.function` and `code.filepath` attributes in a span may not match the source-level identifiers in the SARIF finding. Minified JavaScript functions lose their names entirely. The matching logic must account for source maps in JavaScript services and use class+method identifiers from build metadata rather than compiled artifacts in JVM services. For Go, the function name in a span (`code.function`) matches the fully-qualified source identifier, making correlation straightforward.

**Stale enrichment on old findings.** A SARIF finding enriched 90 days ago with a zero-call score may have been accurate at enrichment time but irrelevant now because the feature was re-enabled last week. Enrichment should be re-run on all open findings on a schedule — weekly for low-score findings, daily for high-score findings near the auto-dismiss threshold. Findings should display their enrichment timestamp prominently in dashboards so reviewers can identify stale scores.
