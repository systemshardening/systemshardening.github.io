---
title: "AI Agent Observability and Tracing: OpenTelemetry for Agent Runs and Tool Calls"
description: "An agent's run is a graph of model calls, tool invocations, and decisions. Observability that maps cleanly to that graph is the difference between debugging and guessing."
slug: "ai-agent-observability"
date: 2026-04-29
lastmod: 2026-04-29
category: "ai-landscape"
tags: ["agent", "observability", "opentelemetry", "tracing", "ai-security"]
personas: ["security-engineer", "ml-engineer", "platform-engineer"]
article_number: 225
difficulty: "intermediate"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/ai-landscape/ai-agent-observability/index.html"
---

# AI Agent Observability and Tracing: OpenTelemetry for Agent Runs and Tool Calls

## Problem

A production AI agent's single run involves:

- Multiple model calls (planner, executor, summarizer).
- Tool invocations (database queries, API calls, MCP tools).
- Memory reads and writes.
- Internal control-flow decisions.
- Possibly recursive sub-agent calls.

When something goes wrong — wrong tool invoked, leaked data, hallucinated output, runaway tool-call loop — the question is "what happened" and the answer is in the trace. By 2026 the OpenTelemetry semantic conventions for GenAI (`gen_ai.*` namespace) are stable; agent frameworks (LangGraph, AutoGen, Anthropic SDK, OpenAI Agents) emit OTel traces by default or via thin shims.

The structural observability shape:

- **Each run is a trace.** A run has a root span; child spans for each step.
- **Each model call is a span.** Tagged with model, prompt token count, completion token count, finish reason.
- **Each tool call is a span.** Tagged with tool name, arguments (often hashed), duration, return-value type.
- **Each memory operation is a span.** Reads, writes, retrieval scores.
- **Each decision branch is a span event.** Annotates why a particular path was taken.

The observability data has security uses:

- **Detect anomalous tool-call patterns.** A burst of `delete_*` calls or unusual sequences flag attacks-via-prompt-injection.
- **Track per-tenant agent cost** for billing and abuse detection.
- **Forensics for incidents** — when an agent did something wrong, the trace shows the chain of model decisions.
- **Compliance evidence** — auditable record of what an autonomous system did and why.

The specific gaps in default agent deployments:

- Tracing is often left to the agent framework's own pipeline (logs to stdout, not aggregated).
- Tool-call arguments may be logged with sensitive content (PII, customer data).
- Per-run costs aren't attributed to tenants.
- Anomaly-detection on tool-use patterns isn't run.
- Long-running agent runs blow out trace ingest budgets.

This article covers OTel semantic conventions for agents, span hierarchy patterns, redaction at the SDK boundary, anomaly detection on tool-use, and per-tenant cost attribution.

**Target systems:** OpenTelemetry SDK 1.30+ with `gen_ai` semantic conventions; Anthropic SDK with native OTel support; LangSmith / Langfuse / Helicone as commercial agent observability tools; Tempo / Jaeger / Honeycomb as backend.

## Threat Model

- **Adversary 1 — Prompt-injection-driven anomalous tool calls:** an attacker has gotten content into the agent's input that causes unusual tool calls; defender wants to detect and shut down.
- **Adversary 2 — Cost-exhaustion abuse:** a misbehaving (or malicious) agent loops on tool calls; defender wants to detect and bound.
- **Adversary 3 — Data exfil via tool outputs:** an agent run reads sensitive data; defender wants to know what data the agent saw.
- **Adversary 4 — PII leakage in logged spans:** observability captures request bodies that contain customer data; insider with trace-store access reads them.
- **Adversary 5 — Audit gap exploitation:** attacker takes advantage of trace-data deletion or non-aggregation to act untraced.
- **Access level:** all adversaries have only normal user-agent interaction.
- **Objective:** Read sensitive data; cause the agent to act outside intended scope; act without leaving forensic traces.
- **Blast radius:** without good observability, attacks via the agent are slow to detect and hard to investigate. With observability + redaction, agent actions are visible while sensitive data is not exposed in logs.

## Configuration

### Step 1: OTel Agent Semantic Conventions

The `gen_ai` namespace defines standard span attributes:

```
gen_ai.system           # vendor (anthropic, openai, ollama)
gen_ai.request.model    # model name
gen_ai.response.model   # model that actually responded
gen_ai.usage.input_tokens
gen_ai.usage.output_tokens
gen_ai.response.finish_reason   # stop, length, tool_calls
gen_ai.request.temperature
gen_ai.request.max_tokens
gen_ai.tool.name
gen_ai.tool.call.id
gen_ai.operation.name   # chat, embed, tool_call
```

Use these consistently; backends understand them.

### Step 2: Span Hierarchy for an Agent Run

```python
# agent_traced.py
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
import json, hashlib

tracer = trace.get_tracer("my-agent")

class AgentRun:
    def __init__(self, user_id, task):
        self.user_id = user_id
        self.task = task

    def execute(self):
        # Root span for the agent run.
        with tracer.start_as_current_span("agent.run") as run_span:
            run_span.set_attribute("agent.user_id", self.user_id)
            run_span.set_attribute("agent.task_hash",
                hashlib.sha256(self.task.encode()).hexdigest()[:16])
            run_span.set_attribute("gen_ai.operation.name", "agent.execute")

            try:
                plan = self._plan()
                results = self._execute_plan(plan)
                summary = self._summarize(results)
                return summary
            except Exception as e:
                run_span.set_status(Status(StatusCode.ERROR, str(e)))
                raise

    def _plan(self):
        with tracer.start_as_current_span("agent.plan") as span:
            span.set_attribute("gen_ai.operation.name", "chat")
            span.set_attribute("gen_ai.system", "anthropic")
            span.set_attribute("gen_ai.request.model", "claude-opus-4-7")
            response = anthropic_client.messages.create(...)
            span.set_attribute("gen_ai.usage.input_tokens", response.usage.input_tokens)
            span.set_attribute("gen_ai.usage.output_tokens", response.usage.output_tokens)
            span.set_attribute("gen_ai.response.finish_reason", response.stop_reason)
            return response.content

    def _execute_plan(self, plan):
        with tracer.start_as_current_span("agent.execute_plan") as span:
            results = []
            for step in plan:
                results.append(self._execute_step(step))
            return results

    def _execute_step(self, step):
        with tracer.start_as_current_span(f"agent.tool_call.{step.tool}") as span:
            span.set_attribute("gen_ai.operation.name", "tool_call")
            span.set_attribute("gen_ai.tool.name", step.tool)
            # Hash arguments rather than logging them — see Step 3.
            args_json = json.dumps(step.args, sort_keys=True)
            span.set_attribute("gen_ai.tool.args_hash",
                hashlib.sha256(args_json.encode()).hexdigest()[:16])
            span.set_attribute("gen_ai.tool.args_size_bytes", len(args_json))
            try:
                return step.tool_fn(step.args)
            except Exception as e:
                span.set_status(Status(StatusCode.ERROR, str(e)))
                raise
```

The trace tree:

```
agent.run
├── agent.plan         (model call to planner)
├── agent.execute_plan
│   ├── agent.tool_call.search_docs
│   ├── agent.tool_call.fetch_records
│   └── agent.tool_call.summarize_for_user
└── agent.summarize    (model call to summarizer)
```

A backend like Tempo, Honeycomb, or Langfuse renders this as a flame graph.

### Step 3: Redaction at the SDK Boundary

Tool arguments and model prompts often contain user PII or business-sensitive content. Don't log them verbatim.

```python
# safe_attributes.py
import re, hashlib

SENSITIVE_PATTERNS = [
    re.compile(r'(?i)(?<=password["\']?\s*[:=]\s*["\']?)[^\s"\',}]+', re.IGNORECASE),
    re.compile(r'(?i)(?<=api_key["\']?\s*[:=]\s*["\']?)[^\s"\',}]+'),
    re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),  # email
    re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),  # SSN
    re.compile(r'sk-[A-Za-z0-9]{32,}'),    # API key prefix
]

def safe_log_value(s: str, max_len: int = 200) -> dict:
    """Return a dict suitable for span.set_attribute that doesn't leak."""
    for pat in SENSITIVE_PATTERNS:
        s = pat.sub("[REDACTED]", s)
    return {
        "value_redacted": s[:max_len] + ("..." if len(s) > max_len else ""),
        "value_size": len(s),
        "value_hash": hashlib.sha256(s.encode()).hexdigest()[:16],
    }

# Use throughout agent code.
def log_user_input(span, user_input):
    safe = safe_log_value(user_input)
    span.set_attribute("agent.user_input.size", safe["value_size"])
    span.set_attribute("agent.user_input.hash", safe["value_hash"])
    span.set_attribute("agent.user_input.preview", safe["value_redacted"])
```

The hash is useful for cross-correlation ("did the same input appear in another run?") without exposing content.

For tool arguments, prefer schemas — record types and shapes rather than values:

```python
def log_tool_args(span, tool_name, args):
    span.set_attribute("agent.tool.name", tool_name)
    # Record schema, not values.
    schema = {k: type(v).__name__ for k, v in args.items()}
    span.set_attribute("agent.tool.arg_schema", json.dumps(schema))
    # Hash for correlation.
    args_str = json.dumps(args, sort_keys=True)
    span.set_attribute("agent.tool.args_hash",
        hashlib.sha256(args_str.encode()).hexdigest()[:16])
```

### Step 4: Anomaly Detection on Tool-Use Patterns

With per-run trace data, build detection on tool-call patterns:

```python
# tool_anomaly.py
SUSPICIOUS_PATTERNS = [
    {
        "name": "rapid_destructive_calls",
        "match": lambda calls: sum(1 for c in calls if c.startswith("delete_")) > 3,
        "severity": "high",
    },
    {
        "name": "unusual_tool_sequence",
        "match": lambda calls: "fetch_secrets" in calls and "outbound_http" in calls,
        "severity": "critical",
    },
    {
        "name": "tool_call_loop",
        "match": lambda calls: any(calls.count(c) > 10 for c in set(calls)),
        "severity": "medium",
    },
]

def analyze_run(run_id, tool_calls):
    findings = []
    call_names = [c.tool_name for c in tool_calls]
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern["match"](call_names):
            findings.append({
                "run_id": run_id,
                "pattern": pattern["name"],
                "severity": pattern["severity"],
            })
    return findings
```

Run this analyzer over completed traces; alert on findings. For real-time response, consume traces from a streaming pipeline (Kafka with OTel exporter) and react before the run completes.

### Step 5: Per-Tenant Cost Attribution

Tag every span with the tenant ID. Roll up costs:

```sql
-- Example: per-tenant token consumption from trace data.
SELECT
    span.attributes['agent.tenant_id'] AS tenant,
    SUM(span.attributes['gen_ai.usage.input_tokens']) AS input_tokens,
    SUM(span.attributes['gen_ai.usage.output_tokens']) AS output_tokens,
    SUM(span.attributes['gen_ai.usage.input_tokens'] * 0.000003)
        + SUM(span.attributes['gen_ai.usage.output_tokens'] * 0.000015)
        AS estimated_cost_usd
FROM spans
WHERE span.name LIKE 'agent.%'
  AND span.start_time > now() - interval '1 day'
GROUP BY tenant
ORDER BY estimated_cost_usd DESC;
```

A tenant whose cost spikes 10x in a day is either using the agent more legitimately or being abused. Both warrant investigation.

### Step 6: Trace Sampling for Volume Management

Per-run traces are detailed; volume scales with agent invocations. Sample:

```python
from opentelemetry.sdk.trace.sampling import (
    ParentBased, TraceIdRatioBased, ALWAYS_ON, ALWAYS_OFF,
)

# Always sample for: errors, suspicious patterns, high-cost runs.
# Sample 10% of routine runs.
sampler = ParentBased(
    root=TraceIdRatioBased(0.1),
)
provider = TracerProvider(sampler=sampler)
```

For tail-based sampling (decide post-completion based on trace contents), use the OTel Collector's `tail_sampling` processor:

```yaml
# otel-collector-config.yaml
processors:
  tail_sampling:
    decision_wait: 30s
    policies:
      - name: errors
        type: status_code
        status_code: {status_codes: [ERROR]}
      - name: long-runs
        type: latency
        latency: {threshold_ms: 60000}
      - name: anomaly
        type: numeric_attribute
        numeric_attribute: {key: agent.anomaly_score, min_value: 1}
      - name: routine-sample
        type: probabilistic
        probabilistic: {sampling_percentage: 10}
```

100% of error or anomalous traces; 10% of routine runs. Forensic detail when needed; manageable volume otherwise.

### Step 7: Forensic Replay

For incident investigation, you need enough trace detail to reconstruct what happened.

```python
def replay_trace(run_id):
    spans = trace_store.fetch_by_root(run_id)
    print(f"Run {run_id} for tenant {spans[0].attributes['agent.tenant_id']}")
    for span in sorted(spans, key=lambda s: s.start_time):
        indent = "  " * span.depth
        print(f"{indent}{span.name} ({span.duration_ms}ms)")
        if span.attributes.get("gen_ai.tool.name"):
            print(f"{indent}  tool={span.attributes['gen_ai.tool.name']}")
            print(f"{indent}  args_hash={span.attributes['agent.tool.args_hash']}")
        if span.status == "ERROR":
            print(f"{indent}  ERROR: {span.events[0].attributes['exception.message']}")
```

The output is a step-by-step record of the run. For a real incident response, the trace combined with model-input hashes (for correlating with other agent runs that saw the same input) is the forensic core.

### Step 8: Telemetry SLOs

```
agent_runs_total{tenant, outcome}                              counter
agent_run_duration_seconds                                     histogram
agent_tool_calls_total{tenant, tool, outcome}                  counter
agent_anomaly_detections_total{pattern, severity}              counter
agent_token_usage_total{tenant, model}                          counter
agent_redaction_replacements_total                              counter
agent_trace_pii_findings_total{pattern}                         counter (post-trace audit)
```

Alert on:

- `agent_anomaly_detections_total{severity="critical"}` non-zero — likely active prompt-injection attack.
- `agent_trace_pii_findings_total` non-zero — redaction failed; tighten patterns.

## Expected Behaviour

| Signal | Without observability | With OTel agent observability |
|--------|------------------------|----------------------------------|
| Per-run cost attribution | None / aggregate only | Per-tenant per-run |
| Tool-call anomaly detection | After-the-fact via SIEM | Real-time on trace stream |
| Forensic reconstruction of incidents | Logs piecewise | Single trace shows full chain |
| PII in trace data | Often present | Hashed / redacted at SDK |
| Volume management | Per-event keep-all (expensive) | Tail-sampled by anomaly + error |
| Cross-run correlation | Hard | Via input hashes |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Detailed per-call spans | Fine forensics | Trace volume | Tail sampling: keep what matters. |
| SDK-side redaction | Sensitive data not exfiltrated to observability | Some debug context lost | Pair with secured / audited debug log for known-narrow cases. |
| Hash-based correlation | Track patterns without content | Can't see actual content during routine ops | Acceptable; for incident, retrieve from a separate (more-secured) log. |
| Real-time anomaly detection | Stop attacks in progress | Streaming pipeline complexity | Use existing OTel + Kafka; small custom processor for patterns. |
| Per-tenant attribution | Billing / abuse signals | Per-tenant index in trace store | Standard for multi-tenant deployments. |
| Tail sampling | Volume bounded | Some traces lost (acceptable) | Decision policies cover errors + anomalies; routine sample is small. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Redaction misses sensitive pattern | PII in trace store | Periodic scan of stored traces | Tighten patterns; consider LLM-based classifier for high-stakes audit. |
| Sampler discards relevant trace | Forensic gap during incident | Specific trace not in store post-event | Tail sampling captures errors / anomalies; routine sampling discards by design. Increase sampling for high-risk tenants. |
| Trace ingest latency | Anomaly detection lags | Detection-rule firing time vs. event time | Use streaming ingest (Kafka); reduce decision_wait if needed. |
| Per-tenant tagging missed | Cost attribution incomplete | Some agent runs missing `tenant_id` attribute | Enforce at SDK init; reject runs without tenant context. |
| Anomaly false positive | Legitimate operations flagged | Operator review of detected anomalies | Tune patterns; allow operator-triggered "expected" annotations. |
| Trace export down | Brief observability gap | Standard health check on exporter | Buffer locally for short outages; escalate if extended. |
| Span attribute size limit | Long arguments truncated | Backend rejection or silent truncation | Hash + size; don't try to fit full content in span attrs. |

## Related Articles

- [LLM Deployment Security](/articles/ai-landscape/llm-deployment-security/)
- [MCP Authentication Patterns](/articles/ai-landscape/mcp-authentication/)
- [Continuous AI Red-Teaming Pipelines](/articles/ai-landscape/continuous-red-teaming/)
- [Agent Memory Poisoning Defence](/articles/ai-landscape/agent-memory-poisoning/)
- [OpenTelemetry PII Leakage](/articles/observability/otel-pii-leakage/)
