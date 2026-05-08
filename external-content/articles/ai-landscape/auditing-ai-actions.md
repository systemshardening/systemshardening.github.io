---
title: "Auditing AI Actions at Scale: Building Tamper-Proof Logs for Non-Human Actors"
description: "AI agents operate at machine speed, generating 10-100x the audit data of human operators."
slug: "auditing-ai-actions"
date: 2026-03-29
lastmod: 2026-03-29
category: "ai-landscape"
tags: ["ai-agents", "audit-logging", "opentelemetry", "immutable-storage", "forensics"]
personas: ["security-engineer", "sre", "ai-ml-engineer"]
article_number: 110
difficulty: "advanced"
estimated_reading_time: 18
provider_bridges:
  - name: "Axiom"
    id: 112
    category: "observability"
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
  - name: "Backblaze"
    id: 161
    category: "object-storage"
premium_pack: "ai-audit-logging-pack"
published: true
layout: article.njk
permalink: "/articles/ai-landscape/auditing-ai-actions/index.html"
---

# Auditing AI Actions at Scale: Building Tamper-Proof Logs for Non-Human Actors

## Problem

AI agents operate at machine speed, generating 10-100x the audit data of human operators. A single agent making 50 API calls per minute produces 72,000 audit events per day. Standard audit logging infrastructure ([auditd](https://github.com/linux-audit/audit-userspace), [Kubernetes](https://kubernetes.io) audit logs) was not designed for this volume.

More fundamentally, AI agent audit trails must answer a question that human audit trails do not: **why did the agent do that?** For a human operator, the "why" is reconstructed from context, Slack messages, and tickets. For an AI agent, the "why" must be captured in the log (the input context that triggered the action) because the agent's reasoning is opaque after the fact.

## Threat Model

- **Adversary:** The agent itself, after it has caused damage (intentional or not). The audit trail is the investigation tool.
- **Key requirements:** (1) Tamper-proof, the agent cannot modify its own audit trail. (2) Complete, every action, every input, every output. (3) Queryable, investigators need fast search across millions of events.

## Configuration

### Audit Schema Design

Every agent action produces a structured log entry with these fields:

```json
{
  "timestamp": "2026-04-22T10:30:15.123Z",
  "agent_id": "web-hardening-agent-01",
  "agent_version": "1.2.3",
  "session_id": "sess-abc123",
  "trace_id": "trace-xyz789",
  "action_type": "kubectl_apply",
  "action_category": "infrastructure_mutation",
  "input_context": "User requested NGINX config update for production",
  "input_hash": "sha256:a1b2c3...",
  "target_resource": "deployment/nginx",
  "target_namespace": "production",
  "target_cluster": "prod-eu-west-1",
  "dry_run": false,
  "approval_required": true,
  "approval_status": "approved",
  "approved_by": "alice@company.com",
  "approval_timestamp": "2026-04-22T10:29:50.000Z",
  "output": "deployment.apps/nginx configured",
  "output_hash": "sha256:d4e5f6...",
  "result": "success",
  "duration_ms": 1250,
  "error": null
}
```

Key design decisions:

- **`input_context`** captures what prompted the action, essential for "why" investigations
- **`input_hash`** and **`output_hash`** enable integrity verification
- **`trace_id`** correlates agent actions with Kubernetes audit log entries
- **`approval_status`** records whether human-in-the-loop was required and who approved
- **`dry_run`** distinguishes preview from actual execution

### OTel Instrumentation for Agent Actions

```python
# Python example - instrument agent tool calls with OpenTelemetry
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
import hashlib
import json
import time

# Configure OTel exporter
provider = TracerProvider()
exporter = OTLPSpanExporter(endpoint="otel-collector.monitoring:4317")
provider.add_span_processor(BatchSpanProcessor(exporter))
trace.set_tracer_provider(provider)
tracer = trace.get_tracer("ai-agent")

def execute_agent_action(action_type: str, target: str, input_context: str, dry_run: bool = True):
    """Execute an agent action with full audit logging via OTel spans."""

    with tracer.start_as_current_span("agent.action") as span:
        span.set_attribute("agent.id", "web-hardening-agent-01")
        span.set_attribute("agent.action_type", action_type)
        span.set_attribute("agent.target_resource", target)
        span.set_attribute("agent.input_context", input_context)
        span.set_attribute("agent.input_hash", hashlib.sha256(input_context.encode()).hexdigest())
        span.set_attribute("agent.dry_run", dry_run)
        span.set_attribute("agent.timestamp", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

        try:
            # Execute the action
            result = _do_action(action_type, target, dry_run)

            span.set_attribute("agent.result", "success")
            span.set_attribute("agent.output", str(result)[:1000])  # Truncate large outputs
            span.set_attribute("agent.output_hash", hashlib.sha256(str(result).encode()).hexdigest())

            return result

        except Exception as e:
            span.set_attribute("agent.result", "error")
            span.set_attribute("agent.error", str(e)[:500])
            span.record_exception(e)
            raise
```

### Shipping to Immutable Storage

Agent audit logs must be shipped to storage the agent cannot access, modify, or delete.

```yaml
# vector-agent-audit.yaml
# Vector sidecar in the agent pod - ships logs to immutable storage.
# The agent process has no access to the Vector configuration or credentials.

sources:
  agent_stdout:
    type: file
    include:
      - /var/log/agent/actions.jsonl

transforms:
  enrich:
    type: remap
    inputs:
      - agent_stdout
    source: |
      .source = "ai-agent"
      .shipped_at = now()

sinks:
  # Primary: Axiom for queryable storage
  axiom:
    type: axiom
    inputs:
      - enrich
    dataset: "agent-audit"
    token: "${AXIOM_API_TOKEN}"

  # Secondary: Immutable object storage for long-term archival
  s3_immutable:
    type: aws_s3
    inputs:
      - enrich
    bucket: "agent-audit-immutable"
    region: "eu-west-1"
    key_prefix: "audit/{{ timestamp }}"
    encoding:
      codec: json
    # The S3 bucket has Object Lock enabled (WORM - Write Once Read Many).
    # Neither the agent nor the Vector process can delete or modify stored objects.
```

**S3 bucket with Object Lock (immutable storage):**

```bash
# Create bucket with Object Lock
aws s3api create-bucket \
  --bucket agent-audit-immutable \
  --region eu-west-1 \
  --object-lock-enabled-for-bucket

# Set default retention (365 days, compliance mode - cannot be shortened)
aws s3api put-object-lock-configuration \
  --bucket agent-audit-immutable \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "COMPLIANCE",
        "Days": 365
      }
    }
  }'

# IAM policy for Vector: write-only (no read, no delete)
# {
#   "Version": "2012-10-17",
#   "Statement": [
#     {
#       "Effect": "Allow",
#       "Action": ["s3:PutObject"],
#       "Resource": "arn:aws:s3:::agent-audit-immutable/*"
#     }
#   ]
# }
```

For non-AWS environments: [Backblaze](https://www.backblaze.com) B2 with Object Lock, or [Wasabi](https://wasabi.com) with immutable buckets.

### Correlating Agent Actions with Infrastructure State

Link the agent's `kubectl apply` to the resulting Kubernetes API audit log entry:

```yaml
# OTel Collector configuration: inject trace ID into kubectl calls
processors:
  # Add trace context to HTTP headers for kubectl API calls
  attributes:
    actions:
      - action: insert
        key: "traceparent"
        from_attribute: "trace_id"
```

The Kubernetes audit log entry includes the `traceparent` header, allowing join between:
- Agent audit: "agent applied deployment/nginx with trace_id=xyz"
- K8s audit: "deployment/nginx was updated by system:serviceaccount:ai-agents:ai-agent-sa with traceparent=xyz"

### Agent Activity Dashboard

```json
{
  "dashboard": {
    "title": "AI Agent Activity",
    "panels": [
      {
        "title": "Actions per Agent per Hour",
        "type": "timeseries",
        "targets": [{"expr": "sum by (agent_id) (rate(agent_actions_total[1h]))"}]
      },
      {
        "title": "Action Type Distribution",
        "type": "piechart",
        "targets": [{"expr": "sum by (action_type) (agent_actions_total)"}]
      },
      {
        "title": "Error Rate",
        "type": "stat",
        "targets": [{"expr": "sum(rate(agent_actions_total{result='error'}[1h])) / sum(rate(agent_actions_total[1h]))"}]
      },
      {
        "title": "Approval Wait Time (P95)",
        "type": "gauge",
        "targets": [{"expr": "histogram_quantile(0.95, sum by (le) (rate(agent_approval_wait_seconds_bucket[1h])))"}]
      },
      {
        "title": "Anomaly Indicator",
        "type": "stat",
        "thresholds": [{"value": 0, "color": "green"}, {"value": 1, "color": "red"}],
        "targets": [{"expr": "ALERTS{alertname=~'Agent.*', alertstate='firing'}"}]
      }
    ]
  }
}
```

### Forensic Investigation Procedure

When an agent causes an incident:

```bash
# Step 1: Identify the time window
# From the incident alert, get the approximate time of the issue.

# Step 2: Query agent audit logs for the time window
# In Axiom:
# dataset: agent-audit
# query: agent_id = "web-hardening-agent-01" AND timestamp > "2026-04-22T10:00:00Z" AND timestamp < "2026-04-22T11:00:00Z"

# Step 3: Find the specific action that caused the issue
# Look for: action_type, target_resource, result, error

# Step 4: Examine the input context
# The input_context field shows WHAT prompted the agent to take the action.
# This is the "why" - was it a legitimate user request, a scheduled task,
# or something unexpected (potential prompt injection)?

# Step 5: Correlate with Kubernetes audit log
# Use trace_id to find the matching K8s audit entry:
# query in K8s audit logs: traceparent contains "trace-xyz789"

# Step 6: Determine root cause
# - Agent error: fix agent logic, add guardrail
# - Prompt injection: investigate input source, add Lakera (#142)
# - Credential scope too broad: tighten Vault policy and RBAC
# - Rate limit not set: add rate limiting

# Step 7: Document in post-mortem
# Include: timeline, root cause, agent audit log excerpts, corrective actions
```

## Expected Behaviour

- Every agent action logged within 1 second of execution
- Agent cannot access, modify, or delete its own audit logs
- Audit logs queryable in Axiom within 5 seconds for 30-day window
- Dashboard shows real-time agent activity with anomaly highlighting
- 12-month retention in immutable object storage for compliance
- Forensic investigation can reconstruct agent decision chain from logs

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Full input context logging | Captures "why" for every action (1-10KB per event) | Storage volume: 3+ agents produce 1TB+ within weeks | Use [Axiom](https://axiom.co) free tier (500GB/month). Archive older data to object storage. |
| Immutable storage (S3 Object Lock) | Tamper-proof audit trail | Higher cost than mutable storage; cannot fix erroneous entries | Compliance mode prevents even root from deleting. Accept the storage cost. agent audit integrity is non-negotiable. |
| Vector sidecar shipping | Agent cannot suppress its own logs | Additional 50-100MB memory per agent pod | Minimal overhead. The sidecar approach is the only way to ensure the agent cannot interfere with log shipping. |
| OTel trace correlation | Links agent actions to K8s API calls | Requires OTel Collector in the pipeline; adds configuration complexity | OTel Collector is already deployed for most K8s observability setups. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Vector sidecar crashes | Agent actions not captured | Log volume metric drops to zero; sidecar pod restart count increases | Fix sidecar. Local buffer replays missed events. Investigate gap period. |
| Axiom ingestion rate exceeded | Logs queued but not queryable in real-time | Axiom status shows ingestion delay; Vector shows delivery backlog | Scale Axiom plan. Or reduce log volume by filtering low-value events. |
| S3 Object Lock prevents cleanup | Immutable storage fills up; costs increase | S3 storage cost alerts | Retention is intentionally 365 days. Budget for the storage. After 365 days, objects expire automatically. |
| Trace ID not propagating | Cannot correlate agent and K8s audit logs | Investigation dead end when trying to match events | Fix OTel instrumentation. Ensure trace context propagation in agent's HTTP client. |

## When to Consider a Managed Alternative

Self-managed audit log storage for 3+ agents with 12-month retention exceeds 1TB within weeks.

- **[Axiom](https://axiom.co):** 500GB/month free, unlimited retention, serverless query. Zero cluster management. Perfect for high-volume agent audit logs.
- **[Grafana Cloud](https://grafana.com/cloud):** Centralized logging with correlation to infrastructure metrics and traces. Native [Grafana](https://grafana.com) dashboards for agent activity.
- **[Better Stack](https://betterstack.com):** Integrated logging + incident management for agent-triggered incidents.
- **[Backblaze](https://www.backblaze.com) B2 / [Wasabi](https://wasabi.com):** Immutable object storage for long-term archival at $0.006/GB/month. Use alongside a queryable primary (Axiom or Grafana Cloud).

**Premium content pack:** AI agent audit logging pack. OTel instrumentation templates (Python, Go, Node), Vector pipeline configs for Axiom and S3, Grafana dashboards for agent activity monitoring, [Prometheus](https://prometheus.io) alert rules for anomalous agent behaviour, and forensic investigation procedure templates.


## Related Articles

- [Claude, Mythos, and the Non-Human Infrastructure Consumer: Writing Hardening Guides for AI Agents](/articles/ai-landscape/claude-non-human-consumers/)
- [Sandboxing AI Agent Tool Use: Filesystem, Network, and Process Isolation for Autonomous Actions](/articles/ai-landscape/agent-tool-use-sandboxing/)
- [Agent-to-Agent Trust: Authentication, Delegation, and Capability Boundaries in Multi-Agent Systems](/articles/ai-landscape/agent-to-agent-trust/)
- [AI Credential Delegation: Short-Lived Tokens, Scope Narrowing, and Audit Trails for Agent Access](/articles/ai-landscape/ai-credential-delegation/)
- [Verifying AI Agent Output: Deterministic Checks, Human-in-the-Loop Gates, and Rollback Safety](/articles/ai-landscape/ai-agent-output-verification/)
