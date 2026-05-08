---
title: "Observability for LLM Applications: Token Usage, Latency Anomalies, and Output Classification"
description: "LLM-powered applications have unique observability requirements that standard APM tools do not address: token-based cost tracking (not just request..."
slug: "llm-observability"
date: 2026-01-05
lastmod: 2026-01-05
category: "kubernetes"
tags: ["llm", "observability", "opentelemetry", "token-usage", "cost-tracking", "ai"]
personas: ["ai-ml-engineer", "sre"]
article_number: 80
difficulty: "intermediate"
estimated_reading_time: 14
provider_bridges:
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
  - name: "Axiom"
    id: 112
    category: "observability"
premium_pack: "llm-observability-dashboards"
published: true
layout: article.njk
permalink: "/articles/kubernetes/llm-observability/index.html"
---

# Observability for LLM Applications: Token Usage, Latency Anomalies, and Output Classification

## Problem

LLM-powered applications have unique observability requirements that standard APM tools do not address: token-based cost tracking (not just request count), latency distributions with cold start vs warm inference, output quality monitoring (safety, accuracy, relevance), and prompt injection attempt detection. Without LLM-specific observability, you cannot detect model degradation, cost overruns, or abuse patterns.

## Threat Model

- **Adversary:** Cost abuse (automated requests consuming expensive GPU inference), model abuse (using the model for unintended purposes), or quality degradation (model performance declines without detection).

## Configuration

### Token Usage Metrics with [OpenTelemetry](https://opentelemetry.io)

```python
# otel_llm_instrumentation.py
from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter

provider = MeterProvider()
metrics.set_meter_provider(provider)
meter = metrics.get_meter("llm-service")

# Token counters
prompt_tokens = meter.create_counter(
    "llm.tokens.prompt",
    description="Number of prompt/input tokens processed",
    unit="tokens"
)
completion_tokens = meter.create_counter(
    "llm.tokens.completion",
    description="Number of completion/output tokens generated",
    unit="tokens"
)
total_cost = meter.create_counter(
    "llm.cost.usd",
    description="Estimated cost in USD",
    unit="usd"
)

# Latency histogram
request_duration = meter.create_histogram(
    "llm.request.duration",
    description="End-to-end request duration",
    unit="ms"
)
first_token_latency = meter.create_histogram(
    "llm.first_token.latency",
    description="Time to first token (TTFT)",
    unit="ms"
)

def record_inference(api_key: str, model: str, input_tokens: int,
                      output_tokens: int, duration_ms: float, ttft_ms: float):
    labels = {"api_key": api_key, "model": model}
    prompt_tokens.add(input_tokens, labels)
    completion_tokens.add(output_tokens, labels)

    # Cost estimation (adjust per model pricing)
    cost = (input_tokens * 0.000003) + (output_tokens * 0.000015)  # Example: GPT-4 pricing
    total_cost.add(cost, labels)

    request_duration.record(duration_ms, labels)
    first_token_latency.record(ttft_ms, labels)
```

### [Prometheus](https://prometheus.io) Alert Rules for LLM Monitoring

```yaml
groups:
  - name: llm-monitoring
    rules:
      # Cost spike per API key
      - alert: LLMCostSpike
        expr: >
          sum by (api_key) (rate(llm_cost_usd_total[1h]))
          > 5 * avg_over_time(sum by (api_key) (rate(llm_cost_usd_total[1h]))[7d:1h])
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "API key {{ $labels.api_key }} cost 5x above baseline"

      # First-token latency degradation (model performance issue)
      - alert: LLMLatencyDegradation
        expr: >
          histogram_quantile(0.95, sum by (le, model) (rate(llm_first_token_latency_bucket[5m])))
          > 2 * histogram_quantile(0.95, sum by (le, model) (rate(llm_first_token_latency_bucket[1h])))
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Model {{ $labels.model }} P95 TTFT doubled, possible GPU saturation or model issue"

      # Token throughput drop (model serving degradation)
      - alert: LLMThroughputDrop
        expr: >
          sum(rate(llm_tokens_completion_total[5m])) < 0.5 * avg_over_time(sum(rate(llm_tokens_completion_total[5m]))[7d:5m])
        for: 10m
        labels:
          severity: critical
        annotations:
          summary: "LLM throughput dropped to 50% of baseline, check GPU health and model serving status"
```

### Output Quality Monitoring

```python
# output_monitor.py - classify model outputs for safety and quality

import re
from typing import Dict

def classify_output(output: str, expected_topic: str = None) -> Dict[str, bool]:
    """Basic output classification. For production, use a dedicated classifier model."""
    classifications = {
        "contains_pii": bool(re.search(
            r'\b\d{3}-\d{2}-\d{4}\b|\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b',
            output, re.IGNORECASE
        )),
        "contains_code": bool(re.search(
            r'(import |def |class |function |const |var |let )', output
        )),
        "excessive_length": len(output) > 10000,
        "empty_response": len(output.strip()) < 10,
        "possible_system_prompt_leak": bool(re.search(
            r'(you are|your instructions|system prompt|your role is)',
            output, re.IGNORECASE
        )),
    }
    return classifications
```

### [Grafana](https://grafana.com) Dashboard Design

Key panels for an LLM observability dashboard:

1. **Token usage per API key per hour**, time series, stacked by key
2. **Cost per API key per day**, table with daily/weekly/monthly projections
3. **P50/P95/P99 TTFT (time to first token)**, heatmap by model
4. **Tokens per second throughput**, gauge showing current vs capacity
5. **Output classification distribution**, pie chart (normal, PII detected, system prompt leak, excessive length)
6. **Request error rate**, 4xx/5xx by endpoint
7. **Active inference requests**, gauge showing current GPU utilisation

## Expected Behaviour

- Token usage tracked per API key with cost estimation
- Cost spike alerts fire within 15 minutes of 5x baseline
- P95 TTFT degradation detected within 10 minutes
- Output classification runs on all responses, flagging PII and system prompt leaks
- Dashboard provides real-time visibility into model performance, cost, and safety

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Per-API-key token tracking | High-cardinality metrics (one series per key × model) | Prometheus storage grows with key count | Use recording rules to pre-aggregate. Or: use [Grafana Cloud](https://grafana.com/cloud) / [Axiom](https://axiom.co) for high-cardinality. |
| Output classification on every response | Adds 5-20ms per response; CPU overhead | Latency increase on the response path | Run classification asynchronously (log output, classify in background). |
| Cost estimation in metrics | Provides real-time cost visibility | Pricing changes require metric update | Use configurable cost-per-token map. Update when pricing changes. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| OTel exporter fails | Metrics stop updating; dashboards show gaps | Prometheus `up == 0` for the LLM service scrape target | Fix OTel exporter configuration. Check network connectivity to the collector. |
| Cost estimation wrong | Budgets based on incorrect cost data | Manual audit reveals discrepancy between estimated and actual costs | Update cost-per-token configuration. Validate against provider invoice monthly. |
| Output classifier false positive | Legitimate outputs flagged as PII | Output monitoring shows high PII rate with no actual PII in reviewed samples | Tune regex patterns. For production: use a dedicated NLP model for PII detection. |

## When to Consider a Managed Alternative

LLM metrics are high-cardinality (per-key × per-model × per-endpoint). Self-managed Prometheus struggles past 50K active series.

- **[Grafana Cloud](https://grafana.com/cloud):** Handles high-cardinality metrics natively. Managed dashboards with team sharing. Start free (10K metrics).
- **[Axiom](https://axiom.co):** Unlimited retention for LLM event data. Serverless query. 500GB/month free.

**Premium content pack:** LLM observability dashboard pack. Grafana dashboard JSON for token usage, cost tracking, latency distributions, output quality, and OTel instrumentation templates for Python, Go, and Node.


## Related Articles

- [AI Data Leakage Prevention: Input Filtering, Output Scanning, and Audit Trails](/articles/kubernetes/ai-data-leakage-prevention/)
- [Jupyter Notebook Security: Authentication, Isolation, and Data Protection](/articles/kubernetes/jupyter-notebook-security/)
- [LLM Observability in Production: Monitoring Latency, Token Usage, Safety Violations, and Drift](/articles/kubernetes/llm-observability-production/)
- [Kubernetes Audit Log Analysis: What to Log, How to Query, and What to Alert On](/articles/kubernetes/audit-log-analysis/)
- [Hardening Model Inference Endpoints: Authentication, Rate Limiting, and Input Validation](/articles/kubernetes/inference-endpoint-hardening/)
