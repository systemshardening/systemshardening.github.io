---
title: "LLM Observability in Production: Monitoring Latency, Token Usage, Safety Violations, and Drift"
description: "Traditional application monitoring (CPU, memory, HTTP status codes, latency) tells you nothing about what an LLM is doing."
slug: "llm-observability-production"
date: 2026-01-23
lastmod: 2026-01-23
category: "kubernetes"
tags: ["observability", "llm-monitoring", "prometheus", "grafana", "metrics", "drift-detection"]
personas: ["sre", "ai-ml-engineer", "security-engineer"]
article_number: 134
difficulty: "advanced"
estimated_reading_time: 18
provider_bridges:
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
  - name: "Datadog"
    id: 104
    category: "observability"
premium_pack: "llm-observability-dashboards"
published: true
layout: article.njk
permalink: "/articles/kubernetes/llm-observability-production/index.html"
---

# LLM Observability in Production: Monitoring Latency, Token Usage, Safety Violations, and Drift

## Problem

Traditional application monitoring (CPU, memory, HTTP status codes, latency) tells you nothing about what an LLM is doing. A model can return 200 OK while generating hallucinated medical advice, leaking PII, or producing biased content. LLM observability requires a new layer of metrics: token consumption (cost), generation latency (user experience), safety violations (risk), content quality (drift), and user feedback (satisfaction).

Most teams deploy LLM applications with the same monitoring they use for REST APIs: is it up? Is it fast? This misses the fundamental question: is it behaving correctly? A model that drifts in quality, starts hallucinating more frequently, or subtly changes its response style will not trigger any traditional alert.

LLM observability covers four dimensions: operational metrics (latency, throughput, errors), economic metrics (tokens, costs), safety metrics (violations, guardrail triggers), and quality metrics (semantic drift, user feedback, hallucination rate).

## Threat Model

- **Adversary:** This article addresses operational risk, not adversarial threats. The "adversary" is entropy: model degradation, distribution shift, cost overruns, and quality drift.
- **Objective:** Detect and alert on model behaviour changes before they impact users or costs. Maintain visibility into model performance across all four dimensions.
- **Blast radius:** Unmonitored degradation leads to: cost overruns (token usage spikes), user experience degradation (latency increases), safety incidents (undetected violations), and quality erosion (gradual drift that is invisible until users complain).

## Configuration

### Metrics Collection: Custom [Prometheus](https://prometheus.io) Metrics

```python
# llm_metrics.py - comprehensive LLM metrics collection
from prometheus_client import (
    Counter, Histogram, Gauge, Summary,
    CollectorRegistry, generate_latest,
)
import time

# Create a dedicated registry for LLM metrics
LLM_REGISTRY = CollectorRegistry()

# Operational metrics
REQUEST_LATENCY = Histogram(
    "llm_request_duration_seconds",
    "End-to-end request latency including guardrails",
    ["model", "endpoint"],
    buckets=[0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0],
    registry=LLM_REGISTRY,
)

INFERENCE_LATENCY = Histogram(
    "llm_inference_duration_seconds",
    "Model inference latency only (excluding guardrails)",
    ["model"],
    buckets=[0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0],
    registry=LLM_REGISTRY,
)

TIME_TO_FIRST_TOKEN = Histogram(
    "llm_time_to_first_token_seconds",
    "Time from request to first token in streaming responses",
    ["model"],
    buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
    registry=LLM_REGISTRY,
)

REQUEST_TOTAL = Counter(
    "llm_requests_total",
    "Total LLM requests",
    ["model", "endpoint", "status"],
    registry=LLM_REGISTRY,
)

# Economic metrics
INPUT_TOKENS = Counter(
    "llm_input_tokens_total",
    "Total input tokens consumed",
    ["model"],
    registry=LLM_REGISTRY,
)

OUTPUT_TOKENS = Counter(
    "llm_output_tokens_total",
    "Total output tokens generated",
    ["model"],
    registry=LLM_REGISTRY,
)

ESTIMATED_COST = Counter(
    "llm_estimated_cost_usd_total",
    "Estimated cost in USD",
    ["model"],
    registry=LLM_REGISTRY,
)

# Safety metrics
SAFETY_VIOLATIONS = Counter(
    "llm_safety_violations_total",
    "Safety violations detected in output",
    ["model", "violation_type", "severity"],
    registry=LLM_REGISTRY,
)

GUARDRAIL_BLOCKS = Counter(
    "llm_guardrail_blocks_total",
    "Requests blocked by guardrails",
    ["model", "stage", "reason"],
    registry=LLM_REGISTRY,
)

PII_DETECTIONS = Counter(
    "llm_pii_detections_total",
    "PII detected in model output",
    ["model", "pii_type"],
    registry=LLM_REGISTRY,
)

# Quality metrics
USER_FEEDBACK = Counter(
    "llm_user_feedback_total",
    "User feedback (thumbs up/down)",
    ["model", "feedback_type"],
    registry=LLM_REGISTRY,
)

RESPONSE_LENGTH = Histogram(
    "llm_response_length_tokens",
    "Response length in tokens",
    ["model"],
    buckets=[10, 50, 100, 250, 500, 1000, 2000, 4000],
    registry=LLM_REGISTRY,
)


class LLMMetricsCollector:
    """Collect and record LLM metrics for each request."""

    COST_PER_TOKEN = {
        # Approximate costs per 1K tokens (USD)
        "gpt-4": {"input": 0.03, "output": 0.06},
        "gpt-4-turbo": {"input": 0.01, "output": 0.03},
        "gpt-3.5-turbo": {"input": 0.0005, "output": 0.0015},
        "claude-3-opus": {"input": 0.015, "output": 0.075},
        "claude-3-sonnet": {"input": 0.003, "output": 0.015},
    }

    def record_request(self, model: str, endpoint: str, input_tokens: int,
                       output_tokens: int, latency_seconds: float,
                       inference_seconds: float, status: str = "success",
                       ttft_seconds: float = None):
        REQUEST_LATENCY.labels(model=model, endpoint=endpoint).observe(latency_seconds)
        INFERENCE_LATENCY.labels(model=model).observe(inference_seconds)
        REQUEST_TOTAL.labels(model=model, endpoint=endpoint, status=status).inc()
        INPUT_TOKENS.labels(model=model).inc(input_tokens)
        OUTPUT_TOKENS.labels(model=model).inc(output_tokens)
        RESPONSE_LENGTH.labels(model=model).observe(output_tokens)

        if ttft_seconds is not None:
            TIME_TO_FIRST_TOKEN.labels(model=model).observe(ttft_seconds)

        # Calculate and record cost
        costs = self.COST_PER_TOKEN.get(model, {"input": 0.01, "output": 0.03})
        cost = (input_tokens / 1000 * costs["input"]) + (output_tokens / 1000 * costs["output"])
        ESTIMATED_COST.labels(model=model).inc(cost)

    def record_safety_violation(self, model: str, violation_type: str, severity: str):
        SAFETY_VIOLATIONS.labels(
            model=model, violation_type=violation_type, severity=severity
        ).inc()

    def record_guardrail_block(self, model: str, stage: str, reason: str):
        GUARDRAIL_BLOCKS.labels(model=model, stage=stage, reason=reason).inc()

    def record_pii_detection(self, model: str, pii_type: str):
        PII_DETECTIONS.labels(model=model, pii_type=pii_type).inc()

    def record_feedback(self, model: str, feedback_type: str):
        USER_FEEDBACK.labels(model=model, feedback_type=feedback_type).inc()
```

### Semantic Drift Detection

```python
# drift_detector.py - detect semantic drift in LLM responses
import numpy as np
from collections import deque
from typing import Optional

class SemanticDriftDetector:
    """
    Detect when LLM responses drift from expected behaviour.
    Uses embedding similarity to compare recent responses against a baseline.
    """

    def __init__(self, embedding_fn, baseline_window: int = 1000,
                 detection_window: int = 100, threshold: float = 0.15):
        self.embedding_fn = embedding_fn
        self.baseline_embeddings = deque(maxlen=baseline_window)
        self.recent_embeddings = deque(maxlen=detection_window)
        self.threshold = threshold
        self.baseline_centroid: Optional[np.ndarray] = None

    def add_response(self, response_text: str) -> dict:
        embedding = self.embedding_fn(response_text)
        self.recent_embeddings.append(embedding)

        # Build baseline from first N responses
        if len(self.baseline_embeddings) < self.baseline_embeddings.maxlen:
            self.baseline_embeddings.append(embedding)
            if len(self.baseline_embeddings) == self.baseline_embeddings.maxlen:
                self.baseline_centroid = np.mean(list(self.baseline_embeddings), axis=0)
            return {"drift_detected": False, "status": "building_baseline"}

        if self.baseline_centroid is None:
            return {"drift_detected": False, "status": "building_baseline"}

        # Compare recent window centroid to baseline centroid
        recent_centroid = np.mean(list(self.recent_embeddings), axis=0)
        drift_distance = float(np.linalg.norm(recent_centroid - self.baseline_centroid))

        # Cosine similarity
        cosine_sim = float(
            np.dot(recent_centroid, self.baseline_centroid) /
            (np.linalg.norm(recent_centroid) * np.linalg.norm(self.baseline_centroid) + 1e-8)
        )

        drift_detected = drift_distance > self.threshold

        return {
            "drift_detected": drift_detected,
            "drift_distance": round(drift_distance, 4),
            "cosine_similarity": round(cosine_sim, 4),
            "baseline_size": len(self.baseline_embeddings),
            "recent_window_size": len(self.recent_embeddings),
            "status": "monitoring",
        }
```

### Prometheus Alerting Rules

```yaml
# prometheus-llm-observability.yaml
groups:
  - name: llm-operational
    interval: 1m
    rules:
      # Latency alerts
      - alert: LLMLatencyP99High
        expr: >
          histogram_quantile(0.99,
            rate(llm_request_duration_seconds_bucket[5m])
          ) > 5.0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "LLM P99 latency exceeds 5s for {{ $labels.model }}"

      - alert: LLMTimeToFirstTokenSlow
        expr: >
          histogram_quantile(0.95,
            rate(llm_time_to_first_token_seconds_bucket[5m])
          ) > 2.0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Time to first token P95 exceeds 2s for {{ $labels.model }}"

      # Error rate
      - alert: LLMErrorRateHigh
        expr: >
          rate(llm_requests_total{status="error"}[5m])
          / rate(llm_requests_total[5m]) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "LLM error rate exceeds 5% for {{ $labels.model }}"

  - name: llm-economic
    interval: 5m
    rules:
      # Cost alerts
      - alert: LLMHourlyCostHigh
        expr: >
          increase(llm_estimated_cost_usd_total[1h]) > 100
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "LLM cost exceeds $100/hour for {{ $labels.model }}"

      - alert: LLMDailyCostSpike
        expr: >
          increase(llm_estimated_cost_usd_total[1h])
          > 2 * avg_over_time(increase(llm_estimated_cost_usd_total[1h])[24h:1h])
        for: 30m
        labels:
          severity: warning
        annotations:
          summary: "LLM cost spike: current hourly rate is 2x the 24h average"

      # Token usage anomaly
      - alert: LLMOutputTokenSpike
        expr: >
          rate(llm_output_tokens_total[5m])
          > 2 * avg_over_time(rate(llm_output_tokens_total[5m])[24h:5m])
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "Output token rate is 2x the 24h average for {{ $labels.model }}"

  - name: llm-safety
    interval: 1m
    rules:
      # Safety violation alerts
      - alert: LLMSafetyViolation
        expr: increase(llm_safety_violations_total{severity="critical"}[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "Critical safety violation detected in {{ $labels.model }} output"
          description: "Type: {{ $labels.violation_type }}. Investigate immediately."

      - alert: LLMGuardrailBlockSpike
        expr: >
          rate(llm_guardrail_blocks_total[5m])
          / rate(llm_requests_total[5m]) > 0.2
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: ">20% of requests blocked by guardrails for {{ $labels.model }}"

      - alert: LLMPIILeakage
        expr: increase(llm_pii_detections_total[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "PII detected in output of {{ $labels.model }}: {{ $labels.pii_type }}"

  - name: llm-quality
    interval: 5m
    rules:
      # Drift detection
      - alert: LLMSemanticDrift
        expr: llm_semantic_drift_distance > 0.15
        for: 30m
        labels:
          severity: warning
        annotations:
          summary: "Semantic drift detected in {{ $labels.model }} responses"
          description: "Drift distance: {{ $value }}. Response style may have changed."

      # User feedback degradation
      - alert: LLMNegativeFeedbackSpike
        expr: >
          rate(llm_user_feedback_total{feedback_type="negative"}[1h])
          / rate(llm_user_feedback_total[1h]) > 0.3
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: ">30% negative feedback for {{ $labels.model }} in the last hour"
```

### [Grafana](https://grafana.com) Dashboard Configuration

```json
{
  "dashboard": {
    "title": "LLM Production Observability",
    "uid": "llm-observability",
    "panels": [
      {
        "title": "Request Latency (P50/P95/P99)",
        "type": "timeseries",
        "targets": [
          {
            "expr": "histogram_quantile(0.5, rate(llm_request_duration_seconds_bucket[5m]))",
            "legendFormat": "P50 - {{ model }}"
          },
          {
            "expr": "histogram_quantile(0.95, rate(llm_request_duration_seconds_bucket[5m]))",
            "legendFormat": "P95 - {{ model }}"
          },
          {
            "expr": "histogram_quantile(0.99, rate(llm_request_duration_seconds_bucket[5m]))",
            "legendFormat": "P99 - {{ model }}"
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0}
      },
      {
        "title": "Hourly Cost by Model",
        "type": "timeseries",
        "targets": [
          {
            "expr": "increase(llm_estimated_cost_usd_total[1h])",
            "legendFormat": "{{ model }}"
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0}
      },
      {
        "title": "Token Throughput",
        "type": "timeseries",
        "targets": [
          {
            "expr": "rate(llm_input_tokens_total[5m])",
            "legendFormat": "Input - {{ model }}"
          },
          {
            "expr": "rate(llm_output_tokens_total[5m])",
            "legendFormat": "Output - {{ model }}"
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8}
      },
      {
        "title": "Safety Violations",
        "type": "stat",
        "targets": [
          {
            "expr": "increase(llm_safety_violations_total[24h])",
            "legendFormat": "{{ violation_type }}"
          }
        ],
        "gridPos": {"h": 8, "w": 6, "x": 12, "y": 8}
      },
      {
        "title": "Guardrail Block Rate",
        "type": "gauge",
        "targets": [
          {
            "expr": "rate(llm_guardrail_blocks_total[5m]) / rate(llm_requests_total[5m])",
            "legendFormat": "{{ reason }}"
          }
        ],
        "gridPos": {"h": 8, "w": 6, "x": 18, "y": 8}
      },
      {
        "title": "User Feedback Ratio",
        "type": "timeseries",
        "targets": [
          {
            "expr": "rate(llm_user_feedback_total{feedback_type='positive'}[1h]) / rate(llm_user_feedback_total[1h])",
            "legendFormat": "Positive ratio"
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16}
      },
      {
        "title": "Semantic Drift Distance",
        "type": "timeseries",
        "targets": [
          {
            "expr": "llm_semantic_drift_distance",
            "legendFormat": "{{ model }}"
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16}
      }
    ]
  }
}
```

## Expected Behaviour

- All four dimensions of LLM observability are monitored: operational, economic, safety, quality
- Latency alerts fire when P99 exceeds 5 seconds or time-to-first-token exceeds 2 seconds
- Cost alerts fire when hourly spend exceeds budget or spikes 2x above the 24-hour average
- Safety violations trigger immediate critical alerts
- Semantic drift alerts fire after 30 minutes of sustained drift above threshold
- User feedback ratio below 70% positive triggers investigation
- Grafana dashboards provide real-time visibility across all dimensions

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Comprehensive metrics collection | Full visibility into LLM behaviour | Metric cardinality grows with models and endpoints | Use bounded label values. Aggregate by model, not by user. |
| Semantic drift detection | Catches quality degradation | Requires computing embeddings for every response (CPU/cost) | Sample responses (embed 10% of responses). Use lightweight embedding models. |
| Cost tracking | Prevents budget overruns | Estimated costs may not match actual provider bills | Reconcile estimated costs with provider invoices weekly. Adjust cost-per-token tables. |
| User feedback collection | Direct signal on quality | Low feedback rate makes signal noisy | Make feedback low-friction (thumbs up/down). Prompt for feedback selectively. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Metrics exporter down | No metrics flowing to Prometheus | Prometheus target down alert; gaps in dashboard | Restart metrics exporter. Use sidecar pattern for reliability. |
| Cost estimate drift | Budget alerts not firing despite high actual spend | Monthly reconciliation shows divergence | Update cost-per-token tables. Add provider API billing integration. |
| Drift detector false alarm | Drift alert on expected model update | Alert fires after intentional model version change | Reset drift baseline after planned model updates. Add deployment annotations to dashboards. |
| Alert fatigue | Too many low-severity alerts lead to critical alerts being missed | Alert response time increases; incidents discovered late | Tune thresholds quarterly. Route critical alerts to PagerDuty, warnings to Slack. |

## When to Consider a Managed Alternative

LLM observability requires custom metrics, specialised dashboards, and domain-specific alerting that generic APM tools do not provide out of the box.

- **[Grafana Cloud](https://grafana.com/cloud):** Managed Prometheus and Grafana with long-term metric storage. ML-powered anomaly detection. Custom dashboards for LLM metrics.
- **[Datadog](https://www.datadoghq.com):** APM with LLM observability features. Token tracking, cost analytics, and integration with major LLM providers.

**Premium content pack:** LLM observability dashboard pack. Prometheus metrics library (Python), complete alerting rules across four dimensions, Grafana dashboard JSON (7 panels), semantic drift detection service, cost tracking middleware, and user feedback collection widget.


## Related Articles

- [Observability for LLM Applications: Token Usage, Latency Anomalies, and Output Classification](/articles/kubernetes/llm-observability/)
- [GPU Cost and Security Monitoring: Detecting Abuse and Optimising Spend](/articles/kubernetes/gpu-cost-security-monitoring/)
- [Kubernetes Audit Log Analysis: What to Log, How to Query, and What to Alert On](/articles/kubernetes/audit-log-analysis/)
- [Jupyter Notebook Security: Authentication, Isolation, and Data Protection](/articles/kubernetes/jupyter-notebook-security/)
- [AI Data Leakage Prevention: Input Filtering, Output Scanning, and Audit Trails](/articles/kubernetes/ai-data-leakage-prevention/)
