---
title: "Building a Content Filtering Pipeline for LLM Applications: From Raw Input to Safe Output"
description: "A single content filter is not a pipeline. Most LLM deployments add one filter (usually on output) and call it done."
slug: "ai-content-filtering-pipeline"
date: 2026-03-01
lastmod: 2026-03-01
category: "kubernetes"
tags: ["content-filtering", "llm-security", "sidecar", "input-classification", "output-scanning"]
personas: ["ai-ml-engineer", "security-engineer", "sre"]
article_number: 132
difficulty: "advanced"
estimated_reading_time: 17
provider_bridges:
  - name: "Lakera"
    id: 142
    category: "llm-security"
  - name: "Kong"
    id: 35
    category: "api-gateway"
premium_pack: "content-filtering-pipeline-configs"
published: true
layout: article.njk
permalink: "/articles/kubernetes/ai-content-filtering-pipeline/index.html"
---

# Building a Content Filtering Pipeline for LLM Applications: From Raw Input to Safe Output

## Problem

A single content filter is not a pipeline. Most LLM deployments add one filter (usually on output) and call it done. This leaves gaps: the input filter might catch "write malware" but not a jailbreak that makes the model think it is writing a security tutorial. The output filter might catch profanity but not a detailed phishing template wrapped in professional language.

A content filtering pipeline processes every request through multiple independent stages: input classification, input transformation, inference, output scanning, and output rewriting. Each stage operates independently so that a bypass at one stage is caught by another. The pipeline must handle edge cases: multi-turn conversations where context accumulates across turns, multimodal inputs (images with embedded text), streaming responses where the full output is not available until generation completes, and adversarial inputs designed to exploit gaps between stages.

The engineering challenge is latency. Every filter stage adds milliseconds. Users expect sub-second responses. The pipeline must be fast enough to be invisible.

## Threat Model

- **Adversary:** (1) Users crafting inputs to bypass content restrictions. (2) Attackers injecting payloads through multi-turn conversations. (3) The model generating unsafe content without adversarial input.
- **Objective:** Generate policy-violating content. Bypass content filters through encoding, language switching, or context manipulation. Extract sensitive information through the model. Accumulate harmful context across conversation turns.
- **Blast radius:** Harmful content reaches users. Regulatory violations. Brand damage. Legal liability for generated content.

## Configuration

### Multi-Stage Filtering Pipeline

```python
# content_pipeline.py - multi-stage content filtering pipeline
import asyncio
import time
from dataclasses import dataclass, field
from typing import List, Optional, Callable, Any
from enum import Enum

class FilterAction(Enum):
    PASS = "pass"
    FLAG = "flag"
    REWRITE = "rewrite"
    BLOCK = "block"

@dataclass
class FilterResult:
    action: FilterAction
    stage: str
    filter_name: str
    confidence: float = 0.0
    rewritten_text: Optional[str] = None
    details: dict = field(default_factory=dict)

@dataclass
class PipelineResult:
    final_action: FilterAction
    original_input: str
    processed_input: str
    original_output: Optional[str] = None
    processed_output: Optional[str] = None
    filter_results: List[FilterResult] = field(default_factory=list)
    total_latency_ms: float = 0.0

class ContentFilterPipeline:
    """
    Multi-stage content filtering pipeline.
    Stages:
    1. Input classification (is this input safe to process?)
    2. Input transformation (sanitise, normalise, redact)
    3. [Inference happens here - external to pipeline]
    4. Output scanning (does the output violate policies?)
    5. Output rewriting (redact, soften, or replace unsafe content)
    """

    def __init__(self):
        self.input_classifiers: List[dict] = []
        self.input_transformers: List[dict] = []
        self.output_scanners: List[dict] = []
        self.output_rewriters: List[dict] = []

    def add_input_classifier(self, name: str, fn: Callable, blocking: bool = True):
        self.input_classifiers.append({"name": name, "fn": fn, "blocking": blocking})

    def add_input_transformer(self, name: str, fn: Callable):
        self.input_transformers.append({"name": name, "fn": fn})

    def add_output_scanner(self, name: str, fn: Callable, blocking: bool = True):
        self.output_scanners.append({"name": name, "fn": fn, "blocking": blocking})

    def add_output_rewriter(self, name: str, fn: Callable):
        self.output_rewriters.append({"name": name, "fn": fn})

    async def process_input(self, text: str) -> PipelineResult:
        start = time.time()
        results = []
        processed = text

        # Stage 1: Input classification (run classifiers in parallel)
        classifier_tasks = [
            asyncio.to_thread(c["fn"], processed) for c in self.input_classifiers
        ]
        classifier_results = await asyncio.gather(*classifier_tasks, return_exceptions=True)

        for i, result in enumerate(classifier_results):
            if isinstance(result, Exception):
                results.append(FilterResult(
                    action=FilterAction.FLAG,
                    stage="input_classification",
                    filter_name=self.input_classifiers[i]["name"],
                    details={"error": str(result)},
                ))
                continue

            fr = FilterResult(
                action=result.get("action", FilterAction.PASS),
                stage="input_classification",
                filter_name=self.input_classifiers[i]["name"],
                confidence=result.get("confidence", 0.0),
                details=result,
            )
            results.append(fr)

            if fr.action == FilterAction.BLOCK and self.input_classifiers[i]["blocking"]:
                return PipelineResult(
                    final_action=FilterAction.BLOCK,
                    original_input=text,
                    processed_input=processed,
                    filter_results=results,
                    total_latency_ms=(time.time() - start) * 1000,
                )

        # Stage 2: Input transformation (sequential - each transforms the text)
        for transformer in self.input_transformers:
            result = transformer["fn"](processed)
            processed = result.get("text", processed)
            results.append(FilterResult(
                action=FilterAction.REWRITE if processed != text else FilterAction.PASS,
                stage="input_transformation",
                filter_name=transformer["name"],
                rewritten_text=processed if processed != text else None,
                details=result,
            ))

        return PipelineResult(
            final_action=FilterAction.PASS,
            original_input=text,
            processed_input=processed,
            filter_results=results,
            total_latency_ms=(time.time() - start) * 1000,
        )

    async def process_output(self, output: str, original_input: str) -> PipelineResult:
        start = time.time()
        results = []
        processed = output

        # Stage 4: Output scanning (run scanners in parallel)
        scanner_tasks = [
            asyncio.to_thread(s["fn"], processed, original_input) for s in self.output_scanners
        ]
        scanner_results = await asyncio.gather(*scanner_tasks, return_exceptions=True)

        should_block = False
        for i, result in enumerate(scanner_results):
            if isinstance(result, Exception):
                results.append(FilterResult(
                    action=FilterAction.FLAG,
                    stage="output_scanning",
                    filter_name=self.output_scanners[i]["name"],
                    details={"error": str(result)},
                ))
                continue

            fr = FilterResult(
                action=result.get("action", FilterAction.PASS),
                stage="output_scanning",
                filter_name=self.output_scanners[i]["name"],
                confidence=result.get("confidence", 0.0),
                details=result,
            )
            results.append(fr)

            if fr.action == FilterAction.BLOCK and self.output_scanners[i]["blocking"]:
                should_block = True

        if should_block:
            return PipelineResult(
                final_action=FilterAction.BLOCK,
                original_input=original_input,
                processed_input=original_input,
                original_output=output,
                processed_output="I cannot provide that information.",
                filter_results=results,
                total_latency_ms=(time.time() - start) * 1000,
            )

        # Stage 5: Output rewriting (sequential)
        for rewriter in self.output_rewriters:
            result = rewriter["fn"](processed)
            processed = result.get("text", processed)
            results.append(FilterResult(
                action=FilterAction.REWRITE if processed != output else FilterAction.PASS,
                stage="output_rewriting",
                filter_name=rewriter["name"],
                rewritten_text=processed if processed != output else None,
                details=result,
            ))

        return PipelineResult(
            final_action=FilterAction.PASS,
            original_input=original_input,
            processed_input=original_input,
            original_output=output,
            processed_output=processed,
            filter_results=results,
            total_latency_ms=(time.time() - start) * 1000,
        )
```

### Deploying Filter Models as Sidecars

```yaml
# llm-service-with-filter-sidecar.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: llm-service
  namespace: ai-services
spec:
  replicas: 3
  selector:
    matchLabels:
      app: llm-service
  template:
    metadata:
      labels:
        app: llm-service
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
    spec:
      containers:
        # Main LLM inference container
        - name: llm-inference
          image: internal-registry/llm-inference:3.0.0
          ports:
            - containerPort: 8080
              name: inference
          env:
            - name: FILTER_SIDECAR_URL
              value: "http://localhost:8081"
            - name: PRE_FILTER_ENABLED
              value: "true"
            - name: POST_FILTER_ENABLED
              value: "true"
          resources:
            requests:
              cpu: "2"
              memory: 8Gi
            limits:
              cpu: "4"
              memory: 16Gi

        # Content filter sidecar - runs filter models locally
        - name: content-filter
          image: internal-registry/content-filter:2.1.0
          ports:
            - containerPort: 8081
              name: filter
          env:
            - name: INPUT_CLASSIFIERS
              value: "toxicity,jailbreak,topic"
            - name: OUTPUT_SCANNERS
              value: "safety,pii,policy"
            - name: MODEL_DIR
              value: "/models"
            - name: MAX_LATENCY_MS
              value: "200"
          resources:
            requests:
              cpu: "1"
              memory: 2Gi
            limits:
              cpu: "2"
              memory: 4Gi
          volumeMounts:
            - name: filter-models
              mountPath: /models
              readOnly: true
          readinessProbe:
            httpGet:
              path: /ready
              port: 8081
            periodSeconds: 10
            initialDelaySeconds: 30
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8081
            periodSeconds: 30

        # Metrics exporter sidecar
        - name: metrics
          image: internal-registry/filter-metrics-exporter:1.0.0
          ports:
            - containerPort: 9090
              name: metrics
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
            limits:
              cpu: 100m
              memory: 128Mi

      volumes:
        - name: filter-models
          persistentVolumeClaim:
            claimName: filter-models-pvc
```

### Async vs Sync Filtering Configuration

```python
# filter_config.py - configure sync vs async filtering per stage
# Sync: blocks until filter completes (safe, adds latency)
# Async: returns immediately, flags retroactively (fast, less safe)

FILTER_CONFIG = {
    "input_classifiers": {
        # Fast checks run synchronously (block before inference)
        "toxicity_regex": {"mode": "sync", "timeout_ms": 10, "blocking": True},
        "injection_pattern": {"mode": "sync", "timeout_ms": 10, "blocking": True},
        "input_length": {"mode": "sync", "timeout_ms": 1, "blocking": True},

        # Slow checks run synchronously but with a timeout fallback
        "jailbreak_classifier": {"mode": "sync", "timeout_ms": 200, "blocking": True,
                                  "fallback_on_timeout": "pass"},
        "topic_classifier": {"mode": "sync", "timeout_ms": 200, "blocking": False},
    },
    "output_scanners": {
        # PII scanning is always synchronous (never leak PII)
        "pii_scanner": {"mode": "sync", "timeout_ms": 20, "blocking": True},

        # Safety classifier runs synchronously for blocking violations
        "safety_classifier": {"mode": "sync", "timeout_ms": 200, "blocking": True},

        # Policy compliance runs async (flags for review, does not block)
        "policy_compliance": {"mode": "async", "blocking": False},
    },
    "output_rewriters": {
        # PII redaction is always synchronous
        "pii_redactor": {"mode": "sync", "timeout_ms": 10},

        # Tone adjustment runs async (best effort)
        "tone_adjuster": {"mode": "async"},
    },
}
```

### Handling Edge Cases

```python
# edge_cases.py - handle multi-turn and streaming edge cases

class MultiTurnFilter:
    """
    Filter content in multi-turn conversations.
    Individual messages may be benign, but the accumulated context
    can build toward harmful content across turns.
    """

    def __init__(self, max_context_window: int = 10):
        self.max_context = max_context_window

    def check_accumulated_context(self, conversation: list) -> dict:
        """
        Analyse the full conversation context, not just the latest message.
        Catches multi-turn jailbreak attempts that build context gradually.
        """
        # Concatenate recent turns for context analysis
        recent = conversation[-self.max_context:]
        full_context = " ".join([msg["content"] for msg in recent])

        # Check for escalation patterns
        escalation_signals = 0
        for i, msg in enumerate(recent):
            if i == 0:
                continue
            prev = recent[i - 1]
            # Check if each turn pushes boundaries further
            if msg.get("role") == "user":
                if self._is_boundary_pushing(prev.get("content", ""), msg["content"]):
                    escalation_signals += 1

        return {
            "passed": escalation_signals < 3,
            "escalation_count": escalation_signals,
            "context_length": len(recent),
            "reason": f"multi_turn_escalation: {escalation_signals} signals" if escalation_signals >= 3 else None,
        }

    def _is_boundary_pushing(self, previous: str, current: str) -> bool:
        """Heuristic: does the current message push beyond the previous boundary?"""
        boundary_phrases = [
            "now go further", "more detail", "be more specific",
            "actually", "no really", "forget what I said",
            "but what about", "just this once",
        ]
        current_lower = current.lower()
        return any(phrase in current_lower for phrase in boundary_phrases)


class StreamingFilter:
    """
    Filter streaming LLM outputs.
    Challenge: cannot see full output until generation completes.
    Solution: scan accumulated buffer at intervals.
    """

    def __init__(self, scan_interval_tokens: int = 50):
        self.scan_interval = scan_interval_tokens
        self.buffer = ""
        self.token_count = 0

    def add_token(self, token: str) -> dict:
        self.buffer += token
        self.token_count += 1

        if self.token_count % self.scan_interval == 0:
            scan_result = self._scan_buffer()
            if scan_result["action"] == "abort":
                return {
                    "action": "abort",
                    "reason": scan_result["reason"],
                    "tokens_generated": self.token_count,
                }

        return {"action": "continue"}

    def _scan_buffer(self) -> dict:
        """Scan accumulated buffer for policy violations."""
        import re
        critical_patterns = [
            r"(?:step\s*\d+\s*:.*){3,}",  # step-by-step instructions
            r"\bpassword\s*[:=]\s*\S+",     # credential exposure
        ]
        for pattern in critical_patterns:
            if re.search(pattern, self.buffer, re.IGNORECASE | re.DOTALL):
                return {"action": "abort", "reason": f"pattern_match: {pattern}"}
        return {"action": "continue"}
```

### [Prometheus](https://prometheus.io) Monitoring

```yaml
# prometheus-content-filter.yaml
groups:
  - name: content-filtering
    interval: 1m
    rules:
      - alert: FilterBlockRateHigh
        expr: >
          sum(rate(content_filter_blocked_total[5m])) by (stage, filter_name)
          / sum(rate(content_filter_requests_total[5m])) by (stage, filter_name) > 0.15
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Filter {{ $labels.filter_name }} blocking >15% of requests at {{ $labels.stage }}"

      - alert: FilterLatencyBudgetExceeded
        expr: >
          histogram_quantile(0.99,
            rate(content_filter_latency_seconds_bucket{stage="input"}[5m])
          ) > 0.3
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Input filtering P99 latency exceeds 300ms budget"

      - alert: FilterSidecarDown
        expr: up{job="content-filter-sidecar"} == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Content filter sidecar is down on {{ $labels.pod }}"
          description: "LLM requests may be processed without content filtering."

      - alert: MultiTurnEscalation
        expr: increase(multi_turn_escalation_detected_total[10m]) > 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Multiple multi-turn escalation attempts detected"
```

## Expected Behaviour

- Input classification completes within 10-200ms depending on classifier type
- PII is always scanned synchronously on both input and output
- Safety-critical output scanners block harmful content before it reaches the user
- Streaming responses are scanned at 50-token intervals with abort capability
- Multi-turn conversations are analysed for escalation patterns across turns
- Filter sidecar runs co-located with inference for minimal network latency
- Pipeline total overhead stays under 300ms at P99 for input + output filtering combined

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Sidecar deployment | Co-located filtering (low network latency) | Filter consumes pod CPU/memory resources | Right-size sidecar resources. Share GPU for classifier inference if available. |
| Sync input filtering | Blocks harmful input before model processes it | Adds latency to every request | Run fast checks sync, slow checks with timeout fallback. |
| Async output scanning | No latency penalty for non-blocking checks | Policy violation reaches user before async flag | Reserve async mode for non-safety-critical checks only. |
| Streaming scan interval (50 tokens) | Catches violations mid-generation | Cannot catch violations shorter than scan interval | Reduce interval for high-risk use cases. Accept higher CPU cost. |
| Multi-turn context window (10 turns) | Catches gradual escalation | Misses very slow escalation over 10+ turns | Increase window for high-risk applications. Accept memory cost. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Sidecar crash | Inference continues without filtering | Health check failures; filter metrics drop to zero | Configure LLM service to reject requests when sidecar is unhealthy. [Kubernetes](https://kubernetes.io) restarts sidecar automatically. |
| Classifier model OOM | ML-based filters stop responding | Sidecar memory usage at limit; timeout errors | Increase sidecar memory limit. Use quantised classifier models. Reduce batch size. |
| Async filter backlog | Async flags arrive minutes after response was sent | Async queue depth grows; flag latency increases | Scale async workers. Reduce async filter scope. Move critical checks to sync. |
| Multi-turn bypass | Attacker resets context to avoid escalation detection | Harmful output from a "fresh" conversation context | Apply stateless output scanning regardless of conversation history. Do not rely solely on context analysis. |

## When to Consider a Managed Alternative

Building a multi-stage content filtering pipeline with sync/async modes, sidecar deployment, streaming support, and multi-turn analysis is significant engineering. Maintaining classifier models and filter rules is ongoing work.

- **[Lakera](https://www.lakera.ai):** Managed content filtering API with input classification, output scanning, and policy enforcement. Sub-50ms latency. Continuously updated models.
- **[Kong](https://konghq.com):** API gateway with plugin ecosystem for request/response transformation, rate limiting, and content filtering middleware.

**Premium content pack:** Content filtering pipeline pack. Multi-stage pipeline framework (Python async), sidecar deployment manifests (Kubernetes), streaming filter implementation, multi-turn context analyser, filter model configurations, and Prometheus monitoring rules.


## Related Articles

- [AI Red Teaming Methodology: Structured Adversarial Testing for LLM Applications](/articles/kubernetes/ai-red-teaming/)
- [Hardening Model Inference Endpoints: Authentication, Rate Limiting, and Input Validation](/articles/kubernetes/inference-endpoint-hardening/)
- [Prompt Injection Defence in Production: Input Validation, Output Filtering, and Monitoring](/articles/kubernetes/prompt-injection/)
- [AI Data Leakage Prevention: Input Filtering, Output Scanning, and Audit Trails](/articles/kubernetes/ai-data-leakage-prevention/)
- [Implementing AI Guardrails: Input Validation, Output Filtering, and Safety Classifiers in Production](/articles/kubernetes/ai-guardrails-implementation/)
