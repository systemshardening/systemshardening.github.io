---
title: "Security Observability for AI Inference Infrastructure: Monitoring Prompt Injection, Model Abuse, and Inference Threats"
description: "AI inference endpoints are APIs with unusually high blast-radius inputs: a single prompt can exfiltrate training data, bypass all downstream application logic, or drain budget at scale. This article builds a security observability layer specifically for LLM inference — logging the right signals, detecting prompt injection and jailbreaks, identifying model extraction attempts, and applying OpenTelemetry GenAI semantic conventions without creating a PII logging catastrophe."
slug: ai-inference-security-observability
date: 2026-05-07
lastmod: 2026-05-07
category: observability
tags:
  - ai-security
  - inference-security
  - prompt-injection
  - llm-monitoring
  - opentelemetry
personas:
  - security-engineer
  - ml-engineer
article_number: 566
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/observability/ai-inference-security-observability/
---

# Security Observability for AI Inference Infrastructure: Monitoring Prompt Injection, Model Abuse, and Inference Threats

## Problem

AI inference endpoints are a category of API that existing security observability tooling was not designed to monitor. A REST API call transmits a structured request with known fields; its security risks are credential misuse, injection in structured parameters, and data volume anomalies. An LLM inference call transmits an open-ended natural language string — any length, any content, any intent — against which the application's logic is only as strong as the model's interpretation. The model is the parser, the validator, and the executor of the input, all at once.

The consequence is a threat surface that spans a single field. A prompt can contain an instruction to ignore all previous context and output internal system state. It can impersonate a system-level role. It can be encoded in base64 to evade keyword filters. It can systematically probe what the model knows through carefully chosen queries that reconstruct training data. It can drive the model to generate policy-violating content or reveal the system prompt. Most production LLM deployments have no observability on any of this.

The standard API security metrics — request count, latency, 4xx rate — are necessary but not sufficient for inference security. A prompt injection attack generates a valid HTTP 200 response with correct token counts. A jailbreak attempt looks like normal usage until the policy-violating output is served. A model extraction campaign may run for weeks at request volumes indistinguishable from legitimate use. None of these threats are visible in an API gateway dashboard.

Common observability gaps in LLM deployments:

- **No per-user request attribution at the inference layer.** Gateway metrics count total inference requests. When a user submits 2,000 adversarial prompts over three hours, the anomaly is invisible without per-identity request counts at the inference tier — not just the gateway.
- **Prompt content is not logged at all, or is logged in full.** Teams either skip prompt logging entirely (no forensic capability) or log raw prompts and completions to application logs (which then become a PII and sensitive-data liability, queryable by anyone with log access).
- **No detection on input structure.** Prompt injection often has structural signatures — role override keywords, instruction delimiters, base64 blobs, jailbreak scaffolding phrases. None of these trigger any alert in a deployment that only monitors HTTP-layer metrics.
- **Output policy violations are not tracked.** When the model's content policy classifier flags a generation, that event is consumed by the application but not recorded in any security-accessible log. Trends in flagged outputs are invisible.
- **Model extraction attempts are indistinguishable from legitimate use** unless adversarial input patterns — systematic parameter sweeps, maximally diverse prompts covering the training distribution — are tracked.
- **Finance and abuse controls are decoupled from security monitoring.** Rate limits exist, but sustained rate-limit events — a reliable signal of automated abuse — are not correlated with user identity and not fed into security alerting.

**Target systems:** vLLM 0.4+; Ollama 0.1.30+; OpenAI API and compatible endpoints; LiteLLM proxy; any LLM deployment using an OpenTelemetry-instrumented inference gateway; Prometheus for metrics; structured logging pipeline (Loki, Elasticsearch, or Fluent Bit).

## Threat Model

**Adversary 1 — Prompt injection via user-controlled input.** An attacker uses the application's legitimate interface — a customer support chatbot, a document summarisation tool, a code assistant — to submit inputs that override the system prompt. The injected instruction redirects the model to output the system prompt, return internal knowledge, or invoke a downstream tool with attacker-controlled parameters. The attack arrives as a valid HTTP POST and produces an HTTP 200; the only security-relevant signals are in the prompt's structural characteristics and the content of the completion.

**Adversary 2 — Jailbreak to extract policy-violating content.** The attacker iterates through known jailbreak scaffolds — roleplay framings, hypothetical scenarios, base64-encoded payloads, token manipulation — to bypass the model's content policy or the application's output filter. Individual attempts may fail; the attack is the sequence of escalating attempts over multiple requests. The signal is a burst of content-policy classifier hits from a single user identity.

**Adversary 3 — Model extraction.** The attacker systematically queries the model with inputs designed to reconstruct its weights, training data, or fine-tuning content. Model extraction proceeds through maximally diverse prompts that probe different regions of the model's parameter space — different topics, styles, languages, and tasks — in high volume. Legitimate users have usage patterns clustered around specific tasks; extractors span the entire capability surface.

**Adversary 4 — API abuse for cost exhaustion or rate gaming.** An attacker submits requests designed to maximise token generation — prompts that elicit the longest possible completions — or rotates through API keys to evade per-key rate limits. The signal is abnormal token-per-request ratios and sustained rate-limit events across key identities.

**Adversary 5 — Sensitive data in prompts and exfiltration through the model.** A user or automated workflow submits prompts containing PII, credentials, or confidential business data. If the model's context window is accessible to other users (session mismanagement) or if completions are logged in full, the sensitive data persists in observability infrastructure with broad read access.

- **Access level:** Adversaries 1–3 have legitimate authenticated access to the inference endpoint. Adversary 4 may operate with legitimate keys or compromised keys. Adversary 5 may be an unwitting user or an automated pipeline.
- **Objective:** Override application logic, extract protected content, steal model IP, exhaust budget, exfiltrate sensitive data.
- **Blast radius:** A successful prompt injection in an agent with tool access can result in arbitrary downstream actions. An undetected model extraction campaign can exfiltrate proprietary fine-tuning data and associated training investment. Sensitive data logged in full is a GDPR-reportable event.

## Configuration

### Step 1: Deciding What to Log — The Prompt Logging Dilemma

The first security decision in AI inference observability is what to persist about prompts and completions. Full prompt logging creates a PII database: user prompts often contain names, account numbers, medical information, and confidential queries. The observability system should not become the exfiltration vector.

The principle is: log metadata and hashed identifiers, not content. This enables correlation, volume analysis, and anomaly detection without storing the prompt text.

```python
# Python: compute security-relevant metadata from a prompt without storing content.
import hashlib
import re
import base64
from typing import Any

def extract_prompt_security_metadata(
    prompt: str,
    user_id: str,
    model_id: str,
    session_id: str,
) -> dict[str, Any]:
    """
    Extract security-relevant metadata from a prompt.
    Returns a dict safe to emit as structured log fields.
    Does NOT include the raw prompt text.
    """
    # Hash for correlation — links related requests without storing content.
    # SHA-256 truncated to 16 hex chars: enough for correlation, not reversible.
    prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:16]

    # Structural anomaly signals.
    prompt_lower = prompt.lower()

    # Injection keyword detection — role-override and instruction-override patterns.
    injection_keywords = [
        "ignore previous instructions",
        "ignore all previous",
        "disregard the above",
        "forget your instructions",
        "you are now",
        "act as",
        "pretend you are",
        "your new instructions",
        "system prompt",
        "reveal your instructions",
        "repeat the above",
        "what were your instructions",
        "new persona",
        "jailbreak",
        "dan mode",
        "developer mode",
        "do anything now",
    ]
    injection_keyword_hits = sum(
        1 for kw in injection_keywords if kw in prompt_lower
    )

    # Detect base64-encoded content in the prompt.
    # Attackers encode instructions to evade keyword filters.
    base64_segments = re.findall(
        r'[A-Za-z0-9+/]{40,}={0,2}',
        prompt
    )
    has_base64_blob = any(
        _is_likely_base64(seg) for seg in base64_segments
    )

    # Role delimiter injection — attempts to inject system-level context.
    role_delimiters = [
        "<system>", "</system>",
        "[system]", "[/system]",
        "### system",
        "### instruction",
        "<|im_start|>system",
        "<|begin_of_text|>",
        "human:", "assistant:",   # Few-shot injection patterns.
    ]
    role_delimiter_hits = sum(
        1 for d in role_delimiters if d in prompt_lower
    )

    # Prompt length — very long prompts can indicate context stuffing attacks.
    token_estimate = len(prompt.split())   # Rough approximation.

    return {
        # Identity and correlation.
        "user_id": user_id,
        "session_id": session_id,
        "model_id": model_id,
        "prompt_hash": prompt_hash,            # Correlate without storing content.

        # Size metrics — used for abuse detection and cost monitoring.
        "prompt_char_count": len(prompt),
        "prompt_token_estimate": token_estimate,

        # Structural anomaly signals.
        "injection_keyword_hits": injection_keyword_hits,
        "role_delimiter_hits": role_delimiter_hits,
        "has_base64_blob": has_base64_blob,

        # Composite risk score (0–10).
        "structural_risk_score": min(10, (
            injection_keyword_hits * 2
            + role_delimiter_hits * 3
            + (5 if has_base64_blob else 0)
        )),
    }


def _is_likely_base64(s: str) -> bool:
    """Check if a string segment decodes as printable UTF-8 (probable encoded text)."""
    try:
        decoded = base64.b64decode(s + "==").decode("utf-8")
        return len(decoded) > 20 and decoded.isprintable()
    except Exception:
        return False
```

This function produces structured log fields that can be indexed and alerted on without the prompt ever touching the logging pipeline.

### Step 2: OpenTelemetry GenAI Semantic Conventions

The OpenTelemetry GenAI semantic conventions (stabilised in OTel 1.26) define standard attribute names for LLM spans. Use these so that security tooling can query inference telemetry consistently regardless of whether the model is served via vLLM, Ollama, or a managed API.

```python
# Python: instrument an inference call with OTel GenAI semantic conventions
# plus security-specific extensions.
from opentelemetry import trace
from opentelemetry.trace import SpanKind

tracer = trace.get_tracer("ai.inference")

def instrumented_inference(
    prompt: str,
    user_id: str,
    model_id: str,
    session_id: str,
    client,   # Your inference client (openai, vllm, etc.)
) -> dict:
    security_meta = extract_prompt_security_metadata(
        prompt, user_id, model_id, session_id
    )

    with tracer.start_as_current_span(
        "llm.inference",
        kind=SpanKind.CLIENT,
    ) as span:
        # OTel GenAI semantic convention attributes.
        span.set_attributes({
            # Standard GenAI conventions.
            "gen_ai.system": "openai",                # or "vllm", "ollama", "anthropic".
            "gen_ai.request.model": model_id,
            "gen_ai.operation.name": "chat",          # "chat", "completion", "embeddings".

            # Identity — critical for per-user attribution.
            "enduser.id": user_id,
            "session.id": session_id,

            # Security metadata from Step 1 — not the prompt content.
            "ai.security.prompt_hash": security_meta["prompt_hash"],
            "ai.security.injection_keyword_hits": security_meta["injection_keyword_hits"],
            "ai.security.role_delimiter_hits": security_meta["role_delimiter_hits"],
            "ai.security.has_base64_blob": security_meta["has_base64_blob"],
            "ai.security.structural_risk_score": security_meta["structural_risk_score"],
            "ai.security.prompt_char_count": security_meta["prompt_char_count"],
        })

        # Execute inference.
        response = client.chat.completions.create(
            model=model_id,
            messages=[{"role": "user", "content": prompt}],
        )

        # Post-response attributes.
        usage = response.usage
        span.set_attributes({
            # Standard GenAI conventions — input/output token counts.
            "gen_ai.usage.input_tokens": usage.prompt_tokens,
            "gen_ai.usage.output_tokens": usage.completion_tokens,

            # Finish reason — policy violation signals.
            # "stop" is normal; "content_filter" means policy hit.
            "gen_ai.response.finish_reasons": [response.choices[0].finish_reason],

            # Output size — abnormal ratio signals prompt-completion abuse.
            "ai.security.output_char_count": len(response.choices[0].message.content),
            "ai.security.token_ratio": (
                usage.completion_tokens / max(usage.prompt_tokens, 1)
            ),
        })

        # Log if content policy triggered — without storing the content.
        if response.choices[0].finish_reason == "content_filter":
            span.set_attribute("ai.security.policy_violation", True)

        return response
```

Key attributes for security:

| Attribute | Convention | Security Use |
|-----------|-----------|--------------|
| `gen_ai.system` | OTel GenAI | Identifies the model provider; scopes alerts to specific deployments |
| `gen_ai.usage.input_tokens` | OTel GenAI | Volume-based abuse detection; cost monitoring |
| `gen_ai.usage.output_tokens` | OTel GenAI | Exfiltration via generation detection; cost exhaustion |
| `gen_ai.response.finish_reasons` | OTel GenAI | `content_filter` = policy violation event |
| `enduser.id` | OTel base | Per-user attribution for all security aggregations |
| `ai.security.structural_risk_score` | Custom | Drives prompt injection alerting |
| `ai.security.token_ratio` | Custom | Detects prompts engineered to maximise output |

### Step 3: Prometheus Metrics for Inference Security

These recording rules and alerts implement the core inference security detection layer. They operate on labelled counters emitted by the inference gateway.

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: ai-inference-security
  namespace: monitoring
spec:
  groups:
    - name: inference_security
      interval: 30s
      rules:

        # Recording rule: request rate per user.
        # High-cardinality label (user_id): use with caution on large deployments;
        # consider aggregating to user tier or hashing to limit cardinality.
        - record: security:inference_requests:rate5m
          expr: >
            sum by (user_id, model_id) (
              rate(llm_inference_requests_total[5m])
            )

        # Alert: abnormal per-user request volume (model extraction signal).
        # A user making 10x their baseline request rate is probing systematically.
        - alert: InferenceUserRequestVolumeAnomaly
          expr: >
            security:inference_requests:rate5m
            > 10 * (
              avg_over_time(security:inference_requests:rate5m[24h])
              + 0.01
            )
          for: 10m
          labels:
            severity: warning
          annotations:
            summary: "User {{ $labels.user_id }} inference volume is 10x above 24h baseline"
            description: "Model: {{ $labels.model_id }}. Rate: {{ $value | humanize }}/sec. Investigate for model extraction or abuse."

        # Alert: sustained rate limit hits from a single user (automated abuse).
        - alert: InferenceRateLimitAbuseSignal
          expr: >
            sum by (user_id) (
              rate(llm_inference_rate_limit_hits_total[5m])
            ) > 0.1
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "User {{ $labels.user_id }} hitting inference rate limits continuously"
            description: "Sustained rate limit events indicate automated abuse. Review request patterns."

        # Alert: elevated structural risk scores (prompt injection campaign).
        # Fires when >5% of a user's requests in 5 min have high risk scores.
        - alert: InferenceHighRiskPromptPattern
          expr: >
            (
              sum by (user_id) (
                rate(llm_inference_requests_total{structural_risk_score="high"}[5m])
              )
            )
            /
            (
              sum by (user_id) (
                rate(llm_inference_requests_total[5m])
              )
            ) > 0.05
          for: 5m
          labels:
            severity: critical
          annotations:
            summary: "User {{ $labels.user_id }}: >5% of requests match prompt injection patterns"
            description: "Injection keyword hits, role delimiter injection, or base64-encoded instructions detected at elevated rate. Review prompt hashes."

        # Alert: content policy violation burst (jailbreak attempt sequence).
        - alert: InferenceContentPolicyViolationBurst
          expr: >
            sum by (user_id, model_id) (
              rate(llm_inference_policy_violations_total[10m])
            ) > 0.05
          for: 3m
          labels:
            severity: warning
          annotations:
            summary: "User {{ $labels.user_id }} generating content policy violations"
            description: "Sustained policy violations on {{ $labels.model_id }}. Possible jailbreak iteration. Check for finish_reason=content_filter pattern."

        # Alert: abnormal token output ratio (output maximisation abuse).
        # token_ratio > 5 means the model is generating 5x more tokens than received.
        # Legitimate chat averages around 0.5–2; extraction prompts target 5+.
        - alert: InferenceAbnormalTokenRatio
          expr: >
            histogram_quantile(0.95,
              sum by (user_id, le) (
                rate(llm_inference_token_ratio_bucket[15m])
              )
            ) > 5
          for: 10m
          labels:
            severity: warning
          annotations:
            summary: "User {{ $labels.user_id }} p95 token ratio exceeds 5 (output exhaustion signal)"
            description: "High output-to-input token ratios indicate prompts engineered for maximum generation. Check for cost exhaustion or verbatim output extraction."

        # Alert: latency spike indicating heavy generation (possible exfiltration).
        # Unusually long generation bursts from a single user are worth investigating.
        - alert: InferenceLatencySpike
          expr: >
            histogram_quantile(0.99,
              sum by (user_id, le) (
                rate(llm_inference_duration_seconds_bucket[5m])
              )
            ) > 60
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "User {{ $labels.user_id }} p99 inference latency >60s"
            description: "Sustained long-generation requests. Possible verbatim output exfiltration or runaway context window abuse."
```

### Step 4: vLLM and Ollama Security Metrics

vLLM and Ollama both expose Prometheus metrics. The security-relevant subset:

```bash
# vLLM (>=0.4): Prometheus metrics at /metrics on port 8000.
# Key security metrics:

vllm:request_success_total{model_name, finished_reason}
# finished_reason="abort" spikes = requests being force-stopped (policy hits, timeouts).

vllm:request_prompt_tokens_total{model_name}
vllm:request_generation_tokens_total{model_name}
# Track per-model token consumption. Segment by user via access log correlation.

vllm:num_requests_running
vllm:num_requests_waiting
# Queue depth spikes during abuse or extraction campaigns.

vllm:gpu_cache_usage_perc
# Cache exhaustion caused by very long contexts — possible context stuffing attack.
```

```yaml
# Scrape vLLM metrics in Prometheus.
scrape_configs:
  - job_name: vllm
    static_configs:
      - targets: ['vllm-service.inference.svc.cluster.local:8000']
    metric_relabel_configs:
      # Add deployment label for multi-model environments.
      - source_labels: [model_name]
        target_label: deployment_model
```

```bash
# Ollama: metrics via /api/generate response fields (not a Prometheus endpoint by default).
# Use the OpenTelemetry collector to parse Ollama API responses and emit metrics,
# or deploy a sidecar that scrapes the Ollama process via /proc.

# Key fields in Ollama API response body:
# eval_count: number of output tokens generated.
# prompt_eval_count: number of prompt tokens.
# eval_duration: time spent generating (nanoseconds).
# load_duration: model load time (spikes = cold-start, not abuse signal).

# Emit these as custom metrics via your inference wrapper:
llm_inference_requests_total{model_id, user_id, finish_reason}     counter
llm_inference_policy_violations_total{model_id, user_id}           counter
llm_inference_rate_limit_hits_total{user_id}                       counter
llm_inference_token_ratio_bucket{user_id, le}                      histogram
llm_inference_duration_seconds_bucket{user_id, le}                 histogram
llm_inference_high_risk_prompts_total{user_id}                     counter
```

### Step 5: Detecting Prompt Injection in Structured Logs

Metrics detect patterns over time. Structured logs detect individual high-risk requests. Route inference security logs to a searchable backend (Loki, Elasticsearch) for per-event investigation.

```python
# Inference gateway: emit a structured security event for each request.
# This log record contains no raw prompt or completion content.
import structlog
import time

log = structlog.get_logger()

def log_inference_security_event(
    security_meta: dict,
    response_meta: dict,
    request_id: str,
) -> None:
    """Emit a structured security log record for an inference request."""
    log.info(
        "inference.security_event",
        # Correlation IDs.
        request_id=request_id,
        prompt_hash=security_meta["prompt_hash"],
        session_id=security_meta["session_id"],

        # Identity.
        user_id=security_meta["user_id"],
        model_id=security_meta["model_id"],

        # Input signals.
        prompt_char_count=security_meta["prompt_char_count"],
        injection_keyword_hits=security_meta["injection_keyword_hits"],
        role_delimiter_hits=security_meta["role_delimiter_hits"],
        has_base64_blob=security_meta["has_base64_blob"],
        structural_risk_score=security_meta["structural_risk_score"],

        # Output signals.
        input_tokens=response_meta.get("input_tokens"),
        output_tokens=response_meta.get("output_tokens"),
        finish_reason=response_meta.get("finish_reason"),
        policy_violation=response_meta.get("finish_reason") == "content_filter",
        output_char_count=response_meta.get("output_char_count"),
        latency_ms=response_meta.get("latency_ms"),

        # Derived signals.
        token_ratio=response_meta.get("token_ratio"),
        timestamp=time.time(),
    )
```

```yaml
# Loki: LogQL query to find injection-pattern requests in the last 1 hour.
# Run from Grafana Explore or as an alerting rule.

# Find all requests with structural risk score >= 5.
{job="inference-gateway"}
  | json
  | structural_risk_score >= 5
  | line_format "user={{ .user_id }} hash={{ .prompt_hash }} score={{ .structural_risk_score }} b64={{ .has_base64_blob }}"

# Find all content policy violations by user.
{job="inference-gateway"}
  | json
  | policy_violation = `true`
  | line_format "user={{ .user_id }} model={{ .model_id }} hash={{ .prompt_hash }}"

# Count unique prompt hashes per user — low uniqueness = repeated probing.
# (Model extraction: high volume + high diversity; jailbreak: high volume + low diversity.)
sum by (user_id) (
  count_over_time(
    {job="inference-gateway"} | json | policy_violation = `true` [1h]
  )
) > 10
```

### Step 6: Detecting Model Extraction Campaigns

Model extraction looks like legitimate use at the individual request level. The signal is across requests: systematically diverse inputs covering the full capability surface, at volumes and patterns inconsistent with any specific task.

Normal usage is clustered. A developer using a code assistant submits code-related prompts. A customer service agent submits customer queries in a narrow domain. An extractor submits prompts spanning programming, creative writing, mathematics, science, foreign languages, and roleplay — all within the same session or user identity — because the goal is to cover parameter space, not accomplish a task.

```python
# Model extraction detection via prompt diversity analysis.
# Run as a scheduled job every 15 minutes against the inference log store.
# Does not require prompt content — operates on metadata only.

from elasticsearch import Elasticsearch
from datetime import datetime, timedelta

es = Elasticsearch("https://elasticsearch.internal:9200")

def detect_extraction_campaign(window_minutes: int = 60) -> list[dict]:
    """
    Identify users showing model extraction signatures:
    - High request volume.
    - High prompt length variance (diverse prompt sizes = diverse tasks).
    - High unique prompt hash count relative to request count (no repeated queries).
    - Spread across multiple model IDs (probing the full available model surface).
    """
    result = es.search(
        index="inference-security-*",
        body={
            "size": 0,
            "query": {
                "range": {
                    "timestamp": {
                        "gte": f"now-{window_minutes}m"
                    }
                }
            },
            "aggs": {
                "per_user": {
                    "terms": {
                        "field": "user_id.keyword",
                        "size": 1000,
                        # Only consider users with meaningful volume.
                        "min_doc_count": 50,
                    },
                    "aggs": {
                        "request_count": {
                            "value_count": {"field": "prompt_hash.keyword"}
                        },
                        "unique_prompt_hashes": {
                            "cardinality": {"field": "prompt_hash.keyword"}
                        },
                        "unique_models": {
                            "cardinality": {"field": "model_id.keyword"}
                        },
                        # Variance in prompt size = task diversity proxy.
                        "prompt_size_stats": {
                            "extended_stats": {"field": "prompt_char_count"}
                        },
                        "hash_uniqueness_ratio": {
                            "bucket_script": {
                                "buckets_path": {
                                    "unique": "unique_prompt_hashes",
                                    "total": "request_count",
                                },
                                "script": "params.unique / params.total"
                            }
                        },
                        "extraction_flag": {
                            "bucket_selector": {
                                "buckets_path": {
                                    "ratio": "hash_uniqueness_ratio",
                                    "models": "unique_models",
                                    "total": "request_count",
                                    "std_dev": "prompt_size_stats.std_deviation",
                                },
                                # Extraction signature:
                                # - >80% unique prompts (no repetition, systematic probing).
                                # - >1 model targeted (breadth coverage).
                                # - High prompt size variance (diverse task types).
                                # - Minimum volume threshold already set by min_doc_count.
                                "script": """
                                    params.ratio > 0.8
                                    && params.models > 1
                                    && params.std_dev > 200
                                """
                            }
                        }
                    }
                }
            }
        }
    )

    suspects = []
    for bucket in result["aggregations"]["per_user"]["buckets"]:
        suspects.append({
            "user_id": bucket["key"],
            "request_count": bucket["request_count"]["value"],
            "unique_hashes": bucket["unique_prompt_hashes"]["value"],
            "unique_models": bucket["unique_models"]["value"],
            "prompt_std_dev": bucket["prompt_size_stats"]["std_deviation"],
            "hash_uniqueness_ratio": bucket["hash_uniqueness_ratio"]["value"],
        })

    return suspects
```

The output of this job feeds into a security alert. Treat extraction suspects as high-priority manual investigations — the detection is probabilistic and may produce false positives for API integration developers, but the blast radius of an undetected extraction campaign (proprietary fine-tuning data, training IP, alignment-relevant internal prompts) justifies the investigation cost.

### Step 7: Rate Limiting as a Detection Control

Rate limits are usually implemented as availability controls. At the inference tier, sustained rate-limit events are also a security signal.

A legitimate user working within their quota rarely hits rate limits. An automated abuse campaign — model extraction, jailbreak iteration, cost exhaustion — consistently runs at the rate limit ceiling because the attack is optimised for throughput. Sustained rate-limit events over minutes to hours indicate a tool, not a user.

```python
# Track rate limit hits per user in Redis for security correlation.
# Implement in your inference gateway middleware.
import redis
import time

r = redis.Redis(host="redis.internal", port=6379, db=0)

def record_rate_limit_event(user_id: str) -> dict:
    """
    Record a rate limit hit for security monitoring.
    Returns the count and whether the abuse threshold has been exceeded.
    """
    now = int(time.time())
    window = 300   # 5-minute sliding window.
    key = f"ratelimit:events:{user_id}"

    pipe = r.pipeline()
    # Add event to sorted set with timestamp as score.
    pipe.zadd(key, {str(now): now})
    # Remove events older than the window.
    pipe.zremrangebyscore(key, 0, now - window)
    # Count remaining events in window.
    pipe.zcard(key)
    # Set expiry on the key.
    pipe.expire(key, window * 2)
    results = pipe.execute()

    event_count = results[2]

    # Abuse threshold: >20 rate limit hits in 5 minutes = automated activity.
    abuse_detected = event_count > 20

    if abuse_detected:
        # Emit Prometheus counter for alerting.
        # In production, use the prometheus_client library.
        pass

    return {
        "user_id": user_id,
        "rate_limit_hits_5m": event_count,
        "abuse_signal": abuse_detected,
    }
```

```yaml
# Prometheus alert: sustained rate limit pattern triggers security review.
# Separate from the availability alert — this is a security signal.
- alert: InferenceRateLimitAbuseSustained
  expr: >
    sum by (user_id) (
      increase(llm_inference_rate_limit_hits_total[5m])
    ) > 20
  for: 5m
  labels:
    severity: warning
    category: abuse
  annotations:
    summary: "User {{ $labels.user_id }}: >20 rate limit hits in 5 minutes"
    description: "Sustained rate limit saturation indicates automated tooling. Review for model extraction or jailbreak iteration."
    runbook_url: "https://systemshardening.com/runbooks/inference-rate-abuse"
```

### Step 8: Output Classifier Integration

Production LLM deployments typically have an output classifier — a content filter that evaluates completions before serving them. The security observability layer should receive classifier results as first-class events, not consume them silently.

```python
# Emit classifier results as structured security events.
# Do not store the flagged content — store the classification metadata only.

def process_classifier_result(
    response_content: str,
    user_id: str,
    prompt_hash: str,
    request_id: str,
    classifier,   # Your content classifier instance.
) -> dict:
    """
    Run the output classifier and emit a security event if flagged.
    Returns the classification result without storing content.
    """
    result = classifier.classify(response_content)

    if result.flagged:
        log.warning(
            "inference.output_policy_violation",
            request_id=request_id,
            user_id=user_id,
            prompt_hash=prompt_hash,
            # Classification categories — not the content itself.
            violation_categories=result.categories,
            violation_scores=result.category_scores,
            # Output length — but not output content.
            output_char_count=len(response_content),
        )
        # Increment Prometheus counter.
        # llm_inference_policy_violations_total.labels(
        #     user_id=user_id,
        #     categories=",".join(result.categories)
        # ).inc()

    return {
        "flagged": result.flagged,
        "categories": result.categories if result.flagged else [],
        "finish_reason": "content_filter" if result.flagged else "stop",
    }
```

### Step 9: Security Telemetry Summary

```
# Core inference security metrics.

llm_inference_requests_total{user_id, model_id, finish_reason}          counter
llm_inference_policy_violations_total{user_id, model_id, categories}    counter
llm_inference_rate_limit_hits_total{user_id}                            counter
llm_inference_high_risk_prompts_total{user_id, model_id}                counter
llm_inference_token_ratio_bucket{user_id, le}                           histogram
llm_inference_duration_seconds_bucket{user_id, le}                      histogram
llm_inference_input_tokens_total{user_id, model_id}                     counter
llm_inference_output_tokens_total{user_id, model_id}                    counter

# Extraction detection (from scheduled job).
llm_extraction_suspects_total{user_id}                                  counter
```

Alert priority matrix:

| Alert | Threat | Severity | Response |
|-------|--------|----------|----------|
| `InferenceHighRiskPromptPattern` | Prompt injection campaign | Critical | Review prompt hashes; revoke session |
| `InferenceContentPolicyViolationBurst` | Jailbreak iteration | Warning | Review violation categories; issue warning or suspend |
| `InferenceUserRequestVolumeAnomaly` | Model extraction / abuse | Warning | Correlate with extraction detection job |
| `InferenceRateLimitAbuseSustained` | Automated tooling | Warning | Identify whether legitimate integration; suspend if not |
| `InferenceAbnormalTokenRatio` | Output maximisation / cost exhaustion | Warning | Review request patterns; apply tighter token limits |
| `InferenceLatencySpike` | Context stuffing / generation exfiltration | Warning | Review input token counts; apply context window limits |

## Expected Behaviour

| Threat | Without inference observability | With inference observability |
|--------|---------------------------------|-----------------------------|
| Prompt injection via injection keywords | HTTP 200; application logic overridden silently | `structural_risk_score` alert within 5 min; prompt hash logged for investigation |
| Jailbreak iteration | Content filtered per-request; no trend visible | `InferenceContentPolicyViolationBurst` fires after 3 sustained minutes |
| Model extraction campaign | Indistinguishable from normal API use | Extraction detection job flags hash uniqueness + model diversity anomaly |
| API abuse / cost exhaustion | Rate limited; no security signal | `InferenceRateLimitAbuseSustained` fires after 5 min; user suspended |
| Sensitive data in prompts | Raw prompt stored in logs; PII exposure | Prompt hash logged; content never stored; correlation preserved |
| Base64-encoded injection | Evades keyword filters in naive systems | `has_base64_blob` + decoded content check flags structural anomaly |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Log prompt hash instead of content | No PII in observability infrastructure | Cannot reconstruct attack from logs alone | Retain ability to fetch original from source (e.g., message queue with short TTL) for active investigations under access control |
| Structural risk scoring | Detects injection patterns without content | False positives on legitimate prompts that contain quoted injection examples | Tune thresholds per application context; score is advisory, not blocking |
| Per-`user_id` Prometheus labels | Per-user abuse detection | High cardinality at scale | Aggregate by user tier or hash to bucket; use VictoriaMetrics for high-cardinality environments |
| Output classifier as security event source | Policy violations are observable trends | Classifier adds per-request latency | Deploy classifier as async post-processing for latency-sensitive paths; accept that blocking checks are synchronous |
| Extraction detection job (15 min interval) | Detects campaign patterns across requests | 15-minute detection lag | Reduce interval to 5 min for higher-risk deployments; accept higher Elasticsearch query load |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Security metadata not emitted (instrumentation gap) | All `injection_keyword_hits` are zero; alerts never fire | `llm_inference_requests_total` rising but `llm_inference_high_risk_prompts_total` flat | Audit instrumentation in inference middleware; add integration test that submits a known injection keyword and verifies it appears in logs |
| Classifier offline | Policy violations stop being recorded; `policy_violation` always false | `llm_inference_policy_violations_total` drops to zero during traffic | Health check on classifier endpoint; circuit breaker with fail-closed default (block generation if classifier unavailable) |
| Prometheus cardinality explosion on `user_id` | Prometheus OOM; scrape target down | Memory growth; Prometheus `up == 0` | Switch to `user_tier` label (bucketing users into tiers); use recording rules to pre-aggregate before storing |
| Extraction detection job produces false positives | Security team alert fatigue from API integration developers | High `llm_extraction_suspects_total` during onboarding | Add suppression for new API keys in their first 48 hours; require integration review before production key issuance |
| Redis unavailable for rate limit tracking | Rate limit event counts lost; abuse detection blind | `llm_inference_rate_limit_hits_total` counter flat despite visible rate limiting | Fall back to in-process counter with shorter window; alert on Redis unavailability separately |

## Related Articles

- [API Traffic Security Observability](/articles/observability/api-security-observability/)
- [OpenTelemetry PII Leakage Prevention](/articles/observability/otel-pii-leakage/)
- [Application Security Logging](/articles/observability/application-security-logging/)
- [Detection Rules: Alert Design for Security Events](/articles/observability/detection-rules/)
- [Detecting AI-Automated Container Escapes with Runtime Monitoring](/articles/observability/detecting-ai-automated-container-escapes/)
- [User Behavior Analytics](/articles/observability/user-behavior-analytics/)
