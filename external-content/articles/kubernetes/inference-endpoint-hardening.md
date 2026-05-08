---
title: "Hardening Model Inference Endpoints: Authentication, Rate Limiting, and Input Validation"
description: "Model inference endpoints are GPU-backed and expensive, $2-30 per hour per GPU. A single unprotected endpoint exposed to the internet can accumulate.."
slug: "inference-endpoint-hardening"
date: 2026-03-18
lastmod: 2026-03-18
category: "kubernetes"
tags: ["ai", "inference", "rate-limiting", "authentication", "prompt-injection", "gpu"]
personas: ["ai-ml-engineer", "security-engineer"]
article_number: 76
difficulty: "intermediate"
estimated_reading_time: 16
provider_bridges:
  - name: "Cloudflare"
    id: 29
    category: "cdn-edge"
  - name: "Lakera"
    id: 142
    category: "llm-security"
  - name: "Kong"
    id: 86
    category: "api-gateways"
premium_pack: "inference-security-configs"
published: true
layout: article.njk
permalink: "/articles/kubernetes/inference-endpoint-hardening/index.html"
---

# Hardening Model Inference Endpoints: Authentication, Rate Limiting, and Input Validation

## Problem

Model inference endpoints are GPU-backed and expensive, $2-30 per hour per GPU. A single unprotected endpoint exposed to the internet can accumulate thousands of dollars in compute costs within hours from abuse, intentional or accidental. Most model serving frameworks (TorchServe, Triton, vLLM) ship with management APIs exposed without authentication, no rate limiting, and no input validation. An attacker can exfiltrate data through carefully crafted prompts, exhaust GPU resources through oversized inputs, or abuse the model for purposes it was not intended for.

**Target systems:** Any model inference endpoint running on [Kubernetes](https://kubernetes.io). Specific configurations for [NGINX](https://nginx.org) ingress, [Kong](https://konghq.com) gateway, and direct integration patterns.

## Threat Model

- **Adversary:** Unauthenticated user or compromised API key holder accessing the inference endpoint over HTTPS.
- **Objective:** Cost exhaustion (flood endpoint with large requests, consuming GPU hours). Data exfiltration (prompt injection to extract training data or system prompts). Model abuse (use the model for unintended purposes, generating harmful content, automated spam, etc.).
- **Blast radius:** GPU cost spike (financial). Data leakage (confidentiality). Model reputation damage (safety).

## Configuration

### API Key Authentication at the Gateway

Do not rely on the model serving framework for authentication. Place authentication at the API gateway or ingress layer:

```yaml
# kong-inference-auth.yaml - Kong gateway with API key auth
apiVersion: configuration.konghq.com/v1
kind: KongPlugin
metadata:
  name: inference-key-auth
spec:
  plugin: key-auth
  config:
    key_names: ["X-API-Key"]
    hide_credentials: true
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: inference-api
  annotations:
    konghq.com/plugins: inference-key-auth
spec:
  ingressClassName: kong
  rules:
    - host: inference.example.com
      http:
        paths:
          - path: /v1
            pathType: Prefix
            backend:
              service:
                name: inference-service
                port:
                  number: 8080
```

For NGINX ingress without an API gateway:

```nginx
# nginx-inference-auth.conf
# Simple API key validation at the NGINX level.
map $http_x_api_key $api_key_valid {
    default 0;
    "sk-production-abc123def456" 1;
    "sk-staging-xyz789ghi012" 1;
}

server {
    listen 443 ssl;
    server_name inference.example.com;

    # Reject requests without a valid API key
    if ($api_key_valid = 0) {
        return 401 '{"error": "Invalid or missing API key"}';
    }

    location /v1/ {
        proxy_pass http://inference-service:8080;
    }
}
```

### GPU-Aware Rate Limiting

Standard rate limiting (requests per second) does not capture the real cost of inference requests. A single request with a 10,000-token input costs 100x more GPU time than a 100-token request. Rate limit by both request count AND token/input size:

```nginx
# Rate limit by request count (baseline protection)
limit_req_zone $http_x_api_key zone=inference_rate:10m rate=10r/s;

# Rate limit by request body size (proxy for token count)
# Large request bodies → large token inputs → more GPU time
limit_req_zone $http_x_api_key zone=inference_size:10m rate=2r/s;

location /v1/completions {
    # Standard rate limit
    limit_req zone=inference_rate burst=20 nodelay;

    # Strict limit for large requests (>10KB body ≈ >2000 tokens)
    limit_req zone=inference_size burst=5 nodelay;

    # Hard limit on request body size
    client_max_body_size 100k;  # ~25,000 tokens max

    proxy_pass http://inference-service:8080;
}
```

For edge-level rate limiting before traffic reaches GPU infrastructure:

```
# Cloudflare (#29) rate limiting rule (via dashboard or API):
# - Match: hostname = inference.example.com AND path begins with /v1/
# - Rate: 100 requests per minute per API key
# - Action: Block (return 429)
#
# This absorbs abuse at the edge before it consumes GPU resources.
```

### Input Validation

```python
# input_validator.py - middleware for inference endpoints
# Validate and sanitise inputs before they reach the model.

import re
from fastapi import Request, HTTPException

MAX_INPUT_LENGTH = 25000  # characters (~6000 tokens)
MAX_TOKENS_REQUESTED = 4096

async def validate_inference_input(request: Request):
    body = await request.json()

    # 1. Input length limit
    prompt = body.get("prompt", "") or body.get("messages", [{}])[-1].get("content", "")
    if len(prompt) > MAX_INPUT_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Input exceeds maximum length of {MAX_INPUT_LENGTH} characters"
        )

    # 2. Max tokens limit
    max_tokens = body.get("max_tokens", 0)
    if max_tokens > MAX_TOKENS_REQUESTED:
        raise HTTPException(
            status_code=400,
            detail=f"max_tokens exceeds limit of {MAX_TOKENS_REQUESTED}"
        )

    # 3. Basic prompt injection detection (pattern-based)
    # This catches obvious injection attempts. For production,
    # use Lakera (#142) for ML-based detection.
    injection_patterns = [
        r"ignore (previous|all|above) instructions",
        r"you are now",
        r"disregard (your|the) (instructions|system prompt)",
        r"repeat (your|the) system (prompt|message|instructions)",
        r"what (is|are) your (instructions|system prompt|rules)",
    ]
    for pattern in injection_patterns:
        if re.search(pattern, prompt, re.IGNORECASE):
            # Log the attempt but don't reveal the detection
            # (attacker would adapt their technique)
            raise HTTPException(status_code=400, detail="Invalid input")

    return body
```

### Output Filtering

```python
# output_filter.py - filter model outputs for sensitive data leakage

import re

# PII patterns (basic - use a dedicated NLP model for production)
PII_PATTERNS = {
    "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
    "credit_card": r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
    "api_key": r'\b(sk|pk|api[_-]?key)[_-][a-zA-Z0-9]{20,}\b',
}

def filter_output(text: str) -> str:
    """Redact PII from model output before returning to the client."""
    for pii_type, pattern in PII_PATTERNS.items():
        matches = re.findall(pattern, text)
        for match in matches:
            text = text.replace(match, f"[REDACTED:{pii_type}]")
            # Log the redaction for audit
            log_redaction(pii_type, len(matches))
    return text
```

### Observability for Inference Security

```yaml
# Prometheus metrics for inference endpoint monitoring
# Instrument the inference service or gateway to export these:

# Token usage per API key (cost tracking)
# inference_tokens_total{api_key="sk-xxx", type="prompt|completion"}

# Request latency by API key (detect abuse - automated requests are faster)
# inference_request_duration_seconds{api_key="sk-xxx"}

# Input validation rejections
# inference_input_rejected_total{reason="too_long|injection_detected|invalid_format"}

# Output redactions
# inference_output_redacted_total{pii_type="email|ssn|api_key"}
```

```yaml
# Alert: cost spike per API key
groups:
  - name: inference-security
    rules:
      - alert: InferenceCostSpike
        expr: >
          sum by (api_key) (rate(inference_tokens_total{type="completion"}[1h]))
          > 5 * avg_over_time(sum by (api_key) (rate(inference_tokens_total{type="completion"}[1h]))[7d:1h])
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "API key {{ $labels.api_key }} token usage 5x above baseline"

      - alert: PromptInjectionSpike
        expr: rate(inference_input_rejected_total{reason="injection_detected"}[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Elevated prompt injection attempts: {{ $value | humanize }}/sec"
```

### Network Isolation

```yaml
# Inference service should only be reachable from the API gateway.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: inference-ingress
  namespace: ai-inference
spec:
  podSelector:
    matchLabels:
      app: inference-service
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kong-system
      ports:
        - port: 8080
          protocol: TCP
```

## Expected Behaviour

- All inference requests authenticated via API key at the gateway layer
- Rate limiting blocks >100 requests/minute per API key at the edge (Cloudflare #29)
- Input length capped at 25,000 characters; max_tokens capped at 4,096
- Obvious prompt injection patterns rejected with 400 (without revealing detection logic)
- PII in model outputs redacted before returning to client
- Token usage per API key tracked; cost spike alerts fire within 15 minutes
- Inference service only reachable from the API gateway (network policy enforced)

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| API key auth at gateway | Adds 1-5ms latency per request | Gateway becomes a single point of failure | Run gateway in HA (3+ replicas). |
| Input length limit (25K chars) | Blocks legitimate long-context use cases | Some users may need longer inputs | Offer a higher tier with longer limits (paid plan, higher rate). |
| Prompt injection pattern matching | Blocks obvious injections | Sophisticated injections bypass regex patterns | Supplement with [Lakera](https://www.lakera.ai) ML-based detection for production. Pattern matching is a first layer, not the only layer. |
| Output PII filtering | Redacts sensitive data | False positives: redacts strings that look like PII but aren't | Review redaction logs weekly. Tune patterns. For regulated industries: use a dedicated PII detection model. |
| GPU-aware rate limiting | Prevents cost exhaustion | Legitimate batch users may hit limits | Per-key rate tiers. Exempt internal service accounts with higher limits. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| API key leaked | Unauthorized usage of the inference endpoint | Cost spike alert; usage from unexpected IPs | Revoke the key immediately. Issue a new key. Audit usage during the exposure window. |
| Rate limit too aggressive | Legitimate users get 429 errors | User reports; 429 rate metric increases for known-good keys | Increase per-key rate limit. Or: move user to a higher tier. |
| Prompt injection bypasses detection | Attacker extracts system prompt or training data | Output monitoring detects unexpected content (system prompt text in response) | Add the bypass technique to the pattern list. Implement [Lakera](https://www.lakera.ai) for ML-based detection. |
| Input validator crashes | All requests fail with 500 | Error rate metric spikes; all inference requests return 500 | Fail-open or fail-closed: decide your policy. For safety-critical: fail-closed (reject all). For availability-critical: fail-open (allow through without validation). |

## When to Consider a Managed Alternative

- **[Cloudflare](https://www.cloudflare.com):** Edge rate limiting before traffic reaches GPU infrastructure. Bot detection. API Shield for endpoint-specific security.
- **[Lakera](https://www.lakera.ai):** Managed prompt injection detection API. ML-based, not pattern-based. Real-time classification.
- **[Kong](https://konghq.com) Enterprise:** Per-key rate limiting, analytics, and access control. Managed Konnect platform.

**Premium content pack:** Inference endpoint security configuration pack. NGINX rate limiting configs, Kong gateway setup, input validation middleware (Python, Go, Node), output PII filtering, Prometheus alert rules for cost and injection monitoring, and Kubernetes network policies for inference namespace isolation.


## Related Articles

- [Prompt Injection Defence in Production: Input Validation, Output Filtering, and Monitoring](/articles/kubernetes/prompt-injection/)
- [GPU Workload Isolation: MIG, MPS, and vGPU Security Boundaries](/articles/kubernetes/gpu-isolation/)
- [Network Segmentation for AI Training Infrastructure](/articles/kubernetes/ai-training-network-segmentation/)
- [Jupyter Notebook Security: Authentication, Isolation, and Data Protection](/articles/kubernetes/jupyter-notebook-security/)
- [AI API Key Management: Rotation, Scoping, and Abuse Detection](/articles/kubernetes/ai-api-key-management/)
