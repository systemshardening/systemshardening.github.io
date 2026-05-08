---
title: "Implementing AI Guardrails: Input Validation, Output Filtering, and Safety Classifiers in Production"
description: "Deploying an LLM without guardrails is deploying an application where any user can make it say or do anything."
slug: "ai-guardrails-implementation"
date: 2026-01-26
lastmod: 2026-01-26
category: "kubernetes"
tags: ["guardrails", "ai-safety", "input-validation", "output-filtering", "content-safety", "pii-detection"]
personas: ["ai-ml-engineer", "security-engineer", "sre"]
article_number: 131
difficulty: "advanced"
estimated_reading_time: 18
provider_bridges:
  - name: "Lakera"
    id: 142
    category: "llm-security"
  - name: "Cloudflare"
    id: 29
    category: "cdn-edge"
premium_pack: "guardrails-implementation-configs"
published: true
layout: article.njk
permalink: "/articles/kubernetes/ai-guardrails-implementation/index.html"
---

# Implementing AI Guardrails: Input Validation, Output Filtering, and Safety Classifiers in Production

## Problem

Deploying an LLM without guardrails is deploying an application where any user can make it say or do anything. Guardrails are the engineering controls that sit between users and the model: validating input before it reaches inference, filtering output before it reaches users, and classifying content for safety violations at both stages.

Most teams bolt guardrails on as an afterthought, a regex check here, a content filter there. This produces gaps. The input filter catches "how to hack" but not "explain the security testing methodology for unauthorized access." The output filter blocks profanity but misses a detailed social engineering script. The PII detector catches US Social Security numbers but not UK National Insurance numbers.

Production guardrails require a pipeline architecture: pre-processing, inference, post-processing, each stage with independent controls, each stage monitored independently.

## Threat Model

- **Adversary:** (1) Users attempting to misuse the model (jailbreaks, harmful content). (2) Attackers injecting malicious content through the application. (3) The model itself generating unsafe content without adversarial input (hallucination, off-topic responses, PII leakage).
- **Objective:** Generate harmful, biased, or policy-violating content. Extract PII from training data or context. Bypass topic restrictions. Exfiltrate data through model outputs.
- **Blast radius:** Regulatory penalties (PII exposure). Brand damage (harmful content). Liability (incorrect advice in regulated domains). Data breach (context exfiltration).

## Configuration

### Guardrails Pipeline Architecture

```python
# guardrails_pipeline.py - three-stage guardrails pipeline
from dataclasses import dataclass, field
from typing import List, Optional, Callable
import time

@dataclass
class GuardrailResult:
    passed: bool
    stage: str
    checks: List[dict] = field(default_factory=list)
    blocked_reason: Optional[str] = None
    latency_ms: float = 0.0

class GuardrailsPipeline:
    """
    Three-stage guardrails pipeline:
    1. Pre-processing: validate and sanitise input before inference
    2. Inference: the model call (not managed by guardrails)
    3. Post-processing: filter and validate output before returning to user
    """

    def __init__(self):
        self.pre_checks: List[Callable] = []
        self.post_checks: List[Callable] = []

    def add_pre_check(self, name: str, check_fn: Callable, blocking: bool = True):
        self.pre_checks.append({"name": name, "fn": check_fn, "blocking": blocking})

    def add_post_check(self, name: str, check_fn: Callable, blocking: bool = True):
        self.post_checks.append({"name": name, "fn": check_fn, "blocking": blocking})

    def run_pre_processing(self, user_input: str) -> GuardrailResult:
        start = time.time()
        checks = []

        for check in self.pre_checks:
            result = check["fn"](user_input)
            checks.append({"name": check["name"], "result": result})

            if not result.get("passed", True) and check["blocking"]:
                return GuardrailResult(
                    passed=False,
                    stage="pre-processing",
                    checks=checks,
                    blocked_reason=result.get("reason", check["name"]),
                    latency_ms=(time.time() - start) * 1000,
                )

        return GuardrailResult(
            passed=True,
            stage="pre-processing",
            checks=checks,
            latency_ms=(time.time() - start) * 1000,
        )

    def run_post_processing(self, model_output: str, user_input: str) -> GuardrailResult:
        start = time.time()
        checks = []

        for check in self.post_checks:
            result = check["fn"](model_output, user_input)
            checks.append({"name": check["name"], "result": result})

            if not result.get("passed", True) and check["blocking"]:
                return GuardrailResult(
                    passed=False,
                    stage="post-processing",
                    checks=checks,
                    blocked_reason=result.get("reason", check["name"]),
                    latency_ms=(time.time() - start) * 1000,
                )

        return GuardrailResult(
            passed=True,
            stage="post-processing",
            checks=checks,
            latency_ms=(time.time() - start) * 1000,
        )
```

### Content Safety Classifier

```python
# safety_classifier.py - content safety classification for input and output
from transformers import pipeline
from typing import Dict

class ContentSafetyClassifier:
    """
    Classify content for safety violations using a fine-tuned model.
    Categories: harassment, hate_speech, self_harm, sexual_content,
    violence, dangerous_content, regulated_advice.
    """

    def __init__(self, model_name: str = "models/content-safety-classifier"):
        self.classifier = pipeline(
            "text-classification",
            model=model_name,
            top_k=None,  # return all labels with scores
            truncation=True,
            max_length=512,
        )
        self.thresholds = {
            "harassment": 0.7,
            "hate_speech": 0.7,
            "self_harm": 0.5,       # lower threshold for safety-critical
            "sexual_content": 0.7,
            "violence": 0.7,
            "dangerous_content": 0.6,
            "regulated_advice": 0.6,
        }

    def classify(self, text: str) -> Dict:
        results = self.classifier(text)[0]
        scores = {r["label"]: r["score"] for r in results}

        violations = []
        for category, threshold in self.thresholds.items():
            if scores.get(category, 0) > threshold:
                violations.append({
                    "category": category,
                    "score": round(scores[category], 4),
                    "threshold": threshold,
                })

        return {
            "passed": len(violations) == 0,
            "violations": violations,
            "scores": {k: round(v, 4) for k, v in scores.items()},
            "reason": f"safety_violation: {violations[0]['category']}" if violations else None,
        }
```

### PII Detection and Redaction

```python
# pii_guardrail.py - detect and redact PII in both input and output
import re
from typing import Dict, List, Tuple

class PIIGuardrail:
    """
    Detect and redact personally identifiable information.
    Runs on both input (prevent PII from reaching the model)
    and output (prevent PII from reaching the user).
    """

    PII_PATTERNS = {
        "email": (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "[EMAIL]"),
        "phone_us": (r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "[PHONE]"),
        "phone_uk": (r"\b(?:\+44[-.\s]?|0)(?:\d[-.\s]?){9,10}\b", "[PHONE]"),
        "ssn": (r"\b\d{3}-\d{2}-\d{4}\b", "[SSN]"),
        "nino": (r"\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b", "[NINO]"),
        "credit_card": (r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", "[CARD]"),
        "ipv4": (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "[IP]"),
        "date_of_birth": (r"\b(?:0[1-9]|[12]\d|3[01])[/-](?:0[1-9]|1[0-2])[/-]\d{4}\b", "[DOB]"),
    }

    def detect(self, text: str) -> List[dict]:
        findings = []
        for pii_type, (pattern, _) in self.PII_PATTERNS.items():
            matches = re.findall(pattern, text)
            if matches:
                findings.append({"type": pii_type, "count": len(matches)})
        return findings

    def redact(self, text: str) -> Tuple[str, List[dict]]:
        findings = self.detect(text)
        redacted = text
        for pii_type, (pattern, replacement) in self.PII_PATTERNS.items():
            redacted = re.sub(pattern, replacement, redacted)
        return redacted, findings

    def check_input(self, text: str) -> dict:
        findings = self.detect(text)
        return {
            "passed": len(findings) == 0,
            "pii_found": findings,
            "reason": f"pii_in_input: {findings[0]['type']}" if findings else None,
        }

    def check_output(self, output: str, user_input: str) -> dict:
        redacted, findings = self.redact(output)
        return {
            "passed": len(findings) == 0,
            "pii_found": findings,
            "redacted_output": redacted,
            "reason": f"pii_in_output: {findings[0]['type']}" if findings else None,
        }
```

### Topic Restriction Enforcement

```python
# topic_restrictor.py - enforce topic boundaries for the LLM
from transformers import pipeline

class TopicRestrictor:
    """
    Restrict LLM responses to approved topics.
    Uses zero-shot classification to determine if input/output
    falls within allowed topic boundaries.
    """

    def __init__(
        self,
        allowed_topics: list,
        blocked_topics: list,
        model_name: str = "facebook/bart-large-mnli",
    ):
        self.allowed_topics = allowed_topics
        self.blocked_topics = blocked_topics
        self.classifier = pipeline(
            "zero-shot-classification",
            model=model_name,
        )
        self.allowed_threshold = 0.4
        self.blocked_threshold = 0.6

    def check(self, text: str) -> dict:
        # Check blocked topics first
        if self.blocked_topics:
            blocked_result = self.classifier(text, self.blocked_topics)
            top_blocked = blocked_result["labels"][0]
            top_blocked_score = blocked_result["scores"][0]

            if top_blocked_score > self.blocked_threshold:
                return {
                    "passed": False,
                    "reason": f"blocked_topic: {top_blocked} (score: {top_blocked_score:.2f})",
                    "blocked_topic": top_blocked,
                    "score": round(top_blocked_score, 4),
                }

        # Check allowed topics
        allowed_result = self.classifier(text, self.allowed_topics)
        top_allowed = allowed_result["labels"][0]
        top_allowed_score = allowed_result["scores"][0]

        if top_allowed_score < self.allowed_threshold:
            return {
                "passed": False,
                "reason": f"off_topic: best match '{top_allowed}' scored {top_allowed_score:.2f}",
                "best_topic": top_allowed,
                "score": round(top_allowed_score, 4),
            }

        return {
            "passed": True,
            "matched_topic": top_allowed,
            "score": round(top_allowed_score, 4),
        }
```

### [Kubernetes](https://kubernetes.io) Deployment with Latency-Aware Architecture

```yaml
# guardrails-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: guardrails-service
  namespace: ai-services
spec:
  replicas: 3
  selector:
    matchLabels:
      app: guardrails-service
  template:
    metadata:
      labels:
        app: guardrails-service
    spec:
      containers:
        # Fast checks (pattern matching, PII regex) - runs synchronously
        - name: fast-guardrails
          image: internal-registry/guardrails-fast:2.0.0
          ports:
            - containerPort: 8080
          env:
            - name: CHECKS
              value: "pii,injection_patterns,length_limit"
            - name: TIMEOUT_MS
              value: "50"
          resources:
            requests:
              cpu: 200m
              memory: 256Mi
            limits:
              cpu: 500m
              memory: 512Mi
        # Slow checks (ML classifiers) - runs asynchronously where possible
        - name: ml-guardrails
          image: internal-registry/guardrails-ml:2.0.0
          ports:
            - containerPort: 8081
          env:
            - name: CHECKS
              value: "safety_classifier,topic_restriction,jailbreak_classifier"
            - name: TIMEOUT_MS
              value: "500"
            - name: ASYNC_MODE
              value: "true"
          resources:
            requests:
              cpu: "1"
              memory: 2Gi
            limits:
              cpu: "2"
              memory: 4Gi
          volumeMounts:
            - name: models
              mountPath: /models
              readOnly: true
      volumes:
        - name: models
          persistentVolumeClaim:
            claimName: guardrails-models-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: guardrails-service
  namespace: ai-services
spec:
  selector:
    app: guardrails-service
  ports:
    - name: fast
      port: 8080
      targetPort: 8080
    - name: ml
      port: 8081
      targetPort: 8081
```

### [Prometheus](https://prometheus.io) Monitoring

```yaml
# prometheus-guardrails.yaml
groups:
  - name: guardrails
    interval: 1m
    rules:
      - alert: GuardrailBlockRate
        expr: >
          rate(guardrail_blocked_total[5m])
          / rate(guardrail_requests_total[5m]) > 0.2
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: ">20% of requests blocked by guardrails"
          description: "Check guardrail_blocked_total by reason label for breakdown."

      - alert: GuardrailLatencyHigh
        expr: >
          histogram_quantile(0.99, rate(guardrail_duration_seconds_bucket{stage="pre-processing"}[5m])) > 0.2
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Pre-processing guardrail P99 latency exceeds 200ms"

      - alert: PIILeakage
        expr: increase(guardrail_pii_detected_total{stage="output"}[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "PII detected in model output"
          description: "PII was found in model output and redacted. Investigate the source."

      - alert: SafetyViolation
        expr: increase(guardrail_safety_violation_total{stage="output"}[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "Safety violation detected in model output"
```

## Expected Behaviour

- Fast guardrails (pattern matching, PII regex) complete within 5-50ms
- ML-based guardrails (safety classifier, topic restriction) complete within 100-500ms
- PII detected in input is logged and optionally redacted before reaching the model
- PII detected in output is always redacted before reaching the user
- Safety violations in output trigger blocking and alerting
- Off-topic queries are rejected with a helpful redirect message
- Block rate above 20% triggers investigation (may indicate overly aggressive rules or an attack)

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Synchronous ML guardrails | Adds 100-500ms to every request | User-facing latency exceeds SLA | Run ML checks asynchronously. Block only on fast checks; flag on slow checks. |
| PII redaction on input | Removes PII before model sees it | Model cannot reference user-provided PII even when legitimate (e.g., "what does my email john@example.com do?") | Allow PII passthrough for authenticated, consented use cases. Redact by default. |
| Topic restriction | Keeps model on-topic | Legitimate edge-case queries are rejected | Tune allowed topics broadly. Log rejected queries for periodic review and topic expansion. |
| Safety classifier threshold 0.5 for self-harm | Very aggressive blocking for self-harm content | False positives on mental health support queries | Route self-harm detections to human review rather than hard blocking. Provide crisis resources. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| ML guardrail service down | All requests pass without ML-level checking | Health check failures; guardrail check count drops to zero | Fast guardrails continue operating. Alert on ML guardrail downtime. Queue requests for retroactive scanning. |
| PII regex too broad | Legitimate numbers (order IDs, dates) redacted | User reports; redaction rate spikes for specific PII types | Refine regex patterns. Add context-aware rules (only flag numbers in certain positions). |
| Topic classifier drift | Allowed topics score too low; everything rejected | Block rate climbs over time without changes to traffic | Retrain or recalibrate topic classifier. Update allowed topic list. |
| Safety classifier false negative | Harmful content passes all checks | User report; external disclosure; output monitoring on historical data | Add the missed content pattern to the training set. Retrain classifier. Tighten output monitoring. |

## When to Consider a Managed Alternative

Building and maintaining a full guardrails pipeline (pattern matching, PII detection, safety classification, topic restriction, monitoring) is significant engineering investment. Model retraining, pattern updates, and threshold tuning are ongoing.

- **[Lakera](https://www.lakera.ai):** Managed guardrails API with input/output filtering, jailbreak detection, PII detection, and content safety. Sub-50ms latency. Continuously updated models.
- **[Cloudflare](https://www.cloudflare.com) AI Gateway:** Edge-level guardrails for AI endpoints. Content filtering, rate limiting, and observability.

**Premium content pack:** Guardrails implementation pack. Three-stage pipeline framework (Python), content safety classifier training pipeline, PII detection library with international patterns, topic restriction configuration, Kubernetes deployment manifests, and Prometheus monitoring rules.


## Related Articles

- [Prompt Injection Defence in Production: Input Validation, Output Filtering, and Monitoring](/articles/kubernetes/prompt-injection/)
- [AI Data Leakage Prevention: Input Filtering, Output Scanning, and Audit Trails](/articles/kubernetes/ai-data-leakage-prevention/)
- [Hardening Model Inference Endpoints: Authentication, Rate Limiting, and Input Validation](/articles/kubernetes/inference-endpoint-hardening/)
- [Hardening Kubernetes Ingress Controllers: NGINX, Traefik, and Envoy Compared](/articles/kubernetes/ingress-controller-comparison/)
- [Hardening Model Serving Frameworks: TorchServe, Triton, and vLLM Security Configuration](/articles/kubernetes/model-serving-hardening/)
