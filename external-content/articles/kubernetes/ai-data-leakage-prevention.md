---
title: "AI Data Leakage Prevention: Input Filtering, Output Scanning, and Audit Trails"
description: "AI systems leak data in ways traditional applications do not. A language model trained on customer data can reproduce verbatim customer records in..."
slug: "ai-data-leakage-prevention"
date: 2026-03-08
lastmod: 2026-03-08
category: "kubernetes"
tags: ["ai", "data-leakage", "pii", "compliance", "output-filtering", "audit"]
personas: ["ai-ml-engineer", "platform-engineer", "security-engineer"]
article_number: 87
difficulty: "advanced"
estimated_reading_time: 16
provider_bridges:
  - name: "Axiom"
    id: 112
    category: "observability"
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
  - name: "Lakera"
    id: 142
    category: "ai-security"
premium_pack: "data-leakage-prevention-policy-pack"
published: true
layout: article.njk
permalink: "/articles/kubernetes/ai-data-leakage-prevention/index.html"
---

# AI Data Leakage Prevention: Input Filtering, Output Scanning, and Audit Trails

## Problem

AI systems leak data in ways traditional applications do not. A language model trained on customer data can reproduce verbatim customer records in its outputs. An embedding API returns vector representations that can be used to reconstruct the original input text. A fine-tuned model carries training data in its weights, accessible through carefully crafted prompts.

The leakage vectors are:

- **Model outputs:** The model generates text containing PII, credentials, or proprietary data from its training set or context window.
- **Memorised training data:** Models memorise and regurgitate training data, especially data that appears multiple times in the training set.
- **Embedding reconstruction:** Embedding vectors can be inverted to approximate the original text. Sending embeddings to third parties is not anonymisation.
- **Prompt injection:** An attacker crafts input that causes the model to reveal its system prompt, context data, or other users' conversation history.

Compliance frameworks (GDPR, HIPAA) require provable data controls. "The model might output PII" is not an acceptable risk posture for regulated industries.

**Target systems:** AI inference APIs (self-hosted or third-party). RAG (Retrieval-Augmented Generation) pipelines. Fine-tuned models with proprietary data. Any system where user inputs are processed by a language model.

## Threat Model

- **Adversary:** External user interacting with the AI system through its public API, or an internal user with access to model outputs. Also: compliance auditor reviewing data handling practices.
- **Objective:** Extract PII, proprietary data, or credentials from model outputs. Reconstruct training data. Bypass output filters to access restricted information.
- **Blast radius:** A single unfiltered response containing PII can trigger a GDPR breach notification (72-hour deadline). Systematic extraction of training data through prompt injection can expose the entire training dataset. Leaked credentials in model outputs provide direct access to infrastructure.

## Configuration

### PII Detection in Model Outputs

Build a filtering layer that scans every model response before it reaches the user.

```python
# pii_scanner.py
# Runs as a sidecar or middleware in the inference pipeline
import re
from typing import List, Tuple

PII_PATTERNS = {
    "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
    "ssn": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    "credit_card": re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
    "phone_us": re.compile(r'\b(?:\+1[-\s]?)?\(?\d{3}\)?[-\s]?\d{3}[-\s]?\d{4}\b'),
    "ip_address": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "aws_key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "api_key_generic": re.compile(r'(?:sk|pk|api)[_-][a-zA-Z0-9]{20,}'),
    "uk_nino": re.compile(r'\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b'),
    "iban": re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b'),
}

def scan_for_pii(text: str) -> List[Tuple[str, str, int, int]]:
    """Return list of (pii_type, matched_text, start, end) tuples."""
    findings = []
    for pii_type, pattern in PII_PATTERNS.items():
        for match in pattern.finditer(text):
            findings.append((pii_type, match.group(), match.start(), match.end()))
    return findings

def redact_pii(text: str) -> Tuple[str, List[Tuple[str, str]]]:
    """Redact PII from text. Return (redacted_text, list of redactions)."""
    findings = scan_for_pii(text)
    redacted = text
    redactions = []
    # Process in reverse order to preserve positions
    for pii_type, matched, start, end in sorted(findings, key=lambda x: x[2], reverse=True):
        placeholder = f"[REDACTED_{pii_type.upper()}]"
        redacted = redacted[:start] + placeholder + redacted[end:]
        redactions.append((pii_type, matched))
    return redacted, redactions
```

### Output Filtering Middleware

```python
# output_filter.py
# FastAPI middleware that wraps the inference endpoint
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
import json
import logging
import time
from pii_scanner import scan_for_pii, redact_pii

app = FastAPI()
audit_logger = logging.getLogger("audit")

@app.middleware("http")
async def filter_outputs(request: Request, call_next):
    # Capture the request body for audit logging
    body = await request.body()
    request_data = json.loads(body) if body else {}

    start_time = time.time()
    response = await call_next(request)

    # Read response body
    response_body = b""
    async for chunk in response.body_iterator:
        response_body += chunk

    response_text = response_body.decode()
    response_data = json.loads(response_text)

    # Scan model output for PII
    model_output = response_data.get("choices", [{}])[0].get("message", {}).get("content", "")
    pii_findings = scan_for_pii(model_output)

    if pii_findings:
        # Redact PII before sending to user
        redacted_output, redactions = redact_pii(model_output)
        response_data["choices"][0]["message"]["content"] = redacted_output
        response_data["pii_redacted"] = True

        # Log the redaction event (not the PII itself)
        audit_logger.warning(json.dumps({
            "event": "pii_redacted",
            "timestamp": time.time(),
            "request_id": request.headers.get("x-request-id"),
            "pii_types": [r[0] for r in redactions],
            "count": len(redactions),
            "model": request_data.get("model"),
            "user": request.headers.get("x-user-id"),
        }))

    # Always log request/response metadata for audit trail
    audit_logger.info(json.dumps({
        "event": "inference_request",
        "timestamp": time.time(),
        "request_id": request.headers.get("x-request-id"),
        "model": request_data.get("model"),
        "user": request.headers.get("x-user-id"),
        "input_tokens": len(request_data.get("messages", [{}])[-1].get("content", "").split()),
        "output_tokens": len(model_output.split()),
        "latency_ms": (time.time() - start_time) * 1000,
        "pii_detected": len(pii_findings) > 0,
    }))

    return Response(
        content=json.dumps(response_data),
        status_code=response.status_code,
        headers=dict(response.headers),
        media_type="application/json",
    )
```

### Network Egress Restrictions for Inference Services

Prevent inference services from making outbound calls to unauthorised destinations.

```yaml
# inference-egress-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: inference-egress-restrict
  namespace: ml-serving
spec:
  podSelector:
    matchLabels:
      workload-type: inference
  policyTypes:
    - Egress
  egress:
    # DNS only
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
    # Model storage (read-only)
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: storage
      ports:
        - protocol: TCP
          port: 9000
    # Metrics export
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
      ports:
        - protocol: TCP
          port: 9090
    # No general internet access.
    # If the model needs to call external APIs (RAG, tool use),
    # add specific FQDN-based rules with Cilium.
```

### Complete Audit Trail with [OpenTelemetry](https://opentelemetry.io)

```yaml
# otel-collector-config.yaml
# Capture all inference requests and responses for audit
apiVersion: v1
kind: ConfigMap
metadata:
  name: otel-collector-config
  namespace: ml-serving
data:
  config.yaml: |
    receivers:
      otlp:
        protocols:
          grpc:
            endpoint: 0.0.0.0:4317
          http:
            endpoint: 0.0.0.0:4318

    processors:
      batch:
        timeout: 5s
        send_batch_size: 100

      # Remove actual PII from audit logs
      # Log metadata only (token counts, PII detection flag, latency)
      attributes:
        actions:
          - key: "input.text"
            action: delete
          - key: "output.text"
            action: delete

    exporters:
      otlphttp:
        endpoint: "https://otel.example.com:4318"
        headers:
          Authorization: "Bearer ${OTEL_AUTH_TOKEN}"

    service:
      pipelines:
        traces:
          receivers: [otlp]
          processors: [batch, attributes]
          exporters: [otlphttp]
        logs:
          receivers: [otlp]
          processors: [batch]
          exporters: [otlphttp]
```

### Input Classification Pipeline

Classify inputs before they reach the model to detect prompt injection and data extraction attempts.

```python
# input_classifier.py
import re
from enum import Enum

class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    BLOCKED = "blocked"

# Patterns that suggest prompt injection or data extraction
INJECTION_PATTERNS = [
    re.compile(r'ignore\s+(previous|above|all)\s+(instructions|prompts)', re.I),
    re.compile(r'(system\s+prompt|initial\s+instructions|hidden\s+instructions)', re.I),
    re.compile(r'repeat\s+(everything|all|back)\s+(above|before|you\s+know)', re.I),
    re.compile(r'(output|print|show|reveal)\s+(your|the)\s+(instructions|prompt|context)', re.I),
    re.compile(r'you\s+are\s+now\s+(DAN|unrestricted|jailbroken)', re.I),
]

DATA_EXTRACTION_PATTERNS = [
    re.compile(r'(list|show|give)\s+(all|every)\s+(customer|user|patient|record)', re.I),
    re.compile(r'(dump|export|extract)\s+(database|table|records)', re.I),
    re.compile(r'what\s+(personal|private)\s+(data|information)\s+do\s+you\s+(have|know)', re.I),
]

def classify_input(text: str) -> RiskLevel:
    """Classify input risk level based on pattern matching."""
    for pattern in INJECTION_PATTERNS:
        if pattern.search(text):
            return RiskLevel.BLOCKED

    for pattern in DATA_EXTRACTION_PATTERNS:
        if pattern.search(text):
            return RiskLevel.HIGH

    # Check for excessive special characters (potential encoding attacks)
    special_ratio = sum(1 for c in text if not c.isalnum() and not c.isspace()) / max(len(text), 1)
    if special_ratio > 0.3:
        return RiskLevel.MEDIUM

    return RiskLevel.LOW
```

## Expected Behaviour

- Every model response is scanned for PII patterns before reaching the user
- Detected PII is redacted and replaced with type-specific placeholders
- All redaction events are logged with PII type counts (never the PII itself)
- Prompt injection attempts are blocked at the input classification layer
- Inference services have no outbound internet access (preventing exfiltration through model-initiated requests)
- Complete audit trail captures request metadata, token counts, latency, and PII detection flags
- Audit logs retain for the compliance-required period (GDPR: demonstrate compliance, HIPAA: 6 years)

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| Regex-based PII detection | Fast (sub-millisecond), no external dependencies | Misses PII in non-standard formats; false positives on data that resembles PII | Layer regex with NER (Named Entity Recognition) model for higher accuracy. Start with regex, add NER when false positive rate is measured. |
| Redaction (not blocking) | Users still get useful responses with PII removed | Redaction may break response coherence | If coherence matters more than data exposure risk, log and alert instead of redacting. For regulated data, always redact. |
| Full request/response audit logging | Complete forensic trail for compliance | Storage costs; privacy risk if audit logs themselves contain PII | Strip actual text from audit logs (keep metadata only). Store full text in a separate, access-controlled audit store with short retention. |
| Input classification blocking | Prevents prompt injection at the boundary | False positives block legitimate queries that happen to match patterns | Start in log-only mode. Review blocked queries weekly. Tune patterns to reduce false positives before switching to block mode. |
| Network egress deny | Prevents model from exfiltrating data through outbound requests | Blocks legitimate tool-use and RAG retrieval | Add specific egress rules for approved external endpoints. Use FQDN-based policies (Cilium) for precise control. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| PII scanner bypass (novel PII format) | PII appears in model output unredacted | Periodic manual review of sampled outputs; user reports PII in response | Add new pattern to PII scanner. Review and redact affected audit logs. Notify affected data subjects if required by GDPR. |
| False positive redaction | Legitimate data (e.g., example phone number in documentation) is redacted | User reports unexpected redaction; high redaction rate in metrics | Add allowlist for known safe patterns (example data, test values). Tune regex specificity. |
| Audit log pipeline failure | Gap in audit trail; compliance violation | OTel collector health check; log volume drops to zero | Buffer logs locally (OTel collector persistent queue). Replay buffered logs when pipeline recovers. |
| Input classifier blocks legitimate query | User receives "request blocked" for a normal question | Blocked request count spikes; user complaints | Review blocked query log. Add exception for the false-positive pattern. Switch to log-only mode if block rate exceeds 1%. |
| Model memorisation not caught by output scanner | Model regurgitates training data that does not match PII patterns (e.g., proprietary code, internal documents) | Canary queries detect memorisation; manual output review | Add content-specific patterns for proprietary data. Retrain model with deduplication and differential privacy. |

## When to Consider a Managed Alternative

[Lakera](https://www.lakera.ai) for managed AI output filtering with continuously updated detection models covering PII, prompt injection, and toxicity. [Axiom](https://axiom.co) for high-volume inference audit log storage with fast querying. [Grafana Cloud](https://grafana.com/cloud) for monitoring PII detection rates and audit pipeline health. [Sysdig](https://sysdig.com) and [Aqua](https://www.aquasec.com) for compliance reporting that includes AI workload data handling.

**Premium content pack:** Data leakage prevention policy pack. PII regex patterns for US, EU, and UK data types. [OPA](https://www.openpolicyagent.org) egress policies for inference namespaces. OpenTelemetry logging templates for inference audit trails. Input classification rules for prompt injection detection.


## Related Articles

- [Kubernetes Audit Log Analysis: What to Log, How to Query, and What to Alert On](/articles/kubernetes/audit-log-analysis/)
- [Observability for LLM Applications: Token Usage, Latency Anomalies, and Output Classification](/articles/kubernetes/llm-observability/)
- [Hardening Model Inference Endpoints: Authentication, Rate Limiting, and Input Validation](/articles/kubernetes/inference-endpoint-hardening/)
- [Network Segmentation for AI Training Infrastructure](/articles/kubernetes/ai-training-network-segmentation/)
- [Prompt Injection Defence in Production: Input Validation, Output Filtering, and Monitoring](/articles/kubernetes/prompt-injection/)
