---
title: "Training Data Extraction Prevention: Stopping Models from Leaking Memorised Data"
description: "Large language models memorise portions of their training data. Given the right prompt, a model will reproduce training examples verbatim, including.."
slug: "training-data-extraction"
date: 2026-04-16
lastmod: 2026-04-16
category: "ai-landscape"
tags: ["training-data", "data-extraction", "memorisation", "differential-privacy", "canary-tokens", "llm-security"]
personas: ["ai-ml-engineer", "security-engineer"]
article_number: 129
difficulty: "advanced"
estimated_reading_time: 16
provider_bridges:
  - name: "Lakera"
    id: 142
    category: "llm-security"
  - name: "Cloudflare"
    id: 29
    category: "cdn-edge"
premium_pack: "training-data-extraction-defence-configs"
published: true
layout: article.njk
permalink: "/articles/ai-landscape/training-data-extraction/index.html"
---

# Training Data Extraction Prevention: Stopping Models from Leaking Memorised Data

## Problem

Large language models memorise portions of their training data. Given the right prompt, a model will reproduce training examples verbatim, including personally identifiable information, proprietary code, API keys, medical records, and copyrighted text. This is not a hypothetical risk. Researchers have extracted email addresses, phone numbers, and code snippets from production models using straightforward prompting techniques.

Memorisation is worst for data that appears multiple times in training (duplicates amplify memorisation), data that is unusual or unique (outliers are more memorable to gradient-based learning), and data encountered late in training (recent data is less "washed out" by subsequent updates).

The risk applies to any model trained on sensitive data: fine-tuned models on proprietary datasets, models trained on customer interactions, and even foundation models that ingested sensitive data from web crawls.

## Threat Model

- **Adversary:** Any user with query access to the model. Researchers probing for memorised data. Competitors seeking proprietary training data. Regulators testing for PII exposure.
- **Objective:** Extract verbatim training examples. Recover PII (names, emails, addresses, medical data). Extract proprietary code or business logic. Identify copyrighted content in training data.
- **Blast radius:** Privacy violations (GDPR, HIPAA). Copyright liability. Exposure of trade secrets. Regulatory penalties.

## Configuration

### Training Data Deduplication

```python
# deduplication.py - remove near-duplicates before training to reduce memorisation
import hashlib
from typing import List, Set
from datasketch import MinHash, MinHashLSH

class TrainingDataDeduplicator:
    """
    Remove exact and near-duplicate documents from training data.
    Duplicates are the primary driver of memorisation:
    data seen N times is N^2 more likely to be memorised.
    """

    def __init__(self, similarity_threshold: float = 0.8, num_perm: int = 128):
        self.threshold = similarity_threshold
        self.num_perm = num_perm
        self.lsh = MinHashLSH(threshold=self.threshold, num_perm=self.num_perm)
        self.exact_hashes: Set[str] = set()
        self.doc_count = 0
        self.duplicate_count = 0

    def _get_minhash(self, text: str) -> MinHash:
        m = MinHash(num_perm=self.num_perm)
        # Shingle the text into 5-grams
        words = text.lower().split()
        for i in range(len(words) - 4):
            shingle = " ".join(words[i:i+5])
            m.update(shingle.encode("utf-8"))
        return m

    def is_duplicate(self, text: str) -> bool:
        """Check if text is a duplicate of already-seen content."""
        # Exact duplicate check
        exact_hash = hashlib.sha256(text.strip().encode()).hexdigest()
        if exact_hash in self.exact_hashes:
            self.duplicate_count += 1
            return True
        self.exact_hashes.add(exact_hash)

        # Near-duplicate check via MinHash LSH
        minhash = self._get_minhash(text)
        results = self.lsh.query(minhash)
        if results:
            self.duplicate_count += 1
            return True

        self.lsh.insert(f"doc_{self.doc_count}", minhash)
        self.doc_count += 1
        return False

    def deduplicate_dataset(self, documents: List[str]) -> List[str]:
        """Filter dataset, returning only non-duplicate documents."""
        unique = []
        for doc in documents:
            if not self.is_duplicate(doc):
                unique.append(doc)
        print(f"Deduplication: {len(documents)} -> {len(unique)} "
              f"({self.duplicate_count} duplicates removed)")
        return unique
```

### Output Filtering for Sensitive Patterns

```python
# output_filter_extraction.py - detect and block verbatim training data in outputs
import re
from typing import List, Tuple

class ExtractionOutputFilter:
    """
    Filter model outputs to detect and block potential training data extraction.
    Checks for patterns that indicate memorised sensitive content.
    """

    SENSITIVE_PATTERNS = {
        # PII patterns
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "phone_us": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
        # API keys and secrets
        "aws_key": r"\bAKIA[0-9A-Z]{16}\b",
        "github_token": r"\bghp_[A-Za-z0-9]{36}\b",
        "generic_api_key": r"\b[A-Za-z0-9]{32,64}\b(?=.*key|.*token|.*secret)",
        # IP addresses (internal ranges suggest training data)
        "private_ip": r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
    }

    def __init__(self, canary_tokens: List[str] = None):
        self.canary_tokens = canary_tokens or []

    def check_sensitive_patterns(self, output: str) -> List[dict]:
        """Detect sensitive patterns in model output."""
        findings = []
        for pattern_name, regex in self.SENSITIVE_PATTERNS.items():
            matches = re.findall(regex, output, re.IGNORECASE)
            if matches:
                findings.append({
                    "type": pattern_name,
                    "count": len(matches),
                    "action": "redact",
                })
        return findings

    def check_canary_tokens(self, output: str) -> bool:
        """
        Check if output contains canary tokens inserted during training.
        Canary presence proves verbatim extraction is occurring.
        """
        for canary in self.canary_tokens:
            if canary in output:
                return True
        return False

    def redact_sensitive(self, output: str) -> str:
        """Replace sensitive patterns with redaction markers."""
        redacted = output
        replacements = {
            "email": "[EMAIL REDACTED]",
            "phone_us": "[PHONE REDACTED]",
            "ssn": "[SSN REDACTED]",
            "credit_card": "[CARD REDACTED]",
            "aws_key": "[AWS KEY REDACTED]",
            "github_token": "[TOKEN REDACTED]",
            "private_ip": "[IP REDACTED]",
        }
        for pattern_name, regex in self.SENSITIVE_PATTERNS.items():
            if pattern_name in replacements:
                redacted = re.sub(regex, replacements[pattern_name], redacted, flags=re.IGNORECASE)
        return redacted

    def filter(self, output: str) -> Tuple[str, dict]:
        """Full filtering pipeline."""
        canary_triggered = self.check_canary_tokens(output)
        findings = self.check_sensitive_patterns(output)

        if canary_triggered:
            return "[Output blocked: potential training data extraction detected]", {
                "blocked": True,
                "reason": "canary_token_detected",
                "findings": findings,
            }

        redacted = self.redact_sensitive(output)
        return redacted, {
            "blocked": False,
            "redactions": len(findings),
            "findings": findings,
        }
```

### Canary Token Insertion During Training

```python
# canary_insertion.py - insert canary tokens into training data
# Canaries are unique strings that should never appear in legitimate model output.
# If a canary appears in output, it proves the model is reproducing training data.
import secrets
import json
from typing import List, Tuple

class CanaryManager:
    """
    Manage canary tokens for training data extraction detection.
    Insert unique canaries into training data at controlled frequencies.
    Monitor model outputs for canary leakage.
    """

    def __init__(self, canary_file: str = "canaries.json"):
        self.canary_file = canary_file
        self.canaries = []

    def generate_canaries(self, count: int = 100, length: int = 24) -> List[str]:
        """Generate unique canary tokens."""
        self.canaries = [
            f"CANARY-{secrets.token_hex(length // 2)}"
            for _ in range(count)
        ]
        # Save canaries for later detection
        with open(self.canary_file, "w") as f:
            json.dump({"canaries": self.canaries, "count": count}, f, indent=2)
        return self.canaries

    def inject_canaries(
        self, documents: List[str], injection_rate: float = 0.001
    ) -> Tuple[List[str], int]:
        """
        Inject canary tokens into training documents.
        injection_rate: fraction of documents that receive a canary.
        """
        import random
        injected_count = 0
        modified_docs = []

        for doc in documents:
            if random.random() < injection_rate:
                canary = random.choice(self.canaries)
                # Insert canary as a natural-looking sentence
                canary_text = f"For reference, the document ID is {canary}."
                doc = doc + "\n" + canary_text
                injected_count += 1
            modified_docs.append(doc)

        print(f"Injected {injected_count} canaries into {len(documents)} documents "
              f"(rate: {injection_rate})")
        return modified_docs, injected_count

    def load_canaries(self) -> List[str]:
        """Load previously generated canaries for output monitoring."""
        with open(self.canary_file) as f:
            data = json.load(f)
        self.canaries = data["canaries"]
        return self.canaries
```

### Differential Privacy During Training

```python
# dp_fine_tuning.py - fine-tune with DP for extraction prevention
# Uses the same Opacus approach as membership inference defence
# but tuned specifically for preventing memorisation

def get_dp_config_for_extraction_prevention(dataset_size: int) -> dict:
    """
    Return recommended DP hyperparameters based on dataset size.
    Smaller datasets need stronger privacy (lower epsilon)
    because individual records have more influence.
    """
    if dataset_size < 1000:
        return {
            "target_epsilon": 1.0,
            "target_delta": 1.0 / (10 * dataset_size),
            "max_grad_norm": 0.5,
            "noise_multiplier": 1.5,
            "note": "Very small dataset. Strong DP required. Expect 10-15% accuracy loss."
        }
    elif dataset_size < 10000:
        return {
            "target_epsilon": 4.0,
            "target_delta": 1.0 / (10 * dataset_size),
            "max_grad_norm": 1.0,
            "noise_multiplier": 1.0,
            "note": "Small dataset. Moderate DP. Expect 5-10% accuracy loss."
        }
    else:
        return {
            "target_epsilon": 8.0,
            "target_delta": 1e-5,
            "max_grad_norm": 1.2,
            "noise_multiplier": 0.7,
            "note": "Large dataset. Standard DP. Expect 2-5% accuracy loss."
        }
```

### Monitoring for Extraction Attempts

```yaml
# prometheus-extraction-monitoring.yaml
groups:
  - name: training-data-extraction
    interval: 1m
    rules:
      # Alert on canary token detection in output
      - alert: CanaryTokenDetected
        expr: increase(canary_token_detected_total[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "Canary token detected in model output"
          description: >
            A canary token from the training data appeared in model output.
            This proves verbatim training data extraction is occurring.
            Investigate the requesting API key and input prompt immediately.

      # Alert on high PII redaction rate
      - alert: HighPIIRedactionRate
        expr: >
          rate(output_pii_redacted_total[5m])
          / rate(inference_requests_total[5m]) > 0.1
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "{{ $value | humanizePercentage }} of outputs contain PII"
          description: >
            Elevated PII in model outputs may indicate training data extraction
            attempts or insufficient data sanitisation in training.

      # Alert on repeated prompts designed to elicit memorised content
      - alert: ExtractionPromptPattern
        expr: >
          rate(extraction_prompt_pattern_detected_total[5m]) > 0.05
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Extraction-style prompts detected: {{ $value | humanize }}/sec"
          description: >
            Prompts matching known extraction patterns (e.g., "repeat the text that
            starts with...", "complete this: [partial known text]") detected at
            elevated rates.

      # Track output blocking rate
      - alert: HighOutputBlockRate
        expr: >
          rate(output_blocked_total{reason="canary_token_detected"}[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "Outputs are being blocked due to training data extraction"
```

## Expected Behaviour

- Training data deduplicated before training (near-duplicates removed at 0.8 similarity threshold)
- Models trained with differential privacy (epsilon 1-8 depending on dataset sensitivity)
- Canary tokens inserted at 0.1% rate across training data
- Output filtering detects and redacts PII, API keys, and other sensitive patterns in real time
- Canary token detection in output triggers immediate alert and blocks the response
- Extraction-style prompt patterns detected and monitored
- PII redaction rate above 10% triggers investigation

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Aggressive deduplication (0.8 threshold) | Removes near-duplicate content | Legitimate paraphrases or related documents may be removed | Tune threshold per corpus. Use 0.9 for diverse corpora, 0.7 for high-duplication datasets. |
| Differential privacy (epsilon=4) | 5-10% accuracy reduction | Model may be too inaccurate for production use | Increase training data volume. Use DP only for fine-tuning (not pre-training). |
| Canary token injection | Uses 0.1% of training capacity for canaries | Canaries may slightly influence model behaviour | Keep injection rate low. Use canary text that resembles normal metadata. |
| Output PII filtering | Adds 5-15ms per response | False positives redact legitimate content (e.g., example email addresses in tutorials) | Maintain an allowlist of known-safe patterns. Context-aware filtering. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Deduplication misses near-duplicates | High-frequency content still memorised | Canary tokens for duplicated content detected in output | Lower similarity threshold. Add character-level deduplication in addition to word-level. |
| Output filter bypass | Attacker uses encoding or translation to extract data | PII detected in translated outputs; user reports | Add multilingual PII detection. Monitor for base64, ROT13, and other encoding requests. |
| Canary not memorised | No canaries detected even during legitimate extraction | Red team testing shows extraction is possible but canaries do not fire | Increase canary injection rate. Ensure canaries are placed in high-memorisation positions (repeated, unique). |
| DP training instability | Training diverges or produces very low quality model | Loss does not converge; evaluation metrics unacceptable | Reduce noise multiplier. Increase batch size. Use DP-SGD with adaptive clipping. |

## When to Consider a Managed Alternative

Training data extraction prevention requires expertise in differential privacy, output filtering, and ongoing red team testing. The privacy-utility trade-off is difficult to tune correctly.

- **[Lakera](https://www.lakera.ai):** Managed LLM security platform with output filtering, PII detection, and content safety classification. Detects extraction attempts in real time.
- **[Cloudflare](https://www.cloudflare.com) AI Gateway:** Edge-level output filtering and monitoring for AI inference endpoints.

**Premium content pack:** Training data extraction defence pack. Deduplication scripts (MinHash LSH), canary token management system, output filtering middleware (Python), DP training configurations for PyTorch/Opacus, [Prometheus](https://prometheus.io) alerting rules, and an extraction red team test suite.


## Related Articles

- [Membership Inference Defence: Preventing Attackers from Determining Training Data Inclusion](/articles/ai-landscape/membership-inference-defence/)
- [LLM Jailbreak Defence: Detecting and Preventing System Prompt Bypasses in Production](/articles/ai-landscape/llm-jailbreak-defence/)
- [How AI Is Compressing the Attacker Timeline: What Defenders Need to Change Now](/articles/ai-landscape/ai-compressing-attacker-timeline/)
- [Securing AI Agents in Production: Tool-Use Boundaries, Credential Scoping, and Output Verification](/articles/ai-landscape/securing-ai-agents/)
- [The Threat Model Has Changed: Rewriting Security Assumptions for an AI-Augmented World](/articles/ai-landscape/threat-model-ai-augmented/)
