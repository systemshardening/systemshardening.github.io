---
title: "Model Extraction Prevention: Detecting and Blocking Model Stealing Through API Queries"
description: "Model extraction (model stealing) is an attack where an adversary queries a production ML API systematically to reconstruct a functionally equivalent..."
slug: "model-extraction-prevention"
date: 2026-04-12
lastmod: 2026-04-12
category: "ai-landscape"
tags: ["model-extraction", "model-stealing", "api-security", "rate-limiting", "watermarking"]
personas: ["ai-ml-engineer", "security-engineer"]
article_number: 127
difficulty: "advanced"
estimated_reading_time: 16
provider_bridges:
  - name: "Cloudflare"
    id: 29
    category: "cdn-edge"
  - name: "Kong"
    id: 35
    category: "api-gateway"
premium_pack: "model-extraction-defence-configs"
published: true
layout: article.njk
permalink: "/articles/ai-landscape/model-extraction-prevention/index.html"
---

# Model Extraction Prevention: Detecting and Blocking Model Stealing Through API Queries

## Problem

Model extraction (model stealing) is an attack where an adversary queries a production ML API systematically to reconstruct a functionally equivalent copy of the model. The attacker sends carefully chosen inputs, collects outputs (predictions, probabilities, embeddings), and trains a surrogate model that replicates the target's behaviour. A stolen model gives the attacker free inference (bypassing API costs), the ability to find adversarial examples offline, and access to proprietary capabilities without licensing.

The attack does not require exploiting a vulnerability. It uses the model's own API exactly as designed. Every prediction returned is a training sample for the attacker's surrogate. With modern distillation techniques, a few thousand queries can extract a high-fidelity copy of many classification and regression models. For LLMs, systematic querying can extract fine-tuning data, alignment preferences, and decision boundaries.

Rate limiting alone is insufficient. Sophisticated attackers spread queries across time, rotate API keys, and use diverse input distributions that look like normal usage.

## Threat Model

- **Adversary:** Competitor, researcher, or attacker with legitimate API access (valid API key, free tier account, or compromised credentials).
- **Objective:** Create a functionally equivalent model without training costs. Map decision boundaries for adversarial example generation. Extract proprietary fine-tuning or alignment data from LLMs.
- **Blast radius:** Loss of intellectual property. Competitor deploys equivalent capability. Attacker uses extracted model to craft adversarial inputs that transfer to the production model.

## Configuration

### Query Pattern Detection

```python
# query_pattern_detector.py - detect systematic probing of model decision boundaries
import numpy as np
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Optional
import time

@dataclass
class QueryProfile:
    api_key: str
    queries: List[dict] = field(default_factory=list)
    timestamps: List[float] = field(default_factory=list)
    input_embeddings: List[np.ndarray] = field(default_factory=list)

class ExtractionDetector:
    """
    Detect model extraction attempts by analysing query patterns.
    Extraction attacks exhibit distinct statistical signatures:
    - High query volume with systematic input variation
    - Inputs clustered around decision boundaries
    - Low entropy in query distribution (not random usage)
    - Requests for full probability distributions (not just top-1)
    """

    def __init__(self, window_seconds: int = 3600, boundary_threshold: float = 0.1):
        self.profiles = defaultdict(lambda: QueryProfile(api_key=""))
        self.window = window_seconds
        self.boundary_threshold = boundary_threshold

    def record_query(self, api_key: str, input_data: dict,
                     output_probs: np.ndarray, embedding: Optional[np.ndarray] = None):
        profile = self.profiles[api_key]
        profile.api_key = api_key
        profile.queries.append(input_data)
        profile.timestamps.append(time.time())
        if embedding is not None:
            profile.input_embeddings.append(embedding)

        # Prune old entries outside the window
        cutoff = time.time() - self.window
        valid = [i for i, t in enumerate(profile.timestamps) if t > cutoff]
        profile.queries = [profile.queries[i] for i in valid]
        profile.timestamps = [profile.timestamps[i] for i in valid]
        profile.input_embeddings = [profile.input_embeddings[i] for i in valid if i < len(profile.input_embeddings)]

    def check_boundary_probing(self, api_key: str, output_probs: np.ndarray) -> float:
        """
        Detect decision boundary probing.
        Extraction attacks often query near boundaries where the model is uncertain.
        Returns a score 0-1 (1 = high suspicion).
        """
        # Boundary probing signature: many queries with near-uniform probability
        max_prob = np.max(output_probs)
        margin = max_prob - np.partition(output_probs, -2)[-2] if len(output_probs) > 1 else max_prob

        profile = self.profiles[api_key]
        if len(profile.queries) < 50:
            return 0.0

        # Track how many recent queries had low decision margin
        boundary_count = sum(
            1 for q in profile.queries[-100:]
            if q.get("_margin", 1.0) < self.boundary_threshold
        )
        return boundary_count / min(len(profile.queries), 100)

    def check_systematic_coverage(self, api_key: str) -> float:
        """
        Detect systematic input space coverage.
        Normal users cluster around specific use cases.
        Extraction attacks spread uniformly across the input space.
        Returns a score 0-1 (1 = high suspicion).
        """
        profile = self.profiles[api_key]
        if len(profile.input_embeddings) < 100:
            return 0.0

        embeddings = np.array(profile.input_embeddings[-500:])
        # Compute pairwise cosine similarity
        norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
        normalised = embeddings / (norms + 1e-8)
        similarity_matrix = normalised @ normalised.T

        # Normal usage: high average similarity (clustered)
        # Extraction: low average similarity (spread out)
        avg_similarity = (similarity_matrix.sum() - len(embeddings)) / (len(embeddings) * (len(embeddings) - 1))
        # Threshold: avg similarity below 0.3 is suspicious
        return max(0.0, 1.0 - avg_similarity / 0.3)

    def get_risk_score(self, api_key: str, output_probs: np.ndarray) -> dict:
        boundary_score = self.check_boundary_probing(api_key, output_probs)
        coverage_score = self.check_systematic_coverage(api_key)
        profile = self.profiles[api_key]

        # Volume score: queries per hour
        volume = len(profile.queries)
        volume_score = min(1.0, volume / 1000)  # 1000 queries/hour = max score

        composite = 0.3 * volume_score + 0.4 * boundary_score + 0.3 * coverage_score

        return {
            "api_key": api_key,
            "risk_score": round(composite, 3),
            "volume_score": round(volume_score, 3),
            "boundary_probing_score": round(boundary_score, 3),
            "coverage_score": round(coverage_score, 3),
            "queries_in_window": volume,
            "action": "block" if composite > 0.7 else "throttle" if composite > 0.4 else "allow",
        }
```

### Rate Limiting with Adaptive Thresholds

```yaml
# kong-rate-limiting.yaml - adaptive rate limiting for ML inference endpoints
apiVersion: configuration.konghq.com/v1
kind: KongPlugin
metadata:
  name: ml-inference-rate-limit
  namespace: ai-services
plugin: rate-limiting-advanced
config:
  # Base rate limits
  limit:
    - 100   # requests per window
  window_size:
    - 3600  # 1 hour
  window_type: sliding
  strategy: cluster
  sync_rate: 10
  namespace: ml-inference
  # Per-consumer limits (identified by API key)
  consumer_groups:
    - name: free-tier
      limit: [50]
      window_size: [3600]
    - name: standard
      limit: [500]
      window_size: [3600]
    - name: enterprise
      limit: [5000]
      window_size: [3600]
  # Return remaining quota in headers
  hide_client_headers: false
```

### Output Perturbation

```python
# output_perturbation.py - add controlled noise to model outputs
# This makes extraction harder without significantly affecting utility
import numpy as np
from typing import Optional

class OutputPerturbator:
    """
    Add calibrated noise to model outputs to degrade extraction quality.
    The noise is small enough that top-1 predictions are unchanged
    but large enough that probability distributions cannot be used
    to train a high-fidelity surrogate.
    """

    def __init__(self, noise_scale: float = 0.05, top_k: Optional[int] = 5):
        self.noise_scale = noise_scale
        self.top_k = top_k

    def perturb_probabilities(self, probs: np.ndarray) -> np.ndarray:
        """Add Laplace noise to probability distribution."""
        noise = np.random.laplace(0, self.noise_scale, size=probs.shape)
        perturbed = probs + noise
        # Re-normalise to valid probability distribution
        perturbed = np.clip(perturbed, 0, 1)
        perturbed = perturbed / perturbed.sum()
        return perturbed

    def truncate_output(self, probs: np.ndarray, labels: list) -> dict:
        """Return only top-k predictions instead of full distribution."""
        if self.top_k is None:
            return {labels[i]: float(probs[i]) for i in range(len(labels))}

        top_indices = np.argsort(probs)[-self.top_k:][::-1]
        return {labels[i]: float(probs[i]) for i in top_indices}

    def process(self, probs: np.ndarray, labels: list) -> dict:
        perturbed = self.perturb_probabilities(probs)
        return self.truncate_output(perturbed, labels)
```

### Monitoring for Extraction Attempts

```yaml
# prometheus-extraction-detection.yaml
groups:
  - name: model-extraction
    interval: 1m
    rules:
      # Track query volume per API key
      - record: inference:queries:per_key_1h
        expr: >
          sum by (api_key) (
            increase(inference_requests_total[1h])
          )

      # Alert on high query volume
      - alert: HighInferenceVolume
        expr: inference:queries:per_key_1h > 500
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "API key {{ $labels.api_key }} made {{ $value }} queries in 1h"
          description: "Investigate for potential model extraction. Normal usage is under 200 queries/hour."

      # Alert on extraction risk score
      - alert: ModelExtractionRiskHigh
        expr: model_extraction_risk_score > 0.7
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High model extraction risk for API key {{ $labels.api_key }}"
          description: >
            Risk score: {{ $value }}. Boundary probing and systematic coverage
            indicators elevated. Consider blocking this API key.

      # Alert on requests for full probability distributions
      - alert: FullDistributionRequests
        expr: >
          rate(inference_full_distribution_requests_total[1h])
          / rate(inference_requests_total[1h]) > 0.5
        for: 30m
        labels:
          severity: warning
        annotations:
          summary: "{{ $labels.api_key }} requesting full distributions in >50% of queries"
```

### Watermarking Model Outputs

```python
# output_watermark.py - embed imperceptible watermarks in model outputs
# Used to prove ownership if a stolen model is discovered
import hashlib
import numpy as np

class OutputWatermarker:
    """
    Embed a statistical watermark in model outputs.
    The watermark is imperceptible in individual predictions
    but detectable across a corpus of outputs.
    """

    def __init__(self, secret_key: str, watermark_strength: float = 0.01):
        self.secret_key = secret_key.encode()
        self.strength = watermark_strength

    def _get_watermark_signal(self, input_hash: str, output_dim: int) -> np.ndarray:
        """Generate a deterministic watermark signal from the input."""
        seed = int(hashlib.sha256(self.secret_key + input_hash.encode()).hexdigest()[:8], 16)
        rng = np.random.RandomState(seed)
        return rng.randn(output_dim) * self.strength

    def apply(self, probs: np.ndarray, input_text: str) -> np.ndarray:
        """Apply watermark to output probabilities."""
        input_hash = hashlib.sha256(input_text.encode()).hexdigest()
        signal = self._get_watermark_signal(input_hash, len(probs))
        watermarked = probs + signal
        watermarked = np.clip(watermarked, 0, 1)
        watermarked = watermarked / watermarked.sum()
        return watermarked

    def detect(self, collected_outputs: list, collected_inputs: list) -> dict:
        """
        Detect watermark presence in a collection of outputs.
        Requires access to multiple input-output pairs from the suspected copy.
        """
        correlations = []
        for inp, out in zip(collected_inputs, collected_outputs):
            input_hash = hashlib.sha256(inp.encode()).hexdigest()
            expected_signal = self._get_watermark_signal(input_hash, len(out))
            correlation = np.corrcoef(out - out.mean(), expected_signal)[0, 1]
            correlations.append(correlation)

        avg_correlation = np.mean(correlations)
        return {
            "watermark_detected": avg_correlation > 0.3,
            "confidence": min(1.0, avg_correlation / 0.5),
            "samples_tested": len(correlations),
            "avg_correlation": float(avg_correlation),
        }
```

## Expected Behaviour

- Queries analysed in real time for extraction signatures (boundary probing, systematic coverage)
- Risk scores computed per API key and updated with each query
- API keys with risk score above 0.7 are automatically blocked pending review
- Output probabilities perturbed with calibrated noise (top-1 accuracy preserved, surrogate training degraded)
- Full probability distributions restricted to top-k unless enterprise tier
- Watermarks embedded in all outputs for post-hoc ownership verification
- Alerts fire within 5 minutes of sustained suspicious query patterns

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Output perturbation | Adds noise to probability distributions | Downstream applications relying on exact probabilities may degrade | Tune noise scale per use case. Offer exact probabilities only to trusted enterprise customers. |
| Top-k truncation | Returns only top-k predictions | Users who need full distributions for calibration lose functionality | Provide full distributions through a separate, audited endpoint with additional authentication. |
| Boundary probing detection | Flags queries near decision boundaries | Legitimate active learning workflows probe boundaries intentionally | Allowlist known active learning pipelines. Review flagged API keys before blocking. |
| Rate limiting | Caps queries per time window | Legitimate high-volume users hit limits | Tier-based limits. Enterprise customers get higher limits with contractual anti-extraction clauses. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Low-and-slow extraction | Attacker stays below rate limits and detection thresholds | Model copy appears externally; detection scores stayed low | Lower detection thresholds. Add longer-window analysis (weekly, monthly). |
| False positive on power user | Legitimate high-volume user blocked | User reports access issues; support tickets | Review query patterns manually. Allowlist after verification. Adjust detection parameters. |
| Watermark removed by retraining | Attacker retrains surrogate, removing watermark | Watermark detection returns negative on suspected copy | Use multiple independent watermarking schemes. Combine with fingerprinting (unique responses to canary inputs). |
| Perturbation too aggressive | Top-1 predictions occasionally change | User reports inconsistent results; accuracy metrics drop | Reduce noise scale. Validate that top-1 accuracy is preserved on a test set before deploying noise parameters. |

## When to Consider a Managed Alternative

Model extraction defence requires ongoing monitoring, threshold tuning, and response to evolving attack techniques. The detection system itself needs regular updating.

- **[Cloudflare](https://www.cloudflare.com) AI Gateway:** Managed API gateway with rate limiting, request logging, and abuse detection for ML inference endpoints.
- **[Kong](https://konghq.com):** API gateway with advanced rate limiting plugins, consumer grouping, and request analytics for detecting anomalous usage patterns.

**Premium content pack:** Model extraction defence pack. Query pattern detector (Python), output perturbation library, watermarking toolkit, Kong rate limiting configurations, [Prometheus](https://prometheus.io) alerting rules, and extraction attack simulation scripts for testing defences.


## Related Articles

- [Hardening the AI Control Plane: Kill Switches, Rate Limits, and Human-in-the-Loop Gates](/articles/ai-landscape/ai-control-plane/)
- [How AI Is Compressing the Attacker Timeline: What Defenders Need to Change Now](/articles/ai-landscape/ai-compressing-attacker-timeline/)
- [The Threat Model Has Changed: Rewriting Security Assumptions for an AI-Augmented World](/articles/ai-landscape/threat-model-ai-augmented/)
- [Membership Inference Defence: Preventing Attackers from Determining Training Data Inclusion](/articles/ai-landscape/membership-inference-defence/)
- [Training Data Extraction Prevention: Stopping Models from Leaking Memorised Data](/articles/ai-landscape/training-data-extraction/)
