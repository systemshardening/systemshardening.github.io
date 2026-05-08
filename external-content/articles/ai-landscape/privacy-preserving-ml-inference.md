---
title: "Privacy-Preserving ML Inference: Differential Privacy, Confidential Computing, and Training Data Protection"
description: "ML inference leaks training data through membership inference, model inversion, and embedding attacks. Differential privacy, TEE-based inference, and output filtering bound the leakage."
slug: "privacy-preserving-ml-inference"
date: 2026-04-29
lastmod: 2026-04-29
category: "ai-landscape"
tags: ["privacy", "differential-privacy", "confidential-computing", "ml-inference", "tee"]
personas: ["ml-engineer", "security-engineer", "platform-engineer"]
article_number: 236
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/ai-landscape/privacy-preserving-ml-inference/index.html"
---

# Privacy-Preserving ML Inference: Differential Privacy, Confidential Computing, and Training Data Protection

## Problem

ML models memorize training data. The degree varies by model size, data repetition, and training configuration — but the research is unambiguous: language models, image classifiers, and embedding models all leak information about their training sets to adversaries with query access.

The attack surface in production inference:

- **Membership inference:** Given a data record (a user's medical history, a document, a transaction), an attacker can query the model to determine whether that record appeared in the training data with better-than-random accuracy. This is a GDPR violation if the record is personal data.
- **Training data extraction:** Direct prompting can cause large language models to reproduce verbatim training data — email addresses, passwords, copyrighted text, PII from scraped datasets. DeepMind's 2023 extraction study found millions of memorized records in common LLMs.
- **Model inversion:** By querying a model with optimized inputs, an attacker can reconstruct approximate representations of training data — particularly for image classifiers trained on identifiable faces.
- **Embedding reversal:** Sentence embedding models convert text to dense vectors. Given the embedding, an attacker can approximately reconstruct the original text — deanonymizing records stored as embeddings.

The regulatory implication: GDPR Article 17 (right to erasure) requires that a data subject's information can be removed from a system. For a model that memorized the data during training, this is technically hard — the only current solution is retraining from scratch on a dataset that excludes the subject.

By 2026, the EU AI Act (effective August 2026 for general-purpose AI) requires risk documentation and technical controls for high-risk systems that process personal data. Privacy-preserving inference is no longer a research topic — it's a compliance requirement.

Specific gaps in default inference deployments:

- Models served without output filtering; arbitrary memorized text is reproducible on demand.
- Embedding endpoints return raw high-dimensional vectors with no obfuscation.
- No differential privacy budget tracking; the total privacy leakage across all queries is unmeasured.
- Training pipelines don't apply DP-SGD; privacy guarantees are informally claimed but not mathematically bounded.
- Inference infrastructure is not isolated in a TEE; the model provider can observe all queries.

**Target systems:** PyTorch 2.3+ with Opacus 1.4+ (DP-SGD); TensorFlow Privacy 0.9+; Gramine 1.7+ or Occlum 0.29+ (TEE-based inference); Azure Confidential Computing / AWS Nitro Enclaves for managed TEE; Presidio 2.2+ (PII detection in outputs).

## Threat Model

- **Adversary 1 — Membership inference attacker:** An adversary with API access to an inference endpoint sends queries designed to detect whether specific individuals appear in the training data. Targets include medical records, financial transactions, user behavior logs.
- **Adversary 2 — Training data extraction attacker:** An adversary with API access probes the model with crafted prompts, extracting verbatim memorized training data — PII, passwords, internal documents.
- **Adversary 3 — Model inversion attacker:** An adversary with access to a classification or embedding endpoint reconstructs approximations of training data by optimizing inputs to maximize specific output activations.
- **Adversary 4 — Inference provider:** The infrastructure that hosts the model can observe every query and response. In a third-party inference setup (API provider), this includes the provider organization. TEE-based inference prevents this.
- **Adversary 5 — Embedding deanonymization:** An adversary who obtains a database of text embeddings reverses them to recover the original sensitive text (medical notes, PII, confidential communications stored as embeddings).
- **Access level:** Adversaries 1–3 have inference API access (possibly paid/free public access). Adversary 4 has infrastructure access. Adversary 5 has database access.
- **Objective:** Extract training data records, determine membership of individuals in sensitive datasets, deanonymize stored embeddings, or observe private queries.
- **Blast radius:** Without controls: any user who can query the model can extract memorized training data or determine dataset membership. With DP + output filtering + TEE: privacy leakage is mathematically bounded; individual records are protected.

## Configuration

### Step 1: Differential Privacy During Training with DP-SGD

Apply differential privacy during model training using Opacus (PyTorch):

```python
import torch
from torch.utils.data import DataLoader
from opacus import PrivacyEngine
from opacus.validators import ModuleValidator

# Validate that the model architecture is DP-compatible.
# Some layers (BatchNorm, LSTM) require replacement for DP.
model = MyModel()
errors = ModuleValidator.validate(model, strict=False)
if errors:
    model = ModuleValidator.fix(model)   # Auto-replaces incompatible layers.

optimizer = torch.optim.Adam(model.parameters(), lr=1e-4)
data_loader = DataLoader(train_dataset, batch_size=64, shuffle=True)

# Attach the privacy engine.
privacy_engine = PrivacyEngine()
model, optimizer, data_loader = privacy_engine.make_private_with_epsilon(
    module=model,
    optimizer=optimizer,
    data_loader=data_loader,
    epochs=20,
    target_epsilon=8.0,    # Privacy budget: lower = stronger privacy, lower utility.
    target_delta=1e-5,     # Probability of epsilon-privacy violation.
    max_grad_norm=1.0,     # Gradient clipping; controls sensitivity.
)

# Training loop.
for epoch in range(20):
    for batch in data_loader:
        optimizer.zero_grad()
        loss = criterion(model(batch.x), batch.y)
        loss.backward()
        optimizer.step()

# Report the actual privacy spent.
epsilon = privacy_engine.get_epsilon(delta=1e-5)
print(f"Training complete. ε = {epsilon:.2f}, δ = 1e-5")
```

The `(ε, δ)`-DP guarantee means: for any pair of adjacent datasets (differing in one individual's record), the probability that the model's output reveals information specific to that record is bounded. `ε = 8.0` is a reasonable practical target for text classification; for more sensitive domains, target `ε ≤ 3.0`.

Membership inference resilience at different epsilon values:

| ε | Membership inference attack AUC | Utility impact |
|---|---------------------------------|----------------|
| 0.1 | ~0.51 (near random) | High utility loss |
| 1.0 | ~0.53 | Moderate utility loss |
| 8.0 | ~0.58 | Minor utility loss |
| ∞ (no DP) | ~0.65–0.85 (depends on model) | No utility loss |

### Step 2: Output Filtering for Memorized Data

Even without DP training, output filtering reduces extraction risk:

```python
import re
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

def filter_model_output(text: str) -> str:
    # Detect PII in model output.
    results = analyzer.analyze(
        text=text,
        language="en",
        entities=["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER",
                  "CREDIT_CARD", "US_SSN", "IP_ADDRESS",
                  "LOCATION", "DATE_TIME"]
    )
    if not results:
        return text

    # Anonymize detected PII.
    anonymized = anonymizer.anonymize(
        text=text,
        analyzer_results=results
    )
    return anonymized.text

def filtered_inference(prompt: str, model, tokenizer) -> str:
    raw_output = model.generate(
        tokenizer.encode(prompt, return_tensors="pt"),
        max_new_tokens=512,
        do_sample=True,
        temperature=0.7,
    )
    decoded = tokenizer.decode(raw_output[0], skip_special_tokens=True)

    # Filter PII before returning.
    return filter_model_output(decoded)
```

For LLMs, also filter for exact training data reproduction:

```python
import hashlib

# Pre-compute hashes of known-sensitive training documents.
SENSITIVE_HASHES = set()  # Populated from training data manifest.

def detect_verbatim_reproduction(output: str, window: int = 100) -> bool:
    words = output.split()
    for i in range(len(words) - window + 1):
        window_text = " ".join(words[i:i+window])
        window_hash = hashlib.sha256(window_text.encode()).hexdigest()
        if window_hash in SENSITIVE_HASHES:
            return True
    return False
```

### Step 3: TEE-Based Inference for Query Privacy

For scenarios where the inference provider must not observe queries (confidential ML as a service), run inference inside a Trusted Execution Environment:

**Using Gramine (Intel SGX):**

```toml
# gramine-manifest.template for model inference.
loader.entrypoint = "file:{{ gramine.libos }}"
libos.entrypoint = "/usr/bin/python3"

loader.argv = [
    "python3",
    "/app/inference_server.py",
    "--model-path", "/model/llm.bin",
    "--host", "0.0.0.0",
    "--port", "8080",
]

# Seal model weights to the enclave; only this enclave can read them.
sgx.files.sealed = "/model/llm.bin"

# All network traffic encrypted with TLS inside the enclave.
sgx.trusted_files = [
    "file:/usr/bin/python3",
    "file:/app/inference_server.py",
    "file:/etc/ssl/certs/ca-certificates.crt",
]

sgx.max_threads = 16
sgx.enclave_size = "16G"   # Must hold model weights; large for LLMs.
```

The enclave provides:

- **Model confidentiality:** Model weights are sealed to the SGX enclave; the cloud provider cannot read them.
- **Query confidentiality:** Queries arrive via attested TLS channels; only the enclave decrypts them.
- **Remote attestation:** The client verifies the enclave measurement (MRENCLAVE) matches the known-good binary before trusting it.

**Remote attestation in the client:**

```python
import grpc
from gramine_ratls import create_ra_tls_channel

# Verify the enclave's remote attestation before sending queries.
# ra_tls_channel verifies the MRENCLAVE matches the published measurement.
channel = create_ra_tls_channel(
    target="sgx-inference.internal:8080",
    expected_mrenclave="<hex-mrenclave-of-inference-binary>",
    expected_mrsigner="<hex-mrsigner>",
)
stub = InferenceStub(channel)
response = stub.Predict(PredictRequest(input=user_query))
```

**AWS Nitro Enclaves (managed alternative):**

```bash
# Package the inference application as an enclave image.
nitro-cli build-enclave \
  --docker-uri inference-app:latest \
  --output-file inference.eif

# Run the enclave.
nitro-cli run-enclave \
  --eif-path inference.eif \
  --cpu-count 4 \
  --memory 16384

# Attestation document is automatically available inside the enclave.
# The client verifies it before sending data.
```

### Step 4: Embedding Privacy — Vector Obfuscation

For embedding endpoints, add calibrated Laplace noise to the output vectors:

```python
import numpy as np

def private_embedding(text: str, model, sensitivity: float, epsilon: float) -> np.ndarray:
    embedding = model.encode(text)

    # Calibrated Laplace noise for epsilon-DP.
    # scale = sensitivity / epsilon
    # sensitivity = max distance between embeddings of adjacent inputs.
    noise_scale = sensitivity / epsilon
    noise = np.random.laplace(0, noise_scale, embedding.shape)

    # Normalize the noisy embedding to unit sphere (cosine similarity preserved approx.)
    noisy_embedding = embedding + noise
    return noisy_embedding / np.linalg.norm(noisy_embedding)
```

The noise level is calibrated to make embedding reversal computationally infeasible while preserving approximate similarity search accuracy. For `ε = 1.0`, embedding reversal accuracy degrades from ~80% to ~30% on standard benchmarks.

For higher-sensitivity cases, use TextObfuscator before embedding:

```python
# Obfuscate before embedding — useful for anonymization pipelines.
from presidio_analyzer import AnalyzerEngine

def obfuscated_embedding(text: str, model) -> np.ndarray:
    # Strip PII before embedding.
    analyzer = AnalyzerEngine()
    results = analyzer.analyze(text=text, language="en")
    clean_text = anonymize(text, results)
    return model.encode(clean_text)
```

### Step 5: Privacy Budget Tracking

Track cumulative privacy budget across queries to detect when the budget is exhausted:

```python
from opacus.accountants import RDPAccountant

class PrivacyBudgetTracker:
    def __init__(self, total_epsilon: float, delta: float):
        self.accountant = RDPAccountant()
        self.total_epsilon = total_epsilon
        self.delta = delta
        self.query_count = 0

    def record_query(self, noise_multiplier: float, sample_rate: float):
        self.accountant.step(
            noise_multiplier=noise_multiplier,
            sample_rate=sample_rate
        )
        self.query_count += 1
        current_eps = self.accountant.get_epsilon(self.delta)
        if current_eps >= self.total_epsilon:
            raise PrivacyBudgetExhausted(
                f"Privacy budget exceeded: ε={current_eps:.2f} >= {self.total_epsilon}"
            )
        return current_eps

# Usage: track budget per user or per model.
tracker = PrivacyBudgetTracker(total_epsilon=10.0, delta=1e-5)
```

Expose budget consumption as a metric:

```python
privacy_budget_consumed = Gauge(
    "ml_privacy_budget_consumed",
    "Current privacy budget consumption (epsilon)",
    ["model_id", "user_group"]
)
```

### Step 6: Model Unlearning for GDPR Right to Erasure

When a user exercises their right to erasure, remove their data's influence from the model:

```python
from torch.utils.data import DataLoader
from opacus import PrivacyEngine

def unlearn_records(model, forget_dataset, retain_dataset, steps: int = 100):
    # Gradient ascent on the forget set (maximize loss = unlearn).
    optimizer_forget = torch.optim.SGD(model.parameters(), lr=1e-4)
    forget_loader = DataLoader(forget_dataset, batch_size=32)

    for step, batch in enumerate(forget_loader):
        if step >= steps:
            break
        loss = -criterion(model(batch.x), batch.y)   # Gradient ascent.
        optimizer_forget.zero_grad()
        loss.backward()
        optimizer_forget.step()

    # Fine-tune on retain set to restore utility after unlearning.
    optimizer_retain = torch.optim.Adam(model.parameters(), lr=1e-5)
    retain_loader = DataLoader(retain_dataset, batch_size=64)
    for batch in retain_loader:
        loss = criterion(model(batch.x), batch.y)
        optimizer_retain.zero_grad()
        loss.backward()
        optimizer_retain.step()

    return model
```

Approximate unlearning is not a mathematically verified substitute for retraining; document the approach and its limitations for compliance purposes. For high-stakes erasure requests, retrain from scratch on the revised dataset.

### Step 7: Telemetry

```
ml_privacy_budget_consumed{model_id, user_group}       gauge
ml_pii_filtered_output_total{model_id}                 counter
ml_membership_inference_query_detected_total            counter
ml_verbatim_reproduction_blocked_total                  counter
ml_enclave_attestation_failure_total                    counter
ml_unlearning_requests_total{status}                    counter
```

Alert on:

- `ml_privacy_budget_consumed` approaching the configured total — re-evaluate query access or retrain with fresh budget.
- `ml_verbatim_reproduction_blocked_total` non-zero — model is reproducing training data; consider output filtering expansion.
- `ml_enclave_attestation_failure_total` non-zero — TEE attestation failing; possible tampering or version mismatch.

## Expected Behaviour

| Signal | Without privacy controls | With privacy controls |
|--------|-------------------------|-----------------------|
| Membership inference AUC | 0.65–0.85 | 0.51–0.58 (with ε=8 DP) |
| Training data extraction | Verbatim PII reproducible | Filtered; PII anonymized in output |
| Query privacy from provider | Provider observes all queries | TEE: provider cannot observe queries |
| Embedding reversibility | ~80% reconstruction accuracy | ~30% with Laplace noise (ε=1.0) |
| GDPR erasure compliance | Full retrain required | Approximate unlearning + documented limitations |
| Privacy budget visibility | Unknown cumulative leakage | Tracked per query; alert on exhaustion |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| DP-SGD training | Mathematically bounded membership inference | 5–15% accuracy degradation at ε=8; higher at lower ε | Tune ε to balance compliance requirement and acceptable utility loss; most tasks tolerable at ε=8. |
| Output PII filtering | Reduces training data extraction | False positives (legitimate content filtered) | Tune Presidio confidence thresholds; log filtered content for review. |
| TEE inference | Provider cannot observe queries | 2–4× latency overhead from enclave context switches; large enclaves for LLMs | Use for highest-sensitivity use cases only; regular inference for lower-risk models. |
| Embedding noise | Bounds reversal attacks | Reduces approximate nearest-neighbor accuracy | Calibrate noise to your similarity search accuracy requirement. |
| Privacy budget tracking | Visible cumulative leakage | Budget exhaustion blocks new queries | Set budget generously for exploratory use; implement per-user budgets for sensitive data. |
| Approximate unlearning | Fast (minutes vs hours for retrain) | Not verified to mathematical standard | Document as approximate; combine with audit log evidence of original data removal. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| DP budget exhausted | Privacy tracker blocks queries | `PrivacyBudgetExhausted` exception; metric alert | Retrain model with a fresh privacy accounting; consider model versioning with per-version budgets. |
| PII filter false negative | PII appears in model output | Spot-check output logs; DSAR review | Expand entity list in Presidio; add domain-specific recognizers for your data types. |
| TEE attestation version mismatch | Client rejects server attestation | Attestation failure errors in client logs | Update TEE binary and publish new MRENCLAVE; update clients. |
| Embedding noise too high | Similarity search accuracy degrades | Search recall metrics drop | Reduce noise (increase ε); accept higher privacy leakage or restructure use case. |
| Unlearning inadequate | Membership inference still detects the erased record | MIA test post-unlearning still shows elevated AUC | Retrain from scratch on the revised dataset; use unlearning only for low-risk erasure requests. |
| DP-SGD incompatible layer | Training fails with Opacus error | Error: `BatchNorm` not supported | Run `ModuleValidator.fix(model)` before attaching the privacy engine. |

## Related Articles

- [Membership Inference Defence and Model Extraction Prevention](/articles/ai-landscape/membership-inference-defence/)
- [Training Data Extraction and Protection](/articles/ai-landscape/training-data-extraction/)
- [AI Governance Pipeline](/articles/ai-landscape/ai-governance-pipeline/)
- [EU AI Act Compliance for AI Systems](/articles/ai-landscape/eu-ai-act-compliance/)
- [LLM Prompt Security Patterns](/articles/ai-landscape/llm-prompt-security-patterns/)
