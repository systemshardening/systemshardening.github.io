---
title: "Differential Privacy for ML Training: ε-DP Guarantees and Implementation"
description: "Differential privacy adds calibrated noise to gradients during model training, providing a mathematical bound on how much any individual's data can influence model outputs. DP-SGD with TensorFlow Privacy or Opacus limits membership inference and training data extraction attacks."
slug: "differential-privacy-ml"
date: 2026-05-01
lastmod: 2026-05-01
category: "ai-landscape"
tags: ["differential-privacy", "dp-sgd", "opacus", "tensorflow-privacy", "ml-security", "privacy"]
personas: ["security-engineer", "ml-engineer", "platform-engineer"]
article_number: 284
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/ai-landscape/differential-privacy-ml/index.html"
---

# Differential Privacy for ML Training: ε-DP Guarantees and Implementation

## Problem

Machine learning models memorise their training data. This is not a software bug — it is an inherent property of gradient-based optimisation. A model trained on sensitive data (medical records, financial transactions, private communications) can leak that data through:

- **Membership inference attacks:** Given a data point, an adversary can determine with high confidence whether it was in the training set. For a medical model, this reveals that a specific patient was treated for a specific condition.
- **Training data extraction:** A language model can be prompted to reproduce exact training examples — credit card numbers, social security numbers, verbatim private messages — when those examples appear multiple times in training data.
- **Model inversion:** An adversary with query access to a model can reconstruct approximate training examples. This is especially concerning for face recognition models trained on private images.

The standard ML workflow has no defence against these attacks. Regularisation, dropout, and early stopping reduce overfitting but do not provide measurable privacy guarantees — they reduce the probability of memorisation but cannot bound it.

Differential privacy (DP) provides a mathematical guarantee: a model trained with (ε, δ)-DP cannot leak information about any individual training example beyond a bounded amount. The guarantee is composable and auditable — you can state precisely how much privacy budget was consumed.

The practical cost is accuracy: DP training adds noise to gradients, which slows convergence and reduces model quality. The noise-accuracy trade-off is the central engineering challenge in DP ML.

**Target systems:** DP-SGD via Opacus 1.4+ (PyTorch) and TensorFlow Privacy 0.9+; Google's DP library for tabular models; mechanisms for fine-tuning LLMs with DP guarantees; privacy accounting with Rényi DP and PRV accountants.

## Threat Model

- **Adversary 1 — Membership inference attack:** An adversary who can query the trained model or observe its loss values determines which individuals were in the training set. For a model trained on patient data, this reveals medical history.
- **Adversary 2 — Training data extraction:** An adversary queries a language model with prompts designed to elicit memorised training examples. The model reproduces PII, trade secrets, or sensitive text from training data.
- **Adversary 3 — Model inversion:** An adversary with repeated query access to the model reconstructs approximate representations of training examples — faces from a recognition model, text from a sentiment model.
- **Adversary 4 — Gradient leakage during federated training:** In federated learning, model gradients are shared with a central server. An adversary observing gradients can reconstruct the training data batch that produced those gradients (gradient inversion).
- **Access level:** Adversaries 1 and 2 need inference API access. Adversary 3 needs many inference queries. Adversary 4 operates within a federated training setup.
- **Objective:** Extract private training data, identify data contributors, reconstruct sensitive examples.
- **Blast radius:** A model trained on HIPAA-covered data without DP that leaks membership information is a HIPAA breach. A language model that reproduces PII from training data can expose millions of individuals.

## Configuration

### Step 1: Understanding ε and δ

(ε, δ)-differential privacy means: for any two training datasets differing in exactly one individual's data, the probability that the trained model produces any given output differs by at most a factor of e^ε, with probability 1-δ.

Practical interpretation:

| ε value | Privacy level | Typical use case |
|---------|--------------|-----------------|
| ε < 1   | Strong privacy | Census data, medical records |
| 1 ≤ ε ≤ 10 | Moderate privacy | Most ML applications with sensitive data |
| 10 < ε ≤ 100 | Weak privacy | Still meaningful; better than no DP |
| ε > 100 | Negligible privacy | DP in name only |

δ should be less than 1/n where n is the training set size — typically 10^-5 or smaller.

The privacy budget ε is consumed across training steps. Tracking consumption requires a privacy accountant.

### Step 2: DP-SGD with Opacus (PyTorch)

Opacus implements DP-SGD, which clips per-sample gradients and adds Gaussian noise:

```python
import torch
from opacus import PrivacyEngine
from opacus.validators import ModuleValidator
from torch.utils.data import DataLoader

# Validate and fix model compatibility with Opacus.
# Some layers (BatchNorm) are not DP-compatible; replace with GroupNorm.
model = MyModel()
model = ModuleValidator.fix(model)   # Replaces BatchNorm with GroupNorm.
errors = ModuleValidator.validate(model, strict=False)
assert not errors, f"Model has DP-incompatible layers: {errors}"

optimizer = torch.optim.SGD(model.parameters(), lr=0.05)

# DP-specific parameters.
TARGET_EPSILON = 3.0          # Privacy budget.
TARGET_DELTA = 1e-5           # Must be < 1/training_set_size.
MAX_GRAD_NORM = 1.0           # Gradient clipping bound (sensitivity).
EPOCHS = 10

# Attach PrivacyEngine to model, optimizer, and data loader.
privacy_engine = PrivacyEngine()
model, optimizer, train_loader = privacy_engine.make_private_with_epsilon(
    module=model,
    optimizer=optimizer,
    data_loader=DataLoader(train_dataset, batch_size=256, shuffle=True),
    epochs=EPOCHS,
    target_epsilon=TARGET_EPSILON,
    target_delta=TARGET_DELTA,
    max_grad_norm=MAX_GRAD_NORM,
)

# Training loop — same as standard PyTorch.
for epoch in range(EPOCHS):
    for batch_x, batch_y in train_loader:
        optimizer.zero_grad()
        predictions = model(batch_x)
        loss = criterion(predictions, batch_y)
        loss.backward()
        optimizer.step()

    # Report privacy budget consumed this epoch.
    epsilon = privacy_engine.get_epsilon(TARGET_DELTA)
    print(f"Epoch {epoch}: ε = {epsilon:.2f} (target: {TARGET_EPSILON})")
    # Stop training if budget is exhausted.
    if epsilon >= TARGET_EPSILON:
        print("Privacy budget exhausted; stopping training.")
        break
```

Key parameters and their effect on the privacy-accuracy trade-off:

```python
# Noise multiplier: higher = more noise = stronger privacy = lower accuracy.
# Opacus calculates this from target_epsilon, target_delta, and epochs.
# You can set it manually for precise control:
model, optimizer, train_loader = privacy_engine.make_private(
    module=model,
    optimizer=optimizer,
    data_loader=train_loader,
    noise_multiplier=1.0,       # σ parameter. Higher = more privacy, less accuracy.
    max_grad_norm=1.0,
)

# Gradient clipping bound: limits how much one sample can influence gradients.
# Lower = less sensitivity = less noise needed for same privacy.
# Too low = gradients always clipped = slow convergence.
# Tune by inspecting the fraction of clipped gradients:
# target: ~50% clipped at max_grad_norm.
```

### Step 3: DP Fine-Tuning for LLMs

Fine-tuning an LLM with DP is computationally intensive but provides strong guarantees against training data extraction:

```python
from transformers import AutoModelForCausalLM, AutoTokenizer
from opacus import PrivacyEngine
from opacus.validators import ModuleValidator
import torch

# Load pre-trained LLM.
model = AutoModelForCausalLM.from_pretrained("gpt2")
tokenizer = AutoTokenizer.from_pretrained("gpt2")

# DP-compatible modification: freeze most layers, fine-tune only the head.
# Fine-tuning fewer parameters reduces the noise needed for the same privacy.
for param in model.parameters():
    param.requires_grad_(False)
# Unfreeze only the last 2 transformer blocks and language model head.
for block in model.transformer.h[-2:]:
    for param in block.parameters():
        param.requires_grad_(True)
for param in model.lm_head.parameters():
    param.requires_grad_(True)

# Validate and fix for Opacus compatibility.
model = ModuleValidator.fix(model)

optimizer = torch.optim.AdamW(
    filter(lambda p: p.requires_grad, model.parameters()),
    lr=5e-5
)

privacy_engine = PrivacyEngine()
model, optimizer, train_loader = privacy_engine.make_private_with_epsilon(
    module=model,
    optimizer=optimizer,
    data_loader=train_loader,
    epochs=3,
    target_epsilon=8.0,    # ε=8 is a common LLM fine-tuning target.
    target_delta=1e-5,
    max_grad_norm=0.1,     # Lower clipping for LLMs: less gradient norm variation.
)
```

For very large models, use LoRA (Low-Rank Adaptation) with DP — fine-tune only a small number of adapter parameters:

```python
from peft import LoraConfig, get_peft_model
from opacus import PrivacyEngine

# Add LoRA adapters (typically <1% of original parameters).
lora_config = LoraConfig(
    r=8,
    lora_alpha=32,
    target_modules=["q_proj", "v_proj"],
    lora_dropout=0.05,
    bias="none",
)
model = get_peft_model(base_model, lora_config)

# Only LoRA parameters are trained — far fewer parameters means
# much lower noise needed for the same ε.
privacy_engine = PrivacyEngine()
model, optimizer, train_loader = privacy_engine.make_private_with_epsilon(
    module=model,
    optimizer=optimizer,
    data_loader=train_loader,
    epochs=5,
    target_epsilon=3.0,    # Achievable with LoRA; hard with full fine-tuning.
    target_delta=1e-5,
    max_grad_norm=1.0,
)
```

### Step 4: Privacy Accounting and Audit

Track and log the privacy budget spent across all training runs:

```python
# privacy_audit/accountant.py
import json
from datetime import datetime, UTC
from pathlib import Path
from opacus.accountants import RDPAccountant

class PrivacyBudgetLedger:
    """Track cumulative privacy budget consumption across training runs."""

    def __init__(self, ledger_path: str, max_epsilon: float, delta: float):
        self.ledger_path = Path(ledger_path)
        self.max_epsilon = max_epsilon
        self.delta = delta
        self.history = self._load()

    def _load(self) -> list:
        if self.ledger_path.exists():
            return json.loads(self.ledger_path.read_text())
        return []

    def record_run(self, run_id: str, epsilon: float, noise_multiplier: float,
                   max_grad_norm: float, steps: int, dataset_name: str):
        entry = {
            "run_id": run_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "epsilon_consumed": epsilon,
            "noise_multiplier": noise_multiplier,
            "max_grad_norm": max_grad_norm,
            "steps": steps,
            "dataset": dataset_name,
        }
        self.history.append(entry)
        self.ledger_path.write_text(json.dumps(self.history, indent=2))

        total = sum(e["epsilon_consumed"] for e in self.history)
        if total > self.max_epsilon:
            raise ValueError(
                f"Privacy budget exhausted: {total:.2f} > {self.max_epsilon} "
                f"for dataset {dataset_name}. No further training permitted."
            )
        return total

    def remaining_budget(self) -> float:
        total_spent = sum(e["epsilon_consumed"] for e in self.history)
        return self.max_epsilon - total_spent
```

### Step 5: TensorFlow Privacy (Alternative)

For TensorFlow/Keras workflows:

```python
import tensorflow as tf
from tensorflow_privacy.optimizers.dp_optimizer_keras import make_keras_optimizer_class
from tensorflow_privacy.privacy.analysis import compute_dp_sgd_privacy

# Create DP optimizer.
DPAdam = make_keras_optimizer_class(tf.keras.optimizers.Adam)

dp_optimizer = DPAdam(
    l2_norm_clip=1.0,           # Gradient clipping bound.
    noise_multiplier=1.1,       # Gaussian noise σ.
    num_microbatches=256,       # Process gradients per example, then aggregate.
    learning_rate=0.001,
)

model.compile(
    optimizer=dp_optimizer,
    loss=tf.keras.losses.SparseCategoricalCrossentropy(from_logits=True),
    metrics=["accuracy"],
)

model.fit(train_dataset, epochs=60, validation_data=test_dataset)

# Compute ε spent.
epsilon, best_alpha = compute_dp_sgd_privacy.compute_dp_sgd_privacy(
    n=60000,                    # Training set size.
    batch_size=256,
    noise_multiplier=1.1,
    epochs=60,
    delta=1e-5,
)
print(f"ε = {epsilon:.2f} at δ = 1e-5 (α = {best_alpha})")
```

### Step 6: Privacy Auditing with Membership Inference

After training, empirically validate the DP guarantee using membership inference:

```python
# privacy_audit/audit.py
import numpy as np
from sklearn.model_selection import train_test_split

def run_membership_inference_audit(
    model,
    train_data,
    test_data,
    n_shadow_models: int = 10,
) -> float:
    """
    Shadow model membership inference attack.
    Returns AUC-ROC: 0.5 = perfect privacy, 1.0 = full memorisation.
    """
    from sklearn.metrics import roc_auc_score

    train_losses = get_losses(model, train_data)  # Members.
    test_losses = get_losses(model, test_data)    # Non-members.

    # Members typically have lower loss (memorised).
    labels = np.concatenate([
        np.ones(len(train_losses)),    # 1 = member.
        np.zeros(len(test_losses)),    # 0 = non-member.
    ])
    scores = np.concatenate([
        -train_losses,                 # Negate: lower loss = higher score.
        -test_losses,
    ])

    auc = roc_auc_score(labels, scores)
    print(f"Membership inference AUC: {auc:.4f}")
    print(f"  0.50 = perfect privacy (random guessing)")
    print(f"  1.00 = complete memorisation")
    # With DP training at ε=3, expect AUC ≈ 0.52-0.55.
    return auc
```

### Step 7: Deploying with Privacy Documentation

Document the DP guarantee in a model card:

```yaml
# model-card.yaml — append privacy section.
model_privacy:
  mechanism: "DP-SGD (Opacus 1.4)"
  epsilon: 3.0
  delta: 1.0e-5
  max_grad_norm: 1.0
  noise_multiplier: 1.2
  training_set_size: 50000
  guarantee: >
    This model was trained with (ε=3.0, δ=1e-5)-differential privacy.
    The probability that any individual's data contributed more than e^3.0
    times to any model output is bounded by 1e-5. This provides protection
    against membership inference and training data extraction attacks.
  membership_inference_auc: 0.53    # Empirically measured.
  caveats: >
    DP guarantee applies to the training process only. Post-training fine-tuning
    or continued training consumes additional privacy budget. Total budget across
    all training runs: 3.0 epsilon. No further training on this dataset is permitted.
```

### Step 8: Telemetry

```
dp_training_epsilon_consumed{model, dataset, run_id}      gauge
dp_training_budget_remaining{dataset}                     gauge
dp_gradient_clip_fraction{model, layer}                   gauge
dp_noise_multiplier{model}                                gauge
dp_membership_inference_auc{model}                        gauge
dp_training_accuracy_delta{model}                         gauge (vs non-DP baseline)
```

Alert on:

- `dp_training_budget_remaining{dataset}` approaches zero — additional training runs will exhaust the privacy budget; require approval before proceeding.
- `dp_membership_inference_auc` > 0.60 — empirical audit suggests higher memorisation than expected for the stated ε; investigate training configuration.
- `dp_gradient_clip_fraction` > 0.90 — almost all gradients are being clipped; `max_grad_norm` is too low; model is not learning effectively.
- Any training run against a DP-protected dataset without registering epsilon consumption in the ledger — privacy budget accounting failure.

## Expected Behaviour

| Signal | Standard training | DP training (ε=3) |
|--------|------------------|-------------------|
| Membership inference AUC | 0.65-0.80 (memorisation evident) | ~0.52 (close to random guessing) |
| Training data extraction | Possible for repeated examples | Probabilistic bound prevents reliable extraction |
| Model accuracy | Baseline | Typically 1-5% lower (dataset/task dependent) |
| Training time | Baseline | 2-5× slower (per-sample gradient computation) |
| Privacy guarantee | None (informal "regularisation helps") | Mathematical (ε, δ)-bound on information leakage |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| DP-SGD on full model | Strongest guarantee | 2-5× training time; 1-10% accuracy loss | Use LoRA/adapter fine-tuning to reduce parameters and required noise |
| Low ε (strong privacy) | Strong guarantee | Significant accuracy degradation | Choose ε based on data sensitivity; medical data warrants ε<1, analytics data tolerates ε=10 |
| Privacy budget ledger | Prevents unlimited training on same data | Operational overhead; training runs require registration | Automate via training pipeline integration |
| Membership inference audit | Empirical validation of DP guarantee | Requires test set split; adds evaluation step | Automate as part of model evaluation pipeline |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Budget exhausted mid-training | Training halted; model not converged | Budget ledger raises exception | Pre-calculate required ε before starting; use larger budget allocation or smaller ε per run |
| max_grad_norm too low | Model fails to learn; accuracy plateaus near chance | `dp_gradient_clip_fraction` > 0.90; low training accuracy | Increase max_grad_norm; more clipping means more noise required for same ε |
| DP-incompatible layer | Opacus raises ModuleNotSupportedError | Immediate error at make_private() | Use ModuleValidator.fix() to replace BatchNorm with GroupNorm before attaching PrivacyEngine |
| Epsilon calculation error | Model deployed with incorrect ε claim | Audit detects higher AUC than expected for stated ε | Recompute ε with correct training parameters; update model card |
| Non-DP fine-tuning after DP training | Privacy guarantee invalidated | No automated detection without ledger enforcement | Enforce ledger requirement for all fine-tuning runs on protected datasets |

## Related Articles

- [Membership Inference Defence](/articles/ai-landscape/membership-inference-defence/)
- [Federated Learning Security](/articles/ai-landscape/federated-learning-security/)
- [Privacy-Preserving ML Inference](/articles/ai-landscape/privacy-preserving-ml-inference/)
- [Training Data Extraction Attacks and Defences](/articles/ai-landscape/training-data-extraction/)
- [AI Model Weight Security](/articles/ai-landscape/ai-model-weight-security/)
