---
title: "AI Model Cards in Production: Documenting Capabilities, Limitations, and Security Properties"
description: "Every production AI model has boundaries: input domains where it performs well, edge cases where it fails, and security properties that constrain how..."
slug: "ai-model-cards"
date: 2026-02-02
lastmod: 2026-02-02
category: "ai-landscape"
tags: ["model-cards", "ai-governance", "documentation", "supply-chain", "ml-ops"]
personas: ["ai-ml-engineer", "security-engineer", "platform-engineer"]
article_number: 122
difficulty: "intermediate"
estimated_reading_time: 16
provider_bridges:
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
  - name: "Vanta"
    id: 169
    category: "compliance"
  - name: "Axiom"
    id: 112
    category: "observability"
premium_pack: "model-card-templates-pack"
published: true
layout: article.njk
permalink: "/articles/ai-landscape/ai-model-cards/index.html"
---

# AI Model Cards in Production: Documenting Capabilities, Limitations, and Security Properties

## Problem

Every production AI model has boundaries: input domains where it performs well, edge cases where it fails, and security properties that constrain how it should be deployed. These boundaries exist whether or not anyone documents them. Undocumented boundaries become production incidents.

A model card is a structured document that travels with the model artifact. It declares what the model can do, what it cannot do, and what it should never be asked to do. The concept originated in a 2019 Google research paper, but most implementations remain academic. They describe models for research publication, not for production deployment.

Production model cards must answer questions that research model cards ignore. Can this model be exposed to untrusted input? What happens when input distribution shifts? Has the model been tested for adversarial robustness? What data was used for training, and does that create legal exposure? Can the model produce outputs that violate content policies?

Without machine-readable model cards enforced at deployment time, teams deploy models they do not fully understand into environments where failures cause real harm. The model that scores 94% accuracy on the test set may score 60% on the population it actually encounters in production, and nobody discovers this until a customer complains.

## Threat Model

- **Adversary:** Operational risk from deploying models outside their validated boundaries. Attackers who exploit undocumented model weaknesses.
- **Key requirements:** (1) Every model in production has a machine-readable model card. (2) Deployment pipelines validate that the deployment context matches the model's documented capabilities. (3) Security properties are explicit and enforceable.
- **Failure scenario:** A model trained on English-language financial documents is deployed to process multilingual input. Performance degrades silently. Downstream decisions based on low-confidence outputs cause financial losses before anyone notices.

## Configuration

### Model Card Schema

Define a schema that is both human-readable and machine-parseable. YAML works well because it lives in version control alongside the model code.

```yaml
# model-card.yaml
# This file is stored in the model's artifact registry alongside the model weights.
# It is validated at build time and checked at deployment time.

schema_version: "1.0"
model_id: "fraud-detection-v4"
model_version: "4.1.2"
model_hash: "sha256:a3f2c1d8e9b0..."

# Section 1: Model Details
model_details:
  name: "Transaction Fraud Detection Model"
  architecture: "transformer_encoder"
  framework: "PyTorch 2.3"
  task: "binary_classification"
  created_date: "2026-03-15"
  created_by: "ml-platform-team"
  license: "proprietary"
  contact: "ml-platform@company.com"

# Section 2: Training Data Provenance
training_data:
  sources:
    - name: "internal_transaction_history"
      records: 18000000
      date_range: "2022-01-01 to 2025-12-31"
      geographic_scope: ["US", "EU", "UK"]
      pii_handling: "tokenised_before_training"
      consent_basis: "legitimate_interest"
    - name: "synthetic_fraud_samples"
      records: 500000
      generation_method: "rule_based_augmentation"
      purpose: "address_class_imbalance"
  preprocessing:
    - "currency_normalisation_to_usd"
    - "transaction_amount_log_scaling"
    - "merchant_category_encoding"
  excluded_features:
    - "customer_name"
    - "customer_address"
    - "customer_ethnicity"
    - "customer_gender"

# Section 3: Intended Use
intended_use:
  primary_use: "Flag potentially fraudulent card transactions for human review"
  intended_users: ["fraud_operations_team"]
  deployment_context:
    - "real_time_transaction_scoring"
    - "batch_retroactive_analysis"
  out_of_scope_uses:
    - "autonomous_transaction_blocking_without_human_review"
    - "customer_creditworthiness_assessment"
    - "law_enforcement_investigation"

# Section 4: Performance
performance:
  primary_metric: "f1_score"
  evaluation_datasets:
    - name: "holdout_test_set"
      records: 2000000
      metrics:
        accuracy: 0.967
        precision: 0.91
        recall: 0.94
        f1_score: 0.925
        auc_roc: 0.98
    - name: "production_shadow_30d"
      records: 45000000
      metrics:
        accuracy: 0.959
        precision: 0.87
        recall: 0.92
        f1_score: 0.894
        auc_roc: 0.97
  performance_boundaries:
    - condition: "transaction_amount_below_5_usd"
      impact: "precision drops to 0.72 due to limited training samples"
    - condition: "cryptocurrency_merchant_category"
      impact: "recall drops to 0.68; category underrepresented in training data"
    - condition: "non_usd_eur_gbp_currencies"
      impact: "f1 drops to 0.81; currency normalisation introduces noise"

# Section 5: Fairness
fairness:
  tested_dimensions:
    - dimension: "geographic_region"
      metric: "equalised_odds_difference"
      result: 0.04
      threshold: 0.05
      status: "pass"
    - dimension: "transaction_amount_quartile"
      metric: "demographic_parity_difference"
      result: 0.08
      threshold: 0.05
      status: "fail_monitored"
      mitigation: "additional training data collection for Q1 transactions in progress"

# Section 6: Known Failure Modes
failure_modes:
  - name: "novel_fraud_pattern"
    description: "Model cannot detect fraud patterns not present in training data"
    likelihood: "medium"
    impact: "high"
    mitigation: "quarterly retraining; human review of low-confidence scores"
  - name: "adversarial_transaction_structuring"
    description: "Attackers split transactions to stay below detection thresholds"
    likelihood: "high"
    impact: "medium"
    mitigation: "session-level aggregation model runs in parallel"
  - name: "data_pipeline_schema_drift"
    description: "Upstream data format changes cause silent input corruption"
    likelihood: "low"
    impact: "critical"
    mitigation: "Great Expectations validation on every input batch"

# Section 7: Security Properties
security:
  adversarial_robustness:
    tested: true
    method: "FGSM and PGD perturbations on numerical features"
    result: "accuracy degrades less than 3% under l-inf perturbation of 0.1"
  input_validation:
    schema_enforced: true
    max_input_size: "4KB"
    allowed_types: ["float64", "int64", "categorical"]
    injection_protection: "input features are numerical; no free-text fields"
  model_artifact_integrity:
    signing: "cosign"
    signature_verification: "required_at_deployment"
    artifact_registry: "internal_oci_registry"
  data_exfiltration_risk: "low"
  prompt_injection_applicable: false
```

### Model Card Validation in CI/CD

```python
# validate_model_card.py
# Runs in CI/CD to ensure every model has a complete, valid model card.

import yaml
import sys
import json

REQUIRED_SECTIONS = [
    "schema_version", "model_id", "model_version", "model_hash",
    "model_details", "training_data", "intended_use",
    "performance", "failure_modes", "security"
]

REQUIRED_SECURITY_FIELDS = [
    "adversarial_robustness", "input_validation",
    "model_artifact_integrity"
]

REQUIRED_PERFORMANCE_FIELDS = [
    "primary_metric", "evaluation_datasets", "performance_boundaries"
]

def validate(card_path: str) -> list:
    """Validate a model card for production readiness."""
    with open(card_path) as f:
        card = yaml.safe_load(f)

    errors = []

    # Check required top-level sections
    for section in REQUIRED_SECTIONS:
        if section not in card:
            errors.append(f"Missing required section: {section}")

    # Check security section completeness
    if "security" in card:
        for field in REQUIRED_SECURITY_FIELDS:
            if field not in card["security"]:
                errors.append(f"Missing security field: {field}")
        if card["security"].get("adversarial_robustness", {}).get("tested") is False:
            errors.append("Adversarial robustness testing has not been performed")

    # Check performance section
    if "performance" in card:
        for field in REQUIRED_PERFORMANCE_FIELDS:
            if field not in card["performance"]:
                errors.append(f"Missing performance field: {field}")
        if not card["performance"].get("performance_boundaries"):
            errors.append("No performance boundaries documented")

    # Check training data provenance
    if "training_data" in card:
        sources = card["training_data"].get("sources", [])
        if not sources:
            errors.append("No training data sources documented")
        for source in sources:
            if "pii_handling" not in source and "generation_method" not in source:
                errors.append(f"Training data source '{source.get('name')}' missing pii_handling")

    # Check failure modes
    if "failure_modes" in card:
        for mode in card["failure_modes"]:
            if "mitigation" not in mode:
                errors.append(f"Failure mode '{mode.get('name')}' has no mitigation documented")

    return errors

if __name__ == "__main__":
    card_path = sys.argv[1]
    errors = validate(card_path)

    if errors:
        print(f"Model card validation FAILED with {len(errors)} errors:")
        for error in errors:
            print(f"  - {error}")
        sys.exit(1)
    else:
        print("Model card validation PASSED")
```

### Deployment-Time Boundary Check

The model card is not just documentation. It enforces boundaries at deployment time.

```python
# deployment_boundary_check.py
# Runs as a Kubernetes admission webhook or pre-deployment hook.
# Compares the deployment context against the model card's intended use.

import yaml
import sys

def check_deployment_boundaries(card_path: str, deployment_config: dict) -> list:
    """Verify that a deployment context matches model card boundaries."""
    with open(card_path) as f:
        card = yaml.safe_load(f)

    violations = []
    intended = card.get("intended_use", {})

    # Check deployment context is within scope
    allowed_contexts = intended.get("deployment_context", [])
    requested_context = deployment_config.get("context")
    if requested_context and requested_context not in allowed_contexts:
        violations.append(
            f"Deployment context '{requested_context}' not in allowed contexts: {allowed_contexts}"
        )

    # Check for out-of-scope uses
    out_of_scope = intended.get("out_of_scope_uses", [])
    declared_use = deployment_config.get("use_case")
    if declared_use in out_of_scope:
        violations.append(
            f"Use case '{declared_use}' is explicitly out of scope for this model"
        )

    # Check model artifact integrity
    security = card.get("security", {})
    integrity = security.get("model_artifact_integrity", {})
    if integrity.get("signature_verification") == "required_at_deployment":
        if not deployment_config.get("signature_verified"):
            violations.append("Model artifact signature not verified")

    # Check geographic scope if applicable
    training_sources = card.get("training_data", {}).get("sources", [])
    deployment_region = deployment_config.get("region")
    if deployment_region:
        all_scopes = set()
        for source in training_sources:
            scope = source.get("geographic_scope", [])
            if isinstance(scope, list):
                all_scopes.update(scope)
            else:
                all_scopes.add(scope)
        if all_scopes and deployment_region not in all_scopes:
            violations.append(
                f"Deployment region '{deployment_region}' outside training data scope: {all_scopes}"
            )

    return violations

if __name__ == "__main__":
    card_path = sys.argv[1]
    deployment = {
        "context": sys.argv[2] if len(sys.argv) > 2 else None,
        "use_case": sys.argv[3] if len(sys.argv) > 3 else None,
        "region": sys.argv[4] if len(sys.argv) > 4 else None,
        "signature_verified": True
    }
    violations = check_deployment_boundaries(card_path, deployment)
    if violations:
        print("DEPLOYMENT BLOCKED - boundary violations:")
        for v in violations:
            print(f"  - {v}")
        sys.exit(1)
    print("Deployment boundaries check PASSED")
```

### Performance Boundary Monitoring

After deployment, continuously monitor whether the model is operating within its documented boundaries.

```yaml
# prometheus-rules-model-boundaries.yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: model-boundary-alerts
  namespace: monitoring
spec:
  groups:
    - name: model-card-boundaries
      interval: 60s
      rules:
        # Alert when model serves input outside documented boundaries
        - alert: ModelInputOutsideBoundary
          expr: |
            sum(rate(model_input_boundary_violation_total[5m])) by (model_id, boundary_name) > 0
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "Model {{ $labels.model_id }} receiving input outside documented boundary: {{ $labels.boundary_name }}"
            runbook: "Check model card performance_boundaries section. Evaluate if model is safe for this input domain."

        # Alert when model performance drifts below documented metrics
        - alert: ModelPerformanceBelowCard
          expr: |
            model_live_f1_score < on(model_id) model_card_documented_f1_score * 0.95
          for: 15m
          labels:
            severity: critical
          annotations:
            summary: "Model {{ $labels.model_id }} live F1 score is below 95% of documented model card value"
            runbook: "Investigate input distribution shift. Compare live data profile against training data profile."

        # Alert when confidence distribution shifts
        - alert: ModelConfidenceDistributionShift
          expr: |
            histogram_quantile(0.5, rate(model_output_confidence_bucket[1h])) < 0.7
          for: 30m
          labels:
            severity: warning
          annotations:
            summary: "Median model confidence dropped below 0.7, indicating potential distribution shift"
```

### Model Card Registry API

```python
# model_card_registry.py
# Simple registry that stores and serves model cards.
# Integrates with artifact registries (OCI, MLflow).

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import yaml
import hashlib
from pathlib import Path

app = FastAPI(title="Model Card Registry")
CARDS_DIR = Path("/data/model-cards")

@app.get("/cards/{model_id}/{model_version}")
def get_card(model_id: str, model_version: str):
    """Retrieve a model card by model ID and version."""
    card_path = CARDS_DIR / model_id / f"{model_version}.yaml"
    if not card_path.exists():
        raise HTTPException(status_code=404, detail="Model card not found")
    with open(card_path) as f:
        return yaml.safe_load(f)

@app.get("/cards/{model_id}/{model_version}/security")
def get_security_properties(model_id: str, model_version: str):
    """Return only the security section for quick deployment checks."""
    card = get_card(model_id, model_version)
    return card.get("security", {})

@app.get("/cards/{model_id}/{model_version}/boundaries")
def get_boundaries(model_id: str, model_version: str):
    """Return performance boundaries and intended use for deployment validation."""
    card = get_card(model_id, model_version)
    return {
        "intended_use": card.get("intended_use", {}),
        "performance_boundaries": card.get("performance", {}).get("performance_boundaries", []),
        "failure_modes": card.get("failure_modes", [])
    }
```

## Expected Behaviour

- Every model artifact in the registry has an accompanying model card validated against the schema
- CI/CD pipeline rejects model artifacts with missing or incomplete model cards
- Deployment pipeline validates that the target deployment context matches the model card's intended use
- Models deployed outside their documented geographic scope or use case are blocked automatically
- Performance monitoring alerts fire when live metrics drift below model card documented values
- Security properties (adversarial robustness, input validation, artifact signing) are verifiable at any time
- Model cards are versioned alongside model code and artifacts

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Mandatory model cards in CI/CD | Every model is documented before deployment | ML engineers spend 30-60 minutes per model version writing and updating cards | Provide templates. Auto-populate fields from training metadata where possible. |
| Deployment boundary checking | Prevents models from serving outside their validated domain | False positives block legitimate deployments when use cases evolve | Allow boundary overrides with explicit sign-off and documented justification. |
| Performance boundary monitoring | Catches distribution shift before it causes harm | Alert fatigue if boundaries are set too tightly | Set boundaries at 95% of documented metrics. Tune per-model based on operational experience. |
| Model card registry API | Centralised, queryable model documentation | Another service to maintain and keep available | Deploy as a lightweight FastAPI service. Back with a file system or object storage. No database required. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Model card does not match actual model behaviour | Card says accuracy is 0.96, live accuracy is 0.85 | Performance monitoring detects drift from card values | Investigate. Update card if model was retrained. Retrain if model degraded. |
| Deployment boundary check has false positive | Legitimate deployment blocked | Engineering team escalates blocked deployment | Review boundary definitions. Add the new context to intended_use if validated. |
| Model card schema evolves but old cards not migrated | Old models missing newly required fields | Validation pipeline fails for old model versions | Schema migration script updates existing cards. Add defaults for new required fields. |
| Training data provenance is incomplete | Card lists sources but not PII handling or consent basis | Model card validation catches missing fields | Work with data governance team to document provenance retroactively. |

## When to Consider a Managed Alternative

Model card management becomes complex when organisations operate dozens of models across multiple teams and deployment environments.

- **[Vanta](https://www.vanta.com):** Integrates model card documentation into broader compliance workflows. Tracks which models have complete documentation and flags gaps.
- **[Grafana Cloud](https://grafana.com/cloud):** Dashboards that overlay model card documented metrics against live performance metrics. Visual boundary monitoring across all models.
- **[Axiom](https://axiom.co):** Store and query model card change history. Track which card version was active when an incident occurred.

**Premium content pack:** Model card templates pack. Complete YAML schemas for classification, NLP, computer vision, and generative models. CI/CD validation scripts (Python), deployment boundary checker, [Prometheus](https://prometheus.io) alert rules for performance boundary monitoring, and FastAPI model card registry with OCI artifact integration.


## Related Articles

- [EU AI Act Compliance for Infrastructure Teams: Risk Classification, Documentation, and Technical Controls](/articles/ai-landscape/eu-ai-act-compliance/)
- [Building an AI Governance Pipeline: Automated Checks from Training to Production](/articles/ai-landscape/ai-governance-pipeline/)
- [Algorithmic Auditing: Testing AI Systems for Bias, Fairness, and Safety Before Deployment](/articles/ai-landscape/algorithmic-auditing/)
- [Claude, Mythos, and the Non-Human Infrastructure Consumer: Writing Hardening Guides for AI Agents](/articles/ai-landscape/claude-non-human-consumers/)
- [Auditing AI Actions at Scale: Building Tamper-Proof Logs for Non-Human Actors](/articles/ai-landscape/auditing-ai-actions/)
