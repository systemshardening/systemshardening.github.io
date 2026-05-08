---
title: "Building an AI Governance Pipeline: Automated Checks from Training to Production"
description: "AI governance in most organisations is a manual process. A model is trained, someone writes a document, a committee meets, approvals are collected..."
slug: "ai-governance-pipeline"
date: 2026-04-08
lastmod: 2026-04-08
category: "ai-landscape"
tags: ["ai-governance", "governance-as-code", "ml-pipeline", "compliance-automation", "model-approval"]
personas: ["platform-engineer", "ai-ml-engineer", "compliance-lead"]
article_number: 125
difficulty: "advanced"
estimated_reading_time: 19
provider_bridges:
  - name: "Vanta"
    id: 169
    category: "compliance"
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
  - name: "Axiom"
    id: 112
    category: "observability"
premium_pack: "ai-governance-pipeline-pack"
published: true
layout: article.njk
permalink: "/articles/ai-landscape/ai-governance-pipeline/index.html"
---

# Building an AI Governance Pipeline: Automated Checks from Training to Production

## Problem

AI governance in most organisations is a manual process. A model is trained, someone writes a document, a committee meets, approvals are collected via email or Slack, and the model ships. The governance artifacts (if they exist) are disconnected from the model artifacts. Nobody can tell you which governance checks were applied to the model currently serving traffic in production.

This disconnect creates two problems. First, governance becomes a bottleneck. ML engineers wait days or weeks for approvals while models that could be improving production systems sit in staging. Second, governance becomes theatrical. Documents are written to satisfy a process, not to catch real issues. The bias test results in the approval document may not correspond to the model version being deployed.

Governance-as-code solves both problems. Governance checks become automated pipeline stages that run alongside training, evaluation, and deployment. Every model artifact in the registry has a machine-verifiable governance record. The governance record is cryptographically linked to the model artifact it describes. If the model changes, the governance checks re-run automatically.

This approach is not about removing humans from governance decisions. It is about ensuring that humans make decisions based on accurate, current information, and that the evidence supporting those decisions is permanently linked to the model.

## Threat Model

- **Adversary:** Ungoverned models reaching production. Stale governance artifacts that do not match the deployed model. Governance processes that slow delivery without improving safety.
- **Key requirements:** (1) Every model in production has a verifiable governance record. (2) Governance checks run automatically on every model version. (3) Human approval is required for high-risk models, with the approval cryptographically linked to the model artifact. (4) Governance status is visible in real time.
- **Failure scenario:** A model passes governance review for version 3.1. An ML engineer retrains with new data and deploys version 3.2 without re-running governance checks. Version 3.2 has a bias issue that version 3.1 did not, but the governance record shows "approved" because it references version 3.1.

## Configuration

### Governance Pipeline Architecture

The governance pipeline runs as a set of stages in the ML CI/CD pipeline. Each stage produces a signed attestation that is stored alongside the model artifact.

```yaml
# governance-pipeline.yaml
# Defines the governance stages that every model must pass.
# Runs as part of the ML CI/CD pipeline (GitHub Actions, GitLab CI, Argo Workflows).

stages:
  - name: "data_provenance"
    description: "Verify training data sources, lineage, and consent"
    required: true
    checks:
      - "training_data_sources_documented"
      - "pii_handling_verified"
      - "consent_basis_documented"
      - "data_retention_policy_compliant"
    blocking: true

  - name: "model_card"
    description: "Validate model card completeness and accuracy"
    required: true
    checks:
      - "model_card_schema_valid"
      - "performance_metrics_populated"
      - "failure_modes_documented"
      - "security_properties_documented"
      - "intended_use_defined"
    blocking: true

  - name: "bias_and_fairness"
    description: "Run automated bias testing across protected attributes"
    required: true
    checks:
      - "demographic_parity_within_threshold"
      - "equalised_odds_within_threshold"
      - "disparate_impact_ratio_above_minimum"
    blocking: true

  - name: "safety_evaluation"
    description: "Test for adversarial robustness and edge case handling"
    required: true
    checks:
      - "adversarial_perturbation_test_passed"
      - "edge_case_inputs_handled"
      - "output_boundary_verified"
    blocking: true

  - name: "security_review"
    description: "Verify model artifact integrity and deployment security"
    required: true
    checks:
      - "model_artifact_signed"
      - "inference_endpoint_tls_configured"
      - "input_validation_configured"
      - "rate_limiting_configured"
    blocking: true

  - name: "risk_classification"
    description: "Classify model by regulatory risk tier"
    required: true
    checks:
      - "risk_tier_assigned"
      - "required_controls_for_tier_present"
    blocking: true

  - name: "human_approval"
    description: "Human review and sign-off for high-risk models"
    required_for_risk_tiers: ["high_risk"]
    approval_roles: ["ml_lead", "compliance_officer"]
    blocking: true
```

### Governance-as-Code Implementation

```python
# governance_runner.py
# Executes governance checks and produces signed attestations.

import hashlib
import json
import subprocess
import sys
import yaml
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict

@dataclass
class GovernanceCheck:
    name: str
    stage: str
    passed: bool
    details: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

@dataclass
class GovernanceRecord:
    model_id: str
    model_version: str
    model_hash: str
    pipeline_run_id: str
    checks: list = field(default_factory=list)
    human_approvals: list = field(default_factory=list)

    @property
    def all_passed(self):
        return all(c.passed for c in self.checks)

    @property
    def record_hash(self):
        content = json.dumps(asdict(self), sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

def run_governance_pipeline(
    model_id: str,
    model_version: str,
    model_artifact_path: str,
    pipeline_config_path: str = "governance-pipeline.yaml"
) -> GovernanceRecord:
    """Execute the full governance pipeline for a model."""

    # Compute model artifact hash
    with open(model_artifact_path, "rb") as f:
        model_hash = hashlib.sha256(f.read()).hexdigest()

    with open(pipeline_config_path) as f:
        config = yaml.safe_load(f)

    record = GovernanceRecord(
        model_id=model_id,
        model_version=model_version,
        model_hash=model_hash,
        pipeline_run_id=f"gov-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    )

    for stage in config["stages"]:
        stage_name = stage["name"]
        print(f"\n--- Running governance stage: {stage_name} ---")

        for check_name in stage.get("checks", []):
            result = _execute_check(check_name, model_id, model_version)
            record.checks.append(GovernanceCheck(
                name=check_name,
                stage=stage_name,
                passed=result["passed"],
                details=result["details"]
            ))

            status = "PASS" if result["passed"] else "FAIL"
            print(f"  [{status}] {check_name}: {result['details']}")

            if not result["passed"] and stage.get("blocking", False):
                print(f"\nBLOCKING FAILURE in stage '{stage_name}'. Pipeline halted.")
                return record

    return record

def _execute_check(check_name: str, model_id: str, model_version: str) -> dict:
    """Execute a single governance check. Returns {passed: bool, details: str}."""
    check_script = f"checks/{check_name}.py"
    try:
        result = subprocess.run(
            ["python", check_script, model_id, model_version],
            capture_output=True, text=True, timeout=300
        )
        output = json.loads(result.stdout) if result.stdout else {}
        return {
            "passed": result.returncode == 0,
            "details": output.get("details", result.stderr or "No details")
        }
    except subprocess.TimeoutExpired:
        return {"passed": False, "details": "Check timed out after 300 seconds"}
    except Exception as e:
        return {"passed": False, "details": f"Check execution error: {str(e)}"}

def sign_governance_record(record: GovernanceRecord, key_path: str) -> str:
    """Sign the governance record with cosign for tamper detection."""
    record_json = json.dumps(asdict(record), sort_keys=True)
    record_path = f"/tmp/governance-{record.pipeline_run_id}.json"

    with open(record_path, "w") as f:
        f.write(record_json)

    # Sign with cosign
    subprocess.run([
        "cosign", "sign-blob",
        "--key", key_path,
        "--output-signature", f"{record_path}.sig",
        record_path
    ], check=True)

    return record_path
```

### CI/CD Integration

```yaml
# .github/workflows/ml-governance-pipeline.yaml
name: ML Governance Pipeline

on:
  push:
    paths:
      - 'models/**'
      - 'training/**'

jobs:
  governance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: pip install -r requirements-governance.txt

      - name: Compute model artifact hash
        id: model_hash
        run: |
          HASH=$(sha256sum models/fraud-detection/model.onnx | cut -d' ' -f1)
          echo "hash=$HASH" >> "$GITHUB_OUTPUT"

      - name: Stage 1 - Data Provenance
        run: |
          python checks/training_data_sources_documented.py fraud-detection-v4 4.1.2
          python checks/pii_handling_verified.py fraud-detection-v4 4.1.2
          python checks/consent_basis_documented.py fraud-detection-v4 4.1.2

      - name: Stage 2 - Model Card Validation
        run: |
          python validate_model_card.py models/fraud-detection/model-card.yaml

      - name: Stage 3 - Bias and Fairness Testing
        run: |
          python run_bias_tests.py \
            bias-testing-config.yaml \
            models/fraud-detection/eval-predictions.parquet

      - name: Stage 4 - Safety Evaluation
        run: |
          python safety_evaluations.py \
            --model models/fraud-detection/model.onnx \
            --config safety-eval-config.yaml

      - name: Stage 5 - Security Review
        run: |
          # Verify model artifact is signed
          cosign verify-blob \
            --key cosign.pub \
            --signature models/fraud-detection/model.onnx.sig \
            models/fraud-detection/model.onnx

          # Validate deployment security config
          python checks/deployment_security.py fraud-detection-v4 4.1.2

      - name: Stage 6 - Risk Classification
        id: risk
        run: |
          RESULT=$(python classify_ai_system.py "$(cat models/fraud-detection/metadata.json)")
          echo "risk_tier=$(echo $RESULT | jq -r '.risk_tier')" >> "$GITHUB_OUTPUT"
          echo "$RESULT"

      - name: Stage 7 - Human Approval Gate (high-risk only)
        if: steps.risk.outputs.risk_tier == 'high_risk'
        uses: trstringer/manual-approval@v1
        with:
          secret: ${{ secrets.GITHUB_TOKEN }}
          approvers: ml-leads,compliance-officers
          minimum-approvals: 2
          issue-title: "Governance approval required: fraud-detection-v4 v4.1.2"
          issue-body: |
            Model: fraud-detection-v4 v4.1.2
            Risk tier: high_risk
            Model hash: ${{ steps.model_hash.outputs.hash }}
            All automated governance checks passed.
            Please review the governance report and approve.

      - name: Generate Governance Record
        run: |
          python governance_runner.py \
            --model-id fraud-detection-v4 \
            --model-version 4.1.2 \
            --artifact models/fraud-detection/model.onnx \
            --output governance-record.json

      - name: Sign Governance Record
        run: |
          cosign sign-blob \
            --key ${{ secrets.COSIGN_KEY }} \
            --output-signature governance-record.json.sig \
            governance-record.json

      - name: Store Governance Record
        run: |
          # Store alongside model artifact in registry
          aws s3 cp governance-record.json \
            s3://ml-governance/fraud-detection-v4/4.1.2/governance-record.json
          aws s3 cp governance-record.json.sig \
            s3://ml-governance/fraud-detection-v4/4.1.2/governance-record.json.sig
```

### Model Approval Workflow

```python
# approval_workflow.py
# Manages human approval workflows for high-risk model deployments.

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

class ApprovalStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"

@dataclass
class ApprovalRequest:
    model_id: str
    model_version: str
    model_hash: str
    governance_record_hash: str
    risk_tier: str
    requested_by: str
    required_approvers: list
    required_approvals: int
    approvals: list
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: str = ""
    expires_at: str = ""

class ApprovalManager:
    def __init__(self, storage_backend):
        self.storage = storage_backend

    def create_request(self, model_id: str, model_version: str,
                       model_hash: str, governance_record_hash: str,
                       risk_tier: str, requested_by: str) -> ApprovalRequest:
        """Create a new approval request for a model deployment."""

        # Determine required approvers based on risk tier
        if risk_tier == "high_risk":
            required_approvers = ["ml_lead", "compliance_officer"]
            required_approvals = 2
        else:
            required_approvers = ["ml_lead"]
            required_approvals = 1

        request = ApprovalRequest(
            model_id=model_id,
            model_version=model_version,
            model_hash=model_hash,
            governance_record_hash=governance_record_hash,
            risk_tier=risk_tier,
            requested_by=requested_by,
            required_approvers=required_approvers,
            required_approvals=required_approvals,
            approvals=[],
            created_at=datetime.now(timezone.utc).isoformat(),
            expires_at=""  # Set based on policy
        )

        self.storage.save(request)
        return request

    def approve(self, model_id: str, model_version: str,
                approver_id: str, approver_role: str, comment: str = "") -> dict:
        """Record an approval for a model deployment."""
        request = self.storage.get(model_id, model_version)

        if request.status != ApprovalStatus.PENDING:
            return {"error": f"Request is {request.status.value}, not pending"}

        if approver_role not in request.required_approvers:
            return {"error": f"Role '{approver_role}' is not a required approver"}

        approval = {
            "approver_id": approver_id,
            "approver_role": approver_role,
            "comment": comment,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "governance_record_hash_verified": request.governance_record_hash
        }

        request.approvals.append(approval)

        if len(request.approvals) >= request.required_approvals:
            request.status = ApprovalStatus.APPROVED

        self.storage.save(request)
        return {"status": request.status.value, "approvals": len(request.approvals)}
```

### Continuous Compliance Monitoring

After deployment, continuously verify that the governance record matches the running model.

```yaml
# prometheus-rules-governance.yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: governance-compliance-alerts
  namespace: monitoring
spec:
  groups:
    - name: ai-governance
      interval: 300s
      rules:
        # Alert when a model in production has no governance record
        - alert: ModelMissingGovernanceRecord
          expr: |
            model_serving_active == 1
            unless on(model_id, model_version)
            governance_record_exists == 1
          for: 5m
          labels:
            severity: critical
          annotations:
            summary: "Model {{ $labels.model_id }} v{{ $labels.model_version }} is serving traffic without a governance record"
            runbook: "Block traffic to this model. Run governance pipeline before re-enabling."

        # Alert when governance record hash does not match deployed model hash
        - alert: GovernanceRecordMismatch
          expr: |
            governance_model_hash != on(model_id, model_version) model_deployed_hash
          for: 5m
          labels:
            severity: critical
          annotations:
            summary: "Governance record for {{ $labels.model_id }} does not match deployed artifact hash"
            runbook: "Model may have been modified after governance approval. Investigate immediately."

        # Alert when governance approval has expired
        - alert: GovernanceApprovalExpired
          expr: |
            (time() - governance_approval_timestamp) > 7776000
          for: 1h
          labels:
            severity: warning
          annotations:
            summary: "Governance approval for {{ $labels.model_id }} is older than 90 days"
            runbook: "Re-run governance pipeline to renew approval. Check for regulation or policy changes since last approval."

        # Alert when required governance stage was skipped
        - alert: GovernanceStageSkipped
          expr: |
            governance_required_stages_total - governance_completed_stages_total > 0
          for: 5m
          labels:
            severity: critical
          annotations:
            summary: "Model {{ $labels.model_id }} has {{ $value }} skipped governance stages"
```

### Governance Dashboard

```json
{
  "dashboard": {
    "title": "AI Governance Pipeline",
    "panels": [
      {
        "title": "Models in Production by Governance Status",
        "type": "piechart",
        "targets": [{"expr": "count by (governance_status) (model_serving_active == 1)"}]
      },
      {
        "title": "Governance Pipeline Pass Rate (30d)",
        "type": "stat",
        "targets": [{"expr": "sum(governance_pipeline_passed_total) / sum(governance_pipeline_runs_total)"}]
      },
      {
        "title": "Pending Approvals",
        "type": "stat",
        "targets": [{"expr": "count(governance_approval_status{status='pending'})"}],
        "thresholds": [{"value": 0, "color": "green"}, {"value": 3, "color": "yellow"}, {"value": 5, "color": "red"}]
      },
      {
        "title": "Governance Check Failures by Stage (7d)",
        "type": "barchart",
        "targets": [{"expr": "sum by (stage) (increase(governance_check_failed_total[7d]))"}]
      },
      {
        "title": "Time from Training to Production (P50)",
        "type": "gauge",
        "targets": [{"expr": "histogram_quantile(0.5, rate(model_training_to_production_seconds_bucket[30d]))"}],
        "unit": "hours"
      },
      {
        "title": "Models with Expired Governance Approvals",
        "type": "table",
        "targets": [{"expr": "governance_approval_age_seconds > 7776000"}]
      }
    ]
  }
}
```

## Expected Behaviour

- Every model artifact in the registry has a signed governance record linking it to the exact model hash
- Governance checks run automatically on every model version; no manual steps required for automated checks
- High-risk models require human approval from designated roles before deployment proceeds
- Models deployed without governance records trigger critical alerts within 5 minutes
- Governance record hash mismatches (modified model after approval) trigger critical alerts
- Governance dashboard shows real-time status of all models: governed, pending, expired, or ungoverned
- Average time from training completion to production deployment (including governance) is under 4 hours for low-risk models
- Governance approvals expire after 90 days, requiring re-evaluation

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Blocking governance pipeline in CI/CD | No ungoverned model reaches production | Governance pipeline failures block all ML deployments | Keep governance checks fast (under 10 minutes total). Have an expedited manual override path for urgent fixes with post-hoc documentation. |
| Signed governance records | Tamper-proof link between governance decision and model artifact | Key management overhead; signing adds pipeline complexity | Use cosign with keyless signing ([Sigstore](https://www.sigstore.dev)) for simplicity. Store signatures alongside artifacts in OCI registry. |
| Human approval for high-risk models | Critical decisions reviewed by qualified humans | Approval bottleneck when approvers are unavailable | Define backup approvers. Set SLA for approval response (4 hours). Auto-escalate when SLA is breached. |
| 90-day governance expiry | Forces periodic re-evaluation as regulations and data evolve | Operational burden of re-running governance for stable models | Auto-renew governance for models with no code, data, or configuration changes. Full re-run only when inputs change. |
| Continuous compliance monitoring | Catches governance drift in production | Additional metrics and alerting infrastructure | Governance metrics are lightweight (one series per model). Marginal overhead on existing [Prometheus](https://prometheus.io) deployment. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Governance pipeline check script has a bug | Checks pass when they should fail, or vice versa | Periodic manual audit of governance check results against known-good and known-bad models | Fix the check script. Re-run governance for all models approved during the buggy period. |
| Model deployed via bypass mechanism | Model serving without governance record | ModelMissingGovernanceRecord alert fires | Block traffic. Run governance pipeline. If model passes, re-enable. If it fails, roll back. |
| Cosign key compromised | Attacker can sign fraudulent governance records | Key usage monitoring; unexpected signing events | Rotate keys. Re-sign all governance records with new key. Investigate scope of compromise. |
| Approval workflow blocked by unavailable approvers | Models stuck in pending state; deployments delayed | Pending approval count metric exceeds threshold; escalation alert fires | Activate backup approvers. Review approval role assignments to ensure coverage across time zones. |
| Governance dashboard data goes stale | Dashboard shows incorrect compliance status | Dashboard data freshness check; staleness alert | Fix the metrics pipeline. Reconcile dashboard state against actual model registry. |

## When to Consider a Managed Alternative

Building and maintaining a governance pipeline across dozens of models and multiple teams requires sustained engineering investment.

- **[Vanta](https://www.vanta.com):** Automated compliance monitoring that integrates with ML pipelines. Maps governance controls to regulatory frameworks (EU AI Act, NIST AI RMF). Generates audit-ready evidence packages.
- **[Grafana Cloud](https://grafana.com/cloud):** Governance dashboards with alerting. Visualise pipeline pass rates, pending approvals, and governance coverage across all models. Correlate governance events with model performance metrics.
- **[Axiom](https://axiom.co):** Store governance records, approval histories, and audit trails with full-text search. Query historical governance decisions to demonstrate compliance trends.

**Premium content pack:** AI governance pipeline pack. Complete governance pipeline configuration (GitHub Actions, GitLab CI, Argo Workflows), governance check scripts (data provenance, model card validation, security review), approval workflow implementation (Python), cosign signing integration, Prometheus alert rules for continuous compliance monitoring, and [Grafana](https://grafana.com) governance dashboard templates.


## Related Articles

- [EU AI Act Compliance for Infrastructure Teams: Risk Classification, Documentation, and Technical Controls](/articles/ai-landscape/eu-ai-act-compliance/)
- [AI Model Cards in Production: Documenting Capabilities, Limitations, and Security Properties](/articles/ai-landscape/ai-model-cards/)
- [Algorithmic Auditing: Testing AI Systems for Bias, Fairness, and Safety Before Deployment](/articles/ai-landscape/algorithmic-auditing/)
- [Auditing AI Actions at Scale: Building Tamper-Proof Logs for Non-Human Actors](/articles/ai-landscape/auditing-ai-actions/)
- [AI Incident Reporting: Detection, Classification, and Response Procedures for AI System Failures](/articles/ai-landscape/ai-incident-reporting/)
