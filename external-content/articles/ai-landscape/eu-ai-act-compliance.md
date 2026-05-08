---
title: "EU AI Act Compliance for Infrastructure Teams: Risk Classification, Documentation, and Technical Controls"
description: "The EU AI Act entered into force in August 2024, with enforcement timelines staggered through 2027."
slug: "eu-ai-act-compliance"
date: 2026-04-03
lastmod: 2026-04-03
category: "ai-landscape"
tags: ["eu-ai-act", "compliance", "risk-classification", "ai-governance", "technical-documentation"]
personas: ["security-engineer", "platform-engineer", "compliance-lead"]
article_number: 121
difficulty: "advanced"
estimated_reading_time: 18
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
premium_pack: "eu-ai-act-controls-pack"
published: true
layout: article.njk
permalink: "/articles/ai-landscape/eu-ai-act-compliance/index.html"
---

# EU AI Act Compliance for Infrastructure Teams: Risk Classification, Documentation, and Technical Controls

## Problem

The EU AI Act entered into force in August 2024, with enforcement timelines staggered through 2027. Infrastructure teams deploying AI systems that serve EU users or operate within the EU must now classify every AI workload by risk tier, implement mandatory technical controls, and maintain auditable documentation proving compliance.

The regulation is not optional for non-EU companies. If your AI system processes data from EU residents or outputs decisions that affect them, the Act applies regardless of where your servers sit.

Most compliance guidance targets legal and policy teams. Infrastructure engineers are left to translate legal language into technical controls. The Act requires "appropriate levels of accuracy, robustness and cybersecurity" (Article 15), "automatic recording of events" (Article 12), and "effective human oversight" (Article 14). These are infrastructure problems, not legal ones.

The penalty structure makes this urgent. Non-compliance fines reach 35 million euros or 7% of global annual turnover for prohibited AI practices, and 15 million euros or 3% for high-risk system violations. These are not theoretical. National supervisory authorities are staffing enforcement offices now.

This article maps the AI Act's requirements to concrete infrastructure controls: risk classification logic, logging pipelines, human oversight mechanisms, and documentation systems that satisfy auditors.

## Threat Model

- **Adversary:** National supervisory authorities conducting audits, and internal compliance teams assessing readiness.
- **Key requirements:** (1) Every AI system classified by risk tier with documented justification. (2) High-risk systems have logging, human oversight, and technical documentation in place. (3) Evidence of compliance is machine-readable and audit-ready at any time.
- **Failure scenario:** An AI system deployed without classification is discovered during an audit or after an incident. The organisation cannot produce the required documentation within the timeframe demanded by the authority.

## Configuration

### Risk Classification Engine

Every AI workload needs a risk classification before deployment. Encode the classification logic so it runs automatically in your CI/CD pipeline.

```yaml
# ai-risk-classifier.yaml
# Runs as a pre-deployment check in CI/CD.
# Maps AI system properties to EU AI Act risk tiers.

classification_rules:
  prohibited:
    description: "Banned under Article 5"
    conditions:
      - social_scoring: true
      - real_time_biometric_identification_public: true
      - subliminal_manipulation: true
      - exploitation_vulnerable_groups: true
    action: "block_deployment"

  high_risk:
    description: "Subject to full compliance requirements (Annex III)"
    conditions:
      - domain: "biometric_identification"
      - domain: "critical_infrastructure"
      - domain: "education_vocational_training"
      - domain: "employment_worker_management"
      - domain: "essential_services_access"
      - domain: "law_enforcement"
      - domain: "migration_asylum"
      - domain: "justice_democratic_process"
      - safety_component: true
    action: "require_full_controls"

  limited_risk:
    description: "Transparency obligations only (Article 52)"
    conditions:
      - generates_synthetic_content: true
      - emotion_recognition: true
      - biometric_categorisation: true
      - chatbot_interaction: true
    action: "require_transparency_controls"

  minimal_risk:
    description: "No mandatory requirements"
    conditions:
      - default: true
    action: "log_classification_only"
```

```python
# classify_ai_system.py
# Called during CI/CD to classify and gate deployments.

import yaml
import json
import sys
from datetime import datetime, timezone

def classify(system_metadata: dict, rules_path: str = "ai-risk-classifier.yaml") -> dict:
    """Classify an AI system according to EU AI Act risk tiers."""
    with open(rules_path) as f:
        rules = yaml.safe_load(f)

    # Check prohibited first
    for condition in rules["classification_rules"]["prohibited"]["conditions"]:
        for key, value in condition.items():
            if system_metadata.get(key) == value:
                return {
                    "risk_tier": "prohibited",
                    "action": "block_deployment",
                    "reason": f"System uses prohibited practice: {key}",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "system_id": system_metadata["system_id"]
                }

    # Check high-risk
    for condition in rules["classification_rules"]["high_risk"]["conditions"]:
        if isinstance(condition, dict):
            for key, value in condition.items():
                if system_metadata.get(key) == value:
                    return {
                        "risk_tier": "high_risk",
                        "action": "require_full_controls",
                        "reason": f"System matches high-risk condition: {key}={value}",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "system_id": system_metadata["system_id"]
                    }

    # Check limited risk
    for condition in rules["classification_rules"]["limited_risk"]["conditions"]:
        for key, value in condition.items():
            if system_metadata.get(key) == value:
                return {
                    "risk_tier": "limited_risk",
                    "action": "require_transparency_controls",
                    "reason": f"System has transparency obligation: {key}",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "system_id": system_metadata["system_id"]
                }

    return {
        "risk_tier": "minimal_risk",
        "action": "log_classification_only",
        "reason": "No mandatory requirements apply",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "system_id": system_metadata["system_id"]
    }

if __name__ == "__main__":
    metadata = json.loads(sys.argv[1])
    result = classify(metadata)
    print(json.dumps(result, indent=2))
    if result["action"] == "block_deployment":
        sys.exit(1)
```

### Article 12: Automatic Logging for High-Risk Systems

High-risk AI systems must automatically record events (logs) throughout their lifetime. The logs must enable tracing of the system's operation and support post-market monitoring.

```yaml
# otel-collector-ai-act.yaml
# OpenTelemetry Collector pipeline for Article 12 logging.
# Captures all required event types for high-risk AI systems.

receivers:
  otlp:
    protocols:
      grpc:
        endpoint: "0.0.0.0:4317"

processors:
  attributes/ai_act:
    actions:
      - action: insert
        key: "ai_act.risk_tier"
        value: "high_risk"
      - action: insert
        key: "ai_act.system_id"
        from_attribute: "ai.system_id"
      - action: insert
        key: "ai_act.article_12_compliant"
        value: true

  # Article 12(2): logs must record input data automatically
  # (or references to input data for privacy compliance)
  filter/required_fields:
    error_mode: send
    logs:
      log_record:
        - 'attributes["ai.input_reference"] == nil and attributes["ai.input_hash"] == nil'

exporters:
  otlp/axiom:
    endpoint: "https://api.axiom.co"
    headers:
      Authorization: "Bearer ${AXIOM_API_TOKEN}"

  file/local_backup:
    path: "/var/log/ai-act/events.jsonl"
    rotation:
      max_megabytes: 500
      max_days: 365
      max_backups: 10

service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [attributes/ai_act, filter/required_fields]
      exporters: [otlp/axiom, file/local_backup]
```

Required log fields for Article 12 compliance:

```json
{
  "timestamp": "2026-04-22T14:30:00.000Z",
  "system_id": "loan-scoring-model-v3",
  "risk_tier": "high_risk",
  "event_type": "inference",
  "input_reference": "request-id-abc123",
  "input_hash": "sha256:e3b0c44298fc...",
  "output": "decision: approved, confidence: 0.87",
  "output_hash": "sha256:d7a8fbb307d7...",
  "model_version": "3.2.1",
  "model_hash": "sha256:9f86d081884c...",
  "data_pipeline_version": "2.1.0",
  "human_oversight_active": true,
  "override_applied": false,
  "processing_duration_ms": 45,
  "geographic_scope": "EU"
}
```

### Article 14: Human Oversight Implementation

High-risk AI systems must allow human oversight. This means humans must be able to understand the system's capabilities and limitations, monitor operation, interpret outputs, and override or stop the system.

```yaml
# human-oversight-controller.yaml
# Kubernetes deployment for human oversight gateway.
# All high-risk AI system outputs pass through this gateway.

apiVersion: apps/v1
kind: Deployment
metadata:
  name: ai-oversight-gateway
  namespace: ai-production
  labels:
    ai-act.compliance: "article-14"
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ai-oversight-gateway
  template:
    metadata:
      labels:
        app: ai-oversight-gateway
    spec:
      containers:
        - name: oversight-gateway
          image: internal/ai-oversight-gateway:1.4.0
          ports:
            - containerPort: 8080
          env:
            - name: OVERSIGHT_MODE
              value: "human_in_the_loop"  # Options: human_in_the_loop, human_on_the_loop, human_in_command
            - name: CONFIDENCE_THRESHOLD
              value: "0.85"  # Below this, human review is mandatory
            - name: AUTO_APPROVE_ENABLED
              value: "false"  # Set to true only for human_on_the_loop mode
            - name: KILL_SWITCH_ENABLED
              value: "true"  # Article 14(4)(e): ability to stop the system
            - name: MAX_QUEUE_DEPTH
              value: "100"  # Circuit breaker: stop accepting if review queue backs up
          readinessProbe:
            httpGet:
              path: /health
              port: 8080
            periodSeconds: 10
          resources:
            limits:
              memory: "256Mi"
              cpu: "500m"
---
apiVersion: v1
kind: Service
metadata:
  name: ai-oversight-gateway
  namespace: ai-production
spec:
  selector:
    app: ai-oversight-gateway
  ports:
    - port: 8080
      targetPort: 8080
```

```python
# oversight_gateway.py
# Core logic for routing AI decisions through human oversight.

from dataclasses import dataclass
from enum import Enum
import time

class OversightMode(Enum):
    HUMAN_IN_THE_LOOP = "human_in_the_loop"      # Human approves every decision
    HUMAN_ON_THE_LOOP = "human_on_the_loop"       # Human monitors, intervenes when needed
    HUMAN_IN_COMMAND = "human_in_command"          # Human sets parameters, AI executes

@dataclass
class AIDecision:
    system_id: str
    decision: str
    confidence: float
    input_reference: str
    model_version: str
    explanation: str

class OversightGateway:
    def __init__(self, mode: OversightMode, confidence_threshold: float = 0.85):
        self.mode = mode
        self.confidence_threshold = confidence_threshold
        self.kill_switch_active = False

    def process_decision(self, decision: AIDecision) -> dict:
        """Route an AI decision through the appropriate oversight path."""

        # Article 14(4)(e): kill switch check
        if self.kill_switch_active:
            return {
                "status": "blocked",
                "reason": "kill_switch_active",
                "decision_id": decision.input_reference,
                "timestamp": time.time()
            }

        if self.mode == OversightMode.HUMAN_IN_THE_LOOP:
            return self._queue_for_review(decision)

        if self.mode == OversightMode.HUMAN_ON_THE_LOOP:
            if decision.confidence < self.confidence_threshold:
                return self._queue_for_review(decision)
            return self._auto_approve_with_logging(decision)

        if self.mode == OversightMode.HUMAN_IN_COMMAND:
            return self._execute_within_parameters(decision)

    def activate_kill_switch(self, operator_id: str, reason: str):
        """Article 14(4)(e): immediately stop AI system operation."""
        self.kill_switch_active = True
        # Log is critical for audit trail
        return {
            "action": "kill_switch_activated",
            "operator_id": operator_id,
            "reason": reason,
            "timestamp": time.time()
        }
```

### Technical Documentation System (Article 11)

High-risk AI systems require comprehensive technical documentation. Store it as code alongside the system.

```yaml
# ai-system-technical-doc.yaml
# Machine-readable technical documentation for Article 11.
# Stored in the same repository as the AI system.

system_identification:
  name: "Loan Eligibility Scoring Model"
  system_id: "loan-scoring-model-v3"
  version: "3.2.1"
  provider: "Internal ML Platform Team"
  risk_classification: "high_risk"
  annex_iii_category: "essential_services_access"
  intended_purpose: >
    Automated scoring of loan applications to assist human
    underwriters in assessing eligibility. The system produces
    a score and explanation. Final decisions are made by human
    underwriters.

design_specifications:
  model_architecture: "gradient_boosted_trees"
  framework: "XGBoost 2.1.0"
  training_data:
    sources:
      - name: "historical_loan_applications"
        records: 2400000
        date_range: "2020-01-01 to 2025-12-31"
        geographic_scope: "EU"
    preprocessing:
      - "removed_protected_characteristics"
      - "applied_demographic_parity_constraint"
      - "synthetic_oversampling_for_underrepresented_groups"
    data_governance:
      gdpr_basis: "legitimate_interest"
      dpia_reference: "DPIA-2026-004"

performance_metrics:
  accuracy: 0.91
  precision: 0.88
  recall: 0.93
  false_positive_rate: 0.07
  false_negative_rate: 0.12
  fairness_metrics:
    demographic_parity_difference: 0.03
    equalised_odds_difference: 0.04
    tested_across:
      - "age_group"
      - "gender"
      - "nationality"

human_oversight:
  mode: "human_on_the_loop"
  confidence_threshold: 0.85
  mandatory_review_triggers:
    - "confidence_below_threshold"
    - "applicant_flags_decision"
    - "model_drift_detected"
  kill_switch: true

logging:
  article_12_compliant: true
  retention_days: 365
  storage: "axiom + s3_immutable"
  fields_captured:
    - "input_reference"
    - "output_decision"
    - "confidence_score"
    - "model_version"
    - "human_override_applied"

cybersecurity:
  article_15_controls:
    - "model_artifact_signed_with_cosign"
    - "inference_endpoint_mutual_tls"
    - "input_validation_and_sanitisation"
    - "adversarial_robustness_testing_quarterly"
    - "data_poisoning_detection_in_training_pipeline"
```

### CI/CD Compliance Gate

```yaml
# .github/workflows/ai-act-compliance.yaml
name: AI Act Compliance Check

on:
  pull_request:
    paths:
      - 'ml-models/**'
      - 'ai-systems/**'

jobs:
  classify-and-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Classify AI System Risk
        id: classify
        run: |
          RESULT=$(python classify_ai_system.py "$(cat ai-system-metadata.json)")
          echo "risk_tier=$(echo $RESULT | jq -r '.risk_tier')" >> "$GITHUB_OUTPUT"
          echo "$RESULT"

      - name: Check Technical Documentation
        if: steps.classify.outputs.risk_tier == 'high_risk'
        run: |
          # Validate required documentation exists and is complete
          python validate_tech_doc.py ai-system-technical-doc.yaml

      - name: Check Logging Configuration
        if: steps.classify.outputs.risk_tier == 'high_risk'
        run: |
          # Verify Article 12 logging is configured
          python check_logging.py --require-fields input_reference,output,model_version,human_oversight_active

      - name: Check Human Oversight Configuration
        if: steps.classify.outputs.risk_tier == 'high_risk'
        run: |
          # Verify Article 14 oversight mechanism exists
          python check_oversight.py --require-kill-switch --require-review-queue

      - name: Block Prohibited Systems
        if: steps.classify.outputs.risk_tier == 'prohibited'
        run: |
          echo "BLOCKED: This AI system uses prohibited practices under Article 5 of the EU AI Act."
          exit 1
```

## Expected Behaviour

- Every AI system classified by risk tier before deployment, with classification stored as a versioned artifact
- High-risk systems blocked from production without complete Article 11 technical documentation
- Article 12 logging captures all required fields for every inference, with 365-day retention
- Human oversight gateway routes low-confidence decisions to human reviewers within 30 seconds
- Kill switch stops AI system operation within 5 seconds of activation
- CI/CD pipeline blocks deployment of prohibited AI practices and undocumented high-risk systems
- Classification and documentation are machine-readable and exportable for supervisory authority audits

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Risk classification gate in CI/CD | Prevents unclassified AI systems from reaching production | Slows deployment by 1-2 minutes per pipeline run | Classification is cached per system version. Only re-runs when metadata changes. |
| Article 12 full-field logging | Complete audit trail for every inference | Storage volume increases 3-5x compared to standard application logs | Use [Axiom](https://axiom.co) for queryable 30-day window. Archive to immutable S3 for 365-day retention. |
| Human-in-the-loop oversight | Every decision reviewed by a human; highest compliance confidence | Latency increases from milliseconds to minutes; throughput limited by reviewer availability | Use human-on-the-loop for systems where confidence scoring is reliable. Reserve human-in-the-loop for the highest-risk decisions. |
| Technical documentation as code | Documentation stays in sync with the system it describes | Adds maintenance burden to ML engineers | Validate documentation completeness in CI. Incomplete docs block deployment. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Risk classification miscategorises a system | High-risk system deployed without required controls | Periodic audit compares deployed systems against Annex III criteria | Re-classify. Retrofit missing controls. Document the gap and remediation timeline. |
| Article 12 logging pipeline drops events | Gaps in audit trail discovered during investigation | Log volume metrics drop below expected baseline; missing events alert fires | Fix pipeline. Replay from local buffer. Document the gap period for authorities. |
| Human oversight queue backs up | Decisions delayed; users experience timeouts | Queue depth metric exceeds threshold; P95 review time alert fires | Scale reviewer pool. Consider switching to human-on-the-loop with higher confidence threshold for low-risk decision subtypes. |
| Kill switch fails to propagate | System continues operating after kill switch activation | Health check shows system still serving after kill switch event logged | Network-level kill switch as fallback: block traffic at the load balancer. |
| Technical documentation drifts from reality | Documentation says one thing, system does another | Automated validation compares documentation fields against live system configuration | CI gate catches drift on every deployment. Enforce documentation updates before merging. |

## When to Consider a Managed Alternative

Building and maintaining a full EU AI Act compliance framework requires ongoing investment as the regulation evolves and enforcement precedents are set.

- **[Vanta](https://www.vanta.com):** Automated compliance monitoring with EU AI Act framework support. Maps controls to requirements, tracks evidence collection, and generates audit-ready reports.
- **[Axiom](https://axiom.co):** High-volume log ingestion for Article 12 compliance. 500GB/month free tier covers most AI system logging needs. Serverless query means no cluster management.
- **[Grafana Cloud](https://grafana.com/cloud):** Unified dashboards for AI system monitoring, human oversight queue metrics, and compliance status. Native alerting for kill switch events and logging pipeline failures.

**Premium content pack:** EU AI Act controls pack. Risk classification engine with full Annex III mapping, Article 11 technical documentation templates, Article 12 OTel logging pipeline configs, Article 14 human oversight gateway (Python, Go), CI/CD compliance gate configs for GitHub Actions and GitLab CI, and audit preparation checklists.


## Related Articles

- [AI Model Cards in Production: Documenting Capabilities, Limitations, and Security Properties](/articles/ai-landscape/ai-model-cards/)
- [Building an AI Governance Pipeline: Automated Checks from Training to Production](/articles/ai-landscape/ai-governance-pipeline/)
- [Algorithmic Auditing: Testing AI Systems for Bias, Fairness, and Safety Before Deployment](/articles/ai-landscape/algorithmic-auditing/)
- [Auditing AI Actions at Scale: Building Tamper-Proof Logs for Non-Human Actors](/articles/ai-landscape/auditing-ai-actions/)
- [AI Incident Reporting: Detection, Classification, and Response Procedures for AI System Failures](/articles/ai-landscape/ai-incident-reporting/)
