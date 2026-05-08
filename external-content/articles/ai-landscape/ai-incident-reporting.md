---
title: "AI Incident Reporting: Detection, Classification, and Response Procedures for AI System Failures"
description: "Traditional incident response assumes failures are binary: the service is up or it is down, the response is correct or it throws an error."
slug: "ai-incident-reporting"
date: 2026-01-12
lastmod: 2026-01-12
category: "ai-landscape"
tags: ["incident-response", "ai-incidents", "runbooks", "model-failures", "post-incident-review"]
personas: ["sre", "security-engineer", "ai-ml-engineer"]
article_number: 124
difficulty: "advanced"
estimated_reading_time: 18
provider_bridges:
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
  - name: "Better Stack"
    id: 113
    category: "observability"
  - name: "Axiom"
    id: 112
    category: "observability"
premium_pack: "ai-incident-response-pack"
published: true
layout: article.njk
permalink: "/articles/ai-landscape/ai-incident-reporting/index.html"
---

# AI Incident Reporting: Detection, Classification, and Response Procedures for AI System Failures

## Problem

Traditional incident response assumes failures are binary: the service is up or it is down, the response is correct or it throws an error. AI systems break this model. A model can return HTTP 200 with high confidence while producing outputs that are subtly wrong, biased, or harmful. The system appears healthy by every infrastructure metric while causing damage.

Consider a loan approval model that starts approving high-risk applications after a data pipeline schema change silently corrupts an input feature. CPU usage is normal. Latency is within SLA. Error rate is zero. The model is confidently producing wrong answers. By the time the default rate spikes three months later, thousands of bad loans have been issued.

Existing incident response frameworks (PagerDuty runbooks, [Kubernetes](https://kubernetes.io) health checks, HTTP status monitoring) do not cover this class of failure. AI incidents require different detection methods (output distribution monitoring, not just error rates), different classification schemes (bias incidents are not the same as availability incidents), and different response procedures (rolling back a model is not the same as rolling back a deployment).

Teams that bolt AI workloads onto their existing incident process will miss AI-specific failures entirely or respond to them with the wrong playbook.

## Threat Model

- **Adversary:** Silent model degradation, data pipeline corruption, adversarial inputs, and emergent model behaviours. These produce incidents that infrastructure monitoring does not detect.
- **Key requirements:** (1) AI-specific incident detection beyond traditional health checks. (2) Classification taxonomy that covers AI failure modes. (3) Response procedures tailored to model-level remediation. (4) Post-incident review that captures AI-specific root causes.
- **Failure scenario:** A content moderation model begins over-flagging content from a specific language group after a model update. Traditional monitoring shows the model is healthy (low latency, no errors). Users from the affected group experience degraded service for weeks before a support escalation triggers investigation.

## Configuration

### AI Incident Taxonomy

Define the categories of AI-specific incidents. This taxonomy drives detection, classification, and response.

```yaml
# ai-incident-taxonomy.yaml
# Classification scheme for AI system incidents.

incident_types:
  model_performance_degradation:
    description: "Model accuracy, precision, or recall drops below acceptable thresholds"
    detection: "output_distribution_monitoring"
    examples:
      - "F1 score drops from 0.92 to 0.78 over 24 hours"
      - "False positive rate doubles after data pipeline update"
    default_severity: "high"

  data_pipeline_corruption:
    description: "Input data to the model is corrupted, missing, or schema-drifted"
    detection: "input_validation_and_schema_checks"
    examples:
      - "Feature column renamed upstream, model receives null values"
      - "Currency field changes from USD to EUR without conversion"
    default_severity: "critical"

  bias_and_fairness_violation:
    description: "Model outputs show disparate impact across protected groups"
    detection: "fairness_metric_monitoring"
    examples:
      - "Approval rate for age group 60+ drops 15% after retraining"
      - "Content moderation flags non-English content at 3x the rate of English"
    default_severity: "critical"

  adversarial_attack:
    description: "Model targeted by crafted inputs designed to cause misclassification"
    detection: "input_anomaly_detection"
    examples:
      - "Spike in inputs with unusual Unicode characters or formatting"
      - "Coordinated submission of inputs near decision boundaries"
    default_severity: "critical"

  model_drift:
    description: "Production input distribution diverges from training distribution"
    detection: "distribution_shift_monitoring"
    examples:
      - "New product category not present in training data reaches 10% of inputs"
      - "Seasonal pattern shift causes confidence score distribution to change"
    default_severity: "medium"

  harmful_output:
    description: "Model produces outputs that are toxic, unsafe, or policy-violating"
    detection: "output_content_filtering"
    examples:
      - "Generative model produces personally identifiable information"
      - "Recommendation model surfaces prohibited content"
    default_severity: "critical"

  resource_exhaustion:
    description: "Model inference consumes excessive compute, memory, or storage"
    detection: "infrastructure_monitoring"
    examples:
      - "Inference latency increases 10x due to input size edge case"
      - "Batch prediction job runs out of memory on unexpected data volume"
    default_severity: "medium"

severity_levels:
  critical:
    description: "Active harm to users or regulatory violation in progress"
    response_time: "15 minutes"
    actions: ["page_on_call", "activate_kill_switch", "escalate_to_management"]
  high:
    description: "Significant degradation affecting output quality"
    response_time: "1 hour"
    actions: ["page_on_call", "begin_investigation"]
  medium:
    description: "Measurable drift or degradation, not yet impacting users"
    response_time: "4 hours"
    actions: ["create_ticket", "schedule_investigation"]
  low:
    description: "Minor anomaly detected, monitoring closely"
    response_time: "next business day"
    actions: ["create_ticket", "add_to_review_queue"]
```

### Automated Detection Pipeline

```yaml
# prometheus-rules-ai-incidents.yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: ai-incident-detection
  namespace: monitoring
spec:
  groups:
    - name: ai-model-incidents
      interval: 60s
      rules:
        # Detect model performance degradation
        - alert: AIModelPerformanceDegraded
          expr: |
            model_live_accuracy < on(model_id) (model_baseline_accuracy * 0.90)
          for: 15m
          labels:
            severity: high
            incident_type: model_performance_degradation
          annotations:
            summary: "Model {{ $labels.model_id }} accuracy dropped to {{ $value }} (baseline: {{ $labels.baseline }})"
            runbook_url: "https://runbooks.internal/ai-incidents/performance-degradation"

        # Detect input distribution shift
        - alert: AIModelInputDistributionShift
          expr: |
            model_input_kl_divergence > 0.5
          for: 30m
          labels:
            severity: medium
            incident_type: model_drift
          annotations:
            summary: "Model {{ $labels.model_id }} input KL divergence is {{ $value }} (threshold: 0.5)"
            runbook_url: "https://runbooks.internal/ai-incidents/distribution-shift"

        # Detect confidence distribution anomaly
        - alert: AIModelConfidenceAnomaly
          expr: |
            histogram_quantile(0.5, rate(model_output_confidence_bucket[1h]))
            < 0.6
          for: 15m
          labels:
            severity: high
            incident_type: model_performance_degradation
          annotations:
            summary: "Model {{ $labels.model_id }} median confidence dropped below 0.6"
            runbook_url: "https://runbooks.internal/ai-incidents/confidence-drop"

        # Detect null or invalid model outputs
        - alert: AIModelInvalidOutputs
          expr: |
            rate(model_output_invalid_total[5m]) > 0
          for: 5m
          labels:
            severity: critical
            incident_type: data_pipeline_corruption
          annotations:
            summary: "Model {{ $labels.model_id }} producing invalid outputs at {{ $value }}/s"
            runbook_url: "https://runbooks.internal/ai-incidents/invalid-outputs"

        # Detect adversarial input patterns
        - alert: AIModelAdversarialInputSpike
          expr: |
            rate(model_input_anomaly_score_high_total[5m]) > 10
          for: 5m
          labels:
            severity: critical
            incident_type: adversarial_attack
          annotations:
            summary: "Model {{ $labels.model_id }} receiving anomalous inputs at {{ $value }}/s"
            runbook_url: "https://runbooks.internal/ai-incidents/adversarial-input"

        # Detect output policy violations
        - alert: AIModelOutputPolicyViolation
          expr: |
            rate(model_output_policy_violation_total[5m]) > 0
          for: 1m
          labels:
            severity: critical
            incident_type: harmful_output
          annotations:
            summary: "Model {{ $labels.model_id }} producing policy-violating outputs"
            runbook_url: "https://runbooks.internal/ai-incidents/harmful-output"
```

### AI Incident Response Runbooks

```yaml
# runbook-performance-degradation.yaml
# Response procedure for model performance degradation incidents.

runbook:
  name: "AI Model Performance Degradation"
  incident_type: "model_performance_degradation"
  version: "1.3"

  triage:
    steps:
      - action: "Confirm the alert is not a false positive"
        command: |
          # Check model accuracy over the last 24 hours
          curl -s "http://prometheus:9090/api/v1/query_range?query=model_live_accuracy{model_id='MODEL_ID'}&start=$(date -d '24 hours ago' +%s)&end=$(date +%s)&step=300" | jq '.data.result[0].values'
        expected: "Accuracy should show a clear downward trend, not a single dip"

      - action: "Check if a recent deployment or data pipeline change correlates"
        command: |
          # List recent deployments
          kubectl get events --namespace ai-production --sort-by='.metadata.creationTimestamp' | tail -20
          # Check data pipeline last successful run
          kubectl get jobs --namespace data-pipeline --sort-by='.status.completionTime' | tail -5

      - action: "Determine scope of impact"
        command: |
          # Check how many predictions are affected
          curl -s "http://prometheus:9090/api/v1/query?query=sum(rate(model_predictions_total{model_id='MODEL_ID'}[1h]))"

  containment:
    steps:
      - action: "Switch to fallback model if available"
        command: |
          # Update the model serving config to point to the previous version
          kubectl set env deployment/model-server -n ai-production MODEL_VERSION=MODEL_PREVIOUS_VERSION
          # Verify the rollback
          kubectl rollout status deployment/model-server -n ai-production
        rollback: |
          kubectl set env deployment/model-server -n ai-production MODEL_VERSION=MODEL_CURRENT_VERSION

      - action: "If no fallback, enable human-in-the-loop for all predictions"
        command: |
          kubectl set env deployment/ai-oversight-gateway -n ai-production OVERSIGHT_MODE=human_in_the_loop CONFIDENCE_THRESHOLD=1.0

      - action: "If active harm, activate kill switch"
        command: |
          curl -X POST http://ai-oversight-gateway:8080/kill-switch \
            -H "Content-Type: application/json" \
            -d '{"operator_id": "OPERATOR_EMAIL", "reason": "performance degradation incident INC-XXXX"}'

  investigation:
    steps:
      - action: "Compare input distribution against training data baseline"
        command: |
          python compare_distributions.py --model MODEL_ID --window 24h --baseline training_data_profile.json

      - action: "Check data pipeline outputs for schema drift"
        command: |
          python check_schema.py --pipeline fraud-detection-features --expected-schema schema_v4.json

      - action: "Run offline evaluation on recent production inputs"
        command: |
          python evaluate_model.py --model MODEL_ID --data recent_production_sample.parquet --output evaluation_report.json

  resolution:
    options:
      - name: "Rollback to previous model version"
        when: "Previous version performed better and issue is in the new model"
        steps:
          - "Deploy previous model version"
          - "Verify performance metrics recover"
          - "Investigate root cause of regression in new version"

      - name: "Fix data pipeline and redeploy"
        when: "Issue is in input data, not the model itself"
        steps:
          - "Fix the data pipeline issue"
          - "Verify input data quality"
          - "Redeploy current model version"
          - "Monitor for performance recovery"

      - name: "Retrain model"
        when: "Distribution shift has made the current model obsolete"
        steps:
          - "Collect new training data covering the shifted distribution"
          - "Retrain and validate offline"
          - "Run full bias and safety audit"
          - "Deploy via standard pipeline"
```

### AI Incident Record Schema

```json
{
  "incident_id": "AI-INC-2026-0042",
  "incident_type": "model_performance_degradation",
  "severity": "high",
  "status": "resolved",
  "model_id": "fraud-detection-v4",
  "model_version": "4.1.2",
  "detected_at": "2026-04-22T08:15:00Z",
  "detected_by": "AIModelPerformanceDegraded alert",
  "acknowledged_at": "2026-04-22T08:22:00Z",
  "resolved_at": "2026-04-22T10:45:00Z",
  "duration_minutes": 150,
  "impact": {
    "affected_predictions": 12400,
    "false_positive_increase": "12%",
    "user_impact": "340 legitimate transactions flagged as fraudulent",
    "financial_impact_estimate": "processing delays for flagged transactions"
  },
  "root_cause": {
    "category": "data_pipeline_corruption",
    "description": "Upstream data pipeline renamed 'merchant_category_code' to 'mcc'. Model received null values for this feature, causing degraded accuracy.",
    "contributing_factors": [
      "No schema validation between data pipeline and model input",
      "Feature importance: merchant_category_code accounts for 18% of model decisions"
    ]
  },
  "timeline": [
    {"time": "2026-04-22T06:00:00Z", "event": "Data pipeline deployed with schema change"},
    {"time": "2026-04-22T08:15:00Z", "event": "AIModelPerformanceDegraded alert fires"},
    {"time": "2026-04-22T08:22:00Z", "event": "On-call ML engineer acknowledges"},
    {"time": "2026-04-22T08:45:00Z", "event": "Root cause identified: schema drift"},
    {"time": "2026-04-22T09:15:00Z", "event": "Model rolled back to v4.1.1"},
    {"time": "2026-04-22T09:30:00Z", "event": "Performance metrics recovering"},
    {"time": "2026-04-22T10:00:00Z", "event": "Data pipeline fix deployed"},
    {"time": "2026-04-22T10:30:00Z", "event": "Model v4.1.2 redeployed with schema validation"},
    {"time": "2026-04-22T10:45:00Z", "event": "Incident resolved, metrics nominal"}
  ],
  "corrective_actions": [
    {
      "action": "Add Great Expectations schema validation between data pipeline and model input",
      "owner": "data-platform-team",
      "due_date": "2026-04-29",
      "status": "in_progress"
    },
    {
      "action": "Add input schema drift alert to model monitoring",
      "owner": "ml-platform-team",
      "due_date": "2026-04-25",
      "status": "completed"
    },
    {
      "action": "Document feature dependencies in model card",
      "owner": "fraud-model-team",
      "due_date": "2026-04-26",
      "status": "in_progress"
    }
  ]
}
```

### Post-Incident Review Template

```yaml
# post-incident-review-template.yaml
# Template for AI-specific post-incident reviews.

review:
  incident_id: ""
  review_date: ""
  participants: []

  sections:
    impact_assessment:
      questions:
        - "How many predictions were affected during the incident window?"
        - "Were any predictions used to make decisions that harmed users?"
        - "Is there regulatory reporting required (EU AI Act Article 62, sector regulators)?"
        - "Do affected users need to be notified?"

    ai_specific_root_cause:
      questions:
        - "Was the root cause in the model, the data, the serving infrastructure, or the interaction between them?"
        - "Did the model behave as designed given the inputs it received, or did the model itself malfunction?"
        - "Was the failure mode documented in the model card? If not, should it be?"
        - "Could this failure mode have been caught by the bias/fairness testing pipeline?"

    detection_effectiveness:
      questions:
        - "How long was the model producing incorrect outputs before detection?"
        - "What monitoring signal triggered the alert? Was it the right signal?"
        - "Were there earlier signals that were missed? What additional monitoring would have caught this sooner?"
        - "Is the current detection threshold appropriate, or does it need tuning?"

    response_effectiveness:
      questions:
        - "Did the runbook cover this incident type?"
        - "Was the rollback/containment procedure effective?"
        - "Was the right team paged? Did they have the context and access needed?"
        - "What was the time from detection to containment? Can it be shortened?"

    prevention:
      questions:
        - "What changes to the data pipeline, model, or serving infrastructure would prevent recurrence?"
        - "Should the model card be updated with this failure mode?"
        - "Should the bias/safety testing pipeline be updated to cover this case?"
        - "Are similar models at risk of the same failure?"
```

## Expected Behaviour

- AI-specific alerts fire within 15 minutes of model performance degradation, input anomalies, or output policy violations
- Every AI incident is classified using the AI incident taxonomy, not generic infrastructure categories
- On-call engineers have AI-specific runbooks that guide triage, containment, and investigation
- Model rollback or kill switch containment executes within 5 minutes of decision to act
- Post-incident reviews cover AI-specific root causes (data drift, fairness violations, adversarial inputs) alongside standard infrastructure causes
- Incident records include affected prediction counts, model versions, and corrective actions
- Regulatory reporting obligations (EU AI Act Article 62) are assessed for every critical AI incident

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Output distribution monitoring | Catches silent model failures that error-rate monitoring misses | Requires ground truth labels, which may be delayed by days or weeks | Use proxy metrics (confidence distribution, output entropy) for real-time detection. Validate with delayed ground truth. |
| AI-specific incident taxonomy | Responders use the right playbook for the failure type | Additional cognitive load during incident response | Keep taxonomy concise. Train on-call engineers on AI incident types quarterly. |
| Automated kill switch on critical alerts | Stops active harm within minutes | False positive kills disrupt service unnecessarily | Require two consecutive alert evaluations before automated kill switch. Manual kill switch available immediately. |
| Detailed incident records with prediction counts | Full accountability and regulatory compliance | Time-consuming to populate during an active incident | Auto-populate what can be computed (prediction counts, model version, timeline from alerts). Humans fill in root cause and corrective actions post-resolution. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Silent model failure not detected by any alert | Users report incorrect results; no alerts fired | Customer complaints, support ticket volume increase, delayed ground truth evaluation | Add the missing detection signal. Update monitoring to cover this failure mode. Backfill impacted predictions. |
| Kill switch fires on false positive | AI system stops serving; users get errors | Kill switch activation event with no confirming evidence of model failure | Restore service. Tune alert threshold. Add confirmation step before automated kill switch. |
| Runbook does not cover the incident type | On-call engineer improvises response; containment delayed | Incident timeline shows long gap between detection and effective action | Write a new runbook. Add this incident type to the taxonomy if missing. |
| Model rollback deploys a version with known issues | Previous model version had a different set of problems | Monitoring after rollback shows different but still degraded performance | Maintain a "known good" version tag separate from "previous" version. Validate rollback target before deploying. |
| Post-incident review skipped or superficial | Same failure repeats; corrective actions not implemented | Repeat incident with same root cause | Make post-incident review mandatory for all high and critical AI incidents. Track corrective action completion. |

## When to Consider a Managed Alternative

AI incident detection and response requires monitoring infrastructure that goes beyond standard application performance monitoring.

- **[Better Stack](https://betterstack.com):** Integrated logging and incident management. Correlate model output logs with infrastructure events. On-call scheduling with escalation policies tuned for AI incident severity levels.
- **[Grafana Cloud](https://grafana.com/cloud):** Unified dashboards for model performance, fairness metrics, and infrastructure health. Native alerting with annotation support for marking model deployments and data pipeline changes on performance graphs.
- **[Axiom](https://axiom.co):** Store and query AI incident records, model output samples, and investigation artifacts. Full-text search across incident timelines and root cause analyses.

**Premium content pack:** AI incident response pack. Incident taxonomy configuration, [Prometheus](https://prometheus.io) alert rules for all AI incident types, response runbooks (performance degradation, data corruption, bias violation, adversarial attack, harmful output), post-incident review templates, incident record schema with auto-population scripts, and on-call training materials for AI incident response.


## Related Articles

- [Auditing AI Actions at Scale: Building Tamper-Proof Logs for Non-Human Actors](/articles/ai-landscape/auditing-ai-actions/)
- [EU AI Act Compliance for Infrastructure Teams: Risk Classification, Documentation, and Technical Controls](/articles/ai-landscape/eu-ai-act-compliance/)
- [AI Model Cards in Production: Documenting Capabilities, Limitations, and Security Properties](/articles/ai-landscape/ai-model-cards/)
- [Algorithmic Auditing: Testing AI Systems for Bias, Fairness, and Safety Before Deployment](/articles/ai-landscape/algorithmic-auditing/)
- [Building an AI Governance Pipeline: Automated Checks from Training to Production](/articles/ai-landscape/ai-governance-pipeline/)
