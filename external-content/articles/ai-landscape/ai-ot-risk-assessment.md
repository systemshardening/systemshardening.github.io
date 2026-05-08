---
title: "AI in OT Risk Assessment: CISA's Framework for Safe AI Procurement"
description: "CISA's companion AI-in-OT guidance defines an 'Assess AI Use' principle. Build a risk-scoring framework for evaluating AI products before OT deployment — covering SIL compatibility, adversarial robustness, vendor governance, and fail-safe requirements."
slug: ai-ot-risk-assessment
date: 2026-05-03
lastmod: 2026-05-03
category: ai-landscape
tags:
  - ot-security
  - ai-governance
  - risk-assessment
  - ics
  - safety-integrity
personas:
  - security-engineer
  - platform-engineer
article_number: 412
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/ai-landscape/ai-ot-risk-assessment/
---

# AI in OT Risk Assessment: CISA's Framework for Safe AI Procurement

## The Problem

AI vendors are increasingly targeting OT markets with products that promise predictive maintenance, anomaly detection, and process optimisation. Many of these products have no safety certification, no adversarial robustness testing, and no defined failure mode — properties that are unacceptable in safety-critical OT environments. CISA's December 2025 companion guidance, "Principles for Secure Integration of Artificial Intelligence in Operational Technology" (co-authored with Australian Signals Directorate, NSA, FBI, UK NCSC, and German BSI), acknowledges that IT-trained AI evaluation practices — benchmark accuracy, latency, cost — are insufficient for OT.

A classification model with 98% accuracy in a benchmark has a 2% error rate. For email spam filtering, that is acceptable. For a safety system that must correctly identify a dangerous pressure condition every time, it is not. A false negative from an IT anomaly detector means a phishing email reaches a mailbox. A false negative from an AI system monitoring a gas turbine means a compressor surge goes undetected.

CISA's "Assess AI Use in OT" principle requires organisations to answer three questions before procurement: what authority does the AI have over the OT system; what happens when the AI is wrong; and what happens when the AI is attacked. Vendors rarely answer these questions in their sales materials. This article provides a concrete scoring rubric that forces those answers before a purchase order is signed.

This article focuses on the pre-procurement risk assessment phase. Deployment-time controls for ML anomaly detection and LLM-assisted triage are covered in the [AI OT Security Operations](/articles/ai-landscape/ai-ot-security-operations/) article.

## Threat Model

- **AI system with write authority over OT setpoints:** An adversarial input — a spoofed sensor reading, a crafted packet on the OT network, or a manipulated upstream data feed — causes the AI to issue a dangerous control command. The attacker does not need to compromise the PLC directly; compromising the AI system that can write to the PLC is sufficient and may be substantially easier if the AI system runs on commodity IT infrastructure without OT-grade access controls.

- **ML model trained on poisoned operational data:** The AI vendor's model was trained, or is continuously fine-tuned, on operational data. An attacker who can influence that data during the training or retraining window can cause the model to learn a sabotaged definition of "normal." The model will subsequently fail to detect anomalies that match the patterns the attacker introduced during poisoning. This is particularly dangerous for AI systems that advertise continuous learning or adaptive baselining.

- **Vendor AI system that calls back to a cloud API during operation:** Many AI products for OT are architecturally hybrid: the inference engine runs on-premises, but model updates, licence validation, or telemetry are transmitted to a vendor cloud endpoint during operation. A compromise of that cloud endpoint gives an attacker indirect influence over every OT installation running the same product. For air-gapped OT networks, even the presence of this call-home behaviour disqualifies the product without an explicitly supported offline mode.

- **AI system with no defined fail-safe:** If the AI system becomes unavailable — due to a network partition, a GPU hardware failure, a software crash, or a deliberate denial-of-service attack — and no defined fail-safe behaviour exists, the OT system is left in an undefined state. The OT system may have been integrated in a way that the operators have come to rely on AI-generated recommendations for routine decisions. When those recommendations disappear without notice, the operators face an unexpected decision burden at exactly the moment when something has gone wrong.

- **AI-generated alerts suppressed by a confidence threshold:** An AI monitoring system that only surfaces alerts above a confidence threshold creates an exploitable blind spot. An attacker who knows the threshold — from reverse engineering, insider access, or probing — can craft activity that the model scores just below the threshold. High-confidence false negatives are more dangerous than low-confidence false positives because they are invisible: no alert is raised, no analyst sees the activity, and no investigation occurs.

## Hardening Configuration

The following sections define a risk assessment rubric structured around CISA's "Assess AI Use in OT" principle. Each section produces a scored output that feeds a procurement decision gate. An AI product that does not clear the gate is not deployed; it is returned to the vendor with specific requirements, or the procurement is abandoned.

### 1. Authority Classification

Classify the AI system by the authority it has over the OT process before evaluating any other property. Authority classification determines which subsequent assessments are required and sets the minimum bar for acceptable risk.

The four categories, in ascending order of risk:

- **(a) Read-only monitoring.** The AI system observes OT data — sensor readings, historian records, network traffic — but cannot write to any OT component. It has no path to influence physical process state. Compromise of the AI system leaks operational data but cannot cause process disruption directly. Lowest risk.

- **(b) Advisory.** The AI system generates recommendations — alerts, setpoint suggestions, maintenance schedules — that are presented to a human operator for review. No recommendation takes effect without explicit operator confirmation. The AI cannot initiate any write action. Risk is moderate; the primary failure mode is advisory fatigue causing operators to approve recommendations without genuine review.

- **(c) Supervisory.** The AI system adjusts setpoints or issues control commands within defined, bounded ranges, with human oversight and the ability to override or halt the AI at any time. Requires formal change management, defined safe operating envelopes, and real-time operator visibility. High risk; requires functional safety assessment.

- **(d) Autonomous.** The AI system takes control actions without human confirmation in the loop. Highest risk; requires Safety Integrity Level certification per IEC 61508 or equivalent, independent of any safety certification the vendor claims for the underlying OT system. CISA's companion guidance explicitly recommends categories (a) and (b) only for initial OT AI deployments.

```yaml
authority_classification:
  product_name: ""
  vendor: ""
  assessment_date: ""
  assessor: ""

  declared_authority: ""
  evidence_reviewed:
    - ""

  classification:
    category: ""
    rationale: ""

  flags:
    autonomous_without_sil_cert: false
    supervisory_without_safety_assessment: false
    advisory_with_auto_approval_path: false
    read_only_with_write_api_in_sdk: false

  decision: ""
  notes: ""
```

A product that declares itself "advisory" but ships an SDK that exposes a write API to OT setpoints is flagged as `read_only_with_write_api_in_sdk`. The vendor's marketing category is irrelevant; the technical capability is the classification.

### 2. SIL Compatibility Assessment

If the OT system or any subsystem it interfaces with carries a Safety Integrity Level (SIL 1 through SIL 4 per IEC 61508), the AI system must not reduce the overall system SIL. This is not a statement about the AI's internal reliability; it is a statement about how the integrated system behaves. Introducing an AI component with undefined failure modes into a SIL 2 safety loop degrades that loop's SIL to undefined.

The questions that a functional safety engineer must answer before integration:

- Does the AI system have a defined safe state that it enters on failure? A safe state is an operating condition in which the AI's unavailability cannot cause or contribute to a hazardous event. For a monitoring-only AI, the safe state is simply absence of output. For a supervisory AI, the safe state requires the OT system to revert to a defined fallback setpoint without AI input.
- Is the AI's failure mode detectable? A failed AI that returns plausible-looking but incorrect outputs is more dangerous than one that stops responding. Silent degradation — the model continuing to produce outputs after a hardware fault has corrupted its computations — is a specific failure mode that must be addressed in the integration design.
- Can the OT system operate safely without the AI? If the answer is no, the AI has become a safety-critical component regardless of how it was classified at procurement. This changes the SIL requirements retrospectively and means the original SIL assessment must be redone.

```yaml
sil_compatibility_checklist:
  product_name: ""
  ot_system_sil: ""
  assessment_date: ""
  functional_safety_engineer: ""

  safe_state:
    defined: false
    description: ""
    documented_in_vendor_safety_manual: false

  failure_mode_detectability:
    silent_degradation_addressed: false
    watchdog_mechanism_present: false
    output_validation_independent_of_ai: false

  ot_system_without_ai:
    can_operate_safely: false
    fallback_mode_documented: false
    fallback_mode_tested: false
    operator_training_for_ai_loss_exists: false

  sil_impact_assessment:
    reduces_system_sil: false
    requires_independent_safety_assessment: false
    assessment_body: ""

  outcome:
    sil_compatible: false
    conditions: ""
    blocking_issues: []
```

For SIL 3 and SIL 4 systems, a vendor-issued safety manual is a minimum, not a sufficient, condition. An independent functional safety assessment by a TÜV-accredited body or equivalent is required. Budget for this assessment as a procurement cost: it is typically four to eight weeks of engineering effort and should be scoped before the purchase order is raised, not after.

### 3. Adversarial Robustness Questionnaire

Ask these questions of every AI vendor before procurement. A vendor that cannot answer them has not tested their product for adversarial robustness. Treat the absence of answers as a risk signal, not an automatic disqualifier — the OT AI market is nascent and formal adversarial testing is not yet universal — but weight it heavily in the overall procurement score.

```yaml
adversarial_robustness_questionnaire:
  product_name: ""
  vendor: ""
  completed_by: ""
  date: ""

  input_manipulation:
    fgsm_tested:
      answer: false
      evidence: ""
    pgd_tested:
      answer: false
      evidence: ""
    sensor_spoofing_tested:
      answer: false
      methodology: ""
      ot_domain_test_set_used: false

  distribution_shift:
    tested_on_ot_domain_data: false
    domain_test_set_description: ""
    accuracy_under_distribution_shift: ""
    minimum_acceptable_accuracy: ""

  robustness_score:
    vendor_reported_score: ""
    scoring_methodology: ""
    independently_verified: false
    verification_body: ""

  slow_drift_resistance:
    tested: false
    drift_scenario_description: ""
    detection_latency_days: ""
    maximum_acceptable_detection_latency_days: 5

  model_behaviour_on_spoofed_sensors:
    defined_behaviour: false
    description: ""
    reverts_to_safe_state: false

  scoring:
    fgsm_pgd_both_tested: 10
    sensor_spoofing_tested: 10
    ot_domain_test_set: 10
    slow_drift_tested: 10
    independently_verified: 20
    maximum_score: 60
    vendor_score: 0
    procurement_threshold: 30
```

A vendor score below 30 out of 60 on the adversarial robustness questionnaire triggers a procurement block pending further information. A score of zero — a vendor that has conducted no adversarial testing at all — requires escalation to the CISO before the assessment continues.

### 4. Cloud Dependency Audit

Map every network call the AI system makes during operation before deploying it in an OT environment. Vendors frequently do not disclose call-home behaviour in their product documentation; it is discovered only when network monitoring catches it in a test environment. Conduct this audit in a lab network before any production trial.

Run the AI system under its normal operating conditions — inference, anomaly detection, dashboard updates — and capture all outbound connections:

```bash
tcpdump -i any -w /tmp/ai-vendor-traffic.pcap &
TCPDUMP_PID=$!

./run_ai_product_normal_operation.sh --duration 3600

kill $TCPDUMP_PID

tshark -r /tmp/ai-vendor-traffic.pcap \
  -T fields \
  -e ip.dst \
  -e tcp.dstport \
  -e udp.dstport \
  -e dns.qry.name \
  | sort | uniq -c | sort -rn \
  > /tmp/ai-vendor-connections.txt
```

For AI systems that run as containerised workloads, supplement `tcpdump` with `strace` on the primary inference process to catch connections that are established and closed quickly:

```bash
strace -f -e trace=network \
  -p $(pgrep -f ai_inference_engine) \
  2>&1 | grep -E 'connect|sendto|recvfrom' \
  > /tmp/ai-vendor-syscalls.txt
```

Any connection to an IP address or hostname outside the OT network boundary during normal operation is a finding. Classify each finding:

```yaml
cloud_dependency_audit:
  product_name: ""
  vendor: ""
  audit_date: ""
  test_environment: ""
  audit_duration_seconds: 3600

  outbound_connections:
    - destination: ""
      port: 0
      protocol: ""
      purpose: ""
      frequency: ""
      classification: ""
      required_for_operation: false
      air_gap_impact: ""

  findings:
    connections_to_vendor_cloud: 0
    connections_to_third_party_services: 0
    connections_to_update_endpoints: 0
    licence_validation_calls: 0
    telemetry_calls: 0

  offline_mode:
    vendor_claims_offline_mode: false
    offline_mode_tested: false
    offline_mode_duration_tested_hours: 0
    all_features_available_offline: false
    degraded_features_in_offline_mode: []

  air_gap_decision:
    suitable_for_air_gapped_deployment: false
    conditions: ""
    blocking_issues: []
```

For any AI system that makes calls to a vendor cloud API during OT operation, require a demonstrated offline mode before approving deployment. The offline mode must be tested for a duration equivalent to the organisation's maximum expected network isolation period — at minimum 72 hours, and longer for facilities with extended maintenance windows.

### 5. Fail-Safe Requirements

Define the required behaviour when the AI system is unavailable before deploying it. A fail-safe requirement defined after integration is frequently discovered to be impossible to satisfy because the integration architecture assumed AI availability. The fail-safe contract must be agreed with the vendor and tested in the lab environment before production deployment.

The minimum fail-safe requirements for any AI system in an OT environment are:

- Operator notification within a defined time window — recommended 30 seconds — of AI system unavailability.
- No control authority retained by the AI system during unavailability. An AI in supervisory or autonomous category that holds setpoint values during a failure — rather than releasing them to a defined safe value — is a safety hazard.
- Automatic fallback to a documented safe operating state that has been validated against the OT system's process safety analysis.
- Structured logging of every unavailability event, including duration, trigger cause where determinable, and the state of the OT system during the unavailability window.

```yaml
fail_safe_contract:
  product_name: ""
  vendor: ""
  ot_system: ""
  contract_version: "1.0"
  effective_date: ""
  agreed_by:
    vendor_representative: ""
    ot_engineering_lead: ""
    ot_security_lead: ""

  unavailability_notification:
    maximum_notification_delay_seconds: 30
    notification_channel: ""
    notification_recipients: []
    tested: false
    test_date: ""
    test_result: ""

  control_authority_on_failure:
    releases_setpoints_on_failure: false
    fallback_setpoint_values: {}
    fallback_validated_against_process_safety_analysis: false
    validation_reference: ""

  safe_operating_state:
    defined: false
    description: ""
    documented_in_process_safety_analysis: false
    operator_training_completed: false

  unavailability_logging:
    logs_unavailability_events: false
    log_destination: ""
    log_fields:
      - timestamp_start
      - timestamp_end
      - duration_seconds
      - trigger_cause
      - ot_system_state_at_onset
      - ot_system_state_at_recovery

  testing_requirements:
    fail_safe_test_required_before_production: true
    test_scenarios:
      - network_partition
      - gpu_hardware_failure
      - software_crash
      - deliberate_shutdown
    last_test_date: ""
    next_test_date: ""
    test_results_location: ""
```

Test the fail-safe behaviour in the lab environment for each scenario listed before production deployment. The first test of the fail-safe must not be an actual failure event in a live OT environment.

### 6. Vendor Governance Score

Assess the AI vendor's security practices independently of the product's technical properties. A vendor with poor security practices is a persistent risk regardless of how well the product performs at initial assessment: their update pipeline is an attack surface, their support staff are a social engineering target, and their internal security posture determines whether a future vulnerability in the product will be disclosed promptly or suppressed.

Score the vendor on the following criteria:

```yaml
vendor_governance_scorecard:
  vendor: ""
  product: ""
  assessment_date: ""
  assessor: ""

  vulnerability_disclosure:
    has_public_vdp: false
    vdp_url: ""
    cvss_scoring_used: false
    historical_cve_count: 0
    average_patch_response_days: 0
    score: 0
    maximum: 20

  software_bill_of_materials:
    sbom_provided: false
    sbom_format: ""
    sbom_covers_ml_dependencies: false
    sbom_covers_model_artifacts: false
    sbom_update_cadence: ""
    score: 0
    maximum: 15

  model_update_integrity:
    model_updates_signed: false
    signing_key_management_documented: false
    update_verification_client_side: false
    rollback_mechanism_available: false
    score: 0
    maximum: 15

  red_team_and_testing:
    conducts_red_team_exercises: false
    red_team_cadence: ""
    results_shared_with_customers: false
    ot_specific_red_team: false
    third_party_penetration_test: false
    penetration_test_report_available: false
    score: 0
    maximum: 20

  security_certifications:
    iso_27001: false
    soc2_type2: false
    iec_62443_certified_product: false
    iec_61508_sil_certified: false
    score: 0
    maximum: 15

  incident_response:
    has_documented_ir_plan: false
    customer_notification_sla_hours: 0
    ot_specific_ir_playbooks: false
    score: 0
    maximum: 15

  totals:
    raw_score: 0
    maximum_score: 100
    normalised_score: 0.0
    procurement_threshold: 60
    decision: ""
    blocking_issues: []
```

A vendor normalised score below 60 blocks procurement. A score between 60 and 75 requires a written risk acceptance from the CISO with a defined remediation timeline agreed with the vendor. A score above 75 clears this gate and proceeds to final procurement approval.

The absence of a software bill of materials for the AI system — covering both the software dependencies and the model artifacts themselves — is a standalone blocking issue regardless of the overall score. An organisation cannot assess supply chain risk for an AI system whose components are opaque.

## Expected Behaviour After Hardening

After authority classification: an AI product that claims "autonomous optimisation" with no SIL certification is scored as Category (d) and the procurement gate blocks the purchase. The vendor receives a requirements document specifying that deployment requires IEC 61508 functional safety certification at the applicable SIL level before the evaluation resumes.

After adversarial robustness assessment: a vendor that has conducted no adversarial testing scores zero on the robustness questionnaire. The procurement is paused, the vendor is issued a formal request for adversarial test results or a commitment to commission testing against the organisation's OT domain dataset, and a risk acceptance decision is escalated to the CISO.

After cloud dependency audit: an AI system that makes licence validation and telemetry calls to the vendor's cloud API during normal OT operation is flagged as incompatible with the organisation's air-gapped deployment requirement. The procurement does not advance until the vendor demonstrates a supported offline mode that has been tested for the required isolation duration in the lab environment. If the vendor cannot deliver an offline mode, the procurement is abandoned and the requirement is carried forward to the next vendor evaluation.

After fail-safe testing: an AI system in supervisory category that retains its last commanded setpoint value during a network partition — rather than releasing to a defined safe value — fails the fail-safe contract test and cannot be deployed in any OT system with a SIL designation until the behaviour is corrected.

## Trade-offs and Operational Considerations

SIL compatibility assessment requires a functional safety engineer with IEC 61508 expertise. This expertise is not common in most OT security teams and is rarely available in-house at smaller operators. Budget for an external assessment engagement as a procurement cost and scope it before the purchase order is raised. An assessment commissioned after deployment, when a SIL conflict has already been identified, is substantially more expensive to resolve.

Adversarial robustness testing in the OT domain is a nascent field. Most AI vendors targeting OT markets will not have formal adversarial test results for ICS-specific attack scenarios. Use the absence of testing as a risk signal that increases the weight given to other controls — authority classification, fail-safe requirements, and vendor governance — rather than as an automatic disqualifier. Requiring adversarial testing in the procurement requirements document, with a defined timeline for the vendor to commission it, is a more productive outcome than blocking all AI adoption from vendors who are willing to invest in it.

Cloud dependency requirements will disqualify most AI vendors in their current form for air-gapped OT deployments. Use this as a driver for procurement requirements — specify air-gap compatibility as a mandatory requirement in the RFP — rather than as grounds for blocking all AI consideration. The market will respond to procurement requirements that are consistently applied across multiple organisations. An industry body requirement or a regulatory mandate carries more weight than an individual procurement decision; consider participating in relevant working groups (IEC SC65A, ISA99) to contribute to the development of OT-AI standards.

The scoring rubrics in this article are illustrative starting points. Organisations must adapt them to their specific OT risk profile, the regulatory framework governing their sector — NERC CIP for bulk electric, IEC 62443 for industrial automation, FDA 21 CFR Part 11 for pharmaceutical manufacturing — and the specific hazard scenarios documented in their process safety analyses. A rubric that is not calibrated to actual process hazards will produce scores that do not reflect actual risk.

## Failure Modes

- **Risk assessment performed once at procurement but not re-evaluated after model updates.** Vendors ship model updates as routine software releases. A model update can change the AI's failure modes, its confidence threshold behaviour, or its dependency on cloud endpoints. The risk assessment must be repeated — at minimum, the adversarial robustness questionnaire and the cloud dependency audit — after any significant model update, not just after the initial procurement.

- **AI system classified as Advisory but operators routinely approve its recommendations without review.** Effective authority is determined by how the system is used, not by how it is classified. An advisory AI whose recommendations are approved by operators within seconds, without examination, is functioning as an autonomous system for practical purposes. Monitor the approval latency distribution for advisory AI recommendations. If median approval latency falls below a threshold — 30 seconds is a reasonable starting point — investigate whether the governance controls are functioning as intended or have become a rubber stamp.

- **Fail-safe contract defined but not tested.** A fail-safe requirement that exists only as a document is not a control. The first test of the fail-safe must occur in a controlled lab environment, not during an actual failure event in a live OT system. Test every scenario defined in the fail-safe contract on a schedule aligned with the maintenance window cadence, and require evidence that the test was conducted and that the system behaved as specified.

- **Vendor scorecard used as a checkbox rather than a risk input.** An organisation that deploys a low-scoring AI system because "we followed the assessment process" has converted a risk management tool into a liability shield. The scorecard output is a risk input to a procurement decision, not a procurement decision itself. A vendor score of 45 out of 100 means the procurement carries substantial residual risk that must be accepted in writing by an accountable authority, not quietly absorbed into the standard approval process.

## Related Articles

- [AI OT Security Operations](/articles/ai-landscape/ai-ot-security-operations/)
- [AI Governance Pipeline](/articles/ai-landscape/ai-governance-pipeline/)
- [AI Model Cards](/articles/ai-landscape/ai-model-cards/)
- [Algorithmic Auditing](/articles/ai-landscape/algorithmic-auditing/)
- [OT NPC Identity PKI](/articles/cross-cutting/ot-npe-identity-pki/)
