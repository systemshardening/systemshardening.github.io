---
title: "AI for OT Security Operations: CISA's Framework for Safe ML in ICS"
description: "CISA's companion AI-in-OT guidance defines governance for ML deployed in industrial control environments. Learn how to build ML anomaly detection for predictable ICS traffic, use LLMs for OT alert triage, and avoid AI failure modes in safety-critical systems."
slug: ai-ot-security-operations
date: 2026-05-03
lastmod: 2026-05-03
category: ai-landscape
tags:
  - ot-security
  - anomaly-detection
  - ics
  - llm
  - ai-governance
personas:
  - security-engineer
  - platform-engineer
article_number: 404
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/ai-landscape/ai-ot-security-operations/
---

# AI for OT Security Operations: CISA's Framework for Safe ML in ICS

## The Problem

IT security operations centres have adopted AI/ML for alert triage, anomaly detection, and threat hunting over the past five years. OT SOCs have lagged for a specific reason: introducing ML models into safety-critical control environments creates new failure modes. A false positive from an ML anomaly detector that triggers an OT system shutdown during peak production is a different category of consequence from a false positive in an IT email spam filter.

CISA's December 2025 companion guidance, "Principles for Secure Integration of Artificial Intelligence in Operational Technology" (co-authored with Australian Signals Directorate, NSA, FBI, UK NCSC, and German BSI), acknowledges this and provides a framework: AI in OT must have defined boundaries, must not create control authority over safety systems without human approval, and must be assessed for adversarial robustness. The April 2026 "Adapting Zero Trust Principles to Operational Technology" guidance reinforces this by requiring continuous verification of all actors in an OT environment — including AI systems making recommendations.

Despite these constraints, OT is actually an excellent environment for ML. Modbus polling cycles, DNP3 scan intervals, and EtherNet/IP I/O update rates are precise, repeatable, and well-bounded. A PLC polling a temperature sensor every 500ms produces a traffic pattern that a statistical anomaly detector can baseline to within single-digit millisecond variance. This predictability allows ML models deployed in OT to achieve false positive rates that IT-focused models can rarely match. The challenge is not the model quality — it is governance. Who approves the model? What can it do when it finds an anomaly? What happens when it is wrong in a water treatment plant at 3am?

CISA's companion guidance defines four principles that structure the governance answer: Understand AI (know what the model does and does not detect), Assess AI Use in OT (test against adversarial conditions before deployment), Establish AI Governance (define the boundary between AI recommendation and human decision), and Embed Safety and Security (ensure AI failures do not propagate to safety systems). This article implements each principle with concrete technical controls.

## Threat Model

- **Undetected ICS lateral movement:** Without ML-assisted detection in the OT SOC, an attacker who gains initial access to the historian server can pivot to PLCs over Modbus without generating a security alert. Engineering workstations query PLCs routinely; a new source doing the same looks identical to a human analyst reviewing raw packet captures.

- **Adversarial ML evasion:** An attacker who knows an ML anomaly model is monitoring the OT network can craft traffic that remains inside the model's learned distribution while still achieving their objective. The canonical example is gradual setpoint drift: incrementally adjusting a Modbus register value over days or weeks, keeping the rate of change below the model's detection threshold at each step, until the physical process is operating outside its safe range.

- **Training data poisoning:** If the training data window for a baseline model includes a period of attacker presence, the model learns the attacker's traffic patterns as normal. A threat actor who maintains a low-and-slow foothold during the baselining period can effectively vaccinate the model against detecting their own activity. This is not a theoretical risk — CISA's guidance specifically calls out poisoning as a concern for AI systems whose training data is derived from the operational environment being protected.

- **Hallucinating LLM triage assistant:** An LLM integrated into the OT SOC for alert triage can misclassify a critical alert as a known-benign pattern if its training data contains similar-looking benign events. Unlike a human analyst who would escalate when uncertain, a poorly configured LLM triage assistant may assign high confidence to an incorrect dismissal. The consequence in an OT environment can be a missed intrusion that reaches a safety instrumented system.

- **AI with write access to OT configuration:** Any AI component authorised to write to PLC setpoints, control logic, or historian configuration becomes a high-value attacker objective. Compromising an AI agent with write access achieves the same outcome as directly compromising a PLC, but may be easier if the AI system's authentication controls are weaker than the PLC's native access controls.

## Hardening Configuration

### 1. ML Traffic Baseline Model

OT traffic exhibits three distinct temporal patterns: daily cycles (shift changes, scheduled reports), weekly cycles (maintenance windows, calibration routines), and seasonal cycles (production rate changes, feedstock variations). A baseline trained on less than two weeks of data misses the weekly maintenance cycle entirely, causing false positives every time maintenance runs. Train on a minimum of 30 days.

The feature set for an OT traffic anomaly model differs from IT network models. OT anomaly detection is primarily about communication structure, not content. The relevant features are: source IP, destination IP, destination port, protocol (from Zeek's OT protocol parsers — `modbus`, `dnp3`, `enip`), inter-packet interval, and byte count. Payload content is secondary because OT protocols carry engineering values whose interpretation requires process context the model does not have. A temperature reading of 450 degrees is anomalous in a boiler monitoring a 200-degree process limit but normal in a steel furnace. The model should flag the unexpected communication, not the value.

Zeek with the [ICSNPP](https://github.com/cisagov/icsnpp) plugins logs Modbus function codes, DNP3 object identifiers, and EtherNet/IP service codes into structured `modbus.log`, `dnp3.log`, and `enip.log` files alongside the standard `conn.log`. Use these as the primary data source.

```python
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import joblib

def load_zeek_conn_log(log_path: str) -> pd.DataFrame:
    df = pd.read_csv(
        log_path,
        sep="\t",
        comment="#",
        names=[
            "ts", "uid", "id.orig_h", "id.orig_p",
            "id.resp_h", "id.resp_p", "proto", "service",
            "duration", "orig_bytes", "resp_bytes",
            "conn_state", "missed_bytes", "history",
            "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"
        ],
        low_memory=False
    )
    df = df[df["service"].isin(["modbus", "dnp3", "enip"])].copy()
    df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
    df = df.dropna(subset=["ts", "id.orig_h", "id.resp_h", "id.resp_p"])
    return df

def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.sort_values(["id.orig_h", "id.resp_h", "id.resp_p", "ts"])
    df["interval"] = df.groupby(
        ["id.orig_h", "id.resp_h", "id.resp_p"]
    )["ts"].diff().fillna(0)

    enc_src = LabelEncoder()
    enc_dst = LabelEncoder()
    enc_svc = LabelEncoder()

    df["src_encoded"] = enc_src.fit_transform(df["id.orig_h"])
    df["dst_encoded"] = enc_dst.fit_transform(df["id.resp_h"])
    df["svc_encoded"] = enc_svc.fit_transform(df["service"].fillna("unknown"))

    features = df[[
        "src_encoded",
        "dst_encoded",
        "id.resp_p",
        "svc_encoded",
        "interval",
        "orig_bytes",
        "resp_bytes",
    ]].fillna(0)

    return features, {"src": enc_src, "dst": enc_dst, "svc": enc_svc}

def train_baseline_model(log_path: str, model_output_path: str) -> None:
    df = load_zeek_conn_log(log_path)
    features, encoders = engineer_features(df)

    model = IsolationForest(
        n_estimators=200,
        contamination=0.001,
        random_state=42,
        n_jobs=-1
    )
    model.fit(features)

    joblib.dump({"model": model, "encoders": encoders}, model_output_path)
    print(f"Model trained on {len(features)} OT connection records.")
    print(f"Saved to {model_output_path}")

def score_new_connections(log_path: str, model_path: str, threshold: float = -0.15) -> pd.DataFrame:
    df = load_zeek_conn_log(log_path)
    features, _ = engineer_features(df)

    artifact = joblib.load(model_path)
    model = artifact["model"]

    scores = model.score_samples(features)
    df["anomaly_score"] = scores
    df["anomaly"] = scores < threshold

    anomalies = df[df["anomaly"]].copy()
    return anomalies[["ts", "id.orig_h", "id.resp_h", "id.resp_p", "service", "anomaly_score"]]
```

Run the scorer continuously against live Zeek output. Any connection with an `anomaly_score` below the threshold generates a SIEM alert. New source IPs communicating on Modbus port 502 will have no prior history in the feature space and score well below threshold.

```bash
python3 score_connections.py \
  --log /data/zeek/conn.log \
  --model /opt/ot-baseline/isolation_forest.pkl \
  --threshold -0.15 \
  --output-siem tcp://siem.corp:5044
```

### 2. Governance Boundary: Read-Only AI

CISA's Establish AI Governance principle is explicit: AI systems in OT must operate within defined functional boundaries, and the boundary between AI recommendation and AI action must be enforced technically, not just by policy.

The implementation is architectural. The service account or API key used by the ML scoring system must have read-only access to the OT network monitoring infrastructure. It must not have write access to the historian, the engineering workstation file shares, or — critically — to the OT SIEM ticketing system in a way that allows autonomous alert closure.

Document this as a formal governance statement, version-controlled alongside the model artifact:

```yaml
ai_governance_policy:
  system_id: ot-anomaly-detector-v1
  version: "1.0"
  effective_date: "2026-05-03"
  owner: ot-security-team

  access_controls:
    data_sources:
      - name: zeek-conn-log
        access: read-only
        path: /data/zeek/
      - name: ot-siem-api
        access: write-alert-only
        scope: "CREATE new alert; PROHIBITED: close, suppress, update severity"

    prohibited_actions:
      - write to PLC setpoints
      - write to historian configuration
      - close or suppress SIEM alerts
      - modify network ACLs or firewall rules
      - trigger automated response playbooks without human approval

  human_approval_requirements:
    - action: change detection threshold
      approvers: [ot-security-lead, ot-engineering-lead]
      minimum_approvals: 2
      approval_channel: out-of-band (voice or physical presence)
    - action: retrain model
      approvers: [ot-security-lead]
      minimum_approvals: 1
      approval_channel: signed ticket in SIEM

  review_schedule:
    frequency: quarterly
    trigger_events:
      - major OT reconfiguration (new PLC, new network segment)
      - confirmed false positive cluster (> 5 per shift)
      - confirmed false negative (missed incident)
      - model retrain
```

The out-of-band approval requirement for threshold changes and retrains matters. If the approval channel is the same system the AI is connected to, a compromised AI component could fabricate or influence the approval record.

### 3. LLM-Assisted OT Alert Triage

OT SOC analysts deal with alert queues that mix genuine anomalies with maintenance noise, vendor remote-access sessions, and firmware update traffic. An LLM triage assistant can pre-classify alerts by comparing the anomaly features against known-benign patterns documented in your OT asset inventory, reducing the analyst's time to the high-confidence anomalies.

The pattern: Zeek generates an anomaly alert, the scoring pipeline enriches it with asset context from the OT asset inventory (asset owner, asset type, expected communication partners, maintenance schedule), the enriched alert is passed to the LLM via a structured prompt, and the LLM returns a triage classification with a confidence score. The LLM output is advisory only. No alert is closed, suppressed, or downgraded without analyst confirmation.

```python
import anthropic
import json
from datetime import datetime

SYSTEM_PROMPT = """You are an OT security analyst assistant. You triage anomaly alerts from an industrial control system network.

Your role is ADVISORY ONLY. Your output will be reviewed by a human analyst before any action is taken. You do not have the ability to close alerts, modify system configurations, or take any action in the OT environment.

Context you will receive:
- Anomaly alert details (source IP, destination IP, port, protocol, anomaly score)
- Asset inventory context for the source and destination assets
- Recent alert history for the same asset pair
- Scheduled maintenance windows currently active

Your output must be a JSON object with exactly these fields:
- classification: one of ["likely_benign", "requires_investigation", "high_priority_escalate"]
- confidence: a float between 0.0 and 1.0
- reasoning: a single paragraph explaining your classification
- recommended_analyst_actions: a list of 1-3 specific investigative steps for the human analyst
- data_gaps: any information that would change your classification if available

Constraints:
- Do not classify as "likely_benign" if confidence is below 0.85.
- Do not classify as "high_priority_escalate" without citing a specific threat pattern from MITRE ATT&CK for ICS.
- If you lack sufficient OT context to classify with confidence >= 0.6, set classification to "requires_investigation".
- Never recommend closing or suppressing the alert in your output."""

def triage_ot_alert(alert: dict, asset_context: dict, recent_history: list) -> dict:
    client = anthropic.Anthropic()

    user_message = json.dumps({
        "alert": alert,
        "asset_context": asset_context,
        "recent_alert_history_24h": recent_history,
        "current_time_utc": datetime.utcnow().isoformat()
    }, indent=2)

    response = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}]
    )

    raw_output = response.content[0].text

    try:
        triage_result = json.loads(raw_output)
    except json.JSONDecodeError:
        triage_result = {
            "classification": "requires_investigation",
            "confidence": 0.0,
            "reasoning": "LLM output was not valid JSON. Route to human analyst immediately.",
            "recommended_analyst_actions": ["Review raw alert manually"],
            "data_gaps": ["LLM triage failed — raw output: " + raw_output[:500]]
        }

    triage_result["triage_timestamp"] = datetime.utcnow().isoformat()
    triage_result["advisory_only"] = True
    triage_result["human_confirmation_required"] = True

    return triage_result
```

Set a maximum response time SLA for the LLM component — 30 seconds is a reasonable starting point for OT SOC triage. If the LLM does not respond within the SLA, route the alert directly to the analyst queue without LLM pre-classification. Never block alert delivery waiting for an LLM response.

### 4. Adversarial Robustness Requirements

CISA's Assess AI Use principle requires testing the anomaly model against adversarial inputs before deployment. For OT anomaly detection, the primary adversarial technique is slow-drift injection: gradually shifting a value over time so that no single observation exceeds the model's detection threshold, but the cumulative effect places the process outside its safe operating range.

Before deploying the model in production, run a slow-drift injection test against a copy of the model trained on the baseline dataset:

```python
import numpy as np
import pandas as pd
import joblib
from datetime import datetime, timedelta

def slow_drift_injection_test(
    model_path: str,
    baseline_features: pd.DataFrame,
    drift_days: int = 7,
    polls_per_day: int = 172800,
    initial_value: float = 250.0,
    target_value: float = 450.0,
    detection_threshold: float = -0.15
) -> dict:
    artifact = joblib.load(model_path)
    model = artifact["model"]

    total_polls = drift_days * polls_per_day
    drift_per_poll = (target_value - initial_value) / total_polls

    detected_polls = []
    detection_day = None

    for poll_index in range(total_polls):
        current_value = initial_value + (drift_per_poll * poll_index)
        day = poll_index // polls_per_day

        sample = baseline_features.sample(1).copy()
        sample["orig_bytes"] = current_value

        score = model.score_samples(sample)[0]

        if score < detection_threshold:
            detected_polls.append(poll_index)
            if detection_day is None:
                detection_day = day

    detection_rate = len(detected_polls) / total_polls
    result = {
        "drift_days": drift_days,
        "initial_value": initial_value,
        "target_value": target_value,
        "total_polls_tested": total_polls,
        "anomaly_polls_detected": len(detected_polls),
        "detection_rate": round(detection_rate, 4),
        "first_detection_day": detection_day,
        "meets_requirement": detection_rate >= 0.90 and detection_day is not None and detection_day <= 5
    }

    return result

def assert_adversarial_requirements(test_result: dict) -> None:
    assert test_result["detection_rate"] >= 0.90, (
        f"Model detects only {test_result['detection_rate']:.1%} of slow-drift polls. "
        f"Minimum requirement is 90%. Retrain with longer baseline or adjust threshold."
    )
    assert test_result["first_detection_day"] is not None, (
        "Model never detected the drift. Do not deploy."
    )
    assert test_result["first_detection_day"] <= 5, (
        f"Model first detected drift on day {test_result['first_detection_day']}. "
        f"Maximum acceptable first detection is day 5 of a 7-day drift."
    )
    print(f"Adversarial robustness test PASSED.")
    print(f"  Detection rate: {test_result['detection_rate']:.1%}")
    print(f"  First detection: day {test_result['first_detection_day']}")
```

The minimum requirements are: detect 90% of injected anomaly polls in the test set, and achieve first detection no later than day 5 of a 7-day drift scenario. A model that fails these requirements must not be deployed in production, regardless of its performance on the standard evaluation set.

### 5. Model Retraining Controls

Model retraining in an OT environment is a security-sensitive operation. A retrain that incorporates data from a period of attacker presence will encode the attacker's behaviour as normal. The controls are:

```yaml
retraining_policy:
  system_id: ot-anomaly-detector-v1

  authorization:
    who_can_request: [ot-security-lead, ot-security-analyst]
    who_must_approve: [ot-security-lead]
    minimum_approvals: 1
    approval_must_precede_retrain: true

  prohibited_conditions:
    - condition: active_incident_open
      description: "Do not retrain while a security incident is open in the OT environment."
    - condition: post_incident_window
      description: "Do not retrain using data from the 30 days following incident closure without manual data review."
    - condition: unreviewed_anomaly_cluster
      description: "Do not retrain if there are unreviewed anomaly alerts in the queue from the proposed training window."

  data_provenance_requirements:
    - log_training_window_start: required
    - log_training_window_end: required
    - log_data_sources: required
    - log_anomaly_alerts_in_window: required
    - log_incidents_in_window: required
    - sign_training_dataset_hash: required

  logging:
    retrain_events_log: /var/log/ot-ai/retrain-audit.log
    log_fields:
      - timestamp
      - requested_by
      - approved_by
      - approval_ticket_id
      - training_window_start
      - training_window_end
      - training_dataset_sha256
      - previous_model_sha256
      - new_model_sha256
      - adversarial_test_result

  post_retrain_validation:
    - adversarial_robustness_test: required (must pass before deployment)
    - comparison_against_previous_model: required
    - staging_period_days: 3
```

Every retrain event must be logged with the training data hash, the previous model hash, the new model hash, and the adversarial test result. This creates an auditable chain: if a future incident reveals that the model missed something, you can determine exactly which data was used to train the version that was running and whether that data window overlapped with the incident.

## Expected Behaviour After Hardening

After ML baseline deployment, a new source IP communicating on Modbus port 502 generates an anomaly score below the `-0.15` threshold and creates a SIEM alert within one polling cycle (500ms to 1 second, depending on the Zeek analysis pipeline latency). The alert includes source IP, destination IP, port, protocol, anomaly score, and the asset inventory context for the destination PLC.

After governance control implementation, an AI-generated triage recommendation to change a PLC setpoint — whether generated by the LLM triage assistant or any other AI component — is logged as a draft recommendation in the SIEM with status `pending_human_approval`. No write action occurs. The analyst sees the recommendation alongside the original alert and must explicitly confirm or reject it. The confirmation action is logged with the analyst's identity and timestamp.

After adversarial testing, the slow-drift injection test detects the injected drift at day 4 of the 7-day test scenario, achieving a detection rate above 90% for the full test set. The model is certified for deployment and the test result is stored alongside the model artifact in the model registry.

## Trade-offs and Operational Considerations

LSTM autoencoders can capture temporal dependencies in OT traffic more precisely than Isolation Forest — a PLC that polls every 500ms will have a highly structured inter-packet interval sequence that a sequence model can learn. However, LSTM training requires GPU infrastructure and significantly longer training times. For small OT deployments (fewer than 50 PLCs, single production line), an Isolation Forest or Z-score model over a 30-day window achieves acceptable detection rates with CPU-only infrastructure and retrains in minutes rather than hours. Start simple and add complexity only when the simpler model's false positive or false negative rate is demonstrably insufficient.

Model retraining controls that require security team approval add delay. If a major OT reconfiguration (a new PLC installed, a new network segment added) requires a retrain before the model stops generating false positives, the approval process may take 24 to 48 hours. During that period, the analyst must manually filter false positives on the new asset. This is a deliberate trade-off: the cost of a day of manual filtering is lower than the cost of a poisoned model that passes an attacker's activity as normal for the next 90 days.

LLM-based triage adds latency to alert response. A 30-second SLA is appropriate for non-emergency triage, but if the OT SOC receives a burst of 50 anomaly alerts during an active incident (a plausible scenario when an attacker begins lateral movement), the LLM queue may become a bottleneck. Implement a circuit breaker: if the LLM response queue exceeds a configurable depth, bypass LLM triage and route all alerts directly to the analyst queue with a tag indicating that LLM triage was skipped.

OT-specific context is sparse in public LLM training data. Most LLM models have seen extensive IT security content but relatively little on ICS-specific protocols, PLClogic, or MITRE ATT&CK for ICS. If the LLM triage assistant consistently misclassifies DNP3 or Modbus anomalies, consider fine-tuning on ICS-CERT advisories, the MITRE ATT&CK for ICS knowledge base, and your own OT network documentation. Alternatively, include relevant ICS context directly in the system prompt as few-shot examples.

## Failure Modes

- **ML model trained on too short a baseline (under 2 weeks):** Weekly maintenance windows, scheduled calibration runs, and vendor remote-access sessions do not appear in the training data. Every maintenance window generates a false positive cluster. Analysts learn to ignore Monday morning alerts, which is precisely when an attacker would choose to operate. Always train on a minimum of 30 days.

- **AI triage assistant deployed with write access to the ticketing system:** The LLM triage assistant can close or suppress alerts autonomously if its service account has `UPDATE` permission on alert records. A hallucinating LLM dismissing a critical alert as benign, with no human seeing it, is a complete failure of the triage control. The service account must be scoped to `CREATE` new annotation records only, not to update the alert's status.

- **Model not retrained after major OT reconfiguration:** A new PLC added to the OT network has no representation in the training data. Every connection to or from that PLC generates an anomaly alert. If the retraining process takes days and the false positive rate is high, analysts will begin treating all anomaly alerts as likely noise — and will miss a real intrusion on another asset that happens to be flagged at the same time as the legitimate new-PLC traffic.

- **No human review of AI recommendations in the SOC:** Alert fatigue combined with an advisory AI creates a perverse dynamic: analysts approve AI-recommended dismissals without reading them because the volume is high and the AI has been right 19 out of 20 times. The 20th alert, which the AI misclassified as benign, is the one that matters. Require a mandatory review field for any AI-recommended dismissal that includes a free-text justification from the analyst. The friction is intentional.

## Related Articles

- [OT Network Monitoring Malcolm](/articles/observability/ot-network-monitoring-malcolm/)
- [AI Agent Observability](/articles/ai-landscape/ai-agent-observability/)
- [AI Governance Pipeline](/articles/ai-landscape/ai-governance-pipeline/)
- [Detecting AI Attacks](/articles/ai-landscape/detecting-ai-attacks/)
- [Continuous Red Teaming](/articles/ai-landscape/continuous-red-teaming/)
