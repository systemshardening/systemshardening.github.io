---
title: "Detection Engineering Metrics: MTTD, MTTR, Signal-to-Noise, and Coverage Tracking"
description: "If you cannot measure your detection program, you cannot improve it. The metrics that matter, how to compute them, and what they trigger when they shift."
slug: "detection-engineering-metrics"
date: 2026-04-27
lastmod: 2026-04-27
category: "observability"
tags: ["detection-engineering", "mttd", "mttr", "metrics", "soc"]
personas: ["security-engineer", "soc-analyst", "sre"]
article_number: 197
difficulty: "intermediate"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/observability/detection-engineering-metrics/index.html"
---

# Detection Engineering Metrics: MTTD, MTTR, Signal-to-Noise, and Coverage Tracking

## Problem

Detection programs accumulate rules over time. A team starts with a handful of carefully-crafted detections; six months later, there are 200; two years later, 800, with nobody quite sure which still fire, which fire too often, which never fire, and which are silently broken because a log schema changed.

Without metrics, the program degrades:

- **Alert fatigue.** Analysts stop investigating alerts they recognize as habitual false positives. Real attacks hide in the same patterns.
- **Coverage drift.** New attacker techniques (a new MITRE ATT&CK sub-technique, a new cloud service abuse pattern) appear; nobody maps the gap.
- **Silent decay.** A detection that worked when written stops firing because the upstream log source was renamed, the log volume dropped, or the rule's threshold no longer fits the baseline.
- **No improvement signal.** A new detection's value is debated subjectively — "this catches something the others don't" — without measurable contribution.

Detection engineering as a discipline (per Palantir's 2018 paper, the SpecterOps and Red Canary practices, the ATT&CK Evaluation results) has a small set of metrics that, tracked together, reveal whether the program is healthy and improving:

- **MTTD (Mean Time To Detect).** From compromise event to first alert.
- **MTTR (Mean Time To Respond).** From first alert to containment.
- **Signal-to-noise ratio (true positive rate).** Of alerts an analyst worked, what fraction were true positives.
- **Coverage.** Of attacker techniques relevant to the environment, what fraction has at least one detection.
- **Decay rate.** Of detections shipped N months ago, what fraction still fire as designed.

This article covers how to define each metric concretely, how to instrument the pipeline to compute them, where the data lives (SIEM + ticketing + version control), and how to act on movement in the numbers.

**Target systems:** Splunk / Elastic / Sentinel / Chronicle SIEMs; PagerDuty / incident.io / Jira ticketing; SOC playbook tooling (Tines, Torq); detection-as-code repositories.

## Threat Model

Different from most articles in this series — the "adversary" here is the detection program decay, not an active attacker. But the consequences of a decayed program are exactly what an attacker exploits.

- **Adversary 1 — Evasion via known-noisy detections:** an attacker reads the same MITRE Navigator dashboard you publish; they craft activity that doesn't trigger your specific rules.
- **Adversary 2 — Exploitation of detection blind spots:** attackers focus their tradecraft on techniques that defenders can't easily detect.
- **Adversary 3 — Alert-fatigue exploitation:** attackers generate noise that triggers known-false-positive detections, burying the real signal.
- **Access level:** All adversaries have either inside knowledge of your detection coverage or generic threat-intel knowledge of common gaps.
- **Objective:** Operate inside detection blind spots; outlast the alert before incident response engages.
- **Blast radius:** Time-bounded by your MTTD. A program with MTTD of hours stops attacks before significant lateral movement; MTTD of days lets the attacker complete most objectives.

## Configuration

### Metric 1: MTTD (Mean Time to Detect)

Measure from the earliest evidence of compromise to the first detection event. Definition matters: "first evidence" usually comes from log review during incident triage, not from anything that fired in real time.

```sql
-- After an incident closes, compute MTTD.
SELECT incident_id,
       compromise_timestamp,                   -- earliest evidence in retro analysis
       first_alert_timestamp,                  -- when the alerting system fired
       (first_alert_timestamp - compromise_timestamp) AS mttd_seconds
FROM incidents
WHERE status = 'closed'
  AND closed_at > now() - interval '90 days';
```

Aggregate:

```sql
SELECT severity,
       percentile_disc(0.5) WITHIN GROUP (ORDER BY mttd_seconds) AS p50_mttd,
       percentile_disc(0.95) WITHIN GROUP (ORDER BY mttd_seconds) AS p95_mttd,
       count(*) AS n
FROM incidents
GROUP BY severity;
```

For incidents where the program never detected (discovered via external report, post-incident audit), MTTD is the time to discovery — usually longer. Track these separately as a coverage-failure signal.

Target ranges (industry baselines):

| Severity | P50 MTTD | P95 MTTD |
|----------|----------|----------|
| Critical (data exfil, ransomware) | < 15 min | < 1 hr |
| High (unauthorized access) | < 1 hr | < 4 hr |
| Medium (policy violation) | < 4 hr | < 24 hr |

### Metric 2: MTTR (Mean Time to Respond / Resolve)

Two flavors, often confused:

- **MTTR-respond:** alert → analyst acknowledges → first investigative action.
- **MTTR-resolve:** alert → containment / closure.

Track both; they reveal different bottlenecks.

```sql
SELECT alert_id,
       fired_at,
       acknowledged_at,
       first_action_at,
       resolved_at,
       (acknowledged_at - fired_at) AS time_to_ack,
       (first_action_at - acknowledged_at) AS time_to_first_action,
       (resolved_at - fired_at) AS time_to_resolve
FROM alerts
WHERE resolved_at IS NOT NULL
  AND fired_at > now() - interval '90 days';
```

A long `time_to_ack` indicates the alerting integration (PagerDuty rotation, on-call setup) needs work. A long `time_to_first_action` indicates the runbook is unclear or the alert lacks context. A long `time_to_resolve` after fast first-action indicates the underlying response process needs improvement.

### Metric 3: Signal-to-Noise Ratio

Of all alerts an analyst worked, what fraction were true positives (resulted in an actual incident or required real action)?

Tracked at alert-disposition time. Every closed alert gets a disposition:

- `true_positive` — confirmed real incident
- `benign_true_positive` — rule fired correctly but on a non-malicious event
- `false_positive` — rule fired when it shouldn't have
- `inconclusive` — could not determine

```sql
SELECT detection_rule,
       count(*) FILTER (WHERE disposition = 'true_positive') AS tp,
       count(*) FILTER (WHERE disposition = 'false_positive') AS fp,
       count(*) FILTER (WHERE disposition = 'benign_true_positive') AS btp,
       count(*) AS total,
       round(count(*) FILTER (WHERE disposition = 'true_positive')::numeric / count(*), 3) AS tpr
FROM alerts
WHERE resolved_at > now() - interval '30 days'
GROUP BY detection_rule
ORDER BY tpr ASC;
```

Rules with TPR < 0.05 over 30 days with > 100 alerts are candidates for tuning, suppression, or retirement. Rules with TPR = 0 over 90 days with > 1000 alerts are definitionally noise; retire or fix them.

### Metric 4: Coverage Against an Attack Framework

Map detection rules to MITRE ATT&CK techniques. Periodically compute coverage:

```yaml
# detections/_meta/rule-mappings.yaml
- rule: mimikatz-command-line
  attck: [T1003.001]
- rule: kerberoasting-detection
  attck: [T1558.003]
- rule: psexec-remote-execution
  attck: [T1021.002, T1570]
```

Compute coverage:

```python
# scripts/coverage.py
import yaml, json
mappings = yaml.safe_load(open("detections/_meta/rule-mappings.yaml"))

# Techniques relevant to your environment.
relevant_techniques = set(open("relevant-techniques.txt").read().splitlines())

covered_techniques = set()
for rule in mappings:
    for t in rule["attck"]:
        covered_techniques.add(t)

print(f"Coverage: {len(covered_techniques & relevant_techniques)} / {len(relevant_techniques)}")
print(f"Gaps: {sorted(relevant_techniques - covered_techniques)}")
```

The MITRE ATT&CK Navigator can render the result. Publish quarterly to leadership; track movement.

Critical caveat: "covered" doesn't mean "detected reliably." A rule for T1003.001 that fires only on a specific tool name won't catch a renamed tool. Pair coverage with quality (TPR) and verification (next metric).

### Metric 5: Detection Decay

The most-overlooked metric. Of detections shipped N months ago, are they still firing as designed?

Two failure modes:

- **Silent decay:** rule no longer fires because the log source it depends on changed schema, was renamed, or stopped emitting.
- **Threshold drift:** rule's threshold (e.g., "more than 100 failed logins in 5 min") no longer matches a baseline that has shifted over time.

Detect via continuous testing. For each rule, store a known-malicious test fixture:

```python
# scripts/test_decay.py
# For each rule, replay test fixtures and confirm the rule fires.
import json, glob

stale_rules = []
for fixture_path in glob.glob("tests/fixtures/*.json"):
    fixture = json.load(open(fixture_path))
    rule_id = fixture["_meta"]["rule_id"]
    expected = fixture["_meta"]["expected"]   # match or no-match
    actual = run_rule_against_events(rule_id, fixture["events"])
    if actual != expected:
        stale_rules.append({"rule": rule_id, "expected": expected, "actual": actual})

print(f"Stale rules: {len(stale_rules)}")
for r in stale_rules:
    print(f"  {r}")
```

Run weekly. Stale rules are P1 — they are the gap an attacker walks through.

Also track: rules that have not fired at all in the production environment over N days. Combined with the test-fixture run: if the fixture says it should fire and the production rule hasn't fired in months, either the environment doesn't see the activity (good) or the rule is broken (bad — investigate).

### Metric 6: Detection Pipeline Latency

How long from event-generation to alert-fired?

```sql
SELECT detection_rule,
       percentile_disc(0.5) WITHIN GROUP (ORDER BY (alert_fired_at - event_timestamp))
         AS p50_pipeline_latency_seconds,
       percentile_disc(0.95) WITHIN GROUP (ORDER BY (alert_fired_at - event_timestamp))
         AS p95_pipeline_latency_seconds
FROM alert_events
WHERE alert_fired_at > now() - interval '7 days'
GROUP BY detection_rule
HAVING count(*) > 50;
```

Targets:

- p50 < 60 seconds for real-time-class detections
- p95 < 5 minutes
- Anything beyond 30 minutes is batch-class detection; document explicitly.

A rule with p50 > 5 minutes is operating in the wrong class — either accept it as batch or fix the pipeline so it runs in real-time.

### Metric 7: Dashboard

Combine the metrics into a single SOC-leadership dashboard:

```
Headline metrics (last 30 days):
  Critical incidents: 3
  P50 MTTD: 11 min  (target <15)        [GREEN]
  P95 MTTD: 47 min  (target <60)         [GREEN]
  P50 MTTR-resolve: 2 h 14 m  (target <4 h)  [GREEN]

Detection program health:
  Total active rules: 312
  Rules with TPR < 0.05: 18  (action: tune)
  Rules with 0 alerts in 90d: 41  (action: verify)
  Stale rules (test-fixture failures): 4  (action: P1)

Coverage:
  ATT&CK techniques relevant: 87
  Covered: 71 (82%)  (was 79% last quarter)
  Recently added gaps: T1497.003, T1656

Pipeline:
  P50 detection latency: 38 s  (target <60 s)  [GREEN]
  P95 detection latency: 3 m 12 s  (target <5 m) [GREEN]
```

Refresh daily. Each line item links to the underlying query and the action playbook.

## Expected Behaviour

| Signal | Without measurement | With measurement |
|--------|----------------------|--------------------|
| Knowledge of program effectiveness | "We catch most things" | Quantitative confidence intervals |
| Detection retirement | Never; rules accumulate | TPR-driven tuning and retirement quarterly |
| Coverage gaps | Discovered post-incident | Identified proactively against ATT&CK |
| Decayed rules | Discovered when an incident slips through | Caught weekly by automated fixture replay |
| Alert volume | Trend unknown | Tracked; can correlate with pipeline change |
| Reporting to leadership | Anecdotal | Dashboard with movement over time |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Disposition discipline | True signal-to-noise visible | Requires analyst discipline at every alert close | Mandatory dropdown at close; analyst metric on dispositions filled. |
| Test-fixture maintenance | Continuous decay detection | Fixtures need refresh as log shape evolves | Auto-extract from production logs (with redaction); rotate fixtures monthly. |
| MITRE mapping per rule | Quantitative coverage | Manual mapping work | One-time per rule; review on PR; tooling (DeTT&CT) can suggest. |
| Pipeline-latency tracking | Catches slow detections | Requires every alert have an `event_timestamp` field | Standardize event-time ingestion at the SIEM ingest pipeline. |
| Public dashboard | Forces accountability | Movement may be embarrassing in early phase | Embrace the visibility; metric movement justifies investment. |
| Gating new detections on TPR | Prevents alert-fatigue accumulation | Reduces detection variety | Allow exceptions for high-severity-rare detections; TPR-gate only the ones that fire >N times/day. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Disposition fields missing or default | Inability to compute TPR | Dashboard shows mostly `inconclusive` dispositions | Train analysts; require disposition before close in tooling. |
| Test fixtures don't match production log shape | Decay tests false-pass while real detections silently broken | Production alerts don't fire while fixtures still pass | Re-extract fixtures from real production logs (sampled, redacted). Rotate fixtures monthly. |
| Latency metric polluted by reprocessing | A backfill or replay produces alerts with high apparent latency | P95 latency suddenly spikes | Tag reprocessed alerts; exclude from real-time SLA. |
| MTTD computed from alert-fire instead of true compromise | Optimistic MTTD that masks coverage gaps | Discrepancy between "detected" incidents and externally-reported ones | Always compute MTTD from earliest evidence found in retro, not from the alert that initiated the response. |
| Coverage map drifts | New ATT&CK sub-techniques appear; mapping not updated | Quarterly coverage report shows decline | Subscribe to ATT&CK release feed; refresh `relevant-techniques.txt` quarterly. |
| Metrics dashboard becomes vanity | Numbers improve but real outcomes don't | Incident reviews don't show fewer / faster | Pair metrics with red-team / purple-team exercises that test actual detection performance. |

## Related Articles

- [Detection-as-Code with Sigma](/articles/observability/detection-as-code-sigma/)
- [Writing Detection Rules That Catch Real Attacks](/articles/observability/detection-rules/)
- [Building a Security Audit Log Pipeline That Scales](/articles/observability/audit-log-pipeline/)
- [Incident Response Runbooks](/articles/observability/incident-response-runbooks/)
- [Lateral Movement Detection](/articles/observability/lateral-movement-detection/)
