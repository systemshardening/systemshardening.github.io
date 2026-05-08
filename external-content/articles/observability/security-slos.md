---
title: "Security SLOs and Error Budgets: SRE Discipline Applied to Detection and Response"
description: "Treat security as a service: define SLIs (detection coverage, MTTD), set SLOs, track burn rate. The same discipline that makes reliability measurable makes security measurable."
slug: "security-slos"
date: 2026-04-29
lastmod: 2026-04-29
category: "observability"
tags: ["slo", "sre", "metrics", "detection", "incident-response"]
personas: ["security-engineer", "sre", "engineering-manager"]
article_number: 221
difficulty: "intermediate"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/observability/security-slos/index.html"
---

# Security SLOs and Error Budgets: SRE Discipline Applied to Detection and Response

## Problem

Engineering organizations adopted SRE-style SLOs (service-level objectives) and error budgets a decade ago. Reliability became measurable; teams justified investment based on burn rate; on-call rotations had clear targets.

Security has lagged. The standard "metrics" — vulnerability counts, patch SLA, audit findings — are activity, not outcomes. They tell you nothing about whether the security program is working. The questions that matter — "are we detecting attacks fast enough?", "are we responding fast enough?", "is the program improving?" — get qualitative, post-hoc answers.

By 2026 the practice is maturing: security teams adopt SLO discipline. The framework: pick a small set of measurable Service Level Indicators (SLIs), set Service Level Objectives (SLOs) defining acceptable thresholds, track burn rate against the SLO. When burn-rate exceeds budget, the team prioritizes fixing the underlying gap.

The specific gaps in non-SLO security programs:

- "We detect attacks" — how fast? what fraction?
- "We respond to incidents" — within what time?
- "Coverage is comprehensive" — measured how?
- "We're getting better" — compared to what?

This article covers the SLI selection for security, defining realistic SLO targets, computing burn rate over rolling windows, the operational integration with engineering management (where SLO violations drive prioritization), and the failure modes — chasing the wrong metric, tying compensation to easily-gamed numbers.

**Target systems:** Prometheus / Grafana for metrics; SLI sources: SIEM, alerting platform, ticketing system, drill-results database. Alerting via Pyrra, Sloth, or hand-rolled error-budget alerting.

## Threat Model

Different from typical articles — the "adversary" is the security gap that emerges when the program lacks measurable accountability:

- **Adversary 1 — Steady decay:** the program ships features, accumulates debt, declines in effectiveness. Without measurement, decline is invisible until breach.
- **Adversary 2 — Whack-a-mole prioritization:** every quarter is a new shiny project; baseline operations (rule maintenance, drill repetition) atrophy.
- **Adversary 3 — Activity-vs-outcome confusion:** the program produces lots of activity (rules written, dashboards built, vulnerabilities patched) without measurable outcome improvement.
- **Access level:** the failure mode is internal accountability.
- **Objective:** the bad outcome — visible only when an incident reveals what the program failed to prevent.
- **Blast radius:** unbounded; under-performing security programs face the same external threats with less effective defense.

## Configuration

### Step 1: Pick SLIs (Service Level Indicators)

Three categories produce SLIs that are both measurable and meaningful:

**Detection SLIs:**

- **Detection coverage:** fraction of MITRE ATT&CK techniques relevant to your environment that have at least one detection rule with TPR > some threshold.
- **Detection latency:** time from event-generation to alert-fired.
- **MTTD (mean time to detect):** time from compromise event to first detection — measured per incident, retrospectively.

**Response SLIs:**

- **Time to acknowledge (TTA):** alert fired → analyst acknowledges.
- **Time to first action (TTFA):** alert fired → first investigative action.
- **Time to containment:** alert fired → blast radius limited.
- **Time to resolution:** alert fired → closed.

**Program-health SLIs:**

- **Detection-rule decay rate:** percent of rules failing weekly fixture tests.
- **Drill cadence compliance:** drills run vs. scheduled.
- **Threat-model freshness:** percent of services with TM reviewed within 365 days.

Pick 4-7 SLIs total. More than that becomes ceremony rather than instrument.

### Step 2: Define SLOs

For each SLI, pick a threshold the team commits to. Realistic, not aspirational.

```yaml
# slos.yaml — checked into the security-team repo.
slos:
  - name: "P1 Detection Latency"
    description: "Critical detection rules fire within 60 seconds of event generation."
    sli:
      type: histogram_p95
      query: 'histogram_quantile(0.95, sum by (le) (rate(detection_pipeline_latency_seconds_bucket{severity="critical"}[5m])))'
    objective: 60   # seconds
    period: 30d
    error_budget_minutes: 21.6   # 0.05% of 30d, computed below

  - name: "Alert Acknowledgement Time"
    description: "Critical alerts acknowledged by on-call within 5 minutes p99."
    sli:
      type: histogram_p99
      query: 'histogram_quantile(0.99, sum by (le) (rate(alert_acknowledge_seconds_bucket{severity="critical"}[5m])))'
    objective: 300
    period: 30d

  - name: "Detection-Rule Test Coverage"
    description: "All active detection rules pass weekly fixture tests."
    sli:
      type: ratio
      good: 'detection_rule_tests_total{result="pass"}'
      total: 'detection_rule_tests_total'
    objective: 0.99
    period: 7d

  - name: "Threat-Model Freshness"
    description: "Tier-1 services have threat models reviewed within 365 days."
    sli:
      type: ratio
      good: 'service_threat_model_age_days{tier="1"} < 365'
      total: 'count(service_threat_model_age_days{tier="1"})'
    objective: 0.95
    period: 30d
```

The `error_budget` for "P1 Detection Latency" computes as: in a 30-day window, 0.05% (the 99.95% target) of measurements may exceed 60s. With a measurement every minute (43,200 measurements/30d), error budget = 21.6 measurements.

### Step 3: Burn Rate Alerting

A 30-day SLO with rapid burn means the team is on track to violate it. Burn rate = (SLO violation rate observed in window) / (acceptable steady-state rate).

```yaml
# alerting-rules.yaml
groups:
  - name: security-slo-burnrate
    rules:
      - alert: HighBurnRateP1Detection
        expr: |
          (
            sum(rate(detection_pipeline_latency_seconds_bucket{severity="critical",le="60"}[1h]))
            /
            sum(rate(detection_pipeline_latency_seconds_count{severity="critical"}[1h]))
          ) < 0.99   # less than 99% within budget over 1h
          AND
          (
            sum(rate(detection_pipeline_latency_seconds_bucket{severity="critical",le="60"}[5m]))
            /
            sum(rate(detection_pipeline_latency_seconds_count{severity="critical"}[5m]))
          ) < 0.99
        for: 5m
        labels:
          severity: critical
          team: security
        annotations:
          summary: "P1 detection latency burning budget at high rate"
          description: |
            In the last 1h, > 1% of P1 detections breached the 60s latency SLO.
            At this rate, the 30-day budget will be exhausted in {{ ... }}.
```

The dual-window approach (1h + 5m) catches both sudden bursts and sustained drift. Pyrra and Sloth automate this rule generation from the SLO config.

### Step 4: Incident-Driven SLI Updates

After every incident, compute its impact on SLIs:

```python
# update-slo-from-incident.py
def update_mttd_for_incident(incident):
    """Compute MTTD from an incident's retrospective and update SLI dataset."""
    compromise_time = parse_iso(incident["compromise_evidence_earliest_timestamp"])
    first_alert = parse_iso(incident["first_alert_fired_at"])
    mttd_seconds = (first_alert - compromise_time).total_seconds()
    metrics.histogram("incident_mttd_seconds",
                      labels={"severity": incident["severity"]},
                      value=mttd_seconds)

    # Also: did any pre-incident detection rules fire that, in retrospect, should have escalated?
    if incident.get("detection_rules_fired_in_window"):
        metrics.counter("incident_rule_fired_underranked_total",
                        labels={"severity": incident["severity"]}).inc()
```

The SLI is the histogram of incident-MTTDs over time. SLO violations (MTTD > target for too many incidents) trigger backlog work.

### Step 5: Dashboards That Drive Action

Per-SLO dashboard with three things: current burn rate, time-to-budget-exhaustion projection, top contributing factors.

```
P1 Detection Latency SLO  (objective: <60s p95)
  Current 30d window:  98.7%   (target 99.95%)  [BURNING]
  Time-to-exhaustion:  14 days
  Top contributors:
    - rules/aws/iam-priv-esc:    p95=320s   (slow CloudTrail ingest)
    - rules/k8s/secret-access:    p95=180s   (audit-log batching)
    - all other rules combined:   p95=42s
  Action: tickets PROD-1234 (CloudTrail ingest tuning), PROD-1235 (audit batching)
```

The dashboard is one surface; the tickets are the work. SLO violation = ticket priority elevation.

### Step 6: SLO Review Cadence

Weekly SLO review with engineering management:

- Which SLOs are burning?
- Are the underlying tickets prioritized?
- Are objectives still right? (After 6+ months, recalibrate.)

Quarterly: re-evaluate the SLI selection. Some SLIs become uninteresting (always green, no signal); others become important (new threat surface).

### Step 7: Connecting to Business

For executive reporting, translate SLOs to business outcome:

```
Detection Coverage: 87% (target 90%)
  → 13% of relevant attacker techniques have no reliable detection.
  → Estimated mean dwell time for those attacks: 14 days
  → Estimated incident scope multiplier vs. covered detections: 3.5x

MTTD p95 (across all incidents in 90 days): 4.3 hours (target 1 hour)
  → For the 95% of incidents detected slowly, attacker had ~4x more time to act.
  → Expected loss given an incident: 2x baseline.
```

The translation requires assumptions; document them. Business-leadership consumption is "X% improvement in MTTD reduces expected loss by Y%."

### Step 8: Avoid Common Anti-Patterns

- **Optimize for SLI, not for outcome.** If the SLI is "alerts acknowledged within 5 min" and incentives reward this, analysts will ack-and-investigate-later. Pair with quality SLIs (e.g., "incidents resolved correctly").
- **Tie SLOs to compensation.** Easily gamed; people optimize for the metric, not the goal.
- **Set unrealistic SLOs.** A 99.99% target sounds impressive; if it's perpetually violated, it loses meaning. Set SLOs you can hit ~95% of the time, with budget for the rest.
- **Drown in SLIs.** 4-7 is the sweet spot. More becomes noise.
- **Ignore burning budget.** Every burn is a signal; if you ignore it, the SLO program is theatre.

## Expected Behaviour

| Signal | Without SLOs | With SLOs |
|--------|----------------|------------|
| Investment justification | Anecdotal | Quantified — "MTTD violated; need detection-engineering cycles" |
| Engineering-management visibility | Project status | SLO compliance trend |
| Drift detection | Discovered post-incident | Caught at burn-rate alerting |
| Cross-team coordination | Ad-hoc | Tied to specific SLO violations |
| Calibration over time | Static | Reviewed quarterly |
| Connection to business outcome | Implicit | Explicit translation |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Defined SLIs | Measurable program health | Some SLIs are noise; require maintenance | Quarterly review; prune SLIs that don't drive action. |
| Realistic SLOs | Honest signal | Less impressive on paper | Frame for engineering audience; for executive reporting, translate. |
| Burn-rate alerting | Proactive, not reactive | Alert fatigue if too many SLOs | Limit to 4-7 SLOs total; high-volume metrics get burn-rate alerts. |
| Incident-derived SLIs | Connects metrics to actual outcomes | Each incident requires retrospective discipline | Use post-incident ticket templates; populate SLI fields automatically where possible. |
| Cross-team SLO ownership | Shared accountability | Negotiation between teams | Make ownership explicit per SLO; engineering management arbitrates. |
| Quarterly SLO review | Calibration over time | Meeting overhead | 1 hour per quarter. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| SLO drift over time | SLOs always green / always red | No useful signal | Recalibrate to a realistic threshold; avoid both extremes. |
| SLI gaming | Numbers improve, real outcomes don't | Incident retrospectives don't show improvement | Pair leading SLIs (latency, ack time) with lagging SLIs (incident MTTD computed from retrospectives). |
| Alert fatigue | Burn-rate alerts daily | Engineering ignores | Tune; not every SLO needs a fast-burn-rate alert. |
| Compensation tied to SLI | Behavior shifts to gaming | Hard to detect from numbers | Don't tie security SLOs to individual compensation. Use them for prioritization, not performance review. |
| Budget exhaustion ignored | SLO violations don't drive ticket priority | Burn alerts fire repeatedly without resolution | Engineering management mandates: SLO red = ticket priority, period. |
| Wrong objects measured | SLIs don't correlate with security outcome | Quarterly review reveals lack of correlation | Replace; don't keep an irrelevant metric for tradition. |
| Budget consumed by single event | One bad week wipes a quarter | Trend analysis | Two-tier alerting: page on imminent violation, daily-digest for slow burn. |

## Related Articles

- [Detection Engineering Metrics](/articles/observability/detection-engineering-metrics/)
- [Alert Deduplication and Correlation Patterns](/articles/observability/alert-correlation/)
- [SIEM Cost Optimization](/articles/observability/siem-cost-optimization/)
- [Tabletop Exercises and Chaos Security Drills](/articles/cross-cutting/tabletop-exercises/)
- [Incident Response Hardening Playbook](/articles/cross-cutting/incident-response-hardening-playbook/)
