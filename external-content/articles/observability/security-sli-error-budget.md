---
title: "Security SLIs and Error Budgets: Measuring Posture with SRE Discipline"
description: "Apply SRE error-budget discipline to security posture: define SLIs for mTLS coverage, vulnerability scan pass rates, secret rotation, patch SLA, and MTTD. Set realistic SLOs, implement multi-window burn-rate alerts in Prometheus, and use budget depletion to trigger security sprints."
slug: security-sli-error-budget
date: 2026-05-07
lastmod: 2026-05-07
category: observability
tags:
  - sli
  - slo
  - error-budget
  - security-metrics
  - posture-management
personas:
  - security-engineer
  - security-analyst
article_number: 567
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/observability/security-sli-error-budget/
---

# Security SLIs and Error Budgets: Measuring Posture with SRE Discipline

## Problem

Security posture is usually described in terms of activity: vulnerabilities patched, scans run, audits completed. Activity metrics are not outcome metrics. You can patch 100% of your critical CVEs while an attacker moves through an unmonitored east-west path. You can run a vulnerability scanner on every image while skipping the ones that never get rebuilt. Activity feels like progress; outcome measurement tells you whether the program is working.

SRE teams solved the equivalent problem for reliability a decade ago. Service Level Indicators (SLIs) — measurable ratios of good events to total events — replaced MTTF estimates and anecdotal uptime claims. Error budgets gave teams a mechanism to negotiate between reliability investment and feature velocity. Burn-rate alerting caught degradation before the SLO window closed.

The same framework applies directly to security posture. An SLI measuring the fraction of traffic with valid mTLS is as concrete as an availability SLI measuring the fraction of successful HTTP requests. An error budget for patch SLA compliance is as operationally useful as an error budget for p99 latency. The math is identical; the instrumentation is different.

This article covers:

- Selecting security SLIs that are measurable and meaningful
- Setting SLO targets at realistic thresholds (not 100%)
- Computing error budgets and understanding what they represent
- Implementing SLIs as Prometheus recording rules
- Multi-window burn-rate alerting with PrometheusRules
- Using error budget depletion to trigger security sprints
- Reporting posture to leadership via SLO dashboards

## Why 100% Is the Wrong Target

The instinct in security is to demand 100%: all traffic encrypted, all images scanned, all secrets rotated, all patches applied. This produces two problems.

First, 100% targets are dishonest. Known exceptions exist in every real environment. A legacy integration that cannot support mTLS, a base image with a pinned vulnerability while the upstream fix is validated, a secret with a longer rotation window for operational reasons. If the target is 100% and the actual state is 98.5% due to managed exceptions, the SLO reports red permanently and teams stop reading it.

Second, 100% targets eliminate the error budget entirely. The error budget is the operational mechanism: it is the allowance of imperfection that can be traded for velocity, absorbed by known exceptions, and monitored as it depletes. Remove the budget and the framework degrades to a simple alert that is permanently firing.

A 99.5% mTLS coverage SLO says: "At most 0.5% of traffic may traverse unencrypted paths." That 0.5% is the error budget. It accommodates the two legacy services you cannot migrate until Q3. It allows transient drops during certificate renewal. When the budget starts burning faster than expected, it signals something new is going wrong — not the planned exceptions, but an unplanned regression.

The correct target is the level you can reliably achieve given known exceptions, with budget left over to detect unplanned degradation.

## Security SLIs: The Core Set

Six categories cover the posture surface of most infrastructure-focused security programs. Each is expressible as a ratio suitable for Prometheus.

### mTLS Coverage

**What it measures:** The fraction of in-cluster service-to-service traffic that carries a valid mutual TLS session. Measured at the sidecar proxy or service mesh control plane.

**Why it matters:** Unencrypted east-west traffic is the attacker's path after initial access. An mTLS coverage SLI tells you whether your mesh is enforcing STRICT mode everywhere or whether PERMISSIVE exceptions are spreading.

**Prometheus expression:**
```
sum(rate(istio_requests_total{connection_security_policy="mutual_tls"}[5m]))
/
sum(rate(istio_requests_total[5m]))
```

### Vulnerability Scan Pass Rate Before Deployment

**What it measures:** The fraction of container image deployments where the image passed the vulnerability scan at or before deployment time — meaning no critical/high CVEs above the policy threshold were present in the image when it was promoted to production.

**Why it matters:** Scanners are useless if images deploy before or despite scan failure. This SLI measures enforcement, not just scanning activity.

**Prometheus expression (requires scan gate telemetry):**
```
sum(rate(image_deployments_total{scan_result="passed"}[5m]))
/
sum(rate(image_deployments_total[5m]))
```

### API Authentication Rate

**What it measures:** The fraction of API requests that carry a valid, verified authentication credential — JWT with valid signature, API key matching a known active key, mutual TLS client certificate. Requests failing authentication are bad events.

**Why it matters:** A declining authentication rate indicates misconfigurations (services losing credentials), token expiry cascades, or an attacker probing unauthenticated endpoints.

**Prometheus expression:**
```
sum(rate(http_requests_total{auth_result="authenticated"}[5m]))
/
sum(rate(http_requests_total{path!~"/health|/ready|/metrics"}[5m]))
```

### Mean Time to Detect Known Attack Patterns (MTTD SLI)

**What it measures:** For simulated attack patterns (red team runs, canary detections, synthetic attack payloads), the time from attack execution to first alert. Expressed as a ratio of detections completing within the SLO threshold (e.g., 90 seconds for known patterns).

**Why it matters:** This is the closest proxy for "does our detection actually work." It requires a synthetic signal injection pipeline, but teams with regular red team or purple team exercises can populate this from exercise records.

**Prometheus expression:**
```
sum(rate(detection_latency_seconds_bucket{le="90", attack_type="known_pattern"}[1h]))
/
sum(rate(detection_latency_seconds_count{attack_type="known_pattern"}[1h]))
```

### Secret Rotation Compliance

**What it measures:** The fraction of secrets (database passwords, API keys, signing keys, service account tokens) that have been rotated within the policy window. Policy window is typically 30, 60, or 90 days depending on secret type.

**Why it matters:** Secrets that are never rotated are effectively static credentials. An attacker who exfiltrates them retains access indefinitely. This SLI makes the rotation program measurable.

**Prometheus expression (requires secrets inventory exporter):**
```
count(secret_last_rotated_days < 30)   # or the applicable policy window
/
count(secret_last_rotated_days >= 0)
```

### Patch SLA Compliance

**What it measures:** The fraction of critical vulnerabilities that received a patch or accepted mitigation within the policy SLA window — typically 14 days for critical, 30 days for high.

**Why it matters:** CVSS scores and patch counts describe volume, not velocity. This SLI measures whether the program actually closes vulnerabilities on time.

**Prometheus expression (requires vuln management exporter):**
```
sum(rate(vulnerabilities_remediated_total{within_sla="true",severity="critical"}[1d]))
/
sum(rate(vulnerabilities_detected_total{severity="critical"}[1d]))
```

## Turning SLIs into SLOs

Each SLI gets a target and a measurement window:

```yaml
# security-slos.yaml — commit to the security team repo
slos:
  - name: mtls-coverage
    description: "At least 99.5% of in-cluster service traffic uses mutual TLS."
    sli_query: |
      sum(rate(istio_requests_total{connection_security_policy="mutual_tls"}[5m]))
      /
      sum(rate(istio_requests_total[5m]))
    objective: 0.995
    window: 30d
    error_budget_ratio: 0.005   # 1 - 0.995

  - name: image-scan-pass-rate
    description: "At least 99% of image deployments pass vulnerability scan before deploy."
    sli_query: |
      sum(rate(image_deployments_total{scan_result="passed"}[5m]))
      /
      sum(rate(image_deployments_total[5m]))
    objective: 0.990
    window: 30d

  - name: api-auth-rate
    description: "At least 99.9% of non-health API requests carry valid authentication."
    sli_query: |
      sum(rate(http_requests_total{auth_result="authenticated"}[5m]))
      /
      sum(rate(http_requests_total{path!~"/health|/ready|/metrics"}[5m]))
    objective: 0.999
    window: 30d

  - name: mttd-known-patterns
    description: "90% of known attack pattern detections complete within 90 seconds."
    sli_query: |
      sum(rate(detection_latency_seconds_bucket{le="90",attack_type="known_pattern"}[1h]))
      /
      sum(rate(detection_latency_seconds_count{attack_type="known_pattern"}[1h]))
    objective: 0.90
    window: 30d

  - name: secret-rotation-compliance
    description: "At least 98% of secrets rotated within policy window."
    sli_query: |
      count(secret_last_rotated_days < scalar(secret_policy_window_days))
      /
      count(secret_last_rotated_days >= 0)
    objective: 0.980
    window: 30d

  - name: patch-sla-compliance
    description: "At least 95% of critical vulnerabilities patched within 14-day SLA."
    sli_query: |
      sum(rate(vulnerabilities_remediated_total{within_sla="true",severity="critical"}[1d]))
      /
      sum(rate(vulnerabilities_detected_total{severity="critical"}[1d]))
    objective: 0.950
    window: 30d
```

**Error budget calculation:** For a 30-day window with a 99.5% SLO target, the error budget is 0.5% of the window — 21.6 minutes of budget for a metric evaluated every minute (43,200 data points × 0.005 = 216 bad events).

The error budget answers a concrete question: "How much can we let things slide before we have definitively violated our commitment?"

## Prometheus Recording Rules for SLI Ratios

Before writing burn-rate alerts, create recording rules that pre-aggregate the SLI ratios. This keeps alert expressions readable and reduces query load.

```yaml
# security-sli-recording-rules.yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: security-sli-recording
  namespace: monitoring
  labels:
    prometheus: kube-prometheus
    role: alert-rules
spec:
  groups:
    - name: security_sli_ratios
      interval: 30s
      rules:
        # mTLS coverage — ratio of mutually-authenticated traffic
        - record: security_sli:mtls_coverage:ratio5m
          expr: |
            sum(rate(istio_requests_total{connection_security_policy="mutual_tls"}[5m]))
            /
            sum(rate(istio_requests_total[5m]))

        # Image scan pass rate — ratio of scan-passing deployments
        - record: security_sli:image_scan_pass:ratio5m
          expr: |
            sum(rate(image_deployments_total{scan_result="passed"}[5m]))
            /
            sum(rate(image_deployments_total[5m]))

        # API authentication rate — ratio of authenticated non-health requests
        - record: security_sli:api_auth_rate:ratio5m
          expr: |
            sum(rate(http_requests_total{auth_result="authenticated"}[5m]))
            /
            sum(rate(http_requests_total{path!~"/health|/ready|/metrics"}[5m]))

        # MTTD known patterns — fraction detected within 90s (1h window for stability)
        - record: security_sli:mttd_known_patterns:ratio1h
          expr: |
            sum(rate(detection_latency_seconds_bucket{le="90",attack_type="known_pattern"}[1h]))
            /
            sum(rate(detection_latency_seconds_count{attack_type="known_pattern"}[1h]))

        # Secret rotation compliance
        - record: security_sli:secret_rotation_compliance:gauge
          expr: |
            count(secret_last_rotated_days < 30)
            /
            count(secret_last_rotated_days >= 0)

        # Patch SLA compliance — rolling 7d for stability
        - record: security_sli:patch_sla_compliance:ratio7d
          expr: |
            sum(rate(vulnerabilities_remediated_total{within_sla="true",severity="critical"}[7d]))
            /
            sum(rate(vulnerabilities_detected_total{severity="critical"}[7d]))
```

## Multi-Window Burn-Rate Alerting

The Google SRE workbook defines multi-window multi-burn-rate alerting as the production standard for SLO alerting. The principle: a fast burn over a short window warrants an immediate page; a slow burn over a longer window warrants a ticket before budget is exhausted.

For a 30-day SLO:
- **Fast burn (14.4×):** Budget will be gone in ~2 days. Alert on 1-hour + 5-minute windows. Page the on-call.
- **Slow burn (6×):** Budget will be gone in ~5 days. Alert on 6-hour + 30-minute windows. Create a ticket.

```yaml
# security-slo-burnrate-alerts.yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: security-slo-burnrate
  namespace: monitoring
  labels:
    prometheus: kube-prometheus
    role: alert-rules
spec:
  groups:
    - name: security_slo_burnrate
      rules:
        # ─── mTLS Coverage ───────────────────────────────────────────────────────
        # Fast burn: budget exhaustion in <2 days. Page now.
        - alert: SecuritySLO_mTLS_FastBurn
          expr: |
            (1 - security_sli:mtls_coverage:ratio5m) > (14.4 * 0.005)
            and
            (1 - avg_over_time(security_sli:mtls_coverage:ratio5m[5m])) > (14.4 * 0.005)
          for: 2m
          labels:
            severity: critical
            slo: mtls-coverage
            team: security
          annotations:
            summary: "mTLS coverage SLO burning error budget at critical rate"
            description: |
              mTLS coverage has dropped below threshold, burning the 30-day error
              budget at 14× the sustainable rate. At this rate, the budget will be
              exhausted within 48 hours.
              Current ratio: {{ printf "%.4f" $value }}. SLO target: 0.995.
            runbook_url: "https://systemshardening.com/runbooks/mtls-coverage"

        # Slow burn: budget exhaustion in <5 days. Ticket.
        - alert: SecuritySLO_mTLS_SlowBurn
          expr: |
            (1 - avg_over_time(security_sli:mtls_coverage:ratio5m[6h])) > (6 * 0.005)
            and
            (1 - avg_over_time(security_sli:mtls_coverage:ratio5m[30m])) > (6 * 0.005)
          for: 15m
          labels:
            severity: warning
            slo: mtls-coverage
            team: security
          annotations:
            summary: "mTLS coverage SLO burning error budget at elevated rate"
            description: |
              mTLS coverage has been below target for the past 6 hours at 6× the
              sustainable error rate. Create a ticket to investigate new PERMISSIVE
              mode exceptions or certificate renewal failures.

        # ─── Image Scan Pass Rate ─────────────────────────────────────────────
        - alert: SecuritySLO_ImageScan_FastBurn
          expr: |
            (1 - security_sli:image_scan_pass:ratio5m) > (14.4 * 0.01)
            and
            (1 - avg_over_time(security_sli:image_scan_pass:ratio5m[5m])) > (14.4 * 0.01)
          for: 2m
          labels:
            severity: critical
            slo: image-scan-pass-rate
            team: security
          annotations:
            summary: "Image scan gate SLO burning budget at critical rate"
            description: |
              More than 14.4% of deployments (10× the SLO budget rate) are bypassing
              or failing the vulnerability scan gate. Immediate investigation required.

        - alert: SecuritySLO_ImageScan_SlowBurn
          expr: |
            (1 - avg_over_time(security_sli:image_scan_pass:ratio5m[6h])) > (6 * 0.01)
            and
            (1 - avg_over_time(security_sli:image_scan_pass:ratio5m[30m])) > (6 * 0.01)
          for: 15m
          labels:
            severity: warning
            slo: image-scan-pass-rate
            team: security
          annotations:
            summary: "Image scan gate SLO burning budget at elevated rate"

        # ─── API Authentication Rate ──────────────────────────────────────────
        - alert: SecuritySLO_APIAuth_FastBurn
          expr: |
            (1 - security_sli:api_auth_rate:ratio5m) > (14.4 * 0.001)
            and
            (1 - avg_over_time(security_sli:api_auth_rate:ratio5m[5m])) > (14.4 * 0.001)
          for: 2m
          labels:
            severity: critical
            slo: api-auth-rate
            team: security
          annotations:
            summary: "API authentication rate SLO burning budget at critical rate"
            description: |
              More than 1.44% of API requests are failing authentication — 14.4× the
              SLO budget rate. This may indicate a service losing its credentials, a
              token expiry cascade, or unauthenticated endpoint probing.

        - alert: SecuritySLO_APIAuth_SlowBurn
          expr: |
            (1 - avg_over_time(security_sli:api_auth_rate:ratio5m[6h])) > (6 * 0.001)
            and
            (1 - avg_over_time(security_sli:api_auth_rate:ratio5m[30m])) > (6 * 0.001)
          for: 15m
          labels:
            severity: warning
            slo: api-auth-rate
            team: security
          annotations:
            summary: "API authentication rate SLO burning budget at elevated rate"
```

The dual-window check (`and` of long window + short window) is the key property. It prevents false positives from a single-minute spike while still catching sustained degradation quickly.

## Error Budget Depletion and Security Sprints

The error budget policy is where the framework produces organisational change. Define it explicitly and get engineering management sign-off:

```
Security SLO Error Budget Policy (v1.2, signed: CISO, VP Engineering)

1. At 50% error budget consumed (15 days remaining in 30-day window):
   - Security team lead notified.
   - A P2 ticket is created in the engineering backlog.
   - The ticket is reviewed in the next sprint planning session.

2. At 75% error budget consumed:
   - A P1 ticket is created.
   - Engineering lead for the affected service is paged.
   - If no fix is in flight within 24 hours, the security team has authority
     to freeze new feature deployments to the affected component until a
     remediation plan is approved.

3. At 100% error budget consumed (SLO violated):
   - A security sprint is declared for the affected SLO.
   - For the following sprint, at least 50% of engineering capacity for the
     affected team is allocated to the security remediation work.
   - New feature work resumes only when the SLO is green for 7 consecutive days.

4. Planned exceptions:
   - Known exceptions to an SLO (e.g., a legacy service awaiting migration)
     are documented in the SLO exceptions register.
   - Exception time-boxes are tracked. If an exception exceeds its time-box,
     it becomes a P1 vulnerability.
```

This policy eliminates the common failure mode where burn-rate alerts fire, get acknowledged, and produce no engineering action. The error budget depletion threshold is the trigger for prioritisation negotiation — and by the time 50% depletion fires, there is still time to fix the issue before the SLO window closes.

## Grafana Dashboard Layout

The per-SLO dashboard structure that produces actionable situational awareness at a glance:

```
┌─────────────────────────────────────────────────────────────────┐
│  mTLS Coverage SLO — 30-day window                              │
│                                                                 │
│  Current ratio:    99.62%     Target: 99.5%   [GREEN]          │
│  Error budget:     38% remaining               (12 of 216 used) │
│  Burn rate (1h):   1.2×       (sustainable = 1×)               │
│  Burn rate (6h):   0.8×                                        │
│                                                                 │
│  [Ratio time series — 30 days]  [Error budget burn down — 30d] │
│                                                                 │
│  Top bad-event contributors:                                    │
│  namespace/legacy-payment-svc:   2.1% unauthenticated traffic  │
│  namespace/batch-processor:      0.4% unauthenticated traffic  │
│  All others:                     < 0.05%                       │
│                                                                 │
│  Open tickets:  SEC-2341 (legacy-payment migration, due Q3)    │
└─────────────────────────────────────────────────────────────────┘
```

The critical element is the "top contributors" panel. Knowing the aggregate SLI is red is useless without knowing which component is responsible. Implement this with a breakdown recording rule:

```yaml
# Per-namespace mTLS ratio for contributor breakdown
- record: security_sli:mtls_coverage_by_namespace:ratio5m
  expr: |
    sum by (destination_service_namespace) (
      rate(istio_requests_total{connection_security_policy="mutual_tls"}[5m])
    )
    /
    sum by (destination_service_namespace) (
      rate(istio_requests_total[5m])
    )
```

## Reporting Posture to Leadership

The SLO dashboard has two audiences. For the security team and engineering, the burn-rate graph and contributor breakdown drive daily operations. For leadership, the reporting cadence is monthly and the translation is:

| Metric | Engineering view | Leadership view |
|--------|-----------------|-----------------|
| mTLS coverage 99.62% | 38% budget remaining, on track | 99.6% of internal service communication is encrypted end-to-end |
| Image scan SLO violated | Budget exhausted day 22 of 30 | 3% of production deployments bypassed vulnerability gate last month; security sprint declared |
| Patch SLA 94% (below 95% target) | Slow burn since day 8 | 6% of critical vulnerabilities missed the 14-day remediation window; root cause: understaffed patching rotation |
| MTTD known patterns 91% | Green, budget healthy | 91% of simulated attacks detected within 90 seconds; exercise gap in cloud API exfiltration patterns |

Leadership does not need burn rates. They need: "are we meeting commitments, and if not, what is the concrete gap and what are we doing about it?" SLO data provides the answer without requiring the security team to produce a narrative assessment each month. The dashboard produces the report; the team focuses on the work.

## Expected Behaviour

Once SLIs, recording rules, and burn-rate alerts are deployed:

- Recording rules evaluate every 30 seconds; SLI ratios are visible in Prometheus immediately
- Fast-burn alerts fire within 2 minutes of a critical degradation event
- Slow-burn alerts fire within 15 minutes of a sustained moderate degradation
- Error budget consumption is queryable at any point: `1 - avg_over_time(security_sli:mtls_coverage:ratio5m[30d])`
- Grafana dashboards show current ratio, 30-day trend, burn rate, and top contributors
- At 50% budget consumed, a ticket exists and is in the engineering backlog
- At SLO violation, a security sprint is in progress with engineering management aware

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Ratio-based SLIs | Measurable, comparable over time | Requires instrumented exporters | Build exporters incrementally; start with two SLIs and expand |
| Realistic SLO targets (not 100%) | Useful signal; accommodates known exceptions | Appears to "accept" security gaps | Document the exceptions register; time-box every exception |
| Multi-window burn-rate alerting | Catches both sudden and sustained degradation | Alert complexity higher than simple thresholds | Use Sloth or Pyrra to generate burn-rate rules from SLO config |
| Error budget policy | Creates engineering accountability | Requires management sign-off | Frame as "we get 0.5% budget to trade for velocity; burning more than that needs engineering action" |
| Per-namespace breakdowns | Identifies responsible component immediately | Higher metric cardinality | Namespace-level is fine; avoid per-pod-level SLI breakdowns |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| SLI exporter gap | An SLI is always 1.0 (looks perfect) | No bad events ever recorded; check exporter health | Inject a synthetic bad event weekly to verify the pipeline end-to-end |
| SLO too tight | Budget exhausted by day 3 every month | Permanent red; teams stop reading | Recalibrate; if 99% target fails due to real exceptions, document them and set 97% |
| SLO too loose | Always green; no signal | Budget never depletes; alerts never fire | Add canary bad-event injection; tighten SLO to the point where exceptions create visible burn |
| Budget policy ignored | Burn alerts fire; no tickets created | Check backlog monthly: do active SLO violations have open tickets? | Engineering management must enforce the budget policy; make it a standing agenda item |
| Alert routing mis-configured | Fast-burn critical fires; nobody is paged | Test alerting monthly with a synthetic drop | Include SLO alerting in the on-call drill; verify delivery path |
| SLI gaming | An SLI improves; actual posture does not | Pair leading SLIs with lagging outcome checks (e.g., incident retrospective MTTD) | Never tie SLI compliance to individual performance review |

## Related Articles

- [Security SLOs and Error Budgets: SRE Discipline Applied to Detection and Response](/articles/observability/security-slos/)
- [Security-Relevant Prometheus Metrics: What to Collect, How to Alert, When to Page](/articles/observability/prometheus-security-metrics/)
- [Security Dashboards That Engineers Actually Use: Grafana Designs for Hardening Verification](/articles/observability/security-dashboards/)
- [Detection Engineering Metrics](/articles/observability/detection-engineering-metrics/)
- [Certificate Expiry Monitoring: Automated Detection Across TLS, mTLS, and Signing Certificates](/articles/observability/certificate-expiry-monitoring/)
