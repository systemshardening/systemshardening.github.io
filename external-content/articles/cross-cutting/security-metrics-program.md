---
title: "Security Metrics Program: KPIs, Dashboards, and Board Reporting"
description: "Most security teams measure what is easy to count, not what matters. A metrics program built on MTTD, MTTR, coverage, and risk reduction connects security activity to business outcomes executives can act on."
slug: "security-metrics-program"
date: 2026-04-30
lastmod: 2026-04-30
category: "cross-cutting"
tags: ["metrics", "kpi", "dashboard", "board-reporting", "security-posture"]
personas: ["security-engineer", "sre", "platform-engineer"]
article_number: 261
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/cross-cutting/security-metrics-program/index.html"
---

# Security Metrics Program: KPIs, Dashboards, and Board Reporting

## Problem

Security teams are drowning in data but starved for insight. A typical programme generates: vulnerability scanner output, SIEM alert counts, penetration test findings, compliance audit results, patch compliance percentages, and awareness training completion rates. Individually, each number sounds like progress. Together, they don't answer the question boards and executives actually ask: *are we getting safer, and how do we know?*

The specific failure modes of unmanaged security metrics:

- **Activity metrics masquerade as outcome metrics.** "We closed 1,200 vulnerabilities this quarter" says nothing about risk. Were they critical? Were they on internet-facing systems? Were they replaced by 1,300 new ones?
- **Vanity metrics dominate.** Patch compliance at 98% looks excellent until you notice the 2% includes the three servers with known exploited CVEs.
- **Metrics are collected but not acted on.** A dashboard shows mean time to remediate (MTTR) at 47 days for critical vulnerabilities. Nobody is accountable for reducing it.
- **Board reporting is anecdote-based.** Security updates to the board consist of news clippings about other companies' breaches and a reassurance that "we're doing better." No trend data, no comparison to targets.
- **Coverage is unmeasured.** The team doesn't know what fraction of the fleet runs EDR, what percentage of code goes through security review, or what proportion of services have security SLOs.

A sound security metrics programme answers four questions: How much of the attack surface do we cover? How quickly do we detect threats? How quickly do we respond? Are we reducing risk over time?

**Target systems:** Any security programme; metric collection via Prometheus/Grafana, Datadog, or Splunk; executive dashboards via Grafana, Metabase, or Looker; data sources include vulnerability scanners (Tenable, Qualys, Snyk), SIEM (Splunk, Elastic, Chronicle), ticketing (Jira, Linear), and cloud inventories.

## Threat Model

This article doesn't address a traditional adversary. The problem it solves is:

- **Risk 1 — Invisible regression:** Security posture degrades (patch latency increases, detection coverage drops) but no metric surfaces it until an incident occurs.
- **Risk 2 — Resource misallocation:** Security effort focuses on low-risk work (patch compliance on dev laptops) while high-risk gaps (unmonitored production APIs) are unmeasured.
- **Risk 3 — Accountability gap:** No metric is owned, so nobody is accountable for improving it. MTTR stays at 47 days forever.
- **Risk 4 — Incomplete board picture:** The board approves security budget based on anecdote and fear rather than trend data showing ROI or deterioration.
- **Risk 5 — False confidence:** High scores on vanity metrics (98% patch compliance) create confidence that prevents investment in areas with real gaps.

## Configuration

### Step 1: The Four Metric Categories

Organise every metric into one of four categories before collecting anything:

**Coverage** — What fraction of the attack surface is under active protection?
- EDR coverage: hosts with EDR agent / total hosts
- Secrets scanning coverage: repos with scanning enabled / total repos
- Vulnerability scanning coverage: assets scanned in last 7 days / total assets
- Security logging coverage: services emitting structured security events / total services
- Network policy coverage: pods with NetworkPolicy / total pods (Kubernetes)

**Detection** — How fast do you find threats?
- Mean Time to Detect (MTTD): time from attacker action to alert
- Alert-to-investigation time: time from alert creation to analyst starting investigation
- False positive rate: alerts that require no action / total alerts
- Detection rule coverage: percentage of MITRE ATT&CK techniques with at least one detection rule

**Response** — How fast do you contain and remediate?
- Mean Time to Respond (MTTR): time from detection to containment
- Mean Time to Remediate: time from vulnerability disclosure to patched
- SLA compliance: vulnerabilities remediated within defined SLA / total vulnerabilities
- Critical CVE patch latency: P50/P90/P99 days from CVE disclosure to patch in production

**Risk reduction** — Are you getting safer over time?
- Vulnerability density: critical/high vulnerabilities per 1000 lines of code (trending down = good)
- Unresolved critical vulnerability age: average age of open critical findings
- Repeat incident rate: incidents caused by the same root cause in the last 12 months
- Attack surface change: new internet-facing assets discovered vs. expected

### Step 2: Define Targets Before Collecting Data

Every metric needs a target and an owner before it goes on a dashboard. Without both, dashboards are decoration.

```yaml
# security-metrics-targets.yaml — committed to your security programme repo.

metrics:
  - name: critical_vuln_patch_latency_p90
    description: "90th percentile days from CVE publication to patch in production"
    target: 14          # days
    current_baseline: 31   # days (measured at programme start)
    owner: platform-team
    review_cadence: monthly

  - name: edr_coverage_pct
    description: "Percentage of production hosts with EDR agent running"
    target: 99.5         # percent
    current_baseline: 94
    owner: security-team
    review_cadence: weekly

  - name: mttd_hours
    description: "Mean time to detect (alert fires) from incident start"
    target: 4            # hours
    current_baseline: 18
    owner: detection-team
    review_cadence: monthly

  - name: sla_compliance_critical
    description: "Critical vulnerabilities remediated within 7-day SLA"
    target: 90           # percent
    current_baseline: 62
    owner: vulnerability-management-team
    review_cadence: weekly

  - name: false_positive_rate
    description: "SIEM alerts requiring no action"
    target: 20           # percent (lower is better)
    current_baseline: 58
    owner: detection-team
    review_cadence: monthly
```

### Step 3: Collect Metrics Programmatically

Automate metric collection; manual spreadsheets drift from reality within weeks.

**Vulnerability patch latency from Tenable/Qualys:**

```python
import datetime
import requests

def get_critical_patch_latency_p90(scanner_api_key: str) -> float:
    """Return P90 days from CVE publication to current patch status."""
    findings = requests.get(
        "https://cloud.tenable.com/workbenches/assets/vulnerabilities",
        headers={"X-ApiKeys": f"accessKey={scanner_api_key}"},
        params={"severity": "critical", "state": "open"},
    ).json()["vulnerabilities"]

    latencies = []
    for f in findings:
        published = datetime.datetime.fromisoformat(f["plugin"]["published"])
        latencies.append((datetime.datetime.utcnow() - published).days)

    latencies.sort()
    p90_index = int(len(latencies) * 0.9)
    return latencies[p90_index] if latencies else 0

# Export as Prometheus gauge.
from prometheus_client import Gauge

critical_patch_latency = Gauge(
    "security_critical_patch_latency_p90_days",
    "P90 days from CVE publication to current patch",
)
critical_patch_latency.set(get_critical_patch_latency_p90(API_KEY))
```

**EDR coverage from fleet inventory:**

```python
def get_edr_coverage_pct(fleet_inventory_api, edr_api) -> float:
    total_hosts = fleet_inventory_api.count_production_hosts()
    edr_hosts = edr_api.count_hosts_with_active_agent()
    return (edr_hosts / total_hosts) * 100 if total_hosts else 0

edr_coverage = Gauge(
    "security_edr_coverage_pct",
    "Percentage of production hosts with active EDR agent",
)
edr_coverage.set(get_edr_coverage_pct(fleet_api, edr_api))
```

**MTTD from SIEM:**

```python
def get_mean_time_to_detect_hours(siem_client, lookback_days: int = 30) -> float:
    """Calculate MTTD from SIEM incident data."""
    incidents = siem_client.get_incidents(
        start=datetime.datetime.utcnow() - datetime.timedelta(days=lookback_days),
        end=datetime.datetime.utcnow(),
        status="resolved",
    )
    detect_times = []
    for incident in incidents:
        if incident.get("first_attacker_action") and incident.get("first_alert_time"):
            delta = incident["first_alert_time"] - incident["first_attacker_action"]
            detect_times.append(delta.total_seconds() / 3600)

    return sum(detect_times) / len(detect_times) if detect_times else 0

mttd = Gauge("security_mttd_hours", "Mean time to detect in hours (30-day rolling)")
mttd.set(get_mean_time_to_detect_hours(siem))
```

### Step 4: Grafana Dashboard Structure

Organise the dashboard in three sections matching the audience:

**Section 1: Security Operations (daily view — for the security team)**

Row 1 — Coverage:
- EDR coverage gauge (target line at 99.5%)
- Secrets scanning coverage
- Vulnerability scan coverage
- Services with structured security logging

Row 2 — Open risk:
- Critical/high vulnerability count (trending)
- Unresolved critical CVE age heatmap
- SLA breach count by owner team

**Section 2: Detection & Response (weekly view — for security management)**

- MTTD trend (30-day rolling average vs target)
- MTTR by severity (P50/P90)
- Alert volume and false positive rate trend
- Incident count by category (auth failure, data access, privilege escalation)

**Section 3: Risk Trend (monthly view — for leadership/board)**

- Vulnerability density per 1000 LOC (6-month trend)
- SLA compliance rate (4-quarter trend)
- Coverage metrics vs targets (all four categories)
- Repeat incident rate

```yaml
# Grafana alert rules — alert on regression against targets.
groups:
  - name: security-metrics
    rules:
      - alert: CriticalPatchLatencyHigh
        expr: security_critical_patch_latency_p90_days > 14
        for: 1d
        labels: {severity: warning, owner: platform-team}
        annotations:
          summary: "P90 critical patch latency is {{ $value }} days (target: 14)"

      - alert: EDRCoverageDropped
        expr: security_edr_coverage_pct < 99.5
        for: 1h
        labels: {severity: critical, owner: security-team}
        annotations:
          summary: "EDR coverage is {{ $value }}% (target: 99.5%)"

      - alert: SLAComplianceBelowTarget
        expr: security_sla_compliance_critical_pct < 90
        for: 1d
        labels: {severity: warning, owner: vuln-management-team}
```

### Step 5: Quarterly Review Process

Metrics without a review process collect dust. Run a quarterly security metrics review:

```
Quarterly Security Metrics Review Agenda (60 minutes):

1. Coverage review (15 min)
   - Which coverage metric is furthest from target?
   - What is the plan to close the gap?
   - Who owns it and by when?

2. Detection & response review (20 min)
   - MTTD trend: improving, stable, or regressing?
   - Top alert categories: is false positive rate improving?
   - Longest-open critical vulnerability: root cause of SLA breach?

3. Risk trend (15 min)
   - Vulnerability density: is it trending down?
   - Repeat incidents: same root cause appearing twice = process failure.
   - New attack surface: what was added this quarter? Is it covered?

4. Metric hygiene (10 min)
   - Which metrics lost data quality this quarter?
   - New metrics to add for emerging risk?
   - Metrics to retire (no longer relevant)?
```

### Step 6: Board-Level Reporting

A board security update should fit on one page and answer three questions:

```
Security Posture Summary — Q2 2026

OVERALL STATUS: ⬆ IMPROVING

Coverage:
  EDR coverage:     98.2% → 99.1% (+0.9pp vs last quarter, target 99.5%)
  Secrets scanning: 91.0% → 97.3% (+6.3pp)

Detection & Response:
  Mean time to detect:     18h → 12h (target: 4h; on track)
  Critical CVE patch P90:  31d → 22d (target: 14d; on track)
  SLA compliance:          62% → 74% (target: 90%; lagging)

Risk Trend:
  Vulnerability density (critical/KLOC): 3.2 → 2.8 (-12%, improving)
  Repeat incidents:        3 this quarter (same root cause: API auth config;
                           post-incident action item on track)

Items requiring board attention:
  1. SLA compliance for critical vulnerabilities is behind target. The
     platform team requires one additional FTE to meet the 14-day remediation
     target. This represents a $X risk exposure for N days per quarter.

  2. Three internet-facing APIs added to production without security review.
     Process gap identified; new review gate added to deployment pipeline.
     No exploitation detected.
```

The board report uses absolute trend data (not "we had X alerts"), names the gap and its business implication, and makes a concrete ask.

### Step 7: Telemetry

The metrics programme itself should be monitored:

```
security_metric_collection_success_total{metric_name}       counter
security_metric_collection_failure_total{metric_name}       counter
security_metric_staleness_hours{metric_name}                gauge
security_target_breach_total{metric_name, direction}        counter
security_metric_data_quality_score{metric_name}             gauge (0-1)
```

Alert on:

- `security_metric_staleness_hours` > 24 — a metric hasn't updated; data pipeline broken.
- `security_metric_collection_failure_total` — scanner API or SIEM query failing.
- `security_target_breach_total` for a metric with `direction=worsening` — a metric crossed its target in the wrong direction; escalate to metric owner.

## Expected Behaviour

| Signal | No metrics programme | Structured metrics programme |
|--------|---------------------|------------------------------|
| Security regression | Discovered during incident | MTTD/coverage metrics show regression within days |
| Board security update | Anecdote + news clippings | One-page trend dashboard with targets and gaps |
| Metric ownership | Nobody | Named owner per metric; accountable in quarterly review |
| Patch latency | Unknown | P90 measured weekly; alert on breach of 14-day target |
| Coverage blind spots | Unknown until breach | Coverage metric shows 94% EDR; 6% gap identified and assigned |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Automated metric collection | Current, accurate data | Integration effort per data source | 3–5 integrations cover 80% of metrics; build incrementally. |
| Targets before metrics | Accountability; prevents vanity metric drift | Requires agreement on what "good" looks like | Start with industry benchmarks (e.g., CIS, CISA guidance); refine with internal data. |
| Board-level summary | Enables informed decision-making | Simplification loses nuance | Include a link to the full technical dashboard; board report is a summary, not the only view. |
| Quarterly review process | Forces accountability; surfaces gaps | 60 minutes per quarter for the security team | Cheap relative to the cost of undiscovered drift. |
| Metric staleness alerts | Catches broken data pipelines | Another alert to manage | Route to a metrics-ops channel, not the main security alert queue. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Scanner API breaks data collection | Metrics go stale; dashboard shows old data | `security_metric_staleness_hours` alert | Fix the API connection; back-fill from scanner export if available. |
| Metric ownership unclear | No action taken when target breached | Target breach alerts pile up unactioned | Assign owners during metric definition; track in `security-metrics-targets.yaml`. |
| Metric manipulated (Goodhart's Law) | Teams close low-severity vulns to hit patch count targets | High-severity open count rises while total count drops | Always track severity-weighted counts; patch count is an activity metric, not an outcome metric. |
| False confidence from high-level metrics | 98% patch compliance hides 2% with critical vulns | Hidden by aggregation | Always show distribution, not just mean; P90 patch latency reveals the tail. |
| Board ignores metrics | Board report not actioned | Tracking shows same metric breaching repeatedly | Frame metrics in financial terms (risk exposure in $); include a specific ask. |
| Data source changes schema | Metric collection breaks silently | Metrics flatline at last-known value | Add schema version validation to all collectors; alert on unexpected schema changes. |

## Related Articles

- [Security SLOs and Error Budgets](/articles/observability/security-slos/)
- [Security Dashboards](/articles/observability/security-dashboards/)
- [Detection Engineering Metrics](/articles/observability/detection-engineering-metrics/)
- [Compliance as Code](/articles/cross-cutting/compliance-as-code/)
- [Hardening Scorecard](/articles/cross-cutting/hardening-scorecard/)
