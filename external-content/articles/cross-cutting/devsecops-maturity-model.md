---
title: "DevSecOps Maturity Model: Measuring and Advancing Security Programme Capability"
description: "A maturity model provides a structured way to assess where a security programme is today, identify the highest-value next steps, and measure progress over time. Without measurement, security programmes grow by adding tools and headcount without improving outcomes."
slug: "devsecops-maturity-model"
date: 2026-05-01
lastmod: 2026-05-01
category: "cross-cutting"
tags: ["devsecops", "maturity-model", "security-programme", "measurement", "capability"]
personas: ["ciso", "security-engineer", "platform-engineer"]
article_number: 317
difficulty: "intermediate"
estimated_reading_time: 12
published: true
layout: article.njk
permalink: "/articles/cross-cutting/devsecops-maturity-model/index.html"
---

# DevSecOps Maturity Model: Measuring and Advancing Security Programme Capability

## Problem

Security programmes grow by accumulating tools. A SIEM is added. A vulnerability scanner is deployed. DAST runs in CI. A bug bounty is launched. Each addition seems like progress, but the organisation remains unable to answer the questions that actually matter: How quickly do critical vulnerabilities get fixed? What percentage of production deployments are reviewed for security? How many of our security alerts are actionable?

The symptom is that the security team can describe the tools they use, but not the outcomes they produce. This is the gap that a maturity model addresses: it provides a framework for measuring whether security practice is actually improving.

A DevSecOps maturity model measures capability across the dimensions that matter for engineering organisations:

- **How integrated is security into the development workflow?** Are security checks blocking unsafe code from merging, or are they advisory reports that nobody reads?
- **How quickly are vulnerabilities remediated?** Is there a measurable reduction in mean time to remediate over the past 12 months?
- **How much of the attack surface is visible?** What percentage of production workloads have security monitoring coverage?
- **How effective are security controls under test?** Do security chaos experiments and red team exercises confirm controls work, or reveal that they don't?

**Target systems:** Software engineering organisations with existing DevOps practice. The model applies to teams of 5 engineers to organisations of 5,000.

## Threat Model for the Maturity Programme

- **Adversary 1 — Security theatre without outcome improvement.** The organisation advances through maturity levels by checking boxes (deploy scanner, add policy) without measuring whether outcomes improve. The maturity score increases; the attack surface doesn't shrink.
- **Adversary 2 — Over-investment in one dimension.** The organisation achieves level 5 in vulnerability scanning and level 1 in incident response. A blind spot in one dimension enables attacks that are well-covered in another.
- These are programme design risks, not technical vulnerabilities.

## Configuration

### Step 1: The Five-Level Maturity Scale

```yaml
# devsecops-maturity.yaml — maturity level definitions.
levels:
  1:
    name: "Initial"
    description: "Ad-hoc security. Reactive to incidents. No consistent process."
    characteristics:
      - "Security reviews happen after incidents, not before deployments."
      - "No centralised vulnerability tracking."
      - "No security metrics tracked."
      - "Single security person or none dedicated."

  2:
    name: "Developing"
    description: "Basic controls in place. Some automation. Inconsistent adoption."
    characteristics:
      - "Vulnerability scanner runs but results often ignored."
      - "Some secrets management (not universal)."
      - "Security reviews for major releases but not all changes."
      - "Basic SIEM with high alert volume and poor signal-to-noise."

  3:
    name: "Defined"
    description: "Consistent process across teams. Security integrated into SDLC."
    characteristics:
      - "SAST/SCA/DAST in CI pipeline with SLA-based remediation."
      - "All production secrets managed centrally."
      - "Branch protection and code review required for all production changes."
      - "SLAs defined for vulnerability remediation."
      - "Security metrics reviewed quarterly."

  4:
    name: "Managed"
    description: "Quantitative. Metrics drive decisions. Security is predictable."
    characteristics:
      - "MTTR tracked and trending downward."
      - "Security coverage measured (>90% of workloads monitored)."
      - "Incident response time meets defined SLA."
      - "Threat modelling for all significant new features."
      - "Regular penetration testing with tracked findings."

  5:
    name: "Optimising"
    description: "Continuous improvement. Security enables velocity."
    characteristics:
      - "Security chaos engineering validates controls under real conditions."
      - "Automated detection of new attack patterns."
      - "Security posture score improves measurably quarter-over-quarter."
      - "Developer security training results in measurable defect reduction."
      - "Red team exercises with full kill-chain simulation."
```

### Step 2: Capability Domains

Assess maturity across eight capability domains independently:

```yaml
# capability-domains.yaml

domains:
  - name: "vulnerability_management"
    description: "Discovering and remediating known vulnerabilities"
    metrics:
      - "MTTR for critical vulnerabilities (days)"
      - "% vulnerabilities remediated within SLA"
      - "Scan coverage (% assets scanned)"
      - "False positive rate (%)"
    level_indicators:
      1: "Scans run on demand; no SLA"
      2: "Scheduled scans; results tracked informally"
      3: "SLAs defined; tracked in ticketing system"
      4: "MTTR trending down; >90% SLA compliance"
      5: "Predictive prioritisation; near-zero MTTR for critical KEVs"

  - name: "secure_development"
    description: "Security controls in the development workflow"
    metrics:
      - "% of repos with SAST enabled"
      - "% of PRs with security gate"
      - "% of developers completed security training"
      - "Security defect introduction rate (defects/sprint)"
    level_indicators:
      1: "No SAST; manual code review only"
      2: "SAST on some repos; advisory results"
      3: "SAST blocking on all production repos"
      4: "SAST + SCA + secret scanning; enforced gates"
      5: "AI-assisted code review; developer security metrics tracked"

  - name: "identity_access"
    description: "Authentication, authorisation, and access management"
    metrics:
      - "% of production access using SSO"
      - "% of privileged access using JIT"
      - "Mean time to remove access after offboarding (hours)"
      - "% of service accounts with scoped permissions"
    level_indicators:
      1: "Shared credentials; no access review"
      2: "SSO for most systems; annual access review"
      3: "MFA everywhere; quarterly access review; some JIT"
      4: "JIT for all privileged access; offboarding SLA < 4h"
      5: "Zero-standing-privilege; workload identity for all services"

  - name: "incident_response"
    description: "Detecting, containing, and recovering from security incidents"
    metrics:
      - "Mean time to detect (MTTD) in hours"
      - "Mean time to contain (MTTC) in hours"
      - "% incidents with documented post-mortem"
      - "IR playbook coverage (%)"
    level_indicators:
      1: "Incidents discovered by customers; no playbook"
      2: "Basic SIEM; IR process defined but untested"
      3: "MTTD < 24h; IR playbooks for top 5 scenarios"
      4: "MTTD < 4h; MTTC < 8h; tabletop exercises quarterly"
      5: "Automated containment; MTTD < 1h; full kill-chain detection"

  - name: "cloud_infrastructure"
    description: "Cloud configuration security and posture management"
    metrics:
      - "% resources passing CIS benchmark"
      - "% resources with drift detection"
      - "CSPM findings SLA compliance (%)"
      - "% environments with least-privilege IAM"
    level_indicators:
      1: "Cloud used but no security baseline"
      2: "Periodic CSPM scans; findings reviewed informally"
      3: "Continuous CSPM; SLAs for findings"
      4: ">95% CIS benchmark compliance; automated remediation"
      5: "Policy-as-code; no manual infrastructure changes"

  - name: "supply_chain"
    description: "Software dependencies, build pipeline, and artefact security"
    metrics:
      - "% dependencies scanned for CVEs"
      - "% artefacts signed and verified"
      - "SLSA level (0-3)"
      - "% CI pipelines with egress control"
    level_indicators:
      1: "No dependency scanning; unsigned artefacts"
      2: "Dependabot for some repos; no build signing"
      3: "SCA on all repos; artefacts signed"
      4: "SLSA 2+; SBOM generated; provenance verified"
      5: "SLSA 3; hermetic builds; reproducible builds"

  - name: "observability_detection"
    description: "Security visibility and threat detection"
    metrics:
      - "% workloads with security telemetry"
      - "Alert signal-to-noise ratio"
      - "Detection coverage for MITRE ATT&CK techniques (%)"
      - "Mean time to investigate an alert (hours)"
    level_indicators:
      1: "Logs collected; not analysed for security"
      2: "SIEM with basic rules; high false positive rate"
      3: "Detection as code; alert SLAs defined"
      4: ">80% MITRE coverage; <30min mean investigation time"
      5: "ML-based anomaly detection; near-zero false positive rate"

  - name: "security_culture"
    description: "Developer security knowledge and programme engagement"
    metrics:
      - "% developers completed security training (annual)"
      - "Internal vulnerability reports per quarter"
      - "Security defect escapement rate (% defects found post-deploy)"
      - "Developer security satisfaction score (survey)"
    level_indicators:
      1: "Security is a separate team's responsibility"
      2: "Annual training; security champions informally"
      3: "Security champions programme; threat modelling training"
      4: "Security metrics in engineering OKRs"
      5: "Developers catch security issues before tooling does"
```

### Step 3: Scoring and Assessment

```python
# maturity_assessor.py — structured self-assessment.
from dataclasses import dataclass

@dataclass
class DomainScore:
    domain: str
    current_level: int          # 1-5.
    evidence: list[str]         # Specific evidence for current level.
    target_level: int           # Desired level in 12 months.
    blockers: list[str]         # What prevents reaching target.
    next_actions: list[str]     # Specific steps to advance.
    owner: str                  # Who is accountable for this domain.

def calculate_programme_score(scores: list[DomainScore]) -> dict:
    """Calculate overall programme maturity."""
    domain_scores = {s.domain: s.current_level for s in scores}
    avg_score = sum(domain_scores.values()) / len(domain_scores)
    min_score = min(domain_scores.values())
    weak_domains = [d for d, s in domain_scores.items() if s <= 2]

    return {
        "average_level": round(avg_score, 1),
        "minimum_level": min_score,
        "overall_maturity": avg_score,
        "weak_domains": weak_domains,
        "recommendation": (
            "Focus on weakest domains before advancing strongest."
            if min_score < avg_score - 1
            else "Balanced programme — advance all domains."
        ),
        "domain_scores": domain_scores,
    }
```

### Step 4: Quarterly Review Process

```markdown
## Quarterly Maturity Review Agenda

### 1. Metrics Review (30 minutes)
For each domain, review:
- Current score vs. last quarter.
- Evidence for current level.
- Metrics trending in the right direction?

### 2. Next-Level Gap Analysis (20 minutes)
For the 2-3 domains furthest below target:
- What specifically is missing to reach the next level?
- What is the highest-leverage action?

### 3. Roadmap Update (20 minutes)
- Which domain advances are planned for next quarter?
- Who owns each initiative?
- What is the measurable success criterion?

### 4. Metric Ownership (10 minutes)
- Confirm each metric has an owner.
- Confirm dashboards are up to date.
- Any metrics that are no longer meaningful?

### Outputs
- Updated domain scores with evidence.
- Prioritised initiative list for next quarter.
- Updated maturity roadmap (12-month view).
```

### Step 5: Maturity vs. Outcomes — The Critical Test

Maturity scores are means, not ends. Connect maturity to outcome metrics:

```yaml
# outcome-metrics.yaml — what maturity improvement should produce.
outcome_metrics:
  security_incidents:
    - metric: "Number of security incidents per quarter"
      expected_trend: "Decreasing as detection improves; then stable (not zero)"
      level_3_target: "< 5 incidents per quarter undetected >24h"
      level_4_target: "All incidents detected within 4 hours"

  vulnerability_exposure:
    - metric: "Mean exposure window for critical CVEs (days from disclosure to patch)"
      level_3_target: "< 30 days"
      level_4_target: "< 7 days for internet-facing; < 14 days for internal"
      level_5_target: "< 3 days for CISA KEV"

  developer_productivity:
    - metric: "Security gate cycle time (time from PR to security check passing)"
      level_3_target: "< 5 minutes for SAST/SCA"
      level_4_target: "< 2 minutes (cached results)"
      rationale: "Security should not slow development; if it does, fix the tooling"

  breach_impact:
    - metric: "Mean time to contain after incident (hours)"
      level_3_target: "< 24 hours"
      level_4_target: "< 4 hours"
      level_5_target: "< 1 hour (automated containment)"
```

### Step 6: Level-Up Playbooks

For each domain, define the specific steps to advance from level N to N+1:

```yaml
# level-up-playbooks.yaml — concrete advancement steps.

secure_development:
  from_2_to_3:
    - action: "Enable SAST on all production repositories"
      tool_options: ["Semgrep", "CodeQL", "Snyk Code"]
      success_criterion: "100% of production repos with SAST gate"
      effort_estimate: "2-4 weeks"

    - action: "Enable SCA for dependency scanning on all repos"
      tool_options: ["Dependabot", "Snyk", "Renovate + Grype"]
      success_criterion: "All repos have automated dependency PRs"
      effort_estimate: "1-2 weeks"

    - action: "Define and enforce remediation SLAs"
      success_criterion: "SLA defined per severity; tracked in JIRA"
      effort_estimate: "1 week for policy; ongoing enforcement"

  from_3_to_4:
    - action: "Add secret scanning to all CI pipelines"
      tool_options: ["GitHub Advanced Security", "Gitleaks", "truffleHog"]
      success_criterion: "No secrets committed; historical secrets rotated"
      effort_estimate: "2-3 weeks"

    - action: "Add DAST to integration test pipeline"
      tool_options: ["OWASP ZAP", "Nuclei", "Burp Suite Enterprise"]
      success_criterion: "DAST runs against staging on every PR to main"
      effort_estimate: "4-8 weeks"
```

### Step 7: CISO / Leadership Reporting

```python
# maturity_report.py — generate executive-readable maturity report.

def generate_executive_summary(
    scores: list[DomainScore],
    previous_quarter_scores: list[DomainScore],
) -> str:
    current = {s.domain: s.current_level for s in scores}
    previous = {s.domain: s.current_level for s in previous_quarter_scores}

    improved = [d for d in current if current[d] > previous.get(d, 0)]
    declined = [d for d in current if current[d] < previous.get(d, 99)]
    unchanged = [d for d in current if current[d] == previous.get(d, current[d])]

    overall = sum(current.values()) / len(current)

    return f"""
Security Programme Maturity — Q{current_quarter} {current_year}

Overall score: {overall:.1f} / 5.0

Improvements this quarter:
{chr(10).join(f'  ✓ {d}: {previous.get(d,0)} → {current[d]}' for d in improved) or '  None'}

Areas for attention:
{chr(10).join(f'  → {d}: still at level {current[d]}' for d in unchanged if current[d] <= 2) or '  None at critical level'}

Key metrics:
  - Mean time to remediate critical CVEs: {get_metric("mttr_critical")} days
  - Security incidents detected within 4h: {get_metric("detection_rate_4h")}%
  - % workloads with security monitoring: {get_metric("monitoring_coverage")}%

Next quarter priorities:
  1. Advance {get_lowest_domain(current)} from level {current[get_lowest_domain(current)]}
  2. {get_next_initiative()}
"""
```

### Step 8: Telemetry

```
devsecops_maturity_level{domain, quarter}                  gauge
devsecops_maturity_trend{domain}                           gauge  (delta from previous)
security_incident_mttd_hours{quarter}                      gauge
security_incident_mttc_hours{quarter}                      gauge
vulnerability_mttr_days{severity, quarter}                 gauge
vulnerability_sla_compliance_pct{severity}                 gauge
sast_coverage_pct{quarter}                                 gauge
alert_signal_ratio{quarter}                                gauge
```

Alert on:

- `devsecops_maturity_trend` < 0 for any domain — a domain has regressed; investigate cause.
- `vulnerability_sla_compliance_pct{severity="critical"}` < 90% — critical vulnerability SLA being breached.
- `sast_coverage_pct` drops — new repos added without SAST coverage.
- No quarterly review completed — maturity assessment is overdue.

## Expected Behaviour

| Maturity Level | Incident Response | Vulnerability Management | Developer Impact |
|---------------|------------------|------------------------|-----------------|
| Level 1 | Days to weeks to detect | No SLA; most untracked | Security invisible |
| Level 2 | 24-48h to detect | Informal tracking | Some friction |
| Level 3 | < 24h detect; playbooks exist | SLAs defined and tracked | Gates in CI |
| Level 4 | < 4h detect; automated containment | MTTR trending down; >90% SLA | Fast gates; minimal friction |
| Level 5 | < 1h detect; automated response | Near-real-time patching for critical | Security enables velocity |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Domain-level scoring | Identifies specific weaknesses | More work to assess and maintain | Annual deep assessment; quarterly metrics-only update |
| Quantitative metrics | Objective progress tracking | Metric gaming (teaching to the test) | Outcome metrics alongside process metrics |
| Staged advancement (N to N+1) | Avoids premature optimisation | Slow progress perception | Celebrate level advances; track intermediate milestones |
| Cross-domain visibility | Exposes blind spots | Risk of over-indexing on lagging domains | Balance: advance weakest without stalling strongest |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Maturity scores disconnected from outcomes | High maturity score; incidents still happening | Outcome metrics flat despite maturity increase | Re-examine evidence for maturity claims; connect to real measures |
| One domain advanced at expense of others | High security score in one area; critical gaps elsewhere | Domain score variance > 2 levels | Rebalance investment; set minimum floor for all domains |
| Maturity exercise becomes compliance checkbox | Annual assessment; no quarterly follow-through | No domain improvements between annual reviews | Mandate quarterly reviews; tie to engineering OKRs |
| Ownership unclear | Domains stagnate; "someone else's problem" | No owner assigned; no progress | Assign named owner per domain; make it an OKR |

## Related Articles

- [Security Metrics Program](/articles/cross-cutting/security-metrics-program/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
- [Penetration Testing Methodology](/articles/cross-cutting/penetration-testing-methodology/)
- [Bug Bounty Program Setup](/articles/cross-cutting/bug-bounty-program/)
- [Compliance as Code](/articles/cross-cutting/compliance-as-code/)
