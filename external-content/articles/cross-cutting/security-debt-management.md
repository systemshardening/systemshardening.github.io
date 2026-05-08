---
title: "Security Debt Management: Prioritising, Tracking, and Reducing Accumulated Risk"
description: "Security debt accumulates when known vulnerabilities are deferred, security controls are skipped under time pressure, and deprecated libraries linger. Unmanaged security debt grows faster than it's resolved. This guide covers security debt taxonomy, risk-based prioritisation, tracking in engineering systems, and making the business case for security remediation."
slug: security-debt-management
date: 2026-05-07
lastmod: 2026-05-07
category: cross-cutting
tags:
  - security-debt
  - risk-management
  - vulnerability-management
  - technical-debt
  - prioritisation
personas:
  - security-engineer
  - security-analyst
article_number: 614
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/cross-cutting/security-debt-management/
---

# Security Debt Management: Prioritising, Tracking, and Reducing Accumulated Risk

## Problem

Security debt is the accumulated backlog of known security risks that an organisation has chosen, explicitly or implicitly, to defer. It differs from a vulnerability management program in a fundamental way: vulnerability management is reactive — finding and fixing newly discovered weaknesses. Security debt management is proactive — deliberately tracking risks that are already known, already accepted, and still outstanding.

Every engineering organisation carries security debt. The question is whether that debt is managed or invisible.

Unmanaged security debt has a compounding effect. A legacy authentication library with a known design flaw is deferred because "it still works". Six months later, a public exploit appears. Twelve months later, the service has grown to serve one million users and the remediation cost is ten times higher than it would have been. The risk was never zero — it was just untracked.

Common failure modes that create security debt:

- **Deferral under time pressure.** A sprint deadline is imminent. A security review flags that the session token implementation is weak. The team accepts the risk verbally and ships. No ticket is created. The risk is never revisited.
- **EOL dependency drift.** A Python 2.7 service was scheduled for deprecation in 2023. It is still running in production in 2026. Every dependency in that service is now beyond end-of-life; no patches are available for any vulnerabilities discovered after the EOL date.
- **Missing security controls.** A new microservice was deployed without mTLS because the infrastructure wasn't ready. The intent was to add it "soon". That service has been in production for 14 months.
- **Insecure-by-design legacy components.** A monolith from 2016 uses MD5 for internal checksums, a flat database with no row-level access control, and user-supplied input concatenated into SQL queries. The team knows. Nobody has been given the mandate or capacity to fix it.
- **Undocumented security exceptions.** A penetration test in 2024 identified three critical findings. All three were marked "accepted" in the test report. No ticket was created. Nobody knows whether compensating controls were implemented or whether the issues still exist.
- **Unpatched infrastructure.** Kubernetes nodes are running a kernel version from 2022. Nobody owns the patching schedule for nodes; it was assumed to be the platform team's responsibility but was never formally assigned.

The common thread: each item was known when it entered the backlog. None of them are surprises. The failure is not in detection but in tracking, ownership, and remediation.

**Target systems:** Any engineering organisation managing production software, infrastructure, or cloud resources. The practices in this guide apply equally to a five-person startup and a five-thousand-person enterprise; the tooling choices differ but the framework does not.

## Threat Model

- **Adversary 1 — Deferred vulnerability exploitation:** A known CVE was accepted as risk 18 months ago because no exploit was publicly available. An exploit is released. The security debt item was never re-evaluated; the compensating controls were never reviewed. The system is compromised.
- **Adversary 2 — EOL dependency supply chain attack:** A Python package that is beyond EOL is not receiving security patches. A new vulnerability is discovered in that package, but no patch is available and the team has no mechanism to track EOL risk items to escalation. The vulnerability persists indefinitely.
- **Adversary 3 — Undocumented exception accumulation:** Over three years, forty security exceptions have been granted. None have been reviewed. Twenty of them contain findings that now have available patches. Nobody knows because the exception records exist only in audit PDFs.
- **Adversary 4 — Missing control exploitation:** A service was deployed without authentication on its internal management API "temporarily". That service is network-accessible from a compromised container in the same cluster. The missing control is never in any backlog; it simply does not exist as a tracked risk.
- **Adversary 5 — Insecure legacy component lateral movement:** A legacy component with SQL injection vulnerabilities is used as an internal data service. An attacker who gains limited initial access pivots through the SQL injection to exfiltrate the entire database. The finding was in the security backlog but had been deferred twelve times.
- **Blast radius:** Legacy and deferred risks tend to be in the oldest, most interconnected parts of the system — the components with the highest blast radius if compromised.

## Configuration

### Step 1: Security Debt Taxonomy

Before you can track security debt, you need consistent categories. Without taxonomy, "security issues" is a single undifferentiated mass that is impossible to prioritise or report on.

```yaml
# security-debt-taxonomy.yaml
# Use these categories as labels in Jira, GitHub Issues, or your security backlog.

categories:
  known_vulnerability_deferred:
    label: "sd-known-vuln"
    description: >
      A CVE or known vulnerability affecting a component we own or operate,
      where patching has been formally or informally deferred.
    examples:
      - "CVE-2023-44487 (HTTP/2 Rapid Reset) on nginx — deferred pending upgrade window"
      - "Log4Shell on internal audit logging service — no exploitable path identified but unfixed"
    escalation_trigger: "Weaponised exploit published, or CISA KEV inclusion"

  eol_dependency:
    label: "sd-eol"
    description: >
      A library, runtime, operating system, or infrastructure component
      that has reached end-of-life and is no longer receiving security patches.
    examples:
      - "Python 2.7 runtime on payment-processor service"
      - "Ubuntu 18.04 LTS base image (EOL April 2023)"
      - "OpenSSL 1.0.x — no patches since 2020"
    escalation_trigger: "New CVE published with no available fix due to EOL status"

  missing_security_control:
    label: "sd-missing-control"
    description: >
      A security control that was intentionally omitted or never implemented,
      where the absence creates known risk.
    examples:
      - "Payments API missing rate limiting on /auth/token endpoint"
      - "Internal admin service has no authentication (VPN-only access assumed)"
      - "No MFA enforcement for admin accounts in legacy identity provider"
    escalation_trigger: "Related control bypass technique published; audit finding"

  insecure_by_design:
    label: "sd-design"
    description: >
      A component whose architecture or design contains a fundamental security flaw
      that cannot be patched — only redesigned or replaced.
    examples:
      - "Session tokens are sequential integers — enumerable by design"
      - "Shared API key used by all consumers — no per-consumer isolation"
      - "All users share a single database role with full table access"
    escalation_trigger: "Related design pattern publicly exploited; compliance requirement"

  unpatched_infrastructure:
    label: "sd-infra"
    description: >
      Infrastructure components (OS kernels, node images, firmware) with available
      security patches that have not been applied.
    examples:
      - "Kubernetes nodes running kernel 5.15 with CVE-2024-1086 (local privilege escalation)"
      - "Network appliance firmware 18 months behind vendor releases"
    escalation_trigger: "PoC exploit published for an unpatched CVE"

  undocumented_exception:
    label: "sd-exception"
    description: >
      A previously accepted security exception with no current tracking ticket,
      no compensating controls documented, and no review date set.
    examples:
      - "Pentest finding from 2023 report marked 'accepted' — no follow-up"
      - "RBAC bypass documented in bug tracker but closed without fix in 2024"
    escalation_trigger: "Exception review date passed; original risk conditions changed"
```

### Step 2: Distinguishing Security Debt from Vulnerability Management

These two disciplines overlap but are not the same. Conflating them leads to poor tracking discipline.

| Dimension | Vulnerability Management | Security Debt Management |
|-----------|--------------------------|--------------------------|
| Trigger | Scanner finds a new CVE | Known risk is deferred or design is acknowledged as weak |
| Discovery | Automated scanning | Security reviews, pentest reports, architecture audits, retrospectives |
| Lifecycle | Find → Assess → Patch → Verify | Acknowledge → Score → Track → Prioritise → Remediate or formally accept |
| Ownership | Assigned to asset owner | May require team negotiation; often cross-team |
| Tooling | Trivy, Grype, Dependabot, Inspector | Jira security backlog, GitHub Issues, risk register |
| SLA model | SLA from discovery date | SLA from deferral date + re-evaluation triggers |

Vulnerability management handles the stream of new findings. Security debt management handles the accumulated backlog of deferred and known risks. Both require different workflows and different metrics.

### Step 3: Risk Scoring for Security Debt Prioritisation

A security debt backlog without prioritisation is a list. Prioritisation requires a consistent scoring model so that the most dangerous items surface to the top regardless of when they were added or who added them.

```python
# security_debt/risk_scorer.py
from dataclasses import dataclass, field
from enum import IntEnum
from datetime import date, timedelta

class AssetCriticality(IntEnum):
    CRITICAL   = 4   # Revenue-generating, PII, authentication
    HIGH       = 3   # Internal services with sensitive data
    MEDIUM     = 2   # Internal tools, dev environments
    LOW        = 1   # Non-production, sandboxed

class Exploitability(IntEnum):
    WEAPONISED = 4   # Point-and-click exploit; in CISA KEV
    POC_PUBLIC = 3   # Proof-of-concept published
    THEORETICAL= 2   # Exploit technique known; no public PoC
    NONE       = 1   # No known exploitation path

class CompensatingControlStrength(IntEnum):
    NONE        = 0   # No compensating controls
    WEAK        = 1   # Logging/monitoring only
    MODERATE    = 2   # WAF rule or network restriction
    STRONG      = 3   # Multiple layered controls; near-equivalent mitigation

@dataclass
class SecurityDebtItem:
    item_id: str
    category: str                    # From taxonomy labels above.
    cvss_base_score: float           # 0.0–10.0; 5.0 if no CVE applies.
    exploitability: Exploitability
    asset_criticality: AssetCriticality
    compensating_controls: CompensatingControlStrength
    days_deferred: int               # Days since item was first identified.
    deferred_count: int              # Number of times item has been deferred.

def calculate_risk_score(item: SecurityDebtItem) -> float:
    """
    Returns a risk score for prioritisation.
    Higher score = higher priority for remediation.
    
    Formula rationale:
    - CVSS base score provides the vulnerability severity baseline.
    - Exploitability evidence is the strongest predictor of active exploitation.
    - Asset criticality scales risk by business impact.
    - Compensating controls reduce risk — but not to zero.
    - Aging penalty: items deferred repeatedly are more dangerous (drift, forgotten context).
    """
    base = item.cvss_base_score * 10  # Scale to 0–100.
    
    # Exploitability multiplier: weaponised exploits demand immediate action.
    exploitability_multipliers = {
        Exploitability.WEAPONISED:  2.5,
        Exploitability.POC_PUBLIC:  1.8,
        Exploitability.THEORETICAL: 1.2,
        Exploitability.NONE:        1.0,
    }
    base *= exploitability_multipliers[item.exploitability]
    
    # Asset criticality scaling.
    base *= (item.asset_criticality / 2.0)
    
    # Compensating controls reduce effective risk.
    control_discount = {
        CompensatingControlStrength.STRONG:   0.4,
        CompensatingControlStrength.MODERATE: 0.6,
        CompensatingControlStrength.WEAK:     0.85,
        CompensatingControlStrength.NONE:     1.0,
    }
    base *= control_discount[item.compensating_controls]
    
    # Aging penalty: items deferred 3+ times get escalation weight.
    if item.deferred_count >= 3:
        base *= 1.3
    elif item.deferred_count >= 1:
        base *= 1.1
    
    # Age factor: items older than 90 days with no re-evaluation get a bump.
    if item.days_deferred > 180:
        base *= 1.25
    elif item.days_deferred > 90:
        base *= 1.1
    
    return round(base, 1)


def risk_band(score: float) -> str:
    """Map numeric score to a priority band for SLA assignment."""
    if score >= 200: return "P1-Critical"
    if score >= 120: return "P2-High"
    if score >= 60:  return "P3-Medium"
    return "P4-Low"
```

Example scoring for a realistic item:

```python
# Example: legacy auth library with active exploit in the wild.
auth_lib_debt = SecurityDebtItem(
    item_id="SD-0042",
    category="sd-known-vuln",
    cvss_base_score=8.8,
    exploitability=Exploitability.WEAPONISED,
    asset_criticality=AssetCriticality.CRITICAL,
    compensating_controls=CompensatingControlStrength.WEAK,  # WAF rule only.
    days_deferred=47,
    deferred_count=2,
)
# Score: 8.8 * 10 * 2.5 * 2.0 * 0.85 * 1.1 = ~411 → P1-Critical
```

### Step 4: Tracking Security Debt in Engineering Systems

Security debt lives in the same systems as product work. Items tracked only in a security team's spreadsheet will never be prioritised alongside features.

**Jira configuration:**

```yaml
# security-debt-jira-config.yaml

issue_type: "Security Debt"  # Distinct from Bug or Story.

required_fields:
  - debt_category        # From taxonomy: sd-known-vuln, sd-eol, etc.
  - risk_score           # Calculated numeric score.
  - risk_band            # P1-Critical through P4-Low.
  - asset_affected       # Link to CMDB or asset identifier.
  - date_first_identified:
  - deferred_count       # Incremented each time item is pushed to a future sprint.
  - review_due_date      # Maximum date for re-evaluation (not necessarily fix).
  - compensating_controls: # Freetext description of current mitigations.
  - remediation_owner    # Assigned engineer or team.

labels:
  - security-debt        # Always applied; enables cross-project dashboards.
  - {debt_category}      # e.g., sd-eol, sd-missing-control.
  - {risk_band}          # e.g., p1-critical.

workflow:
  states:
    - Identified         # Item entered; risk score calculated.
    - Prioritised        # Assigned to a sprint backlog; owner confirmed.
    - In Progress        # Active remediation work underway.
    - Remediated         # Fix applied; pending verification.
    - Verified           # Verification scan or test confirms fix.
    - Formally Accepted  # Board-level risk acceptance; mandatory review date.
    - Escalated          # Passed re-evaluation threshold; management notified.

automation_rules:
  - trigger: "deferred_count incremented to 3"
    action: "Set status to Escalated; notify security-eng-lead and CISO"
  - trigger: "review_due_date exceeded by 7 days"
    action: "Set status to Escalated; create child ticket for review meeting"
  - trigger: "exploitability changes to WEAPONISED"
    action: "Set risk_band to P1-Critical; page on-call security engineer"
```

**GitHub Issues configuration (for teams using GitHub Projects):**

```yaml
# .github/ISSUE_TEMPLATE/security-debt.yml
name: Security Debt Item
description: Track a known security risk that requires remediation or formal acceptance.
labels: ["security-debt"]
body:
  - type: dropdown
    id: category
    label: Debt Category
    options:
      - sd-known-vuln (Known vulnerability, deferred patch)
      - sd-eol (End-of-life dependency or runtime)
      - sd-missing-control (Security control not implemented)
      - sd-design (Insecure-by-design component)
      - sd-infra (Unpatched infrastructure)
      - sd-exception (Undocumented or expired exception)

  - type: input
    id: cvss
    label: CVSS Base Score (0.0–10.0; use 5.0 if no CVE applies)

  - type: dropdown
    id: exploitability
    label: Exploitability Evidence
    options:
      - WEAPONISED (in CISA KEV or active exploitation confirmed)
      - POC_PUBLIC (public proof-of-concept available)
      - THEORETICAL (technique known; no public PoC)
      - NONE (no known exploitation path)

  - type: dropdown
    id: asset_criticality
    label: Asset Criticality
    options:
      - CRITICAL (revenue, PII, authentication)
      - HIGH (internal sensitive data)
      - MEDIUM (internal tooling)
      - LOW (non-production)

  - type: textarea
    id: compensating_controls
    label: Compensating Controls Currently in Place

  - type: input
    id: review_date
    label: Review Due Date (YYYY-MM-DD)
    description: Maximum date for re-evaluation. Must not exceed SLA for the risk band.
```

### Step 5: SLAs and SLOs for Security Debt

Security debt without time constraints accumulates indefinitely. SLAs define the maximum age for a security debt item at each risk band before mandatory escalation.

```yaml
# security-debt-sla.yaml

sla_policy:
  # SLA = maximum time from identification to remediation or formal board-level acceptance.
  # Re-evaluation = mandatory review of compensating controls and risk score.

  P1_Critical:
    remediation_sla_days: 14
    re_evaluation_interval_days: 7
    escalation_path: "CISO + Engineering VP"
    deferral_allowed: false
    notes: >
      P1 items must be remediated or escalated to board within 14 days.
      No deferrals. If technically infeasible, a board-level risk acceptance
      with documented compensating controls is required.

  P2_High:
    remediation_sla_days: 30
    re_evaluation_interval_days: 14
    escalation_path: "Security Engineering Lead + Engineering Director"
    max_deferrals: 1
    notes: >
      One deferral allowed with written justification and updated
      compensating controls. Second deferral requires director approval.

  P3_Medium:
    remediation_sla_days: 90
    re_evaluation_interval_days: 30
    escalation_path: "Security Engineering Lead"
    max_deferrals: 2

  P4_Low:
    remediation_sla_days: 180
    re_evaluation_interval_days: 90
    escalation_path: "Team Lead"
    max_deferrals: 3

mandatory_re_evaluation_triggers:
  - "Exploitability evidence changes (e.g., PoC published for a previously theoretical risk)"
  - "Asset criticality changes (e.g., service now exposed to internet)"
  - "Compensating control fails or is removed"
  - "Related CVE or attack campaign confirmed in wild"
  - "Compliance audit scheduled within 60 days"
  - "Third-party penetration test scheduled within 30 days"
```

### Step 6: Making the Business Case

Security debt items that remain invisible to engineering leadership and product management will not be funded. Translating security risk into business language is a core skill for security engineers.

```
# Business case framing template for security debt items.
# Use this language in sprint planning, quarterly planning, and risk reviews.

AVOID: "CVE-2023-44487 affects our nginx version and has a CVSS score of 7.5."

USE:
  "Our authentication service is running a version of nginx with a publicly
   known denial-of-service vulnerability that has been exploited in the wild
   against organisations similar to ours. The service handles login for
   1.2 million active users. A successful attack would prevent all users from
   logging in until mitigation or recovery — estimated 4–8 hours of incident
   response. The patch is a one-line version bump with a 30-minute deployment
   window. We are asking for one engineer-day this sprint."

AVOID: "We have three sd-eol items in the Python 2.7 service."

USE:
  "The payment-processor service runs on a Python runtime that reached
   end-of-life in January 2020. Any vulnerability discovered in that runtime
   today will never receive a patch — we are permanently exposed. The service
   processes $4M in transactions per day. Migrating to Python 3.12 is estimated
   at 8 engineer-weeks. The alternative is accepting unlimited future liability
   on a critical revenue system."
```

When presenting security debt to non-technical stakeholders, structure the case around three questions:

1. **What is the specific, credible harm?** Not "attacker could gain access" — instead, "an attacker who exploits this can exfiltrate the customer PII database, exposing us to GDPR notification obligations and regulatory fines."
2. **What is the probability or evidence of exploitation?** CISA KEV inclusion, active campaign reports, or exploit availability are concrete signals. Absence of exploits is also meaningful — it shifts the urgency without removing the risk.
3. **What is the cost of remediation versus the cost of the incident?** A four-day engineering effort to patch a vulnerable component is almost always cheaper than four weeks of incident response, forensics, and notification. Quantifying this comparison makes the case concrete.

### Step 7: Security Debt Aging Reports

Security debt items that survive multiple deferrals should be automatically surfaced to leadership. A debt item deferred three times is not a low-priority item — it is a stuck item that requires escalation, not another deferral.

```python
# security_debt/aging_report.py
from datetime import date, timedelta
from collections import defaultdict

def generate_aging_report(debt_items: list) -> dict:
    """
    Produces a weekly security debt aging report.
    Used as input for the security engineering all-hands and sprint planning.
    """
    today = date.today()
    report = {
        "overdue_by_band":   defaultdict(list),
        "repeatedly_deferred": [],
        "escalation_required": [],
        "eol_items_no_fix_path": [],
        "approaching_sla": [],
    }
    
    sla_days = {"P1-Critical": 14, "P2-High": 30, "P3-Medium": 90, "P4-Low": 180}
    
    for item in debt_items:
        age_days = (today - item.date_identified).days
        band_sla  = sla_days[item.risk_band]
        days_until_sla = band_sla - age_days
        
        # Overdue items.
        if age_days > band_sla and item.status not in ("Verified", "Formally Accepted"):
            report["overdue_by_band"][item.risk_band].append({
                "id":         item.item_id,
                "title":      item.title,
                "days_overdue": age_days - band_sla,
                "owner":      item.owner,
                "deferred_count": item.deferred_count,
            })
        
        # Items deferred 3+ times — mandatory escalation.
        if item.deferred_count >= 3 and item.status not in ("Verified", "Formally Accepted"):
            report["repeatedly_deferred"].append(item.item_id)
        
        # Approaching SLA within 7 days.
        if 0 < days_until_sla <= 7:
            report["approaching_sla"].append({
                "id":       item.item_id,
                "band":     item.risk_band,
                "days_left": days_until_sla,
                "owner":    item.owner,
            })
        
        # EOL items with no upstream fix path.
        if item.category == "sd-eol" and not item.fix_available:
            report["eol_items_no_fix_path"].append(item.item_id)
    
    return report
```

The aging report should be distributed weekly to:

- Security engineering lead (owns the overall debt backlog)
- Engineering directors (for items in their domain)
- CISO (for items overdue by more than 14 days or repeatedly deferred)

### Step 8: Paying Down Security Debt in Sprints

Security debt is paid down in the same engineering sprints as feature work. It does not happen in a dedicated "security sprint" scheduled for some future quarter — that quarter never arrives.

```yaml
# sprint-security-debt-policy.yaml

capacity_allocation:
  default_security_debt_pct: 15
  description: >
    Teams allocate 15% of sprint capacity to security debt items each sprint.
    For a team of 6 with 80 story points per sprint, this is 12 points of security
    debt work per sprint — approximately one major debt item or two minor ones.
  
  escalation_override: true
  escalation_override_description: >
    P1-Critical items override all other allocations. A P1 item is worked
    immediately until resolved, even if this displaces planned feature work.
    Feature deferral for a P1 is a normal operating condition, not an exception.

sprint_selection_criteria:
  # In sprint planning, security debt items are selected from the backlog using
  # these criteria, in order of priority:
  1: "P1-Critical items — all must be in active work."
  2: "P2-High items that are past their SLA."
  3: "P2-High items that are within 7 days of their SLA."
  4: "Items that are prerequisites for other planned features (dependency unblocking)."
  5: "P3-Medium items ranked by risk score, highest first."

definition_of_done:
  - "Remediation applied and verified by scan, test, or peer review."
  - "Jira/GitHub ticket updated with resolution evidence."
  - "Compensating controls documented if full remediation was not achieved."
  - "If partially resolved: residual risk re-scored and new SLA set."
  - "If accepted risk: formal acceptance ticket linked; review date set."
```

### Step 9: Avoiding New Security Debt

The cheapest security debt to remediate is the debt that is never created. Two practices prevent new debt from entering the backlog untracked.

**Secure design review before implementation:**

```yaml
# secure-design-review-checklist.yaml
# Run before any new service, major feature, or significant architecture change.
# Items flagged as "deferred" must be immediately entered as security debt items.

authentication_and_authorisation:
  - "Does the feature handle authentication? If so, is it using the standard identity provider?"
  - "Are authorisation decisions made server-side or client-side?"
  - "Is there a permission model? Has it been reviewed for privilege escalation paths?"

data_handling:
  - "What data does this feature process? Is it classified?"
  - "Is PII or financial data stored? Where? How long? Under what access controls?"
  - "Is data encrypted at rest and in transit?"

dependencies:
  - "What new third-party libraries are being introduced?"
  - "Are all new dependencies at a current, supported version?"
  - "Is there a plan to keep them updated?"
  - "Any dependencies with known EOL dates in the next 24 months?"

security_controls_present:
  - "Rate limiting on all externally-facing endpoints?"
  - "Input validation on all user-controlled input?"
  - "Output encoding to prevent injection?"
  - "Logging and alerting for security-relevant events?"

deferred_items_process:
  instruction: >
    Any item marked "deferred" or "will implement later" during this review
    MUST be entered as a security debt item in the project tracker before
    the review is closed. The reviewer's name and review date must be recorded
    on the debt item. No security control may be deferred without a tracking ticket.
```

**Security gates in the SDLC:**

```yaml
# sdlc-security-gates.yaml

gates:
  pre_commit:
    - "Secret scanning (git-secrets, gitleaks)"
    - "SAST for high-confidence critical issues (Semgrep rules)"
    blocking: true

  ci_pipeline:
    - "Dependency vulnerability scan — block on CRITICAL CVEs with available fix"
    - "Container image scan — block if base image is EOL or has CRITICAL unfixed CVEs"
    - "IaC misconfiguration scan (Checkov, tfsec)"
    blocking: true
    exception_process: >
      If a scan finding must be suppressed to unblock CI, the suppression
      MUST be accompanied by a security debt ticket ID in the suppression comment.
      Suppression without a ticket ID fails the gate.

  pre_production:
    - "Security design review sign-off for new services or major changes"
    - "No open P1-Critical security debt items for the service being deployed"
    blocking: true
    exception_process: >
      Deployment of a service with open P1-Critical debt requires
      written approval from the CISO. This is logged and triggers an
      immediate remediation sprint.

  quarterly:
    - "Full security debt review: re-score all items older than 90 days"
    - "EOL inventory scan: identify any new EOL dependencies"
    - "Exception review: all formally accepted risks re-evaluated"
    - "Aging report presented to engineering leadership"
```

### Step 10: Telemetry and Metrics

```
# Security debt program metrics — export to Grafana or security dashboard.

security_debt_open_total{band, category}              gauge
security_debt_overdue_total{band}                     gauge
security_debt_deferred_3plus_total{}                  gauge
security_debt_age_days{band}                          histogram
security_debt_remediated_per_sprint{team}             counter
security_debt_created_per_sprint{category}            counter
security_debt_capacity_pct{team}                      gauge
security_debt_eol_no_fix_total{}                      gauge
security_debt_exceptions_active_total{}               gauge
security_debt_exceptions_past_review_date_total{}     gauge
```

Alert on:

- `security_debt_open_total{band="P1-Critical"}` > 0 and age > 7 days — P1 item approaching SLA without resolution.
- `security_debt_deferred_3plus_total` > 0 — mandatory escalation; items are stuck, not deprioritised.
- `security_debt_exceptions_past_review_date_total` > 0 — expired exceptions; unknown whether controls are still valid.
- `security_debt_eol_no_fix_total` growing week-over-week — EOL drift accelerating; requires EOL migration roadmap.
- `security_debt_created_per_sprint` consistently exceeds `security_debt_remediated_per_sprint` — debt is growing faster than it is being paid down; capacity allocation needs review.

## Expected Behaviour

| Signal | Unmanaged security debt | Managed security debt program |
|--------|------------------------|-------------------------------|
| Known vulnerability deferred | Verbally accepted; no ticket; forgotten | Scored, categorised, assigned, tracked to SLA |
| EOL dependency | Discovered by accident or not at all | Tracked as sd-eol with remediation plan and review date |
| Pentest finding | Appears in PDF report; never actioned | Entered as debt item within 48h of report delivery |
| P1 item deferred 3 times | Normal; nobody notices | Automatic escalation to CISO; leadership decision required |
| Security exception | Granted verbally or in report; never reviewed | Formal ticket; compensating controls documented; mandatory review date |
| Sprint planning | Security work competes invisibly with features | 15% capacity explicitly allocated; P1 items take override priority |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Structured debt taxonomy | Consistent categorisation; dashboarding; trend analysis | Initial overhead to categorise existing backlog | Run a one-time audit to categorise existing items; new items categorised at creation |
| Risk scoring model | Objective prioritisation; removes politics from ordering | Requires asset criticality and exploitability data | Start with coarse asset criticality (3 bands: critical/standard/low); refine over time |
| 15% sprint capacity allocation | Systematic debt reduction; prevents indefinite deferral | Reduces feature velocity by 15% | Frame as insurance: 15% now prevents 100% capacity incident response later |
| Mandatory escalation at 3 deferrals | Forces decision rather than indefinite deferral | Creates friction in sprint planning | Friction is the point; stuck items need a decision, not another deferral |
| SDLC suppression-with-ticket requirement | No untracked suppressions; debt always visible | Developers must create tickets to suppress findings | Provide a CLI tool that creates the ticket and inserts the ID automatically |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Security debt backlog disconnected from sprint planning | Backlog grows; nothing is selected for sprints | `security_debt_remediated_per_sprint` near zero | Embed security debt into sprint planning template; require lead to select items |
| Risk scores not updated | Items scored 18 months ago; exploitability changed | Items with unchanged risk score and recent exploit activity | Mandatory re-score at re-evaluation triggers; automate CISA KEV monitoring |
| Exception backlog | Formally accepted items accumulate; review dates missed | `security_debt_exceptions_past_review_date_total` growing | Automated ticket creation 14 days before review date; CISO notified on miss |
| New debt created faster than remediated | Backlog grows every sprint | Created vs remediated trend in dashboard | SDLC security gates prevent new debt; increase capacity allocation |
| Security debt invisible to product/leadership | No prioritisation; always loses to features | No debt items completed in 3+ sprints | Present aging report in quarterly business review; translate to business risk language |

## Related Articles

- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
- [DevSecOps Maturity Model](/articles/cross-cutting/devsecops-maturity-model/)
- [Security Metrics Program](/articles/cross-cutting/security-metrics-program/)
- [Compliance as Code](/articles/cross-cutting/compliance-as-code/)
- [Threat Modeling at Scale](/articles/cross-cutting/threat-modeling-at-scale/)
- [Security Champions Program](/articles/cross-cutting/security-champions-program/)
