---
title: "Bug Bounty Program Setup: Scope, Triage, and Researcher Relations"
description: "A bug bounty program extends vulnerability discovery beyond internal security teams by paying external researchers for valid findings. A poorly designed program creates legal risk, researcher frustration, and low signal-to-noise. Structured scope, clear policies, and fast triage convert researcher effort into genuine risk reduction."
slug: "bug-bounty-program"
date: 2026-05-01
lastmod: 2026-05-01
category: "cross-cutting"
tags: ["bug-bounty", "vulnerability-disclosure", "researcher-relations", "security-program"]
personas: ["security-engineer", "ciso"]
article_number: 309
difficulty: "intermediate"
estimated_reading_time: 12
published: true
layout: article.njk
permalink: "/articles/cross-cutting/bug-bounty-program/index.html"
---

# Bug Bounty Program Setup: Scope, Triage, and Researcher Relations

## Problem

Bug bounty programs have become a standard component of mature security programmes. The concept is simple: pay external security researchers to find vulnerabilities you haven't found yourself. The execution is harder: a poorly designed program creates legal exposure, wastes triage time on non-issues, frustrates legitimate researchers, and ultimately produces less value than an equivalent investment in internal security work.

Common failure modes:

- **No scope definition.** Researchers test systems they shouldn't — third-party integrations, customer infrastructure, systems the company doesn't own. The company receives reports for out-of-scope systems; legal exposure follows for researchers who accessed systems without permission.
- **No safe harbour language.** Without explicit legal protection, a researcher who finds a critical vulnerability risks prosecution under the Computer Fraud and Abuse Act or similar laws, even if the finding is legitimate and reported in good faith. Without safe harbour, only unsophisticated researchers participate; skilled researchers avoid the program.
- **Slow triage drives researcher attrition.** A researcher submits a critical finding. Three weeks pass with no response. They assume the program is unmaintained and stop reporting. The vulnerability remains open.
- **Payout table not calibrated to finding quality.** A flat $500 payout for any finding regardless of severity creates perverse incentives: researchers submit large volumes of low-quality findings (missing headers, informational issues) to maximise payout per hour. High-quality researchers who find critical vulnerabilities receive the same payout as information-disclosure reports.
- **Duplicate reports not handled gracefully.** A vulnerability is found by five researchers simultaneously. Only the first receives payment. The other four receive no acknowledgement, become frustrated, and may not report future findings.
- **No researcher reputation system.** Anonymous submissions with no accountability produce more low-quality noise than named submissions where researcher reputation is on the line.

**Target systems:** HackerOne, Bugcrowd, Intigriti, Synack (managed platforms); self-hosted VDP (Vulnerability Disclosure Programs) via security.txt; internal bug bounty programs.

## Threat Model for the Program Itself

- **Adversary 1 — Social engineering via bug report:** An attacker submits a "bug report" that asks engineering to test a fix for a vulnerability by clicking a link or running a command. The report is a social engineering attempt, not a real vulnerability.
- **Adversary 2 — Extortion via vulnerability withholding:** A researcher finds a critical vulnerability, threatens to publish it publicly unless paid a ransom exceeding the bounty table. Clear policies and legal language are the primary defence.
- **Adversary 3 — Denial-of-service via automated report spam:** Automated scanners submit thousands of low-quality reports simultaneously. Triage team is overwhelmed; real findings are missed.
- **Adversary 4 — Data exfiltration beyond scope:** A researcher uses a valid finding as a pivot to exfiltrate customer data beyond what is needed to demonstrate the vulnerability. Scope limitations and data handling rules prevent this.
- These risks are mitigated by program design, legal agreements, and operational controls — not technical controls.

## Configuration

### Step 1: Program Policy Document

The policy is the foundation. Every program needs:

```markdown
# Security Bug Bounty Policy

## Safe Harbour

We commit to not pursuing legal action against security researchers who:
- Act in good faith to avoid privacy violations, service disruption, and data destruction.
- Report findings through this program before public disclosure.
- Do not access data beyond what is necessary to demonstrate the vulnerability.
- Do not exploit the vulnerability further than necessary to confirm its existence.

We will consider activities conducted in accordance with this policy as authorised,
and will work with researchers to understand and remediate their findings quickly.

## Scope

### In Scope
| Target | Description |
|--------|-------------|
| *.example.com | All public subdomains |
| api.example.com | Production REST API |
| app.example.com | Web application |

**Notes:**
- Test accounts only. Do not test against real user accounts.
- Do not exfiltrate customer data. Screenshot or record the vulnerability's existence.
- Production data must not be modified, deleted, or exfiltrated.

### Out of Scope
- Third-party services (Stripe, Salesforce, SendGrid) — report to them directly.
- Social engineering (phishing, vishing) of employees.
- Physical security testing.
- Denial of service attacks.
- Automated scanning that generates more than 100 requests/minute.
- *.staging.example.com unless explicitly added to scope.
- Any system owned by our customers.

## Reward Table

| Severity | Example | Reward Range |
|----------|---------|--------------|
| Critical | RCE, auth bypass, SQL injection exposing all data | $5,000–$20,000 |
| High | IDOR accessing another user's data, SSRF to internal services | $1,000–$5,000 |
| Medium | Stored XSS, CSRF on sensitive action, privilege escalation | $250–$1,000 |
| Low | Reflected XSS (self), info disclosure | $100–$250 |
| Informational | Missing headers, TLS configuration | $0 (recognition only) |

Rewards are at our discretion. We will not pay for:
- Known issues already tracked internally.
- Issues that require significant user interaction to exploit.
- Issues in software we do not control.

## Disclosure Timeline
- We will acknowledge your report within **3 business days**.
- We will confirm validity or request more information within **10 business days**.
- We aim to remediate Critical findings within **7 days**, High within **30 days**.
- We will notify you when the issue is remediated.
- Coordinated public disclosure: we request 90 days before public disclosure.

## Rules of Engagement
- Do not access, modify, or delete data that is not yours.
- Do not disrupt production service availability.
- Do not test from more than 3 IP addresses simultaneously.
- Do not perform automated scanning above 100 req/min.
- Report only through the official submission form.
```

### Step 2: Triage Workflow

```yaml
# triage-workflow.yaml — SLA-driven triage process.
triage_slas:
  acknowledge: "3 business days"
  initial_assessment: "5 business days"
  validity_determination: "10 business days"
  critical_remediation: "7 calendar days"
  high_remediation: "30 calendar days"
  medium_remediation: "90 calendar days"
  payout_after_validation: "14 calendar days"

triage_steps:
  step_1_acknowledge:
    action: "Send templated acknowledgement; assign internal ticket"
    owner: "Security engineer on rotation"
    sla: "3 business days"
    template: |
      Thank you for your submission. We've received your report (#BBP-{id}) and
      will review it within 10 business days. We'll reach out if we need
      clarification.

  step_2_assess:
    action: "Reproduce the finding; determine scope and severity"
    questions:
      - "Is the target in scope?"
      - "Is the finding reproducible?"
      - "Is this a known issue?"
      - "What is the actual impact if exploited?"
    owner: "Security engineer"
    sla: "5 business days from acknowledgement"

  step_3_validate:
    action: "Confirm finding; assign internal severity; notify researcher"
    owner: "Security engineer + engineering lead for affected area"
    output: "Validity determination: valid / informational / duplicate / out-of-scope / not-applicable"

  step_4_remediate:
    action: "Engineering team remediates; security verifies"
    owner: "Engineering team lead"

  step_5_reward:
    action: "Determine payout amount; process payment"
    factors:
      - "Severity: CVSS or internal severity matrix"
      - "Quality: how complete and clear was the report?"
      - "Impact: what is the realistic blast radius?"
      - "Novelty: is this a common issue or a creative, hard-to-find finding?"
    owner: "Security lead"

  step_6_close:
    action: "Notify researcher; confirm fix; allow coordinated disclosure discussion"
    owner: "Security engineer"
```

### Step 3: Payout Calibration

```python
# payout_calculator.py — structured payout determination.
from dataclasses import dataclass
from enum import Enum

class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFORMATIONAL = 0

class ReportQuality(Enum):
    EXCEPTIONAL = 1.5   # Clear PoC, detailed writeup, suggested remediation.
    GOOD = 1.0          # Reproducible, clearly explained.
    ADEQUATE = 0.75     # Reproducible but minimal detail.
    POOR = 0.5          # Hard to reproduce; minimal detail.

@dataclass
class Finding:
    severity: Severity
    quality: ReportQuality
    is_duplicate: bool
    already_known_internally: bool
    requires_user_interaction: bool   # CSRF requires victim to click a link.
    authentication_required: bool

BASE_PAYOUTS = {
    Severity.CRITICAL: 10000,
    Severity.HIGH: 3000,
    Severity.MEDIUM: 500,
    Severity.LOW: 150,
    Severity.INFORMATIONAL: 0,
}

def calculate_payout(finding: Finding) -> int:
    if finding.is_duplicate or finding.already_known_internally:
        return 0  # No payment; acknowledge with thanks.

    base = BASE_PAYOUTS[finding.severity]

    # Quality multiplier.
    payout = int(base * finding.quality.value)

    # Reduce for findings requiring extensive user interaction.
    if finding.requires_user_interaction and finding.severity in [Severity.MEDIUM, Severity.LOW]:
        payout = int(payout * 0.7)

    # Reduce for post-authentication findings on shared endpoints.
    if finding.authentication_required and finding.severity == Severity.MEDIUM:
        payout = int(payout * 0.8)

    return payout
```

### Step 4: Duplicate Handling

```markdown
## Duplicate Report Policy

When multiple researchers report the same vulnerability:

1. **First valid report wins the reward.** Timestamp of submission determines priority.

2. **Subsequent reporters receive acknowledgement:**
   "Thank you for your report (#BBP-{id}). We've confirmed this vulnerability
    was reported by another researcher. We're working on a fix. While we cannot
    offer a monetary reward for duplicate submissions, we appreciate your
    contribution and will acknowledge you in our Hall of Fame if you consent."

3. **If the duplicate provides new information** (attack vector, higher impact,
   better PoC), the original reporter's payout may be increased and the new
   reporter may receive a partial reward at our discretion.

4. **Race conditions:** Reports submitted within 48 hours of each other for the
   same finding are reviewed for unique contribution. Both researchers may
   receive partial reward.
```

### Step 5: Researcher Communication Templates

```python
# response_templates.py
TEMPLATES = {
    "acknowledgement": """
Hi {researcher_name},

Thank you for submitting report #{report_id} regarding {title}.

We've received your submission and will review it within {sla_days} business days.
If we need additional information, we'll reach out to you directly.

Our security team handles all reports through this platform. Please do not follow up
via other channels (email, social media) — all communication should remain here.

Best regards,
{company_name} Security Team
    """,

    "validation_valid": """
Hi {researcher_name},

We've reviewed your report #{report_id} and confirmed the issue you reported.

We've assessed it as **{severity}** severity and are working on a remediation.
Based on our reward table and the quality of your submission, we'll be awarding
**${payout}**.

We aim to have this fixed within {remediation_days} days and will update you when
it's been resolved. We'd appreciate your patience while we remediate.

Thank you for helping improve our security.

Best regards,
{company_name} Security Team
    """,

    "validation_out_of_scope": """
Hi {researcher_name},

Thank you for your report #{report_id}. After review, we've determined this
finding is outside our current scope:

**Reason:** {reason}

We recommend reporting this to: {redirect_to} (if applicable).

We appreciate your time and encourage you to continue testing in-scope targets.

Best regards,
{company_name} Security Team
    """,
}
```

### Step 6: Operational Security for the Program

```yaml
# Operational security requirements for the bug bounty program.
operational_security:
  submission_handling:
    - "All submissions received through the platform (HackerOne/Bugcrowd); never email."
    - "Platform DMs are not for sensitive technical discussion — use encrypted channel."
    - "Do not share submission details with engineering until triage is complete."

  internal_tracking:
    - "Create internal security ticket immediately; link to platform report."
    - "Do not paste PoC content into Slack or unencrypted channels."
    - "Use the platform's collaboration features for engineering discussion."

  payment_processing:
    - "Process payments only through the official platform (not bank transfer to researchers)."
    - "Do not request researchers' personal information beyond what the platform requires."
    - "Record all payouts in the security budget tracker."

  researcher_data:
    - "Do not retain researcher PII beyond what the platform retains."
    - "Do not share researcher identity with engineering teams without consent."
    - "Hall of Fame: opt-in only; never publish without explicit consent."
```

### Step 7: Programme Metrics

```python
# programme_metrics.py
def calculate_programme_health(reports: list, period_days: int = 90) -> dict:
    from statistics import mean

    recent = [r for r in reports
              if (datetime.now() - r.submitted_at).days <= period_days]

    return {
        # Volume.
        "total_submissions": len(recent),
        "valid_findings": len([r for r in recent if r.status == "valid"]),
        "duplicates": len([r for r in recent if r.status == "duplicate"]),
        "out_of_scope": len([r for r in recent if r.status == "out_of_scope"]),

        # Quality (signal-to-noise ratio).
        "signal_ratio": len([r for r in recent if r.status == "valid"]) / max(len(recent), 1),

        # Severity distribution of valid findings.
        "critical_count": len([r for r in recent if r.status == "valid" and r.severity == "critical"]),
        "high_count": len([r for r in recent if r.status == "valid" and r.severity == "high"]),

        # Responsiveness.
        "mean_time_to_acknowledge_days": mean(
            [r.acknowledged_at.timestamp() - r.submitted_at.timestamp()
             for r in recent if r.acknowledged_at] ) / 86400,
        "mean_time_to_validate_days": mean(
            [(r.validated_at - r.submitted_at).days
             for r in recent if r.validated_at]),

        # Value.
        "total_paid": sum(r.payout for r in recent if r.payout),
        "cost_per_valid_finding": sum(r.payout for r in recent if r.payout) / max(
            len([r for r in recent if r.status == "valid"]), 1),
    }
```

### Step 8: Telemetry

```
bbp_submissions_total{severity, status, period}         counter
bbp_time_to_acknowledge_days{percentile}                gauge
bbp_time_to_validate_days{percentile}                   gauge
bbp_time_to_remediate_days{severity, percentile}        gauge
bbp_payout_total{severity, period}                      counter
bbp_signal_ratio{period}                                gauge  # valid/total
bbp_duplicate_rate{period}                              gauge
bbp_sla_breach_total{sla_type}                          counter
```

Alert on:

- `bbp_time_to_acknowledge_days` P50 > 3 — SLA breach on acknowledgement; triage process is understaffed.
- `bbp_signal_ratio` < 0.1 — more than 90% of reports are invalid; scope may be too broad, or automated scanning generating noise.
- `bbp_sla_breach_total{sla_type="critical_remediation"}` — a critical finding is not remediated within 7 days.
- Unusual spike in submissions from a single researcher — possible automated submission; review for quality.

## Expected Behaviour

| Signal | Ad-hoc VDP | Structured bug bounty |
|--------|-----------|----------------------|
| Researcher finds critical vuln | May not report; unsure of legal protection | Safe harbour provides explicit protection; report submitted |
| Triage takes 30 days | Researcher assumes unmaintained; no further reports | 3-day acknowledge SLA; researcher remains engaged |
| All reports pay same amount | Low-quality submissions dominate | Payout table with quality multiplier incentivises high-quality reports |
| Duplicate handling unclear | First reporter unsatisfied; others resentful | Clear policy; duplicates acknowledged with thanks |
| Programme quality metrics | Unknown | Signal ratio, MTTR, cost-per-finding tracked quarterly |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Public vs private program | Public: more researchers, broader coverage | Public: higher volume of noise reports | Start private (invited researchers); expand to public after triage process is mature |
| Managed platform (HackerOne/Bugcrowd) | Triage support, researcher network, payment handling | Platform fees (~20% of payouts) | Justified by reduced triage overhead and researcher trust |
| High rewards | Attracts skilled researchers to high-value findings | Budget impact; creates expectations | Cap maximum rewards; weight by impact, not just severity |
| Strict scope | Focused, manageable | Misses vulnerabilities on out-of-scope assets | Expand scope gradually as triage capacity allows |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Triage overwhelmed by spam | SLA breaches; valid findings missed | `bbp_time_to_acknowledge_days` spike | Rate-limit automated submissions; require manual verification; narrow scope |
| No engineering buy-in | Valid findings not remediated | `bbp_sla_breach_total` for high/critical | Establish bug bounty SLA as engineering OKR; CISO escalation path |
| Researcher extortion attempt | Demand exceeds bounty; threat to publish | Out-of-band communication from researcher | Follow legal escalation procedure; do not negotiate; engage legal counsel |
| False positive paid out | Payout processed for invalid finding | Post-payout review finds error | Implement two-person review before payout; accept cost as learning |

## Related Articles

- [Penetration Testing Methodology](/articles/cross-cutting/penetration-testing-methodology/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
- [Security Metrics Program](/articles/cross-cutting/security-metrics-program/)
- [Continuous Red Teaming](/articles/ai-landscape/continuous-red-teaming/)
- [Tabletop Exercises](/articles/cross-cutting/tabletop-exercises/)
