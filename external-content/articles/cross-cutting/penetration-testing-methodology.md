---
title: "Penetration Testing Methodology: Scoping, Execution, and Findings Management"
description: "A penetration test is only as valuable as its scope and findings management. Poorly scoped tests miss critical attack paths; poorly managed findings sit in a PDF report and never get remediated. Structured scoping, execution phases, and a remediation workflow convert pentest findings into actual risk reduction."
slug: "penetration-testing-methodology"
date: 2026-05-01
lastmod: 2026-05-01
category: "cross-cutting"
tags: ["penetration-testing", "red-team", "vulnerability-assessment", "scoping", "findings-management"]
personas: ["security-engineer", "ciso", "platform-engineer"]
article_number: 301
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/cross-cutting/penetration-testing-methodology/index.html"
---

# Penetration Testing Methodology: Scoping, Execution, and Findings Management

## Problem

Most organisations that commission penetration tests get less value than they should. The test finds real vulnerabilities, generates a detailed report, the CISO presents it to the board, and then — the findings sit in a PDF, partially remediated at best, forgotten at worst. The same critical findings appear in the next year's test.

The root causes are process failures, not technical ones:

- **Scope that doesn't match actual risk.** The pentest scope is defined by "what the security team thinks the testers should look at" rather than "what an attacker would actually target." An external pentest that covers the marketing website but excludes the developer VPN, the CI/CD pipeline, and the internal admin portals has missed the highest-value attack paths.
- **No remediation owner assigned before the test ends.** The report lists 47 findings. Nobody is assigned responsibility for any of them before the pentest firm leaves. The findings drift into a queue and the highest-severity ones are "escalated" to a team that doesn't have context.
- **Retest not included in scope.** Developers fix the SQL injection. Nobody verifies the fix is correct. The next test finds the same issue — or a variation of it.
- **Black-box only, every time.** External black-box tests discover what an internet-based attacker would find. They miss insider threats, post-authentication vulnerabilities, and the entire internal attack surface. Running only external black-box tests every year creates a false sense of comprehensive coverage.
- **No measurement of improvement.** There is no baseline from the previous test to compare against. It is unknown whether the security programme is improving, stagnating, or regressing.

**Target systems:** Web applications, APIs, infrastructure, cloud environments, Kubernetes clusters, CI/CD pipelines, mobile applications; internal and external attack surface; assumes engagement with a qualified penetration testing firm or internal red team.

## Threat Model for the Pentest Process Itself

- **Adversary 1 — Out-of-scope data access during test:** A tester who has access to the production environment as part of a test accesses data (customer PII, financial records) beyond what is necessary for the test objective. Clear scope boundaries and data handling agreements prevent this.
- **Adversary 2 — Test disruption of production services:** An aggressive test technique (DoS, blind SQL injection, portscan storm) causes production service disruption. Rules of engagement must specify what is and is not permitted.
- **Adversary 3 — Credential handling post-test:** Credentials obtained during the test (for post-exploitation demonstration) are not revoked after the test. An attacker who obtains the pentest report inherits working credentials.
- **Adversary 4 — Report interception:** The pentest report — a comprehensive list of vulnerabilities — is transmitted over email without encryption, or stored in a shared drive with broad access. The report itself is a high-value target.
- These are process risks, not technical ones. They are addressed by the rules of engagement, credential management, and report handling procedures.

## Configuration

### Step 1: Scope Definition

Scope definition is the most important phase. Use a threat model to drive scope:

```yaml
# pentest-scope.yaml — scoping document template.

engagement:
  name: "Q2 2026 External Penetration Test"
  type: "external-black-box"    # external-black-box | internal-grey-box | red-team | web-app
  start_date: "2026-06-01"
  end_date: "2026-06-14"
  point_of_contact: "security-eng-lead@example.com"
  emergency_halt_contact: "+1-555-0100"  # 24/7 number to stop the test.

in_scope:
  # Define by IP range, hostname, application, and component.
  external_hosts:
    - "*.example.com"                    # All public subdomains.
    - "api.example.com"                  # Production API.
    - "admin.example.com"                # Admin portal.
  ip_ranges:
    - "203.0.113.0/24"                   # Company IP block.
  
  applications:
    - name: "Customer Portal"
      url: "https://app.example.com"
      authentication: "Tester accounts provided (see credentials section)"
      roles_to_test: ["viewer", "editor", "admin"]
    
    - name: "REST API"
      url: "https://api.example.com/v2"
      documentation: "Swagger spec attached"
      authentication_method: "OAuth2 JWT"

out_of_scope:
  # Explicit out-of-scope prevents scope creep and accidental testing of third parties.
  - "Third-party SaaS integrations (Salesforce, Stripe, SendGrid)"
  - "CDN infrastructure (Cloudflare) — owned by third party"
  - "DNS registrar"
  - "Corporate email (Microsoft 365) — separate engagement"
  - "Production database — data must not be read, exfiltrated, or modified"

test_types_permitted:
  - "Port and service scanning"
  - "Web application testing (OWASP Top 10)"
  - "Authentication bypass attempts"
  - "Privilege escalation attempts (within provided test accounts)"
  - "Credential stuffing against test accounts"

test_types_not_permitted:
  - "Denial of service attacks"
  - "Social engineering of employees"
  - "Physical security testing"
  - "Automated bulk data exfiltration"
  - "Destructive testing (data deletion, configuration changes)"

data_handling:
  pii_discovered: "Note the vulnerability; do not exfiltrate actual PII records"
  credentials_found: "Report immediately; do not use for further access without authorisation"
  report_classification: "Confidential — encrypt in transit; restricted access"
  report_deletion: "90 days after remediation verification"
```

### Step 2: Test Types and Coverage Matrix

Structure the pentest programme to cover the full attack surface over time:

```yaml
# pentest-programme.yaml — annual testing plan.
testing_types:
  external_network:
    frequency: annual
    scope: "Internet-facing IP ranges, web applications, APIs"
    methodology: "PTES, OWASP WSTG"
    covers: "External attacker with no prior knowledge"

  internal_network:
    frequency: annual
    scope: "Internal network from a compromised endpoint perspective"
    methodology: "PTES, MITRE ATT&CK"
    covers: "Insider threat, compromised employee workstation"

  web_application:
    frequency: "bi-annual for tier-1 apps; annual for tier-2"
    scope: "Authentication, authorisation, business logic, injection, OWASP Top 10"
    methodology: "OWASP WSTG"
    
  cloud_infrastructure:
    frequency: annual
    scope: "AWS/GCP/Azure IAM, storage misconfigurations, network exposure"
    methodology: "CIS Cloud Benchmarks, cloud-specific attack techniques"

  cicd_pipeline:
    frequency: annual
    scope: "Source control, CI/CD systems, artefact registries, secrets management"
    methodology: "OWASP CICD Security Top 10"

  red_team:
    frequency: "every 2 years"
    scope: "Full kill-chain simulation; social engineering permitted"
    methodology: "MITRE ATT&CK; APT simulation"
    note: "Requires separate authorisation; longer planning phase"
```

### Step 3: Pre-Engagement Checklist

```markdown
## Pre-Engagement Checklist

### Legal and Authorisation
- [ ] Signed statement of work (SOW) from both parties.
- [ ] Written authorisation from system/data owner (not just security team).
- [ ] NDA signed by testing firm covering report handling.
- [ ] Data processing addendum if tester may encounter PII.
- [ ] Emergency halt procedure tested (emergency contact can reach on-call in < 5 min).

### Technical Setup
- [ ] Test accounts provisioned (separate from production accounts; labelled "pentest-*").
- [ ] Test accounts added to monitoring/alerting allowlist (to suppress false-positive alerts
      during testing — but NOT to hide test activity; review logs post-test).
- [ ] IP addresses of testers provided; add to WAF monitoring (not bypassed).
- [ ] Staging environment available if tests require destructive activity.
- [ ] Backup of critical systems verified before test start.

### Internal Communication
- [ ] Engineering teams notified: "Pentest running from [date] to [date]; expected alerts."
- [ ] SOC/SIEM team notified: monitor for actual incidents vs. test activity.
- [ ] On-call rotation briefed: escalation path during test.

### Scope Confirmation
- [ ] Scope document signed by authorised executive (CISO or above).
- [ ] Out-of-scope explicitly documented and communicated to testers.
- [ ] Rules of engagement confirmed in writing.
```

### Step 4: Findings Classification and Management

```yaml
# findings-severity.yaml — severity classification framework.
severity_levels:
  critical:
    description: "Exploitation achieves immediate, significant impact without authentication"
    examples:
      - "Unauthenticated RCE on production server"
      - "SQL injection bypassing authentication on login endpoint"
      - "AWS key exposed; provides cloud admin access"
    remediation_sla_days: 7
    owner: "Engineering VP + security team"

  high:
    description: "Exploitation achieves significant impact with low-privilege authentication"
    examples:
      - "IDOR allowing any user to access any other user's data"
      - "Privilege escalation from user to admin within application"
      - "XXE allowing internal network SSRF"
    remediation_sla_days: 30
    owner: "Product engineering team lead"

  medium:
    description: "Exploitation requires specific conditions or provides partial impact"
    examples:
      - "CSRF on non-sensitive action"
      - "Reflected XSS requiring victim interaction"
      - "Information disclosure of non-sensitive data"
    remediation_sla_days: 90
    owner: "Assigned developer"

  low:
    description: "Minimal direct impact; defence-in-depth improvement"
    examples:
      - "Missing security headers"
      - "Verbose error messages"
      - "Non-sensitive information disclosure"
    remediation_sla_days: 180
    owner: "Team backlog"

  informational:
    description: "Best practice recommendation; no direct vulnerability"
    remediation_sla_days: null  # No mandatory SLA; tracked as improvement.
    owner: "Engineering backlog"
```

### Step 5: Finding Handoff Workflow

Do not wait for the final report to start remediation:

```markdown
## Finding Handoff Process

### During the Engagement
1. **Critical findings**: Notify immediately via phone/Signal to security lead.
   - Do not email critical findings before encryption is confirmed.
   - Assign a remediation owner before the call ends.
   - Log the finding and owner in the tracking system within 2 hours.

2. **High findings**: Notify within 24 hours via encrypted channel.
   - Assign to an engineering team owner with SLA date.

3. **Daily debrief call**: Tester presents findings from the previous day.
   - Security lead assigns preliminary severity and owner.
   - Engineering manager confirms owner is appropriate and has capacity.

### After the Engagement
4. **Draft report review** (within 5 business days of test end):
   - Security team reviews for accuracy and severity calibration.
   - Flag false positives with evidence.
   - Confirm every finding has an assigned owner and SLA.

5. **Findings entered into tracking system** before final report is accepted:
   - One ticket per finding.
   - Severity, owner, SLA, and remediation steps from the report.
   - Link to relevant section of the report.

6. **Final report accepted** only after tickets are created.
```

### Step 6: Remediation Verification (Retest)

```yaml
# Include retest scope in the original SOW.
retest:
  timing: "45-60 days after final report delivery"
  scope: "All Critical and High findings; sample of Medium findings"
  process:
    - "Engineering provides changelog of fixes applied."
    - "Tester retests original finding with original technique."
    - "If remediated: finding closed in tracking system."
    - "If not remediated or partially remediated: finding remains open with updated notes."
    - "New findings discovered during retest: out of scope for this engagement;
       log for next test cycle."
  deliverable: "Retest letter: list of retested findings with pass/fail status."
```

### Step 7: Year-over-Year Metrics

```python
# pentest_metrics.py — track programme improvement.
from dataclasses import dataclass
from typing import List

@dataclass
class PentestEngagement:
    year: int
    quarter: str
    findings_critical: int
    findings_high: int
    findings_medium: int
    findings_low: int
    remediated_within_sla_critical_pct: float
    remediated_within_sla_high_pct: float
    mean_days_to_remediate_critical: float
    repeat_findings: int   # Same finding as previous test.

def calculate_programme_health(engagements: List[PentestEngagement]) -> dict:
    if len(engagements) < 2:
        return {"status": "insufficient_history"}
    
    current = engagements[-1]
    previous = engagements[-2]
    
    return {
        "critical_finding_trend": current.findings_critical - previous.findings_critical,
        "repeat_finding_rate": current.repeat_findings / max(previous.findings_critical + previous.findings_high, 1),
        "sla_compliance_critical": current.remediated_within_sla_critical_pct,
        "programme_health": "improving" if (
            current.findings_critical <= previous.findings_critical
            and current.repeat_findings == 0
            and current.remediated_within_sla_critical_pct >= 90
        ) else "needs_attention"
    }
```

### Step 8: Telemetry

```
pentest_findings_total{severity, engagement_year}              gauge
pentest_findings_remediated_pct{severity, engagement_year}     gauge
pentest_repeat_findings_total{severity}                        counter
pentest_sla_compliance_pct{severity}                           gauge
pentest_mean_days_to_remediate{severity}                       gauge
pentest_findings_open_overdue_total{severity}                  gauge
```

Alert on:

- `pentest_findings_open_overdue_total{severity="critical"}` > 0 — a critical pentest finding is past SLA without remediation or formal exception.
- `pentest_repeat_findings_total` non-zero — the same vulnerability appeared in consecutive tests; remediation was ineffective or incomplete.
- Report not delivered within 10 business days of test end — engagement SLA breach.
- No retest scheduled 30 days after final report — retest will be missed.

## Expected Behaviour

| Signal | Ad-hoc pentest | Structured programme |
|--------|---------------|---------------------|
| Critical finding discovered | Emailed in final report 2 weeks later | Immediate verbal notification; owner assigned same day |
| Finding remediation | "Remediated" when developer closes ticket | Verified by retest; not closed until tester confirms |
| Year-over-year comparison | Not tracked | Metrics show critical count trending down; repeat findings approaching zero |
| Out-of-scope accident | Not defined; discovered post-test | Rules of engagement prevent; emergency halt process defined |
| Report distribution | Emailed unencrypted | Encrypted delivery; access restricted to named individuals |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Grey-box vs black-box | Grey-box covers more attack surface in same time | Tester has internal context; less realistic as external attack simulation | Run both annually; external black-box for realism, grey-box for coverage |
| Retest inclusion in SOW | Confirms fixes are actually effective | Additional cost (typically 1-2 days of tester time) | Required for Critical and High; optional for Medium |
| Year-over-year metrics | Demonstrates programme improvement | Requires consistent scope and methodology across engagements | Use the same firm or methodology for longitudinal comparison |
| Immediate critical notification | Faster remediation; less exposure window | Disrupts engineering teams during test | Pre-notify engineering leads; establish clear escalation path |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Test disrupts production | Service degradation during test hours | Monitoring alert; user reports | Emergency halt procedure; tester stops immediately; root cause analysis |
| Tester credentials not revoked | Working test credentials in production post-engagement | Credential audit after test | Immediately revoke all test accounts; rotate any shared credentials |
| Report intercepted | Unencrypted report email intercepted | Typically detected too late | Enforce PGP or portal-based report delivery; never email unencrypted |
| Findings not entered in tracking | Report delivered; no tickets; findings forgotten | Findings absent from vulnerability management system | Contract requires tracking system entries before report acceptance |

## Related Articles

- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
- [Security Chaos Engineering](/articles/observability/security-chaos-engineering/)
- [Tabletop Exercises](/articles/cross-cutting/tabletop-exercises/)
- [Continuous Red Teaming](/articles/ai-landscape/continuous-red-teaming/)
- [AI-Powered Security Assessments](/articles/ai-landscape/ai-powered-security-assessments/)
