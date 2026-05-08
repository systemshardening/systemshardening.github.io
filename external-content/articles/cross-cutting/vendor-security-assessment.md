---
title: "Third-Party Vendor Security Assessment: Questionnaires, Monitoring, and SLAs"
description: "Third-party vendors extend your attack surface without extending your control. A structured assessment program — questionnaires, continuous monitoring, contractual SLAs, and offboarding procedures — limits the blast radius of vendor compromise."
slug: "vendor-security-assessment"
date: 2026-04-30
lastmod: 2026-04-30
category: "cross-cutting"
tags: ["vendor-management", "third-party-risk", "supply-chain", "questionnaire", "sla"]
personas: ["security-engineer", "ciso", "platform-engineer"]
article_number: 277
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/cross-cutting/vendor-security-assessment/index.html"
---

# Third-Party Vendor Security Assessment: Questionnaires, Monitoring, and SLAs

## Problem

Third-party vendors — SaaS applications, managed service providers, open-source dependencies, cloud services — are operationally necessary and security liabilities simultaneously. They access your systems, hold your data, and often have broader permissions than the specific integration requires. When a vendor is compromised, your data moves with it.

The pattern of third-party breaches is consistent: a vendor has access to customer environments as part of their service; the vendor is compromised through their own software supply chain, a phishing attack on an employee, or an unpatched vulnerability; the attacker pivots from the vendor's systems into customer environments using the legitimately provisioned access.

Organisations typically respond to this by assessing vendors at contract time (once) and then doing nothing until renewal. The vendor's security posture at the time of onboarding is not the vendor's security posture eighteen months later. Continuous monitoring does not mean continuous questionnaires — it means automated signals that detect meaningful changes without manual overhead.

Common failures in vendor security programs:

- **Questionnaires without verification.** Vendors self-report security controls; no evidence is requested. A vendor can claim SOC 2 Type II compliance without having completed the audit.
- **No access inventory.** Nobody knows which vendors have access to what. When a vendor is compromised, security cannot determine blast radius because no inventory exists.
- **No offboarding process.** Vendor access is provisioned when the relationship starts and forgotten. Terminated vendor relationships retain active API keys, OAuth grants, and SSO access.
- **SLAs that don't include security.** Contracts specify uptime and support response times but not breach notification timelines, maximum permitted data retention, or acceptable-use restrictions on customer data.
- **Monitoring limited to questionnaire cycle.** The vendor is assessed at contract signature and at renewal — a gap of twelve to thirty-six months during which posture changes go undetected.

**Target systems:** Vendor management programs for SaaS, managed services, professional services, and open-source dependencies. Applicable to organisations with 10+ vendors in scope.

## Threat Model

- **Adversary 1 — Vendor supply chain compromise:** An attacker compromises a vendor's software build pipeline (as in SolarWinds) and distributes malicious updates to all customers. The update runs in the customer environment with the permissions of the vendor's agent.
- **Adversary 2 — Vendor credential compromise:** An attacker phishes a vendor employee who has access to the customer environment. The attacker uses the vendor's provisioned credentials to access customer data directly.
- **Adversary 3 — Vendor insider threat:** A vendor employee with access to customer data exfiltrates it deliberately. Without audit logging on vendor access, the exfiltration may not be detected.
- **Adversary 4 — Abandoned vendor access:** A vendor relationship ends; nobody removes the API key or OAuth grant. An attacker who subsequently compromises the vendor's systems discovers active customer credentials in the vendor's database.
- **Adversary 5 — Misconfigured data sharing:** A vendor shares customer data with a sub-processor not disclosed in the vendor's data processing addendum. The sub-processor is compromised; the customer has no knowledge the sub-processor held their data.
- **Access level:** Adversaries 1 and 2 need to compromise the vendor first; Adversary 3 is an insider; Adversary 4 exploits abandoned credentials; Adversary 5 exploits contractual gaps.
- **Objective:** Access customer data or systems using the trust relationship established by the vendor integration.
- **Blast radius:** Depends on vendor access scope. A vendor with read access to all customer data can exfiltrate everything. A vendor with write access to production infrastructure can deploy malicious code.

## Configuration

### Step 1: Vendor Inventory and Classification

No assessment program works without knowing which vendors exist and what they access. Build and maintain an inventory:

```yaml
# vendor-inventory.yaml — stored in a private repo or GRC system.
vendors:
  - name: "DataDog"
    category: "observability"
    criticality: "high"          # Loss would significantly impact operations.
    data_access:
      - type: "infrastructure_metrics"
      - type: "application_logs"
      - type: "traces"
    pii_access: false
    production_access: true
    access_mechanism: "agent_installed_on_hosts"
    access_credentials:
      - type: "api_key"
        location: "vault:secret/vendors/datadog/api-key"
        last_rotated: "2026-01-15"
    contract_expiry: "2027-03-31"
    assessment_due: "2026-10-01"    # 6 months before renewal.
    assessment_last_completed: "2025-10-01"
    soc2_report_expiry: "2026-06-30"
    contacts:
      security: "security@datadog.com"
      account: "account-manager@datadog.com"

  - name: "AcmePII Processor"
    category: "data_processor"
    criticality: "critical"
    data_access:
      - type: "customer_pii"
      - type: "payment_data"
    pii_access: true
    production_access: false
    access_mechanism: "sftp_data_export"
    dpa_signed: true
    subprocessors_disclosed: true
    subprocessor_list_url: "https://acme.example/subprocessors"
    contract_expiry: "2026-12-31"
    assessment_due: "2026-06-30"
```

Criticality classification:

| Level | Criteria | Assessment Frequency |
|-------|----------|---------------------|
| Critical | PII/payment data; production write access; single-point-of-failure | Annual + continuous monitoring |
| High | Production read access; significant data access; business-critical | Annual |
| Medium | Non-production access; aggregate/anonymised data | Every 2 years |
| Low | No data access; no system access; commodity services | At onboarding only |

### Step 2: Security Questionnaire Template

Use a tiered questionnaire. Critical and high vendors complete the full questionnaire; medium vendors complete a shortened version.

```markdown
# Vendor Security Questionnaire — Full (Critical/High Tier)

## Section 1: Security Programme

1.1  Does your organisation have a documented information security policy? 
     [ ] Yes — please attach or provide a URL
     [ ] No

1.2  Do you have a dedicated security function (CISO, security team, or equivalent)?
     [ ] Yes — describe size and reporting structure
     [ ] No — describe how security decisions are made

1.3  Do you maintain a risk register and conduct formal risk assessments?
     [ ] Yes — frequency: ________
     [ ] No

## Section 2: Compliance and Certification

2.1  Current certifications (attach most recent reports):
     [ ] SOC 2 Type II — expiry: ________ — scope: ________
     [ ] ISO 27001 — expiry: ________ — certification body: ________
     [ ] PCI DSS — level: ________ — last QSA assessment: ________
     [ ] None

2.2  Have you had a third-party penetration test in the last 12 months?
     [ ] Yes — scope: ________ — conducted by: ________ — critical findings remediated: Y/N
     [ ] No — reason: ________

2.3  Do you have a vulnerability disclosure / bug bounty program?
     [ ] Yes — URL: ________
     [ ] No

## Section 3: Access Control

3.1  Do you enforce MFA for all employee access to systems that hold customer data?
     [ ] Yes — mechanisms: ________
     [ ] Partial — describe exceptions: ________
     [ ] No

3.2  Do you use privileged access management (PAM) for production access?
     [ ] Yes — product: ________
     [ ] No

3.3  How is access to customer data restricted to need-to-know?
     Free text: ________

3.4  How frequently are access rights reviewed?
     [ ] Monthly  [ ] Quarterly  [ ] Annually  [ ] Not reviewed

## Section 4: Data Handling

4.1  Where is customer data stored (regions/countries)?
     ________

4.2  Do you use sub-processors to process customer data?
     [ ] Yes — list: ________ (or provide URL to sub-processor list)
     [ ] No

4.3  How is customer data encrypted at rest?
     [ ] AES-256 or equivalent — key management: ________
     [ ] Encrypted — algorithm/mechanism: ________
     [ ] Not encrypted — reason: ________

4.4  How is customer data encrypted in transit?
     [ ] TLS 1.2+ enforced — minimum version: ________
     [ ] Other: ________

4.5  What is your data retention period for customer data after contract termination?
     ________

4.6  How is customer data deleted/destroyed at termination?
     ________

## Section 5: Incident Response

5.1  Do you have a documented incident response plan?
     [ ] Yes — last tested: ________
     [ ] No

5.2  What is your committed notification timeline for security incidents affecting customer data?
     [ ] < 24 hours  [ ] < 48 hours  [ ] < 72 hours  [ ] No commitment

5.3  Describe your most recent security incident (if any) and how it was handled:
     Free text: ________

## Section 6: Software Development Security

6.1  Do you perform SAST/DAST scanning on code changes?
     [ ] Yes — tools: ________  [ ] No

6.2  Do you have a software supply chain security program (SBOM, dependency scanning)?
     [ ] Yes — describe: ________  [ ] No

6.3  How are security patches applied to production systems?
     Mean time to patch critical vulnerabilities: ________
```

### Step 3: Evidence Collection and Verification

Questionnaire responses must be verified against evidence. Self-assertion without evidence is meaningless:

```python
# vendor_assessment/evidence_tracker.py

EVIDENCE_REQUIREMENTS = {
    "soc2_type2": {
        "description": "SOC 2 Type II report from licensed CPA firm",
        "acceptance_criteria": [
            "Report dated within 12 months",
            "Opinion is unqualified (not qualified/adverse/disclaimer)",
            "Scope includes services provided to us",
            "User entity controls reviewed"
        ],
        "reject_if": [
            "SOC 2 Type I (point-in-time, not period)",
            "Expired (>12 months old)",
            "Scope gap: services we use not covered"
        ]
    },
    "pentest_report": {
        "description": "Executive summary from third-party penetration test",
        "acceptance_criteria": [
            "Conducted within 12 months",
            "Conducted by named third party (not internal team)",
            "Scope covers production environment",
            "Critical/high findings have remediation status"
        ],
        "reject_if": [
            "Internal red team only",
            "Scope limited to non-production",
            "Critical findings open with no remediation plan"
        ]
    },
    "mfa_enforcement": {
        "description": "Screenshot or configuration export of IdP MFA policy",
        "acceptance_criteria": [
            "MFA required for all users, or documented exceptions",
            "Phishing-resistant MFA (FIDO2/WebAuthn) for privileged access"
        ]
    }
}
```

### Step 4: Contractual Security Requirements

Security requirements must be in the contract, not the questionnaire. Questionnaire responses are pre-sales commitments; contracts are enforceable:

```markdown
# Security Addendum Template

## 4. Security Requirements

### 4.1 Data Protection
Vendor shall:
a) Encrypt all Customer Data at rest using AES-256 or equivalent.
b) Encrypt all Customer Data in transit using TLS 1.2 or higher.
c) Not process Customer Data in countries outside the approved list in Schedule A.

### 4.2 Access Control
Vendor shall:
a) Enforce multi-factor authentication for all personnel with access to Customer Data.
b) Restrict access to Customer Data to personnel with documented need-to-know.
c) Complete access reviews no less than quarterly.
d) Remove access for terminated personnel within 24 hours of termination.

### 4.3 Vulnerability Management
Vendor shall:
a) Remediate critical vulnerabilities in systems holding Customer Data within 14 days 
   of discovery.
b) Remediate high vulnerabilities within 30 days.
c) Conduct annual third-party penetration testing of systems holding Customer Data.
d) Provide Customer with executive summary of penetration test results upon request.

### 4.4 Incident Notification
Vendor shall:
a) Notify Customer of any confirmed or suspected security incident affecting Customer Data 
   within 24 hours of discovery via security@[customer].com.
b) Notification shall include: nature of incident, data potentially affected, containment 
   steps taken, and contact information for Vendor's incident commander.
c) Vendor shall provide a written incident report within 72 hours.

### 4.5 Audit Rights
Customer shall have the right to:
a) Request Vendor's current SOC 2 Type II report annually.
b) Request completion of Customer's security questionnaire annually.
c) Conduct security assessments of Vendor's environment with 30 days notice, 
   limited to systems processing Customer Data.

### 4.6 Termination and Data Deletion
Upon contract termination:
a) Vendor shall delete all Customer Data within 30 days.
b) Vendor shall provide written certification of deletion within 45 days.
c) Customer retains the right to request an export of all Customer Data 
   before deletion.

### 4.7 Sub-processors
Vendor shall:
a) Maintain a publicly accessible list of sub-processors used to process Customer Data.
b) Notify Customer at least 30 days before adding a new sub-processor.
c) Customer has the right to object to new sub-processors within 15 days of notification.
d) Vendor remains liable for sub-processor compliance with this addendum.
```

### Step 5: Continuous Monitoring — Automated Signals

Don't rely on the next questionnaire cycle to detect vendor posture changes. Use automated signals:

```python
# vendor_monitoring/monitor.py
import requests
from datetime import datetime, timedelta

VENDOR_CHECKS = {
    "soc2_expiry": {
        "check": "report_expiry_date < today + 90_days",
        "alert": "Vendor SOC 2 report expires within 90 days — request renewal"
    },
    "breach_news": {
        "check": "vendor_name in breach_news_feeds",
        "sources": [
            "https://haveibeenpwned.com/api/v3/breaches",  # Check for known breaches.
            "https://feeds.feedburner.com/TheHackersNews",
        ]
    },
    "certificate_expiry": {
        "check": "vendor_tls_cert_expiry < today + 30_days",
        "description": "Vendor's TLS certificate expiring; may cause service disruption"
    },
    "api_key_age": {
        "check": "credential_last_rotated > 365_days",
        "alert": "Vendor API key not rotated in over a year — initiate rotation"
    }
}

def check_security_scorecard(vendor_domain: str) -> dict:
    """Query SecurityScorecard or similar for continuous security rating."""
    # SecurityScorecard API, BitSight, or similar services provide
    # automated scoring based on public signals (DNS config, open ports,
    # credential leaks, patch cadence from CVE data).
    response = requests.get(
        f"https://api.securityscorecard.io/companies/{vendor_domain}",
        headers={"Token": SCORECARD_API_KEY}
    )
    return response.json()

def check_vendor_breach_notifications(vendor_name: str) -> list:
    """Check Have I Been Pwned and breach aggregators for vendor mentions."""
    # In practice: subscribe to FS-ISAC, breach notification services,
    # and set up Google Alerts for "[vendor_name] breach" and
    # "[vendor_name] security incident".
    pass
```

Key continuous monitoring signals:

| Signal | Source | Action Threshold |
|--------|--------|-----------------|
| Security rating drop | SecurityScorecard / BitSight | Drop > 10 points → initiate review |
| Public breach disclosure | FS-ISAC, HIBP, news | Any mention → immediate contact |
| SOC 2 expiry | Internal inventory | 90 days before expiry → request renewal |
| Certificate expiry | Certificate Transparency logs | 30 days → notify vendor |
| Credential age | Vault / secret manager | > 365 days → initiate rotation |
| Sub-processor list change | Vendor change notification | New sub-processor → review and approve/object |

### Step 6: Access Inventory and Offboarding

Maintain an inventory of all active vendor access, and offboard automatically:

```bash
#!/bin/bash
# vendor_offboard.sh — run when a vendor relationship ends.
VENDOR=$1

echo "=== Offboarding vendor: $VENDOR ==="

# 1. Revoke API keys.
echo "Revoking API keys..."
aws iam list-access-keys --user-name "vendor-${VENDOR}" \
  | jq -r '.AccessKeyMetadata[].AccessKeyId' \
  | xargs -I{} aws iam delete-access-key --user-name "vendor-${VENDOR}" --access-key-id {}

# 2. Revoke OAuth grants.
echo "Revoking OAuth grants..."
# List and revoke via identity provider API (Okta, Auth0, etc.)
# okta-cli app list --query "label eq \"${VENDOR}\"" | xargs okta-cli app deactivate

# 3. Remove from internal groups/roles.
echo "Removing from groups..."
# kubectl delete clusterrolebinding vendor-${VENDOR} --ignore-not-found

# 4. Rotate any shared secrets the vendor had access to.
echo "Rotating shared secrets..."
# vault write -f secret/vendors/${VENDOR}/rotate

# 5. Log offboarding to audit trail.
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) vendor=${VENDOR} action=offboard operator=${USER}" \
  >> /var/log/vendor-offboard.log

echo "=== Offboarding complete. Verify: ==="
echo "  - Data deletion request sent to vendor? [manual]"
echo "  - DNS/firewall rules for vendor IPs removed? [manual]"
echo "  - Verify deletion certificate received within 45 days [calendar reminder]"
```

### Step 7: Assessment Workflow Automation

Automate assessment scheduling to prevent gaps:

```python
# vendor_assessment/scheduler.py

def get_vendors_requiring_assessment(days_ahead: int = 60) -> list:
    """Return vendors whose assessments are due within the specified window."""
    today = datetime.now().date()
    deadline = today + timedelta(days=days_ahead)
    
    due = []
    for vendor in load_vendor_inventory():
        if vendor.assessment_due <= deadline:
            due.append({
                "name": vendor.name,
                "criticality": vendor.criticality,
                "due_date": vendor.assessment_due,
                "last_completed": vendor.assessment_last_completed,
                "contact": vendor.contacts["security"],
                "days_remaining": (vendor.assessment_due - today).days
            })
    
    return sorted(due, key=lambda v: v["days_remaining"])

def send_assessment_requests(vendors: list):
    """Send questionnaire requests to vendor security contacts."""
    for vendor in vendors:
        send_email(
            to=vendor["contact"],
            subject=f"Annual Security Assessment Request — {vendor['name']}",
            body=QUESTIONNAIRE_EMAIL_TEMPLATE.format(
                vendor_name=vendor["name"],
                due_date=vendor["due_date"],
                questionnaire_url=f"https://grc.internal/vendor/{vendor['name']}/questionnaire"
            )
        )
```

### Step 8: Telemetry

```
vendor_assessment_overdue_total{vendor, criticality}           gauge
vendor_soc2_expiry_days{vendor}                                gauge
vendor_security_score{vendor, provider}                        gauge
vendor_credential_age_days{vendor, credential_type}            gauge
vendor_access_accounts_total{vendor}                           gauge
vendor_offboarding_pending_days{vendor}                        gauge
vendor_incident_notifications_total{vendor}                    counter
```

Alert on:

- `vendor_assessment_overdue_total` non-zero — a vendor assessment has passed its due date without completion; no current security posture data.
- `vendor_soc2_expiry_days` < 30 — the vendor's SOC 2 report is about to expire; request the renewal report immediately.
- `vendor_security_score` drops > 10 points — significant deterioration in vendor's externally-observable security posture.
- `vendor_credential_age_days` > 365 — vendor credentials have not been rotated in over a year.
- `vendor_offboarding_pending_days` > 30 — an offboarded vendor has not yet provided data deletion confirmation.

## Expected Behaviour

| Signal | Ad-hoc vendor management | Structured assessment program |
|--------|--------------------------|-------------------------------|
| Vendor breach discovered | Unknown access scope; manual scramble | Inventory gives immediate blast radius; offboard procedure starts |
| Vendor access after contract end | API keys persist indefinitely | Offboarding procedure revokes all access at termination |
| SOC 2 expiry | Discovered at renewal | Alert at 90 days; request before expiry |
| Sub-processor data exposure | Unknown; not disclosed | Sub-processor list in contract; change notification required |
| Vendor questionnaire verification | Self-reported; unverified | Evidence checklist; SOC 2 opinion reviewed by security team |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Full questionnaire for all vendors | Comprehensive coverage | High vendor burden; completion rates drop | Tier vendors; full questionnaire for critical/high only |
| Contractual security SLAs | Enforceable obligations | Legal negotiation adds time; vendors push back | Standard addendum reduces negotiation; treat pushback as signal |
| Continuous monitoring services | Automated signals without manual overhead | Cost (SecurityScorecard/BitSight are paid services) | Use HIBP + Google Alerts + internal SOC 2 tracking as a free baseline |
| Access inventory maintenance | Enables offboarding; enables blast radius assessment | Inventory goes stale if not process-driven | Provision vendor access through a service account system that enforces inventory entries |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Vendor not in inventory | Breach notification arrives; no idea what data they held | Periodic IAM / OAuth grant audit discovers unknown vendor | Add vendor; assess retroactively; review contract; check breach scope |
| Assessment questionnaire not returned | Assessment cycle passes; no updated posture data | Overdue assessment alert | Follow up; if critical vendor non-responsive, escalate to contract terms (cooperation clause); consider offboarding |
| SOC 2 report scoped incorrectly | Report covers different services than those used | Evidence review step catches scope gap | Request supplemental controls documentation; if unresolvable, treat as unverified |
| Offboarding incomplete | Former vendor's API key still active months later | Credential age alert; periodic IAM audit | Revoke immediately; audit for access since termination; notify if data was accessed |
| Sub-processor disclosure gap | Customer data held by unlisted sub-processor | Breach at sub-processor reveals relationship | Invoke contract breach clause; demand sub-processor list; consider termination |
| Incident notification not received | Customer learns of vendor breach from news, not vendor | External breach notification sources | Invoke contract penalty clause; request post-incident report; reassess vendor |

## Related Articles

- [Cloud Security Posture Management](/articles/cross-cutting/cloud-security-posture-management/)
- [Sigstore Keyless Signing](/articles/cicd/sigstore-keyless-signing/)
- [Security Metrics Program](/articles/cross-cutting/security-metrics-program/)
- [Secrets Rotation Orchestration](/articles/cross-cutting/secrets-rotation-orchestration/)
- [GitHub Advanced Security: Secret Scanning, Code Scanning, and Dependabot](/articles/cicd/github-advanced-security/)
