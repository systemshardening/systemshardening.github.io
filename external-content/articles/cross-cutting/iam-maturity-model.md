---
title: "IAM Maturity Model: Assessing and Advancing Identity and Access Management Capabilities"
description: "Most organisations have ad-hoc IAM — permissions granted manually, never reviewed, and accumulated over years. A structured IAM maturity model provides a roadmap from reactive, manual IAM to automated, continuously verified least-privilege. This guide covers the five maturity levels, assessment methodology, and a prioritised improvement roadmap."
slug: iam-maturity-model
date: 2026-05-07
lastmod: 2026-05-07
category: cross-cutting
tags:
  - iam
  - maturity-model
  - access-management
  - least-privilege
  - identity-governance
personas:
  - security-engineer
  - security-analyst
article_number: 619
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/cross-cutting/iam-maturity-model/
---

# IAM Maturity Model: Assessing and Advancing Identity and Access Management Capabilities

## Problem

Most organisations cannot answer three questions that every security programme should be able to answer: Who has access to what? Is that access still appropriate? How quickly can you remove it?

The inability to answer these questions has a root cause: Identity and Access Management grew organically. An engineer needed database access, so access was granted. A contractor joined, so an account was created. A project ended, but the account and its permissions remained. Over years, the access inventory accumulates — permissions layered on permissions, accounts attached to employees who left two years ago, service accounts with production write access that haven't been used in eight months.

The pattern is not a technology failure. It is a process failure. Organisations without a structured IAM practice converge on the same state: access is granted reactively, rarely reviewed, and almost never removed. The aggregate effect is a sprawling, unmapped entitlement surface that attackers are adept at exploiting. Lateral movement, privilege escalation, and persistent access after initial compromise all rely on this surface.

A maturity model addresses this by providing a structured vocabulary for where an organisation is today, where it needs to be, and what the ordered sequence of improvements looks like. The goal is not to reach Level 5 in every dimension simultaneously — that is neither realistic nor necessary. The goal is to eliminate the highest-risk gaps first, in the right order.

**Target systems:** Organisations running any mix of on-premises systems, cloud infrastructure, and SaaS applications. The model applies regardless of organisation size, though the tooling choices differ.

## Threat Model

- **Adversary 1 — Credential theft exploiting over-privileged accounts.** An attacker who compromises a developer's credentials inherits every entitlement that account accumulated over three years. Without least-privilege enforcement, initial compromise becomes full domain compromise.
- **Adversary 2 — Orphaned accounts used for persistent access.** An attacker who identifies a dormant account from a former employee or contractor can use it for months without triggering alerts, because nobody is looking for activity on accounts that should be inactive.
- **Adversary 3 — Insider threat via excessive standing access.** A malicious or compromised insider can exfiltrate data from every system they have access to. Without need-to-know enforcement, the blast radius is bounded only by historical accident.
- **Adversary 4 — Machine identity abuse.** Service accounts and API keys with overly broad permissions are a reliable pivot point. Compromising a CI/CD pipeline service account with write access to production is equivalent to compromising production directly.

## The Five IAM Maturity Levels

```yaml
# iam-maturity-levels.yaml
levels:
  1:
    name: "Initial"
    description: "Ad-hoc, manual, no defined process."
    characteristics:
      - "Access granted by informal request — email, Slack message, ticket."
      - "No centralised identity directory or authoritative source of truth."
      - "Shared credentials and service accounts with no individual accountability."
      - "No access review process; access accumulates indefinitely."
      - "Offboarding is manual, inconsistent, and frequently incomplete."
      - "No MFA enforcement; password policies are advisory."
      - "Privileged access indistinguishable from standard access."
    risk_profile: "Critical. Full account compromise = full blast radius."

  2:
    name: "Developing"
    description: "Documented process, inconsistently applied."
    characteristics:
      - "Central directory exists (Active Directory or IdP), but not all systems are integrated."
      - "MFA enforced for some systems (VPN, email) but not all."
      - "Annual access reviews exist in policy but completion rate is low."
      - "Offboarding process documented; execution still manual and error-prone."
      - "Privileged accounts are separated from standard accounts in theory."
      - "Some SSO adoption; islands of local accounts remain."
      - "No visibility into service account permissions or usage."
    risk_profile: "High. Significant gaps in coverage; orphaned accounts common."

  3:
    name: "Defined"
    description: "Consistent process, some automation."
    characteristics:
      - "Single IdP is the authoritative source for all user identities."
      - "MFA enforced universally via conditional access policies."
      - "SSO covers all critical systems; local accounts inventoried and minimised."
      - "Quarterly access reviews with tracked completion rate (>80%)."
      - "Offboarding automated for account disablement within 24 hours."
      - "Privileged Access Management (PAM) tool deployed for admin credentials."
      - "RBAC model documented; roles aligned to job functions."
      - "Service accounts inventoried with documented owners and purposes."
    risk_profile: "Moderate. Consistent controls reduce opportunistic exploitation."

  4:
    name: "Managed"
    description: "Metrics-driven, automated enforcement."
    characteristics:
      - "Just-in-time (JIT) access replaces standing privilege for all admin functions."
      - "Access reviews automated via IGA platform; completion rate >95%."
      - "Offboarding SLA enforced: account disabled within 4 hours, access revoked within 24 hours."
      - "Entitlement analytics identify unused and excessive permissions continuously."
      - "Machine identities managed with short-lived credentials (SPIFFE/SPIRE or equivalent)."
      - "IAM metrics reviewed monthly; trends drive remediation priorities."
      - "HR system integration drives joiner/mover/leaver lifecycle automatically."
      - "Anomalous access patterns detected and alerted within hours."
    risk_profile: "Low. Automated controls close gaps before they become exploitable."

  5:
    name: "Optimising"
    description: "Continuous improvement, predictive, zero-standing-privilege."
    characteristics:
      - "Zero-standing-privilege for all privileged access — all access is JIT and time-bounded."
      - "Machine learning models predict access risk and surface outliers proactively."
      - "Access request and approval fully automated for routine entitlements."
      - "Entitlement drift detected in real time; automatic remediation for defined violations."
      - "IAM posture is a measurable, improving metric reported to leadership."
      - "Red team exercises specifically test IAM controls; findings drive improvements."
      - "Workload identity replaces API keys and shared secrets entirely."
      - "Fine-grained authorisation (ABAC/ReBAC) replaces coarse RBAC where appropriate."
    risk_profile: "Minimal. Credential compromise does not translate to meaningful access."
```

## Assessment Methodology: Scoring Six Dimensions

Assess IAM maturity across six dimensions independently. Each dimension can be at a different maturity level — most organisations are at Level 3 in authentication and Level 1 in machine identity. The assessment produces a dimension-level heat map, not a single number.

```yaml
# iam-assessment-dimensions.yaml

dimensions:
  authentication_strength:
    description: "How users and machines prove their identity."
    scoring_criteria:
      level_1: "Passwords only. No MFA. Shared accounts."
      level_2: "MFA for some systems (VPN, email). Password policies inconsistently enforced."
      level_3: "MFA enforced universally via conditional access. Phishing-resistant MFA (FIDO2/WebAuthn) on admin accounts."
      level_4: "Phishing-resistant MFA everywhere. Passwordless for supported systems. Continuous authentication signals."
      level_5: "Risk-adaptive authentication. Biometric + hardware key. Step-up auth based on resource sensitivity."
    questions:
      - "What percentage of user accounts require MFA for all access?"
      - "Is phishing-resistant MFA (hardware keys, passkeys) deployed for privileged users?"
      - "Are there any accounts with password-only authentication to production systems?"
      - "How are machine-to-machine authentication credentials issued and rotated?"

  authorisation_model:
    description: "How access decisions are made and enforced."
    scoring_criteria:
      level_1: "Ad-hoc permissions. No model. Access granted by request."
      level_2: "RBAC exists in policy but roles are inconsistently defined and overlapping."
      level_3: "RBAC fully implemented. Roles aligned to job functions. No direct permission assignments."
      level_4: "ABAC/PBAC supplements RBAC for sensitive resources. Policy-as-code enforced in CI."
      level_5: "Fine-grained ReBAC for complex resource hierarchies. Authorisation logic centralised and independently testable."
    questions:
      - "Is access granted via roles, or directly to individuals?"
      - "How many distinct roles exist? Are they based on job function?"
      - "Are there users with permissions that no defined role grants (direct permission assignments)?"
      - "Is authorisation policy version-controlled and reviewed before deployment?"

  identity_lifecycle:
    description: "How identities are created, maintained, and removed."
    scoring_criteria:
      level_1: "Manual, inconsistent. No offboarding process. Orphaned accounts accumulate."
      level_2: "Onboarding process exists. Offboarding manual, frequently incomplete."
      level_3: "HR system triggers provisioning and deprovisioning. SLA defined for offboarding."
      level_4: "Full JML automation. Mover events trigger access review, not just add. SLA enforced with alerting."
      level_5: "Access adjusts automatically with role changes. No manual intervention for standard lifecycle events."
    questions:
      - "How long after an employee's last day are their accounts disabled?"
      - "Is your HR system connected to your IdP for automated provisioning?"
      - "When an employee changes roles, is their previous access automatically reviewed?"
      - "How many accounts exist for users who are no longer active?"

  privileged_access_management:
    description: "How administrative and high-privilege access is controlled."
    scoring_criteria:
      level_1: "No separation. Admin credentials shared. No audit log."
      level_2: "Separate admin accounts exist. Some credential vaulting. Minimal audit."
      level_3: "PAM tool deployed. Admin credentials vaulted and rotated. Session recording for privileged access."
      level_4: "JIT privileged access for all admin functions. Approval workflow enforced. Standing privilege eliminated for most roles."
      level_5: "Zero-standing-privilege. All admin access is ephemeral. Full session recording with anomaly detection."
    questions:
      - "Can any administrator access production systems without approval?"
      - "Are admin credentials rotated after each use?"
      - "Is privileged session activity recorded and retained?"
      - "How many accounts have persistent administrative access to production?"

  monitoring_and_audit:
    description: "How IAM events are observed and investigated."
    scoring_criteria:
      level_1: "No centralised IAM logging. Authentication events not collected."
      level_2: "Auth logs collected centrally but not analysed. Alerts rare."
      level_3: "Authentication and authorisation events sent to SIEM. Alerts on known-bad patterns."
      level_4: "Baseline behaviour modelled. Anomalous access patterns alerted. IAM events correlated with HR events."
      level_5: "ML-based anomaly detection. Access patterns inform risk scoring. Predictive alerting on privilege misuse."
    questions:
      - "Are all authentication events (success and failure) captured centrally?"
      - "Is there alerting on authentication from unexpected geographies or devices?"
      - "Are access review decisions and changes logged immutably?"
      - "How quickly can you reconstruct what a specific user accessed in the past 90 days?"

  machine_identity:
    description: "How non-human identities are managed."
    scoring_criteria:
      level_1: "Long-lived API keys and shared credentials. No rotation. No inventory."
      level_2: "API keys inventoried. Some secrets management tooling. Manual rotation."
      level_3: "Secrets manager deployed (Vault, AWS Secrets Manager). Automated rotation for most secrets."
      level_4: "Short-lived credentials via OIDC or SPIFFE. No long-lived API keys for workloads."
      level_5: "All workload credentials are ephemeral. Identity tied to verified workload attestation."
    questions:
      - "How many long-lived API keys exist with no expiry?"
      - "Are service account credentials rotated automatically?"
      - "Can you identify every service account and its owner?"
      - "Do CI/CD pipelines authenticate to cloud platforms using OIDC federation (not stored keys)?"
```

### Running the Assessment

Score each dimension on a 1–5 scale using the criteria above. Combine evidence from three sources:

1. **Technical inventory** — Pull actual data: count of accounts without MFA, list of service accounts with last-used dates, PAM tool coverage percentage, offboarding ticket closure times.
2. **Process documentation review** — Assess whether documented processes match reality; a policy that says "quarterly access review" is Level 2, not Level 3, if completion rate is 30%.
3. **Interviews with owners** — Identity team, HR/IT, platform team, and a sample of application owners. Discrepancies between what documentation says and what owners describe reveal the real maturity level.

Document findings per dimension with evidence:

```markdown
## Assessment Results — [Organisation] — [Date]

| Dimension                  | Current Level | Target Level | Evidence Summary                             |
|----------------------------|:-------------:|:------------:|----------------------------------------------|
| Authentication Strength    | 3             | 4            | MFA universal, but FIDO2 only on 40% of admins |
| Authorisation Model        | 2             | 3            | RBAC defined but direct assignments common   |
| Identity Lifecycle         | 2             | 4            | Offboarding manual; avg 72h to disable        |
| Privileged Access Mgmt     | 2             | 4            | PAM tool licensed but not fully deployed     |
| Monitoring and Audit       | 3             | 4            | Auth logs in SIEM; no baseline modelling     |
| Machine Identity           | 1             | 3            | Long-lived keys; no inventory                |
```

## Dimension-by-Dimension Gap Analysis

A heat map is only useful if it drives action. For each dimension below Level 3, document the specific gap:

```yaml
# gap-analysis.yaml — example for a Level 2 organisation

gaps:
  machine_identity:
    current_level: 1
    target_level: 3
    gap_description: >
      No inventory of service accounts or API keys. Keys are long-lived and
      embedded in CI/CD configuration. No secrets manager deployed.
    evidence:
      - "207 API keys found across GitHub Actions, terraform state, and application config"
      - "Oldest key created 4 years ago, last rotated: never"
      - "No secrets manager deployed; Vault evaluated but not implemented"
    risk: >
      Any repository compromise or CI/CD breach exposes long-lived credentials
      with production access. No ability to detect or respond to key misuse.

  identity_lifecycle:
    current_level: 2
    target_level: 4
    gap_description: >
      Offboarding relies on a manual ticket process. IT and HR operate on
      different systems with no integration. Review of departure tickets
      found 12% completed after the employee's last day; 6% never completed.
    evidence:
      - "HR system has no API integration with Active Directory"
      - "Departure tickets reviewed: median closure time 4.2 days after last day"
      - "23 accounts found active for users who left in the past 12 months"
    risk: >
      Former employees retain access to critical systems. Insider threat
      and credential-based attack surface includes ex-employees.

  privileged_access_management:
    current_level: 2
    target_level: 4
    gap_description: >
      PAM tool (CyberArk) is deployed but covers only 30% of privileged accounts.
      Network devices, cloud consoles, and developer tools are excluded.
      No JIT access implemented; all admin access is standing.
    evidence:
      - "CyberArk manages 47 accounts; AD privileged group has 156 members"
      - "AWS console root credentials not in vault; MFA device held by one person"
      - "No approval workflow for elevated access"
    risk: >
      Standing administrative access means any compromised admin account
      provides immediate, persistent access to production systems.
```

## Prioritised Improvement Roadmap

The order of improvements is as important as the improvements themselves. Two principles govern prioritisation:

**Authentication before authorisation.** It is not useful to build a precise RBAC model if credentials can be phished. Enforce phishing-resistant MFA universally before investing in fine-grained access controls.

**Privileged access before general access.** The blast radius of a compromised admin account is orders of magnitude larger than a standard user account. JIT for admin access delivers more risk reduction than quarterly access reviews for general users.

```yaml
# improvement-roadmap.yaml — prioritised by risk reduction per effort

phases:
  phase_1:
    name: "Eliminate Critical Gaps (Months 1-3)"
    goal: "No critical-risk IAM gaps in any dimension."
    initiatives:
      - name: "Universal MFA enforcement"
        dimension: "authentication_strength"
        action: "Enable conditional access policy blocking all authentication without MFA. No exceptions."
        effort: "Low-Medium (policy change + user communications)"
        risk_reduction: "High — eliminates credential-phishing attack path"

      - name: "Machine identity inventory"
        dimension: "machine_identity"
        action: "Enumerate all service accounts and API keys. Document owner, purpose, and last-used date."
        effort: "Medium (scripted discovery across systems)"
        risk_reduction: "High — prerequisite for all subsequent machine identity improvements"

      - name: "Offboarding SLA enforcement"
        dimension: "identity_lifecycle"
        action: "Define and enforce 4-hour SLA for account disablement. Alert when SLA is breached."
        effort: "Low (process change + monitoring)"
        risk_reduction: "High — closes orphaned account attack path"

  phase_2:
    name: "Automate Core Lifecycle (Months 3-9)"
    goal: "Reach Level 3 in all dimensions. No manual processes for standard lifecycle events."
    initiatives:
      - name: "HR-to-IdP integration for JML automation"
        dimension: "identity_lifecycle"
        action: >
          Connect HR system to IdP via SCIM provisioning. Automate account creation on hire,
          access adjustment on role change, and account disablement on departure.
        effort: "High (integration project)"
        risk_reduction: "High — eliminates orphaned account accumulation"

      - name: "PAM tool full deployment"
        dimension: "privileged_access_management"
        action: >
          Extend PAM coverage to all privileged accounts: network devices, cloud consoles,
          database administrators, DevOps tooling. Enforce credential vaulting and session recording.
        effort: "High (deployment project)"
        risk_reduction: "High — eliminates unvaulted admin credentials"

      - name: "Secrets manager for machine credentials"
        dimension: "machine_identity"
        action: >
          Deploy HashiCorp Vault or cloud-native secrets manager. Migrate long-lived API keys
          to dynamic, short-lived credentials. Start with highest-privilege service accounts.
        effort: "High (infrastructure + application changes)"
        risk_reduction: "High — eliminates long-lived credential exposure risk"

      - name: "RBAC model definition and cleanup"
        dimension: "authorisation_model"
        action: >
          Define role-to-job-function mapping. Remove direct permission assignments.
          Assign all users to defined roles. Document exceptions with owner and review date.
        effort: "Medium-High (access model design + cleanup)"
        risk_reduction: "Medium — reduces entitlement sprawl and simplifies access review"

  phase_3:
    name: "JIT and Continuous Verification (Months 9-18)"
    goal: "Reach Level 4. Automate access reviews. Replace standing privilege with JIT."
    initiatives:
      - name: "Just-in-time privileged access"
        dimension: "privileged_access_management"
        action: >
          Implement JIT access request and approval for all admin functions. Remove standing
          membership from privileged groups. Use PIM (Azure AD PIM, AWS IAM Identity Center)
          or PAM tool's JIT capability.
        effort: "High (process redesign + tool configuration)"
        risk_reduction: "Very High — standing privilege is the primary admin compromise path"

      - name: "IGA platform for automated access reviews"
        dimension: "identity_lifecycle"
        action: >
          Deploy IGA platform (SailPoint, Saviynt, or open-source alternative).
          Connect to authoritative data sources. Automate access certification campaigns.
        effort: "Very High (major project)"
        risk_reduction: "High — continuous access hygiene at scale"

      - name: "OIDC federation for CI/CD and cloud workloads"
        dimension: "machine_identity"
        action: >
          Replace long-lived cloud API keys in CI/CD with OIDC federation.
          GitHub Actions, GitLab CI, and most CI systems support this natively.
          Eliminate all cloud provider credentials stored in CI/CD systems.
        effort: "Medium (per-pipeline configuration)"
        risk_reduction: "High — eliminates highest-value credential theft target"
```

## Automating Access Reviews with IGA

Manually reviewing who has access to what does not scale. An organisation with 500 employees, 80 applications, and quarterly review cycles needs managers to certify thousands of entitlements — most of whom lack the context to make accurate decisions. The result is rubber-stamping. Access reviews become compliance theatre rather than genuine hygiene.

Identity Governance and Administration (IGA) platforms exist to solve this. They pull entitlement data from all connected systems, correlate it against the HR system and role model, surface outliers (access that doesn't match job function, access not used in 90 days), and route certifications to the right decision-makers.

```yaml
# iga-platform-comparison.yaml

platforms:
  sailpoint:
    type: "Commercial"
    strengths:
      - "Deep integration library (thousands of connectors)"
      - "AI-based access recommendations"
      - "Strong lifecycle management (joiner/mover/leaver)"
      - "Well-supported in regulated industries (finance, healthcare)"
    considerations:
      - "Significant implementation and licensing cost"
      - "Complex to deploy; typically requires professional services"
    best_for: "Large enterprises with complex hybrid environments"

  saviynt:
    type: "Commercial (cloud-native)"
    strengths:
      - "Cloud-native architecture; SaaS delivery"
      - "Strong cloud IAM integration (AWS, Azure, GCP)"
      - "Application access governance"
      - "Built-in compliance frameworks"
    considerations:
      - "Higher cost for full feature set"
      - "Less mature than SailPoint for on-premises systems"
    best_for: "Cloud-first organisations with SaaS-heavy environments"

  microsoft_entra_id_governance:
    type: "Commercial (platform-native)"
    strengths:
      - "Native integration with Microsoft ecosystem"
      - "Entitlement management, access reviews, lifecycle workflows"
      - "Lower incremental cost for Microsoft-heavy shops"
    considerations:
      - "Limited coverage for non-Microsoft systems"
      - "Access reviews less sophisticated than dedicated IGA"
    best_for: "Microsoft-centric organisations already paying for E5 licensing"

  midpoint:
    type: "Open Source (Evolveum)"
    strengths:
      - "Full-featured IGA; production deployments in large organisations"
      - "No per-user licensing cost"
      - "Active community and commercial support available"
      - "Flexible connector framework"
    considerations:
      - "Significant implementation effort"
      - "UI less polished than commercial alternatives"
      - "Requires in-house expertise or consulting"
    best_for: "Organisations with strong internal engineering capability and cost constraints"
```

### Connecting IGA to HR Systems

The authoritative source for whether an account should exist is the HR system, not the identity directory. An IGA deployment without HR integration is a significant gap — it can manage access reviews, but it cannot detect that an account belongs to someone who left the company last month.

```python
# hr-iga-sync-example.py
# Example: polling HR system and triggering IGA lifecycle events
# Adapt to your HR system API (Workday, BambooHR, ADP, etc.)

import requests
import json
from datetime import datetime, timedelta

HR_API_BASE = "https://hr.internal/api/v1"
IGA_API_BASE = "https://iga.internal/api/v1"

def get_recent_hr_events(since_hours: int = 24) -> list[dict]:
    """Fetch employee status changes from HR system."""
    since = (datetime.utcnow() - timedelta(hours=since_hours)).isoformat()
    response = requests.get(
        f"{HR_API_BASE}/employees/events",
        params={"since": since, "types": "hire,termination,role_change"},
        headers={"Authorization": f"Bearer {get_hr_token()}"},
    )
    response.raise_for_status()
    return response.json()["events"]

def process_termination(employee: dict) -> None:
    """Trigger immediate account disablement and access review."""
    payload = {
        "userId": employee["email"],
        "event": "leaver",
        "effectiveDate": employee["termination_date"],
        "priority": "immediate",  # triggers <4h SLA
    }
    response = requests.post(
        f"{IGA_API_BASE}/lifecycle/events",
        json=payload,
        headers={"Authorization": f"Bearer {get_iga_token()}"},
    )
    response.raise_for_status()
    print(f"[LEAVER] Triggered deprovisioning for {employee['email']}")

def process_role_change(employee: dict) -> None:
    """Trigger access review on mover events — don't just add, also review existing."""
    payload = {
        "userId": employee["email"],
        "event": "mover",
        "previousRole": employee["previous_role"],
        "newRole": employee["new_role"],
        "reviewScope": "all_existing_access",  # critical: don't just add new access
    }
    response = requests.post(
        f"{IGA_API_BASE}/lifecycle/events",
        json=payload,
        headers={"Authorization": f"Bearer {get_iga_token()}"},
    )
    response.raise_for_status()
    print(f"[MOVER] Triggered access review for {employee['email']}")

def sync_hr_events() -> None:
    events = get_recent_hr_events(since_hours=24)
    for event in events:
        if event["type"] == "termination":
            process_termination(event["employee"])
        elif event["type"] == "role_change":
            process_role_change(event["employee"])
        elif event["type"] == "hire":
            # hire events trigger provisioning; handled by IGA role assignment
            pass
```

## Moving from Standing to Just-in-Time Access

The jump from Level 3 to Level 4 is the most significant maturity advance in IAM. At Level 3, administrators have standing membership in privileged groups — they can access production systems at any time without approval. At Level 4, no such standing access exists. Every privileged action requires an explicit, time-bounded access grant.

This is not a minor process improvement. It fundamentally changes the risk profile: an attacker who compromises an admin's credentials during a period when that admin has no active JIT grant cannot use those credentials to access anything privileged. The window of exploitability shrinks from "forever" to "the duration of the active session."

```bash
# jit-access-example.sh
# Using Azure AD Privileged Identity Management (PIM) as an example
# Equivalent capability exists in AWS IAM Identity Center, CyberArk, BeyondTrust

# Request temporary elevation to Global Admin (requires approval)
az rest --method POST \
  --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests" \
  --body '{
    "action": "selfActivate",
    "principalId": "user-object-id",
    "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
    "directoryScopeId": "/",
    "justification": "Incident response: investigating auth failure in prod",
    "scheduleInfo": {
      "startDateTime": null,
      "expiration": {
        "type": "AfterDuration",
        "duration": "PT4H"
      }
    }
  }'

# Access is granted for 4 hours only, with justification logged
# After 4 hours: access automatically revoked with no action required
# Audit log captures: who requested, justification, approver, duration, all actions taken
```

```yaml
# jit-access-policy.yaml — configuration for JIT access governance

jit_policy:
  privileged_roles:
    - role: "Production Database Administrator"
      max_duration: "PT4H"       # 4 hours maximum
      approval_required: true
      approvers: ["security-team", "engineering-lead"]
      justification_required: true
      session_recording: true

    - role: "Cloud Infrastructure Admin"
      max_duration: "PT8H"       # 8 hours for extended maintenance
      approval_required: true
      approvers: ["security-team"]
      justification_required: true
      mfa_required: true         # step-up MFA even if session is already authenticated
      session_recording: true

    - role: "Security Incident Responder"
      max_duration: "PT24H"      # longer window for active incident response
      approval_required: false   # break-glass: auto-approved, but heavily logged
      justification_required: true
      alert_on_activation: true  # immediately notify security team

  standing_access_elimination:
    deadline: "2026-09-01"
    exceptions_process: "Exceptions documented in risk register, reviewed quarterly"
    exceptions_current: 0        # target: zero standing privilege
```

## IAM Metrics

Tracking IAM maturity requires metrics that reflect outcomes, not activity. "Access reviews completed" is an activity metric. "Percentage of accounts with unused access for >90 days" is an outcome metric — it reflects whether access hygiene is improving.

```yaml
# iam-metrics.yaml — core IAM KPIs with collection method and targets

metrics:
  accounts_with_excessive_privilege:
    description: "% of user accounts with entitlements beyond job function baseline"
    calculation: "accounts_exceeding_role_baseline / total_active_accounts * 100"
    collection: "IGA platform or entitlement analytics tool (e.g., Varonis, Authomize)"
    frequency: "Monthly"
    target: "<5%"
    alert_threshold: ">15%"
    maturity_level_indicator:
      level_2: "Not measured"
      level_3: "Measured; >25%"
      level_4: "Measured; <10%"
      level_5: "Measured; <2%; auto-remediated"

  unused_access_percentage:
    description: "% of entitlements not exercised in the past 90 days"
    calculation: "entitlements_unused_90d / total_entitlements * 100"
    collection: "Auth logs correlated with entitlement inventory"
    frequency: "Monthly"
    target: "<10%"
    alert_threshold: ">30%"
    rationale: >
      Unused access is a reliable proxy for privilege creep. It identifies
      entitlements that could be removed to reduce attack surface with no
      operational impact.

  access_review_completion_rate:
    description: "% of access certification decisions completed within SLA"
    calculation: "certifications_completed_on_time / certifications_assigned * 100"
    collection: "IGA platform reporting"
    frequency: "Per review cycle"
    target: ">95%"
    alert_threshold: "<80%"
    note: >
      Completion rate alone is insufficient. Also track certification quality:
      what % of decisions were auto-approved by a manager without review?
      High completion + high auto-approval = compliance theatre.

  mean_time_to_deprovision:
    description: "Median time from offboarding event to full account disablement"
    calculation: "median(account_disabled_timestamp - termination_effective_timestamp)"
    collection: "HR system events joined with IdP account state changes"
    frequency: "Monthly"
    target: "<4 hours"
    alert_threshold: ">24 hours"
    maturity_level_indicator:
      level_1: "Not measured; days to weeks"
      level_2: "Days; manual process"
      level_3: "<24 hours; partially automated"
      level_4: "<4 hours; automated with SLA enforcement"
      level_5: "<1 hour; real-time HR integration"

  privileged_access_without_jit:
    description: "% of privileged role memberships that are standing (not JIT)"
    calculation: "standing_privileged_members / total_privileged_role_members * 100"
    collection: "PAM tool + IdP privileged group inventory"
    frequency: "Weekly"
    target: "0%"
    alert_threshold: ">0%"
    note: "Any non-zero value is an exception that should be documented and justified."

  service_accounts_with_longlivedkeys:
    description: "% of service accounts using credentials older than 90 days"
    calculation: "service_accounts_key_age_gt_90d / total_service_accounts * 100"
    collection: "Cloud IAM APIs, secrets manager metadata"
    frequency: "Weekly"
    target: "0%"
    alert_threshold: ">5%"
```

## Cloud IAM Maturity vs. Enterprise IAM Maturity

Cloud IAM and enterprise IAM have different failure modes, different tooling, and often different teams. A mature enterprise IAM programme does not automatically translate to mature cloud IAM.

Enterprise IAM matures around a central directory (Active Directory, Okta), an IdP, and applications that integrate via SAML/OIDC. The failure mode is accumulated entitlements, orphaned accounts, and manual processes at scale.

Cloud IAM (AWS IAM, Azure RBAC, GCP IAM) matures around policy-as-code, infrastructure-as-code, and the principle that IAM policies are code artifacts subject to the same review and enforcement as application code. The failure mode is over-permissive policies deployed at infrastructure provisioning time and never tightened.

```yaml
# cloud-iam-maturity.yaml

cloud_iam_levels:
  level_1:
    name: "Ad-hoc Cloud IAM"
    characteristics:
      - "IAM policies created manually in cloud console."
      - "Admin users with '*:*' policies are common."
      - "No infrastructure as code; IAM state is console-only."
      - "No policy review process."

  level_2:
    name: "Basic Cloud IAM Controls"
    characteristics:
      - "IAM policies in Terraform or CloudFormation."
      - "Manual review of significant policy changes."
      - "Root/admin accounts have MFA; access keys still used."
      - "No automated scanning of IAM policies."

  level_3:
    name: "Policy-as-Code with Guardrails"
    characteristics:
      - "All IAM resources managed as code; no console exceptions."
      - "IAM policy analysis in CI pipeline (checkov, tf-iam-auditor)."
      - "Service Control Policies (AWS) or Azure Policy enforce boundaries."
      - "No IAM access keys for EC2/Lambda; instance profiles used."
      - "CloudTrail/CloudWatch for IAM event monitoring."

  level_4:
    name: "Automated Continuous Compliance"
    characteristics:
      - "CIEM tool (Cloud Infrastructure Entitlement Management) continuously analyses effective permissions."
      - "Unused permissions auto-remediated or flagged for removal."
      - "OIDC federation for all CI/CD; no stored cloud credentials."
      - "Cross-account access via IAM roles, not shared credentials."
      - "Automated detection and alerting on overly permissive policies."

  level_5:
    name: "Least-Privilege Enforced at Provisioning"
    characteristics:
      - "IAM policies generated from observed usage (AWS IAM Access Analyzer)."
      - "Policies automatically tightened after deployment to match actual usage."
      - "Zero access keys in any environment; all identity is instance/workload-native."
      - "Continuous permission boundary enforcement."
      - "IAM posture score tracked across accounts; declining scores auto-alert."
```

```bash
# ciem-quick-wins.sh
# Cloud IAM quick wins before a CIEM tool is deployed

# AWS: Find IAM users with access keys (should be minimal/zero in modern deployments)
aws iam generate-credential-report && \
  aws iam get-credential-report --query 'Content' --output text | \
  base64 -d | \
  awk -F',' 'NR>1 && $9=="true" {print $1, "has active access key 1"}'

# AWS: Find policies with admin-equivalent permissions
aws iam list-policies --scope Local --query 'Policies[*].Arn' --output text | \
  xargs -I{} aws iam get-policy-version \
    --policy-arn {} \
    --version-id $(aws iam get-policy --policy-arn {} --query 'Policy.DefaultVersionId' --output text) \
    --query "PolicyVersion.Document.Statement[?Effect=='Allow' && contains(Action, '*')]"

# GCP: Find service accounts with project-level editor or owner bindings
gcloud projects get-iam-policy YOUR_PROJECT \
  --flatten="bindings[].members" \
  --format="table(bindings.role,bindings.members)" \
  --filter="bindings.role:roles/editor OR bindings.role:roles/owner"

# Azure: Find role assignments with Owner or Contributor at subscription scope
az role assignment list \
  --scope "/subscriptions/YOUR_SUBSCRIPTION_ID" \
  --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor'].{Principal:principalName,Role:roleDefinitionName}" \
  --output table
```

## Verifying Improvements

At each maturity level, validate that improvements have genuinely reduced risk rather than just changed process documentation.

```bash
# iam-verification.sh — spot checks for each phase

# Phase 1 verification: MFA enforcement is real
# Check: Can any user authenticate without MFA?
# Test: Attempt authentication with password only (should fail at conditional access)

# Phase 2 verification: Offboarding automation works
# Test: Use a test account in HR system; confirm IdP account disabled within SLA
# Check timing from HR event to IdP disable:
python3 - <<'EOF'
import boto3
import json

# Pull CloudTrail events for a test user deprovisioning
client = boto3.client('cloudtrail')
response = client.lookup_events(
    LookupAttributes=[
        {'AttributeKey': 'Username', 'AttributeValue': 'test-leaver@example.com'}
    ]
)
for event in response['Events']:
    print(event['EventTime'], event['EventName'])
EOF

# Phase 3 verification: JIT access cannot be bypassed
# Check: Are any users still in privileged groups without active PIM/JIT assignments?
# AWS: Check if any IAM users have direct admin policies vs role assumption
aws iam get-account-authorization-details \
  --filter User \
  --query 'UserDetailList[?AttachedManagedPolicies[?PolicyName==`AdministratorAccess`]].{User:UserName}'

# Phase 3 verification: No long-lived credentials in CI/CD
# GitHub: check if any repository secrets are cloud provider credentials
# (automated via GitHub secret scanning or Trufflehog in CI)
trufflehog github --org YOUR_ORG \
  --token $GITHUB_TOKEN \
  --only-verified \
  --json | \
  jq 'select(.DetectorName | test("AWS|Azure|GCP"))'
```

## Common Implementation Mistakes

**Stopping at access review completion without measuring quality.** A 95% completion rate means nothing if managers approve all requests without review. Measure certification decision time — reviews completed in under 10 seconds per entitlement are likely not being genuinely reviewed.

**Implementing JIT for administrators but not for cloud console access.** Many organisations roll out JIT for Active Directory privileged groups but leave AWS console access via permanent IAM roles. The cloud surface needs the same treatment.

**Confusing authentication maturity with IAM maturity.** Deploying FIDO2 hardware keys is an authentication improvement. It does not address excessive entitlements, orphaned accounts, or service account sprawl. These require separate tracks.

**Treating IGA as a compliance tool rather than a security tool.** IGA platforms are frequently deployed to satisfy audit requirements for annual access certification. The actual value — continuous entitlement analytics, automated remediation, and lifecycle automation — is unrealised because the organisation only uses the certification module.

**Not including machine identities in the scope.** The most common IAM maturity assessments focus exclusively on human users. Service accounts, API keys, and workload identities are frequently more numerous, more over-privileged, and harder to review than human accounts. Include them from the start.

## Summary

IAM maturity follows a predictable progression: from manual and reactive (Level 1) to automated, metrics-driven, and continuously verified (Level 4–5). The assessment methodology produces a dimension-level picture, not a single score, because different dimensions advance at different rates and have different risk profiles.

The prioritisation order matters: close authentication gaps before building authorisation sophistication, and address privileged access before general access. The most impactful single improvement most Level 2–3 organisations can make is implementing JIT for all administrative access — it converts the question "was this admin account compromised?" from a catastrophe into a recoverable incident.

Measure what changes. Track unused access percentage, mean time to deprovision, and accounts with excessive privilege monthly. If those numbers are not improving, the programme is producing activity rather than outcomes.
