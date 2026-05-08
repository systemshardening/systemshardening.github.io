---
title: "DORA Technical Implementation: ICT Risk Management, Resilience Testing, and Third-Party Oversight"
description: "The EU Digital Operational Resilience Act (DORA) is in force from January 2025 for banks, insurers, investment firms, and their critical ICT providers. DORA mandates specific technical capabilities: ICT risk management frameworks, incident classification and reporting, TLPT penetration testing, and contractual controls on ICT third-party providers. This guide maps DORA Articles to concrete technical controls."
slug: dora-technical-implementation
date: 2026-05-07
lastmod: 2026-05-07
category: cross-cutting
tags:
  - dora
  - financial-resilience
  - ict-risk
  - regulatory-compliance
  - penetration-testing
personas:
  - security-engineer
  - compliance-engineer
article_number: 631
difficulty: Intermediate
estimated_reading_time: 14
published: true
layout: article.njk
permalink: /articles/cross-cutting/dora-technical-implementation/
---

# DORA Technical Implementation: ICT Risk Management, Resilience Testing, and Third-Party Oversight

## Problem

The EU Digital Operational Resilience Act (Regulation 2022/2554) became applicable on 17 January 2025. Unlike the NIS2 Directive, which relies on transposition into member-state law and leaves significant discretion on technical specifics, DORA is directly applicable EU law with prescriptive technical requirements that leave little room for interpretation. Non-compliance exposes entities to supervisory sanctions up to 2% of total annual worldwide turnover; critical ICT third-party providers (CTPPs) face fines of up to 1% of average daily global turnover for each day of non-compliance.

**Scope.** DORA applies to a broad set of financial entities defined in Article 2:

- Credit institutions (banks)
- Payment institutions and e-money institutions
- Investment firms and crypto-asset service providers (CASPs)
- Insurance and reinsurance undertakings
- Central counterparties (CCPs) and central securities depositories (CSDs)
- Trade repositories, management companies, and alternative investment fund managers
- Data reporting service providers and credit rating agencies
- Crowdfunding service providers and securitisation repositories

Micro-enterprises (fewer than 10 staff, annual turnover under EUR 2 million) benefit from a proportionality principle — they are exempted from the most burdensome requirements including TLPT — but are not exempted from ICT risk management obligations entirely. The proportionality principle (Article 4) applies across all entity types: a small insurance firm has fewer obligations than a systemically important bank, but both must have documented ICT risk management frameworks.

ICT third-party service providers are not themselves "financial entities" under DORA, but those designated as **critical third-party providers (CTPPs)** by the Joint Supervisory Committee of the European Supervisory Authorities (EBA, ESMA, EIOPA) are subject to direct oversight under Articles 31-44. Cloud infrastructure providers, core banking platform vendors, and market data aggregators are the most likely candidates for CTPP designation.

**How DORA differs from NIS2.** NIS2 (Directive 2022/2555) covers a wide set of "essential and important entities" across sectors including energy, transport, health, and digital infrastructure. Financial entities are in scope for NIS2 but DORA acts as a lex specialis — Article 1 of DORA explicitly states that it takes precedence over NIS2 for financial entities on matters it covers. The key differences:

- NIS2 requires "appropriate and proportionate" security measures (Article 21) without specifying what they are. DORA Article 9 lists specific ICT security policies required by name.
- NIS2 incident reporting to national CSIRTs uses a 24-hour initial notification. DORA requires initial notification to the competent financial supervisor within 4 hours of classifying an incident as major using a defined multi-criteria test.
- NIS2 does not mandate penetration testing methodology. DORA Article 26 mandates Threat-Led Penetration Testing (TLPT) using the TIBER-EU methodology for significant entities.
- NIS2 third-party risk provisions are general (Article 21(2)(d)). DORA dedicates Articles 28-44 to ICT third-party risk with mandatory contract clauses listed explicitly in Article 30.

**TIBER-EU and TLPT.** TIBER-EU (Threat Intelligence-Based Ethical Red Teaming) was developed by the ECB in 2018 as a voluntary framework for testing the resilience of financial market infrastructure. DORA Article 26 mandates TLPT that follows the TIBER-EU methodology (or equivalent national frameworks) for in-scope entities. The practical difference: TIBER-EU was advisory; DORA makes it obligatory and enforceable. The competent authority must receive test results and can require remediation.

**Technical implementation gap.** Most financial entities entering 2025 had some form of ISO 27001-based ISMS or a governance framework referencing NIST CSF. These frameworks helped with general risk management but did not satisfy DORA's prescriptive requirements. The gap is not conceptual — it is operational. Entities typically lack: (1) formal ICT asset registers linked to business functions; (2) automated incident classification pipelines that apply DORA's multi-criteria test; (3) documented TLPT evidence packages acceptable to supervisors; (4) ICT third-party registers with the contractual data points DORA Article 30 requires.

## Threat Model

Three scenarios drive DORA's technical requirements and explain why the regulation is structured as it is.

**Scenario 1: Ransomware causing critical ICT system outage with regulatory reporting obligation.** A threat actor with access to a bank's internal network deploys ransomware that encrypts core banking system hosts and their backup targets. The bank cannot process payments for 14 hours. Under DORA, the entity must determine within hours whether this constitutes a "major ICT-related incident" using the classification criteria in Article 18. If it does, the initial notification to the competent authority must occur within 4 hours of that classification. Banks that lack automated incident scoring against DORA criteria miss the reporting window, compounding the regulatory exposure. The threat model requires that incident detection, classification, and regulatory notification workflows be pre-built and tested, not constructed during the incident.

**Scenario 2: Third-party ICT provider outage affecting financial services availability.** A cloud provider hosting the payment processing tier of several EU banks experiences a regional availability zone failure lasting 9 hours. Affected banks cannot process card transactions during EU business hours. The root cause is outside the bank's perimeter, but DORA's operational resilience requirements do not accept "our provider was down" as a complete explanation. Under Article 28, financial entities must have exit strategies and continuity plans for critical ICT services. Under Article 30, contracts with critical ICT providers must include SLA terms, audit rights, and sub-contracting disclosure. Entities that signed standard cloud provider terms of service without DORA-specific contract amendments will face supervisory scrutiny.

**Scenario 3: Nation-state APT targeting financial market infrastructure.** A sophisticated threat actor conducts a multi-month intrusion against a central securities depository, exfiltrating market position data and mapping internal settlement workflows. The entity detects the intrusion during a TLPT exercise — the red team discovers indicators of compromise that predate the exercise. This scenario explains why DORA mandates TLPT with threat intelligence preparation: generic vulnerability scanning would not have detected the lateral movement pattern. The intelligence preparation phase of TLPT (the "targeted threat intelligence" component of TIBER-EU) requires engagement with sector-level threat intelligence, which surfaces nation-state TTPs targeting the specific entity type.

## Configuration / Implementation

### ICT Risk Management Framework (Articles 5-16)

DORA Articles 5-16 establish requirements for an ICT risk management framework that must be documented, approved by the management body, and reviewed at least annually (Article 6(5)).

**Asset inventory and dependency mapping (Article 8).** Article 8 requires financial entities to identify, classify, and document all ICT assets that support business functions. The minimum data points for each asset: asset identifier, asset type (hardware/software/data), business function supported, criticality classification, owner, location, and dependencies on other ICT assets.

```yaml
# ICT Asset Register schema (minimum DORA-compliant fields)
asset:
  id: "ICT-0042"
  name: "Core Banking System — Transaction Processing Module"
  type: software
  criticality: critical          # critical | important | standard
  business_function: "Payment processing — SEPA credit transfers"
  rto_hours: 4                   # Recovery Time Objective
  rpo_hours: 1                   # Recovery Point Objective
  owner: "Head of Core Banking Engineering"
  hosting: "on-premises"         # on-premises | cloud | hybrid
  cloud_provider: null
  dependencies:
    - asset_id: "ICT-0011"       # Database cluster
      dependency_type: runtime
    - asset_id: "ICT-0019"       # HSM for PIN processing
      dependency_type: runtime
    - asset_id: "ICT-0031"       # Network connectivity — interbank
      dependency_type: runtime
  ict_third_party_providers:
    - provider_id: "TPSP-0003"   # Links to ICT third-party register
  last_reviewed: "2025-03-15"
  dora_article_ref: "Art. 8"
```

The dependency graph is operationally important. DORA Article 8(1)(e) specifically requires mapping of "interdependencies between ICT assets." A flat asset list satisfies the letter but not the intent; the dependencies are what enable impact assessment when an asset fails or is compromised.

**ICT risk assessment (Article 9).** The risk assessment must identify threats to each critical ICT asset, assess likelihood and potential impact, and document risk acceptance decisions. Minimum required output: a risk register with threat/vulnerability pairs, inherent risk rating, control effectiveness, residual risk rating, and risk owner sign-off.

Operationally, this means connecting the asset register to the risk register: each critical or important ICT asset must appear in the risk register with at least one associated risk scenario. Generic risks ("cyberattack") are insufficient; DORA supervisors expect scenarios that map to the entity's specific threat profile (ransomware targeting core banking, insider threat accessing settlement data, cloud provider outage affecting custody services).

**Mandatory ICT security policies (Article 9(4)).** DORA Article 9(4) lists the specific ICT security policy areas that the framework must cover:

| Policy area | DORA reference | Minimum scope |
|---|---|---|
| Access control | Art. 9(4)(a) | Identity lifecycle, privilege management, MFA |
| Physical and environmental security | Art. 9(4)(b) | Data centre access, hardware disposal |
| Cryptography and encryption | Art. 9(4)(c) | Key management, in-transit and at-rest encryption |
| ICT project and change management | Art. 9(4)(d) | Change advisory process, rollback procedures |
| Operations security | Art. 9(4)(e) | Patch management, logging, capacity management |
| Network security | Art. 9(4)(f) | Segmentation, perimeter controls, monitoring |
| Data security | Art. 9(4)(g) | Data classification, handling, retention |
| Supplier relationships | Art. 9(4)(h) | Third-party risk process, contract requirements |
| Backup and recovery | Art. 9(4)(i) | Backup frequency, integrity testing, recovery procedures |
| Business continuity | Art. 9(4)(j) | BIA, continuity plans, crisis management |
| Incident management | Art. 9(4)(k) | Detection, classification, reporting, lessons learned |

Each policy must be approved by the management body. Most entities have policies covering these areas through their existing ISMS, but DORA requires specific attestation that each area is covered and the policy is current. A policy last reviewed in 2022 will not satisfy a supervisor who asks for evidence of annual review per Article 6(5).

**Business impact analysis and RTO/RPO (Article 11).** Article 11 requires financial entities to identify and document critical or important functions (a subset of all ICT-supported business functions) and to define Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO) for each. These targets must be achievable — the BIA must include evidence that recovery tests have been conducted and the targets were met.

The RTO/RPO values must connect to the asset register. If the core banking system has an RTO of 4 hours, every dependency with a longer individual recovery time represents a gap. The BIA exercise is therefore the mechanism by which the dependency graph becomes operationally meaningful.

### Incident Classification and Reporting (Articles 17-23)

**Major incident classification (Article 18).** DORA uses a multi-criteria approach for classifying ICT-related incidents as "major." An incident is major if it meets criteria across several dimensions. The EBA RTS on major incident classification (EBA/RTS/2023/02) operationalises these criteria:

```
DORA Major Incident Classification Decision Tree
─────────────────────────────────────────────────

START: ICT-related incident detected
    │
    ▼
Is the incident ongoing or resolved?
    │
    ├─ Resolved → assess impact criteria below
    └─ Ongoing → assess available impact data; reassess at 4h intervals
    │
    ▼
Apply multi-criteria test (ALL applicable criteria must be assessed):

[CRITERION 1] Clients and financial counterparts affected
    • Significant impact: ≥10% of total clients affected
      OR absolute threshold exceeded (varies by entity type)

[CRITERION 2] Transactions failed or delayed
    • Significant impact: ≥25% of daily transaction volume
      OR EUR threshold exceeded

[CRITERION 3] Duration
    • Significant impact: >4 hours for critical services
      OR >24 hours for other services

[CRITERION 4] Geographic spread
    • Significant impact: services affected in ≥2 EU member states

[CRITERION 5] Reputational impact
    • Media coverage of the incident
      OR regulatory or supervisory enquiries received

[CRITERION 6] Data losses
    • Personal data breach under GDPR with regulatory obligation
      OR confidential financial data exfiltrated

    │
    ▼
≥1 significant criterion met?
    │
    ├─ NO  → Classify as standard incident; follow internal process
    │
    └─ YES → Classify as MAJOR INCIDENT
               │
               ▼
         Start regulatory reporting timeline:
         T+0: Incident classified as major
         T+4h: Initial notification to competent authority
         T+72h: Intermediate report submitted
         T+1 month: Final report submitted
```

**Reporting workflow implementation.** The 4-hour initial notification window makes manual processes impractical. A functional DORA incident reporting pipeline requires:

1. **SIEM rule set for DORA criteria.** Each classification criterion should have a corresponding SIEM alert or dashboard. When a payment processing outage occurs, the SIEM should automatically calculate: percentage of total clients affected (from active session counts), transaction failure rate against the prior 30-day daily average, and duration counter. This does not make the classification decision automatically — a human must sign off — but it provides the data before the 4-hour window closes.

2. **Incident management platform workflow.** The regulatory reporting workflow should be a first-class workflow in the incident management platform (PagerDuty, Opsgenie, ServiceNow). When an incident is upgraded to "DORA Major" severity, the workflow automatically: notifies the Chief Information Security Officer and Chief Risk Officer, opens a regulatory reporting task with a 4-hour countdown, generates a pre-populated initial notification template, and schedules the 72-hour and 1-month report reminders.

3. **Notification template (initial report).** The EBA ITS on reporting formats specifies the data points for the initial notification: entity identification, date and time of classification, classification criteria met, description of the incident, affected services, estimated number of clients affected, and initial assessment of cause. Most entities use a structured JSON submission to the competent authority's reporting portal (the ECB's IMAS portal for significant institutions; national competent authority portals for less significant institutions).

### Digital Operational Resilience Testing (Articles 24-27)

**Basic testing (Article 25 — all entities).** All financial entities in scope must conduct basic digital operational resilience testing. The minimum test types are:

- Vulnerability assessments and scans (quarterly for critical systems)
- Network security assessments
- Gap analyses against ICT security policies
- Source code reviews for internally developed applications
- Scenario-based testing (tabletop exercises for ICT incidents)
- Compatibility testing for ICT changes

These are threshold requirements, not exhaustive. Many entities already conduct these activities under their existing security programme; the DORA obligation is to document them, retain evidence, and link findings to a remediation tracker.

**TLPT — Threat-Led Penetration Testing (Article 26 — significant entities).** TLPT is the DORA requirement with the highest operational complexity. The TIBER-EU framework defines three phases:

**Phase 1: Scoping and preparation.**
- The financial entity and its competent authority agree on the TLPT scope. The scope must include critical or important functions as defined in the entity's BIA and must cover systems that support those functions end-to-end.
- The entity engages a **Threat Intelligence (TI) provider** who produces a Targeted Threat Intelligence (TTI) report. The TTI report identifies the threat actors most likely to target this specific entity (based on sector, geography, and publicly known threat intelligence), their known TTPs, and the systems most likely to be targeted.
- The entity engages a **Red Team (RT) provider** who receives the TTI report and uses it to design a realistic attack scenario.

**TLPT engagement scope template:**

```
TLPT SCOPE DEFINITION DOCUMENT
Entity: [Name of financial entity]
Competent Authority: [ECB / National CA]
TLPT Reference: [CA-assigned reference number]
Test Period: [Planned start date] — [Planned end date]

1. CRITICAL FUNCTIONS IN SCOPE
   Function 1: SEPA credit transfer processing
     Supporting systems: [list ICT asset IDs]
     ICT third-party providers involved: [list TPSP IDs]
     Environments in scope: production (required), pre-production

   Function 2: Client authentication and access (online banking)
     Supporting systems: [list ICT asset IDs]
     ICT third-party providers involved: [list TPSP IDs]

2. OUT-OF-SCOPE EXCLUSIONS (must be justified and CA-approved)
   - [List any systems explicitly excluded and rationale]

3. ICT THIRD-PARTY PROVIDERS PARTICIPATION
   Provider: [Cloud provider name]
   Role in test: Target environment hosting; provider has been notified per Art. 26(7)
   Coordination contact: [Name, role, contact]

4. RED TEAM CONSTRAINTS
   - No deployment of destructive payloads in production
   - Exfiltration of real customer data prohibited; synthetic data substitution required
   - Out-of-hours attacks: permitted / not permitted [select]
   - Physical social engineering: in scope / out of scope [select]

5. EVIDENCE REQUIREMENTS
   - Red team activity logs (full TTPs documented)
   - TI provider TTI report
   - Remediation tracker linked to test findings
   - Attestation letter for competent authority submission
```

**Phase 2: Red team execution.** The red team conducts a covert operation against the scoped systems using the TTPs identified in the TTI report. TIBER-EU distinguishes this from conventional penetration testing in two ways: (1) the test is against production or a production-equivalent environment, not a test environment; (2) only a small "white team" at the entity knows the test is in progress — the blue team, SOC, and incident response teams are tested without prior knowledge.

**Phase 3: Closure and remediation.** After the red team concludes, a closure meeting ("purple team session") brings the red and blue teams together to review each finding. Every finding must be entered into a remediation tracker with an owner, target remediation date, and status. The entity submits an attestation letter to the competent authority confirming the test was conducted per the TIBER-EU framework and that a remediation plan exists.

**TLPT frequency and pooled testing.** DORA Article 26(1) requires TLPT at least every 3 years. Article 26(5) permits pooled testing where ICT third-party providers participate in a single test covering multiple financial entities — reducing cost and avoiding duplicative red team engagements against the same cloud provider infrastructure.

### ICT Third-Party Risk Management (Articles 28-44)

**ICT third-party register (Article 28(3)).** Financial entities must maintain a register of all ICT third-party service providers. This is not a simple vendor list; DORA requires specific data points:

```yaml
# ICT Third-Party Service Provider Register entry
provider:
  id: "TPSP-0003"
  name: "Acme Cloud Services Ltd"
  lei: "5493001KJTIIGC8Y1R12"    # Legal Entity Identifier
  registered_country: "IE"
  services_provided:
    - service: "Cloud infrastructure — compute and storage"
      ict_assets_supported:
        - "ICT-0042"              # Core banking transaction processing
        - "ICT-0051"              # Customer data platform
      classification: critical    # critical | important | other
      criticality_rationale: "Hosts payment processing; no alternative provider for >72h"
  contractual_arrangement:
    contract_ref: "MSA-2023-0047"
    contract_start: "2023-06-01"
    contract_expiry: "2026-05-31"
    termination_notice_days: 180
    governing_law: "IE"
    sla_availability_pct: 99.95
    audit_rights: true
    subcontractors_disclosed: true
    exit_strategy_documented: true
    dora_art30_compliant: true
  concentration_risk:
    # Assessed per Art. 29 — concentration risk assessment
    sole_provider_for_function: true
    alternative_provider_identified: false
    alternative_provider_transition_time_days: null
    concentration_risk_accepted: false    # Remediation in progress
    risk_owner: "Chief Risk Officer"
  last_reviewed: "2025-01-15"
  next_review_due: "2026-01-15"
```

**Contractual requirements for critical ICT providers (Article 30).** DORA Article 30(2) lists mandatory contract clauses for agreements with ICT third-party providers supporting critical or important functions. Standard cloud provider agreements (AWS Customer Agreement, Azure standard terms) do not include all required clauses. Entities must negotiate addenda or use providers' DORA-specific schedules where available.

Required clauses (Article 30(2)):

- Full description of services, service levels, and data locations
- Audit rights: the financial entity's right to conduct audits and inspections, or to commission third-party audits
- Sub-contracting disclosure: any subcontractors providing part of the service must be disclosed; changes to subcontractors require prior notification
- Exit strategy and termination assistance: the provider must support a transition period on termination, providing data migration assistance
- Service continuity obligations: what the provider must do during an incident affecting the financial entity
- Data security and encryption requirements
- Compliance with relevant legal and regulatory requirements

The audit rights clause is a particular negotiation point with hyperscale cloud providers. AWS, Azure, and GCP offer DORA-specific attestation packages (shared responsibility matrices, audit reports via ISO 27001, SOC 2 Type II, and sector-specific certifications) as a substitute for direct on-site audits. Supervisors have accepted attestation-based audit rights for hyperscale providers in practice, but the contract must explicitly grant the right even if the entity uses attestation reports in practice.

**Concentration risk (Article 29).** Article 29 requires assessment of ICT concentration risk — over-reliance on a single provider or group of providers. The concern is that if all critical ICT functions run on a single cloud provider, an outage at that provider becomes a systemic risk across multiple financial entities simultaneously. The concentration risk assessment must:

- Identify functions where no alternative provider could take over within the entity's RTO
- Document the risk acceptance decision (or remediation plan)
- Include a scenario where the provider is unavailable for 7 days and assess the impact

## Expected Behaviour

The following table maps DORA articles to the technical controls they require and the evidence artefacts that demonstrate compliance:

| DORA Article | Requirement | Technical Control | Evidence Artefact |
|---|---|---|---|
| Art. 6 | ICT risk management framework, annually reviewed | Risk management framework document; management body approval minutes | Approved policy document; board minutes |
| Art. 8 | ICT asset identification and classification | ICT asset register with dependency mapping | Asset register export; network topology diagram |
| Art. 9(2) | ICT risk assessment | Threat/vulnerability risk register | Risk register with residual risk ratings and owner sign-off |
| Art. 9(4) | 11 mandatory ICT security policy areas | Individual policy documents for each area | Dated, approved policy documents per area |
| Art. 11 | BIA, RTO/RPO for critical functions | BIA document; recovery test results | BIA report; recovery test evidence with RTO/RPO validation |
| Art. 13 | ICT capacity and performance management | Monitoring dashboards; capacity planning process | Monthly capacity reports; alert threshold documentation |
| Art. 14 | ICT security awareness training | Annual training programme | Completion records; training content |
| Art. 17 | Incident management process | Incident management procedure; SIEM classification rules | Procedure document; SIEM rule configuration |
| Art. 18 | Major incident classification | DORA criteria-based classification workflow | Classification decision records for each incident |
| Art. 19 | Major incident reporting to competent authority | Regulatory reporting workflow in incident platform | Initial, intermediate, and final report submissions with timestamps |
| Art. 25 | Basic resilience testing | Vulnerability scan programme; tabletop exercises | Scan reports; tabletop exercise records; remediation tracker |
| Art. 26 | TLPT for significant entities | TIBER-EU methodology engagement | TTI report; red team report; purple team closure; attestation letter |
| Art. 28 | ICT third-party risk policy | Third-party risk management procedure | Policy document; ICT provider register |
| Art. 30 | Contractual requirements for critical providers | DORA-compliant contract amendments | Contract amendments or DORA schedules for each critical provider |
| Art. 29 | Concentration risk assessment | Concentration risk register | Risk assessment document; management acceptance |

## Trade-offs

**Regulatory overhead vs operational agility.** DORA's documentation requirements are substantial. Maintaining a continuously accurate ICT asset register, risk register, and third-party register requires process discipline. Many engineering teams find that the initial cost of building these records is large (3-6 months of effort for a mid-size entity), but the ongoing maintenance cost is lower if the registers are embedded into change management processes. Every infrastructure change should trigger an asset register update; every new vendor should trigger a third-party register entry. If the registers are updated as a retrospective compliance exercise, the effort scales with how stale the data has become.

**TLPT frequency vs cost.** A full TIBER-EU TLPT engagement for a significant financial institution costs EUR 500,000-1,500,000 when including the TI provider, red team provider, and internal coordination effort. The 3-year frequency means this is approximately EUR 165,000-500,000 per year annualised — material for smaller in-scope entities. The pooled testing provision (Article 26(5)) offers partial relief where the same ICT provider serves multiple entities. Entities should actively coordinate with their ICT third-party providers and peer institutions on pooled TLPT opportunities, particularly for shared cloud infrastructure.

**Third-party contractual requirements vs vendor willingness.** Large technology vendors are accustomed to financial services regulatory requirements, and most have DORA readiness programmes with pre-drafted contract schedules. The challenge is with smaller, specialist ICT providers — identity verification vendors, market data providers, core banking software vendors — who may not have DORA-compliant contract templates and may resist negotiating specific clauses. Entities have limited leverage over vendors that serve only the financial sector but not at sufficient scale to have invested in DORA compliance. The practical resolution is: document the gap, assess whether the provider's risk profile warrants replacement, and negotiate the minimum required clauses incrementally. Article 30(4) provides a fallback — where a provider refuses required clauses, the entity must assess whether the relationship should continue.

## Failure Modes

**Missing the major incident classification — late or omitted regulatory notification.** The most operationally damaging failure mode is classifying a qualifying incident as standard, discovering it was major after the 4-hour notification window has passed, and then notifying the competent authority late. The RTS on major incident classification is deliberately conservative — criteria are worded so that borderline cases are classified as major and reported. Entities that apply a high threshold for "significant impact" to avoid the reporting burden will face supervisory challenge. The correct posture is to classify high and de-classify if the criteria are clearly not met, rather than the reverse. A late notification with a credible internal record showing the entity was tracking the incident is treated differently by supervisors than a notification that appears only after external pressure.

**Inadequate TLPT scope — critical functions excluded.** The TLPT scope must cover critical and important functions. Entities sometimes narrow the scope to reduce test complexity and cost, excluding systems that have dependencies on third-party cloud providers (on the grounds that the provider's environment cannot be tested without the provider's involvement). Article 26(7) requires ICT third-party providers to cooperate with TLPT; a scope that excludes critical cloud-hosted systems on the grounds of provider access is not acceptable without prior competent authority agreement. The failure mode is a supervisor reviewing the TLPT scope and finding that the entity's highest-risk systems were outside the test perimeter.

**ICT third-party register gaps — unregistered critical providers.** Entities that define "ICT third-party provider" narrowly will have gaps. DORA's definition includes any company providing ICT services — software, hardware, data services, or digital services. This includes SaaS providers for internal tools (HR systems, communication platforms), certificate authorities, DNS providers, and threat intelligence feeds. An entity that registers only its top-tier cloud and core banking providers but omits identity providers, email security vendors, or market data feeds may find that one of these providers is involved in a major incident and is absent from the register. The register should be populated from a discovery exercise — reviewing actual network traffic, software asset management data, and procurement records — not from memory.

**Undocumented concentration risk.** An entity that relies on a single cloud provider for 90% of its critical ICT services but has not conducted the Article 29 concentration risk assessment, or has conducted it but not documented an accepted risk position or remediation plan, faces dual exposure: operational risk if the provider has an outage, and supervisory risk if the concentration is discovered during inspection without evidence of risk ownership. The concentration risk assessment is not a one-time exercise; it must be updated when the entity adds new services with a provider, changes its critical function inventory, or when the provider itself changes (merger, acquisition, or service discontinuation).
