---
title: "Threat Modeling at Scale: STRIDE-per-Component, PASTA, and Continuous Threat Modeling"
description: "Threat modeling does not scale by adding more whiteboard sessions. Codify the methodology, embed in design review, and treat threat models like code."
slug: "threat-modeling-at-scale"
date: 2026-04-27
lastmod: 2026-04-27
category: "cross-cutting"
tags: ["threat-modeling", "stride", "pasta", "security-design", "continuous"]
personas: ["security-engineer", "platform-engineer", "engineering-manager"]
article_number: 203
difficulty: "intermediate"
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/cross-cutting/threat-modeling-at-scale/index.html"
---

# Threat Modeling at Scale: STRIDE-per-Component, PASTA, and Continuous Threat Modeling

## Problem

Threat modeling has been an industry-standard practice for two decades. Yet at most engineering organizations:

- It happens once at design time, then never again — unless a security incident forces a re-examination.
- It produces a document that becomes stale within months as the system evolves.
- It is performed by a security engineer in isolation rather than the team building the system.
- It treats every system the same, regardless of risk profile.
- The output is qualitative — "we identified spoofing risk" — without coupled mitigations or follow-through.

At small scale, a quarterly whiteboard session per service works. Past 50 services, it doesn't. Past 200 services, the security-engineer-led model is impossible: there aren't enough hours.

The mature practice — Continuous Threat Modeling (CTM, popularized by Autodesk's adoption and the OWASP CTM-Pyramid) — solves the scaling problem by:

- **Pushing threat modeling into product teams.** Security engineers train and review; teams own their threat models.
- **Standardizing the methodology.** STRIDE-per-component for new services; PASTA for high-risk systems; lightweight checklists for routine changes.
- **Treating models as living artifacts.** Stored in version control alongside code; updated when architecture changes; reviewed in PRs.
- **Tying mitigations to specific code.** Each identified threat has an associated control with a measurable verification.
- **Automating the obvious.** Common patterns (untrusted-input handling, authentication, secret management) come from a library; teams focus on the unique.

This article covers STRIDE-per-component for greenfield design, PASTA for systems with explicit threat actors, the lightweight checklist for change reviews, threat-model-as-code patterns, and the operational integration with engineering workflows.

**Target systems:** any organization with > 30 engineers and > 30 services. Tooling: GitHub / GitLab for storage; pytm or Threat-Dragon for diagram generation; Linear / Jira for tracking; OWASP ASVS as a control catalogue.

## Threat Model

Different from typical articles — the "adversary" here is the security gap that emerges from out-of-date or absent threat models, plus the specific gaps that scaling exposes:

- **Adversary 1 — Inattentional drift:** the threat model was correct two years ago. The system has changed; nobody noticed the new attack surface.
- **Adversary 2 — Unmodeled component:** a new third-party dependency, a new internal API, a refactored boundary — never had a threat model.
- **Adversary 3 — Tribal-knowledge security:** team members know "the right way" but it isn't written down. New hires miss it.
- **Adversary 4 — One-off heroic threat-model that didn't reach production:** the analysis happened, the mitigations were never tracked to completion.
- **Access level:** threat-modeling failure exposes whatever an actual external threat model would identify.
- **Objective:** the bad outcomes — undetected gaps that real attackers exploit — that good threat modeling exists to prevent.
- **Blast radius:** a service designed without a threat model is reactive at best; a fleet of services without continuous TM is structurally unable to keep up with attacker innovation.

## Configuration

### Step 1: Tier Systems by Threat Surface

Not every service warrants the same depth. Establish three tiers:

| Tier | Examples | Threat-modeling depth | Frequency |
|------|----------|----------------------|-----------|
| Critical | Authentication, payments, secrets store, customer data warehouse | PASTA (full); 6 stages, business-impact analysis | Per major change; reviewed yearly |
| Standard | Most internal services that handle user data | STRIDE-per-component | At design; per architecture change |
| Routine | Internal tools, dashboards, devex tooling | Checklist-based change review | Per PR for security-affecting changes |

A small CMDB-style mapping stores tier per service. Tier drives which template the team uses.

### Step 2: STRIDE-per-Component for Standard Services

STRIDE is the workhorse: for each component, ask "could this component face Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege?" The "per component" variant makes it tractable: don't model the whole system at once.

```yaml
# threat-model.yaml — checked into the service repo.
service: payments-api
tier: standard
last_reviewed: 2026-04-27

components:
  - name: HTTP API
    type: ingress
    trust_boundary: internal-cluster-edge
    data_classification: PII

    threats:
      - id: T-API-001
        category: spoofing
        description: Attacker impersonates a legitimate caller via stolen JWT
        likelihood: medium
        impact: high
        controls:
          - id: C-001
            description: JWT verification with rotating signing key (JWKS)
            verification: ci-test/jwt_verification_test.go
            owner: platform-team
        residual_risk: low

      - id: T-API-002
        category: information_disclosure
        description: Verbose error messages leak schema or stack trace to caller
        likelihood: high
        impact: medium
        controls:
          - id: C-002
            description: Production error responses sanitized via middleware
            verification: e2e-test/error_response_test.go
            owner: payments-team
        residual_risk: low

  - name: Postgres connection
    type: data-store
    trust_boundary: cluster-internal
    data_classification: PII

    threats:
      - id: T-DB-001
        category: information_disclosure
        description: Database connection in plaintext on cluster network
        likelihood: low
        impact: high
        controls:
          - id: C-003
            description: TLS to Postgres enforced via NetworkPolicy
            verification: nightly-network-test
            owner: platform-team
        residual_risk: low
```

A simple structure. PRs that add new components, change data classification, or affect trust boundaries trigger threat-model updates as part of CI.

### Step 3: PASTA for Critical Systems

PASTA (Process for Attack Simulation and Threat Analysis) takes longer but goes deeper. The seven stages:

1. **Define objectives** — what does this system protect, why does it exist, who depends on it.
2. **Define technical scope** — architecture, components, data flows.
3. **Application decomposition** — components, trust boundaries, entry/exit points.
4. **Threat analysis** — what threat actors target this, motivations, capabilities.
5. **Vulnerability analysis** — known weaknesses in components.
6. **Attack analysis** — chains of vulnerabilities into realistic attack paths.
7. **Risk and impact analysis** — business impact, prioritization.

For critical services, PASTA is the design-time activity. Output is a richer threat model with explicit threat actors:

```yaml
# threat-model-pasta.yaml — for critical-tier services.
service: customer-data-warehouse
tier: critical
last_full_review: 2026-04-27
next_review: 2027-04-27

threat_actors:
  - id: TA-1
    name: External targeted attacker
    motivation: Customer-data theft for resale
    capabilities: [phishing, credential-stuffing, supply-chain-injection]
    tools: [Cobalt Strike, custom malware, leaked credential dumps]
    likelihood_to_target: high

  - id: TA-2
    name: Insider with database access
    motivation: Self-enrichment / extortion
    capabilities: [database-query, ETL-modification, log-tampering]
    likelihood_to_target: medium

  - id: TA-3
    name: Cloud provider compromise
    motivation: Mass exfiltration
    capabilities: [hypervisor-level access, hardware-level access]
    likelihood_to_target: very-low

attack_paths:
  - id: AP-001
    description: External attacker -> phishing engineer -> stolen Vault role -> data exfil
    threat_actor: TA-1
    components_traversed: [employee-laptop, vault, customer-warehouse]
    mitigations:
      - C-100: FIDO2 SSH for warehouse access (defeats phishing)
      - C-101: Vault dynamic credentials with short TTL (limits stolen-token window)
      - C-102: Egress NetworkPolicy on warehouse pods (limits exfil destinations)
    residual_risk: medium

  - id: AP-002
    description: Insider abuses query access to dump customer records
    threat_actor: TA-2
    components_traversed: [employee-database-account, customer-warehouse]
    mitigations:
      - C-103: Per-query audit logging with anomaly detection
      - C-104: Row-level security; engineers see only their assigned scope
    residual_risk: low
```

PASTA outputs feed into the security operations: detection rules align with attack paths, drills exercise specific paths, post-incident reviews check whether the path was modeled.

### Step 4: Lightweight PR-Time Threat Modeling

For routine code changes that don't warrant a full review, embed a checklist in the PR template:

```markdown
## Security Considerations

For each "yes," briefly describe what you did:

- [ ] Does this change introduce a new external trust boundary (new API, new vendor)?
- [ ] Does this change handle untrusted input differently than existing code?
- [ ] Does this change introduce new authentication / authorization logic?
- [ ] Does this change alter data classification (e.g., new PII field)?
- [ ] Does this change modify cryptographic primitives or key management?
- [ ] Does this change introduce a new external network call?

If 2+ boxes are checked, request review from #security-engineering.
```

Only changes that genuinely affect threat surface trigger security review. The signal-to-noise vs. "every PR needs security sign-off" is much higher.

### Step 5: Threat-Model Validation in CI

Models that aren't checked decay. Validate them:

```python
# scripts/validate-threat-model.py
import yaml, sys, glob

def validate(path):
    model = yaml.safe_load(open(path))
    errors = []

    # Every component must have at least one identified threat.
    for comp in model.get("components", []):
        if not comp.get("threats"):
            errors.append(f"{path}: component {comp['name']} has no threats listed")

    # Every threat must have a control or accept-risk justification.
    for comp in model.get("components", []):
        for threat in comp.get("threats", []):
            if not threat.get("controls") and not threat.get("accepted_risk_reason"):
                errors.append(f"{path}: threat {threat['id']} has no control or acceptance")

    # Every control must reference a verification.
    for comp in model.get("components", []):
        for threat in comp.get("threats", []):
            for control in threat.get("controls", []):
                if not control.get("verification"):
                    errors.append(f"{path}: control {control['id']} has no verification")

    # last_reviewed within the past 365 days.
    last = model.get("last_reviewed")
    if last and (datetime.now().date() - parse(last).date()).days > 365:
        errors.append(f"{path}: last review > 365 days ago")

    return errors

errors = []
for f in glob.glob("**/threat-model*.yaml", recursive=True):
    errors.extend(validate(f))

if errors:
    print("\n".join(errors))
    sys.exit(1)
```

Run on every PR. Stale or incomplete threat models block merges (after a reasonable rollout period).

### Step 6: Cross-Reference Threats to Detection Rules

Each PASTA attack path has expected signals; tie those to your detection ruleset:

```yaml
# threat-model-pasta.yaml continued.
attack_paths:
  - id: AP-001
    detection_signals:
      - sigma_rule: rules/cloud/aws/iam-privilege-escalation.yml
      - sigma_rule: rules/aws/cloudtrail-vault-token-anomaly.yml
      - prometheus_alert: vault-policy-attempts-by-user
```

A periodic audit confirms each PASTA attack path has a corresponding detection. Gaps reveal threats the SOC can't observe.

### Step 7: Quarterly Review Cadence

Threat models go stale. Set quarterly review:

- **Tier 1 (PASTA / critical):** full re-review yearly; quarterly check for material changes.
- **Tier 2 (STRIDE / standard):** quarterly check for material changes; full re-review when architecture changes.
- **Tier 3 (checklist):** PR-time only; sample-audit 5% per quarter.

A "stale model" report from CI (last_reviewed > N days) feeds the security-engineering team's queue.

## Expected Behaviour

| Signal | No threat-model program | Continuous TM |
|--------|--------------------------|----------------|
| Time per service to identify gaps | Hours-of-security-engineer-thought ad-hoc | Bounded by team-size; runs in CI |
| New service born with TM | Often not | Required by template |
| Stale model detection | Manual / never | Automated, fail-CI |
| Threat-to-mitigation traceability | Lost | Explicit in YAML |
| New attack path picked up by detection | Discovered post-incident | Mapped in TM |
| Engineer-side ownership | Security team owns | Service team owns |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Tier-based methodology | Right-sized investment | Tier definition + maintenance work | Use cmdb / service catalogue if available; tag at service registration. |
| Threat-model-as-code | Versioned, reviewable, lintable | Requires teams to author YAML | Provide a template / scaffolding tool (cookiecutter); start with examples. |
| PR-time checklist | Cheap; scales | Self-reported; checkbox cheating | Spot-audit; the goal is awareness more than enforcement. |
| CI-validated models | Catches drift mechanically | False positives for legitimate temporary states | Allow `last_reviewed_override` with expiration for emergency bypasses. |
| Detection-rule cross-reference | Forces thinking about observability | Mapping work | Use Sigma rule IDs; each attack-path mapping is one line of YAML. |
| Quarterly review cadence | Models stay current | Reviewer time | Reviews can be 30-min meetings — only review what changed since last quarter. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Threat models become checkbox theatre | Models exist but don't influence decisions | Detection rules don't align with documented attack paths | Tie review meetings to actual incidents and changes; if no real value emerges, rethink the methodology. |
| Tier inflation | Every service marked Tier 1 | Disproportionate PASTA workload | Document tier criteria explicitly; review tier assignments quarterly. |
| Untrained authors produce unsafe threats | Quality varies wildly across services | Inconsistent depth and quality in checked-in models | Office-hours from security-engineering; templates with examples; pair-review for first model from each team. |
| Models lag architecture | Diagrams reflect last year's design | Architecture diff vs. threat-model diff | Tie threat-model updates to specific architecture-doc tags; PR template asks "does this change the threat model?" |
| Detection-rule mapping drifts | Sigma rule renamed; threat-model still references old name | CI validation catches | Rule IDs must be UUID / stable across renames (covered in detection-as-code-sigma article). |
| Review cadence missed | Quarterly slips to never | `last_reviewed` field stale across services | CI fails on stale models; surface the list to engineering management quarterly. |
| Adversary capability lags reality | Threat actor profiles describe 2018 capability; attackers have moved on | Real incidents exploit techniques not in the model | Annual external red-team exercise; map findings back into PASTA models. |

## Related Articles

- [Detection Engineering Metrics](/articles/observability/detection-engineering-metrics/)
- [Compliance-as-Code with Open Policy Agent](/articles/cross-cutting/compliance-as-code/)
- [Hardening Scorecard for Engineering Teams](/articles/cross-cutting/hardening-scorecard/)
- [Incident Response Hardening Playbook](/articles/cross-cutting/incident-response-hardening-playbook/)
- [Hardening Strategies for Small Teams](/articles/cross-cutting/hardening-small-teams/)
