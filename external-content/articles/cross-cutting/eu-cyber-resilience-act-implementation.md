---
title: "EU Cyber Resilience Act: Technical Implementation Guide"
description: "Practical technical implementation of EU CRA obligations: SBOMs, vulnerability handling, conformity assessment, and security update commitments for software vendors."
slug: "eu-cyber-resilience-act-implementation"
date: 2026-05-08
lastmod: 2026-05-08
category: "cross-cutting"
tags: ["cra", "compliance", "eu", "sbom", "vulnerability-handling", "conformity"]
personas: ["security-engineer", "platform-engineer", "compliance"]
article_number: 655
difficulty: "intermediate"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/cross-cutting/eu-cyber-resilience-act-implementation/index.html"
---

# EU Cyber Resilience Act: Technical Implementation Guide

## Problem

The EU Cyber Resilience Act (Regulation (EU) 2024/2847, "CRA") entered into force on 10 December 2024 with phased application. The reporting obligation under Article 14 (active exploitation and incidents) becomes applicable on 11 September 2026, and the full obligations on 11 December 2027. Any "product with digital elements" (PDE) placed on the EU market — software, hardware containing software, software-as-a-product distributed for installation — must comply, regardless of the manufacturer's location. The penalty ceiling is €15M or 2.5% of global turnover, whichever is higher.

CRA is unusual among EU regulations in that it imposes concrete *technical* obligations rather than primarily process ones: SBOMs in machine-readable format, automatic security updates by default, vulnerability handling that meets specified timelines, conformity assessment, and 24/72-hour reporting of actively exploited vulnerabilities and severe incidents. For most vendors, the technical implementation work is significant: an SBOM pipeline that survives compliance audit, a vulnerability-handling lifecycle that demonstrably meets the timelines, an update mechanism that is on-by-default and signed, and the operational machinery to file Article 14 reports.

The practical compliance gap most teams face is not "we don't know what to do" — ENISA and the Commission have published implementing acts and guidance — but "our existing security practices are 80% there but the audit-trail and documentation gaps will fail conformity". This article maps the CRA's technical obligations onto concrete engineering deliverables that an SME or mid-sized vendor can realistically implement using OSS tools, and identifies the half-dozen places where ad-hoc practice typically fails the standard.

CRA distinguishes "important" and "critical" PDEs (Annexes III and IV) from default products. Critical PDEs (passwords managers, EDR, network management systems, hardware HSMs, smart-meter gateways) require third-party conformity assessment via a notified body. Important Class II products (e.g., container runtimes, identity-management systems, CSPMs) require either harmonised-standard self-assessment or third-party. Most products fall in the default category and self-assess against essential requirements.

Target audience: software vendors placing products in the EU market, regardless of legal entity location. Target stack: any modern build pipeline (GitHub Actions, GitLab CI, Jenkins) plus standard OSS tooling — Syft, Grype, Sigstore, Dependency-Track, OpenSSF Scorecard.

## Threat Model

CRA framing inverts the traditional threat model: the regulator is not an adversary but the obligation source. The relevant *failure modes* — and the corresponding "threats" to compliance — are:

1. **Audit-trail gaps.** Inability to demonstrate that the SBOM and vulnerability-handling claims in the technical documentation correspond to the released product. Surface: ad-hoc SBOM generation outside the build pipeline.
2. **Notification timeline misses.** Failure to file an early-warning notification within 24h of awareness of an actively exploited vulnerability. Surface: ambiguous on-call ownership; unclear definition of "becoming aware".
3. **Default-insecure shipped configuration.** Product ships with default password, exposed admin port, or telemetry without consent. Surface: legacy "first run" UX and undocumented defaults.
4. **Update channel insufficiency.** No automatic, signed update mechanism, or one that requires acceptance of new T&Cs. Surface: opt-in update model; no signing infrastructure.

The penalty for each is direct: fines, market withdrawal, reputational damage that reaches procurement databases and disqualifies the product from EU public-sector contracts under NIS2-aligned requirements.

## Configuration / Implementation

### Step 1 — Build SBOMs in the pipeline, not after the fact

CRA Annex I §2(1) requires SBOMs in a "commonly used and machine-readable format". CycloneDX 1.6 and SPDX 2.3 both qualify. Generate inside the build, attest, and ship alongside the artefact:

```yaml
# .github/workflows/release.yml
- name: Generate SBOM
  uses: anchore/sbom-action@v0
  with:
    path: .
    format: cyclonedx-json
    output-file: sbom.cdx.json
    upload-artifact: false

- name: Sign SBOM with Sigstore
  uses: sigstore/cosign-installer@v3
- run: |
    cosign sign-blob --yes \
      --bundle sbom.cdx.json.sigstore \
      sbom.cdx.json

- name: Attach to release
  run: |
    gh release upload ${{ github.ref_name }} \
      sbom.cdx.json sbom.cdx.json.sigstore
```

Two non-obvious requirements:

1. The SBOM must include the *full* dependency graph, not just direct dependencies. Use `--scope all` (Syft) or `npm sbom --sbom-type=cyclonedx --omit=` with no exclusions.
2. Include licence and supplier per component — `cdx-property: cdx:license` and `cdx:supplier` — both fields the conformity-assessment template asks for.

### Step 2 — Wire SBOMs into vulnerability handling

CRA Article 13 obliges manufacturers to "address and remediate vulnerabilities without delay". The implementing acts establish indicative timelines: 90 days for high-severity, faster for actively-exploited. Operationalise via Dependency-Track:

```yaml
# docker-compose.yml for dependency-track
services:
  dtrack-apiserver:
    image: dependencytrack/apiserver:4.12
    environment:
      - ALPINE_DATABASE_URL=jdbc:postgresql://db/dtrack
    volumes:
      - dtrack:/data

  dtrack-frontend:
    image: dependencytrack/frontend:4.12
    ports:
    - "8080:8080"
```

After each release, push the SBOM:

```bash
curl -X POST https://dtrack.example.net/api/v1/bom \
  -H "X-Api-Key: ${DT_API_KEY}" \
  -F "project=${PROJECT_UUID}" \
  -F "bom=@sbom.cdx.json"
```

Configure project-level policies: notify the security team within 1 hour of any new CVE matching a component, escalate to incident if CVSS ≥ 7.0 + Known Exploited Vulnerabilities catalogue match.

### Step 3 — Default-secure configuration

Audit and document defaults systematically:

```yaml
# docs/security/cra-default-config.yaml
defaults:
- name: admin_password
  default: null               # forces first-run setup
  cra_compliance: §2(3)(b)
- name: admin_listen_address
  default: "127.0.0.1"
  cra_compliance: §2(3)(d)    # minimise attack surface
- name: telemetry
  default: "off"
  cra_compliance: §2(3)(g)    # data minimisation
- name: tls_min_version
  default: "1.3"
  cra_compliance: §2(3)(e)
- name: auto_update
  default: true
  cra_compliance: §2(3)(k)
```

Enforce in CI:

```python
# tests/test_cra_defaults.py
import yaml
def test_admin_password_no_default():
    cfg = yaml.safe_load(open("dist/default-config.yaml"))
    assert cfg["admin"]["password"] is None
def test_telemetry_opt_in():
    cfg = yaml.safe_load(open("dist/default-config.yaml"))
    assert cfg["telemetry"]["enabled"] is False
```

### Step 4 — Signed automatic updates

Article 13(2)(d) requires automatic security updates on by default. The mechanism must be authenticated. Combine The Update Framework (TUF) with Sigstore for keyless signing:

```bash
# Build pipeline:
cosign sign --yes \
  --bundle dist/app-1.4.0.bin.sigstore \
  dist/app-1.4.0.bin

# At install time the client verifies:
cosign verify-blob \
  --bundle app-1.4.0.bin.sigstore \
  --certificate-identity 'https://github.com/example/app/.github/workflows/release.yml@refs/tags/v1.4.0' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  app-1.4.0.bin
```

For embedded products, ship the verifying public key in firmware and use TUF metadata for delegation/rotation.

### Step 5 — Vulnerability disclosure policy and PSIRT

Article 13(1)(c) requires a coordinated vulnerability disclosure policy. The minimum-viable policy:

```markdown
# SECURITY.md
## Reporting a Vulnerability

Email: security@example.net  (PGP key: 0xABCD…)
HackerOne / private bug bounty: https://hackerone.com/example

We acknowledge within 72 hours, provide an initial assessment within 7 days,
and target remediation per CVSS:
- Critical (≥9.0) or actively exploited: ≤14 days
- High (7.0-8.9): ≤30 days
- Medium (4.0-6.9): ≤60 days
- Low (<4.0): next minor release

We coordinate disclosure with reporters; default embargo is 90 days.
```

Publish the same in security.txt at the well-known path.

### Step 6 — 24/72-hour notification machinery

Article 14 requires notification to the relevant CSIRT and ENISA within 24h (early warning) and 72h (incident notification) of becoming aware of an actively exploited vulnerability or severe incident. ENISA published the single reporting platform; the technical work is wiring your incident process to it:

```yaml
# Runbook excerpt
on_actively_exploited_vuln:
  T+0:        triage; verify exploitation in the wild
  T+1h:       assemble facts: CVE, scope, mitigations, affected versions
  T+24h:      file ENISA early warning via single-reporting-platform API
  T+72h:      file follow-up incident notification
  T+14d:      file final report
```

The single reporting platform exposes a JSON API; pre-build the payload templates so the on-call engineer is filling fields, not formatting:

```json
{
  "report_type": "early_warning",
  "manufacturer": {"name": "Example", "id": "EU-MFG-12345"},
  "product": {"name": "Example Server", "version_range": ">=1.3.0,<1.4.2"},
  "vulnerability": {"cve_id": "CVE-2026-NNNN", "cvss_v4": "9.1"},
  "exploitation_evidence": "...",
  "interim_mitigation": "..."
}
```

### Step 7 — Conformity assessment and technical documentation

For default-class products, self-assess against essential requirements (Annex I) and produce a Declaration of Conformity. Maintain technical documentation in a dedicated repo:

```
cra-tech-docs/
├── product-description.md
├── risk-assessment.md
├── annex-i-section-1-essential-requirements.md
├── annex-i-section-2-vulnerability-handling.md
├── conformity-assessment.md
├── eu-declaration-of-conformity.md
├── sbom/
│   └── 1.4.0.cdx.json
└── test-results/
    ├── pen-test-2026-Q1.pdf
    └── security-review-2026-Q1.md
```

Automate where possible: the SBOM is built artefact, test results auto-deposited from CI, the DoC is templated and refreshed per release.

## Expected Behaviour

| Signal | Before CRA implementation | After CRA implementation |
|--------|---------------------------|-------------------------|
| SBOM availability | On request | Published with every release; signed |
| New CVE in dependency | Noticed at next sprint | Alerted within 1 hour; remediated per timeline |
| Default-insecure defaults | Several legacy ones | Documented, tested, blocked in CI |
| Update mechanism | Opt-in, unsigned | On by default, Sigstore-verified |
| Active-exploit awareness | Unstructured | T+24h ENISA filing; runbook executed |
| Conformity documentation | Scattered | Dedicated repo; tied to release tags |

```bash
# Verify that the latest release has SBOM + signature.
gh release view v1.4.0 --json assets \
  | jq '.assets[].name' | grep -E '^sbom\.cdx\.json(\.sigstore)?$'
# expected: both sbom.cdx.json and sbom.cdx.json.sigstore

# Verify Sigstore bundle.
cosign verify-blob --bundle sbom.cdx.json.sigstore \
  --certificate-identity-regexp 'github.com/example/app' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  sbom.cdx.json
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| In-pipeline SBOM | Audit-grade provenance | CI duration +30–90s | Cache Syft results; parallelise |
| Auto-update on by default | Reduces fleet exposure | Some enterprise customers want change control | Ship policy controls (deferral windows) but default-on |
| 24h notification readiness | Avoids fines, signals maturity | On-call burden during weekends | Pre-built templates; clear "becoming aware" definition |
| Self-assessed conformity (default class) | No notified-body cost | Higher liability if assessment is wrong | Engage external counsel for first iteration |
| Sigstore keyless signing | No key-rotation logistics | OIDC dependency on GitHub/etc | Mirror Rekor entries; key fallback for offline verification |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| SBOM stale relative to artefact | DoC reviewer flags mismatch | CI step verifying `syft <artefact>` matches stored SBOM | Block release if mismatch |
| ENISA filing missed window | Regulator inquiry | Internal SLA dashboard | Document the miss honestly; corrective action; do not retroactively backdate |
| Sigstore verifying chain breaks | Updates fail in field | Telemetry on update success rate | Maintain bundle's transparency-log entry; offline verification fallback |
| Default-config drift between docs and binary | Audit finding | Scheduled CI test comparing built defaults to YAML doc | Block release; treat as P1 |
| Vulnerability remediation timeline missed | Customer or researcher complains | Per-CVE timer in PSIRT tracker | Honest disclosure; root-cause; tighten triage process |

## When to Consider a Managed Alternative

- Compliance-as-a-service offerings (Vanta, Drata, Scrut) handle the documentation surface; the *technical* implementations here remain your responsibility.
- For SBOM hosting and continuous CVE matching, GitHub Advanced Security, Snyk, and Dependency-Track Cloud reduce build-out cost.
- For embedded / IoT vendors lacking PKI infrastructure, services like Memfault or Mender provide signed-update-as-a-service compatible with CRA Article 13 obligations.

## Related Articles

- [DORA Technical Implementation](/articles/cross-cutting/dora-technical-implementation/)
- [SBOM in CI](/articles/cicd/sbom/)
- [Sigstore Keyless Signing](/articles/cicd/sigstore-keyless-signing/)
- [SLSA Provenance](/articles/cicd/slsa-provenance/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
