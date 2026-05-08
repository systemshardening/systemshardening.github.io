---
title: "Building a Unified AppSec Programme: Integrating SAST, SCA, Secret Scanning, and DAST"
description: "Running four separate security scanning tools produces four separate finding lists with duplicates, different severity scales, and no unified remediation tracking. A mature AppSec programme correlates findings across tools, deduplicates across the same vulnerability found by multiple scanners, normalises severity, and tracks remediation through a single workflow. This guide builds that programme using DefectDojo and open-source tooling."
slug: unified-appsec-programme
date: 2026-05-08
lastmod: 2026-05-08
category: cross-cutting
tags:
  - appsec
  - sast
  - sca
  - dast
  - defectdojo
personas:
  - security-engineer
  - security-analyst
article_number: 647
difficulty: Intermediate
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/cross-cutting/unified-appsec-programme/
---

# Building a Unified AppSec Programme: Integrating SAST, SCA, Secret Scanning, and DAST

## Problem

Most teams running application security tooling are not running an AppSec programme — they are running four separate tools that happen to share a CI pipeline. Semgrep flags insecure code patterns. Trivy reports vulnerable dependencies. Gitleaks catches hardcoded secrets. OWASP ZAP probes the running application for exploitable weaknesses. Each tool produces its own finding list, in its own format, with its own severity scale, stored in its own place.

The practical consequence is tool noise without signal. A medium-sized application under active development can produce several thousand findings per month across four scanners. Without a unified view, developers face duplicated tickets, security engineers spend their time triaging instead of remediating, and the organisation cannot answer the questions that determine whether the programme is working: Are we fixing vulnerabilities faster than we are introducing them? What is our actual exposure in the critical severity tier right now?

### The Deduplication Problem

The most damaging symptom of disconnected tooling is duplicate findings. A SQL injection vulnerability in a user-facing endpoint may appear as three separate findings: Semgrep flags the unsanitised query construction in the source file (SAST). ZAP confirms exploitability by successfully injecting into the running application (DAST). Trivy flags the underlying ORM library version with a known injection-facilitation CVE (SCA). Three tickets are opened, potentially assigned to three different people, and it is entirely possible that two of the three get marked as false positives while the real issue remains open.

Deduplication is not just about reducing noise. Without it, teams over-report progress: closing the SAST finding while the DAST finding remains active creates the illusion of remediation. At audit time, the organisation cannot demonstrate that it knows whether the SQL injection was actually fixed.

### The Remediation Tracking Gap

Even teams that manage finding deduplication manually often have no programmatic mechanism for confirming that a fix was deployed. A developer commits a fix, closes the security ticket, and moves on. Three questions go unanswered: Was the fix verified by re-running the scan? Did the fix cover all three manifestations of the vulnerability (source, library, runtime)? If the same pattern was reintroduced two sprints later, did anyone notice?

A mature AppSec programme treats findings as having a lifecycle — opened, triaged, risk-accepted or assigned, fixed, verified — and gates the lifecycle transitions on evidence rather than developer attestation.

## Threat Model

**Finding burial.** A security team operating on 10,000 undeduplicated findings cannot reliably surface the three critical ones that matter. An attacker targeting the SQL injection identified by ZAP has a meaningful advantage over a team that has classified it as a duplicate of the Trivy finding and closed it without deploying a fix.

**Unverified closure.** Developers who have easy access to security findings also have the ability to close them. Without an approval workflow for false positive and risk acceptance classifications, findings get closed because they are inconvenient rather than because they have been addressed. This is particularly common in high-velocity teams where security debt competes directly with feature delivery.

**Invisible regression.** AppSec tooling that does not feed metrics cannot demonstrate whether the programme is improving. Without trend data — mean time to remediate by severity tier, vulnerability introduction rate, false positive rate — security leadership cannot make the case for investment or identify which teams need additional attention. The programme becomes defensible on the basis that it exists, not that it is working.

## Configuration and Implementation

### DefectDojo as the Unified AppSec Platform

DefectDojo is an open-source security orchestration and vulnerability management platform designed specifically to aggregate findings from multiple security tools, deduplicate across tools, and provide a unified remediation workflow. It natively parses output from Semgrep, Trivy, Gitleaks, and OWASP ZAP, among dozens of other scanners.

**Deployment.** DefectDojo provides a Docker Compose configuration for single-node deployments and a Helm chart for Kubernetes. For a production deployment supporting multiple engineering teams, the Helm chart is the appropriate choice, as it separates the Celery worker (used for background import processing and deduplication), Redis, and the Django application into independently scalable components.

```bash
helm repo add defectdojo https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/helm-charts
helm install defectdojo defectdojo/defectdojo \
  --namespace defectdojo \
  --create-namespace \
  --set django.ingress.enabled=true \
  --set django.ingress.host=defectdojo.internal.example.com \
  --set initializer.run=true
```

For smaller teams, the Docker Compose path is viable:

```bash
git clone https://github.com/DefectDojo/django-DefectDojo
cd django-DefectDojo
./dc-up.sh
```

**Product and engagement model.** DefectDojo organises findings in a three-level hierarchy: Products represent applications or services. Engagements represent a point-in-time security assessment — a CI run, a sprint, a penetration test. Tests within an engagement represent the output of a single tool run. This hierarchy is important because deduplication operates at the product level: a SQL injection finding from Semgrep in Engagement 12 will deduplicate against the same finding from ZAP in Engagement 13, provided both belong to the same product.

The recommended mapping is one DefectDojo product per deployable application. Shared libraries or internal packages can be separate products or grouped under a product group. Every CI pipeline run creates a new engagement (named by Git commit hash or sprint number), and each scanner uploads its results as a separate test within that engagement.

### Importing Findings via the DefectDojo API

DefectDojo exposes a REST API for programmatic import. The `reimport` endpoint (as opposed to `import`) is the correct choice for CI, because it applies deduplication against the product's existing finding history and automatically closes findings that no longer appear in the latest scan.

```python
# defectdojo_upload.py
import argparse
import requests
import os

SCAN_TYPE_MAP = {
    ".sarif": "SARIF",
    ".json": None,  # resolved by --scan-type flag per file
    ".xml": "ZAP Scan",
}

def upload(host, token, product_name, engagement_name, scan_file, scan_type):
    headers = {"Authorization": f"Token {token}"}

    # Resolve or create product
    prod_resp = requests.get(
        f"{host}/api/v2/products/",
        headers=headers,
        params={"name": product_name},
    )
    product_id = prod_resp.json()["results"][0]["id"]

    # Resolve or create engagement
    eng_resp = requests.post(
        f"{host}/api/v2/engagements/",
        headers=headers,
        json={
            "name": engagement_name,
            "product": product_id,
            "engagement_type": "CI/CD",
            "status": "In Progress",
            "target_start": "2026-01-01",
            "target_end": "2026-12-31",
        },
    )
    engagement_id = eng_resp.json().get("id") or \
        requests.get(f"{host}/api/v2/engagements/",
                     headers=headers,
                     params={"name": engagement_name, "product": product_id}
                    ).json()["results"][0]["id"]

    with open(scan_file, "rb") as f:
        requests.post(
            f"{host}/api/v2/reimport-scan/",
            headers=headers,
            data={
                "engagement": engagement_id,
                "scan_type": scan_type,
                "close_old_findings": "true",
                "deduplication_on_engagement": "false",
            },
            files={"file": f},
        )
```

### CI/CD Integration Pipeline

The GitHub Actions workflow below runs all four scanners and uploads results to DefectDojo in the same pipeline run. The upload step is non-blocking by default — if DefectDojo is unavailable, the pipeline continues. This is a deliberate trade-off: blocking CI on the availability of a security platform is appropriate only once the platform has demonstrated sustained reliability.

```yaml
name: Security Scan

on:
  push:
    branches: [main, "release/**"]
  pull_request:

jobs:
  appsec-scan:
    runs-on: ubuntu-latest
    env:
      DEFECTDOJO_URL: ${{ secrets.DEFECTDOJO_URL }}
      DEFECTDOJO_TOKEN: ${{ secrets.DEFECTDOJO_TOKEN }}
      PRODUCT_NAME: ${{ github.repository }}
      ENGAGEMENT_NAME: ${{ github.sha }}

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: "p/owasp-top-ten p/cwe-top-25"
          generateSarif: "1"
        env:
          SEMGREP_RULES: auto

      - name: Run Trivy SCA
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: "fs"
          format: "json"
          output: "trivy.json"

      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITLEAKS_CONFIG: .gitleaks.toml
          GITLEAKS_REPORT_FORMAT: json
          GITLEAKS_REPORT_PATH: gitleaks.json

      - name: Upload to DefectDojo
        if: always()
        run: |
          python defectdojo_upload.py \
            --host "$DEFECTDOJO_URL" \
            --token "$DEFECTDOJO_TOKEN" \
            --product "$PRODUCT_NAME" \
            --engagement "$ENGAGEMENT_NAME" \
            --file semgrep.sarif --scan-type "SARIF" \
            --file trivy.json --scan-type "Trivy Scan" \
            --file gitleaks.json --scan-type "Gitleaks Scan"
```

The ZAP DAST scan runs in a separate job triggered on deployment to the staging environment, because DAST requires a running application:

```yaml
      - name: Run OWASP ZAP DAST
        uses: zaproxy/action-full-scan@v0.10.0
        with:
          target: "https://staging.example.com"
          rules_file_name: ".zap/rules.tsv"
          cmd_options: "-J zap.json"

      - name: Upload ZAP results to DefectDojo
        if: always()
        run: |
          python defectdojo_upload.py \
            --host "$DEFECTDOJO_URL" \
            --token "$DEFECTDOJO_TOKEN" \
            --product "$PRODUCT_NAME" \
            --engagement "$ENGAGEMENT_NAME" \
            --file zap.json --scan-type "ZAP Scan"
```

### Severity Normalisation

Semgrep uses its own severity levels (INFO, WARNING, ERROR). Trivy uses UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL. Gitleaks does not emit severity levels at all — every secret is implicitly critical. ZAP uses INFORMATIONAL, LOW, MEDIUM, HIGH.

DefectDojo normalises all incoming severity values to its internal scale: Informational, Low, Medium, High, Critical. The mapping is configured per scanner parser in the DefectDojo source, but can be overridden via the API at the product level. The recommended approach is to override based on asset criticality rather than tool severity: a High finding from Trivy against a customer-facing authentication service should be treated as Critical; the same finding against an internal test fixture can remain Medium.

Define severity overrides in DefectDojo's product configuration:

```python
# DefectDojo API: create severity override rule
requests.post(
    f"{DEFECTDOJO_URL}/api/v2/risk_acceptance/",
    headers={"Authorization": f"Token {token}"},
    json={
        "name": "Auth Service Severity Uplift",
        "product": auth_service_product_id,
        "severity_override": "Critical",
        "cwe": [89, 78, 22],  # SQL injection, command injection, path traversal
    },
)
```

### Remediation Workflow and SLAs

DefectDojo tracks findings through a defined lifecycle. The recommended SLA configuration by severity tier:

| Severity | SLA Target | Escalation |
|----------|-----------|------------|
| Critical | 24 hours | Auto-escalate to CISO after 12h |
| High | 7 days | Notify security champion after 5d |
| Medium | 30 days | Weekly digest reminder |
| Low | 90 days | Monthly report inclusion |

Configure SLA policies in DefectDojo under System Settings → SLA Configuration. When a finding breaches its SLA, DefectDojo marks it as overdue and can trigger webhook notifications to Slack or PagerDuty.

Finding lifecycle states in DefectDojo:

- **Active**: newly imported, unreviewed
- **Confirmed**: triaged and verified as real
- **Risk Accepted**: acknowledged as a real finding that the business has decided not to fix within SLA — requires a written justification and an expiry date; Critical risk acceptances require additional approval
- **Mitigated**: fix has been deployed and the finding has been closed by a reimport scan that no longer reports it
- **False Positive**: tool error, with mandatory justification and approval workflow enabled for Critical and High

The approval workflow for False Positive and Risk Accepted transitions is enforced through DefectDojo's built-in review mechanism: a finding cannot move to either state without a reviewer other than the submitter approving the change. For Critical findings, the reviewer must hold the CISO or Security Manager role in DefectDojo.

Risk acceptances must carry an expiry date. DefectDojo automatically reopens findings when their risk acceptance expires, returning them to the Active state and restarting the SLA clock. For infrastructure vulnerabilities that cannot be patched without a major maintenance window, a maximum acceptance period of 90 days is appropriate, with monthly review checkpoints.

### DefectDojo Deduplication Engine

DefectDojo's deduplication logic matches findings across tools using a configurable hash. The default algorithm combines:

1. **Title** (normalised)
2. **CWE identifier**
3. **File path** (for SAST findings)
4. **Line number** (within a window, to tolerate minor code movement)
5. **Vulnerability ID** (CVE or tool-specific ID, for SCA)

When a DAST finding for SQL injection at `/api/users` matches an existing SAST finding for SQL injection in `api/users.py`, DefectDojo marks the newer finding as a duplicate and links it to the original. The original finding accumulates evidence from multiple tools, providing higher confidence that the vulnerability is real and not a tool false positive.

Cross-tool deduplication requires that the product's deduplication algorithm is set to `unique_id_from_tool_or_hash` rather than the default `unique_id_from_tool`. The former allows matching across tool boundaries using the hash algorithm; the latter only deduplicates within a single tool's output.

### AppSec Metrics Dashboard

DefectDojo exposes metrics via its API. A Grafana dashboard should track:

- **Open findings by severity**: current snapshot, broken down by product and team
- **Mean time to remediate (MTTR)**: average time from finding opened to Mitigated, by severity tier — the primary indicator of programme effectiveness
- **Vulnerability introduction rate**: new findings per deployment — rising rate indicates deteriorating engineering practices
- **False positive rate**: percentage of findings closed as False Positive — an unusually high rate (above 20%) indicates scanner tuning is required
- **Risk acceptance rate**: percentage of findings closed via risk acceptance rather than remediation — a rising rate indicates accumulating security debt
- **SLA breach rate**: percentage of findings that exceeded their SLA target — should be tracked over time and treated as a leading indicator

Grafana provisioning via the DefectDojo metrics API:

```yaml
# grafana/provisioning/datasources/defectdojo.yaml
apiVersion: 1
datasources:
  - name: DefectDojo
    type: simplejson
    url: https://defectdojo.internal.example.com/api/v2
    jsonData:
      httpHeaderName1: Authorization
    secureJsonData:
      httpHeaderValue1: "Token ${DEFECTDOJO_TOKEN}"
```

### Scaling to Multiple Teams

DefectDojo supports product groups, which allow organising products by team, service domain, or business unit. An organisation with ten engineering squads should configure ten product groups, each containing the products owned by that squad.

Notification routing is product-scoped. Assign each product a security champion from the owning team, and configure DefectDojo to route Critical and High finding notifications directly to the security champion's Slack channel. The central security team receives aggregated notifications for SLA breaches and risk acceptance requests requiring CISO approval.

The DefectDojo API supports programmatic product creation, enabling the security team to automatically provision a DefectDojo product when a new service repository is created, as part of the platform engineering onboarding workflow:

```bash
# Called from repo scaffolding automation
curl -X POST "$DEFECTDOJO_URL/api/v2/products/" \
  -H "Authorization: Token $DEFECTDOJO_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"$SERVICE_NAME\",
    \"description\": \"Auto-provisioned for $TEAM_NAME\",
    \"prod_type\": $PROD_TYPE_ID,
    \"team_manager\": $SECURITY_CHAMPION_USER_ID
  }"
```

## Expected Behaviour

| Tool | Finding Type | DefectDojo Dedup Strategy | Remediation SLA |
|------|-------------|--------------------------|-----------------|
| Semgrep (SAST) | Insecure code patterns, misconfigurations | File path + line number + CWE hash | Critical 24h, High 7d, Medium 30d |
| Trivy (SCA) | Vulnerable dependency CVEs | CVE ID + package name + version | Critical 24h, High 7d (patch available), Medium 30d |
| Gitleaks (Secret Scanning) | Hardcoded secrets, API keys | Secret type + file path + commit hash | All findings treated as Critical: 24h revoke |
| OWASP ZAP (DAST) | Runtime exploitable vulnerabilities | CWE + endpoint URL + parameter | Critical 24h, High 7d |
| Cross-tool duplicate | Same vuln from SAST + DAST | CWE + file/endpoint correlation | Deduped to single finding; DAST confirmation upgrades confidence |

When a Gitleaks finding is imported, DefectDojo immediately fires a webhook to the secrets rotation workflow. The finding SLA clock starts on import; if the secret has not been rotated and the finding mitigated within 24 hours, an automated PagerDuty alert fires to the on-call security engineer.

## Trade-offs

**DefectDojo maintenance overhead.** DefectDojo is a Django application with a Celery worker, Redis, and a PostgreSQL database. Operating it at production quality requires the same care as any other internal platform: backups, upgrades, health monitoring, and capacity planning. Teams that lack platform engineering capacity may find that the operational overhead of running DefectDojo outweighs the benefit over a lighter-weight finding aggregator or a commercial alternative such as Brinqa, Nucleus, or Drata. Evaluate honestly whether the security team has the capacity to own the platform before committing to self-hosting.

**Deduplication false negatives.** DefectDojo's hash-based deduplication works well when tools report the same vulnerability using consistent identifiers. It breaks down at the boundary between DAST and SAST: a ZAP finding for an injected endpoint and a Semgrep finding for the vulnerable source line may not share a CWE or file reference that allows automatic correlation. Cross-tool deduplication of DAST findings requires either manual review or custom deduplication rules tuned to the application's URL structure. Budget time for this tuning during initial deployment — expect it to take several sprint cycles before deduplication rates stabilise.

**Developer workflow friction.** Developers who have not previously worked with DefectDojo will encounter a new tool, a new ticket lifecycle, and a new approval workflow for closing findings. The integration friction is real. Mitigate it by connecting DefectDojo finding notifications to the tools developers already use: Jira (via the DefectDojo Jira integration), Slack, or GitHub Issues. Avoid requiring developers to log into DefectDojo to close tickets; instead, configure bidirectional sync with the existing issue tracker so that closing the Jira ticket propagates the Mitigated status back to DefectDojo.

## Failure Modes

**DefectDojo import failures blocking CI.** The upload step in the CI pipeline must be configured as non-blocking (`if: always()`, with a failure mode that posts a Slack alert rather than failing the build). A DefectDojo outage should not prevent code from shipping; the security programme is a risk management layer, not a deployment gate, unless the organisation has explicitly made that trade-off for Critical severity findings. Implement a dead-letter queue: if the API upload fails, store the scan artifacts in S3 or GCS and retry the upload via a background job when DefectDojo recovers.

**Deduplication missing cross-tool duplicates.** When the deduplication engine fails to link a DAST finding to its SAST equivalent, the team ends up with two open findings for the same vulnerability. The failure mode is subtle: the SAST finding gets fixed, the CI scan stops reporting it, DefectDojo closes it via reimport — but the DAST finding remains open because it is scoped to the staging environment rather than the source file. Establishing a weekly deduplication review process, where a security engineer reviews all open DAST findings alongside open SAST findings, catches the manual linking cases that the algorithm misses.

**Finding closure without verification.** DefectDojo's `close_old_findings=true` parameter on reimport automatically closes findings that no longer appear in the latest scan. This is the correct default, but it creates a risk: if a scanner is misconfigured and stops reporting a class of vulnerabilities (for example, Semgrep rules are narrowed, or ZAP's scan scope is reduced), DefectDojo closes the corresponding findings as mitigated without any actual fix. Monitor for sudden drops in finding counts by scanner as a signal of scanner misconfiguration rather than remediation success. A finding count that drops by more than 30% in a single scan without a corresponding code change should trigger a manual review of the scanner configuration.

## Summary

A unified AppSec programme is not the sum of its tools — it is the integration layer that makes findings actionable. DefectDojo provides that layer: aggregating output from Semgrep, Trivy, Gitleaks, and OWASP ZAP into a single product-scoped finding lifecycle, with deduplication that prevents the same SQL injection from generating three separate tickets, severity normalisation that makes cross-tool prioritisation meaningful, and SLA tracking that converts the question "are we improving?" from an intuition into a measurable trend.

The investment required to stand this up correctly is non-trivial: DefectDojo needs to be operated as a production platform, deduplication rules need tuning, and developer workflow integration requires careful change management. The return on that investment is a security programme that can demonstrate its own effectiveness — which, in the current environment of limited security headcount and competing engineering priorities, is not optional.
