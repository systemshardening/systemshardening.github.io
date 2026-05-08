---
title: "GitHub Advanced Security at Enterprise Scale: Push Protection, Code Scanning Policies, and Autofix"
description: "GitHub Advanced Security (GHAS) includes secret scanning with push protection, CodeQL code scanning, dependency review, and Copilot Autofix — but default configuration leaves most of its security value on the table. This guide covers enterprise-wide GHAS enablement, push protection bypass governance, organisation-level code scanning policies, custom secret patterns, and measuring AppSec programme effectiveness with GHAS security overview."
slug: github-advanced-security-enterprise
date: 2026-05-08
lastmod: 2026-05-08
category: cicd
tags:
  - github-advanced-security
  - ghas
  - secret-scanning
  - code-scanning
  - push-protection
personas:
  - security-engineer
  - platform-engineer
article_number: 644
difficulty: Intermediate
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/cicd/github-advanced-security-enterprise/
---

# GitHub Advanced Security at Enterprise Scale: Push Protection, Code Scanning Policies, and Autofix

## Problem

GitHub Advanced Security (GHAS) is an application security platform built into GitHub. It covers four functional areas: secret scanning with push protection, code scanning via CodeQL, dependency review, and (with a Copilot licence) Autofix. Each area provides real detection value — but every one of them ships with defaults that leave large gaps.

Common gaps in enterprise GHAS deployments:

- **Code scanning is not enabled uniformly.** New repositories are created without scanning. Repositories in less-active languages are excluded. Organisations with hundreds of repos have a long tail of unscanned code.
- **Push protection is configured as alerting-only.** Secret scanning generates alerts after the push. The default does not block the push. Secrets reach the remote, get cloned, and propagate through CI caches and forks before the alert is triaged.
- **No custom secret patterns for internal credentials.** GHAS ships with roughly 200 partner patterns covering major SaaS providers. Internal API keys, service account tokens, internal JWTs, and legacy credential formats used by the organisation's own services are not detected unless custom patterns are defined.
- **Autofix suggestions are applied without quality review.** Copilot Autofix generates a fix PR for CodeQL findings. The fix addresses the surface symptom but does not always resolve the root cause, and can introduce subtle regressions if merged without review.
- **Security Overview is not reviewed.** GHAS provides an organisation-level dashboard showing open alerts by severity, mean time to remediate, and repositories without scanning. Most organisations never open it.

Beyond configuration gaps, enterprise rollout has operational challenges. With thousands of repositories across multiple organisations, bulk enablement requires scripting. Language mix is uneven — CodeQL supports Go, Python, JavaScript/TypeScript, Java, C#, Ruby, Kotlin, and Swift, but not every language in a polyglot environment. Developers experiencing high false-positive rates from custom patterns or overly aggressive query suites will bypass controls or suppress alerts. Push protection bypass workflows need to exist for legitimate cases (copying a revoked key for rotation purposes, testing with expired credentials), but those bypasses must be audited or they become permanent holes.

GHAS scope boundaries also matter. GHAS covers:
- **Secrets in source code** via secret scanning and push protection
- **Known vulnerability patterns in application code** via CodeQL static analysis
- **Vulnerable dependencies** via Dependabot and dependency review

GHAS does not cover runtime behaviour, infrastructure configuration drift, container image vulnerabilities at deploy time, or network-level threats. It operates entirely on source code and dependencies. Combining GHAS with runtime security (Falco, eBPF tracing) and infrastructure scanning (Trivy, Checkov) is required for comprehensive coverage.

## Threat Model

**Scenario 1: Developer accidentally commits an API key — push protection not enabled.**
A developer runs `git commit -m "fix: add service client"` and includes a config file with a real API key. Without push protection blocking the commit, the key reaches the remote, is picked up by bots monitoring GitHub for credential patterns within seconds, and the associated service account is compromised. A GHAS secret scanning alert is created, but it takes hours before anyone on the security team sees it. The key has already been used.

**Scenario 2: CodeQL false negative — default queries miss a vulnerability class.**
A Java service has a custom deserialization pattern that leads to remote code execution. The default CodeQL query suite includes standard deserialization sinks but does not cover the organisation's internal serialisation library. Without a custom CodeQL query targeting that library's deserialise methods, the vulnerability passes code review and reaches production. An attacker with network access exploits it six months later.

**Scenario 3: Push protection bypass without justification — secret goes unrotated.**
A developer is blocked pushing a commit that contains a test API key, which is actually a real key they copied from a shared Slack message. They click the bypass option with reason "testing credential." The bypass is logged in the GitHub audit log, but no automation reads the audit log to alert the security team. The key remains unrotated in the repository's commit history for four months.

## Configuration

### Enterprise-Wide GHAS Enablement

Enabling GHAS one repository at a time is unscalable. Use the GitHub REST API to enable GHAS across an entire organisation:

```bash
# Enable GHAS for a single repository.
gh api \
  --method PATCH \
  -H "Accept: application/vnd.github+json" \
  /repos/{owner}/{repo} \
  -f "security_and_analysis[advanced_security][status]=enabled"
```

For bulk enablement across all repositories in an organisation, iterate with `gh api` and the `/orgs/{org}/repos` paginated endpoint:

```bash
#!/usr/bin/env bash
# bulk-enable-ghas.sh — enables GHAS on every repo in an org.
# Requires: gh CLI authenticated with admin:org and repo scopes.
set -euo pipefail

ORG="${1:?Usage: $0 <org>}"
PAGE=1
PER_PAGE=100

while true; do
  REPOS=$(gh api \
    -H "Accept: application/vnd.github+json" \
    "/orgs/${ORG}/repos?per_page=${PER_PAGE}&page=${PAGE}&type=all" \
    --jq '.[].name')

  [[ -z "$REPOS" ]] && break

  while IFS= read -r REPO; do
    echo "Enabling GHAS on ${ORG}/${REPO}..."
    gh api \
      --method PATCH \
      -H "Accept: application/vnd.github+json" \
      "/repos/${ORG}/${REPO}" \
      -f "security_and_analysis[advanced_security][status]=enabled" \
      --silent || echo "  WARN: failed for ${REPO}"
  done <<< "$REPOS"

  (( PAGE++ ))
done
echo "Done."
```

Run this script from a GitHub Actions workflow with a scheduled trigger to catch newly-created repositories. Track enablement coverage from the GitHub Security Overview at **`github.com/orgs/{org}/security`** — the summary card shows what percentage of repositories have GHAS features active.

At the enterprise level, set policies via **Enterprise Settings → Policies → Code security** to require GHAS on all repositories in all organisations under the enterprise account. This prevents org admins from disabling GHAS after it has been enabled.

### Secret Scanning Push Protection

Enabling GHAS turns on secret scanning in alerting mode. Enabling push protection requires an additional step at the organisation level:

```bash
# Enable push protection for the whole organisation.
gh api \
  --method PATCH \
  -H "Accept: application/vnd.github+json" \
  /orgs/{org} \
  -f "secret_scanning_push_protection_enabled_for_new_repositories=true"
```

For existing repositories, the bulk enablement script above can additionally set `security_and_analysis[secret_scanning_push_protection][status]=enabled` per repository.

**Custom secret patterns** are the highest-leverage configuration investment for push protection. Every organisation has internal credential formats that the built-in partner patterns do not cover. Define them under **Organisation Settings → Security → Secret scanning → Custom patterns**:

```
Pattern name: Internal Service API Key
Secret format: [A-Z]{3}-[0-9]{8}-[a-f0-9]{32}
Test string:   SVC-20260401-a3f2b1c4d5e6f7a8b9c0d1e2f3a4b5c6
```

Write custom patterns for:
- Internal API gateway tokens (typically organisation-specific prefix + random hex)
- Internal JWT signing secrets (often base64-encoded strings of a fixed length)
- Database connection strings with embedded credentials
- Machine account SSH private keys stored inline

Test every custom pattern in the GitHub pattern tester before deploying. A pattern that matches filenames, log output, or test fixtures will generate alert fatigue that causes developers to suppress all push protection warnings.

**Bypass governance** is as important as enabling push protection. Developers will occasionally have legitimate reasons to push a commit containing a pattern match: copying a revoked key for incident documentation, adding a pattern as a test fixture with the secret already rotated. The bypass must be auditable.

Configure bypass governance via a GitHub Actions workflow that queries the audit log API and alerts the security team on every bypass:

```yaml
# .github/workflows/push-protection-bypass-alert.yml
name: Push Protection Bypass Monitor

on:
  schedule:
    - cron: "*/15 * * * *"   # Poll audit log every 15 minutes.
  workflow_dispatch:

jobs:
  check-bypasses:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - name: Query audit log for push protection bypasses
        env:
          GH_TOKEN: ${{ secrets.SECURITY_AUDIT_TOKEN }}
          ORG: ${{ vars.ORG_NAME }}
        run: |
          SINCE=$(date -u -d '15 minutes ago' +%Y-%m-%dT%H:%M:%SZ)
          BYPASSES=$(gh api \
            -H "Accept: application/vnd.github+json" \
            "/orgs/${ORG}/audit-log?phrase=action:secret_scanning.push_protection_bypass&per_page=100" \
            --jq "[.[] | select(.created_at >= \"${SINCE}\")]")

          COUNT=$(echo "$BYPASSES" | jq 'length')
          if [[ "$COUNT" -gt "0" ]]; then
            echo "ALERT: ${COUNT} push protection bypass(es) in the last 15 minutes."
            echo "$BYPASSES" | jq -r '.[] | "User: \(.actor) | Repo: \(.repo) | Reason: \(.reason // "none provided") | Time: \(.created_at)"'
            # Post to your security team Slack channel or create an issue.
            # Replace with your notification integration.
            exit 1
          fi
          echo "No bypasses in the last 15 minutes."
```

Hold a weekly review of bypass events. Any bypass where the reason is blank, generic ("testing"), or unverifiable should trigger a credential rotation request to the developer.

### Code Scanning at Scale

GHAS provides two code scanning setup modes: default setup and advanced setup.

**Default setup** uses GitHub-managed CodeQL configuration. GitHub detects the repository language and runs appropriate query suites. It requires no configuration file and is the right choice for repositories that do not have custom security requirements or unusual language toolchains.

**Advanced setup** uses a `.github/workflows/codeql.yml` file in the repository. It is required when you need:
- Custom CodeQL query packs
- Extended or experimental query suites
- Language-specific build steps (C/C++, Java with non-standard build systems)
- Scan scheduling beyond the defaults (e.g., nightly full scans in addition to PR scans)

At enterprise scale, manage advanced setup templates centrally. Keep a canonical `codeql.yml` workflow in an `.github` repository (the special repository that provides default files for all repositories in the organisation). All repositories without their own `codeql.yml` inherit the organisation default.

For enterprises with GitHub Enterprise Cloud, configure **organisation-level code scanning default configuration** under **Organisation Settings → Code security and analysis → Code scanning → Set up default**. This enables default setup across all eligible repositories with one action.

**Enforcing code scanning as a branch protection check** prevents merging PRs with unresolved high-severity alerts. Under **Branch protection rules** for the default branch, add a required status check for the CodeQL analysis workflow:

```
Required status checks:
  ✓ CodeQL / Analyze (javascript)
  ✓ CodeQL / Analyze (python)
  ✓ CodeQL / Analyze (go)
```

Pair this with a code scanning alert policy that blocks merging when alerts of `high` or `critical` severity are open against the PR's changed files. Configure this under **Rulesets → Repository rules → Code scanning results**.

### CodeQL Configuration at Scale

Manage CodeQL configuration via a central file and distribute it through all repositories. Store the canonical configuration in a policy repository:

```yaml
# .github/codeql/codeql-config.yml
# Managed centrally — do not edit in individual repositories.
name: "Enterprise CodeQL Config"

queries:
  - uses: security-extended       # Adds ~50 more queries vs default.
  - uses: security-and-quality    # Adds quality-related security patterns.
  - uses: myorg/codeql-custom-queries@v1.2.0   # Internal query pack.

paths-ignore:
  - "vendor/**"
  - "third_party/**"
  - "**/*_test.go"    # Exclude test files from results (reduce noise).
  - "**/*.generated.*"

query-filters:
  - exclude:
      tags contain: "experimental"    # Exclude experimental queries in prod.
```

Reference this config from the central `codeql.yml` workflow using `config-file: .github/codeql/codeql-config.yml`.

### Custom CodeQL Query Deployment

Custom CodeQL queries target organisation-specific vulnerability classes: internal library misuse, proprietary authentication bypass patterns, or custom serialization sinks. Package custom queries as a CodeQL query pack and publish them to GitHub Packages.

Directory structure for a custom query pack:

```
codeql-custom-queries/
  qlpack.yml
  queries/
    java/
      InternalDeserializationSink.ql
      CustomAuthBypass.ql
    python/
      InternalTemplateInjection.ql
```

`qlpack.yml`:

```yaml
name: myorg/codeql-custom-queries
version: 1.2.0
library: false
dependencies:
  codeql/java-all: "*"
  codeql/python-all: "*"
```

Publish to GitHub Packages:

```bash
codeql pack publish --github-auth-stdin <<< "$GITHUB_TOKEN"
```

Pin the version in `codeql-config.yml` (`@v1.2.0`, not `@latest`) to prevent new queries rolling out to all repositories without review. Increment the version and update the central config via a PR with security team approval.

### Copilot Autofix

Copilot Autofix generates a suggested code change PR for CodeQL findings. When a code scanning alert is reviewed in the GitHub Security tab, an "Autofix" button generates a patch that attempts to remediate the vulnerability.

**Where Autofix works well:**
- SQL injection via parameterised query substitution (high confidence, mechanical fix)
- Path traversal via canonical path checks
- XSS via output encoding
- Insecure hash algorithm substitution (MD5 → SHA-256)
- Hardcoded credential removal (replacing literal with environment variable reference)

**Where Autofix performs poorly:**
- Business logic flaws where the fix requires understanding application context
- Vulnerabilities in framework-specific code where Autofix generates syntactically valid but semantically incorrect patches
- Multi-file vulnerabilities where the root cause spans more than one file
- C/C++ memory safety issues where ownership semantics must be preserved

**Review workflow for Autofix:**

1. CodeQL scan creates an alert on the default branch or a PR.
2. Autofix generates a fix PR (labelled `autofix/...`).
3. A security champion reviews the PR against three criteria:
   - Does the fix address the root cause, or only the symptom reported by CodeQL?
   - Does the fix introduce new behaviour that could be exploited (e.g., swallowing exceptions, changing null handling)?
   - Does the fix pass the existing test suite without modification?
4. Security champion approval is required before merging. Do not enable auto-merge for Autofix PRs.
5. After merging, verify the original CodeQL alert is closed (not just dismissed).

Autofix is a productivity tool, not an autonomous remediation system. Treat it as a well-informed first draft that still requires human judgement.

### Dependency Review

The `dependency-review-action` GitHub Action blocks PRs that introduce dependencies with high-severity vulnerabilities or unacceptable licences. Add it to all repositories via the central workflow template:

```yaml
# .github/workflows/dependency-review.yml
name: Dependency Review

on:
  pull_request:
    branches: ["main"]

permissions:
  contents: read
  pull-requests: write

jobs:
  dependency-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/dependency-review-action@v4
        with:
          fail-on-severity: high
          allow-licenses: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC
          deny-licenses: GPL-3.0, AGPL-3.0
          comment-summary-in-pr: always
          # Warn on (but do not block) packages with no licence metadata.
          warn-on-openssf-scorecard-level: 5
```

This configuration blocks merging if the PR adds a dependency with a CVE at `high` or `critical` severity that has no fix available. The license allowlist prevents accidental introduction of copyleft dependencies.

### Security Overview Metrics

GitHub Security Overview provides an organisation-level view of AppSec programme health. Access it at `github.com/orgs/{org}/security`. Key metrics to review weekly:

- **Repositories without scanning enabled:** Any non-zero value needs remediation.
- **Open alerts by severity:** Track the ratio of critical/high to medium/low alerts over time. A rising critical count with flat remediation indicates SLA non-compliance.
- **Mean time to remediate (MTTR) by severity:** Target MTTR < 7 days for critical, < 30 days for high. Security Overview computes this automatically.
- **Alert age distribution:** Alerts open for > 90 days at critical severity are candidates for exception review or SLA enforcement.

Export Security Overview data via the GraphQL API for custom dashboards:

```graphql
query OrgSecurityAlerts($org: String!, $cursor: String) {
  organization(login: $org) {
    repositories(first: 100, after: $cursor) {
      pageInfo { hasNextPage endCursor }
      nodes {
        name
        vulnerabilityAlerts(first: 100, states: [OPEN]) {
          totalCount
          nodes {
            createdAt
            securityVulnerability {
              severity
              package { name }
              advisory { summary }
            }
          }
        }
        codeScanning: codeAlerts: alertsByRepository {
          # Use REST API for code scanning; GraphQL support is partial.
        }
      }
    }
  }
}
```

For code scanning alert export, use the REST API:

```bash
gh api \
  -H "Accept: application/vnd.github+json" \
  "/orgs/{org}/code-scanning/alerts?per_page=100&state=open&severity=high,critical" \
  --paginate \
  | jq -r '.[] | [.rule.id, .most_recent_instance.location.path, .created_at, .repository.name] | @csv' \
  > high-critical-alerts.csv
```

Load this output into your security metrics dashboard (Grafana, Tableau, or a simple spreadsheet) to track MTTR trends across the organisation.

## Expected Behaviour

| GHAS Feature | Default State | Hardened State | Evidence of Effectiveness |
|---|---|---|---|
| Secret scanning | Alerting only; partner patterns only | Push protection enabled; custom internal patterns defined | Zero secrets committed to main since push protection enabled; bypass count per week trending down |
| Code scanning | Default setup on manually-enabled repos only | Default or advanced setup on all repos; security-extended queries; branch protection blocks high/critical | CodeQL alert backlog size and MTTR tracked in Security Overview; no critical alerts older than 7 days |
| Dependency review | No PR blocking; Dependabot alerts only | dependency-review-action on all PRs; blocks high/critical; licence policy enforced | No new high/critical dependency CVEs introduced via PRs; zero GPL introductions |
| Copilot Autofix | No Autofix review process; fixes applied directly | Autofix PR requires security champion approval; fix quality checklist | Autofix acceptance rate tracked; regression rate post-merge tracked via test failures |
| Security Overview | Not monitored | Weekly security review meeting uses Security Overview; MTTR tracked; 100% repo scanning coverage target | MTTR by severity chart; coverage percentage trending to 100% |
| Push protection bypass | Bypasses not audited | Every bypass triggers security team alert; weekly bypass review; credential rotation required for unjustified bypasses | Bypass count and justification quality tracked weekly |

## Trade-offs

**CodeQL scan duration.** CodeQL analysis for a large Java or C# monorepo takes 15–30 minutes. On high-frequency PR workflows, this adds meaningful latency to the developer feedback loop. Mitigate by running lightweight default setup on PR triggers and full extended-suite scans on a nightly schedule. Use CodeQL caching (the `cache: autosave` option in the action) to reduce incremental scan time.

**Developer friction from push protection.** Push protection blocks a push mid-workflow, which is more disruptive than a post-push alert. Some developers will experience false positives from custom patterns matching test fixtures or documentation. Budget time for custom pattern tuning and establish a clear bypass process with a reasonable reason taxonomy (e.g., "already rotated", "test credential that was never valid", "false positive — adding suppression comment"). A bypass process that requires extensive justification will be circumvented creatively.

**Autofix false-fix rate.** Copilot Autofix is not perfect. In internal benchmarks published by GitHub, Autofix correctly resolves the vulnerability in approximately 75–85% of cases for well-supported languages (JavaScript, Python). For less-common languages or complex multi-step fixes, the rate drops. The review workflow above catches false fixes before they merge; the trade-off is the added latency of human review.

**Custom pattern false positive rate.** Overly broad regex patterns for internal credentials will match comments, log output, generated code, and test fixtures. A pattern matching 50 false positives for every 1 real credential is worse than no pattern: it trains developers to dismiss push protection warnings. Start patterns as narrow as possible and widen only when false negatives are reported.

## Failure Modes

**CodeQL timing out on monorepos.** CodeQL has a default timeout of 6 hours for database creation and query execution. Large monorepos with millions of lines of Java or generated code can exceed this. Mitigations: exclude generated code directories in `codeql-config.yml` (`paths-ignore`), split the monorepo into per-language scan jobs, reduce the query suite to `security-and-quality` instead of `security-extended` for the first scan, then expand.

**Push protection bypasses not reviewed.** The audit log workflow above works only if the `SECURITY_AUDIT_TOKEN` has `read:audit_log` scope and the workflow is not disabled or rate-limited. Establish a fallback: a weekly manual export of the audit log filtered for `secret_scanning.push_protection_bypass` events. If the automation fires zero alerts for two weeks, investigate whether it is working or whether there genuinely are no bypasses.

**Custom patterns matching non-secrets.** A pattern written to match a 32-character hex string followed by `@` is likely to match UUIDs, commit hashes, and email addresses in comments. Test every pattern against a representative sample of your codebase before deploying as push protection (as opposed to alerting-only, which can run for a week in shadow mode). Use GitHub's pattern testing UI: the "Dry run" option runs the pattern against recent push history and shows matches before protection is enforced.

**Autofix introducing regressions.** Autofix-generated PRs pass CodeQL analysis because they fix the specific pattern the query targets. They do not necessarily pass unit tests, integration tests, or the broader CI pipeline. Ensure that Autofix PRs are subject to the same required status checks as any other PR. A security champion approving an Autofix PR without waiting for CI to complete has bypassed the safety net.

## References

- [GitHub Docs: Enabling GitHub Advanced Security for your enterprise](https://docs.github.com/en/enterprise-cloud@latest/admin/code-security/managing-github-advanced-security-for-your-enterprise)
- [GitHub Docs: About push protection](https://docs.github.com/en/code-security/secret-scanning/push-protection-for-repositories-and-organizations)
- [GitHub Docs: Custom secret scanning patterns](https://docs.github.com/en/code-security/secret-scanning/defining-custom-patterns-for-secret-scanning)
- [GitHub Docs: CodeQL query packs](https://docs.github.com/en/code-security/codeql-cli/using-the-advanced-functionality-of-the-codeql-cli/publishing-and-using-codeql-packs)
- [GitHub Docs: Configuring code scanning at scale using CodeQL](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/configuring-code-scanning-at-scale)
- [actions/dependency-review-action](https://github.com/actions/dependency-review-action)
- [GitHub Docs: About Copilot Autofix for code scanning](https://docs.github.com/en/code-security/code-scanning/managing-code-scanning-alerts/about-autofix-for-codeql-code-scanning)
- [GitHub Docs: Security overview for organisations](https://docs.github.com/en/code-security/security-overview/about-security-overview)
