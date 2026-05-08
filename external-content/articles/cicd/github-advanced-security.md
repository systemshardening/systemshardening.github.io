---
title: "GitHub Advanced Security: Secret Scanning, CodeQL, and Dependabot at Scale"
description: "GHAS ships three controls — secret scanning, code scanning with CodeQL, and Dependabot — that organisations routinely leave at defaults. Hardened configuration dramatically changes what gets caught."
slug: "github-advanced-security"
date: 2026-04-29
lastmod: 2026-04-29
category: "cicd"
tags: ["github", "ghas", "secret-scanning", "codeql", "dependabot"]
personas: ["security-engineer", "platform-engineer", "systems-engineer"]
article_number: 242
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/cicd/github-advanced-security/index.html"
---

# GitHub Advanced Security: Secret Scanning, CodeQL, and Dependabot at Scale

## Problem

GitHub Advanced Security (GHAS) bundles three security capabilities into the GitHub platform: secret scanning, code scanning with CodeQL, and Dependabot. All three are available for private repositories on GitHub Enterprise and GitHub.com with GHAS licences; secret scanning and Dependabot are free for public repositories.

Most organisations that have GHAS licences run it at defaults. The defaults miss a substantial fraction of what GHAS can find:

- **Secret scanning** ships with ~230 partner patterns. Custom patterns for internal API key formats, internal tokens, and legacy secret formats are not configured. Push protection is disabled by default for enterprise-wide rollouts. Alerts are created but no one is paged.
- **CodeQL** scans are triggered only on PRs and pushes to the default branch. The default query suite excludes security-extended and experimental queries that find real vulnerabilities. Custom queries for organisation-specific patterns are never written.
- **Dependabot** creates PRs for direct dependency updates. Indirect (transitive) dependency vulnerabilities are reported in the Dependabot alerts tab but not auto-remediated. Auto-merge rules are rarely configured, leading to alert fatigue and stale PRs that are never reviewed.

The result: a GHAS licence that generates noise but doesn't prevent incidents.

By 2026, GHAS integration with GitHub Actions, CodeQL analysis across hundreds of repositories, and organisation-wide security policies via `advanced-security` org settings have made configuration-at-scale the primary challenge.

**Target systems:** GitHub Enterprise Cloud or GitHub Enterprise Server 3.10+; GHAS licence; repositories in Go, Python, JavaScript, TypeScript, Java, C#, Ruby, Kotlin, Swift (CodeQL language support as of 2026).

## Threat Model

- **Adversary 1 — Secret in commit history:** A developer commits an API key or credential to a repository. Without push protection or scanning, the secret is in git history indefinitely and may be cloned by anyone with repo access (or all of the internet for public repos).
- **Adversary 2 — Vulnerable dependency exploitation:** A third-party library has a known CVE. The team is unaware because Dependabot alerts are noise and unenforced. An attacker targeting a known CVE in the library succeeds.
- **Adversary 3 — SQL injection / XSS / RCE in application code:** A CodeQL query would have found the vulnerability, but the scan uses only the default suite and missed the pattern. The vulnerability reaches production.
- **Adversary 4 — Supply chain via transitive dependency:** A direct dependency pulls in a transitive dependency with a critical CVE. Dependabot alerts on the direct dependency but not on the transitive chain without specific configuration.
- **Adversary 5 — Developer bypasses push protection:** Push protection blocks a commit containing a secret, but the developer clicks "bypass" because it's a "test" credential. The bypass is not reviewed.
- **Access level:** Adversary 1 needs read access to the repo (or public access). Adversaries 2 and 3 target the deployed application. Adversary 4 has transitive supply chain access. Adversary 5 is an insider bypass.
- **Objective:** Obtain credentials, exploit application vulnerabilities, introduce malicious dependencies.
- **Blast radius:** A committed AWS secret in a public repo leads to account compromise within minutes (bots scan GitHub continuously). A critical CVE in production with no remediation SLA = indefinite exposure window.

## Configuration

### Step 1: Enable GHAS Organisation-Wide

Enable GHAS for all repositories in an organisation via the API (not just manually per-repo):

```bash
# Enable GHAS for all repos in an org via GitHub API.
# This requires org admin or security manager role.
gh api \
  --method PATCH \
  -H "Accept: application/vnd.github+json" \
  /orgs/{org}/settings/security \
  -f advanced_security_enabled_for_new_repositories=true \
  -f secret_scanning_enabled_for_new_repositories=true \
  -f secret_scanning_push_protection_enabled_for_new_repositories=true \
  -f dependabot_alerts_enabled_for_new_repositories=true \
  -f dependabot_security_updates_enabled_for_new_repositories=true

# Enable on existing repositories (batch).
gh repo list YOUR_ORG --limit 200 --json nameWithOwner -q '.[].nameWithOwner' \
  | xargs -I {} gh api \
      --method PATCH \
      /repos/{} \
      -f security_and_analysis[advanced_security][status]=enabled \
      -f security_and_analysis[secret_scanning][status]=enabled \
      -f security_and_analysis[secret_scanning_push_protection][status]=enabled
```

Alternatively, use Terraform:

```hcl
resource "github_repository" "app" {
  name = "application"

  security_and_analysis {
    advanced_security {
      status = "enabled"
    }
    secret_scanning {
      status = "enabled"
    }
    secret_scanning_push_protection {
      status = "enabled"
    }
  }
}
```

### Step 2: Custom Secret Scanning Patterns

Add organisation-specific patterns for internal token formats that GitHub's built-in patterns don't recognise:

```yaml
# .github/secret-scanning.yml (or via org-level security policy repo)
# Custom patterns: define using regex in PCRE2 format.

patterns:
  - name: "Internal API Key"
    pattern: "myorg_(?:live|test)_[a-zA-Z0-9]{32}"
    additional_match:
      - "myorg"
    test_strings:
      - "myorg_live_abc123def456ghi789jkl012mno345pqr"
    negative_test_strings:
      - "myorg_dev_short"

  - name: "Legacy JWT Secret"
    pattern: "jwt_secret\\s*=\\s*[\"'][A-Za-z0-9+/]{43,}={0,2}[\"']"
    additional_match:
      - "jwt_secret"

  - name: "Database Connection String with Password"
    pattern: "(?:postgres|mysql|mongodb)://[^:]+:([^@]{8,})@"
    additional_match:
      - "://"

  - name: "Internal SSH Private Key Header"
    pattern: "-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY-----"
```

Publish custom patterns via the org-level security configuration repository (if using GitHub Enterprise):

```bash
# Create the org-level security configuration repo.
gh repo create YOUR_ORG/.github --private --description "Org security configuration"

# Push the secret-scanning.yml there; it applies org-wide.
```

### Step 3: Push Protection and Bypass Audit

Push protection blocks commits containing detected secrets before they enter git history. Configure bypass policies and ensure bypasses are audited:

```bash
# Enable push protection org-wide.
gh api \
  --method PATCH \
  /orgs/{org}/settings/secret_scanning \
  -f push_protection_enabled=true

# Configure bypass actors (who can bypass push protection).
# Options: repository admins, security managers, or nobody.
gh api \
  --method PATCH \
  /orgs/{org}/settings/secret_scanning \
  -f push_protection_bypass_role_ids[]="security-managers-team-id"
```

Alert on every bypass via a webhook:

```yaml
# GitHub webhook configuration → security-alerts receiver.
# Event: secret_scanning_alert

# Receiver (example in Python/FastAPI):
@app.post("/webhook/ghas")
async def ghas_webhook(payload: dict, x_github_event: str = Header(None)):
    if x_github_event == "secret_scanning_alert":
        if payload["action"] == "created":
            alert_security_team(
                f"Secret detected: {payload['alert']['secret_type']} "
                f"in {payload['repository']['full_name']}"
            )
        if payload["action"] == "bypass":
            alert_security_team(
                f"Push protection BYPASSED by {payload['alert']['resolved_by']['login']} "
                f"in {payload['repository']['full_name']} — requires review"
            )
```

Enforce: every bypass must be resolved (verified as a false positive, secret rotated, or reported as a risk acceptance) within your defined SLA.

### Step 4: CodeQL — Extended Query Suite

The default CodeQL query suite catches common CWEs. The `security-extended` suite adds patterns with lower confidence that are nonetheless worth reviewing in code review:

```yaml
# .github/workflows/codeql.yml
name: CodeQL

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: "0 3 * * 1"   # Weekly full scan on Monday 3am.

jobs:
  analyze:
    name: Analyze (${{ matrix.language }})
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    strategy:
      matrix:
        language: [python, javascript, go]

    steps:
      - uses: actions/checkout@v4

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}
          # Use security-extended for more coverage; higher false-positive rate.
          queries: security-extended
          # Add custom queries from your org's query pack.
          packs: your-org/codeql-security-queries

      - name: Autobuild
        uses: github/codeql-action/autobuild@v3

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3
        with:
          category: "/language:${{ matrix.language }}"
          # Fail the workflow if any HIGH or CRITICAL alerts are introduced.
          # (Requires GHAS + code scanning enforcement)
```

Custom CodeQL query for organisation-specific patterns:

```ql
// queries/insecure-random-in-token-gen.ql
/**
 * @name Cryptographically insecure random in token generation
 * @description Uses math.random() or similar for security tokens.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id js/insecure-random-token
 * @tags security
 */

import javascript

from CallExpr call
where
  call.getCalleeName() = "random" and
  call.getCalleeNode().toString().matches("Math.random") and
  exists(Assignment assign |
    assign.getRhs() = call and
    assign.getLhs().toString().matches(["token", "secret", "key", "nonce", "salt", "csrf"])
  )
select call, "Math.random() is not cryptographically secure; use crypto.randomBytes()."
```

### Step 5: Code Scanning Enforcement in Branch Protection

Block PRs from merging if they introduce new CodeQL alerts:

```bash
# Via GitHub API: add code scanning as a required status check.
gh api \
  --method PUT \
  /repos/{owner}/{repo}/branches/main/protection \
  --input - <<'EOF'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "CodeQL / Analyze (python)",
      "CodeQL / Analyze (javascript)",
      "CodeQL / Analyze (go)"
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true
  },
  "restrictions": null
}
EOF
```

For GHAS Enterprise, use the code scanning merge protection rule (available in org settings):

```bash
# Enable code scanning merge protection: block PRs that introduce CRITICAL/HIGH alerts.
gh api \
  --method POST \
  /orgs/{org}/code-scanning/default-setup \
  -f state=configured \
  -f query_suite=security-extended \
  -f languages[]="python" \
  -f languages[]="javascript"
```

### Step 6: Dependabot at Scale

Configure Dependabot for every repository with ecosystem-appropriate settings:

```yaml
# .github/dependabot.yml
version: 2

updates:
  - package-ecosystem: npm
    directory: "/"
    schedule:
      interval: weekly
      day: monday
      time: "03:00"
    open-pull-requests-limit: 10
    groups:
      # Group minor/patch updates into one PR to reduce noise.
      minor-and-patch:
        patterns: ["*"]
        update-types: ["minor", "patch"]
    # Auto-merge patch updates that pass CI.
    auto-merge: true

  - package-ecosystem: pip
    directory: "/"
    schedule:
      interval: weekly
    ignore:
      # Ignore major version bumps for framework deps (breaking changes).
      - dependency-name: "django"
        update-types: ["version-update:semver-major"]

  - package-ecosystem: gomod
    directory: "/"
    schedule:
      interval: daily   # Go module updates are low-noise; daily is manageable.
    groups:
      all-go-modules:
        patterns: ["*"]
        update-types: ["minor", "patch"]
```

Configure auto-merge for security updates:

```yaml
# .github/workflows/dependabot-automerge.yml
name: Dependabot auto-merge

on: pull_request

permissions:
  contents: write
  pull-requests: write

jobs:
  auto-merge:
    runs-on: ubuntu-latest
    if: github.actor == 'dependabot[bot]'
    steps:
      - uses: actions/checkout@v4

      - name: Get Dependabot metadata
        id: meta
        uses: dependabot/fetch-metadata@v2

      - name: Auto-merge patch and minor security updates
        if: |
          steps.meta.outputs.update-type == 'version-update:semver-patch' ||
          (steps.meta.outputs.update-type == 'version-update:semver-minor' &&
           steps.meta.outputs.dependency-type == 'direct:production')
        run: gh pr merge --auto --squash "$PR_URL"
        env:
          PR_URL: ${{ github.event.pull_request.html_url }}
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Step 7: Remediation SLAs via GitHub Issues

Track GHAS alert remediation with automated SLA enforcement:

```yaml
# .github/workflows/ghas-sla-check.yml
name: GHAS SLA Enforcement

on:
  schedule:
    - cron: "0 9 * * *"   # Daily at 9am.

jobs:
  sla-check:
    runs-on: ubuntu-latest
    steps:
      - name: Check overdue GHAS alerts
        run: |
          # Find CRITICAL code scanning alerts open > 7 days.
          gh api /repos/${{ github.repository }}/code-scanning/alerts \
            --paginate \
            -q '.[] | select(.state=="open" and .rule.security_severity_level=="critical") |
                {number: .number, rule: .rule.id, created: .created_at, url: .html_url}' \
          | jq -r '. | select(
              (now - (.created | fromdateiso8601)) > (7 * 86400)
            ) | "OVERDUE: \(.rule) alert #\(.number) \(.url)"' \
          | tee overdue-alerts.txt

          if [ -s overdue-alerts.txt ]; then
            echo "::warning::Overdue CRITICAL alerts found"
            cat overdue-alerts.txt | while read line; do
              echo "Alerting: $line"
              # Post to Slack or create a GitHub issue.
            done
          fi
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Step 8: Telemetry

```
ghas_secret_scanning_alerts_open{repo, secret_type}       gauge
ghas_secret_scanning_bypasses_total{repo, user}            counter
ghas_code_scanning_alerts_open{repo, severity, rule}       gauge
ghas_dependabot_alerts_open{repo, ecosystem, severity}     gauge
ghas_dependabot_prs_open{repo, ecosystem}                  gauge
ghas_dependabot_prs_merged_total{repo, update_type}        counter
ghas_alert_mean_time_to_remediate{severity}                histogram
```

Alert on:

- `ghas_secret_scanning_alerts_open` non-zero — any unresolved secret scanning alert is a credential at risk.
- `ghas_secret_scanning_bypasses_total` non-zero — push protection bypassed; requires manual review.
- `ghas_code_scanning_alerts_open{severity="critical"}` > 0 for > 7 days — SLA breach; escalate.
- `ghas_dependabot_alerts_open{severity="critical"}` > 0 for > 14 days — critical vulnerability unpatched.

## Expected Behaviour

| Signal | Default GHAS | Hardened GHAS |
|--------|-------------|--------------|
| Internal API key committed | Not detected (not a built-in pattern) | Detected by custom pattern; push blocked |
| Developer bypasses push protection | Silent | Webhook fires; security team alerted within minutes |
| SQL injection introduced in PR | Possibly caught by default suite | Caught by security-extended suite; PR blocked |
| Critical CVE in dependency | Alert created; no one acts | Auto-PR created; auto-merged if tests pass; escalated if > 14 days |
| CodeQL scan scope | PR + default branch only | PR + weekly full scan + custom queries |
| Alert remediation SLA | None enforced | Daily SLA check; Slack/issue on breach |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| security-extended query suite | More vulnerabilities found | Higher false-positive rate (some queries are medium-confidence) | Triage false positives and dismiss with rationale; retain signal-to-noise ratio. |
| Push protection org-wide | Secrets blocked before entering history | Breaks workflows that test with live credentials (bad practice) | Replace test credentials with dummy values or mocked endpoints; fix the workflow, not the policy. |
| Dependabot auto-merge | Zero-lag patch application | Automated merges can break on API changes in minor updates | Require CI to pass before auto-merge; restrict auto-merge to patch updates only. |
| Custom CodeQL queries | Org-specific vulnerability detection | Query development effort | Start with SAST queries from the CodeQL community; adapt to your codebase. |
| SLA enforcement automation | Compliance pressure to remediate | May generate noise if not tuned | Start with CRITICAL-only SLAs; add HIGH after workflow is established. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Secret scanning pattern too broad | High false-positive rate; developers dismiss all alerts | Alert dismissal rate > 80% | Tighten regex; add `additional_match` context; test with `negative_test_strings`. |
| CodeQL fails to build | Scan silently skipped; no alerts generated | GitHub Actions shows "Autobuild failed"; no code scanning alerts for days | Add explicit build steps to the CodeQL workflow instead of relying on autobuild. |
| Dependabot PR conflicts | PR becomes stale; never merges | Dependabot PRs open > 30 days | Rebase or recreate PRs weekly via Dependabot's "Rebase this PR" comment. |
| Push protection misconfigured for monorepo | Some sub-directories not scanned | Secret in sub-directory committed without alert | Verify scanning covers all directories; push protection is repo-level, not directory-level. |
| GHAS alerts not surfaced to security team | Alerts accumulate unreviewed | Alert age metrics show growing backlog | Route alerts to a dedicated security queue; assign triage rotation. |
| Auto-merge breaks production | A minor version bump contains a breaking change | CI failure post-merge | Require full test suite on Dependabot PRs before auto-merge; pin major versions where APIs are unstable. |

## Related Articles

- [Sigstore Keyless Signing and Cosign Verification](/articles/cicd/sigstore-keyless-signing/)
- [Securing GitHub Actions Workflows](/articles/cicd/securing-github-actions/)
- [Software Supply Chain Third-Party Risk](/articles/cicd/software-supply-chain-third-party-risk/)
- [Dependency Pinning and Integrity Verification](/articles/cicd/dependency-pinning/)
- [Renovate and Dependabot Security Configuration](/articles/cicd/renovate-dependabot-security/)
