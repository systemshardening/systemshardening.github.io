---
title: "Secret Scanning in CI/CD Pipelines: Detecting Leaked Credentials Before They Cause Damage"
description: "Secrets end up in git history through committed .env files, debug logging, and convenience shortcuts. Once pushed, they are permanent without history rewriting. This article covers pre-commit hooks, Gitleaks and TruffleHog integration, GitHub and GitLab native scanning, false positive management, and incident response when a secret is found."
slug: secret-scanning-cicd
date: 2026-05-07
lastmod: 2026-05-07
category: cicd
tags:
  - secret-scanning
  - gitleaks
  - trufflehog
  - pre-commit
  - credential-detection
personas:
  - security-engineer
  - platform-engineer
article_number: 518
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/cicd/secret-scanning-cicd/
---

# Secret Scanning in CI/CD Pipelines: Detecting Leaked Credentials Before They Cause Damage

## Problem

Secrets end up in source code for predictable reasons. A developer copies a `.env` file template and accidentally commits the populated version. An on-call engineer adds `echo $AWS_SECRET_ACCESS_KEY` to debug a failing deploy and forgets to remove it before pushing. A new team member hard-codes an API key to "just get things working" and creates a pull request. A CI job logs environment variables at debug verbosity and the output is stored for 90 days.

Each path ends at the same place: a credential in git history or a build log, accessible to anyone with repository read access and permanently retrievable even after the file is deleted. Deleting a file does not remove it from git history. Setting a variable to an empty string does not remove the original commit. A secret pushed to a remote repository should be treated as compromised from the moment of push.

The cost of a leaked credential depends on its type and scope. A leaked AWS root account key can result in full account compromise within minutes. A leaked database password can expose customer records. A leaked signing key can allow an attacker to produce artifacts that appear legitimate. Automated scanners — bots actively monitoring GitHub, GitLab, and Bitbucket for credential patterns — run constantly. The average time between a secret being pushed to a public repository and first use by an attacker is measured in minutes.

Detection at three layers prevents the damage: pre-commit hooks that block the secret from entering the repository at all, CI pipeline scans that catch anything that slipped through, and continuous history scanning that finds secrets committed weeks or months ago before anyone else does.

## Threat Model

- **Adversary 1 — Automated credential bot:** Bots continuously scan public repositories for patterns matching AWS access keys, GitHub tokens, Stripe API keys, and hundreds of other credential formats. A secret pushed to a public repository is indexed within seconds.
- **Adversary 2 — Insider with read access:** A developer, contractor, or former employee with repository access searches git history for credentials belonging to services they do not have direct access to (production databases, cloud accounts).
- **Adversary 3 — CI log scraping:** An attacker with access to build logs searches for credentials printed by debug statements, verbose dependency installers, or test frameworks that echo environment variables on failure.
- **Adversary 4 — Pull request contributor:** An external contributor opens a PR containing a file with real credentials (malicious or accidental). The PR is visible to all repository contributors before review.
- **Access level:** Adversaries 1 and 4 require only public repository visibility or the ability to open a PR. Adversaries 2 and 3 need authenticated repository access.
- **Objective:** Obtain a working credential to access cloud infrastructure, databases, third-party APIs, or internal services.
- **Blast radius:** A single leaked credential with broad IAM permissions or a shared service account can result in data exfiltration, infrastructure destruction, or persistent backdoor access.

## Configuration

### Step 1: Pre-Commit Hook with detect-secrets

`detect-secrets` from Yelp provides a baseline approach: it scans the repository once to record all current potential secrets (many of which are false positives), then fails future commits that introduce *new* potential secrets. This reduces noise compared to tools that scan without context.

```bash
pip install detect-secrets
```

Initialize a baseline file, which records all current findings so they are not re-flagged:

```bash
detect-secrets scan > .secrets.baseline
```

Review the baseline before committing it. Any real secrets in the baseline must be rotated:

```bash
detect-secrets audit .secrets.baseline
```

Add the pre-commit hook configuration:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.5.0
    hooks:
      - id: detect-secrets
        args:
          - --baseline
          - .secrets.baseline
          # Exclude test fixtures and generated files.
          - --exclude-files
          - "tests/fixtures/.*"
          - --exclude-files
          - ".*\\.min\\.js$"
```

Install the hooks:

```bash
pre-commit install
```

Commit the baseline alongside the hook configuration. Future commits that introduce a new high-entropy string or a pattern matching a known credential format will fail with a list of the flagged lines.

### Step 2: Gitleaks Pre-Commit Hook with Custom Rules

Gitleaks uses regex rules to match specific credential formats. It ships with over 150 built-in rules covering AWS, GCP, Azure, GitHub, Stripe, Twilio, and many others.

```bash
# Install Gitleaks.
brew install gitleaks          # macOS
# Or download binary from https://github.com/gitleaks/gitleaks/releases
```

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.2
    hooks:
      - id: gitleaks
```

The default configuration covers most credential formats. For internal systems (internal API gateways, internal PKI tokens, custom service account formats), add a `.gitleaks.toml`:

```toml
# .gitleaks.toml
title = "Gitleaks configuration"

# Extend the built-in rules.
[extend]
useDefault = true

# Custom rule for internal service tokens.
[[rules]]
id = "internal-service-token"
description = "Internal service account token"
regex = '''svc_[a-zA-Z0-9]{32,}'''
tags = ["internal", "service-account"]

# Custom rule for internal API gateway keys.
[[rules]]
id = "apigw-key"
description = "Internal API gateway key"
regex = '''apigw-key-[0-9a-f]{40}'''
tags = ["internal", "api"]

# Allowlist: paths that should never be scanned.
[allowlist]
description = "Global allowlist"
paths = [
  # Test fixtures intentionally contain credential-shaped strings.
  '''tests/fixtures/.*''',
  # Vendored dependencies — not our code.
  '''vendor/.*''',
  # Generated lockfiles contain hash strings that trigger false positives.
  '''.*\.lock$''',
]

# Allowlist: specific strings known to be safe (test values, example outputs).
[[rules.allowlist]]
description = "Example values in documentation"
regexes = [
  # Placeholder patterns used in docs and comments.
  '''EXAMPLE_KEY_REPLACE_ME''',
  '''YOUR_API_KEY_HERE''',
]
```

A `.gitleaksignore` file can suppress specific findings by their fingerprint (a hash of the finding location):

```bash
# Generate fingerprints for known false positives.
gitleaks detect --report-format json --report-path /tmp/report.json
# The report includes a "Fingerprint" field per finding.
# Add the fingerprint to .gitleaksignore, one per line.
```

```
# .gitleaksignore
# False positive: test fixture with a fake Stripe key used in unit tests.
3b4c2d1e8f9a0b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9
```

### Step 3: Gitleaks GitHub Actions Integration

Run Gitleaks on every push and pull request. The GitHub Actions integration posts findings as PR annotations.

```yaml
# .github/workflows/secret-scan.yml
name: Secret Scanning

on:
  push:
    branches: ["**"]
  pull_request:
    branches: ["**"]

permissions:
  contents: read
  # Required for PR annotations.
  pull-requests: read

jobs:
  gitleaks:
    name: Detect secrets with Gitleaks
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
        with:
          # Fetch full history for accurate delta scanning.
          fetch-depth: 0

      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          # GITLEAKS_LICENSE is required for the GitHub org/enterprise
          # report-to-PR feature. Omit for the standard scan-and-fail behaviour.
          # GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}
        with:
          # Scan only commits in the push/PR (not full history on every run).
          args: detect --source=. --log-opts="${{ github.event.before }}..HEAD"
```

For repositories where history has never been scanned, run a one-time full history scan:

```yaml
      - name: Full history scan (first run only)
        if: github.event_name == 'workflow_dispatch'
        run: |
          gitleaks detect \
            --source=. \
            --report-format sarif \
            --report-path gitleaks-report.sarif \
            --exit-code 0
      
      - name: Upload SARIF to GitHub Security tab
        if: github.event_name == 'workflow_dispatch'
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: gitleaks-report.sarif
```

### Step 4: TruffleHog for Deep History Scanning

TruffleHog goes further than pattern matching: it verifies findings against live APIs before reporting. An AWS key is checked against the AWS API; a GitHub token is checked against the GitHub API. This dramatically reduces false positives.

```yaml
# .github/workflows/trufflehog.yml
name: TruffleHog Secret Scanning

on:
  # Run on schedule to catch secrets in branches and historical commits.
  schedule:
    - cron: "0 2 * * *"   # Daily at 02:00 UTC.
  workflow_dispatch:
  push:
    branches: [main]

permissions:
  contents: read
  # Required to post Security alerts.
  security-events: write

jobs:
  trufflehog:
    name: TruffleHog
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
        with:
          fetch-depth: 0

      - name: TruffleHog OSS scan
        uses: trufflesecurity/trufflehog@v3
        with:
          # Scan full git history.
          extra_args: >-
            git file://.
            --since-commit HEAD~100
            --only-verified
            --fail
```

Run TruffleHog locally for a deep scan before pushing a new feature branch:

```bash
# Scan git history for verified secrets.
trufflehog git file://. --since-commit main --only-verified --fail

# Scan a specific commit range.
trufflehog git file://. \
  --since-commit a1b2c3d4 \
  --branch HEAD \
  --only-verified

# Scan a GitHub repository without cloning.
trufflehog github --repo https://github.com/your-org/your-repo \
  --only-verified \
  --include-detectors=all
```

The `--only-verified` flag suppresses unverified findings. For air-gapped environments where verification API calls cannot be made, omit the flag but expect higher false-positive rates.

### Step 5: GitHub Native Secret Scanning and Push Protection

GitHub Advanced Security provides secret scanning for private repositories and push protection that blocks pushes containing known credential patterns before they land in the repository.

Enable secret scanning and push protection in repository settings:

```
Settings → Security → Code security and analysis:
  ☑ Secret scanning: Enabled
  ☑ Push protection: Enabled
    ☑ Prevent secret scanning bypass for push protection
```

For organizations, enforce these settings via policy:

```bash
# Enable push protection for all repositories in the organization.
gh api \
  --method PATCH \
  /orgs/YOUR_ORG/secret-scanning/push-protection-bypass-policy \
  -f bypass_policy_type=not_allowed

# List all open secret scanning alerts.
gh api \
  /repos/YOUR_ORG/YOUR_REPO/secret-scanning/alerts \
  --jq '.[] | select(.state == "open") | {number: .number, secret_type: .secret_type, created_at: .created_at}'
```

Reviewing and resolving alerts:

```bash
# List alerts filtered by type.
gh api \
  "/repos/YOUR_ORG/YOUR_REPO/secret-scanning/alerts?secret_type=aws_access_key_id&state=open"

# Close an alert as a false positive (document the reason).
gh api \
  --method PATCH \
  /repos/YOUR_ORG/YOUR_REPO/secret-scanning/alerts/42 \
  -f state=resolved \
  -f resolution=false_positive \
  -f resolution_comment="Test fixture value; not a real key"
```

### Step 6: GitLab Secret Detection CI Component

GitLab provides secret detection as a first-class CI security template:

```yaml
# .gitlab-ci.yml
include:
  - template: Security/Secret-Detection.gitlab-ci.yml

stages:
  - test

variables:
  # Scan only the commits in this pipeline (default).
  SECRET_DETECTION_HISTORIC_SCAN: "false"

# Override the included job to add custom configuration.
secret_detection:
  stage: test
  variables:
    # Fail the pipeline on detected secrets (do not just report).
    SECRET_DETECTION_LOG_OPTIONS: "--exit-code 1"
```

For a one-time historical scan against a large existing repository:

```yaml
# Run as a manual job (not on every commit).
secret_detection_historical:
  extends: secret_detection
  variables:
    SECRET_DETECTION_HISTORIC_SCAN: "true"
  rules:
    - when: manual
      allow_failure: false
```

GitLab Ultimate tier also provides push rules to reject pushes containing secrets:

```
Settings → Repository → Push rules:
  ☑ Reject secrets in commits: Enabled
```

### Step 7: Handling False Positives

False positives are the main friction point that leads teams to disable scanners. The right response is to classify them explicitly rather than disable detection.

**Gitleaks allowlist by fingerprint** (preferred — surgical, does not affect other findings):

```bash
# Get the fingerprint for a specific finding.
gitleaks detect --report-format json --report-path /tmp/gl.json
cat /tmp/gl.json | jq -r '.[].Fingerprint'
# Add the fingerprint to .gitleaksignore.
```

**detect-secrets allowlist by file and line** (for test fixtures):

```bash
# Mark a specific line as a false positive in the baseline.
detect-secrets audit .secrets.baseline
# Answer 'n' (not a real secret) for each false positive.
# The baseline is updated with the false positive marked.
```

**Naming conventions that reduce noise** — name test credential variables with patterns that tools can recognize as non-real:

```python
# In test code, use clearly fake values.
TEST_AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"   # AWS documents this as an example key.
FAKE_STRIPE_KEY = "sk_test_PLACEHOLDER_NOT_REAL_0000000000000000"
```

**Exclude generated and vendored paths globally:**

```toml
# .gitleaks.toml
[allowlist]
paths = [
  '''vendor/''',
  '''node_modules/''',
  '''\.yarn/''',
  '''dist/''',
  '''.*_test\.go$''',    # Go test files with fixture data.
]
```

### Step 8: Responding to a Detected Secret

When a scanner finds a real secret in repository history or a build log, the response has a mandatory first step: rotate immediately, before doing anything else. Do not assess blast radius first. Do not try to scrub history while the credential is still live.

**Immediate rotation checklist:**

1. Revoke the credential at the issuing service (AWS IAM, GitHub, Stripe dashboard, etc.).
2. Issue a replacement credential and update all legitimate references.
3. Review the audit logs of the compromised service for access by unexpected principals or from unexpected IPs during the period the secret was exposed.
4. Notify your security team and document the timeline.

**Rewriting git history with git-filter-repo** (after the credential is rotated):

```bash
pip install git-filter-repo

# Remove a specific file from all history.
git filter-repo --path secrets.env --invert-paths

# Replace a specific string (the leaked credential value) with a placeholder.
echo "LEAKEDVALUE123==>REDACTED" > /tmp/replacements.txt
git filter-repo --replace-text /tmp/replacements.txt

# Force-push to all remotes (coordinate with the team first).
git push origin --force --all
git push origin --force --tags
```

History rewriting does not eliminate the exposure — the secret was visible on the remote between the original push and the rewrite, and anyone who cloned or forked the repository in that window has a copy. It is necessary to prevent future exposure and to satisfy compliance requirements, but it does not substitute for rotation.

**Preventing bypass with HMAC-based verification tokens:**

Pattern-based scanners can be bypassed by encoding secrets (base64, hex, split across lines). HMAC-based tokens replace the raw secret in application code: the application receives a token identifier, looks up the actual value from a secrets manager at runtime, and never has the raw credential in source.

```python
# Instead of:
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Use a reference that cannot be used directly:
AWS_SECRET_KEY_REF = "vault:secret/aws/production#secret_access_key"
# The application resolves this reference at startup via the Vault SDK.
```

This is a complementary control, not a replacement for scanning. See the [CI/CD Secret Management](/articles/cicd/cicd-secret-management/) article for full implementation details.

## Expected Behaviour

| Layer | Without scanning | With scanning |
|-------|-----------------|---------------|
| Developer commit with `.env` file | Secret enters git history | Pre-commit hook blocks the commit |
| PR from fork containing API key | Secret visible to all reviewers | GitHub push protection rejects the push |
| Debug `echo` left in pipeline script | Credential appears in 90-day build log | CI Gitleaks scan fails the build |
| Legacy secret committed 6 months ago | Discoverable by anyone with repo access | TruffleHog scheduled scan detects and alerts |
| Suppressed false positive | Either accepted (noise) or scanner disabled | Explicit allowlist entry with documented reason |

## Trade-offs

| Control | Benefit | Cost | Mitigation |
|---------|---------|------|------------|
| Pre-commit hooks | Stops secrets before they are pushed | Developer can skip with `--no-verify` | Enforce scanning in CI as the authoritative gate; pre-commit is a fast feedback loop |
| `--only-verified` in TruffleHog | Near-zero false positives | Unverifiable secrets (internal APIs, rotated keys) are not reported | Run a separate unverified scan on a schedule; triage findings manually |
| GitHub push protection | Platform-enforced block on known secret patterns | Developers can request a bypass with a reason | Disable bypass for repositories handling production credentials |
| Full history rewrite | Removes the secret from future clones | Disrupts all existing clones; requires force-push; not retroactive for forks | Coordinate with team; require all contributors to re-clone; file a DMCA takedown request for public forks if necessary |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Pre-commit hook skipped with `--no-verify` | Secret bypasses local scanning | CI pipeline scan catches the pushed secret | Enforce CI scanning as the mandatory gate; alert on `--no-verify` usage in commit metadata |
| Scanner false negative on obfuscated secret | Base64-encoded credential not detected | TruffleHog verified scan would catch live credentials | Add entropy detection to complement pattern matching; require runtime secret references |
| Allowlist entry too broad | Real secrets suppressed by a path pattern | Manual review of allowlist entries quarterly | Allowlist by fingerprint, not by path, wherever possible |
| History rewrite causes merge conflicts | Contributors cannot push after force-push | Contributors report push rejection | Coordinate the rewrite; announce in advance; require re-clone |
| Rotation breaks production | New credential not propagated to all consumers | Application error rate spikes post-rotation | Maintain a documented credential inventory; use a staged rotation (add new, deploy, remove old) |

## Related Articles

- [CI/CD Secret Management: Vault, SOPS, and OIDC Federation](/articles/cicd/cicd-secret-management/)
- [Securing GitHub Actions: Permissions, Pinning, and Workflow Injection Prevention](/articles/cicd/securing-github-actions/)
- [GitLab CI Security: Protected Variables, Runner Isolation, and Pipeline Hardening](/articles/cicd/gitlab-ci-security/)
- [GitHub Advanced Security](/articles/cicd/github-advanced-security/)
- [Branch Protection and Code Review Enforcement](/articles/cicd/branch-protection-code-review/)
