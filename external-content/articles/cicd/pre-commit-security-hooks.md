---
title: "Pre-Commit Hooks for Security Enforcement in Development Workflows"
description: "Pre-commit hooks catch secrets, misconfigurations, and vulnerable code at commit time — before they reach CI or a remote repository. This article covers the pre-commit framework, key security hooks, team-wide enforcement, and the architectural limits of client-side hooks."
slug: pre-commit-security-hooks
date: 2026-05-07
lastmod: 2026-05-07
category: cicd
tags:
  - pre-commit
  - git-hooks
  - developer-security
  - shift-left
  - secret-detection
personas:
  - security-engineer
  - platform-engineer
article_number: 521
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/cicd/pre-commit-security-hooks/
---

# Pre-Commit Hooks for Security Enforcement in Development Workflows

## Problem

A secret committed to a repository is harder to contain than a secret that never leaves a developer's terminal. Even if a repository is private, secrets committed to git history persist across clones, forks, CI caches, and backup snapshots. By the time a CI scanner raises an alert, the secret has already traversed the network, touched a remote, and been visible to anyone with repository access.

The same applies to infrastructure misconfigurations and known vulnerable code patterns. A Terraform module with overly permissive IAM, a Dockerfile running as root, or a Python function calling `eval()` on untrusted input: these are all cheaper to fix before they enter the commit graph than after they have been reviewed, merged, and deployed.

Pre-commit hooks move security checks to the earliest possible point in the development loop — the moment a developer runs `git commit`. The feedback is immediate, the fix cost is low, and the developer context (what they were just working on) is still fresh. This is the practical meaning of shifting security left.

**Target systems:** git 2.x; the `pre-commit` framework (Python); `detect-secrets`, `gitleaks`, `git-secrets`, `checkov`, `hadolint`, `bandit`, `shellcheck`; husky (Node.js); server-side git hooks.

## Threat Model

- **Adversary 1 — Accidental secret commit:** A developer hard-codes a database password or API key while debugging, intends to remove it before committing, and forgets. The secret reaches the remote repository, where CI logs, pull request previews, and other consumers see it.
- **Adversary 2 — Misconfigured IaC committed and merged:** A Terraform change opens an S3 bucket to `"*"` or a Kubernetes manifest drops all security contexts. No hook checks the IaC before it is committed; the change goes undetected until a reviewer notices — or it does not.
- **Adversary 3 — Vulnerable code pattern introduced:** A developer introduces a shell injection via unsanitised `subprocess.call(user_input, shell=True)`. Bandit would flag it; without a pre-commit hook, the pattern reaches code review where it may or may not be caught by a reviewer unfamiliar with Python security.
- **Access level:** These are insider-risk or unintentional-error scenarios. The developer has full repository write access. No external attacker involvement is needed.
- **Objective:** Detect and block the commit locally, before it is pushed to any remote.
- **Blast radius:** Without hooks, secrets in private repositories have a containment window of seconds (time to push). In public repositories, secret scanners operated by credential providers (GitHub, AWS, etc.) detect and invalidate known formats, but not all credentials have automatic revocation.

## Configuration

### Step 1: Install the pre-commit Framework

The `pre-commit` framework (https://pre-commit.com) manages hook installation, virtualenv isolation, and versioning for a collection of hooks defined in a single YAML file. It is the standard approach for polyglot repositories.

```bash
# Install system-wide or into a project virtual environment.
pip install pre-commit

# Verify.
pre-commit --version
```

### Step 2: Create `.pre-commit-config.yaml`

Place this file at the repository root. It is checked into version control so every developer runs the same hook versions.

```yaml
# .pre-commit-config.yaml
# Pin hook versions to avoid unexpected behaviour on updates.
# Run `pre-commit autoupdate` periodically to advance pinned revs.

repos:
  # ── Secret detection ───────────────────────────────────────────────────────

  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.5.0
    hooks:
      - id: detect-secrets
        args: ["--baseline", ".secrets.baseline"]
        # Exclude generated files and known-safe test fixtures.
        exclude: >
          (?x)^(
            tests/fixtures/.*|
            \.secrets\.baseline$
          )$

  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.2
    hooks:
      - id: gitleaks

  # ── Infrastructure as Code ─────────────────────────────────────────────────

  - repo: https://github.com/bridgecrewio/checkov
    rev: 3.2.400
    hooks:
      - id: checkov
        args:
          - "--quiet"
          - "--compact"
          # Fail on HIGH and CRITICAL only during development.
          # Tighten to MEDIUM in CI.
          - "--check"
          - "HIGH,CRITICAL"
        files: \.(tf|tfvars|json|yaml|yml)$

  # ── Dockerfile linting ─────────────────────────────────────────────────────

  - repo: https://github.com/hadolint/hadolint
    rev: v2.13.1-beta
    hooks:
      - id: hadolint-docker
        args:
          # Deny specific rules that have security implications.
          - "--failure-threshold"
          - "warning"
          - "--deny"
          - "DL3002"  # Last USER should not be root.
          - "--deny"
          - "DL3008"  # Pin package versions in apt-get.

  # ── Python security ────────────────────────────────────────────────────────

  - repo: https://github.com/PyCQA/bandit
    rev: 1.8.3
    hooks:
      - id: bandit
        args: ["-c", "pyproject.toml"]
        files: \.py$
        exclude: tests/

  # ── Shell scripts ──────────────────────────────────────────────────────────

  - repo: https://github.com/koalaman/shellcheck-precommit
    rev: v0.10.0
    hooks:
      - id: shellcheck
        args: ["--severity=warning"]

  # ── General hygiene ────────────────────────────────────────────────────────

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: check-added-large-files
        args: ["--maxkb=500"]
      - id: check-merge-conflict
      - id: check-yaml
      - id: check-json
      - id: detect-private-key
      - id: end-of-file-fixer
      - id: mixed-line-ending
      - id: no-commit-to-branch
        args: ["--branch", "main", "--branch", "master"]
```

Install the hooks into the local git repository:

```bash
pre-commit install
pre-commit install --hook-type commit-msg
pre-commit install --hook-type pre-push
```

### Step 3: Initialise a `detect-secrets` Baseline

`detect-secrets` works by comparing staged content against a baseline of known-safe patterns. Initialise the baseline on first setup to avoid false positives from existing content.

```bash
# Scan the repo and create an initial baseline.
# Review the output before committing — it lists every potential secret found.
detect-secrets scan > .secrets.baseline

# Audit the baseline: mark each finding as a true or false positive.
detect-secrets audit .secrets.baseline

# Commit the baseline.
git add .secrets.baseline
git commit -m "chore: add detect-secrets baseline"
```

On subsequent commits, `detect-secrets` flags only new potential secrets not in the baseline.

### Step 4: Configure Bandit via `pyproject.toml`

Bandit severity levels map to security impact. Configure skip lists carefully — skipping a test globally is the wrong response to a false positive.

```toml
# pyproject.toml
[tool.bandit]
exclude_dirs = ["tests", "venv", ".venv"]
# Skips: none by default. Add only after documented review.
# skips = ["B101"]  # B101 = assert statements — only skip in test code.
severity = "medium"
confidence = "medium"
```

For test directories, assert statements are expected. Use inline suppression rather than a global skip:

```python
# In test code only — never in production code paths.
assert response.status_code == 200  # noqa: S101
```

### Step 5: Enforce Installation Across the Team

The pre-commit framework only runs hooks in repositories where `pre-commit install` has been executed. A developer who clones the repository and never runs the install command gets no hooks. Enforcement requires making the install step unavoidable.

**Makefile target:**

```makefile
# Makefile

.PHONY: setup
setup: ## Set up the development environment.
	@command -v pre-commit >/dev/null 2>&1 || pip install pre-commit
	pre-commit install
	pre-commit install --hook-type commit-msg
	pre-commit install --hook-type pre-push
	@echo "pre-commit hooks installed."

# Make setup a prerequisite for common targets.
.PHONY: test
test: setup
	pytest

.PHONY: lint
lint: setup
	ruff check .
```

**Onboarding script (run once after cloning):**

```bash
#!/usr/bin/env bash
# scripts/dev-setup.sh
# Run this after cloning the repository.
set -euo pipefail

echo "Installing development dependencies..."

# Python tooling.
pip install -r requirements-dev.txt

# pre-commit hooks.
pre-commit install
pre-commit install --hook-type commit-msg
pre-commit install --hook-type pre-push

# Verify hooks are active.
if ! grep -q "pre-commit" .git/hooks/pre-commit 2>/dev/null; then
  echo "ERROR: pre-commit hook installation failed."
  exit 1
fi

echo "Setup complete. Hooks are active."
```

**CI verification that hooks ran:**

In CI, run all hooks against the diff between the PR branch and the base branch. This catches cases where a developer bypassed hooks locally.

```yaml
# .github/workflows/pre-commit-ci.yml
name: pre-commit checks

on:
  pull_request:
  push:
    branches: [main]

jobs:
  pre-commit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip

      - name: Install pre-commit
        run: pip install pre-commit

      - name: Run hooks against changed files
        # Uses the official pre-commit CI action which caches hook environments.
        uses: pre-commit/action@v3.0.1

      - name: Run hooks against all files (weekly full scan)
        if: github.event_name == 'schedule'
        run: pre-commit run --all-files
```

The `pre-commit/action` action caches virtualenvs by hook repo and revision, keeping CI fast. The weekly full-file run catches issues in files that were never touched in recent PRs.

### Step 6: Commit-Msg Hooks

A `commit-msg` hook validates the commit message itself before the commit is recorded. Use it to enforce conventional commit format and ticket references — both have security relevance (ticket references are required for change management traceability; conventional commit types like `fix:` and `feat:` feed automated changelogs and release notes).

```bash
#!/usr/bin/env bash
# .git/hooks/commit-msg
# Or manage via pre-commit with a commit-msg hook.
set -euo pipefail

COMMIT_MSG_FILE="$1"
COMMIT_MSG=$(cat "$COMMIT_MSG_FILE")

# Conventional commits pattern.
CONVENTIONAL_PATTERN="^(feat|fix|docs|style|refactor|test|chore|ci|revert|perf|security)(\(.+\))?: .{1,72}"

if ! echo "$COMMIT_MSG" | grep -qP "$CONVENTIONAL_PATTERN"; then
  echo "ERROR: Commit message does not follow Conventional Commits format."
  echo "  Expected: <type>(<scope>): <description>"
  echo "  Example:  fix(auth): prevent token reuse after logout"
  echo "  Types: feat|fix|docs|style|refactor|test|chore|ci|revert|perf|security"
  exit 1
fi

# Ticket reference check (optional — enable if your team uses a tracker).
# TICKET_PATTERN="(JIRA-[0-9]+|GH-[0-9]+|#[0-9]+)"
# if ! echo "$COMMIT_MSG" | grep -qP "$TICKET_PATTERN"; then
#   echo "ERROR: Commit message must reference a ticket (e.g. JIRA-1234)."
#   exit 1
# fi

exit 0
```

Manage the `commit-msg` hook through pre-commit by adding a local hook:

```yaml
# In .pre-commit-config.yaml, add:
  - repo: local
    hooks:
      - id: conventional-commit-msg
        name: Conventional commit message format
        language: script
        entry: scripts/check-commit-msg.sh
        stages: [commit-msg]
        pass_filenames: false
```

### Step 7: Pre-Push Hooks for Slower Checks

Pre-commit hooks run on every commit and must be fast (under a few seconds) to avoid disrupting developer flow. Slower checks belong in `pre-push` hooks, which run once when the developer runs `git push`.

```yaml
# In .pre-commit-config.yaml, add stages to slower hooks:

  - repo: https://github.com/bridgecrewio/checkov
    rev: 3.2.400
    hooks:
      - id: checkov
        stages: [pre-push]  # Run at push, not every commit.
        args: ["--quiet", "--compact"]
        files: \.(tf|tfvars)$
```

```bash
# Install the pre-push hook.
pre-commit install --hook-type pre-push
```

Pre-push hooks are appropriate for:

- Full Checkov or tfsec scans of all IaC (slow for large repos)
- Dependency vulnerability scans (`pip-audit`, `npm audit`)
- Integration test runs
- Container image builds and scans

### Step 8: Husky for Node.js Projects

For Node.js projects where Python tooling is undesirable, husky provides the same lifecycle hook management using npm scripts.

```bash
npm install --save-dev husky lint-staged
npx husky init
```

```json
// package.json
{
  "scripts": {
    "prepare": "husky"
  },
  "lint-staged": {
    "*.{js,ts,jsx,tsx}": [
      "eslint --max-warnings=0",
      "prettier --check"
    ],
    "*.{json,yaml,yml}": [
      "prettier --check"
    ],
    "Dockerfile*": [
      "hadolint"
    ]
  }
}
```

```bash
# .husky/pre-commit
#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

# Run lint-staged (only checks staged files — fast).
npx lint-staged

# Run gitleaks on staged content.
gitleaks protect --staged --redact
```

```bash
# .husky/commit-msg
#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

npx commitlint --edit "$1"
```

`commitlint` enforces conventional commits in Node.js projects, equivalent to the bash `commit-msg` hook above.

The `prepare` script in `package.json` means `npm install` automatically installs husky hooks — solving the same team-adoption problem that the Makefile `setup` target solves for Python projects.

## The Architectural Limit: Pre-Commit is Not a Security Boundary

This is the most important section in this article.

**Any developer can bypass pre-commit hooks with a single flag:**

```bash
git commit --no-verify -m "push anyway"
git push --no-verify
```

The `--no-verify` flag skips all client-side hooks entirely. No detection. No log entry. No audit trail. Client-side hooks are developer tooling, not a security control.

This has several implications for your security architecture:

**Pre-commit hooks are not a replacement for CI checks.** Every security check that matters must also run in CI, on infrastructure the developer does not control. The pre-commit hook provides fast, local feedback. CI provides the enforcing layer.

**Secrets committed with `--no-verify` will be caught by CI secret scanning.** Configure your CI pipeline to run `gitleaks` or `trufflehog` on every push, with a non-zero exit code that blocks the build and prevents the pull request from merging.

```yaml
# .github/workflows/secret-scan.yml
name: Secret scanning

on: [push, pull_request]

jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history — scan all commits in the push.
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Server-side hooks are the enforcing layer.** For self-hosted git servers (Gitea, GitLab self-managed, Bitbucket Data Center, Gerrit), server-side `pre-receive` hooks run on the server when a push is received and can reject the push before it is accepted into the repository. Unlike client-side hooks, these cannot be bypassed by `--no-verify`.

```bash
#!/usr/bin/env bash
# Server-side pre-receive hook (place in repository's hooks/pre-receive).
# Rejects pushes containing secrets detected by gitleaks.

while IFS=' ' read -r old_rev new_rev ref_name; do
  if [[ "$old_rev" == "0000000000000000000000000000000000000000" ]]; then
    # New branch — scan all commits being pushed.
    range="$new_rev"
  else
    range="${old_rev}..${new_rev}"
  fi

  if ! gitleaks detect \
    --source . \
    --log-opts "$range" \
    --redact \
    --exit-code 1 \
    --quiet; then
    echo "REJECTED: gitleaks detected secrets in this push."
    echo "Rotate the affected credentials immediately."
    exit 1
  fi
done

exit 0
```

GitHub, GitLab, and Bitbucket Cloud operate their own server-side secret scanning on every push and will notify (or block, with the right settings) on detected credentials.

## Telemetry

Track hook bypass and CI finding correlation to understand how often developers are skipping local checks:

```
pre_commit_bypass_total{repo, hook_id}           counter  # from CI: finding present but hook should have caught it
ci_secret_scan_finding_total{repo, severity}     counter
ci_iac_scan_finding_total{repo, check_id}        counter
pre_receive_rejection_total{repo, reason}        counter
```

Alert on:

- `pre_receive_rejection_total` — a push was rejected server-side; the developer bypassed local hooks and tried to push a secret. Treat as a security event, not a developer mistake.
- Rising `ci_secret_scan_finding_total` with no corresponding increase in `pre_commit_bypass_total` — hooks may not be installed across the team; audit.

## Expected Behaviour

| Action | No hooks configured | Hooks installed and running |
|--------|--------------------|-----------------------------|
| Developer commits a hardcoded API key | Succeeds silently; reaches remote | `detect-secrets` and `gitleaks` block the commit; developer rotates before pushing |
| Terraform opens S3 bucket to `"*"` | Committed and pushed | `checkov` fails at pre-commit; developer fixes IAM policy |
| Dockerfile sets `USER root` at end | Committed and pushed | `hadolint` fails; developer adds non-root USER instruction |
| Developer runs `git commit --no-verify` | N/A | Commit succeeds locally; CI secret scan catches it and blocks the PR |
| New developer clones and commits without running setup | No hooks active | Makefile `setup` target installs hooks; `prepare` script in npm installs husky |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Fast local feedback | Developer fixes issues immediately with full context | Hook failures interrupt commit flow | Keep hooks fast (< 5s); move slow checks to pre-push |
| Shared `.pre-commit-config.yaml` | Consistent check versions across all developers | Updating hook versions requires a PR and review | Use `pre-commit autoupdate` on a schedule; review diffs in the update PR |
| `detect-secrets` baseline | Avoids false positives on existing content | Baseline can become stale and mask real secrets | Audit the baseline quarterly; regenerate after large refactors |
| Bandit for Python | Catches common vulnerability patterns at commit time | High false-positive rate on some rules (B101, B404) | Tune via `pyproject.toml`; use inline `# noqa: S<id>` with documented rationale |
| husky for Node.js projects | No Python dependency for JS teams | `prepare` only runs on `npm install`; not all environments run it | Document in README; add CI verification step |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Developer bypasses with `--no-verify` | Secret or misconfiguration reaches remote | CI secret scan finds it; `pre_receive_rejection_total` rises | Revoke the secret; retrain the developer; verify CI blocking is active |
| Hook virtualenv becomes corrupted | `pre-commit` errors on commit; developers disable hooks | Developer reports hook errors | Run `pre-commit clean` then `pre-commit install`; document in onboarding |
| `detect-secrets` baseline out of date | Hook fails on pre-existing content; developers skip | Developers report false positives on unchanged files | Run `detect-secrets scan --update .secrets.baseline`; audit and commit |
| Hook version pinned too old | Known bypass for old hook version; new secret patterns undetected | Manual review of hook changelogs; dependabot alerts on hook repos | Run `pre-commit autoupdate`; test against baseline before merging |
| Pre-commit not installed on CI runner | CI does not re-check for hook bypasses | PR merges with issues CI should have caught | Add `pre-commit run --all-files` as a required CI check |

## Related Articles

- [CI/CD Secret Management](/articles/cicd/cicd-secret-management/)
- [Branch Protection and Code Review Security at Scale](/articles/cicd/branch-protection-code-review/)
- [Securing GitHub Actions Workflows](/articles/cicd/securing-github-actions/)
- [Dependency Pinning and Supply Chain Integrity](/articles/cicd/dependency-pinning/)
- [SLSA Provenance and Build Integrity](/articles/cicd/slsa-provenance/)
