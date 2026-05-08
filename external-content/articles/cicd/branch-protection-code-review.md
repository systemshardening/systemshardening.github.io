---
title: "Branch Protection and Code Review Security at Scale"
description: "Branch protection rules prevent force-pushes, require review, and gate on status checks. At scale across hundreds of repos, enforcement requires the Rulesets API, CODEOWNERS, and automated compliance checks."
slug: "branch-protection-code-review"
date: 2026-04-30
lastmod: 2026-04-30
category: "cicd"
tags: ["branch-protection", "code-review", "codeowners", "github", "supply-chain"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 266
difficulty: "intermediate"
estimated_reading_time: 12
published: true
layout: article.njk
permalink: "/articles/cicd/branch-protection-code-review/index.html"
---

# Branch Protection and Code Review Security at Scale

## Problem

Code review is the last human gate before code reaches production. Branch protection rules enforce that gate: they prevent direct pushes to protected branches, require review approvals, and block merges when required status checks fail. Without them, a developer — or an attacker with developer credentials — can push directly to `main` and bypass all CI security checks.

At scale, branch protection has additional failure modes:

- **Inconsistent enforcement.** Rules are configured per-repository by repository owners. New repos created by developers often have no protection. A supply chain attacker targets the least-protected repository.
- **Admin bypass.** Repository admins are often exempt from protection rules (`enforce admins: false`). An attacker who compromises an admin account pushes directly to `main`.
- **Review rubber-stamping.** Approval requirements exist, but the same person can approve their own team's PRs, or approvals are given without reading the diff. Stale reviews (approved before subsequent commits) persist.
- **CODEOWNERS not enforced.** Security-critical files (IAM policies, Terraform state, pipeline configuration) don't have mandatory reviewers. A developer unfamiliar with security implications merges a change.
- **Status checks not required.** CI passes optional security scans but they're not blocking. PRs merge despite CodeQL findings.

**Target systems:** GitHub (Enterprise Cloud and Server 3.9+), GitLab 16+, Bitbucket Cloud; GitHub Rulesets API (GitHub Enterprise); CODEOWNERS syntax; `gh` CLI for bulk configuration.

## Threat Model

- **Adversary 1 — Direct push to main:** A developer account is compromised. The attacker pushes malicious code directly to the default branch, bypassing CI and review. Without branch protection, this deploys to production immediately.
- **Adversary 2 — Admin account takeover + branch protection bypass:** A repository admin account is compromised. The attacker disables branch protection, merges a backdoored commit, re-enables protection. Without `enforce admins: true`, this is silent.
- **Adversary 3 — Self-approval on security-critical change:** A developer modifies a security policy file (`terraform/iam.tf`, `.github/workflows/deploy.yml`) and approves their own PR (if they have another account), or gets a colleague to approve without understanding the change. Without CODEOWNERS pointing a security team to the review, nobody with security expertise sees it.
- **Adversary 4 — Stale approval bypass:** A PR is reviewed and approved. The developer pushes additional commits containing malicious changes. The stale approval persists. Without stale review dismissal, the PR merges with the malicious changes unchecked.
- **Adversary 5 — New unprotected repository:** A developer creates a new repository for a service that will be deployed to production. No protection rules are applied by default. An attacker targets it.
- **Access level:** Adversary 1 has developer credentials. Adversaries 2 and 3 have developer or admin credentials. Adversary 4 has developer credentials and an approved PR. Adversary 5 needs only network access to push code to the unprotected repo.
- **Objective:** Introduce malicious code to the production deployment pipeline without triggering review controls.
- **Blast radius:** A direct push to `main` with no review gate can deploy arbitrary code to production within minutes of the push. CODEOWNERS violations lead to unreviewed changes to security-critical infrastructure.

## Configuration

### Step 1: GitHub Rulesets for Org-Wide Enforcement

GitHub Rulesets (available in Enterprise and organisation-level settings) apply branch protection rules to all repositories in an organisation simultaneously, including new ones created after the ruleset is configured.

```bash
# Create an org-level ruleset via the GitHub API.
gh api \
  --method POST \
  /orgs/{org}/rulesets \
  --input - <<'EOF'
{
  "name": "default-branch-protection",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": ["~DEFAULT_BRANCH"],
      "exclude": []
    },
    "repository_name": {
      "include": ["~ALL"],
      "exclude": ["sandbox-*", "test-*"]
    }
  },
  "rules": [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {"type": "required_linear_history"},
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": true,
        "require_last_push_approval": true,
        "allowed_merge_methods": ["squash", "merge"]
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "required_status_checks": [
          {"context": "CodeQL / Analyze (python)", "integration_id": 0},
          {"context": "CodeQL / Analyze (javascript)", "integration_id": 0},
          {"context": "security-scan", "integration_id": 0}
        ]
      }
    },
    {"type": "required_signatures"}
  ],
  "bypass_actors": [
    {
      "actor_id": 1,
      "actor_type": "OrganizationAdmin",
      "bypass_mode": "pull_request"
    }
  ]
}
EOF
```

Key rules in the ruleset:

- `"type": "deletion"` — prevents branch deletion.
- `"type": "non_fast_forward"` — prevents force-pushes (rewrites history).
- `"dismiss_stale_reviews_on_push": true` — removes approvals when new commits are pushed (closes stale approval bypass).
- `"require_last_push_approval": true` — the person who pushed the last commit cannot be the approver.
- `"require_code_owner_review": true` — CODEOWNERS-defined owners must approve changes to their paths.
- `"required_signatures"` — commits must be GPG-signed.
- `bypass_actors` with `bypass_mode: pull_request` — admins can bypass only via PRs, not direct push.

### Step 2: CODEOWNERS for Security-Critical Paths

```
# .github/CODEOWNERS
# Format: <pattern>  <owner> [<owner2> ...]
# Owners are GitHub usernames, team names (@org/team), or email addresses.

# Default: any change requires review from the platform team.
*                                   @myorg/platform-team

# IAM and access control changes: security team required.
terraform/iam/                      @myorg/security-team
terraform/iam/**                    @myorg/security-team
.github/workflows/                  @myorg/security-team
.github/CODEOWNERS                  @myorg/security-team

# Deployment configuration: SRE team required.
kubernetes/                         @myorg/sre-team
helm/                               @myorg/sre-team
Makefile                            @myorg/sre-team

# Database schema changes: DBA team required.
db/migrations/                      @myorg/dba-team

# Security policies (Kyverno, OPA): security team required.
policies/                           @myorg/security-team

# CI/CD pipeline configuration: security team + platform team.
.github/workflows/deploy.yml        @myorg/security-team @myorg/platform-team
.github/workflows/release.yml       @myorg/security-team @myorg/platform-team

# Package manifests: security scan required (enforced by CI, not CODEOWNERS reviewer).
package.json                        @myorg/security-team
requirements.txt                    @myorg/security-team
go.mod                              @myorg/security-team
```

CODEOWNERS is only effective when `require_code_owner_review: true` is set in branch protection. Without that setting, CODEOWNERS is informational only.

### Step 3: Enforce Admin Compliance

The `enforce admins: true` equivalent in Rulesets is not exempting org admins from the bypass rules:

```bash
# Check if any repositories have admins exempt from protection.
gh api /orgs/{org}/repos --paginate --jq '.[].name' | while read repo; do
  rule=$(gh api /repos/{org}/$repo/branches/main/protection 2>/dev/null | \
    jq -r '.enforce_admins.enabled // "not-protected"')
  if [[ "$rule" == "false" || "$rule" == "not-protected" ]]; then
    echo "RISK: $repo admin bypass enabled"
  fi
done
```

With Rulesets, bypass_actors of type `OrganizationAdmin` with `bypass_mode: pull_request` means admins must still submit PRs — they just don't need approvals. This is a reasonable emergency access pattern while closing the direct-push bypass.

### Step 4: Commit Signing Enforcement

Require signed commits to verify developer identity:

```bash
# Enable commit signing requirement for the main branch.
# Already included in the Ruleset above as "required_signatures".

# Developers: configure GPG signing.
git config --global commit.gpgsign true
git config --global user.signingkey <key-id>

# Or use SSH signing (GitHub supports since 2022).
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub

# Add the signing key to GitHub.
gh ssh-key add ~/.ssh/id_ed25519.pub --type signing
```

In CI pipelines, sign commits using a bot GPG key:

```yaml
# .github/workflows/auto-pr.yml
- name: Import GPG key
  uses: crazy-max/ghaction-import-gpg@v6
  with:
    gpg_private_key: ${{ secrets.BOT_GPG_PRIVATE_KEY }}
    passphrase: ${{ secrets.BOT_GPG_PASSPHRASE }}
    git_user_signingkey: true
    git_commit_gpgsign: true
```

### Step 5: Automate Compliance Checks Across Repos

Run nightly to detect drift from the expected ruleset:

```bash
#!/bin/bash
# check-branch-protection-compliance.sh
# Checks that all production repositories meet protection standards.

REQUIRED_APPROVALS=1
REQUIRED_CHECKS=("CodeQL / Analyze (python)" "security-scan")
VIOLATIONS=()

repos=$(gh api /orgs/{org}/repos --paginate \
  --jq '.[] | select(.archived == false and .fork == false) | .name')

for repo in $repos; do
  protection=$(gh api /repos/{org}/$repo/branches/main/protection 2>/dev/null)

  if [ -z "$protection" ]; then
    VIOLATIONS+=("$repo: no branch protection on main")
    continue
  fi

  # Check required reviews.
  required_reviews=$(echo $protection | jq -r \
    '.required_pull_request_reviews.required_approving_review_count // 0')
  if [[ $required_reviews -lt $REQUIRED_APPROVALS ]]; then
    VIOLATIONS+=("$repo: required approvals = $required_reviews (need $REQUIRED_APPROVALS)")
  fi

  # Check enforce admins.
  enforce_admins=$(echo $protection | jq -r '.enforce_admins.enabled // false')
  if [[ $enforce_admins == "false" ]]; then
    VIOLATIONS+=("$repo: admins not subject to protection rules")
  fi

  # Check stale review dismissal.
  dismiss_stale=$(echo $protection | jq -r \
    '.required_pull_request_reviews.dismiss_stale_reviews // false')
  if [[ $dismiss_stale == "false" ]]; then
    VIOLATIONS+=("$repo: stale reviews not dismissed on push")
  fi
done

if [ ${#VIOLATIONS[@]} -gt 0 ]; then
  echo "BRANCH PROTECTION VIOLATIONS:"
  for v in "${VIOLATIONS[@]}"; do
    echo "  - $v"
  done
  exit 1
fi
echo "All repositories compliant."
```

Run in CI on a schedule:

```yaml
on:
  schedule:
    - cron: "0 9 * * *"
jobs:
  compliance-check:
    runs-on: ubuntu-latest
    steps:
      - run: ./scripts/check-branch-protection-compliance.sh
        env:
          GH_TOKEN: ${{ secrets.ORG_READ_TOKEN }}
```

### Step 6: PR Size and Complexity Limits

Large PRs are rarely reviewed carefully. Enforce size limits:

```yaml
# .github/workflows/pr-size-check.yml
name: PR size check

on: pull_request

jobs:
  size-check:
    runs-on: ubuntu-latest
    steps:
      - name: Check PR size
        uses: CodelyTV/pr-size-labeler@v1
        with:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          xs_label: 'size/XS'
          xs_max_size: 10
          s_label: 'size/S'
          s_max_size: 100
          m_label: 'size/M'
          m_max_size: 500
          l_label: 'size/L'
          l_max_size: 1000
          xl_label: 'size/XL'
          fail_if_xl: true    # Block XL PRs; force splitting.
          message_if_xl: "This PR is too large for effective review. Please split it into smaller changes."
```

For security-critical paths (from CODEOWNERS), require two reviewers on large changes:

```yaml
# Second required review for large security-policy changes.
# In Ruleset: set required_approving_review_count: 2 for the policies/ path.
# Or: use a separate ruleset with higher review count for security-critical paths.
```

### Step 7: Telemetry

```
branch_protection_violation_total{repo, violation_type}       counter
pr_merged_without_required_review_total{repo}                 counter
codeowner_review_required_total{repo, path_owner}             counter
codeowner_review_bypassed_total{repo}                         counter
commit_unsigned_total{repo}                                   counter
direct_push_to_protected_branch_total{repo, user}             counter
```

Alert on:

- `branch_protection_violation_total` — a repo is out of compliance; fix immediately.
- `direct_push_to_protected_branch_total` — this should never happen with Rulesets; if it does, admin bypass was used without proper process.
- `codeowner_review_bypassed_total` — a merge happened without CODEOWNERS review; investigate.

## Expected Behaviour

| Signal | No branch protection | Hardened branch protection |
|--------|---------------------|---------------------------|
| Developer pushes to `main` directly | Succeeds | Blocked; PR required |
| Admin force-pushes to override | Succeeds silently | Blocked (ruleset bypass_mode=pull_request) |
| PR approved, then new malicious commit added | Old approval persists; merges | Stale review dismissed; re-review required |
| Security-critical file changed without security team review | Merges without expertise | CODEOWNERS blocks merge until required owner approves |
| New repository created | No protection by default | Org Ruleset applies automatically |
| Unsigned commits | Accepted | Blocked by required_signatures rule |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Org-level Rulesets | Consistent enforcement; covers new repos | Some repos have legitimate exceptions | Use repo-name conditions in Ruleset to exclude sandbox/test repos explicitly. |
| `enforce admins: true` | No bypass path for admins | Slows legitimate emergency changes | Allow admin bypass via PR only (bypass_mode: pull_request); document emergency process. |
| Stale review dismissal | Prevents post-approval injection | Developers must re-request review after fixing feedback | Expected behaviour; the review covers the entire PR including fixes. |
| Commit signing | Verified developer identity | Setup friction; CI pipelines need signing keys | Provide setup instructions and a pre-commit hook; automate for CI. |
| Required CODEOWNERS review | Security expertise on critical paths | CODEOWNERS team may become a bottleneck | Keep CODEOWNERS teams small; set response SLAs; use teams not individuals. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Ruleset misconfigured excludes prod repos | Production repos unprotected | Compliance check script detects; `branch_protection_violation_total` rises | Fix ruleset condition; verify all production repos are included. |
| CODEOWNERS owner left the organisation | PRs to security-critical paths can never merge | PRs show "Review required from @departed-user" | Update CODEOWNERS to replace with a team or current individual; use teams over individuals. |
| Required status check renamed in CI | All PRs blocked; check name doesn't match | PRs show "Waiting for required status: old-check-name" | Update the required_status_checks in the Ruleset to match the new check name. |
| Branch protection bypass during incident | Incident responder needs direct push | Detected via `direct_push_to_protected_branch_total` | Document the incident; create a break-glass procedure; post-incident review. |
| PR size limit breaks a legitimate large refactor | Developer cannot merge large but legitimate PR | Build fails with size label check failure | CODEOWNERS team reviews and approves an exception; or split the refactor into logical chunks. |

## Related Articles

- [Securing GitHub Actions Workflows](/articles/cicd/securing-github-actions/)
- [GitHub Advanced Security](/articles/cicd/github-advanced-security/)
- [Repository Policy as Code](/articles/cicd/repo-policy-as-code/)
- [GitOps Security](/articles/cicd/gitops-security/)
- [SLSA Provenance and Build Integrity](/articles/cicd/slsa-provenance/)
