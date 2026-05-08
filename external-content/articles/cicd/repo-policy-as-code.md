---
title: "Branch Protection and Repository Policy as Code: Terraform GitHub for Hundreds of Repos"
description: "Hand-clicking branch protection rules across 200 repos guarantees drift. Terraform + the github provider + a shared module makes it auditable, reviewable, and reversible."
slug: "repo-policy-as-code"
date: 2026-04-27
lastmod: 2026-04-27
category: "cicd"
tags: ["github", "terraform", "branch-protection", "policy-as-code", "scm"]
personas: ["platform-engineer", "security-engineer", "devops"]
article_number: 202
difficulty: "intermediate"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/cicd/repo-policy-as-code/index.html"
---

# Branch Protection and Repository Policy as Code: Terraform GitHub for Hundreds of Repos

## Problem

Branch protection — required reviewers, status checks, push restrictions, signed commits — is the gate between "developer pushes code" and "code reaches production." When configured by hand-clicking through GitHub's UI, it silently degrades:

- New repositories created without the org-standard protection.
- Engineers add temporary exceptions ("just disable required reviews to merge this hotfix") that never get reverted.
- Policy changes (new required check, updated reviewer count) require visiting every repo individually — at scale, this never finishes.
- No audit trail of when a rule changed, by whom, why.
- No diff workflow for policy changes; admins make decisions in isolation.

By 2026 the practical pattern is repository policy as code: Terraform's `github` provider, modeled per-repo, applied centrally. New rules ship via PR and rollout; rule history is git history; manual UI changes are reverted by the next plan apply.

The specific gaps in a default GitHub org configuration:

- Org-wide rulesets exist (since 2023) but interact awkwardly with repo-level settings.
- Branch-protection rules per repo are not idempotent through clicking.
- Required reviewers don't propagate to forks unless explicitly configured.
- Status-check requirements drift as CI workflows are renamed.
- CODEOWNERS files exist but aren't enforced for older repos.
- Repository visibility, secret-scanning, dependabot, and signed-commit settings are scattered across the UI.

This article covers the Terraform GitHub provider for branch protection rulesets, a shared module pattern for policy uniformity, the migration from clickops to code, audit-log integration, and the rollout patterns for policy changes that affect every repo.

**Target systems:** Terraform 1.10+ with the `integrations/github` provider 6.4+; GitHub.com Cloud or GitHub Enterprise Cloud / Server; OpenTofu also supported.

## Threat Model

- **Adversary 1 — Insider with admin on a single repo:** disables branch protection on a repo to push directly to main, bypassing review.
- **Adversary 2 — Compromised maintainer account:** uses admin access to weaken protection (lower reviewer count, remove required CI check) and merge malicious code.
- **Adversary 3 — Drift via creation race:** new repo created and seeded with code before any branch protection is applied.
- **Adversary 4 — Policy regression on rule change:** an org-wide policy update is rolled out incorrectly, weakening protection on many repos at once.
- **Access level:** Adversary 1 has repo admin. Adversary 2 has maintainer / admin via stolen credentials. Adversary 3 has repo creation rights. Adversary 4 has org admin.
- **Objective:** Bypass code review, push unauthorized changes, weaken supply-chain controls.
- **Blast radius:** Without policy-as-code, a single weakening goes undetected indefinitely. With policy-as-code, every change is a PR; weakenings are immediately visible in diff and require explicit approval.

## Configuration

### Step 1: Terraform Provider Setup

```hcl
# providers.tf
terraform {
  required_version = ">= 1.10"
  required_providers {
    github = {
      source  = "integrations/github"
      version = "~> 6.4"
    }
  }
  backend "s3" {
    bucket = "myorg-terraform-state"
    key    = "github-policy/terraform.tfstate"
    region = "us-east-1"
    encrypt = true
    dynamodb_table = "terraform-state-lock"
  }
}

provider "github" {
  owner = "myorg"
  # Auth via GITHUB_TOKEN env var with admin:org scope; ideally a GitHub App.
}
```

For larger orgs, use a GitHub App rather than a PAT. App-based auth allows fine-grained permissions (Contents: read, Administration: write) and eliminates expiring PATs.

### Step 2: Shared Module for Repository Policy

Define one module that captures the org-standard policy. Each repo instantiates it.

```hcl
# modules/standard-repo/main.tf
variable "name" { type = string }
variable "description" { type = string }
variable "visibility" { type = string; default = "private" }
variable "required_reviewers" { type = number; default = 2 }
variable "required_checks" { type = list(string); default = [] }
variable "allow_dangerous" { type = bool; default = false }

resource "github_repository" "this" {
  name        = var.name
  description = var.description
  visibility  = var.visibility

  has_issues   = true
  has_projects = false
  has_wiki     = false

  delete_branch_on_merge      = true
  allow_merge_commit          = false
  allow_squash_merge          = true
  allow_rebase_merge          = false
  allow_auto_merge            = true

  vulnerability_alerts        = true

  security_and_analysis {
    secret_scanning {
      status = "enabled"
    }
    secret_scanning_push_protection {
      status = "enabled"
    }
    advanced_security {
      status = "enabled"
    }
  }
}

resource "github_repository_ruleset" "main_branch" {
  name        = "main-branch-protection"
  repository  = github_repository.this.name
  target      = "branch"
  enforcement = "active"

  conditions {
    ref_name {
      include = ["refs/heads/main"]
      exclude = []
    }
  }

  rules {
    creation                = true
    deletion                = true
    non_fast_forward        = true
    required_linear_history = true
    required_signatures     = true

    pull_request {
      required_approving_review_count   = var.required_reviewers
      dismiss_stale_reviews_on_push     = true
      require_code_owner_review         = true
      require_last_push_approval        = true
      required_review_thread_resolution = true
    }

    required_status_checks {
      strict_required_status_checks_policy = true
      required_check {
        context = "ci/build"
      }
      dynamic "required_check" {
        for_each = var.required_checks
        content {
          context = required_check.value
        }
      }
    }
  }

  bypass_actors {
    actor_id    = 0
    actor_type  = "OrganizationAdmin"
    bypass_mode = "pull_request"
  }
}

# CODEOWNERS file managed via repository file resource.
resource "github_repository_file" "codeowners" {
  repository = github_repository.this.name
  branch     = "main"
  file       = ".github/CODEOWNERS"
  content    = templatefile("${path.module}/codeowners.tpl", {
    name = var.name
  })
  commit_message      = "chore: enforce CODEOWNERS"
  overwrite_on_create = true
}
```

### Step 3: Per-Repo Configuration

Each repo's policy is a small block calling the module:

```hcl
# repos/payments-api.tf
module "payments_api" {
  source = "../modules/standard-repo"
  name        = "payments-api"
  description = "Payments service API"
  required_reviewers = 2
  required_checks = ["security/cosign-verify", "security/trivy-scan"]
}

# repos/internal-tools.tf
module "internal_tools" {
  source = "../modules/standard-repo"
  name        = "internal-tools"
  description = "Internal tooling and scripts"
  required_reviewers = 1
}
```

A weekly drift detection (`terraform plan` against the org) catches manual UI changes.

### Step 4: Org-Wide Rulesets for Cross-Cutting Rules

Some rules apply to every repo by default; manage them at the org level.

```hcl
resource "github_organization_ruleset" "all_repos_main" {
  name        = "all-repos-main-baseline"
  target      = "branch"
  enforcement = "active"

  conditions {
    ref_name {
      include = ["refs/heads/main"]
      exclude = []
    }
    repository_name {
      include = ["~ALL"]
      exclude = ["myorg/sandbox-*"]   # sandboxes exempt
    }
  }

  rules {
    deletion         = true   # block branch deletion on main
    non_fast_forward = true   # block force-push on main
    required_signatures = true
  }
}
```

Org-level rules apply universally; per-repo rules add additional constraints. New repos automatically inherit the org baseline even before per-repo Terraform runs.

### Step 5: CI Workflow to Apply Plans

Apply changes via PR + automation:

```yaml
# .github/workflows/terraform.yml in the policy repo.
name: Terraform GitHub Policy
on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

permissions:
  id-token: write
  contents: read
  pull-requests: write

jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.10.0
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/terraform-state-role
          aws-region: us-east-1
      - name: Plan
        env:
          GITHUB_TOKEN: ${{ secrets.ORG_ADMIN_TOKEN }}
        run: terraform plan -no-color | tee plan.txt
      - name: Comment plan on PR
        if: github.event_name == 'pull_request'
        uses: peter-evans/create-or-update-comment@v4
        with:
          issue-number: ${{ github.event.pull_request.number }}
          body-file: plan.txt
      - name: Apply
        if: github.event_name == 'push' && github.ref == 'refs/heads/main'
        env:
          GITHUB_TOKEN: ${{ secrets.ORG_ADMIN_TOKEN }}
        run: terraform apply -auto-approve
```

Every change is a PR with a plan visible to reviewers. Apply only on merge to `main`. Manual changes via the UI are reverted on the next scheduled plan.

### Step 6: Drift Detection

Schedule a weekly drift check that fails loudly if anyone has clicked something in the UI:

```yaml
# .github/workflows/drift-check.yml
name: Drift detection
on:
  schedule:
    - cron: "0 6 * * 1"   # Monday 06:00 UTC

jobs:
  drift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - run: |
          terraform init
          terraform plan -detailed-exitcode -out=plan.bin
        env:
          GITHUB_TOKEN: ${{ secrets.ORG_ADMIN_TOKEN }}
      - if: failure()
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {"text": "Repo policy drift detected. Review terraform plan in CI logs."}
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_DRIFT_WEBHOOK }}
```

`-detailed-exitcode` returns 2 when the plan would change resources — drift exists. Slack-alert and review.

### Step 7: Policy Version Pinning Per-Repo

For phased rollouts, version the shared module and let repos opt in to the latest policy:

```hcl
module "payments_api" {
  source  = "git::https://github.com/myorg/policy-modules.git//standard-repo?ref=v2.0.0"
  name    = "payments-api"
  ...
}
```

A new policy version goes through testing in a few canary repos before propagation across the fleet. The `?ref=` pin prevents accidental policy changes.

## Expected Behaviour

| Signal | Click-ops | Policy-as-code |
|--------|-----------|------------------|
| New repo born without protection | Common | Impossible if creation is via the same Terraform |
| Rule rollback | Manual; lossy | `git revert`; full audit |
| Drift between repos | Frequent | Detected weekly |
| Audit trail | GitHub audit log only | Git history of policy + GitHub audit log of applied changes |
| Time to apply org-wide rule change | Hours-to-days; never finishes | Hours; automated |
| Dispute about who changed a rule | Hard to investigate | PR shows author and reviewer |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Terraform GitHub provider | Standard tooling; predictable | Provider has quirks (some resources don't import cleanly) | Use the latest provider; for unsupported settings, fall back to GitHub API via `restapi` resource. |
| Shared module | Uniformity | Less per-repo flexibility | Variables expose the dimensions worth varying (reviewer count, required checks); resist module sprawl. |
| Org-wide rulesets | Universal baseline | Tougher to exempt edge cases | Use ruleset conditions to exclude specific repos; document the exemptions. |
| GitHub App auth | Fine-grained permissions, no expiring PAT | Setup overhead; rotation policy needed | Use Atlantis or Spacelift to manage app credentials. |
| Drift detection | Catches click-ops drift | False positives on emergency in-UI changes | Document the emergency-bypass procedure: in-UI change followed by Terraform sync within 24 hours. |
| Policy version pinning | Phased rollout | Repos may stay on stale versions if forgotten | Periodic upgrade-PR automation; deprecate old versions. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| GitHub Actions secret leaked | Anyone who can read the workflow can apply terraform | GitHub audit log shows actions from unexpected source | Rotate token; investigate. Use OIDC federation rather than long-lived secrets where possible. |
| Provider rate-limited | Terraform plan / apply slow or fails | Provider logs `429 rate-limited` | Use `parallelism` setting to lower API call rate; spread plan over multiple repos rather than a single global plan. |
| Rule change weakens protection accidentally | Reviewer count lowered; required check removed | Drift check flags the change after merge | PR review should catch; set required-reviewers on the policy repo itself to >2. The policy-of-policy is critical. |
| Repository created outside Terraform | Repo lacks protection; not in state | Drift check detects un-managed repo | Periodic enumeration: query GitHub API for repos, diff against Terraform state, alert on missing. |
| CODEOWNERS file deleted by user | Required reviewers no longer enforced | drift check shows file content drift | Terraform reasserts the file content on next apply; investigate why it was deleted. |
| Org policy bypass via fork | Forks of internal repos may not inherit protection | Contributor uses fork to bypass review | Disable forking on sensitive repos via `fork_pull_request_workflows: false` ruleset configuration. |
| Apply runs in the wrong direction | Test-policy applied to production | Production rules suddenly relaxed | Use Terraform workspaces or separate state files per environment; never share state between policy environments. |

## When to Consider a Managed Alternative

Self-hosted policy-as-code requires Terraform infrastructure, GitHub App management, drift detection, and ongoing module maintenance (4-8 hours/month for a 100-repo org).

- **GitHub Advanced Security:** built-in policy enforcement features for orgs with the licence.
- **[Atlantis](https://www.runatlantis.io/):** PR-driven Terraform with merge-on-apply; reduces the apply pipeline to a config file.
- **[Spacelift](https://spacelift.io/):** managed Terraform-as-a-service; integrates with GitHub.
- **[Terraform Cloud](https://www.hashicorp.com/products/terraform):** HashiCorp-managed state and runs.

## Related Articles

- [Securing GitHub Actions Workflows](/articles/cicd/securing-github-actions/)
- [OIDC Federation Hardening for CI-to-Cloud](/articles/cicd/oidc-federation-hardening/)
- [Securing Self-Hosted CI/CD Runners](/articles/cicd/securing-cicd-runners/)
- [Ephemeral CI Runners with Firecracker and Kata](/articles/cicd/firecracker-kata-ci-runners/)
- [SLSA Build Provenance: Source-to-Registry Integrity](/articles/cicd/slsa-provenance/)
