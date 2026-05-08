---
title: "GitHub Apps vs PATs vs Deploy Keys vs OIDC: Choosing the Right SCM Identity"
description: "Four identity types, four very different scope/lifetime/permission models. Pick wrong and you ship the wrong-shaped credential to every CI run for years."
slug: "scm-identity-choice"
date: 2026-04-29
lastmod: 2026-04-29
category: "cicd"
tags: ["github", "scm", "identity", "github-apps", "oidc", "pat"]
personas: ["platform-engineer", "security-engineer", "devops"]
article_number: 210
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/cicd/scm-identity-choice/index.html"
---

# GitHub Apps vs PATs vs Deploy Keys vs OIDC: Choosing the Right SCM Identity

## Problem

Every team integrating with GitHub (or GitLab, with analogous mechanisms) has at least one credential question per integration: how does the CI / infrastructure / tool authenticate?

Four common answers, each with different trade-offs:

- **Personal Access Token (PAT):** classic and fine-grained variants. Tied to a human user account; full access by default; long-lived.
- **Deploy Key:** SSH key associated with a specific repository. Read-only or read-write; repository-scoped; long-lived.
- **GitHub App:** an application identity. Org-scoped or repo-scoped; permission-bounded; tokens are short-lived (1 hour) but easily refreshed.
- **OIDC federation:** workflow identity from GitHub Actions to cloud or external systems. No long-lived credential at all.

Most production setups use the wrong identity for the use case, often defaulting to PATs because they're the easiest to set up. The consequences:

- A PAT scoped to "all repos in the org" sits in a CI secret, used by one workflow that needs read on one repo. Compromise gives the entire org.
- A deploy key with read-write access lets any compromise of the deploy target push to the repo.
- A GitHub App with overly-broad permissions is functionally equivalent to a PAT but hides the breadth in a separate UI.
- OIDC federation is unused for cloud access where it's the strictly better option.

By 2026 the toolchain is mature: GitHub fine-grained PATs (2022 GA), GitHub Apps with installation tokens (longstanding), Repository OIDC tokens (2021), and most cloud providers natively support OIDC federation from GitHub.

The specific gaps:

- New integrations default to PATs because the documentation shows PATs.
- Deploy keys persist indefinitely without rotation.
- GitHub Apps require setup overhead that gets skipped.
- OIDC requires understanding both sides (GitHub + cloud trust policy).

This article covers the decision framework for which identity to use, the scope and lifetime properties of each, the migration patterns from PATs to GitHub Apps and OIDC, and the audit questions to ask of existing integrations.

**Target systems:** GitHub.com / GitHub Enterprise Cloud, GitLab.com (with analogous concepts: personal tokens, deploy tokens, group-level access tokens, OIDC). Concepts apply to Bitbucket, Azure DevOps with vendor-specific naming.

## Threat Model

- **Adversary 1 — CI secret leak:** an attacker exfiltrates a credential from a CI environment (compromised dependency, log leak, misconfigured workflow).
- **Adversary 2 — Maintainer-account compromise:** an attacker takes over a maintainer's GitHub account; PATs they created become attacker-controlled.
- **Adversary 3 — Long-lived deploy-key compromise:** a deployment system is compromised and its deploy key extracted; attacker pushes malicious commits.
- **Adversary 4 — Excess-permission abuse:** a credential that has more permission than it needs gets used for an unintended action.
- **Access level:** Adversary 1 has CI environment read. Adversary 2 has GitHub session takeover. Adversary 3 has compromised deploy target. Adversary 4 has any of the prior plus knowledge of credential scope.
- **Objective:** Read repository contents; modify code; trigger deploys; pivot to other systems via the SCM identity.
- **Blast radius:** wrong identity means broad blast radius — entire org, multiple repos, write access where read suffices. Right identity means scoped, time-bounded, auditable per-action.

## Configuration

### Decision Framework

Pick by use case:

| Use case | Identity to choose | Why |
|----------|---------------------|-----|
| GitHub Actions → AWS / GCP / Azure | **OIDC federation** | No long-lived credential; tokens minted per workflow run; scoped via cloud-side trust policy. |
| GitHub Actions → another internal service | **OIDC federation** (if service trusts GitHub OIDC) | Same as above; many internal services can be configured to validate GitHub's OIDC tokens. |
| Bot that comments on PRs across the org | **GitHub App** | Org-scoped; permissions bounded (issues:write, pull_requests:write); short-lived installation tokens. |
| CI workflow needs read access to a private repo | **GitHub App** with `Contents: read` on that repo, OR a fine-grained **PAT** scoped to only that repo | App is cleaner; PAT acceptable for one-off / personal-tool use. |
| Deploy target pulls from a single repo | **Deploy Key** (read-only) | Repo-scoped; well-defined; cannot escalate. |
| Generic automation across many repos | **GitHub App** | Bounded permissions; rotatable; auditable. |
| CLI tool a developer uses occasionally | **Fine-grained PAT** | Tied to the user; expires; scoped. |
| Long-running agent in production | **GitHub App** | Avoid PATs in production; user accounts shouldn't authenticate production systems. |

The pattern: GitHub Apps for any system-to-GitHub integration; OIDC for any GitHub-to-system integration; PATs only for human-tied tools.

### Identity 1: Personal Access Token (PAT)

```bash
# Fine-grained PAT setup at https://github.com/settings/personal-access-tokens
# - Scope: specific repositories only
# - Permissions: minimum required (e.g., Contents: read)
# - Expiration: 90 days max for production use

# Use:
export GITHUB_TOKEN=github_pat_xxx...
gh repo clone myorg/myrepo
```

Properties:

- **Scope:** repository-level (fine-grained) or org-wide (classic).
- **Permissions:** rich set, fine-grained per resource.
- **Lifetime:** up to 1 year; 90 days recommended max.
- **Tied to:** a human user account. If the user leaves, the PAT works until expiration.
- **Audit:** appears as the user's actions in audit log.
- **Best for:** human-controlled tools; one-off scripts; local development.
- **Avoid for:** production systems, shared CI secrets.

### Identity 2: Deploy Key

```bash
# Generate.
ssh-keygen -t ed25519 -f ~/.ssh/myrepo-deploy -C "deploy@myrepo"

# Add public key at: https://github.com/myorg/myrepo/settings/keys
# - Allow write access: only if needed (often read-only suffices)

# Use.
GIT_SSH_COMMAND="ssh -i ~/.ssh/myrepo-deploy" git pull
```

Properties:

- **Scope:** exactly one repository.
- **Permissions:** read or read-write (no finer granularity).
- **Lifetime:** indefinite until manually revoked.
- **Tied to:** the SSH key; survives any user account changes.
- **Audit:** appears in audit log without user attribution (key fingerprint).
- **Best for:** deploy targets that pull code from a specific repo.
- **Avoid for:** anything that needs API access (deploy keys are SSH-only); multi-repo workflows.

### Identity 3: GitHub App

```yaml
# Manifest for a new GitHub App.
name: myorg-ci-bot
url: https://internal.example.com/ci-bot
hook_attributes:
  url: https://internal.example.com/ci-bot/webhook
default_permissions:
  contents: read
  issues: write
  pull_requests: write
  metadata: read
default_events:
  - pull_request
  - push
```

```python
# Authenticate as the App, then mint an installation token.
import jwt, time, requests

def app_jwt(app_id, private_key_pem):
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 600, "iss": app_id}
    return jwt.encode(payload, private_key_pem, algorithm="RS256")

def installation_token(app_id, private_key_pem, installation_id):
    headers = {
        "Authorization": f"Bearer {app_jwt(app_id, private_key_pem)}",
        "Accept": "application/vnd.github+json",
    }
    r = requests.post(
        f"https://api.github.com/app/installations/{installation_id}/access_tokens",
        headers=headers,
    )
    return r.json()["token"]   # valid for 1 hour
```

Properties:

- **Scope:** all installed repos (org-level install), or a chosen subset.
- **Permissions:** fine-grained, declared in the manifest.
- **Lifetime:** the App key is long-lived; installation tokens are 1 hour.
- **Tied to:** the App identity; survives user changes.
- **Audit:** all actions attributed to the App; rich audit detail.
- **Best for:** any system-to-GitHub integration; production automation; bots.
- **Avoid for:** trivial one-off use (overkill); developer CLIs (use PAT).

The 1-hour installation token is the key safety feature: a leaked token has bounded usable lifetime. Refresh logic in the application handles rotation transparently.

### Identity 4: OIDC Federation

GitHub Actions automatically provides an OIDC token to each workflow run. Configure the cloud (or any service that trusts JWTs) to accept it.

```yaml
# .github/workflows/deploy.yml
permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/github-deploy
          aws-region: us-east-1
      - run: aws s3 sync ./dist s3://myapp-prod/
```

The corresponding AWS role trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:myorg/myapp:ref:refs/heads/main"
      }
    }
  }]
}
```

Properties:

- **Scope:** per workflow run; bounded by the trust policy's `sub` matching.
- **Permissions:** decided by the cloud-side role's policy.
- **Lifetime:** the OIDC token is one-shot for the workflow run; minted fresh each time.
- **Tied to:** the GitHub workflow + ref; impossible to use outside of an actual workflow run.
- **Audit:** cloud-side IAM logs show every assumption.
- **Best for:** any GitHub Actions → cloud / external service authentication.
- **Avoid for:** anything that's not initiated from a GitHub Actions run.

OIDC is the strictly best option when applicable. No secret to leak, no rotation, scoped to specific workflows.

### Pattern: Audit Existing Identities

```bash
# List all PATs in use across the org.
gh api -X GET /orgs/myorg/credential-authorizations | \
  jq '.[] | {login, credential_type, credential_authorized_at}'

# List all GitHub Apps installed.
gh api /orgs/myorg/installations | \
  jq '.installations[] | {app_slug, created_at, permissions}'

# Find deploy keys per repo.
for repo in $(gh repo list myorg --limit 1000 --json name -q '.[].name'); do
  gh api "/repos/myorg/$repo/keys" | jq ".[] | {repo: \"$repo\", title, read_only, created_at}"
done
```

Build a per-credential inventory: identity type, scope, age, last used. Anything older than 90 days that isn't auto-rotating is a candidate for review.

### Pattern: Migration From PATs to GitHub App

Common migration:

```yaml
# Before: GH Action with PAT.
- name: Comment on PR
  env:
    GITHUB_TOKEN: ${{ secrets.MAINTAINER_PAT }}
  run: gh pr comment ${{ github.event.pull_request.number }} --body "..."

# After: GH App via official action.
- uses: actions/create-github-app-token@v1
  id: app-token
  with:
    app-id: ${{ vars.MYORG_BOT_APP_ID }}
    private-key: ${{ secrets.MYORG_BOT_PRIVATE_KEY }}
    owner: myorg
    repositories: ${{ github.event.repository.name }}

- name: Comment on PR
  env:
    GITHUB_TOKEN: ${{ steps.app-token.outputs.token }}
  run: gh pr comment ${{ github.event.pull_request.number }} --body "..."
```

The PAT secret is removed; the App private key is the only long-lived secret, used to mint hour-bounded installation tokens per workflow run.

### Pattern: Migration From PATs to OIDC

For workflows that authenticate to external systems (cloud providers, SaaS APIs that support OIDC):

```yaml
# Before: long-lived AWS access keys as secrets.
- env:
    AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
  run: aws s3 sync ./dist s3://myapp/

# After: OIDC federation (covered in oidc-federation-hardening article).
permissions:
  id-token: write
  contents: read
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::123456789012:role/myapp-deploy
- run: aws s3 sync ./dist s3://myapp/
```

The AWS keys are deleted; trust policy on the cloud side lists the specific workflow + ref allowed to assume the role.

## Expected Behaviour

| Property | PAT | Deploy Key | GitHub App | OIDC |
|----------|-----|-------------|--------------|------|
| Scope | Org or per-repo | Per repo | Per-installation | Per-workflow-run |
| Permissions | Many fine-grained scopes | read or read-write only | Many fine-grained | Decided by token consumer |
| Default lifetime | Up to 1 year | Indefinite | App key permanent; tokens 1h | Per workflow run |
| Tied to | User account | SSH key | App entity | Workflow + ref |
| Rotation | Manual | Manual | Automatic (per token) | None needed |
| Audit attribution | User name | Key fingerprint | App slug | Workflow + sub |
| Best for | Developer tools | Single-repo deploy pull | Bots + integrations | GH Actions to external |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Fine-grained PAT | Easiest to set up | Tied to user; long-lived | Use only for human-tied tools; mandate <90 day expiration. |
| Deploy key | No GitHub API surface; just SSH | One per repo; manual lifecycle | Use for read-only deploy targets; rotate annually. |
| GitHub App | Production-grade; auditable | Setup overhead | Once set up, reusable for many integrations. Document in platform onboarding. |
| OIDC federation | No long-lived secret | Both sides need configuration | Standard now; major clouds + many SaaS support it. |
| Audit / inventory | Visibility | Manual or scripted enumeration | Scheduled job; quarterly review. |
| Migration | Better security posture | Engineering work | Start with the highest-value PATs (production CI); incremental. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| PAT in CI secret leaks | Attacker uses for unauthorized actions | Audit log shows actions from unexpected IP | Revoke the PAT; rotate. Investigate exposure. |
| Deploy key with write access compromised | Attacker pushes malicious commits | Branch shows commits from unexpected source | Revoke the key; rotate; review commit history. |
| GitHub App private key leaked | Attacker mints installation tokens | Audit log shows App actions outside expected scope | Rotate the App's private key (UI generates a new one). All in-flight tokens become invalid quickly (1 hour max). |
| OIDC trust policy too broad | Workflow from unexpected branch / repo can assume role | Cloud audit log shows assumption from unexpected sub | Tighten trust policy; pin sub to specific repo + ref. |
| Maintainer leaves; PAT still works | Account closed but PAT continues to authenticate | PAT continues to work after user removed from org | Audit org members; revoke PATs of departed users. |
| App permission scope creep | App has more permission than it uses | Audit App permissions vs. actual API call patterns | Reduce App permissions; if App is widely used, careful migration. |
| OIDC `aud` not validated | Token from one cloud accepted by another | Cross-cloud authentication possible | Always set `aud` claim in trust policy; validate. |

## Related Articles

- [OIDC Federation Hardening for CI-to-Cloud](/articles/cicd/oidc-federation-hardening/)
- [Branch Protection and Repository Policy as Code](/articles/cicd/repo-policy-as-code/)
- [Securing GitHub Actions Workflows](/articles/cicd/securing-github-actions/)
- [CI/CD Pipeline Egress Control](/articles/cicd/pipeline-egress-control/)
- [CI/CD Secret Management](/articles/cicd/cicd-secret-management/)
