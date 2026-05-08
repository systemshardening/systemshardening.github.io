---
title: "Securing GitHub Actions: Permissions, Pinning, and Workflow Injection Prevention"
description: "GitHub Actions is the most widely used CI/CD platform, but its security model is scattered across dozens of documentation pages."
slug: "securing-github-actions"
date: 2026-02-13
lastmod: 2026-02-13
category: "cicd"
tags: ["github-actions", "cicd", "supply-chain", "workflow-security", "oidc"]
personas: ["devops-engineer", "security-engineer"]
article_number: 55
difficulty: "intermediate"
estimated_reading_time: 16
provider_bridges:
  - name: "Snyk"
    id: 48
    category: "container-security"
premium_pack: "github-actions-templates"
published: true
layout: article.njk
permalink: "/articles/cicd/securing-github-actions/index.html"
---

# Securing GitHub Actions: Permissions, Pinning, and Workflow Injection Prevention

## Problem

GitHub Actions is the most widely used CI/CD platform, but its security model is scattered across dozens of documentation pages. Default configurations are dangerously permissive: `GITHUB_TOKEN` has write access to the repository, actions referenced by tag can be hijacked by the maintainer, `pull_request_target` workflows execute attacker-controlled code with repository secrets, and environment secrets are accessible to any workflow in the repository.

## Threat Model

- **Adversary:** Malicious contributor (fork-based attack), compromised third-party action maintainer, or attacker with write access to the repository.
- **Objective:** Extract repository secrets, inject code into builds, modify workflows for persistent access.
- **Blast radius:** All secrets in the repository; all deployments triggered by workflows.

## Configuration

### Minimal Permissions on Every Workflow

```yaml
# Default: no permissions. Each job declares what it needs.
name: Build and Test
on: [push, pull_request]

# Top-level: restrict GITHUB_TOKEN to read-only by default
permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
      - run: make build
      - run: make test

  deploy:
    runs-on: ubuntu-latest
    needs: build
    if: github.ref == 'refs/heads/main'
    # This job needs write permissions for deployment
    permissions:
      contents: read
      id-token: write    # OIDC
      packages: write    # Push to GHCR
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: Push to registry
        run: |
          echo "${{ secrets.GITHUB_TOKEN }}" | docker login ghcr.io -u ${{ github.actor }} --password-stdin
          docker push ghcr.io/${{ github.repository }}:${{ github.sha }}
```

### Pin Actions by SHA (Not Tag)

Tags can be force-pushed. An action maintainer (or attacker who compromises their account) can change the code behind `v4` at any time.

```yaml
# BAD: pinned by tag - can be changed by the action maintainer
- uses: actions/checkout@v4

# GOOD: pinned by full SHA - immutable reference to a specific commit
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
```

Automate SHA updates with Dependabot:

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    # Dependabot will create PRs that update SHA pins
    # when new versions of actions are released.
```

### Prevent `pull_request_target` Injection

`pull_request_target` runs in the context of the BASE branch with full access to secrets, but can checkout and build code from the HEAD (attacker's fork). This is the most dangerous GitHub Actions footgun.

```yaml
# DANGEROUS: checks out attacker's code with repository secrets available
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # Attacker's code!
      - run: make build  # Runs attacker's Makefile with repo secrets

# SAFE: use pull_request_target only for labelling/commenting (no code checkout)
on: pull_request_target
jobs:
  label:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - uses: actions/labeler@v5  # Only reads PR metadata, doesn't checkout code
```

For workflows that need to build untrusted code AND access secrets, use `workflow_run`:

```yaml
# Workflow 1: Build untrusted code (no secrets)
name: Build PR
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - run: make build
      - uses: actions/upload-artifact@v4
        with:
          name: build-output
          path: ./dist

# Workflow 2: Deploy/comment using artifacts from Workflow 1 (has secrets)
name: Post-Build
on:
  workflow_run:
    workflows: ["Build PR"]
    types: [completed]
jobs:
  deploy-preview:
    if: ${{ github.event.workflow_run.conclusion == 'success' }}
    runs-on: ubuntu-latest
    permissions:
      deployments: write
    steps:
      - uses: actions/download-artifact@v4
        # Download artifacts from the untrusted build - safe because
        # the artifact is a build output, not executable code in this context.
```

### Environment Protection Rules

```yaml
# Configure environments in GitHub repository settings:
# Settings → Environments → production
# - Required reviewers: 2 team members
# - Wait timer: 5 minutes
# - Deployment branches: main only
# - Environment secrets: PROD_AWS_ROLE_ARN (scoped to this environment only)

jobs:
  deploy-production:
    runs-on: ubuntu-latest
    environment: production  # Triggers approval gate
    permissions:
      id-token: write
    steps:
      - name: Deploy to production
        run: |
          # This only runs after 2 reviewers approve
          echo "Deploying to production..."
```

### Workflow File Protection

```yaml
# CODEOWNERS - require security team review for workflow changes
# .github/CODEOWNERS
.github/workflows/ @your-org/security-team
.github/dependabot.yml @your-org/security-team
```

Enable branch protection rules:
- Require PR reviews for changes to `.github/workflows/`
- CODEOWNERS review required (not just any reviewer)
- No force push to main
- Status checks must pass before merge

### Secret Leak Detection

```yaml
# Add to every workflow that handles secrets:
- name: Scan for secret leaks in output
  if: always()
  run: |
    # Check that no secrets appear in the job log
    # GitHub automatically masks secrets, but custom secrets
    # or secrets in error messages may not be masked.
    echo "Secret scan complete, review job output manually for any unmasked values"
```

For comprehensive secret scanning, integrate `trufflehog` or `gitleaks`:

```yaml
- name: Scan for secrets in repository
  uses: trufflesecurity/trufflehog@v3
  with:
    extra_args: --only-verified
```

## Expected Behaviour

- Every workflow declares minimal `permissions`; no workflow has default write-all
- All third-party actions pinned by full SHA with Dependabot automated updates
- No `pull_request_target` workflows check out untrusted code
- Production deployments require environment approval (2 reviewers)
- Workflow file changes require CODEOWNERS (security team) review
- Secret scanning runs on every push

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| SHA pinning | Verbose workflow files; frequent Dependabot PRs | Missing action security updates if Dependabot PRs are ignored | Review and merge Dependabot PRs weekly. |
| Minimal permissions | Must declare each permission per job | Jobs fail with 403 if a permission is missing | Iteratively add permissions as needed. |
| Environment approvals | Deployment speed reduced (human approval gate) | Bottleneck if approver unavailable | Require 2 approvers from a pool of 4+ people. |
| CODEOWNERS for workflows | Security team must review every workflow change | Bottleneck for rapid CI changes | Security team commits to 24-hour review SLA for workflow PRs. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Permission too restrictive | Workflow step fails with `HttpError: Resource not accessible` | Job logs show 403; step that needs the permission is clear from the error | Add the specific permission to the job's `permissions` block. |
| SHA-pinned action has CVE | Action vulnerable but pinned to old SHA | Dependabot PR for action update; GitHub advisory notification | Merge the Dependabot PR. Verify the new SHA matches the security fix. |
| `pull_request_target` code injection | Attacker's code executes with repo secrets | Audit log shows unexpected workflow run from fork PR; secrets used in unexpected API calls | Remove `pull_request_target` trigger. Switch to `workflow_run` pattern. Rotate all exposed secrets immediately. |
| Approver unavailable | Production deployment blocked | Deployment queue backs up; team cannot ship | Pool of 4+ approvers across time zones. Emergency bypass with post-hoc review. |

## When to Consider a Managed Alternative

Enforcing workflow standards across 20+ repositories requires governance tooling. [Snyk](https://snyk.io) provides GitHub integration scanning for secrets and vulnerabilities in CI config. GitHub Enterprise adds: secret scanning push protection (blocks commits containing secrets), code scanning (SAST in CI), and advanced audit logging. For teams outgrowing GitHub Actions: [Buildkite](https://buildkite.com) provides managed orchestration with stricter runner isolation.

**Premium content pack:** GitHub Actions workflow templates. hardened build/test/deploy workflows with OIDC, minimal permissions, SHA-pinned actions, and environment protection. Includes Dependabot configuration and CODEOWNERS template.


## Related Articles

- [Securing CI/CD Runners: Isolation, Credential Scoping, and Ephemeral Environments](/articles/cicd/securing-cicd-runners/)
- [Secret Management in CI/CD Pipelines: Vault, SOPS, and OIDC Federation](/articles/cicd/cicd-secret-management/)
- [Pipeline-as-Code Security: Preventing CI Configuration Tampering](/articles/cicd/pipeline-config-security/)
- [SLSA Provenance for Container Images: From Build to Admission Control](/articles/cicd/slsa-provenance/)
- [Dependency Pinning and Lockfile Integrity: Preventing Supply Chain Attacks in CI](/articles/cicd/dependency-pinning/)
