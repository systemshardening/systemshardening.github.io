---
title: "GitHub Actions Supply Chain: The Trivy Action Compromise and SHA Pinning"
description: "TeamPCP rewrote 76 of 77 aquasecurity/trivy-action release tags with credential-stealing malware in March 2026. If your workflow pinned to a tag like @v0.25.0 rather than a commit SHA, you ran the malicious version. Learn how SHA pinning and action verification close this gap."
slug: github-actions-trivy-compromise
date: 2026-05-04
lastmod: 2026-05-04
category: cicd
tags:
  - github-actions
  - supply-chain
  - sha-pinning
  - credential-theft
  - cicd
personas:
  - platform-engineer
  - security-engineer
article_number: 434
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/cicd/github-actions-trivy-compromise/
---

# GitHub Actions Supply Chain: The Trivy Action Compromise and SHA Pinning

## The Problem

Every `uses:` line in a GitHub Actions workflow is a trust decision. Between March 19 and March 31 2026, the threat actor known as TeamPCP demonstrated exactly how expensive a bad trust decision can be: they compromised credentials associated with the `aquasecurity/trivy-action` repository and force-pushed malicious code into 76 of 77 release tags of one of the most widely deployed GitHub Actions in existence. The Trivy action — used to scan container images and filesystems for vulnerabilities — runs in tens of thousands of CI pipelines. Any pipeline that referenced the action by tag name (`uses: aquasecurity/trivy-action@v0.25.0`, or any other compromised tag) immediately began executing the malicious version on its next workflow trigger: no change to the workflow file, no warning, no diff to review.

This is the fundamental vulnerability in GitHub Actions' reference model. A `ref` in a `uses:` directive can be a tag name, a branch name, or a commit SHA. Tags and branch names are mutable — they are just named pointers that a repository owner (or anyone who has compromised their credentials) can silently advance to a different commit using a force-push. Commit SHAs are immutable — a SHA identifies a specific object in the Git content-addressed store and cannot be forged or redirected. When TeamPCP force-pushed the malicious payload to 76 tags, every workflow pinned by tag name updated instantly. Every workflow pinned by commit SHA was completely unaffected.

The malicious payload was a credential-stealing exfiltration script. Running inside the CI job with access to the job's full environment, it targeted all secrets injected into the CI context: `GITHUB_TOKEN`, AWS credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), Azure client secrets, Google Cloud service account keys, Docker Hub passwords, npm tokens, and any other key-value pairs present as environment variables or accessible through the GitHub Actions secret store. These credentials were exfiltrated to attacker-controlled infrastructure over HTTPS — a channel that most CI runner egress controls do not block.

TeamPCP also compromised `ast-github-action` and `kics-github-action` using the same technique during the same campaign, suggesting a coordinated effort to target security-adjacent actions — tools that teams often grant elevated permissions because they need to scan code or post results to pull requests.

The scale matters. Trivy Action's adoption spans both large enterprises and small teams. Even assuming that exposure lasted only three hours before the malicious tags were removed and replaced, the number of CI pipeline runs during a working day within that window across all adopters represents a significant number of credential exposures. Stolen `GITHUB_TOKEN` credentials were used to push malicious commits to downstream repositories. Stolen cloud credentials were used to create compute resources for cryptomining and to attempt lateral movement into cloud environments. The downstream blast radius extended well beyond the CI pipeline itself.

This incident is not an edge case. It is the predictable outcome of a reference model that treats mutable pointers as stable identifiers. SHA pinning converts a mutable reference into an immutable one. It is not a best practice — it is the correct implementation of the `uses:` directive for any action you do not control.

## Threat Model

- A workflow references a third-party action by tag (`uses: aquasecurity/trivy-action@v0.25.0`). The action maintainer's credentials are compromised. The attacker force-pushes a credential-stealing payload to the `v0.25.0` tag. The next workflow run executes the malicious code with no change to the workflow file.
- Credential exfiltration targets all secrets available in the job environment: `GITHUB_TOKEN`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AZURE_CLIENT_SECRET`, `GCP_SA_KEY`, Docker Hub credentials, npm tokens, and any other secret mapped into the job. CI jobs routinely have access to credentials scoped to the environments they deploy to — production cloud credentials are frequently present.
- A stolen `GITHUB_TOKEN` with write permissions allows the attacker to push commits, create releases, modify workflow files to persist access, approve pull requests, and interact with the GitHub API on behalf of the repository.
- Stolen cloud credentials allow resource creation (compute for cryptomining, data pipelines for exfiltration), read access to storage and secret managers, and lateral movement within the cloud account. The blast radius extends to every resource accessible with those credentials.
- Actions triggered on `push` to main or on every `pull_request` run frequently — multiple times per day for active repositories. High trigger frequency means broad exposure within a short compromise window.
- Actions granted `packages: write`, `contents: write`, or `deployments: write` can persist attacker access beyond the initial secret theft by modifying workflow files or pushing malicious releases.

## Hardening Configuration

### 1. Pin All Actions to Commit SHAs

Find every tag-based action reference in your repository's workflows:

```bash
grep -rn 'uses:' .github/workflows/ | grep -v '@[0-9a-f]\{40\}'
```

This prints every `uses:` line that is not already pinned to a 40-character commit SHA. A clean repository produces no output.

For an existing workflow using Trivy Action by tag, the change looks like this:

```yaml
- name: Run Trivy vulnerability scanner
  uses: aquasecurity/trivy-action@v0.25.0
```

becomes:

```yaml
- name: Run Trivy vulnerability scanner
  uses: aquasecurity/trivy-action@18f2510ee396bbf400402947b394f2dd8c87dbb0
```

The SHA comment is optional but makes the version human-readable when reviewing diffs. To find the commit SHA for a specific tag without cloning the repository:

```bash
git ls-remote https://github.com/aquasecurity/trivy-action refs/tags/v0.25.0
```

This prints the SHA the tag currently points to. Alternatively, use the GitHub API:

```bash
gh api repos/aquasecurity/trivy-action/git/refs/tags/v0.25.0 \
  --jq '.object.sha'
```

Note that an annotated tag object has its own SHA; to get the commit SHA the tag ultimately resolves to:

```bash
gh api repos/aquasecurity/trivy-action/git/refs/tags/v0.25.0 \
  --jq '.object.url' \
  | xargs gh api --jq '.object.sha // .sha'
```

For bulk migration of existing workflows, `sed` can replace tag patterns, but review the result before committing — automatic substitution without verification introduces the same trust problem it is meant to solve.

### 2. Automate SHA Pinning with Dependabot or Renovate

SHA pinning creates an ongoing maintenance obligation: when a new action version is released, the SHA must be updated. Dependabot handles this automatically.

```yaml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    commit-message:
      prefix: "chore(actions)"
    groups:
      actions-updates:
        patterns:
          - "*"
```

With this configuration, Dependabot opens pull requests each week that update pinned SHAs to the latest release for each action. The PR shows the commit SHA changing and the version comment updating — a reviewable diff. Merge the PR after verifying the new SHA corresponds to the expected release commit.

Renovate provides equivalent functionality with more granular control over grouping and automerge policies:

```json
{
  "extends": ["config:base"],
  "github-actions": {
    "enabled": true,
    "pinDigests": true
  },
  "packageRules": [
    {
      "matchManagers": ["github-actions"],
      "automerge": false,
      "reviewers": ["team:platform-engineering"]
    }
  ]
}
```

Setting `pinDigests: true` causes Renovate to convert any tag references it finds to SHA pins on first run, then keep them updated. `automerge: false` ensures a human reviews the SHA update before it merges — important because a malicious SHA update is exactly what SHA pinning is designed to prevent.

### 3. Verify Action Integrity with Sigstore Attestation

GitHub Actions supports artifact attestation via Sigstore. Actions that publish attestations allow you to verify that the code at a given SHA was actually built from the expected source before your workflow executes it.

Check whether an action has a published attestation:

```bash
gh attestation verify \
  oci://ghcr.io/aquasecurity/trivy-action:v0.25.0 \
  --owner aquasecurity
```

For actions that publish provenance, add a verification step before any sensitive action in your workflow:

```yaml
- name: Verify action provenance
  env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: |
    gh attestation verify \
      oci://ghcr.io/aquasecurity/trivy-action:v0.25.0 \
      --owner aquasecurity \
      --format json | jq -e '.[] | .verificationResult.verified == true'

- name: Run Trivy vulnerability scanner
  uses: aquasecurity/trivy-action@18f2510ee396bbf400402947b394f2dd8c87dbb0
  with:
    image-ref: ${{ env.IMAGE_REF }}
    format: sarif
    output: trivy-results.sarif
```

Not all actions publish attestations. Treat the absence of an attestation as a risk signal: the action's code cannot be verified against a published provenance record. Consider forking such actions into your organisation's namespace and maintaining them directly, or replace them with attested alternatives.

### 4. Restrict GITHUB_TOKEN Permissions

The default `GITHUB_TOKEN` in many repositories has `read-write` permissions for all repository resources. A compromised action that steals this token can push code, create releases, and modify workflows. Restrict to the minimum required for the specific job.

```yaml
name: Vulnerability Scan
on:
  push:
    branches: [main]
  pull_request:

permissions: {}

jobs:
  trivy-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@18f2510ee396bbf400402947b394f2dd8c87dbb0
        with:
          image-ref: ${{ env.IMAGE_REF }}
          format: sarif
          output: trivy-results.sarif

      - name: Upload SARIF to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy-results.sarif
```

Setting `permissions: {}` at the workflow level removes all default permissions. Each job then declares only what it needs. For the Trivy scan job: `contents: read` to check out the code, `security-events: write` to upload SARIF results. A compromised Trivy action running with this token cannot push commits, create releases, or modify workflows — the token simply does not have those permissions.

Set the repository default to read-only permissions in Settings > Actions > General > Workflow permissions. This ensures that workflows which do not declare a `permissions` block are not silently granted write access.

### 5. Audit Existing Workflows for Tag References

Scan all workflow files across an organisation for non-SHA action references:

```bash
gh api --paginate "orgs/{org}/repos" --jq '.[].full_name' \
  | while read repo; do
      gh api "repos/${repo}/contents/.github/workflows" 2>/dev/null \
        --jq '.[].download_url' \
        | while read url; do
            gh api "${url}" --jq '. | split("\n")[] | select(test("uses:.*@(?!.*[0-9a-f]{40})"))'  \
            | sed "s|^|${repo}: |"
          done
    done
```

This outputs every tag-referenced action across all repositories in the organisation, prefixed with the repository name. Prioritise remediating actions that have access to production secrets: deployment workflows, release workflows, and any workflow that touches cloud credentials.

For repositories using GitHub Advanced Security, the dependency graph includes GitHub Actions — you can also identify which repositories use a specific action version through the GitHub API:

```bash
gh api graphql -f query='
{
  organization(login: "your-org") {
    repositories(first: 100) {
      nodes {
        name
        dependencyGraphManifests {
          nodes {
            dependencies {
              nodes {
                packageName
                requirements
              }
            }
          }
        }
      }
    }
  }
}'
```

### 6. Detect Compromised Action Execution

GitHub's audit log records workflow runs and secret access events. Query for unexpected secret access patterns:

```bash
gh api \
  "orgs/{org}/audit-log" \
  --paginate \
  -f phrase="action:secrets.access" \
  --jq '.[] | {actor: .actor, repo: .repo, secret_name: .name, timestamp: .created_at}'
```

For repository-level audit events:

```bash
gh api \
  "repos/{owner}/{repo}/actions/runs" \
  --jq '.workflow_runs[] | select(.conclusion == "failure") | {id: .id, name: .name, event: .event, created_at: .created_at}'
```

Alert when an action accesses a secret it has not previously accessed. This requires baselining normal secret access patterns. A simple approach: export the audit log to a SIEM or object storage daily, and alert on first-seen `(action_name, secret_name)` pairs. A Trivy action suddenly accessing `AWS_PROD_DEPLOY_ROLE` is anomalous — Trivy only needs to read images, not deploy infrastructure.

## Expected Behaviour After Hardening

After SHA pinning: the Trivy action reference in your workflow is `uses: aquasecurity/trivy-action@18f2510ee396bbf400402947b394f2dd8c87dbb0`. TeamPCP force-pushing the `v0.25.0` tag to a malicious commit has no effect on your pipeline. GitHub resolves the SHA to the same commit object it always has — the force-push is invisible to your workflow.

After `GITHUB_TOKEN` restriction: a compromised action that attempts to push a malicious commit to your repository receives a `403 Resource not accessible by integration`. The token scoped to `contents: read` cannot write. The attacker can exfiltrate the token, but it has no write surface to exploit.

After Dependabot configuration: a PR appears each week with updated SHAs for any actions that released new versions. The diff shows only SHA and version comment changes. Reviewing the PR includes checking that the new SHA corresponds to the expected release on the action's repository — a 30-second check that maintains the security property without manual tracking.

## Trade-offs and Operational Considerations

SHA pinning requires updating the SHA whenever a new action version is released. Without Dependabot or Renovate automation, this becomes a recurring manual task that teams will eventually skip. The automation is not optional — it is what makes the security property sustainable over months and years rather than degrading as the repository ages.

Actions without published SHA attestations cannot be verified against a provenance record. This affects a large proportion of available actions, including some widely used ones. The practical response is to treat unattested actions as higher-risk: consider forking them into your organisation's namespace (so you control the tag references), require additional review of any workflow changes that add unattested actions, and monitor their execution more closely through audit logs.

Setting `permissions: {}` at the workflow level and declaring minimum permissions per job will break actions that rely on the default broad token. Common failures: actions that post PR comments need `pull-requests: write`; actions that update commit status checks need `statuses: write`; actions that create GitHub releases need `contents: write`. The correct response is to add the specific permission to the specific job that needs it — not to restore broad default permissions for the entire workflow.

## Failure Modes

- Dependabot is configured and opens SHA update PRs, but the team does not review and merge them. SHA pins drift out of date. After six months, the pinned SHAs are far behind current releases, and team members begin bypassing pinning to use tag references because "Dependabot isn't keeping up." The security property is lost. Resolution: treat Dependabot action update PRs as a weekly 10-minute team task, not optional review queue items. Set a policy that unreviewed Dependabot PRs are merged after 7 days if CI passes and no team member objects.

- `GITHUB_TOKEN` permissions are restricted in the workflow file with `permissions: contents: read`, but the repository's default workflow permissions setting in GitHub is `read-write`. A different workflow in the same repository that does not declare a `permissions` block still runs with full write access. The restriction in one workflow file does not affect other workflows. Resolution: change the repository default to `read-only` in Settings > Actions > General > Workflow permissions. This makes the secure configuration the default, and any workflow that needs write access must explicitly request it.

- The audit for tag-based action references uses `grep -v '@v'` to find `@v1`, `@v2`, `@v0.x.x` patterns, but misses `@main`, `@master`, and `@latest` branch and alias references. Branch references are equally mutable — an attacker who compromises a maintainer can push to `main` without force-pushing any tag. The audit must cover all non-SHA references, not just version tag patterns. Resolution: use the full SHA pattern check: flag any `uses:` line where the ref is not exactly 40 hexadecimal characters.

## Related Articles

- [Securing GitHub Actions](/articles/cicd/securing-github-actions/)
- [Sigstore Keyless Signing](/articles/cicd/sigstore-keyless-signing/)
- [GitHub Advanced Security](/articles/cicd/github-advanced-security/)
- [Software Supply Chain Third-Party Risk](/articles/cicd/software-supply-chain-third-party-risk/)
- [npm Publish Account Hardening](/articles/cicd/npm-publish-account-hardening/)
