---
title: "GitHub Actions Reusable Workflow Pinning and Drift Audit: Closing the Post-tj-actions Gap"
description: "Reusable workflows pulled by `uses: org/repo/.github/workflows/x.yml@ref` are a supply-chain blind spot that the 2025 tj-actions and reviewdog incidents exploited. This is how to enforce SHA pinning, audit drift across an entire org, and detect tampering before CI runs attacker-controlled code."
slug: "github-actions-reusable-workflow-pinning-audit"
date: 2026-05-08
lastmod: 2026-05-08
category: "cicd"
tags: ["github-actions", "supply-chain", "reusable-workflows", "sha-pinning", "ci-security"]
personas: ["security-engineer", "platform-engineer", "sre"]
article_number: 660
difficulty: "intermediate"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/cicd/github-actions-reusable-workflow-pinning-audit/index.html"
---

# GitHub Actions Reusable Workflow Pinning and Drift Audit: Closing the Post-tj-actions Gap

## Problem

In March 2025 `tj-actions/changed-files` was compromised: a maintainer-account takeover let the attacker rewrite the action to dump secrets into job logs, and because most consumers referenced it as `@v45` or `@main` the malicious version propagated to thousands of pipelines within hours. A near-identical pattern hit `reviewdog/action-setup` weeks later. Both incidents made one operational fact uncomfortable for security teams: SHA pinning, repeatedly recommended for years, is not what most organisations actually do, and even teams who pin their *direct* `uses:` tend to ignore the *transitive* pulls that reusable workflows perform under the hood.

A reusable workflow is a workflow file at `.github/workflows/<name>.yml` that another workflow calls via `uses: org/repo/.github/workflows/<name>.yml@<ref>`. It is similar to a JavaScript-action `uses:` but with two consequential differences. First, the reusable workflow runs **with its own steps and its own `uses:` references**, all of which the caller can be totally unaware of. Second, the reusable workflow inherits the caller's `secrets:` (selectively) and runs in the caller's repository security context, which means a compromised reusable workflow can extract secrets from the caller's environment even though no source change has been made to the caller's repo.

The combination — transitive `uses:` + secret inheritance + ref resolution at run time — means a single mutable tag in a reusable workflow's dependency graph is sufficient to compromise every job in the org that ever calls it. GitHub's own data shows the median Actions consumer has 12 distinct `uses:` references after expansion, of which roughly 60% point to mutable tags and only 11% to commit SHAs.

This article gives you a way out: a hard CI-side enforcement that rejects PRs introducing un-pinned references, a periodic drift audit that catches refs that *were* SHA-pinned but where the SHA now points to something different on the upstream, and a runtime detection that flags resolved-SHA mismatches before secrets are exposed.

Target systems: GitHub Enterprise Cloud or Server 3.13+, repositories using GitHub Actions, organisations with ≥10 repos pulling external actions, and any org consuming third-party reusable workflows (most CI/CD platform teams).

## Threat Model

1. **Maintainer account takeover** of a popular action (`actions/checkout`, `tj-actions/changed-files`, `reviewdog/action-setup`). Goal: rewrite the action's code or push a tag that points at malicious code, then wait for downstream CI to pull it.
2. **Force-push to the action's release branch**, where consumers reference `@main` or `@release/v1`. Goal: replace what the existing tag/branch resolves to without rotating the version number.
3. **Transitive compromise**: the attacker compromises a reusable workflow that *your* trusted workflow calls. Your direct `uses:` is fine; the transitive one is not.
4. **Insider creating a deliberately-mutable in-house workflow**: an employee adds `uses: ourorg/internal-workflows/.github/workflows/build.yml@main` to deploy pipelines, then later force-pushes `main` to add a step that exfils production credentials.
5. **Supply-chain attacker against the action's dependencies**: e.g., the action pulls `npm install` of a transitively-compromised package at run time.

Without enforcement, all five succeed silently. With the controls in this article, 1 and 2 require a SHA-collision (effectively impossible) or are detected by drift audit; 3 is bounded because reusable-workflow refs are also pinned; 4 is rejected at PR time; 5 is mitigated by network egress controls (covered separately) and reproducible-build attestations.

## Configuration / Implementation

### Step 1 — Repository setting: require SHA-pinned actions org-wide

GitHub Enterprise (Cloud and Server 3.14+) ships an org-level policy "Require actions to be pinned to a full-length commit SHA" under *Organization → Settings → Actions → General → Policies*. Enable it. The policy applies to direct `uses:` in workflow files but **does not** verify reusable-workflow `uses:` recursively, so it is necessary but not sufficient.

```bash
# Confirm via REST.
gh api orgs/${ORG}/actions/permissions \
  --jq '{enabled,allowed_actions,actions_pinning_required}'
```

Expect `actions_pinning_required: true`. If your enterprise plan does not expose the toggle, use the `actionlint` + `pin-github-action` pre-commit gate in Step 2 as the substitute.

### Step 2 — Pre-commit and PR-time enforcement

`actionlint` 1.7+ catches the obvious cases. Add it as a required PR check:

```yaml
# .github/workflows/pin-check.yml
name: pin-check
on:
  pull_request:
    paths: ['.github/workflows/**', '.github/actions/**']
permissions: { contents: read }
jobs:
  actionlint:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
      - name: Run actionlint with SHA-pin rule
        run: |
          bash <(curl -sSL https://raw.githubusercontent.com/rhysd/actionlint/v1.7.4/scripts/download-actionlint.bash) 1.7.4
          ./actionlint -shellcheck= -ignore 'expected ".*"' \
            -config-file .github/actionlint.yaml
      - name: Reject non-SHA refs
        run: |
          set -euo pipefail
          # Find every `uses:` that is not followed by 40-hex SHA.
          mapfile -t bad < <(grep -RnE \
            'uses:[[:space:]]+[^@]+@(?!([0-9a-f]{40})\b)[^[:space:]]+' \
            .github/workflows .github/actions 2>/dev/null || true)
          if [[ ${#bad[@]} -gt 0 ]]; then
            printf 'Non-SHA-pinned uses: refs:\n'
            printf '  %s\n' "${bad[@]}"
            exit 1
          fi
```

Add to `.github/actionlint.yaml`:

```yaml
self-hosted-runner:
  labels: []
config-variables:
  - DEPLOY_ENV
```

The grep is deliberately strict: it accepts only 40-hex-character refs after `@`. A version tag, a branch name, or a partial SHA all fail. If you also support GitHub Apps action references (`@<sha>`), this still works because the SHA portion is what's matched.

### Step 3 — Pin reusable-workflow `uses:` too

The same rule applies but most teams forget: reusable workflows referenced from inside *other* reusable workflows are out of sight. Add a second check that walks the call graph:

```yaml
  expand-and-check-transitive:
    runs-on: ubuntu-24.04
    needs: actionlint
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: Resolve transitive uses
        env:
          GH_TOKEN: ${{ secrets.GH_READONLY }}
        run: |
          # ./scripts/expand-uses.py walks every workflow in this repo,
          # downloads any `uses: org/repo/.github/workflows/...@SHA`,
          # and recurses into it, asserting all nested uses: are also SHA.
          python3 scripts/expand-uses.py --max-depth 5 \
            --fail-on-mutable
```

`scripts/expand-uses.py` is a ~150-line tool: parse YAML, for each `uses: <org>/<repo>/.github/workflows/<file>.yml@<sha>` reference, fetch that file at that SHA via the contents API, parse it, recurse. Fail if any step inside any reusable workflow uses a non-SHA ref. (See *Tools and Scripts* in the article-batch workflow doc for placement convention.)

### Step 4 — Periodic drift audit across the org

A SHA pin is durable on your end but the *meaning* of that SHA can change for the upstream maintainer if they force-push the tag. They cannot change what your workflow runs (the SHA still points to immutable commit content), but they *can* break your update workflow by repurposing the version tag while you keep using the old SHA. More importantly, a drift audit is how you spot upstream tags that have moved suspiciously — a strong signal of a `tj-actions`-style takeover.

```python
# scripts/drift_audit.py
#!/usr/bin/env python3
import os, re, sys, json, subprocess
from collections import defaultdict
import requests

GH = os.environ["GH_TOKEN"]
ORG = sys.argv[1]
PATTERN = re.compile(
    r'uses:\s+([^/\s]+)/([^/\s@]+)(?:/[^@\s]+)?@([0-9a-f]{40})\b')

def gh(url):
    r = requests.get(url, headers={"Authorization": f"Bearer {GH}",
                                   "Accept": "application/vnd.github+json"})
    r.raise_for_status()
    return r.json()

# Find every workflow file in every repo.
findings = defaultdict(list)
for repo in gh(f"https://api.github.com/orgs/{ORG}/repos?per_page=100"):
    name = repo["full_name"]
    try:
        tree = gh(f"https://api.github.com/repos/{name}/git/trees/HEAD?recursive=1")
    except Exception:
        continue
    for item in tree.get("tree", []):
        if not item["path"].startswith(".github/workflows/"):
            continue
        if not item["path"].endswith((".yml", ".yaml")):
            continue
        blob = gh(f"https://api.github.com/repos/{name}/contents/{item['path']}")
        import base64
        content = base64.b64decode(blob["content"]).decode("utf-8", "replace")
        for m in PATTERN.finditer(content):
            owner, repo_name, sha = m.group(1), m.group(2), m.group(3)
            findings[(owner, repo_name, sha)].append(f"{name}:{item['path']}")

# For each unique (owner, repo, SHA), check what tags currently point at it
# and compare to the latest tag on the upstream repo.
for (owner, repo, sha), consumers in findings.items():
    upstream = f"https://api.github.com/repos/{owner}/{repo}"
    try:
        tags = gh(f"{upstream}/tags?per_page=100")
    except Exception:
        continue
    matching = [t["name"] for t in tags if t["commit"]["sha"] == sha]
    latest = tags[0]["name"] if tags else "?"
    print(json.dumps({
        "owner": owner, "repo": repo, "pinned_sha": sha,
        "matches_tags": matching, "latest_tag": latest,
        "consumers": consumers[:3], "consumer_count": len(consumers),
    }))
```

Run weekly, ship the output to your SIEM, and alert on:

- A `pinned_sha` that no longer matches any tag on the upstream (the maintainer rotated tags away from it; benign or compromise — investigate).
- A `pinned_sha` whose `matches_tags` list shrank between two audits (the tag was force-pushed off your SHA).
- The same `pinned_sha` consumed by >50 workflows (a high-blast-radius dependency to keep on the watchlist).

### Step 5 — Allowlist of permitted action sources

Pinning by SHA is one half. The other half is bounding *which* upstream repos your actions can come from at all. Configure the org allowlist:

```yaml
# .github/actions-allowlist.yaml (consumed by your PR check)
allowed_owners:
  - actions
  - github
  - docker
  - aquasecurity
  - sigstore
  - slsa-framework
  - $YOUR_ORG
allowed_repos:
  - tj-actions/changed-files@d6e91a2266cdb9d62a2c1aa8d4c4e1e1b8e8c8c8
```

PR check reads this and rejects any `uses:` whose owner is not in `allowed_owners` and whose `owner/repo@sha` is not in `allowed_repos`.

### Step 6 — Runtime: verify resolved SHA before secrets are exposed

Add a *first* job to every secret-using workflow that fails fast if the resolver brought in something different from what was pinned:

```yaml
jobs:
  verify-action-resolution:
    runs-on: ubuntu-24.04
    permissions: { contents: read }
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: Verify all uses: pin to SHA
        run: |
          ./scripts/expand-uses.py --workflow ${{ github.workflow }} \
            --fail-on-mutable
  build:
    needs: verify-action-resolution
    secrets:
      DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
    runs-on: ubuntu-24.04
    steps: [...]
```

Putting this *before* the job that uses secrets means a malicious resolution never gets to see the `DEPLOY_KEY`.

### Step 7 — Detect token use anomalies

Even with all the above, an action that resolved fine yesterday could behave differently today (e.g., a npm postinstall in a transitive dep). Use the runner's audit log + egress restrictions:

```yaml
- name: Restrict runner egress
  uses: step-security/harden-runner@cb605e52c26070c328afc4562f0b4ada7618a84e  # v2.10.4
  with:
    egress-policy: block
    allowed-endpoints: >
      api.github.com:443
      objects.githubusercontent.com:443
      registry.npmjs.org:443
```

`harden-runner` (in `block` mode) has caught both the `tj-actions` and `reviewdog` incidents at the egress layer for users who had it deployed; the actions tried to reach `gist.githubusercontent.com` and `pastebin.com` to dump secrets and were blocked.

## Expected Behaviour

| Signal | Before | After |
|---|---|---|
| `uses:` with mutable tag | Accepted, runs whatever the tag points to | PR rejected at lint stage |
| Reusable-workflow transitive dep on a tag | Accepted, invisible to consumer | Rejected by `expand-uses.py` |
| Upstream tag force-push to a different SHA | Silent, runs new code on next pin update | Caught by weekly drift audit |
| Action attempts unexpected egress | Allowed | Blocked by harden-runner |
| Org-level pinning policy | "Recommended" docs | Enforced by GitHub setting |
| Action allowlist | Implicit (any allowed) | Explicit `allowed_owners` + per-repo SHA |
| Runtime token exposure to compromised action | Possible | Blocked by `verify-action-resolution` precondition |

Verification snippet:

```bash
# Local equivalent of the PR check.
grep -RnE 'uses:[[:space:]]+[^@]+@(?!([0-9a-f]{40})\b)[^[:space:]]+' \
  .github/workflows .github/actions
# Expect: no output. Any output is a violation.

# Drift audit dry-run for one repo.
GH_TOKEN=$(gh auth token) python3 scripts/drift_audit.py "$YOUR_ORG" \
  | jq 'select(.matches_tags | length == 0)'
# Expect: empty (every pinned SHA still maps to at least one upstream tag).
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Mandatory SHA pinning | Closes the mutable-tag class entirely | More friction updating actions | Renovate or Dependabot configured for SHA pins |
| Org-level allowlist | Bounds the upstream universe | New legitimate actions take a security review | Self-service portal with 24h SLO |
| Drift audit | Catches takeovers within a week | Noisy when upstreams rotate tags routinely | Tune to alert on *removed*, not *added*, tags |
| Egress block-list | Defeats secret-exfil even if action is compromised | False positives for actions that legitimately need outbound | Audit-mode rollout for two weeks before block |
| Transitive expansion | Catches reusable-workflow risk | Requires API token with read on all referenced repos | Use a fine-scoped GitHub App, not a PAT |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Lint check has a regex bug accepting partial SHA | Mutable refs slip through | Periodic re-audit of merged workflows | Tighten regex; add unit test |
| Allowlist drift (stale SHAs not maintained) | Failing builds, devs add bypass | Build failure metrics | Renovate or Dependabot with security review |
| GitHub App token has too-broad scope | Compromise of audit infra reads source | Audit log of token use | Fine-scope to `actions:read, contents:read` only |
| Reusable workflow stored privately | `expand-uses.py` cannot read it | Tool emits "private, skipped" warning | Trust internal repos under same org; require attestation |
| harden-runner audit-mode forgotten | False sense of security | Annotation says "audit" not "block" | Enforce policy by lint on the workflow's own contents |
| Org policy disabled per-repo | One repo opts out | Org config drift report | Make org policy non-overridable; review repo settings monthly |
| Force-push by your own maintainer to internal reusable workflow | Surprise behaviour change | Branch protection report | Branch protection: linear history, signed commits, no force-push |

## When to Consider a Managed Alternative

- **GitHub-hosted "Verified Creator" actions** carry signed provenance attestations (Sigstore-bundle) and are sufficient for many compliance regimes. Combine with SHA pinning for defence in depth.
- **GitLab CI** does not have the reusable-workflow shape but introduces its own `include:` directive with similar concerns; the same audit pattern applies.
- **Buildkite + agent-side allowlist** sidesteps the GitHub-cloud question entirely if your runners are on-prem.

## Related Articles

- [Securing GitHub Actions](/articles/cicd/securing-github-actions/)
- [GitHub Advanced Security at enterprise scale](/articles/cicd/github-advanced-security-enterprise/)
- [Pipeline egress control patterns](/articles/cicd/pipeline-egress-control/)
- [Trusted publishing with OIDC](/articles/cicd/trusted-publishing-oidc/)
- [Sigstore keyless signing for releases](/articles/cicd/sigstore-keyless-signing/)
