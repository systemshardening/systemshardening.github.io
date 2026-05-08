---
title: "Renovate and Dependabot Security Configuration: Auto-Merge Boundaries and Scope Rules"
description: "Bots that update dependencies are great until one auto-merges a malicious release. The defaults are safe-ish; the configuration that makes them production-safe is more deliberate."
slug: "renovate-dependabot-security"
date: 2026-04-29
lastmod: 2026-04-29
category: "cicd"
tags: ["renovate", "dependabot", "supply-chain", "auto-merge", "dependencies"]
personas: ["platform-engineer", "security-engineer", "devops"]
article_number: 226
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/cicd/renovate-dependabot-security/index.html"
---

# Renovate and Dependabot Security Configuration: Auto-Merge Boundaries and Scope Rules

## Problem

Dependency-update bots — Renovate, Dependabot — solve a real problem. Without them, dependencies stagnate; CVEs accumulate; teams spend half-days bumping versions before they can ship. With them, updates flow constantly.

The tension: every auto-merged update is a supply-chain decision. A compromised package, a typosquatted dependency, a maintainer-takeover release becomes an automatically-deployed update if the bot is configured to auto-merge.

The 2024-2025 incident landscape made this concrete: the `xz` backdoor, multiple npm typosquats with auto-malicious post-install scripts, the GitHub Actions registry compromises. Each could have been propagated by an auto-merging bot to hundreds of repositories.

By 2026 the bot-defaults are safer — Renovate's `minimumReleaseAge` and Dependabot's reviewer requirements provide friction — but production-safe configuration is more deliberate than what the docs default to.

The specific gaps in default bot configurations:

- Auto-merge enabled for all minor/patch updates without review.
- Major version bumps allowed automatically (often missed in policy).
- Indirect dependencies (transitive) updated with the same automation.
- No CVE-only auto-merge tier.
- No release-age requirement (a brand-new release auto-merges within minutes).
- No alignment with the org's update SLAs.
- Branch protection sometimes bypassed for the bot's PRs.

This article covers Renovate (the more flexible of the two) and Dependabot configuration patterns: scope rules, minimum-release-age requirements, CVE-only auto-merge, sign-off and reviewer requirements, dependency-confusion mitigations, and the operational integration with code-owners.

**Target systems:** Renovate self-hosted or via GitHub App; Dependabot via GitHub native; concepts apply to GitLab Renovate, Snyk PR creator, etc.

## Threat Model

- **Adversary 1 — Maintainer-takeover attack:** legitimate package's maintainer account compromised; a malicious release ships under the package's name. Bot auto-merges into your repos.
- **Adversary 2 — Typosquat / dependency confusion:** attacker publishes a package similar in name to one you depend on; misconfigured bot picks it up.
- **Adversary 3 — Malicious post-install script:** new release contains code that runs during dependency install on your CI runners, exfiltrating secrets.
- **Adversary 4 — Major-version-bump abuse:** bot auto-merges a major version that introduces silent breaking changes to security-relevant behavior.
- **Adversary 5 — Forged sign-off:** the bot's auto-approver mechanism is bypassed; updates merge without genuine review.
- **Access level:** Adversaries 1-3 have malicious-package distribution capability. Adversary 4 is structural. Adversary 5 has CI-config-modify access.
- **Objective:** Get malicious code into your build / runtime; cause subtle security regressions through unwanted updates.
- **Blast radius:** with auto-merge enabled across an org, a single bad upstream release lands in every consumer repo simultaneously. With proper scope rules and release-age requirements, the same bad release is held back, observed, and either merged after vetting or skipped.

## Configuration

### Step 1: Renovate Base Configuration

```json
// renovate.json — checked into the repo root.
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": [
    "config:recommended",
    ":dependencyDashboard"
  ],
  "labels": ["dependencies"],
  "automergeStrategy": "squash",
  "commitMessagePrefix": "chore(deps):",
  "rangeStrategy": "bump",
  "lockFileMaintenance": {
    "enabled": true,
    "schedule": ["before 5am on monday"]
  },
  "minimumReleaseAge": "7 days",
  "internalChecksFilter": "strict",
  "configMigration": true
}
```

Key settings:

- `minimumReleaseAge: 7 days` — refuses updates to releases newer than 7 days. The xz backdoor was caught within ~3 days; this catches most recent compromises.
- `internalChecksFilter: strict` — Renovate's internal checks must pass; PRs aren't created for known-stale or known-broken updates.
- `lockFileMaintenance` confined to a weekly window.

### Step 2: Per-Manager Scope Rules

Different package managers have different risk profiles. npm has the highest typosquat / supply-chain risk; Cargo has stronger publishing controls; system packages (apt) have distro maintainers.

```json
{
  "packageRules": [
    {
      "matchManagers": ["npm"],
      "matchUpdateTypes": ["patch"],
      "automerge": true,
      "automergeType": "branch",
      "platformAutomerge": true,
      "minimumReleaseAge": "14 days"
    },
    {
      "matchManagers": ["npm"],
      "matchUpdateTypes": ["minor"],
      "automerge": false,
      "reviewers": ["team:security", "team:platform"]
    },
    {
      "matchManagers": ["npm"],
      "matchUpdateTypes": ["major"],
      "automerge": false,
      "reviewers": ["team:security"],
      "labels": ["dependencies", "major-version"]
    },
    {
      "matchManagers": ["cargo"],
      "matchUpdateTypes": ["patch", "minor"],
      "automerge": true,
      "minimumReleaseAge": "5 days"
    },
    {
      "matchManagers": ["dockerfile"],
      "matchUpdateTypes": ["pin", "digest"],
      "automerge": true,
      "minimumReleaseAge": "0 days"
    }
  ]
}
```

The rules:

- **npm patches**: 14-day delay, auto-merge OK.
- **npm minor**: requires security + platform review.
- **npm major**: requires security review + explicit label.
- **Cargo patches/minors**: 5-day delay (Cargo's stricter publishing).
- **Dockerfile digest pins**: auto-merge immediately (we control the pinning).

### Step 3: Security-Tier Auto-Merge

Some updates fix CVEs; for those, bypass the standard delay (the CVE patch is *more* important than aging concerns).

```json
{
  "packageRules": [
    {
      "matchUpdateTypes": ["patch", "minor"],
      "matchPackagePatterns": ["*"],
      "matchCurrentVersion": "!/^0/",
      "vulnerabilityAlerts": {
        "automerge": true,
        "labels": ["security", "vulnerability"],
        "minimumReleaseAge": "0 days",
        "schedule": ["at any time"]
      }
    }
  ]
}
```

A CVE-fixing patch auto-merges immediately. A non-CVE patch waits 7-14 days. The trade-off is intentional: known-bad-version-now > unknown-but-aging-version-later.

### Step 4: Dependency Confusion Mitigation

```json
{
  "packageRules": [
    {
      "matchManagers": ["npm"],
      "matchPackagePatterns": ["^@myorg/"],
      "registryUrls": ["https://npm.internal.example.com"],
      "automerge": false,
      "reviewers": ["team:platform"]
    },
    {
      "matchManagers": ["pip"],
      "matchPackagePatterns": ["^myorg-"],
      "registryUrls": ["https://pypi.internal.example.com"],
      "automerge": false
    }
  ]
}
```

Internal-namespace packages must come from the internal registry; never from the public registry. Pin via `registryUrls`.

For `.npmrc` enforcement at the build level:

```ini
# .npmrc
@myorg:registry=https://npm.internal.example.com
//npm.internal.example.com/:_authToken=${NPM_INTERNAL_TOKEN}

# Reject installation from any other registry by default.
registry=https://npm.internal.example.com
```

Combined: Renovate uses the right registry; the build-time install is also pinned. Dependency-confusion attacks (where a public registry has a package matching an internal name) fail at both.

### Step 5: Reviewer Requirements

Bot PRs should require reviewers like any other PR. Renovate alone won't bypass branch protection if your branch-protection rules require reviews.

```yaml
# Branch protection in repo settings (or via Terraform GitHub).
required_pull_request_reviews:
  required_approving_review_count: 1
  require_code_owner_reviews: true
  dismiss_stale_reviews: true

# CODEOWNERS includes:
#   /package.json @myorg/security
#   /Cargo.toml @myorg/platform
#   /go.mod @myorg/platform
```

A code-owner from the security team reviews every dependency change. For auto-merging tiers, set up a bot-account that has CODEOWNERS approval rights but only on dependency files — and only triggers auto-merge after passing CI.

### Step 6: Auto-Merge via Bot Account With Limited Scope

Don't grant the same human-PAT auto-merge that a human has. Use a GitHub App or bot-account with scope to only merge dependency-related PRs:

```yaml
# Branch protection allows the bot to bypass:
allowance_for_admins: false
allowance_for_specific_actors:
  - apps: [renovate-merge-bot]   # ONLY this bot can bypass
```

The Renovate bot account has no permission to push directly; it only merges PRs that pass CI and CODEOWNERS.

### Step 7: Weekly / Monthly Aggregation

For low-velocity dependencies, aggregate updates rather than per-package PRs:

```json
{
  "packageRules": [
    {
      "matchPackagePatterns": ["^@types/"],
      "groupName": "TypeScript types",
      "schedule": ["before 5am on monday"]
    },
    {
      "matchManagers": ["github-actions"],
      "groupName": "GitHub Actions",
      "schedule": ["before 5am on monday"]
    }
  ]
}
```

One PR with all type-package updates per week; one PR for GitHub Actions updates. Reviewers see a focused list rather than 30 individual PRs.

### Step 8: Dependabot for GitHub Actions Specifically

Dependabot has good defaults for GitHub Actions specifically; complement Renovate (Renovate handles application deps; Dependabot can handle Actions).

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
    pull-request-branch-name:
      separator: "-"
    open-pull-requests-limit: 5
    reviewers:
      - "myorg/security-team"
    labels:
      - "dependencies"
      - "github-actions"
    commit-message:
      prefix: "ci"
      include: "scope"
```

GitHub Actions are themselves a supply-chain risk; treat the bot's PRs as security-relevant. Pin actions to specific commits, not just tags:

```yaml
# In workflow:
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11   # v4.1.1
```

Tag-floats are risky; commit-pin-and-bot-update keeps you safe.

### Step 9: Telemetry on Bot Activity

```
deps_pr_created_total{manager, type}
deps_pr_merged_total{manager, type, auto}
deps_pr_closed_unmerged_total{reason}
deps_security_vuln_detected_total{severity}
deps_security_vuln_fixed_total{severity, fix_age_seconds}
```

Alert on:

- `deps_security_vuln_detected_total{severity="critical"}` rising — supply chain has lots of CVEs; investigate.
- Long `fix_age_seconds` for critical vulns — bot stuck somewhere; investigate config.

### Step 10: Periodic Audit

Quarterly:

- Review PRs from the last 90 days; spot-audit auto-merged PRs.
- Confirm CODEOWNERS still aligns with team responsibilities.
- Update `minimumReleaseAge` based on observed incident response times.
- Confirm no bypass routes (admin force-merge, etc.) were used.

## Expected Behaviour

| Signal | Default bot config | Hardened |
|--------|----------------------|------------|
| New release published | Auto-merged within hours | Held until `minimumReleaseAge` (7-14 days) |
| Major version bump | Often auto-merged | Blocked; requires explicit review |
| CVE patch released | Same delay as routine update | Auto-merged immediately |
| Internal-namespace package from public registry | Possibly merged | Refused; registry pinned |
| Auto-merge bypass via admin | Possible | Blocked or alerted |
| GitHub Actions update with float tag | Tag-only pin | Commit-pin + bot maintains |
| Reviewer requirements | Often skipped for bot PRs | Required via CODEOWNERS |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| `minimumReleaseAge` | Catches recent compromises | Slower legitimate updates | 7-14 days is reasonable; CVEs bypass for urgency. |
| Major-version review | Avoids surprise breaking changes | More PRs require human time | Major bumps are rare; review effort proportional. |
| CVE fast-merge | Fast security fix | Depends on CVE detection accuracy | Snyk / GitHub Dependabot / OSV scoring is generally reliable; fail-open on CVE detection (i.e., still apply the CVE patch). |
| Dependency-confusion pinning | Defeats namespace squatting | Internal registry must be operational | Cache layer; failover to public is intentionally disabled. |
| Bot-account auto-merge | Bot can't be a backdoor for arbitrary code | Bot-account scope to maintain | Standard GitHub App pattern. |
| Quarterly audit | Catches drift | Time investment | 1-2 hours per quarter. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| `minimumReleaseAge` blocks legitimate fix | Long-pending dep update | Renovate dashboard shows aging PR | If a legit security fix needs faster merge, manually merge with PR review. |
| CVE database miss | Critical update treated as routine | Vulnerability tracker shows your repo affected | Subscribe to upstream security feeds; use GitHub Security Advisories. |
| Internal-namespace package mistakenly published to public | Dependency-confusion vulnerability | Public registry shows your package name | Take down public publication; rotate any tokens published with it. |
| Auto-merge bot has too-broad permissions | Bot can merge non-dependency PRs | Audit log shows bot merging unexpected paths | Tighten bot-account RBAC; restrict to dependency files only. |
| Reviewer subverted | Code-owner team wins approval but reviewer was a bot account | Audit shows reviews from automation | Require human reviewer flag; refuse approvals from non-human accounts. |
| Dependency removal but bot keeps trying | Confusing PRs for removed deps | Renovate logs show errors | Use `ignoreDeps` to explicitly skip; clean up old config. |
| Lock-file maintenance corrupts file | Build fails after Monday merge | CI reports broken lockfile | Revert; investigate the specific package's lockfile change; re-run. |

## Related Articles

- [SLSA Build Provenance: Source-to-Registry Integrity](/articles/cicd/slsa-provenance/)
- [Dependency Pinning](/articles/cicd/dependency-pinning/)
- [Software Supply Chain Third-Party Risk](/articles/cicd/software-supply-chain-third-party-risk/)
- [SBOM Generation and Use](/articles/cicd/sbom/)
- [Just-in-Time CI Access](/articles/cicd/jit-ci-access/)
