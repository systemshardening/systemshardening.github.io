---
title: "OpenSSF Scorecard for Supply Chain Security"
description: "Use OpenSSF Scorecard to evaluate whether open source dependencies follow security best practices, enforce minimum scores in CI, and identify projects that ship silent CVE fixes via public PRs."
slug: openssf-scorecard-supply-chain
date: 2026-05-02
lastmod: 2026-05-02
category: cross-cutting
tags: ["openssf", "scorecard", "supply-chain", "open-source", "cve", "security-posture", "dependencies"]
personas: ["security-engineer", "platform-engineer", "sre"]
article_number: 349
difficulty: intermediate
estimated_reading_time: 15
published: true
layout: article.njk
permalink: "/articles/cross-cutting/openssf-scorecard-supply-chain/index.html"
---

# OpenSSF Scorecard for Supply Chain Security

## Problem

An average production service depends on hundreds of open source packages. Each package brings its own security posture: some have dedicated security teams, coordinated CVE disclosure, signed release artifacts, and automated dependency updates; others are maintained by a single developer who has never heard of SECURITY.md and merges PRs directly to main without review. From the outside, both packages look identical in a `requirements.txt` or `go.sum`. A version number and a package name convey nothing about whether the project is likely to disclose vulnerabilities responsibly, sign its release artifacts, or even keep up with its own transitive dependencies. The question "is this dependency safe to use?" has no simple answer — but OpenSSF Scorecard provides a structured, automated framework for forming a defensible judgment.

OpenSSF Scorecard is a tool from the Open Source Security Foundation that automatically evaluates a GitHub-hosted open source project across 19 or more security checks. Each check maps to a concrete security practice: Does the repository have a SECURITY.md? Are releases cryptographically signed? Does the project use Dependabot or Renovate to keep its own dependencies current? Does it require code review before merging PRs? Are dangerous GitHub Actions workflow patterns present — specifically `pull_request_target` with untrusted code checkout, a known supply chain attack vector? Does the project pin its CI dependencies to digest rather than mutable tag? Has the project been integrated with a fuzzing harness via OSS-Fuzz? Scorecard aggregates these checks into a composite score from 0 to 10, with individual check scores and explanations available in JSON format. The checks are free to run against any public GitHub repository and take under two minutes per project.

The core problem this article addresses is the relationship between Scorecard signals and the silent-fix / patch-gap problem. Many open source projects score poorly on Scorecard precisely because they do not follow the security practices that would make CVE disclosure and patch tracking tractable. No SECURITY.md means there is no established channel for researchers to report vulnerabilities privately: when someone finds a bug, they open a public issue or a public PR because there is nowhere else to go. No signed releases means that even if a maintainer does publish a fixed version, you have no cryptographic assurance that the artifact you downloaded corresponds to the public commit. No branch protection and no mandatory code review mean that security fixes — and, equally, malicious commits — can land without a second pair of eyes. Projects scoring below 5 out of 10 on Scorecard are statistically more likely to have real vulnerabilities fixed quietly as "bug fix" commits with no associated advisory, no CVE, and no notification to downstream consumers.

The open source angle is the central theme of this article. Scorecard results let you identify which of your dependencies are structurally predisposed to the silent-fix problem before a crisis forces the discovery. A low "Maintained" score — fewer than ten commits in the past 90 days — indicates a project where security fixes may not be getting applied at all, and where any fix that does land may do so months after the vulnerability was identified. A missing "Security-Policy" check means no responsible disclosure channel exists: vulnerabilities will be fixed, if they are fixed, via public PRs with no advance warning and no coordination window. A low "Signed-Releases" score means you cannot verify that the release artifact you are consuming came from the official maintainer rather than a compromised account or a compromised package registry. A failing "Binary-Artifacts" check flags pre-built binaries committed to the repository that cannot be verified against source — a classic supply chain compromise vector. A low "Code-Review" score means PRs are merged without oversight, making it difficult to distinguish a genuine security fix from an injected backdoor. A failing "Dangerous-Workflow" check indicates GitHub Actions configurations that accept untrusted code from forks and run it in a privileged context — an attack surface that has been exploited against real open source projects.

To make this concrete, consider projects covered elsewhere in this series. The `vector` log pipeline (github.com/vectordotdev/vector) scores above 7 and shows passing checks for branch protection, dependency update tooling, and code review — the security process maturity is visible in the Scorecard output. By contrast, older network utilities like `arpwatch` have minimal or no recent Scorecard data and no SECURITY.md, which matches their actual security disclosure history: fixes appear as commits with no associated CVE. `litellm` (github.com/BerriAI/litellm) is a fast-moving project in the LLM proxy space; its Scorecard reflects the trade-offs of rapid iteration — dependency pinning and signed releases are weaker than projects with longer security maturity. `dagger` (github.com/dagger/dagger) shows stronger scores given its infrastructure focus and the security awareness of its maintainers. The pattern is consistent: Scorecard scores predict security process maturity, and security process maturity predicts whether you will get advance warning of a vulnerability fix.

**Target systems:** OpenSSF Scorecard CLI 5.x, GitHub Actions integration, any repository with open source dependencies.

## Threat Model

**1. Silent CVE fix exploited before patch applied.** A dependency your team uses for parsing network packets has no SECURITY.md. A researcher discovers a memory corruption vulnerability and opens a public PR because there is no private disclosure channel. The fix is merged without an advisory, without a CVE request, and without a tagged release — it is present only in a subsequent point release bundled with unrelated changes. Your vulnerability scanner never generates an alert because no CVE exists. An attacker monitors public GitHub for security-relevant commits in popular open source projects, identifies the fix 12 hours after merge, develops a working exploit, and reaches your service 48 hours after the fix was public. Your team learns about the vulnerability when the incident begins.

**2. Compromised unsigned release.** A dependency with low Signed-Releases score on Scorecard does not sign its PyPI or npm releases. An attacker compromises the maintainer's package registry credentials — a credential-stuffing attack against a reused password — and publishes a malicious version with a higher version number. Because releases are not signed, your CI pipeline's `pip install` or `npm install` fetches and executes the malicious artifact without any verification that it came from the legitimate maintainer. A signed-release workflow would have allowed `cosign` or PEP 740 attestations to block the installation at the point of consumption.

**3. The patch-gap amplifier.** Low-Scorecard projects combine multiple independent risk factors. No signed releases mean you cannot verify artifacts. No mandatory code review means you cannot distinguish legitimate commits from injected ones. No SECURITY.md means vulnerability fixes arrive without coordination. No Dependabot means the project's own transitive dependencies are out of date, adding a second layer of exposure. Each factor independently widens the patch-gap exploitation window. Together, they create a dependency that is simultaneously difficult to monitor, difficult to verify, and slow to patch. A single high-CVSS CVE in a package with all four gaps can remain exploitable in production for months because the signals that would trigger remediation — an advisory, a CVE, a signed release with clear changelog — never materialise.

**4. Dangerous CI workflow injection.** A dependency's GitHub Actions configuration uses `pull_request_target` to run CI against fork PRs with write access to secrets. A Scorecard "Dangerous-Workflow" check failure would have flagged this pattern. An attacker submits a pull request to the dependency repository with a workflow modification that exfiltrates the repository's signing keys or package registry credentials. The malicious code runs in the privileged context granted to `pull_request_target`. A compromised signing key or registry credential enables the attacker to publish a malicious release artifact that passes any signature check your pipeline performs, because it is signed with the legitimate key.

**Blast radius:** The common factor across all four scenarios is that Scorecard signals are available before the incident. A dependency that scores 3 out of 10 with failing checks for Security-Policy, Signed-Releases, Code-Review, and Dangerous-Workflow is telling you, in structured machine-readable form, that it lacks the practices that would give you advance warning, verification capability, and oversight. Ignoring those signals means accepting the blast radius of all four threat scenarios simultaneously.

## Configuration / Implementation

### Running Scorecard Against Your Dependencies

Install the Scorecard CLI via the official release:

```bash
# Install Scorecard CLI (requires GITHUB_AUTH_TOKEN for API access)
export GITHUB_AUTH_TOKEN="ghp_your_token_here"

# Score a single dependency
scorecard --repo=github.com/vectordotdev/vector --format json \
  | jq '.checks[] | {name, score, reason}'

# Score a specific project and show only failing or low-score checks
scorecard --repo=github.com/opencontainers/runc --format json \
  | jq '[.checks[] | select(.score < 5)] | sort_by(.score)'
```

For bulk evaluation across your dependency list, extract repositories from language-specific lockfiles and iterate:

```bash
#!/usr/bin/env bash
# score-dependencies.sh — score Go module dependencies from go.sum
set -euo pipefail

THRESHOLD=5
FAILED=0

# Extract unique GitHub-hosted module paths from go.sum
go list -m all \
  | grep 'github.com' \
  | awk '{print $1}' \
  | sort -u \
  | while read -r module; do
      repo=$(echo "$module" | sed 's|github.com/||' | cut -d'/' -f1-2)
      result=$(scorecard --repo="github.com/${repo}" --format json 2>/dev/null || echo '{"score":0}')
      score=$(echo "$result" | jq -r '.score // 0')
      if (( $(echo "$score < $THRESHOLD" | bc -l) )); then
        echo "FAIL score=${score} repo=github.com/${repo}"
        FAILED=1
      else
        echo "PASS score=${score} repo=github.com/${repo}"
      fi
  done

exit "$FAILED"
```

For Python projects, extract GitHub-sourced packages from `pip freeze` output:

```bash
#!/usr/bin/env bash
# score-python-deps.sh
set -euo pipefail

THRESHOLD=5

pip freeze \
  | grep -E '^[A-Za-z0-9_-]+ @ https://github\.com/' \
  | sed 's|.* @ https://github.com/||' \
  | cut -d'/' -f1-2 \
  | sort -u \
  | while read -r repo; do
      score=$(scorecard --repo="github.com/${repo}" --format json 2>/dev/null \
        | jq -r '.score // 0')
      echo "score=${score} repo=github.com/${repo}"
  done
```

### Integrating Scorecard into CI

Use `ossf/scorecard-action` to score your own repository on each push and publish results to the GitHub Security tab:

```yaml
# .github/workflows/scorecard.yml
name: Scorecard supply chain security
on:
  push:
    branches: [main]
  schedule:
    - cron: "30 1 * * 1"
  pull_request:
    branches: [main]

permissions:
  security-events: write
  id-token: write
  contents: read
  actions: read

jobs:
  analysis:
    name: Scorecard analysis
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Run analysis
        uses: ossf/scorecard-action@v2.4.0
        with:
          results_file: results.sarif
          results_format: sarif
          publish_results: true

      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: SARIF file
          path: results.sarif
          retention-days: 5

      - name: Upload to code-scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

For dependency auditing as a CI gate, add a step that scores direct dependencies and fails on threshold violations:

```yaml
# Add to an existing workflow
- name: Audit dependency Scorecard scores
  env:
    GITHUB_AUTH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: |
    THRESHOLD=5
    FAILED=0
    # Read dependency list from file (one github.com/org/repo per line)
    while IFS= read -r repo; do
      [[ -z "$repo" || "$repo" =~ ^# ]] && continue
      score=$(scorecard --repo="${repo}" --format json 2>/dev/null \
        | jq -r '.score // 0')
      if awk "BEGIN{exit !($score < $THRESHOLD)}"; then
        echo "::error::Low Scorecard score (${score}/10) for ${repo}"
        FAILED=1
      else
        echo "::notice::Scorecard score ${score}/10 for ${repo}"
      fi
    done < .github/tracked-dependencies.txt
    exit "$FAILED"
```

### Enforcing Minimum Scores as a Policy

Use an OPA/Rego policy to evaluate Scorecard JSON output and enforce per-check thresholds as part of a dependency approval workflow:

```rego
# policies/scorecard.rego
package scorecard

import future.keywords.if
import future.keywords.in

# Minimum acceptable composite score for any dependency
default allow := false

# Required minimum scores per check (0-10 scale)
minimum_check_scores := {
  "Signed-Releases":  5,
  "Security-Policy":  1,
  "Code-Review":      5,
  "Branch-Protection": 3,
  "Dangerous-Workflow": 8,
  "Dependency-Update-Tool": 3,
}

allow if {
  count(violations) == 0
}

violations contains msg if {
  some check in input.checks
  min_score := minimum_check_scores[check.name]
  check.score < min_score
  msg := sprintf(
    "Check '%s' scored %d, minimum required is %d: %s",
    [check.name, check.score, min_score, check.reason]
  )
}

violations contains msg if {
  input.score < 4
  msg := sprintf(
    "Composite Scorecard score %v is below minimum threshold of 4",
    [input.score]
  )
}
```

Evaluate it against a Scorecard JSON result:

```bash
scorecard --repo=github.com/some/dependency --format json > scorecard-result.json
opa eval \
  --data policies/scorecard.rego \
  --input scorecard-result.json \
  --format pretty \
  'data.scorecard.allow'
```

For dependencies that score below threshold but have no viable alternative, document accepted risk formally:

```yaml
# .github/accepted-scorecard-exceptions.yml
exceptions:
  - repo: github.com/legacy-project/important-lib
    composite_score: 3.2
    failing_checks:
      - Signed-Releases
      - Security-Policy
    accepted_risk: >
      No alternative available. Compensating controls: GitHub watch
      notifications enabled, weekly manual commit review, pinned to
      exact commit digest in go.mod.
    owner: platform-team
    review_date: 2026-08-01
    ticket: PLAT-4421
```

### Using Scorecard to Identify Patch-Gap Risk

For dependencies scoring low on "Security-Policy" and "Signed-Releases", set up GitHub watch notifications and supplementary monitoring:

```bash
# Enable GitHub watch notifications for a repository via API
gh api \
  --method PUT \
  /repos/some-org/some-repo/subscription \
  -f subscribed=true \
  -f ignored=false

# Poll for recent commits touching security-relevant paths
gh api repos/some-org/some-repo/commits \
  --jq '.[] | {sha: .sha, message: .commit.message, date: .commit.author.date}' \
  | head -20

# Check commits touching auth or crypto paths specifically
gh api "repos/some-org/some-repo/commits?path=src/crypto&per_page=10" \
  --jq '.[].commit | {message, date: .author.date}'
```

Combine OSV and deps.dev data for a complete picture of each flagged dependency:

```bash
# Query OSV for known vulnerabilities in a package
curl -s "https://api.osv.dev/v1/query" \
  -H "Content-Type: application/json" \
  -d '{"package": {"name": "somepackage", "ecosystem": "PyPI"}}' \
  | jq '.vulns[] | {id, summary, modified}'

# Cross-reference using osv-scanner against a lockfile
osv-scanner --lockfile=requirements.txt --json \
  | jq '.results[].packages[] | select(.vulnerabilities | length > 0)'
```

### deps.dev and osv.dev Integration

The `deps.dev` API surfaces Scorecard scores alongside dependency graph data and known vulnerabilities, enabling a single query to retrieve both security posture and CVE exposure:

```bash
# Get Scorecard data for a package version via deps.dev
curl -s "https://api.deps.dev/v3alpha/systems/npm/packages/express/versions/4.18.2" \
  | jq '{
      version: .versionKey.version,
      scorecard: .scorecard.overallScore,
      advisories: [.advisoryKeys[].id]
    }'

# Get the full dependency graph for a Go module
curl -s "https://api.deps.dev/v3alpha/systems/go/packages/github.com%2Fvectordotdev%2Fvector/versions/v0.38.0:dependencies" \
  | jq '.nodes[] | {package: .versionKey.name, version: .versionKey.version}'
```

Run `osv-scanner` against multiple lockfile formats in a single pass:

```bash
# Scan all lockfiles in the repository
osv-scanner \
  --lockfile=go.sum \
  --lockfile=package-lock.json \
  --lockfile=requirements.txt \
  --json \
  | jq '.results[].packages[]
        | select(.vulnerabilities | length > 0)
        | {name: .package.name, version: .package.version,
           vulns: [.vulnerabilities[].id]}'
```

### Scorecard for Your Own Project

Running Scorecard against your own repositories reveals gaps that downstream consumers of your project would see:

```bash
# Score your own repository
scorecard --repo=github.com/your-org/your-repo --format json \
  | jq '.checks[] | select(.score < 8) | {name, score, reason, documentation}'
```

Common improvements and their Scorecard impact:

```bash
# Add SECURITY.md to the repository root (improves Security-Policy check)
cat > SECURITY.md << 'EOF'
# Security Policy

## Reporting a Vulnerability

Report security vulnerabilities to security@your-org.com.
We will respond within 72 hours and aim to release a fix within 30 days.
EOF

# Sign releases with cosign (improves Signed-Releases check)
# In your release workflow:
cosign sign-blob \
  --key cosign.key \
  --output-signature dist/binary.sig \
  dist/binary

# Pin GitHub Actions to commit digests (improves Pinned-Dependencies check)
# Replace: uses: actions/checkout@v4
# With:    uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

### Monitoring Scorecard Changes Over Time

The `scorecard-monitor` tool from the OpenSSF project tracks score changes for a watchlist of repositories and alerts on regressions:

```bash
# Install scorecard-monitor
go install github.com/ossf/scorecard-monitor@latest

# Create a watchlist configuration
cat > watchlist.yml << 'EOF'
repositories:
  - github.com/vectordotdev/vector
  - github.com/opencontainers/runc
  - github.com/grpc/grpc-go
  - github.com/BerriAI/litellm
minimum_score: 5
alert_on_decrease: true
EOF

# Run monitor and report changes since last run
scorecard-monitor \
  --config=watchlist.yml \
  --report-format=json \
  > scorecard-changes.json

jq '.changes[] | select(.score_delta < -1)
    | {repo: .repository, old: .previous_score, new: .current_score, delta: .score_delta}' \
  scorecard-changes.json
```

Alert on score decreases by integrating with your alerting pipeline. A project that drops from 7 to 3 after a key maintainer departs is a concrete signal that your monitoring and patching strategy for that dependency needs to change.

## Expected Behaviour

| Signal | Without Scorecard evaluation | With Scorecard-based dependency policy |
|---|---|---|
| Silent CVE fix in low-score dependency (no SECURITY.md, no CVE filed) | No alert generated; vulnerability remains unpatched until incident or manual discovery | Dependency flagged at onboarding; GitHub watch enabled; commit monitoring catches security-relevant changes within hours |
| Unsigned release from compromised registry account | Malicious version installed by CI without verification | Low Signed-Releases score triggers policy block at dependency approval; release signature verification enforced in install step |
| Dangerous CI workflow (`pull_request_target`) in dependency | Potential supply chain compromise goes undetected until attack occurs | Failing Dangerous-Workflow check surfaces in bulk evaluation; dependency flagged for review before adoption |
| Patch-gap exploitation window | Measured in weeks to months; no tooling closes the gap for silent fixes | Reduced to hours for monitored repositories; GitHub watch and commit polling catch public fixes before attackers can weaponise |
| Dependency abandonment (maintainer stops committing) | Discovered during an incident when a fix is needed but the project is dead | Low Maintained score and score regression alert surfaces abandonment proactively; migration or fork decision made before a crisis |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Strict composite score threshold (e.g., minimum 5/10) | Blocks high-risk dependencies before adoption; creates consistent policy | Blocks mature projects with good security practices that score low due to missing tooling (e.g., no Dependabot because they use an internal tool) | Per-check thresholds instead of composite-only; exception process with documented rationale and review date |
| CI integration for dependency auditing | Automated enforcement; prevents score regressions going unnoticed | GitHub API rate limits (5,000 requests/hour authenticated) constrain bulk runs across large dependency trees | Cache Scorecard results (TTL 24 hours); run only on dependency lockfile changes, not every commit; use deps.dev API for cached results |
| Using Scorecard as primary security signal | Structured, automated, consistent across all GitHub-hosted projects | High score does not mean no vulnerabilities — a project can have excellent process and still have undisclosed bugs; Scorecard measures process, not outcomes | Combine with osv-scanner for known CVE coverage; treat Scorecard as a process maturity signal, not a vulnerability-free certification |
| Bulk evaluation of transitive dependencies | Full-depth visibility into supply chain risk | Transitive dependency trees can be hundreds of packages; scoring all of them is time-consuming and API-intensive | Prioritise direct dependencies and first-level transitive dependencies; use deps.dev bulk API endpoint for cached results |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| GitHub API rate limit exhausts during bulk Scorecard run | CI job fails mid-run with HTTP 403; partial results only; some dependencies not evaluated | Monitor `X-RateLimit-Remaining` header in Scorecard output; CI job exits non-zero with rate limit error message | Implement result caching with 24-hour TTL; split bulk runs across multiple tokens (one per team); use deps.dev cached Scorecard API as fallback |
| Dependency scores fluctuate between runs (breaking CI) | CI fails on a dependency whose score dropped transiently (e.g., a check re-evaluated differently as GitHub data changes) | Score variance greater than 1 point between consecutive runs for the same repository | Apply a 7-day rolling average threshold rather than single-run score; add ±1 tolerance band before triggering a failure |
| Scorecard false positive on a legitimate project | A well-maintained project scores low because it uses a non-standard toolchain that Scorecard does not recognise (e.g., internal signing tool not detected by Signed-Releases check) | Security team review of failing check reveals tooling gap rather than real risk | Per-check exception with documented evidence (e.g., link to signing documentation); set check-specific override in exception file; engage OpenSSF to add support for the toolchain |
| Scorecard result data is stale (cached copy from deps.dev or internal cache) | Evaluation uses a score from weeks ago; a project that has since deteriorated (maintainer abandonment) appears healthy | Add `scored_at` field to cached results; alert if cache age exceeds threshold | Enforce maximum cache age of 7 days for actively monitored dependencies; re-score on dependency version bump; scorecard-monitor weekly re-scan |
| Critical dependency scores below threshold with no viable alternative | Policy blocks a required dependency (e.g., a hardware vendor SDK with score 2/10) | Policy evaluation fails; security team escalated | Invoke formal exception process: document risk, add compensating controls (pin to exact digest, restrict network access, sandbox process), set 90-day review date, assign named owner |

## Related Articles

- [Software Supply Chain and Third-Party Risk](/articles/cicd/software-supply-chain-third-party-risk/)
- [SBOM: Software Bill of Materials](/articles/cicd/sbom/)
- [Dependency Pinning](/articles/cicd/dependency-pinning/)
- [Artifact Integrity](/articles/cicd/artifact-integrity/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
