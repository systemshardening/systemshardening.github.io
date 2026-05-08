---
title: "Automating License Compliance Checks in CI/CD Pipelines"
description: "A copyleft dependency buried three levels deep in your transitive graph can legally obligate you to open-source your entire product. Automated license scanning in CI catches that before it ships."
slug: license-compliance-cicd
date: 2026-05-07
lastmod: 2026-05-07
category: cicd
tags:
  - license-compliance
  - sbom
  - open-source-compliance
  - legal-risk
  - supply-chain
personas:
  - security-engineer
  - platform-engineer
article_number: 535
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/cicd/license-compliance-cicd/
---

# Automating License Compliance Checks in CI/CD Pipelines

## Problem

A copyleft dependency buried three levels deep in your transitive graph can legally obligate you to open-source your entire product. This is not a theoretical risk: GPL and AGPL violations have resulted in litigation, forced source disclosure, and product recalls. The problem compounds in modern software because direct dependencies import other dependencies, which import others — a typical Node.js application has 800–1,500 transitive dependencies, each carrying its own license. No developer reviews every transitive license manually.

The security-adjacent nature of license compliance is often misunderstood. Unlike a CVE, a license violation does not result in a breach. It results in a legal incident: cease-and-desist letters, mandatory source disclosure, or injunctions that halt distribution. For SaaS companies running AGPL-licensed libraries server-side, the trigger condition is running the software over a network — no distribution required. Discovery typically happens at the worst possible moment: during an acquisition due-diligence review, when the entire product's IP provenance is scrutinised.

Automated license scanning in CI makes compliance a build-time property, not a quarterly audit.

## Threat Model

- **Adversary:** A developer who adds a GPL-licensed dependency without realising its implications (the most common case), or a malicious contributor who deliberately introduces a license poison pill to create downstream legal exposure.
- **Blast radius:** Copyleft infection propagates to any code that links against or derives from the violating dependency. In the worst case, the entire application codebase becomes subject to the copyleft license's requirements. AGPL is particularly aggressive: SaaS deployment counts as distribution.

## License Categories and Risk Levels

Understanding risk requires knowing how licenses propagate:

**Permissive (low risk):** MIT, Apache 2.0, BSD-2-Clause, BSD-3-Clause, ISC. These require only attribution (keeping the copyright notice and license text). You can use them in proprietary software, SaaS, and closed-source distributions without restriction. Apache 2.0 also provides an explicit patent grant, making it safer than MIT for patent-sensitive applications.

**Weak copyleft (medium risk):** LGPL, MPL-2.0, CDDL. These apply copyleft only to modifications of the licensed file itself, not to software that links against it. LGPL-licensed libraries can generally be used in proprietary applications if the library is dynamically linked and unmodified. Statically linking an LGPL library is more complicated and requires legal review.

**Strong copyleft (high risk for proprietary code):** GPL-2.0, GPL-3.0. Any software that links against or incorporates GPL code must itself be distributed under the GPL. This includes the source code. For closed-source applications this is typically a blocker.

**Network copyleft (critical risk for SaaS):** AGPL-3.0. The GPL requirement triggers not just on distribution but on network interaction. Running AGPL code in a backend service accessed over the internet means you must publish the source of that service. Many organisations treat AGPL as equivalent to "cannot use."

**Commercial/proprietary:** Some packages carry commercial licenses that restrict use to paid subscribers or prohibit certain use cases entirely. These can be discovered by automated tools but require manual review for compliance.

**Unknown/unlicensed:** A package with no license is not permissively licensed. Under copyright law, all rights are reserved. Using unlicensed code requires explicit written permission from the copyright holder.

## Configuration

### SBOM Generation with Syft

License scanning requires knowing what you have first. Syft generates a Software Bill of Materials (SBOM) that includes license information for every detected package:

```bash
# Install Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Generate CycloneDX SBOM with license metadata
syft ghcr.io/your-org/your-app:${{ github.sha }} \
  -o cyclonedx-json=sbom-cdx.json

# Or scan a directory (source-level scanning)
syft dir:. -o cyclonedx-json=sbom-cdx.json

# Extract just the license summary
syft dir:. -o table | grep -E "^(Package|---)" -A 2
```

The CycloneDX format includes a `licenses` field per component, which downstream tools can query. Syft detects licenses from SPDX identifiers in package metadata, `LICENSE` files, and copyright headers.

### Defining a License Policy

Store your policy as a YAML file committed to the repository. This makes policy changes reviewable and auditable:

```yaml
# .license-policy.yml
policy:
  # Licenses that are always allowed without review
  allowed:
    - MIT
    - Apache-2.0
    - BSD-2-Clause
    - BSD-3-Clause
    - ISC
    - Unlicense
    - CC0-1.0
    - Python-2.0

  # Licenses that require legal review before use
  review_required:
    - LGPL-2.0-only
    - LGPL-2.0-or-later
    - LGPL-2.1-only
    - LGPL-2.1-or-later
    - MPL-2.0
    - CDDL-1.0
    - EPL-2.0

  # Licenses that are never allowed in this repository
  denied:
    - GPL-2.0-only
    - GPL-2.0-or-later
    - GPL-3.0-only
    - GPL-3.0-or-later
    - AGPL-3.0-only
    - AGPL-3.0-or-later
    - EUPL-1.2
    - SSPL-1.0

  # Packages granted explicit exceptions despite a denied license
  # Each exception must include a justification and reviewer
  exceptions:
    - package: some-cli-tool
      version: ">=1.0.0"
      license: GPL-3.0-or-later
      reason: "Used only in build tooling, not linked into the application binary"
      approved_by: legal@your-org.com
      approved_date: 2026-03-01
```

This policy YAML becomes the source of truth. All tooling references it; exceptions are explicit and tracked in Git history.

### npm: license-checker

```bash
# Install
npm install -g license-checker

# List all licenses in the dependency tree
license-checker --production --json > license-report.json

# Fail the build if any denied licenses are present
license-checker --production \
  --failOn "GPL-2.0;GPL-3.0;AGPL-3.0" \
  --excludePackages "some-cli-tool@1.2.3"

# List only non-permissive licenses for review
license-checker --production \
  --onlyAllow "MIT;Apache-2.0;BSD-2-Clause;BSD-3-Clause;ISC;Unlicense"
```

```yaml
# .github/workflows/license-check.yml
name: License Compliance
on:
  push:
    paths:
      - 'package*.json'
  pull_request:
    paths:
      - 'package*.json'

jobs:
  license-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Setup Node
        uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8
        with:
          node-version: '20'

      - name: Install dependencies
        run: npm ci

      - name: Check licenses
        run: |
          npx license-checker --production \
            --failOn "GPL-2.0;GPL-2.0-only;GPL-3.0;GPL-3.0-only;AGPL-3.0;AGPL-3.0-only" \
            --json > license-report.json

      - name: Upload license report
        uses: actions/upload-artifact@5d5d22a31266ced268874388b861e4b58bb5c2f3
        with:
          name: license-report
          path: license-report.json
```

### Python: pip-licenses

```bash
# Install
pip install pip-licenses

# List all licenses
pip-licenses --format=json --output-file=license-report.json

# Fail on denied licenses
pip-licenses --fail-on="GPL;AGPL" --format=plain-vertical

# Include transitive dependencies (default behaviour - includes all installed packages)
# Use a virtual environment scoped to the project to avoid system package pollution:
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip-licenses --format=json --with-urls --with-authors > license-report.json

# Check against allowed list
pip-licenses --allow-only="MIT License;Apache Software License;BSD License;ISC License"
```

### Go: go-licenses

```bash
# Install
go install github.com/google/go-licenses@latest

# List all licenses for the module's dependencies
go-licenses report ./... --template=csv 2>/dev/null > license-report.csv

# Check for restricted licenses (exits non-zero if any are found)
go-licenses check ./... --allowed_licenses="MIT,Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC"

# Save copies of all license files (required for attribution)
go-licenses save ./... --save_path=./third_party/licenses
```

```yaml
# GitHub Actions step for Go
- name: Check Go licenses
  run: |
    go install github.com/google/go-licenses@latest
    go-licenses check ./... \
      --allowed_licenses="MIT,Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC,BSD-2-Clause-FreeBSD" \
      2>&1 | tee license-check-output.txt
    if grep -qiE "GPL|AGPL|SSPL" license-check-output.txt; then
      echo "::error::Disallowed license detected"
      exit 1
    fi
```

### Ruby: licensee

```bash
# Install
gem install licensee

# Check a project's license
licensee detect

# Check dependencies
bundle exec licensee

# For Gemfile.lock transitive scanning, use licensed (GitHub's tool):
gem install licensed
licensed cache
licensed status
# Fails if any dependency has an unrecognised or disallowed license
```

### FOSSA Integration

FOSSA is a dedicated license compliance platform with deeper transitive analysis and legal review workflows. It integrates with CI as a blocking step:

```yaml
# GitHub Actions with FOSSA
- name: FOSSA Scan
  uses: fossas/fossa-action@09b9e29ee82d01a24b02b1a6b93b0dfdf55a9ed0
  with:
    api-key: ${{ secrets.FOSSA_API_KEY }}

- name: FOSSA Test (fail on policy violation)
  uses: fossas/fossa-action@09b9e29ee82d01a24b02b1a6b93b0dfdf55a9ed0
  with:
    api-key: ${{ secrets.FOSSA_API_KEY }}
    run-tests: true
    # run-tests: true causes the step to block until FOSSA completes analysis
    # and exits non-zero if any component violates the policy configured in the FOSSA dashboard
```

FOSSA maintains a policy in its dashboard where you define allowed/denied/flagged licenses, then `fossa test` enforces that policy against the current scan. This separates the policy definition (in FOSSA) from the CI enforcement (exit code).

### CycloneDX SBOM with License Information

For compliance archiving and SBOM interchange, generate a CycloneDX SBOM that includes license data:

```bash
# For npm projects
npm install -g @cyclonedx/cyclonedx-npm
cyclonedx-npm --output-format JSON --output-file sbom.cdx.json

# For Python
pip install cyclonedx-bom
cyclonedx-py environment --output-format JSON > sbom.cdx.json

# For Go
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest
cyclonedx-gomod app -json -output sbom.cdx.json

# Verify the SBOM includes license data
jq '.components[].licenses' sbom.cdx.json | head -20
```

The CycloneDX format's `licenses` field supports SPDX identifiers and full license text. This SBOM can be stored alongside the container image or build artifact as an auditable compliance record.

## Handling False Positives and Dual-Licensed Dependencies

Several common situations produce incorrect results from automated tools:

**Dual-licensed packages:** Many packages offer a choice of licenses, e.g., `MIT OR Apache-2.0`. Tools may report only one option. Review the package's README and `package.json` `license` field. If both options are permissive, both are acceptable. Picking Apache-2.0 provides the patent grant.

**License expression parsing errors:** Some tools misparse SPDX expressions like `(MIT AND BSD-3-Clause)`. Check the raw SPDX expression in the package metadata and evaluate manually if the tool reports an error.

**Missing license metadata:** Particularly common in older npm packages that predate SPDX standardisation. Use `license-checker --unknown` to list packages with unknown licenses. Investigate each: check the repository's LICENSE file directly.

**License file not in expected location:** go-licenses and licensee identify licenses by parsing actual LICENSE files. If a package's LICENSE is in a non-standard path, the tool may report `Unknown`. Check the source repository manually.

**Exception management:** Track all approved exceptions in the `.license-policy.yml` file under `exceptions`. Each exception requires a justification and a named approver. Review exceptions quarterly: package licenses do occasionally change between versions.

## Transitive Dependency Scanning

Direct dependencies are the easy case. Transitive dependencies — the dependencies of your dependencies — are where compliance incidents actually occur.

The challenge: transitive graphs are large, version-locked, and often contain packages with unclear provenance. A production Node.js application might have 5 direct dependencies that expand to 800 transitive ones.

**npm:** `license-checker` scans all packages in `node_modules`, which includes all transitive dependencies installed by `npm ci`. This is the correct approach: scan the actual installed tree, not just what's declared in `package.json`.

**Python:** `pip-licenses` scans the active virtual environment. Running `pip install -r requirements.txt` before scanning captures all transitive packages (assuming `requirements.txt` was generated with full transitive resolution via `pip-compile`).

**Go:** `go-licenses report ./...` follows the full module graph declared in `go.sum`. The `go.sum` file contains every transitive module, making complete transitive scanning straightforward.

**Containers:** For transitive scanning at the OS package level (system libraries), use Syft against the container image. This captures Alpine/Debian packages and their licenses — including C libraries that your application links at runtime.

```bash
# Scan a container image for all package licenses (including OS packages)
syft ghcr.io/your-org/your-app:latest -o cyclonedx-json | \
  jq '.components[] | {name: .name, version: .version, licenses: [.licenses[]?.expression]}' | \
  grep -v '"licenses": \[\]'
```

## CI Pipeline Integration

A complete license compliance gate in GitHub Actions:

```yaml
# .github/workflows/license-compliance.yml
name: License Compliance
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'   # Weekly Monday scan (catches new CVEs in policy)

jobs:
  license-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Setup Node
        uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8
        with:
          node-version: '20'

      - name: Install dependencies
        run: npm ci

      - name: Scan licenses
        id: license-scan
        run: |
          npx license-checker --production \
            --json \
            --excludePackages "$(jq -r '.policy.exceptions[].package' .license-policy.yml | tr '\n' ';')" \
            > license-report.json

      - name: Enforce policy
        run: |
          DENIED=$(jq -r '.policy.denied[]' .license-policy.yml | tr '\n' ';')
          npx license-checker --production \
            --failOn "$DENIED" \
            --excludePackages "$(jq -r '.policy.exceptions[].package' .license-policy.yml | tr '\n' ';')"

      - name: Flag review-required licenses
        run: |
          REVIEW=$(jq -r '.policy.review_required[]' .license-policy.yml | tr '\n' '|')
          FLAGGED=$(jq -r 'to_entries[] | select(.value.licenses | test("'"$REVIEW"'")) | .key' license-report.json)
          if [ -n "$FLAGGED" ]; then
            echo "::warning::The following packages require legal review:"
            echo "$FLAGGED"
          fi

      - name: Generate SBOM with license data
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
          syft dir:. -o cyclonedx-json=sbom-with-licenses.cdx.json

      - name: Upload artifacts
        uses: actions/upload-artifact@5d5d22a31266ced268874388b861e4b58bb5c2f3
        with:
          name: license-compliance-${{ github.sha }}
          path: |
            license-report.json
            sbom-with-licenses.cdx.json
```

## Expected Behaviour

- Build fails immediately when a denied license (GPL, AGPL, SSPL) is introduced via any dependency, direct or transitive
- Review-required licenses (LGPL, MPL) generate a warning, not a hard failure — they go to a legal review queue
- CycloneDX SBOM with full license metadata attached to every release artifact
- Weekly scheduled scan catches policy drift from dependency updates via Renovate/Dependabot
- All exceptions are documented, named, and dated in `.license-policy.yml` under version control

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Hard fail on denied licenses | Blocks merges that introduce GPL/AGPL | Developer confusion when a transitive dependency changes license | Clear error message linking to `.license-policy.yml`. Exception process for justified cases. |
| Scanning all transitive deps | Catches actual compliance risk | Large number of packages in review-required category initially | Triage once. Add exceptions with justifications. The list stabilises after the first pass. |
| Weekly scheduled scan | Catches license changes in existing dependencies | Alert noise if dependencies change frequently | Scope the scheduled scan to report-only mode; treat findings as async review queue, not blocking incident. |
| SBOM as compliance artifact | Audit trail for every release | SBOM storage overhead | SBOMs are typically under 2MB per image. Store alongside release artifacts in S3 or OCI registry. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Transitive dependency introduces GPL | Build fails with license violation; developer is confused because they didn't add a GPL package | CI failure on license enforcement step | Identify which direct dependency pulled in the GPL package. Find a GPL-free alternative, or wrap the GPL code in a separate process to avoid linking. |
| False positive from dual-licensed package | Build fails on a package that is actually MIT OR Apache-2.0 | CI failure; investigation shows the SPDX expression was misread | Add an explicit exception for that package version with justification. File an issue with the tool to fix the parser. |
| License changes between versions | Renovate/Dependabot upgrade brings in a new version with a changed license | Weekly scheduled scan reports new violation | Pin the dependency to the last permissively-licensed version. Evaluate alternatives. |
| Unknown license (no metadata) | Tool reports `UNKNOWN` for a package | CI warning or failure on unknown licenses | Inspect the package's source repository for a LICENSE file. If no license exists, treat it as all-rights-reserved and replace the dependency. |
| FOSSA scan times out | `fossa test` hangs in CI | CI job timeout | Set a timeout on the FOSSA step (`timeout-minutes: 10`). On timeout, fail the build rather than passing silently. |

## When to Consider a Managed Alternative

OSS tooling per-language works well for single-language repositories. Polyglot monorepos and repositories with many exceptions benefit from a dedicated compliance platform.

- **[FOSSA](https://fossa.com):** Purpose-built license compliance with a legal review workflow, policy management UI, and remediation guidance. Handles dual-licensed packages and complex SPDX expressions better than per-language tools.
- **[Snyk](https://snyk.io):** License compliance integrated with vulnerability scanning. Single tool for both concerns. Policy defined in the Snyk dashboard.
- **[TLDR Legal](https://tldrlegal.com):** Not a CI tool, but useful for understanding what a specific license actually requires before adding it to your policy.

## Related Articles

- [Software Bill of Materials (SBOM) Generation and Consumption in CI/CD](/articles/cicd/sbom/)
- [Dependency Pinning and Lockfile Integrity: Preventing Supply Chain Attacks in CI](/articles/cicd/dependency-pinning/)
- [Software Supply Chain Third-Party Risk Management](/articles/cicd/software-supply-chain-third-party-risk/)
- [SLSA Provenance for Container Images: From Build to Admission Control](/articles/cicd/slsa-provenance/)
- [Securing GitHub Actions: Permissions, Pinning, and Workflow Injection Prevention](/articles/cicd/securing-github-actions/)
