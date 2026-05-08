---
title: "Integrating SAST into CI/CD Pipelines: Semgrep, CodeQL, and False Positive Management"
description: "A practical guide to embedding Static Application Security Testing into CI/CD pipelines — covering Semgrep custom rules, CodeQL queries, language-specific scanners, SARIF output, and the critical discipline of keeping false positive rates low enough that developers don't tune out alerts."
slug: sast-integration-cicd
date: 2026-05-07
lastmod: 2026-05-07
category: cicd
tags:
  - sast
  - semgrep
  - codeql
  - static-analysis
  - shift-left
personas:
  - security-engineer
  - platform-engineer
article_number: 520
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/cicd/sast-integration-cicd/
---

# Integrating SAST into CI/CD Pipelines: Semgrep, CodeQL, and False Positive Management

## The Landscape: SAST, DAST, and SCA

Before placing any scanner in a pipeline, it helps to be clear about what each class of tool actually finds — because the overlap is smaller than most people assume.

**Static Application Security Testing (SAST)** analyses source code or compiled bytecode without executing the program. It finds things that are visible in the code itself: hardcoded secrets, SQL injection patterns, unsafe deserialization, dangerous function calls, missing input validation, and logic errors that create security boundaries. SAST runs in seconds to minutes, needs no running infrastructure, and can block a pull request before a line is merged. Its blind spot is runtime behaviour — it cannot see what happens when two microservices talk to each other, or when user-supplied data flows through a queue before reaching a sink.

**Dynamic Application Security Testing (DAST)** probes a running application from the outside, just as an attacker would. It finds authentication failures, server misconfigurations, reflected XSS that only manifests at runtime, and second-order injection where the payload is stored then executed later. DAST needs a deployed environment, so it fits staging rather than PR checks, and it typically takes 20–90 minutes per scan. It cannot see what is happening inside the code, so it misses many of the vulnerabilities SAST finds.

**Software Composition Analysis (SCA)** tracks third-party dependencies and checks them against vulnerability databases (CVE, OSV, GitHub Advisory). It finds known vulnerabilities in the libraries you import, not in the code you write. SCA is fast and essential — a dependency with a known RCE is a higher-probability finding than most SAST alerts — but it tells you nothing about application logic.

All three are needed. A pipeline that has SCA but no SAST will miss SQL injection written in first-party code. A pipeline with SAST but no DAST will miss the misconfigured authentication endpoint that the scanner never sees. Treat the three as layers of a detection strategy, not substitutes for each other.

This article focuses on SAST, specifically on making it useful rather than just present.

## Problem

SAST is widely deployed and widely ignored. The pattern repeats: a security team adds a scanner to the pipeline, it fires on the first repository with 400 findings, developers add a `# nosec` annotation or an exclusion glob and move on. The scanner keeps running. The alerts keep accumulating. Nobody reads them.

The failure mode is not technical — the scanners are capable. The failure mode is operational: too many findings with too low a signal-to-noise ratio means the tool trains developers to dismiss alerts reflexively. Fixing SAST means fixing the operational loop, not just the tooling.

**Target systems:** GitHub Actions, GitLab CI, any pipeline with access to source code. Language-specific sections cover Python, Go, and JavaScript. General principles apply to any language with a Semgrep or CodeQL ruleset.

## Threat Model

- **Adversary:** A developer who introduces a vulnerability through inattention — SQL injection via string concatenation, an insecure random number generator used for a session token, a deprecated authentication function that bypasses access control.
- **Detection window without SAST:** The vulnerability exists from the moment the code is committed. It may be found in code review (unreliable), in a pentest (quarterly at best), or after exploitation.
- **Detection window with SAST:** The CI job fails on the PR. The developer sees the finding inline in the pull request diff. The fix happens before merge.
- **What SAST does not catch:** Architectural flaws, logic errors that require understanding business context, vulnerabilities introduced through runtime configuration, and findings that require data-flow analysis across service boundaries.

## Configuration

### Semgrep in CI

[Semgrep](https://semgrep.dev) is a fast, open-source pattern-matching engine for security and correctness rules. It has three relevant components for CI integration: the community ruleset, the ability to write custom rules, and the `--gitlab-sast` / `--sarif` output modes that feed findings into the platform's native security dashboard.

**Basic GitHub Actions integration:**

```yaml
# .github/workflows/sast.yml
name: SAST

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # needed to upload SARIF to GitHub Code Scanning
  pull-requests: write     # needed for PR comment mode

jobs:
  semgrep:
    name: Semgrep Scan
    runs-on: ubuntu-24.04
    container:
      image: semgrep/semgrep:1.75.0   # pin the version; breaking changes happen
    steps:
      - uses: actions/checkout@v4

      - name: Run Semgrep
        env:
          SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_APP_TOKEN }}
        run: |
          semgrep ci \
            --config auto \
            --sarif \
            --output semgrep.sarif \
            --severity ERROR \
            --severity WARNING

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: semgrep.sarif
          category: semgrep
```

The `--config auto` flag pulls the community ruleset appropriate for the languages detected in the repository. For a Python/Django project it loads the `python.django` and `python.security` packs automatically. This is a reasonable starting point, but the auto ruleset is broad and will produce false positives on patterns it cannot fully contextualise.

**Blocking behaviour:** The `semgrep ci` command exits non-zero when findings at `ERROR` severity are present, causing the CI job to fail and the PR check to block merge (assuming branch protection requires the check to pass). `WARNING` findings are reported but do not block — useful for informational findings you want visibility on without stopping development.

**PR comment mode:** When `SEMGREP_APP_TOKEN` is set and the scan runs on a pull request, Semgrep posts inline comments on the diff at the exact lines that triggered findings. This surfaces the issue in the PR review UI rather than requiring developers to hunt through a CI log.

**Custom rules with YAML pattern syntax:**

Semgrep rules are YAML files. The pattern language is close to the source language being matched — a Python rule looks like slightly abstracted Python, which makes it approachable for security engineers who are not tool specialists.

```yaml
# rules/custom/deprecated-auth.yml
rules:
  - id: deprecated-auth-function
    patterns:
      - pattern: authenticate_legacy($USER, $PASS)
      - pattern-not-inside: |
          # legacy-auth-allowed
          ...
    message: >
      authenticate_legacy() was deprecated in v2.3 and removed the CSRF
      check introduced in v2.4. Use authenticate() from auth.security instead.
      See the internal migration guide at https://wiki.internal/auth-migration.
    languages: [python]
    severity: ERROR
    metadata:
      category: security
      confidence: HIGH
      subcategory: [vuln]
      cwe: "CWE-287: Improper Authentication"

  - id: raw-sql-format-string
    patterns:
      - pattern: |
          $CURSOR.execute("..." % ...)
      - pattern: |
          $CURSOR.execute("..." .format(...))
    message: >
      String interpolation in a SQL query creates an injection risk.
      Use parameterised queries: cursor.execute("SELECT ... WHERE id = %s", (user_id,))
    languages: [python]
    severity: ERROR
    metadata:
      category: security
      confidence: HIGH
      subcategory: [vuln]
      cwe: "CWE-89: SQL Injection"
```

To run custom rules alongside the community set:

```yaml
- name: Run Semgrep with custom rules
  run: |
    semgrep ci \
      --config auto \
      --config rules/custom/ \
      --sarif \
      --output semgrep.sarif
```

The `pattern-not-inside` construct in the first rule suppresses the finding when a specific exemption comment is present. This is the principled way to handle legitimate uses of a deprecated function — explicit, reviewable, and searchable in the codebase — rather than blanket `# nosec` suppressions.

### CodeQL GitHub Actions Integration

[CodeQL](https://codeql.github.com) is GitHub's semantic code analysis engine. Where Semgrep matches patterns, CodeQL builds a full program database and runs QL queries against it. This allows taint tracking — following user-controlled data from a source (an HTTP parameter) through the code to a sink (a shell command execution) even when the path spans multiple files and function calls. The trade-off is scan time: CodeQL typically takes 5–20 minutes depending on repository size, compared to Semgrep's 30–90 seconds.

```yaml
# .github/workflows/codeql.yml
name: CodeQL

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * 1'   # weekly full scan on Monday at 2am UTC

permissions:
  actions: read
  contents: read
  security-events: write

jobs:
  analyze:
    name: Analyze (${{ matrix.language }})
    runs-on: ubuntu-24.04
    timeout-minutes: 30

    strategy:
      fail-fast: false
      matrix:
        include:
          - language: python
            build-mode: none
          - language: javascript-typescript
            build-mode: none
          - language: go
            build-mode: autobuild

    steps:
      - uses: actions/checkout@v4

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}
          build-mode: ${{ matrix.build-mode }}
          # Use the default query suite for most languages; override to
          # 'security-extended' to enable lower-confidence queries
          queries: security-and-quality

      - name: Build (for compiled languages)
        if: matrix.build-mode == 'autobuild'
        uses: github/codeql-action/autobuild@v3

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3
        with:
          category: "/language:${{ matrix.language }}"
          # Upload SARIF automatically; findings appear in the Security tab
          upload: true
```

**Scheduled vs. PR scans:** Running CodeQL on every PR is correct for main-branch protection, but a full database build on every small commit is expensive. The schedule trigger runs a full scan weekly and catches findings that only appear when the complete codebase is analysed together — cross-file taint flows that would not show up in an incremental diff. Both are useful; the PR scan catches new vulnerabilities before merge, the scheduled scan finds existing ones that no PR scan would have triggered.

**Custom QL queries:** CodeQL's query language allows organisation-specific checks. For example, to detect calls to an internal function that must always be followed by an audit log:

```ql
// custom-queries/missing-audit-log.ql
/**
 * @name Privileged operation without audit log
 * @description Calls to performPrivilegedAction() must be followed by
 *              auditLog.record(). Missing audit logs violate our compliance policy.
 * @kind problem
 * @problem.severity error
 * @id custom/missing-audit-log
 */
import python

from Call privilegedCall
where
  privilegedCall.getFunc().(Attribute).getName() = "performPrivilegedAction" and
  not exists(Call auditCall |
    auditCall.getFunc().(Attribute).getName() = "record" and
    auditCall.getLocation().getStartLine() > privilegedCall.getLocation().getStartLine()
  )
select privilegedCall, "performPrivilegedAction() called without a subsequent auditLog.record()"
```

### Language-Specific Scanners

For repositories with a single dominant language, purpose-built scanners often produce better signal than generic engines because their rules encode language ecosystem knowledge that a general-purpose engine may not have.

**Bandit for Python:**

```yaml
- name: Bandit security scan
  run: |
    pip install bandit[toml]==1.8.3
    bandit -r src/ \
      --format sarif \
      --output bandit.sarif \
      --severity-level medium \
      --confidence-level medium \
      --skip B101   # skip assert_used — common in test files
```

Bandit's plugin IDs map directly to CWEs. `B608` is SQL injection, `B501`–`B509` cover TLS/SSL misconfigurations, `B105`/`B106` flag hardcoded passwords. The `--severity-level medium` flag suppresses low-severity informational findings that produce noise without value. A common mistake is running Bandit at `--severity-level low`, which floods output with `B101` (use of `assert`) in test files.

**gosec for Go:**

```yaml
- name: gosec security scan
  run: |
    go install github.com/securego/gosec/v2/cmd/gosec@v2.21.4
    gosec \
      -fmt sarif \
      -out gosec.sarif \
      -exclude G104 \
      -severity medium \
      ./...
```

`G104` (errors unhandled) produces hundreds of findings in most Go codebases because idiomatic Go defers error handling. Excluding it focuses the output on higher-value findings: `G201`/`G202` for SQL injection, `G501`/`G502` for weak cryptography, and `G304` for file path traversal.

**ESLint security plugins for JavaScript/TypeScript:**

```bash
npm install --save-dev \
  eslint@9 \
  eslint-plugin-security@3 \
  eslint-plugin-no-unsanitized@4 \
  @microsoft/eslint-plugin-sdl@0.2
```

```javascript
// eslint.config.js (flat config)
import security from 'eslint-plugin-security';
import noUnsanitized from 'eslint-plugin-no-unsanitized';
import sdl from '@microsoft/eslint-plugin-sdl';

export default [
  security.configs.recommended,
  noUnsanitized.configs.recommended,
  {
    plugins: { '@microsoft/sdl': sdl },
    rules: {
      '@microsoft/sdl/no-inner-html': 'error',
      '@microsoft/sdl/no-document-write': 'error',
      '@microsoft/sdl/no-cookies': 'warn',
    },
  },
];
```

The `eslint-plugin-security` ruleset catches `eval()` usage, `RegExp` with user-controlled input (ReDoS risk), and unsafe object key access. The `no-unsanitized` plugin specifically tracks `innerHTML`, `outerHTML`, and similar DOM sinks.

## SARIF Output and Platform Integration

SARIF (Static Analysis Results Interchange Format) is an OASIS standard JSON format for static analysis results. Both GitHub Code Scanning and GitLab SAST use SARIF as their import format, which means any tool that produces SARIF output can feed into the platform's native security dashboard.

**GitHub Code Scanning:** Uploading a SARIF file with `github/codeql-action/upload-sarif` causes findings to appear under Security → Code scanning alerts, with inline annotations in pull request diffs and filtering by severity, state, and tool.

**GitLab SAST:** GitLab expects a `gl-sast-report.json` file as a CI artifact. Semgrep, Bandit, and gosec can each produce this format. For tools that only produce SARIF, use the `gitlab-converter` utility:

```yaml
# .gitlab-ci.yml
sast:
  image: semgrep/semgrep:1.75.0
  script:
    - semgrep ci --config auto --gitlab-sast --output gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
    paths:
      - gl-sast-report.json
    when: always
```

With `reports: sast:` defined, GitLab renders findings in the merge request widget and in the Security Dashboard without any additional configuration.

## Tuning False Positive Rates

This is where most SAST deployments fail or succeed. A scanner that produces 300 findings per repository, with 80% false positives, trains developers to ignore all alerts — including the 20% that are real.

**The threshold discipline:** Start with a high-severity-only configuration. Accept that you are not catching everything at first. A pipeline that blocks on `ERROR` findings with a 10% false positive rate is far more valuable than one that reports 400 `WARNING` findings that nobody reads.

**Per-rule suppression with justification:** When suppressing a finding, require the suppression to include a reason:

```python
# This use of MD5 is for cache key generation, not security.
# Finding: B303 (use of MD5) - suppressed because cache key collision
# is acceptable and not a security boundary.
import hashlib
cache_key = hashlib.md5(content).hexdigest()  # nosec B303
```

In Semgrep, the equivalent is `# nosec` or a Semgrep-specific `# nosemgrep: rule-id` with a comment explaining why. The comment is reviewable in the PR diff, so suppressions are auditable rather than invisible.

**Feedback loops:** Track suppression rates per rule. A rule where more than 30% of findings are suppressed is producing too many false positives and should be disabled or refined. A rule with a 0% suppression rate and consistent findings is high-signal and should be promoted to a blocking check if it is not already.

**Separating new from existing findings:** Blocking on all findings in a large legacy codebase is impractical. Use Semgrep's `--baseline-commit` flag or CodeQL's differential mode to only report findings that were introduced in the current PR:

```bash
semgrep ci \
  --config auto \
  --baseline-commit $(git merge-base HEAD origin/main)
```

This limits the CI failure to new code, while existing findings are tracked separately and addressed through a remediation backlog.

## Writing Custom Rules for Organisation-Specific Patterns

The most valuable SAST rules are often not in any public ruleset. They encode knowledge of your codebase's specific anti-patterns, deprecated APIs, and compliance requirements.

Common categories worth encoding as custom rules:

- **Deprecated internal functions** that were replaced for security reasons (authentication bypass, broken cryptography, missing audit logging).
- **Framework-specific sinks** that your organisation's threat model treats as high-risk (internal HTTP clients that should not reach the public internet, database connection factories that bypass the query layer).
- **Compliance requirements** that map to code patterns (PCI DSS prohibits storing CVV, GDPR limits where PII can be logged).

A Semgrep rule for detecting logging of an internal `UserRecord` type (which may contain PII):

```yaml
rules:
  - id: pii-in-logs
    patterns:
      - pattern: |
          logger.$METHOD(..., $USER_RECORD, ...)
      - metavariable-type:
          metavariable: $USER_RECORD
          types: [UserRecord, UserProfile, CustomerData]
    message: >
      Logging a UserRecord may write PII to log storage. Extract only
      non-identifying fields before logging. See data-handling policy.
    languages: [python, javascript]
    severity: ERROR
    metadata:
      category: security
      confidence: HIGH
      cwe: "CWE-532: Insertion of Sensitive Information into Log File"
```

## Measuring SAST Effectiveness

Deploying a scanner is not the same as running an effective security programme. Metrics that matter:

**Mean time to remediate (MTTR):** The time from a finding appearing in a PR to the fix being merged. A high MTTR (days or weeks) indicates developers lack the context to fix findings quickly, or the findings are low-confidence and disputed. Reduce MTTR by ensuring every finding links to a remediation guide, not just a CWE number.

**False positive rate:** The percentage of findings that are suppressed or dismissed as not-a-bug. Measure this per rule. At the portfolio level, a false positive rate above 30% degrades trust in the tooling. Below 15% is a reasonable target for a tuned configuration.

**Escape rate:** Vulnerabilities of the type SAST covers that are found in production (by pentest, bug bounty, or incident). If SQL injection findings are being found post-deployment, either the scanner is not running, developers are suppressing findings without review, or the rules are not covering the relevant code paths.

**Coverage:** The percentage of repositories with SAST enabled and configured to block merge on findings. A scanner that runs in one team's pipeline but not others provides patchy coverage. Track this as an infrastructure metric and address gaps through platform-level defaults rather than per-team configuration.

## Putting It Together

A practical integration path:

1. Deploy Semgrep with `--config auto` and `--severity ERROR` in non-blocking mode for two weeks. Measure finding volume and false positive rate per repository.
2. Identify the five highest-signal rule IDs from step 1 and enable blocking on those rules only.
3. Add CodeQL on a weekly schedule for taint-tracking coverage that Semgrep cannot provide.
4. Add language-specific scanners (Bandit, gosec, ESLint security) as advisory findings feeding into the security dashboard.
5. Write custom Semgrep rules for the three to five most critical internal anti-patterns identified by the security team.
6. Establish a suppression review process: all `# nosec` and `# nosemgrep` annotations must include a justification comment and are reviewed in the PR.
7. Review metrics quarterly: MTTR, false positive rate, escape rate. Retire rules that produce only noise. Promote advisory findings to blocking when false positive rates are acceptably low.

The operational discipline matters as much as the tooling. SAST only prevents vulnerabilities if developers trust the output enough to act on it. Keeping the signal-to-noise ratio high is the prerequisite for everything else.
