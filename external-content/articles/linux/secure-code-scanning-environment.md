---
title: "Securing the Code Scanning Environment: Preventing Scan Bypass and Result Tampering on Linux"
description: "SAST and SCA tools are only as trustworthy as the environment that runs them. A developer who can modify the scan configuration, suppress findings before they're recorded, or tamper with result files defeats the security gate entirely. This guide hardens the Linux environments where code scanning runs — covering file integrity for scanner binaries, result chain-of-custody, isolated scan execution, and detecting bypass attempts."
slug: secure-code-scanning-environment
date: 2026-05-08
lastmod: 2026-05-08
category: linux
tags:
  - code-scanning
  - build-security
  - sast
  - environment-hardening
  - supply-chain
personas:
  - security-engineer
  - platform-engineer
article_number: 641
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/linux/secure-code-scanning-environment/
---

# Securing the Code Scanning Environment: Preventing Scan Bypass and Result Tampering on Linux

## Problem

Security scanning in CI — SAST tools like Semgrep and CodeQL, SCA tools like Trivy and Grype — creates the impression of a gate that blocks vulnerable code from reaching production. That impression is wrong unless the environment running the scan is itself hardened. The scan is only as reliable as the pipeline that executes it.

The bypass surface is larger than most teams realise. Consider what a developer who is motivated to suppress a finding can do without touching the scanner itself:

**Ignore-file manipulation.** Every major SAST and SCA tool honours ignore files: `.semgrepignore`, `.trivyignore`, `.grype.yaml`. These files live in the application repository. A developer can add a rule that suppresses a specific finding, push the change alongside the vulnerable code, and the scanner reports a clean result. The ignore file change may not receive the same scrutiny as the code change it is hiding.

**Configuration scope reduction.** Scan configuration files (`semgrep.yml`, `.trivyignore`, `.snyk`) control which rules run, which severity levels are reported, and which paths are in scope. Modifying `paths: exclude:` in a Semgrep configuration or raising `severity-threshold` in Trivy can silently remove large categories of findings without any visible "skip scan" marker.

**Result file deletion.** In naive pipeline configurations, the SARIF result file is written to the workspace and then uploaded in a separate step. If the developer-controlled code has any influence over post-scan steps — through shared scripts, Makefiles, or build system hooks — a malicious step can delete or truncate the SARIF file before upload. The upload step either uploads an empty file or silently fails.

**Selective scan invocation.** Tools like Semgrep support `--skip-git-diff` or explicit path filters. A CI script that constructs the scan invocation from repository-controlled files can pass flags that limit the scan to irrelevant directories while appearing to run normally.

**Not running the scan.** The most direct bypass: a CI configuration change that marks the scan job as `allow_failure: true`, changes its branch filter to exclude the current branch, or removes the required status check. Without server-side enforcement, the PR merges without a scan result.

Running scans on developer laptops solves none of this. The environment is uncontrolled, the scanner binary may be outdated or modified, results are not tied to a specific commit hash, there is no audit trail, and the developer can simply not run the tool before pushing.

The requirement is a trusted scanning environment: a CI context where the developer cannot modify the scanner binary, its configuration, or the path results take from generation to recording. This article describes how to build that environment on Linux-based CI runners.

## Threat Model

Three distinct actors cover most realistic bypass scenarios:

**Developer suppressing a finding in their own code.** The developer knows their code has a vulnerability (or a finding they consider a false positive but cannot get reviewed). They add an inline suppression annotation (`# nosemgrep: rule-id`), add a path exclusion to the ignore file, or commit a configuration change that disables the relevant rule. The security gate passes. The vulnerability ships.

**Build engineer or CI administrator skipping scanning for a specific branch.** Someone with write access to the CI configuration — `.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile` — modifies the scan job to exclude a specific branch, adds `continue-on-error: true`, or changes the workflow trigger so the scan does not run on the branch being used for the release. This requires more access than a typical developer has but is possible for anyone who can merge CI configuration changes.

**Insider compromising the SAST tool binary.** The most capable threat: someone with access to the CI runner or the artifact cache replaces the scanner binary with a modified version that always produces a clean result, or that produces results which exclude specific rule IDs. This attack is silent — scan jobs appear to run normally, produce SARIF output, and upload results. Only binary integrity verification catches it.

All three threat actors share a common weakness: they require either modifying something in the application repository, or modifying the CI environment itself. The controls below address each path.

## Configuration and Implementation

### Immutable Scanner Configuration

The root of most ignore-file and configuration-scope attacks is that scan configuration lives in the application repository, where the developer has write access. The fix is to move authoritative scan configuration out of the application repository.

Store scan policy in a dedicated policy repository that developers cannot push to directly. Only the security team has merge rights. The application repository references this policy as a read-only dependency:

```yaml
# .github/workflows/scan.yml (in application repo)
jobs:
  scan:
    runs-on: ubuntu-24.04
    steps:
      - name: Checkout application code (read-only ref)
        uses: actions/checkout@v4
        with:
          path: src

      - name: Checkout scan policy (pinned SHA)
        uses: actions/checkout@v4
        with:
          repository: your-org/scan-policy
          ref: a3f9c1e2b4d5f6a7b8c9d0e1f2a3b4c5d6e7f8a9  # pinned, not a branch
          token: ${{ secrets.SCAN_POLICY_READ_TOKEN }}
          path: policy
```

The policy repository contains `semgrep.yml`, `.trivyignore`, and any other scanner configuration files. Application developers cannot commit to it. Any change to scan policy requires a PR reviewed by the security team.

Verify configuration checksums before each scan run to detect tampering in transit or in the cache:

```bash
# policy/checksums.sha256 is committed to the policy repo
# Verify before scanning
cd policy
sha256sum --check checksums.sha256
if [ $? -ne 0 ]; then
  echo "FATAL: scan policy checksum mismatch — aborting"
  exit 1
fi
```

For files that must remain in the application repository (such as inline suppression annotations), enforce CODEOWNERS:

```
# .github/CODEOWNERS
.semgrepignore       @your-org/security-team
.trivyignore         @your-org/security-team
.grype.yaml          @your-org/security-team
semgrep.yml          @your-org/security-team
.snyk                @your-org/security-team
```

CODEOWNERS enforcement means any PR that modifies these files requires approval from the security team before it can merge. The files can still exist in the application repository for tool compatibility; they simply cannot be changed without security review.

### Scanner Binary Integrity

A scanner that can be silently replaced provides no security guarantee. Pin container-based scanners by digest, not by tag — tags are mutable, digests are not:

```yaml
# Pin by digest, not by tag
- name: Run Semgrep
  uses: docker://ghcr.io/returntocorp/semgrep@sha256:3f8c2a1b4e5d6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a

- name: Run Trivy
  uses: aquasecurity/trivy-action@0.28.0
  # Verify the action itself is pinned in your lockfile or uses a digest ref
```

For binary (non-container) scanners installed on the runner, verify the checksum against the publisher's published hash before execution:

```bash
SEMGREP_VERSION="1.78.0"
EXPECTED_SHA256="a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"

curl -fsSL "https://github.com/returntocorp/semgrep/releases/download/v${SEMGREP_VERSION}/semgrep-linux-amd64" \
  -o /usr/local/bin/semgrep

echo "${EXPECTED_SHA256}  /usr/local/bin/semgrep" | sha256sum --check
chmod +x /usr/local/bin/semgrep
```

For scanners distributed as container images signed with cosign, verify the signature before pulling:

```bash
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/aquasecurity/trivy/.github/workflows/release.yaml@refs/tags/v0.52.0" \
  aquasecurity/trivy:0.52.0
```

Never allow the scanned repository to modify the scanner. The scanner binary, its configuration, and its dependencies must be fetched from sources that the application code cannot write to.

### Isolated Scan Execution

The scan job must run in a context where the developer's code can be read but not executed in ways that affect the scan infrastructure. Structure CI jobs so the scan step has read-only access to source:

```yaml
# GitHub Actions example
jobs:
  checkout:
    runs-on: ubuntu-24.04
    outputs:
      sha: ${{ steps.get-sha.outputs.sha }}
    steps:
      - uses: actions/checkout@v4
      - id: get-sha
        run: echo "sha=$(git rev-parse HEAD)" >> "$GITHUB_OUTPUT"
      - uses: actions/upload-artifact@v4
        with:
          name: source-${{ github.sha }}
          path: .

  sast-scan:
    needs: checkout
    runs-on: scan-runner  # dedicated runner, no developer write access
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: source-${{ needs.checkout.outputs.sha }}
          path: /src-readonly

      - name: Set source read-only
        run: chmod -R a-w /src-readonly

      - name: Run Semgrep
        run: |
          semgrep scan \
            --config /policy/semgrep.yml \
            --sarif \
            --output /results/semgrep.sarif \
            /src-readonly
```

Mounting source as read-only prevents any build-system hook or Makefile target in the scanned code from modifying scanner inputs or outputs at scan time.

Network isolation during SAST execution prevents a compromised build from exfiltrating source code to an external service while the scanner runs. On Linux runners with network namespaces available, this can be enforced with a network policy or a simple iptables drop at job start:

```bash
# Block outbound during scan (allow only localhost and the results storage endpoint)
iptables -I OUTPUT -m state --state NEW -j DROP
iptables -I OUTPUT -d 127.0.0.1 -j ACCEPT
iptables -I OUTPUT -d 10.0.0.0/8 -j ACCEPT  # internal CI network only
```

Dedicated scan runners should have no developer SSH access, no write access from application CI jobs to runner configuration, and their own service account credentials scoped only to uploading results.

### Result Chain-of-Custody

A clean SARIF file proves nothing unless you can verify it was produced by the authorised scanner from the specific commit under review, and was not modified between generation and upload.

Sign SARIF results immediately after generation using cosign's keyless signing via the CI OIDC token:

```bash
# Sign the SARIF result before upload
cosign sign-blob \
  --bundle semgrep.sarif.bundle \
  semgrep.sarif

# Record the hash in the CI audit log
sha256sum semgrep.sarif | tee -a "${GITHUB_STEP_SUMMARY}"
```

Upload results directly to the GitHub Code Scanning API or your SIEM — not to an artifact store that developers can write to:

```bash
# Upload directly to GitHub Code Scanning (results are immutable once uploaded)
gh api \
  --method POST \
  -H "Accept: application/vnd.github+json" \
  /repos/${{ github.repository }}/code-scanning/sarifs \
  -f commit_sha="${{ github.sha }}" \
  -f ref="${{ github.ref }}" \
  --field sarif=@<(gzip -c semgrep.sarif | base64 -w0) \
  -f tool_name="semgrep"
```

On upload, verify the SARIF hash against the signed bundle before the upload is accepted. If results pass through any intermediate storage, verify the cosign bundle at the point of consumption:

```bash
cosign verify-blob \
  --bundle semgrep.sarif.bundle \
  semgrep.sarif
```

A failed signature verification must fail the pipeline — a missing or invalid signature is as suspicious as a missing SARIF file.

### Detecting Bypass Attempts

Prevention controls stop motivated attackers. Detection controls catch the attempts that slip through and create an audit trail for post-incident review.

Configure auditd on CI runners to watch for writes to scan configuration files during a build:

```bash
# /etc/audit/rules.d/scan-integrity.rules
# Alert on writes to scan configuration files during CI job
-w /workspace/.semgrepignore -p wa -k scan_config_tamper
-w /workspace/.trivyignore -p wa -k scan_config_tamper
-w /workspace/semgrep.yml -p wa -k scan_config_tamper
-w /workspace/.snyk -p wa -k scan_config_tamper
-w /policy -p wa -k policy_dir_tamper

# Alert on writes to results directory from unexpected processes
-a always,exit -F dir=/results -F perm=w -F auid>=1000 -k results_tamper
```

Alert on scan jobs that complete successfully but produce no SARIF output, or produce a SARIF file below a minimum size threshold (an empty SARIF envelope is under 200 bytes):

```bash
SARIF_FILE="/results/semgrep.sarif"
MIN_BYTES=500

if [ ! -f "$SARIF_FILE" ]; then
  echo "SECURITY ALERT: SARIF output not produced — scan may have been skipped"
  exit 1
fi

SARIF_SIZE=$(stat -c%s "$SARIF_FILE")
if [ "$SARIF_SIZE" -lt "$MIN_BYTES" ]; then
  echo "SECURITY ALERT: SARIF output suspiciously small (${SARIF_SIZE} bytes) — possible empty result injection"
  exit 1
fi
```

In GitHub, use required status checks to enforce that the scan job must produce a SARIF upload before a PR can merge. The upload step must be a distinct required check — marking only the job as required still allows the upload step within it to be skipped:

```yaml
# Branch protection settings (via API or UI)
# Required status checks:
#   - "sast-scan / upload-results"   <-- the upload step, not just the job
#   - "sca-scan / upload-results"
```

Monitor PR diffs for changes to scan workflow files and ignore files. A PR that modifies `.github/workflows/scan.yml` and also introduces a SQL injection in the same changeset is a significant signal. This can be implemented as a separate "policy change detector" job that comments on any PR touching these files:

```yaml
  policy-change-alert:
    if: |
      contains(github.event.pull_request.changed_files, '.semgrepignore') ||
      contains(github.event.pull_request.changed_files, '.trivyignore') ||
      contains(github.event.pull_request.changed_files, '.github/workflows/')
    steps:
      - name: Post security team review required
        run: gh pr comment ${{ github.event.pull_request.number }} --body "This PR modifies scan configuration or workflow files. @your-org/security-team review required."
```

### Pre-commit vs CI Scanning Separation

Pre-commit hooks running Semgrep or Trivy locally give developers fast feedback and reduce the volume of findings that reach CI. They are useful. They are not security controls.

A developer can bypass any pre-commit hook with `git commit --no-verify`. The hook can be deleted from `.pre-commit-config.yaml`. The tool may not be installed. Results are not recorded anywhere.

CI scanning is the enforcing layer. The split in responsibilities should be explicit:

| Layer | Purpose | Bypassable? |
|---|---|---|
| Pre-commit hook | Developer feedback, reduce CI noise | Yes — `git commit --no-verify` |
| CI SAST scan | Security gate, results recorded | No — enforced by required status check |
| CI SCA scan | Dependency vulnerability gate | No — enforced by required status check |

If server-side pre-receive hooks are available (GitHub Enterprise, GitLab self-managed), they can be used to enforce that a commit was scanned before it reaches the remote. Pre-receive hooks run on the server and cannot be bypassed with `--no-verify`. They are a stronger control than pre-commit hooks but require more infrastructure to operate safely — a failing pre-receive hook that cannot be bypassed will block all pushes until it is fixed.

## Expected Behaviour

The following table maps bypass attempts to the detection method that surfaces them and the prevention control that stops them:

| Bypass Attempt | Detection Method | Prevention Control |
|---|---|---|
| Add rule to `.semgrepignore` | CODEOWNERS blocks merge without security approval; auditd write alert during build | CODEOWNERS enforcement; policy repo separation |
| Modify `semgrep.yml` to exclude path | CODEOWNERS blocks merge; configuration checksum mismatch at scan start | Checksum verification before scan; policy repo |
| Delete SARIF file before upload | SARIF existence and size check fails pipeline | SARIF file check; direct API upload without intermediate storage |
| Run scan with `--skip-git-diff` | Scan produces SARIF without expected finding count signal; audit log shows unexpected flags | Scanner invocation controlled by policy repo scripts, not application repo |
| Change workflow to skip scan branch | Required status check not satisfied; PR cannot merge | Branch protection required status checks |
| Replace scanner binary with modified version | Cosign signature verification fails at job start | Digest pinning; binary hash check; cosign verify |
| Add `continue-on-error: true` to scan job | Monitored by policy change detector job | Workflow file in CODEOWNERS; centrally managed scan job |
| Empty SARIF upload | Size threshold check fails pipeline | Minimum SARIF size validation |

## Trade-offs

**Scan isolation vs build speed.** Running the scan in a separate job with a read-only source mount adds latency — the source must be uploaded as an artifact and re-downloaded. On large repositories this can add several minutes. The alternative (running the scan in the same job as the build) allows the build to interfere with the scan. Accept the latency cost; use shallow clones and artifact compression to minimise it.

**Centralised configuration vs developer flexibility.** Moving scan configuration to a policy repository means developers cannot tune the scanner for their specific codebase without a security team review cycle. This is intentional but creates friction. Mitigate by providing a well-defined process for teams to request rule exceptions, and a fast-track path for clear false positives. The alternative — developer-editable scan configuration — makes the security gate meaningless.

**Strictness vs false positive handling.** Requiring security team approval for every `.semgrepignore` entry creates a backlog if the scanner produces many false positives. The real fix is to reduce false positives at the rule level, not to make the suppression process easier to bypass. Invest in tuning the policy repository's ruleset to a precision level where suppressions are rare and reviewable.

**Cosign keyless signing and OIDC token scope.** Keyless signing via GitHub Actions OIDC tokens means the signing identity is tied to the workflow run. If the workflow is compromised, signatures from that run are also compromised. This is a limitation of any OIDC-based approach — the signature proves the result came from a specific workflow execution, not that the workflow itself was unmodified. Combine with workflow file CODEOWNERS and required review to reduce this risk.

## Failure Modes

**Scanner digest pinning breaking on binary rotation.** Container image digests become unavailable if the registry removes the specific manifest (during a security incident, platform migration, or cleanup). When this happens, the scan job fails with a pull error and no SARIF is produced. The required status check blocks all PRs. Maintain a mirrored copy of pinned scanner images in an internal registry, and have a documented process for updating pins — including a break-glass procedure that allows temporary unpinning with security team approval and an audit log entry.

**CODEOWNERS not enforced on fork PRs.** GitHub does not enforce CODEOWNERS for pull requests from forks by default — CODEOWNERS is evaluated against the base repository's branch protection rules, but fork PR workflows run with limited permissions. An attacker who forks the repository can submit a PR with a modified `.semgrepignore` that triggers the scan but without CODEOWNERS enforcement. Mitigate by requiring approval from code owners for all PRs (including forks) in branch protection settings, and by running scans with the policy repository configuration rather than the PR's repository configuration.

**SARIF upload failure blocking legitimate PRs.** The GitHub Code Scanning API occasionally returns errors under load. If the required status check is the SARIF upload step and the upload fails transiently, the PR is blocked until the job is re-run. Implement retry logic in the upload step with exponential backoff. Distinguish between a scan-produced-no-results failure (security signal, should block) and an API-upload-failed failure (operational, should retry). Track SARIF upload failures separately in your monitoring stack to distinguish the two cases.

**Auditd rules causing performance issues on busy runners.** Fine-grained auditd rules on paths that receive high write volume during builds can cause syscall overhead. Watch for `backlog_wait_time` increases in `/proc/audit/status` and tune rules to narrow the watch path. Use `-k` keys to allow rapid `ausearch` queries without full log scanning.

---

**Target systems:** Any Linux-based CI runner (GitHub Actions, GitLab CI, Jenkins on Linux, self-hosted runners on Ubuntu 22.04+/RHEL 9+).

**Related articles:** [Argo CD Security Hardening](/articles/cicd/argocd-security-hardening/), [Sigstore Keyless Signing](/articles/cicd/sigstore-keyless-signing/), [auditd Deep Dive](/articles/linux/auditd-deep-dive/).
