---
title: "Using AI to Harden Systems: Automated Configuration Review and Remediation"
description: "Manual security review of infrastructure-as-code takes 2-4 hours per pull request for complex changes."
slug: "ai-assisted-hardening"
date: 2026-01-23
lastmod: 2026-01-23
category: "ai-landscape"
tags: ["ai-security", "llm", "iac-review", "automation", "configuration", "remediation"]
personas: ["devops-engineer", "security-engineer", "platform-engineer"]
article_number: 107
difficulty: "intermediate"
estimated_reading_time: 14
provider_bridges:
  - name: "Snyk"
    id: 48
    category: "vulnerability-scanning"
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
premium_pack: "security-review-prompt-library"
published: true
layout: article.njk
permalink: "/articles/ai-landscape/ai-assisted-hardening/index.html"
---

# Using AI to Harden Systems: Automated Configuration Review and Remediation

## Problem

Manual security review of infrastructure-as-code takes 2-4 hours per pull request for complex changes. A team managing 20+ [Terraform](https://www.terraform.io) modules, 50+ [Kubernetes](https://kubernetes.io) manifests, and a dozen [Ansible](https://www.ansible.com) playbooks cannot review every change manually with security depth. The result: security review becomes a bottleneck that either slows deployment velocity or gets skipped entirely.

LLMs can accelerate this. An AI model can review a Kubernetes manifest and identify missing security contexts, overly permissive RBAC bindings, unencrypted secrets, and missing network policies in seconds rather than hours. But AI-generated security recommendations must be verified. An LLM can hallucinate non-existent Kubernetes API fields, recommend deprecated configurations, or miss business-context violations that only a human reviewer would catch.

The challenge is not "can AI review security configs?" (it can, with limitations) but "how do you build a workflow where AI review is trustworthy enough to act on?" The answer is: AI generates recommendations, automated tools validate them, and humans approve the final change.

**Target systems:** CI/CD pipelines with infrastructure-as-code. Terraform, Kubernetes manifests, Ansible playbooks, Dockerfiles. Any configuration format where security misconfigurations are common.

## Threat Model

- **Adversary:** Not an external attacker. The threat is the AI itself: hallucinated configurations, outdated recommendations, and missing context that leads to a worse security posture if applied blindly.
- **Objective (positive):** Catch security misconfigurations faster than manual review. Reduce the time from "PR opened" to "security issues identified" from hours to minutes.
- **Blast radius:** An incorrect AI-generated configuration applied to production can break services (overly restrictive network policy), expose data (misconfigured RBAC), or create false confidence (AI says "looks good" when it is not). The verification pipeline is the safety net.

## Configuration

### IaC Security Review with LLMs

Integrate LLM-based review into the PR workflow. The LLM reviews changed files and posts findings as PR comments.

```yaml
# .github/workflows/ai-security-review.yml
name: AI Security Review
on:
  pull_request:
    paths:
      - '*.tf'
      - '*.yaml'
      - '*.yml'
      - 'Dockerfile*'
      - 'ansible/**'

jobs:
  ai-review:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
      contents: read
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Get changed files
        id: changed
        run: |
          FILES=$(git diff --name-only origin/${{ github.base_ref }}...HEAD | grep -E '\.(tf|yaml|yml)$|Dockerfile' || true)
          echo "files=${FILES}" >> $GITHUB_OUTPUT

      - name: AI Security Review
        if: steps.changed.outputs.files != ''
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          python scripts/ai-security-review.py \
            --files "${{ steps.changed.outputs.files }}" \
            --output review-results.json

      - name: Post review comments
        if: steps.changed.outputs.files != ''
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const results = JSON.parse(fs.readFileSync('review-results.json', 'utf8'));
            if (results.findings.length > 0) {
              let body = '## AI Security Review\n\n';
              body += '> These findings are AI-generated and require human verification before acting on them.\n\n';
              for (const finding of results.findings) {
                body += `### ${finding.severity}: ${finding.title}\n`;
                body += `**File:** \`${finding.file}\`\n`;
                body += `${finding.description}\n\n`;
                if (finding.suggestion) {
                  body += `**Suggested fix:**\n\`\`\`\n${finding.suggestion}\n\`\`\`\n\n`;
                }
              }
              body += '\n---\n*AI review by Claude. Verify all suggestions before applying.*';
              await github.rest.issues.createComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                issue_number: context.issue.number,
                body: body
              });
            }
```

```python
# scripts/ai-security-review.py
import anthropic
import json
import sys
import os

REVIEW_PROMPT = """Review this infrastructure configuration file for security issues.

Focus on:
1. Missing security contexts (runAsNonRoot, readOnlyRootFilesystem, drop ALL capabilities)
2. Overly permissive RBAC (cluster-admin usage, wildcard permissions)
3. Missing network policies for namespaces with sensitive workloads
4. Hardcoded secrets or credentials
5. Missing encryption (at rest, in transit)
6. Privileged containers or host namespace sharing
7. Missing resource limits (enabling resource exhaustion attacks)
8. Deprecated or insecure API versions

For each finding, provide:
- severity: critical, high, medium, or low
- title: one-line summary
- description: what the issue is and why it matters
- suggestion: the corrected configuration (if applicable)

If the configuration looks secure, say so. Do not invent issues that do not exist.
Only report issues you are confident about. If you are unsure, note the uncertainty.

File: {filename}
Content:
```
{content}
```

Respond in JSON format:
{{"findings": [{{"severity": "...", "title": "...", "file": "...", "description": "...", "suggestion": "..."}}]}}
"""

def review_file(client, filename, content):
    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=4096,
        messages=[{
            "role": "user",
            "content": REVIEW_PROMPT.format(filename=filename, content=content)
        }]
    )
    try:
        return json.loads(message.content[0].text)
    except json.JSONDecodeError:
        return {"findings": []}

def main():
    client = anthropic.Anthropic()
    files = os.environ.get("FILES", "").split()

    all_findings = []
    for filepath in files:
        if not os.path.exists(filepath):
            continue
        with open(filepath) as f:
            content = f.read()
        result = review_file(client, filepath, content)
        all_findings.extend(result.get("findings", []))

    with open("review-results.json", "w") as f:
        json.dump({"findings": all_findings}, f, indent=2)

if __name__ == "__main__":
    main()
```

### Effective Prompts for Security Review

What LLMs catch well and what they miss:

```yaml
# What LLMs are good at detecting:
strengths:
  - Missing securityContext fields (runAsNonRoot, capabilities drop)
  - Overly permissive RBAC (cluster-admin, wildcard verbs/resources)
  - Hardcoded secrets (API keys, passwords in environment variables)
  - Missing encryption settings (S3 bucket without encryption, RDS without TLS)
  - Deprecated API versions (extensions/v1beta1 Ingress)
  - Privileged containers (privileged: true, hostPID, hostNetwork)
  - Missing resource limits on pods
  - Common Terraform misconfigurations (public S3 buckets, overly broad security groups)

# What LLMs commonly miss or get wrong:
weaknesses:
  - Business logic: "this service should not have access to that database"
    (LLM does not know your architecture)
  - Runtime behaviour: configuration looks safe but breaks at runtime
  - Provider-specific edge cases (AWS IAM conditions, GCP org policies)
  - Interactions between multiple files (network policy in one file, pod in another)
  - Custom CRDs (LLM may not know the schema)
  - Version-specific features (suggesting config that works on K8s 1.30 but not 1.28)
```

### Automated Config Validation Pipeline

LLM generates a recommendation. Automated tools validate it. Human reviews the result.

```yaml
# .github/workflows/validate-ai-suggestions.yml
name: Validate AI Security Suggestions
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Step 1: Run automated security scanners (ground truth)
      - name: Trivy IaC scan
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: 'config'
          scan-ref: '.'
          format: 'json'
          output: 'trivy-iac.json'

      - name: kube-linter
        run: |
          kube-linter lint k8s/ --format json > kube-linter.json 2>&1 || true

      - name: Checkov scan
        run: |
          checkov -d . --output json > checkov.json 2>&1 || true

      # Step 2: Compare AI findings with scanner findings
      - name: Cross-reference results
        run: |
          python scripts/cross-reference.py \
            --ai-results review-results.json \
            --trivy-results trivy-iac.json \
            --kubelinter-results kube-linter.json \
            --output validation-report.json

      # Step 3: Human reviews the validated report
      - name: Post validation report
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = JSON.parse(fs.readFileSync('validation-report.json', 'utf8'));
            let body = '## Security Validation Report\n\n';
            body += `| Source | Findings | Confirmed by Scanner |\n`;
            body += `|--------|----------|---------------------|\n`;
            body += `| AI Review | ${report.ai_findings} | ${report.confirmed} |\n`;
            body += `| Trivy | ${report.trivy_findings} | N/A |\n`;
            body += `| kube-linter | ${report.kubelinter_findings} | N/A |\n\n`;

            if (report.ai_only.length > 0) {
              body += '### AI-Only Findings (Require Human Verification)\n';
              for (const f of report.ai_only) {
                body += `- **${f.severity}**: ${f.title} (${f.file})\n`;
              }
            }
            body += '\n*Findings confirmed by both AI and scanners are high confidence.*';
            await github.rest.issues.createComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body: body
            });
```

### Remediation Script Generation

Use LLM output from vulnerability scanners to generate remediation scripts, then validate before applying.

```python
# generate-remediation.py
# Input: Trivy vulnerability report
# Output: Remediation PR with fixed Dockerfile

import anthropic
import json

REMEDIATION_PROMPT = """Given this vulnerability scan result, generate a fix.

Vulnerability:
- Package: {pkg_name}@{installed_version}
- Fixed Version: {fixed_version}
- CVE: {cve_id}
- Severity: {severity}

Current Dockerfile:
```
{dockerfile_content}
```

Generate the corrected Dockerfile that updates {pkg_name} to {fixed_version} or later.
Only change what is necessary. Keep all other instructions identical.
Respond with just the corrected Dockerfile content, no explanation.
"""

def generate_fix(client, vuln, dockerfile_content):
    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=4096,
        messages=[{
            "role": "user",
            "content": REMEDIATION_PROMPT.format(
                pkg_name=vuln["PkgName"],
                installed_version=vuln["InstalledVersion"],
                fixed_version=vuln["FixedVersion"],
                cve_id=vuln["VulnerabilityID"],
                severity=vuln["Severity"],
                dockerfile_content=dockerfile_content
            )
        }]
    )
    return message.content[0].text
```

### Critical Limitations

There are configurations where AI-generated output must never be applied without human review and automated validation.

```yaml
# NEVER auto-apply AI-generated configs for:
critical_review_required:
  - type: "NetworkPolicy"
    reason: "Incorrect policy can break inter-service communication with no immediate error signal. Failure mode is silent (connections timeout)."
    verification: "Apply in staging. Run integration tests. Verify no connection timeouts in monitoring."

  - type: "RBAC (Role, ClusterRole, RoleBinding)"
    reason: "Overly restrictive RBAC blocks deployments. Overly permissive RBAC creates security holes. Both fail silently until someone tries to use the permission."
    verification: "Compare effective permissions before and after. Test with `kubectl auth can-i` for affected service accounts."

  - type: "Secret management (Vault policies, KMS config)"
    reason: "Misconfigured Vault policy can lock out applications or expose secrets to wrong consumers."
    verification: "Test policy with Vault's built-in policy testing. Verify with `vault token capabilities`."

  - type: "TLS/certificate configuration"
    reason: "Incorrect TLS config can cause service outages (wrong cipher suite, wrong CA) or silently downgrade security."
    verification: "Test TLS handshake with `openssl s_client`. Verify certificate chain."

# Safe to auto-apply after automated validation:
auto_apply_safe:
  - type: "Dockerfile package version updates"
    condition: "Fixed version passes CI tests"
  - type: "Adding missing securityContext fields"
    condition: "Pod starts successfully in staging"
  - type: "Trivy-identified CVE patches (patch versions)"
    condition: "CI tests pass and canary deployment succeeds"
```

## Expected Behaviour

- Every PR with infrastructure-as-code changes receives an AI security review comment within 5 minutes
- AI findings are cross-referenced with automated scanner results (Trivy, kube-linter, Checkov)
- Findings confirmed by both AI and scanners are marked as high confidence
- AI-only findings are flagged for human verification
- Remediation scripts are generated for Trivy-identified CVEs with known fixed versions
- Critical configuration types (network policies, RBAC, secrets) always require human approval regardless of AI recommendation

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| AI review on every PR | Catches issues in seconds instead of hours | API cost ($0.01-$0.10 per review depending on file size) | Cost is negligible compared to manual review time. Set a maximum file size to avoid expensive reviews of generated files. |
| Cross-referencing with scanners | Reduces false positives; increases confidence in findings | Scanners and AI may have the same blind spots | Use multiple scanner types (Trivy for CVEs, kube-linter for K8s, Checkov for Terraform). Diversity reduces shared blind spots. |
| AI-generated remediation | Faster fix for known vulnerabilities | LLM may generate syntactically correct but semantically wrong fixes | All remediation must pass CI tests. For critical services, staging deployment before production. |
| Human review always required for critical configs | Prevents AI from breaking critical systems | Bottleneck returns for critical changes | The scope of "critical" is small (network policies, RBAC, secrets). Most changes are not in this category. |
| Prompt engineering for review quality | Better prompts produce more relevant findings | Prompts need maintenance as tools and APIs change | Version control prompts alongside code. Review prompt effectiveness quarterly. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| LLM hallucinates non-existent API field | AI suggests adding a field that does not exist in the Kubernetes API | Admission webhook rejects the manifest; CI validation fails | Cross-reference AI suggestions against API schema. kube-linter and kubeval catch invalid fields. |
| LLM recommends deprecated configuration | AI suggests config that was valid in older versions | CI tests may still pass (deprecated but functional); manifest validation catches removed fields | Include cluster version in the review prompt. Validate against the target cluster's API version. |
| AI review API unavailable | PR does not receive security review | GitHub Actions job fails; no review comment posted | Fail open (do not block the PR) but alert the security team. Automated scanners still run. Manual review for PRs that missed AI review. |
| False positive rate too high | Team ignores AI review comments | Low engagement with review comments; no fixes applied from AI findings | Tune prompts to reduce false positives. Track which findings lead to actual fixes. Remove finding categories with high false positive rates. |
| AI-generated fix breaks production | Remediation script introduces a regression | CI tests fail (caught pre-production) or canary deployment degrades (caught in production) | Canary deployment with automated rollback. All AI-generated fixes must pass the same CI gate as human-written code. |

## When to Consider a Managed Alternative

[Snyk](https://snyk.io) IaC scanning provides automated security review without AI dependency, catching known misconfigurations through rule-based analysis. Use alongside AI review for comprehensive coverage. [Sysdig](https://sysdig.com) posture management validates configurations against runtime reality, catching issues that static analysis (AI or rule-based) misses. [Grafana Cloud](https://grafana.com/cloud) for monitoring the impact of AI-applied changes on system behaviour post-deployment.

**Premium content pack:** Security review prompt library. Tested prompts for Terraform, Kubernetes, Ansible, and [Docker](https://www.docker.com) security review. Cross-referencing scripts for AI and scanner results. GitHub Actions workflow templates for the complete AI review pipeline.


## Related Articles

- [AI-Powered Vulnerability Discovery: What Automated Code Analysis Means for Your Patch Cycle](/articles/ai-landscape/ai-vulnerability-discovery/)
- [Detecting AI-Generated Attacks: Moving from Signatures to Behavioural Baselines](/articles/ai-landscape/detecting-ai-attacks/)
- [Claude for Security Detection: How Large Language Models Find What Scanners Miss](/articles/ai-landscape/claude-security-detection/)
- [How AI Is Compressing the Attacker Timeline: What Defenders Need to Change Now](/articles/ai-landscape/ai-compressing-attacker-timeline/)
- [Claude, Mythos, and the Non-Human Infrastructure Consumer: Writing Hardening Guides for AI Agents](/articles/ai-landscape/claude-non-human-consumers/)
