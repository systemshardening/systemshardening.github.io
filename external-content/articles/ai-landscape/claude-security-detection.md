---
title: "Claude for Security Detection: How Large Language Models Find What Scanners Miss"
description: "Traditional security scanners operate on pattern matching. They check for known CVEs in dependency trees, match regex patterns for hardcoded secrets,..."
slug: "claude-security-detection"
date: 2026-01-26
lastmod: 2026-01-26
category: "ai-landscape"
tags: ["claude", "llm", "security-detection", "vulnerability-analysis", "code-review", "audit", "anthropic"]
personas: ["security-engineer", "devops-engineer", "platform-engineer", "sre"]
article_number: 136
difficulty: "intermediate"
estimated_reading_time: 18
provider_bridges:
  - name: "Snyk"
    id: 48
    category: "vulnerability-scanning"
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
published: true
layout: article.njk
permalink: "/articles/ai-landscape/claude-security-detection/index.html"
---

# [Claude](https://claude.ai) for Security Detection: How Large Language Models Find What Scanners Miss

## Problem

Traditional security scanners operate on pattern matching. They check for known CVEs in dependency trees, match regex patterns for hardcoded secrets, and validate configurations against static rule sets. These tools are essential, but they have a fundamental limitation: they cannot reason about intent, context, or the interaction between components.

A static analysis tool will flag `chmod 777` but will not notice that a [Terraform](https://www.terraform.io) module creates an S3 bucket with a policy that grants `s3:GetObject` to `*` only when a specific variable combination is used. A [Kubernetes](https://kubernetes.io) policy scanner will catch a missing `runAsNonRoot` but will not recognise that a [Helm](https://helm.sh) chart's default values override every security context the template defines. A secret scanner will find `AWS_SECRET_ACCESS_KEY` in plaintext but will not identify that an application logs its entire request context, including bearer tokens, to stdout.

These are the gaps where security incidents happen. Not in the obvious misconfigurations that scanners catch on day one, but in the subtle interactions between components, the logic errors in policy definitions, and the business-context violations that no rule set anticipates.

Large language models, specifically Claude, can reason about these gaps. Claude reads configuration files, application code, and infrastructure definitions the way a senior security engineer does: understanding what the code is trying to accomplish, identifying where the implementation diverges from secure practice, and explaining why the divergence matters. The difference is speed. Claude can review a 2,000-line Terraform module in seconds rather than hours.

This article covers practical patterns for using Claude to detect security issues that traditional scanners miss, with real examples, integration patterns, and honest limitations.

**Target systems:** Any infrastructure or application codebase. Terraform, Kubernetes, [Ansible](https://www.ansible.com), Dockerfiles, application code in Python, Go, JavaScript, and Rust. CI/CD pipelines using GitHub Actions, GitLab CI, or Jenkins.

## Threat Model

- **Adversary:** Attackers exploiting misconfigurations, logic errors, and subtle vulnerabilities that pass through automated scanning and manual review.
- **Access level:** Varies. Some issues (public S3 buckets, overly permissive RBAC) require no authentication. Others (token leakage, SSRF via misconfigured proxies) require initial access to the application or network.
- **Objective:** Exploit gaps between what scanners check and what actually matters. These are configuration errors that are syntactically valid but semantically dangerous.
- **Blast radius:** Depends on the specific issue. A leaked service account token can compromise an entire Kubernetes cluster. An overly permissive IAM policy can expose all data in an AWS account. A logic error in an authentication middleware can bypass access controls for every endpoint.

## Configuration

### What Claude Detects That Scanners Cannot

Claude's strength is contextual reasoning across file boundaries. Here are the categories of issues where Claude consistently outperforms pattern-based scanners.

**1. Cross-file logic errors**

Scanners analyse files individually. Claude can reason about how files interact. Consider a Kubernetes setup where the Deployment references a ServiceAccount, the ServiceAccount has a ClusterRoleBinding, and the ClusterRole grants `*` verbs on secrets. No single file is obviously wrong. The Deployment looks fine. The ServiceAccount looks fine. The ClusterRole is overly permissive, but a scanner might not flag it if it matches an allowed pattern. Claude identifies the chain: this pod can read every secret in the cluster.

**2. Default value exploitation in templates**

Helm charts and Terraform modules define defaults. A Helm chart might set `securityContext.runAsNonRoot: true` in the template, but the `values.yaml` overrides it with `securityContext: {}`. The template is secure. The defaults are not. Claude reads both files and identifies that the deployed configuration will not include the security context.

**3. Token and credential leakage through logging**

Applications frequently log request/response bodies for debugging. Claude identifies when logging middleware captures authorization headers, session tokens, or API keys. This is not a hardcoded secret (scanners would catch that); it is a dynamic secret being written to logs at runtime.

**4. TOCTOU (time-of-check-time-of-use) vulnerabilities**

Claude can identify race conditions in security checks. For example, an application that validates a user's permissions, then performs an action in a separate database transaction. Between the check and the action, the user's permissions might change. This is a logic error that no static scanner can detect.

**5. Infrastructure drift risks**

Claude can review Terraform state alongside configuration and identify resources that were created manually (not in Terraform), resources where the configuration has changed since last apply, and resources where the provider's default behaviour has changed between versions.

### Integration Pattern: Claude in CI/CD

The most effective integration runs Claude as a review step in pull requests. Here is a GitHub Actions workflow that sends changed files to Claude for security review:

```yaml
# .github/workflows/security-review.yml
name: Claude Security Review
on:
  pull_request:
    paths:
      - '**.tf'
      - '**.yml'
      - '**.yaml'
      - '**.py'
      - '**.go'
      - 'Dockerfile*'

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0

      - name: Get changed files
        id: files
        run: |
          echo "files=$(git diff --name-only origin/${{ github.base_ref }}...HEAD | tr '\n' ' ')" >> "$GITHUB_OUTPUT"

      - name: Run Claude security review
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          # Collect file contents
          for f in ${{ steps.files.outputs.files }}; do
            echo "=== FILE: $f ===" >> review_input.txt
            cat "$f" >> review_input.txt
            echo "" >> review_input.txt
          done

          # Send to Claude API
          python3 scripts/claude-review.py \
            --input review_input.txt \
            --output review_output.md

      - name: Post review as PR comment
        if: always()
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          if [ -f review_output.md ]; then
            gh pr comment ${{ github.event.pull_request.number }} \
              --body-file review_output.md
          fi
```

### The Review Script

```python
# scripts/claude-review.py
import anthropic
import argparse
import sys

SYSTEM_PROMPT = """You are a senior infrastructure security engineer reviewing 
configuration changes. Analyse the provided files for security issues.

Focus on:
1. Cross-file interactions that create security gaps
2. Default values that override security settings
3. Credential or token exposure through logging or error handling
4. Overly permissive access controls (IAM, RBAC, network policies)
5. Missing encryption (at rest, in transit)
6. Race conditions in security checks
7. Supply chain risks (unpinned dependencies, unsigned images)

For each issue found, provide:
- SEVERITY: Critical / High / Medium / Low
- FILE: the affected file(s)
- LINE: approximate line number(s)
- ISSUE: what is wrong
- IMPACT: what an attacker could do
- FIX: the specific change to make

If no issues are found, say so. Do not invent issues.
Do not flag items that are already handled by the configuration.
Be precise. False positives erode trust in the review process."""


def review(input_file: str, output_file: str):
    client = anthropic.Anthropic()

    with open(input_file) as f:
        content = f.read()

    if len(content) > 500_000:
        print("Input too large, truncating to 500K characters")
        content = content[:500_000]

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": f"Review these infrastructure files for security issues:\n\n{content}"
            }
        ]
    )

    output = f"## Claude Security Review\n\n{message.content[0].text}"

    with open(output_file, "w") as f:
        f.write(output)

    # Exit with non-zero if critical issues found
    if "SEVERITY: Critical" in output:
        print("Critical security issues found")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    review(args.input, args.output)
```

### Interactive Security Audit with [Claude Code](https://claude.ai/code)

Beyond CI/CD, Claude Code (Anthropic's CLI tool) enables interactive security audits directly in the terminal. An engineer can point Claude at a directory and ask targeted security questions:

```bash
# Review a Terraform module for IAM issues
claude "Review the terraform/ directory for overly permissive IAM 
policies. Check for wildcard actions, wildcard resources, and 
policies that grant cross-account access."

# Audit Kubernetes manifests for privilege escalation paths
claude "Trace all service accounts in k8s/ to their role bindings 
and identify any that can read secrets, create pods, or escalate 
privileges."

# Check application code for credential handling issues
claude "Review src/ for anywhere credentials, tokens, or API keys 
are logged, stored in memory longer than necessary, or passed as 
command-line arguments."
```

This interactive mode is particularly effective for incident response, where an engineer needs to quickly understand the blast radius of a compromised component. Claude can trace data flows, identify all consumers of a leaked credential, and map the attack surface faster than manual grep-and-read workflows.

### Comparing Claude to Traditional Scanners

| Capability | Static Scanners | Claude |
|---|---|---|
| Known CVE detection | Excellent (database-driven) | Limited (knowledge cutoff) |
| Hardcoded secret detection | Excellent (pattern matching) | Good (contextual, fewer false positives) |
| Configuration policy violations | Good (rule-based) | Excellent (contextual reasoning) |
| Cross-file logic analysis | Poor (single-file analysis) | Excellent (multi-file reasoning) |
| Business context understanding | None | Good (when provided context) |
| Template/default interaction | Poor | Excellent |
| Novel vulnerability patterns | None (requires rule updates) | Good (reasoning from principles) |
| Speed at scale | Fast (milliseconds per file) | Slower (seconds per review) |
| Deterministic results | Yes (same input, same output) | No (probabilistic) |
| False positive rate | Varies (often high) | Low (but not zero) |

The key insight: Claude and scanners are complementary, not competing. Scanners handle the high-volume, deterministic checks (every dependency, every file, every commit). Claude handles the reasoning-intensive checks that scanners cannot perform. The strongest security review pipeline uses both.

### Structured Output for Automation

For automated pipelines, request structured output from Claude so downstream tools can parse the results:

```python
import anthropic
import json

client = anthropic.Anthropic()

message = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=4096,
    system="""Analyse the provided infrastructure code for security issues.
Return a JSON object with this structure:
{
  "issues": [
    {
      "severity": "critical|high|medium|low",
      "file": "path/to/file",
      "line": 42,
      "title": "Short description",
      "description": "Detailed explanation",
      "fix": "Specific remediation"
    }
  ],
  "summary": {
    "files_reviewed": 5,
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 1
  }
}""",
    messages=[{"role": "user", "content": code_content}]
)

results = json.loads(message.content[0].text)
if results["summary"]["critical"] > 0:
    raise SystemExit("Critical security issues detected")
```

## Expected Behaviour

After integrating Claude into security review workflows:

- **PR reviews include contextual security analysis.** Every pull request that touches infrastructure or application code receives a security review comment identifying cross-file issues, logic errors, and configuration gaps.
- **Review time decreases.** A human reviewer can focus on Claude's findings rather than reading every line. The human validates Claude's reasoning rather than performing the initial analysis.
- **Novel issues are caught.** Issues that no scanner rule covers, like a Helm values file that silently disables security contexts, are identified before merge.
- **Scanner and Claude results are correlated.** When both flag the same issue, confidence is high. When only Claude flags an issue, a human reviews it. When only the scanner flags an issue, it is likely a known pattern that Claude correctly contextualised as safe.

Verification:

```bash
# Check that the CI workflow runs on PRs
gh run list --workflow=security-review.yml --limit 5

# Review a sample Claude output for quality
gh pr view 42 --comments | grep "Claude Security Review"

# Track false positive rate over time
# Log each Claude finding as confirmed/false-positive in a spreadsheet
# Target: under 15% false positive rate after prompt tuning
```

## Trade-offs

| Decision | Benefit | Cost |
|---|---|---|
| Claude Sonnet for reviews (not Opus) | Faster response, lower API cost | Slightly less depth on complex logic chains |
| Review only changed files | Faster, focused, lower cost | Misses issues in unchanged files that interact with changes |
| Post as PR comment | Visible to all reviewers | Noisy if false positive rate is high |
| Fail CI on critical findings | Blocks dangerous changes | False positives block legitimate work |
| Include file contents in prompt | Full context for analysis | Large files consume tokens, increase cost |

**API cost estimate:** A typical PR review (5-10 files, 2,000-5,000 lines) costs $0.01-0.05 with Claude Sonnet. At 20 PRs per day, monthly cost is $6-30. This is negligible compared to the engineering time saved.

**Latency:** Claude reviews take 5-15 seconds per PR. This runs in parallel with other CI checks and does not increase total pipeline time if other checks take longer.

## Failure Modes

| Failure | Symptom | Detection | Response |
|---|---|---|---|
| False positive on safe configuration | Claude flags a correctly configured resource as insecure | Human reviewer marks finding as false positive; track rate over time | Refine system prompt with examples of the false positive pattern |
| Missed vulnerability (false negative) | Claude does not flag a real issue that a scanner or human catches | Compare Claude findings against scanner results and manual reviews periodically | Add the missed pattern to the system prompt as an explicit check |
| Hallucinated API fields or config options | Claude recommends a fix using a Kubernetes field or Terraform argument that does not exist | Apply Claude's fix, CI validation fails (terraform validate, kubectl dry-run) | Always validate Claude's recommendations with the actual tool before applying |
| Context window overflow | Large PRs exceed Claude's input limit, review is incomplete | Monitor input size, alert when truncation occurs | Split large PRs into focused reviews, or summarise unchanged context |
| API rate limiting or downtime | Claude review step fails, PR is blocked | CI step has a timeout and fallback; treat Claude failure as a warning, not a blocker | Make Claude review non-blocking (advisory) rather than a gate |
| Prompt injection via code under review | Malicious code in a PR contains instructions that manipulate Claude's review output | Review Claude's output for unusual formatting, off-topic content, or "no issues found" on obviously problematic code | Sanitise code input (strip comments matching prompt patterns), use separate system/user messages |

## When to Consider a Managed Alternative

**Transition point:** When your team reviews more than 50 PRs per week with infrastructure changes, or when you need compliance-grade audit trails for every security review.

**What managed providers handle:**

- **[Snyk](https://snyk.io):** Automated dependency scanning, container scanning, and IaC scanning with a managed rule database updated for new CVEs daily. Snyk handles the deterministic scanning that Claude is not suited for. Use Snyk for known vulnerabilities, Claude for unknown configuration risks.
- **[Sysdig](https://sysdig.com):** Runtime security monitoring that detects issues Claude identifies in code review but that were not caught before deployment. Sysdig verifies at runtime what Claude recommends at review time.

**What Claude handles that managed tools do not:** Cross-file reasoning, business-context analysis, novel vulnerability patterns, and natural-language explanations of why something is dangerous. No managed tool provides this today.

**The optimal stack:** Snyk or equivalent for deterministic scanning + Claude for contextual review + Sysdig or equivalent for runtime verification. Each tool covers gaps the others cannot.


## Related Articles

- [Claude for Application Security: Finding Logic Vulnerabilities in Source Code](/articles/ai-landscape/claude-code-vulnerability/)
- [Claude for Infrastructure-as-Code Security Review: Terraform, CloudFormation, and Pulumi](/articles/ai-landscape/claude-iac-review/)
- [Claude for Kubernetes Security Auditing: Finding Privilege Escalation Paths Scanners Cannot See](/articles/ai-landscape/claude-kubernetes-audit/)
- [Using AI to Harden Systems: Automated Configuration Review and Remediation](/articles/ai-landscape/ai-assisted-hardening/)
- [Claude, Mythos, and the Non-Human Infrastructure Consumer: Writing Hardening Guides for AI Agents](/articles/ai-landscape/claude-non-human-consumers/)
