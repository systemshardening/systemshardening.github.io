---
title: "IaC Security Scanning in CI/CD: Checkov, tfsec, and Policy-as-Code for Terraform, CloudFormation, Kubernetes, and Helm"
description: "A practical guide to catching infrastructure misconfigurations before they reach production — covering Checkov, tfsec, Trivy, KICS, terrascan, and conftest integrated into GitHub Actions with SARIF annotations, custom policies, false positive suppression, and severity-based blocking."
slug: iac-security-scanning-cicd
date: 2026-05-07
lastmod: 2026-05-07
category: cicd
tags:
  - iac-security
  - checkov
  - tfsec
  - terraform
  - policy-as-code
personas:
  - security-engineer
  - platform-engineer
article_number: 539
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/cicd/iac-security-scanning-cicd/
---

# IaC Security Scanning in CI/CD: Checkov, tfsec, and Policy-as-Code for Terraform, CloudFormation, Kubernetes, and Helm

## Why IaC Misconfigurations Are a Production Problem

Every large cloud breach of the past five years has at least one Infrastructure as Code misconfiguration in its causal chain. An S3 bucket provisioned with `acl = "public-read"`. A security group with `0.0.0.0/0` open on port 22. An IAM role with `Action: "*"` and `Resource: "*"`. These are not obscure edge cases — they are the default settings in many Terraform examples, CloudFormation getting-started guides, and Helm chart values files.

The reason they persist is process timing. A developer writes a Terraform module on Monday. The module passes code review because reviewers are looking at application logic, not cloud resource configuration. The module ships to production on Thursday. A security scan runs monthly. The misconfiguration lives in production for three weeks before anyone notices — if it is noticed at all, rather than discovered by a threat actor.

IaC security scanning in CI inverts this. A scanner runs on every pull request. It fails the PR if the module opens a public S3 bucket. The developer fixes it before merge. The fix takes five minutes. The alternative — fixing a misconfiguration that has been in production and is referenced by downstream modules — takes days.

The three categories of finding that account for most IaC security debt are:

**Public exposure.** S3 buckets without public access block settings, security groups allowing ingress from `0.0.0.0/0` or `::/0` on sensitive ports, load balancers without HTTPS enforcement, RDS instances with `publicly_accessible = true`.

**Overpermissive identity.** IAM policies with wildcard actions or resources, instance profiles with admin-equivalent policies, Kubernetes RBAC bindings with `cluster-admin` granted to service accounts, Helm values that set `securityContext.privileged: true`.

**Missing controls.** Encryption at rest not enabled for RDS, EBS volumes, or S3. Logging disabled for CloudTrail, VPC Flow Logs, or S3 access logs. No deletion protection on databases. No MFA delete on state buckets. Container images running as root.

A scanner that checks for all three categories on every PR closes the feedback loop that makes IaC misconfigurations a solved problem rather than a recurring audit finding.

## Tool Landscape

There are five tools worth knowing. They are not exclusive — most teams run two or three together.

**[Checkov](https://www.checkov.io)** (Bridgecrew/Palo Alto) scans Terraform, CloudFormation, Kubernetes manifests, Helm charts, Dockerfiles, GitHub Actions workflows, and Bicep in a single tool. It ships with 1,000+ built-in checks and supports custom checks in Python. SARIF output works natively. It is the most practical starting point because one tool covers the full stack.

**[tfsec](https://aquasecurity.github.io/tfsec)** (Aqua Security) focuses specifically on Terraform. Its HCL-aware parser understands variable references and module calls rather than treating the files as text, which reduces false positives on parameterised resources. It integrates well with `tfsec-action` in GitHub Actions.

**[Trivy](https://trivy.dev)** (Aqua Security) is primarily a container vulnerability scanner but its `--scanners misconfig` flag runs IaC checks against Kubernetes manifests and Terraform. If you already use Trivy for container scanning, adding `--scanners misconfig` covers a large fraction of Kubernetes misconfiguration findings with no additional tooling.

**[KICS](https://kics.io)** (Checkmarx) — Keeping Infrastructure as Code Secure — covers Terraform, CloudFormation, Kubernetes, Helm, Ansible, and Docker Compose using queries written in [OPA](https://www.openpolicyagent.org) Rego. Its strength is the breadth of platforms and the ability to write custom Rego queries for teams already using OPA elsewhere.

**[terrascan](https://runterrascan.io)** (Tenable) covers Terraform, CloudFormation, Kubernetes, Helm, and Kustomize with a policy engine built on OPA. Its multi-cloud coverage and Rego-based extensibility make it useful in enterprises with mixed AWS/Azure/GCP estates.

## Checkov: Multi-Framework Scanning

Checkov's value is breadth. A single invocation can scan an entire monorepo containing Terraform, Kubernetes manifests, and Helm charts.

```bash
# Scan everything: Terraform, CloudFormation, Kubernetes, Helm, Dockerfiles
checkov --directory . \
  --output sarif \
  --output-file-path checkov-results.sarif \
  --soft-fail  # Exit 0 even with findings (used for PR annotation without blocking)

# Scan a specific framework
checkov --directory ./terraform \
  --framework terraform \
  --output cli

# Scan a Helm chart (renders values before scanning)
checkov --directory ./charts/myapp \
  --framework helm \
  --var-file ./charts/myapp/values-production.yaml

# Show only HIGH and CRITICAL findings
checkov --directory . \
  --check-threshold HIGH
```

By default Checkov exits non-zero if any check fails. For CI integration, control exit behaviour with `--soft-fail` (always exit 0) or `--hard-fail-on HIGH,CRITICAL` (fail only on those severities).

## tfsec: Terraform Deep Scanning

tfsec resolves variable references across module calls, which matters for Terraform that uses locals and module outputs to construct resource configurations.

```bash
# Basic scan
tfsec ./terraform

# JSON output for parsing
tfsec ./terraform --format json > tfsec-results.json

# SARIF for GitHub Advanced Security
tfsec ./terraform --format sarif > tfsec-results.sarif

# Exclude specific checks
tfsec ./terraform --exclude-checks aws-s3-block-public-acls,aws-s3-block-public-policy

# Set minimum severity (options: CRITICAL, HIGH, MEDIUM, LOW)
tfsec ./terraform --minimum-severity HIGH

# Show only results for a specific check
tfsec ./terraform --include-checks aws-iam-no-policy-wildcards
```

The check IDs follow a `provider-service-check-name` format (e.g., `aws-iam-no-policy-wildcards`, `aws-ec2-no-public-ingress-sgr`). These are the IDs used in inline suppression comments.

## Trivy for Kubernetes and Terraform Misconfigurations

If Trivy is already in the pipeline for container image scanning, enabling misconfiguration scanning costs one flag.

```bash
# Kubernetes manifest scan
trivy config ./kubernetes/ \
  --scanners misconfig \
  --format sarif \
  --output trivy-misconfig.sarif

# Terraform scan
trivy config ./terraform/ \
  --scanners misconfig \
  --severity HIGH,CRITICAL

# Combined: vulnerabilities AND misconfigurations in one pass (for container+IaC)
trivy image --scanners vuln,misconfig myimage:latest

# Helm chart scan (renders chart before scanning)
trivy config ./charts/myapp \
  --helm-values ./charts/myapp/values-production.yaml \
  --scanners misconfig
```

## GitHub Actions Integration with SARIF

SARIF (Static Analysis Results Interchange Format) is the format GitHub uses to display inline PR annotations. When a scanner outputs SARIF and you upload it with `actions/upload-sarif`, findings appear as annotations on the changed lines in the PR diff — exactly where the developer needs to see them.

```yaml
# .github/workflows/iac-security.yml
name: IaC Security Scanning

on:
  pull_request:
    paths:
      - 'terraform/**'
      - 'kubernetes/**'
      - 'charts/**'
      - '**/*.tf'
      - '**/*.yaml'
      - '**/*.yml'

permissions:
  contents: read
  security-events: write  # Required for uploading SARIF results
  pull-requests: read

jobs:
  checkov:
    name: Checkov (multi-framework)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Run Checkov
        uses: bridgecrewio/checkov-action@v12
        with:
          directory: .
          framework: terraform,cloudformation,kubernetes,helm
          output_format: sarif
          output_file_path: checkov-results.sarif
          soft_fail: false
          check: CKV_AWS_*,CKV_K8S_*,CKV_HELM_*
          # Block on HIGH and CRITICAL, warn on lower
          hard_fail_on: HIGH,CRITICAL

      - name: Upload SARIF to GitHub Security tab
        if: always()  # Upload even if Checkov failed
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: checkov-results.sarif
          category: checkov

  tfsec:
    name: tfsec (Terraform deep scan)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Run tfsec
        uses: aquasecurity/tfsec-action@v1.0.3
        with:
          working_directory: terraform/
          format: sarif
          sarif_file: tfsec-results.sarif
          minimum_severity: HIGH
          soft_fail: false

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: tfsec-results.sarif
          category: tfsec

  trivy-k8s:
    name: Trivy (Kubernetes misconfigs)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Run Trivy for Kubernetes manifests
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: config
          scan-ref: kubernetes/
          scanners: misconfig
          format: sarif
          output: trivy-k8s.sarif
          severity: HIGH,CRITICAL
          exit-code: '1'

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy-k8s.sarif
          category: trivy-k8s
```

The `security-events: write` permission on the workflow is required. Without it the SARIF upload silently fails and findings never appear in the Security tab.

## Custom Checkov Checks in Python

Built-in checks cover common misconfigurations. Custom checks encode organisation-specific policies that no upstream ruleset knows about: your company's naming conventions, mandatory tagging requirements, approved AMI lists, or required encryption key ARNs.

```python
# .checkov/checks/check_s3_requires_org_tag.py
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class S3BucketRequiresOrgTag(BaseResourceCheck):
    def __init__(self):
        name = "Ensure S3 buckets have required org:team tag"
        id = "CKV_CUSTOM_1"
        supported_resources = ["aws_s3_bucket"]
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(
            name=name,
            id=id,
            categories=categories,
            supported_resources=supported_resources,
        )

    def scan_resource_conf(self, conf) -> CheckResult:
        tags = conf.get("tags", [{}])
        if isinstance(tags, list):
            tags = tags[0] if tags else {}

        if isinstance(tags, dict) and "org:team" in tags:
            return CheckResult.PASSED
        return CheckResult.FAILED


scanner = S3BucketRequiresOrgTag()
```

```python
# .checkov/checks/check_no_public_ecr.py
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class ECRNoPublicAccess(BaseResourceCheck):
    """Block ECR repositories configured as public (aws_ecrpublic_repository)."""

    def __init__(self):
        name = "Ensure no public ECR repositories are created"
        id = "CKV_CUSTOM_2"
        supported_resources = ["aws_ecrpublic_repository"]
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(
            name=name,
            id=id,
            categories=categories,
            supported_resources=supported_resources,
        )

    def scan_resource_conf(self, conf) -> CheckResult:
        # The mere existence of this resource type is a policy violation
        return CheckResult.FAILED


scanner = ECRNoPublicAccess()
```

Register the custom checks directory when running Checkov:

```bash
checkov --directory ./terraform \
  --external-checks-dir ./.checkov/checks \
  --framework terraform
```

In the GitHub Actions workflow, pass the `external_checks_dir` input to the Checkov action to include custom checks in CI runs.

## Suppressing False Positives

False positives are inevitable. The question is how you suppress them: inline in code with an auditable comment, or in a baseline file that gradually grows until nobody reviews it.

### Inline suppression (preferred for single-resource exceptions)

```hcl
# Terraform: suppress a specific Checkov check on a resource
resource "aws_s3_bucket" "access_logs" {
  bucket = "my-org-access-logs"

  #checkov:skip=CKV_AWS_18: Access log bucket does not need its own access logging (would be circular)
  #checkov:skip=CKV2_AWS_62: Event notifications not required for log-only bucket
}

# tfsec suppression uses a different comment format
resource "aws_security_group_rule" "allow_vpn" {
  type        = "ingress"
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["10.8.0.0/16"]  # VPN range only

  #tfsec:ignore:aws-ec2-no-public-ingress-sgr
}
```

The inline format makes the suppression visible in code review. A reviewer can challenge it. A future developer sees the justification. This is the correct approach for documented, intentional exceptions.

### Checkov baseline file (useful for brownfield onboarding)

When adding Checkov to a repository with a large existing codebase, a baseline file lets you start blocking new misconfigurations without immediately failing on the existing backlog.

```bash
# Generate a baseline from the current state of the repository
checkov --directory ./terraform \
  --framework terraform \
  --create-baseline

# This creates .checkov.baseline — commit it to Git
# Future runs with --baseline .checkov.baseline will only fail on NEW findings
checkov --directory ./terraform \
  --baseline .checkov.baseline
```

The risk with baseline files is they can grow indefinitely. Treat baseline entries as technical debt. Track the count in your metrics dashboard and require that it decreases over time — never increases.

## terrascan with OPA Policies

terrascan is useful when you need multi-cloud coverage with custom policies written in Rego — the same language used for OPA/Gatekeeper admission control, which means security engineers can share expertise across policy layers.

```bash
# Scan Terraform for AWS, Azure, and GCP misconfigurations
terrascan scan \
  --iac-type terraform \
  --policy-type aws,azure,gcp \
  --severity HIGH \
  --output sarif > terrascan.sarif

# Scan Kubernetes manifests
terrascan scan \
  --iac-type k8s \
  --iac-dir ./kubernetes \
  --severity HIGH

# Use custom Rego policies
terrascan scan \
  --iac-type terraform \
  --policy-path ./policies/custom \
  --severity MEDIUM
```

A custom terrascan Rego policy:

```rego
# policies/custom/deny_admin_role.rego
package accurics.terraform.security.aws

import input as tfplan

deny[msg] {
  resource := tfplan.resource.aws_iam_role_policy[_]
  policy := json.unmarshal(resource.config.policy)
  statement := policy.Statement[_]
  statement.Effect == "Allow"
  statement.Action[_] == "*"
  msg := sprintf(
    "IAM role policy '%v' grants wildcard action — use least-privilege actions instead",
    [resource.config.name]
  )
}
```

## Scanning OpenTofu/Terraform Plan JSON with conftest

The static configuration represents intent. The plan represents what Terraform will actually do, including values resolved from data sources and remote state. Scanning the plan JSON catches misconfigurations that static analysis misses because a resource's effective configuration is only known after `terraform plan`.

```bash
# Generate a plan and convert to JSON
terraform init -input=false
terraform plan -input=false -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json

# Scan the plan JSON with conftest and OPA policies
conftest test tfplan.json \
  --policy ./policies \
  --namespace terraform.plan
```

```rego
# policies/terraform_plan.rego
package terraform.plan

import input as plan

# Block any planned resource that opens port 22 to the world
deny[msg] {
  resource := plan.resource_changes[_]
  resource.type == "aws_security_group_rule"
  resource.change.after.type == "ingress"
  resource.change.after.from_port <= 22
  resource.change.after.to_port >= 22
  resource.change.after.cidr_blocks[_] == "0.0.0.0/0"
  msg := sprintf(
    "Security group rule '%v' opens SSH (port 22) to 0.0.0.0/0",
    [resource.address]
  )
}

# Block any S3 bucket without server-side encryption
deny[msg] {
  resource := plan.resource_changes[_]
  resource.type == "aws_s3_bucket"
  not resource.change.after.server_side_encryption_configuration
  msg := sprintf(
    "S3 bucket '%v' has no server-side encryption configuration",
    [resource.address]
  )
}
```

The `conftest` approach gives you full visibility into the resolved plan and allows policies that cannot be expressed against static HCL — for example, verifying that a security group's CIDR block comes from a specific approved range stored in remote state.

## Severity Thresholds and Blocking Policy

The most important operational decision is which findings block a merge and which generate warnings. A policy that blocks on everything produces alert fatigue and developers suppressing findings reflexively. A policy that blocks on nothing produces a scanner that runs but has no effect.

The practical approach:

**Block on HIGH and CRITICAL.** These are misconfigurations with a direct exploitation path: publicly accessible databases, world-open security group rules, IAM wildcards, unencrypted storage containing PII. A developer should not merge code that introduces these.

**Warn on MEDIUM.** Missing access logs, no deletion protection on non-critical resources, tags absent. These are worth fixing but should not block shipping a feature.

**Report MEDIUM/LOW but do not alert actively.** Feed them into the metrics dashboard described below. Address them in batch cleanup sprints.

```yaml
# GitHub Actions step: enforce severity policy
- name: Checkov with severity threshold
  uses: bridgecrewio/checkov-action@v12
  with:
    directory: .
    framework: terraform,kubernetes,helm
    # These severities fail the job (non-zero exit)
    hard_fail_on: HIGH,CRITICAL
    # These are reported but do not fail
    soft_fail_on: MEDIUM,LOW
    output_format: sarif
    output_file_path: checkov-results.sarif
```

The same logic applies in shell scripts for scanners that do not have built-in threshold support:

```bash
# Parse Checkov JSON output and exit non-zero only on HIGH/CRITICAL
checkov --directory ./terraform \
  --framework terraform \
  --output json > checkov-output.json

CRITICAL=$(jq '[.results.failed_checks[] | select(.check_result.result == "failed") | select(.severity == "CRITICAL" or .severity == "HIGH")] | length' checkov-output.json)

if [ "$CRITICAL" -gt 0 ]; then
  echo "Found $CRITICAL HIGH/CRITICAL findings — blocking merge"
  exit 1
fi
echo "No HIGH/CRITICAL findings"
exit 0
```

## Tracking Remediation Rates Over Time

Running scanners and blocking PRs is the prevention layer. Measuring remediation rates is the feedback loop that tells you whether the prevention layer is working and whether the backlog is growing or shrinking.

The metrics worth tracking:

**New findings introduced per week.** This measures whether developers are introducing new misconfigurations faster than they are fixing them. If this number is increasing, the PR blocking policy is not effective — typically because too many findings are suppressed inline.

**Mean time to remediate by severity.** How long does a CRITICAL finding live in the codebase before it is fixed? If CRITICAL findings live for more than 24 hours, the blocking policy is not being enforced consistently.

**Baseline file size trend.** If you use Checkov baselines for brownfield onboarding, the baseline entry count should decrease each sprint. A flat or increasing baseline is a signal that engineers are not prioritising remediation.

**Suppression comment count.** Count `checkov:skip`, `tfsec:ignore`, and `#nosec` comments across the codebase. This number should be stable or decreasing. A spike typically means a team responded to a scanner by suppressing rather than fixing.

```bash
# Count active suppressions (run as part of a weekly reporting job)
CHECKOV_SKIPS=$(grep -r "checkov:skip" ./terraform ./kubernetes ./charts | wc -l)
TFSEC_IGNORES=$(grep -r "tfsec:ignore" ./terraform | wc -l)
echo "checkov:skip count: $CHECKOV_SKIPS"
echo "tfsec:ignore count: $TFSEC_IGNORES"
```

Feed these numbers into your existing observability stack — a Grafana dashboard, a Datadog monitor, or simply a weekly Slack message generated by a scheduled CI job. The dashboard does not need to be complex. A line chart showing HIGH/CRITICAL open findings over 90 days is enough to make the security posture trend visible to engineering leadership.

## Expected Behaviour After Full Integration

- Every PR touching Terraform, CloudFormation, Kubernetes manifests, or Helm charts triggers Checkov and tfsec.
- HIGH and CRITICAL findings produce non-zero exit codes that block merge.
- SARIF output is uploaded to GitHub Security, and findings appear as inline annotations on the PR diff.
- Custom Python checks enforce organisation-specific policies (tagging, approved key ARNs, prohibited resource types).
- Inline suppression comments (`#checkov:skip=CKV_AWS_18: reason`) are visible in code review and require a justification string.
- The brownfield baseline file shrinks by at least five entries per sprint.
- A weekly report posts CRITICAL/HIGH open findings and suppression counts to the security engineering Slack channel.

## Trade-offs

| Control | Benefit | Risk | Mitigation |
|---|---|---|---|
| Block on HIGH/CRITICAL | Prevents high-severity misconfigs reaching production | Developers learn to suppress rather than fix if checks are noisy | Tune check selection before enforcement; review suppression comments in code review |
| SARIF inline annotations | Findings visible in PR diff context | Requires GitHub Advanced Security (free for public repos) | Fall back to plain-text CI step output for private repos without GHAS |
| Custom Python checks | Encodes org policy in code | Custom checks add maintenance burden | Keep them simple; use built-in checks where they exist |
| Baseline files for brownfield | Enables incremental adoption | Baseline grows and becomes permanent tech debt | Set a policy that baselines can only shrink; track size in metrics |
| Plan JSON scanning with conftest | Catches misconfigs only visible after variable resolution | Requires a live Terraform init and plan in CI (slower, needs credentials) | Run plan-scanning in a separate job with read-only credentials; gate on merge rather than PR open |

## Related Articles

- [Terraform Security: State File Protection, Provider Pinning, and Plan Review Automation](/articles/cicd/terraform-security/)
- [Terraform State Security: Remote Backends, Encryption, and Access Control](/articles/cicd/terraform-state-security/)
- [Kubernetes Manifest Validation in CI: Conftest, Kubeconform, and OPA](/articles/cicd/kubernetes-manifest-validation-ci/)
- [Helm Chart Security: Supply Chain Verification and Values Hardening](/articles/cicd/helm-chart-security/)
- [SAST Integration in CI/CD: Semgrep, CodeQL, and False Positive Management](/articles/cicd/sast-integration-cicd/)
- [Pre-commit Security Hooks: Secrets Detection, IaC Linting, and Dependency Auditing](/articles/cicd/pre-commit-security-hooks/)
