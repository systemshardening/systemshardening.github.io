---
title: "Terraform Security: State File Protection, Provider Pinning, and Plan Review Automation"
description: "Terraform state files contain every secret, IP address, and configuration detail of your infrastructure in plaintext JSON."
slug: "terraform-security"
date: 2026-04-02
lastmod: 2026-04-02
category: "cicd"
tags: ["terraform", "iac", "state-file", "security", "opentofu", "supply-chain"]
personas: ["devops-engineer", "platform-engineer"]
article_number: 57
difficulty: "intermediate"
estimated_reading_time: 16
provider_bridges:
  - name: "Snyk"
    id: 48
    category: "container-security"
premium_pack: "terraform-security-modules"
published: true
layout: article.njk
permalink: "/articles/cicd/terraform-security/index.html"
---

# [Terraform](https://www.terraform.io) Security: State File Protection, Provider Pinning, and Plan Review Automation

## Problem

Terraform state files contain every secret, IP address, and configuration detail of your infrastructure in plaintext JSON. Anyone with state file access can read database passwords, API keys, and TLS private keys. Provider plugins are downloaded from the internet with minimal integrity verification by default. `terraform apply` in CI runs with permissions broad enough to create, modify, and destroy any resource.

## Threat Model

- **Adversary:** Attacker who compromises the state file backend (reads all secrets), hijacks a provider download (injects malicious code into the provider binary), or modifies a Terraform module (infrastructure as code injection).
- **Blast radius:** State file compromise: all secrets for all managed resources. Provider compromise: arbitrary code execution during plan/apply. Module compromise: infrastructure provisioned with attacker-controlled configuration.

## Configuration

### State File Encryption and Access Control

```hcl
# backend.tf - S3 backend with encryption and locking
terraform {
  backend "s3" {
    bucket         = "your-org-terraform-state"
    key            = "production/terraform.tfstate"
    region         = "eu-west-1"
    encrypt        = true
    kms_key_id     = "arn:aws:kms:eu-west-1:123456789012:key/abcd-1234-efgh"
    dynamodb_table = "terraform-locks"

    # Access control: only the CI role and break-glass admin can read state
    # Configured via S3 bucket policy and IAM
  }
}
```

```json
// S3 bucket policy: restrict state file access
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::your-org-terraform-state",
        "arn:aws:s3:::your-org-terraform-state/*"
      ],
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalArn": [
            "arn:aws:iam::123456789012:role/terraform-ci",
            "arn:aws:iam::123456789012:role/break-glass-admin"
          ]
        }
      }
    }
  ]
}
```

### Provider and Module Pinning

```hcl
# versions.tf - pin providers by version AND hash
terraform {
  required_version = ">= 1.8.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.46.0"  # Exact version, not range
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.30.0"
    }
  }
}
```

```bash
# Generate .terraform.lock.hcl with platform-specific hashes
terraform providers lock \
  -platform=linux_amd64 \
  -platform=darwin_amd64 \
  -platform=darwin_arm64

# The lock file contains SHA-256 hashes for each provider binary.
# Commit this file to Git.
# terraform init verifies hashes - fails if the binary doesn't match.

# Example .terraform.lock.hcl entry:
# provider "registry.terraform.io/hashicorp/aws" {
#   version     = "5.46.0"
#   constraints = "5.46.0"
#   hashes = [
#     "h1:abc123...",
#     "zh:def456...",
#   ]
# }
```

### Plan Review in CI

```yaml
# .github/workflows/terraform.yml
name: Terraform
on:
  pull_request:
    paths: ['terraform/**']

permissions:
  id-token: write
  contents: read
  pull-requests: write

jobs:
  plan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: "1.8.0"

      - name: Configure AWS credentials (OIDC, no static keys)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/terraform-ci-readonly
          aws-region: eu-west-1

      - name: Terraform Init
        run: terraform init -input=false
        working-directory: terraform/

      - name: Terraform Plan
        id: plan
        run: terraform plan -input=false -no-color -out=tfplan
        working-directory: terraform/
        continue-on-error: true

      - name: Post plan to PR
        uses: actions/github-script@v7
        with:
          script: |
            const output = `#### Terraform Plan
            \`\`\`
            ${{ steps.plan.outputs.stdout }}
            \`\`\`
            *Review the plan before approving the apply.*`;
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: output
            })

      - name: Security scan with tfsec
        uses: aquasecurity/tfsec-action@v1.0.3
        with:
          working_directory: terraform/
          soft_fail: false  # Fail the PR if security issues found

  apply:
    needs: plan
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    environment: production  # Requires manual approval
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Configure AWS credentials (OIDC, write access)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/terraform-ci-apply
          aws-region: eu-west-1

      - name: Terraform Apply
        run: terraform apply -input=false -auto-approve
        working-directory: terraform/
```

### Sensitive Output Handling

```hcl
# Mark outputs as sensitive to prevent them from appearing in plan output
output "database_password" {
  value     = random_password.db.result
  sensitive = true
}

output "api_key" {
  value     = aws_iam_access_key.deploy.secret
  sensitive = true
}

# Even with sensitive=true, the value IS in the state file.
# State file encryption (S3+KMS) protects at rest.
# State file access control protects in transit.
```

### Drift Detection

```yaml
# Scheduled drift detection
# .github/workflows/drift-detection.yml
name: Terraform Drift Detection
on:
  schedule:
    - cron: '0 6 * * *'  # Daily at 06:00 UTC

jobs:
  detect-drift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: Terraform Plan (detect-only)
        run: |
          terraform init -input=false
          terraform plan -input=false -detailed-exitcode
          # Exit code 2 = changes detected (drift)
        working-directory: terraform/
        continue-on-error: true
        id: drift

      - name: Alert on drift
        if: steps.drift.outcome == 'failure'
        run: |
          curl -X POST "$SLACK_WEBHOOK" \
            -H 'Content-Type: application/json' \
            -d '{"text": "Terraform drift detected in production. Review and reconcile."}'
```

## Expected Behaviour

- State file encrypted at rest with KMS; access restricted to CI role and break-glass admin
- All providers pinned by exact version with `.terraform.lock.hcl` hash verification
- `terraform plan` posted to every PR for review; `tfsec` blocks PRs with security issues
- `terraform apply` requires manual approval via GitHub environment protection
- CI uses OIDC (no static credentials); read-only for plan, write for apply
- Daily drift detection alerts on infrastructure changes outside Terraform

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Exact version pinning | Prevents accidental upgrades | Must manually update versions for security patches | Dependabot/Renovate PRs for Terraform provider updates. |
| State file encryption (KMS) | Secrets encrypted at rest | KMS key management; key rotation | Use AWS-managed KMS key with automatic rotation. |
| Plan-in-PR | Every change is reviewed before apply | Slows deployment for urgent changes | Break-glass: apply directly with audit trail. |
| OIDC for CI credentials | No static credentials | OIDC trust policy must be precise | Restrict by repo, branch, and environment. |
| Drift detection | Catches manual changes | Alert fatigue if infrastructure is frequently modified outside Terraform | Import manual changes into Terraform. Reduce manual access to AWS console. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| State file corrupted | `terraform plan` shows unexpected destroy/recreate | Plan shows resources being replaced that shouldn't be | Restore state from S3 versioning. Never modify state files manually (use `terraform state` commands). |
| Provider hash mismatch | `terraform init` fails with hash verification error | CI fails at init step; lockfile hash doesn't match downloaded provider | Verify the provider release is legitimate. Re-run `terraform providers lock`. |
| OIDC trust too broad | Unintended repositories can assume the Terraform role | Security audit reveals overly permissive trust policy | Restrict trust policy to specific repository AND branch AND environment. |
| Drift accumulates | Infrastructure diverges from Terraform state | Drift detection alert fires daily | Import manual changes. Restrict console/API access to prevent out-of-band modifications. |

## When to Consider a Managed Alternative

State management, plan review, and drift detection require significant CI/CD infrastructure.

- **Terraform Cloud:** Managed state, plan review UI, drift detection, RBAC, and policy enforcement (Sentinel).
- **[Snyk](https://snyk.io) IaC:** Scans Terraform for security misconfigurations in CI. Complements tfsec.

**Premium content pack:** Security-focused Terraform module collection. modules for VPC, security groups, IAM, and [Kubernetes](https://kubernetes.io) cluster provisioning with hardened defaults, state backend configuration, and CI/CD workflow templates.


## Related Articles

- [SLSA Provenance for Container Images: From Build to Admission Control](/articles/cicd/slsa-provenance/)
- [Dependency Pinning and Lockfile Integrity: Preventing Supply Chain Attacks in CI](/articles/cicd/dependency-pinning/)
- [Secret Management in CI/CD Pipelines: Vault, SOPS, and OIDC Federation](/articles/cicd/cicd-secret-management/)
- [Reproducible Builds for Container Images: Achieving Deterministic Output](/articles/cicd/reproducible-builds/)
- [Securing GitHub Actions: Permissions, Pinning, and Workflow Injection Prevention](/articles/cicd/securing-github-actions/)
