---
title: "Terraform State Security: Remote Backends, Encryption, and Drift Detection"
description: "Terraform state files contain plaintext secrets, resource IDs, and full infrastructure topology. Securing the backend, encrypting state at rest, locking against concurrent writes, and detecting config drift are all required."
slug: "terraform-state-security"
date: 2026-04-30
lastmod: 2026-04-30
category: "cicd"
tags: ["terraform", "state", "backend", "encryption", "drift-detection"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 274
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/cicd/terraform-state-security/index.html"
---

# Terraform State Security: Remote Backends, Encryption, and Drift Detection

## Problem

Terraform state files are a comprehensive map of your infrastructure. Beyond resource IDs and ARNs, they frequently contain sensitive values: database passwords passed as inputs, TLS private keys managed by Terraform, SSH keys for provisioners, API tokens for provider authentication. These are stored in plaintext in the state file unless specific measures are taken.

A default `terraform init` creates `terraform.tfstate` locally — a JSON file readable by anyone with filesystem access. Teams that progress past this store state in S3, but often without the additional controls that make S3 state genuinely secure:

- **No state-level encryption.** S3 SSE encrypts at rest, but the encryption key is AWS-managed, not customer-managed. Anyone with the S3 IAM role reads plaintext state.
- **No state locking.** Two `terraform apply` operations running simultaneously can corrupt state by concurrent writes. Without DynamoDB locking, this is a silent corruption risk.
- **Overpermissive S3 IAM.** The service account used in CI has `s3:*` on the state bucket — it can delete state, read secrets from it, or exfiltrate the entire infrastructure topology.
- **State never audited.** Nobody knows who ran `terraform state pull` or `terraform state push`. There is no audit trail of state access.
- **Drift is undetected.** Infrastructure changes made outside Terraform (console clicks, AWS CLI, hot patches) create drift between state and reality. Drift is only discovered when `terraform plan` runs, and if it's never run, drift accumulates indefinitely.
- **State is shared across environments.** A single state file covers dev, staging, and production. A mistake in Terraform that corrupts state affects all three.

**Target systems:** Terraform 1.6+ (native state encryption preview), 1.9+ (stable state encryption); OpenTofu 1.7+ (state encryption GA); AWS S3+DynamoDB backend; GCS backend; Terraform Cloud/Enterprise; Atlantis 0.27+ for GitOps apply.

## Threat Model

- **Adversary 1 — State file exfiltration:** An attacker who obtains the CI service account credentials (from a leaked secret, a compromised CI runner, or a misconfigured IAM role) reads the Terraform state file, extracting all plaintext secrets, database passwords, and API keys stored in it.
- **Adversary 2 — State corruption via concurrent apply:** Two engineers run `terraform apply` simultaneously against the same state. Without locking, both read the same state, one commits changes, the other overwrites with a stale result. Resources managed by the second apply are now in an inconsistent state with reality.
- **Adversary 3 — State deletion for infrastructure erasure:** An attacker (or a misconfigured automation) deletes the state file. Without the state, Terraform has no record of existing resources. Running `terraform apply` after state deletion could recreate resources (creating duplicates) or fail. Running `terraform destroy` without state would fail silently, leaving infrastructure dangling.
- **Adversary 4 — Undetected drift enabling re-compromise:** A compromised host is remediated manually (malware removed, config restored). The Terraform state still reflects the pre-compromise configuration; `terraform apply` would re-apply the original configuration, including any misconfiguration that enabled the compromise.
- **Adversary 5 — State poisoning:** An attacker who can write to the state file replaces resource IDs with references to attacker-controlled infrastructure. The next `terraform apply` considers the attacker's resources as managed by Terraform and may apply additional configuration to them.
- **Access level:** Adversaries 1 and 5 need IAM credentials for the state bucket or Terraform Cloud API token. Adversary 2 is a developer mistake. Adversary 3 needs `s3:DeleteObject` on the state bucket. Adversary 4 exploits a process gap.
- **Objective:** Extract credentials, corrupt infrastructure, enable persistence through configuration management.
- **Blast radius:** A leaked Terraform state is equivalent to leaking all the secrets it contains. For a production environment, this typically includes database passwords, TLS keys, and API credentials — a full credential compromise.

## Configuration

### Step 1: S3 Backend with DynamoDB Locking

```hcl
# backend.tf
terraform {
  backend "s3" {
    bucket         = "company-terraform-state-prod"
    key            = "services/payments/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true                          # SSE-S3 (minimum).
    kms_key_id     = "arn:aws:kms:us-east-1:ACCOUNT:key/STATE-KMS-KEY"  # SSE-KMS.
    dynamodb_table = "terraform-state-locks"       # State locking.

    # Versioning allows state recovery after accidental modification.
    # Enable on the bucket itself; terraform uses this implicitly.
  }
}
```

Create the backend infrastructure:

```bash
# S3 bucket with versioning and Object Lock.
aws s3api create-bucket \
  --bucket company-terraform-state-prod \
  --region us-east-1 \
  --object-lock-enabled-for-bucket   # Prevents state deletion.

aws s3api put-bucket-versioning \
  --bucket company-terraform-state-prod \
  --versioning-configuration Status=Enabled

aws s3api put-bucket-encryption \
  --bucket company-terraform-state-prod \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "arn:aws:kms:us-east-1:ACCOUNT:key/STATE-KMS-KEY"
      }
    }]
  }'

# DynamoDB table for state locking.
aws dynamodb create-table \
  --table-name terraform-state-locks \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST
```

### Step 2: Terraform Native State Encryption (1.9+)

Terraform 1.9+ and OpenTofu 1.7+ support native client-side state encryption — the state is encrypted before being written to the backend:

```hcl
# encryption.tf (Terraform 1.9+ / OpenTofu 1.7+)
terraform {
  encryption {
    key_provider "aws_kms" "main" {
      kms_key_id = "arn:aws:kms:us-east-1:ACCOUNT:key/STATE-KMS-KEY"
      region     = "us-east-1"
    }

    method "aes_gcm" "default" {
      keys = key_provider.aws_kms.main
    }

    state {
      method = method.aes_gcm.default
      # Enforce: fail if state cannot be encrypted.
      enforced = true
    }

    plan {
      method = method.aes_gcm.default
      enforced = true
    }
  }
}
```

With client-side encryption, the state is encrypted in memory before being written to S3. An attacker who reads the S3 object gets ciphertext; they need KMS decrypt permission to recover the plaintext.

### Step 3: IAM Policy — Minimum Permissions

CI pipelines need specific, not broad, state access:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "StateReadWrite",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::company-terraform-state-prod",
        "arn:aws:s3:::company-terraform-state-prod/services/payments/*"
      ]
    },
    {
      "Sid": "StateLocking",
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:DeleteItem"
      ],
      "Resource": "arn:aws:dynamodb:us-east-1:ACCOUNT:table/terraform-state-locks"
    },
    {
      "Sid": "KMSDecryptForState",
      "Effect": "Allow",
      "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
      "Resource": "arn:aws:kms:us-east-1:ACCOUNT:key/STATE-KMS-KEY"
    }
  ]
}
```

Notably absent: `s3:DeleteObject`. Without it, CI cannot delete state files. Object Lock provides a hard floor; this provides an IAM floor.

**Separate read-only state access for audit/plan:**

```json
{
  "Action": ["s3:GetObject", "s3:ListBucket", "kms:Decrypt"],
  "Resource": ["arn:aws:s3:::company-terraform-state-prod/*", "..."]
}
```

Give this to developers who need to run `terraform plan` without apply permission.

### Step 4: Separate State Per Environment

Never share a state file across environments:

```
# Directory structure enforcing state isolation.
terraform/
  environments/
    dev/
      backend.tf          # state key: environments/dev/terraform.tfstate
      main.tf
    staging/
      backend.tf          # state key: environments/staging/terraform.tfstate
      main.tf
    production/
      backend.tf          # state key: environments/production/terraform.tfstate
      main.tf
  modules/
    ...
```

```hcl
# environments/production/backend.tf
terraform {
  backend "s3" {
    key = "environments/production/terraform.tfstate"
    # Separate KMS key per environment.
    kms_key_id = "arn:aws:kms:us-east-1:ACCOUNT:key/PROD-STATE-KEY"
  }
}
```

IAM policies further enforce environment isolation: the production CI role can only access the production state key, not staging or dev.

### Step 5: Atlantis for GitOps Apply with Audit Trail

Atlantis proxies all Terraform plans and applies through Git pull requests, providing a complete audit trail:

```yaml
# atlantis.yaml
version: 3
projects:
  - name: payments-prod
    dir: terraform/environments/production
    workspace: default
    terraform_version: v1.9.5
    autoplan:
      when_modified: ["*.tf", "../modules/**/*.tf"]
      enabled: true
    apply_requirements:
      - approved                  # Requires PR approval before apply.
      - mergeable                 # PR must be mergeable (no conflicts).
      - undiverged                # Branch must be up to date with base.
```

With Atlantis, `terraform apply` only runs from the Atlantis server (via PR comment), not from developer laptops. The Atlantis server holds the state access credentials; developers never have direct S3 access to production state.

### Step 6: Drift Detection

Run `terraform plan` regularly to detect drift between state and reality:

```yaml
# .github/workflows/drift-detection.yml
name: Terraform Drift Detection

on:
  schedule:
    - cron: "0 8 * * *"   # Daily at 8am.

jobs:
  detect-drift:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        environment: [production, staging]
    steps:
      - uses: actions/checkout@v4

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.9.5

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::ACCOUNT:role/terraform-drift-read
          aws-region: us-east-1

      - name: Terraform Init
        run: terraform init
        working-directory: terraform/environments/${{ matrix.environment }}

      - name: Terraform Plan (drift detection)
        id: plan
        run: |
          terraform plan \
            -detailed-exitcode \
            -refresh=true \
            -out=/tmp/drift.plan \
            2>&1 | tee /tmp/plan-output.txt

          EXITCODE=${PIPESTATUS[0]}
          # Exit code 0 = no changes (no drift)
          # Exit code 1 = error
          # Exit code 2 = changes detected (drift!)
          echo "exit_code=$EXITCODE" >> $GITHUB_OUTPUT
        working-directory: terraform/environments/${{ matrix.environment }}
        continue-on-error: true

      - name: Alert on Drift
        if: steps.plan.outputs.exit_code == '2'
        run: |
          echo "DRIFT DETECTED in ${{ matrix.environment }}!"
          cat /tmp/plan-output.txt | grep -E "^\s+[+~-]" | head -50
          # Create a GitHub issue or send a Slack alert.
          gh issue create \
            --title "Infrastructure drift detected: ${{ matrix.environment }} ($(date +%Y-%m-%d))" \
            --body "$(cat /tmp/plan-output.txt | head -100)" \
            --label "terraform,drift"
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Step 7: Sensitive Value Management

Avoid storing sensitive values in Terraform state by using data sources:

```hcl
# BAD: password hardcoded in resource; stored in state.
resource "aws_db_instance" "main" {
  password = var.db_password   # Stored in state in plaintext.
}

# GOOD: reference an existing secret; only the ARN is in state.
data "aws_secretsmanager_secret_version" "db_password" {
  secret_id = "prod/db/password"
}

resource "aws_db_instance" "main" {
  password = data.aws_secretsmanager_secret_version.db_password.secret_string
  # The password is not stored in state; only the secret ARN reference is.
}
```

For values that must be in state, mark them as sensitive:

```hcl
variable "api_key" {
  type      = string
  sensitive = true   # Redacted from plan output; still stored in state.
}

output "api_endpoint" {
  value     = aws_api_gateway_deployment.main.invoke_url
  sensitive = false   # URL is safe to display.
}
```

### Step 8: Telemetry

```
terraform_state_access_total{environment, operation, principal}    counter
terraform_state_lock_acquired_total{environment}                   counter
terraform_state_lock_timeout_total{environment}                    counter
terraform_drift_detected_total{environment, resource_type}         counter
terraform_apply_success_total{environment}                         counter
terraform_apply_failure_total{environment}                         counter
s3_state_unexpected_access_total{principal}                        counter
```

Alert on:

- `s3_state_unexpected_access_total` — a non-Atlantis IAM role accessed the state bucket.
- `terraform_drift_detected_total` non-zero — infrastructure has changed outside Terraform; review immediately.
- `terraform_state_lock_timeout_total` — a lock acquisition timed out; a previous apply may not have released its lock (possible crash mid-apply).
- CloudTrail: `DeleteObject` on the state bucket — never expected given IAM policy; immediate investigation.

## Expected Behaviour

| Signal | Local state / unprotected S3 | Hardened state backend |
|--------|------------------------------|----------------------|
| Plaintext secrets in state | Readable by anyone with S3 access | Encrypted; requires KMS decrypt permission |
| Concurrent apply | Silent state corruption | DynamoDB lock serialises applies |
| State deletion | Permanent data loss | Object Lock blocks deletion; IAM blocks `DeleteObject` |
| Drift detection | Only discovered on next plan | Daily automated drift check; alert on deviation |
| Apply audit trail | None | Atlantis logs every plan and apply with PR context |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Native state encryption | State ciphertext in S3; KMS needed to read | Adds KMS call latency per state operation | Acceptable overhead (~50ms); use KMS key caching. |
| DynamoDB locking | Prevents state corruption | DynamoDB table is another resource to manage | Terraform can create the table; minimal operational overhead. |
| Atlantis for apply | Centralised audit; no direct state access for developers | One more service to operate; PR-based workflow | Worth the overhead for production; Atlantis is well-maintained. |
| Per-environment state | Blast radius isolation | More state files to manage | Directory structure enforces it; small overhead for large protection gain. |
| Drift detection daily | Catches out-of-band changes | Plan run costs; may timeout on large infrastructure | Run plan in refresh-only mode; faster than full plan. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Lock not released after crash | `terraform apply` hangs waiting for lock | `terraform_state_lock_timeout_total` alert | `terraform force-unlock <lock-id>`; investigate the crashed apply. |
| State corruption from concurrent apply | Resources in Terraform state don't match reality | `terraform plan` shows unexpected changes | Restore from versioned S3 backup; reconcile differences manually. |
| KMS key deleted | State unreadable; all Terraform operations fail | Terraform operations fail with `AccessDeniedException` | KMS keys have 7-day deletion window; cancel deletion if within window. |
| Drift detection false positive | Alert fires for legitimate pending changes | High alert rate | Exclude expected pending changes using `-target` in the drift check. |
| Atlantis server down | No applies can proceed | Atlantis health check fails | Atlantis is stateless; restart from the same ECS task definition or Pod spec. |
| Sensitive value leaked in plan output | Secret appears in CI logs | Log scanning detects pattern | Use `sensitive = true` on variables and outputs; Terraform redacts them from output. |

## Related Articles

- [Terraform Security](/articles/cicd/terraform-security/)
- [GitOps Security](/articles/cicd/gitops-security/)
- [Secrets Rotation Orchestration](/articles/cross-cutting/secrets-rotation-orchestration/)
- [Cloud Security Posture Management](/articles/cross-cutting/cloud-security-posture-management/)
- [OIDC Federation Hardening for CI-to-Cloud](/articles/cicd/oidc-federation-hardening/)
