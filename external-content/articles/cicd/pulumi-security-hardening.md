---
title: "Pulumi Security Hardening: State, Secrets, CrossGuard, and OIDC Authentication"
description: "Pulumi state files hold every resource attribute your infrastructure owns. Locking down state backends, encrypting secrets with KMS, enforcing policy as code with CrossGuard, and replacing API tokens with OIDC are the controls that prevent a compromised CI pipeline from becoming a full infrastructure takeover."
slug: pulumi-security-hardening
date: 2026-05-07
lastmod: 2026-05-07
category: cicd
tags:
  - pulumi
  - iac-security
  - state-management
  - secrets-management
  - infrastructure-as-code
personas:
  - security-engineer
  - platform-engineer
article_number: 527
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/cicd/pulumi-security-hardening/
---

# Pulumi Security Hardening: State, Secrets, CrossGuard, and OIDC Authentication

## Problem

Pulumi state files are structured JSON documents that record every attribute of every managed resource: database connection strings, IAM access key IDs, TLS private keys, and every piece of configuration you passed through `pulumi config`. Anyone who can read the state file can reconstruct your entire infrastructure's sensitive data.

Unlike Terraform, Pulumi programs are written in general-purpose languages — TypeScript, Python, Go, C#. That means the full supply chain risk of npm, pip, and Go modules applies to every stack, not just a narrow HCL DSL. A compromised transitive dependency can exfiltrate secrets during a `pulumi up` run inside your CI environment.

Pulumi's default encryption model encrypts secrets stored in config using a passphrase-derived key, which is far weaker than a hardware-backed KMS key. Without explicit hardening, secrets at rest are protected only as well as the passphrase itself.

## Threat Model

- **Adversary:** Attacker who reads the state backend bucket (extracts all secrets and resource attributes), compromises a CI API token (triggers arbitrary stack updates), or injects a malicious npm/pip package into the program's dependency tree (runs code in the context of your cloud credentials during `pulumi up`).
- **Blast radius:** State backend compromise: complete knowledge of infrastructure configuration and all managed secrets. CI token compromise: ability to call `pulumi up --yes` with broad cloud permissions. Dependency compromise: arbitrary code execution with the IAM role assumed by the CI runner.

## Configuration

### State Backend: Self-Managed with Encryption

Pulumi Cloud stores state on Pulumi's servers. For environments that cannot accept that trust boundary, use an S3, GCS, or Azure Blob backend with envelope encryption and versioning enabled.

```bash
# Log in to an S3 state backend instead of Pulumi Cloud
pulumi login s3://your-org-pulumi-state/production

# GCS
pulumi login gs://your-org-pulumi-state

# Azure Blob
pulumi login azblob://your-org-pulumi-state
```

```json
// S3 bucket policy: deny all access except the CI role and break-glass admin
// Attach this to the state bucket, not the CI role
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAllExceptAuthorizedPrincipals",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::your-org-pulumi-state",
        "arn:aws:s3:::your-org-pulumi-state/*"
      ],
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalArn": [
            "arn:aws:iam::123456789012:role/pulumi-ci",
            "arn:aws:iam::123456789012:role/break-glass-admin"
          ]
        }
      }
    }
  ]
}
```

Enable versioning and object lock on the bucket so that a destructive write (whether accidental or from a compromised principal) does not permanently lose state history.

```bash
# Enable versioning and server-side encryption with a CMK
aws s3api put-bucket-versioning \
  --bucket your-org-pulumi-state \
  --versioning-configuration Status=Enabled

aws s3api put-bucket-encryption \
  --bucket your-org-pulumi-state \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "arn:aws:kms:eu-west-1:123456789012:key/abcd-1234"
      },
      "BucketKeyEnabled": true
    }]
  }'
```

### Secrets Encryption Providers

Every Pulumi stack has an encryption provider that protects secrets stored in `Pulumi.<stack>.yaml`. The default passphrase provider is inadequate for production. Use a KMS-backed provider instead.

```bash
# Create a new stack with AWS KMS encryption
pulumi stack init production \
  --secrets-provider="awskms://alias/pulumi-secrets?region=eu-west-1"

# Rotate to KMS from passphrase on an existing stack
pulumi stack change-secrets-provider \
  "awskms://alias/pulumi-secrets?region=eu-west-1"

# GCP KMS
pulumi stack init production \
  --secrets-provider="gcpkms://projects/my-project/locations/europe-west1/keyRings/pulumi/cryptoKeys/secrets"

# Azure Key Vault
pulumi stack init production \
  --secrets-provider="azurekeyvault://my-vault.vault.azure.net/keys/pulumi-secrets"
```

The KMS key ID is recorded in `Pulumi.<stack>.yaml`. The CI role must have `kms:Decrypt` permission on the key to run `pulumi up`. Scope that permission narrowly: only the CI role and the break-glass operator role should have it.

```bash
# Set a secret config value - encrypted with the stack's KMS key at rest
pulumi config set --secret database_password "$(vault kv get -field=password secret/prod/db)"

# Verify the value is stored encrypted in Pulumi.<stack>.yaml
# It should show: database_password: [secret]
pulumi config
```

### Pulumi ESC: Centralised Secrets and Configuration

Pulumi ESC (Environments, Secrets, Configuration) provides a centralised secrets store that is separate from stack state. Instead of embedding secrets in per-stack config files, ESC pulls them from Vault, AWS Secrets Manager, or 1Password at runtime and injects them as environment variables or Pulumi config values.

```yaml
# esc/production.yaml - ESC environment definition
imports:
  - aws-oidc-login  # Shared environment that establishes AWS credentials via OIDC

values:
  pulumiConfig:
    database:host: "${aws-secrets.database_host}"
    database:port: "5432"

  environmentVariables:
    DATABASE_PASSWORD:
      fn::secret:
        fn::fromBase64: "${aws-secrets.database_password_b64}"

  aws:
    secrets:
      database_host:
        fn::open::aws-secrets:
          region: eu-west-1
          get:
            name: prod/database/host
            property: value
```

```bash
# Open the ESC environment to inspect resolved values
pulumi env open myorg/production

# Run pulumi up with the ESC environment active
pulumi up --env myorg/production
```

ESC enforces access control at the environment level. Grant CI the minimum set of environments it needs per stack, not blanket access to all environments in the organisation.

### OIDC Authentication in CI: No API Tokens

Pulumi API tokens stored as CI secrets are a persistent credential that can be extracted from logs, memory, or CI configuration. Replace them with OIDC-federated short-lived tokens.

```yaml
# .github/workflows/pulumi.yml
name: Pulumi
on:
  push:
    branches: [main]
  pull_request:

permissions:
  id-token: write   # Required for OIDC
  contents: read

jobs:
  preview:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      # Exchange the GitHub OIDC token for a Pulumi Cloud token (no static secret)
      - uses: pulumi/auth-actions@v1
        with:
          organization: myorg
          requested-token-type: urn:pulumi:token-type:access_token:personal
          scope: user

      # Also exchange for AWS credentials via OIDC
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/pulumi-ci-readonly
          aws-region: eu-west-1

      - uses: pulumi/actions@v6
        with:
          command: preview
          stack-name: myorg/production
          comment-on-pr: true

  update:
    runs-on: ubuntu-latest
    needs: preview
    if: github.ref == 'refs/heads/main'
    environment: production   # Requires manual approval
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - uses: pulumi/auth-actions@v1
        with:
          organization: myorg
          requested-token-type: urn:pulumi:token-type:access_token:personal
          scope: user

      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/pulumi-ci-apply
          aws-region: eu-west-1

      - uses: pulumi/actions@v6
        with:
          command: up
          stack-name: myorg/production
```

For self-managed state backends (not Pulumi Cloud), skip the `pulumi/auth-actions` step and rely entirely on the cloud provider OIDC token (AWS, GCP, or Azure).

### Protecting Critical Resources from Accidental Destruction

Mark production resources as protected so that `pulumi up` cannot delete them without an explicit unprotect step.

```typescript
// index.ts - TypeScript stack
import * as aws from "@pulumi/aws";

const productionDatabase = new aws.rds.Instance("production-db", {
  instanceClass: "db.t3.medium",
  engine: "postgres",
  engineVersion: "15.4",
  allocatedStorage: 100,
  // ... other config
}, {
  protect: true,  // pulumi destroy and pulumi up cannot delete this resource
                  // Must run: pulumi state unprotect <urn> first
  retainOnDelete: false,
});
```

```python
# __main__.py - Python stack
import pulumi
import pulumi_aws as aws

production_bucket = aws.s3.Bucket(
    "production-data",
    opts=pulumi.ResourceOptions(
        protect=True,  # Deletion blocked at the Pulumi engine level
    ),
)
```

For Pulumi Cloud stacks, you can also require confirmation for destructive changes by enabling deployment policies in the stack settings, preventing `--yes` from bypassing the review step on updates that include deletes.

### CrossGuard: Policy as Code

Pulumi CrossGuard enforces compliance rules against every stack update before resources are created or modified. Policies run during `pulumi preview` and `pulumi up`, blocking changes that violate them.

```typescript
// policy/index.ts - CrossGuard policy pack (TypeScript)
import { PolicyPack, validateResourceOfType } from "@pulumi/policy";
import * as aws from "@pulumi/aws";

new PolicyPack("security-baseline", {
  policies: [
    {
      name: "s3-bucket-encryption-required",
      description: "S3 buckets must have server-side encryption enabled.",
      enforcementLevel: "mandatory",
      validateResource: validateResourceOfType(aws.s3.Bucket, (bucket, args, report) => {
        if (!bucket.serverSideEncryptionConfiguration) {
          report("S3 bucket must have server-side encryption configured.");
        }
      }),
    },
    {
      name: "no-public-s3-buckets",
      description: "S3 buckets must not have public ACLs.",
      enforcementLevel: "mandatory",
      validateResource: validateResourceOfType(aws.s3.Bucket, (bucket, args, report) => {
        if (bucket.acl === "public-read" || bucket.acl === "public-read-write") {
          report(`S3 bucket '${args.name}' has a public ACL: ${bucket.acl}`);
        }
      }),
    },
    {
      name: "iam-no-wildcard-actions",
      description: "IAM policies must not grant wildcard (*) actions.",
      enforcementLevel: "mandatory",
      validateResource: validateResourceOfType(aws.iam.Policy, (policy, args, report) => {
        const doc = JSON.parse(policy.policy as string);
        for (const statement of doc.Statement || []) {
          const actions = Array.isArray(statement.Action)
            ? statement.Action
            : [statement.Action];
          if (actions.includes("*")) {
            report(`IAM policy '${args.name}' grants wildcard (*) actions.`);
          }
        }
      }),
    },
    {
      name: "rds-deletion-protection-required",
      description: "RDS instances must have deletion protection enabled.",
      enforcementLevel: "mandatory",
      validateResource: validateResourceOfType(aws.rds.Instance, (db, args, report) => {
        if (!db.deletionProtection) {
          report(`RDS instance '${args.name}' must have deletionProtection set to true.`);
        }
      }),
    },
  ],
});
```

```python
# policy/__main__.py - CrossGuard policy pack (Python)
from pulumi_policy import (
    EnforcementLevel,
    PolicyPack,
    ReportViolation,
    ResourceValidationArgs,
    ResourceValidationPolicy,
)

def s3_no_public_acl(args: ResourceValidationArgs, report: ReportViolation):
    if args.resource_type == "aws:s3/bucket:Bucket":
        acl = args.props.get("acl", "")
        if acl in ("public-read", "public-read-write", "authenticated-read"):
            report(f"S3 bucket '{args.name}' must not use a public ACL.")

def sg_no_ingress_all(args: ResourceValidationArgs, report: ReportViolation):
    if args.resource_type == "aws:ec2/securityGroup:SecurityGroup":
        for rule in args.props.get("ingress", []):
            if rule.get("cidrBlocks") and "0.0.0.0/0" in rule["cidrBlocks"]:
                if rule.get("fromPort") == 0 and rule.get("toPort") == 0:
                    report(
                        f"Security group '{args.name}' allows all ingress from 0.0.0.0/0."
                    )

PolicyPack(
    "security-baseline",
    policies=[
        ResourceValidationPolicy(
            name="s3-no-public-acl",
            description="S3 buckets must not use public ACLs.",
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=s3_no_public_acl,
        ),
        ResourceValidationPolicy(
            name="sg-no-ingress-all",
            description="Security groups must not allow all ingress from the internet.",
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=sg_no_ingress_all,
        ),
    ],
)
```

```bash
# Run a preview with a local policy pack applied
pulumi preview --policy-pack ./policy

# In Pulumi Cloud, publish the policy pack and enforce it at the organisation level
# so it applies to all stacks regardless of how they are run
pulumi policy publish myorg
```

### Drift Detection with `pulumi refresh`

`pulumi up` reconciles actual state to desired state. But it only runs when triggered. Between runs, someone with direct cloud API access can change a resource. `pulumi refresh` compares the actual cloud state with the Pulumi state file and reports differences without making changes.

```yaml
# .github/workflows/drift-detection.yml
name: Pulumi Drift Detection
on:
  schedule:
    - cron: '0 6 * * *'  # Daily at 06:00 UTC

permissions:
  id-token: write
  contents: read

jobs:
  detect-drift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - uses: pulumi/auth-actions@v1
        with:
          organization: myorg
          requested-token-type: urn:pulumi:token-type:access_token:personal
          scope: user

      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/pulumi-ci-readonly
          aws-region: eu-west-1

      - name: Detect drift
        id: refresh
        uses: pulumi/actions@v6
        with:
          command: refresh
          stack-name: myorg/production
          expect-no-changes: true   # Exit non-zero if refresh shows differences
        continue-on-error: true

      - name: Alert on drift
        if: steps.refresh.outcome == 'failure'
        run: |
          curl -X POST "$SLACK_WEBHOOK" \
            -H 'Content-Type: application/json' \
            -d '{"text":"Pulumi drift detected in production. Run `pulumi refresh` to inspect and reconcile."}'
        env:
          SLACK_WEBHOOK: ${{ secrets.SLACK_WEBHOOK }}
```

### Dependency Supply Chain Controls

Pulumi programs are regular application code. The same supply chain risks that apply to any TypeScript, Python, or Go project apply here — and the stakes are higher because the program runs with cloud provider credentials.

```bash
# TypeScript/Node: pin exact versions in package.json and commit the lockfile
npm install --save-exact @pulumi/pulumi @pulumi/aws

# Audit for known vulnerabilities before running
npm audit --audit-level=moderate

# Python: pin exact versions in requirements.txt
pip install pulumi==3.116.0 pulumi-aws==6.37.1
pip freeze > requirements.txt

# Go: go.sum is a cryptographic lockfile - always commit it
go mod tidy
git add go.sum
```

Run `npm audit`, `pip-audit`, or `govulncheck` as a CI step before `pulumi preview`. A dependency with a known RCE vulnerability executing in the context of a Pulumi program is an infrastructure compromise, not just a code vulnerability.

For TypeScript and Python stacks, consider a private package registry (Artifactory, GitHub Packages, Google Artifact Registry) and block direct access to the public registry from CI runners. This limits the attack surface to packages you have explicitly approved.

### Audit Logging

Pulumi Cloud records every `pulumi up`, `pulumi destroy`, and `pulumi config set` operation in an audit log tied to the authenticated identity. For self-managed backends, audit logging requires additional instrumentation.

```bash
# Download audit log from Pulumi Cloud API (requires admin token)
curl -H "Authorization: token $PULUMI_ACCESS_TOKEN" \
  "https://api.pulumi.com/api/orgs/myorg/auditlogs?startTime=$(date -d '7 days ago' +%s)" \
  | jq '.auditLogEvents[] | {time: .timestamp, user: .user.name, event: .event}'
```

For self-managed S3 backends, enable S3 access logging on the state bucket. Every `GetObject`, `PutObject`, and `DeleteObject` is written to a separate logging bucket with the requester's IAM ARN, IP address, and timestamp.

```bash
# Enable S3 access logging on the state bucket
aws s3api put-bucket-logging \
  --bucket your-org-pulumi-state \
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "your-org-access-logs",
      "TargetPrefix": "pulumi-state/"
    }
  }'
```

Ship these logs to your SIEM. Alert on any access from a principal that is not the CI role or the break-glass operator, and on any `DeleteObject` call against the state bucket.

## Expected Behaviour

- State stored in S3/GCS/Azure Blob with KMS envelope encryption; access restricted by bucket policy to CI role and break-glass admin
- Stack secrets encrypted with a KMS-backed provider, not a passphrase
- CI authenticates via OIDC — no long-lived Pulumi API tokens or cloud access keys in CI secrets
- CrossGuard policies block non-compliant resource creation before `pulumi up` modifies real infrastructure
- Critical resources marked `protect: true`; deletions require explicit unprotect with audit trail
- Daily `pulumi refresh` run detects manual infrastructure changes
- Dependency audits (`npm audit`, `pip-audit`, `govulncheck`) run before every `pulumi preview`

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Self-managed state backend | No trust dependency on Pulumi Cloud | Operational overhead for bucket management, encryption, and access control | Use IaC (Terraform or Pulumi itself) to manage the state bucket configuration. |
| KMS secrets provider | Secrets at rest protected by HSM-backed key | `pulumi up` requires `kms:Decrypt` permission; key rotation must be explicit | Use AWS-managed CMK with automatic annual rotation. |
| CrossGuard mandatory policies | Prevents non-compliant resources | Overly broad policies block legitimate changes | Start with advisory enforcement; graduate to mandatory after confirming no false positives. |
| OIDC for CI credentials | No persistent secrets to rotate or leak | OIDC trust policy must be scoped precisely | Restrict trust to specific repository, branch, and environment. |
| `protect: true` on resources | Accidental deletes blocked at engine level | Requires deliberate unprotect step during legitimate decommissioning | Document the unprotect procedure in runbooks. Include it in change approval process. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| State file corrupted or deleted | `pulumi preview` shows all resources as new (state is empty) | Unexpected plan proposes creating all resources from scratch | Restore previous state version from S3 versioning. Never edit state files manually. |
| KMS key access revoked | `pulumi up` fails with `AccessDenied` decrypting secrets | CI run fails at secret decryption step | Restore `kms:Decrypt` permission on the CI role. Check key policy for unintended denials. |
| OIDC trust policy too broad | Unintended repositories can assume the Pulumi CI role | Security audit reveals overly permissive trust conditions | Restrict trust to `repo:your-org/your-repo:environment:production`. |
| CrossGuard policy rejects valid change | `pulumi up` blocked by a false-positive policy violation | CI fails with a policy violation message | Set the specific policy to advisory temporarily. Fix the resource definition to comply. |
| Protected resource needs deletion | `pulumi up` errors: resource is protected | Plan output shows resource cannot be deleted | Run `pulumi state unprotect <urn>`. Record the action in your change management system. |
| Dependency compromise via npm/pip | Malicious code runs during `pulumi up` with cloud credentials | Unexpected cloud API calls in CloudTrail/audit logs | Rotate all credentials used by the affected stack. Audit all cloud changes in the time window. |

## Related Articles

- [Terraform State Security: Backend Encryption, Access Control, and State File Hygiene](/articles/cicd/terraform-state-security/)
- [Terraform Security: State File Protection, Provider Pinning, and Plan Review Automation](/articles/cicd/terraform-security/)
- [OIDC Federation Hardening: Scoping Trust Policies for CI/CD](/articles/cicd/oidc-federation-hardening/)
- [Secret Management in CI/CD Pipelines: Vault, SOPS, and OIDC Federation](/articles/cicd/cicd-secret-management/)
- [Dependency Pinning and Lockfile Integrity: Preventing Supply Chain Attacks in CI](/articles/cicd/dependency-pinning/)
- [Argo CD Security Hardening: RBAC, SSO, and Preventing Drift](/articles/cicd/argocd-security-hardening/)
