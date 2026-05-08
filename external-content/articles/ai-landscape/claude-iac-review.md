---
title: "Claude for Infrastructure-as-Code Security Review: Terraform, CloudFormation, and Pulumi"
description: "Infrastructure-as-Code scanners like Checkov, tflint, and cfn-lint enforce policy through pattern matching."
slug: "claude-iac-review"
date: 2026-03-10
lastmod: 2026-03-10
category: "ai-landscape"
tags: ["claude", "llm", "iac", "terraform", "cloudformation", "pulumi", "security-review", "infrastructure"]
personas: ["security-engineer", "devops-engineer", "platform-engineer", "cloud-architect"]
article_number: 137
difficulty: "intermediate"
estimated_reading_time: 20
provider_bridges:
  - name: "Snyk"
    id: 48
    category: "vulnerability-scanning"
  - name: "Checkov"
    id: 71
    category: "iac-scanning"
published: true
layout: article.njk
permalink: "/articles/ai-landscape/claude-iac-review/index.html"
---

# [Claude](https://claude.ai) for Infrastructure-as-Code Security Review: [Terraform](https://www.terraform.io), CloudFormation, and Pulumi

## Problem

Infrastructure-as-Code scanners like Checkov, tflint, and cfn-lint enforce policy through pattern matching. They check whether an S3 bucket has versioning enabled, whether a security group allows ingress on port 22, and whether an IAM policy uses wildcards. These checks are valuable, but they operate on individual resources in isolation.

Real IaC security problems rarely live in a single resource block. They emerge from the interaction between resources: an IAM role that looks reasonable until you trace its trust policy to an external account, a security group that looks locked down until you notice a second rule added by a dynamic block using a variable with an overly broad default, or a Terraform module pulled from a public registry that overrides the security settings you thought you were configuring.

Checkov will not flag a `data "aws_iam_policy_document"` that grants `s3:*` to a role when the resource ARN is constructed from a variable and the variable's default is `"*"`. tflint will not warn you that a module's internal `count` conditional creates an entirely different resource topology when a feature flag is enabled. cfn-lint will not notice that a CloudFormation nested stack overrides the `DeletionPolicy` your parent stack sets.

Claude reads IaC the way an experienced cloud security engineer does. It traces variable references across files, evaluates conditional logic to understand which resource configurations actually deploy, and reasons about the effective permissions that result from IAM policy composition. This article covers specific patterns for using Claude to review Terraform, CloudFormation, and Pulumi code, with real examples of issues that traditional scanners miss.

**Target systems:** AWS, GCP, and Azure infrastructure managed through Terraform (0.13+), CloudFormation, or Pulumi. CI/CD pipelines running plan or preview stages.

## Threat Model

- **Adversary:** Internal developers who inadvertently introduce misconfigurations, compromised upstream module maintainers, and external attackers who exploit overly permissive infrastructure.
- **Access level:** Varies. Public bucket exposure requires no authentication. IAM privilege escalation requires initial access to any role in the account. Cross-account trust abuse requires compromise of the trusted account.
- **Objective:** Gain unauthorized access to data, escalate privileges within a cloud account, or establish persistent access through overly permissive trust relationships.
- **Blast radius:** A single misconfigured IAM policy can grant full account access. A permissive S3 bucket policy can expose every object in the bucket to the public internet. A security group misconfiguration can expose databases and internal services to the internet.

## Configuration

### IAM Policy Analysis: Detecting Wildcard Permissions and Cross-Account Trust

Static scanners flag `Action: "*"` on an IAM policy. Claude catches the subtler cases where effective permissions are overly broad despite appearing scoped.

Consider this Terraform configuration that Checkov passes without warning:

```hcl
# modules/data-pipeline/iam.tf

variable "bucket_arns" {
  description = "S3 bucket ARNs the pipeline needs access to"
  type        = list(string)
  default     = []
}

variable "enable_cross_region" {
  description = "Enable cross-region replication"
  type        = bool
  default     = false
}

data "aws_iam_policy_document" "pipeline" {
  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket",
    ]
    resources = length(var.bucket_arns) > 0 ? var.bucket_arns : ["arn:aws:s3:::*"]
  }

  dynamic "statement" {
    for_each = var.enable_cross_region ? [1] : []
    content {
      effect = "Allow"
      actions = [
        "s3:ReplicateObject",
        "s3:ReplicateDelete",
        "s3:GetReplicationConfiguration",
      ]
      resources = ["arn:aws:s3:::*"]
    }
  }
}

resource "aws_iam_role" "pipeline" {
  name = "data-pipeline-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.pipeline_trust.json
}

data "aws_iam_policy_document" "pipeline_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = var.trusted_accounts
    }
  }
}

variable "trusted_accounts" {
  description = "AWS account IDs that can assume this role"
  type        = list(string)
  default     = ["*"]
}
```

Claude identifies three issues here that Checkov and tflint miss:

1. **Wildcard fallback on bucket ARNs.** When `bucket_arns` is empty (the default), the policy grants S3 access to every bucket in the account. The conditional looks like a safety check but is actually a dangerous fallback. A caller who forgets to set this variable gets full S3 access.

2. **Cross-region statement always uses wildcard resources.** Even when `enable_cross_region` is true and specific `bucket_arns` are provided, the replication statement grants access to all buckets, not just the ones specified.

3. **Cross-account trust defaults to all AWS accounts.** The `trusted_accounts` variable defaults to `["*"]`, meaning any AWS account in the world can assume this role. This is invisible to Checkov because the wildcard is in a variable default, not inline in the resource.

Here is the Claude prompt that catches these:

```python
SYSTEM_PROMPT = """You are reviewing Terraform code for IAM security issues.
For each IAM policy, role, or trust relationship, check:

1. Effective permissions when variables use their DEFAULT values
2. Wildcard resources that appear only in conditional branches
3. Trust policies that allow cross-account or cross-service access
4. Policy conditions (or lack thereof) on sensitive actions
5. Variable defaults that silently broaden permissions

Trace every variable reference to its default value and evaluate the
resulting policy. Report the effective permissions, not just the
declared intent."""
```

### Security Group Rule Evaluation

Scanners check individual `ingress` and `egress` blocks. Claude evaluates the complete set of rules and their interactions with other resources:

```hcl
# networking/security_groups.tf

resource "aws_security_group" "app" {
  name   = "app-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    description = "HTTPS from ALB"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
}

resource "aws_security_group_rule" "app_debug" {
  type              = "ingress"
  from_port         = 9090
  to_port           = 9090
  protocol          = "tcp"
  cidr_blocks       = [var.debug_cidr]
  security_group_id = aws_security_group.app.id
}

variable "debug_cidr" {
  description = "CIDR block for debug access"
  type        = string
  default     = "0.0.0.0/0"
}
```

Checkov flags the inline security group as compliant (scoped to another security group). It does not correlate the separate `aws_security_group_rule` resource that opens port 9090 to the world. Claude sees both resources, traces the `debug_cidr` variable to its `0.0.0.0/0` default, and flags that the application's debug endpoint is exposed to the entire internet.

### S3 and GCS Bucket Policy Analysis

Claude excels at evaluating bucket policies that use complex conditions:

```hcl
# storage/buckets.tf

resource "aws_s3_bucket_policy" "data" {
  bucket = aws_s3_bucket.data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowVPCAccess"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.data.arn}/*"
        Condition = {
          StringEquals = {
            "aws:sourceVpc" = var.vpc_id
          }
        }
      },
      {
        Sid       = "AllowCloudFront"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.data.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:Referer" = var.cloudfront_secret
          }
        }
      }
    ]
  })
}
```

Claude identifies that the second statement uses `AWS:Referer` as a pseudo-secret to restrict CloudFront access. This is a known insecure pattern because the Referer header can be spoofed by any HTTP client. The correct approach is to use an Origin Access Identity or Origin Access Control. A scanner sees a condition and considers the policy scoped. Claude understands that the condition provides no real access control.

### RDS and Database Exposure Detection

```hcl
resource "aws_db_instance" "main" {
  identifier     = "production-db"
  engine         = "postgres"
  instance_class = "db.r5.large"

  publicly_accessible    = false
  db_subnet_group_name   = aws_db_subnet_group.private.name
  vpc_security_group_ids = [aws_security_group.db.id]

  storage_encrypted = true
  kms_key_id        = aws_kms_key.db.arn
}

resource "aws_security_group" "db" {
  name   = "db-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    cidr_blocks     = [aws_vpc.main.cidr_block]
  }
}
```

The RDS instance is not publicly accessible, which is correct. However, Claude identifies that the security group allows ingress from the entire VPC CIDR, not just the application subnet. Any compromised workload in any subnet of the VPC can connect to the database. If the VPC contains public subnets with internet-facing instances, an attacker who compromises one of those can reach the database directly.

### Terraform Module Supply Chain Risks

Claude evaluates module sources for supply chain risks that no scanner checks:

```hcl
# main.tf

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
  # Pinned to minor version range - acceptable
}

module "kubernetes" {
  source = "git::https://github.com/acme-internal/tf-modules.git//k8s-cluster?ref=main"
  # Pinned to branch, not tag or commit - risky
}

module "monitoring" {
  source = "git::https://github.com/some-user/terraform-monitoring.git"
  # No version pin at all - very risky
}

module "custom_iam" {
  source = "./modules/iam"
  # Local module - safe from supply chain, but audit the code
}
```

Claude flags three distinct risk levels:

1. The `kubernetes` module references `main` branch, meaning any commit pushed to that branch changes what Terraform deploys. An attacker who compromises the repository can inject resources into every environment using this module.

2. The `monitoring` module has no version pin at all. Terraform will pull the latest commit on the default branch at `terraform init` time. This is a direct supply chain attack vector.

3. Claude also checks whether the registry module (`terraform-aws-modules/vpc/aws`) has had recent maintainer changes or known security advisories, based on its training data.

### CloudFormation Nested Stack Analysis

```yaml
# parent-stack.yaml
Resources:
  DatabaseStack:
    Type: AWS::CloudFormation::Stack
    DeletionPolicy: Retain
    Properties:
      TemplateURL: !Sub "https://${TemplateBucket}.s3.amazonaws.com/database.yaml"
      Parameters:
        VpcId: !Ref VpcId
        SubnetIds: !Join [",", !Ref PrivateSubnets]
```

```yaml
# database.yaml
Resources:
  Database:
    Type: AWS::RDS::DBInstance
    # No DeletionPolicy specified - defaults to Delete
    Properties:
      Engine: postgres
      PubliclyAccessible: false
```

Claude identifies that the parent stack sets `DeletionPolicy: Retain` on the nested stack resource itself, but the RDS instance inside the nested stack has no `DeletionPolicy`. If the parent stack is deleted, CloudFormation will delete the nested stack, which will delete the database. The parent stack's `Retain` policy protects the nested stack object, not its contents. This is a common misunderstanding that causes data loss.

### Pulumi Security Review

Claude also reasons about Pulumi code since it is standard programming language code:

```python
# __main__.py
import pulumi_aws as aws

bucket = aws.s3.Bucket("data-bucket",
    acl="private",
)

bucket_policy = aws.s3.BucketPolicy("data-bucket-policy",
    bucket=bucket.id,
    policy=bucket.arn.apply(lambda arn: f"""{{
        "Version": "2012-10-17",
        "Statement": [{{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "{arn}/*"
        }}]
    }}""")
)
```

Claude identifies that the bucket is created with `acl="private"` but a separate policy grants public read access to all objects. The ACL and the policy contradict each other, and the policy wins. A scanner checking the ACL would report the bucket as private. Claude reads both resources and identifies the effective access is public.

## Expected Behaviour

After integrating Claude-based IaC review into your pipeline:

- **Variable default analysis catches permission escalation.** Every Terraform plan review evaluates what happens when variables use their default values, catching wildcard fallbacks and overly permissive defaults before they reach production.
- **Cross-resource analysis identifies composite risks.** Security groups, IAM policies, bucket policies, and network configurations are evaluated together, not in isolation. Issues that span multiple resource blocks are flagged.
- **Module supply chain risks are surfaced.** Unpinned module sources, branch-pinned references, and modules from untrusted registries are flagged with specific recommendations for pinning strategy.
- **CloudFormation nested stack interactions are validated.** Deletion policies, parameter passing, and resource dependencies across stack boundaries are checked for correctness.

Verification:

```bash
# Run Claude review against your Terraform directory
claude "Review the terraform/ directory. For each IAM policy, evaluate
the effective permissions when all variables use their default values.
Flag any policy that grants access to wildcard resources."

# Check for module supply chain issues
claude "List every module source in the terraform/ directory. For each,
report whether it is pinned to a specific version, tag, or commit.
Flag any module pinned to a branch or with no version constraint."

# Validate that Claude catches the known test cases
# Maintain a directory of intentionally insecure Terraform files
# and verify Claude flags each one
python3 scripts/claude-review.py \
  --input test/insecure-iac/ \
  --output test/review-results.md
diff test/review-results.md test/expected-findings.md
```

## Trade-offs

| Decision | Benefit | Cost |
|---|---|---|
| Review all .tf files, not just changed ones | Catches cross-file interactions with unchanged resources | Higher token usage, slower reviews on large repos |
| Evaluate variable defaults | Catches permission escalation from unset variables | May flag intentional defaults that are overridden by tfvars |
| Fail CI on IAM wildcard findings | Blocks dangerous IAM changes | Requires exception process for legitimate wildcard needs |
| Include terraform plan output | Claude sees the actual resources that will be created | Plan output can be very large, consuming context window |
| Pin Claude model version in CI | Reproducible results across runs | Must manually update when better models are available |

**API cost estimate:** Reviewing a 500-file Terraform repository (approximately 50,000 lines) costs $0.10-0.30 per review with Claude Sonnet. Reviewing only changed files in a PR costs $0.01-0.05. At 30 PRs per day, monthly cost is $9-45.

**Accuracy note:** Claude's IaC analysis is not a substitute for `terraform validate` or `terraform plan`. Claude may occasionally reference provider arguments that do not exist or suggest resource configurations that are syntactically invalid. Always validate Claude's recommendations by running the actual Terraform, CloudFormation, or Pulumi toolchain.

## Failure Modes

| Failure | Symptom | Detection | Response |
|---|---|---|---|
| False positive on intentional wildcard | Claude flags an IAM policy that legitimately requires broad access (e.g., an admin role) | Human reviewer dismisses finding; pattern recurs across PRs | Add exclusion patterns to the system prompt for known-intentional broad policies |
| Missed conditional branch | Claude does not evaluate a `count` or `for_each` conditional that changes resource topology | Manual review finds the issue; Claude's output does not mention the conditional | Include `terraform plan` output alongside HCL so Claude sees the resolved configuration |
| Hallucinated provider argument | Claude recommends adding a security setting that does not exist in the provider | `terraform validate` fails when applying the recommendation | Always validate Claude's fix suggestions with the provider documentation |
| Module source not analysed | Claude reviews the module call but not the module's internal code | Issues inside the module are missed | Include module source code in the review input, not just the module call |
| Stale knowledge of provider defaults | Claude assumes a provider default that has changed in a newer version | Resource deploys with unexpected default settings | Include provider version in review context; verify defaults against current provider docs |
| Context window exceeded on monorepo | Large Terraform repositories exceed Claude's input limit | Review output is incomplete or missing files | Split review by directory or module, review each independently |

## When to Consider a Managed Alternative

**Transition point:** When your team manages more than 200 Terraform modules across multiple cloud providers and needs continuous compliance monitoring, not just PR-time review.

**What managed providers handle:**

- **[Snyk](https://snyk.io):** Snyk IaC scans Terraform, CloudFormation, and [Kubernetes](https://kubernetes.io) manifests against a continuously updated policy database. It covers compliance frameworks (CIS, SOC2, PCI-DSS) with pre-built rule sets. Use Snyk for deterministic compliance checks that must produce auditable evidence.
- **[Checkov](https://www.checkov.io):** Open-source IaC scanner with over 1,000 built-in policies. Checkov handles the high-volume pattern matching that Claude should not be used for: checking every resource against known misconfiguration patterns. Checkov is fast, deterministic, and free.

**What Claude handles that managed tools do not:** Variable default evaluation, conditional branch analysis, cross-resource permission tracing, module supply chain risk assessment, and natural-language explanations of why a configuration is dangerous in context. No managed IaC scanner reasons about what happens when a variable is unset or when a conditional changes resource topology.

**The optimal stack:** Checkov or Snyk for deterministic policy enforcement + Claude for contextual reasoning about variable interactions, conditional logic, and cross-resource dependencies. Checkov catches the 90% of issues that are pattern-matchable. Claude catches the 10% that require reasoning.


## Related Articles

- [Claude for Security Detection: How Large Language Models Find What Scanners Miss](/articles/ai-landscape/claude-security-detection/)
- [Claude for Application Security: Finding Logic Vulnerabilities in Source Code](/articles/ai-landscape/claude-code-vulnerability/)
- [Claude, Mythos, and the Non-Human Infrastructure Consumer: Writing Hardening Guides for AI Agents](/articles/ai-landscape/claude-non-human-consumers/)
- [Claude for Kubernetes Security Auditing: Finding Privilege Escalation Paths Scanners Cannot See](/articles/ai-landscape/claude-kubernetes-audit/)
- [Claude for Security Incident Triage: Rapid Analysis of Logs, Alerts, and Blast Radius](/articles/ai-landscape/claude-incident-triage/)
