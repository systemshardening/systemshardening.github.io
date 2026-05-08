---
title: "Infrastructure Drift Detection: Closing the Gap Between IaC State and Live Infrastructure"
description: "Manual changes, emergency fixes, and console hotpatches silently diverge your infrastructure from the IaC source of truth—bypassing security review and accumulating compliance debt. Learn to detect, alert on, and prevent drift using Terraform plan schedules, Driftctl, Argo CD self-heal, Flux reconciliation, AWS Config, and CloudTrail analysis."
slug: infrastructure-drift-detection
date: 2026-05-07
lastmod: 2026-05-07
category: cicd
tags:
  - drift-detection
  - terraform
  - gitops
  - infrastructure-as-code
  - compliance
personas:
  - security-engineer
  - platform-engineer
article_number: 529
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/cicd/infrastructure-drift-detection/
---

# Infrastructure Drift Detection: Closing the Gap Between IaC State and Live Infrastructure

## Problem

Infrastructure as Code creates a security contract: every resource is defined in version-controlled code, reviewed by humans, and applied through a controlled pipeline. Drift breaks that contract. A security group rule added via the AWS console at 2 AM to unblock a production incident was never reviewed. A manually scaled auto-scaling group never got put back. A database parameter changed during a troubleshooting session was never codified.

Each of these changes represents a resource whose current state differs from the IaC source of truth. They accumulate silently.

The security consequences are significant:

- **Security review bypass.** Changes applied outside the pipeline skip peer review, static analysis, and policy checks. A security group that opens port 5432 to 0.0.0.0/0 "temporarily" to fix an application bug bypasses every control in your pipeline.
- **Emergency fixes that never get codified.** Under pressure, engineers make direct changes. The change solves the immediate problem but is never back-ported to IaC. The next `terraform apply` from the pipeline reverts the fix—or worse, the team discovers the drift months later during a compliance audit.
- **Compliance drift.** CIS benchmarks, SOC 2 controls, and PCI requirements describe specific resource configurations. If your Terraform defines an S3 bucket with public access blocked, but someone enabled public access via the console, your compliance posture has diverged from what your IaC would imply. Automated compliance scanning of the IaC gives a false clean result.
- **Incident response blindspots.** When you are investigating an incident, you assume your IaC matches reality. If it does not, your mental model of the environment is wrong.

**Target systems:** AWS, GCP, Azure multi-account environments managed with Terraform or OpenTofu; Kubernetes workloads managed with Argo CD or Flux; any organisation where multiple engineers or teams have direct cloud console access.

## Threat Model

- **Adversary 1 — Insider or compromised credential making stealthy changes:** An attacker with a compromised AWS IAM credential makes targeted changes to security groups, IAM role trust policies, or S3 bucket policies directly via API or console. Without drift detection, these changes persist indefinitely alongside legitimate infrastructure and go unnoticed until they are exploited.
- **Adversary 2 — Accumulated unreviewed changes masking a security regression:** Over months, dozens of engineers make small console changes during incidents. The cumulative effect is an environment that bears little resemblance to the IaC state. A security audit of the Terraform code produces a clean result while the live environment has multiple misconfigurations.
- **Adversary 3 — Resource created outside Terraform entirely:** A developer spins up an EC2 instance or RDS cluster via console for testing and forgets about it. The resource is not in Terraform state, has no hardening applied, and may run for months. It is also outside your patch management pipeline.
- **Blast radius:** Undetected drift allows attacker-controlled changes to persist in production. Resources outside IaC management are outside security tooling coverage. Compliance certifications become invalid once auditors discover the IaC does not match reality.

## Configuration

### Scheduled Terraform Drift Detection in CI

The `terraform plan` command with `-detailed-exitcode` returns exit code 2 when it detects differences between state and reality. A scheduled pipeline that runs plan daily (or hourly for critical environments) turns this into a drift alarm.

```yaml
# .github/workflows/drift-detection.yml
name: Terraform Drift Detection
on:
  schedule:
    - cron: '0 */6 * * *'   # Every 6 hours
  workflow_dispatch:          # Allow manual trigger

permissions:
  id-token: write
  contents: read

jobs:
  detect-drift:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        environment: [production, staging]
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: "1.8.0"

      - name: Configure AWS credentials via OIDC
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/terraform-drift-readonly
          aws-region: eu-west-1

      - name: Terraform Init
        run: terraform init -input=false
        working-directory: terraform/${{ matrix.environment }}/

      - name: Detect drift
        id: plan
        run: |
          set +e
          terraform plan \
            -input=false \
            -detailed-exitcode \
            -no-color \
            -out=drift.tfplan \
            2>&1 | tee plan_output.txt
          EXIT_CODE=${PIPESTATUS[0]}
          echo "exit_code=$EXIT_CODE" >> $GITHUB_OUTPUT
          exit $EXIT_CODE
        working-directory: terraform/${{ matrix.environment }}/
        continue-on-error: true

      - name: Parse drift summary
        if: steps.plan.outputs.exit_code == '2'
        run: |
          # Extract the change summary line
          SUMMARY=$(grep -E "^Plan:" plan_output.txt || echo "Changes detected")
          echo "DRIFT_SUMMARY=$SUMMARY" >> $GITHUB_ENV
        working-directory: terraform/${{ matrix.environment }}/

      - name: Alert via Slack on drift
        if: steps.plan.outputs.exit_code == '2'
        uses: slackapi/slack-github-action@v1.26.0
        with:
          payload: |
            {
              "text": ":rotating_light: *Terraform drift detected in ${{ matrix.environment }}*",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "*Environment:* ${{ matrix.environment }}\n*Summary:* ${{ env.DRIFT_SUMMARY }}\n*Workflow:* <${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}|View details>"
                  }
                }
              ]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_DRIFT_WEBHOOK }}

      - name: Open GitHub issue on drift
        if: steps.plan.outputs.exit_code == '2'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const planOutput = fs.readFileSync('terraform/${{ matrix.environment }}/plan_output.txt', 'utf8');
            await github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: `[DRIFT] Infrastructure drift detected in ${{ matrix.environment }} - ${new Date().toISOString().split('T')[0]}`,
              body: `## Drift Detected\n\nTerraform plan found differences between IaC state and live infrastructure.\n\n**Environment:** ${{ matrix.environment }}\n\n<details><summary>Plan output</summary>\n\n\`\`\`\n${planOutput.slice(0, 60000)}\n\`\`\`\n</details>\n\n**Actions required:**\n- [ ] Review the drift\n- [ ] Determine if the live change is intentional\n- [ ] Either update Terraform to codify the change, or apply Terraform to revert it\n- [ ] Close this issue once resolved`,
              labels: ['drift', 'infrastructure', '${{ matrix.environment }}']
            });

      - name: Fail job on drift (for visibility)
        if: steps.plan.outputs.exit_code == '2'
        run: exit 1

      - name: Fail job on plan error
        if: steps.plan.outputs.exit_code == '1'
        run: |
          echo "Terraform plan encountered an error (not drift). Review the output."
          exit 1
```

The exit code distinction matters:
- Exit code `0`: no changes, no drift
- Exit code `1`: plan error (credentials, provider issues, syntax error)
- Exit code `2`: changes detected—this is drift

Set up the IAM role `terraform-drift-readonly` with read-only permissions across the AWS services Terraform manages. It does not need write permissions; it only calls `plan`, never `apply`.

### Driftctl for Resources Outside Terraform Management

Terraform plan only detects drift in resources it already tracks in state. It cannot detect resources that were created manually and never added to Terraform at all. [Driftctl](https://driftctl.com) (now part of the Snyk ecosystem as `iac-describe`) scans your entire cloud account and identifies unmanaged resources.

```bash
# Install driftctl
curl -L https://github.com/snyk/driftctl/releases/latest/download/driftctl_linux_amd64 \
  -o /usr/local/bin/driftctl
chmod +x /usr/local/bin/driftctl

# Scan for unmanaged resources against a Terraform state file
driftctl scan \
  --from tfstate+s3://your-org-terraform-state/production/terraform.tfstate \
  --output json://drift-report.json

# Scan across multiple state files (multi-module environments)
driftctl scan \
  --from tfstate+s3://your-org-terraform-state/production/terraform.tfstate \
  --from tfstate+s3://your-org-terraform-state/networking/terraform.tfstate \
  --from tfstate+s3://your-org-terraform-state/iam/terraform.tfstate \
  --output console://
```

```yaml
# CI job: driftctl scan for unmanaged resources
# .github/workflows/driftctl-scan.yml
name: Driftctl Unmanaged Resource Scan
on:
  schedule:
    - cron: '0 8 * * 1'   # Weekly on Monday morning

jobs:
  driftctl:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Configure AWS credentials via OIDC
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/driftctl-readonly
          aws-region: eu-west-1

      - name: Install driftctl
        run: |
          curl -L https://github.com/snyk/driftctl/releases/download/v0.40.0/driftctl_linux_amd64 \
            -o /usr/local/bin/driftctl
          chmod +x /usr/local/bin/driftctl

      - name: Run drift scan
        run: |
          driftctl scan \
            --from tfstate+s3://your-org-terraform-state/production/terraform.tfstate \
            --output json://drift-report.json \
            --output console://
        continue-on-error: true

      - name: Upload drift report
        uses: actions/upload-artifact@v4
        with:
          name: driftctl-report
          path: drift-report.json
          retention-days: 90

      - name: Alert if unmanaged resources found
        run: |
          UNMANAGED=$(jq '.summary.total_unmanaged' drift-report.json)
          if [ "$UNMANAGED" -gt "0" ]; then
            echo "Found $UNMANAGED unmanaged resources"
            jq '.unmanaged[] | "\(.resource_type) \(.resource_id)"' drift-report.json
            exit 1
          fi
```

Driftctl supports an allowlist file (`.driftignore`) for resources that are intentionally unmanaged—such as resources created by AWS itself (default VPC, default security groups) or resources managed by separate tooling.

```
# .driftignore — resources intentionally outside Terraform management
# Format: resource_type.resource_id

# Default VPC and its components (AWS-created, not managed by us)
aws_vpc.vpc-0123456789abcdef0
aws_internet_gateway.igw-0123456789abcdef0

# IAM roles created by AWS services (not user-managed)
aws_iam_role.AWSServiceRoleForElasticLoadBalancing
aws_iam_role.AWSServiceRoleForRDS

# EKS node IAM instance profiles (managed by EKS module, separate state)
aws_iam_instance_profile.eks-node-*
```

### Argo CD Drift Detection and Self-Heal

For Kubernetes workloads, Argo CD continuously compares the desired state in Git against the live cluster state. The `OutOfSync` status is the Kubernetes equivalent of Terraform drift.

```yaml
# Application with strict sync policy and self-heal enabled.
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: payments-api
  namespace: argocd
spec:
  project: payments

  source:
    repoURL: https://github.com/example/payments-manifests.git
    targetRevision: main
    path: clusters/production/payments

  destination:
    server: https://kubernetes.default.svc
    namespace: payments

  syncPolicy:
    automated:
      # Self-heal: if someone manually patches a resource, Argo CD reverts it.
      selfHeal: true
      # Prune: if someone manually creates a resource not in Git, Argo CD deletes it.
      prune: true
    syncOptions:
      - CreateNamespace=false
      - PrunePropagationPolicy=foreground
      - RespectIgnoreDifferences=true
    retry:
      limit: 3
      backoff:
        duration: 5s
        factor: 2
        maxDuration: 3m
```

Self-heal is appropriate for application workloads where any deviation from Git is unwanted. For platform infrastructure (cluster-level resources, CRDs), you may prefer manual sync with alerting on `OutOfSync`—so a human reviews and approves the sync.

```yaml
# Alert on OutOfSync status (Prometheus AlertManager rule).
groups:
  - name: argocd-drift
    rules:
      - alert: ArgoCDApplicationOutOfSync
        expr: |
          argocd_app_info{sync_status="OutOfSync"} == 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Argo CD application {{ $labels.name }} is OutOfSync"
          description: |
            The live state of {{ $labels.name }} in {{ $labels.dest_namespace }}
            has diverged from Git. Either a manual change was made, or the
            application has not yet synced after a commit.
            Review: https://argocd.internal.example.com/applications/{{ $labels.name }}

      - alert: ArgoCDApplicationDegradedAfterSync
        expr: |
          argocd_app_info{health_status="Degraded"} == 1
        for: 10m
        labels:
          severity: critical
        annotations:
          summary: "Argo CD application {{ $labels.name }} is Degraded"
```

To detect manual changes without auto-reverting them, disable `selfHeal` and rely on the `OutOfSync` metric alert. Operations teams get a Slack notification and must explicitly approve the sync after reviewing what changed.

### Flux Reconciliation as Continuous Drift Prevention

Flux's reconciliation loop is structurally drift-preventive: every `interval` period, Flux applies the Git state to the cluster, overwriting any manual changes. The default `interval: 5m` means drift can only persist for up to five minutes before Flux corrects it.

```yaml
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: production-workloads
  namespace: flux-system
spec:
  interval: 5m        # Reconcile every 5 minutes
  retryInterval: 1m   # Retry failed reconciliations every minute
  timeout: 3m         # Give up on a single reconciliation attempt after 3 minutes
  prune: true         # Delete resources removed from Git
  force: false        # Do not force-apply (avoids replacing resources unnecessarily)
  sourceRef:
    kind: GitRepository
    name: production-manifests
  path: ./clusters/production
```

The `prune: true` setting is what makes Flux a drift-prevention tool rather than just a deployment tool. When a resource is removed from Git, Flux deletes it from the cluster. Without `prune: true`, Flux would only add and update resources, and manually created resources would accumulate indefinitely.

Monitor reconciliation lag—the gap between the last Git commit timestamp and the last successful reconciliation—as a drift window metric:

```
gotk_reconcile_condition{type="Ready", status="False"}  # Reconciliation failures
gotk_reconcile_duration_seconds                         # Reconciliation latency
```

Alert if `gotk_reconcile_condition{status="False"}` persists for more than 10 minutes: the cluster is open to accumulating drift for as long as the reconciliation is failing.

### AWS Config Rules for Console Change Detection

AWS Config records configuration changes to all AWS resources and evaluates them against rules. This gives you a cloud-native layer of drift detection that does not require Terraform.

```hcl
# terraform/config-rules.tf

# Detect security groups with overly permissive rules.
resource "aws_config_config_rule" "restricted_ssh" {
  name = "restricted-ssh"

  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Detect S3 buckets that have public access enabled.
resource "aws_config_config_rule" "s3_public_access_prohibited" {
  name = "s3-bucket-public-read-write-prohibited"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Custom rule: detect EC2 instances not tagged with the required "managed-by" tag.
# Untagged resources are often manually created outside IaC.
resource "aws_config_config_rule" "required_tags" {
  name = "required-tags"

  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"
  }

  input_parameters = jsonencode({
    tag1Key   = "managed-by"
    tag1Value = "terraform"
    tag2Key   = "environment"
  })

  scope {
    compliance_resource_types = [
      "AWS::EC2::Instance",
      "AWS::RDS::DBInstance",
      "AWS::ElasticLoadBalancingV2::LoadBalancer",
    ]
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# EventBridge rule: alert immediately when any Config rule transitions to NON_COMPLIANT.
resource "aws_cloudwatch_event_rule" "config_compliance_change" {
  name        = "config-compliance-change"
  description = "Alert when AWS Config rules detect non-compliance (drift indicator)"

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "config_compliance_sns" {
  rule      = aws_cloudwatch_event_rule.config_compliance_change.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.security_alerts.arn
}
```

### CloudTrail Analysis for Changes Outside the CI/CD Role

CloudTrail logs every API call. Changes made via the CI/CD IAM role are expected. Changes made by any other identity—a human IAM user, an assumed role from a developer's session, or a third-party tool—are candidates for drift investigation.

```bash
# Athena query: find all write-type API calls not made by the CI/CD role.
# Run this query periodically or in response to drift alerts.

SELECT
  eventTime,
  userIdentity.type           AS caller_type,
  userIdentity.arn            AS caller_arn,
  userIdentity.sessionContext.sessionIssuer.arn AS assumed_role,
  eventName,
  awsRegion,
  requestParameters
FROM cloudtrail_logs
WHERE
  -- Only write operations (changes)
  readOnly = false
  -- Exclude the known CI/CD roles
  AND userIdentity.arn NOT LIKE '%role/terraform-ci-apply%'
  AND userIdentity.arn NOT LIKE '%role/eks-node-group%'
  AND userIdentity.arn NOT LIKE '%role/AWSServiceRole%'
  -- Only infrastructure-relevant services
  AND eventSource IN (
    'ec2.amazonaws.com',
    'rds.amazonaws.com',
    's3.amazonaws.com',
    'iam.amazonaws.com',
    'elasticloadbalancing.amazonaws.com',
    'eks.amazonaws.com'
  )
  -- Last 24 hours
  AND eventTime > to_iso8601(current_timestamp - interval '24' hour)
ORDER BY eventTime DESC;
```

Automate this query on a schedule and compare results against a known allowlist of legitimate non-CI callers (on-call break-glass role, specific service accounts). Flag any caller outside the allowlist as requiring investigation.

```python
# scripts/cloudtrail_drift_analysis.py
# Run via AWS Lambda on a schedule; post results to Slack.

import boto3
import json
import time

ALLOWED_ROLE_PATTERNS = [
    "role/terraform-ci-apply",
    "role/terraform-ci-readonly",
    "role/eks-",
    "role/AWSServiceRole",
    "root",   # AWS internal operations
]

def is_allowed_caller(caller_arn: str) -> bool:
    return any(pattern in caller_arn for pattern in ALLOWED_ROLE_PATTERNS)

def analyze_recent_changes(hours: int = 24) -> list[dict]:
    """Return write-type API calls from unexpected callers."""
    client = boto3.client("cloudtrail")
    end_time = time.time()
    start_time = end_time - (hours * 3600)

    paginator = client.get_paginator("lookup_events")
    unexpected = []

    for page in paginator.paginate(
        StartTime=start_time,
        EndTime=end_time,
        LookupAttributes=[{"AttributeKey": "ReadOnly", "AttributeValue": "false"}],
    ):
        for event in page["Events"]:
            caller_arn = event.get("Username", "")
            if not is_allowed_caller(caller_arn):
                unexpected.append({
                    "time": event["EventTime"].isoformat(),
                    "caller": caller_arn,
                    "event": event["EventName"],
                    "source": event.get("EventSource", ""),
                })

    return unexpected
```

### Preventing Manual Changes via IAM Policy

Detection is reactive. The most effective drift prevention is denying console write access for everyone except the CI/CD role.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyConsoleWriteAccessForHumans",
      "Effect": "Deny",
      "Action": [
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:AuthorizeSecurityGroupEgress",
        "ec2:RevokeSecurityGroupIngress",
        "ec2:ModifyInstanceAttribute",
        "rds:ModifyDBInstance",
        "s3:PutBucketPolicy",
        "s3:PutPublicAccessBlock",
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy",
        "iam:UpdateAssumeRolePolicy",
        "eks:UpdateClusterConfig"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/terraform-ci-apply",
            "arn:aws:iam::*:role/break-glass-admin"
          ]
        },
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

Attach this policy as an AWS Organizations Service Control Policy (SCP) at the organizational unit level to enforce it across all accounts in a business unit. SCPs cannot be overridden by any IAM policy within the account—they are an absolute ceiling.

Reserve the `break-glass-admin` role for genuine emergencies. Require MFA to assume it. Audit every use via CloudTrail. Require a post-incident review for any production changes made via break-glass within 48 hours of the incident.

## Documenting Legitimate Drift Exceptions

Not all drift is unauthorised. Some is intentional and expected. Document exceptions so that automated tools do not fire spuriously on known-good deviations.

Create a `drift-exceptions.yaml` file in the repository:

```yaml
# drift-exceptions.yaml
# Each exception requires: resource, reason, owner, review_date
# Exceptions older than 90 days should be re-evaluated.

exceptions:
  - resource: "aws_autoscaling_group.api_workers"
    reason: "Desired capacity is set dynamically by KEDA based on queue depth. Terraform manages min/max; current desired count diverges intentionally."
    owner: "platform-team"
    review_date: "2026-08-01"
    type: "expected-runtime-change"

  - resource: "aws_security_group_rule.allow_vpn_temp"
    reason: "Temporary rule added during VPN migration. Will be removed once migration completes on 2026-06-01."
    owner: "network-team"
    expiry_date: "2026-06-01"
    type: "time-limited-exception"
    jira_ticket: "INFRA-4821"

  - resource: "aws_iam_role_policy_attachment.break-glass-*"
    reason: "Break-glass role policies are managed by the security team via a separate Terraform workspace. Drift from the main workspace is expected."
    owner: "security-team"
    review_date: "2026-07-01"
    type: "separate-management-scope"
```

Integrate this exception list into the drift detection pipeline. Skip alerting for resources listed with an active exception. Flag exceptions past their `review_date` or `expiry_date` automatically.

## Escalation Workflow When Drift Is Detected

Define a response process before drift is detected, not after.

**Severity classification:**

| Drift type | Severity | Response time |
|------------|----------|---------------|
| IAM policy, security group, S3 bucket ACL changed outside IaC | Critical | Immediate — page on-call security engineer |
| Resource created outside IaC with public exposure | High | 4 hours — investigate and either import or terminate |
| Configuration parameter changed (instance type, capacity) | Medium | 24 hours — codify or revert in next business day |
| Tag or annotation change | Low | Weekly review — update IaC if intentional |

**Response steps:**

1. **Acknowledge** the drift alert within the response SLA. Assign an owner.
2. **Determine intent.** Was this change intentional? Cross-reference CloudTrail to identify who made it and when. Check for a corresponding JIRA ticket, incident, or change request.
3. **Assess security impact.** Does the drift introduce a security regression? Did a security group rule open an unexpected port? Did an IAM policy gain new permissions?
4. **Resolve.** Choose one of two paths:
   - **Revert:** Apply Terraform to restore the IaC-defined state. Use this when the change was unauthorised, unreviewed, or accidental.
   - **Codify:** Update the IaC to reflect the intentional change. Open a PR, get it reviewed, and merge it. The next drift detection run should be clean.
5. **Post-mortem** for critical drift: how did the change bypass the pipeline? Update IAM policies or SCP rules to prevent recurrence.

## Expected Behaviour

| Signal | Without drift detection | With drift detection |
|--------|------------------------|---------------------|
| Security group modified via console | Persists indefinitely; bypasses security review | CloudTrail query flags within 24 hours; Config rule fires immediately for high-risk changes |
| Terraform manages 80 resources; 20 exist outside Terraform | No visibility | Driftctl weekly scan reports 20 unmanaged resources by type and ID |
| Engineer patches Kubernetes Deployment replicas manually | Persists until next deployment | Argo CD self-heal reverts within seconds; Flux reverts within interval |
| `terraform apply` in CI reverts an emergency fix | Emergency fix is lost; incident recurs | Drift exception documented; codification PR reviewed and merged before revert |

## Trade-offs

| Control | Benefit | Cost | Mitigation |
|---------|---------|------|------------|
| Scheduled `terraform plan` every 6 hours | Detects configuration drift promptly | Read-only API calls to AWS; small cost and latency | Use OIDC credentials; plan only, never apply |
| SCP denying console writes | Prevents drift at source | Blocks engineers from making emergency fixes via console | Define and document break-glass role; require post-incident review |
| Argo CD self-heal enabled | Manual changes reverted automatically | A legitimate emergency fix is immediately reverted | Disable self-heal for critical components; require Git PR for all changes |
| Driftctl weekly scan | Identifies completely unmanaged resources | Requires broad read permissions across the account | Scope to specific resource types; maintain `.driftignore` for known-good exceptions |
| Drift exception documentation | Reduces alert noise for known deviations | Exceptions can accumulate and obscure real drift | Enforce expiry dates; auto-flag stale exceptions |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Drift detection pipeline itself drifts | CI workflow is modified; drift runs are skipped | Monitor for workflow runs not completing on schedule | Pin workflow file; require signed commits to `.github/workflows/` |
| Alert fatigue from noisy drift | Engineers start ignoring drift alerts | High volume of non-actionable drift tickets; SLA breaches | Tune severity classification; expand `.driftignore`; enforce codification backlog |
| Terraform state and reality diverge before drift detection runs | 6-hour window during which undetected changes persist | Critical changes detected by AWS Config rules in near-real-time | Use AWS Config EventBridge rules for immediate high-severity change alerting |
| Break-glass changes not codified | Emergency fix is reverted by next `terraform apply` | Post-incident review checklist includes IaC update step | Require codification PR before closing incident ticket |

## Related Articles

- [Terraform Security: State File Protection, Provider Pinning, and Plan Review Automation](/articles/cicd/terraform-security/)
- [Terraform State Security](/articles/cicd/terraform-state-security/)
- [GitOps Security](/articles/cicd/gitops-security/)
- [Argo CD Security Hardening](/articles/cicd/argocd-security-hardening/)
- [Flux CD Security](/articles/cicd/flux-cd-security/)
- [Pipeline Configuration Security](/articles/cicd/pipeline-config-security/)
