---
title: "Cloud Security Posture Management: Automated Drift Detection and Compliance"
description: "CSPM tools continuously compare live cloud configuration against a security baseline. Without them, misconfigurations — public S3 buckets, overpermissive security groups, disabled MFA — persist undetected for months."
slug: "cloud-security-posture-management"
date: 2026-04-30
lastmod: 2026-04-30
category: "cross-cutting"
tags: ["cspm", "cloud-security", "misconfiguration", "compliance", "drift-detection"]
personas: ["security-engineer", "platform-engineer", "sre"]
article_number: 269
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/cross-cutting/cloud-security-posture-management/index.html"
---

# Cloud Security Posture Management: Automated Drift Detection and Compliance

## Problem

Cloud environments misconfigure themselves. Every `terraform apply`, every console click, every IAM policy attached by a developer trying to unblock themselves, every new service spun up in a hurry — each is an opportunity for a security control to drift from its intended state.

The statistics are sobering: the 2024 Verizon DBIR found misconfiguration as a factor in 21% of breaches. Cloud misconfiguration is the leading cause of data exposure incidents involving public object storage. The reason is structural: cloud resources are created and modified at high velocity, security review of every change is impractical, and the configuration state of hundreds of cloud accounts is too large to comprehend manually.

Cloud Security Posture Management (CSPM) addresses this by continuously scanning cloud APIs, comparing the current configuration state against a security baseline, and surfacing deviations:

- A security group was updated to allow `0.0.0.0/0` on port 22.
- An S3 bucket's public access block was removed.
- A root account was used.
- An IAM role has `*:*` permissions attached.
- A CloudTrail was disabled.

Without CSPM, these misconfigurations persist until an auditor, a penetration tester, or an attacker finds them.

Specific gaps without CSPM:

- No continuous visibility into the current security state of cloud resources.
- Compliance checks happen quarterly during audits; drift accumulates between checks.
- New accounts, subscriptions, or projects are added without baseline security controls.
- Developer self-service creates permissive configurations that production teams don't review.
- No cross-account or cross-cloud visibility; security posture is per-account at best.

**Target systems:** AWS Config + Security Hub; GCP Security Command Center; Azure Defender for Cloud; open-source: Prowler 4.x, CloudSploit, Steampipe; commercial: Wiz, Orca, Lacework; infrastructure as code: Checkov 3.x, tfsec.

## Threat Model

- **Adversary 1 — Public S3 bucket exploitation:** An S3 bucket containing customer data has its public access block removed (accidentally or by a developer misconfiguration). An attacker scanning for public buckets discovers and exfiltrates the data within hours. CSPM would have detected the configuration change and alerted within minutes.
- **Adversary 2 — Overpermissive IAM lateral movement:** A developer attaches `AdministratorAccess` to a service account to unblock a task. CSPM detects the overpermissive IAM attachment. Without CSPM, it persists — and when the service is compromised, the attacker has administrator-level access to the entire account.
- **Adversary 3 — Security group opened to the internet:** An engineer opens port 3306 (MySQL) to `0.0.0.0/0` to test a database connection from their laptop, then forgets to close it. CSPM detects and alerts within the next scan cycle (typically 5–15 minutes).
- **Adversary 4 — Disabled CloudTrail:** An attacker who gains account access disables CloudTrail to cover tracks. CSPM detects the configuration change immediately via EventBridge.
- **Adversary 5 — New account with no baseline controls:** A new AWS account is created for a project. It has no CloudTrail, no Config, no GuardDuty, no SCPs. An attacker who compromises a developer's credentials for that account has full access with no logging or detection. CSPM would flag the account as non-compliant immediately.
- **Access level:** Adversaries 1–3 exploit misconfigurations from the internet (no authentication required). Adversary 4 has IAM credentials. Adversary 5 targets an unmonitored account.
- **Objective:** Access exposed data, escalate privileges, disable logging and evade detection.
- **Blast radius:** A missed misconfiguration is an open attack surface for as long as it persists. CSPM reduces the window from months to minutes.

## Configuration

### Step 1: AWS Config + Security Hub

AWS Config records every configuration change to AWS resources. Security Hub aggregates findings from Config, GuardDuty, Macie, IAM Access Analyzer, and third-party tools.

```bash
# Enable AWS Config in all regions (required for cross-region visibility).
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  aws configservice put-configuration-recorder \
    --region $region \
    --configuration-recorder name=default,roleARN=arn:aws:iam::ACCOUNT:role/config-role \
    --recording-group '{"allSupported":true,"includeGlobalResourceTypes":true}'

  aws configservice put-delivery-channel \
    --region $region \
    --delivery-channel "name=default,s3BucketName=config-logs-ACCOUNT,configSnapshotDeliveryProperties={deliveryFrequency=TwentyFour_Hours}"

  aws configservice start-configuration-recorder \
    --region $region \
    --configuration-recorder-name default
done

# Enable Security Hub with CIS AWS Foundations Benchmark.
aws securityhub enable-security-hub \
  --enable-default-standards \
  --control-finding-generator SECURITY_CONTROL

# Enable specific standards.
aws securityhub batch-enable-standards \
  --standards-subscription-requests \
    'StandardsArn=arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0' \
    'StandardsArn=arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0'
```

Enable Security Hub across the entire AWS Organization:

```bash
# Designate a delegated admin account for Security Hub.
aws organizations enable-aws-service-access \
  --service-principal securityhub.amazonaws.com

aws securityhub enable-organization-admin-account \
  --admin-account-id SECURITY-ACCOUNT-ID

# Auto-enable Security Hub in new accounts.
aws securityhub update-organization-configuration \
  --auto-enable \
  --auto-enable-standards DEFAULT
```

### Step 2: Custom AWS Config Rules

Built-in Config rules cover common misconfigurations. Add custom rules for organisation-specific policies:

```python
# lambda/config-rule-no-admin-iam.py
# Custom Config rule: deny IAM policies with admin permissions.

import boto3
import json

def evaluate_compliance(configuration_item: dict) -> str:
    if configuration_item["resourceType"] != "AWS::IAM::Policy":
        return "NOT_APPLICABLE"

    policy_doc = json.loads(
        configuration_item["configuration"]["policyDocument"]
    )

    for statement in policy_doc.get("Statement", []):
        if (statement.get("Effect") == "Allow" and
            statement.get("Action") in ["*", ["*"]] and
            statement.get("Resource") in ["*", ["*"]]):
            return "NON_COMPLIANT"

    return "COMPLIANT"

def handler(event, context):
    config = boto3.client("config")
    invoking_event = json.loads(event["invokingEvent"])
    configuration_item = invoking_event["configurationItem"]

    compliance = evaluate_compliance(configuration_item)

    config.put_evaluations(
        Evaluations=[{
            "ComplianceResourceType": configuration_item["resourceType"],
            "ComplianceResourceId": configuration_item["resourceId"],
            "ComplianceType": compliance,
            "Annotation": "IAM policy grants admin-level permissions",
            "OrderingTimestamp": configuration_item["configurationItemCaptureTime"],
        }],
        ResultToken=event["resultToken"],
    )
```

Deploy the custom rule:

```bash
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "no-admin-iam-policies",
    "Source": {
      "Owner": "CUSTOM_LAMBDA",
      "SourceIdentifier": "arn:aws:lambda:us-east-1:ACCOUNT:function:config-rule-no-admin-iam",
      "SourceDetails": [{
        "EventSource": "aws.config",
        "MessageType": "ConfigurationItemChangeNotification"
      }]
    },
    "Scope": {
      "ComplianceResourceTypes": ["AWS::IAM::Policy"]
    }
  }'
```

### Step 3: Prowler for Open-Source CSPM

Prowler is an open-source CSPM tool with 300+ checks across AWS, GCP, and Azure:

```bash
# Install Prowler.
pip install prowler

# Run against all AWS accounts with CIS benchmark checks.
prowler aws --compliance cis_2.0 \
  --output-formats json html \
  --output-filename prowler-report \
  --log-level ERROR

# Run specific check categories.
prowler aws --checks s3_bucket_public_access_block_enabled \
               s3_bucket_acl_prohibit_public_read \
               iam_root_mfa_enabled \
               ec2_securitygroup_not_open_to_world_rdp \
               ec2_securitygroup_not_open_to_world_ssh

# Run across multiple accounts using assume-role.
prowler aws --role arn:aws:iam::ACCOUNT1:role/ProwlerRole \
            --role arn:aws:iam::ACCOUNT2:role/ProwlerRole \
            --checks s3_bucket_public_access_block_enabled

# Output findings in OCSF format for Security Lake ingestion.
prowler aws --output-formats ocsf-json
```

Integrate Prowler into CI for infrastructure-as-code validation:

```yaml
# .github/workflows/cspm-scan.yml
name: CSPM Scan

on:
  schedule:
    - cron: "0 6 * * *"   # Daily at 6am.
  push:
    paths: ["terraform/**"]   # Also run on Terraform changes.

jobs:
  prowler:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::ACCOUNT:role/ProwlerReadOnly
          aws-region: us-east-1

      - name: Run Prowler
        run: |
          pip install prowler
          prowler aws \
            --compliance cis_2.0 \
            --severity critical high \
            --exit-code-vulnerability-status FAIL \
            --output-formats json
```

### Step 4: Infrastructure-as-Code Scanning with Checkov

Detect misconfigurations before they reach the cloud:

```bash
# Install Checkov.
pip install checkov

# Scan Terraform files.
checkov -d terraform/ \
  --framework terraform \
  --check CKV_AWS_18,CKV_AWS_20,CKV_AWS_21 \   # S3 checks.
  --check CKV_AWS_25,CKV_AWS_24 \               # Security group checks.
  --check CKV_AWS_40,CKV_AWS_41                  # IAM checks.

# Fail CI if HIGH or CRITICAL findings.
checkov -d terraform/ --soft-fail-on LOW MEDIUM

# Output SARIF for GitHub Security tab.
checkov -d terraform/ --output sarif --output-file results.sarif
```

```yaml
# .github/workflows/iac-security-scan.yml
- name: Run Checkov
  uses: bridgecrewio/checkov-action@v12
  with:
    directory: terraform/
    framework: terraform
    soft_fail: true
    output_format: sarif
    output_file_path: checkov-results.sarif

- name: Upload to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: checkov-results.sarif
```

### Step 5: GCP Security Command Center

```bash
# Enable Security Command Center Standard tier.
gcloud scc settings update \
  --organization=ORG-ID \
  --enable-asset-discovery

# Enable built-in detectors.
gcloud scc sources list --organization=ORG-ID

# Export SCC findings to BigQuery for SIEM integration.
gcloud scc notifications create my-scc-notification \
  --organization=ORG-ID \
  --pubsub-topic=projects/PROJECT/topics/scc-notifications \
  --filter="state=ACTIVE AND severity=CRITICAL OR severity=HIGH"

# Subscribe and forward to your SIEM.
gcloud pubsub subscriptions create scc-siem-sub \
  --topic=projects/PROJECT/topics/scc-notifications \
  --push-endpoint=https://siem.internal/scc-ingest \
  --ack-deadline=60
```

Custom SCC findings via the Security Command Center API:

```python
from google.cloud import securitycenter

client = securitycenter.SecurityCenterClient()

def create_custom_finding(org_id: str, resource_name: str, description: str, severity: str):
    """Create a custom SCC finding for an organisation-specific policy violation."""
    source_name = f"organizations/{org_id}/sources/CUSTOM-SOURCE-ID"

    finding = {
        "state": securitycenter.Finding.State.ACTIVE,
        "resource_name": resource_name,
        "category": "CUSTOM_POSTURE_VIOLATION",
        "severity": getattr(securitycenter.Finding.Severity, severity),
        "description": description,
    }

    client.create_finding(
        request={
            "parent": source_name,
            "finding_id": f"custom-{hash(resource_name + description)}",
            "finding": finding,
        }
    )
```

### Step 6: Automated Remediation for Low-Risk Findings

For deterministic, low-risk misconfigurations, auto-remediate rather than page:

```python
# Auto-remediate: re-enable public access block on S3 buckets.
import boto3

def auto_remediate_s3_public_access(event, context):
    """Triggered by Config rule non-compliance event via EventBridge."""
    if event.get("detail", {}).get("newEvaluationResult", {}).get("complianceType") == "NON_COMPLIANT":
        bucket_name = event["detail"]["resourceId"]
        s3 = boto3.client("s3")

        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )

        # Log the auto-remediation.
        print(f"Auto-remediated: re-enabled public access block on s3://{bucket_name}")

        # Create a ticket for review even though it was auto-remediated.
        create_security_ticket(
            title=f"Auto-remediated: S3 public access block removed on {bucket_name}",
            body=f"A public access block was removed from s3://{bucket_name} and auto-remediated. Investigate who removed it and why.",
            priority="medium",
        )
```

Auto-remediation candidates (safe to automate):

- Re-enabling S3 public access block
- Re-enabling CloudTrail
- Removing security group rules allowing `0.0.0.0/0` on well-known vulnerable ports (3306, 5432, 27017)

Do NOT auto-remediate:

- IAM policy changes (may break legitimate access)
- KMS key policy changes (may cause data loss if key is deleted)
- Any change where the correct state is ambiguous

### Step 7: Telemetry

```
cspm_finding_total{severity, check, account, region}        counter
cspm_finding_open_total{severity, check, account}            gauge
cspm_finding_mean_age_hours{severity}                        gauge
cspm_finding_auto_remediated_total{check}                    counter
cspm_account_compliance_score{account, standard}             gauge (0-100)
iac_scan_violation_total{check, severity, repo}              counter
```

Alert on:

- `cspm_finding_total{severity="CRITICAL"}` — immediate review; critical misconfigurations must be addressed within SLA.
- `cspm_finding_mean_age_hours{severity="HIGH"}` > 168 (7 days) — findings are aging without action; escalate.
- `cspm_account_compliance_score` drops > 5 points — significant posture regression; investigate.
- `cspm_finding_total` for CloudTrail-disabled or S3-public-access-removed — always alert immediately; these are attack prerequisites.

## Expected Behaviour

| Signal | No CSPM | CSPM deployed |
|--------|---------|--------------|
| S3 bucket made public | Discovered by attacker or quarterly audit | Alert within 5–15 minutes of Config recording |
| Security group opened to 0.0.0.0/0 | Persists until found | Alert within next scan cycle; auto-remediation optional |
| New account with no controls | No visibility | Account appears in CSPM scope; flagged as non-compliant immediately |
| IaC Terraform changes with misconfig | Reaches cloud | Checkov blocks in CI; never applied |
| Cross-account compliance view | Per-account at best | Organization-wide dashboard via Security Hub / SCC |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Config in all regions | Full coverage | ~$0.003 per configuration item recorded (costs scale with resource count) | Use Config aggregator; consolidate storage in one account. |
| Auto-remediation | Zero-lag response to specific misconfigs | Risk of breaking legitimate unusual configurations | Only auto-remediate well-understood, deterministic misconfigurations; always create a review ticket. |
| Checkov in CI | Catches misconfigs before they reach cloud | False positives block legitimate infra changes | Tune Checkov check list; add skip annotations with justification for intentional exceptions. |
| Prowler daily scans | Comprehensive checks with CIS mapping | Scan takes 10–30 minutes depending on account size | Run full scan daily; run specific checks on PR for speed. |
| Commercial CSPM (Wiz/Orca) | Deeper context (attack paths, secrets in workloads) | Cost ($50k–$500k/year at scale) | Start with free tier (Prowler, Config, Security Hub); add commercial when organisation size justifies it. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Config recorder disabled | No change history; compliance checks stale | `cspm_finding_total` flat; Config console shows disabled | Re-enable; retroactive recording not possible — gap in history. |
| New account not onboarded | Account not in CSPM scope | Account appears in org but not in Security Hub aggregator | Automate account onboarding via AWS Control Tower or a custom Lambda on `CreateAccount` event. |
| Alert fatigue from low-severity findings | High-severity findings missed in noise | High-severity finding age growing despite alerts being sent | Implement priority-based routing; suppress low-severity findings or increase their threshold. |
| Auto-remediation breaks legitimate use | Service stops working after auto-remediation | Application error; ticket created by auto-remediator | Roll back the remediation; add an exception to the Config rule; investigate the original configuration intent. |
| Checkov false positive blocks deployment | CI fails; engineers add skip annotations without review | Increase in unannotated skips | Require security team review for any Checkov skip annotation on HIGH/CRITICAL rules. |
| Cross-account IAM role not deployed | Prowler cannot scan a specific account | Account missing from Prowler output | Automate IAM role deployment across all accounts via Organizations + CloudFormation StackSets. |

## Related Articles

- [Cloud Provider Audit Logs: CloudTrail, GCP, and Azure Monitor](/articles/observability/cloud-provider-audit-logs/)
- [Compliance as Code](/articles/cross-cutting/compliance-as-code/)
- [Multi-Cloud Hardening](/articles/cross-cutting/multi-cloud-hardening/)
- [Terraform Security](/articles/cicd/terraform-security/)
- [Hardening Scorecard](/articles/cross-cutting/hardening-scorecard/)
