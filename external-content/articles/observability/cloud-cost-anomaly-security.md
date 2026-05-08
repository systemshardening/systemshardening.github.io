---
title: "Cloud Cost Anomaly Detection as a Security Signal: Crypto Mining and Unauthorized Compute"
description: "Cost spikes are often the earliest observable indicator of a cloud compromise. Learn how to configure AWS, GCP, and Azure cost anomaly detection, correlate billing signals with security events, and automate quarantine responses."
slug: cloud-cost-anomaly-security
date: 2026-05-07
lastmod: 2026-05-07
category: observability
tags:
  - crypto-mining-detection
  - cloud-security
  - cost-anomaly
  - aws-cost-explorer
  - resource-monitoring
personas:
  - security-engineer
  - platform-engineer
article_number: 559
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/observability/cloud-cost-anomaly-security/
---

# Cloud Cost Anomaly Detection as a Security Signal: Crypto Mining and Unauthorized Compute

## Problem

Most cloud compromises generate a financial footprint before they generate a security alert. An attacker who steals AWS credentials and launches a fleet of GPU instances for crypto mining will show up on the billing dashboard within hours. The same is true for data exfiltration (egress bandwidth charges), credential abuse (API call volume charges), and unauthorised storage access (data retrieval fees from S3 Glacier or Coldline). Cost anomaly detection is a detection layer that security teams consistently under-use.

The specific failure modes:

- **Cost anomaly tools are treated as FinOps, not security.** AWS Cost Anomaly Detection alerts go to a cloud finance email address. No one on the security team sees them. By the time the bill is reviewed, the attacker has been mining for three weeks.
- **Billing data has no per-service or per-tag granularity in alerts.** A single threshold on total monthly spend misses an attacker who has taken over one service account while overall spending remains within normal ranges.
- **Cost signals are not correlated with IAM events.** A cost spike combined with a new IAM access key created in the same hour is a high-confidence compromise indicator. Neither signal in isolation is conclusive.
- **Resource quotas and limits are not monitored for violations.** Kubernetes resource quota violations and pod OOMKill events are early warnings that something is consuming more than it should.
- **No automated response exists for unexpected resource launches.** An EC2 instance launched in an unexpected region, in an unexpected instance family, with no associated deployment pipeline event should trigger immediate investigation, not a weekly cost review.

**Target systems:** AWS (Cost Anomaly Detection, CloudWatch, GuardDuty, Config, Lambda), GCP (Cloud Billing budget alerts, Cloud Monitoring), Azure (Cost Management + Billing, Azure Monitor), Kubernetes (resource quotas, LimitRanges, metrics-server).

## Threat Model

- **Adversary:** An attacker who has obtained valid cloud credentials (via phishing, leaked CI/CD secrets, SSRF against instance metadata, or compromised developer workstation) and uses them to launch compute resources for crypto mining or to exfiltrate large datasets.
- **Blast radius:** Crypto mining on GPU instances costs $2–$8 per GPU-hour. A single compromised credential launching 20 `p3.8xlarge` instances runs up $2,000–$8,000 per day. Data exfiltration of 10 TB via NAT gateway costs approximately $450 in transfer fees. Both attacks are detected by cost anomaly tools before most security scanners catch them, because the financial signal precedes log-based detection by hours.
- **What cost signals detect that other tools miss:** A miner running inside an existing authorised EC2 instance that was launched by a legitimate pipeline may not trigger GuardDuty's unusual instance launch finding. But it will exceed the CPU-hours billing baseline for that account. Cost anomaly detection catches the compute consumption even when the instance itself looks legitimate.

## Configuration

### AWS Cost Anomaly Detection

AWS Cost Anomaly Detection uses machine learning to establish a spending baseline and alerts when actual spend deviates from it. Configure monitors at the service level, not just total spend.

```bash
# Create a cost anomaly monitor for EC2 spending.
# Monitoring EC2 separately isolates compute abuse from unrelated cost changes.
aws ce create-anomaly-monitor \
  --anomaly-monitor '{
    "MonitorName": "EC2-Security-Monitor",
    "MonitorType": "DIMENSIONAL",
    "MonitorDimension": "SERVICE"
  }'

# Create an alert subscription that notifies the security team via SNS.
# Use a low threshold: $50 above expected is significant for a single service.
aws ce create-anomaly-subscription \
  --anomaly-subscription '{
    "SubscriptionName": "EC2-Security-Alert",
    "MonitorArnList": ["arn:aws:ce::123456789012:anomalymonitor/MONITOR_ID"],
    "Subscribers": [
      {
        "Address": "arn:aws:sns:us-east-1:123456789012:security-alerts",
        "Type": "SNS"
      }
    ],
    "Threshold": 50,
    "Frequency": "IMMEDIATE"
  }'
```

```bash
# Create per-linked-account monitors for organisations with multiple AWS accounts.
# This catches an attacker who compromises a dev account while prod spend looks normal.
aws ce create-anomaly-monitor \
  --anomaly-monitor '{
    "MonitorName": "Per-Account-Security-Monitor",
    "MonitorType": "DIMENSIONAL",
    "MonitorDimension": "LINKED_ACCOUNT"
  }'

# Separate monitor for data transfer costs (exfiltration signal).
aws ce create-anomaly-monitor \
  --anomaly-monitor '{
    "MonitorName": "DataTransfer-Security-Monitor",
    "MonitorType": "DIMENSIONAL",
    "MonitorDimension": "SERVICE"
  }'
# Associate this monitor with a subscription that filters on "AWS Data Transfer" service.
```

Tag-based monitors give per-team and per-service cost visibility, which is the baseline for detecting anomalies in a single service account:

```bash
# Create a monitor scoped to a specific cost allocation tag.
# Assumes tags like: Environment=production, Team=platform
aws ce create-anomaly-monitor \
  --anomaly-monitor '{
    "MonitorName": "Production-Platform-Monitor",
    "MonitorType": "CUSTOM",
    "MonitorSpecification": {
      "Tags": {
        "Key": "Team",
        "Values": ["platform"],
        "MatchOptions": ["EQUALS"]
      }
    }
  }'
```

The SNS topic receiving anomaly alerts should deliver to both the finance distribution list and the security team's alert channel. Use an SNS subscription filter to route by alert type if your security team uses a separate topic:

```bash
# Route Cost Anomaly SNS messages to the security SIEM or Slack webhook.
aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:123456789012:security-alerts \
  --protocol https \
  --notification-endpoint https://your-siem.example.com/webhooks/aws-cost-anomaly
```

### CloudWatch Alarms: CPU and GPU Utilisation as a Crypto Mining Signal

EC2 CPU utilisation sustained at 95–100% for extended periods is a reliable crypto mining signal when it occurs on instance types not associated with known compute workloads.

```bash
# CloudWatch alarm: sustained high CPU on EC2 instances tagged as application servers.
# Mining on an app server is unexpected. ML training on a GPU fleet is not.
aws cloudwatch put-metric-alarm \
  --alarm-name "Sustained-High-CPU-AppServer" \
  --alarm-description "EC2 CPU >90% for 60 minutes on non-compute instance — crypto mining signal" \
  --namespace "AWS/EC2" \
  --metric-name "CPUUtilization" \
  --dimensions Name=AutoScalingGroupName,Value=app-server-asg \
  --statistic Average \
  --period 300 \
  --evaluation-periods 12 \
  --threshold 90 \
  --comparison-operator GreaterThanThreshold \
  --alarm-actions arn:aws:sns:us-east-1:123456789012:security-alerts \
  --treat-missing-data notBreaching
```

For GPU instances, monitor `gpu_memory_used_percent` and `gpu_memory_utilization` via the CloudWatch Agent with NVIDIA DCGM integration. A `p3` or `g4` instance at 100% GPU utilisation that was not launched by a known ML pipeline is a high-confidence mining indicator:

```json
{
  "metrics": {
    "namespace": "CWAgent",
    "metrics_collected": {
      "nvidia_gpu": {
        "measurement": [
          "utilization_gpu",
          "utilization_memory",
          "power_draw"
        ],
        "metrics_collection_interval": 60
      }
    }
  }
}
```

```bash
# Alarm on GPU utilisation above 80% for instances not tagged as ml-workload.
# Requires metric math to filter by tag — use a Lambda to check instance tags on alarm.
aws cloudwatch put-metric-alarm \
  --alarm-name "Unexpected-GPU-Utilization" \
  --alarm-description "GPU >80% on instance not tagged ml-workload — mining signal" \
  --namespace "CWAgent" \
  --metric-name "utilization_gpu" \
  --statistic Average \
  --period 300 \
  --evaluation-periods 6 \
  --threshold 80 \
  --comparison-operator GreaterThanThreshold \
  --alarm-actions arn:aws:sns:us-east-1:123456789012:security-alerts
```

### GCP Cost Anomaly Alerts

GCP Cloud Billing budget alerts are simpler to configure but effective. Create budgets at the project level and by service:

```bash
# Create a billing budget for a project with 50% and 100% threshold alerts.
# Route alerts to a Pub/Sub topic consumed by your security tooling.
gcloud billing budgets create \
  --billing-account=BILLING_ACCOUNT_ID \
  --display-name="compute-project-security-budget" \
  --budget-amount=1000USD \
  --threshold-rule=percent=0.5,basis=CURRENT_SPEND \
  --threshold-rule=percent=1.0,basis=CURRENT_SPEND \
  --filter-projects=projects/PROJECT_ID \
  --filter-services=services/6F81-5844-456A \
  --notifications-rule-pubsub-topic=projects/PROJECT_ID/topics/billing-security-alerts \
  --notifications-rule-disable-default-iam-recipients
```

For anomaly detection beyond fixed budgets, enable GCP Recommender and Cost Anomaly Insights:

```bash
# List cost anomaly insights for a billing account.
# Integrate this into a daily security review pipeline.
gcloud recommender insights list \
  --project=PROJECT_ID \
  --location=global \
  --insight-type=google.billing.CostInsight \
  --filter="stateInfo.state=ACTIVE" \
  --format="json"
```

The output includes `anomalyDetails` with affected services, timestamps, and magnitude. Pipe this to your SIEM or a Cloud Function that correlates it with Cloud Audit Logs for the same time window.

### Azure Cost Management Anomaly Detection

Azure Cost Management includes built-in anomaly detection at the subscription and resource group level. Configure alert rules via Azure CLI:

```bash
# Create a cost alert for a resource group with a $200 threshold.
az consumption budget create \
  --budget-name "rg-security-budget" \
  --amount 500 \
  --time-grain Monthly \
  --time-period start=2026-05-01 \
  --resource-group my-resource-group \
  --notification key=actual_GreaterThan_50_Percent \
      enabled=true \
      operator=GreaterThan \
      threshold=50 \
      contact-emails security-team@example.com \
      contact-roles Owner,Contributor \
  --notification key=actual_GreaterThan_90_Percent \
      enabled=true \
      operator=GreaterThan \
      threshold=90 \
      contact-emails security-team@example.com
```

Enable anomaly detection in Azure Cost Management by navigating to Cost Alerts > Anomaly Alerts, or via ARM template. Azure's anomaly detection uses ML to detect spend deviations beyond what static thresholds catch — enable it at the subscription scope so it covers all resource groups.

For VM-level CPU monitoring equivalent to the AWS setup:

```bash
# Create an Azure Monitor alert for sustained high CPU on VMs not in a known scale set.
az monitor metrics alert create \
  --name "Unexpected-High-CPU-VM" \
  --resource-group my-resource-group \
  --scopes /subscriptions/SUBSCRIPTION_ID/resourceGroups/my-resource-group \
  --condition "avg Percentage CPU > 90" \
  --window-size 1h \
  --evaluation-frequency 5m \
  --action my-security-action-group \
  --description "VM CPU >90% for 1 hour — crypto mining signal"
```

### Detecting Unauthorised EC2 Instance Launches

GuardDuty finding `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` and `Recon:EC2/PortProbeUnprotectedPort` are useful but not sufficient. Add Config rules to detect instance launches in unexpected regions or of unexpected instance types:

```json
{
  "ConfigRuleName": "restricted-instance-types",
  "Description": "Flag EC2 instances of GPU or high-compute types not approved by the platform team.",
  "Source": {
    "Owner": "CUSTOM_LAMBDA",
    "SourceIdentifier": "arn:aws:lambda:us-east-1:123456789012:function:check-instance-type",
    "SourceDetails": [
      {
        "EventSource": "aws.config",
        "MessageType": "ConfigurationItemChangeNotification"
      }
    ]
  },
  "Scope": {
    "ComplianceResourceTypes": ["AWS::EC2::Instance"]
  }
}
```

```python
# Lambda function for the Config rule above.
# Flags p2, p3, p4, g4, g5 instance types launched outside the ml-workloads account.

import boto3
import json

APPROVED_GPU_ACCOUNT = "111122223333"
GPU_INSTANCE_FAMILIES = {"p2", "p3", "p4d", "p4de", "g4dn", "g4ad", "g5", "g5g"}

def lambda_handler(event, context):
    config = boto3.client("config")
    invoking_event = json.loads(event["invokingEvent"])
    ci = invoking_event.get("configurationItem", {})

    if ci.get("resourceType") != "AWS::EC2::Instance":
        return build_evaluation("NOT_APPLICABLE", ci, event)

    instance_type = ci.get("configuration", {}).get("instanceType", "")
    instance_family = instance_type.split(".")[0]
    account_id = ci.get("awsAccountId", "")

    if instance_family in GPU_INSTANCE_FAMILIES and account_id != APPROVED_GPU_ACCOUNT:
        return build_evaluation(
            "NON_COMPLIANT",
            ci,
            event,
            annotation=f"GPU instance {instance_type} launched outside approved account"
        )

    return build_evaluation("COMPLIANT", ci, event)

def build_evaluation(compliance_type, ci, event, annotation=""):
    return {
        "ComplianceResourceType": ci["resourceType"],
        "ComplianceResourceId": ci["resourceId"],
        "ComplianceType": compliance_type,
        "Annotation": annotation,
        "OrderingTimestamp": ci["configurationItemCaptureTime"]
    }
```

Also configure a CloudWatch Events rule to detect instance launches in unexpected regions directly, without waiting for Config evaluation:

```bash
# EventBridge rule: trigger on EC2 RunInstances in any region except approved ones.
aws events put-rule \
  --name "EC2-Launch-Unexpected-Region" \
  --event-pattern '{
    "source": ["aws.ec2"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventName": ["RunInstances"],
      "awsRegion": [{
        "anything-but": ["us-east-1", "us-west-2", "eu-west-1"]
      }]
    }
  }' \
  --state ENABLED

aws events put-targets \
  --rule EC2-Launch-Unexpected-Region \
  --targets Id=SecuritySNS,Arn=arn:aws:sns:us-east-1:123456789012:security-alerts
```

### Kubernetes Resource Quota Violations as Early Warning

Kubernetes resource quotas limit the total compute a namespace can consume. A pod that repeatedly hits `OOMKilled` or a namespace that has exhausted its CPU quota unexpectedly is an early warning of resource abuse:

```yaml
# ResourceQuota: enforce per-namespace CPU and memory limits.
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: production
spec:
  hard:
    requests.cpu: "40"
    requests.memory: 80Gi
    limits.cpu: "80"
    limits.memory: 160Gi
    pods: "50"
---
# LimitRange: require every container to declare resource requests and limits.
# Prevents miners from running as limit-free containers that consume unlimited CPU.
apiVersion: v1
kind: LimitRange
metadata:
  name: container-limits
  namespace: production
spec:
  limits:
    - type: Container
      default:
        cpu: 500m
        memory: 512Mi
      defaultRequest:
        cpu: 100m
        memory: 128Mi
      max:
        cpu: "4"
        memory: 8Gi
```

Monitor quota usage with Prometheus and alert before saturation (which is where misbehaving workloads surface):

```yaml
groups:
  - name: resource-quota-security
    rules:
      # Alert when a namespace uses >90% of its CPU quota unexpectedly.
      - alert: NamespaceCPUQuotaExhaustion
        expr: >
          kube_resourcequota{resource="limits.cpu", type="used"}
          /
          kube_resourcequota{resource="limits.cpu", type="hard"}
          > 0.9
        for: 10m
        labels:
          severity: warning
          detection_type: resource_abuse
        annotations:
          summary: >
            Namespace {{ $labels.namespace }} CPU quota at
            {{ $value | humanizePercentage }} — investigate for unexpected workloads

      # Alert on sustained container CPU throttling (container hitting its limit constantly).
      # Normal workloads are throttled occasionally; a miner is throttled continuously.
      - alert: ContinuousCPUThrottling
        expr: >
          rate(container_cpu_cfs_throttled_seconds_total[5m])
          /
          rate(container_cpu_cfs_periods_total[5m])
          > 0.95
        for: 20m
        labels:
          severity: warning
          detection_type: resource_abuse
        annotations:
          summary: >
            Container {{ $labels.container }} in {{ $labels.namespace }}/{{ $labels.pod }}
            is CPU-throttled 95%+ of the time — hitting resource limit
```

### Correlating Cost Alerts with Security Events

A cost anomaly in isolation is low-confidence. A cost anomaly correlated with a concurrent security event is high-confidence. The two most important correlations to automate:

**Correlation 1: Cost spike + new IAM access key creation**

An attacker who steals credentials often creates a new access key immediately after gaining access, then uses it to launch resources. CloudTrail logs `CreateAccessKey` events. If a `CreateAccessKey` event and an EC2 cost anomaly occur within the same 4-hour window for the same account, treat it as a confirmed compromise:

```python
# Lambda function invoked by Cost Anomaly SNS alert.
# Checks CloudTrail for suspicious IAM events in the preceding 4 hours.

import boto3
from datetime import datetime, timedelta, timezone

def lambda_handler(event, context):
    sns_message = event["Records"][0]["Sns"]["Message"]
    anomaly_account = extract_account_from_anomaly(sns_message)
    anomaly_time = datetime.now(timezone.utc)

    cloudtrail = boto3.client("cloudtrail")
    iam_events = cloudtrail.lookup_events(
        LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "CreateAccessKey"}],
        StartTime=anomaly_time - timedelta(hours=4),
        EndTime=anomaly_time,
    )

    if iam_events["Events"]:
        # High-confidence compromise indicator: cost spike + new access key
        sns = boto3.client("sns")
        for iam_event in iam_events["Events"]:
            sns.publish(
                TopicArn="arn:aws:sns:us-east-1:123456789012:security-critical",
                Subject="HIGH CONFIDENCE: Cost anomaly + IAM key creation — likely compromise",
                Message=(
                    f"Cost anomaly detected in account {anomaly_account}.\n"
                    f"IAM key created at: {iam_event['EventTime']}\n"
                    f"By principal: {iam_event['Username']}\n"
                    f"Action required: rotate credentials, audit launched instances."
                ),
            )

def extract_account_from_anomaly(message):
    # Parse account ID from Cost Anomaly Detection SNS message JSON.
    import json
    data = json.loads(message)
    return data.get("accountId", "unknown")
```

**Correlation 2: Cost spike in unexpected region + GuardDuty finding**

```bash
# EventBridge rule: correlate GuardDuty findings with cost anomaly SNS.
# When GuardDuty fires UnauthorizedAccess findings, enrich with cost data.
aws events put-rule \
  --name "GuardDuty-Cost-Correlation" \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "type": [
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
        "CryptoCurrency:EC2/BitcoinTool.B",
        "CryptoCurrency:EC2/BitcoinTool.B!DNS"
      ]
    }
  }' \
  --state ENABLED
```

### Automated Response: Lambda Quarantine for Suspicious Instances

When a cost anomaly correlates with an unexpected instance launch, an automated quarantine response limits the blast radius while preserving forensic evidence:

```python
# Lambda function: quarantine a suspicious EC2 instance.
# Called by the cost-anomaly + IAM event correlation function, or directly by GuardDuty.
# Quarantine = isolate network access + take EBS snapshot + tag for investigation.

import boto3
import json
from datetime import datetime, timezone

ec2 = boto3.client("ec2")

def quarantine_instance(instance_id: str, reason: str) -> dict:
    """
    Quarantine a suspicious EC2 instance by:
    1. Replacing its security groups with an isolation group (no inbound or outbound).
    2. Snapshotting all attached EBS volumes for forensics.
    3. Tagging the instance as quarantined to prevent automated remediation re-launching it.
    Does NOT terminate the instance — preserves volatile memory evidence.
    """
    isolation_sg_id = get_or_create_isolation_sg(instance_id)

    # Step 1: Replace security groups with the isolation group.
    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[isolation_sg_id],
    )

    # Step 2: Snapshot EBS volumes.
    volumes = ec2.describe_instance_attribute(
        InstanceId=instance_id,
        Attribute="blockDeviceMapping",
    )["BlockDeviceMappings"]

    snapshot_ids = []
    for bdm in volumes:
        volume_id = bdm["Ebs"]["VolumeId"]
        snap = ec2.create_snapshot(
            VolumeId=volume_id,
            Description=f"Forensic snapshot: quarantine of {instance_id} at {datetime.now(timezone.utc).isoformat()}",
            TagSpecifications=[{
                "ResourceType": "snapshot",
                "Tags": [
                    {"Key": "SecurityEvent", "Value": "quarantine"},
                    {"Key": "SourceInstance", "Value": instance_id},
                    {"Key": "Reason", "Value": reason},
                ],
            }],
        )
        snapshot_ids.append(snap["SnapshotId"])

    # Step 3: Tag the instance.
    ec2.create_tags(
        Resources=[instance_id],
        Tags=[
            {"Key": "SecurityStatus", "Value": "quarantined"},
            {"Key": "QuarantineReason", "Value": reason},
            {"Key": "QuarantineTime", "Value": datetime.now(timezone.utc).isoformat()},
            {"Key": "ForensicSnapshots", "Value": json.dumps(snapshot_ids)},
        ],
    )

    return {"instance_id": instance_id, "isolation_sg": isolation_sg_id, "snapshots": snapshot_ids}


def get_or_create_isolation_sg(instance_id: str) -> str:
    """Return the ID of the isolation security group, creating it if it does not exist."""
    vpc_id = ec2.describe_instances(
        InstanceIds=[instance_id]
    )["Reservations"][0]["Instances"][0]["VpcId"]

    existing = ec2.describe_security_groups(
        Filters=[
            {"Name": "group-name", "Values": ["isolation-no-traffic"]},
            {"Name": "vpc-id", "Values": [vpc_id]},
        ]
    )["SecurityGroups"]

    if existing:
        return existing[0]["GroupId"]

    sg = ec2.create_security_group(
        GroupName="isolation-no-traffic",
        Description="Isolation group: no inbound or outbound traffic. For quarantined instances.",
        VpcId=vpc_id,
    )

    # Remove the default allow-all-outbound rule.
    ec2.revoke_security_group_egress(
        GroupId=sg["GroupId"],
        IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )

    return sg["GroupId"]


def lambda_handler(event, context):
    instance_id = event.get("instance_id")
    reason = event.get("reason", "cost-anomaly-security-response")
    result = quarantine_instance(instance_id, reason)
    print(f"Quarantine complete: {result}")
    return result
```

## Establishing Cost Baselines Per Team and Service

Cost anomaly detection only works if your baseline is granular enough to detect deviations at the service level. A $10,000 spike in a $1,000,000/month account is invisible if you monitor only total spend.

Required tagging strategy for effective cost security monitoring:

```bash
# Enforce tagging via AWS Config managed rule: required-tags.
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "required-tags-for-ec2",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "REQUIRED_TAGS"
    },
    "Scope": {
      "ComplianceResourceTypes": ["AWS::EC2::Instance", "AWS::ECS::TaskDefinition"]
    },
    "InputParameters": "{\"tag1Key\":\"Team\",\"tag2Key\":\"Environment\",\"tag3Key\":\"Service\"}"
  }'
```

Untagged instances are themselves a security signal — a miner launched by an attacker will not follow your tagging conventions. A Config rule that flags untagged instances will catch many unauthorised launches independently of cost monitoring.

## Expected Behaviour

- Cost Anomaly Detection alerts reach the security team within 2–6 hours of anomaly onset (AWS ML evaluation cadence)
- EventBridge rules for `RunInstances` in unexpected regions trigger within seconds of the API call
- GuardDuty `CryptoCurrency:EC2/BitcoinTool.B!DNS` findings trigger within minutes of mining pool DNS queries
- Correlation Lambda fires on cost anomaly SNS and enriches with CloudTrail IAM events from the preceding 4 hours
- Quarantine Lambda isolates suspicious instance network, takes forensic EBS snapshots, and tags for investigation — without terminating the instance
- Kubernetes resource quota alerts fire when namespace CPU usage exceeds 90% of quota for 10 minutes
- Untagged EC2 instance Config rule non-compliance triggers within 15 minutes of instance launch

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| AWS Cost Anomaly Detection $50 threshold | Catches significant but not trivial anomalies quickly | A slowly growing miner (gradual ramp-up) may stay under threshold for days | Combine with CloudWatch CPU alarms that do not depend on billing data. Cost anomaly detection is a backstop, not the primary signal. |
| Quarantine without termination | Preserves volatile memory and EBS for forensics | Instance continues to consume cost during investigation window | Set a CloudWatch alarm to notify if quarantined instance runs >4 hours. Terminate after forensic collection completes. |
| Config rule for GPU instance types | Catches lateral moves to GPU instances immediately | Legitimate ML workloads in unexpected accounts trigger false positives | Maintain an approved-account list in the Config rule Lambda. Update it as ML workloads expand to new accounts. |
| Correlating cost + IAM events in a 4-hour window | High confidence for fast-moving attackers | Slow-moving attackers create the key days before launching instances | Extend the CloudTrail lookback to 48 hours for CreateAccessKey events. Wider window = more false positives; tune based on your IAM key rotation frequency. |
| Kubernetes LimitRange defaults | Every container gets limits automatically, preventing unlimited mining | A legitimate high-CPU batch job may be throttled by default limits | Use a separate namespace with higher limits for batch workloads. Apply stricter LimitRange to user-facing application namespaces only. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Miner launched in a new, unmonitored AWS account | No Cost Anomaly monitor exists for the account | Monthly billing review shows unexpected charges from a linked account | Enable organisational Cost Anomaly monitors at the AWS Organizations level so all linked accounts are covered automatically. |
| Attacker stays under cost threshold by using reserved instance capacity | Miner runs on pre-paid Reserved Instances; no incremental cost spike | No cost anomaly fires; only CPU metrics reveal mining | CPU-based alarms are essential. Cost anomaly detection alone is insufficient if the attacker has access to Reserved Instance capacity. |
| Tags missing from attacker-launched instances | Cost anomaly detected but cannot identify which team or service is affected | Config untagged-instance rule fires; investigation is slower | Enforce tagging via Service Control Policies (SCPs) so that `RunInstances` without required tags is denied in production accounts. |
| Quarantine Lambda has insufficient IAM permissions | Lambda cannot modify security groups or create snapshots | Lambda error in CloudWatch Logs; instance not quarantined | Pre-test quarantine Lambda monthly in a non-production account using a safe test instance. Include Lambda execution errors in security alert routing. |
| GCP cost anomaly insight is stale | Insight API returns yesterday's data; current mining is not reflected | Real-time CPU metrics via Cloud Monitoring show the spike before billing does | Use Cloud Monitoring VM CPU utilisation alerts as the primary real-time signal. Budget alerts and cost insights are confirmatory signals, not the first detector. |

## Related Articles

- [Crypto Mining Detection: CPU Patterns, Network Signatures, and Automated Response](/articles/observability/crypto-mining-detection/)
- [Cloud Provider Audit Logs: CloudTrail, GCP Audit Logs, and Azure Monitor Hardening](/articles/observability/cloud-provider-audit-logs/)
- [Data Exfiltration Detection: Network Egress Monitoring, DLP Integration, and Alert Correlation](/articles/observability/data-exfiltration-detection/)
- [User Behaviour Analytics: Detecting Insider Threats and Compromised Accounts](/articles/observability/user-behavior-analytics/)
- [Alert Correlation: Combining Low-Fidelity Signals into High-Confidence Incidents](/articles/observability/alert-correlation/)
