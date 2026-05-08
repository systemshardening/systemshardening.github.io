---
title: "Cloud Provider Audit Logs: CloudTrail, GCP Audit Logs, and Azure Monitor Hardening"
description: "Cloud audit logs are your primary evidence source for privilege escalation, data exfiltration, and lateral movement at the cloud control plane. They require active hardening to be tamper-proof and queryable."
slug: "cloud-provider-audit-logs"
date: 2026-04-30
lastmod: 2026-04-30
category: "observability"
tags: ["cloudtrail", "gcp-audit", "azure-monitor", "cloud", "audit-logs"]
personas: ["security-engineer", "sre", "platform-engineer"]
article_number: 251
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/observability/cloud-provider-audit-logs/index.html"
---

# Cloud Provider Audit Logs: CloudTrail, GCP Audit Logs, and Azure Monitor Hardening

## Problem

Cloud providers generate detailed audit logs of every API call: who created the S3 bucket, who assumed the role, who deleted the database snapshot, who changed the security group rule. These logs are the primary evidence source for cloud-layer incidents.

In practice, they are frequently misconfigured:

- **CloudTrail disabled for some regions.** CloudTrail by default logs only the region it's enabled in. Global services (IAM, STS, Route 53) require explicit configuration. An attacker operating in `ap-southeast-1` while CloudTrail is only configured for `us-east-1` leaves no trail.
- **Logs stored in the same account.** An attacker with IAM privileges can delete CloudTrail logs, disable CloudTrail, or simply wait for the default 90-day retention to expire. Logs in the same account are not tamper-proof.
- **No integrity validation.** CloudTrail supports log file integrity validation (SHA-256 hash chain). Without it, a sophisticated attacker who modifies log files cannot be detected.
- **GCP audit logs with admin activity disabled.** GCP's data access audit logs are disabled by default (chargeable); admin activity logs are free but sometimes selectively disabled.
- **Azure diagnostic settings not configured for all subscriptions.** Each Azure subscription requires its own diagnostic setting routing logs to a Log Analytics Workspace or Storage Account.
- **No alerting on high-value events.** Logs are stored but no alerts fire when root credentials are used, when CloudTrail is disabled, when IAM policies are attached to users, or when unusual API call patterns appear.

**Target systems:** AWS CloudTrail (multi-region, organisational trail); GCP Cloud Audit Logs (admin activity + data access); Azure Monitor (activity logs + diagnostic settings); Security Lake / Splunk / Elastic for aggregation.

## Threat Model

- **Adversary 1 — CloudTrail disable-and-attack:** An attacker with sufficient IAM privileges disables CloudTrail, performs their attack, then re-enables it. Without cross-account log aggregation or integrity validation, the gap in logs goes undetected.
- **Adversary 2 — Log bucket deletion:** An attacker deletes the S3 bucket receiving CloudTrail logs or empties it. Evidence of prior actions is destroyed.
- **Adversary 3 — Privilege escalation via IAM:** An attacker assumes a role, attaches an admin policy to their user, and escalates to full account control. Without alerting on IAM policy attachment, the escalation goes unnoticed until the blast radius expands.
- **Adversary 4 — Cross-region blind spot:** An attacker creates resources in a region where CloudTrail isn't enabled. Lateral movement or exfiltration from that region leaves no trail.
- **Adversary 5 — Root account use:** Root account credentials are used to perform actions that bypass SCPs and permission boundaries. Without a root account usage alert, this is discovered only retrospectively.
- **Access level:** Adversaries 1 and 2 need IAM privileges to modify CloudTrail and S3. Adversaries 3 and 5 need initial IAM credentials. Adversary 4 needs any IAM credentials with cross-region access.
- **Objective:** Cover tracks after intrusion, escalate privileges undetected, exfiltrate data without evidence.
- **Blast radius:** CloudTrail disabled for 24 hours = 24 hours of unlogged API activity. Without cross-account logs, that window is lost permanently. With immutable cross-account storage, the gap is visible and bounded.

## Configuration

### Step 1: AWS — Organisational CloudTrail (Multi-Region)

Create a single trail at the AWS Organizations level, covering all accounts and all regions:

```bash
# Create an S3 bucket in a dedicated security log account (separate from workload accounts).
# This bucket is the tamper-resistant destination.

# In the security/audit account:
aws s3api create-bucket \
  --bucket org-cloudtrail-logs-$(aws sts get-caller-identity --query Account --output text) \
  --region us-east-1

# Apply Object Lock for immutability (WORM: Write Once Read Many).
aws s3api put-object-lock-configuration \
  --bucket org-cloudtrail-logs-<security-account-id> \
  --object-lock-configuration \
    'ObjectLockEnabled=Enabled,Rule={DefaultRetention={Mode=GOVERNANCE,Days=365}}'

# In the management/root account:
aws cloudtrail create-trail \
  --name org-trail \
  --s3-bucket-name org-cloudtrail-logs-<security-account-id> \
  --is-multi-region-trail \
  --include-global-service-events \
  --enable-log-file-validation \   # SHA-256 integrity chain.
  --is-organization-trail          # Covers all member accounts.

# Enable the trail.
aws cloudtrail start-logging --name org-trail

# Enable CloudWatch Logs integration for real-time alerting.
aws cloudtrail update-trail \
  --name org-trail \
  --cloud-watch-logs-log-group-arn arn:aws:logs:us-east-1:<security-account>:log-group:cloudtrail \
  --cloud-watch-logs-role-arn arn:aws:iam::<security-account>:role/CloudTrailToCloudWatch
```

Verify integrity validation is working:

```bash
# Validate log file integrity for the last 24 hours.
aws cloudtrail validate-logs \
  --trail-arn arn:aws:cloudtrail:us-east-1:<account>:trail/org-trail \
  --start-time $(date -d '24 hours ago' --iso-8601=seconds) \
  --end-time $(date --iso-8601=seconds)
# Output: "Log files from <time> to <time> validated. N valid log files and 0 invalid log files."
```

### Step 2: AWS — Critical Event Alerts via CloudWatch

Alert on high-value events using CloudWatch metric filters:

```bash
# Create metric filters on the CloudTrail log group.

# Alert: CloudTrail disabled.
aws cloudwatch put-metric-alarm \
  --alarm-name "CloudTrail-Disabled" \
  --metric-name "CloudTrailDisabled" \
  --namespace "Security/CloudTrail" \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions arn:aws:sns:us-east-1:<account>:security-alerts
```

Metric filter patterns for high-value events:

```bash
# Publish these as CloudFormation or Terraform for reproducibility.

FILTERS=(
  # CloudTrail disabled.
  '{ ($.eventName = "StopLogging") }'
  'CloudTrailDisabled'

  # Root account used.
  '{ ($.userIdentity.type = "Root") && ($.userIdentity.invokedBy NOT EXISTS) && ($.eventType != "AwsServiceEvent") }'
  'RootAccountUsed'

  # IAM admin policy attached.
  '{ ($.eventName = "AttachUserPolicy" || $.eventName = "AttachRolePolicy") && ($.requestParameters.policyArn = "arn:aws:iam::aws:policy/AdministratorAccess") }'
  'AdminPolicyAttached'

  # S3 bucket ACL set to public.
  '{ ($.eventName = "PutBucketAcl") && ($.requestParameters.AccessControlPolicy.AccessControlList.Grant[*].Grantee.URI = "*") }'
  'S3BucketMadePublic'

  # Security group opened to 0.0.0.0/0.
  '{ ($.eventName = "AuthorizeSecurityGroupIngress") && ($.requestParameters.ipPermissions.items[*].ipRanges.items[*].cidrIp = "0.0.0.0/0") }'
  'SecurityGroupOpenToInternet'

  # Console login failures.
  '{ ($.eventName = "ConsoleLogin") && ($.errorMessage = "Failed authentication") }'
  'ConsoleLoginFailure'
)

for ((i=0; i<${#FILTERS[@]}; i+=2)); do
  aws logs put-metric-filter \
    --log-group-name cloudtrail \
    --filter-name "${FILTERS[$i+1]}" \
    --filter-pattern "${FILTERS[$i]}" \
    --metric-transformations metricName="${FILTERS[$i+1]}",metricNamespace="Security/CloudTrail",metricValue=1
done
```

### Step 3: GCP — Enable All Audit Log Types

GCP has three audit log types: Admin Activity (always on, free), Data Access (off by default, chargeable), System Event (always on). Enable Data Access for sensitive services:

```bash
# Enable data access logs for all services (use IAM audit config).
gcloud resource-manager org-policies set-policy - <<'EOF'
name: organizations/<org-id>/policies/gcp.resourcemanager.organizationPolicy
spec:
  rules:
    - enforce: true
EOF

# Set audit log configuration via gcloud (or Terraform).
gcloud projects get-iam-policy <project-id> --format json | \
  jq '.auditConfigs += [
    {
      "service": "allServices",
      "auditLogConfigs": [
        {"logType": "ADMIN_READ"},
        {"logType": "DATA_READ"},
        {"logType": "DATA_WRITE"}
      ]
    }
  ]' > policy-with-audit.json

gcloud projects set-iam-policy <project-id> policy-with-audit.json
```

Export audit logs to a SIEM-accessible destination:

```bash
# Create a log sink to BigQuery for long-term analysis.
gcloud logging sinks create security-audit-sink \
  bigquery.googleapis.com/projects/<project>/datasets/security_audit_logs \
  --log-filter='logName:"cloudaudit.googleapis.com"' \
  --include-children \
  --organization=<org-id>

# Create a log sink to Pub/Sub for real-time alerting.
gcloud logging sinks create security-alert-sink \
  pubsub.googleapis.com/projects/<project>/topics/security-alerts \
  --log-filter='protoPayload.methodName=("SetIamPolicy" OR "CreateServiceAccount" OR "DeleteServiceAccount")' \
  --organization=<org-id>
```

GCP alert policy for privilege escalation:

```bash
gcloud alpha monitoring policies create --policy-from-file=- <<'EOF'
{
  "displayName": "IAM Policy Change Alert",
  "conditions": [
    {
      "displayName": "SetIamPolicy called",
      "conditionMatchedLog": {
        "filter": "protoPayload.methodName=\"SetIamPolicy\" AND protoPayload.serviceData.policyDelta.bindingDeltas.action=\"ADD\" AND protoPayload.serviceData.policyDelta.bindingDeltas.role=\"roles/owner\""
      }
    }
  ],
  "alertStrategy": {"autoClose": "604800s"},
  "notificationChannels": ["projects/<project>/notificationChannels/<channel-id>"]
}
EOF
```

### Step 4: Azure — Diagnostic Settings Across All Subscriptions

Azure activity logs capture all control-plane operations. Route them to a central Log Analytics Workspace:

```bash
# Create a central Log Analytics Workspace in the security subscription.
az monitor log-analytics workspace create \
  --resource-group security-rg \
  --workspace-name org-security-logs \
  --location eastus \
  --retention-time 365

WORKSPACE_ID=$(az monitor log-analytics workspace show \
  --resource-group security-rg \
  --workspace-name org-security-logs \
  --query id --output tsv)

# Create a diagnostic setting for each subscription.
az monitor diagnostic-settings create \
  --name "activity-log-to-central" \
  --resource "/subscriptions/<subscription-id>" \
  --workspace $WORKSPACE_ID \
  --logs '[{"category": "Administrative", "enabled": true},
           {"category": "Security", "enabled": true},
           {"category": "ServiceHealth", "enabled": true},
           {"category": "Alert", "enabled": true},
           {"category": "Policy", "enabled": true}]'
```

For large organisations, use Azure Policy to enforce diagnostic settings on all subscriptions:

```json
{
  "if": {
    "field": "type",
    "equals": "Microsoft.Resources/subscriptions"
  },
  "then": {
    "effect": "deployIfNotExists",
    "details": {
      "type": "Microsoft.Insights/diagnosticSettings",
      "deploymentScope": "subscription",
      "existenceCondition": {
        "field": "Microsoft.Insights/diagnosticSettings/workspaceId",
        "equals": "<workspace-resource-id>"
      },
      "deployment": { ... }
    }
  }
}
```

Azure Sentinel alert rule for role assignment:

```kql
// KQL query: alert when Owner or Contributor role is assigned.
AzureActivity
| where OperationNameValue == "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
| where ActivityStatusValue == "Success"
| extend RoleDefinitionId = tostring(parse_json(tostring(parse_json(Properties).requestbody)).RoleDefinitionId)
| where RoleDefinitionId contains "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"   // Owner
    or RoleDefinitionId contains "b24988ac-6180-42a0-ab88-20f7382dd24c"   // Contributor
| project TimeGenerated, Caller, OperationNameValue, RoleDefinitionId, ResourceGroup
```

### Step 5: Cross-Cloud Log Aggregation

Route all cloud audit logs to a single SIEM for cross-cloud correlation:

```bash
# Using AWS Security Lake (OCSF-normalised, cross-cloud).
aws securitylake create-data-lake \
  --configurations '[{
    "region": "us-east-1",
    "encryptionConfiguration": {
      "kmsKeyId": "arn:aws:kms:us-east-1:<account>:key/<key-id>"
    },
    "lifecycleConfiguration": {
      "transitions": [{"days": 60, "storageClass": "ONEZONE_IA"}],
      "expiration": {"days": 365}
    }
  }]' \
  --meta-store-manager-role-arn arn:aws:iam::<account>:role/SecurityLakeMetaStoreManager

# Add GCP source to Security Lake via a custom source.
aws securitylake create-custom-log-source \
  --source-name GCPAuditLogs \
  --configuration '{"crawlerConfiguration":{"roleArn":"..."}, "providerIdentity":{"externalId":"...","principal":"..."}}'
```

Alternatively, stream all providers to an Elasticsearch / OpenSearch cluster:

```bash
# Logstash pipeline: ingest from CloudTrail S3, GCP Pub/Sub, Azure Event Hub.
# Normalise to a common schema before indexing.
```

### Step 6: Log Retention and Immutability

```bash
# AWS: S3 Object Lock on the CloudTrail bucket (GOVERNANCE mode allows compliance team to delete; COMPLIANCE mode does not).
aws s3api put-object-lock-configuration \
  --bucket cloudtrail-logs \
  --object-lock-configuration 'ObjectLockEnabled=Enabled,Rule={DefaultRetention={Mode=COMPLIANCE,Years=1}}'

# GCP: set Cloud Storage retention policy.
gsutil retention set 1y gs://gcp-audit-logs-bucket

# Azure: set immutability policy on the storage container.
az storage container immutability-policy create \
  --account-name securitylogssa \
  --container-name activity-logs \
  --period 365 \
  --allow-protected-append-writes true
```

### Step 7: Telemetry

```
cloud_audit_log_ingestion_rate{provider, account}          gauge
cloud_audit_log_gap_minutes{provider, account}             gauge (alert if > 5)
cloudtrail_validation_failure_total{account, trail}        counter
high_value_event_total{provider, event_type, account}      counter
iam_privilege_escalation_detected_total{provider}          counter
root_account_usage_total{account}                          counter
```

Alert on:

- `cloud_audit_log_gap_minutes` > 5 — log delivery stopped; possible CloudTrail disable.
- `cloudtrail_validation_failure_total` non-zero — log file modified; possible tamper.
- `root_account_usage_total` non-zero — root/superadmin credentials used; immediate investigation.
- `iam_privilege_escalation_detected_total` non-zero — admin policy attached; review immediately.

## Expected Behaviour

| Signal | Default cloud audit log setup | Hardened setup |
|--------|-------------------------------|---------------|
| CloudTrail disabled | No trail in affected region | Org-level multi-region trail; gap visible immediately |
| Log bucket deleted | Evidence destroyed | S3 Object Lock (COMPLIANCE); deletion blocked |
| Log file tampered | Tamper undetectable | Integrity validation chain detects modification |
| Root account used | Logged but no alert | CloudWatch metric filter fires within 60s |
| GCP data access | Not logged (disabled by default) | All data access logged; exported to BigQuery |
| Cross-account visibility | Per-account only | Central security account receives all org logs |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Org-level trail | Single trail covers all accounts | Management account permissions required to create | Standard practice for multi-account AWS orgs; no functional downside. |
| S3 Object Lock (COMPLIANCE mode) | Logs truly immutable | Cannot delete logs even if you want to (legal hold) | Use GOVERNANCE mode if you need flexibility; COMPLIANCE for strict regulatory requirements. |
| GCP Data Access logs | Full API activity visibility | Additional cloud logging cost | Enable selectively for sensitive services first (IAM, GCS, BigQuery); expand as budget allows. |
| Cross-cloud centralisation | Single query surface for all providers | Ingestion and storage cost | Use Security Lake or OCSF normalisation to reduce transformation overhead. |
| CloudWatch metric filters | Real-time alerting on API events | CloudWatch Logs cost scales with ingestion volume | Filter to high-value events; don't send all API calls to CloudWatch. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| CloudTrail not enabled in a new region | API calls in that region unlogged | Gap discovered during incident or audit | Create org-level multi-region trail (covers all present and future regions). |
| S3 bucket policy allows log deletion | Attacker deletes logs | Post-incident gap in log timeline | Apply S3 Object Lock; restrict bucket policy to CloudTrail service principal only. |
| Log integrity validation failure | Tampered log file detected | `cloudtrail_validation_failure_total` alert | Preserve the tampered file; investigate; correlate with other signals to reconstruct timeline. |
| Alert filter pattern mismatch | High-value event occurs; no alert fires | Post-incident review reveals the event was loggable but not alerted | Test metric filters with simulated events before relying on them. |
| Log retention too short | Incident discovered after logs expired | Unable to reconstruct attack timeline | Set retention to ≥ 1 year; adjust Object Lock period accordingly. |
| GCP log sink backlog | Real-time alerting delayed | Pub/Sub message age metric rising | Increase subscriber throughput; add more consumers to the Pub/Sub subscription. |

## Related Articles

- [Audit Log Pipeline Design](/articles/observability/audit-log-pipeline/)
- [Kubernetes Audit Log Design](/articles/observability/k8s-audit-log-design/)
- [SIEM Cost Optimisation](/articles/observability/siem-cost-optimization/)
- [Detection Rules and Sigma Correlation](/articles/observability/detection-rules/)
- [Multi-Cloud Hardening](/articles/cross-cutting/multi-cloud-hardening/)
