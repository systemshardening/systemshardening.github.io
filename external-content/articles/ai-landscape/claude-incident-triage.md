---
title: "Claude for Security Incident Triage: Rapid Analysis of Logs, Alerts, and Blast Radius"
description: "When a security alert fires at 2 AM, the on-call engineer faces an information overload problem."
slug: "claude-incident-triage"
date: 2026-01-12
lastmod: 2026-01-12
category: "ai-landscape"
tags: ["claude", "llm", "incident-response", "triage", "log-analysis", "blast-radius", "siem"]
personas: ["security-engineer", "sre", "incident-responder", "devops-engineer"]
article_number: 139
difficulty: "intermediate"
estimated_reading_time: 20
provider_bridges:
  - name: "CrowdStrike"
    id: 95
    category: "endpoint-detection"
  - name: "Splunk"
    id: 67
    category: "siem"
published: true
layout: article.njk
permalink: "/articles/ai-landscape/claude-incident-triage/index.html"
---

# [Claude](https://claude.ai) for Security Incident Triage: Rapid Analysis of Logs, Alerts, and Blast Radius

## Problem

When a security alert fires at 2 AM, the on-call engineer faces an information overload problem. The alert says a credential was used from an unexpected IP address. The engineer needs to determine: Is this a real compromise or a false positive? If real, what has the attacker accessed? What is the blast radius? What systems need to be isolated immediately?

Answering these questions requires correlating data across multiple systems. The engineer must pull CloudTrail logs to see what the credential did, check VPC flow logs to identify network connections, review application logs for unusual access patterns, check the IAM policy attached to the credential to understand what it could access, and examine the resource tags to identify which team and environment is affected.

This manual correlation process takes 30 to 90 minutes for an experienced engineer. During that time, an attacker with valid credentials is moving laterally. Every minute of triage delay is a minute of potential data exfiltration.

Claude can perform this correlation in seconds. Given raw log data from multiple sources, Claude identifies patterns, builds timelines, estimates blast radius, and generates actionable incident summaries. The engineer still makes the decisions, but Claude reduces the triage phase from an hour to minutes.

This article covers practical patterns for feeding logs and alerts to Claude during active incidents, with real examples of how Claude pieces together attack narratives from raw data.

**Target systems:** Any environment generating structured logs. AWS CloudTrail, [Kubernetes](https://kubernetes.io) audit logs, application logs in JSON format, VPC flow logs, authentication system logs (Okta, Azure AD, Google Workspace).

## Threat Model

- **Adversary:** An attacker who has obtained valid credentials (through phishing, leaked secrets, or compromised CI/CD) and is using them to access cloud resources, Kubernetes clusters, or application APIs.
- **Access level:** The attacker has authenticated access equivalent to the compromised credential. This might be a developer's IAM role, a service account, or an application API key.
- **Objective:** Exfiltrate data, establish persistence (create new credentials, deploy backdoors), or move laterally to higher-privilege accounts.
- **Blast radius:** Depends on the compromised credential's permissions and how long the attacker has been active. A developer IAM role might access multiple S3 buckets, RDS databases, and Secrets Manager entries. A Kubernetes ServiceAccount might access secrets across namespaces.

## Configuration

### Feeding CloudTrail Logs to Claude for Pattern Recognition

When you receive an alert about suspicious API activity, the first step is extracting the relevant CloudTrail events. Here is a script that extracts events for a specific IAM principal and feeds them to Claude:

```bash
#!/bin/bash
# scripts/incident-triage.sh
# Extract and analyse CloudTrail events for a compromised credential

PRINCIPAL_ARN="$1"
START_TIME="$2"  # ISO 8601 format
OUTPUT_FILE="incident-$(date +%s).json"

# Extract CloudTrail events
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue="$PRINCIPAL_ARN" \
  --start-time "$START_TIME" \
  --max-results 500 \
  --output json > "$OUTPUT_FILE"

# Also get events by access key if known
if [ -n "$3" ]; then
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$3" \
    --start-time "$START_TIME" \
    --max-results 500 \
    --output json >> "$OUTPUT_FILE"
fi

echo "Events extracted to $OUTPUT_FILE"
echo "Run: claude 'Analyse these CloudTrail events for signs of compromise. Build a timeline.' < $OUTPUT_FILE"
```

### Real Log Analysis: Credential Compromise Timeline

Here is a realistic set of CloudTrail events that Claude analyses during an incident. The raw logs are verbose, so this shows the key fields:

```json
[
  {
    "eventTime": "2026-04-05T02:14:33Z",
    "eventName": "GetCallerIdentity",
    "sourceIPAddress": "198.51.100.47",
    "userAgent": "aws-cli/2.15.0 Python/3.11.6",
    "userIdentity": {
      "type": "IAMUser",
      "arn": "arn:aws:iam::123456789012:user/deploy-bot",
      "accessKeyId": "AKIA9EXAMPLE1234"
    }
  },
  {
    "eventTime": "2026-04-05T02:14:41Z",
    "eventName": "ListBuckets",
    "sourceIPAddress": "198.51.100.47",
    "userIdentity": {
      "arn": "arn:aws:iam::123456789012:user/deploy-bot",
      "accessKeyId": "AKIA9EXAMPLE1234"
    }
  },
  {
    "eventTime": "2026-04-05T02:15:02Z",
    "eventName": "ListObjects",
    "sourceIPAddress": "198.51.100.47",
    "requestParameters": {
      "bucketName": "company-production-data",
      "prefix": "customers/"
    }
  },
  {
    "eventTime": "2026-04-05T02:15:18Z",
    "eventName": "GetObject",
    "sourceIPAddress": "198.51.100.47",
    "requestParameters": {
      "bucketName": "company-production-data",
      "key": "customers/export-2026-03.csv"
    }
  },
  {
    "eventTime": "2026-04-05T02:16:45Z",
    "eventName": "CreateAccessKey",
    "sourceIPAddress": "198.51.100.47",
    "requestParameters": {
      "userName": "deploy-bot"
    },
    "responseElements": {
      "accessKey": {
        "accessKeyId": "AKIA9EXAMPLE5678",
        "status": "Active"
      }
    }
  },
  {
    "eventTime": "2026-04-05T02:17:30Z",
    "eventName": "ListSecrets",
    "sourceIPAddress": "198.51.100.47",
    "eventSource": "secretsmanager.amazonaws.com"
  },
  {
    "eventTime": "2026-04-05T02:17:55Z",
    "eventName": "GetSecretValue",
    "sourceIPAddress": "198.51.100.47",
    "requestParameters": {
      "secretId": "prod/database/master-credentials"
    }
  },
  {
    "eventTime": "2026-04-05T02:19:10Z",
    "eventName": "DescribeDBInstances",
    "sourceIPAddress": "198.51.100.47",
    "eventSource": "rds.amazonaws.com"
  }
]
```

Claude produces this analysis:

```
INCIDENT TIMELINE - Compromised credential: deploy-bot (AKIA9EXAMPLE1234)
Source IP: 198.51.100.47
Duration: 02:14:33 - 02:19:10 UTC (4 minutes 37 seconds)

PHASE 1 - RECONNAISSANCE (02:14:33 - 02:14:41)
- GetCallerIdentity: Attacker verified which account and role they have
- ListBuckets: Enumerated all S3 buckets in the account
  Note: GetCallerIdentity is a common first step when testing stolen
  credentials. Legitimate automation rarely calls this API.

PHASE 2 - DATA ACCESS (02:15:02 - 02:15:18)
- Listed objects in company-production-data bucket under customers/ prefix
- Downloaded customers/export-2026-03.csv
  IMPACT: Customer data has been exfiltrated. This file likely contains
  PII. Data breach notification may be required.

PHASE 3 - PERSISTENCE (02:16:45)
- Created new access key AKIA9EXAMPLE5678 for deploy-bot
  CRITICAL: Attacker now has a second set of credentials. Rotating the
  original key (AKIA9EXAMPLE1234) will not revoke access. Both keys
  must be deactivated.

PHASE 4 - LATERAL MOVEMENT PREPARATION (02:17:30 - 02:19:10)
- Listed secrets in Secrets Manager
- Retrieved prod/database/master-credentials
- Enumerated RDS instances
  CRITICAL: Attacker has database master credentials and knows the
  RDS endpoint. Database access is imminent or may have already
  occurred via a different channel.

IMMEDIATE ACTIONS REQUIRED:
1. Deactivate BOTH access keys: AKIA9EXAMPLE1234 and AKIA9EXAMPLE5678
2. Rotate the database master credential in Secrets Manager
3. Check RDS audit logs for connections from unexpected IPs
4. Check VPC flow logs for connections to the RDS endpoint from
   outside the VPC
5. Assess customers/export-2026-03.csv for PII content and begin
   breach notification process if applicable
```

This analysis takes Claude approximately 5 seconds. A human performing the same correlation manually would spend 20 to 40 minutes reading through raw JSON events, cross-referencing the timeline, and understanding the implications.

### Blast Radius Estimation

After initial triage, the next question is: what else could this credential access? Claude can estimate the blast radius by analysing the IAM policy:

```python
# scripts/blast-radius.py
import anthropic
import boto3
import json

def estimate_blast_radius(principal_arn: str):
    iam = boto3.client("iam")
    username = principal_arn.split("/")[-1]

    # Get all policies attached to the user
    attached = iam.list_attached_user_policies(UserName=username)
    inline = iam.list_user_policies(UserName=username)

    policies = []
    for p in attached["AttachedPolicies"]:
        version = iam.get_policy(PolicyArn=p["PolicyArn"])
        doc = iam.get_policy_version(
            PolicyArn=p["PolicyArn"],
            VersionId=version["Policy"]["DefaultVersionId"]
        )
        policies.append({
            "name": p["PolicyName"],
            "document": doc["PolicyVersion"]["Document"]
        })

    for p_name in inline["PolicyNames"]:
        doc = iam.get_user_policy(UserName=username, PolicyName=p_name)
        policies.append({
            "name": p_name,
            "document": doc["PolicyDocument"]
        })

    # Get group memberships and their policies
    groups = iam.list_groups_for_user(UserName=username)
    for group in groups["Groups"]:
        group_policies = iam.list_attached_group_policies(
            GroupName=group["GroupName"]
        )
        for p in group_policies["AttachedPolicies"]:
            version = iam.get_policy(PolicyArn=p["PolicyArn"])
            doc = iam.get_policy_version(
                PolicyArn=p["PolicyArn"],
                VersionId=version["Policy"]["DefaultVersionId"]
            )
            policies.append({
                "name": f"{group['GroupName']}/{p['PolicyName']}",
                "document": doc["PolicyVersion"]["Document"]
            })

    client = anthropic.Anthropic()
    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=4096,
        system="""You are analysing IAM policies for a compromised credential.
List every AWS service and resource the credential can access.
Group by risk level:
- CRITICAL: Data stores (S3, RDS, DynamoDB, Secrets Manager)
- HIGH: Compute (EC2, Lambda, ECS) and IAM modification
- MEDIUM: Networking, monitoring, logging
- LOW: Read-only access to non-sensitive services

For each service, list the specific actions allowed and whether
resource-scoping limits the blast radius.""",
        messages=[{
            "role": "user",
            "content": f"Policies for compromised user {username}:\n{json.dumps(policies, indent=2)}"
        }]
    )

    return message.content[0].text
```

### Correlating Alerts Across Multiple Systems

During an incident, alerts arrive from different systems. Claude correlates them into a unified narrative:

```python
# scripts/correlate-alerts.py
import anthropic

ALERT_DATA = """
=== GUARDDUTY ALERT (02:13:00 UTC) ===
Type: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
Resource: arn:aws:iam::123456789012:user/deploy-bot
Detail: IAM credentials used from IP 198.51.100.47 which is outside
the expected network range for this principal.

=== CLOUDWATCH ALARM (02:16:00 UTC) ===
Alarm: s3-unusual-download-volume
Metric: S3 BytesDownloaded > 100MB in 5 minutes
Bucket: company-production-data

=== SECRETSMANAGER EVENT (02:17:55 UTC) ===
Event: SecretAccessed
SecretId: prod/database/master-credentials
SourceIP: 198.51.100.47
Note: This secret was last accessed 90 days ago by a Lambda function
from within the VPC.

=== VPC FLOW LOG (02:20:15 UTC) ===
srcaddr=10.0.3.47 dstaddr=10.0.1.22 dstport=5432 protocol=6 action=ACCEPT
Note: 10.0.1.22 is the production RDS endpoint. 10.0.3.47 is not
a known application server.
"""

client = anthropic.Anthropic()
message = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=4096,
    system="""You are a security incident responder. Correlate the
following alerts from different systems into a single incident narrative.

For each alert, explain:
1. What it tells us about the attack progression
2. How it connects to the other alerts
3. What action to take based on this specific alert

Then provide a unified timeline and overall blast radius assessment.""",
    messages=[{
        "role": "user",
        "content": f"Correlate these alerts:\n{ALERT_DATA}"
    }]
)
```

Claude connects the dots that would take a human engineer significant time:

1. GuardDuty fired first because the credential was used from an external IP.
2. Three minutes later, CloudWatch detected high download volume from the same bucket the attacker accessed.
3. Two minutes after that, a secret that has not been accessed in 90 days was read from the same external IP.
4. Two minutes after the secret access, a connection to the RDS endpoint appeared from an internal IP (10.0.3.47) that is not a known application server.

Claude's conclusion: the attacker used the stolen database credentials from the Secrets Manager access to connect to the database. The source IP 10.0.3.47 suggests the attacker has also compromised a host in the VPC (subnet 10.0.3.0/24), or is tunnelling through a compromised service. The blast radius now includes not just S3 data but potentially the entire production database.

### Generating Incident Timelines from Raw Logs

For post-incident review, Claude generates structured timelines from raw log dumps:

```bash
# Combine logs from multiple sources for timeline generation
cat cloudtrail-events.json \
    k8s-audit-log.json \
    application-access.log \
    vpc-flowlogs.csv > combined-logs.txt

claude "Build a minute-by-minute incident timeline from these logs.
Focus on:
- First sign of compromise
- Reconnaissance activity (enumeration, discovery calls)
- Data access (reads from sensitive resources)
- Persistence (credential creation, backdoor deployment)
- Lateral movement (access to new services or accounts)
For each entry, note the source system and the significance."
```

### Identifying Lateral Movement Paths

Claude analyses network and authentication logs to identify lateral movement:

```json
{
  "kubernetes_audit": [
    {
      "timestamp": "2026-04-05T02:22:00Z",
      "verb": "create",
      "resource": "pods/exec",
      "namespace": "production",
      "user": "system:serviceaccount:ci:deploy-agent",
      "sourceIPs": ["10.0.2.15"]
    },
    {
      "timestamp": "2026-04-05T02:22:45Z",
      "verb": "list",
      "resource": "secrets",
      "namespace": "production",
      "user": "system:serviceaccount:ci:deploy-agent",
      "sourceIPs": ["10.0.2.15"]
    },
    {
      "timestamp": "2026-04-05T02:23:10Z",
      "verb": "get",
      "resource": "secrets",
      "namespace": "production",
      "resourceName": "database-url",
      "user": "system:serviceaccount:ci:deploy-agent",
      "sourceIPs": ["10.0.2.15"]
    }
  ]
}
```

Claude identifies the pattern: the CI deploy-agent ServiceAccount, which normally only creates deployments, is now exec-ing into pods and reading secrets. The source IP is a CI runner node. This suggests the attacker has moved from the compromised AWS credential to the CI/CD system (possibly through a shared secret or a deployment pipeline that uses the compromised credential) and is now using the CI ServiceAccount's Kubernetes permissions to access production secrets.

## Expected Behaviour

After integrating Claude into incident triage workflows:

- **Triage time decreases from 30-60 minutes to 5-10 minutes.** Claude performs the initial log correlation and timeline generation, allowing the responder to move directly to containment decisions.
- **Blast radius is assessed within minutes of the first alert.** Claude maps the compromised credential's permissions and correlates observed activity to estimate what the attacker accessed and what they could still access.
- **Cross-system attack paths are visible.** Claude connects alerts from GuardDuty, CloudWatch, Kubernetes audit logs, and VPC flow logs into a single narrative instead of requiring the responder to manually cross-reference multiple dashboards.
- **Incident reports are generated faster.** Claude's timeline and analysis serve as the foundation for the post-incident report, reducing documentation burden on the responding team.

Verification:

```bash
# Test with a known-benign event set to calibrate Claude's analysis
python3 scripts/blast-radius.py \
  "arn:aws:iam::123456789012:user/deploy-bot"

# Run a tabletop exercise using historical incident data
# Feed sanitised logs from a past incident to Claude
# Compare Claude's analysis to the actual incident report

# Verify that the triage script handles edge cases
# - Empty CloudTrail results (credential not used)
# - Very large log volumes (> 1000 events)
# - Events from multiple AWS regions
```

## Trade-offs

| Decision | Benefit | Cost |
|---|---|---|
| Send raw logs to Claude API | Full context, no pre-filtering that might drop important events | API costs scale with log volume; sensitive data leaves your network |
| Pre-filter logs before sending | Lower cost, faster response, reduced data exposure | May filter out events that are important for context |
| Use Claude during the incident (real-time) | Fastest triage, actionable results within minutes | Responder must trust Claude's analysis under pressure |
| Use Claude after containment (post-incident) | No time pressure, can validate findings carefully | Does not help with real-time containment decisions |
| Include IAM policies in the prompt | Claude can estimate full blast radius | Policy documents can be large, consuming context window |

**Data sensitivity considerations:** CloudTrail logs and Kubernetes audit logs may contain sensitive information including resource names, account IDs, and IP addresses. If your security policy prohibits sending this data to external APIs, run Claude through Amazon Bedrock or a self-hosted deployment where data stays within your cloud account. Alternatively, sanitise account IDs and resource names before sending, though this reduces Claude's ability to correlate across data sources.

**API cost estimate:** A typical incident triage session (500-1000 log events across multiple sources) costs $0.05-0.15 per analysis with Claude Sonnet. Even at 10 incidents per month, the cost is under $2/month, which is insignificant compared to the engineering time saved.

## Failure Modes

| Failure | Symptom | Detection | Response |
|---|---|---|---|
| False narrative construction | Claude connects unrelated events into a plausible but incorrect attack story | Human responder verifies key claims against raw data; the narrative does not match when checked | Always verify Claude's critical claims (e.g., "this IP accessed the database") against raw logs before taking containment action |
| Missed log source | Claude analyses CloudTrail but was not given VPC flow logs; misses network-level lateral movement | Post-incident review reveals activity in log sources that were not included in triage | Maintain a checklist of log sources to include in triage; automate collection |
| Hallucinated timestamps | Claude infers events between log entries that did not actually occur | Timeline includes entries with no corresponding raw log event | Ask Claude to cite the specific log entry for each timeline item |
| API latency during incident | Claude API is slow or unavailable during a critical incident | Triage script times out or returns no results | Have a fallback: pre-built correlation queries in your SIEM for the most common scenarios |
| Overwhelming log volume | Thousands of events exceed the context window; analysis is incomplete | Claude's output stops mid-analysis or mentions truncation | Pre-filter logs to the relevant time window and principal; send in batches if necessary |
| Attacker-manipulated logs | Attacker has modified CloudTrail or application logs to mislead analysis | Claude's analysis contains inconsistencies or gaps that suggest log tampering | Cross-reference multiple independent log sources; check for disabled CloudTrail trails or modified log buckets |

## When to Consider a Managed Alternative

**Transition point:** When your organisation handles more than 20 security incidents per month, needs automated correlation across more than 5 log sources, or requires compliance-grade incident documentation with chain-of-custody tracking.

**What managed providers handle:**

- **[CrowdStrike](https://www.crowdstrike.com):** Endpoint detection and response with automated investigation playbooks. CrowdStrike's Falcon platform correlates endpoint telemetry, network data, and threat intelligence automatically. For endpoint-focused incidents, CrowdStrike provides deeper visibility than Claude analysing logs.
- **[Splunk](https://www.splunk.com):** SIEM with pre-built correlation rules, dashboards, and automated response playbooks. Splunk handles the continuous monitoring and alerting that Claude is not suited for. Splunk processes log streams in real time; Claude analyses snapshots.

**What Claude handles that managed tools do not:** Natural-language explanation of attack narratives, blast radius estimation from IAM policy analysis, ad-hoc correlation of log sources that are not pre-integrated into the SIEM, and answering questions about the incident in conversational form ("Could the attacker have accessed the production database?" "What would happen if they used the second access key?"). No managed tool provides this interactive reasoning today.

**The optimal stack:** Splunk or equivalent SIEM for continuous monitoring and alerting + CrowdStrike or equivalent for endpoint visibility + Claude for rapid triage analysis, blast radius estimation, and incident report generation. The SIEM detects the incident, the EDR provides endpoint context, and Claude helps the responder understand what happened and what to do next.


## Related Articles

- [Claude, Mythos, and the Non-Human Infrastructure Consumer: Writing Hardening Guides for AI Agents](/articles/ai-landscape/claude-non-human-consumers/)
- [Claude for Security Detection: How Large Language Models Find What Scanners Miss](/articles/ai-landscape/claude-security-detection/)
- [Claude for Infrastructure-as-Code Security Review: Terraform, CloudFormation, and Pulumi](/articles/ai-landscape/claude-iac-review/)
- [Claude for Kubernetes Security Auditing: Finding Privilege Escalation Paths Scanners Cannot See](/articles/ai-landscape/claude-kubernetes-audit/)
- [Claude for Application Security: Finding Logic Vulnerabilities in Source Code](/articles/ai-landscape/claude-code-vulnerability/)
