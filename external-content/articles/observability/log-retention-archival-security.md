---
title: "Log Retention Policy, Archival Security, and Compliance-Driven Log Management"
description: "Regulatory frameworks disagree on how long logs must be kept, but they all agree logs must be tamper-evident and access-controlled. This guide covers tiered retention design, WORM archival with S3 Object Lock, Elasticsearch ILM, GDPR right-to-erasure tensions, and cost-optimised cold storage for PCI DSS, SOC 2, HIPAA, and GDPR compliance."
slug: log-retention-archival-security
date: 2026-05-07
lastmod: 2026-05-07
category: observability
tags:
  - log-retention
  - compliance
  - log-archival
  - worm-storage
  - gdpr
personas:
  - security-engineer
  - compliance-engineer
article_number: 562
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/observability/log-retention-archival-security/
---

# Log Retention Policy, Archival Security, and Compliance-Driven Log Management

## Problem

Most organisations have logs. Far fewer have a log retention *policy* — a documented decision about how long different log types are kept, in what storage tier, with what access controls, and under what legal framework. The result is one of two failure modes: logs deleted too early (you cannot satisfy a forensic investigation or audit request), or logs kept indefinitely with no access control (an attacker who breaches your archive bucket exfiltrates years of application behaviour, credentials logged in error messages, and internal system topology).

Compliance frameworks impose minimum retention windows, but they conflict with each other, and the GDPR right to erasure creates a direct tension with security retention requirements. The solution is not one blanket policy — it is a tiered, documented architecture with different retention rules for different log types, cryptographic integrity for archives, and a separation between PII-containing data and security-relevant events.

**Target systems:** Elasticsearch/OpenSearch with Index Lifecycle Management (ILM); AWS S3 with Object Lock; any compliance-regulated environment (PCI DSS, SOC 2, HIPAA, GDPR).

## Threat Model

- **Adversary 1 — Compliance auditor finding gaps:** An auditor requests 12 months of access logs for a PCI DSS assessment. Logs were rotated after 30 days. The finding is a critical compliance gap that triggers re-audit and potential fine.
- **Adversary 2 — Attacker tampering with forensic evidence:** After a breach, the attacker modifies archived logs to remove evidence of their lateral movement. Unsigned archives with no integrity chain cannot prove tampering occurred.
- **Adversary 3 — Insider accessing the compliance archive:** A developer with access to the production log role also reads the compliance archive, which contains 3 years of security events. There is no separation of duties and no audit trail of archive access.
- **Adversary 4 — Regulatory exposure from over-retained PII:** A GDPR right-to-erasure request is submitted. Application logs contain user IDs linked to PII. The logs are in immutable WORM storage and cannot be deleted. The organisation is non-compliant with the erasure requirement.
- **Adversary 5 — Unreadable archives at audit time:** Logs archived 2 years ago were written in a proprietary binary format. The application that generated them no longer exists. The auditor cannot read the evidence.

## Retention Requirements by Regulation

No single retention window satisfies every framework. The table below summarises the common requirements:

| Framework | Log Types | Minimum Retention | Online Requirement |
|-----------|-----------|-------------------|-------------------|
| PCI DSS 4.0 (Req 10.5) | Audit logs, access logs | 12 months total; 3 months immediately available | 3 months queryable, remaining 9 months archived |
| SOC 2 (Trust Services Criteria) | System activity logs | Typically 12 months (auditor-specified) | No formal tier split, auditor expectation is searchable |
| HIPAA (45 CFR §164.312) | ePHI access logs, audit controls | 6 years from creation or last effective date | No tier requirement, but must be retrievable within reasonable time |
| GDPR (Art. 5(1)(e)) | Any logs containing personal data | Only as long as necessary for the stated purpose | N/A — conflicts with security retention (see below) |
| ISO 27001 (A.12.4) | Security event logs | Organisation-defined; auditors expect ≥1 year | Organisation-defined |
| NIS2 (EU) | Incident-relevant logs | Typically 1 year for critical infrastructure | No formal specification |

The critical insight: **PCI DSS gives you the most concrete numbers** (3 months online, 12 months total). Use this as your baseline for security log classes and extend where HIPAA's 6-year requirement applies to ePHI access logs.

## Designing a Tiered Retention Policy

A tiered approach matches storage cost to access frequency. Four tiers cover the full lifecycle:

| Tier | Duration | Storage Type | Query Latency | Cost Profile |
|------|----------|-------------|---------------|-------------|
| Hot | 0–30 days | Elasticsearch hot nodes (SSD) | Milliseconds | High — fast local disks |
| Warm | 31–90 days | Elasticsearch warm nodes (HDD) or searchable snapshots | Seconds | Medium — slower disks, compressed |
| Cold | 91–365 days | S3 Standard + Elasticsearch searchable snapshots | 10–60 seconds to mount | Low — object storage |
| Frozen/Compliance | 1–7 years | S3 Glacier Instant Retrieval or Deep Archive | Minutes to hours | Minimal — cold archival tiers |

Define which log *classes* map to which retention window. Security audit logs (auth, privilege escalation, network access) should always have longer retention than application debug logs:

```yaml
# log-retention-policy.yaml
# This document is the single source of truth for log retention.
# Changes require approval from Security + Legal + Compliance.

retention_classes:
  security_audit:
    description: "Authentication, authorisation, privilege use, network access changes"
    hot_days: 30
    warm_days: 90
    cold_days: 365
    compliance_years: 6   # HIPAA-derived; covers ePHI access
    integrity: required
    worm: true

  application_access:
    description: "HTTP access logs, API calls, session events"
    hot_days: 14
    warm_days: 60
    cold_days: 365
    compliance_years: 1   # PCI DSS baseline
    integrity: required
    worm: true

  application_debug:
    description: "DEBUG/INFO application logs, stack traces"
    hot_days: 7
    warm_days: 30
    cold_days: 0          # Not archived to compliance tier
    compliance_years: 0
    integrity: optional
    worm: false

  infrastructure:
    description: "Host metrics, kubelet, container runtime, network flow"
    hot_days: 14
    warm_days: 45
    cold_days: 180
    compliance_years: 1
    integrity: required
    worm: true
```

## Elasticsearch Index Lifecycle Management (ILM)

ILM automates tier transitions based on index age and size. Configure a policy that matches your retention tiers:

```json
PUT _ilm/policy/security-audit-retention
{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": {
            "max_primary_shard_size": "50gb",
            "max_age": "1d"
          },
          "set_priority": { "priority": 100 }
        }
      },
      "warm": {
        "min_age": "30d",
        "actions": {
          "shrink": { "number_of_shards": 1 },
          "forcemerge": { "max_num_segments": 1 },
          "set_priority": { "priority": 50 },
          "allocate": {
            "require": { "data": "warm" }
          }
        }
      },
      "cold": {
        "min_age": "90d",
        "actions": {
          "searchable_snapshot": {
            "snapshot_repository": "s3-compliance-repo",
            "force_merge_index": true
          },
          "set_priority": { "priority": 0 }
        }
      },
      "frozen": {
        "min_age": "365d",
        "actions": {
          "searchable_snapshot": {
            "snapshot_repository": "s3-glacier-repo",
            "force_merge_index": true
          }
        }
      },
      "delete": {
        "min_age": "2557d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}
```

Register the S3 snapshot repositories. The cold repository uses S3 Standard; the frozen repository uses S3 Glacier Instant Retrieval:

```json
PUT _snapshot/s3-compliance-repo
{
  "type": "s3",
  "settings": {
    "bucket": "es-snapshots-compliance",
    "region": "eu-west-1",
    "base_path": "cold-tier",
    "storage_class": "standard",
    "server_side_encryption": true,
    "readonly": false
  }
}

PUT _snapshot/s3-glacier-repo
{
  "type": "s3",
  "settings": {
    "bucket": "es-snapshots-compliance",
    "region": "eu-west-1",
    "base_path": "frozen-tier",
    "storage_class": "intelligent_tiering",
    "server_side_encryption": true,
    "readonly": false
  }
}
```

Apply the ILM policy to your index template so every new security audit index automatically inherits it:

```json
PUT _index_template/security-audit-template
{
  "index_patterns": ["security-audit-*"],
  "template": {
    "settings": {
      "index.lifecycle.name": "security-audit-retention",
      "index.lifecycle.rollover_alias": "security-audit",
      "index.number_of_shards": 3,
      "index.number_of_replicas": 1,
      "index.codec": "best_compression"
    }
  }
}
```

## S3 Object Lock for WORM Archival

When logs transition to the compliance archive, they must be immutable. S3 Object Lock provides two modes:

- **Governance mode:** Prevents most users from deleting or overwriting objects. Users with the `s3:BypassGovernanceRetention` IAM permission can still override. Use this for development and pre-production environments where accidental deletion protection is needed but some administrative flexibility is acceptable.
- **Compliance mode:** No user — including the AWS root account — can delete or shorten the retention period before expiry. Use this for regulated compliance archives.

```bash
# Create the compliance archive bucket with Object Lock enabled.
# Object Lock MUST be enabled at bucket creation time — it cannot be added later.
aws s3api create-bucket \
  --bucket compliance-log-archive-prod \
  --region eu-west-1 \
  --object-lock-enabled-for-bucket \
  --create-bucket-configuration LocationConstraint=eu-west-1

# Enable versioning (required for Object Lock).
aws s3api put-bucket-versioning \
  --bucket compliance-log-archive-prod \
  --versioning-configuration Status=Enabled

# Set default retention: 7 years in Compliance mode for HIPAA-covered logs.
aws s3api put-object-lock-configuration \
  --bucket compliance-log-archive-prod \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "COMPLIANCE",
        "Days": 2557
      }
    }
  }'

# Enable server-side encryption with KMS.
aws s3api put-bucket-encryption \
  --bucket compliance-log-archive-prod \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "arn:aws:kms:eu-west-1:123456789012:key/compliance-logs-key"
      },
      "BucketKeyEnabled": true
    }]
  }'
```

For logs that fall under the 1-year PCI DSS window rather than the 6-year HIPAA window, use a separate bucket with a 365-day Compliance mode lock. Never mix retention windows in a single bucket — the longest retention period in the bucket becomes the effective policy for every object, because you cannot selectively expire objects that are Object Lock protected.

## Log Integrity for Archives

Storing logs in WORM storage prevents deletion but does not prove the logs were not tampered with *before* archival. Apply HMAC-based signing to log batches before they reach S3.

```python
#!/usr/bin/env python3
# sign-log-batch.py
# Signs a batch of log entries with HMAC-SHA256 before archival.
# The signing key is retrieved from AWS Secrets Manager; it is NEVER logged.

import hashlib
import hmac
import json
import os
import time
import boto3
import base64

def get_signing_key(secret_name: str, region: str) -> bytes:
    client = boto3.client("secretsmanager", region_name=region)
    response = client.get_secret_value(SecretId=secret_name)
    return base64.b64decode(response["SecretString"])

def sign_batch(entries: list, sequence_number: int,
               previous_batch_hash: str, signing_key: bytes) -> dict:
    batch = {
        "schema_version": "1",
        "sequence": sequence_number,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "previous_batch_hash": previous_batch_hash,
        "entry_count": len(entries),
        "entries": entries,
    }

    # Canonical serialisation: sort keys, no extra whitespace.
    canonical = json.dumps(batch, sort_keys=True, separators=(",", ":"))

    # HMAC-SHA256 over the canonical form.
    mac = hmac.new(signing_key, canonical.encode("utf-8"), hashlib.sha256)
    batch["batch_hmac"] = mac.hexdigest()

    # SHA-256 of the complete signed batch for chain linking.
    batch_hash = hashlib.sha256(
        json.dumps(batch, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    return batch, batch_hash

# Before archiving to S3, run each batch through sign_batch().
# Store the returned batch_hash as previous_batch_hash for the next batch.
# Verification: recompute the HMAC server-side using the same key.
# Any modification to batch content invalidates the HMAC.
```

During an audit or forensic investigation, a compliance engineer with access to the signing key can verify each archived batch. A broken HMAC proves tampering. A broken hash chain (where `previous_batch_hash` does not match the prior batch's recorded hash) proves insertion, deletion, or reordering of batches.

## Access Control for the Compliance Archive

The role that writes real-time logs to Elasticsearch should not be the same role that reads the compliance archive. Operational log access (for debugging, alerting, dashboards) should be entirely separate from compliance archive access.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ComplianceArchiveReadOnly",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::compliance-log-archive-prod",
        "arn:aws:s3:::compliance-log-archive-prod/*"
      ]
    },
    {
      "Sid": "DenyDelete",
      "Effect": "Deny",
      "Action": [
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
        "s3:PutObject",
        "s3:AbortMultipartUpload"
      ],
      "Resource": "arn:aws:s3:::compliance-log-archive-prod/*"
    }
  ]
}
```

Create a separate `compliance-archive-reader` IAM role. Require MFA for assumption. Log every `AssumeRole` call for this role via CloudTrail. Access to the compliance archive should be a deliberate, auditable action — not something that happens incidentally during normal operational work.

Assign the Elasticsearch ILM snapshot role write-only access to S3 — it can create new snapshot objects but cannot list or retrieve existing ones. This limits the blast radius if Elasticsearch service account credentials are compromised.

## GDPR Right to Erasure vs Log Retention

GDPR Article 17 gives individuals the right to erasure of their personal data. Security logs legitimately retain records of user activity. These requirements collide when a user who requests erasure has associated log entries that are also security-relevant (authentication events, access logs, audit trails).

The resolution is **pseudonymisation at log generation time**:

```python
# log-pseudonymisation.py
# Replace direct user identifiers with a pseudonym before logs are shipped.
# The mapping between pseudonym and real identity is stored in a separate
# deletion index that can be purged without modifying log archives.

import hashlib
import hmac
import os

# A stable per-environment secret. All log entries for the same user
# produce the same pseudonym, so correlation still works.
# The secret is separate from the HMAC signing key.
PSEUDONYM_SECRET = os.environ["LOG_PSEUDONYM_SECRET"].encode("utf-8")

def pseudonymise_user_id(user_id: str) -> str:
    """
    Produce a stable pseudonym for a user ID.
    Consistent across log entries — searchable but not directly identifying.
    """
    mac = hmac.new(PSEUDONYM_SECRET, user_id.encode("utf-8"), hashlib.sha256)
    # Use first 16 hex chars for brevity; still 64 bits of pseudonymity.
    return "uid-" + mac.hexdigest()[:16]

# Example: user_id "alice@example.com" -> "uid-3f8a1c9d2e7b4f05"
# The original identity is not in the log. The logs retain full utility
# for correlation and forensic investigation.
```

Alongside pseudonymisation, maintain a **deletion index** that maps pseudonyms to the real user identity. When a right-to-erasure request arrives:

1. Locate the pseudonym for the requesting user.
2. Delete the deletion index entry (the pseudonym-to-identity mapping).
3. The log archives retain the pseudonymised entries — security value is preserved.
4. The link between the pseudonym and the real person is gone — GDPR erasure obligation is satisfied.

This approach requires legal review before deployment. Some interpretations of GDPR consider pseudonymised data as still personal data if the key can be recovered. The key point is that by deleting the key (the deletion index entry), re-identification becomes computationally infeasible.

**What to never log in the first place:** Full email addresses in access logs (use the pseudonym), full name fields in audit events (use the pseudonym or role), credit card numbers or payment data (PCI DSS requirement A3.3), passwords or secrets (any log level), national ID numbers or government identifiers.

## Cost-Optimised Archival Storage

The compliance tier spans years. Choosing the right S3 storage class for each phase of the frozen tier significantly affects cost without compromising retrieval SLAs.

| S3 Class | Retrieval Time | Cost (EU) | Best For |
|----------|---------------|-----------|---------|
| S3 Standard | Immediate | $0.023/GB/month | Hot + warm Elasticsearch snapshots |
| S3 Standard-IA | Milliseconds | $0.0125/GB/month | Cold tier snapshots (90–365 days) |
| S3 Glacier Instant Retrieval | Milliseconds | $0.004/GB/month | Compliance archives needing same-day retrieval |
| S3 Glacier Flexible Retrieval | 1–12 hours | $0.0036/GB/month | Archives where next-day access is acceptable |
| S3 Glacier Deep Archive | 12–48 hours | $0.00099/GB/month | True long-term frozen archives (HIPAA 6-year) |

For most compliance use cases: use **Glacier Instant Retrieval** for years 1–3 (audits are likely, retrieval must be fast) and transition to **Glacier Deep Archive** for years 4–7 (HIPAA retention tail, audits rare, 48-hour retrieval acceptable).

Configure a lifecycle rule to automate the Glacier tier transition:

```json
{
  "Rules": [
    {
      "ID": "compliance-archive-tiering",
      "Status": "Enabled",
      "Filter": { "Prefix": "frozen-tier/" },
      "Transitions": [
        {
          "Days": 1095,
          "StorageClass": "GLACIER_IR"
        },
        {
          "Days": 1460,
          "StorageClass": "DEEP_ARCHIVE"
        }
      ]
    }
  ]
}
```

Note: S3 Object Lock retention periods are independent of lifecycle transitions. An object can transition to Deep Archive for cost reasons while remaining under a Compliance mode lock that prevents deletion.

## Log Format Standardisation for Long-Term Archival

Logs archived today must be parseable by a different team using different tooling in 6 years. Proprietary binary formats, application-specific encodings, and tool-dependent schemas are forensic liabilities.

Requirements for archival-safe log formats:

1. **Plain text or JSON.** Never archive binary formats, compressed-then-unindexed blobs, or formats tied to a specific application version.
2. **Include schema version in every log entry.** Not in a header file — in each entry. If a subset of entries is extracted, the schema version travels with them.
3. **ISO 8601 timestamps with timezone.** Never Unix epoch without a documented epoch definition. Never localtime. Always UTC.
4. **Self-describing field names.** `user_id` not `uid`. `source_ip` not `src`. `event_type` not `t`. Future analysts cannot consult your internal naming convention.
5. **OpenTelemetry log data model** (or a documented schema that maps to it). The OTel log model is stable, widely understood, and tool-agnostic.

```json
{
  "schema_version": "1",
  "timestamp": "2026-05-07T14:23:01.452Z",
  "severity_text": "WARN",
  "severity_number": 13,
  "body": "Failed authentication attempt",
  "resource": {
    "service.name": "auth-service",
    "service.version": "2.4.1",
    "host.name": "web-01.prod.example.com"
  },
  "attributes": {
    "event.type": "authentication.failure",
    "user.pseudonym": "uid-3f8a1c9d2e7b4f05",
    "source.ip": "203.0.113.42",
    "http.method": "POST",
    "http.path": "/api/v1/login"
  }
}
```

Archive format: newline-delimited JSON (NDJSON) compressed with gzip. One file per hour per log class. This gives auditors a file they can decompress with standard tools, read line by line, and parse with any JSON library — without needing Elasticsearch, Kibana, or any part of your current stack.

Store the schema definition alongside the archive:

```
s3://compliance-log-archive-prod/
  frozen-tier/
    schema/
      security-audit-v1.json       # Field definitions, types, examples
      security-audit-v2.json       # If schema evolves, document both
    security-audit/
      2026/05/07/14/
        security-audit-2026050714.ndjson.gz
        security-audit-2026050714.ndjson.gz.hmac
```

The `.hmac` sidecar file contains the HMAC signature for the corresponding log file. Store it as a separate object so integrity verification does not require downloading the full archive.

## Expected Behaviour

- Hot-tier security audit logs remain queryable in Elasticsearch for 30 days with sub-second search latency.
- Warm-tier logs (30–90 days) are accessible via Elasticsearch with slightly higher latency due to HDD-backed nodes and best_compression codec.
- Cold-tier logs (90–365 days) are searchable snapshots mounted from S3; queries take 10–60 seconds but require no restore operation.
- Compliance archives (1+ years) are Object Lock protected in Compliance mode; no user can delete or modify them before the retention period expires.
- Every archived batch has an HMAC signature; a compliance engineer can verify archive integrity at any time with the signing key from Secrets Manager.
- GDPR erasure requests are satisfied by deleting the deletion index entry for the requesting user; the pseudonymised log archive is untouched.
- An IAM role assumption is required to access the compliance archive; all assumptions are logged to CloudTrail.

## Trade-offs

| Decision | Benefit | Cost | Mitigation |
|----------|---------|------|-----------|
| Compliance mode Object Lock | Legally defensible immutability; satisfies PCI DSS 10.5 | Cannot delete logs even for legitimate reasons (data subject request, accidental PII ingestion) | Pseudonymise PII before archival; test log content in staging before enabling Compliance mode in production |
| HMAC signing before archival | Proves logs were not modified post-generation | Signing key management adds operational complexity | Store signing key in Secrets Manager; rotate annually; document verification procedure |
| Pseudonymisation for GDPR | Satisfies erasure requests without modifying archives | Correlation requires the deletion index; if the index is lost, pseudonyms cannot be re-identified | Replicate the deletion index to a separate region; treat it as critical data |
| Tiered ILM with S3 snapshots | 60–80% cost reduction versus keeping all logs on hot nodes | Cold and frozen tier queries are slower; operational complexity of managing snapshot repos | Use hot tier for day-to-day alerting; cold tier access is for investigations where latency is acceptable |
| Separate archive IAM role | Separation of duties; auditable access | Additional IAM complexity; developers may push back on needing a separate role for investigations | Document the workflow; make role assumption easy but audited (MFA + CloudTrail) |

## Related Articles

- [Log Integrity and Tamper Detection: Ensuring Your Audit Trail Is Trustworthy](/articles/observability/log-integrity/)
- [Elasticsearch Security Hardening: TLS, Role-Based Access, and Audit Logging](/articles/observability/elasticsearch-security-hardening/)
- [Building a Security Audit Log Pipeline That Scales: auditd to Elasticsearch](/articles/observability/audit-log-pipeline/)
- [OpenTelemetry PII Leakage: Preventing Sensitive Data Exposure in Telemetry Pipelines](/articles/observability/otel-pii-leakage/)
- [Centralised Logging Architecture for Security: Fluentd, Vector, and Loki Compared](/articles/observability/centralized-logging/)
