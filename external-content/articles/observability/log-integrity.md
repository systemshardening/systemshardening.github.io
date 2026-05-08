---
title: "Log Integrity and Tamper Detection: Ensuring Your Audit Trail Is Trustworthy"
description: "An attacker's first post-compromise action is covering their tracks. On a Linux host, this means deleting /var/log/audit/audit.log, clearing journal.."
slug: "log-integrity"
date: 2026-02-10
lastmod: 2026-02-10
category: "observability"
tags: ["log-integrity", "tamper-detection", "immutable-storage", "hash-chaining", "forensics"]
personas: ["security-engineer", "sre"]
article_number: 65
difficulty: "advanced"
estimated_reading_time: 16
provider_bridges:
  - name: "Axiom"
    id: 112
    category: "observability"
  - name: "Backblaze"
    id: 161
    category: "object-storage"
  - name: "Wasabi"
    id: 162
    category: "object-storage"
premium_pack: "log-integrity-toolkit"
published: true
layout: article.njk
permalink: "/articles/observability/log-integrity/index.html"
---

# Log Integrity and Tamper Detection: Ensuring Your Audit Trail Is Trustworthy

## Problem

An attacker's first post-compromise action is covering their tracks. On a Linux host, this means deleting `/var/log/audit/audit.log`, clearing journal entries, and modifying application logs to remove evidence. If your audit logs are stored on the same host the attacker compromised, they are worthless for investigation.

Most organisations ship logs centrally, but few verify integrity. A sophisticated attacker who compromises the log shipper, the aggregation layer, or the storage backend can modify logs in transit or at rest. Without integrity verification, you cannot prove your audit trail is complete and unmodified.

This matters for incident response (was the evidence tampered with?) and compliance (SOC 2 requires provable log integrity).

**Target systems:** Any Linux host with [auditd](https://github.com/linux-audit/audit-userspace). [Vector](https://vector.dev) or [Fluentd](https://www.fluentd.org) for shipping. S3-compatible object storage for immutable archival.

## Threat Model

- **Adversary:** Post-compromise attacker with root access on a host, attempting to erase forensic evidence. Or: attacker who has compromised the log pipeline (shipper, aggregator, or storage backend).
- **Objective:** Delete, modify, or suppress log entries that would reveal the attack timeline, techniques, and scope.
- **Blast radius:** Without log integrity, complete loss of forensic evidence. The incident cannot be investigated, root cause cannot be determined, and compliance audits fail.

## Configuration

### Ship Logs Off-Host Before the Attacker Can Delete Them

The most important control: minimise the time window between log generation and off-host shipment.

```yaml
# /etc/vector/vector.yaml
# Ship audit logs via Unix socket - lowest possible latency.
# auditd writes to the socket; Vector reads immediately.

sources:
  auditd_socket:
    type: unix_datagram
    path: /var/run/audispd_events
    max_length: 8192

transforms:
  parse:
    type: remap
    inputs: [auditd_socket]
    source: |
      .host = get_hostname!()
      .shipped_at = now()
      .source = "auditd"

sinks:
  # Primary: queryable storage
  axiom:
    type: axiom
    inputs: [parse]
    dataset: "audit-logs"
    token: "${AXIOM_API_TOKEN}"

  # Secondary: immutable archival
  s3_immutable:
    type: aws_s3
    inputs: [parse]
    bucket: "audit-logs-immutable"
    region: "eu-west-1"
    key_prefix: "{{ host }}/{{ timestamp }}"
    encoding:
      codec: json
    batch:
      max_bytes: 10485760
      timeout_secs: 60
```

Configure auditd to write to the Unix socket via audisp:

```ini
# /etc/audit/plugins.d/vector.conf
active = yes
direction = out
path = /var/run/audispd_events
type = builtin
format = string
```

**Latency target:** Log entries should arrive in off-host storage within 5 seconds of generation. With the Unix socket approach, typical latency is under 1 second.

### Immutable Storage with S3 Object Lock

```bash
# Create bucket with Object Lock (WORM - Write Once Read Many)
aws s3api create-bucket \
  --bucket audit-logs-immutable \
  --region eu-west-1 \
  --object-lock-enabled-for-bucket \
  --create-bucket-configuration LocationConstraint=eu-west-1

# Set default retention: 365 days in Compliance mode
# Compliance mode: even the root account cannot delete or shorten retention.
aws s3api put-object-lock-configuration \
  --bucket audit-logs-immutable \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "COMPLIANCE",
        "Days": 365
      }
    }
  }'
```

**IAM policy for the log shipper, write-only, no read, no delete:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:PutObject"],
      "Resource": "arn:aws:s3:::audit-logs-immutable/*"
    },
    {
      "Effect": "Deny",
      "Action": [
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::audit-logs-immutable",
        "arn:aws:s3:::audit-logs-immutable/*"
      ]
    }
  ]
}
```

The shipper can write new log objects but cannot read, list, or delete existing ones. Even if the attacker compromises the shipper's credentials, they cannot modify or delete already-shipped logs.

For non-AWS: [Backblaze](https://www.backblaze.com) B2 with Object Lock, or [Wasabi](https://wasabi.com) with immutable bucket policy.

### Hash-Chaining for Tamper Detection

Each log batch includes the SHA-256 hash of the previous batch, creating an append-only chain. Any modification, insertion, or deletion breaks the chain.

```python
#!/usr/bin/env python3
# hash-chain-shipper.py
# Wraps log batches with hash-chain integrity before shipping.

import hashlib
import json
import time
import sys

previous_hash = "GENESIS"  # First batch has no predecessor

def create_batch(log_entries: list) -> dict:
    global previous_hash

    batch = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": "web-01.example.com",
        "previous_hash": previous_hash,
        "entries": log_entries,
        "entry_count": len(log_entries),
    }

    # Hash the entire batch content (excluding the batch_hash field itself)
    batch_content = json.dumps(batch, sort_keys=True)
    batch["batch_hash"] = hashlib.sha256(batch_content.encode()).hexdigest()

    # Update the chain
    previous_hash = batch["batch_hash"]

    return batch

# Example usage:
# entries = [line.strip() for line in sys.stdin]
# batch = create_batch(entries)
# print(json.dumps(batch))
# Ship batch to S3 and Axiom
```

**Verification script:**

```python
#!/usr/bin/env python3
# verify-hash-chain.py
# Verifies the integrity of a hash-chained log archive.
# Detects: insertions, deletions, modifications, and reordering.

import json
import hashlib
import sys
import glob

def verify_chain(batch_files: list) -> bool:
    """Verify hash chain integrity across a series of batch files."""
    expected_previous = "GENESIS"
    errors = []

    for i, filepath in enumerate(sorted(batch_files)):
        with open(filepath) as f:
            batch = json.load(f)

        # Verify previous_hash links correctly
        if batch["previous_hash"] != expected_previous:
            errors.append(
                f"CHAIN BROKEN at batch {i} ({filepath}): "
                f"expected previous_hash={expected_previous}, "
                f"got {batch['previous_hash']}"
            )

        # Verify batch_hash is correct for the content
        stored_hash = batch.pop("batch_hash")
        recomputed = hashlib.sha256(
            json.dumps(batch, sort_keys=True).encode()
        ).hexdigest()
        batch["batch_hash"] = stored_hash  # Restore

        if stored_hash != recomputed:
            errors.append(
                f"CONTENT MODIFIED in batch {i} ({filepath}): "
                f"stored hash={stored_hash}, computed={recomputed}"
            )

        expected_previous = stored_hash

    if errors:
        for e in errors:
            print(f"FAIL: {e}", file=sys.stderr)
        return False
    else:
        print(f"OK: {len(batch_files)} batches verified, chain intact.")
        return True

# Usage: python3 verify-hash-chain.py /path/to/batch-*.json
files = glob.glob(sys.argv[1]) if len(sys.argv) > 1 else []
if not files:
    print("Usage: verify-hash-chain.py '/path/to/batch-*.json'")
    sys.exit(1)

sys.exit(0 if verify_chain(files) else 1)
```

### Log Gap Detection

Monitor the expected log rate per host. If a host stops sending logs, it may be compromised.

```yaml
# Prometheus alert: log rate drops to zero for a host
groups:
  - name: log-integrity
    rules:
      - alert: LogGapDetected
        expr: >
          absent_over_time(
            vector_component_events_out_total{component_id="auditd_socket"}[5m]
          )
        labels:
          severity: critical
        annotations:
          summary: "No audit logs received from {{ $labels.host }} for 5 minutes"
          runbook: |
            CRITICAL: A host has stopped sending audit logs.
            Possible causes:
            1. Host is down (check uptime monitoring)
            2. Vector/auditd crashed (check process status)
            3. Host is compromised and attacker killed the log shipper
            If cause is unknown: treat as potential compromise.
            Do NOT SSH to the host, use out-of-band console access.

      - alert: LogRateAnomaly
        expr: >
          rate(vector_component_events_out_total{component_id="auditd_socket"}[5m])
          < 0.1 * avg_over_time(
            rate(vector_component_events_out_total{component_id="auditd_socket"}[5m])[7d:5m]
          )
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Audit log rate from {{ $labels.host }} dropped to 10% of normal"
          description: "May indicate selective log suppression by an attacker."
```

## Expected Behaviour

- Audit logs arrive in off-host storage within 5 seconds of generation (typically <1 second with Unix socket)
- Immutable S3 storage prevents deletion or modification of stored logs for 365 days
- Log shipper credentials are write-only, compromising the shipper does not allow reading or deleting existing logs
- Hash-chain verification script detects any tampered, inserted, or deleted batch
- Log gap alert fires within 5 minutes of a host going silent
- Log rate anomaly alert detects selective log suppression within 10 minutes

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Immediate off-host shipping | Network bandwidth: 1-5GB/host/day | Shipper failure creates a gap | Vector's disk buffer preserves events during network outages; replays when connection restores |
| S3 Object Lock (Compliance mode) | Cannot delete logs even if you want to (365-day lock) | Accidental sensitive data in logs cannot be removed | Filter PII before shipping. Review log content in staging before enabling immutable shipping in production. |
| Hash-chaining | Adds processing overhead to each batch | Verification requires downloading all batches in sequence | Run verification on a schedule (daily) rather than real-time. Keep batch sizes manageable (1-10MB). |
| Write-only IAM | Shipper cannot verify its own uploads | Upload failures are silent from the shipper's perspective | Monitor S3 PutObject success rate via CloudWatch. Vector reports delivery success/failure metrics. |
| Log gap detection (5-minute window) | Attacker has up to 5 minutes to operate before gap is detected | Not instant. some log suppression goes undetected for 5 min | Reduce alert window to 2 minutes for high-security hosts. Accept the increased false positive rate from brief network glitches. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Vector crashes on host | Logs buffer locally but don't ship | Log gap alert fires within 5 minutes; Vector restart count increases | Vector auto-restarts via [systemd](https://systemd.io). Disk buffer replays missed events. Investigate why Vector crashed. |
| S3 IAM policy misconfigured | Attacker with shipper credentials can delete logs | Hash-chain verification fails; log count mismatch between primary and archival | Fix IAM policy. Restore from secondary storage if available. This is why dual-shipping (Axiom + S3) matters. |
| auditd killed by attacker | No new log entries generated on the compromised host | Log gap alert fires; auditd process not running | Do NOT SSH to the host. Use out-of-band console access. Capture forensic image. The already-shipped logs are the primary evidence. |
| Hash chain broken | Verification script reports chain break at a specific batch | `verify-hash-chain.py` identifies the exact batch with the break | Investigate: is the break from a legitimate issue (shipper restart, missed batch) or tampering? Compare primary (Axiom) and archival (S3) copies. |
| Network outage prevents shipping | Logs accumulate locally; gap in centralized storage | Vector backlog metrics increase; log gap alert fires | Vector disk buffer holds events (configure buffer size for expected outage duration). Events ship automatically when network restores. |

## When to Consider a Managed Alternative

**Transition point:** Building tamper-proof log infrastructure requires: immutable storage configuration, hash-chaining implementation, gap detection alerting, and dual-shipping pipeline. For teams without dedicated security engineering, this is 20-30 hours of initial setup.

- **[Axiom](https://axiom.co):** Immutable storage by design. All data in Axiom is append-only. No configuration needed for immutability. 500GB/month free tier. Serverless query. This is the simplest path to tamper-proof log storage.
- **[Grafana Cloud](https://grafana.com/cloud):** Managed [Loki](https://grafana.com/oss/loki/) for log storage. Not inherently immutable, but provider-managed infrastructure is significantly harder for an attacker to compromise than self-managed.
- **[Better Stack](https://betterstack.com):** Integrated logging + incident management. Managed storage with retention controls.
- **[Backblaze](https://www.backblaze.com) B2 / [Wasabi](https://wasabi.com):** Cheapest immutable object storage ($0.006/GB/month) for long-term archival alongside a queryable primary (Axiom or [Grafana](https://grafana.com) Cloud).

**Premium content pack:** Log integrity toolkit. Vector pipeline configs for dual-shipping (queryable + immutable), hash-chaining scripts (Python), verification scripts, S3 Object Lock configuration templates, Prometheus alert rules for gap detection, and IAM policy templates for write-only shipping.


## Related Articles

- [Building a Security Audit Log Pipeline That Scales: auditd to Elasticsearch](/articles/observability/audit-log-pipeline/)
- [Kubernetes Audit Log Pipeline Design: From API Server to SIEM](/articles/observability/k8s-audit-log-design/)
- [OpenTelemetry for Security: Distributed Tracing of Authentication and Authorization Flows](/articles/observability/otel-security-tracing/)
- [Centralized Logging Architecture for Security: Fluentd, Vector, and Loki Compared](/articles/observability/centralized-logging/)
- [Lateral Movement Detection: Network Patterns, Authentication Anomalies, and Alert Correlation](/articles/observability/lateral-movement-detection/)
