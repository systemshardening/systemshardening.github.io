---
title: "Forensic Readiness: Log Retention, Capture, and Chain of Custody for Incident Response"
description: "What you don't capture, you can't investigate. Forensic readiness is the discipline of designing the logging layer so post-incident you have what you need."
slug: "forensic-readiness"
date: 2026-04-29
lastmod: 2026-04-29
category: "observability"
tags: ["forensic-readiness", "incident-response", "logging", "retention", "audit"]
personas: ["security-engineer", "soc-analyst", "compliance"]
article_number: 229
difficulty: "intermediate"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/observability/forensic-readiness/index.html"
---

# Forensic Readiness: Log Retention, Capture, and Chain of Custody for Incident Response

## Problem

When an incident happens, the question isn't "what's our SIEM doing right now?" It's "what data do we have from the past N days, and can we reconstruct what happened?" The difference between answerable and unanswerable depends on decisions made months earlier — what was logged, how long it was kept, whether the integrity is verifiable, whether it's been processed in ways that destroy detail.

Forensic readiness is the discipline of designing the logging and retention layer so that post-incident the SOC has what it needs. ISO 27037 and NIST SP 800-86 cover the methodology; production engineering operationalizes it.

The dimensions:

- **What to capture proactively.** Not every event is interesting at logging time, but is at incident time.
- **Retention strategy.** Hot for routine, cold for long-tail forensic.
- **Integrity preservation.** Logs must be tamper-evident; an attacker who compromises a host shouldn't be able to delete their tracks.
- **Chain of custody.** When logs become evidence in a legal context, their handling must be documented.
- **Capture-time vs. analysis-time decisions.** Some processing (PII redaction, sampling) loses information that's needed later; trade-offs require thought.
- **Time synchronization.** Logs without consistent timestamps across hosts are nearly useless for cross-host correlation.

By 2026 the toolchain is mature: forwarder agents (Vector, Fluent Bit, Cribl), tamper-evident sinks (S3 Object Lock, Azure immutable storage), structured-log standardization (OpenTelemetry, ECS), legal hold automation. The challenge is the policy and operational discipline.

The specific gaps in unprepared environments:

- Logs retained 7-14 days; an attack discovered after 30 days has no logs.
- High-cardinality fields aggregated at ingest; per-event detail lost.
- Log forwarding agent runs as root with write access to its own logs.
- Time skew across hosts means cross-host correlation requires manual reconciliation.
- Audit logs for the audit pipeline itself are missing.
- "Sensitive" logs auto-redacted before analysis, removing the very content forensics needs.

This article covers the proactive-capture decisions, retention tiering, tamper-evident storage, time-sync requirements, chain-of-custody patterns, and the legal-hold automation. The goal: when an incident happens, the data is there.

**Target systems:** Vector / Fluent Bit / Cribl as forwarders; S3 with Object Lock or Azure Storage immutable blobs; Splunk / Elastic / Loki for hot retention; cold tier in S3 Glacier / GCS Coldline / Azure Archive; chrony / systemd-timesyncd for time.

## Threat Model

Different from typical articles — the failure modes here are about preparedness, not active attackers:

- **Adversary 1 — Slow-burn attacker:** activity over weeks or months. Detection happens after retention has rolled past evidence.
- **Adversary 2 — Log-tampering attacker:** has root on a host; deletes / modifies local logs to cover tracks before forwarder ships them.
- **Adversary 3 — Forwarder-agent compromise:** the log-forwarding agent itself is compromised; modifies logs in transit.
- **Adversary 4 — Insider abusing audit access:** has legitimate read access to logs; tries to alter or delete to cover their own actions.
- **Adversary 5 — Compliance gap:** investigator / auditor / regulator needs logs for a specific time range; logs unavailable.
- **Access level:** Adversary 1 has any attacker capability. Adversary 2 has compromised a host with root. Adversary 3 has compromised the log-forwarder. Adversary 4 has audit-store access. Adversary 5 has audit / regulator status.
- **Objective:** Hide actions from forensic review; cause investigation to fail or be inconclusive.
- **Blast radius:** investigations conclude "we don't know what happened"; actor goes uncaught; insurance / legal positions weaken.

## Configuration

### Step 1: Decide What to Capture Proactively

For incident response, you typically need:

- **Process / command execution.** Linux: auditd `execve`, eBPF process events. Windows: Event 4688. Containers: Falco, Tetragon.
- **Authentication events.** Successful logins, failed logins, privilege escalations.
- **Network connections.** Outbound to external IPs, internal to sensitive services.
- **File modifications.** In sensitive directories (`/etc`, `/var/lib/<app>`, `/usr/bin`).
- **API audit.** Cloud provider (CloudTrail, Audit Logs), Kubernetes audit, SaaS audit logs.
- **Application-level events.** Login, password change, key rotation, role assumption.
- **Network metadata.** Connection 5-tuples, DNS queries, TLS SNI (if accessible).
- **Configuration changes.** Infrastructure-as-code applies, kubectl applies, manual edits.

Capture each at the lowest practical layer:

```yaml
# auditd rules: process execution + network + file modifications.
-a always,exit -F arch=b64 -S execve -k execution
-a always,exit -F arch=b64 -S socket -F a0=2 -k network_socket
-w /etc/passwd -p wa -k passwd_changed
-w /etc/shadow -p wa -k shadow_changed
-w /etc/sudoers.d -p wa -k sudoers_changed
-w /usr/bin -p wa -k userland_modified
```

Decide capture by threat model, not "log everything." High-volume noise floods the pipeline; selectivity preserves signal.

### Step 2: Tier Retention by Forensic Need

```yaml
retention_tiers:
  hot:
    duration: 30 days
    queryable: <1 second
    use: real-time detection, ongoing investigations
    cost_per_gb_month: $5

  warm:
    duration: 90 days
    queryable: <1 minute
    use: 30+ day investigations, recent compliance
    cost_per_gb_month: $1

  cold:
    duration: 1 year
    queryable: <1 hour (with retrieval)
    use: long-tail investigations, regulatory compliance
    cost_per_gb_month: $0.10

  archive:
    duration: 7 years
    queryable: <24 hours (restore from glacier)
    use: legal hold, lifetime regulatory compliance
    cost_per_gb_month: $0.004
```

The retention period is policy-driven, not technology-driven. PCI-DSS requires 1 year; HIPAA 6 years; SEC retention can be 7. Within those, what's critical is having tiers, not having everything in hot.

For a typical environment:

- Authentication logs: hot 30d, warm 90d, cold 1y, archive 7y.
- Application access logs: hot 14d, warm 60d, cold 1y, archive 3y.
- Network metadata: hot 7d, warm 30d, cold 90d.
- Cloud audit logs: hot 30d, archive 7y (regulatory minimum).

### Step 3: Tamper-Evident Storage

Cold and archive tiers must be immutable. S3 Object Lock provides this:

```python
import boto3

s3 = boto3.client("s3")

# Enable Object Lock on the bucket (one-time, at bucket creation).
s3.put_object_lock_configuration(
    Bucket="myorg-forensic-logs",
    ObjectLockConfiguration={
        "ObjectLockEnabled": "Enabled",
        "Rule": {
            "DefaultRetention": {
                "Mode": "COMPLIANCE",
                "Days": 2555,   # 7 years
            }
        },
    },
)
```

`COMPLIANCE` mode means even bucket admins cannot delete objects within the retention period. `GOVERNANCE` mode is similar but allows authorized override; for true legal hold, COMPLIANCE.

Pair with content-hashing at ingest:

```python
# At log-ingest time.
def ship_to_archive(log_payload):
    payload_bytes = json.dumps(log_payload).encode()
    sha256 = hashlib.sha256(payload_bytes).hexdigest()

    # Store the log.
    s3.put_object(
        Bucket="myorg-forensic-logs",
        Key=f"{date_path}/{ingest_id}.json.gz",
        Body=gzip.compress(payload_bytes),
        Metadata={"sha256": sha256, "ingest-time": datetime.now(tz=UTC).isoformat()},
        ObjectLockMode="COMPLIANCE",
        ObjectLockRetainUntilDate=datetime.now(tz=UTC) + timedelta(days=2555),
    )

    # Separately, write the hash + key to a tamper-evident chain.
    chain_db.append({
        "ingest_id": ingest_id,
        "sha256": sha256,
        "s3_key": f"{date_path}/{ingest_id}.json.gz",
        "ingest_time": datetime.now(tz=UTC).isoformat(),
    })
```

Periodically post the hash chain itself to a transparency log (Sigstore Rekor or similar). Provides cryptographic evidence that a specific log existed at a specific time.

### Step 4: Time Synchronization Requirements

Cross-host correlation requires consistent time. Skew of seconds is OK; skew of minutes makes investigations impossible.

```bash
# /etc/chrony/chrony.conf — strict time-sync.
pool 2.pool.ntp.org iburst
maxdistance 16
makestep 1.0 3
rtcsync
```

Monitor time-sync health:

```
chrony_offset_seconds
chrony_stratum
chrony_root_dispersion
```

Alert on:

- Offset > 1 second.
- Stratum > 3.
- Time source unreachable for > 5 minutes.

For high-stakes environments (financial, regulated), use chronyd with multiple sources and manual stratum-1 servers.

### Step 5: Forwarder Hardening

The log forwarder is the chokepoint between log producers and the archive. Compromise means logs can be modified or dropped.

```yaml
# Vector config snippet — running as non-root, with cap_sys_admin only for log capture.
data_dir: /var/lib/vector
log_level: info

sources:
  systemd:
    type: systemd
    units: ["nginx.service"]
  auditd:
    type: file
    include: ["/var/log/audit/audit.log"]
  k8s:
    type: kubernetes_logs
    auto_partial_merge: true

transforms:
  redact_pii:
    type: remap
    inputs: [systemd, auditd, k8s]
    source: |
      .body = redact(.body, filters: [/email/, /credit_card/])

sinks:
  s3_archive:
    type: aws_s3
    inputs: [redact_pii]
    bucket: myorg-forensic-logs
    region: us-east-1
    encoding:
      codec: ndjson
    compression: gzip
    object_lock:
      mode: COMPLIANCE
      retain_for_seconds: 220752000   # 7 years
```

The Vector process runs as user `vector` with `chown` on its data dir. The S3 sink writes with Object Lock. Compromised forwarder cannot delete or alter what's already shipped.

### Step 6: Chain of Custody for Investigations

When a specific incident requires evidence preservation:

```yaml
# legal-hold-procedure.md
incident_id: SEC-2026-Q2-INC-007
incident_classification: HIGH
opened: 2026-04-29T14:00:00Z

evidence_capture_sequence:
  1: Identify time range and affected systems.
  2: Place legal hold on relevant log buckets (locks rolling deletion for the range).
  3: Snapshot the relevant logs to a separate, write-protected bucket with case ID prefix.
  4: Document the sha256 of each captured artifact.
  5: Restrict access to the captured bucket to investigation team only.
  6: For physical evidence (host disk images), follow your physical chain of custody.

investigation_log:
  - actor: alice@example.com
    timestamp: 2026-04-29T14:15:00Z
    action: "Initial triage"
    artifacts_accessed: [s3://myorg-forensic-logs/legal-hold/inc-007/access-logs.json.gz]
  - actor: bob@example.com
    timestamp: 2026-04-29T15:30:00Z
    action: "Analysis of authentication events"
    artifacts_accessed: [...]
```

Treat investigation as audited activity. Every analyst's access to evidence is logged. Standard SOAR tools (Splunk SOAR, Cortex XSOAR) provide this; for self-hosted, use a structured ticket + automated evidence-store access logging.

### Step 7: Tamper-Detection Monitoring

Periodically verify the archive's integrity:

```python
# scripts/verify_archive_chain.py
import boto3, hashlib, json, gzip

s3 = boto3.client("s3")

def verify_chain(start_date, end_date):
    failures = []
    for entry in chain_db.iter_range(start_date, end_date):
        # Fetch the object.
        resp = s3.get_object(Bucket="myorg-forensic-logs", Key=entry["s3_key"])
        actual_sha256 = hashlib.sha256(gzip.decompress(resp["Body"].read())).hexdigest()
        if actual_sha256 != entry["sha256"]:
            failures.append({
                "key": entry["s3_key"],
                "expected": entry["sha256"],
                "actual": actual_sha256,
            })
    return failures

# Run weekly.
failures = verify_chain(date_a_week_ago, today)
if failures:
    alert_security_team("Forensic archive integrity check failed", failures)
```

A failure indicates either tampering or a bug; either way, immediate investigation. Ongoing chain integrity means logs can be relied on for legal proceedings.

### Step 8: Audit-Pipeline-Itself Audit

The audit pipeline is itself an attack target. Audit it.

- Who has access to forwarder configs? Log-pipeline modifications should be CI-gated and PR-reviewed.
- Who has access to the archive bucket? Cloud IAM audit.
- What changes have been made to retention policy? Policy-as-code in Git history.

```bash
# Quarterly: audit the pipeline.
# Who has read access to forensic archive?
aws s3api get-bucket-policy --bucket myorg-forensic-logs

# Who has S3 GetObject permission anywhere on this bucket?
aws iam list-policies --query 'Policies[?contains(Document, `myorg-forensic-logs`)]'
```

### Step 9: Telemetry on the Forensic Pipeline

```
forensic_logs_ingested_bytes_total{tier, source}
forensic_logs_archive_objects_total{bucket}
forensic_archive_integrity_check_failures_total
forensic_legal_hold_active_total
forensic_evidence_access_total{case_id, analyst}
forensic_pipeline_latency_seconds{stage}
```

Alert on:

- `forensic_archive_integrity_check_failures_total` non-zero — tampering or corruption.
- `forensic_pipeline_latency_seconds` rising — logs not landing in archive at expected rate.
- Unusual `forensic_evidence_access_total` patterns — investigation activity.

## Expected Behaviour

| Signal | Without forensic readiness | With |
|--------|------------------------------|--------|
| Investigate incident from 60 days ago | Logs rolled past retention | Hot or warm tier still has them |
| Reconstruct cross-host activity | Time-skew complicates | Synchronized time + structured logs |
| Verify a specific log wasn't modified | Trust-the-storage | Hash-chain verifies |
| Comply with legal hold | Manual; risky | Automated; immutable storage |
| Audit who accessed evidence | Logs may not exist | Structured per-access log |
| Cost of retention | Often hot for everything | Tiered; minimum cost for legal-grade retention |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Tiered retention | Cost-effective long-term storage | Cold-tier queries are slower | Investigations within first 30 days hit hot/warm; long-tail investigations accept cold-tier delay. |
| Object Lock immutability | Tamper-resistant | Cannot correct genuinely-bad data (typos, etc.) | Compromise: use governance mode with strict access; reserve compliance mode for highest-risk data. |
| Hash-chain verification | Cryptographic integrity proof | Compute / storage overhead | Periodic vs. continuous verification; per-batch hashing is cheap. |
| Time-sync strictness | Cross-host correlation works | Operational discipline for chrony | Standard configuration; one-time setup. |
| Centralized forwarder | Single observation point for archive | Forwarder is a chokepoint | Run forwarder in HA; harden as critical infrastructure. |
| Per-access audit | Forensic clarity | Logging volume + storage | Acceptable; archive access is rare. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Forwarder buffer exhaustion | Logs dropped at source | Forwarder metrics show buffer-full | Tune buffer size; ensure sink is healthy; back-pressure to source if needed. |
| Object Lock prevents legitimate deletion | Cannot remove malformed test logs | Test environment cluttered | Use governance mode for test environments; compliance only for prod. |
| Time skew breaks correlation | Cross-host investigations slow / inaccurate | Chrony / systemd-timesyncd metrics | Continuously monitor; alert on skew. |
| Hash-chain corruption | Verification fails | Integrity check fails on retrieval | Investigate; differentiate data corruption from tampering; restore from archive if possible. |
| Forwarder runs as root unnecessarily | Compromise = full host control | Process audit | Run as dedicated user with minimum capabilities. |
| Audit-pipeline attack window | Logs don't reach archive during attack | Pipeline-stage gap timestamps | Buffer at source so transient pipeline outage doesn't lose data. |
| Investigation accidentally deletes evidence | Object Lock prevents | Audit log shows attempted delete | Verifies the protection works; correct the analyst's intent; document. |

## Related Articles

- [Building a Security Audit Log Pipeline That Scales](/articles/observability/audit-log-pipeline/)
- [Log Integrity Patterns](/articles/observability/log-integrity/)
- [Centralized Logging Architecture for Security](/articles/observability/centralized-logging/)
- [SIEM Cost Optimization](/articles/observability/siem-cost-optimization/)
- [Incident Response Runbooks](/articles/observability/incident-response-runbooks/)
