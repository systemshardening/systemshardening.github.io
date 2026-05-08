---
title: "Audit Logging Architecture: Designing Tamper-Resistant, Compliance-Ready Audit Trails"
description: "Audit logs that aren't tamper-resistant, complete, and correlated are useless for incident response and compliance. Designing audit logging requires defining what events to capture, ensuring log integrity, centralising across services, and enabling efficient querying. This guide covers event schema design, tamper protection, correlation, and compliance requirements."
slug: audit-logging-architecture
date: 2026-05-07
lastmod: 2026-05-07
category: cross-cutting
tags:
  - audit-logging
  - log-architecture
  - compliance
  - tamper-protection
  - siem
personas:
  - security-engineer
  - compliance-engineer
article_number: 617
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/cross-cutting/audit-logging-architecture/
---

# Audit Logging Architecture: Designing Tamper-Resistant, Compliance-Ready Audit Trails

## Problem

After a breach, you need to reconstruct what happened. The questions are always the same: which account acted, what did they touch, when did the first anomalous event occur, and how far did lateral movement reach? If your audit logs cannot answer those questions — because events were not captured, because the attacker deleted them, because they live in 14 different formats across 9 different systems with no correlation IDs — the forensic investigation stalls and the compliance answer becomes "we don't know."

Most organisations have logs. Few have audit logging architecture. The difference:

- **Logs** are operational noise — application stdout, nginx access logs, kernel messages.
- **Audit logs** are a structured record of security-relevant decisions and actions, designed from the start to be tamper-resistant, correlated, and retained for a defined period to satisfy both forensic and compliance requirements.

Audit logs that an attacker can erase are not audit logs. Audit logs that cannot be queried across services do not support incident response. Audit logs without a defined schema cannot be parsed by a SIEM. Getting the architecture right is a design decision made before the first line of code is written, not a retrofit.

This guide covers what must be logged and why, event schema design, tamper protection mechanisms, centralised aggregation, integrity verification, correlation, compliance requirements, retention, and separation of duties for log access.

## What Must Be Logged

The starting question is not "what does our logging library emit" but "what events, if unrecorded, would prevent us from answering security questions or satisfying a compliance audit?"

### Authentication Events

Every authentication attempt — success or failure — must produce an audit record. This means:

- Successful login (password, SSO, certificate, API key).
- Failed login with the reason (bad password, account locked, expired credential, MFA failure).
- MFA enrolment, removal, and bypass.
- Session creation and termination.
- Password and credential changes.
- Token issuance (OAuth access tokens, refresh tokens, service account tokens).

Why: authentication events establish the timeline. An attacker who compromised credentials will appear in the authentication log before they appear anywhere else. Failed logins reveal brute-force attempts. MFA removal events are a near-certain indicator of account takeover.

### Authorisation Decisions — Especially Denials

Every authorisation check that results in a denial must be logged. Granted access should also be logged for sensitive resources. The authorisation log answers "who tried to do what they were not allowed to do."

Why denials matter: an attacker probing your system generates a trail of permission denials before they find a path that works. Without denial logging you see the successful exploit but not the reconnaissance that preceded it.

### Data Access for Sensitive Resources

Access to PII, financial records, health data, secrets, and cryptographic material must be logged at the record level where feasible — not just at the API endpoint level.

Why: a SELECT query that exfiltrates 50,000 customer records passes through your application layer without triggering any alert unless you are logging data access. Database-level audit logs (PostgreSQL's `pgaudit`, MySQL's audit plugin, Oracle Unified Auditing) capture this. Application-level logs must record which user triggered a bulk export or accessed a record flagged as sensitive.

### Administrative Actions

User creation and deletion, role assignment and revocation, group membership changes, API key issuance and revocation — every administrative action that changes the security posture of the system must be logged.

Why: privilege escalation attacks frequently involve administrative actions. An insider threat will create a backdoor account or escalate their own role. If you only log authentication but not role changes, you cannot see the backdoor creation.

### Configuration Changes

Changes to infrastructure configuration, security group rules, IAM policies, TLS certificates, encryption keys, firewall rules, and application configuration that affects security behaviour must produce audit records.

Why: misconfiguration is the leading cause of cloud security incidents. A change that opened an S3 bucket to public access, weakened a firewall rule, or disabled MFA enforcement needs to be in the audit trail so the change can be attributed, reviewed, and reversed.

## Event Schema Design

Unstructured log lines cannot be parsed at scale. A consistent, machine-readable schema across all services is a prerequisite for centralised analysis. The fields every audit event must carry:

```json
{
  "timestamp": "2026-05-07T14:23:01.834Z",
  "event_id": "01HWZQX5P3BTJG6KQVHZ9M4YN",
  "request_id": "req_7f2a3b9c-1234-4d5e-8abc-def012345678",
  "event_type": "auth.login.success",
  "actor": {
    "id": "user_a1b2c3d4",
    "email": "alice@example.com",
    "ip": "203.0.113.42",
    "user_agent": "Mozilla/5.0 ...",
    "session_id": "sess_89xyz"
  },
  "action": "LOGIN",
  "resource": {
    "type": "user_account",
    "id": "user_a1b2c3d4",
    "name": "alice@example.com"
  },
  "result": "SUCCESS",
  "service": "identity-service",
  "environment": "production",
  "metadata": {
    "mfa_method": "totp",
    "auth_provider": "local"
  }
}
```

The mandatory fields map to the six investigative questions:

| Field | Question | Notes |
|---|---|---|
| `actor.id`, `actor.email` | **Who** acted | Stable identifier, not just display name |
| `action`, `event_type` | **What** happened | Namespaced (domain.entity.verb) |
| `timestamp` | **When** | ISO 8601 with milliseconds, UTC always |
| `resource` | **What** was affected | Type and stable ID |
| `actor.ip`, `service` | **Where** | Origin IP and which service handled it |
| `result`, `metadata` | **How / Why** | Outcome and contextual detail |

The `request_id` is the correlation key. It must be generated at the outermost entry point (API gateway, load balancer, or frontend service) and propagated via headers (`X-Request-ID`, `traceparent`) through every downstream service call. When a single user action produces events in 10 services, the `request_id` ties them together.

Use a namespaced event type taxonomy rather than free text: `auth.login.success`, `authz.permission.denied`, `data.record.read`, `admin.user.created`, `config.policy.updated`. This allows SIEM rules and queries to match on structured fields rather than regex against log lines.

## Tamper Protection

A compromised application server must not be able to erase or modify its own audit trail. This is a non-negotiable architectural constraint.

### Write-Once Destinations

Audit logs must be shipped to a destination the application cannot delete from:

- **AWS S3 with Object Lock (WORM mode):** once written, objects cannot be deleted or overwritten for the configured retention period. S3 Object Lock in Compliance mode cannot be removed even by root.
- **GCS with Bucket Lock:** equivalent for Google Cloud.
- **Azure Immutable Blob Storage:** similar WORM guarantee.
- **Hardware write-once media (WORM tapes):** still used for long-term archival in regulated industries.

The write path must be one-way. The application service account has `s3:PutObject` but never `s3:DeleteObject` or `s3:PutObjectAcl`. Separate IAM roles manage lifecycle policies.

### Cryptographic Log Chaining

Each log record includes the cryptographic hash of the previous record. This creates a chain where any deletion or modification of a record breaks the hash chain, making tampering detectable.

AWS CloudTrail implements this natively via the log file validation feature: each log file includes a SHA-256 digest of its contents and the digest of the previous file, all signed with a CloudTrail-owned key. Running `aws cloudtrail validate-log-files` detects any gap or modification.

For internal application audit logs, implement the same pattern:

```python
import hashlib, json

def chain_event(event: dict, previous_hash: str) -> dict:
    event["previous_hash"] = previous_hash
    canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
    event["hash"] = hashlib.sha256(canonical.encode()).hexdigest()
    return event
```

Store the chain tip in a separate, access-controlled location. Periodic verification replays the chain and checks every hash.

### External Write-Only Log Shipping

Audit events must leave the originating system before they can be tampered with. The pattern:

1. Application emits audit events to a local write-ahead buffer (file or queue).
2. A log shipper agent (Fluent Bit, Vector, Filebeat) reads the buffer and forwards to the centralised log platform over TLS.
3. The receiving platform is in a separate account or tenancy with no trust relationship to production.
4. The application has no credentials that allow it to reach the log platform directly — the shipper runs with a separate identity.

If an attacker achieves root on the application server, they can corrupt the local buffer. They cannot reach the centralised platform because the application's IAM role does not have that permission, and the shipper's credentials are separate. The events already forwarded are already out of reach.

## Centralised Log Aggregation

Running separate log stores per service makes cross-service queries impossible during an incident. All audit logs must converge to a single platform that the application cannot write to directly.

Common platforms:

- **Elasticsearch / OpenSearch with dedicated security indices:** ship via Logstash or Vector; restrict write access to shipper service accounts; enable Index Lifecycle Management for retention.
- **Splunk:** mature SIEM with strong compliance reporting; expensive at scale; use Heavy Forwarders in a separate network zone.
- **Google Chronicle:** cloud-native SIEM designed for security logs; ingestion at scale; correlated against Google threat intelligence.
- **AWS Security Lake:** aggregates findings from CloudTrail, VPC Flow Logs, Route 53, Security Hub into S3 in OCSF format; queryable via Athena.
- **Microsoft Sentinel:** Azure-native SIEM; strong integration with Entra ID, Defender, and Azure Monitor.

The aggregation tier must be in a separate administrative domain. The team that operates production applications must not have permission to modify or delete records in the SIEM. The team that operates the SIEM must not have permission to modify production applications. This is separation of duties at the infrastructure level, not just at the policy level.

Ingest via a push model (shipper → SIEM) rather than pull. A pull-based model requires the SIEM to have read access to production systems, widening the attack surface on the SIEM's credentials.

## Log Integrity Verification

Shipping logs to a central platform is not sufficient. You must also verify that what arrived is what was sent, and that the chain is unbroken.

**AWS CloudTrail log file validation:** enable it at trail creation. Each validation run checks the hash chain and reports any gaps. Automate this on a schedule:

```bash
aws cloudtrail validate-log-files \
  --trail-arn arn:aws:cloudtrail:us-east-1:123456789012:trail/prod-audit \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

Alert on any validation failure as a P1 security event.

**Sequence number gaps:** each audit event should carry a monotonically increasing sequence number per service. The SIEM ingestion pipeline checks for gaps. A gap means either a transmission failure (recoverable from the local buffer) or deliberate deletion (security incident).

**Cross-system reconciliation:** for high-value events — all administrative actions, all authentication events — cross-reference counts between the source system's local record and the SIEM. A count discrepancy triggers an alert.

## Correlation Design

A single user action in a modern microservices application touches many services. A login triggers the identity service, the session service, the notification service, and potentially a risk-scoring service. An API call traverses an API gateway, an authorisation service, one or more backend services, and a database proxy. Without correlation, these events appear as independent, unrelated records.

The request ID is the correlation primitive. Generate it once, propagate it everywhere:

**At the API gateway or load balancer:**
```nginx
map $http_x_request_id $request_id {
    default $http_x_request_id;
    ""      $request_id;
}
proxy_set_header X-Request-ID $request_id;
```

**In each service (Python example):**
```python
import contextvars

request_id: contextvars.ContextVar[str] = contextvars.ContextVar("request_id")

def audit_log(event_type: str, **kwargs):
    emit({
        "request_id": request_id.get("unknown"),
        "event_type": event_type,
        **kwargs
    })
```

**Propagate to async workers:** when an API call enqueues a background job, pass the request ID as a job attribute. The worker includes it in its audit events. One user action now correlates across synchronous and asynchronous processing.

**Propagate to databases:** use `SET application_name` or `SET LOCAL audit.request_id` in PostgreSQL to include the request ID in `pgaudit` output. The database audit log then correlates with the application audit log.

The payoff: during an incident, a single SIEM query for `request_id = "req_7f2a3b9c-..."` returns every event produced by that user action across every service, in chronological order.

## Compliance Requirements

Audit logging requirements are not optional recommendations. They are mandated controls in every major compliance framework:

**SOC 2 (CC7.2):** requires that the organisation monitors system components for anomalies and that audit trails are enabled for all system components. CC7.2 specifically requires detection of anomalous activity, which requires correlated audit logs that support querying.

**PCI DSS Requirement 10:** the most prescriptive audit logging requirement in any framework. PCI DSS 10.2 mandates logging of: all individual user access to cardholder data, all root/administrative actions, access to audit trails, invalid logical access attempts, use of identification and authentication mechanisms, changes to identification and authentication mechanisms, and changes to system-level objects. PCI DSS 10.3 requires protecting audit logs from destruction and modification. PCI DSS 10.5 requires retaining audit logs for at least 12 months, with at least 3 months immediately available.

**HIPAA (45 CFR § 164.312(b)):** the Audit Controls standard requires covered entities to implement hardware, software, and/or procedural mechanisms that record and examine activity in systems that contain ePHI. HIPAA does not specify a retention period in the Security Rule, but the minimum is 6 years under the Documentation requirements (45 CFR § 164.530(j)).

**GDPR:** audit logs themselves contain personal data (IP addresses, user identifiers). Processing audit logs is a legitimate interest (Article 6(1)(f)) and in many cases a legal obligation (Article 6(1)(c)). The privacy-specific requirement is that you document the lawful basis for audit log retention and do not retain logs beyond what is necessary — creating a tension with long compliance retention requirements that must be managed with explicit policy.

**ISO 27001 (A.8.15):** requires logging of events and generation, storage, protection, and analysis of logs. The Annex A control requires that logs are protected against tampering.

## Retention Policy

Retention must be defined per log category, aligned with compliance requirements, and enforced automatically:

| Log category | Minimum retention | Recommended |
|---|---|---|
| Authentication events | 12 months (PCI) | 24 months |
| Authorisation denials | 12 months | 24 months |
| Administrative actions | 12 months (PCI) | 36 months |
| Data access (PII/PHI) | 6 years (HIPAA) | 7 years |
| Configuration changes | 12 months | 24 months |
| Operational logs | 30–90 days | 90 days |

Implement retention in tiers: hot (SIEM, immediately queryable) for recent logs, warm (S3 Standard-IA or GCS Nearline) for months 3–12, cold (S3 Glacier or tape) for compliance archival. Automated lifecycle rules handle the transitions. The SIEM's retention setting must not be the only control — the immutable object store is the retention guarantee; the SIEM is the query layer.

## Separation of Duties for Log Access

The people who run production systems must not be able to modify audit logs. The people who manage audit infrastructure must not be able to use their access to cover their own tracks. This requires explicit access control architecture:

- **Operations team:** can read operational logs (for debugging) but has no access to the security audit log store or SIEM security indices.
- **Security team:** can read and query audit logs in the SIEM but cannot delete records, modify retention policies, or change the log pipeline configuration.
- **Audit log infrastructure team:** can modify the pipeline and retention configuration but does not have query access to log content (they manage the pipe, not the data).
- **Compliance / legal:** read-only access to audit reports generated from the SIEM; no direct query access.

Implement this with IAM role separation, not just process separation. The SIEM's administrative API must require a different role than the query API. S3 bucket policies must deny `s3:DeleteObject` to all roles except the automated lifecycle function, and that function must only delete records past the retention age.

All access to the audit log system itself — the SIEM, the log pipeline, the immutable store — must be logged in a meta-audit log in a separate, isolated account. A security team member querying the SIEM is logged. A pipeline configuration change is logged. The meta-audit log is the audit log for your audit log infrastructure.

## Implementation Checklist

Before declaring an audit logging architecture production-ready, verify:

- [ ] Event schema documented with mandatory fields; enforced at the shipper or library level, not at each call site.
- [ ] `request_id` generated at the API gateway and propagated to all downstream services and async workers.
- [ ] Audit logs ship to a write-once destination (S3 Object Lock, GCS Bucket Lock) before the application can be compromised.
- [ ] Cryptographic hash chain implemented; validation runs on a schedule; validation failures alert P1.
- [ ] Application IAM roles do not have `DeleteObject` or equivalent on the audit log destination.
- [ ] All authentication events, authorisation denials, administrative actions, and configuration changes are captured.
- [ ] Data access logging enabled at the database layer for tables containing PII, PHI, or financial data.
- [ ] Centralised SIEM in a separate administrative domain from production.
- [ ] Retention tiers configured and enforced by automated lifecycle rules, not manual process.
- [ ] Operations team cannot read security audit indices; security team cannot delete records.
- [ ] GDPR lawful basis documented for each log category retained.
- [ ] Compliance-specific requirements validated: PCI 10.x, SOC 2 CC7.2, HIPAA 164.312(b).

Audit logging architecture is not a post-deployment concern. By the time you ship the first version of a service, the schema is defined, the correlation ID is propagated, the shipper is configured, and the destination is immutable. Everything else is a forensic liability.
