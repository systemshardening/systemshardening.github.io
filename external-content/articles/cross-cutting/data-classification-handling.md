---
title: "Data Classification and Secure Handling: From Taxonomy to Technical Controls"
description: "Without a data classification scheme, engineers cannot make informed decisions about encryption strength, access control granularity, or retention periods. This guide covers defining a practical classification taxonomy, tagging data at source, enforcing handling controls per class, and operationalising classification through tooling."
slug: data-classification-handling
date: 2026-05-07
lastmod: 2026-05-07
category: cross-cutting
tags:
  - data-classification
  - data-handling
  - privacy
  - gdpr
  - information-security
personas:
  - security-engineer
  - compliance-engineer
article_number: 604
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/cross-cutting/data-classification-handling/
---

# Data Classification and Secure Handling: From Taxonomy to Technical Controls

## Problem

Engineers make dozens of implicit data-handling decisions every sprint: which fields to log, which columns to encrypt, which API responses to cache, which retention period to set. Without a classification scheme, each decision is a guess. The developer writing the user-management service does not know whether the `phone_number` field is as sensitive as `ssn`, whether the audit log needs the same access controls as the application log, or whether a 90-day retention period on a table containing health data is legally adequate.

The consequences are predictable:

- **Encryption mismatches.** Payment card numbers are encrypted at rest while equally sensitive health records are stored in plaintext because no policy connected the data type to an encryption requirement.
- **Overpermissive access.** A reporting service gets read access to an entire database because no one documented which columns were sensitive enough to require column-level access controls.
- **Log contamination.** PII fields appear in structured logs, which are shipped to a third-party SIEM. The legal team discovers this during a GDPR audit, triggering a remediation project that takes months.
- **Retention violations.** Data is kept indefinitely because no policy specified a maximum retention period. When a subject access request arrives, the legal team cannot delete records because they are spread across systems with no inventory.
- **Breach notification failures.** When a breach occurs, the incident response team cannot determine whether it triggers notification obligations because no one recorded what categories of data were in the affected system.

Data classification is the upstream control that makes all downstream decisions tractable. It answers the question: "what does this data require from us?" and lets that answer propagate into encryption policy, access control design, logging rules, and retention schedules automatically.

**Target systems:** Any engineering organisation storing, processing, or transmitting customer or employee data. The patterns here apply equally to relational databases, object storage, event streams, API layers, and data pipelines.

## Threat Model

- **Adversary 1 — Opportunistic breach of under-protected sensitive data:** An attacker compromises a service account with read access to a reporting database. Because no column-level access control was applied and encryption was not enforced on high-sensitivity columns, the attacker exfiltrates a table containing full names, email addresses, and health indicators. A classification scheme with enforced controls would have encrypted those columns with a key the service account could not access.
- **Adversary 2 — Insider bulk export:** An engineer with legitimate database access downloads a production dataset for local debugging. The download includes columns tagged Restricted. A classification-aware data access proxy would have required MFA re-authentication and produced an audit log entry flagged for review.
- **Adversary 3 — Log-based PII exposure:** A bug in the authentication service logs a full request body that includes a password reset token and email address. Those logs are shipped to a third-party aggregator. Classification-aware log filtering would have redacted or pseudonymised the email field before the log record left the service boundary.
- **Adversary 4 — Data pipeline classification stripping:** An ETL job extracts records from a Restricted source table, transforms them, and writes the output to a data warehouse table with no classification metadata. Downstream consumers treat the warehouse table as Internal and apply weaker controls. Classification preservation in pipeline metadata prevents this downgrade.

## Configuration

### Step 1: Define the Four-Tier Taxonomy

Most organisations benefit from exactly four tiers. Fewer tiers (two or three) collapse distinctions that matter for access control. More tiers create cognitive overhead that causes engineers to default to the wrong tier. Four tiers map cleanly to the spectrum from public information to regulated or highly sensitive data.

```yaml
# data-classification-policy.yaml
classification_tiers:
  PUBLIC:
    label: "Public"
    description: >
      Information intended for unrestricted distribution. Disclosure causes
      no harm. No special handling required.
    examples:
      - Marketing copy and press releases
      - Public API documentation
      - Open source code
      - Published pricing pages
    controls:
      encryption_at_rest: false
      encryption_in_transit: false
      authentication_required: false
      audit_logging: false
      retention_maximum_days: null  # No regulatory constraint

  INTERNAL:
    label: "Internal"
    description: >
      Information for employees and authorised contractors only. Disclosure
      causes reputational or operational harm but not regulatory exposure.
    examples:
      - Internal runbooks and architecture diagrams
      - Employee names and work contact details
      - Non-sensitive system configurations
      - Aggregated, non-identifiable business metrics
    controls:
      encryption_at_rest: false         # Recommended but not mandatory
      encryption_in_transit: true       # TLS required
      authentication_required: true     # Corporate SSO or API key
      audit_logging: false
      retention_maximum_days: 1825      # 5 years

  CONFIDENTIAL:
    label: "Confidential"
    description: >
      Information where disclosure causes significant harm: financial loss,
      regulatory exposure, or breach of contractual obligations. Includes PII
      not subject to strict regulation, business-sensitive data, and most
      customer data.
    examples:
      - Customer email addresses and phone numbers
      - Internal financial projections
      - Employee performance records
      - API keys and service credentials
      - Full names combined with behavioural data
    controls:
      encryption_at_rest: true          # AES-256 minimum
      encryption_in_transit: true       # TLS 1.2+ required
      authentication_required: true
      mfa_required: false
      audit_logging: true               # Read and write events
      retention_maximum_days: 1095      # 3 years (adjust per jurisdiction)

  RESTRICTED:
    label: "Restricted"
    description: >
      Information subject to specific regulatory frameworks or where exposure
      causes severe harm. Includes special-category personal data under GDPR,
      payment card data, health records, and credentials for privileged access.
    examples:
      - Full payment card numbers (CHD)
      - Social security and national insurance numbers
      - Health and medical records
      - Biometric identifiers
      - Special-category data under GDPR Article 9
      - Root credentials and signing keys
    controls:
      encryption_at_rest: true          # Customer-managed keys (CMK) required
      encryption_in_transit: true       # TLS 1.3 required
      authentication_required: true
      mfa_required: true                # MFA on every access session
      audit_logging: true               # All events, immutable log
      access_review_period_days: 90     # Quarterly access recertification
      retention_maximum_days: 365       # 1 year unless regulatory floor applies
      data_minimisation: strict         # Collect only fields strictly necessary
```

Post this taxonomy in your internal documentation wiki and in the data engineering onboarding guide. Classification is only useful if every engineer has seen it and can apply it without looking things up.

### Step 2: Tag Data at Source

Classification tags must attach to data at the point of creation, not retrospectively. Retrospective tagging through automated scanning (the approach taken by tools like AWS Macie) is useful for discovery, but it cannot substitute for declaring classification when you create the schema.

**Database column annotations (PostgreSQL with pg_comment):**

```sql
-- users table: column-level classification comments
CREATE TABLE users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username    TEXT NOT NULL,          -- classification:INTERNAL
    email       TEXT NOT NULL,          -- classification:CONFIDENTIAL
    phone       TEXT,                   -- classification:CONFIDENTIAL
    ssn         TEXT,                   -- classification:RESTRICTED
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Attach comments that tooling can parse
COMMENT ON COLUMN users.email IS 'classification:CONFIDENTIAL purpose:account_communication';
COMMENT ON COLUMN users.ssn   IS 'classification:RESTRICTED regulation:GDPR,CCPA purpose:identity_verification';
```

A CI job can parse these comments and fail the migration if a column is added without a classification comment:

```python
# check_column_classification.py — run in CI on every migration
import re
import sys
import psycopg2

REQUIRED_PATTERN = re.compile(r'classification:(PUBLIC|INTERNAL|CONFIDENTIAL|RESTRICTED)')

conn = psycopg2.connect(os.environ["CI_DB_DSN"])
cur = conn.cursor()
cur.execute("""
    SELECT table_name, column_name, col_description(
        (table_schema || '.' || table_name)::regclass,
        ordinal_position
    ) AS comment
    FROM information_schema.columns
    WHERE table_schema = 'public'
    ORDER BY table_name, ordinal_position
""")

missing = []
for table, column, comment in cur.fetchall():
    if comment is None or not REQUIRED_PATTERN.search(comment):
        missing.append(f"{table}.{column}")

if missing:
    print("ERROR: columns missing classification comment:")
    for col in missing:
        print(f"  {col}")
    sys.exit(1)

print(f"OK: all columns classified ({len(list)} checked)")
```

**Object storage metadata (AWS S3):**

Every object uploaded to S3 should carry a `classification` tag. Enforce this through a bucket policy that denies PutObject requests missing the tag:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireClassificationTag",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::data-lake-prod/*",
      "Condition": {
        "Null": {
          "s3:RequestObjectTag/classification": "true"
        }
      }
    }
  ]
}
```

Upload code must pass the tag explicitly:

```python
s3.put_object(
    Bucket="data-lake-prod",
    Key=f"exports/{filename}",
    Body=data,
    Tagging="classification=CONFIDENTIAL&purpose=billing_export",
    ServerSideEncryption="aws:kms",
    SSEKMSKeyId=KMS_KEY_ID,   # CMK for RESTRICTED, AWS-managed for CONFIDENTIAL
)
```

**OpenAPI schema tags for API responses:**

```yaml
# openapi.yaml
components:
  schemas:
    UserProfile:
      type: object
      properties:
        id:
          type: string
          x-classification: INTERNAL
        email:
          type: string
          x-classification: CONFIDENTIAL
          x-pii: true
          x-gdpr-purpose: account_communication
        phone:
          type: string
          x-classification: CONFIDENTIAL
          x-pii: true
        national_id:
          type: string
          x-classification: RESTRICTED
          x-pii: true
          x-gdpr-article: "9"
```

These `x-classification` extensions can be consumed by a code generator to produce response serialisers that automatically redact fields based on the caller's authorisation scope.

### Step 3: Enforce Technical Controls Per Tier

Controls must be applied automatically, not through developer discipline. Each tier maps to a concrete set of enforced technical requirements.

**Public — no special controls.** Data tagged Public can be served from a CDN without authentication, stored without encryption, and logged in full. No action required beyond confirming the tag is accurate.

**Internal — authentication required.** All endpoints serving Internal data must be behind authentication. Apply this at the API gateway or service mesh level:

```yaml
# Istio AuthorizationPolicy — require JWT for /internal paths
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: require-auth-internal
  namespace: production
spec:
  selector:
    matchLabels:
      app: api-gateway
  rules:
  - to:
    - operation:
        paths: ["/api/internal/*"]
    from:
    - source:
        requestPrincipals: ["*"]   # Any valid JWT; deny unauthenticated
```

**Confidential — encryption at rest and in transit, audit logging.**

Encryption at rest is enforced at the storage layer, not the application layer. Enable default encryption on every RDS instance and S3 bucket, and deny unencrypted writes through policy:

```terraform
# terraform: RDS with enforced encryption
resource "aws_db_instance" "primary" {
  identifier        = "app-primary"
  engine            = "postgres"
  instance_class    = "db.t3.medium"
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds_confidential.arn

  # Block deletion without snapshot; enforce final backup
  deletion_protection       = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "app-primary-final"
}
```

Audit logging for Confidential data should capture who accessed which records, not just HTTP access logs. Implement at the ORM or query layer:

```python
# Django: custom audit log middleware for Confidential model access
from django.utils import timezone
import logging

audit_logger = logging.getLogger("audit")

class AuditQuerySet(models.QuerySet):
    def filter(self, *args, **kwargs):
        qs = super().filter(*args, **kwargs)
        return AuditedQuerySet(self.model, qs.query)

class AuditedModel(models.Model):
    class Meta:
        abstract = True

    def __str_classification__(self):
        return getattr(self.__class__, 'classification', 'UNKNOWN')

    @classmethod
    def from_db(cls, db, field_names, values):
        instance = super().from_db(db, field_names, values)
        if cls.classification in ('CONFIDENTIAL', 'RESTRICTED'):
            audit_logger.info({
                "event": "data_access",
                "model": cls.__name__,
                "classification": cls.classification,
                "pk": instance.pk,
                "fields": field_names,
                "timestamp": timezone.now().isoformat(),
                # Injected by request middleware
                "actor": getattr(_thread_local, 'user_id', 'system'),
                "request_id": getattr(_thread_local, 'request_id', None),
            })
        return instance
```

**Restricted — customer-managed keys, strict access, MFA on access.**

Restricted data must use customer-managed KMS keys (CMK) so that key revocation is possible without deleting data:

```terraform
resource "aws_kms_key" "restricted_cmk" {
  description             = "CMK for Restricted-classified data"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccess"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "RestrictAccessToApprovedRoles"
        Effect = "Allow"
        Principal = {
          AWS = [
            aws_iam_role.restricted_data_service.arn,
            aws_iam_role.data_engineer_restricted.arn,
          ]
        }
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = "*"
        Condition = {
          Bool = { "aws:MultiFactorAuthPresent" = "true" }
        }
      }
    ]
  })
}
```

The `aws:MultiFactorAuthPresent` condition key in the KMS policy means that even a valid IAM role cannot decrypt Restricted data without an active MFA session. Sessions obtained through role assumption without MFA will receive `AccessDeniedException` from KMS.

Access to Restricted data should be reviewed quarterly. Automate access recertification by querying IAM and sending the result to the data owner for confirmation:

```bash
# access-recertification.sh — run quarterly via cron
aws iam list-entities-for-policy \
  --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/RestrictedDataAccess \
  --output json | jq -r '.PolicyGroups[].GroupName, .PolicyUsers[].UserName, .PolicyRoles[].RoleName' \
  | sort | uniq > /tmp/restricted-access-$(date +%Y%m).txt

# Email list to data owner for review
mail -s "Restricted data access review — $(date +%B %Y)" \
  data-owner@example.com < /tmp/restricted-access-$(date +%Y%m).txt
```

### Step 4: GDPR-Specific Handling for PII

Fields tagged `x-pii: true` in your schema carry obligations beyond encryption. GDPR requires:

**Purpose limitation.** Every PII field must have a documented purpose. Record this in the field's metadata comment:

```sql
COMMENT ON COLUMN users.email IS
  'classification:CONFIDENTIAL pii:true gdpr_purpose:account_communication,transactional_email gdpr_basis:contract';
```

The `gdpr_purpose` value must match one of the purposes listed in your privacy notice. A CI check can flag mismatches when purpose labels change.

**Data subject rights.** Implement a rights-request handler that can locate and delete all data for a given subject. This requires a data inventory: a registry of every table and object store that holds PII keyed by user identifier.

```python
# rights_handler.py — Subject Access Request (SAR) deletion
SUBJECT_DATA_LOCATIONS = [
    {"table": "users",        "key_column": "id",      "pii_columns": ["email", "phone", "name"]},
    {"table": "orders",       "key_column": "user_id", "pii_columns": ["shipping_address"]},
    {"table": "audit_events", "key_column": "actor_id","pii_columns": ["ip_address"]},
]

def handle_erasure_request(subject_id: str) -> dict:
    results = {}
    for location in SUBJECT_DATA_LOCATIONS:
        table = location["table"]
        key   = location["key_column"]
        cols  = location["pii_columns"]
        # Pseudonymise rather than delete rows where referential integrity
        # requires the row to remain (e.g. audit events)
        if table == "audit_events":
            db.execute(
                f"UPDATE {table} SET ip_address = 'REDACTED' WHERE {key} = %s",
                (subject_id,)
            )
        else:
            db.execute(f"DELETE FROM {table} WHERE {key} = %s", (subject_id,))
        results[table] = "erased"
    return results
```

**Retention schedules.** Automate deletion based on the `retention_maximum_days` value in the classification policy. A nightly job queries for rows older than the retention limit and deletes or anonymises them:

```python
# retention_enforcer.py
RETENTION_POLICY = {
    "users":          {"days": 1095, "action": "anonymise", "key": "created_at"},
    "payment_tokens": {"days": 365,  "action": "delete",    "key": "created_at"},
    "audit_events":   {"days": 2555, "action": "archive",   "key": "event_time"},
}

def enforce_retention():
    for table, policy in RETENTION_POLICY.items():
        cutoff = datetime.utcnow() - timedelta(days=policy["days"])
        if policy["action"] == "delete":
            db.execute(f"DELETE FROM {table} WHERE {policy['key']} < %s", (cutoff,))
        elif policy["action"] == "anonymise":
            db.execute(
                f"UPDATE {table} SET email='anon@deleted', phone=NULL, name='Deleted User'"
                f" WHERE {policy['key']} < %s", (cutoff,)
            )
```

**Processor agreements.** Every third-party service that processes PII — log aggregators, analytics platforms, CRM tools — must have a signed Data Processing Agreement (DPA) on file before PII is sent to it. Maintain a processor registry and block deployments that send PII to unregistered destinations.

### Step 5: PCI DSS for Payment Card Data

Cardholder data (CHD) — the primary account number (PAN), cardholder name, expiration date, and service code — requires controls beyond RESTRICTED tier defaults.

**Tokenisation.** Do not store the PAN after the initial authorisation. Exchange it for a token through your payment processor or a dedicated tokenisation vault. Store only the token and the last four digits:

```python
# payment_service.py
def save_payment_method(user_id: str, raw_pan: str, expiry: str) -> str:
    # Exchange PAN for a provider token; never persist raw_pan
    token_response = vault_client.tokenise(pan=raw_pan, expiry=expiry)
    db.execute(
        "INSERT INTO payment_methods (user_id, token, last_four, expiry_month, expiry_year) "
        "VALUES (%s, %s, %s, %s, %s)",
        (user_id, token_response.token, raw_pan[-4:],
         token_response.expiry_month, token_response.expiry_year)
    )
    return token_response.token
```

**Scope reduction.** Map every system that stores, processes, or transmits CHD. Move those systems into a dedicated network segment (the Cardholder Data Environment, CDE). Block all communication paths between the CDE and systems that do not need CHD access. The smaller the CDE, the lower the compliance burden.

```terraform
# Dedicated CDE subnet with restrictive NACLs
resource "aws_subnet" "cde" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.50.0/24"
  availability_zone = "eu-west-1a"
  tags = { Name = "cde", classification = "RESTRICTED", pci = "true" }
}

resource "aws_network_acl_rule" "deny_cde_default_egress" {
  network_acl_id = aws_network_acl.cde.id
  rule_number    = 32767
  egress         = true
  protocol       = "-1"
  rule_action    = "deny"
  cidr_block     = "0.0.0.0/0"
}
```

**Never log CHD.** Add a PAN detection check to your log pipeline that rejects records matching a Luhn-valid 16-digit sequence:

```python
# log_filter.py
import re

PAN_PATTERN = re.compile(r'\b(?:\d[ -]?){13,19}\b')

def redact_pan(log_record: dict) -> dict:
    record_str = json.dumps(log_record)
    if PAN_PATTERN.search(record_str):
        # Replace with a redaction marker; alert the security team
        record_str = PAN_PATTERN.sub('[PAN-REDACTED]', record_str)
        alert_security("PAN detected in log record", log_record.get("service"))
    return json.loads(record_str)
```

### Step 6: Classification-Aware Logging

Logs are the highest-risk PII leakage vector in most production systems. Apply these rules without exception:

**Pseudonymise identifiers before logging.** Replace email addresses and user IDs with a deterministic hash using an HMAC key that is rotated on a schedule. This allows correlating log events for a given user without exposing the raw identifier:

```python
import hmac, hashlib

LOG_HMAC_KEY = os.environ["LOG_PSEUDONYMISATION_KEY"].encode()

def pseudonymise(value: str) -> str:
    return hmac.new(LOG_HMAC_KEY, value.encode(), hashlib.sha256).hexdigest()[:16]

# In request logging middleware:
logger.info({
    "event": "api_request",
    "user_id": pseudonymise(request.user.id),   # Not the raw UUID
    "email_hash": pseudonymise(request.user.email),  # Not the raw email
    "endpoint": request.path,
    "status": response.status_code,
})
```

**Redact before shipping.** Apply a redaction filter at the log shipper layer (Fluent Bit, Logstash) so that even if an application emits PII, it is removed before reaching the SIEM or log aggregator:

```ini
# fluent-bit.conf
[FILTER]
    Name    lua
    Match   app.*
    script  redact_pii.lua
    call    redact_fields

# redact_pii.lua
function redact_fields(tag, timestamp, record)
    local sensitive = {"email", "phone", "ssn", "credit_card", "password", "token"}
    for _, field in ipairs(sensitive) do
        if record[field] ~= nil then
            record[field] = "[REDACTED]"
        end
    end
    return 1, timestamp, record
end
```

### Step 7: Preserving Classification Through the Data Pipeline

ETL and data pipeline jobs must propagate classification metadata to every output they produce. A transformation that reads from a RESTRICTED source and writes to a sink without the RESTRICTED tag is a classification downgrade — a serious control gap.

Implement a pipeline metadata contract:

```python
# pipeline_framework.py
class ClassifiedDataset:
    def __init__(self, source_table: str, classification: str):
        self.source_table = source_table
        self.classification = classification
        self.df = None

    def transform(self, func):
        """Apply a transformation, preserving classification."""
        result = ClassifiedDataset(
            source_table=self.source_table,
            classification=self.classification
        )
        result.df = func(self.df)
        return result

    def write(self, target_table: str, conn):
        # Tag the output table with at least the source classification
        self.df.to_sql(target_table, conn, if_exists="replace")
        conn.execute(
            "COMMENT ON TABLE %s IS 'classification:%s derived_from:%s'",
            (target_table, self.classification, self.source_table)
        )
```

A CI-level lineage check traverses the DAG of pipeline jobs and flags any path where output classification is lower than input classification:

```python
# lineage_check.py
def validate_pipeline_lineage(dag: dict) -> list[str]:
    TIER_ORDER = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
    violations = []
    for job_name, job in dag.items():
        max_input_tier = max(
            TIER_ORDER.index(inp["classification"]) for inp in job["inputs"]
        )
        output_tier = TIER_ORDER.index(job["output"]["classification"])
        if output_tier < max_input_tier:
            violations.append(
                f"{job_name}: output classification {job['output']['classification']} "
                f"is lower than input {TIER_ORDER[max_input_tier]}"
            )
    return violations
```

### Step 8: Training Developers Through Code Review

Classification errors most often occur at integration boundaries: when a developer sends a Confidential field to a less-secure endpoint, or when a new API serialiser returns more fields than the caller is authorised to receive.

Add a classification checklist to your pull request template:

```markdown
## Data Classification Checklist

- [ ] All new database columns have a classification comment (`-- classification:TIER`)
- [ ] New API response schemas have `x-classification` tags for each field
- [ ] No Confidential or Restricted fields appear in log statements
- [ ] If this PR stores new PII, the data inventory has been updated
- [ ] If this PR sends data to an external service, that service has a signed DPA
- [ ] Retention period for any new table is documented
```

During code review, treat classification mismatches as bugs, not style issues. A serialiser that returns a field tagged RESTRICTED to an endpoint accessible to INTERNAL-level users is a privilege escalation bug. Review it with the same urgency as a SQL injection finding.

Automate the mechanical checks. A static analysis rule can detect when a model field tagged RESTRICTED is referenced in a view or serialiser that lacks a matching access control annotation:

```python
# semgrep rule: detect RESTRICTED field exposure in unauthenticated views
rules:
  - id: restricted-field-in-public-view
    patterns:
      - pattern: |
          class $VIEW(APIView):
              ...
              $SERIALISER($MODEL(...))
    message: >
      View '$VIEW' may expose fields from '$MODEL'. Verify that all
      RESTRICTED-classified fields are excluded from this serialiser.
    languages: [python]
    severity: WARNING
    metadata:
      category: security
      subcategory: data-classification
```

## Verification

After implementing classification controls, validate coverage across four dimensions:

```bash
# 1. Verify all columns have classification comments
psql $DATABASE_URL -c "
SELECT table_name, column_name
FROM information_schema.columns
LEFT JOIN (
    SELECT objoid, description
    FROM pg_description
    JOIN pg_attribute ON attrelid = objoid AND attnum = objsubid
) d ON d.objoid = (table_schema || '.' || table_name)::regclass
WHERE table_schema = 'public'
  AND description NOT LIKE '%classification:%'
ORDER BY table_name, column_name;"

# 2. Verify S3 objects in sensitive buckets carry classification tags
aws s3api list-objects-v2 --bucket data-lake-prod \
  --query 'Contents[].Key' --output text | xargs -I{} \
  aws s3api get-object-tagging --bucket data-lake-prod --key {} \
  --query 'TagSet[?Key==`classification`].Value' --output text

# 3. Confirm audit logs are emitting for Confidential table access
grep '"classification":"CONFIDENTIAL"' /var/log/app/audit.log | wc -l

# 4. Verify KMS CMK is used for Restricted tables (check RDS cluster encryption)
aws rds describe-db-instances --query \
  'DBInstances[?StorageEncrypted==`true`].[DBInstanceIdentifier,KmsKeyId]' \
  --output table
```

Conduct a synthetic data subject erasure test monthly: create a test user, populate all PII-bearing tables with a known identifier, trigger the erasure handler, and verify that no rows referencing the test identifier remain in any table in the data inventory.

## Key Takeaways

- A four-tier taxonomy (Public, Internal, Confidential, Restricted) provides enough granularity for access control and compliance decisions without creating cognitive overhead that causes engineers to guess.
- Tag classification at the point of schema creation — database column comments, S3 object tags, OpenAPI extensions — not retrospectively through scanning. Scanning finds gaps; tagging at source prevents them.
- Controls must be enforced by infrastructure (KMS key policy conditions, bucket policies, service mesh auth policies), not by developer discipline. Policies that require humans to remember to encrypt are not controls.
- GDPR and PCI DSS are not separate programmes — they are specialisations of the Confidential and Restricted tiers with additional obligations around purpose limitation, tokenisation, and scope.
- Logs are the most common PII leakage vector. Pseudonymise identifiers before logging and apply redaction filters at the shipper layer independent of application behaviour.
- Classification metadata must flow through data pipelines. A transformation that strips classification from its output is a control gap, not an optimisation.
- Treat classification mismatches in code review as bugs. A RESTRICTED field accessible through an INTERNAL-tier endpoint is a privilege escalation vulnerability.
