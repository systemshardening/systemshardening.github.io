---
title: "Backup and Recovery Security: Protecting Your Last Line of Defence Against Ransomware"
description: "Ransomware groups now target backup infrastructure before encrypting production data. Secure backups require immutability, isolation from production credentials, encryption with offline keys, and regular recovery testing. This guide covers the 3-2-1-1-0 backup strategy, immutable storage, backup authentication hardening, and recovery testing."
slug: backup-recovery-security
date: 2026-05-07
lastmod: 2026-05-07
category: cross-cutting
tags:
  - backup-security
  - ransomware-defence
  - disaster-recovery
  - immutable-storage
  - business-continuity
personas:
  - security-engineer
  - platform-engineer
article_number: 612
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/cross-cutting/backup-recovery-security/
---

# Backup and Recovery Security: Protecting Your Last Line of Defence Against Ransomware

## Problem

Ransomware operators do not start by encrypting your production data. They start by finding and deleting your backups.

Modern ransomware groups spend an average of five to fourteen days inside a victim network before triggering encryption. During that dwell period, the attacker's primary objective is to ensure you cannot recover without paying. They map your backup infrastructure, compromise the backup service account, and either delete existing backups or wait until the backup rotation has overwritten all clean copies. Only once your recovery options are exhausted do they detonate the encryption payload across production.

This means backups that are reachable from your production network are not backups at all. If your backup storage is mounted on a file server that production credentials can reach, the attacker can reach it too. If your backup service account has delete permissions on the backup bucket, the attacker who has compromised any credential with equivalent IAM permissions can use those permissions to delete your backups before you even know the attack has started.

The backup problem in 2026 is not whether you have backups. Most organisations have backups. The problem is whether your backups are protected from an attacker who already has admin access to your environment. The answer requires immutability at the storage layer (so deletion is physically impossible, regardless of credentials), credential isolation (so the backup service account cannot be abused to delete what it writes), offline copies (so at least one copy exists that no network-connected system can reach), and verified recovery (so you know the backup actually works before you need it).

## Threat Model

- **Adversary:** A ransomware operator or affiliate with domain-level or cloud account-level access. Access typically begins with a compromised credential or unpatched vulnerability. The attacker escalates privileges during the dwell period specifically to reach backup infrastructure.
- **Objective:** Eliminate recovery options before triggering encryption. Secondary objective: exfiltrate backup data to use as extortion leverage (threatening to publish data even if the victim restores from backups).
- **Blast radius:** Total data loss and operational shutdown if backups are eliminated and production data is encrypted. RTO measured in days to weeks without recovery-ready backups.
- **What the attacker needs:** Write access to your backup storage (to overwrite backups with encrypted or corrupt data), delete access to your backup storage (to remove backups), or control of the encryption keys used to protect backups (to make them unreadable without the key).

**The key constraint:** Immutable backup storage removes the delete and overwrite attack surface entirely. The attacker cannot delete what the storage layer physically prevents from being deleted, regardless of credentials.

## Configuration

### 1. Implement the 3-2-1-1-0 Backup Rule

The 3-2-1 rule (three copies, two different media types, one offsite) has been the baseline for decades. The modern extension adds two further requirements that are specific to ransomware defence.

- **3 copies:** Production data, a local backup (fast restore), and a remote backup (site failure).
- **2 media types:** Disk and tape, or block storage and object storage. Media diversity prevents a single storage failure from eliminating all copies.
- **1 offsite copy:** A backup in a different physical location from production. Protects against fire, flood, and facility-level failures.
- **1 immutable or offline copy:** At least one copy that cannot be modified or deleted by any network-connected credential. This is the ransomware-specific addition. Either immutable object storage (S3 Object Lock in Compliance mode) or a physically disconnected copy (tape, powered-off NAS).
- **0 backup errors:** The final digit is not a count — it is a requirement. Every backup job must complete without errors and must be verified as restorable. An untested backup is not a backup.

**Backup architecture by tier:**

```
Tier 1: Local (fast restore)
  - On-premises NAS or block storage
  - RPO: 1 hour, RTO: <30 minutes
  - Retention: 7 days daily snapshots
  - NOT immutable (traded for restore speed)
  - Reachable from production network

Tier 2: Remote immutable (ransomware-resilient)
  - Cloud object storage with Object Lock (Compliance mode)
  - RPO: 4 hours, RTO: 2-4 hours
  - Retention: 30 days daily, 12 weeks weekly, 12 months monthly
  - WRITE + READ only for backup service account
  - DELETE physically blocked by storage layer

Tier 3: Offline / air-gapped
  - Tape or powered-off NAS, rotated offsite
  - RPO: 24 hours, RTO: 4-8 hours
  - Retention: 12 monthly copies
  - No network connection during storage
  - Physical access controls only
```

### 2. Configure Immutable Backup Storage

S3 Object Lock in Compliance mode is the strongest available defence: even the root account cannot delete objects before the retention period expires. Once an object is written with a Compliance-mode lock, it cannot be modified, overwritten, or deleted by anyone — including AWS support — until the retention period expires.

**Create and configure an immutable S3 backup bucket:**

```bash
#!/bin/bash
# create-immutable-backup-bucket.sh
# Creates an S3 bucket with Object Lock in Compliance mode.
# Run once during initial setup. Object Lock cannot be added
# to an existing bucket — it must be enabled at creation time.

BUCKET_NAME="company-immutable-backups-prod"
REGION="eu-west-2"
BACKUP_ROLE_ARN="arn:aws:iam::123456789012:role/backup-agent"
SECURITY_ADMIN_ARN="arn:aws:iam::123456789012:role/security-admin"

# Create bucket with Object Lock enabled at creation
aws s3api create-bucket \
  --bucket "${BUCKET_NAME}" \
  --region "${REGION}" \
  --create-bucket-configuration LocationConstraint="${REGION}" \
  --object-lock-enabled-for-bucket

# Set default Compliance mode retention: 30 days
# Compliance mode: NO ONE can delete objects before retention expires.
# Not the bucket owner. Not the root account. Not AWS support.
aws s3api put-object-lock-configuration \
  --bucket "${BUCKET_NAME}" \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "COMPLIANCE",
        "Days": 30
      }
    }
  }'

# Enable versioning (required for Object Lock; also protects against
# accidental overwrites — a new version is created, not an in-place write)
aws s3api put-bucket-versioning \
  --bucket "${BUCKET_NAME}" \
  --versioning-configuration Status=Enabled

# Block all public access
aws s3api put-public-access-block \
  --bucket "${BUCKET_NAME}" \
  --public-access-block-configuration \
    'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=false,RestrictPublicBuckets=true'

# Bucket policy: backup-agent can PUT and GET but not DELETE.
# DeleteObject and DeleteObjectVersion are explicitly denied for all principals
# except the security-admin role, which itself cannot override Compliance lock.
aws s3api put-bucket-policy \
  --bucket "${BUCKET_NAME}" \
  --policy "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [
      {
        \"Sid\": \"AllowBackupAgentWrite\",
        \"Effect\": \"Allow\",
        \"Principal\": {\"AWS\": \"${BACKUP_ROLE_ARN}\"},
        \"Action\": [
          \"s3:PutObject\",
          \"s3:GetObject\",
          \"s3:ListBucket\",
          \"s3:GetObjectVersion\",
          \"s3:ListBucketVersions\"
        ],
        \"Resource\": [
          \"arn:aws:s3:::${BUCKET_NAME}\",
          \"arn:aws:s3:::${BUCKET_NAME}/*\"
        ]
      },
      {
        \"Sid\": \"DenyAllDelete\",
        \"Effect\": \"Deny\",
        \"Principal\": \"*\",
        \"Action\": [
          \"s3:DeleteObject\",
          \"s3:DeleteObjectVersion\",
          \"s3:DeleteBucket\"
        ],
        \"Resource\": [
          \"arn:aws:s3:::${BUCKET_NAME}\",
          \"arn:aws:s3:::${BUCKET_NAME}/*\"
        ]
      },
      {
        \"Sid\": \"DenyBucketPolicyChange\",
        \"Effect\": \"Deny\",
        \"Principal\": \"*\",
        \"Action\": \"s3:PutBucketPolicy\",
        \"Resource\": \"arn:aws:s3:::${BUCKET_NAME}\",
        \"Condition\": {
          \"StringNotEquals\": {
            \"aws:PrincipalArn\": \"${SECURITY_ADMIN_ARN}\"
          }
        }
      }
    ]
  }"

echo "Immutable backup bucket created: ${BUCKET_NAME}"
echo "Object Lock: COMPLIANCE mode, 30-day minimum retention"
echo "Delete operations: denied at bucket policy layer"
echo "Note: Compliance mode also prevents AWS from deleting objects at customer request"
```

**Equivalent configuration for Azure immutable blob storage:**

```bash
# Azure: Create storage account and configure immutability policy
RESOURCE_GROUP="rg-backups-prod"
STORAGE_ACCOUNT="companybackupsprod"
CONTAINER_NAME="immutable-backups"

az storage account create \
  --name "${STORAGE_ACCOUNT}" \
  --resource-group "${RESOURCE_GROUP}" \
  --location uksouth \
  --sku Standard_GRS \
  --kind StorageV2 \
  --min-tls-version TLS1_2 \
  --allow-blob-public-access false

az storage container create \
  --name "${CONTAINER_NAME}" \
  --account-name "${STORAGE_ACCOUNT}"

# Set immutability policy: 30-day locked WORM retention
# --locked flag: policy is locked and cannot be decreased or removed
az storage container immutability-policy create \
  --account-name "${STORAGE_ACCOUNT}" \
  --container-name "${CONTAINER_NAME}" \
  --period 30 \
  --allow-protected-append-writes false

az storage container immutability-policy lock \
  --account-name "${STORAGE_ACCOUNT}" \
  --container-name "${CONTAINER_NAME}"
```

### 3. Isolate Backup Credentials from Production

The backup service account is the highest-value credential for a ransomware attacker: it has write access to every backup, so compromising it reveals what data exists and grants write access to overwrite backups. It must be kept completely isolated from production IAM.

**Create a minimal-permission backup IAM role:**

```hcl
# backup-iam.tf
# Backup agent IAM role: write and read backups, but NEVER delete them.
# This role is granted ONLY to the backup agent process, never to
# any production service or developer workstation.

resource "aws_iam_role" "backup_agent" {
  name = "backup-agent"

  # Only EC2 instances tagged as backup agents can assume this role
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "ec2:ResourceTag/Role" = "backup-agent"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "backup_agent_policy" {
  name = "backup-agent-policy"
  role = aws_iam_role.backup_agent.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowBackupWrite"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:GetObjectVersion",
          "s3:ListBucketVersions"
        ]
        Resource = [
          aws_s3_bucket.immutable_backups.arn,
          "${aws_s3_bucket.immutable_backups.arn}/*"
        ]
      },
      # Explicitly deny delete actions even if a broader policy grants them
      {
        Sid    = "ExplicitlyDenyDelete"
        Effect = "Deny"
        Action = [
          "s3:DeleteObject",
          "s3:DeleteObjectVersion",
          "s3:DeleteBucket"
        ]
        Resource = "*"
      }
    ]
  })
}
```

**Separate backup credentials from production credential stores:**

```yaml
# backup-agent-deployment.yaml
# The backup agent runs in a dedicated namespace with its own service account.
# It has NO access to production namespaces, databases, or secrets.
# It reads data from production only via a read-only database replica.
apiVersion: v1
kind: Namespace
metadata:
  name: backup-system
  labels:
    # Network policies restrict what can reach this namespace
    purpose: backup-agent
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: backup-agent
  namespace: backup-system
  annotations:
    # AWS IRSA: binds this Kubernetes service account to the backup-agent IAM role
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/backup-agent
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backup-agent-ingress-deny
  namespace: backup-system
spec:
  podSelector:
    matchLabels:
      app: backup-agent
  policyTypes:
    - Ingress
  # Allow NO inbound connections to the backup agent.
  # It initiates connections outbound (to the database replica and S3).
  # No production service should ever connect to the backup agent.
  ingress: []
```

### 4. Encrypt Backups Before Sending — With Keys Stored Separately

Encrypting backups at rest protects data confidentiality if the backup storage is breached independently. But the encryption only provides protection if the decryption key is not stored in the same location as the backup. Storing the key in the same environment as the encrypted backup (the most common pattern) means an attacker who compromises the backup storage also has the key.

**Use Restic with a password stored in AWS Secrets Manager, with the Secrets Manager entry backed up offline:**

```bash
#!/bin/bash
# backup-with-encryption.sh
# Performs encrypted backup to S3 using Restic.
# The Restic repository password is fetched from Secrets Manager at runtime
# and never written to disk. The backup storage does not know the password.

set -euo pipefail

RESTIC_REPOSITORY="s3:s3.amazonaws.com/company-immutable-backups-prod"
SECRET_NAME="backup/restic-repository-password"
LOG_FILE="/var/log/backup/backup-$(date +%Y%m%d).log"

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" | tee -a "${LOG_FILE}"; }

log "Starting backup job"

# Fetch repository password from Secrets Manager
# The backup-agent IAM role has GetSecretValue permission on this secret only.
# The Secrets Manager secret itself is in a separate AWS account (backup account).
export RESTIC_PASSWORD=$(
  aws secretsmanager get-secret-value \
    --secret-id "${SECRET_NAME}" \
    --query SecretString \
    --output text
)

# Initialise repository if it does not exist
restic snapshots > /dev/null 2>&1 || restic init

# Backup PostgreSQL: dump directly to Restic (no intermediate file on disk)
log "Backing up PostgreSQL"
PGPASSWORD="${DB_PASSWORD}" pg_dumpall \
  --host=db-replica.internal \
  --username=backup_readonly \
  --no-password \
  | restic backup \
    --stdin \
    --stdin-filename "postgresql/db-$(date +%Y%m%d-%H%M%S).sql" \
    --tag "type:database" \
    --tag "env:production"

# Backup application configuration and secrets (excluding private keys —
# private keys should be backed up via the PKI procedure, not here)
log "Backing up application configuration"
restic backup \
  /etc/app \
  /opt/configs \
  --exclude "*.key" \
  --exclude "*.pem" \
  --tag "type:config" \
  --tag "env:production"

# Verify the backup repository is consistent
log "Verifying backup repository"
restic check

# Report backup statistics
restic snapshots --json | jq -r '.[] | "\(.time) \(.id[0:8]) \(.tags | join(","))"'

log "Backup job completed successfully"

# Clear the password from the environment
unset RESTIC_PASSWORD
```

**Offline key backup procedure (run quarterly):**

```bash
#!/bin/bash
# offline-key-backup.sh
# Exports the backup encryption key to a QR code printed on paper
# and stored in a physical safe. Also generates a text copy for
# metal backup storage. Run quarterly or whenever the key rotates.
#
# This script must run on an air-gapped workstation. Do not run on
# any network-connected machine.

set -euo pipefail

SECRET_NAME="backup/restic-repository-password"

# Fetch the current password
RESTIC_PASSWORD=$(
  aws secretsmanager get-secret-value \
    --secret-id "${SECRET_NAME}" \
    --query SecretString \
    --output text
)

# Generate QR code for physical backup
echo "${RESTIC_PASSWORD}" | qrencode -o /tmp/backup-key-qr.png -s 10

# Print the QR code and password in plaintext
echo "=== BACKUP ENCRYPTION KEY — PHYSICAL COPY ==="
echo "Date: $(date)"
echo "Purpose: Restic backup repository password"
echo ""
echo "Password (store in sealed envelope in physical safe):"
echo "${RESTIC_PASSWORD}"
echo ""
echo "QR code written to /tmp/backup-key-qr.png — print and store with password."
echo ""
echo "SECURITY REQUIREMENT:"
echo "  This printout must be stored separately from the backup storage media."
echo "  Store in a different physical location from both production and the backups."

# Wipe from memory
unset RESTIC_PASSWORD
```

### 5. Monitor Backup Operations and Alert on Anomalies

An attacker targeting your backup infrastructure will trigger anomalous activity. Mass deletion of backup objects, access from unusual source IPs, and backup service account usage outside maintenance windows are all indicators of compromise.

**Prometheus alerting rules for backup health and anomalous access:**

```yaml
# backup-monitoring-rules.yaml
groups:
  - name: backup-health
    interval: 5m
    rules:
      # Alert if no backup has completed in the last 26 hours
      - alert: BackupMissed
        expr: time() - backup_last_success_timestamp_seconds > 93600
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "Backup job has not completed successfully in 26 hours"
          description: >
            The last successful backup was more than 26 hours ago.
            Either the backup job failed or is not running.
            Investigate immediately — a missed backup may indicate
            infrastructure compromise.

      # Alert if backup verification fails
      - alert: BackupVerificationFailed
        expr: backup_verification_success == 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Backup verification failed — backup may be unrestorable"
          description: >
            The backup verification check failed. This means the most recent
            backup either did not restore correctly or the repository is corrupt.
            Recovery is not possible from this backup.

      # Alert if backup size drops dramatically (may indicate deletion)
      - alert: BackupSizeDropped
        expr: >
          (backup_repository_size_bytes
           / backup_repository_size_bytes offset 1d) < 0.5
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Backup repository size dropped by more than 50%"
          description: >
            The backup repository is significantly smaller than 24 hours ago.
            This may indicate that backup objects have been deleted.
            Investigate immediately — this is a ransomware pre-encryption indicator.
```

**CloudTrail alerting for backup bucket anomalies:**

```json
{
  "Filters": [
    {
      "Name": "Mass backup deletion alert",
      "Pattern": "{ ($.eventSource = \"s3.amazonaws.com\") && ($.requestParameters.bucketName = \"company-immutable-backups-prod\") && ($.eventName = \"DeleteObject\" || $.eventName = \"DeleteObjects\") }",
      "Destinations": ["arn:aws:sns:eu-west-2:123456789012:security-alerts"],
      "Description": "Alert on any deletion attempt against the immutable backup bucket. Should fire 0 times in normal operation — Object Lock prevents actual deletion, but the attempt itself is a significant indicator."
    },
    {
      "Name": "Backup account accessed outside maintenance window",
      "Pattern": "{ ($.userIdentity.arn = \"arn:aws:iam::123456789012:role/backup-agent\") && ($.eventTime > \"T06:00:00Z\" || $.eventTime < \"T02:00:00Z\") }",
      "Destinations": ["arn:aws:sns:eu-west-2:123456789012:security-alerts"],
      "Description": "Backup agent credentials used outside the 02:00-06:00 UTC maintenance window. Any use outside this window is anomalous and may indicate credential compromise."
    }
  ]
}
```

### 6. Offline and Air-Gapped Copy Rotation

The immutable cloud backup survives credential compromise. The offline copy survives a scenario where the cloud provider account itself is compromised, or where an attacker has found a way to corrupt the cloud backup that predates your detection.

**Tape backup via `bacula` on a dedicated backup server:**

```bash
#!/bin/bash
# weekly-tape-rotation.sh
# Manages weekly tape rotation for the offline backup copy.
# This script runs on the dedicated backup server, which has NO
# inbound network access from the production environment.
# Production data is pulled by the backup server, not pushed from production.

set -euo pipefail

TAPE_DEVICE="/dev/nst0"
BACKUP_LABEL="PROD-WEEKLY-$(date +%Y-W%V)"
LOG_FILE="/var/log/tape-backup/tape-$(date +%Y%m%d).log"

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" | tee -a "${LOG_FILE}"; }

log "Starting weekly tape backup: ${BACKUP_LABEL}"

# Rewind and label the tape
mt -f "${TAPE_DEVICE}" rewind
tar -cf "${TAPE_DEVICE}" --label="${BACKUP_LABEL}" /dev/null

# Write backup data (pulled from the read-only database replica)
# The backup server connects OUTBOUND to the replica — the replica
# never connects to the backup server.
log "Writing database backup to tape"
PGPASSWORD="${READONLY_DB_PASSWORD}" pg_dumpall \
  --host=db-replica.internal \
  --username=backup_readonly \
  | gzip \
  | openssl enc -aes-256-cbc -pbkdf2 -pass file:/etc/backup/tape-encryption-key \
  | dd if=/dev/stdin of="${TAPE_DEVICE}" bs=64k

log "Writing configuration backup to tape"
tar -czf - /opt/configs /etc/app \
  | openssl enc -aes-256-cbc -pbkdf2 -pass file:/etc/backup/tape-encryption-key \
  | dd if=/dev/stdin of="${TAPE_DEVICE}" bs=64k

# Rewind and verify tape is readable
mt -f "${TAPE_DEVICE}" rewind
mt -f "${TAPE_DEVICE}" status

log "Tape backup complete: ${BACKUP_LABEL}"
log "MANUAL ACTION REQUIRED: Remove tape and store in offsite safe"
log "Tape label: ${BACKUP_LABEL}"
log "Offsite location: [document physical location here]"
```

### 7. Quarterly Recovery Testing — Full Restore, Not Spot Check

A backup that has never been restored is a hypothesis, not a backup. Recovery testing must restore actual data to actual infrastructure and verify that the restored environment functions correctly. Spot-checking whether a file exists in the backup repository is not sufficient.

**Quarterly full recovery test procedure:**

```bash
#!/bin/bash
# quarterly-recovery-test.sh
# Full recovery test: restores from backup to isolated test environment
# and verifies that the restored application functions correctly.
# Schedule: first Saturday of each quarter, 03:00 UTC.
# Duration: approximately 2-3 hours.
# Required participants: on-call engineer + backup administrator.

set -euo pipefail

RESTIC_REPOSITORY="s3:s3.amazonaws.com/company-immutable-backups-prod"
TEST_NAMESPACE="recovery-test-$(date +%Y%m)"
RESTORE_DIR="/tmp/recovery-test-$(date +%Y%m%d)"
PASS=0
FAIL=0

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*"; }
pass() { log "PASS: $*"; PASS=$((PASS + 1)); }
fail() { log "FAIL: $*"; FAIL=$((FAIL + 1)); }

log "=== QUARTERLY RECOVERY TEST ==="
log "Date: $(date)"
log "Operator: $(whoami)"
log "Target snapshot: latest as of 24 hours ago (simulates post-incident recovery)"
log ""

mkdir -p "${RESTORE_DIR}"

# Fetch the repository password from Secrets Manager
export RESTIC_PASSWORD=$(
  aws secretsmanager get-secret-value \
    --secret-id "backup/restic-repository-password" \
    --query SecretString \
    --output text
)

# Step 1: Verify repository integrity
log "Step 1: Verifying backup repository integrity..."
if restic check --read-data-subset=10%; then
  pass "Repository integrity check passed"
else
  fail "Repository integrity check FAILED — backup may be corrupt"
fi

# Step 2: List available snapshots and select one from 24 hours ago
log "Step 2: Identifying recovery snapshot..."
SNAPSHOT_ID=$(restic snapshots --json | jq -r \
  --arg cutoff "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  '[.[] | select(.time < $cutoff)] | sort_by(.time) | last | .id')

if [ -n "${SNAPSHOT_ID}" ]; then
  pass "Found snapshot from 24+ hours ago: ${SNAPSHOT_ID}"
else
  fail "No snapshot found from 24+ hours ago"
  exit 1
fi

# Step 3: Restore the database backup
log "Step 3: Restoring database backup from snapshot ${SNAPSHOT_ID}..."
restic restore "${SNAPSHOT_ID}" \
  --target "${RESTORE_DIR}" \
  --include "postgresql/"

DB_DUMP=$(find "${RESTORE_DIR}" -name "*.sql" | head -1)
if [ -n "${DB_DUMP}" ]; then
  pass "Database dump extracted: ${DB_DUMP}"
else
  fail "Database dump not found in restored snapshot"
fi

# Step 4: Load the database dump into the test environment
log "Step 4: Loading database into test PostgreSQL instance..."
kubectl create namespace "${TEST_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

# Deploy a test PostgreSQL instance
kubectl run pg-test \
  --image=postgres:16 \
  --env="POSTGRES_PASSWORD=testpassword" \
  --namespace="${TEST_NAMESPACE}" \
  --restart=Never

kubectl wait --for=condition=Ready pod/pg-test \
  --namespace="${TEST_NAMESPACE}" \
  --timeout=120s

kubectl cp "${DB_DUMP}" "${TEST_NAMESPACE}/pg-test:/tmp/restore.sql"

if kubectl exec -n "${TEST_NAMESPACE}" pg-test -- \
    psql -U postgres -f /tmp/restore.sql > /dev/null 2>&1; then
  pass "Database restored successfully to test instance"
else
  fail "Database restore into test PostgreSQL FAILED"
fi

# Step 5: Verify row counts match production baseline
log "Step 5: Verifying restored data against production baseline..."
RESTORED_COUNT=$(kubectl exec -n "${TEST_NAMESPACE}" pg-test -- \
  psql -U postgres -t -c "SELECT COUNT(*) FROM pg_catalog.pg_tables;")

# Compare against a known-good baseline count stored separately
BASELINE_COUNT=$(cat /etc/backup/recovery-test/table-count-baseline.txt)

if [ "${RESTORED_COUNT// /}" -ge "${BASELINE_COUNT}" ]; then
  pass "Row count check passed: ${RESTORED_COUNT} tables (baseline: ${BASELINE_COUNT})"
else
  fail "Row count below baseline: got ${RESTORED_COUNT}, expected ${BASELINE_COUNT}"
fi

# Step 6: Verify configuration restore
log "Step 6: Verifying configuration restore..."
CONFIG_FILES=$(find "${RESTORE_DIR}/etc/app" -type f 2>/dev/null | wc -l)
if [ "${CONFIG_FILES}" -gt 0 ]; then
  pass "Configuration files restored: ${CONFIG_FILES} files"
else
  fail "No configuration files found in restored snapshot"
fi

# Cleanup
kubectl delete namespace "${TEST_NAMESPACE}" --wait=false
rm -rf "${RESTORE_DIR}"
unset RESTIC_PASSWORD

# Report
log ""
log "=== RECOVERY TEST RESULTS ==="
log "PASSED: ${PASS} checks"
log "FAILED: ${FAIL} checks"
log ""

if [ "${FAIL}" -eq 0 ]; then
  log "RESULT: PASS — Recovery verified. RTO for database: documented below."
  log "Estimated RTO from backup to verified restore: $(date)"
else
  log "RESULT: FAIL — ${FAIL} checks failed. Review failures and remediate."
  log "CRITICAL: Your backup is NOT verified as restorable. Fix before next incident."
  # Send failure alert to security channel
  curl -sf -X POST "${SLACK_WEBHOOK_URL}" \
    -H "Content-Type: application/json" \
    -d "{\"text\": \"CRITICAL: Quarterly recovery test FAILED with ${FAIL} failures. Backups are not verified restorable. Immediate investigation required.\"}"
fi
```

## Defining RTO and RPO

Recovery Time Objective (RTO) and Recovery Point Objective (RPO) must be defined before an incident, not during one. Define them per system, not per organisation:

| System | RPO Target | RTO Target | Backup Tier | Verified Last |
|--------|-----------|-----------|-------------|---------------|
| Customer database | 4 hours | 2 hours | Tier 1 (local) + Tier 2 (immutable cloud) | Quarterly |
| Application config | 24 hours | 1 hour | Tier 2 (immutable cloud) | Quarterly |
| Audit logs | 0 (replicated in real time) | 4 hours | SIEM replication | Monthly |
| Secrets (Vault) | 1 hour | 30 minutes | Vault Raft snapshots | Quarterly |

RTO and RPO targets are meaningless without the quarterly recovery test validating that you can actually meet them. If the quarterly test shows your RTO for the customer database is 6 hours when the target is 2, you have a planning gap that needs to be resolved — by either improving your restore process or revising the target upward and communicating the change to the business.

## Expected Behaviour

- **Immutable backups:** S3 Object Lock in Compliance mode prevents deletion by any credential, including root. Object Lock prevents overwrites — new writes create new versions. Deletion attempts are blocked at the storage layer and trigger CloudTrail alerts.
- **Credential isolation:** The backup service account has PUT and GET permissions on backup storage only. DELETE is denied at both the IAM policy and bucket policy layers. The backup agent is not a member of any production IAM group.
- **Backup monitoring:** A missed backup job triggers an alert within 26 hours. A drop in backup repository size of more than 50% triggers an immediate critical alert. Backup service account use outside the maintenance window triggers an immediate alert.
- **Offline copies:** Weekly tape backups are encrypted with a key stored separately from the tape media. Tapes are stored offsite in a physically secured location.
- **Recovery testing:** Quarterly full restoration to an isolated test environment, with automated verification of database row counts and configuration file integrity. Test results are documented and retained.

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| S3 Object Lock Compliance mode | Cannot delete backups before retention period, even for legitimate cleanup | Storage costs for 30-day minimum retention on all objects | Use S3 Lifecycle policies to transition objects to Glacier after 7 days for cost reduction. Compliance mode still applies — Glacier objects are also locked. |
| Backup service account with no delete permission | Cannot prune old backups using the standard backup-agent credentials | Old backups accumulate unless a separate privileged process runs retention | Use a separate, tightly controlled retention-management role that can only delete objects older than the retention period. Require MFA for this role. |
| Offline tape rotation | Tape restores are significantly slower than cloud restores | Tape can only recover from the most recent weekly rotation | Tier 1 and Tier 2 are used for fast recovery. Tape is the last resort when both have failed. Accept the slower RTO for the tape tier. |
| Quarterly full recovery testing | Requires 2-3 hours of engineering time and a test environment | Recovery test may disrupt test infrastructure; findings may reveal backup gaps | Automate as much of the test as possible (the script above does this). Treat failures as incidents to be resolved before the next test. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Attacker deletes backup service account credentials | Backup jobs fail with authentication errors | BackupMissed alert fires within 26 hours | Rotate backup credentials. Investigate how credentials were compromised. |
| Ransomware overwrites backup data before Object Lock is applied | Backup repository contains encrypted or corrupt data | BackupVerificationFailed alert fires on next verification run | Restore from the offline tape copy. Investigate the timing gap between backup and Object Lock application. |
| Recovery key lost (Restic password not backed up offline) | Cannot decrypt backup repository | Discovered during recovery attempt | No recovery from this failure without the key. Prevention: quarterly offline key backup procedure. |
| Backup size monitoring misses gradual deletion | Slow deletion over weeks does not trigger the 50% drop alert | Quarterly recovery test fails when too few snapshots exist | Add an absolute minimum snapshot count alert: alert if fewer than 7 daily snapshots exist. |
| Tape backup contains no data (write failure not detected) | Tape appears to have been written but restore produces nothing | Quarterly recovery test when tape tier is tested | Add a tape verification step: read back and verify a checksum after each tape write. |

## When to Consider a Managed Alternative

Immutable backup infrastructure is available as a managed service from several providers, removing the operational burden of managing S3 Object Lock policies, retention management roles, and backup encryption key rotation.

- **Veeam Data Platform:** Purpose-built backup software with built-in immutability support for S3-compatible storage, tape, and hardened Linux backup repositories. Veeam immutable backup repositories use a non-root account for repository management, so even if the Veeam server is compromised, the attacker cannot delete immutable backup files. Retention management is built into the backup job configuration.
- **Wasabi Cloud Storage with Object Lock:** S3-compatible immutable object storage at significantly lower cost than AWS S3. No egress fees. Object Lock Compliance mode support. Wasabi's policy prohibits employees from deleting customer data, providing an additional layer of protection beyond the technical controls.
- **Backblaze B2 with Object Lock:** Low-cost S3-compatible storage with Object Lock support. Particularly well-suited as the offsite immutable copy tier in a 3-2-1-1-0 architecture where cost is a constraint.

## Related Articles

- [Ransomware 3.0 and Multi-Stage Extortion: Defence, Detection, and Recovery](/articles/cross-cutting/ransomware-multi-extortion-defence/)
- [Security Infrastructure Disaster Recovery: Vault, PKI, and SIEM Failover](/articles/cross-cutting/security-infra-disaster-recovery/)
- [Incident Response Hardening Playbook: From Detection to Post-Mortem](/articles/cross-cutting/incident-response-hardening-playbook/)
- [HSM Key Management: Hardware-Backed Secrets for Critical Infrastructure](/articles/cross-cutting/hsm-key-management/)
- [Secrets Rotation Orchestration: Automating Credential Lifecycle Without Downtime](/articles/cross-cutting/secrets-rotation-orchestration/)
