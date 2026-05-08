---
title: "Kubernetes Backup Security with Velero: Encryption, RBAC, and Immutable Storage"
description: "Velero backups contain every Kubernetes secret, PersistentVolume, and workload configuration. Without encryption and immutable storage, they are a single-shot path to full cluster compromise or ransomware."
slug: "velero-backup-security"
date: 2026-04-30
lastmod: 2026-04-30
category: "kubernetes"
tags: ["velero", "backup", "encryption", "ransomware", "kubernetes"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 264
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/kubernetes/velero-backup-security/index.html"
---

# Kubernetes Backup Security with Velero: Encryption, RBAC, and Immutable Storage

## Problem

Velero backs up Kubernetes resources and persistent volume data to object storage. A complete backup contains: all Kubernetes Secrets (database passwords, API keys, TLS private keys), all workload configurations, all PersistentVolumeClaims and their data, and — if using the default setup — the etcd encryption key metadata.

This makes Velero backups extraordinarily valuable to attackers and a critical ransomware target:

- **Backup theft = full cluster credential harvest:** An attacker who reads a Velero backup extracts all Secrets, including the TLS keys, database passwords, and OAuth tokens that live in Kubernetes Secrets.
- **Backup deletion = recovery impossible:** A ransomware operator who deletes backups prevents cluster recovery after a destructive attack.
- **Backup overwrite = poisoned restore:** An attacker who can write to the backup bucket replaces legitimate backups with malicious ones; a restore operation deploys the attacker's workloads.

Specific gaps in default Velero deployments:

- Backup bucket has no object lock; backups can be deleted or overwritten.
- Backup data is unencrypted at the object level; S3 server-side encryption (SSE-S3) is managed by AWS, not by Velero; anyone with S3 access can read the backup content.
- Velero's service account or IAM role has `s3:DeleteObject` permission; ransomware targeting the cluster can use Velero to delete its own backups.
- No alerting on backup failure or on unexpected backup access.
- Restores are not tested; a backup that cannot be restored is not a backup.

**Target systems:** Velero 1.13+; AWS S3 with Object Lock; GCS with bucket lock; Azure Blob with immutability policies; `velero-plugin-for-aws` 1.9+; Kopia for backup encryption (Velero's built-in backup repository).

## Threat Model

- **Adversary 1 — Backup data theft:** An attacker who compromises a developer's AWS credentials (or a Kubernetes service account with S3 access) reads backup files and extracts all Kubernetes Secrets from the serialised backup archive.
- **Adversary 2 — Ransomware via backup deletion:** A ransomware operator compromises the cluster, destroys workloads and PVs, then deletes Velero backups. Recovery becomes impossible.
- **Adversary 3 — Backup overwrite for persistence:** An attacker replaces Velero backup files with malicious versions containing backdoored deployments. On the next restore, the malicious workloads are deployed.
- **Adversary 4 — Backup exfiltration via Velero API:** The Velero server has RBAC permissions to download backup data. An attacker who compromises the Velero pod uses it to download all backup archives.
- **Adversary 5 — Cross-cluster replay attack:** A backup from one cluster is restored to a different cluster without sanitisation. The restored Secrets contain credentials for the original cluster's external services, which the new cluster's workloads then use.
- **Access level:** Adversary 1 has S3/GCS read credentials. Adversary 2 has cluster-admin access or S3 write/delete access. Adversary 3 has S3 write access. Adversary 4 has Velero pod exec or k8s API access. Adversary 5 is an operator making a restore mistake.
- **Objective:** Extract credentials, prevent recovery, establish persistent access via restore.
- **Blast radius:** An unencrypted, unprotected backup is equivalent in impact to a full cluster compromise. Deleted backups leave a cluster unrecoverable after a destructive attack.

## Configuration

### Step 1: S3 Bucket with Object Lock (Immutable Backups)

Create the backup bucket with Object Lock before Velero is installed — Object Lock cannot be enabled on existing buckets:

```bash
# Create S3 bucket with Object Lock enabled.
aws s3api create-bucket \
  --bucket velero-backups-prod \
  --region us-east-1 \
  --object-lock-enabled-for-bucket

# Set a default retention policy (COMPLIANCE mode: cannot be overridden even by root).
aws s3api put-object-lock-configuration \
  --bucket velero-backups-prod \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "COMPLIANCE",
        "Days": 30
      }
    }
  }'

# Enable versioning (required for Object Lock).
aws s3api put-bucket-versioning \
  --bucket velero-backups-prod \
  --versioning-configuration Status=Enabled

# Block all public access.
aws s3api put-public-access-block \
  --bucket velero-backups-prod \
  --public-access-block-configuration \
    'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'
```

With COMPLIANCE mode Object Lock, no AWS account (including root) can delete backup objects within the retention window. This is the strongest protection against ransomware backup deletion.

### Step 2: Velero IAM Policy — Minimum Permissions, No Delete

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:AbortMultipartUpload",
        "s3:ListMultipartUploadParts",
        "s3:GetBucketVersioning",
        "s3:GetObjectVersion"
      ],
      "Resource": "arn:aws:s3:::velero-backups-prod/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetBucketLocation",
        "s3:ListBucketMultipartUploads"
      ],
      "Resource": "arn:aws:s3:::velero-backups-prod"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeVolumes",
        "ec2:DescribeSnapshots",
        "ec2:CreateTags",
        "ec2:CreateSnapshot",
        "ec2:DeleteSnapshot",
        "ec2:DescribeTags"
      ],
      "Resource": "*"
    }
  ]
}
```

Notably absent: `s3:DeleteObject`, `s3:DeleteObjectVersion`. Velero does not need to delete objects — Object Lock with lifecycle rules handles expiry. Without `DeleteObject` permission, neither Velero nor an attacker using the Velero IAM role can destroy backups.

```bash
# Create the IAM policy and role.
aws iam create-policy \
  --policy-name velero-backup-policy \
  --policy-document file://velero-iam-policy.json

# Create a service account with IRSA (IAM Roles for Service Accounts).
eksctl create iamserviceaccount \
  --name velero \
  --namespace velero \
  --cluster prod-cluster \
  --attach-policy-arn arn:aws:iam::<account>:policy/velero-backup-policy \
  --approve
```

### Step 3: Backup Encryption with Velero + Kopia

Velero 1.10+ uses Kopia as its backup repository, which supports encryption at the repository level. Data is encrypted before it leaves the cluster:

```bash
# Install Velero with Kopia backend (default since 1.10).
helm install velero vmware-tanzu/velero \
  --namespace velero --create-namespace \
  --set configuration.backupStorageLocation[0].name=aws \
  --set configuration.backupStorageLocation[0].provider=aws \
  --set configuration.backupStorageLocation[0].bucket=velero-backups-prod \
  --set configuration.backupStorageLocation[0].config.region=us-east-1 \
  --set configuration.backupStorageLocation[0].config.s3ForcePathStyle=false \
  --set serviceAccount.server.annotations."eks\.amazonaws\.com/role-arn"=arn:aws:iam::<account>:role/velero-irsa \
  --set "features=EnableCSI" \
  --set "defaultRepoMaintainFrequency=168h" \
  --set "uploaderType=kopia"
```

The Kopia repository is encrypted with a key derived from a repository password. Set the password as a Kubernetes Secret:

```bash
# Create the repository password secret.
kubectl create secret generic velero-repo-credentials \
  --namespace velero \
  --from-literal=repository-password="$(openssl rand -base64 32)"
```

With Kopia encryption:
- Data blocks are encrypted client-side before upload to S3.
- S3 SSE provides a second layer (managed by AWS).
- An attacker who accesses S3 directly gets encrypted ciphertext without the repository password.

### Step 4: Kubernetes RBAC for Velero

Restrict who can create, read, and restore backups:

```yaml
# ClusterRole for backup operators (create backups, view status).
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: velero-backup-operator
rules:
  - apiGroups: [velero.io]
    resources: [backups, schedules]
    verbs: [get, list, create, watch]
  - apiGroups: [velero.io]
    resources: [restores]
    verbs: []   # Cannot create restores — separate role.
---
# ClusterRole for restore operators (restricted to SRE on-call).
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: velero-restore-operator
rules:
  - apiGroups: [velero.io]
    resources: [backups]
    verbs: [get, list]
  - apiGroups: [velero.io]
    resources: [restores]
    verbs: [get, list, create, watch]
  - apiGroups: [velero.io]
    resources: [backups/download]
    verbs: []   # Cannot download backup archives directly.
---
# ClusterRole for backup deletion (should have no members in production).
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: velero-backup-delete
rules:
  - apiGroups: [velero.io]
    resources: [deletebackuprequests]
    verbs: [create]
```

```yaml
# Bind restore role to SRE team (OIDC group).
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: velero-restore-sre
subjects:
  - kind: Group
    name: "oidc:sre-on-call"
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: velero-restore-operator
  apiGroup: rbac.authorization.k8s.io
```

### Step 5: Backup Schedule and Retention

```bash
# Create a scheduled backup covering all namespaces.
velero schedule create prod-daily \
  --schedule="0 2 * * *" \
  --ttl 720h \
  --include-namespaces '*' \
  --exclude-namespaces kube-system,velero \
  --snapshot-volumes=true \
  --volume-snapshot-locations aws \
  --labels environment=production

# Create a weekly full backup with longer retention.
velero schedule create prod-weekly \
  --schedule="0 0 * * 0" \
  --ttl 2160h \
  --include-namespaces '*' \
  --snapshot-volumes=true

# Check schedule status.
velero schedule get
velero backup get --selector "velero.io/schedule-name=prod-daily" | head -5
```

The `--ttl` here controls when Velero marks a backup for deletion via `DeleteBackupRequest`. With Object Lock's COMPLIANCE mode, Velero cannot actually delete the object even when TTL expires — the object lock holds it until the lock period expires. This is intentional: the Object Lock retention period provides a hard floor that cannot be reduced.

### Step 6: Test Restores Regularly

A backup that has never been tested is not a backup.

```bash
# Restore a specific namespace to a test cluster (never restore to production without testing).
velero restore create test-restore-$(date +%Y%m%d) \
  --from-backup prod-daily-20260428000000 \
  --include-namespaces payments \
  --namespace-mappings payments:payments-restore-test \
  --restore-volumes=true

# Check restore status.
velero restore describe test-restore-20260428
velero restore logs test-restore-20260428

# Verify key resources were restored.
kubectl get pods,secrets,pvc -n payments-restore-test

# Validate a critical secret is present (not empty).
kubectl get secret db-credentials -n payments-restore-test -o jsonpath='{.data.password}' | base64 -d | wc -c
# Should return non-zero.
```

Schedule quarterly restore tests with a documented runbook. Store the test results with the backup metadata.

### Step 7: Exclude Sensitive Namespaces Selectively

Some namespaces should not appear in backups due to sensitivity or restore complexity:

```bash
# Backup with exclusions for secrets that should be re-created, not restored.
velero backup create manual-backup \
  --include-namespaces production \
  --exclude-resources secrets \   # Exclude all Secrets; re-create from a secrets manager on restore.
  --snapshot-volumes=true

# Or: use label selectors to exclude specific secrets.
# Label secrets that should not be backed up (e.g., bootstrap secrets rotated on restore).
kubectl label secret bootstrap-token -n kube-system velero.io/exclude-from-backup=true
```

Note the trade-off: excluding Secrets from backups means they must be re-created from an external secrets manager on restore. This is often safer than storing all Secrets in backup archives, especially for Secrets that are short-lived or bootstrapped from Vault.

### Step 8: Telemetry

```
velero_backup_success_total{schedule}                  counter
velero_backup_failure_total{schedule}                  counter
velero_backup_last_successful_timestamp{schedule}      gauge
velero_backup_size_bytes{backup_name}                  gauge
velero_restore_success_total                           counter
velero_restore_failure_total                           counter
s3_backup_object_count{bucket}                         gauge
s3_unexpected_delete_attempt_total{bucket}             counter
```

Alert on:

- `velero_backup_failure_total` non-zero — backups are failing; data loss risk accumulates.
- `velero_backup_last_successful_timestamp` > 26h ago — daily backup missed; investigate.
- `s3_unexpected_delete_attempt_total` non-zero — someone or something attempted to delete backup objects; this is always anomalous given the IAM policy excludes `s3:DeleteObject`.
- Unexpected IAM role assumption against the Velero role — CloudTrail alert on out-of-hours or off-cluster usage.

## Expected Behaviour

| Signal | Default Velero | Hardened Velero |
|--------|---------------|----------------|
| Backup data accessed by attacker with S3 creds | Plaintext k8s resources and Secrets | Encrypted ciphertext; requires Kopia password |
| Attacker deletes backup objects | Succeeds (no protection) | Blocked by Object Lock (COMPLIANCE); S3 returns error |
| Attacker overwrites backup with malicious content | Succeeds | Object Lock blocks overwrite of existing versions |
| Velero pod compromised; backup download | Archives downloadable via Velero API | No `download` RBAC permission for standard roles |
| Restore to wrong cluster | Not prevented | Documented procedure requires namespace mapping and secret re-creation |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Object Lock COMPLIANCE mode | Truly immutable; cannot be overridden | Backups cannot be deleted even if you want to | Set appropriate TTL; lifecycle rules expire after lock period. |
| Kopia encryption | Client-side encryption; S3 access = ciphertext | Repository password is a new secret to manage | Store in HSM or Vault; rotate with defined procedure. |
| No `s3:DeleteObject` for Velero | Prevents Velero from being used to delete its own backups | Velero cannot expire old backups via S3 API | Object Lock lifecycle handles expiry; acceptable trade-off. |
| Excluding Secrets from backups | Reduces sensitivity of backup archives | Restore requires re-creating Secrets from external source | Only viable with a mature secrets manager (Vault, AWS Secrets Manager). |
| Separate restore-test cluster | Safe testing without touching production | Operational overhead of maintaining a test cluster | Use a low-cost k3s or k8s in kind for restore validation; automated quarterly. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Kopia repository password lost | Cannot decrypt any backup archives | Restores fail with decryption error | Emergency: recover password from Vault; without it, backups are irrecoverable — store password securely. |
| Object Lock TTL shorter than incident discovery time | Backup expired before ransomware discovered | Recovery window missed | Set Object Lock retention >= 30 days; review TTL against incident mean-time-to-discovery. |
| Backup schedule silently skipped | Hours of data lost before discovery | `velero_backup_last_successful_timestamp` alert | Check Velero pod logs; Velero schedule controller restarts on pod restart. |
| PVC snapshot quota exceeded | Snapshot creation fails; backup incomplete | Backup status shows `PartiallyFailed` | Increase EBS/GCS snapshot quota or clean up old snapshots. |
| Restore fails due to missing CRDs | Resources cannot be created on target cluster | Restore logs show `no kind Foo` | Install required CRDs before restoring; order-dependent restores need manual intervention. |
| Backup size grows unbounded | Storage costs; Object Lock prevents deletion | S3 cost alert; bucket size metric | Adjust TTL; use lifecycle rules to transition old backups to cheaper storage (Glacier) before expiry. |

## Related Articles

- [Kubernetes Secrets Management](/articles/kubernetes/secrets-management/)
- [etcd Encryption at Rest](/articles/kubernetes/etcd-encryption/)
- [Security Infrastructure Disaster Recovery](/articles/cross-cutting/security-infra-disaster-recovery/)
- [Hardware Security Module Integration](/articles/cross-cutting/hsm-key-management/)
- [Ransomware Multi-Extortion Defence](/articles/cross-cutting/ransomware-multi-extortion-defence/)
