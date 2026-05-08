---
title: "Kubernetes CronJob Security: Least Privilege, Concurrency Controls, and Credential Isolation"
description: "CronJobs run privileged operations on a schedule — database backups, report generation, secret rotation. A CronJob that accumulates permissions over time, leaves credentials in completed pods, or runs with unbounded concurrency creates persistent attack surface. Hardening CronJobs applies the same least-privilege principles as long-running workloads."
slug: "kubernetes-cronjob-security"
date: 2026-05-01
lastmod: 2026-05-01
category: "kubernetes"
tags: ["cronjob", "kubernetes", "least-privilege", "credentials", "concurrency", "rbac"]
personas: ["platform-engineer", "security-engineer"]
article_number: 312
difficulty: "intermediate"
estimated_reading_time: 12
published: true
layout: article.njk
permalink: "/articles/kubernetes/kubernetes-cronjob-security/index.html"
---

# Kubernetes CronJob Security: Least Privilege, Concurrency Controls, and Credential Isolation

## Problem

Kubernetes CronJobs are frequently treated as second-class workloads from a security perspective. They run infrequently, they are not continuously monitored, and their permissions tend to accumulate over time as requirements change. A CronJob that once needed to read a single ConfigMap now has cluster-wide secret access because "it was easier to give it more permission than figure out exactly what it needs."

Specific failure modes:

- **Overpermissive service accounts.** A database backup CronJob uses a service account with read access to all Secrets in all namespaces — far more than the backup key it actually needs. Any compromise of this CronJob's pod provides full secret exfiltration.
- **Credentials left in completed pod environments.** The CronJob completes; the Job pod enters `Completed` state but remains in the cluster. Environment variables containing database passwords, API keys, and service account tokens are readable via `kubectl describe pod` by anyone with pod-read access.
- **Unbounded concurrency creating race conditions.** A CronJob with `concurrencyPolicy: Allow` runs every minute. If the job takes two minutes, two instances run simultaneously. Both read the same state, make conflicting writes, and produce corrupted output. This can be exploited by timing attacks.
- **No job TTL, accumulating forensic evidence.** Completed Job pods accumulate indefinitely. Each one has logs, environment variables, and mounted secret data that persists long after the job finished. An attacker with pod-read access can forensically extract credentials from completed jobs run weeks ago.
- **Container images not pinned.** The CronJob container image uses `:latest`. An update to the base image introduces a vulnerability between CronJob runs; the vulnerability is present for the duration of the image cache lifetime but appears "fixed" when the cache is refreshed.
- **No deadline or active deadline.** A CronJob without `activeDeadlineSeconds` runs indefinitely if it hangs. A hung job using a database connection, holding a lock, or consuming quota blocks subsequent scheduled runs.

**Target systems:** Kubernetes 1.28+ CronJob API (`batch/v1`); Job TTL controller; concurrencyPolicy; RBAC for CronJob service accounts.

## Threat Model

- **Adversary 1 — Pod environment variable credential extraction:** A developer with namespace access runs `kubectl get pods` and finds a completed backup CronJob pod. They run `kubectl describe pod backup-job-1234` and read the database password from the pod's environment variables. The pod has been sitting in Completed state for three weeks.
- **Adversary 2 — Overpermissive SA used by compromised CronJob:** An attacker discovers a vulnerability in the backup script (e.g., shell injection via a filename). The CronJob's service account has `secrets: get` across all namespaces. The attacker extracts all cluster secrets through the vulnerability.
- **Adversary 3 — Concurrent execution race condition:** A secret rotation CronJob reads the current secret value, generates a new one, and writes it. Two instances run simultaneously; both read the same old value; both generate different new values; one overwrites the other's write. The rotation process fails and one system gets a new credential that the other doesn't know about.
- **Adversary 4 — Image substitution between runs:** The CronJob uses `:latest`. An attacker compromises the container registry between Monday and Tuesday. Tuesday's run pulls the compromised image.
- **Adversary 5 — Stale job accumulation for forensic extraction:** Completed jobs accumulate in the cluster. Each completed pod retains environment variables and mounted volume data. An attacker who gains read access to pods can reconstruct weeks of credential history from completed job pods.
- **Access level:** Adversaries 1 and 5 need namespace pod-read access. Adversary 2 exploits a pre-existing vulnerability in the CronJob's workload. Adversary 4 needs registry access. Adversary 3 exploits scheduling configuration.
- **Objective:** Extract credentials, escalate via over-permissive service account, corrupt scheduled operations.
- **Blast radius:** A CronJob service account with cluster-wide secret access provides complete credential exfiltration capability to anyone who can exploit the CronJob's workload.

## Configuration

### Step 1: Dedicated Least-Privilege Service Account

```yaml
# Service account scoped to exactly what the CronJob needs.
apiVersion: v1
kind: ServiceAccount
metadata:
  name: backup-cronjob-sa
  namespace: database

---
# Role: only access the specific secret this backup job needs.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: backup-cronjob-role
  namespace: database
rules:
  # Read the backup credentials secret — by name only.
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["backup-db-credentials"]
    verbs: ["get"]

  # Write backup status to a ConfigMap.
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["backup-status"]
    verbs: ["get", "update", "patch"]

  # NOT: list secrets, access other namespaces, create/delete resources.

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: backup-cronjob-binding
  namespace: database
subjects:
  - kind: ServiceAccount
    name: backup-cronjob-sa
    namespace: database
roleRef:
  kind: Role
  name: backup-cronjob-role
  apiGroup: rbac.authorization.k8s.io
```

### Step 2: CronJob Configuration with Security Controls

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: database-backup
  namespace: database
spec:
  schedule: "0 2 * * *"     # Daily at 2am.

  # Prevent concurrent execution — critical for operations with shared state.
  concurrencyPolicy: Forbid  # Wait for previous job; do not run overlapping.
  # Options: Allow (default), Forbid, Replace.

  # Keep minimal history — don't accumulate completed jobs.
  successfulJobsHistoryLimit: 2   # Keep last 2 successful jobs.
  failedJobsHistoryLimit: 3       # Keep last 3 failed jobs for debugging.

  # Start deadline: if the job can't start within 300s of scheduled time, skip.
  startingDeadlineSeconds: 300

  jobTemplate:
    spec:
      # TTL: delete the Job (and its pods) 1 hour after completion.
      ttlSecondsAfterFinished: 3600

      # Active deadline: kill the job if it runs longer than 2 hours.
      activeDeadlineSeconds: 7200

      # Retry only once on failure.
      backoffLimit: 1

      template:
        spec:
          serviceAccountName: backup-cronjob-sa

          restartPolicy: OnFailure

          securityContext:
            runAsNonRoot: true
            runAsUser: 65534
            seccompProfile:
              type: RuntimeDefault

          containers:
            - name: backup
              # Pin by digest — no surprise image changes between runs.
              image: gcr.io/example/db-backup@sha256:abc123def456...

              securityContext:
                allowPrivilegeEscalation: false
                readOnlyRootFilesystem: true
                capabilities:
                  drop: ["ALL"]

              resources:
                limits:
                  cpu: "500m"
                  memory: "512Mi"
                requests:
                  cpu: "100m"
                  memory: "128Mi"

              # Do NOT pass credentials as environment variables.
              # Mount them as files from a Secret volume instead.
              volumeMounts:
                - name: db-credentials
                  mountPath: /etc/backup/credentials
                  readOnly: true
                - name: tmp
                  mountPath: /tmp

              # No env vars with credentials.
              # Backup script reads from mounted files:
              # DB_PASSWORD=$(cat /etc/backup/credentials/password)

          volumes:
            - name: db-credentials
              secret:
                secretName: backup-db-credentials
                defaultMode: 0400   # Owner read-only.
            - name: tmp
              emptyDir: {}

          # Disable auto-mount of service account token if not needed.
          automountServiceAccountToken: false
```

### Step 3: Avoid Credentials in Environment Variables

```yaml
# BAD: credentials in environment variables — visible in kubectl describe pod.
env:
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: backup-db-credentials
        key: password
# This appears in `kubectl describe pod backup-job-1234` output for all time.

# GOOD: credentials mounted as files — not visible in pod description.
volumeMounts:
  - name: db-credentials
    mountPath: /etc/backup/credentials
    readOnly: true
volumes:
  - name: db-credentials
    secret:
      secretName: backup-db-credentials
      # Mount specific keys only.
      items:
        - key: password
          path: password
          mode: 0400
```

```bash
# In the CronJob script: read credentials from files, not env.
#!/bin/bash
set -euo pipefail

# Read credentials from mounted secret volume.
DB_HOST="$(cat /etc/backup/credentials/host)"
DB_USER="$(cat /etc/backup/credentials/username)"
DB_PASSWORD="$(cat /etc/backup/credentials/password)"

# Use process substitution to avoid password in command arguments.
PGPASSWORD="$DB_PASSWORD" pg_dump \
  -h "$DB_HOST" \
  -U "$DB_USER" \
  --format=custom \
  --file=/tmp/backup-"$(date +%Y%m%d-%H%M%S)".dump \
  mydb

# Zero the credential variables after use.
unset DB_PASSWORD
```

### Step 4: TTL and Cleanup Enforcement

```yaml
# Ensure TTL controller is enabled (it is by default in k8s 1.21+).
# Verify:
kubectl get deployment ttl-controller -n kube-system 2>/dev/null || \
  echo "TTL controller: check kube-controller-manager --feature-gates"

# Enforce cleanup via Kyverno if teams forget to set TTL.
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-job-ttl
spec:
  validationFailureAction: Enforce
  rules:
    - name: require-ttlSecondsAfterFinished
      match:
        any:
          - resources:
              kinds: ["CronJob"]
      validate:
        message: "CronJobs must set ttlSecondsAfterFinished (max 86400)."
        pattern:
          spec:
            jobTemplate:
              spec:
                ttlSecondsAfterFinished: "1-86400"   # Between 1s and 24h.
```

```bash
# Emergency cleanup: delete all completed job pods older than 24 hours.
kubectl get pods --all-namespaces \
  -o json | \
  jq -r '
    .items[] |
    select(
      .status.phase == "Succeeded" and
      (now - (.status.completionTime // .metadata.creationTimestamp | fromdateiso8601)) > 86400
    ) |
    "\(.metadata.namespace) \(.metadata.name)"
  ' | \
  while read ns name; do
    kubectl delete pod "$name" -n "$ns" --grace-period=0
  done
```

### Step 5: NetworkPolicy for CronJob Pods

```yaml
# Restrict CronJob pod network access to only required destinations.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backup-cronjob-netpol
  namespace: database
spec:
  podSelector:
    matchLabels:
      app: database-backup
  policyTypes:
    - Egress
    - Ingress
  ingress: []    # No inbound connections to CronJob pods.
  egress:
    # Only to the database.
    - to:
        - podSelector:
            matchLabels:
              app: postgresql
      ports:
        - port: 5432
    # Only to the backup storage (S3 endpoint).
    - to:
        - ipBlock:
            cidr: 10.0.50.0/24   # Internal S3/object storage.
      ports:
        - port: 443
    # DNS.
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - port: 53
          protocol: UDP
```

### Step 6: Monitoring and Alerting for CronJob Health

```yaml
# Prometheus rules for CronJob monitoring.
groups:
  - name: cronjob-security
    rules:
      # Alert if a CronJob hasn't run in twice its expected interval.
      - alert: CronJobMissedSchedule
        expr: |
          time() - kube_cronjob_status_last_schedule_time{cronjob="database-backup"} > 90000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "CronJob {{ $labels.cronjob }} has not run in 25 hours"

      # Alert if a Job is running longer than expected.
      - alert: CronJobRunningTooLong
        expr: |
          kube_job_status_active{job_name=~"database-backup-.*"} > 0
          and
          (time() - kube_job_status_start_time{job_name=~"database-backup-.*"}) > 7200
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Backup job running for over 2 hours"

      # Alert if failed jobs are accumulating.
      - alert: CronJobFailureAccumulating
        expr: |
          kube_cronjob_status_failed{} > 2
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "CronJob {{ $labels.cronjob }} has {{ $value }} recent failures"
```

### Step 7: Audit Logging for CronJob Activity

```bash
# Kubernetes audit policy: log CronJob execution.
# /etc/kubernetes/audit-policy.yaml
- level: RequestResponse
  resources:
    - group: "batch"
      resources: ["jobs", "cronjobs"]
  verbs: ["create", "delete", "patch", "update"]
  namespaces: ["production", "database"]

# Alert on unexpected CronJob modifications.
# Any change to a production CronJob outside CI/CD should trigger review.
```

### Step 8: Telemetry

```
kube_cronjob_status_last_schedule_time{cronjob, namespace}      gauge
kube_cronjob_status_failed{cronjob, namespace}                  gauge
kube_job_status_active{job_name, namespace}                     gauge
kube_job_duration_seconds{job_name}                             histogram
kube_pod_status_phase{pod, namespace, phase}                    gauge
cronjob_credential_in_env_var_total{cronjob, namespace}         gauge  # Should be 0.
cronjob_ttl_not_set_total{namespace}                            gauge  # Should be 0.
```

Alert on:

- `kube_cronjob_status_failed` > 0 — a scheduled job is failing; investigate before next run.
- `kube_job_status_active` non-zero for longer than `activeDeadlineSeconds` — job has hung; investigate.
- CronJob pod in `Succeeded` phase older than `ttlSecondsAfterFinished` — TTL controller may not be functioning.
- `cronjob_credential_in_env_var_total` non-zero — a CronJob is exposing credentials in environment variables.

## Expected Behaviour

| Signal | Default CronJob | Hardened CronJob |
|--------|----------------|-----------------|
| Completed pod with credentials | Env vars readable via kubectl describe | Credentials in volume files; not in pod description |
| Service account scope | Often namespace-wide or cluster-wide | Scoped to specific named resources |
| Concurrent runs | Allow (default) — may corrupt shared state | Forbid — only one instance runs at a time |
| Completed pod accumulation | Infinite; forensic evidence persists | TTL deletes after 1 hour |
| Image between runs | :latest — may change silently | Digest-pinned — same binary every run |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| `concurrencyPolicy: Forbid` | Prevents race conditions | Next run skipped if current hasn't finished | Increase `activeDeadlineSeconds`; alert on missed runs |
| Short `ttlSecondsAfterFinished` | Limits credential exposure window | Logs lost before debugging | Ship logs to centralised logging before TTL expires |
| `automountServiceAccountToken: false` | Prevents SA token misuse | CronJob cannot call Kubernetes API | Only disable if the CronJob doesn't need API access |
| Credentials in volume files | Not visible in pod description | Slightly more complex scripting | Standardise on file-based credential reading |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| `concurrencyPolicy: Forbid` skips run | Backup not taken for 24h if previous run hung | Missed schedule alert | Investigate hung run; manually delete stuck job; next run proceeds |
| TTL deletes job before debugging | Developer cannot inspect failed pod logs | Logs already shipped to Loki/Elasticsearch | Increase TTL for failed jobs (`failedJobsHistoryLimit`); ship logs |
| Service account too restrictive | Job fails with 403 | Job failure alert; audit log shows permission denied | Add specific required permission; avoid broadening to `secrets: *` |
| `startingDeadlineSeconds` skips job | Node pressure delays pod start; job never runs | Missed schedule alert | Investigate node pressure; increase `startingDeadlineSeconds` |

## Related Articles

- [Kubernetes RBAC Design Patterns](/articles/kubernetes/rbac-design-patterns/)
- [Kubernetes Secrets Management](/articles/kubernetes/secrets-management/)
- [Pod Security Context](/articles/kubernetes/pod-security-context/)
- [Kyverno Policy Development and Testing](/articles/kubernetes/kyverno-policy-development/)
- [Kubernetes Resource Quotas and LimitRanges](/articles/kubernetes/resource-quotas-limitranges/)
