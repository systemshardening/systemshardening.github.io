---
title: "Detecting Credential Access Attempts: Log Analysis and Runtime Monitoring"
description: "Attackers steal credentials before they steal data. This article shows how to instrument auditd, Falco, Kubernetes audit logs, and CloudTrail to detect OS credential dumping, brute force, credential stuffing, and cloud IAM abuse before they lead to a breach."
slug: credential-access-detection
date: 2026-05-07
lastmod: 2026-05-07
category: observability
tags:
  - credential-theft
  - detection
  - authentication-logs
  - mitre-attack
  - siem
personas:
  - security-engineer
  - security-analyst
article_number: 555
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/observability/credential-access-detection/
---

# Detecting Credential Access Attempts: Log Analysis and Runtime Monitoring

## Problem

Credential theft is the highest-frequency path to a significant breach. Verizon DBIR consistently places stolen or misused credentials as the leading initial access vector — and the same pattern recurs at every subsequent stage of an intrusion. An attacker who has a foothold on a Linux host, a compromised CI/CD runner, or a container with over-permissive mounts will attempt to harvest credentials within minutes of gaining access.

Most organizations have authentication logging enabled but are not instrumenting for the access events that *precede* authentication abuse. By the time a brute-force lockout alert fires, the attacker may already have the hash they need. By the time an IAM alert fires in your SIEM, the lateral movement has already happened.

The specific gaps:

- **Filesystem access to credential stores is not logged by default.** `/etc/shadow`, `~/.ssh/id_rsa`, and application secret files are not covered by traditional authentication monitoring. An attacker can `cat /etc/shadow` and walk away with no audit trace unless auditd rules are explicitly configured.
- **Memory credential dumping bypasses filesystem controls entirely.** A process that attaches to `ssh-agent` via ptrace and reads its address space leaves no filesystem footprint at all.
- **Brute force detection focuses on accounts, not sources.** Standard lockout policies are account-scoped. A low-and-slow distributed attack that targets many accounts from many sources stays below every per-account threshold while still being highly detectable from source IP signal.
- **Cloud credential theft happens silently in the control plane.** An `AssumeRole` from a Tor exit node or an unexpected region is not an authentication failure — it succeeds — and is invisible to on-prem tooling.
- **Kubernetes secrets are API objects.** A `LIST secrets` call from a service account that has never done it before is a credential access event, but it looks like a normal API call without audit policy enforcement and log analysis.

This article provides detection rules across all of these layers: auditd for Linux filesystem and syscall monitoring, Falco for container runtime detection, Kubernetes audit logs for secrets API access, CloudTrail and GCP IAM for cloud credential abuse, and auth.log analysis for brute force and credential stuffing.

**Target environments:** Linux hosts with auditd, container workloads with Falco, Kubernetes clusters with audit logging, AWS CloudTrail, and a centralized SIEM (Elasticsearch/OpenSearch, Splunk, or equivalent) for correlation.

## Threat Model

**MITRE ATT&CK Credential Access techniques in scope:**

| Technique | ID | What to detect |
|---|---|---|
| OS Credential Dumping | T1003 | File reads on `/etc/shadow`, `/etc/passwd`, LSASS-equivalent process access |
| Unsecured Credentials | T1552 | Reads of private key files, `.env` files, config files containing secrets |
| Credentials from Password Stores | T1555 | Access to `gnome-keyring`, browser credential DBs, `gpg-agent` socket interaction |
| Brute Force | T1110 | High failure rate per source IP, credential stuffing pattern, password spraying |

**Adversary goals:** Harvest local credentials for offline cracking, steal SSH private keys for lateral movement, abuse cloud credentials for privilege escalation, or enumerate Kubernetes secrets to exfiltrate application secrets and service account tokens.

**Detection philosophy:** Alert on access to credential materials and anomalous authentication patterns — not only on authentication failures. The goal is to fire before a credential is successfully used, or immediately after a successful use that follows a suspicious pattern.

## Configuration

### Linux: auditd Rules for Credential File Access

The foundation of OS-level credential access detection is auditd watch rules on the files an attacker will target. These rules generate `SYSCALL` and `PATH` audit events on any `open`, `openat`, or `read` call touching protected files.

Install rules in `/etc/audit/rules.d/credential-access.rules`:

```bash
# Watch /etc/shadow — any read attempt by any process is suspicious outside
# of PAM-invoked contexts. The -p r flag audits read access specifically.
-w /etc/shadow -p r -k credential_access_shadow
-w /etc/gshadow -p r -k credential_access_shadow

# Watch /etc/passwd for writes — an attacker adding a new UID-0 account.
-w /etc/passwd -p wa -k credential_access_passwd

# Watch SSH private key files in common locations.
-w /root/.ssh -p r -k credential_access_ssh_keys
-w /home -p r -k credential_access_home_ssh

# Watch for access to the SSH agent socket — a process connecting to it
# can sign arbitrary challenges without seeing the private key directly,
# but it is still a credential access event worth tracking.
-a always,exit -F arch=b64 -S connect -F path=/run/user//keyring/ssh \
  -k credential_access_ssh_agent

# Watch for ptrace attach to sensitive processes: ssh-agent, gpg-agent,
# gnome-keyring-daemon. Ptrace is the mechanism used to dump in-memory
# keys. Rule fires when any process issues PTRACE_ATTACH.
-a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k credential_access_ptrace

# Watch for reads of .env files and common application secret locations.
-w /etc/environment -p r -k credential_access_env
-a always,exit -F arch=b64 -S openat -F path_contains=.env \
  -k credential_access_dotenv

# Watch AWS credential files.
-w /root/.aws/credentials -p r -k credential_access_aws_creds
-w /root/.aws/config -p r -k credential_access_aws_creds
```

After loading rules with `augenrules --load`, verify they are active:

```bash
auditctl -l | grep credential_access
```

#### Parsing and Alerting on auditd Events

Raw auditd log lines are structured but terse. Use `ausearch` to filter by key and pipe to `aureport` for aggregation, or ship the raw journal to your SIEM.

```bash
# Real-time watch for shadow file reads; pipe to alerting webhook.
ausearch -k credential_access_shadow --start today -i | \
  grep -v 'auid=0' | \  # filter root (adjust for your environment)
  while IFS= read -r line; do
    curl -s -X POST https://alerts.internal/webhook \
      -H 'Content-Type: application/json' \
      -d "{\"event\": \"shadow_read\", \"detail\": \"$(echo "$line" | jq -Rs .)\"}"
  done
```

For Elasticsearch/OpenSearch SIEM, configure Filebeat with the `auditd` module — it parses audit log format automatically and creates structured documents with `auditd.data.key`, `auditd.summary.actor.primary`, and `process.executable` fields.

A detection rule (in Sigma format, translatable to any SIEM):

```yaml
title: OS Credential File Read
id: 9f2c3a17-bb41-4e8a-9d63-c1f0ae2d7b45
status: production
description: >
  Detects read access to /etc/shadow or SSH private key files via auditd.
  Excludes known-good processes: sshd, sudo, passwd, and the login family.
logsource:
  product: linux
  service: auditd
detection:
  selection:
    auditd.data.key:
      - credential_access_shadow
      - credential_access_ssh_keys
  filter_legitimate:
    process.executable|endswith:
      - /sbin/sshd
      - /usr/bin/sudo
      - /usr/bin/passwd
      - /bin/login
      - /usr/sbin/crond
  condition: selection and not filter_legitimate
falsepositives:
  - Backup agents reading /etc/shadow for account auditing
  - Configuration management tools (Chef/Puppet/Ansible) during initial setup
level: high
tags:
  - attack.credential_access
  - attack.t1003
  - attack.t1552
```

### Linux: Detecting Memory Credential Dumping

Memory-based credential theft (the Linux equivalent of LSASS dumping) targets long-running processes that hold decrypted key material: `ssh-agent`, `gpg-agent`, `gnome-keyring-daemon`, and application processes that cache database passwords.

The ptrace auditd rule above fires on PTRACE_ATTACH. Supplement it with a Falco rule that uses the eBPF-backed ptrace event:

```yaml
# falco rule: detect ptrace attach targeting credential-holding processes.
- rule: Ptrace Attach to Credential Agent
  desc: >
    A process issued PTRACE_ATTACH against ssh-agent, gpg-agent, or
    gnome-keyring. This is the primary mechanism for in-memory key theft.
  condition: >
    ptrace and
    ptrace.request = PTRACE_ATTACH and
    proc.name in (ssh-agent, gpg-agent, gnome-keyring-d) and
    not proc.pname in (gdb, strace)  # allow debuggers if explicitly permitted
  output: >
    Ptrace attach to credential agent
    (tracer=%proc.pname[%proc.ppid] tracee=%proc.name[%proc.pid]
    user=%user.name container=%container.id)
  priority: CRITICAL
  tags: [credential_access, T1003, mitre_attack]
```

Also watch for `/proc/<pid>/mem` reads against these processes — an alternative dumping vector that does not require ptrace:

```yaml
- rule: Proc Mem Read of Credential Agent
  desc: >
    A process opened /proc/<pid>/mem targeting a credential agent process.
    This can exfiltrate key material without PTRACE_ATTACH.
  condition: >
    open_read and
    fd.name glob "/proc/*/mem" and
    proc.name in (ssh-agent, gpg-agent, gnome-keyring-d)
  output: >
    /proc/mem read targeting credential agent
    (reader=%proc.name[%proc.pid] target_fd=%fd.name user=%user.name)
  priority: CRITICAL
  tags: [credential_access, T1003]
```

### Detecting Brute Force Attacks via auth.log Analysis

`/var/log/auth.log` (or `journald` on systemd systems) is the primary signal source for SSH and PAM brute force detection. The key metric is **failed authentication rate per source IP**, not per target account — distributed spraying attacks deliberately stay under per-account thresholds.

#### Prometheus + Promtail Extraction

With Loki/Promtail, extract the failure count as a metric using a pipeline stage:

```yaml
# promtail pipeline stage: extract failed SSH login count by source IP.
- pipeline_stages:
  - regex:
      expression: >
        'Failed password for .* from (?P<src_ip>\d+\.\d+\.\d+\.\d+)
        port \d+ ssh2'
  - labels:
      src_ip:
  - metrics:
      ssh_failed_auth_total:
        type: Counter
        description: SSH authentication failures by source IP
        source: src_ip
        config:
          action: inc
```

Then alert in Prometheus:

```yaml
# Alert: more than 20 SSH failures from a single IP in 5 minutes.
# Threshold should be tuned to your baseline; 20 is conservative for most
# environments where legitimate users do not fail 20 times.
- alert: SshBruteForceBySourceIP
  expr: >
    increase(ssh_failed_auth_total[5m]) by (src_ip) > 20
  for: 1m
  labels:
    severity: high
    mitre_technique: T1110
  annotations:
    summary: "SSH brute force from {{ $labels.src_ip }}"
    description: >
      {{ $value }} failed authentication attempts from {{ $labels.src_ip }}
      in the last 5 minutes. Threshold: 20.
    runbook_url: "https://systemshardening.com/runbooks/brute-force"
```

#### Account Lockout Event Correlation

Linux `pam_faillock` and `pam_tally2` emit syslog messages on lockout. Parse these alongside brute force events to identify which accounts were targeted:

```
# Sigma rule: PAM account lockout following high failure rate.
title: Account Lockout After Brute Force Pattern
detection:
  brute_force:
    EventID: ssh_failed_auth_total  # custom metric alert
  lockout:
    message|contains: "pam_faillock"
    message|contains: "user locked out"
  timeframe: 10m
  condition: brute_force and lockout
```

### Detecting Credential Stuffing

Credential stuffing is structurally different from brute force: the attacker uses known-valid username/password pairs from prior data breaches. The pattern is **few failures followed by a successful login from the same source** — the inverse of what lockout policies catch.

Detection query for Elasticsearch/OpenSearch:

```json
{
  "query": {
    "bool": {
      "filter": [
        { "range": { "@timestamp": { "gte": "now-15m" } } },
        { "term": { "event.category": "authentication" } }
      ]
    }
  },
  "aggs": {
    "by_source": {
      "terms": { "field": "source.ip", "size": 500 },
      "aggs": {
        "failures": {
          "filter": { "term": { "event.outcome": "failure" } }
        },
        "successes": {
          "filter": { "term": { "event.outcome": "success" } }
        },
        "stuffing_pattern": {
          "bucket_selector": {
            "buckets_path": {
              "fail_count": "failures._count",
              "success_count": "successes._count"
            },
            "script": "params.fail_count >= 3 && params.success_count >= 1"
          }
        }
      }
    }
  }
}
```

A source IP with 3 or more failures and at least one success in a 15-minute window is a high-confidence credential stuffing indicator. Tune the failure threshold based on your environment's normal retry patterns — MFA prompts and expired passwords can produce 2–3 failures legitimately.

### Cloud Credential Theft: AWS CloudTrail Detection

Cloud credentials are the most valuable target in a modern infrastructure. AWS IAM credentials, once stolen, can be used from anywhere — they do not require network access to your perimeter.

#### AssumeRole from Anomalous Context

The most common cloud credential abuse pattern is using a stolen IAM key to assume a higher-privileged role. Detection focuses on context anomalies — unusual source IP, unexpected region, or a principal that has never assumed a particular role before.

Athena query for CloudTrail analysis:

```sql
-- Find AssumeRole calls from IPs not previously seen for this principal.
-- Run as a scheduled query against your CloudTrail Athena table.
WITH recent_calls AS (
  SELECT
    useridentity.principalid    AS principal,
    sourceipaddress             AS src_ip,
    awsregion                   AS region,
    requestparameters           AS params,
    eventtime
  FROM cloudtrail_logs
  WHERE eventname = 'AssumeRole'
    AND eventtime > date_add('day', -7, current_timestamp)
),
baseline_ips AS (
  SELECT DISTINCT useridentity.principalid AS principal, sourceipaddress AS src_ip
  FROM cloudtrail_logs
  WHERE eventname = 'AssumeRole'
    AND eventtime BETWEEN date_add('day', -90, current_timestamp)
                      AND date_add('day', -7, current_timestamp)
)
SELECT r.*
FROM recent_calls r
LEFT JOIN baseline_ips b
  ON r.principal = b.principal AND r.src_ip = b.src_ip
WHERE b.principal IS NULL  -- IP not seen in 90-day baseline
ORDER BY r.eventtime DESC;
```

#### CloudWatch Metric Filter for Real-Time Detection

For real-time alerting without Athena query latency, use a CloudWatch metric filter on the CloudTrail log group:

```json
{
  "filterPattern": "{ ($.eventName = AssumeRole) && ($.errorCode NOT EXISTS) }",
  "metricTransformations": [
    {
      "metricName": "AssumeRoleSuccess",
      "metricNamespace": "SecurityDetection",
      "metricValue": "1",
      "dimensions": {
        "SourceIP": "$.sourceIPAddress",
        "Principal": "$.userIdentity.principalId"
      }
    }
  ]
}
```

Alarm on this metric with an anomaly detection band: CloudWatch Anomaly Detection uses ML to model expected call volume and alerts when the actual rate deviates significantly — useful for detecting a stolen key used in a burst pattern.

#### GCP IAM Credential Usage Anomalies

On GCP, service account key exfiltration followed by use is detectable via Cloud Audit Logs. Look for `google.iam.credentials.v1.GenerateAccessToken` or `SignJwt` calls originating from outside GCP infrastructure (external IP addresses), which indicate a key is being used outside its intended compute context:

```sql
-- BigQuery query against GCP audit logs.
SELECT
  protopayload_auditlog.authenticationInfo.principalEmail AS service_account,
  protopayload_auditlog.requestMetadata.callerIp AS caller_ip,
  protopayload_auditlog.methodName AS method,
  timestamp
FROM `PROJECT_ID.DATASET.cloudaudit_googleapis_com_activity`
WHERE
  protopayload_auditlog.methodName IN (
    'google.iam.credentials.v1.IAMCredentials.GenerateAccessToken',
    'google.iam.credentials.v1.IAMCredentials.SignJwt'
  )
  AND NOT NET.IP_IN_NET(
    protopayload_auditlog.requestMetadata.callerIp,
    '35.0.0.0/8'  -- GCP IP ranges; use full list in production
  )
  AND timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
ORDER BY timestamp DESC;
```

### Kubernetes Secrets Access Detection

Kubernetes secrets are API objects protected by RBAC, but RBAC misconfiguration and over-permissive service accounts are endemic. Any `GET`, `LIST`, or `WATCH` on secrets by a service account that has no legitimate need is a credential access event.

#### Enabling the Required Audit Policy

Secrets access is only logged if the Kubernetes API server audit policy explicitly covers it. A minimal policy that captures credential access events:

```yaml
# /etc/kubernetes/audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Log all access to secrets at the Request level (includes request body).
  # RequestResponse would include the secret values themselves in the log —
  # do NOT use RequestResponse for secrets.
  - level: Request
    resources:
      - group: ""
        resources: ["secrets"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]

  # Log service account token creation — used by attackers to forge tokens.
  - level: Request
    resources:
      - group: ""
        resources: ["serviceaccounts/token"]

  # Everything else: Metadata only.
  - level: Metadata
```

#### Detection Query for Unexpected Secret Access

With audit logs flowing to your SIEM, alert when a service account performs a `LIST` on secrets namespace-wide — a common first step in credential harvesting:

```yaml
# Sigma rule: service account performing namespace-wide secrets LIST.
title: Kubernetes Secrets List by Unexpected Service Account
id: 3d8f1c22-aa77-4b19-8e33-f2d09b7c5a11
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    verb: list
    objectRef.resource: secrets
    user.username|startswith: "system:serviceaccount:"
  filter_known_controllers:
    user.username|contains:
      - "system:serviceaccount:kube-system:"
      - "system:serviceaccount:cert-manager:"
      - "system:serviceaccount:external-secrets:"
  condition: selection and not filter_known_controllers
falsepositives:
  - New operators or controllers accessing secrets during initial bootstrap
level: high
tags:
  - attack.credential_access
  - attack.t1552.007
```

### Container Runtime: Falco Rules for Mounted Secret Reads

In containerized environments, secrets are frequently mounted as files into pods. An attacker who compromises the container process can read these files directly. Falco detects this pattern at the syscall level, catching reads that bypass any application-layer access controls:

```yaml
# Detect reads of Kubernetes secret mount paths from unexpected processes.
- macro: k8s_secret_mount_path
  condition: >
    fd.name startswith /var/run/secrets/ or
    fd.name startswith /etc/secrets/ or
    (fd.name startswith /etc/ and
     fd.name endswith .token)

- rule: Container Reads Kubernetes Secret Mount
  desc: >
    A process in a container read a file from the Kubernetes secrets mount
    path. Expected readers are the application entrypoint processes.
    Unexpected readers (shells, package managers, curl) indicate an attacker
    harvesting mounted credentials.
  condition: >
    open_read and
    container and
    k8s_secret_mount_path and
    not proc.name in (container_entrypoint_processes) and
    proc.name in (sh, bash, dash, zsh, curl, wget, python, python3,
                  ruby, perl, nc, ncat, cat, cp, mv, tar, zip)
  output: >
    Suspicious read of Kubernetes secret mount
    (proc=%proc.name[%proc.pid] path=%fd.name
    container=%container.name image=%container.image.repository
    k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name)
  priority: HIGH
  tags: [credential_access, container, T1552, kubernetes]
```

### Secret Sprawl Detection: Environment Variable Scanning

Hardcoded credentials in container environment variables are a persistent problem. CI/CD pipelines that bake secrets into images or deployment manifests create credential sprawl that can be harvested by any process in the container with access to `/proc/self/environ` or the environment of sibling processes.

A runtime scanner (run as a DaemonSet) that checks for credential patterns in running container environments:

```bash
#!/usr/bin/env bash
# secret-env-scanner.sh
# Scans running container environment variables for secret patterns.
# Run as a privileged DaemonSet with access to /proc on the host.

PATTERNS=(
  'AWS_SECRET_ACCESS_KEY=[A-Za-z0-9/+]{40}'
  'GITHUB_TOKEN=ghp_[A-Za-z0-9]{36}'
  'DATABASE_PASSWORD=.{8,}'
  'DB_PASS=.{6,}'
  'SECRET_KEY=.{16,}'
  'PRIVATE_KEY=.{20,}'
  'API_KEY=.{16,}'
)

for pid_dir in /proc/[0-9]*/; do
  pid=$(basename "$pid_dir")
  environ_file="${pid_dir}environ"

  [[ -r "$environ_file" ]] || continue

  # Read null-delimited environment variables.
  env_content=$(tr '\0' '\n' < "$environ_file" 2>/dev/null)

  for pattern in "${PATTERNS[@]}"; do
    if echo "$env_content" | grep -qE "$pattern"; then
      container_id=$(cat "${pid_dir}cgroup" 2>/dev/null | \
        grep -oP '(?<=docker-)[a-f0-9]{12}' | head -1)
      echo "{\"event\":\"secret_in_env\",\"pid\":${pid},\
\"container\":\"${container_id}\",\"pattern\":\"${pattern%%=*}\"}"
    fi
  done
done
```

Ship this output to your SIEM. Any hit represents a secret that should be migrated to a secrets manager (Vault, AWS Secrets Manager, Kubernetes ExternalSecrets) and rotated.

### Correlating Credential Access with Subsequent Authentication

Individual credential access events have moderate signal. The highest-confidence detections come from correlating a credential access event with a successful authentication that follows it — the attack chain made visible.

A correlation rule in Elasticsearch SIEM (EQL):

```eql
/* Sequence: credential file read → successful authentication from
   same host within 30 minutes. This pattern indicates the attacker
   read a credential and immediately used it. */
sequence by host.name with maxspan=30m
  [file where event.action in ("open", "read") and
   file.path in ("/etc/shadow", "/root/.ssh/id_rsa",
                 "/home/*/.ssh/id_rsa", "/root/.aws/credentials") and
   process.name not in ("sshd", "sudo", "passwd")]
  [authentication where event.outcome == "success" and
   source.ip != "127.0.0.1"]
```

A hit on this sequence means: a process on this host read a credential file, and then a successful external login occurred within 30 minutes. The false positive rate is very low — schedule a 5-minute review SLA for all matches.

The same correlation logic applies across cloud layers:

1. CloudTrail event: `GetSecretValue` on a Secrets Manager secret (T1552.001)
2. Followed within 1 hour by: `AssumeRole` using a principal that has access to that secret's rotation target

This chain indicates an attacker exfiltrated a secret and then used it for privilege escalation.

## Operational Considerations

**Exclusion management is critical.** Every detection rule above will fire on legitimate tooling without exclusions: backup agents read `/etc/shadow`, orchestrators call `LIST secrets`, and security scanners trigger secret pattern matches. Maintain exclusions in version-controlled rule files, not in SIEM UI, and require a review + approval process before adding any exclusion. An exclusion for a legitimate tool is also an exclusion for an attacker impersonating that tool.

**Rotate on detection, not on confirmation.** The standard incident response practice of waiting to rotate credentials until an incident is confirmed causes unnecessary dwell time. When a credential access event fires — particularly a cloud credential access event — initiate rotation immediately and investigate in parallel. Modern secrets managers support automated rotation with zero-downtime switchover.

**Baseline before deploying alerts.** The brute force and stuffing rules will produce high false positive rates in environments where users have poor password hygiene or where services have misconfigured retry logic. Run all detection queries in observe-only mode for one week, review the top sources, add legitimate exclusions, then move to alerting. Deploying high-noise alerts without baselining leads to alert fatigue and eventual rule suppression.

**Enrich all events with asset context.** A ptrace event against `ssh-agent` means very different things on a developer workstation versus a production API server. Enrich every alert with the asset criticality tier, known software inventory, and recent change activity. This lets triage analysts dismiss the developer workstation and escalate the production server without manual lookup.

## Summary

Credential access detection requires instrumentation at four distinct layers: the Linux kernel (auditd, Falco/eBPF), the container runtime (Falco rules on secret mount reads), the Kubernetes API (audit policy covering secrets verbs), and the cloud control plane (CloudTrail, GCP Audit Logs). No single layer is sufficient — attackers who find one path blocked pivot to another.

The highest-value detections, in priority order:

1. **Ptrace attach to `ssh-agent` or `gpg-agent`** — almost no legitimate software does this in production; near-zero false positive rate.
2. **`/etc/shadow` read by a non-PAM process** — a direct indicator of offline cracking preparation.
3. **Kubernetes `LIST secrets` from an unexpected service account** — the most common post-compromise enumeration step in container environments.
4. **AssumeRole from a source IP not in the 90-day baseline** — the highest-confidence cloud credential theft indicator.
5. **Credential access event correlated with subsequent successful authentication** — confirms the credential was used, not just accessed.

Build these five detections first, validate them against your environment with one week of observe-only baselining, then layer in the brute force and stuffing rules once you have the exclusions tuned.
