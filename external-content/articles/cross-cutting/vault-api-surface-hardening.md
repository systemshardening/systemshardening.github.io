---
title: "HashiCorp Vault API Surface Hardening"
description: "Harden Vault's unauthenticated /sys/* endpoints against CVE-2026-5807-class denial-of-service, restrict the root token generation surface, and track HCSEC advisories before they reach your deployment."
slug: vault-api-surface-hardening
date: 2026-05-02
lastmod: 2026-05-02
category: cross-cutting
tags: ["vault", "hashicorp", "api-security", "cve-2026-5807", "hcsec-2026-08", "secrets-management", "dos"]
personas: ["security-engineer", "platform-engineer", "sre"]
article_number: 357
difficulty: advanced
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/cross-cutting/vault-api-surface-hardening/index.html"
---

# HashiCorp Vault API Surface Hardening

## Problem

HashiCorp Vault exposes its functionality through a unified HTTP API under the `/v1/` prefix. Within that API, the `/sys/` namespace is the system control plane: cluster management, seal and unseal operations, root token generation, unseal key rekey, HA status, and health checks. The vast majority of `/sys/` endpoints require authentication and a matching policy—a service account calling `/v1/sys/mounts` to list secret engines must present a valid token with appropriate permissions. However, several endpoints are intentionally unauthenticated to allow operators and load balancers to interact with a sealed or degraded Vault before any authentication material is available. The primary unauthenticated surface includes `/sys/health`, `/sys/seal-status`, `/sys/rekey`, `/sys/rekey-recovery-key`, and `/sys/generate-root`. This design is intentional: an operator who has lost all Vault tokens still needs to unseal Vault, generate a new root token, and rekey the unseal shards. Making those operations require authentication would create a circular dependency.

The consequence of this design is that unauthenticated endpoints exist on a network-accessible port by default (8200/tcp). In environments where Vault is reachable from a broad network segment—common in internal enterprise deployments where Vault serves many application teams—those endpoints are reachable by any host on that segment without presenting credentials. This is an accepted trade-off documented in Vault's architecture, but it becomes a material risk when a vulnerability affects one of those endpoints.

HCSEC-2026-08 (CVE-2026-5807, CVSS 7.5, published April 16, 2026) is exactly that scenario. Vault Community Edition ≤ 1.21.4 and Vault Enterprise ≤ 1.21.4 contain a denial-of-service vulnerability in the unauthenticated root token generation and rekey endpoints. Vault enforces a system-level constraint: only one root token generation operation and one rekey operation may be in progress at any time. This is a serialization lock—it prevents conflicting state from corrupting unseal key material or root token nonces. The vulnerability is that an unauthenticated caller can initiate a root token generation (`PUT /v1/sys/generate-root/attempt`) or rekey (`PUT /v1/sys/rekey/attempt`) and then immediately cancel it (`DELETE /v1/sys/generate-root/attempt`). This cycle can be repeated indefinitely. Each cycle occupies the single in-progress operation slot long enough to block any legitimate operator attempting the same operation. Because there is no rate limiting on these endpoints prior to the fix, the attacker can maintain a continuous lock with a trivial request rate. The same attack path applies to `/v1/sys/rekey-recovery-key`. The vulnerability was discovered by the XlabAI Team of Tencent Xuanwu Lab and independently by the Atuin Automated Vulnerability Discovery Engine, and was fixed in Vault 2.0.0 via rate limiting on the affected handler paths.

The operational impact is severe in proportion to its timing. Root token generation and rekey are rare operations—they are performed during emergencies: recovering from a lost root token, rotating unseal key shares after personnel changes, or responding to a suspected compromise of key material. These are exactly the moments when an adversary would want to interfere. A sophisticated attacker who has already achieved internal network access—via a phishing campaign, compromised build system, or lateral movement from a less-protected host—can trigger the DoS at the start of an incident response to prevent operators from generating a root token to revoke compromised service tokens, shut down compromised auth methods, or perform emergency rekey. The attack does not require persistence, privilege, or prior Vault access. It requires only network reachability to Vault's API port.

The advisory disclosure process for HashiCorp Vault follows the HCSEC prefix convention, with advisories published at `https://discuss.hashicorp.com/c/security` and `https://www.hashicorp.com/security` alongside patch releases. HashiCorp's process is more structured than most open source projects: advisories include CVSS scores, affected version ranges, and mitigation guidance. However, the Vault GitHub repository at `github.com/hashicorp/vault` is public, and the fix for HCSEC-2026-08 was committed to `main` before public advisory disclosure. Security researchers monitoring commits to `vault/core.go` and `builtin/logical/system/paths.go` would have seen the addition of rate-limiting logic to the rekey and generate-root handlers before HashiCorp's formal disclosure. Vault Enterprise advisories have historically lagged Community Edition advisories by one to five business days, creating a window where the Community Edition fix and its nature are publicly visible but Enterprise customers have not been formally notified—and Enterprise deployments are disproportionately represented in high-value targets.

**Target systems:** Vault Community Edition ≤ 1.21.4 and Vault Enterprise ≤ 1.21.4, patched in Vault 2.0.0. Both Vault integrated storage (Raft) and Consul storage backends are affected—the vulnerability is in the API handler layer, not the storage backend.

## Threat Model

1. **CVE-2026-5807 DoS via generate-root/rekey cycling.** An unauthenticated attacker on the network—or operating from an already-compromised internal host—sends repeated `PUT /v1/sys/generate-root/attempt` followed immediately by `DELETE /v1/sys/generate-root/attempt` at a rate of several cycles per second. Vault's serialization lock is held and released in each cycle, but the attacker maintains continuous occupancy faster than a human operator can complete the interactive root token generation ceremony. Legitimate operators are blocked from generating a new root token or rekeying unseal shards for the duration of the attack. The attack is stateless from the attacker's perspective: no Vault token required, no persistent connection, no prior reconnaissance beyond confirming Vault is reachable.

2. **Cluster state enumeration via unauthenticated `/sys/health` and `/sys/seal-status`.** Even without CVE-2026-5807, these endpoints return Vault version, initialization status, seal status, HA leader identity, and standby node count without authentication. A network-resident attacker performing reconnaissance before a broader campaign can map out which Vault cluster hosts are leaders versus standbys, which version is running (enabling targeted known-vulnerability enumeration), and whether Vault is currently sealed or unsealed. This information materially aids attack planning and requires zero credentials.

3. **Patch-gap attacker targeting self-managed deployments.** The HCSEC-2026-08 advisory was published April 16, 2026, alongside the Vault 2.0.0 release. An attacker who reads the advisory, examines the GitHub commit, and identifies the rate-limiting additions to the rekey and generate-root handlers can immediately target un-upgraded Vault clusters. Self-managed Vault deployments on a monthly or quarterly patching cadence have a one-to-four-week window during which they are running a version whose precise vulnerability is publicly documented with a working proof of concept trivially derivable from the advisory description. Enterprise customers may not receive formal notification until days after the Community Edition advisory, extending their patch-gap window further.

4. **Insider or compromised service account using `/v1/sys/raw`.** If `raw_storage_endpoint` is enabled in the Vault configuration (it is disabled by default but sometimes enabled for backup tooling or debugging), a caller with a policy granting access to `/sys/raw/*` can read raw storage entries from the backend, bypassing Vault's access control layer entirely. A database password stored in `secret/data/prod/db` is also accessible at `/v1/sys/raw/logical/<mount-uuid>/prod/db` to any caller with raw storage access. This endpoint should never be enabled in production; if it is, a compromised service account with a broad policy or a misconfigured wildcard ACL can exfiltrate all secrets without triggering the normal Vault audit log entries that would be generated by direct secret reads.

The blast radius of a successful CVE-2026-5807 exploitation during an active incident is bounded by time: the attacker cannot steal secrets or escalate privileges through this vulnerability alone. However, the attacker can prevent operators from executing the one recovery action (root token generation) that is prerequisite to all other emergency Vault operations. If the incident involves token compromise, the attacker's DoS buys time for compromised tokens to be used before they can be revoked. If combined with a simultaneous attempt to exhaust unseal shards (through compromising key custodians), the DoS creates a window where Vault cannot be recovered at all. For `/sys/raw` access, the blast radius is total secret exposure.

## Configuration / Implementation

### Upgrading Vault

The primary mitigation for CVE-2026-5807 is upgrading to Vault 2.0.0. Verify the current version first:

```bash
vault version
# Vault v1.21.4 (abc123def456...), built 2026-03-01
```

**Debian/Ubuntu package upgrade:**

```bash
sudo apt-get update
sudo apt-get install --only-upgrade vault=2.0.0
vault version
# Vault v2.0.0 (...)
```

**macOS (Homebrew):**

```bash
brew upgrade vault
vault version
```

**Kubernetes via Helm:**

```bash
helm repo update
helm upgrade vault hashicorp/vault \
  --version 0.30.0 \
  --reuse-values \
  --namespace vault

kubectl rollout status statefulset/vault -n vault
```

After upgrade, verify Vault is initialized and unsealed:

```bash
vault status
# Key             Value
# ---             -----
# Seal Type       shamir
# Initialized     true
# Sealed          false
# Version         2.0.0
```

For HA clusters, upgrade standbys before the active node. Vault supports rolling upgrades within a minor version series; verify compatibility before crossing major version boundaries.

### Network-Level Protection for Unauthenticated /sys/ Endpoints

Even after patching, placing Vault behind a reverse proxy that rate-limits and restricts access to rekey and generate-root endpoints adds defense-in-depth. This layer catches future vulnerabilities in the same class and limits enumeration via `/sys/health` to authorized sources.

**nginx reverse proxy with rate limiting:**

```nginx
# /etc/nginx/conf.d/vault.conf

# Rate limit zone: 1 request per minute per client IP for rekey/generate-root
limit_req_zone $binary_remote_addr zone=vault_rekey:10m rate=1r/m;

# Separate zone for general /sys/ health endpoints
limit_req_zone $binary_remote_addr zone=vault_sys:10m rate=30r/m;

upstream vault_backend {
    server 127.0.0.1:8200;
    keepalive 32;
}

server {
    listen 443 ssl;
    server_name vault.internal.example.com;

    ssl_certificate     /etc/ssl/vault/tls.crt;
    ssl_certificate_key /etc/ssl/vault/tls.key;
    ssl_protocols       TLSv1.3;

    # Block unauthenticated access to rekey and generate-root from external ranges
    # Allow only operator CIDR blocks
    location ~ ^/v1/sys/(rekey|rekey-recovery-key|generate-root) {
        allow 10.10.0.0/24;    # operator jump host subnet
        allow 10.10.1.0/24;    # secondary operator subnet
        deny  all;

        limit_req zone=vault_rekey burst=2 nodelay;
        limit_req_status 429;

        proxy_pass         https://vault_backend;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Real-IP         $remote_addr;
    }

    # Restrict /sys/raw entirely — should never be externally reachable
    location ~ ^/v1/sys/raw {
        deny all;
        return 403;
    }

    # Rate-limit health/seal-status to reduce enumeration
    location ~ ^/v1/sys/(health|seal-status) {
        limit_req zone=vault_sys burst=10 nodelay;
        proxy_pass https://vault_backend;
        proxy_set_header Host $host;
    }

    # All other Vault API traffic
    location / {
        proxy_pass https://vault_backend;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP         $remote_addr;
    }
}
```

**Kubernetes NetworkPolicy restricting Vault ingress:**

```yaml
# vault-network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vault-ingress-restriction
  namespace: vault
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: vault
  policyTypes:
    - Ingress
  ingress:
    # Allow Vault agents and application pods from approved namespaces
    - from:
        - namespaceSelector:
            matchLabels:
              vault-access: "true"
          podSelector:
            matchLabels:
              vault-client: "true"
      ports:
        - protocol: TCP
          port: 8200
    # Allow operator tooling from the ops namespace
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ops
      ports:
        - protocol: TCP
          port: 8200
    # Allow Vault cluster-internal traffic (Raft)
    - from:
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: vault
      ports:
        - protocol: TCP
          port: 8201
```

Apply and verify:

```bash
kubectl apply -f vault-network-policy.yaml
kubectl describe networkpolicy vault-ingress-restriction -n vault
```

### Disabling Unused /sys/ Endpoints

Several `/sys/` endpoints that are disabled by default should be explicitly confirmed disabled in your Vault HCL configuration.

```hcl
# /etc/vault.d/vault.hcl

ui = true

storage "raft" {
  path    = "/opt/vault/data"
  node_id = "vault-node-1"
}

listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/opt/vault/tls/tls.crt"
  tls_key_file  = "/opt/vault/tls/tls.key"
  tls_min_version = "tls13"
}

# Disable raw storage endpoint — NEVER enable in production
# Allows bypassing Vault ACLs by reading raw backend storage
raw_storage_endpoint = false

# Disable unauthenticated OpenAPI introspection endpoint
# Prevents endpoint enumeration by unauthenticated callers
introspection_endpoint = false

# Disable performance standby nodes from serving reads if not licensed
# (Enterprise only; prevents stale reads from degraded standbys)
# disable_performance_standby = true

api_addr     = "https://vault.internal.example.com:8200"
cluster_addr = "https://vault-node-1.internal.example.com:8201"
```

Reload Vault configuration after changes:

```bash
sudo systemctl restart vault
vault status
```

Verify `raw_storage_endpoint` is disabled by confirming the endpoint returns 404:

```bash
curl -sk -H "X-Vault-Token: $VAULT_TOKEN" \
  https://vault.internal.example.com:8200/v1/sys/raw/
# Expected: {"errors":["404 page not found"]}
```

### Vault Sentinel / EGP Policies (Enterprise)

For Vault Enterprise deployments, Endpoint Governing Policies (EGP) allow adding authentication and contextual requirements to specific API paths, including unauthenticated ones when combined with an allowlist approach.

The following Sentinel policy restricts rekey initiation to a defined maintenance window and requires the caller to originate from an approved IP range:

```python
# rekey-maintenance-window.sentinel
import "time"
import "sockaddr"

# Allow rekey only during defined maintenance windows (UTC)
maintenance_windows = [
  {"day": 6, "start_hour": 2, "end_hour": 4},   # Saturday 02:00-04:00 UTC
  {"day": 0, "start_hour": 2, "end_hour": 4},   # Sunday 02:00-04:00 UTC
]

# Approved operator source CIDRs
approved_cidrs = ["10.10.0.0/24", "10.10.1.0/24"]

now = time.now

in_window = any maintenance_windows as w {
  now.weekday == w.day and
  now.hour >= w.start_hour and
  now.hour < w.end_hour
}

source_approved = sockaddr.is_contained(request.connection.remote_addr, approved_cidrs)

main = rule {
  in_window and source_approved
}
```

Apply the EGP policy:

```bash
vault write sys/policies/egp/rekey-maintenance-window \
  policy="$(base64 rekey-maintenance-window.sentinel)" \
  paths="sys/rekey/*,sys/rekey-recovery-key/*" \
  enforcement_level="hard-mandatory"
```

### Root Token Generation Procedure Hardening

Root token generation should be treated as a break-glass operation with documented process controls:

```bash
# Step 1: Initiate root token generation with PGP key for nonce encryption
# The OTP is encrypted to the operator's PGP key — only the key holder can decrypt
vault operator generate-root -init \
  -pgp-key="keybase:operator-username"

# Output:
# Nonce         abc123...
# Started       true
# Progress      0/3
# Complete      false
# OTP Length    26

# Step 2: Each key custodian provides their unseal key share
vault operator generate-root \
  -nonce="abc123..."
# Enter unseal key: [key share]

# Step 3: Once quorum is reached, decode the encrypted root token
vault operator generate-root \
  -nonce="abc123..." \
  -decode="<encoded-token>" \
  -otp="<decrypted-otp>"

# Step 4: Use root token for emergency operation, then revoke immediately
export VAULT_TOKEN="<root-token>"
vault token revoke -self
```

Enforce root token generation as a jump-host-only operation by ensuring operator workstations cannot reach Vault's API directly. The NetworkPolicy above restricts reachability; additionally, document the break-glass procedure in a runbook stored outside Vault (since Vault may be inaccessible during the incident).

### Monitoring Vault for HCSEC Advisories

Subscribe to HashiCorp's security advisory feed and establish pre-merge monitoring of Vault's commit history:

```bash
# Monitor commits to Vault's core system paths for security-relevant changes
# Run before an advisory is published to detect incoming patches early
gh api repos/hashicorp/vault/commits \
  --jq '.[] | select(
    .commit.message | test(
      "rekey|generate.root|sys.*rate|unauthenticated|CVE|HCSEC|dos|denial";
      "i"
    )
  ) | {sha: .sha[0:8], msg: .commit.message, date: .commit.committer.date}'
```

Add to Renovate for automatic Vault Helm chart updates:

```json
{
  "packageRules": [
    {
      "matchPackageNames": ["hashicorp/vault"],
      "matchManagers": ["helmv3"],
      "automerge": false,
      "reviewers": ["team:security-team"],
      "labels": ["security", "vault"],
      "prPriority": 10
    }
  ]
}
```

**Prometheus alerting for DoS attempt detection:**

```yaml
# vault-alerts.yaml
groups:
  - name: vault_api_security
    rules:
      - alert: VaultGenerateRootAttemptSpike
        expr: |
          increase(vault_core_rekey_latency_count{path=~".*/generate-root/attempt"}[1m]) > 5
        for: 1m
        labels:
          severity: critical
          team: security
        annotations:
          summary: "Vault generate-root attempt spike — possible CVE-2026-5807 exploitation"
          description: >
            More than 5 generate-root attempts in 1 minute on {{ $labels.instance }}.
            This may indicate a DoS attempt against the root token generation endpoint.
            Check audit logs for source IP and initiate network block if confirmed.

      - alert: VaultSysRawAccess
        expr: |
          increase(vault_audit_log_request_count{path=~".*/sys/raw.*"}[5m]) > 0
        for: 0m
        labels:
          severity: critical
          team: security
        annotations:
          summary: "Vault /sys/raw endpoint accessed"
          description: >
            Access to the raw storage endpoint detected on {{ $labels.instance }}.
            This endpoint bypasses Vault ACLs. Investigate immediately.
```

### Monitoring the Attack in Audit Logs

Enable Vault's file audit backend if not already active:

```bash
vault audit enable file file_path=/var/log/vault/audit.log
```

Parse audit logs for generate-root activity from unexpected sources:

```bash
# Stream audit log and alert on generate-root from non-operator IPs
tail -f /var/log/vault/audit.log | jq -r '
  select(
    .request.path == "sys/generate-root/attempt" and
    .request.operation == "update"
  ) |
  [.time, .request.remote_address, .request.operation, .request.path] |
  @tsv
'
```

A healthy root token generation audit trail shows: one `update` entry initiating the attempt, multiple `update` entries for each unseal key share, one `update` entry completing the generation, and one `update` entry for the root token self-revocation. Repeated alternating `update` and `delete` entries for `sys/generate-root/attempt` without completion is the DoS pattern. Alert on more than five such cycles per minute from any single IP.

## Expected Behaviour

| Signal | Unpatched Vault (≤ 1.21.4) | Patched + Network Hardening (2.0.0) |
|--------|---------------------------|--------------------------------------|
| Attacker cycles generate-root initiate/cancel | Lock held continuously; legitimate operator generate-root blocked indefinitely | Rate limiter (built-in 2.0.0) rejects excess attempts with HTTP 429; nginx zone adds outer limit of 1r/m per IP; legitimate operator operation succeeds |
| Application service account calls `/v1/sys/raw` | If `raw_storage_endpoint = true` and policy allows, raw storage is readable — ACL bypass succeeds | `raw_storage_endpoint = false` in HCL; nginx blocks the path with HTTP 403; request never reaches Vault |
| Operator attempts generate-root during incident | Succeeds if no attacker holds the lock; fails silently if lock is held by DoS | nginx restricts generate-root to operator CIDR only; Sentinel EGP (Enterprise) enforces maintenance window; attacker from non-operator IP blocked at network layer |
| Self-managed cluster running ≤ 1.21.4 one week after advisory | Patch-gap window open; CVSS 7.5 vulnerability publicly documented with PoC derivable from advisory | Renovate/Dependabot opens PR for Vault Helm chart ≥ 0.30.0 within hours of release; gh monitoring script alerts on relevant commits before advisory publishes |
| Rekey attempt appears in audit log from unknown IP | Single audit log entry; no alerting without custom rules | Prometheus alert fires on generate-root spike; audit log parsed by streaming jq filter; SOC receives alert within 60 seconds |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| nginx rate limiting on rekey/generate-root | Blocks DoS from non-operator IPs; adds defense-in-depth against future endpoint vulnerabilities | Adds a network hop to all Vault API calls; nginx becomes a component that must be HA and maintained | Run nginx as a sidecar or dedicated HA pair; use Envoy with Vault-aware config if already in the stack; document nginx as a Vault dependency |
| `raw_storage_endpoint = false` | Eliminates ACL bypass via raw storage reads; removes a high-severity attack surface | Breaks backup tooling that uses Vault's raw API for snapshot/restore operations (e.g., some Consul-backend backup scripts) | Use `vault operator raft snapshot save` for Raft-backend backups; for Consul backends, use Consul's native snapshot API; remove the backup tooling dependency on raw storage before disabling |
| Sentinel EGP maintenance window policy | Adds time-based and IP-based controls to rekey/generate-root even after authentication; works at the Vault layer without network infrastructure changes | Enterprise license required; Sentinel policy errors are hard to debug; maintenance window policy blocks emergency rekey outside the window | Maintain a documented break-glass EGP override procedure; test EGP policies in staging; use `enforcement_level = "advisory"` initially to log violations before enforcing |
| Strict Kubernetes NetworkPolicy (namespace-selector) | Limits Vault API reachability to labeled namespaces; reduces blast radius if any pod is compromised | Blocks legitimate Vault Agent sidecars in unlabeled namespaces; requires namespace labeling discipline across all teams | Label namespaces at creation time via admission controller; use OPA/Gatekeeper to enforce `vault-access` label on any namespace running pods that mount Vault secrets |
| PGP-encrypted root token generation ceremony | OTP is encrypted to a specific key; prevents root token interception even if the ceremony channel is observed | Requires PGP key infrastructure and custodian coordination; slows emergency response | Pre-stage PGP public keys in a secure document store accessible without Vault; practice the ceremony quarterly in tabletop exercises |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| nginx rate limit blocks legitimate operator during incident | Operator receives HTTP 429 from `PUT /v1/sys/generate-root/attempt`; generate-root ceremony cannot start | Operator reports blocked request; nginx access log shows 429 with operator source IP in the restricted zone | Temporarily increase `rate=1r/m` to `rate=10r/m` in nginx config and reload (`nginx -s reload`); after incident, add operator's source IP to the allow-list and reduce rate back |
| Vault 2.0.0 upgrade changes `/sys/` endpoint path or response schema | Automation (backup scripts, health check monitors, Terraform providers) that calls specific `/sys/` paths returns unexpected errors; health check reports Vault unhealthy | Prometheus alert on increased 4xx rate on `/v1/sys/*`; CI pipeline failures in Vault-dependent jobs | Pin Terraform provider version; test against Vault 2.0.0 in staging before upgrading production; review Vault 2.0.0 changelog for API changes under `api/` and `command/` |
| Sentinel EGP blocks emergency root token generation outside maintenance window | Operator initiates generate-root during a Saturday-night incident; Vault returns `permission denied` from EGP before quorum is reached; incident response stalled | Vault audit log shows EGP deny for `sys/generate-root`; on-call engineer escalates; incident timeline shows Vault recovery blocked | Pre-document break-glass procedure: use `vault delete sys/policies/egp/rekey-maintenance-window` with a root token obtained via a secondary unsealed Vault or HSM-backed recovery; or set `enforcement_level = "advisory"` temporarily |
| Audit log file fills disk from sustained DoS attempt | Vault audit log partition at 100%; Vault may pause writes or crash depending on audit failure mode configuration | Disk usage alert on audit log partition; Vault logs show audit backend errors; `vault status` may show degraded | Rotate and compress audit log immediately; increase partition size; configure `vault audit enable file file_path=... log_raw=false` to reduce per-entry size; add log shipping to reduce local disk dependency; block attacker IP at firewall |

## Related Articles

- [HSM Key Management](/articles/cross-cutting/hsm-key-management/)
- [Secrets Rotation Orchestration](/articles/cross-cutting/secrets-rotation-orchestration/)
- [Production Access Management](/articles/cross-cutting/production-access-management/)
- [Kubernetes Secrets Management](/articles/kubernetes/secrets-management/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
