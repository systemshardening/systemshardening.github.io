---
title: "Secrets Rotation Orchestration: Coordinating Vault, KMS, OIDC, and Database Credentials"
description: "Rotation isn't just minting a new secret. It's a sequenced operation across producers, consumers, and stale-credential drains. Most outages happen during rotation."
slug: "secrets-rotation-orchestration"
date: 2026-04-27
lastmod: 2026-04-27
category: "cross-cutting"
tags: ["secrets-rotation", "vault", "kms", "operations", "production"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 195
difficulty: "advanced"
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/cross-cutting/secrets-rotation-orchestration/index.html"
---

# Secrets Rotation Orchestration: Coordinating Vault, KMS, OIDC, and Database Credentials

## Problem

Rotation is the operation that matters most for credential security and most likely to cause an outage. The naive model is "generate new credential, replace old credential, done." Production reality:

- **Multiple consumers.** A database password is consumed by a connection pool, an analytics warehouse, a backup tool, and a CI job. Each must pick up the new value at a coordinated moment.
- **Cached credentials.** Application processes hold credentials in memory; restart is the typical mechanism for picking up a new one. With 50 instances behind a load balancer, restart waves take time.
- **Stale-connection drain.** Open database connections authenticated with the old credential continue to work after rotation. Cut them off too soon and in-flight requests fail; cut them off too late and the security benefit of rotation is delayed.
- **Cross-system dependencies.** The TLS certificate on a service reaches its consumers via DNS or service mesh. A rotation that updates the cert but not the trust chain on consumers breaks every connection.
- **Dual-write windows.** During rotation, both old and new credentials must work — the producer accepts both, and consumers may use either. A rotation strategy that doesn't tolerate this window will fail at scale.
- **Failed rotations.** A rotation that partially completes leaves some consumers on the old credential and some on the new. Without a rollback path, recovery requires manual intervention at the worst possible time.
- **Audit gap.** Without per-rotation audit, "did rotation succeed?" becomes a guess based on absence of complaints.

This article covers the rotation patterns for the major secret types in production systems: database passwords, TLS certificates, OIDC trust roots, KMS-wrapped data keys, API tokens. The throughline is: every rotation is a sequenced state machine with explicit overlap windows, observability, and rollback paths.

**Target systems:** HashiCorp Vault 1.18+, AWS KMS / Secrets Manager, Google Cloud KMS / Secret Manager, Azure Key Vault, cert-manager 1.16+, External Secrets Operator 0.10+, sealed-secrets / SOPS, internal rotation orchestrators.

## Threat Model

- **Adversary 1 — Stolen credential:** an attacker has obtained a current credential (leaked, exfiltrated, social-engineered). Wants to use it before rotation revokes it.
- **Adversary 2 — Insider with access during rotation gap:** a departing employee or compromised admin who held a credential. Rotation is the bound on their access window.
- **Adversary 3 — Long-tail vulnerability with credential exposure:** a bug exposed credentials in logs / errors months ago. Until rotated, credentials remain exposed.
- **Adversary 4 — Compromise during rotation:** an attacker observes the rotation event itself and races to use the old credential before consumers move to the new one, or steals the new one in-flight.
- **Access level:** Adversary 1 has stolen credential. Adversary 2 has historic access. Adversary 3 has read access to past artifacts. Adversary 4 has on-network observation during the rotation event.
- **Objective:** Authenticate as the credential holder; perform privileged actions; maintain access despite a credential being "rotated."
- **Blast radius:** Determined by how long the old credential continues to be valid. A rotation that takes weeks to drain old connections is a weeks-long window for adversary 1. A correctly orchestrated rotation reduces this to minutes.

## Configuration

### Pattern 1: Database Password Rotation with Vault Dynamic Credentials

The cleanest pattern: don't rotate at all. Vault's dynamic secrets engine issues per-application short-lived credentials.

```bash
# Vault enables the database secrets engine.
vault secrets enable database

# Configure the connection.
vault write database/config/payments-db \
  plugin_name=postgresql-database-plugin \
  allowed_roles="payments-readonly,payments-readwrite" \
  connection_url="postgresql://{{username}}:{{password}}@payments-db.internal:5432/payments?sslmode=require" \
  username="vault" \
  password="$VAULT_DB_ADMIN_PASSWORD" \
  password_authentication=scram-sha-256

# Define a role with TTL.
vault write database/roles/payments-readwrite \
  db_name=payments-db \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
                       GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
  default_ttl="1h" \
  max_ttl="24h"
```

Application requests a credential at startup or before each use:

```python
# app boot.
import hvac
client = hvac.Client(url=VAULT_ADDR, token=app_vault_token())
creds = client.read('database/creds/payments-readwrite')
db_user = creds['data']['username']
db_pass = creds['data']['password']
# Connect with these. Lease auto-renews via background thread.
```

There is no "rotation" — credentials live for an hour, then disappear. A leaked credential expires within 1 hour. The static "vault" admin user is the only long-lived credential, which Vault itself can rotate (`vault write -force database/rotate-root/payments-db`).

### Pattern 2: Static Secret Rotation with Dual-Write

When dynamic credentials are not feasible (legacy app, fixed credential file), the rotation must explicitly support both old and new during a transition window.

The state machine:

```
[stable: cred_v1]
  -> [generate cred_v2]
  -> [database accepts both v1 and v2 (dual-credential window)]
  -> [propagate cred_v2 to all consumers]
  -> [verify all consumers using v2 (drain v1 connections)]
  -> [revoke v1 from database]
  -> [stable: cred_v2]
```

Implementation, using PostgreSQL as example:

```sql
-- Step 1: create cred_v2 alongside v1.
CREATE USER app_v2 WITH PASSWORD 'new-password' IN ROLE app_role;

-- Step 2: ensure both have the same grants.
-- (Alternatively, use ALTER USER to rotate password on the same user account,
--  with replication-style coordination on the cluster side.)

-- Step 3: propagate to consumers.
-- Update Vault / Secrets Manager. Consumers pull and reload.

-- Step 4: monitor.
-- pg_stat_activity.usename shows which user each connection authenticated as.
SELECT usename, count(*) FROM pg_stat_activity GROUP BY usename;
-- app_v1 | 5
-- app_v2 | 47

-- Step 5: when v1 connections == 0, revoke.
DROP USER app_v1;
```

Codify the state machine in an orchestration script:

```python
# rotate.py — orchestrator for one credential.
async def rotate(secret_id):
    state = await store.get_state(secret_id)
    if state == "stable":
        new_value = generate()
        await db.create_user(secret_id + "_v2", new_value)
        await store.transition(secret_id, "dual_credentials", new_value)
    elif state == "dual_credentials":
        await secrets_manager.publish(secret_id, new_value=store.get_new(secret_id))
        await consumer_orchestrator.reload(secret_id)
        await store.transition(secret_id, "propagating")
    elif state == "propagating":
        if await db.count_connections_using(secret_id + "_v1") == 0:
            await store.transition(secret_id, "revoking")
        else:
            await asyncio.sleep(30)
    elif state == "revoking":
        await db.drop_user(secret_id + "_v1")
        await store.transition(secret_id, "stable")
    log_audit_event(secret_id, state, store.get_state(secret_id))
```

Run as a state-driven controller; idempotent re-runs continue from where they were.

### Pattern 3: TLS Certificate Rotation with Trust-Chain Propagation

TLS rotation involves three artifacts: the leaf certificate, its private key, and the trust chain consumers verify against. cert-manager handles leaf rotation via ACME automatically; the gap is when the issuing CA itself rotates.

For an internal CA migration:

```yaml
# Phase 1: Issue an Issuer for the new CA alongside the old.
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: internal-ca-v2
spec:
  ca:
    secretName: internal-ca-v2-secret
---
# Phase 2: Pre-distribute the new CA cert to all clients.
# Trust bundles updated on every node, every Pod's Java truststore, every browser.

# Phase 3: New certificates issued by the new CA.
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: payments-api
spec:
  secretName: payments-api-tls
  issuerRef:
    name: internal-ca-v2  # was internal-ca-v1
    kind: ClusterIssuer
  dnsNames: [payments-api.payments.svc.cluster.local]

# Phase 4: After all certs renewed and old leaves expired, retire the old CA.
```

Critical: the order is **trust first, identity second**. Distribute the new CA to verifiers before any service presents a cert from it. The reverse order causes a cluster-wide TLS outage.

### Pattern 4: OIDC Trust-Root Rotation

OIDC providers rotate their JWKS keys. Consumers cache JWKS based on the `iss` and `kid` headers. Rotation flow:

```
[stable: jwks contains key_v1]
  -> [provider adds key_v2 to JWKS, signs with v1]
  -> [consumers refresh JWKS, now have v1 and v2 cached]
  -> [provider switches signing to v2]
  -> [consumers verify with v2 (lookup by kid succeeds)]
  -> [provider eventually removes v1 from JWKS]
  -> [stable: jwks contains key_v2]
```

Most providers handle this; verification is that consumers refresh JWKS frequently:

```python
# JWT verifier with periodic JWKS refresh.
class JwksCache:
    def __init__(self, jwks_url, refresh_interval=300):
        self.url = jwks_url
        self.cache = {}
        self.last_refresh = 0
        self.refresh_interval = refresh_interval

    def get_key(self, kid):
        if kid not in self.cache or time.time() - self.last_refresh > self.refresh_interval:
            self._refresh()
        return self.cache.get(kid)

    def _refresh(self):
        keys = requests.get(self.url).json()['keys']
        self.cache = {k['kid']: k for k in keys}
        self.last_refresh = time.time()
```

When a kid is unknown, force a refresh — that's how consumers discover newly-rotated keys without polling aggressively.

### Pattern 5: KMS Master-Key Rotation

Cloud KMS keys can rotate their backing material while keeping the same key ID. Existing ciphertexts continue to decrypt with old material; new ciphertexts use new material.

```bash
# AWS KMS automatic rotation.
aws kms enable-key-rotation --key-id alias/payments-data-key
aws kms get-key-rotation-status --key-id alias/payments-data-key
# {"KeyRotationEnabled": true}

# GCP KMS.
gcloud kms keys update payments-data-key \
  --location global --keyring my-ring \
  --rotation-period 90d \
  --next-rotation-time 2026-07-27T00:00:00Z
```

For envelope encryption, the master key rotates without touching the data keys. Re-encrypting individual data keys is a separate, optional operation if you need to fully invalidate access via the old master material:

```bash
# Re-wrap a data key with the latest master version.
aws kms re-encrypt \
  --ciphertext-blob fileb://encrypted-data-key.bin \
  --destination-key-id alias/payments-data-key
```

For long-lived encrypted data (multi-year retention), schedule periodic re-encryption to bound the master-key history that an attacker could leverage if they obtain old material.

### Pattern 6: Audit Logging for Rotations

Every rotation is an event with explicit start, intermediate states, and resolution. Log all of them.

```python
# Structured audit logger for rotation events.
import structlog
log = structlog.get_logger()

def audit_rotation(secret_id, state, actor, **kwargs):
    log.info(
        "rotation_event",
        secret_id=secret_id,
        state=state,
        actor=actor,
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        **kwargs,
    )
```

Forward to your SIEM. Alerts:

- Rotations stuck in `propagating` longer than 30 min — indicates consumer not picking up new credential.
- Rotations transitioning `revoking → stable` faster than expected — possibly a forced revoke without proper drain.
- Manual rotations outside the orchestrator (`actor=human`) on production secrets — human-initiated rotation should always go through the controller; direct intervention is incident territory.

## Expected Behaviour

| Signal | Without orchestration | With orchestration |
|--------|------------------------|----------------------|
| Time from generation to consumer pickup | Minutes to hours; depends on app reload | Seconds (Vault dynamic) or controlled by the controller |
| In-flight requests during rotation | May fail with auth errors | Continue with old credential until drained |
| Old credential lifetime after rotation | Unbounded if revocation skipped | Bounded by drain window + controller-set TTL |
| Rotation success verification | Manual / "did anyone complain?" | Audit log shows full state transition |
| Failed-rotation rollback | Manual intervention | Controller resumes from last-known good state |
| Cross-system rotations (database password + Vault + app config) | Often left out of sync | Controller coordinates; failure halts at safe state |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Vault dynamic credentials | No rotation needed; credentials self-expire | Application changes required to fetch from Vault | Bake into a shared library / sidecar; teams adopt over time. |
| Dual-credential windows | Zero-downtime rotation | More complex state machine; both creds active during transition | Make the window short (minutes), not hours. Monitor connection counts. |
| Trust-first / identity-second ordering | Safe rotation of TLS PKI | Operations team must follow the order rigorously | Encode in the orchestrator's state machine; refuse to issue new-CA-signed certs until trust distribution confirmed. |
| Per-rotation audit | Forensics; SLA evidence | Log volume increases | Acceptable; sampled compaction for high-volume secrets. |
| Controller-driven orchestration | Reproducible, idempotent | Engineering investment to build / adopt | Use existing tools where possible (Vault, External Secrets Operator); write custom only for app-specific edge cases. |
| KMS automatic rotation | Cheap; no application changes | Old material continues to be valid for existing ciphertexts | Periodic re-encrypt for long-retention data; for short-retention, automatic rotation is sufficient. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Consumer fails to reload after secret update | Authentication failures with new credential, success with old | App logs show auth errors; rotation orchestrator stuck in `propagating` | Force pod restart / app reload; investigate why the configured reload mechanism (SIGHUP, sidecar restart) failed. |
| Rotation revokes too early | In-flight requests fail | Monitoring alerts on auth-error rate | Restore old credential (the orchestrator should keep it until 0 connections drain). For some systems (immediate revoke), recovery requires generating a new credential and a fresh rotation. |
| TLS chain order reversed | Cluster-wide handshake failure after rotation | All clients show certificate-validation errors | Pre-distribute the new CA; if already broken, push the new CA via emergency channel (configmap update + restart). Run a full audit before rotating CAs again. |
| Vault sealed during rotation | New credentials cannot be issued | Rotation orchestrator times out at credential-generation step | Unseal Vault; restart rotation. The dual-credential window protects in-flight requests. |
| Refresh-token storm at JWT verifier | Mass auth failures during JWKS rotation | Spike in 401 errors at the auth-protected service | JWKS cache miss for the new kid; force refresh. If the issuer is slow to publish the new key, delay the signing-switch. |
| Rotation orchestrator buggy | Wrong credential propagated, rollback fails | Application errors after rotation | Manual recovery: identify the correct credential, push directly. Then debug the orchestrator. The audit log shows what was attempted. |
| KMS automatic rotation incompatible with hardware-backed keys | Rotation silently disabled for HSM-backed key | Audit shows no rotation events for the key | HSM-backed keys often require manual rotation via separate API. Schedule manual rotation with calendar reminders. |

## Related Articles

- [SPIFFE / SPIRE Workload Identity](/articles/cross-cutting/spiffe-spire-workload-identity/)
- [Post-Quantum Crypto Migration Plan](/articles/cross-cutting/post-quantum-migration/)
- [Secrets Management: Vault, KMS, and Kubernetes Secrets Compared](/articles/kubernetes/secrets-management/)
- [CI/CD Secret Management](/articles/cicd/cicd-secret-management/)
- [TLS 1.3 on NGINX and Envoy: Secure Defaults and Cipher Selection](/articles/network/tls-nginx-envoy/)
