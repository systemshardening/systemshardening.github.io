---
title: "External Secrets Operator: Pulling Secrets from KMS, Vault, and Cloud Stores into Kubernetes"
description: "Native Kubernetes Secrets are visible to anyone with namespace get. External Secrets Operator pulls from your real secret store on schedule, with rotation and audit."
slug: "external-secrets-operator"
date: 2026-04-29
lastmod: 2026-04-29
category: "kubernetes"
tags: ["external-secrets-operator", "vault", "kms", "secrets", "kubernetes"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 216
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/kubernetes/external-secrets-operator/index.html"
---

# External Secrets Operator: Pulling Secrets from KMS, Vault, and Cloud Stores into Kubernetes

## Problem

Native Kubernetes Secrets are convenient and dangerous. They're base64 strings sitting in etcd; anyone with `secrets:get` in a namespace reads them; they're not rotated; they're often committed to Helm charts (sealed or otherwise). Production secret management — credentials, API tokens, signing keys — needs a real secret store: Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, 1Password, Doppler.

The bridge has historically been hand-rolled: a sidecar that fetches secrets at startup, a CronJob that copies, a Helm pre-install hook. Each approach has problems — race conditions on rotation, no audit, no drift detection, divergence across environments.

External Secrets Operator (ESO, CNCF Sandbox 2022, Incubating 2024) is the canonical pattern: a controller that watches `ExternalSecret` CRDs, reads from configured stores, and writes / refreshes Kubernetes Secrets. By 2026 it's deployed in most production K8s environments that use a real secret store.

The operational properties:

- Secrets pulled from the source-of-truth store; the K8s Secret is a derivative.
- Refresh on schedule; rotation in the source store propagates to consumers within the refresh interval.
- Drift detection: if a K8s Secret is modified out-of-band, ESO restores it from the source.
- Multi-source: a single ExternalSecret can pull from Vault, AWS Secrets Manager, and a 1Password vault simultaneously, merging into one K8s Secret.
- Templating: secret values can be transformed (concatenated, encoded, JSON-extracted) before being written to the K8s Secret.

The specific gaps in non-ESO secret deployments:

- Hand-rolled fetchers don't propagate rotation events.
- Helm-templated secrets put the secret in plaintext in the values file.
- Sealed Secrets / SOPS commits encrypted secrets to git, but rotation requires re-encrypting and re-deploying.
- Secrets-Store CSI Driver works for mount-based access but not for env-var injection or "this app expects a Secret resource" patterns.
- Audit on the secret-store side is detached from K8s usage; cross-correlation manual.

This article covers ESO installation, ClusterSecretStore vs SecretStore scoping, refresh-policy patterns, multi-store templating, drift detection, and the audit story across stores.

**Target systems:** External Secrets Operator 0.10+, Kubernetes 1.28+; backends: HashiCorp Vault 1.16+, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, 1Password Connect, Doppler, Akeyless, custom.

## Threat Model

- **Adversary 1 — Compromised namespace admin:** has `secrets:get` in a namespace; wants to read more secrets than the namespace's workload should access.
- **Adversary 2 — Stolen secret-store credential:** an attacker has the ESO controller's credentials to the secret store; wants to mint or read secrets they shouldn't.
- **Adversary 3 — Drift attacker:** modifies a K8s Secret directly to inject a malicious value; expects ESO to overwrite it harmlessly later but uses the window.
- **Adversary 4 — Audit gap exploitation:** uses the time before audit logs are aggregated to act on stolen secrets without leaving easy traces.
- **Access level:** Adversary 1 has K8s namespace access. Adversary 2 has the controller's IAM/credentials. Adversary 3 has K8s Secret-write. Adversary 4 has any prior access.
- **Objective:** Read or modify secrets the namespace shouldn't have access to; pivot through secrets to upstream services.
- **Blast radius:** Without ESO + scoped credentials, a controller compromise often grants access to all secrets across all namespaces. With proper scoping, the ESO controller can read only what it needs to; namespace boundaries enforce on the K8s side.

## Configuration

### Step 1: Install ESO

```bash
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets \
  --namespace external-secrets-system \
  --create-namespace \
  --set installCRDs=true
```

ESO runs as a controller; the `external-secrets-system` namespace contains the controller pod plus its ServiceAccount.

### Step 2: Configure a ClusterSecretStore

A `ClusterSecretStore` defines how to authenticate to a backend.

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ClusterSecretStore
metadata:
  name: vault-prod
spec:
  provider:
    vault:
      server: "https://vault.internal.example.com:8200"
      path: "kv/data"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "external-secrets"
          serviceAccountRef:
            name: external-secrets
            namespace: external-secrets-system
```

ESO authenticates to Vault via Kubernetes ServiceAccount projection — Vault's Kubernetes auth method validates the SA token against the API server, returns a Vault token scoped to the configured role. No long-lived credential anywhere.

For AWS Secrets Manager:

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ClusterSecretStore
metadata:
  name: aws-secrets-prod
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-east-1
      auth:
        jwt:
          serviceAccountRef:
            name: external-secrets
            namespace: external-secrets-system
```

The ESO ServiceAccount is OIDC-federated to an IAM role (covered in [OIDC Federation Hardening](/articles/cicd/oidc-federation-hardening/)). Same pattern for GCP and Azure.

### Step 3: ExternalSecret Per Workload

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: payments-db-credentials
  namespace: payments
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-prod
    kind: ClusterSecretStore
  target:
    name: payments-db-credentials
    creationPolicy: Owner
  data:
    - secretKey: DB_USERNAME
      remoteRef:
        key: secret/payments/db
        property: username
    - secretKey: DB_PASSWORD
      remoteRef:
        key: secret/payments/db
        property: password
```

Every hour, ESO reads `secret/payments/db` from Vault, extracts the `username` and `password` properties, and writes them into the K8s Secret `payments-db-credentials`. Workloads consume the K8s Secret normally.

If the underlying value rotates in Vault (manual update or Vault dynamic-secret expiry), the K8s Secret refreshes within the refresh interval. Application restart picks up the new value (or the application can hot-reload).

### Step 4: Templating for Composite Secrets

Some applications need secrets in specific formats — a connection string, a JSON config, a JWT.

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: postgres-connection
  namespace: payments
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-prod
    kind: ClusterSecretStore
  target:
    name: postgres-connection
    template:
      type: Opaque
      data:
        DATABASE_URL: |
          postgresql://{{ .username }}:{{ .password }}@db-prod.internal:5432/payments?sslmode=require
        POSTGRES_PASSWORD: "{{ .password }}"
  data:
    - secretKey: username
      remoteRef:
        key: secret/payments/db
        property: username
    - secretKey: password
      remoteRef:
        key: secret/payments/db
        property: password
```

The `DATABASE_URL` Secret value is built from the source values; rotation regenerates the connection string.

### Step 5: Per-Namespace SecretStore for Isolation

A `ClusterSecretStore` is global; for tenant isolation, use namespace-scoped `SecretStore`:

```yaml
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: payments-secrets
  namespace: payments
spec:
  provider:
    vault:
      server: "https://vault.internal.example.com:8200"
      auth:
        kubernetes:
          role: "payments-namespace"   # Vault role allowing only payments paths
          serviceAccountRef:
            name: payments-eso
```

The Vault role `payments-namespace` allows reads only under `secret/payments/`. The payments namespace cannot construct ExternalSecrets that read `secret/auth/` or other sensitive paths. ServiceAccount lives in the namespace; only namespace admins can mint Vault tokens through it.

### Step 6: Drift Detection

ESO continuously reconciles. If someone modifies a K8s Secret out-of-band, ESO restores it.

```bash
# Manual override (don't do this in production).
kubectl edit secret payments-db-credentials -n payments

# Within ~30 seconds (or sooner), ESO restores from source.
kubectl get secret payments-db-credentials -n payments -o yaml
# (matches Vault content again)
```

For audit: a K8s admission policy can alert on Secret modifications that don't come from ESO:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: alert-on-direct-secret-edit
spec:
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        resources: ["secrets"]
        operations: ["UPDATE"]
  validations:
    - expression: >
        request.userInfo.username.startsWith("system:serviceaccount:external-secrets-system:")
      messageExpression: |
        "Secret was modified by " + request.userInfo.username +
        " (not external-secrets-operator). This may be intentional; alerting."
      reason: Forbidden
```

In `Audit` mode it logs the event without blocking; in `Deny` mode it blocks all manual edits.

### Step 7: Refresh Strategy

The `refreshInterval` is a trade-off between rotation latency and load on the source.

```yaml
spec:
  refreshInterval: 0      # never refresh after first creation (rare)
  refreshInterval: 1m     # poll every minute (high-rotation cases)
  refreshInterval: 1h     # default; reasonable for most static secrets
  refreshInterval: 24h    # for rare-rotation secrets where load matters
```

For Vault dynamic credentials with short TTLs, set `refreshInterval` shorter than the TTL. For static API keys, hourly is usually fine.

For event-driven refresh (no poll, refresh on demand), use `EventBus` (ESO 0.10+):

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: api-key
spec:
  refreshInterval: 24h         # fallback
  secretStoreRef:
    name: vault-prod
    kind: ClusterSecretStore
  target:
    name: api-key
    immediate: true
  data:
    - secretKey: key
      remoteRef:
        key: secret/payments/api-key
```

A separate webhook on the secret-store side notifies ESO of changes; ESO refreshes immediately rather than waiting for the next poll.

### Step 8: Telemetry

```
externalsecrets_sync_calls_total{name, namespace, status}
externalsecrets_sync_duration_seconds{store, status}
externalsecrets_secrets_total{store_provider}
externalsecrets_drift_detected_total{name}
externalsecrets_store_auth_failure_total{store}
```

Alert on:
- `externalsecrets_sync_calls_total{status="error"}` rising — backend connectivity issues or auth failures.
- `externalsecrets_drift_detected_total` non-zero — possibly an attacker manually editing secrets.
- `externalsecrets_store_auth_failure_total` rising — credential drift; investigate.

## Expected Behaviour

| Signal | K8s Secrets only | ESO + Vault |
|--------|-------------------|---------------|
| Secret source of truth | etcd | Vault |
| Rotation propagation | Manual; per-app | Within `refreshInterval` |
| Audit trail | K8s audit log only | K8s + Vault audit logs combined |
| Drift detection | None | ESO continuously reconciles |
| Cross-tenant isolation | RBAC | RBAC + secret-store role scoping |
| Sealed Secrets / SOPS | Encrypted in git; rotation per-deploy | None of that needed; secrets never in git |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| ClusterSecretStore vs SecretStore | Cluster-scoped centralizes auth | Tenant boundaries blurred | Use namespace-scoped SecretStore for tenant isolation; ClusterSecretStore for global infrastructure secrets. |
| OIDC-federated controller auth | No long-lived credential | Initial setup with each cloud provider | Standard pattern; documented per provider. |
| Refresh-driven rotation | No app-side rotation logic | App may need restart to pick up new value | Use sidecars / hot-reload mechanisms; for some apps, restart on Secret change is acceptable. |
| Templating | Composite secrets | Template logic to maintain | Keep templates simple; complex templates belong in app config. |
| Drift detection | Tampering catches | Some manual fixes look like attacks | Have a documented procedure for emergency manual edits; disable ESO for that secret temporarily. |
| Multi-backend support | Choose by environment | Inconsistent UX across backends | Standardize on one backend per organization where possible. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Vault sealed during refresh | ExternalSecrets stuck in error state | `externalsecrets_sync_calls_total{status="error"}` rises | Unseal Vault; ESO retries automatically. K8s Secrets remain at their last good value during the outage. |
| OIDC trust policy mismatch | Auth fails to backend | Controller logs show auth errors | Verify the trust policy on the cloud side matches the ESO ServiceAccount's projected JWT. |
| Refresh interval too long for rotation | Apps use stale credentials briefly | Application logs show auth errors after rotation | Shorten interval for high-rotation secrets; or use event-driven refresh. |
| Backend rate limit | Refresh storms cause throttling | Backend reports 429 / quota errors | Stagger refresh intervals across ExternalSecrets; coalesce duplicate reads. |
| Template error | Secret value malformed | Application crashes on parse | Test templates in staging; ESO's template-render in dry-run mode helps. |
| Direct Secret edit ignored by app | App still uses old value despite Secret update | App-internal cache | Restart pods on Secret change (use `stakater/Reloader` annotation), or implement hot-reload. |
| ServiceAccount removed | ESO cannot authenticate | Controller logs show repeated auth failures | Restore the ServiceAccount; if intentional removal, also remove the ExternalSecret. |

## Related Articles

- [Secrets Rotation Orchestration](/articles/cross-cutting/secrets-rotation-orchestration/)
- [Secrets Management: Vault, KMS, and Kubernetes Secrets Compared](/articles/kubernetes/secrets-management/)
- [SPIFFE / SPIRE Workload Identity](/articles/cross-cutting/spiffe-spire-workload-identity/)
- [OIDC Federation Hardening for CI-to-Cloud](/articles/cicd/oidc-federation-hardening/)
- [ValidatingAdmissionPolicy with CEL](/articles/kubernetes/validating-admission-policy-cel/)
