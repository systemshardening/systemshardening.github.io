---
title: "Kubernetes Secrets Management: External Secrets Operator, Vault, and Sealed Secrets"
description: "Kubernetes Secrets are base64-encoded, not encrypted. Anyone with RBAC read access to secrets in a namespace can decode every credential stored there."
slug: "secrets-management"
date: 2026-03-21
lastmod: 2026-03-21
category: "kubernetes"
tags: ["kubernetes", "secrets", "vault", "external-secrets", "sealed-secrets", "gitops"]
personas: ["platform-engineer", "devops-engineer"]
article_number: 28
difficulty: "intermediate"
estimated_reading_time: 20
provider_bridges:
  - name: "HashiCorp Vault"
    id: 65
    category: "secrets-management"
  - name: "Infisical"
    id: 67
    category: "secrets-management"
  - name: "Doppler"
    id: 68
    category: "secrets-management"
  - name: "Akeyless"
    id: 66
    category: "secrets-management"
published: true
layout: article.njk
permalink: "/articles/kubernetes/secrets-management/index.html"
---

# [Kubernetes](https://kubernetes.io) Secrets Management: External Secrets Operator, Vault, and Sealed Secrets

## Problem

Kubernetes Secrets are base64-encoded, not encrypted. Running `kubectl get secret my-secret -o jsonpath='{.data.password}' | base64 -d` prints the plaintext value. Anyone with RBAC read access to secrets in a namespace can decode every credential stored there. Combined with etcd encryption at rest (covered in article #22), the data on disk may be protected, but the API-level exposure remains.

This creates three operational problems:

- **GitOps workflows cannot store secrets in Git.** If you manage cluster state with [Flux](https://fluxcd.io) or [ArgoCD](https://argo-cd.readthedocs.io), every resource lives in a Git repository. Committing a Kubernetes Secret means committing plaintext credentials (base64 is not encryption). Teams either exclude secrets from GitOps entirely (creating manual drift) or need a mechanism to encrypt secrets before they reach the repository.
- **No centralized lifecycle management.** Native secrets have no expiry, no automatic rotation, and no audit trail beyond Kubernetes API audit logs. When a database password rotates, someone must update the secret manually or build custom automation.
- **The secrets landscape is fragmented.** Teams must choose between Sealed Secrets, External Secrets Operator, CSI Secret Store Driver, direct Vault injection, and native secrets. Each has different security models, operational costs, and GitOps compatibility. Choosing wrong means a painful migration later.

This article covers the limitations of native secrets, three production-ready alternatives (Sealed Secrets, External Secrets Operator, CSI Secret Store Driver), and migration paths between them.

**Target systems:** Kubernetes 1.29+ with any CNI. All tools covered are CNCF projects or widely adopted open source.

## Threat Model

- **Adversary:** Attacker with access to the Git repository containing cluster manifests, or an insider with limited Kubernetes RBAC permissions.
- **Access level:** Read access to a Git repository (for secrets committed in plaintext or base64), or RBAC `get`/`list` permissions on secrets in one or more namespaces.
- **Objective:** Harvest credentials (database passwords, API keys, TLS private keys) from stored manifests or the Kubernetes API, then use them to pivot to external systems.
- **Blast radius:** Without external secrets management, a single repository compromise or over-permissioned ServiceAccount exposes every secret stored in Git or accessible via RBAC. With external management, the attacker gets encrypted blobs (Sealed Secrets) or must compromise the external provider (Vault, cloud KMS) to access plaintext values.

## Configuration

### Step 1: Understand Native Secrets Limitations

Native Kubernetes Secrets work out of the box but have no encryption at the API layer:

```yaml
# native-secret.yaml
# WARNING: base64 is encoding, not encryption
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
  namespace: production
type: Opaque
data:
  username: cG9zdGdyZXM=       # "postgres"
  password: czNjcjN0LXZhbHVl   # "s3cr3t-value"
```

```bash
# Anyone with secret read RBAC can decode this:
kubectl get secret db-credentials -n production \
  -o jsonpath='{.data.password}' | base64 -d
# Output: s3cr3t-value
```

This is the baseline. Every approach below replaces or wraps this mechanism.

### Step 2: Sealed Secrets for GitOps

Sealed Secrets uses asymmetric encryption. You encrypt secrets client-side with `kubeseal`, commit the encrypted `SealedSecret` resource to Git, and the controller in-cluster decrypts it into a native Secret.

```bash
# Install the Sealed Secrets controller
helm repo add sealed-secrets https://bitnami-labs.github.io/sealed-secrets
helm install sealed-secrets sealed-secrets/sealed-secrets \
  --namespace kube-system \
  --set fullnameOverride=sealed-secrets-controller
```

```bash
# Install kubeseal CLI
KUBESEAL_VERSION=0.27.3
curl -fsSL "https://github.com/bitnami-labs/sealed-secrets/releases/download/v${KUBESEAL_VERSION}/kubeseal-${KUBESEAL_VERSION}-linux-amd64.tar.gz" | \
  tar xz -C /usr/local/bin kubeseal
```

Create and encrypt a secret:

```bash
# Create a normal secret manifest (do not apply it)
kubectl create secret generic db-credentials \
  --namespace production \
  --from-literal=username=postgres \
  --from-literal=password=s3cr3t-value \
  --dry-run=client -o yaml > secret.yaml

# Encrypt it with kubeseal
kubeseal --format yaml < secret.yaml > sealed-secret.yaml

# Delete the plaintext file
rm secret.yaml
```

```yaml
# sealed-secret.yaml (safe to commit to Git)
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: db-credentials
  namespace: production
spec:
  encryptedData:
    username: AgBy3i4OJSWK+PiTySYZZA9rO...  # RSA-encrypted
    password: AgCtrMHFBpLvSZ2X9rK7PQNM...
  template:
    metadata:
      name: db-credentials
      namespace: production
    type: Opaque
```

```bash
# Apply the sealed secret (controller decrypts it in-cluster)
kubectl apply -f sealed-secret.yaml

# Verify the native secret was created
kubectl get secret db-credentials -n production
```

### Step 3: External Secrets Operator with Vault Backend

External Secrets Operator (ESO) syncs secrets from external providers (Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault) into Kubernetes Secrets. The source of truth lives outside the cluster.

```bash
# Install External Secrets Operator
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets \
  --namespace external-secrets \
  --create-namespace \
  --set installCRDs=true
```

Configure the Vault connection:

```yaml
# vault-secret-store.yaml
apiVersion: external-secrets.io/v1beta1
kind: ClusterSecretStore
metadata:
  name: vault-backend
spec:
  provider:
    vault:
      server: "https://vault.internal.example.com:8200"
      path: "secret"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "external-secrets"
          serviceAccountRef:
            name: "external-secrets"
            namespace: "external-secrets"
```

Create an ExternalSecret that syncs from Vault:

```yaml
# external-secret-db.yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-credentials
  namespace: production
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: db-credentials
    creationPolicy: Owner
  data:
    - secretKey: username
      remoteRef:
        key: production/database
        property: username
    - secretKey: password
      remoteRef:
        key: production/database
        property: password
```

```bash
kubectl apply -f vault-secret-store.yaml
kubectl apply -f external-secret-db.yaml

# Check sync status
kubectl get externalsecret db-credentials -n production
# STATUS should show "SecretSynced"
```

For AWS Secrets Manager instead of Vault:

```yaml
# aws-secret-store.yaml
apiVersion: external-secrets.io/v1beta1
kind: ClusterSecretStore
metadata:
  name: aws-backend
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-east-1
      auth:
        jwt:
          serviceAccountRef:
            name: "external-secrets"
            namespace: "external-secrets"
```

### Step 4: CSI Secret Store Driver

The CSI Secret Store Driver mounts secrets as files in pods, bypassing Kubernetes Secrets entirely. The secret never exists as a Kubernetes Secret object (unless you explicitly enable sync).

```bash
# Install the CSI driver
helm repo add secrets-store-csi-driver \
  https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts
helm install csi-secrets-store secrets-store-csi-driver/secrets-store-csi-driver \
  --namespace kube-system \
  --set syncSecret.enabled=true
```

```yaml
# vault-provider-class.yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: vault-db-creds
  namespace: production
spec:
  provider: vault
  parameters:
    vaultAddress: "https://vault.internal.example.com:8200"
    roleName: "production-app"
    objects: |
      - objectName: "db-username"
        secretPath: "secret/data/production/database"
        secretKey: "username"
      - objectName: "db-password"
        secretPath: "secret/data/production/database"
        secretKey: "password"
  secretObjects:
    - secretName: db-credentials
      type: Opaque
      data:
        - objectName: db-username
          key: username
        - objectName: db-password
          key: password
```

```yaml
# pod-with-csi-secrets.yaml
apiVersion: v1
kind: Pod
metadata:
  name: web-app
  namespace: production
spec:
  serviceAccountName: web-app
  containers:
    - name: app
      image: registry.example.com/web-app:2.1.0
      volumeMounts:
        - name: secrets
          mountPath: "/mnt/secrets"
          readOnly: true
      env:
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: password
  volumes:
    - name: secrets
      csi:
        driver: secrets-store.csi.k8s.io
        readOnly: true
        volumeAttributes:
          secretProviderClass: "vault-db-creds"
```

### Step 5: Comparison and Migration Paths

| Approach | Security Model | GitOps Safe | Auto-Rotation | Operational Complexity |
|----------|---------------|-------------|---------------|----------------------|
| Native Secrets | Base64, RBAC only | No | No | Minimal |
| Sealed Secrets | RSA asymmetric encryption | Yes | No (re-seal required) | Low |
| ESO + Vault | External provider, sync on interval | Yes (ExternalSecret CRD in Git) | Yes (refreshInterval) | Medium |
| CSI Driver | Direct mount, no K8s Secret (optional sync) | Partial (SecretProviderClass in Git) | Yes (rotation poll) | Medium-High |

**Migration from native secrets to ESO:**

```bash
# 1. Create the secret in Vault
vault kv put secret/production/database \
  username=postgres password=s3cr3t-value

# 2. Deploy the ExternalSecret (it creates the same-named K8s secret)
kubectl apply -f external-secret-db.yaml

# 3. Verify the synced secret matches the original
kubectl get secret db-credentials -n production -o yaml

# 4. Remove the old native secret manifest from Git
# The ESO-managed secret replaces it with the same name
```

**Migration from Sealed Secrets to ESO:**

```bash
# 1. Store current secret values in Vault
kubectl get secret db-credentials -n production \
  -o jsonpath='{.data.password}' | base64 -d | \
  vault kv put secret/production/database password=-

# 2. Deploy the ExternalSecret targeting the same secret name
# 3. Delete the SealedSecret resource
kubectl delete sealedsecret db-credentials -n production
# The ESO-created secret remains
```

## Expected Behaviour

After implementing external secrets management:

- Plaintext credentials never appear in Git repositories
- Sealed Secrets: `kubeseal` encrypts locally, the controller decrypts in-cluster, and the SealedSecret YAML is safe to commit
- ESO: secrets sync from the external provider on the configured `refreshInterval` (default 1h), and the ExternalSecret status shows `SecretSynced`
- CSI Driver: secrets are mounted as files at pod startup, and rotation happens without pod restart when the driver polls for changes
- Kubernetes RBAC still controls which pods and users can read the resulting native secrets
- Secret rotation in the external provider automatically propagates to the cluster (ESO and CSI only)

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Sealed Secrets controller | Single point of failure for secret decryption; controller private key is the master secret | If the controller key is lost, all SealedSecrets become undecryptable | Back up the controller key. Use `kubeseal --recovery-unseal` to export the key. Store the backup in a separate secure location |
| ESO with Vault | External dependency for every secret sync; Vault downtime prevents secret updates | If Vault is unreachable, new ExternalSecrets cannot sync. Existing secrets remain until TTL expires | Run Vault in HA mode. Set reasonable refreshInterval (1h, not 30s). Existing K8s secrets persist even during Vault outages |
| CSI Secret Store Driver | Pods fail to start if the provider is unavailable; no secret object exists without sync enabled | Pod scheduling depends on external provider availability at startup time | Enable syncSecret to create a K8s Secret as fallback. Monitor provider health |
| Multiple approaches in one cluster | Operational confusion; team must know which approach manages which secret | Misconfiguration leads to stale secrets or duplicate secrets with different values | Standardize on one approach per cluster. Document the chosen approach. Use labels to identify secret management method |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Sealed Secrets controller key lost | New SealedSecrets cannot be decrypted; existing native secrets still work until pods restart | Controller logs show decryption errors; new SealedSecret resources do not produce native secrets | Restore the controller key from backup. If no backup exists, recreate all secrets from source and re-seal them with the new controller key |
| Vault unreachable during ESO sync | ExternalSecret status shows `SecretSyncedError`; existing secrets retain their last-synced values | Monitor ExternalSecret `.status.conditions`; alert on `SecretSyncedError` | Restore Vault connectivity. ESO retries automatically on the next refresh interval. No data loss for existing secrets |
| CSI provider unavailable at pod startup | Pods stuck in `ContainerCreating` with events showing `mount failed: secrets-store.csi.k8s.io` | Pod events and kubelet logs show CSI mount failures | Restore provider availability. Pods retry mounting automatically. Enable syncSecret as a fallback so pods can use the K8s secret object instead |
| ESO refreshInterval too long | Secret rotated in Vault but pods still use the old value for up to the refresh interval | Application authentication failures after a credential rotation in the external provider | Reduce refreshInterval for critical secrets. Use `kubectl annotate externalsecret db-credentials force-sync=$(date +%s)` to trigger immediate sync |
| SealedSecret scope mismatch | SealedSecret encrypted for namespace A cannot be decrypted in namespace B; controller silently ignores it | No native secret is created; controller logs show scope validation failure | Re-seal the secret with the correct namespace and name. Use `--scope cluster-wide` if the secret must work across namespaces |

## When to Consider a Managed Alternative

**Transition point:** Running Vault in production is itself a significant operational commitment: storage backend management, unsealing, HA configuration, audit log management, and access policy maintenance. If your primary goal is "do not store secrets in Git" and you do not already operate Vault, the overhead of deploying Vault to manage Kubernetes secrets may exceed the security benefit.

**Recommended providers:**

- **HashiCorp [Vault](https://www.vaultproject.io):** The standard choice if you already run Vault or need cross-platform secrets management (Kubernetes, VMs, CI/CD, databases). HCP Vault Dedicated removes the operational burden of running Vault yourself while keeping the same API.
- **[Infisical](https://infisical.com):** Developer-focused secrets management with native Kubernetes operator support. Lower operational complexity than Vault for teams that only need secrets sync, not full PKI or dynamic credentials.
- **[Doppler](https://www.doppler.com):** SaaS secrets manager with a Kubernetes operator. Good fit for teams that want zero infrastructure management and are comfortable with a hosted solution.
- **[Akeyless](https://www.akeyless.io):** Vaultless secrets management with a distributed key architecture. Offers a Kubernetes integration and eliminates the need to manage encryption keys locally.

**What you still control:** The choice of which secrets require external management versus native secrets (low-sensitivity configuration values may not warrant the complexity). The sync interval and rotation policy. The RBAC rules that control which pods and users can read the resulting Kubernetes secrets.

**Premium content pack:** [Terraform](https://www.terraform.io) module for deploying External Secrets Operator with Vault backend, including Vault policy configuration, Kubernetes auth method setup, and ExternalSecret templates for common credential types (database, API key, TLS certificate).


## Related Articles

- [AI API Key Management: Rotation, Scoping, and Abuse Detection](/articles/kubernetes/ai-api-key-management/)
- [etcd Encryption at Rest: Configuration, Key Rotation, and Performance Impact](/articles/kubernetes/etcd-encryption/)
- [Kubernetes Network Policies That Actually Work: From Default Deny to Microsegmentation](/articles/kubernetes/kubernetes-network-policies/)
- [Seccomp Profiles for Production Workloads: Writing, Testing, and Deploying Custom Profiles](/articles/kubernetes/seccomp-profiles/)
- [Kubernetes Admission Control: From PodSecurity Standards to Custom OPA/Kyverno Policies](/articles/kubernetes/kubernetes-admission-control/)
