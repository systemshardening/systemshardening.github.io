---
title: "etcd Encryption at Rest: Configuration, Key Rotation, and Performance Impact"
description: "Kubernetes Secrets are stored in etcd as base64-encoded plaintext. Base64 is an encoding, not encryption."
slug: "etcd-encryption"
date: 2026-01-28
lastmod: 2026-01-28
category: "kubernetes"
tags: ["kubernetes", "etcd", "encryption", "secrets", "key-management"]
personas: ["platform-engineer", "sre"]
article_number: 22
difficulty: "intermediate"
estimated_reading_time: 18
provider_bridges:
  - name: "Civo"
    id: 22
    category: "managed-kubernetes"
  - name: "DigitalOcean"
    id: 21
    category: "managed-kubernetes"
  - name: "HashiCorp Vault"
    id: 65
    category: "secrets-management"
published: true
layout: article.njk
permalink: "/articles/kubernetes/etcd-encryption/index.html"
---

# etcd Encryption at Rest: Configuration, Key Rotation, and Performance Impact

## Problem

[Kubernetes](https://kubernetes.io) Secrets are stored in etcd as base64-encoded plaintext. Base64 is an encoding, not encryption. Anyone with direct access to the etcd data directory, an etcd backup, or the etcd API can read every secret in the cluster: database passwords, API keys, TLS certificates, and service account tokens.

This is not a theoretical risk. etcd backups are stored on disk or in object storage. If those backups are not encrypted at the storage level, every secret is exposed. If an attacker gains access to the control plane node filesystem, they can read etcd data files directly. If etcd is exposed without TLS client authentication (a common misconfiguration in self-managed clusters), secrets are accessible over the network.

The Kubernetes `EncryptionConfiguration` API solves this by encrypting secrets before they are written to etcd. But the implementation has real operational costs:

- **Key management is your responsibility.** You generate the encryption key, store it on the control plane node, and rotate it manually. If you lose the key, you lose access to all encrypted secrets.
- **Key rotation requires control plane coordination.** Rotating keys means updating the encryption config, restarting the API server, and re-encrypting all existing secrets. On multi-control-plane clusters, this must be coordinated across all nodes.
- **Performance impact is measurable.** Encryption adds 1-5% latency to secret read/write operations. For clusters with high secret churn (frequent deployments, many short-lived tokens), this is noticeable.
- **Managed providers handle this by default.** If you use a managed Kubernetes service, etcd encryption is typically enabled and managed for you. This article is primarily for self-managed clusters.

**Target systems:** Self-managed Kubernetes 1.29+ clusters (kubeadm, k3s, RKE2). Managed providers (EKS, GKE, AKS, Civo, DigitalOcean) handle etcd encryption automatically.

## Threat Model

- **Adversary:** Attacker with access to etcd data at rest: control plane node filesystem, etcd backups in object storage, or etcd snapshots on a compromised CI/CD system.
- **Access level:** File system read access to etcd data directory (`/var/lib/etcd/`) or access to etcd backup files.
- **Objective:** Read Kubernetes Secrets (database credentials, API keys, TLS private keys, OAuth tokens) from the stored etcd data.
- **Blast radius:** Without encryption at rest, all secrets in the cluster are exposed in plaintext. With encryption, the attacker gets ciphertext that is unusable without the encryption key. The key itself must be stored separately and protected.

## Configuration

### Step 1: Generate an Encryption Key

```bash
# Generate a 32-byte (256-bit) random key, base64-encoded
ENCRYPTION_KEY=$(head -c 32 /dev/urandom | base64)
echo "Generated key: $ENCRYPTION_KEY"

# Store the key securely (outside the cluster)
# This key is the master secret. If you lose it, encrypted data is unrecoverable.
```

### Step 2: Create the EncryptionConfiguration

```yaml
# /etc/kubernetes/encryption-config.yaml
# This file must exist on every control plane node.
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
      - configmaps  # Optional: encrypt configmaps too
    providers:
      # First provider is used for WRITING new data
      - aescbc:
          keys:
            - name: key-2026-04-22
              secret: <base64-encoded-32-byte-key>
      # Identity provider allows READING unencrypted data
      # (existing secrets written before encryption was enabled)
      - identity: {}
```

**Provider comparison:**

| Provider | Algorithm | Performance | Notes |
|----------|-----------|-------------|-------|
| `aescbc` | AES-256-CBC | ~2-3% latency increase | Simple, well-understood. Recommended for most clusters |
| `aesgcm` | AES-256-GCM | ~1-2% latency increase | Faster, provides authentication. Requires careful nonce management; must rotate keys frequently (every 200,000 writes) |
| `secretbox` | XSalsa20-Poly1305 | ~1-2% latency increase | Strong, modern. Good alternative to aescbc |
| `kms` v2 | Envelope encryption | ~1-3% latency (depends on KMS) | Key never leaves KMS (Vault, AWS KMS, GCP KMS). Best security. Requires KMS infrastructure |
| `identity` | None (plaintext) | No overhead | Default. No encryption. Must be listed last during migration |

### Step 3: Configure the API Server

**For kubeadm clusters:**

```yaml
# /etc/kubernetes/manifests/kube-apiserver.yaml
# Add the encryption-provider-config flag
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
    - name: kube-apiserver
      command:
        - kube-apiserver
        - --encryption-provider-config=/etc/kubernetes/encryption-config.yaml
        # ... other existing flags ...
      volumeMounts:
        - name: encryption-config
          mountPath: /etc/kubernetes/encryption-config.yaml
          readOnly: true
  volumes:
    - name: encryption-config
      hostPath:
        path: /etc/kubernetes/encryption-config.yaml
        type: File
```

```bash
# For kubeadm, edit the static pod manifest directly:
sudo vi /etc/kubernetes/manifests/kube-apiserver.yaml

# Add to the command section:
# --encryption-provider-config=/etc/kubernetes/encryption-config.yaml

# Add volume and volumeMount for the config file.
# The kubelet will automatically restart the API server.
```

**For k3s:**

```bash
# Create the encryption config
sudo mkdir -p /var/lib/rancher/k3s/server/
sudo cp encryption-config.yaml /var/lib/rancher/k3s/server/encryption-config.yaml

# Add to k3s server configuration
# /etc/rancher/k3s/config.yaml
# kube-apiserver-arg:
#   - "encryption-provider-config=/var/lib/rancher/k3s/server/encryption-config.yaml"

sudo systemctl restart k3s
```

### Step 4: Encrypt Existing Secrets

Enabling encryption only affects newly written secrets. Existing secrets remain unencrypted until they are re-written.

```bash
# Re-encrypt all secrets in the cluster:
kubectl get secrets --all-namespaces -o json | \
  kubectl replace -f -

# Verify the operation completed:
echo "Re-encrypted $(kubectl get secrets -A --no-headers | wc -l) secrets"
```

### Step 5: Verify Encryption Is Active

```bash
# Read a secret directly from etcd (requires etcd client access)
ETCDCTL_API=3 etcdctl \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/default/my-secret

# Expected output: binary/encrypted data prefixed with "k8s:enc:aescbc:v1:key-2026-04-22"
# If you see plain base64 JSON, encryption is NOT active.

# Quick verification script:
ETCDCTL_API=3 etcdctl \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/default/my-secret | \
  hexdump -C | head -5

# Encrypted: you will see binary data with "k8s:enc:aescbc" prefix
# NOT encrypted: you will see readable JSON with "apiVersion" and "data"
```

### Step 6: Key Rotation

Key rotation requires updating the encryption config, restarting the API server, and re-encrypting all secrets with the new key.

```bash
# 1. Generate a new key
NEW_KEY=$(head -c 32 /dev/urandom | base64)
```

```yaml
# 2. Update encryption-config.yaml
# Add the new key as the FIRST key (used for new writes)
# Keep the old key as the SECOND key (used to decrypt old data)
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key-2026-07-22  # New key (first = write key)
              secret: <new-base64-key>
            - name: key-2026-04-22  # Old key (decrypt only)
              secret: <old-base64-key>
      - identity: {}
```

```bash
# 3. Restart the API server on each control plane node
# For kubeadm: the kubelet watches the static pod manifest
sudo cp encryption-config.yaml /etc/kubernetes/encryption-config.yaml
# Wait for API server to restart (10-30 seconds)
kubectl get nodes  # Verify API server is responding

# 4. Re-encrypt all secrets with the new key
kubectl get secrets --all-namespaces -o json | kubectl replace -f -

# 5. After confirming all secrets are re-encrypted, remove the old key
# Update encryption-config.yaml to remove the old key
# Restart the API server again
```

**For multi-control-plane clusters:** Update the encryption config on ALL control plane nodes before re-encrypting secrets. If node A has the new key but node B does not, reads routed to node B will fail for secrets encrypted with the new key.

### Step 7: KMS Provider (Vault Integration)

For production clusters, use a KMS provider so the encryption key never exists on disk.

```yaml
# /etc/kubernetes/encryption-config.yaml (KMS v2)
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - kms:
          apiVersion: v2
          name: vault-kms
          endpoint: unix:///var/run/kms-plugin/kms.sock
          timeout: 3s
      - identity: {}
```

The KMS plugin runs as a sidecar or DaemonSet that communicates with Vault over a Unix socket. The API server sends data to the plugin for encryption/decryption; the plugin uses the Vault transit engine, and the actual encryption key never leaves Vault.

## Expected Behaviour

After enabling etcd encryption at rest:

- New secrets are encrypted before being written to etcd
- Existing secrets are encrypted after the re-encryption step
- `etcdctl get /registry/secrets/...` returns binary data with a `k8s:enc:aescbc` prefix
- `kubectl get secret` still works normally (the API server decrypts on read)
- Secret creation and retrieval latency increases by 1-5% (measurable, rarely noticeable)
- etcd backups contain encrypted secrets (unreadable without the encryption key)
- Key rotation completes without downtime (rolling API server restarts)

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| aescbc encryption | 2-3% latency increase on secret operations | Performance impact in high-churn clusters (thousands of secret operations per minute) | Use aesgcm or secretbox for lower latency. Benchmark with your workload before deploying |
| Manual key management | Encryption key stored on control plane node filesystem | Key compromise exposes all secrets. Key loss makes secrets unrecoverable | Use KMS provider (Vault, cloud KMS) so the key never exists on disk. Back up the key to a separate secure location |
| Key rotation requires API server restart | 10-30 seconds of API unavailability per control plane node | Disruption during key rotation (rolling restarts across control plane) | Schedule rotation during maintenance windows. Use multi-control-plane clusters so rolling restarts maintain availability |
| KMS provider dependency | External dependency (Vault, cloud KMS) for every secret operation | If KMS is unavailable, API server cannot read or write secrets | Run KMS provider with high availability. Configure appropriate timeouts. Monitor KMS latency and availability |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Encryption config missing on one control plane node | Secrets encrypted by other nodes cannot be decrypted; API returns errors for some reads | Intermittent "unable to decrypt" errors in API server logs; errors depend on which node handles the request | Copy the encryption config to all control plane nodes. Restart the API server on the affected node |
| Encryption key lost | All encrypted secrets are permanently unreadable | API server logs show "unable to decrypt" for all secret operations; no pods can mount secrets | Restore the key from backup. If no backup exists, recreate all secrets from external sources (password managers, Vault, CI/CD variables) |
| Old key removed before re-encryption completes | Secrets still encrypted with the old key cannot be decrypted | API server returns decryption errors for some (not all) secrets | Re-add the old key to the encryption config as a secondary key. Restart the API server. Complete the re-encryption step |
| KMS provider unavailable | API server cannot encrypt or decrypt secrets; all secret operations fail | API server logs show KMS timeout errors; pods in ContainerCreating state waiting for secrets | Restore KMS availability. The API server retries automatically. Consider a local cache/fallback in the KMS plugin |
| etcd backup restored without encryption key | Restored cluster has encrypted secrets but no key to decrypt them | All secret-dependent pods fail after restore; API server logs show decryption errors | Include the encryption config (with key) in your backup procedure. Store it separately from the etcd snapshot but ensure both are recoverable together |

## When to Consider a Managed Alternative

**Transition point:** Managing encryption keys for a self-managed Kubernetes cluster is a permanent operational responsibility. Key rotation must happen on a schedule (quarterly is typical). Key backup must be tested. Multi-control-plane coordination adds complexity to every rotation. If you are running Kubernetes primarily for application workloads (not as a platform product), the key management burden is pure overhead.

**Recommended providers:**

- **[Civo](https://www.civo.com) and [DigitalOcean](https://www.digitalocean.com):** Managed Kubernetes services that encrypt etcd at rest by default. You never see or manage the encryption key. Key rotation is handled automatically. This eliminates the entire operational burden described in this article.
- **HashiCorp [Vault](https://www.vaultproject.io):** If you must run self-managed Kubernetes, use Vault as a KMS provider. The encryption key never exists on the control plane node filesystem. Vault handles key rotation, access logging, and key lifecycle management. The operational burden shifts from "manage a key file on disk" to "manage Vault," which you likely already do for application secrets.

**What you still control:** The decision of which resources to encrypt (secrets only, or configmaps too), the rotation schedule, and the KMS provider selection. Managed providers make the encryption invisible, which is the correct answer for most teams.

**Premium content pack:** [Ansible](https://www.ansible.com) playbook for automated etcd encryption setup on kubeadm clusters, including key generation, config distribution to all control plane nodes, API server restart coordination, and verification. Includes a CronJob-based key rotation automation with Slack notification.


## Related Articles

- [Kubernetes Secrets Management: External Secrets Operator, Vault, and Sealed Secrets](/articles/kubernetes/secrets-management/)
- [Kubernetes Node Hardening: From OS Configuration to kubelet Lockdown](/articles/kubernetes/node-hardening/)
- [Multi-Tenancy Hardening in Kubernetes: Namespace Isolation, Resource Quotas, and Network Boundaries](/articles/kubernetes/multi-tenancy-hardening/)
- [Hardening the Kubernetes Scheduler: Topology Constraints and Security-Aware Placement](/articles/kubernetes/scheduler-hardening/)
- [AI API Key Management: Rotation, Scoping, and Abuse Detection](/articles/kubernetes/ai-api-key-management/)
