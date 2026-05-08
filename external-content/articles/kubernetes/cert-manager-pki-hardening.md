---
title: "cert-manager PKI Hardening: Intermediate CAs, Short-Lived Certificates, and Trust Chain Design"
description: "cert-manager manages certificate lifecycle at scale, but its default configuration creates long-lived certs and flat trust hierarchies. Harden the PKI layer your services depend on."
slug: "cert-manager-pki-hardening"
date: 2026-04-29
lastmod: 2026-04-29
category: "kubernetes"
tags: ["cert-manager", "pki", "tls", "certificates", "kubernetes"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 232
difficulty: "advanced"
estimated_reading_time: 15
published: true
layout: article.njk
permalink: "/articles/kubernetes/cert-manager-pki-hardening/index.html"
---

# cert-manager PKI Hardening: Intermediate CAs, Short-Lived Certificates, and Trust Chain Design

## Problem

cert-manager automates certificate issuance and renewal in Kubernetes. It solves the operational problem of TLS certificates expiring unnoticed and rotations requiring manual intervention. But a default cert-manager installation creates a permissive PKI posture:

- Certificates with 90-day validity (Let's Encrypt default) or 1-year validity (self-signed defaults).
- ClusterIssuers that any namespace can use to issue certificates for any DNS name.
- Root CAs stored directly as Kubernetes Secrets, accessible to cluster-admin and anyone who can read that namespace.
- No certificate policy enforcement — a developer can request a cert for `api.example.com` with a 10-year validity and `isCA: true`.
- Flat trust hierarchy: one root CA signs everything, so a compromised intermediate compromises every service's cert.

By 2026, cert sprawl is a first-tier attack surface. The 2024 SolarWinds post-incident analysis identified long-lived internal certificates as a lateral movement enabler: an attacker who extracted a cert valid for 1 year had 11 months of authenticated access before detection. Short-lived certificates (24–48 hours) bound the blast radius of credential exfiltration.

The specific gaps:

- No intermediate CA layer — root CA used directly for leaf certificate issuance.
- ClusterIssuers with no namespace or domain restrictions.
- Certificate validity periods not enforced by policy.
- No `isCA: false` enforcement — services can self-issue sub-CAs.
- Private keys for issued certificates accessible to service account tokens in the same namespace.
- No alerting on certificates approaching expiry or with anomalous properties.

This article covers hierarchical CA design in cert-manager, enforcing short certificate lifetimes via policy, isolating issuer access by namespace, storing root CAs in HSM or Vault rather than Kubernetes Secrets, and monitoring the certificate estate.

**Target systems:** cert-manager v1.14+, Kubernetes 1.29+, Vault 1.16+ (for Vault PKI integration), trust-manager v0.9+ (for trust bundle distribution).

## Threat Model

- **Adversary 1 — Certificate extraction for lateral movement:** An attacker compromising a service pod reads the TLS private key from the mounted Secret. With a 1-year certificate, they have long-term authenticated access to internal services.
- **Adversary 2 — Unauthorized certificate issuance:** A developer with Kubernetes RBAC access to a namespace-scoped issuer requests a certificate for `*.internal.example.com` to intercept internal traffic.
- **Adversary 3 — Root CA exfiltration:** A privileged attacker reads the root CA private key from the Kubernetes Secret where cert-manager stores it. They sign arbitrary certificates that all services trust.
- **Adversary 4 — CA chain confusion:** A pod issues itself an intermediate CA certificate (by setting `isCA: true`), then issues certificates that other services trust as part of the trusted chain.
- **Access level:** Adversary 1 has pod-level execution. Adversary 2 has Kubernetes API access with namespace-level permissions. Adversary 3 has cluster-admin or namespace-admin in the cert-manager namespace. Adversary 4 has Kubernetes API with Certificate resource create permissions.
- **Objective:** Establish trusted TLS credentials for impersonation, extract private keys for persistent access, or become a trusted CA.
- **Blast radius:** Long-lived certificates with no policy enforcement: one extraction = long-term access. Short-lived certs + intermediate CA isolation: extraction expires within 24–48 hours; intermediate CA compromise affects only that domain subtree.

## Configuration

### Step 1: Hierarchical CA Design

Never issue leaf certificates directly from the root CA. Design a three-tier hierarchy:

```
Root CA (offline, HSM or Vault PKI)
├── Intermediate CA: services.internal (online, 1-year validity)
│   ├── Leaf: payments.services.internal (24h validity)
│   ├── Leaf: auth.services.internal (24h validity)
│   └── Leaf: api.services.internal (24h validity)
├── Intermediate CA: ingress.external (online, 90-day validity)
│   ├── Leaf: *.example.com (60-day via Let's Encrypt)
│   └── Leaf: api.example.com (60-day via Let's Encrypt)
└── Intermediate CA: mutual-tls.internal (online, 1-year validity)
    └── Leaf certs for service-to-service mTLS (24h validity)
```

Each intermediate CA signs only certificates in its domain. Compromise of `services.internal` intermediate doesn't affect `ingress.external` certificates.

### Step 2: Root CA in Vault PKI

Store the root CA in Vault instead of a Kubernetes Secret. cert-manager's Vault issuer signs intermediate CAs using Vault's PKI secrets engine — the root key never leaves Vault.

```bash
# Enable the PKI secrets engine.
vault secrets enable -path=pki pki
vault secrets tune -max-lease-ttl=87600h pki   # 10 years max for root.

# Generate root CA inside Vault (key never exported).
vault write pki/root/generate/internal \
  common_name="systemshardening-root-ca" \
  ttl=87600h \
  key_type=ec \
  key_bits=384

# Configure CRL and OCSP URLs.
vault write pki/config/urls \
  issuing_certificates="https://vault.internal:8200/v1/pki/ca" \
  crl_distribution_points="https://vault.internal:8200/v1/pki/crl"

# Create the intermediate PKI mount.
vault secrets enable -path=pki_int pki
vault secrets tune -max-lease-ttl=43800h pki_int   # 5 years max for intermediates.

# Generate intermediate CSR.
vault write -field=csr pki_int/intermediate/generate/internal \
  common_name="services-intermediate-ca" \
  key_type=ec key_bits=256 > int.csr

# Sign the intermediate CSR with the root CA.
vault write -field=certificate pki/root/sign-intermediate \
  csr=@int.csr \
  format=pem_bundle ttl=43800h > int-signed.pem

# Import signed intermediate back.
vault write pki_int/intermediate/set-signed certificate=@int-signed.pem

# Create a role for issuing leaf certificates.
vault write pki_int/roles/services-internal \
  allowed_domains="services.internal" \
  allow_subdomains=true \
  max_ttl=48h \
  require_cn=true \
  key_type=ec key_bits=256
```

### Step 3: Vault Issuer in cert-manager

Wire cert-manager to the Vault PKI engine:

```yaml
# vault-issuer.yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: vault-services-internal
spec:
  vault:
    path: pki_int/sign/services-internal
    server: https://vault.internal:8200
    caBundle: <base64-encoded-vault-ca-cert>
    auth:
      kubernetes:
        role: cert-manager
        mountPath: /v1/auth/kubernetes
        serviceAccountRef:
          name: cert-manager
```

Vault Kubernetes auth policy for cert-manager:

```hcl
# vault-policy-cert-manager.hcl
path "pki_int/sign/services-internal" {
  capabilities = ["create", "update"]
}
# Read-only access to CA certificates for trust bundle updates.
path "pki_int/cert/ca_chain" {
  capabilities = ["read"]
}
```

```bash
vault policy write cert-manager vault-policy-cert-manager.hcl

vault write auth/kubernetes/role/cert-manager \
  bound_service_account_names=cert-manager \
  bound_service_account_namespaces=cert-manager \
  policies=cert-manager \
  ttl=1h
```

### Step 4: Enforce Certificate Policy

Use cert-manager's `CertificateRequestPolicy` (via the approver-policy plugin) to block out-of-policy certificates before issuance:

```bash
# Install the approver-policy plugin.
helm install approver-policy \
  jetstack/cert-manager-approver-policy \
  --namespace cert-manager \
  --set cert-manager.enabled=false
```

```yaml
# cert-policy-services.yaml
apiVersion: policy.cert-manager.io/v1alpha1
kind: CertificateRequestPolicy
metadata:
  name: services-internal-policy
spec:
  allowed:
    commonName:
      required: true
    dnsNames:
      required: true
      values:
        - "*.services.internal"
    isCA: false
    usages:
      - server auth
      - client auth
    duration:
      min: 1h
      max: 48h    # Hard cap: no certificate valid beyond 48 hours.
    privateKey:
      algorithm: EC
      minSize: 256
  selector:
    issuerRef:
      name: vault-services-internal
      kind: ClusterIssuer
      group: cert-manager.io
    namespace:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: In
          values: [payments, auth, api]   # Only these namespaces can use this issuer.
```

```bash
kubectl apply -f cert-policy-services.yaml
# Grant RBAC so cert-manager's approver plugin can read the policy.
kubectl create clusterrolebinding cert-manager-approver \
  --clusterrole=cert-manager-controller-approve:cert-manager.io \
  --serviceaccount=cert-manager:cert-manager
```

### Step 5: Namespace-Scoped vs Cluster-Scoped Issuers

Use namespace-scoped `Issuer` resources rather than `ClusterIssuer` for tenant isolation. A namespace-scoped Issuer can only sign certificates in its own namespace.

```yaml
# payments namespace issuer
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: payments-internal-issuer
  namespace: payments
spec:
  vault:
    path: pki_int/sign/services-internal
    server: https://vault.internal:8200
    caBundle: <base64-vault-ca>
    auth:
      kubernetes:
        role: cert-manager-payments
        mountPath: /v1/auth/kubernetes
        serviceAccountRef:
          name: cert-manager   # cert-manager's SA in the payments namespace.
```

With this design, a compromise in the `payments` namespace cannot request certificates for `auth.services.internal` — that would require access to the `auth` namespace's Issuer.

### Step 6: Short-Lived Certificates for Service-to-Service mTLS

For internal mTLS, issue 24-hour certificates. cert-manager auto-renews at the `renewBefore` threshold:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: payments-mtls-cert
  namespace: payments
spec:
  secretName: payments-mtls-tls
  duration: 24h
  renewBefore: 4h    # Begin renewal 4 hours before expiry; gives 6 attempts if first fails.
  subject:
    organizations: [payments-team]
  commonName: payments.services.internal
  dnsNames:
    - payments.services.internal
  usages:
    - server auth
    - client auth
  issuerRef:
    name: payments-internal-issuer
    kind: Issuer
```

The resulting Secret (`payments-mtls-tls`) contains a certificate valid for 24 hours. If an attacker exfiltrates it, it expires within a day. cert-manager handles renewal automatically.

### Step 7: Trust Bundle Distribution with trust-manager

Distributing CA trust bundles to all pods that need to verify internal certificates:

```yaml
# Install trust-manager.
helm install trust-manager jetstack/trust-manager \
  --namespace cert-manager

# Define a Bundle that distributes the intermediate CA certificate.
apiVersion: trust.cert-manager.io/v1alpha1
kind: Bundle
metadata:
  name: services-internal-ca
spec:
  sources:
    - secret:
        name: services-internal-ca-cert   # The intermediate CA cert.
        key: ca.crt
  target:
    configMap:
      key: ca-bundle.crt
    namespaceSelector:
      matchLabels:
        inject-ca: "true"
```

Label target namespaces:

```bash
kubectl label namespace payments inject-ca=true
kubectl label namespace auth inject-ca=true
```

Pods in labeled namespaces get a ConfigMap `services-internal-ca` containing the CA bundle, mountable as a volume:

```yaml
volumes:
  - name: ca-bundle
    configMap:
      name: services-internal-ca
containers:
  - name: app
    volumeMounts:
      - name: ca-bundle
        mountPath: /etc/ssl/internal
        readOnly: true
```

### Step 8: Monitor the Certificate Estate

```yaml
# Prometheus alerts for certificate health.
groups:
  - name: certificates
    rules:
      - alert: CertificateExpiringSoon
        expr: certmanager_certificate_expiration_timestamp_seconds - time() < 86400 * 3
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "Certificate {{ $labels.name }} expires in < 3 days"

      - alert: CertificateNotReady
        expr: certmanager_certificate_ready_status{condition="False"} == 1
        for: 10m
        labels:
          severity: critical
        annotations:
          summary: "Certificate {{ $labels.name }} is not ready"

      - alert: CertificateRenewalFailed
        expr: increase(certmanager_certificate_renewal_errors_total[1h]) > 0
        labels:
          severity: warning

      - alert: LongLivedCertificate
        expr: (certmanager_certificate_expiration_timestamp_seconds - certmanager_certificate_not_before_timestamp_seconds) > 86400 * 7
        labels:
          severity: warning
        annotations:
          summary: "Certificate {{ $labels.name }} has validity > 7 days; expected max 48h"
```

Key metrics exposed by cert-manager:

```
certmanager_certificate_expiration_timestamp_seconds{namespace, name}
certmanager_certificate_ready_status{namespace, name, condition}
certmanager_certificate_renewal_errors_total
certmanager_http_acme_client_request_count{status}
certmanager_controller_sync_call_count{controller}
```

## Expected Behaviour

| Signal | Default cert-manager | Hardened setup |
|--------|---------------------|----------------|
| Root CA location | Kubernetes Secret (`cert-manager` namespace) | Vault PKI (key never exported) |
| Leaf cert validity | 90 days (ACME) or manual | 24–48h (enforced by CertificateRequestPolicy) |
| `isCA: true` requests | Allowed by default | Blocked by policy |
| Cross-namespace issuance | ClusterIssuer permits any namespace | Namespace-scoped Issuer restricts to one namespace |
| Trust bundle distribution | Manual ConfigMap updates | trust-manager pushes to labeled namespaces automatically |
| Certificate monitoring | None (must query API) | Prometheus metrics + expiry alerts |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| 24h cert validity | Exfiltrated certs expire within a day | Renewal failures surface quickly; no grace period | Set `renewBefore=4h`; alert on renewal failures immediately; test renewal in staging. |
| Vault PKI for root CA | Root key never in Kubernetes ETCD | Adds Vault as a dependency; Vault downtime blocks new cert issuance | Vault HA mode; cache intermediate CA cert in cert-manager for short-window resilience. |
| Namespace-scoped Issuers | Blast radius limited per namespace | Operational overhead of creating Issuer per namespace | Templatize with Helm or GitOps; one template, many instances. |
| CertificateRequestPolicy enforcement | Hard blocks on out-of-policy certs | Initial rollout breaks existing long-lived certs | Roll out in audit mode first; identify violators; migrate before enforcement. |
| trust-manager bundles | CA rotation propagates automatically | CA cert update triggers pod restarts if mounted as volume | Use ConfigMap mount (no restart) rather than Secret mount where possible. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Vault unavailable during renewal | Cert expires; services fail TLS handshakes | `CertificateNotReady` alert; cert-manager controller logs show Vault 503 | Restore Vault; cert-manager retries automatically. Set `renewBefore` generously to survive short outages. |
| CertificateRequestPolicy rejects valid request | Developer request fails with policy violation | `CertificateRequest` resource has `Denied` condition | Review the policy; if request is legitimate, adjust policy scope. |
| Intermediate CA expires unnoticed | All leaf certs issued from it become untrusted | Widespread TLS failures across services | Monitor intermediate CA expiry separately; set 90-day renewal alert for 1-year intermediates. |
| Trust bundle out of date | Services reject new certificates from rotated CA | Intermittent TLS verification failures | Verify trust-manager Bundle is in sync; force reconcile: `kubectl annotate bundle services-internal-ca cert-manager.io/reconcile=true`. |
| cert-manager controller crashes during renewal | Cert expires if renewal was in progress | `CertificateNotReady` alert persists after controller restarts | cert-manager is stateless — on restart it picks up the renewal loop from the Certificate resource status. |
| Private key extracted from pod Secret | Attacker has authenticated credentials | No direct detection; inferred from anomalous service calls | Short TTL limits damage; rotate issuer if compromise confirmed; revoke via Vault CRL. |

## Related Articles

- [Kubernetes Secrets Management: Vault, KMS, and Kubernetes Secrets Compared](/articles/kubernetes/secrets-management/)
- [External Secrets Operator](/articles/kubernetes/external-secrets-operator/)
- [mTLS Service Mesh Hardening](/articles/network/mtls-service-mesh/)
- [SPIFFE/SPIRE Workload Identity](/articles/cross-cutting/spiffe-spire-workload-identity/)
- [OIDC Federation Hardening for CI-to-Cloud](/articles/cicd/oidc-federation-hardening/)
