---
title: "Post-Quantum Certificate Management in Kubernetes: Migrating Cluster PKI to Hybrid Certificates"
description: "Kubernetes control plane PKI, service mesh CAs, SPIFFE SVIDs, and Ingress TLS certificates all rely on RSA or ECDSA — algorithms vulnerable to harvest-now-decrypt-later. This guide maps the Kubernetes certificate landscape, implements hybrid PQC certificates with cert-manager and step-ca, and provides a phased migration roadmap for production clusters."
slug: kubernetes-post-quantum-pki
date: 2026-05-08
lastmod: 2026-05-08
category: kubernetes
tags:
  - post-quantum
  - kubernetes-pki
  - cert-manager
  - hybrid-certificates
  - spiffe
personas:
  - security-engineer
  - platform-engineer
article_number: 634
difficulty: Advanced
estimated_reading_time: 14
published: true
layout: article.njk
permalink: /articles/kubernetes/kubernetes-post-quantum-pki/
---

# Post-Quantum Certificate Management in Kubernetes: Migrating Cluster PKI to Hybrid Certificates

## Problem

Every Kubernetes cluster runs a layered certificate infrastructure that most platform teams never fully audit. The cluster CA signs the API server certificate, the kubelet client certificates, and the etcd peer and client certificates. Cert-manager issues certificates for Ingress TLS termination and admission webhook endpoints. If you run a service mesh, Istio's Citadel or Linkerd's trust anchor CA sign short-lived mTLS certificates for every workload proxy. If you use SPIFFE/SPIRE, the SPIRE server signs SVIDs that workloads present to each other across trust domains.

Every single one of these certificates — by default, in every Kubernetes distribution including kubeadm, EKS, GKE, and AKS — uses RSA-2048 or ECDSA P-256. Both algorithms are computationally secure against classical computers. Against a cryptographically relevant quantum computer (CRQC), they are not.

The practical threat is not a CRQC existing today. The threat is that adversaries are recording encrypted traffic **now** with the intention of decrypting it once a CRQC becomes available — the harvest-now-decrypt-later (HNDL) attack. For a Kubernetes cluster, the implications are severe:

- A threat actor with a passive tap on your cluster's internal network segment captures kubelet-to-API-server TLS traffic today. When a CRQC is available, they decrypt it and recover pod specs, ConfigMaps, `kubectl exec` session payloads, and bearer tokens sent in request headers.
- etcd replication traffic, even when encrypted at the network layer, contains the serialised state of every Secret in the cluster. If that traffic was recorded, a future CRQC exposes every credential that ever existed in the cluster.
- Service mesh mTLS traffic between workloads is similarly exposed. An adversary who captured east-west traffic between your payment service and your database proxy recovers plaintext years after the workload was decommissioned.

The X.509 certificate standard does not have native support for hybrid (classical + post-quantum) signatures. This creates a practical challenge: you cannot simply swap the algorithm in a certificate and expect every component in the trust chain — Go's TLS stack in kube-apiserver, the BoringSSL-based kubelet, the Envoy proxy in your service mesh — to accept it. Migration requires a structured approach combining near-term TLS key exchange upgrades with a longer-horizon certificate algorithm migration.

NIST finalised three post-quantum cryptography (PQC) standards in August 2024: ML-KEM (FIPS 203, lattice-based key encapsulation), ML-DSA (FIPS 204, lattice-based digital signatures), and SLH-DSA (FIPS 205, hash-based signatures). For Kubernetes PKI, ML-DSA is the relevant algorithm — it replaces ECDSA for certificate signing. ML-KEM replaces Diffie-Hellman for TLS key exchange.

The current state of tooling in early 2026: Go 1.23 includes hybrid X25519+ML-KEM-768 key exchange in `crypto/tls` (enabled by default for TLS 1.3 in Go 1.24). The `liboqs` project provides an OpenSSL provider that adds PQC algorithm support to the OpenSSL command-line tools. Smallstep's `step-ca` has experimental support for ML-DSA certificate issuance via IETF composite certificate drafts. Cert-manager is adding PQC support through a plugin interface, though production-grade support for composite certificates remains experimental as of cert-manager v1.16.

## Threat Model

**Long-term passive adversary.** A nation-state actor or a well-resourced criminal group deploys passive taps on your network segment — at a cloud provider, at a colocation facility, or through a compromised network device. They record all TLS traffic transiting the Kubernetes control plane. The recorded ciphertext is stored and decrypted once a CRQC is available, anticipated in the 2030–2040 timeframe by most assessments. The threat is asymmetric: the cost of recording traffic is low today; the cost of decryption is deferred to a future capability the attacker does not yet need to possess.

**Cluster CA key compromise in a post-quantum world.** Once quantum computers capable of breaking ECDSA exist, an attacker who has ever exfiltrated a cluster CA's private key — or who can reconstruct it from recorded traffic containing the key material — can forge certificates that pass classical signature validation. Every existing certificate chain built on RSA or ECDSA can be invalidated or spoofed without detection by current validation logic.

**Service mesh mTLS traffic capture.** Service mesh proxies issue short-lived certificates (typically 24 hours) but the TLS sessions they protect carry application payloads for the duration of each connection. A network tap between two nodes captures the full session. Even with short certificate lifetimes, the application data is exposed if the underlying key exchange is broken by a CRQC. Short certificate lifetimes do not protect against HNDL — they only limit the forward-secrecy window for an active MITM attacker, not a passive recorder.

## Mapping the Kubernetes Certificate Landscape

The first step in any migration is a complete inventory. The following table covers the standard certificate types in a kubeadm-provisioned cluster with Istio and cert-manager installed.

| Certificate | Signed By | Algorithm (default) | HNDL Risk | Migration Priority |
|---|---|---|---|---|
| Cluster CA (root) | Self-signed | RSA-2048 | Critical | Phase 3 |
| API server serving cert | Cluster CA | RSA-2048 | High | Phase 3 |
| API server kubelet client cert | Cluster CA | RSA-2048 | High | Phase 3 |
| Kubelet server cert | Cluster CA | ECDSA P-256 | High | Phase 3 |
| etcd CA | Self-signed | RSA-2048 | Critical | Phase 3 |
| etcd peer cert | etcd CA | RSA-2048 | Critical | Phase 2 |
| etcd client cert (apiserver) | etcd CA | RSA-2048 | Critical | Phase 2 |
| Front proxy CA | Self-signed | RSA-2048 | Medium | Phase 4 |
| Service account signing key | — (JWT) | RSA-2048 | Medium | Phase 4 |
| Ingress TLS (ACME/Let's Encrypt) | ACME CA | ECDSA P-256 | Medium | Phase 2 |
| Admission webhook TLS | Cluster CA or cert-manager | ECDSA P-256 | Low | Phase 4 |
| Istio Root CA | Self-signed | ECDSA P-256 | High | Phase 3 |
| Istio workload cert (SVID) | Istio CA | ECDSA P-256 | High | Phase 2 |
| SPIRE SVID | SPIRE CA | ECDSA P-256 | High | Phase 2 |
| cert-manager ClusterIssuer CA | Cluster CA | ECDSA P-256 | Medium | Phase 3 |

HNDL risk is rated by two factors: the sensitivity of the data protected by the certificate, and the likelihood that traffic is being recorded. etcd traffic is rated Critical because it carries the full cluster state including Secrets. API server and kubelet communication is rated High because it carries pod specs, exec sessions, and bearer tokens. Ingress TLS is rated Medium because it protects external traffic that is more likely to already be recorded at network boundaries.

## Configuration and Implementation

### Option 1: Hybrid TLS Key Exchange (Near-Term, No Certificate Format Changes)

The fastest win requires no changes to certificates or CAs. It upgrades the TLS 1.3 key exchange from ECDH to hybrid X25519+ML-KEM-768, which protects the session key against HNDL even if the certificate's signature algorithm remains classical.

Go 1.24 enables `X25519MLKEM768` as a default key share in its TLS 1.3 implementation. Because kube-apiserver, kubelet, and kube-controller-manager are all compiled with Go, upgrading to Kubernetes 1.32+ (compiled with Go 1.24) provides hybrid key exchange on the control plane without any configuration change.

To verify that a running API server is negotiating hybrid key exchange:

```bash
# Capture a TLS ClientHello from a kubectl command and inspect key_share groups
openssl s_client \
  -connect <apiserver-endpoint>:6443 \
  -tls1_3 \
  -groups X25519MLKEM768:X25519:P-256 \
  -CAfile /etc/kubernetes/pki/ca.crt \
  2>&1 | grep -E "Server Temp Key|SSL-Session|New, TLS"
```

For Kubernetes clusters running an older Go version, you can force the key share group in the API server flags:

```bash
# kube-apiserver flag (Kubernetes 1.31+)
--tls-cipher-suites=TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256
# Key exchange group negotiation is controlled by the Go TLS stack, not by --tls-cipher-suites
# Ensure KUBERNETES_FEATURE_GATES includes "PQCKeyExchange=true" once graduated
```

This option provides HNDL protection for the TLS session keys immediately. An adversary who records the traffic cannot derive the session key without a CRQC **and** the ability to break both X25519 (classical) and ML-KEM-768 (quantum-resistant) simultaneously. The certificate signature algorithm remains ECDSA, so certificate chain validation is still classically vulnerable, but the data content of recorded sessions is protected.

### Option 2: Hybrid Certificates with liboqs-provider

This option introduces post-quantum signatures into the certificate chain itself, providing protection against a future attacker who can forge ECDSA signatures.

**Install liboqs OpenSSL provider on control plane nodes:**

```bash
# Ubuntu 24.04 — build from source or use the OQS release PPA
apt-get install -y cmake ninja-build libopenssl-dev libssl-dev

git clone --depth 1 --branch 0.11.0 https://github.com/open-quantum-safe/liboqs.git
cmake -S liboqs -B liboqs/build -DOQS_USE_OPENSSL=ON -DBUILD_SHARED_LIBS=ON
cmake --build liboqs/build -j$(nproc)
cmake --install liboqs/build --prefix /usr/local

git clone --depth 1 --branch 0.6.1 https://github.com/open-quantum-safe/oqs-provider.git
cmake -S oqs-provider -B oqs-provider/build \
  -DOPENSSL_ROOT_DIR=/usr \
  -Dliboqs_DIR=/usr/local/lib/cmake/liboqs
cmake --build oqs-provider/build -j$(nproc)
cmake --install oqs-provider/build
```

Configure OpenSSL to load the provider:

```ini
# /etc/ssl/openssl.cnf (add to [provider_sect])
[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
module = /usr/local/lib/ossl-modules/oqsprovider.so
activate = 1
```

**Generate a hybrid CA using composite ML-DSA-65 + ECDSA P-256:**

The IETF draft `draft-ounsworth-pq-composite-sigs` defines composite signature algorithms that embed both a classical and a post-quantum signature in a single X.509 extension. The OID `id-MLDSA65-ECDSA-P256` identifies this composite algorithm in the liboqs provider.

```bash
# Generate a hybrid composite root CA key
openssl genpkey \
  -provider oqsprovider \
  -algorithm "MLDSA65_P256" \
  -out /etc/kubernetes/pki/hybrid-ca.key

# Self-sign the hybrid CA certificate
openssl req -new -x509 \
  -provider oqsprovider \
  -provider default \
  -key /etc/kubernetes/pki/hybrid-ca.key \
  -out /etc/kubernetes/pki/hybrid-ca.crt \
  -days 3650 \
  -subj "/CN=kubernetes-hybrid-ca/O=kubernetes" \
  -extensions v3_ca \
  -config <(cat /etc/ssl/openssl.cnf; echo -e "[v3_ca]\nbasicConstraints=CA:TRUE\nkeyUsage=keyCertSign,cRLSign")

# Inspect the resulting certificate
openssl x509 -in /etc/kubernetes/pki/hybrid-ca.crt -text -noout \
  -provider oqsprovider -provider default | grep -A2 "Public Key Algorithm"
```

The resulting certificate carries two signature values — one ECDSA P-256 signature and one ML-DSA-65 signature — in the composite signature extension. A TLS stack that understands composite certificates validates both. A legacy TLS stack that does not understand composite certificates may reject it, which is the central compatibility challenge.

**cert-manager custom issuer pointing to step-ca with ML-DSA support:**

Smallstep step-ca supports PQC key types via its `--key-type` flag as of version 0.25.0. Deploy step-ca as a pod in the `cert-manager` namespace and configure cert-manager to use it as a custom issuer via the `step-issuer` CRD.

```yaml
# step-ca deployment with ML-DSA key type
apiVersion: apps/v1
kind: Deployment
metadata:
  name: step-ca
  namespace: cert-manager
spec:
  replicas: 1
  selector:
    matchLabels:
      app: step-ca
  template:
    metadata:
      labels:
        app: step-ca
    spec:
      containers:
      - name: step-ca
        image: smallstep/step-ca:0.25.2
        args:
        - /home/step/config/ca.json
        env:
        - name: STEPDEBUG
          value: "1"
        volumeMounts:
        - name: step-config
          mountPath: /home/step/config
        - name: step-secrets
          mountPath: /home/step/secrets
      volumes:
      - name: step-config
        configMap:
          name: step-ca-config
      - name: step-secrets
        secret:
          secretName: step-ca-secrets
```

```json
// step-ca ca.json — configure ML-DSA key type for the intermediate CA
{
  "root": "/home/step/certs/root_ca.crt",
  "federatedRoots": [],
  "crt": "/home/step/certs/intermediate_ca.crt",
  "key": "/home/step/secrets/intermediate_ca_key",
  "kty": "OKP",
  "crv": "ML-DSA-65",
  "address": ":9000",
  "dnsNames": ["step-ca.cert-manager.svc.cluster.local"],
  "logger": {"format": "json"},
  "db": {"type": "badger", "dataSource": "/home/step/db"},
  "authority": {
    "provisioners": [
      {
        "type": "ACME",
        "name": "acme",
        "forceCN": true
      },
      {
        "type": "JWK",
        "name": "k8s-provisioner",
        "key": {"use": "sig", "kty": "EC", "crv": "P-256"},
        "encryptedKey": ""
      }
    ]
  }
}
```

```yaml
# StepClusterIssuer CR requesting hybrid certificate issuance
apiVersion: certmanager.step.sm/v1beta1
kind: StepClusterIssuer
metadata:
  name: hybrid-pqc-issuer
spec:
  url: https://step-ca.cert-manager.svc.cluster.local:9000
  caBundle: <base64-encoded-step-ca-root>
  provisioner:
    name: k8s-provisioner
    kid: <provisioner-key-id>
    passwordRef:
      name: step-provisioner-password
      namespace: cert-manager
      key: password
---
# Certificate request using the hybrid issuer
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: my-service-hybrid-tls
  namespace: production
spec:
  secretName: my-service-hybrid-tls
  duration: 24h
  renewBefore: 8h
  subject:
    organizations: ["my-org"]
  dnsNames:
  - my-service.production.svc.cluster.local
  issuerRef:
    name: hybrid-pqc-issuer
    kind: StepClusterIssuer
    group: certmanager.step.sm
```

### Option 3: Dual-Stack Certificates (Classical + PQC in Parallel)

The safest migration path for production clusters runs two parallel CAs: one classical CA (your existing cluster CA) for components and clients that cannot yet handle PQC certificates, and one PQC CA for components that have been updated to support ML-DSA validation.

This approach avoids breaking existing workloads while allowing opt-in PQC adoption. The NGINX Ingress controller can serve both certificate types, selecting based on the client's TLS extension advertising PQC signature algorithm support.

```yaml
# Two ClusterIssuers in cert-manager: classical and PQC
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: classical-ca-issuer
spec:
  ca:
    secretName: classical-cluster-ca
---
apiVersion: certmanager.step.sm/v1beta1
kind: StepClusterIssuer
metadata:
  name: pqc-hybrid-issuer
spec:
  url: https://step-ca.cert-manager.svc.cluster.local:9000
  caBundle: <pqc-ca-bundle>
  provisioner:
    name: k8s-provisioner
    kid: <kid>
    passwordRef:
      name: step-provisioner-password
      namespace: cert-manager
      key: password
```

```yaml
# Ingress resource with dual TLS secrets (classical + PQC)
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-app-dual-tls
  annotations:
    nginx.ingress.kubernetes.io/ssl-prefer-server-ciphers: "true"
    # Custom annotation supported in NGINX Ingress 1.12+ for dual-cert configuration
    nginx.ingress.kubernetes.io/ssl-certs: "classical-tls,pqc-hybrid-tls"
spec:
  tls:
  - hosts:
    - app.example.com
    secretName: classical-tls   # ECDSA P-256 — for legacy clients
  - hosts:
    - app.example.com
    secretName: pqc-hybrid-tls  # ML-DSA-65+ECDSA — for PQC-capable clients
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: my-app
            port:
              number: 8080
```

NGINX Ingress selects the certificate to present based on SNI and the client's supported signature algorithms extension. When both secrets are available for the same hostname, the server presents the strongest certificate the client supports.

### SPIFFE/SPIRE PQC Migration

SPIRE 1.10 (released Q1 2026) introduced experimental support for ML-DSA SVIDs via the `UpstreamAuthority` plugin interface. Configuring SPIRE to issue hybrid SVIDs requires updating the server configuration and ensuring all SPIRE agents are running a version that can validate ML-DSA signatures in the SVID chain.

```hcl
# SPIRE server configuration for hybrid SVID issuance
server {
  bind_address = "0.0.0.0"
  bind_port = "8081"
  trust_domain = "example.org"
  data_dir = "/run/spire/data"
  log_level = "DEBUG"

  # Enable experimental PQC SVID support
  experimental {
    pqc_svid_key_type = "ML-DSA-65"
    dual_stack_svids = true  # Issue both ECDSA and ML-DSA SVIDs simultaneously
  }
}

plugins {
  DataStore "sql" {
    plugin_data {
      database_type = "sqlite3"
      connection_string = "/run/spire/data/datastore.sqlite3"
    }
  }

  KeyManager "disk" {
    plugin_data {
      keys_path = "/run/spire/data/keys.json"
    }
  }

  UpstreamAuthority "disk" {
    plugin_data {
      key_file_path = "/run/spire/conf/upstream_ca.key"
      cert_file_path = "/run/spire/conf/upstream_ca.crt"
      # Point to a hybrid CA generated with liboqs-provider
    }
  }
}
```

With `dual_stack_svids = true`, each workload receives two SVIDs: one ECDSA SVID (for compatibility with existing SPIFFE validators) and one ML-DSA SVID (for workloads that have been updated to prefer PQC authentication). The SPIFFE Workload API returns both in the `X509SVIDResponse`.

## Phased Migration Plan

**Phase 1: Inventory and baseline (weeks 1–2)**

Enumerate all certificates in the cluster and record their algorithms, expiry dates, and issuing CAs.

```bash
# Enumerate all TLS secrets in the cluster
kubectl get secrets --all-namespaces \
  -o jsonpath='{range .items[?(@.type=="kubernetes.io/tls")]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}'

# For each TLS secret, extract and inspect the certificate
for secret in $(kubectl get secrets --all-namespaces \
  -o jsonpath='{range .items[?(@.type=="kubernetes.io/tls")]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}'); do
  ns=$(echo $secret | cut -d/ -f1)
  name=$(echo $secret | cut -d/ -f2)
  kubectl get secret -n $ns $name \
    -o jsonpath='{.data.tls\.crt}' | base64 -d | \
    openssl x509 -noout -subject -issuer -dates -pubkey 2>/dev/null | \
    grep -E "subject|issuer|notAfter|Public Key Algorithm|ASN1 OID|NIST CURVE"
  echo "---"
done

# Inspect control plane certificates (kubeadm clusters)
for cert in /etc/kubernetes/pki/*.crt; do
  echo "=== $cert ==="
  openssl x509 -in $cert -noout -subject -pubkey 2>/dev/null | \
    grep -E "subject|Public Key Algorithm|ASN1 OID|NIST CURVE"
done
```

**Phase 2: Enable PQC key exchange (weeks 2–4)**

Upgrade Kubernetes to 1.32+ (Go 1.24 compiled) to benefit from X25519+ML-KEM-768 key exchange in the API server and kubelet. No certificate changes required. Verify hybrid key exchange is negotiating in production.

**Phase 3: Deploy hybrid CA infrastructure (months 2–3)**

Deploy step-ca with liboqs support. Create hybrid root and intermediate CAs. Configure a cert-manager StepClusterIssuer. Begin issuing hybrid certificates for new workloads (Ingress TLS, admission webhook TLS) where the client TLS stack is known to support composite certificates.

**Phase 4: Rotate service mesh and SVID certificates (months 3–5)**

Update SPIRE server to 1.10+ and enable `dual_stack_svids`. Update Istio to a version that supports ML-DSA intermediate CA configuration. Rotate service mesh root CA to hybrid. Existing short-lived workload certs (24h) will automatically cycle to hybrid within 24 hours of the CA rotation.

**Phase 5: Rotate control plane certificates (months 5–8, high-risk)**

This is the most disruptive phase. Control plane certificate rotation requires careful sequencing to avoid cluster downtime. Use `kubeadm certs renew` with a custom CA, or the cluster's managed certificate rotation mechanism (EKS Certificate Authority Rotation, GKE Certificate Authority rotation).

```bash
# kubeadm-based cluster: renew control plane certs with new hybrid CA
# 1. Back up existing PKI
cp -r /etc/kubernetes/pki /etc/kubernetes/pki.backup.$(date +%Y%m%d)

# 2. Replace cluster CA with hybrid CA (generated in Phase 3)
cp /path/to/hybrid-ca.crt /etc/kubernetes/pki/ca.crt
cp /path/to/hybrid-ca.key /etc/kubernetes/pki/ca.key

# 3. Renew all certificates signed by the cluster CA
kubeadm certs renew all

# 4. Restart control plane components
systemctl restart kubelet
# (Static pod manifests will trigger API server, controller-manager, scheduler restarts)

# 5. Distribute updated kubeconfig to all users
kubeadm kubeconfig user --client-name admin
```

## Expected Outcomes by Certificate Type

| Certificate | Current Algorithm | Target Algorithm | Migration Command |
|---|---|---|---|
| Cluster CA | RSA-2048 | ML-DSA-65+ECDSA-P256 | Replace `/etc/kubernetes/pki/ca.{crt,key}` then `kubeadm certs renew all` |
| API server cert | RSA-2048 | ML-DSA-65+ECDSA-P256 | `kubeadm certs renew apiserver` after CA rotation |
| Kubelet client cert | ECDSA P-256 | ML-DSA-65+ECDSA-P256 | `kubeadm certs renew apiserver-kubelet-client` |
| etcd peer cert | RSA-2048 | ML-DSA-65+ECDSA-P256 | `kubeadm certs renew etcd-peer` (rolling, one node at a time) |
| etcd client cert | RSA-2048 | ML-DSA-65+ECDSA-P256 | `kubeadm certs renew apiserver-etcd-client` |
| Ingress TLS | ECDSA P-256 | ML-DSA-65+ECDSA-P256 | Update cert-manager Certificate issuerRef to StepClusterIssuer |
| Istio workload cert | ECDSA P-256 | ML-DSA-65+ECDSA-P256 | Rotate Istio CA; workload certs auto-renew within 24h |
| SPIRE SVID | ECDSA P-256 | ML-DSA-65 (parallel) | Enable `dual_stack_svids` in SPIRE server config |

## Trade-offs

**Certificate size.** An ML-DSA-65 public key is approximately 1,952 bytes. An ECDSA P-256 public key is 64 bytes. A composite ML-DSA-65+ECDSA-P256 certificate is roughly 3–4 KB, compared to 500–800 bytes for a standard ECDSA certificate. In the Kubernetes control plane, where certificates are transmitted in every TLS handshake, this increases handshake sizes. For clusters with high kubelet-to-API-server call rates (large clusters with many pods and frequent watch reconnections), this adds measurable overhead.

**TLS handshake latency.** ML-DSA-65 signature verification is fast — faster than ECDSA in some benchmarks — but the larger key and signature sizes increase network round-trip times due to fragmentation across TLS record boundaries. In practice, benchmarks on a 10 GbE network show handshake time increases of 2–8% for composite certificates, well within acceptable bounds for control plane traffic.

**Tooling maturity.** As of May 2026, composite certificate support is not uniformly implemented across the Kubernetes ecosystem. The Go TLS stack (which backs kube-apiserver, kubelet, and all Go-based Kubernetes components) does not yet natively validate composite X.509 signatures — it requires the liboqs-provider to be loaded into the OpenSSL context, which is not how Go TLS operates. This means that composite certificate validation at the Go layer requires either a patched Go build or application-layer verification logic outside the standard `crypto/tls` package. The practical near-term strategy is therefore: use PQC key exchange (Go 1.24 natively) now, and pilot composite certificates for cert-manager-managed workloads where you control the client TLS library.

**Operational complexity.** Maintaining two parallel CAs, two certificate chains, and dual-stack SVID issuance significantly increases PKI operational complexity. A misconfigured hybrid CA that older components cannot validate will cause certificate validation failures across the control plane — a cluster-breaking event. The phased approach is not optional; it is the minimum viable migration strategy.

## Failure Modes

**Composite certificate rejection by legacy TLS stacks.** If a composite certificate is presented to a TLS client that does not recognise the composite signature algorithm OID, the handshake fails with `tls: failed to verify certificate: x509: certificate signed by unknown authority`. This affects any component that uses the system OpenSSL library without the oqs-provider loaded. Symptom: cert-manager Certificate resources show `Issuing` condition with `Failed to obtain certificate` events; kubelet logs show `x509: certificate signed by unknown authority`.

**cert-manager controller version mismatch.** cert-manager v1.15 and earlier do not support the StepClusterIssuer CRD. Upgrading cert-manager without verifying that the step-issuer controller version matches the cert-manager API version causes all StepClusterIssuer resources to fail with `no matches for kind "StepClusterIssuer" in version "certmanager.step.sm/v1beta1"`. Always check compatibility matrices before upgrading either component.

**Control plane certificate rotation causing downtime.** Replacing the cluster CA (`/etc/kubernetes/pki/ca.crt`) without distributing the new CA bundle to all components simultaneously causes a window where some components trust the new CA and others trust only the old CA. During this window, the API server may reject kubelet connections or vice versa. Mitigation: use the certificate bundle approach — include both the old and new CA in the `ca.crt` file during the transition period, then remove the old CA only after all leaf certificates have been rotated to the new CA.

**etcd quorum loss during certificate rotation.** etcd peer certificates must be rotated on one node at a time. If you rotate all etcd member certificates simultaneously and a single node fails to come up with the new certificate, the etcd cluster loses quorum. Mitigation: rotate etcd certificates sequentially, verifying etcd cluster health (`etcdctl endpoint health`) after each node before proceeding.

**liboqs-provider not loaded on all nodes.** If the oqs-provider is installed only on control plane nodes but worker nodes also need to validate hybrid certificates (for admission webhook TLS, for example), webhook calls will fail. The webhook TLS validation happens in the API server — which is on the control plane — but if the webhook server itself presents a hybrid certificate and the kube-apiserver's OpenSSL context does not have the oqs-provider loaded, the connection fails. Ensure the oqs-provider is installed on every node that participates in TLS validation, and that the `openssl.cnf` activating the provider is loaded by the process, not just present on the filesystem.

## Where to Start

For most clusters in 2026, the correct starting point is Phase 2: upgrade to Kubernetes 1.32+ to gain X25519+ML-KEM-768 key exchange automatically. This protects session content against HNDL immediately with zero configuration changes and zero compatibility risk.

Phases 3–5 (composite certificates) should be piloted in non-critical namespaces using cert-manager and step-ca, validating that every component in the certificate validation chain — ingress controller, service mesh proxy, admission webhook, monitoring agent — can handle composite certificates before committing to a control plane rotation.

The harvest-now-decrypt-later threat is active now. The practical protection — hybrid TLS key exchange — is available now and requires only a Kubernetes version upgrade. Delaying Phase 1 and 2 while waiting for composite certificate tooling to mature is the wrong trade-off. Protect the session keys first; migrate the certificate signatures once the ecosystem catches up.
