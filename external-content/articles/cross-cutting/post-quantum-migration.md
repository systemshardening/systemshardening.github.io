---
title: "Post-Quantum Crypto Migration Plan: Hybrid TLS, SSH, Code Signing, and Encryption at Rest"
description: "NIST finalized ML-KEM and ML-DSA in 2024. Harvest-now-decrypt-later is already happening. A migration plan that covers TLS, SSH, artifact signing, and secrets is now tractable."
slug: "post-quantum-migration"
date: 2026-04-24
lastmod: 2026-04-24
category: "cross-cutting"
tags: ["post-quantum", "cryptography", "tls", "ssh", "migration", "pqc"]
personas: ["security-engineer", "platform-engineer", "compliance"]
article_number: 167
difficulty: "advanced"
estimated_reading_time: 18
published: true
layout: article.njk
permalink: "/articles/cross-cutting/post-quantum-migration/index.html"
---

# Post-Quantum Crypto Migration Plan: Hybrid TLS, SSH, Code Signing, and Encryption at Rest

## Problem

Shor's algorithm breaks RSA, DSA, and elliptic-curve cryptography in polynomial time on a sufficiently large fault-tolerant quantum computer. Estimates for when such a machine exists remain contested — somewhere between 2030 and never — but the relevant deadline for most organizations is earlier. Data encrypted with current public-key algorithms and exchanged today will remain sensitive for 10-25 years in many domains (health records, financial history, intellectual property, national infrastructure). An adversary recording TLS traffic now can decrypt it later when quantum capabilities arrive. This is the "harvest now, decrypt later" threat, and there is no future mitigation — the only fix is to migrate the encryption before the sensitive exchange happens.

NIST finalized the first three post-quantum standards in August 2024:

- **FIPS 203 — ML-KEM** (Module-Lattice-based Key-Encapsulation Mechanism, derived from CRYSTALS-Kyber). Replaces RSA/ECDH key exchange.
- **FIPS 204 — ML-DSA** (Module-Lattice-based Digital Signature Algorithm, derived from CRYSTALS-Dilithium). Replaces RSA/ECDSA signatures.
- **FIPS 205 — SLH-DSA** (Stateless Hash-based Digital Signature Algorithm, derived from SPHINCS+). Conservative signature algorithm built only on hash functions.

Chrome, Cloudflare, and Apple shipped hybrid ML-KEM key exchange for TLS in 2024. OpenSSH 9.9 (November 2024) made `sntrup761x25519-sha512@openssh.com` the default key exchange. AWS KMS and Google Cloud KMS have post-quantum-resistant key-wrapping previews. The tools are ready; the migration is organizational.

The specific gaps in a 2026-era production environment:

- **TLS** still uses classical-only curves on most internal services. Public-facing services may have hybrid enabled but backend mTLS between pods almost certainly does not.
- **SSH** continues to use RSA-4096 or ECDSA keys for authentication and pre-PQC key exchange on older servers.
- **Code signing** uses RSA/Ed25519 in Sigstore, cosign, GPG. No PQC yet in common artifact signing tooling.
- **Secrets at rest** in cloud KMS, Vault, or self-managed HSMs use RSA-wrapped keys. A stolen ciphertext today is cryptographically exposed on quantum Day Zero.
- **Document encryption** (S/MIME, PGP email, encrypted archives) is almost universally classical-only.

This article covers inventorying crypto usage, enabling hybrid key exchange on TLS and SSH, migrating artifact signing to hybrid signatures, and rotating long-lived encryption-at-rest keys.

**Target systems:** TLS 1.3 libraries (OpenSSL 3.2+, BoringSSL, rustls), OpenSSH 9.9+, cert-manager, HashiCorp Vault 1.16+, AWS KMS, Google Cloud KMS, Sigstore cosign 2.4+.

## Threat Model

- **Adversary 1 — Harvest now, decrypt later:** State-level actor or well-resourced criminal group passively recording encrypted traffic (TLS, SSH, VPN) and encrypted data at rest (exfiltrated backups, intercepted cloud-provider snapshots). They retain the ciphertext and wait for a quantum capability.
- **Adversary 2 — Signature forgery when CRQC arrives:** Any adversary who can run Shor's algorithm. Once available, any code-signing key, CA root, DNSSEC zone-signing key, or SSH host key that existed in classical form at any point can be forged retroactively. Signatures on historical artifacts become meaningless.
- **Access level:** Network-passive for Adversary 1; post-CRQC capability for Adversary 2. Neither requires active compromise of infrastructure.
- **Objective:** Adversary 1 decrypts harvested traffic once CRQC exists, learning secrets that were sensitive at capture time and remain sensitive years later. Adversary 2 impersonates any key that was never rotated to PQC, forging signatures on malicious software updates, fake certificates, or fraudulent authentication tokens.
- **Blast radius:** For confidentiality: every session key exchanged with classical-only crypto before CRQC is recoverable. For authenticity: every signature that has not been re-issued with PQC before CRQC is forgeable.

## Configuration

### Step 1: Inventory Current Crypto Usage

Before migrating, know what exists. Build a dependency inventory by scanning TLS endpoints, SSH hosts, signed artifacts, and secrets stores.

```bash
# Scan internal TLS endpoints for the algorithms they advertise.
for host in $(cat internal-endpoints.txt); do
  echo "=== $host ==="
  nmap --script ssl-enum-ciphers -p 443 "$host" 2>/dev/null | \
    grep -E "(ciphers|TLSv|key_exchange)"
done

# Classify: OK if X25519Kyber768Draft00 or X25519MLKEM768 appears.
```

```bash
# Check SSH server algorithms across a fleet.
for host in $(cat ssh-hosts.txt); do
  ssh -v -o BatchMode=yes -o ConnectTimeout=5 "$host" true 2>&1 | \
    grep -E "(kex:|host key alg|server host key algorithms)"
done
```

```bash
# Audit cosign signatures in a registry.
cosign tree ghcr.io/myorg/myapp:latest
# Look at signature algorithm in the signature bundle.
cosign download signature ghcr.io/myorg/myapp:latest | jq '.critical.type'
```

Produce a table: every asset, its current algorithm, its rotation deadline, its migration owner. Without this inventory the migration becomes an indefinite slog.

### Step 2: Enable Hybrid Key Exchange on TLS

Hybrid KEX combines a classical algorithm (X25519) with a PQ algorithm (ML-KEM-768). Classical protects against current cryptanalysis; PQ protects against future quantum attacks. If either algorithm is broken, the session remains secure.

Nginx with OpenSSL 3.5+ (includes native ML-KEM):

```nginx
# /etc/nginx/nginx.conf
ssl_protocols TLSv1.3;
# Prefer hybrid groups; fall back to classical for older clients.
ssl_ecdh_curve X25519MLKEM768:X25519:secp384r1;
ssl_conf_command Groups X25519MLKEM768:X25519:secp384r1;
```

For OpenSSL 3.2-3.4, use the `oqs-provider`:

```bash
# Install liboqs and the oqs-provider.
apt install -y libssl-dev
git clone https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider && cmake -B build . && cmake --build build
sudo cmake --install build

# Enable in openssl.cnf:
cat >> /etc/ssl/openssl.cnf <<'EOF'
[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
EOF
```

Envoy 1.30+:

```yaml
# envoy-listener.yaml snippet.
transport_socket:
  name: envoy.transport_sockets.tls
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
    common_tls_context:
      tls_params:
        tls_minimum_protocol_version: TLSv1_3
        # Supported groups in preference order (Envoy 1.30+).
        ecdh_curves:
          - X25519MLKEM768
          - X25519
          - P-256
```

Verify:

```bash
openssl s_client -connect example.com:443 -groups X25519MLKEM768 </dev/null 2>&1 | \
  grep "Server Temp Key"
# Server Temp Key: X25519MLKEM768, 1120 bits
```

### Step 3: Migrate SSH Key Exchange and Host Keys

OpenSSH 9.9+ makes `sntrup761x25519-sha512@openssh.com` the default KEX. For older servers still in your fleet:

```
# /etc/ssh/sshd_config
KexAlgorithms sntrup761x25519-sha512@openssh.com,mlkem768x25519-sha256,curve25519-sha256
HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256
```

`mlkem768x25519-sha256` landed in OpenSSH 9.9 (November 2024). Prefer it when both endpoints support it; `sntrup761` remains a safe transitional choice.

Migrate host keys and user keys to Ed25519 (already quantum-resistant-*ish* via generic hash-based impersonation costs, but plan for SLH-DSA migration when OpenSSH supports it):

```bash
# Generate new host keys.
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ''

# Generate new user keys.
ssh-keygen -t ed25519 -C "user@company.com" -f ~/.ssh/id_ed25519

# Rotate gradually: deploy new keys alongside old, distribute public keys
# via your existing mechanism (Ansible, Puppet, Teleport, Vault SSH CA),
# then remove old keys after verification.
```

When OpenSSH ships ML-DSA or SLH-DSA key types, plan another host-key rotation. Until then, Ed25519 is the best available compromise.

### Step 4: Artifact Signing with Hybrid Signatures

Sigstore/cosign support for PQ is emerging. For immediate migration, use dual signatures — sign with your existing key and additionally with a PQ key, storing both signatures on the artifact:

```bash
# Existing classical signature (cosign with OIDC-minted key).
cosign sign --key cosign.key ghcr.io/myorg/myapp:v1.2.3

# Additional PQ signature using an ML-DSA key produced by openssl.
openssl genpkey -algorithm ml-dsa-65 -out mldsa.key
openssl pkey -in mldsa.key -pubout -out mldsa.pub

# Sign the digest manually and attach as an artifact.
DIGEST=$(crane digest ghcr.io/myorg/myapp:v1.2.3)
openssl pkeyutl -sign -inkey mldsa.key -rawin \
  -in <(echo -n "$DIGEST") -out mldsa.sig
oras attach ghcr.io/myorg/myapp:v1.2.3 \
  --artifact-type application/vnd.mldsa.signature \
  mldsa.sig:application/octet-stream
```

Update verification to require both:

```bash
cosign verify --key cosign.pub ghcr.io/myorg/myapp:v1.2.3

oras discover --artifact-type application/vnd.mldsa.signature \
  ghcr.io/myorg/myapp:v1.2.3 \
  -o json | jq -r '.manifests[0].digest' | \
  while read d; do
    oras pull "ghcr.io/myorg/myapp@$d" -o /tmp/sig
    openssl pkeyutl -verify -pubin -inkey mldsa.pub -rawin \
      -in <(echo -n "$DIGEST") -sigfile /tmp/sig/mldsa.sig
  done
```

The deploy step only proceeds if both classical and PQ verifications pass.

### Step 5: Re-Wrap Secrets at Rest with PQ-Hybrid KEM

Secrets encrypted with envelope encryption use a per-object data key, wrapped by a KMS key. The KMS key is the harvest-now-decrypt-later target.

For AWS KMS:

```bash
# Create a PQ-hybrid KMS key (preview; check current availability).
aws kms create-key --key-spec HYBRID_ML_KEM_768 \
  --key-usage ENCRYPT_DECRYPT --description "PQ-hybrid wrapping key"

# Re-encrypt all data keys currently wrapped by the old key.
for item in $(list-encrypted-items); do
  aws kms re-encrypt \
    --ciphertext-blob "fileb://$item" \
    --destination-key-id arn:aws:kms:...:key/<new-pq-key>
done
```

For HashiCorp Vault 1.16+:

```bash
vault write sys/seal/seal-wrap enabled=true
vault write transit/keys/app-secrets type=mlkem-768
# Existing keys need re-encryption via transit/rewrap.
```

Prioritize secrets with the longest expected lifetime: database master passwords, signing roots, KEKs for customer data, backup encryption keys. Session tokens and ephemeral credentials have short exposure windows and lower priority.

### Step 6: Migration Timeline

| Year | Milestone |
|------|-----------|
| Q2 2025 | Inventory complete. Hybrid TLS enabled on all public-facing edges. |
| Q4 2025 | Hybrid TLS enabled on internal mesh (Istio/Linkerd with rustls-pq). |
| Q2 2026 | OpenSSH 9.9+ deployed fleet-wide. sntrup761 or mlkem768 hybrid default. |
| Q4 2026 | Artifact signing dual-sig with ML-DSA on all new releases. |
| Q2 2027 | Long-lived secrets re-wrapped with PQ KMS keys. Old KMS keys scheduled for deletion once no remaining ciphertext references them. |
| Q4 2027 | Classical-only fallback removed from internal services (external services continue hybrid for compatibility with old clients). |

## Expected Behaviour

| Asset | Before | After |
|-------|--------|-------|
| `openssl s_client` handshake negotiated group | `X25519` | `X25519MLKEM768` |
| SSH KEX | `curve25519-sha256` | `mlkem768x25519-sha256` or `sntrup761x25519-sha512@openssh.com` |
| TLS handshake size | ~1 KB | ~2.5 KB (ML-KEM ciphertext is larger) |
| Artifact signature verification | cosign only | cosign + ML-DSA; both must pass |
| KMS ciphertext format | classical envelope | hybrid envelope (classical-wrapped + PQ-wrapped data key) |
| CPU per handshake | Baseline | +5-15% for ML-KEM operations (negligible on modern CPUs) |

## Trade-offs

| Migration Step | Security Benefit | Cost | Mitigation |
|----------------|------------------|------|------------|
| Hybrid TLS (X25519MLKEM768) | HNDL-safe session keys starting immediately | Handshake ~1.5 KB larger → more round trips on slow networks; TTFB increases 5-20 ms | Use QUIC 0-RTT for repeat connections; prefer ChaCha20 ciphersuite on mobile. |
| OpenSSH 9.9+ rollout | Host keys and sessions protected against HNDL | OS upgrade coordination across the fleet; older OpenSSH clients cannot negotiate | Maintain a compatibility window where both old and new KEX are offered; log usage of the legacy KEX and migrate laggards. |
| Dual artifact signatures | Forgeable signatures become non-catastrophic — adversary needs to forge both | Signing pipeline complexity doubles; registry storage per artifact grows ~10 KB | Automate in your CI signing step; enforce verification via admission controller so unsigned-with-PQ deploys fail. |
| KMS key re-wrapping | Long-lived data resistant to post-CRQC decryption | KMS operations are billed per call; large inventories are expensive | Prioritize by data sensitivity and retention period. Sampling + re-encrypt-on-access patterns can defer cost. |
| SLH-DSA (hash-based) signatures | Conservative algorithm; no new assumptions beyond hash-function security | Signatures ~10-40 KB each — large for many use cases | Use for roots of trust only (CA root, Sigstore Fulcio root, SSH host CA). Use ML-DSA (~3.3 KB signatures) for everything else. |
| Decommissioning classical-only paths | Ends the HNDL window for those paths | Older clients break; API consumers may need to upgrade their TLS libraries | Announce deprecation timelines; expose Prometheus metrics on classical-only handshake counts to identify laggards. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Client does not support ML-KEM | TLS handshake fails; API consumers error with "no supported groups" | Error rates spike on endpoints where you removed classical fallback | Re-add `X25519` to the supported groups list. Hybrid-only enforcement should be feature-flagged per endpoint. |
| OpenSSL version mismatch in fleet | Some services negotiate hybrid; others remain classical | Nmap scan shows inconsistent supported groups across hosts | Pin OpenSSL version in your base images; add `ssl_ecdh_curve` check to your config validator (e.g., a pre-deploy test). |
| cosign signature without PQ twin | Admission controller rejects deploy; release blocked | Deploy pipeline logs `no ml-dsa signature found` | Update the CI signing job to produce both signatures. Until then, rollback to previous release. |
| ML-DSA key compromise | Forged signatures appear in registry | Audit log shows signatures not correlated to a known build pipeline | Revoke ML-DSA key in your trust store; rotate all artifacts signed during the compromise window. The classical signature provides interim protection. |
| KMS re-encryption incomplete | Some ciphertext still wrapped by old key after decommission planned | KMS usage metrics show requests to the old key continuing; audit logs confirm | Never delete the old key until KMS usage drops to zero for 30 days. Schedule `DeleteKey` with the longest waiting period supported (30 days on AWS). |
| Hybrid KEX downgrade attack | Attacker forces classical-only negotiation | Prometheus counter on handshake groups shows unexpected classical usage on otherwise-PQ endpoints | Enforce server-side preference order; once client support is universal, remove classical from the group list entirely. |

## When to Consider a Managed Alternative

Hand-rolling PQ migration requires tracking NIST updates, cipher suite compatibility, KMS key lifecycle, and signing pipeline changes across every team (8-16 hours/month for a multi-product organization).

- **AWS KMS with PQ-hybrid key specs:** handles key generation, rotation, and envelope encryption; exposes `HYBRID_ML_KEM_*` key specs.
- **Google Cloud KMS with Confidential Computing integration:** offers PQ-hybrid key wrapping and integration with Confidential VMs for keys-in-use protection.
- **Cloudflare TLS termination:** already uses hybrid KEM on inbound TLS; back-end connections to origin remain your responsibility.
- **[Open Quantum Safe project](https://openquantumsafe.org/):** open-source liboqs library bundled in OpenSSL providers; upstream for most managed offerings.

## Related Articles

- [TLS 1.3 on NGINX and Envoy: Secure Defaults and Cipher Selection](/articles/network/tls-nginx-envoy/)
- [SSH Hardening for Production Servers](/articles/linux/ssh-hardening/)
- [SLSA Build Provenance: Supply-Chain Integrity from Source to Registry](/articles/cicd/slsa-provenance/)
- [Compliance-as-Code with Open Policy Agent](/articles/cross-cutting/compliance-as-code/)
- [Secrets Management: Vault, KMS, and Kubernetes Secrets Compared](/articles/kubernetes/secrets-management/)
