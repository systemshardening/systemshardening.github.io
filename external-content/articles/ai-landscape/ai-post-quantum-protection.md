---
title: "Post-Quantum Protection for AI Systems: Model Weights, Inference Encryption, and Training Data"
description: "AI model weights encrypted with RSA or ECDH today are vulnerable to harvest-now-decrypt-later. A quantum adversary who captures encrypted model weights, training data, or inference traffic can decrypt them when CRQCs become available. This guide covers PQC threat modelling for AI assets, implementing ML-KEM for model distribution, and protecting inference pipelines with hybrid PQC TLS."
slug: ai-post-quantum-protection
date: 2026-05-08
lastmod: 2026-05-08
category: ai-landscape
tags:
  - post-quantum
  - ai-security
  - model-protection
  - ml-kem
  - inference-security
personas:
  - security-engineer
  - ml-engineer
article_number: 638
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/ai-landscape/ai-post-quantum-protection/
---

# Post-Quantum Protection for AI Systems: Model Weights, Inference Encryption, and Training Data

## Problem

Most AI security discussions focus on prompt injection, adversarial inputs, or supply chain attacks — threats that materialise today. The harvest-now-decrypt-later (HNDL) attack is different: an adversary does not need to break your encryption now. They only need to record the ciphertext and wait for a cryptographically relevant quantum computer (CRQC) to become available. When that happens — current estimates range from five to fifteen years — every bit of data encrypted with RSA, ECDH, or ECDSA today becomes readable.

For most data, this is a moderate risk. For AI systems, the exposure is qualitatively different.

**Model weights represent concentrated, long-lived intellectual property.** A frontier language model trained on proprietary data — code repositories, scientific literature, internal documentation — may represent hundreds of millions of dollars in compute and data curation. The resulting checkpoint is hundreds of gigabytes of floating-point parameters that encode capabilities competitors cannot easily replicate. An adversary who captures an encrypted model download from HuggingFace, an S3 bucket, or a private model registry today is making a low-cost bet: store a few hundred gigabytes now, decrypt it in a decade, and gain immediate access to proprietary architecture and weights without any of the original training cost.

**The operational lifespan of AI models intersects directly with the quantum threat timeline.** A model fine-tuned in 2026 and deployed in a healthcare, financial, or government system will realistically remain in production until 2034 or later. That eight-year operational window overlaps substantially with credible CRQC timelines. The model's cryptographic protection needs to outlast its entire production lifetime, not just its initial deployment window.

**Inference traffic carries sensitive data that accumulates over time.** API calls to LLMs and vision models contain some of the most sensitive queries organisations generate: patient symptom descriptions, draft legal arguments, proprietary financial models, M&A analysis, and software vulnerability details. An adversary recording TLS-encrypted inference traffic to a medical AI API in 2026 does not need to understand it immediately. Decrypting it in 2032 yields a structured archive of patient data and clinical decision patterns, likely with no statute of limitations benefit to the organisation.

**Model signing is vulnerable to verify-later attacks.** ECDSA-signed OCI artefacts published today will be verifiable — or forgeable — by a quantum adversary years after publication. A nation-state actor with a CRQC could generate a valid ECDSA signature for a maliciously modified model checkpoint, then inject that artefact into an AI system's supply chain. Because the model was "correctly signed," automated policy checks would pass.

**Training data compounds the risk.** Datasets containing PII, proprietary text, or government-classified information encrypted with classical algorithms are as recoverable as the models trained on them. A dataset encrypted and stored in cold storage today for compliance or reproducibility purposes carries its own HNDL exposure.

## Threat Model

**Adversary 1 — Nation-state weight harvest.** A nation-state intelligence operation records encrypted model weight downloads from HuggingFace, private S3 buckets, or enterprise model registries. The adversary does not attempt to break encryption immediately. They archive ciphertext alongside decryption key exchanges captured from TLS sessions. When a CRQC is available, they recover the AES data keys (from the captured ECDH key exchange) and decrypt the model checkpoints, obtaining architecture details and fine-tuned weights without conducting any active attack.

**Adversary 2 — Inference traffic bulk collection.** A signals intelligence capability or compromised backbone router performs bulk collection of TLS-encrypted inference API traffic. Targets include inference endpoints for AI systems used in healthcare, legal, financial, and government contexts. The adversary stores ciphertext traffic for later decryption, building archives that will yield sensitive queries and model responses once classical asymmetric protections are broken. The collection is passive and undetectable.

**Adversary 3 — Model artefact signature forgery.** A future quantum adversary targets model supply chains by forging ECDSA signatures on model OCI artefacts. The adversary modifies a widely-used open-weight model checkpoint to include a backdoor (e.g., a specific input token that triggers malicious behaviour), generates a valid ECDSA signature for the modified checkpoint using quantum-derived signature forgery, and publishes the artefact to a registry. Downstream consumers performing signature verification accept the backdoored checkpoint because the signature verifies against the original author's public key.

**Out of scope.** This article does not address active compromise of inference infrastructure (covered in the vLLM and LLM deployment articles), model extraction via query attacks (covered in the model extraction prevention article), or runtime prompt injection. Those threats require different mitigations.

## PQC Threat Inventory for AI Systems

Before implementing anything, map the cryptographic protection applied to each AI asset class and assess its HNDL exposure. The following table provides the starting point for most organisations.

| AI Asset | Current Cryptographic Protection | HNDL Risk | PQC Migration Priority |
|---|---|---|---|
| Model weights in object storage | AES-256 data key wrapped with RSA-2048 or ECDH | **High** — data key recoverable from captured key exchange | 1 — re-wrap keys with ML-KEM |
| Model download from registry (HuggingFace, private) | HTTPS with X25519 or ECDH key exchange | **High** — key exchange recoverable from TLS capture | 1 — hybrid PQC TLS on download endpoints |
| Inference API traffic | TLS 1.3 with X25519 | **High** for sensitive queries (medical, legal, financial) | 1 — hybrid PQC TLS on inference endpoints |
| Model artefact signatures | ECDSA on OCI artefacts | **Medium** — verify-later forgery, not data exposure | 2 — migrate to ML-DSA signatures |
| Training data in transit | HTTPS | **High** if dataset contains long-lived sensitive records | 1 — hybrid PQC TLS on data pipelines |
| Training data at rest | AES-256 with ECDH-wrapped key | **High** if dataset sensitivity exceeds retention period | 2 — re-wrap keys with ML-KEM |
| Model SBOM (CycloneDX) signatures | ECDSA | **Medium** — same as artefact signatures | 2 — ML-DSA with artefact signing migration |

The risk column reflects data sensitivity combined with expected data longevity. Inference traffic to a model answering questions about publicly available facts carries lower HNDL risk than inference traffic to a medical diagnostic model. Adjust the priority column based on your specific context.

## ML-KEM for Model Weight Distribution

The core vulnerability for stored model weights is that the AES-256 data encryption key (DEK) is typically wrapped with a classical asymmetric algorithm — RSA or ECDH. AES-256 itself is quantum-resistant (Grover's algorithm halves effective key length to 128 bits, which remains secure). The exposure is the key wrapping layer. Migrating the wrapping layer to ML-KEM-768 (NIST FIPS 203) eliminates this exposure.

**Envelope encryption with hybrid KEM.** The recommended pattern combines ML-KEM-768 with X25519 in a hybrid KEM. This means the DEK is encapsulated such that breaking either the classical or post-quantum component alone is insufficient to recover the key. This maintains security against classical adversaries today and post-quantum adversaries in the future.

```python
# Using liboqs-python (Open Quantum Safe) for ML-KEM-768
# pip install liboqs-python cryptography

import oqs
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_hybrid_kem_keypair():
    """Generate ML-KEM-768 + X25519 hybrid keypair for model key wrapping."""
    # ML-KEM-768 keypair
    mlkem = oqs.KeyEncapsulation("ML-KEM-768")
    mlkem_public_key = mlkem.generate_keypair()
    
    # X25519 keypair
    x25519_private = X25519PrivateKey.generate()
    x25519_public = x25519_private.public_key()
    
    return {
        "mlkem_private": mlkem,
        "mlkem_public": mlkem_public_key,
        "x25519_private": x25519_private,
        "x25519_public": x25519_public,
    }

def wrap_model_dek(dek: bytes, recipient_public_keys: dict) -> dict:
    """
    Wrap a 256-bit model data encryption key using hybrid ML-KEM-768 + X25519.
    Returns the ciphertext components for storage alongside the encrypted model.
    """
    # ML-KEM-768 encapsulation
    mlkem_enc = oqs.KeyEncapsulation("ML-KEM-768")
    mlkem_ciphertext, mlkem_shared_secret = mlkem_enc.encap_secret(
        recipient_public_keys["mlkem_public"]
    )
    
    # X25519 ephemeral key exchange
    x25519_ephemeral = X25519PrivateKey.generate()
    x25519_shared_secret = x25519_ephemeral.exchange(
        recipient_public_keys["x25519_public"]
    )
    
    # Combine shared secrets with HKDF — both must be known to recover the KEK
    combined_secret = mlkem_shared_secret + x25519_shared_secret
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"model-dek-wrapping-v1",
    )
    kek = kdf.derive(combined_secret)
    
    # Wrap the DEK with the derived key encryption key
    aesgcm = AESGCM(kek)
    nonce = os.urandom(12)
    wrapped_dek = aesgcm.encrypt(nonce, dek, None)
    
    return {
        "mlkem_ciphertext": mlkem_ciphertext,
        "x25519_ephemeral_public": x25519_ephemeral.public_key(),
        "nonce": nonce,
        "wrapped_dek": wrapped_dek,
    }
```

Store the `mlkem_ciphertext`, `x25519_ephemeral_public`, `nonce`, and `wrapped_dek` values in a key manifest file alongside the encrypted model checkpoint. The model weights themselves remain AES-256-GCM encrypted; only the key wrapping changes.

**Practical deployment for model registries.** For organisations using HuggingFace or private OCI-based model registries, the immediate improvement is hybrid PQC TLS on download endpoints — this addresses the in-transit ECDH key exchange vulnerability without requiring changes to stored artefacts. Additionally, model checkpoints stored in object storage (S3, GCS, Azure Blob) that use SSE-KMS should have their CMK wrappers re-issued under a hybrid KEM scheme once AWS KMS, Google Cloud KMS, and Azure Key Vault ship ML-KEM support, which all three providers have announced on their PQC roadmaps.

Until cloud KMS providers ship ML-KEM natively, the practical approach is application-layer ML-KEM wrapping: manage ML-KEM keypairs at the application layer, use them to wrap AES DEKs, and store the wrapped DEK alongside the encrypted model. This is more operationally complex than KMS-native support but provides protection today.

## Hybrid PQC TLS for Inference Endpoints

The fastest path to HNDL protection for AI inference traffic is deploying hybrid TLS with X25519+ML-KEM-768 on inference endpoints. This requires no changes to inference application code — only changes to the TLS termination layer. Nginx 1.27+ and OpenSSL 3.5 support hybrid PQC key exchange natively.

**Prioritise inference endpoints that receive sensitive data first.** An LLM endpoint serving general question-answering over public information is lower priority than:

- Medical AI endpoints receiving symptom descriptions, lab results, or clinical notes
- Legal AI endpoints receiving draft contracts, litigation strategy, or client communications
- Financial AI endpoints receiving portfolio data, deal terms, or proprietary models
- Code intelligence endpoints receiving proprietary source code

For detailed TLS configuration including Nginx directives, OpenSSL build requirements, and client compatibility considerations, refer to the PQC TLS deployment guide.

**AI SDK client libraries.** Python AI client libraries (the OpenAI Python client, Anthropic SDK, HuggingFace `transformers` and `huggingface_hub`) rely on the underlying `requests` or `httpx` library for TLS. As of mid-2026, `httpx` does not yet natively support PQC cipher suites. The current path for PQC-capable Python AI clients is to route traffic through a local PQC-capable proxy (such as a local nginx instance configured with hybrid cipher suites) or to use Python builds linked against an OpenSSL 3.5 binary that includes ML-KEM support.

JavaScript AI clients face the same constraint: Node.js TLS support follows the OpenSSL version bundled with the Node.js release. Node.js 24+ ships with OpenSSL 3.5 support and will offer hybrid PQC cipher suites once the `tls` module exposes the necessary configuration surface.

## PQC Model Signing with ML-DSA

Model artefact signing transitions from ECDSA to ML-DSA (NIST FIPS 204). The toolchain of choice for OCI artefact signing is cosign, which the Sigstore project is extending with PQC algorithm support.

**Current state.** As of May 2026, the upstream cosign repository has experimental ML-DSA support via the `--key-type ml-dsa-65` flag when linked against liboqs. This is not yet in a stable cosign release but is available in development builds. The practical approach for organisations that need ML-DSA signing today is to use liboqs directly for signing operations outside the standard cosign workflow, or to run a hybrid signing approach where both ECDSA (for current compatibility) and ML-DSA (for future verifiability) signatures are produced and stored.

**Hybrid signing for model artefacts.**

```bash
# Sign model checkpoint with ECDSA (current compatibility)
cosign sign \
  --key ecdsa-key.pem \
  registry.example.com/models/llama-3-70b-finetuned:v1.2.0

# Sign the same artefact with ML-DSA using liboqs tooling
# (using the oqs-provider for openssl)
OPENSSL_CONF=oqs-openssl.cnf openssl dgst \
  -sign ml-dsa-65-private.pem \
  -sigopt provider:oqs \
  -out model-checkpoint.tar.gz.mldsa.sig \
  model-checkpoint.tar.gz

# Store both signatures in the model manifest
```

Attach the ML-DSA signature as an OCI annotation or a side-car file in the model repository alongside the ECDSA cosign signature. Verification pipelines should be updated to check both signatures during the migration period, and to prefer ML-DSA verification once the signature is present.

**Model SBOMs.** CycloneDX SBOMs describing model provenance, training data sources, and component dependencies carry the same signature vulnerability. Apply the same hybrid ECDSA + ML-DSA signing approach to SBOM artefacts. The `cyclonedx-cli` tool supports detached signature files; store the ML-DSA signature alongside the SBOM.

## Training Data Protection

Training datasets containing long-lived sensitive records — medical notes used to fine-tune a clinical model, legal documents used to train a contract analysis model, proprietary source code used to fine-tune a coding assistant — require PQC protection if they are retained beyond the near term.

**Identify retention duration and sensitivity.** Not all training data requires PQC migration. The relevant combination is sensitivity level × expected retention period. A dataset containing anonymised news articles retained for two years carries minimal HNDL risk. A dataset containing de-identified but re-identifiable patient records retained for ten years for audit purposes carries substantial risk.

**Re-encryption for high-risk datasets.** The re-encryption process is operationally straightforward: recover the existing DEK using the current ECDH-based key wrapping, then re-wrap the DEK with ML-KEM using the envelope encryption pattern described above. The bulk data does not need to be re-encrypted — only the key wrapping metadata changes.

```python
def migrate_dataset_key_wrapping(
    existing_wrapped_key: dict,
    existing_ecdh_private_key,
    new_mlkem_public_keys: dict,
) -> dict:
    """
    Unwrap a dataset DEK from classical ECDH wrapping
    and re-wrap with hybrid ML-KEM-768 + X25519.
    """
    # Recover DEK from existing ECDH wrapping
    ecdh_shared_secret = existing_ecdh_private_key.exchange(
        existing_wrapped_key["ephemeral_public"]
    )
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"dataset-key-wrapping",
    )
    old_kek = kdf.derive(ecdh_shared_secret)
    aesgcm = AESGCM(old_kek)
    dek = aesgcm.decrypt(
        existing_wrapped_key["nonce"],
        existing_wrapped_key["wrapped_dek"],
        None,
    )
    
    # Re-wrap with hybrid ML-KEM + X25519
    return wrap_model_dek(dek, new_mlkem_public_keys)
```

**PQC-independent alternatives for sensitive training data.** Where training data is too sensitive to retain at all — even encrypted — consider architectures that avoid centralising the data:

- **Federated learning** trains the model locally at each data source, transmitting only gradient updates rather than raw data. Gradient updates are ephemeral and carry substantially lower HNDL risk than the underlying training corpus.
- **Secure multi-party computation (SMPC)** allows training computations across data held by multiple parties without any party seeing another's data. The communication overhead is significant but eliminates centralised data storage.
- **Synthetic data generation** can replace sensitive training records with synthetic equivalents that preserve statistical properties without containing recoverable PII. Differential privacy guarantees on synthetic generation bound re-identification risk.

These alternatives are PQC-independent in the sense that they reduce the attack surface rather than upgrading its cryptographic protection. For datasets that cannot be restructured, ML-KEM key re-wrapping is the direct path.

## Expected Behaviour After PQC Migration

| AI Asset | PQC Control | HNDL Risk Reduction |
|---|---|---|
| Model weights in object storage | DEK re-wrapped with hybrid ML-KEM-768 + X25519 | High → Low: DEK recovery requires breaking both ML-KEM-768 and X25519 |
| Model downloads | Hybrid PQC TLS (X25519+ML-KEM-768) on registry endpoints | High → Low: TLS key exchange resistant to quantum key recovery |
| Inference API traffic | Hybrid PQC TLS on all inference endpoints | High → Low for sensitive queries |
| Model artefact signatures | Hybrid ECDSA + ML-DSA signing | Medium → Low: ML-DSA signatures are quantum-secure |
| Training data at rest | DEK re-wrapped with hybrid ML-KEM-768 + X25519 | High → Low: matches model weight protection |
| Training data in transit | Hybrid PQC TLS on data pipeline endpoints | High → Low |
| Model SBOMs | Hybrid ECDSA + ML-DSA signatures | Medium → Low |

## Prioritisation Framework

Given the operational scope of full PQC migration across an AI system, a phased approach prioritises the controls with the highest impact and lowest implementation friction.

**Phase 1 — Immediate (weeks): Enable hybrid PQC TLS on all inference and distribution endpoints.**
This requires configuration changes to Nginx or other TLS terminators but no application code changes. All inference endpoints receiving sensitive data, all model registry download endpoints, and all training data pipeline ingress points should move to X25519+ML-KEM-768 cipher suites. This addresses the largest category of HNDL risk (in-transit key exchange) across all asset types simultaneously.

**Phase 2 — Short term (one to three months): Re-wrap stored model DEKs with hybrid ML-KEM.**
Identify all model checkpoints in object storage that use classical key wrapping. For each, perform a key rotation: recover the DEK under the existing scheme, re-wrap with hybrid ML-KEM, and update the key manifest. Prioritise models with the longest expected operational lifespan and those representing the highest R&D investment.

**Phase 3 — Medium term (three to six months): Migrate model signing to hybrid ML-DSA.**
Integrate hybrid ECDSA + ML-DSA signing into the model publishing pipeline. Ensure signature verification pipelines accept and check ML-DSA signatures alongside existing ECDSA signatures.

**Phase 4 — Ongoing: Re-encrypt high-risk training datasets.**
Audit training data retention and re-wrap DEKs for datasets meeting the sensitivity × longevity threshold. Implement PQC-native key wrapping for all new training data ingestion.

## Trade-offs

**ML-KEM encapsulation overhead.** ML-KEM-768 key encapsulation takes approximately 100-200 microseconds on modern server hardware — negligible for model key wrapping, which occurs once at model load time rather than per inference. For inference TLS, the hybrid handshake adds roughly 0.5-1 millisecond compared to X25519-only — acceptable for most applications but worth measuring against latency SLOs.

**Client library support requirements.** Deploying hybrid PQC TLS on inference endpoints requires that clients support the negotiated cipher suite. Clients that cannot negotiate X25519+ML-KEM-768 will fall back to classical-only cipher suites if the server is configured with fallback enabled. Disabling classical-only fallback eliminates the HNDL protection gap but will break older clients. A pragmatic migration path enables hybrid cipher suites with fallback initially, monitors cipher suite negotiation rates, and removes fallback once client fleet coverage is sufficient.

**Operational complexity of dual signing.** Maintaining both ECDSA and ML-DSA signatures for model artefacts doubles the signing key management surface: two key types, two revocation procedures, two verification checks in pipelines. This complexity is temporary — once ML-DSA support is universal in the cosign ecosystem, ECDSA signatures can be deprecated — but the transition period requires explicit process documentation.

**Key size increases.** ML-KEM-768 public keys are 1,184 bytes compared to 32 bytes for X25519. ML-DSA-65 public keys are 1,952 bytes. Neither size increase is significant for storage, but key size affects OCI annotation limits and API payload sizes in some model registry implementations. Verify that your model registry and CI/CD pipelines support the larger key and signature sizes before migration.

## Failure Modes

**Inference latency regression.** Hybrid PQC TLS handshakes increase latency due to larger key exchange messages and additional CPU work for ML-KEM operations. Under high inference load, this can compound into measurable latency increases at the p99 and p999 percentiles. Mitigation: enable TLS session resumption (which skips the key exchange for resumed sessions), measure p99 latency under PQC TLS in a staging environment before production rollout, and baseline CPU utilisation on TLS terminators.

**Model download client incompatibility.** Python `huggingface_hub` and similar model download clients that do not yet support PQC cipher suites will fail to connect if the model registry endpoint no longer offers classical fallback. This will manifest as TLS handshake failures, which may be misattributed to network issues. Mitigation: maintain a compatibility period with classical fallback enabled, monitor negotiation metrics disaggregated by client version, and coordinate client upgrade deadlines with internal ML engineering teams.

**Partial migration creating protection gaps.** The most common failure mode in PQC migrations is partial coverage: inference endpoints are upgraded but model storage key wrapping is not, or model signing is migrated but inference traffic is not. An adversary performing bulk collection does not need every asset — they will collect whatever is accessible unprotected. Mitigation: maintain the threat inventory table as a living document, track migration status per asset class, and define a completion criterion that requires all high-priority assets to be covered before declaring Phase 1 complete.

**Key management for ML-KEM keypairs.** ML-KEM private keys used to unwrap model DEKs are high-value targets. Losing the private key makes the wrapped DEK unrecoverable; exposure of the private key negates HNDL protection for all wrapped DEKs. Store ML-KEM private keys in HSMs where available, or in a secrets manager with audit logging and strict IAM scoping. Implement key rotation schedules that ensure old wrapped DEKs are re-wrapped under new keypairs before the old private keys are decommissioned.
