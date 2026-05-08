---
title: "NIST PQC Standards in Practice: Implementing FIPS 203, 204, and 205 with liboqs and Rust"
description: "NIST finalised ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205) in August 2024. This guide covers what each standard provides, when to use each, and how to implement them with the Open Quantum Safe liboqs library, the Rust pqcrypto crate, and integration patterns for existing cryptographic infrastructure — distinct from the high-level migration strategy in our post-quantum migration guide."
slug: nist-pqc-standards-implementation
date: 2026-05-08
lastmod: 2026-05-08
category: cross-cutting
tags:
  - nist-pqc
  - ml-kem
  - ml-dsa
  - slh-dsa
  - liboqs
personas:
  - security-engineer
  - platform-engineer
article_number: 639
difficulty: Advanced
estimated_reading_time: 14
published: true
layout: article.njk
permalink: /articles/cross-cutting/nist-pqc-standards-implementation/
---

# NIST PQC Standards in Practice: Implementing FIPS 203, 204, and 205 with liboqs and Rust

## Problem

NIST finalised three post-quantum cryptography standards in August 2024, ending a six-year standardisation process. The three standards are not interchangeable — each fills a distinct role in a cryptographic protocol, and selecting the wrong one for a use case will either leave a system exposed or incur unnecessary performance cost.

**FIPS 203 — ML-KEM (formerly CRYSTALS-Kyber)** is a key encapsulation mechanism. It does not sign anything. It allows two parties to establish a shared secret: one party generates a key pair, the other encapsulates a shared secret under the public key, and the key holder decapsulates it. ML-KEM replaces RSA PKCS#1 v1.5 key transport and ECDH key agreement in TLS, SSH, hybrid encryption schemes, and symmetric key wrapping protocols.

**FIPS 204 — ML-DSA (formerly CRYSTALS-Dilithium)** is a digital signature algorithm. It does not establish shared secrets. ML-DSA replaces ECDSA and RSA-PSS in code signing, certificate signing, authentication tokens, document signing, and any protocol requiring non-repudiation.

**FIPS 205 — SLH-DSA (formerly SPHINCS+)** is a stateless hash-based signature scheme. Like ML-DSA it only signs. It does not use lattice mathematics — its security rests entirely on the preimage resistance and collision resistance of the underlying hash function (SHA-256 or SHAKE). This makes it the most cryptographically conservative option among the three standards, at the cost of larger signatures and slower signing.

The implementation landscape has consolidated around several production-ready libraries. **liboqs** (Open Quantum Safe) is a C library providing all three standards through a consistent API, with official bindings for Python, Go, Rust, and Java. **pqcrypto** is a Rust crate wrapping liboqs and other PQC implementations with a safe, idiomatic Rust interface. **OpenSSL 3.5** ships with an OQS provider that exposes ML-KEM and ML-DSA through the standard EVP API. **BoringSSL** (Google's TLS fork) has integrated ML-KEM for Chrome's TLS stack. These options let teams integrate PQC into existing OpenSSL, Rust, or Python codebases without writing bindings to new C libraries from scratch.

The algorithm selection problem is the main source of confusion for practitioners starting PQC migrations. ML-KEM, ML-DSA, and SLH-DSA solve different problems, have very different performance profiles, and operate under different security assumptions. This article maps each standard to its appropriate use cases, shows the library calls for each, documents the expected output sizes, and covers the failure modes specific to PQC implementations.

## Threat Model

**Cryptanalytic advance against lattice algorithms.** ML-KEM (FIPS 203) and ML-DSA (FIPS 204) are both built on Module Learning With Errors (Module-LWE) and related Module-SIS problems. These have not been broken. However, lattice cryptanalysis is an active research area and the best known attacks have improved incrementally since CRYSTALS-Kyber was first submitted in 2017. NIST selected parameter sets with significant security margins above the 128-bit, 192-bit, and 256-bit classical security levels, but a breakthrough in lattice reduction algorithms could compress those margins. SLH-DSA is immune to this threat because it does not use lattice mathematics.

**Harvest now, decrypt later attacks on key exchange.** Adversaries with large-scale passive surveillance capability are capturing encrypted traffic today, expecting to decrypt it against a future cryptographically-relevant quantum computer. Data encrypted using ECDH-only key exchange is vulnerable to retroactive decryption. ML-KEM hybrid constructions close this window for sessions established from the transition date forward. Signed data is not directly vulnerable to harvest-now-decrypt-later — a quantum computer can forge future signatures, not retroactively forge past ones — but certificates and trust anchors signed with classical algorithms remain valid concerns for long-lived trust hierarchies.

**Implementation bugs in new PQC code.** RSA and ECDSA implementations have decades of review, fuzzing, and side-channel hardening behind them. ML-KEM and ML-DSA are orders of magnitude younger. Implementation errors are more likely, test coverage is thinner, and the security community's experience identifying subtle bugs in these implementations is limited. Using well-audited library implementations (liboqs, pqcrypto) rather than implementing the standards directly is essential. Even well-maintained libraries require careful API usage to avoid misuse.

**Side-channel attacks.** ML-KEM decapsulation and ML-DSA signing both involve polynomial arithmetic that can leak key material through timing differences if not implemented with constant-time discipline. The liboqs library implements constant-time arithmetic for its supported algorithms, but callers must not conditionally branch on intermediate results, compare secret-derived values with early-exit comparisons, or serialize secret polynomials through non-constant-time paths.

**Access level:** Adversary 1 (cryptanalytic) requires no access — it operates at the mathematical level against deployed ciphertext or signatures. Adversary 2 (harvest now) is a passive network adversary. Adversary 3 (implementation attack) requires the ability to observe timing or power consumption of cryptographic operations, typically on shared infrastructure or with physical access.

## Configuration

### Algorithm Selection Guide

The three standards are not substitutable. Use this table to map your use case to the correct algorithm and parameter set.

| Use Case | Algorithm | Parameter Set | Rationale |
|---|---|---|---|
| TLS key exchange (primary) | ML-KEM | ML-KEM-768 | FIPS 203 Category 3 (≥192-bit classical equivalent). Recommended by NIST for general use. |
| TLS key exchange (hybrid) | ML-KEM + X25519 | ML-KEM-768 + X25519 | Combines PQC and classical security. Protects against both quantum and lattice breaks. |
| Code/document signing (performance) | ML-DSA | ML-DSA-65 | FIPS 204 Category 3. Fast signing and verification, small-enough signatures for most protocols. |
| Code/document signing (conservative) | SLH-DSA | SLH-DSA-SHAKE-128s | FIPS 205. No lattice assumption. Use when maximising long-term trust is more important than performance. |
| Long-term archival signatures (>10 years) | SLH-DSA | SLH-DSA-SHAKE-128s or 256s | Hash-based security assumptions will outlast lattice assumptions in most failure scenarios. |
| Certificate Authority key signing | ML-DSA | ML-DSA-87 | FIPS 204 Category 5 (≥256-bit classical equivalent). CA keys warrant higher-category protection. |
| End-entity certificate signing | ML-DSA | ML-DSA-65 | Category 3 sufficient for leaf certificates with short validity periods. |
| Authentication tokens (JWTs, PASETO) | ML-DSA | ML-DSA-65 | Replaces RS256/ES256. Token size increases but remains manageable. |

**Rules of thumb:**

- Never use ML-KEM for signing. Never use ML-DSA or SLH-DSA for key exchange. The algorithms are purpose-built.
- Default to ML-KEM-768 and ML-DSA-65 (both Category 3) for general use. Category 5 variants add 30–50% overhead for most operations.
- Use SLH-DSA only when the hash-based security property justifies the size and performance penalty. For signing that needs to remain valid in 2070+, SLH-DSA is the conservative choice.
- Always deploy ML-KEM in hybrid mode during the transition period. Hybrid protects against cryptanalytic regression in either the classical or PQC component.

### Key Sizes and Performance Reference

Concrete numbers are necessary for capacity planning. These are for the primary parameter sets, measured on a modern x86-64 system running liboqs 0.10.x. Operations per second are approximate and will vary with CPU generation and compiler flags.

| Algorithm | Public Key | Private Key | Sig / Ciphertext | Sign ops/s | Verify ops/s |
|---|---|---|---|---|---|
| ML-KEM-512 | 800 B | 1,632 B | 768 B (ciphertext) | ~20,000 KeyGen | ~20,000 Decap |
| ML-KEM-768 | 1,184 B | 2,400 B | 1,088 B (ciphertext) | ~14,000 KeyGen | ~14,000 Decap |
| ML-KEM-1024 | 1,568 B | 3,168 B | 1,568 B (ciphertext) | ~10,000 KeyGen | ~10,000 Decap |
| ML-DSA-44 | 1,312 B | 2,528 B | 2,420 B | ~6,000 | ~2,800 |
| ML-DSA-65 | 1,952 B | 4,000 B | 3,309 B | ~3,800 | ~1,900 |
| ML-DSA-87 | 2,592 B | 4,864 B | 4,627 B | ~2,800 | ~1,400 |
| SLH-DSA-SHAKE-128s | 32 B | 64 B | 7,856 B | ~50 | ~2,000 |
| SLH-DSA-SHAKE-128f | 32 B | 64 B | 17,088 B | ~4,000 | ~180 |
| SLH-DSA-SHAKE-256s | 64 B | 128 B | 29,792 B | ~5 | ~500 |
| ECDSA P-256 (reference) | 64 B | 32 B | 64 B | ~30,000 | ~12,000 |
| X25519 (reference) | 32 B | 32 B | — | ~40,000 DH ops | — |

SLH-DSA has tiny public and private keys (hash-based construction) but very large signatures. SLH-DSA-SHAKE-128s (the "s" suffix means "small" signature) is the right variant when signature size is tolerable but key storage is constrained. SLH-DSA-SHAKE-128f (the "f" suffix means "fast" signing) trades a much larger signature for dramatically faster key generation and signing — use it in high-throughput signing scenarios where 17KB signatures are acceptable.

### ML-KEM Implementation with liboqs (Python)

Install the Python wrapper: `pip install liboqs-python`. The liboqs shared library must be built and available on the system — follow the [Open Quantum Safe build instructions](https://github.com/open-quantum-safe/liboqs) to compile it from source or use a pre-built package.

```python
import oqs

# --- Key generation (recipient) ---
kem = oqs.KeyEncapsulation("ML-KEM-768")
public_key = kem.generate_keypair()  # returns public key bytes; private key is held inside kem

# --- Encapsulation (sender) ---
# Sender creates a fresh KEM instance; they do NOT have the private key
kem_sender = oqs.KeyEncapsulation("ML-KEM-768")
ciphertext, shared_secret_sender = kem_sender.encap_secret(public_key)
# ciphertext is 1,088 bytes; shared_secret_sender is 32 bytes

# --- Decapsulation (recipient) ---
shared_secret_recipient = kem.decap_secret(ciphertext)

# shared_secret_sender == shared_secret_recipient
# Both sides now have the same 32-byte shared secret
# Derive a symmetric key from it: shared_secret = HKDF(shared_secret, salt, info)

kem.free()
kem_sender.free()
```

The shared secret output from ML-KEM-768 is a 32-byte pseudorandom value. It is not itself a symmetric key — pass it through HKDF with appropriate context (application name, protocol version, session identifiers) to derive the actual AES-256 or ChaCha20-Poly1305 key.

### Hybrid KEM Construction

During the transition period, run ML-KEM in parallel with X25519. This protects against a break in either algorithm. IETF RFC 9180 (HPKE) and the IETF hybrid KEM draft describe the standard construction, but the core pattern is straightforward:

```python
import oqs
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Recipient generates both keypairs
mlkem = oqs.KeyEncapsulation("ML-KEM-768")
mlkem_pub = mlkem.generate_keypair()

x25519_priv = X25519PrivateKey.generate()
x25519_pub = x25519_priv.public_key()

# Sender: encapsulate under both keys
kem_sender = oqs.KeyEncapsulation("ML-KEM-768")
mlkem_ct, mlkem_ss = kem_sender.encap_secret(mlkem_pub)

x25519_ephemeral = X25519PrivateKey.generate()
x25519_ss = x25519_ephemeral.exchange(x25519_pub)

# Combine shared secrets using HKDF
combined = mlkem_ss + x25519_ss  # concatenate both 32-byte secrets
session_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"hybrid-kem-v1",
).derive(combined)
# session_key is the derived symmetric key — neither secret alone suffices
```

A break in X25519 (from a cryptographically-relevant quantum computer) cannot recover the session key without also breaking ML-KEM. A break in ML-KEM (from a lattice cryptanalysis advance) cannot recover the session key without also breaking X25519. This is the security property hybrid constructions exist to provide.

### ML-DSA Implementation with Rust pqcrypto

Add the dependency to `Cargo.toml`:

```toml
[dependencies]
pqcrypto-mldsa = "0.1"
pqcrypto-traits = "0.3"
```

```rust
use pqcrypto_mldsa::mldsa65::{detached_sign, open, keypair, PublicKey, SecretKey};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as PK, SecretKey as SK};

fn sign_and_verify(message: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Key generation
    let (pk, sk) = keypair();

    // Signing — returns a DetachedSignature (not prepended to message)
    let signature = detached_sign(message, &sk);

    // Verification — returns Ok(()) or Err
    pqcrypto_mldsa::mldsa65::verify_detached_signature(&signature, message, &pk)?;

    // Serialise public key for distribution (e.g., embed in certificate)
    let pk_bytes: &[u8] = pk.as_bytes();   // 1,952 bytes for ML-DSA-65
    let sig_bytes: &[u8] = signature.as_bytes(); // 3,309 bytes for ML-DSA-65

    println!("Public key: {} bytes", pk_bytes.len());
    println!("Signature:  {} bytes", sig_bytes.len());
    Ok(())
}
```

The `pqcrypto_mldsa::mldsa65` module corresponds to ML-DSA-65 (FIPS 204 Category 3). Use `mldsa44` or `mldsa87` for the other parameter sets. The API is identical across parameter sets.

For signing where the private key is stored on disk:

```rust
use std::fs;

fn load_and_sign(key_path: &str, message: &[u8]) -> Vec<u8> {
    let sk_bytes = fs::read(key_path).expect("failed to read key");
    let sk = SecretKey::from_bytes(&sk_bytes).expect("invalid key bytes");
    let sig = detached_sign(message, &sk);
    sig.as_bytes().to_vec()
}
```

### SLH-DSA for Long-Term Archival Signatures

SLH-DSA should be evaluated for any signature that needs to remain verifiable and trustworthy beyond a 10-year horizon, or in any context where the hash-based security property is explicitly required by compliance framework or threat model.

With liboqs Python:

```python
import oqs

# SLH-DSA — liboqs uses the SPHINCS+ names for the algorithm strings
# SLH-DSA-SHAKE-128s maps to "SPHINCS+-SHAKE-128s" in liboqs 0.10.x
signer = oqs.Signature("SPHINCS+-SHAKE-128s")
public_key = signer.generate_keypair()

message = b"archive document requiring 50-year signature validity"

# Sign
signature = signer.sign(message)
print(f"Signature size: {len(signature)} bytes")  # ~7,856 bytes

# Verify (can use a fresh instance with just the public key)
verifier = oqs.Signature("SPHINCS+-SHAKE-128s")
is_valid = verifier.verify(message, signature, public_key)
print(f"Valid: {is_valid}")  # True

signer.free()
verifier.free()
```

Note that liboqs 0.10.x uses the SPHINCS+ algorithm string names internally even though the FIPS 205 standard name is SLH-DSA. The algorithm string `"SPHINCS+-SHAKE-128s"` is the FIPS 205 SLH-DSA-SHAKE-128s algorithm. Check the liboqs changelog for each release — the naming convention will align with FIPS 205 nomenclature in future releases.

**When to choose SLH-DSA over ML-DSA:**

- Signatures on root CA certificates or long-lived trust anchors where the validity period extends into a future where lattice security assumptions may have weakened.
- Archival signatures on legal, regulatory, or medical records that must remain non-repudiable for 20+ years.
- High-security contexts where the threat model explicitly includes a potential future lattice break, and performance is less critical than maximum conservatism.
- FIPS compliance scenarios that require using a non-lattice-based signature algorithm as a hedge.

**When to prefer ML-DSA:**

- Any interactive protocol where signing latency matters — ML-DSA-65 is roughly 75x faster than SLH-DSA-SHAKE-128s for signing.
- Protocols with message size constraints where a 7.8KB signature would create unacceptable overhead (TLS handshakes, JWT tokens, DNS records).
- General-purpose code signing, software update signatures, and authentication tokens where a 10-year security horizon is sufficient.

### Integration with OpenSSL 3.5

OpenSSL 3.5 supports ML-KEM and ML-DSA through the `oqsprovider` — a dynamically loadable provider that exposes PQC algorithms through the standard EVP API.

**Build and configure liboqs-provider:**

```bash
# Build liboqs first
git clone https://github.com/open-quantum-safe/liboqs.git
cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON
cmake --build liboqs/build --parallel $(nproc)
sudo cmake --install liboqs/build

# Build oqsprovider against OpenSSL 3.5
git clone https://github.com/open-quantum-safe/oqs-provider.git
cmake -S oqs-provider -B oqs-provider/build \
    -Dliboqs_DIR=/usr/local/lib/cmake/liboqs \
    -DOPENSSL_ROOT_DIR=$(openssl version -d | cut -d' ' -f2 | tr -d '"')
cmake --build oqs-provider/build --parallel $(nproc)
sudo cmake --install oqs-provider/build
```

Configure OpenSSL to load the provider by adding to `openssl.cnf`:

```ini
[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
module = /usr/local/lib/oqsprovider.so
```

**Generate an ML-DSA-65 self-signed certificate:**

```bash
# Generate a self-signed ML-DSA-65 certificate
openssl req -new -x509 \
    -provider oqsprovider \
    -algorithm mldsa65 \
    -subj "/CN=example.com/O=Example/C=US" \
    -days 365 \
    -out mldsa65_cert.pem \
    -keyout mldsa65_key.pem

# Inspect the certificate
openssl x509 -in mldsa65_cert.pem -text -noout | grep "Public Key Algorithm"
# Public Key Algorithm: ML-DSA-65
```

**Use ML-KEM in a TLS server (hybrid mode):**

```bash
# Configure a test TLS server with ML-KEM-768 key exchange
openssl s_server \
    -provider oqsprovider \
    -cert server_cert.pem \
    -key server_key.pem \
    -groups mlkem768 \
    -port 4433

# Client connecting with ML-KEM-768 preference
openssl s_client \
    -provider oqsprovider \
    -connect localhost:4433 \
    -groups mlkem768:X25519 \
    -brief
```

The `-groups` flag specifies the key exchange group preference order. Specifying both `mlkem768` and `X25519` allows negotiation of the hybrid `mlkem768:X25519` group supported by OpenSSL's IETF draft hybrid extension.

### Testing PQC Implementations

**NIST ACVP test vectors.** The NIST Automated Cryptographic Validation Program publishes Known Answer Test (KAT) vectors for ML-KEM, ML-DSA, and SLH-DSA. These vectors are authoritative: if your implementation produces the correct output for the ACVP test cases, the algorithm is correctly implemented. Run KATs as part of the build process, not just in CI.

```python
import json
import oqs

# Load ML-KEM-768 KAT vectors from NIST ACVP
with open("ml-kem-768-kat.json") as f:
    vectors = json.load(f)

for vec in vectors["testGroups"][0]["tests"]:
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=bytes.fromhex(vec["dk"]))
    shared_secret = kem.decap_secret(bytes.fromhex(vec["c"]))
    assert shared_secret.hex() == vec["k"], f"KAT failure at vector {vec['tcId']}"
    kem.free()

print("All ML-KEM-768 KAT vectors passed")
```

**Constant-time verification.** ML-KEM decapsulation must execute in constant time regardless of whether the ciphertext is valid. A timing difference between valid and invalid ciphertext decapsulation would allow an adaptive attack to recover the private key. The liboqs implementations use constant-time comparison throughout, but integration code must not add conditional branches that depend on the shared secret value. Test for timing leakage using a dudect-style statistical test against a corpus of valid and invalid ciphertexts.

**Interoperability testing.** Generate test keys and signatures with liboqs and verify them with BoringSSL's PQC implementation (and vice versa). ML-KEM and ML-DSA implementations must produce identical results given the same randomness — the algorithms are deterministic given the key and message. Any deviation indicates an incompatible implementation.

## Expected Behaviour

| Algorithm | Operation | Library Call | Input | Output |
|---|---|---|---|---|
| ML-KEM-768 | Key generation | `kem.generate_keypair()` | — | 1,184 B public key |
| ML-KEM-768 | Encapsulation | `kem.encap_secret(pk)` | 1,184 B public key | 1,088 B ciphertext + 32 B shared secret |
| ML-KEM-768 | Decapsulation | `kem.decap_secret(ct)` | 1,088 B ciphertext | 32 B shared secret |
| ML-DSA-65 | Key generation | `keypair()` | — | 1,952 B public key + 4,000 B private key |
| ML-DSA-65 | Sign | `detached_sign(msg, sk)` | Message bytes | 3,309 B signature |
| ML-DSA-65 | Verify | `verify_detached_signature(sig, msg, pk)` | Signature + message + public key | `Ok(())` or error |
| SLH-DSA-SHAKE-128s | Key generation | `signer.generate_keypair()` | — | 32 B public key + 64 B private key |
| SLH-DSA-SHAKE-128s | Sign | `signer.sign(msg)` | Message bytes | 7,856 B signature |
| SLH-DSA-SHAKE-128s | Verify | `verifier.verify(msg, sig, pk)` | Message + signature + public key | `True` or `False` |

A decapsulation with an incorrect ciphertext returns a pseudorandom value indistinguishable from a valid shared secret — this is a property of ML-KEM's implicit rejection mechanism, which prevents chosen-ciphertext attacks. Callers must not branch on the shared secret value to determine whether decapsulation succeeded. Verification of an ML-DSA or SLH-DSA signature returns a clear error on failure — treat any non-success result as a hard failure, not a degraded path.

## Trade-offs

**Key and signature sizes vs. classical algorithms.** ML-KEM-768 public keys (1,184 bytes) are 18x larger than X25519 public keys (32 bytes). ML-DSA-65 signatures (3,309 bytes) are 51x larger than ECDSA P-256 signatures (64 bytes). These sizes matter for protocols with packet-size constraints (DNS, Bluetooth, constrained IoT), certificate chain embedding, and any storage system that accumulates large numbers of signatures. Protocols that were designed with 2048-bit RSA keys (256 bytes) as the worst-case size may need buffer resizing to accommodate PQC.

**Lattice vs. hash-based security assumptions.** ML-KEM and ML-DSA rest on the hardness of Module-LWE and Module-SIS problems — structured variants of the Learning With Errors problem. These are well-studied but younger than the number-theoretic problems underlying RSA and ECC, and lattice cryptanalysis is advancing. SLH-DSA rests only on the preimage resistance and collision resistance of SHA-256 or SHAKE — properties that have been analysed for decades and are not threatened by quantum computers running Grover's algorithm at any realistic scale. The trade-off is concrete: SLH-DSA-SHAKE-128s signing is roughly 75x slower than ML-DSA-65, and its signatures are 2.4x larger.

**Performance characteristics.** ML-KEM encapsulation and decapsulation are fast — comparable to RSA-2048 operations on modern hardware. ML-DSA signing and verification are slower than ECDSA but fast enough for most use cases. SLH-DSA is the outlier: SLH-DSA-SHAKE-128s generates only ~50 signatures per second and SLH-DSA-SHAKE-256s generates roughly 5 per second. This is not a suitable performance profile for authentication tokens, TLS handshakes, or any high-throughput signing path. SLH-DSA is appropriate for operations that happen at human-scale frequency (signing a release artifact, issuing a certificate) but not for machine-scale frequency (signing every API request).

**Hybrid construction overhead.** Running ML-KEM in hybrid with X25519 adds a second DH operation per session but the combined shared secret derivation through HKDF is negligible. Total handshake size increases by roughly 1,200 bytes (for ML-KEM-768 ciphertext). For most TLS use cases this is acceptable. For protocols where every byte is constrained, measure the impact before committing to hybrid mode.

## Failure Modes

**Algorithm parameter set mismatch.** ML-KEM-512, ML-KEM-768, and ML-KEM-1024 produce incompatible key pairs and ciphertexts. A public key generated with ML-KEM-768 cannot be used with an ML-KEM-512 context — the library will return an error, but only at encapsulation time. If parameter set selection is done dynamically (read from a configuration file, negotiated in a protocol), a mismatch that slips through configuration validation will produce a runtime error during key exchange. Enforce parameter set validation at key generation time and include the parameter set identifier in key storage alongside the raw key bytes.

**Non-constant-time integration code.** liboqs implements constant-time arithmetic internally, but application code wrapping the library can introduce timing channels. Common mistakes: comparing the returned shared secret against an expected value with a short-circuit comparison (`==` on `bytes` in Python uses constant-time comparison since 3.x, but memcmp in C does not), logging or conditionally branching on the number of bytes returned, and measuring operation time per request and returning it to callers. Audit any code that touches raw shared secret or signature material before it has been hashed or processed into a derived key.

**liboqs API misuse leading to key reuse.** The liboqs Python API stores the private key inside the `KeyEncapsulation` object. Calling `generate_keypair()` on an existing object replaces the key. Calling `decap_secret()` after `free()` will crash. Applications that share a single `KeyEncapsulation` instance across threads without synchronisation will corrupt the internal state. Treat `KeyEncapsulation` objects as non-thread-safe by default and create per-thread or per-session instances.

**SLH-DSA algorithm name mismatch in liboqs.** The liboqs algorithm string identifiers for SLH-DSA use the legacy SPHINCS+ naming convention in releases prior to full FIPS 205 naming alignment. Passing `"SLH-DSA-SHAKE-128s"` as the algorithm name will raise a `MechanismNotSupported` error in liboqs 0.10.x — use `"SPHINCS+-SHAKE-128s"` instead. Check the `oqs.get_enabled_sig_mechanisms()` output for the exact strings supported by your installed version.

**Missing entropy at key generation.** ML-KEM and ML-DSA key generation is randomised. Calling `generate_keypair()` in an environment with a weak or deterministic PRNG (common in early-boot stages, virtualised environments at snapshot time, or container images that share an initial entropy state) will produce weak keys. Verify that `/dev/urandom` is seeded before generating PQC key pairs. In containerised environments, use the Linux `getrandom()` syscall directly rather than relying on early-boot `/dev/urandom` reads.

**Storing ML-KEM private keys alongside public keys.** A private key leak in a KEM breaks forward secrecy for all sessions where that key pair was used. Unlike ECDH ephemeral keys (generated fresh per session), a static ML-KEM key pair that is reused for many sessions creates a forward-secrecy risk. For TLS, always use ML-KEM ephemerally — generate a new key pair per connection. Static ML-KEM keys are appropriate for asymmetric encryption (e.g., encrypting a stored secret to a recipient's long-term key) but not for key exchange in interactive protocols.
