---
title: "Post-Quantum Cryptography in WASM: Migration Readiness for WebAssembly Deployments"
description: "WASM deployments using RSA or ECDH key exchange are vulnerable to harvest-now-decrypt-later attacks. This guide covers compiling NIST-standardised PQC algorithms (ML-KEM, ML-DSA) to WASM, WASI Crypto's PQC roadmap, performance implications of PQC in constrained WASM environments, and migration strategies for WASM-based TLS and signing."
slug: wasm-post-quantum-cryptography
date: 2026-05-07
lastmod: 2026-05-07
category: wasm
tags:
  - wasm
  - post-quantum
  - pqc
  - cryptography
  - migration
personas:
  - security-engineer
  - platform-engineer
article_number: 594
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/wasm/wasm-post-quantum-cryptography/
---

# Post-Quantum Cryptography in WASM: Migration Readiness for WebAssembly Deployments

## Problem

WebAssembly deployments increasingly handle sensitive key exchange and digital signatures across edge networks, serverless runtimes, plugin sandboxes, and browser-based clients. The cryptographic primitives in use — RSA for key transport, ECDH for ephemeral key agreement, ECDSA for signing — are computationally secure against classical computers. Against a sufficiently large quantum computer running Shor's algorithm, they are not.

The relevant threat is not that quantum computers can currently break these algorithms. They cannot. The threat is harvest-now-decrypt-later (HNDL): an adversary records encrypted traffic today and stores it, waiting for quantum capability to arrive before decrypting. For WASM deployments that protect long-lived secrets — session tokens that authenticate API keys, encrypted configuration passed between microservices, signed firmware distributed over the air — the confidentiality window extends years into the future. If the data must remain secret in 2035, the key exchange protecting it must be quantum-resistant today.

NIST completed its post-quantum cryptography standardisation process in August 2024, publishing three standards:

- **FIPS 203 (ML-KEM)** — Module-Lattice-Based Key Encapsulation Mechanism, formerly CRYSTALS-Kyber. Used for key establishment.
- **FIPS 204 (ML-DSA)** — Module-Lattice-Based Digital Signature Algorithm, formerly CRYSTALS-Dilithium. Used for digital signatures.
- **FIPS 205 (SLH-DSA)** — Stateless Hash-Based Digital Signature Algorithm, formerly SPHINCS+. Hash-based signatures as an alternative security assumption.

These algorithms are now the authoritative choice for quantum-resistant cryptography. The migration question is not whether to adopt them, but how to deploy them in WASM environments where code size, startup latency, SIMD availability, and WASI support surface all constrain implementation choices in ways they do not on native server targets.

**Target systems:** Wasmtime 25+, WasmEdge 0.14+, Spin 2.8+, browser WASM (Chrome 120+, Firefox 120+), any Rust-to-WASM pipeline using `rustls`, `ring`, or hand-rolled key exchange.

## Threat Model

- **Adversary 1 — HNDL attacker against long-lived data:** An adversary captures TLS session establishment traffic from a WASM-based edge service today. The session key is derived via ECDH (P-256 or X25519). The attacker stores the ciphertext. In 10–15 years, with access to a cryptographically relevant quantum computer, they run Shor's algorithm against the captured key exchange and recover the session key, decrypting all traffic from that session.
- **Adversary 2 — Signature forgery against ECDSA-signed artifacts:** A WASM plugin distribution system uses ECDSA signatures to authenticate modules. An adversary with a quantum computer breaks the ECDSA signing key and produces forged signatures for malicious WASM modules that pass existing verification.
- **Adversary 3 — Targeted high-value session interception:** An adversary with current quantum capability (assumed feasible for nation-state actors by the early 2030s in some projections) intercepts TLS traffic to a high-value WASM deployment and decrypts it in near-real time using a large-scale quantum computer.
- **Adversary 4 — Supply chain substitution:** A WASM crypto library shipped via npm or crates.io includes PQC primitives compiled from a subtly backdoored upstream. The attacker relies on operators not verifying the compiled WASM binary against a trusted source.
- **Access level:** Adversary 1 requires only network-level traffic capture (feasible for ISPs, cloud providers, or on-path attackers). Adversary 2 requires breaking the signing key offline. Adversary 3 requires quantum hardware. Adversary 4 requires supply chain access.
- **Objective:** Recover plaintexts encrypted under classical key exchange, forge signatures on WASM artifacts, or undermine the integrity of PQC migrations through supply chain compromise.
- **Blast radius:** HNDL affects all past sessions captured under classical key exchange. Signature forgery affects all future plugin or firmware distribution. Supply chain substitution affects all deployments consuming the compromised library.

## Configuration

### Step 1: Audit Current Key Exchange in WASM Deployments

Before deploying PQC, establish a complete inventory of classical cryptographic operations in your WASM codebase. Key exchange is the highest-priority target for migration because of HNDL; signing can follow, but classical signatures are not vulnerable to harvest-now attacks.

Audit checklist:

- WASM modules using `ring::agreement` (ECDH P-256, X25519) for key derivation
- Modules using `rustls` as a WASM-compiled crate for TLS termination
- Modules calling RSA encrypt/decrypt via `rsa` or `openssl` compiled to WASM
- ECDSA signing in Rust WASM modules using `p256::ecdsa` or `k256::ecdsa`
- Any WASM plugin that accepts or generates JWTs with `RS256`, `ES256`, or `ES384` algorithms

Search the compiled WASM binary for function imports and table entries that reference classical key exchange:

```bash
# wasm-objdump from the WABT toolkit lists all imported and exported functions.
wasm-objdump -x ./plugin.wasm | grep -E "(agreement|ecdh|rsa_|ecdsa)"

# For Rust WASM binaries, inspect the name section to identify classical crypto symbols.
wasm-objdump --section=name ./plugin.wasm | grep -iE "(kyber|ecdh|p256|rsa|x25519)"
```

For modules linked against `ring`, check the Cargo.lock for the version and audit whether the ring version in use includes the ECDH agreement API:

```bash
grep -A 3 'name = "ring"' Cargo.lock
```

Categorise each finding by data sensitivity and longevity:

| Data type | Sensitivity | Longevity | HNDL priority |
|---|---|---|---|
| Ephemeral session keys | High | Minutes | Low — short window |
| API signing keys | Critical | Years | High |
| Firmware encryption keys | Critical | Decades | Critical |
| Config encryption | High | Months–years | High |
| Plugin signature verification | High | Until key rotation | High |

Prioritise long-lived keys for immediate migration. Short-lived ephemeral keys (TLS sessions lasting seconds) have a much smaller exposure window.

### Step 2: Compile liboqs and pqclean to WASM

Two mature libraries provide PQC primitives suitable for WASM compilation.

**liboqs** (Open Quantum Safe) is a C library implementing ML-KEM, ML-DSA, SLH-DSA, and several other NIST candidates. It compiles to WASM via Emscripten:

```bash
# Clone liboqs.
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs

# Configure for WASM build with Emscripten.
# Disable KEMs and sig schemes not needed to reduce binary size.
emcmake cmake -B build \
  -DOQS_ENABLE_KEM_ml_kem_768=ON \
  -DOQS_ENABLE_SIG_ml_dsa_65=ON \
  -DOQS_ENABLE_SIG_slh_dsa_shake_128s=ON \
  -DOQS_ENABLE_KEM_ml_kem_512=OFF \
  -DOQS_ENABLE_KEM_ml_kem_1024=OFF \
  -DOQS_USE_OPENSSL=OFF \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DCMAKE_BUILD_TYPE=Release

emmake make -C build -j$(nproc)
# Output: build/lib/liboqs.a — link this into your WASM module.
```

**pqclean** as a Rust crate (`pqcrypto`) provides a safer Rust API wrapping the pqclean C implementations:

```toml
# Cargo.toml
[dependencies]
pqcrypto-mlkem = { version = "0.1", default-features = false, features = ["std"] }
pqcrypto-mldsa = { version = "0.1", default-features = false, features = ["std"] }
pqcrypto-traits = "0.3"

[target.'cfg(target_arch = "wasm32")'.dependencies]
getrandom = { version = "0.2", features = ["js"] }   # Browser WASM.
```

```rust
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{PublicKey, SecretKey, Ciphertext, SharedSecret};

pub fn generate_ml_kem_keypair() -> (mlkem768::PublicKey, mlkem768::SecretKey) {
    mlkem768::keypair()
}

pub fn encapsulate(pk: &mlkem768::PublicKey) -> (mlkem768::Ciphertext, mlkem768::SharedSecret) {
    mlkem768::encapsulate(pk)
}

pub fn decapsulate(ct: &mlkem768::Ciphertext, sk: &mlkem768::SecretKey) -> mlkem768::SharedSecret {
    mlkem768::decapsulate(ct, sk)
}
```

**oqs-rs** provides Rust bindings to liboqs when you need algorithms not yet in pqcrypto:

```toml
[dependencies]
oqs = { version = "0.9", features = ["ml-kem", "ml-dsa"] }
```

```rust
use oqs::kem::{self, Algorithm as KemAlg};
use oqs::sig::{self, Algorithm as SigAlg};

pub fn kem_example() -> Result<(), oqs::Error> {
    let kem = kem::Kem::new(KemAlg::MlKem768)?;
    let (pk, sk) = kem.keypair()?;
    let (ct, ss_enc) = kem.encapsulate(&pk)?;
    let ss_dec = kem.decapsulate(&sk, &ct)?;
    assert_eq!(ss_enc.as_ref(), ss_dec.as_ref());
    Ok(())
}

pub fn sig_example() -> Result<(), oqs::Error> {
    let sig = sig::Sig::new(SigAlg::MlDsa65)?;
    let (pk, sk) = sig.keypair()?;
    let message = b"sign this WASM artifact";
    let signature = sig.sign(message, &sk)?;
    sig.verify(message, &signature, &pk)?;
    Ok(())
}
```

Build the WASM target with SIMD enabled to get lattice arithmetic acceleration:

```toml
# .cargo/config.toml
[target.wasm32-wasip2]
rustflags = ["-C", "target-feature=+simd128,+bulk-memory"]

[target.wasm32-unknown-unknown]
rustflags = ["-C", "target-feature=+simd128,+bulk-memory"]
```

### Step 3: Performance of PQC in WASM — Expectations and Benchmarks

PQC algorithms have different performance characteristics from their classical equivalents. The differences are particularly relevant in constrained WASM environments such as edge workers with cold-start penalties, browser WASM with limited heap, and IoT WASM runtimes without hardware acceleration.

**Key size comparison:**

| Algorithm | Public key | Private key | Ciphertext / Signature |
|---|---|---|---|
| X25519 (ECDH) | 32 bytes | 32 bytes | 32 bytes (shared secret) |
| ML-KEM-512 | 800 bytes | 1,632 bytes | 768 bytes |
| ML-KEM-768 | 1,184 bytes | 2,400 bytes | 1,088 bytes |
| ML-KEM-1024 | 1,568 bytes | 3,168 bytes | 1,568 bytes |
| P-256 (ECDSA) | 64 bytes | 32 bytes | 64 bytes (signature) |
| ML-DSA-44 | 1,312 bytes | 2,528 bytes | 2,420 bytes |
| ML-DSA-65 | 1,952 bytes | 4,000 bytes | 3,293 bytes |
| SLH-DSA-SHAKE-128s | 32 bytes | 64 bytes | 7,856 bytes |

These key sizes affect WASM deployments at every layer: they increase TLS handshake size (impacting latency at cold start), grow the memory footprint of key stores, and add transfer overhead when WASM modules export or import public keys as part of their protocol.

**Operation count and latency (approximate, Wasmtime on x86-64 without SIMD):**

| Algorithm | Operation | Approximate time |
|---|---|---|
| X25519 | Key exchange | ~50 µs |
| ML-KEM-768 | Keypair gen | ~200 µs |
| ML-KEM-768 | Encapsulate | ~210 µs |
| ML-KEM-768 | Decapsulate | ~220 µs |
| ML-DSA-65 | Keypair gen | ~600 µs |
| ML-DSA-65 | Sign | ~900 µs |
| ML-DSA-65 | Verify | ~350 µs |

ML-KEM key exchange is roughly 4-5x slower than X25519 in pure WASM without SIMD. For server-side WASM handling thousands of handshakes per second, this can be significant. For browser WASM performing a single key exchange per page load, it is imperceptible.

WASM SIMD128 reduces lattice arithmetic cost substantially. Polynomial multiplication — the core of ML-KEM and ML-DSA — maps naturally onto SIMD vector operations. Enable SIMD for all PQC WASM targets:

```bash
# Benchmark with and without SIMD to quantify improvement on your target runtime.
wasm-pack build --target nodejs -- --features simd
node bench/run_bench.js
```

With SIMD128 enabled on Wasmtime (Cranelift backend), ML-KEM-768 encapsulation typically runs 2–3x faster than the scalar path, bringing it close to practical parity with X25519 for most deployment scenarios.

### Step 4: WASM SIMD Acceleration for Lattice Arithmetic

The lattice operations underlying ML-KEM and ML-DSA are dominated by Number Theoretic Transform (NTT) polynomial multiplication. NTT operates on arrays of coefficients, performing butterfly operations in parallel — a natural fit for SIMD lanes.

The WASM SIMD proposal provides 128-bit vector operations (v128 type) mapping to SSE2/AVX2 on x86-64 and NEON on ARM. When the pqclean C implementations are compiled with SIMD support, the Emscripten or clang WASM backend vectorises the NTT loops automatically.

For Rust WASM, the `pqcrypto` and `oqs-rs` crates will use SIMD if the target feature is set:

```rust
// build.rs — detect WASM SIMD availability and set feature flags.
fn main() {
    let target = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target == "wasm32" {
        // Check if SIMD is enabled via RUSTFLAGS.
        if std::env::var("CARGO_CFG_TARGET_FEATURE")
            .unwrap_or_default()
            .contains("simd128")
        {
            println!("cargo:rustc-cfg=wasm_simd");
        }
    }
}
```

```rust
// Use SIMD-optimised path when available.
#[cfg(all(target_arch = "wasm32", wasm_simd))]
mod inner {
    pub use pqcrypto_mlkem::mlkem768 as kem_impl;
}

#[cfg(not(all(target_arch = "wasm32", wasm_simd)))]
mod inner {
    pub use pqcrypto_mlkem::mlkem768 as kem_impl;
    // Same API — SIMD is a compilation option, not a different crate.
}
```

At runtime in Wasmtime, verify SIMD is enabled in the engine configuration:

```rust
use wasmtime::{Config, Engine};

fn build_engine_with_simd() -> Engine {
    let mut config = Config::new();
    config.wasm_simd(true);           // Enable WASM SIMD proposal.
    config.wasm_bulk_memory(true);    // Required for some PQC memory operations.
    Engine::new(&config).expect("failed to build engine with SIMD")
}
```

Without SIMD, pqclean falls back to a scalar C implementation. This is functionally correct but slower — important to know for latency budgets and capacity planning.

### Step 5: WASI Crypto PQC Roadmap

The WASI Crypto proposal (`wasi:crypto`) defines host-native cryptographic operations exposed as WASM imports. The current stable interface (as of WASI 0.2) includes symmetric encryption, HMAC, ECDH key exchange, and ECDSA signatures. Post-quantum algorithms are on the roadmap but not yet in the stable specification.

The WASI Crypto working group has proposed adding ML-KEM and ML-DSA as native host operations in a future revision. The proposed interface mirrors the existing KEM and signature APIs:

```wit
// Proposed WASI Crypto PQC additions (subject to change — not yet standardised).
// This is illustrative of the direction; consult the wasi-crypto GitHub for current status.

interface pqc-kem {
  // ML-KEM key encapsulation.
  resource ml-kem-keypair {
    generate: static func(security-level: ml-kem-level) -> result<ml-kem-keypair, crypto-error>;
    public-key: func() -> list<u8>;
    decapsulate: func(ciphertext: list<u8>) -> result<list<u8>, crypto-error>;
  }

  enum ml-kem-level {
    level-512,    // FIPS 203 ML-KEM-512
    level-768,    // FIPS 203 ML-KEM-768  (NIST recommended)
    level-1024,   // FIPS 203 ML-KEM-1024
  }

  encapsulate: func(public-key: list<u8>, level: ml-kem-level)
    -> result<tuple<list<u8>, list<u8>>, crypto-error>;
}
```

Until WASI Crypto standardises PQC, use one of two strategies:

1. **In-WASM PQC library** (pqcrypto / oqs-rs): PQC runs inside the WASM module as compiled code. This is the deployable approach today.
2. **Host import for PQC**: Expose ML-KEM and ML-DSA from the Wasmtime host process via a custom import namespace. The WASM module calls the host for PQC operations, offloading the computation and keeping PQC key material out of WASM linear memory.

```rust
// Wasmtime host: expose ML-KEM as a host import until WASI Crypto standardises it.
use oqs::kem::{Kem, Algorithm as KemAlg};

fn add_pqc_imports(linker: &mut wasmtime::Linker<HostState>) -> anyhow::Result<()> {
    linker.func_wrap(
        "pqc",
        "ml_kem_768_encapsulate",
        |mut caller: wasmtime::Caller<'_, HostState>,
         pk_ptr: u32,
         pk_len: u32,
         ct_out_ptr: u32,
         ss_out_ptr: u32| -> i32 {
            let mem = caller.get_export("memory")
                .and_then(|e| e.into_memory())
                .unwrap();

            let pk_bytes = {
                let data = mem.data(caller.as_context());
                data[pk_ptr as usize..(pk_ptr + pk_len) as usize].to_vec()
            };

            let kem = Kem::new(KemAlg::MlKem768).unwrap();
            let pk = kem.public_key_from_bytes(&pk_bytes).unwrap();
            let (ct, ss) = kem.encapsulate(&pk).unwrap();

            let ct_bytes = ct.as_ref();
            let ss_bytes = ss.as_ref();

            mem.write(caller.as_context_mut(), ct_out_ptr as usize, ct_bytes).unwrap();
            mem.write(caller.as_context_mut(), ss_out_ptr as usize, ss_bytes).unwrap();

            0i32  // Success.
        },
    )?;
    Ok(())
}
```

Track the WASI Crypto PQC issue at `https://github.com/WebAssembly/wasi-crypto` and plan to migrate to native WASI Crypto operations once they are standardised — they will provide hardware acceleration and eliminate the need to ship PQC implementations inside WASM modules.

### Step 6: Hybrid Key Exchange — X25519 + ML-KEM in TLS 1.3

The recommended migration path for TLS key exchange is hybrid mode: combine a classical algorithm (X25519) with a post-quantum KEM (ML-KEM-768) such that the shared secret is secure if either algorithm is unbroken. This is the approach standardised in RFC 9180 (HPKE) and implemented in the `X25519MLKEM768` TLS 1.3 key share group (IANA code point 0x11EC).

Hybrid key exchange protects against:

- A classical attacker who cannot break X25519
- A quantum attacker who cannot break ML-KEM-768
- Any future discovery of a weakness in either algorithm individually

For WASM-based TLS stacks using `rustls`, hybrid key exchange requires a custom key exchange provider until rustls integrates ML-KEM natively:

```toml
# Cargo.toml — rustls with custom provider support.
[dependencies]
rustls = { version = "0.23", default-features = false, features = ["std", "tls12"] }
rustls-pki-types = "1"
oqs = { version = "0.9", features = ["ml-kem"] }
x25519-dalek = { version = "2", features = ["static_secrets"] }
```

```rust
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use oqs::kem::{Kem, Algorithm as KemAlg};
use sha2::{Sha256, Digest};

/// Hybrid X25519 + ML-KEM-768 shared secret derivation.
/// Concatenates both shared secrets and hashes to produce the final key material.
pub struct HybridKeyExchange {
    x25519_secret: EphemeralSecret,
    mlkem_kem: Kem,
    mlkem_sk: oqs::kem::SecretKey,
    mlkem_pk: oqs::kem::PublicKey,
}

impl HybridKeyExchange {
    pub fn new() -> Self {
        let x25519_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let mlkem_kem = Kem::new(KemAlg::MlKem768).expect("ML-KEM init failed");
        let (mlkem_pk, mlkem_sk) = mlkem_kem.keypair().expect("ML-KEM keypair failed");
        Self { x25519_secret, mlkem_kem, mlkem_sk, mlkem_pk }
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        // Combined public key: X25519 (32 bytes) || ML-KEM-768 public key (1184 bytes).
        let x25519_pk = X25519PublicKey::from(&self.x25519_secret);
        let mut combined = x25519_pk.as_bytes().to_vec();
        combined.extend_from_slice(self.mlkem_pk.as_ref());
        combined
    }

    pub fn complete(
        self,
        peer_x25519_pk: &[u8; 32],
        mlkem_ciphertext: &[u8],
    ) -> [u8; 32] {
        // Classical component: X25519 shared secret.
        let peer_pk = X25519PublicKey::from(*peer_x25519_pk);
        let x25519_ss = self.x25519_secret.diffie_hellman(&peer_pk);

        // PQ component: ML-KEM decapsulation.
        let ct = self.mlkem_kem
            .ciphertext_from_bytes(mlkem_ciphertext)
            .expect("invalid ML-KEM ciphertext");
        let mlkem_ss = self.mlkem_kem
            .decapsulate(&self.mlkem_sk, &ct)
            .expect("ML-KEM decapsulation failed");

        // Combine: Hash(x25519_ss || mlkem_ss || context).
        // Security holds if either component is secure.
        let mut hasher = Sha256::new();
        hasher.update(x25519_ss.as_bytes());
        hasher.update(mlkem_ss.as_ref());
        hasher.update(b"X25519MLKEM768");
        hasher.finalize().into()
    }
}
```

Verify that your TLS layer negotiates the hybrid group when peers support it and falls back gracefully to X25519 when they do not. The fallback is a security downgrade — log it as a warning so you can track the fraction of sessions that did not achieve PQC protection.

### Step 7: Code Size Impact on WASM Bundles and Cold Start

PQC implementations are significantly larger than classical algorithm implementations. This matters in WASM deployments where cold start time scales with module binary size, and where edge runtimes (Cloudflare Workers, Fastly Compute) impose size limits on deployed bundles.

Approximate compiled WASM binary size additions:

| Addition | Size impact |
|---|---|
| ML-KEM-768 only (scalar) | ~120 KB |
| ML-KEM-768 + SIMD | ~180 KB |
| ML-DSA-65 (scalar) | ~250 KB |
| ML-DSA-65 + SIMD | ~320 KB |
| Full oqs-rs (all algorithms) | ~2.5 MB |
| liboqs via Emscripten (all) | ~4 MB |

ML-DSA is notably larger than ML-KEM because the signing operation requires more polynomial arithmetic and the implementation includes extensive domain separation logic. SLH-DSA (SPHINCS+) has a small public key (32 bytes) but produces 7–50 KB signatures depending on the parameter set — impractical for protocols that transmit many signatures.

Mitigation strategies for WASM bundle size:

```toml
# Cargo.toml — enable only the required algorithms.
[dependencies]
pqcrypto-mlkem = { version = "0.1", features = [] }   # ML-KEM only; no ML-DSA.

# Use opt-level = "z" for size-optimised WASM builds.
[profile.release]
opt-level = "z"
lto = true
strip = true

# Enable wee_alloc for a smaller allocator footprint.
[target.'cfg(target_arch = "wasm32")'.dependencies]
wee_alloc = "0.4"
```

```rust
// Use wee_alloc as the global allocator in WASM to save ~10 KB.
#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
```

For edge runtimes with strict size limits, prefer the host import strategy from Step 5: keep PQC operations in the host process and expose them as WASM imports. The WASM module then contains only call stubs (a few dozen bytes) rather than the full PQC implementation.

Measure cold-start impact before deploying PQC to production:

```bash
# Measure Wasmtime instantiation time for PQC-enabled vs classical module.
hyperfine \
  "wasmtime run --invoke main classical_module.wasm" \
  "wasmtime run --invoke main pqc_module.wasm" \
  --warmup 3 --runs 50
```

An additional 200–300 KB of WASM code adds roughly 5–15 ms to cold start on a Wasmtime host with AOT compilation disabled. With AOT pre-compilation (`wasmtime compile`), the cold-start overhead is negligible:

```bash
# Pre-compile the PQC WASM module to native code to eliminate JIT cold start.
wasmtime compile --target x86_64-linux --cranelift-opt-level speed pqc_module.wasm \
  -o pqc_module.cwasm

# Run from pre-compiled native artifact — cold start in microseconds.
wasmtime run --allow-precompiled pqc_module.cwasm
```

### Step 8: Migration Strategy for WASM Services

A phased migration approach reduces risk by maintaining classical cryptography as a fallback while building operational confidence in PQC implementations.

**Phase 1 — Audit and inventory (Weeks 1–2):**

- Complete the audit from Step 1.
- Identify all key exchange and signing operations in WASM deployments.
- Classify by data sensitivity and longevity.
- Pin runtime versions to ensure SIMD support is available.

**Phase 2 — Hybrid key exchange on non-critical paths (Weeks 3–6):**

- Deploy X25519+ML-KEM hybrid key exchange for internal service-to-service communication where you control both sides.
- Use hybrid TLS for WASM sidecar proxies or plugin hosts.
- Log fallback-to-classical events.
- Benchmark cold start and request latency impact.

**Phase 3 — PQC signing for WASM artifact distribution (Weeks 7–12):**

- Sign new WASM plugin releases with ML-DSA-65 in addition to the existing ECDSA signature (dual signing).
- Update plugin verifiers to accept either signature, preferring ML-DSA when present.
- Begin retiring ECDSA signing key issuance for new keys.

**Phase 4 — Full PQC with classical fallback deprecated (Months 4–12):**

- Require ML-KEM for all new WASM service deployments.
- Remove ECDH from the key exchange negotiation in controlled environments.
- Sunset ECDSA-only plugin signatures; require ML-DSA.

```rust
// Migration helper: negotiate hybrid or PQC-only based on peer capability.
pub enum KeyExchangeMode {
    Classical,          // X25519 only — legacy peers.
    Hybrid,             // X25519 + ML-KEM-768 — transition mode.
    PostQuantumOnly,    // ML-KEM-768 only — fully migrated peers.
}

pub fn select_key_exchange_mode(peer_supports_mlkem: bool, require_pqc: bool) -> KeyExchangeMode {
    match (peer_supports_mlkem, require_pqc) {
        (_, true) if peer_supports_mlkem => KeyExchangeMode::PostQuantumOnly,
        (true, false) => KeyExchangeMode::Hybrid,
        (false, true) => {
            // Log this as a security event — PQC required but peer cannot support it.
            tracing::warn!("peer does not support ML-KEM; cannot satisfy PQC requirement");
            KeyExchangeMode::Classical  // Or reject the connection.
        }
        (false, false) => KeyExchangeMode::Classical,
    }
}
```

### Step 9: Monitoring and Alerting

```
wasm_pqc_key_exchange_total{mode, algorithm, result}         counter
wasm_pqc_classical_fallback_total{reason}                    counter
wasm_pqc_operation_duration_ms{algorithm, operation}         histogram
wasm_pqc_module_size_bytes{module}                           gauge
wasm_pqc_cold_start_ms{module, has_aot}                     histogram
wasm_pqc_signature_verify_total{algorithm, result}           counter
```

Alert on:

- `wasm_pqc_classical_fallback_total` increasing — indicates peers that do not support PQC; investigate whether these are expected legacy clients or a misconfiguration.
- `wasm_pqc_operation_duration_ms` p95 exceeding 5x the baseline — may indicate SIMD is not engaged or the runtime version changed.
- `wasm_pqc_module_size_bytes` exceeding the edge runtime size limit — module will fail to deploy.
- `wasm_pqc_signature_verify_total{result="fail"}` non-zero — signature verification failures may indicate a forged or corrupted WASM artifact.

## Expected Behaviour

| Signal | Without PQC | With PQC migration |
|---|---|---|
| ECDH key exchange in TLS | Vulnerable to HNDL | Hybrid X25519+ML-KEM-768; quantum-resistant |
| WASM plugin signatures | ECDSA; forgeable by quantum attacker | ML-DSA-65 dual-signed; classical attacker: secure; quantum attacker: secure |
| Cold start (no AOT) | Baseline | +5–15 ms for PQC module (offset by AOT pre-compilation) |
| Bundle size | Baseline | +120–320 KB for ML-KEM + ML-DSA; mitigated by algorithm selection |
| Classical fallback events | N/A — all connections use X25519 | Logged and alerted; fallback fraction tracked |
| SIMD not available | N/A | PQC scalar fallback active; 2–3x slower; logged |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| ML-KEM over X25519 | Quantum-resistant key exchange | 4–5x slower without SIMD; larger keys (1184 vs 32 bytes) | Enable SIMD128; use hybrid mode to limit blast radius of migration |
| ML-DSA over ECDSA | Quantum-resistant signatures | 250+ KB added to WASM bundle; signatures 50x larger | AOT pre-compile; restrict to signing path only; host-import PQC sig ops |
| Hybrid key exchange | Security if either algorithm holds | Added complexity; slightly more memory | Standard approach endorsed by NIST; complexity is manageable |
| In-WASM PQC vs host import | Self-contained WASM module | Larger bundle; PQC key material in WASM linear memory | Prefer host import for long-lived keys; zeroize key material on drop |
| SLH-DSA vs ML-DSA | Different security assumption (hash-based) | 7–50 KB signatures; slow signing | Use ML-DSA for most deployments; SLH-DSA for long-term archive signing only |
| AOT pre-compilation | Eliminates PQC cold-start penalty | Requires pre-compilation step in deployment pipeline | Add `wasmtime compile` to CI/CD; distribute `.cwasm` artifacts |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| SIMD disabled in runtime | PQC operations 2–3x slower than expected | `wasm_pqc_operation_duration_ms` elevated; benchmark regression | Enable `wasm_simd(true)` in Wasmtime Config; verify RUSTFLAGS include `+simd128` |
| Bundle exceeds edge runtime size limit | Module deployment fails with size error | CI size check fails; deployment pipeline error | Compile with `opt-level = "z"`; select only required algorithms; use host-import strategy |
| Classical fallback not logged | Untracked sessions using X25519-only key exchange | No visibility into PQC adoption rate | Instrument all key exchange paths; alert on fallback events |
| oqs-rs version mismatch vs liboqs | Link failure or ABI incompatibility in WASM build | Build error; WASM instantiation failure | Pin `oqs` crate version; verify liboqs submodule version matches |
| ML-KEM ciphertext not zeroized | Decapsulation key material persists in linear memory | Memory dump shows ciphertext bytes after operation | Wrap ciphertext in `zeroize::Zeroizing<Vec<u8>>`; verify with `valgrind` on native build |
| Hybrid fallback to classical accepted silently | Peer announces no ML-KEM support; server silently uses X25519 | HNDL risk reintroduced without alerting | Require PQC for sensitive paths; log and alert on classical fallback; reject when policy requires PQC |
| Cold start regression after PQC deployment | p99 instantiation time increases significantly | Cold-start histogram shifts; SLA breach | AOT pre-compile WASM modules; cache instantiated modules in the runtime pool |

## Related Articles

- [Cryptographic Algorithm Implementations in WASM](/articles/wasm/wasm-crypto-implementations/)
- [WASM Linear Memory Safety](/articles/wasm/wasm-linear-memory-safety/)
- [WASI Preview 2 Capabilities](/articles/wasm/wasi-preview-2-capabilities/)
- [WASM SIMD Security Implications](/articles/wasm/wasm-simd-security/)
- [WASM Toolchain Security](/articles/wasm/wasm-toolchain-security/)
- [WASM OCI Signing](/articles/wasm/wasm-oci-signing/)
