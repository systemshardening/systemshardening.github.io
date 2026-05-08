---
title: "Cryptographic Implementations in WASM: Timing Safety, WASI Crypto, and Key Handling"
description: "WASM doesn't guarantee constant-time execution — JIT optimisations can introduce timing variations that break cryptographic security. This guide covers evaluating WASM crypto libraries for timing safety, using WASI Crypto for hardware-accelerated operations, key zeroisation in linear memory, and RNG security."
slug: wasm-crypto-implementations
date: 2026-05-07
lastmod: 2026-05-07
category: wasm
tags:
  - wasm
  - cryptography
  - timing-attacks
  - wasi-crypto
  - constant-time
personas:
  - security-engineer
  - platform-engineer
article_number: 580
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/wasm/wasm-crypto-implementations/
---

# Cryptographic Implementations in WASM: Timing Safety, WASI Crypto, and Key Handling

## Problem

WebAssembly is an increasingly common compilation target for cryptographic code. The same Rust crate — `ring`, `RustCrypto`, `dalek-cryptography` — compiles once and runs unmodified across Linux servers, macOS workstations, browser sandboxes, edge runtimes, and IoT devices. Projects like `libsodium.js` ship a production-grade cryptography library compiled to WASM, used across millions of browser applications. This portability is genuinely valuable: a single audited implementation replaces platform-specific codebases, and the WASM sandbox prevents the crypto library from accessing OS resources it doesn't need.

The problem is that WASM does not guarantee constant-time execution.

Constant-time is not a property of source code — it is a property of the executed instruction stream on a specific hardware-and-runtime combination. A Rust implementation that uses `subtle::ConstantTimeEq` produces conditional moves (`cmov`) on native x86-64, avoiding branches on secret data. When that same code compiles to WASM and a JIT compiler (V8 TurboFan, SpiderMonkey IonMonkey, Cranelift) lowers it to native instructions, the translation can silently reintroduce branches. JIT compilers optimise for throughput; they have no model of timing-channel security. A WASM `select` instruction designed to produce a branchless path may be lowered to a conditional branch if the JIT's register allocator decides a branch instruction is cheaper for the current CPU microarchitecture.

The consequence is that secret-dependent timing variance — the signature of a timing side-channel — can emerge in WASM crypto code that is provably timing-safe on native targets. An AES-GCM decryption loop that runs in constant time on native x86-64 with AES-NI may exhibit measurable key-dependent variance when running as WASM on a server where the JIT applied a branch optimisation.

This is not theoretical. Research published in 2021 ("Constant-time WebAssembly?", Vassena et al.) demonstrated that multiple constant-time primitives from production Rust and C crates showed timing variance of 10–200 ns when compiled to WASM and measured under V8. A 50 ns variance is detectable with a few thousand queries from a co-located attacker in a multi-tenant cloud, or via statistical analysis of HTTPS response times from a remote attacker.

Beyond timing, WASM crypto implementations face additional security concerns. Linear memory has no hardware-enforced wiping: freed key material persists until overwritten. Random number generation behaviour differs between browser and WASI environments, and the wrong API call silently produces weak entropy. WASM-SIMD introduces architecture-dependent timing for operations like AES-NI emulation.

**Target systems:** Wasmtime 22+, V8 (Node.js 20+, Chrome 110+), SpiderMonkey (Firefox 110+), Spin 2.6+, WasmEdge 0.13+, any deployment using `ring`, `RustCrypto`, or `libsodium.js` compiled to WASM.

## Threat Model

- **Adversary 1 — Remote timing oracle:** An attacker makes repeated requests to a service performing WASM-based HMAC verification, ECDSA signature validation, or AES-GCM decryption. They measure response latency with sub-millisecond precision. The JIT-compiled WASM path leaks key-dependent timing. Over 10,000–100,000 queries the attacker applies statistical analysis to recover key material.
- **Adversary 2 — Co-tenant timing attacker:** A WASM module runs on a multi-tenant platform sharing CPU time with a target module. The attacker module uses fine-grained timers (a SIMD spin-loop as a clock, `Atomics.wait()`) to measure cache timing on the victim module's AES table lookups or ECC scalar multiplication.
- **Adversary 3 — Key material extraction from linear memory:** A logic error or out-of-bounds read in the WASM module allows reading arbitrary linear memory. Key material that was not zeroed after use persists in freed heap regions and remains readable.
- **Adversary 4 — Weak entropy at startup:** A WASM module generating ephemeral keys calls `Math.random()` or a poorly seeded PRNG instead of `crypto.getRandomValues()` (browser) or WASI `getrandom` (server). Keys are predictable.
- **Access level:** Adversaries 1 and 4 require only network access. Adversary 2 requires co-tenant WASM execution. Adversary 3 requires an additional vulnerability for the out-of-bounds read.
- **Objective:** Recover secret keys, forge authentication tags, decrypt ciphertexts, or predict ephemeral nonces.
- **Blast radius:** Key recovery breaks all past and future operations protected by that key. Nonce bias in ECDSA allows private key recovery with enough signatures. A timing oracle against RSA decryption recovers plaintexts.

## Configuration

### Step 1: Prefer WASI Crypto Host Functions Over In-WASM Implementations

The WASI Crypto proposal (`wasi-crypto`) defines host-provided functions that expose cryptographic primitives — symmetric encryption, asymmetric signatures, key derivation, hashing — as imports implemented by the runtime, not as WASM bytecode. The WASM module calls a host function; the host executes the primitive natively, using hardware acceleration (AES-NI, SHA extensions, AVX-512 VAES) and a constant-time implementation that has been validated for the specific CPU it runs on.

This eliminates the JIT timing problem entirely: the sensitive operation never executes as WASM instructions.

In Rust, using `wasi-crypto` via the `wasi` crate:

```rust
// Cargo.toml:
// [dependencies]
// wasi = { version = "0.11", features = ["wasi-crypto"] }

use wasi::crypto::symmetric::{key_generate, encrypt, OptionalOptions};

fn generate_key() -> wasi::crypto::symmetric::Key {
    // Key generation uses the runtime's entropy source, not Math.random().
    key_generate("AES-256-GCM", OptionalOptions::none())
        .expect("wasi-crypto key_generate failed")
}

fn encrypt_payload(key_handle: wasi::crypto::symmetric::Key, plaintext: &[u8]) -> Vec<u8> {
    // All computation happens inside the host runtime, not in WASM.
    // No JIT-compiled crypto; no timing leakage from WASM instruction lowering.
    let options = OptionalOptions::none();
    let (ciphertext, tag) = encrypt(key_handle, plaintext, &[], options)
        .expect("wasi-crypto encrypt failed");
    [ciphertext, tag].concat()
}
```

Enabling WASI Crypto in a Wasmtime host binary:

```toml
# Cargo.toml for the Wasmtime host binary.
[dependencies]
wasmtime = { version = "22", features = ["cranelift", "async"] }
wasmtime-wasi = { version = "22" }
wasmtime-wasi-crypto = { version = "22" }
```

```rust
use wasmtime_wasi_crypto::WasiCryptoCtx;

fn link_wasi_crypto(linker: &mut Linker<WasiCryptoCtx>) {
    wasmtime_wasi_crypto::add_to_linker(linker)
        .expect("failed to add wasi-crypto to linker");
}
```

When WASI Crypto is unavailable — browser environments, edge runtimes that do not expose it — fall back to the Web Crypto API (`crypto.subtle`) rather than an in-WASM implementation. Web Crypto uses the browser's native constant-time primitives and hardware acceleration and is not subject to JIT lowering.

### Step 2: Evaluating In-WASM Crypto Libraries for Timing Safety

When WASI Crypto is unavailable and a WASM crypto implementation is necessary, choose libraries with documented constant-time properties and validate them against each specific runtime.

**Preferred WASM crypto libraries (ordered by timing-safety evidence):**

- `ring` compiled to `wasm32-wasip2`: Uses assembly-optimised primitives on native targets. The WASM build falls back to Rust implementations that use `subtle` for constant-time comparisons. The guarantee is weaker than on native — test on each target runtime independently.
- `RustCrypto` crates (`aes`, `chacha20`, `sha2`, `p256`): Pure-Rust implementations; most use `subtle::ConstantTimeEq`. Timing behaviour depends on whether the WASM JIT preserves the `select`-based branchless patterns intended by the source.
- `libsodium.js`: libsodium compiled via Emscripten. Includes constant-time implementations for `crypto_secretbox`, `crypto_sign`, and `crypto_auth`. The Emscripten build disables compiler optimisations that would introduce branches. Prefer the WASM build over asm.js, and verify the Subresource Integrity hash when loading it in a browser.

**Libraries to avoid for secret-dependent operations:**

- Any implementation that uses a lookup table-based AES S-box (without AES-NI): cache timing attacks apply in WASM just as they do on native.
- RSA implementations that use square-and-multiply without blinding.
- Any implementation where constant-time properties are not explicitly documented.

When evaluating a library, prefer ChaCha20-Poly1305 over AES-GCM when hardware AES support cannot be guaranteed. ChaCha20 is designed to be timing-safe with only bitwise operations and addition; it does not rely on lookup tables or hardware instructions for its security properties.

### Step 3: Testing Constant-Time Behaviour with DudeCT

Static source analysis cannot determine whether a WASM implementation is constant-time at the JIT output level. Empirical timing measurement is required.

**DudeCT** (from "Dude, Is my Constant-time code really Constant-time?") measures timing distributions between two input classes and applies Welch's t-test. A t-value consistently above 5 indicates a statistically significant timing difference detectable by an attacker.

```bash
# Clone and build DudeCT.
git clone https://github.com/oreparaz/dudect
cd dudect && mkdir build && cd build && cmake .. && make
```

For WASM-specific timing measurement, write a Rust host harness that invokes the WASM module and measures per-call latency:

```rust
use std::time::Instant;
use wasmtime::{Engine, Module, Store, Instance};

fn measure_wasm_crypto(iterations: usize) -> (Vec<u64>, Vec<u64>) {
    let engine = Engine::default();
    let module = Module::from_file(&engine, "crypto_module.wasm").unwrap();
    let mut store = Store::new(&engine, ());
    let instance = Instance::new(&mut store, &module, &[]).unwrap();

    let hmac_fn = instance
        .get_typed_func::<(u32, u32), u32>(&mut store, "hmac_verify")
        .unwrap();

    let mut class0 = Vec::with_capacity(iterations / 2);
    let mut class1 = Vec::with_capacity(iterations / 2);

    for i in 0..iterations {
        // Alternate between all-zero key (class 0) and random key (class 1).
        let key_ptr = if i % 2 == 0 { 0u32 } else { 256u32 };
        let start = Instant::now();
        hmac_fn.call(&mut store, (key_ptr, 32)).unwrap();
        let elapsed = start.elapsed().as_nanos() as u64;
        if i % 2 == 0 {
            class0.push(elapsed);
        } else {
            class1.push(elapsed);
        }
    }

    (class0, class1)
}

fn welch_t_test(class0: &[u64], class1: &[u64]) -> f64 {
    let mean0 = class0.iter().sum::<u64>() as f64 / class0.len() as f64;
    let mean1 = class1.iter().sum::<u64>() as f64 / class1.len() as f64;
    let var0 = class0.iter().map(|&x| (x as f64 - mean0).powi(2)).sum::<f64>()
        / (class0.len() - 1) as f64;
    let var1 = class1.iter().map(|&x| (x as f64 - mean1).powi(2)).sum::<f64>()
        / (class1.len() - 1) as f64;
    (mean0 - mean1).abs()
        / (var0 / class0.len() as f64 + var1 / class1.len() as f64).sqrt()
}
```

A t-value consistently below 5 across 100,000+ iterations gives moderate confidence that the JIT-compiled path does not introduce a measurable timing leak. Retest whenever the runtime version changes — a JIT update can alter instruction lowering and reintroduce variance.

Additionally, use **TIMECOP** (via Valgrind's `memcheck`) on the native build to validate that the Rust source does not contain secret-dependent branches before WASM compilation. This is a necessary prerequisite, not a sufficient test:

```bash
# Build the Rust crypto code for native x86-64 and run under TIMECOP.
cargo build --target x86_64-unknown-linux-gnu --release

# The crypto source must call ct_poison(secret, len) and ct_unpoison(output, len)
# around the sensitive region. Then run:
valgrind --tool=memcheck --error-exitcode=1 \
    ./target/x86_64-unknown-linux-gnu/release/crypto_test
```

### Step 4: WASM-SIMD and Timing Safety

The WASM SIMD proposal adds 128-bit SIMD operations. On x86-64, these lower to SSE/AVX instructions; on ARM, to NEON. This matters for crypto: ChaCha20 and AES-GCM benefit significantly from SIMD, and some WASM runtimes use SIMD to emulate AES-NI acceleration.

Key SIMD timing risks:

- **Architecture-dependent lane timing:** On some ARM Cortex-A cores, NEON operations have different latencies than the corresponding x86-64 SSE2 instructions. A WASM SIMD operation that is timing-safe on x86-64 CI may leak on ARM production hardware.
- **Emulated SIMD:** Runtimes that do not support the WASM SIMD proposal may emulate SIMD operations as scalar loops, destroying constant-time properties entirely.
- **`i8x16.swizzle` for S-box lookups:** Software AES implementations that use `swizzle` as a table lookup are variable-time on CPUs without hardware AES-NI. The WASM portability contract does not guarantee AES-NI is present.
- **AES-NI detection timing:** If a module chooses between hardware-accelerated and software AES paths at runtime and the choice is observable through response latency, it creates an AES-NI detection oracle.

Compile WASM with an explicit SIMD target feature and test timing on every target architecture independently:

```toml
# .cargo/config.toml — compile WASM with SIMD enabled.
[target.wasm32-wasip2]
rustflags = ["-C", "target-feature=+simd128"]
```

Do not assume SIMD is timing-safe without empirical validation on the specific runtime and CPU family. Run DudeCT on ARM hardware (or QEMU ARM emulation) separately from x86-64 CI.

### Step 5: Key Material Handling in WASM Linear Memory

WASM linear memory is a flat byte array. The WASM allocator (wee_alloc, dlmalloc, or the Rust default allocator) frees memory by marking it available for reuse; it does not zero the bytes. If a key is allocated, used, and freed without explicit zeroing, the key bytes remain in linear memory until overwritten by the next allocation. A logic error, out-of-bounds read, or use-after-free vulnerability anywhere in the module can read the freed region and recover the key.

Use the `zeroize` crate to zero key material before deallocation:

```rust
// Cargo.toml:
// [dependencies]
// zeroize = { version = "1.7", features = ["derive"] }

use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]   // Automatically zeroed when the value is dropped, including on panic.
struct AesKey([u8; 32]);

fn perform_encryption(key_bytes: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let key = AesKey(*key_bytes);
    let ciphertext = aes_gcm_encrypt(&key.0, plaintext);
    // key is dropped here; Zeroize::zeroize() writes zeroes before deallocation.
    ciphertext
}
```

For heap-allocated key material:

```rust
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
struct EphemeralKeyPair {
    private_key: Vec<u8>,   // Zeroed on drop.
    public_key: Vec<u8>,    // Zeroed on drop.
}
```

Additional memory considerations:

- WASM has no `mlock` equivalent. On server-side Wasmtime, the host process can call `mlock` on the WASM linear memory region if key material sensitivity requires it.
- WASM locals (stack-frame values) are register-allocated by the JIT and do not exist at a fixed linear memory address, so they are not addressable by an OOB read. However, this is an implementation detail of current JITs, not a specification guarantee.
- The `#[zeroize(drop)]` attribute zeroes key fields even when a panic unwinds the stack — which is the most common way that key material leaks into freed memory without explicit zeroing.

### Step 6: Random Number Generation in WASM

Cryptographic key generation and nonce selection require a CSPRNG seeded from a high-quality hardware entropy source. WASM's portability creates risk: the correct entropy API differs by environment, and a wrong call silently produces weak randomness with no runtime error.

**Browser WASM:**

```javascript
// Host-side JavaScript: expose crypto.getRandomValues to WASM as an import.
// This is the only safe entropy source in browser WASM.
const importObject = {
    env: {
        random_bytes: (ptr, len) => {
            const view = new Uint8Array(memory.buffer, ptr, len);
            crypto.getRandomValues(view);   // OS-backed CSPRNG.
        }
    }
};
```

In Rust targeting browser WASM, configure the `getrandom` crate with the `js` feature so that `rand::thread_rng()` and `OsRng` route through `crypto.getRandomValues`:

```toml
# Cargo.toml.
[target.'cfg(target_arch = "wasm32")'.dependencies]
getrandom = { version = "0.2", features = ["js"] }
```

Without the `js` feature, `getrandom` panics in browser WASM. Verify this is correct before deploying:

```bash
# Confirm getrandom compiles for wasm32 with the js feature.
cargo check --target wasm32-unknown-unknown
```

**Server-side WASM (WASI):**

```rust
// Under WASI, getrandom maps to the wasi_snapshot_preview1 random_get syscall.
// The host runtime satisfies this from /dev/urandom or equivalent.
use getrandom::getrandom;

fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    getrandom(&mut key).expect("getrandom failed — entropy source unavailable");
    key
}
```

**Common mistakes that introduce weak entropy:**

- Seeding an in-WASM PRNG from `Date.now()` or `performance.now()` — timestamps are low-entropy and predictable.
- Using `Math.random()` for any security purpose — it is not a CSPRNG and its state is fully observable.
- Calling `getrandom` without the `js` feature in browser WASM — it panics or returns an error at runtime.
- Using a deterministic test PRNG in production due to a missed feature flag.

### Step 7: When NOT to Implement Crypto in WASM

Some cryptographic operations are too sensitive to trust to a JIT-compiled WASM implementation, regardless of library choice or testing:

- **TLS private key operations (RSA/ECDSA signing):** Use the host TLS stack (rustls, OpenSSL, BoringSSL) or a hardware security module. Never perform RSA or ECDSA signing in WASM for production TLS termination.
- **PAKE (Password Authenticated Key Exchange):** OPAQUE, SRP, and similar protocols require constant-time operations throughout the protocol exchange. The WASM JIT guarantee is insufficient.
- **Threshold signatures and multi-party computation:** Timing leakage in a single party's WASM implementation can reveal partial secrets and allow key reconstruction.
- **Long-term key storage operations:** Key wrapping, unwrapping, and derivation from a master key should go through the host keystore, HSM, or WASI Crypto host functions.
- **Hardware-attested operations:** TPM-backed key operations must run on the host.

For these cases, expose the operation as a host import that calls a trusted host implementation. The private key never enters WASM linear memory:

```rust
// Host side (Wasmtime): expose a signing function to the WASM module.
linker.func_wrap(
    "security",
    "sign_with_host_key",
    |mut caller: Caller<'_, HostState>, data_ptr: u32, data_len: u32, sig_ptr: u32| -> i32 {
        let mem = caller.get_export("memory")
            .and_then(|e| e.into_memory())
            .ok_or(0i32)
            .unwrap();

        // Read the data to sign from WASM linear memory.
        let data = {
            let bytes = mem.data(caller.as_context());
            bytes[data_ptr as usize..(data_ptr + data_len) as usize].to_vec()
        };

        // Sign using the host's key — it is never exposed to WASM linear memory.
        let signature = caller.data().host_signing_key.sign(&data);
        let sig_bytes = signature.to_bytes();

        // Write the signature back to WASM memory.
        mem.write(caller.as_context_mut(), sig_ptr as usize, &sig_bytes)
            .map(|_| sig_bytes.len() as i32)
            .unwrap_or(-1)
    },
)?;
```

The WASM module provides data to sign and receives the signature — the private key is never present in WASM linear memory at any point.

### Step 8: Browser vs Server — Different Runtime Characteristics

WASM crypto in the browser and on the server face different threat models and have different runtime properties.

| Property | Browser WASM | Server WASM (Wasmtime) |
|---|---|---|
| JIT compiler | V8 TurboFan or SpiderMonkey IonMonkey | Cranelift or LLVM |
| Constant-time guarantee | None; JIT optimises freely | None; Cranelift may branch on `select` |
| Timer resolution | `performance.now()` at 5 µs (cross-origin isolated) | `Instant::now()` at nanosecond resolution |
| AES-NI access | Via WASM-SIMD + V8 intrinsics on capable hosts | Via Cranelift AES-NI lowering on capable hosts |
| Entropy source | `crypto.getRandomValues` via `getrandom` with `js` feature | WASI `random_get` → OS CSPRNG |
| Memory isolation | Same process as the JavaScript heap | Linear memory separate from host heap |
| Co-tenant risk | Multiple-origin iframes if COOP/COEP absent | Other WASM modules sharing the same process |
| Key persistence in memory | Until GC collects the backing buffer or explicit zero | Until zeroized or process exit |

Browser timing attacks are degraded by the 5 µs quantisation of `performance.now()` in cross-origin isolated contexts (requiring `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Embedder-Policy: require-corp`). A timing difference of 50 ns — typical for a cache timing attack on AES — falls below the measurement floor in a properly isolated browser context. Server-side attacks have nanosecond resolution and are significantly more dangerous.

For server-side WASM handling private keys or performing authentication, prefer WASI Crypto host functions over any in-WASM crypto implementation. If an in-WASM operation is unavoidable, prefer ChaCha20-Poly1305 over AES-GCM: ChaCha20 does not require hardware support for timing safety and is less sensitive to JIT instruction lowering choices.

### Step 9: Monitoring and Alerting

```
wasm_crypto_operation_duration_ns{operation, runtime, algorithm}  histogram
wasm_crypto_timing_ttest_value{algorithm}                         gauge
wasm_entropy_source_failures_total{module}                        counter
wasm_key_zeroize_calls_total{module}                              counter
wasm_crypto_host_function_calls_total{function}                   counter
```

Alert on:

- `wasm_crypto_timing_ttest_value` exceeding 5 for any algorithm — indicates a detectable timing leak in the JIT-compiled path.
- `wasm_entropy_source_failures_total` non-zero — CSPRNG call failed; keys generated after this event may be weak.
- `wasm_crypto_operation_duration_ns` p99/p1 ratio exceeding 1.05 for an operation expected to be constant-time — unexpected latency distribution.

## Expected Behaviour

| Signal | Without hardening | With hardening |
|---|---|---|
| AES-GCM timing variance under JIT | Key-dependent; t-value above 5 in DudeCT | WASI Crypto host function; variance absent |
| Key material after free | Present in linear memory until overwritten | Zeroed by `Zeroize::zeroize()` on drop, including on panic |
| Entropy source in browser WASM | `Math.random()` or timestamp seed | `crypto.getRandomValues` via `getrandom` with `js` feature |
| RSA/ECDSA signing in WASM | JIT may introduce timing leak; private key in linear memory | Host import; key never enters WASM memory |
| SIMD-path timing on ARM | Untested; may differ from x86-64 | DudeCT run on each target architecture; result documented |
| Server-side timer resolution | Nanosecond; timing attacks feasible | WASI Crypto eliminates WASM-level crypto; no JIT path to attack |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| WASI Crypto over in-WASM | Eliminates JIT timing risk; hardware acceleration | Not available in all runtimes; browser support absent | Feature-detect; fall back to Web Crypto API in browser |
| `zeroize` on all key types | Key material cleared on drop, including panics | Small overhead on every key drop | Negligible for key operations; accept the cost |
| DudeCT testing per runtime version | Catches timing regressions introduced by JIT updates | Requires test infrastructure and runtime version pinning | Integrate into CI; pin runtime versions in production |
| ChaCha20 over AES-GCM in WASM | Timing-safe without hardware; no S-box lookup table | Slightly lower throughput than AES-NI on x86-64 | Acceptable for most WASM crypto workloads |
| Host signing import | Private key never in WASM linear memory | Higher latency per operation due to host function call overhead | Negligible for signature operations; batch if throughput is required |
| Disabling in-WASM RSA/ECDSA | Eliminates entire class of JIT timing attacks | More complex deployment; host must expose a signing API | Design the host API surface carefully; the complexity is warranted |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| JIT de-optimises constant-time path | DudeCT t-value spikes after a runtime update | CI timing test fails on runtime version bump | Pin runtime version; investigate JIT change; switch to WASI Crypto |
| `getrandom` without `js` feature in browser | Panic or error on key generation; module fails to initialise | Browser console error; module instantiation failure | Add `getrandom = { features = ["js"] }` to Cargo.toml for the wasm32 target |
| Key material not zeroed on panic | Key bytes persist in linear memory after an error | Memory dump of WASM linear memory post-crash | Use `#[zeroize(drop)]` attribute; verify panic handlers invoke drop |
| WASI Crypto unavailable at runtime | `wasi-crypto` import fails; module refuses to load | Module instantiation error | Add WASI Crypto availability check at startup; fall back to Web Crypto or reject the deployment |
| `libsodium.js` loaded without integrity check | Tampered `libsodium.js` replaces primitives with backdoored versions | SRI hash mismatch caught by browser | Add `integrity` attribute to the script tag; enforce CSP to restrict script sources |
| SIMD timing leak on ARM target | DudeCT passes on x86-64 CI but leaks on ARM production | Asymmetric timing anomaly in production metrics | Run DudeCT on ARM hardware or QEMU ARM emulation before deployment |

## Related Articles

- [WASM Linear Memory Safety](/articles/wasm/wasm-linear-memory-safety/)
- [WASM SIMD128 Security: Timing Side Channels and Cryptographic Pitfalls](/articles/wasm/wasm-simd-security/)
- [WASM Threads and Shared Memory Security](/articles/wasm/wasm-threads-shared-memory/)
- [WASM Dynamic Linking Security](/articles/wasm/wasm-dynamic-linking-security/)
- [WASM Toolchain Security](/articles/wasm/wasm-toolchain-security/)
- [WASI Preview 2 Capabilities](/articles/wasm/wasi-preview-2-capabilities/)
