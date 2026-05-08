---
title: "WASM SIMD128 Security: Timing Side Channels and Cryptographic Pitfalls"
description: "WASM SIMD128 exposes subtle timing side channels that break constant-time guarantees in cryptographic code. Learn when SIMD is safe, when it leaks secrets, and how to harden SIMD-accelerated WASM workloads against speculative execution and memory disclosure attacks."
slug: wasm-simd-security
date: 2026-05-07
lastmod: 2026-05-07
category: wasm
tags:
  - wasm-simd
  - side-channels
  - timing-attacks
  - cryptography
  - wasm
personas:
  - security-engineer
  - platform-engineer
article_number: 574
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/wasm/wasm-simd-security/
---

# WASM SIMD128 Security: Timing Side Channels and Cryptographic Pitfalls

## Problem

The WASM SIMD128 proposal — standardized and enabled by default in all major runtimes since 2022 — adds 128-bit Single Instruction Multiple Data operations to WebAssembly. SIMD128 allows one instruction to process 16 bytes, four 32-bit integers, or two 64-bit floats simultaneously. The throughput gains are real: AES-GCM accelerated with SIMD128 can be 6–8× faster than scalar WASM, and image processing or ML inference workloads see comparable improvements.

The security problem is equally real: SIMD128 operations do not carry the same constant-time guarantees that cryptographic code depends on. Constant-time programming — ensuring that secret-dependent code paths take identical wall-clock time regardless of the secret value — is the baseline requirement for any cryptographic implementation that must resist timing attacks. SIMD breaks this guarantee in three distinct ways that are easy to miss and hard to detect without deliberate testing.

First, **microarchitecture-dependent latency**: SIMD operations that appear equivalent at the WASM instruction level can have dramatically different execution latencies on different underlying CPUs. A `v128.load` on an Intel Sapphire Rapids host executes at one latency; the same instruction on an AMD Zen 4 host or an Apple M-series ARM core may differ. When a WASM module compiled with SIMD runs on different hardware — as is routine in cloud environments — the timing profile of cryptographic operations changes. An attacker who can measure execution time remotely and knows the target CPU microarchitecture can use these timing differences to recover secret key bits.

Second, **variable-time SIMD operations**: Several SIMD128 operations are not guaranteed to run in constant time on all underlying hardware. Integer division is the canonical example — not directly a SIMD operation, but the general principle extends: certain shuffle, shift, and permutation operations have input-dependent latency on specific microarchitectures. `i8x16.swizzle` — a table lookup across 16 bytes — is particularly dangerous when used in AES S-box implementations, because its latency can vary depending on the indices being looked up on CPUs without hardware AES support.

Third, **Spectre gadgets via SIMD shuffles**: SIMD shuffle instructions — `i8x16.shuffle`, `i8x16.swizzle`, `v128.load_splat`, and related operations — perform indexed memory accesses that are efficient transient execution gadgets. A SIMD gather-style operation that loads from an attacker-controlled index into a vector register can, during speculative execution, read memory that would not be accessible in non-speculative execution. SIMD operations amplify this because a single instruction operates on 16 bytes, increasing the bandwidth of a speculative disclosure gadget.

**Affected systems:** All WASM runtimes with SIMD128 enabled — Wasmtime 8+, WasmEdge 0.11+, V8 (Chrome 91+, Node.js 16.4+), SpiderMonkey (Firefox 89+), WAMR 1.3+. Any WASM cryptographic library compiled with `-msimd128` or the `--enable-simd` flag.

## Threat Model

- **Adversary 1 — Remote timing oracle:** An adversary can submit chosen ciphertexts or trigger HMAC verifications through a network API backed by SIMD-accelerated WASM crypto. By measuring response latencies with nanosecond precision (or statistically across many requests), they detect timing variation in SIMD operations correlated with secret key bytes.
- **Adversary 2 — Spectre via SIMD gadget:** A WASM module in a browser with `crossOriginIsolated` incorrectly configured, or in a multi-tenant server runtime, uses crafted SIMD shuffle sequences as a transient execution gadget to speculatively read memory outside its linear memory sandbox.
- **Adversary 3 — Cross-page vector load:** A WASM module performs `v128.load` (or wider loads) at a memory address near a page boundary. The speculative prefetch of the adjacent page can leak information about whether that page is mapped and its contents via cache-timing effects.
- **Adversary 4 — Microarchitecture fingerprinting:** A WASM module with SIMD enabled executes a calibration sequence to measure its own SIMD timing profile. This fingerprints the underlying CPU microarchitecture, breaking the portability abstraction of the WASM sandbox and leaking host hardware information to the guest module.
- **Access level:** Adversary 1 has network access to an API endpoint. Adversary 2 has WASM execution in a shared runtime. Adversaries 3 and 4 have WASM execution with SIMD enabled.
- **Objective:** Recover cryptographic key material (Adversary 1), read out-of-sandbox memory (Adversary 2), leak host memory layout (Adversary 3), fingerprint host hardware (Adversary 4).
- **Blast radius:** A successful timing attack against an HMAC or AES-GCM key takes hundreds of thousands of queries but is fully automated. Spectre gadget success extracts ~100 bytes per second. Microarchitecture fingerprinting succeeds in milliseconds.

## Configuration

### Step 1: Identify SIMD Use in WASM Binaries

Before hardening, determine which modules in your deployment use SIMD128.

```bash
# Disassemble a WASM binary and search for SIMD opcodes.
wasm-objdump -d module.wasm | grep -E \
  'v128|i8x16|i16x8|i32x4|i64x2|f32x4|f64x2|swizzle|shuffle'

# Using wasm-tools to list all SIMD instructions present.
wasm-tools dump module.wasm | grep -c 'simd'

# Check compiler flags: a WASM binary compiled with SIMD will have
# a producers section noting -msimd128 or equivalent.
wasm-objdump -x module.wasm | grep -A5 'producers'

# For a Rust/cargo-compiled WASM module, check build flags.
# SIMD is enabled by RUSTFLAGS="-C target-feature=+simd128"
# or by the wasm-pack/cargo config.
```

Audit every WASM module that handles cryptographic operations — key derivation, MAC verification, symmetric encryption, signature validation — and flag any that use SIMD128.

### Step 2: Evaluate SIMD Safety for Cryptographic Operations

Not all SIMD operations in cryptographic code are equally dangerous. Apply this classification:

**Safe to use with SIMD (data-independent timing on all major microarchitectures):**

- `v128.and`, `v128.or`, `v128.xor`, `v128.not` — bitwise operations; single-cycle constant-time.
- `v128.load`, `v128.store` — unconditional load/store from known addresses.
- `i32x4.add`, `i64x2.add`, `i16x8.add` — integer vector addition; constant-time.
- `v128.load_splat` when the address is data-independent (not controlled by secret bits).
- `i8x16.shuffle` with **static** (compile-time-fixed) indices — the compiler emits a fixed shuffle instruction; no index-dependent timing.

**Avoid in cryptographic code (variable-time risk):**

- `i8x16.swizzle` — a runtime-variable table lookup. On CPUs without hardware CLMUL/AES support, software S-box implementations using `swizzle` can have input-dependent timing. On CPUs with AES-NI (mapped to WASM SIMD), this is safe, but the WASM portability contract does not guarantee the presence of AES-NI.
- Integer division or remainder in SIMD context — not a SIMD opcode itself, but vectorized division emulation is variable-time on ARM Neon.
- `v128.load` at a secret-derived address — cache-timing disclosure.
- Conditional SIMD branches derived from secret data — any `if` or `br_if` whose condition depends on a SIMD comparison result and a secret value.

Document this classification in a threat model annotation for each cryptographic WASM module.

### Step 3: Implement Constant-Time SIMD Patterns

For AES-GCM, ChaCha20, Poly1305, and similar ciphers compiled to WASM SIMD, enforce constant-time patterns at the source level.

**ChaCha20 quarter-round in constant-time SIMD (Rust, targeting WASM SIMD128):**

```rust
// This implementation uses only constant-time SIMD operations:
// add, xor, and rotate (implemented as shift + or with fixed counts).
// No conditional branches on secret data; no variable-index swizzle.

#[cfg(target_feature = "simd128")]
use core::arch::wasm32::*;

#[inline(always)]
pub fn chacha20_quarter_round_simd(
    a: v128, b: v128, c: v128, d: v128,
) -> (v128, v128, v128, v128) {
    // a += b; d ^= a; d <<<= 16
    let a = i32x4_add(a, b);
    let d = v128_xor(d, a);
    // Rotate left by 16: constant shift count — data-independent timing.
    let d = v128_or(i32x4_shl(d, 16), u32x4_shr(d, 16));

    // c += d; b ^= c; b <<<= 12
    let c = i32x4_add(c, d);
    let b = v128_xor(b, c);
    let b = v128_or(i32x4_shl(b, 12), u32x4_shr(b, 20));

    // a += b; d ^= a; d <<<= 8
    let a = i32x4_add(a, b);
    let d = v128_xor(d, a);
    let d = v128_or(i32x4_shl(d, 8), u32x4_shr(d, 24));

    // c += d; b ^= c; b <<<= 7
    let c = i32x4_add(c, d);
    let b = v128_xor(b, c);
    let b = v128_or(i32x4_shl(b, 7), u32x4_shr(b, 25));

    (a, b, c, d)
}
// All shift counts are compile-time constants. No secret-derived indexing.
// No conditional branches. Safe on all SIMD128-supporting microarchitectures.
```

**Constant-time comparison using SIMD (replaces memcmp in MAC verification):**

```rust
// Timing-safe comparison of two 16-byte values using SIMD.
// This is safe because: v128_xor is constant-time; i8x16_bitmask is
// constant-time; the final comparison is on a public derived value (0 or not).
// The key property: no early exit. Both branches execute in identical time.

#[cfg(target_feature = "simd128")]
#[inline(always)]
pub fn simd_ct_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    use core::arch::wasm32::*;
    unsafe {
        let va = v128_load(a.as_ptr() as *const v128);
        let vb = v128_load(b.as_ptr() as *const v128);
        // XOR: any differing bytes produce non-zero lanes.
        let diff = v128_xor(va, vb);
        // bitmask: produces a u32 where bit i is set iff lane i has MSB set.
        // For equality, all XOR bytes must be zero => bitmask is 0.
        // i8x16_bitmask extracts the high bit of each byte — sufficient for
        // detecting any non-zero byte when combined with the OR-reduction below.
        // Use i8x16_eq to get an all-ones mask if equal, then check the bitmask.
        let eq_mask = i8x16_eq(diff, i8x16_splat(0));
        // all lanes equal => bitmask is 0xFFFF (all bits set).
        i8x16_bitmask(eq_mask) == 0xFFFF
    }
}

// For inputs longer than 16 bytes: XOR-reduce all chunks, then compare.
pub fn simd_ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false; // Length comparison is public; safe.
    }
    // Accumulate XOR differences across all chunks without early exit.
    use core::arch::wasm32::*;
    let mut acc = unsafe { i8x16_splat(0) };
    let chunks = a.len() / 16;
    for i in 0..chunks {
        unsafe {
            let va = v128_load(a[i * 16..].as_ptr() as *const v128);
            let vb = v128_load(b[i * 16..].as_ptr() as *const v128);
            acc = v128_or(acc, v128_xor(va, vb));
        }
    }
    // Handle remaining bytes (scalar, constant-time).
    let mut tail_diff: u8 = 0;
    for i in (chunks * 16)..a.len() {
        tail_diff |= a[i] ^ b[i];
    }
    let tail_zero = (tail_diff == 0) as u8;
    unsafe { i8x16_bitmask(i8x16_eq(acc, i8x16_splat(0))) == 0xFFFF && tail_zero == 1 }
}
```

**Critical**: do not allow the compiler to substitute this with a branch-based `memcmp`. In Rust, mark the function `#[inline(never)]` and verify the generated WASM with `wasm-objdump` to confirm no `br_if` instructions appear in the comparison path.

### Step 4: Prevent AES-NI Portability Divergence

WASM SIMD128 maps to `PCLMULQDQ` and AES-NI instructions on x86-64 hosts that support them, and to ARMv8 Cryptography Extensions on ARM64 hosts. On hosts without these extensions — older x86 CPUs, RISC-V, MIPS — the runtime emulates AES round functions in software using `i8x16.swizzle` table lookups, which are variable-time.

Detect and handle this at runtime in the WASM host:

```rust
// Wasmtime: detect host AES-NI support and configure accordingly.
use wasmtime::{Config, Engine};

fn engine_with_simd_policy(require_aes_ni: bool) -> anyhow::Result<Engine> {
    let mut config = Config::new();
    config.wasm_simd(true);

    // Wasmtime's cranelift backend will use AES-NI when available.
    // Expose a host function to the WASM module so it can query capability.
    // Do NOT rely on the WASM module to self-detect via timing; that leaks
    // microarchitecture information.
    Engine::new(&config)
}

// Host function exposed to the WASM module:
// Returns 1 if AES-NI (x86) or ARMv8 Crypto (ARM64) is available; 0 otherwise.
fn host_has_hw_aes() -> i32 {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("aes") && is_x86_feature_detected!("pclmulqdq") {
            return 1;
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("aes") {
            return 1;
        }
    }
    0
}

// Register with the linker:
// linker.func_wrap("env", "has_hw_aes", host_has_hw_aes)?;
```

In the WASM module, use this capability check to select between SIMD-accelerated AES (constant-time on HW-AES platforms) and a scalar constant-time fallback:

```rust
// WASM module side: select implementation at startup based on host capability.
extern "C" {
    fn has_hw_aes() -> i32;
}

static mut USE_SIMD_AES: bool = false;

pub fn init_crypto() {
    unsafe {
        USE_SIMD_AES = has_hw_aes() == 1;
    }
}

pub fn aes_encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    unsafe {
        if USE_SIMD_AES {
            aes_simd_encrypt(key, block)   // Constant-time via AES-NI/ARMv8 Crypto.
        } else {
            aes_scalar_ct_encrypt(key, block)  // Constant-time scalar fallback.
        }
    }
}
```

Never use `i8x16.swizzle`-based software AES on a platform where hardware AES is unavailable if the WASM module handles keys in high-security contexts. The swizzle-based approach has demonstrated timing leakage under controlled conditions.

### Step 5: Mitigate Spectre Gadgets in SIMD Code

SIMD shuffle operations with attacker-influenced indices are efficient Spectre gadgets. Prevent gadget formation in security-critical WASM modules:

**In Wasmtime (production hardening):**

```toml
# wasmtime serve configuration / Cargo.toml features.
# Enable Spectre mitigations: retpoline-equivalent for indirect calls,
# linear memory bounds checks with masking (not just guard pages).
[features]
# Wasmtime's "spectre-mitigations" cargo feature inserts masking on
# array indices before memory accesses.
default = ["cranelift", "spectre-mitigations"]
```

```rust
// Wasmtime Config: force bounds-checking via masking, not just guard pages.
// Masking clamps an attacker-controlled index before the memory access,
// preventing the speculative out-of-bounds read.
let mut config = Config::new();
// The default in current Wasmtime is already safe for Spectre on x86-64,
// but make the policy explicit.
config.cranelift_flag_set("enable_heap_access_spectre_mitigation", "true")?;
config.cranelift_flag_set("enable_table_access_spectre_mitigation", "true")?;
```

**In WASM source code:** avoid `i8x16.swizzle` with an index derived from external (potentially attacker-controlled) input:

```rust
// UNSAFE: swizzle with an externally derived index.
// On speculative execution, this can act as a Spectre gadget.
fn unsafe_table_lookup(table: v128, index: u8) -> u8 {
    let idx = i8x16_splat(index as i8);  // index from attacker input.
    let result = i8x16_swizzle(table, idx);
    // The speculative load of table[index] can read adjacent memory.
    i8x16_extract_lane::<0>(result) as u8
}

// SAFE: use static shuffle indices known at compile time.
// The shuffle is a fixed permutation; no runtime index.
#[inline(always)]
fn safe_rotate_bytes(v: v128) -> v128 {
    // i8x16_shuffle with literal indices: compile-time constant, no gadget.
    i8x16_shuffle::<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0>(v, v)
}
```

For cases where runtime-variable indices are unavoidable (e.g., a GCM table multiplication), verify that Wasmtime's Cranelift backend emits a bounds-masking instruction before the shuffle, or restrict those modules to non-secret data.

### Step 6: Address Cross-Page Vector Load Risks

A `v128.load` at an address within 16 bytes of a page boundary causes the CPU to prefetch (and potentially cache) the adjacent page, even if only the bytes on the current page are semantically accessed by the load. This cross-page prefetch is detectable via timing in a shared-cache environment.

In WASM linear memory, page boundaries occur every 65536 bytes (one WASM page = 64 KiB). Ensure SIMD-loaded buffers are aligned:

```rust
// In allocator or buffer management: align SIMD buffers to at least 16 bytes,
// and pad to ensure no SIMD load crosses a 64 KiB WASM page boundary
// when operating on secret data.

const SIMD_ALIGN: usize = 16;
const WASM_PAGE: usize = 65536;

fn allocate_simd_safe_buffer(len: usize) -> Vec<u8> {
    // Pad to 16 bytes to prevent cross-boundary loads.
    let padded = (len + SIMD_ALIGN - 1) & !(SIMD_ALIGN - 1);
    // In practice, vec! gives 8-byte alignment on WASM; use aligned_alloc
    // or ensure buffers start on a 16-byte boundary.
    let mut v = vec![0u8; padded + SIMD_ALIGN];
    let offset = v.as_ptr().align_offset(SIMD_ALIGN);
    v[offset..offset + padded].to_vec()
}

// Validate alignment at the WASM module boundary (host-side check):
fn validate_simd_buffer_ptr(ptr: u32, len: u32) -> bool {
    ptr % 16 == 0          // 16-byte aligned.
        && (ptr as u64 + len as u64) <= u64::from(u32::MAX)
        && (ptr / 65536) == ((ptr + len.saturating_sub(1)) / 65536)
    // All bytes within one WASM page — no cross-page SIMD load.
}
```

For buffers that necessarily span page boundaries (e.g., large message inputs), split SIMD processing at the page boundary rather than loading across it.

### Step 7: Browser-Side Mitigations and SharedArrayBuffer Interaction

When WASM SIMD runs in a browser, the Spectre threat surface includes both the SIMD gadgets and the timing precision available to the attacker:

```nginx
# Required headers for any page that loads SIMD-enabled WASM.
# These enable Cross-Origin Isolation, which browsers use to justify
# enabling SharedArrayBuffer AND to apply reduced-precision timers.
location / {
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Embedder-Policy "require-corp" always;
}
```

```javascript
// Verify isolation before instantiating SIMD WASM.
async function loadSimdModule(wasmUrl) {
    if (!crossOriginIsolated) {
        // Without isolation, performance.now() has 1ms resolution —
        // Spectre timing attacks are harder but not impossible.
        // SIMD is still available; warn and reduce attack surface.
        console.warn(
            "Cross-origin isolation absent. " +
            "SharedArrayBuffer unavailable; timer precision already reduced. " +
            "SIMD WASM will load but avoid secret-key operations in this context."
        );
    }

    // performance.now() in a cross-origin-isolated context returns
    // values quantized to 5 microseconds (Chrome) or 20 microseconds (Firefox).
    // This is intentional Spectre mitigation; do not use Date.now() as a
    // workaround — it has the same quantization in isolated contexts.

    const response = await fetch(wasmUrl);
    const bytes = await response.arrayBuffer();
    const { instance } = await WebAssembly.instantiate(bytes, {});
    return instance;
}
```

Browser mitigations after Spectre (summarized for SIMD context):

| Browser | `performance.now()` resolution in isolated context | SharedArrayBuffer |
|---------|---------------------------------------------------|-------------------|
| Chrome 91+ | 5 µs, plus random jitter of 0–100 µs | Requires COOP + COEP |
| Firefox 89+ | 20 µs, jitter enabled | Requires COOP + COEP |
| Safari 15.2+ | 1 ms (no isolation concept yet; conservative) | Disabled by default |

These mitigations degrade remote timing attacks against SIMD operations but do not eliminate them. They are not a substitute for writing constant-time cryptographic code.

### Step 8: Feature Detection and Safe Fallback Code Paths

WASM SIMD128 is a compile-time feature; WASM modules compiled without SIMD cannot use it. Maintain two builds for security-critical modules:

```bash
# Build 1: SIMD-enabled, for platforms with hardware AES support.
cargo build --target wasm32-wasip2 \
    --release \
    -Z build-std \
    -- RUSTFLAGS="-C target-feature=+simd128,+bulk-memory"

# Build 2: Scalar fallback, constant-time on all platforms.
cargo build --target wasm32-wasip2 \
    --release \
    -Z build-std \
    -- RUSTFLAGS="-C target-feature=-simd128"

# Verify: the scalar build contains no SIMD opcodes.
wasm-objdump -d module-scalar.wasm | grep -c 'v128' && \
    echo "FAIL: SIMD found in scalar build" || echo "OK: no SIMD in scalar build"
```

Select the correct build at deployment time based on the host's advertised CPU features:

```rust
// Wasmtime host: select WASM binary based on CPU capability.
fn select_wasm_module(trusted_crypto_tier: bool) -> &'static [u8] {
    let has_aes = {
        #[cfg(target_arch = "x86_64")]
        { is_x86_feature_detected!("aes") }
        #[cfg(not(target_arch = "x86_64"))]
        { false }
    };

    match (trusted_crypto_tier, has_aes) {
        // Trusted deployment + hardware AES: SIMD binary is safe.
        (true, true)  => include_bytes!("../build/module-simd.wasm"),
        // No hardware AES, or untrusted deployment: scalar constant-time.
        _             => include_bytes!("../build/module-scalar.wasm"),
    }
}
```

This selection logic must run on the host, not inside the WASM module. Allowing the WASM module to self-select by timing its own AES operation leaks microarchitecture information to the guest.

### Step 9: Monitoring and Alerting

```
wasm_simd_module_loaded_total{module, has_hw_aes}          counter
wasm_ct_comparison_failures_total{module}                  counter
wasm_simd_buffer_alignment_violations_total{module}        counter
wasm_spectre_mitigation_active{runtime, tenant}            gauge
wasm_timing_quantization_level_microseconds{context}       gauge
```

Alert conditions:

- `wasm_simd_buffer_alignment_violations_total` non-zero — a SIMD load is crossing a boundary; investigate the allocator.
- `wasm_simd_module_loaded_total{has_hw_aes="false"}` for any module handling cryptographic key material — scalar fallback should have been selected.
- `wasm_spectre_mitigation_active` equals 0 for any tenant in a multi-tenant deployment.
- Any WASM module touching key material that is not in the known-constant-time module inventory (maintain a hash allowlist).

## Expected Behaviour

| Scenario | Without hardening | With hardening |
|----------|------------------|----------------|
| AES-GCM on host without AES-NI | `swizzle`-based S-box; variable-time; timing oracle active | Scalar constant-time fallback selected at deploy time |
| MAC comparison | SIMD `memcmp` with early-exit potential | SIMD XOR-accumulate; no early exit; timing-safe |
| Spectre gadget via swizzle | Speculative out-of-bounds read possible | Static shuffle indices only; Cranelift masking enabled |
| Cross-page vector load | Adjacent page cached; timing leaks page presence | Buffers aligned and padded within WASM page boundaries |
| Browser SIMD crypto | `performance.now()` at nanosecond resolution in non-isolated context | COOP + COEP enforced; timer quantized to 5–20 µs |
| Microarchitecture detection by WASM guest | Timing self-probe reveals host CPU | Host provides explicit capability flag; self-timing blocked |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Dual SIMD/scalar builds | Correct constant-time on all platforms | Two binaries to maintain and sign | CI pipeline builds and verifies both; OCI signing covers both. |
| Static shuffle indices only | Eliminates swizzle-based Spectre gadgets | Cannot implement all AES software fallbacks efficiently | On platforms without HW AES, use scalar constant-time AES (bitsliced). |
| Cranelift Spectre masking | Runtime mitigation for speculative index reads | ~3–5% throughput reduction on memory-intensive SIMD workloads | Acceptable for security WASM; profile and confirm for ML inference workloads. |
| SIMD CT comparison (XOR-accumulate) | No early exit; constant-time | Slightly more complex than `memcmp` | Use a well-audited crate (`subtle`, `ring`); do not hand-roll. |
| Cross-origin isolation (browser) | Reduces timer precision; makes Spectre harder | Breaks pages that load cross-origin content without CORS | Audit all cross-origin dependencies; add CORS headers to static assets. |
| Host-side HW AES detection | Prevents guest from fingerprinting CPU | Requires host function in linker | One-time setup; encapsulate in a runtime initialization helper. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| SIMD AES used without HW AES | `swizzle`-based timing oracle; MAC verification time varies with key | Automated timing test shows >5 ns variance across 10,000 trials | Force scalar build; re-audit deployment selection logic. |
| Constant-time comparison replaced by compiler | `wasm-objdump` shows `br_if` in comparison path | CI step: disassemble and grep for `br_if` in crypto comparison functions | Add `#[inline(never)]` and compiler barrier; re-verify disassembly. |
| COOP/COEP headers absent in browser deployment | `crossOriginIsolated === false`; timer at nanosecond resolution | Browser console; automated header check in CI | Add headers; verify with `securityheaders.com` check in pipeline. |
| Unaligned SIMD buffer near page boundary | Cross-page prefetch detected via `wasm_simd_buffer_alignment_violations_total` | Alert fires; or detected in address-sanitizer run | Fix allocator to pad to 16 bytes and check page-span at allocation. |
| Cranelift Spectre masking disabled | Speculative out-of-bounds reads possible | Wasmtime config audit; `cranelift_flag_get("enable_heap_access_spectre_mitigation")` | Enable the flag; rebuild and redeploy engine configuration. |
| Dual builds diverge (scalar not equivalent) | Scalar build produces incorrect output (fails NIST test vectors) | NIST vector test in CI against both builds | Fix scalar implementation; block deployment until both pass vectors. |

## Related Articles

- [WASM Threads and Shared Memory Security](/articles/wasm/wasm-threads-shared-memory/)
- [WASM Linear Memory Safety](/articles/wasm/wasm-linear-memory-safety/)
- [WASM Memory64 Security Implications](/articles/wasm/wasm-memory64-security/)
- [WASM AOT Compilation Security](/articles/wasm/wasm-aot-compilation-security/)
- [WASM Browser Security](/articles/wasm/wasm-browser-security/)
- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
