---
title: "WASM Linear Memory Safety: Bounds Checking, Buffer Overflows, and Stack Protection"
description: "WebAssembly's linear memory model provides strong isolation between the WASM heap and the host, but it does not prevent within-sandbox buffer overflows, use-after-free, or stack smashing. Understanding what WASM's memory model protects and what it doesn't determines where additional defences are needed."
slug: "wasm-linear-memory-safety"
date: 2026-05-01
lastmod: 2026-05-01
category: "wasm"
tags: ["wasm", "memory-safety", "buffer-overflow", "linear-memory", "stack-protection"]
personas: ["platform-engineer", "security-engineer"]
article_number: 310
difficulty: "advanced"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/wasm/wasm-linear-memory-safety/index.html"
---

# WASM Linear Memory Safety: Bounds Checking, Buffer Overflows, and Stack Protection

## Problem

WebAssembly's memory model is frequently described as "memory safe" — and in an important sense it is: a WASM module cannot read or write memory outside its allocated linear memory segment. The host's memory is inaccessible. A bug in WASM code cannot directly corrupt the host process's stack, heap, or code section.

This guarantee is narrower than it appears. Within the WASM sandbox, the same memory vulnerabilities that affect native code can occur:

- **Buffer overflows in linear memory.** A WASM module compiled from C/C++ using Emscripten or wasi-sdk places its stack, heap, and data segments all within the same linear memory array. A buffer overflow in the WASM heap can overwrite the WASM stack or function pointers stored in memory — even though it cannot leave the sandbox. This enables WASM-internal code execution: an attacker who provides crafted input can take control of the module's execution within the sandbox.
- **Use-after-free in the WASM heap.** Heap allocators (`dlmalloc`, `wasm-opt`'s allocator) used by compiled WASM modules are subject to use-after-free just as in native code. Exploiting use-after-free in WASM can corrupt allocator metadata, leading to arbitrary write within linear memory.
- **Integer overflows in memory size calculations.** WASM's instruction set is type-safe, but arithmetic overflow in `i32` multiplication (e.g., `size * count` for buffer allocation) causes incorrect allocation sizes — the foundation of heap overflow vulnerabilities.
- **Indirect call table injection.** WASM function tables (used for indirect calls, implementing C function pointers) are stored in memory in some toolchain configurations. A buffer overflow that overwrites an indirect call table entry redirects execution to an attacker-controlled function within the WASM module.
- **Data segment confusion.** WASM data segments initialise sections of linear memory at module instantiation. If the same linear memory is used for code-like data (function pointers, vtables) and user-controlled buffers, a write to the wrong offset can corrupt control flow.

Understanding these limitations is essential for applications that use WASM to sandbox untrusted code: the sandbox prevents host access, but does not prevent an attacker from taking control of the sandboxed module's own execution.

**Target systems:** WASM modules compiled from C/C++ with Emscripten or wasi-sdk; Rust WASM builds (generally safer but not immune); WASM runtimes: Wasmtime 20+, WasmEdge, Wasmer; applications using WASM for plugin sandboxing.

## Threat Model

- **Adversary 1 — Heap overflow for within-sandbox code execution:** An attacker provides crafted input to a WASM module compiled from C. The input causes a buffer overflow that overwrites an indirect call table entry. The next indirect call executes attacker-chosen code within the module's context — with the module's full capability set.
- **Adversary 2 — Integer overflow leading to heap underallocation:** A WASM module calculates a buffer size as `width * height * channels` using i32 arithmetic. The attacker provides `width=65537, height=65537`, causing the multiplication to overflow to a small value. The allocated buffer is too small; subsequent writes overflow into adjacent heap metadata.
- **Adversary 3 — Use-after-free in heap allocator:** A WASM module with a memory management bug frees a buffer and continues using it. The attacker triggers a re-allocation that overlaps the freed buffer, causing type confusion. In modules with function pointers in heap objects, this leads to control flow hijacking within the sandbox.
- **Adversary 4 — Stack overflow for WASM stack smashing:** WASM runtimes implement the WASM call stack separately from linear memory; traditional stack smashing is not possible. However, in Emscripten-compiled code, the "shadow stack" (local variable frame) lives in linear memory and is subject to overflow.
- **Adversary 5 — Memory confusion via module.grow:** A WASM module calls `memory.grow` to expand linear memory. After growth, previously adjacent memory regions may now be in different positions relative to each other. An attacker who can time memory growth can cause type confusion between adjacent heap objects.
- **Access level:** All adversaries only need to provide input to the WASM module — they need not escape the sandbox to cause significant damage within it.
- **Objective:** Take control of the WASM module's execution within the sandbox, enabling: arbitrary use of the module's host function imports, data exfiltration via allowed channels, and bypass of in-module security checks.
- **Blast radius:** Within-sandbox code execution gives the attacker full use of the WASM module's capability grants — which, if the module has filesystem or network access, is significant even without escaping the sandbox.

## Configuration

### Step 1: Prefer Memory-Safe Languages for WASM

The most effective defence against WASM memory vulnerabilities is using a language that eliminates them:

```toml
# Rust WASM: memory-safe by default.
# Buffer overflows and use-after-free are prevented by the borrow checker.
# Integer overflow: Rust panics in debug mode; wraps in release (use checked_* in production).

[profile.release]
overflow-checks = true   # Enable overflow checks in release builds.
# Costs ~5-10% performance; eliminates integer overflow vulnerabilities.
```

```rust
// Use checked arithmetic for security-relevant size calculations.
fn allocate_buffer(width: u32, height: u32, channels: u32) -> Option<Vec<u8>> {
    let size = width
        .checked_mul(height)?
        .checked_mul(channels)?
        .checked_mul(4)?  // bytes per channel.
        as usize;

    // Enforce a maximum size to prevent DoS via huge allocation.
    if size > 64 * 1024 * 1024 {  // 64 MiB limit.
        return None;
    }

    Some(vec![0u8; size])
}
```

For C/C++ compiled to WASM, use sanitisers:

```bash
# Compile with AddressSanitizer for WASM (Emscripten supports ASAN).
emcc -fsanitize=address \
     -fsanitize=undefined \
     -g \
     module.c \
     -o module-debug.wasm

# Run the ASAN-instrumented module in testing.
# ASAN will catch buffer overflows and use-after-free at runtime.
# Do NOT ship ASAN builds to production (significant overhead and binary size).
```

### Step 2: Stack Overflow Protection in Emscripten

Emscripten's shadow stack (for C local variables) lives in linear memory and is subject to overflow. Enable stack canaries:

```bash
# Emscripten: enable stack overflow detection.
emcc \
  -sSTACK_OVERFLOW_CHECK=2 \    # 2 = full stack canary check.
  -sSTACK_SIZE=65536 \          # Explicit stack size limit.
  -sALLOW_MEMORY_GROWTH=0 \     # Disable memory growth (predictable layout).
  module.c \
  -o module.wasm
```

```c
// In C code: use WASM-aware stack guards.
// Emscripten provides __stack_pointer global; check it explicitly.
#include <emscripten.h>

void check_stack_depth() {
    // __builtin_frame_address(0) gives the current frame address.
    // Compare against the known stack base to detect overflow.
    uintptr_t frame = (uintptr_t)__builtin_frame_address(0);
    uintptr_t stack_base = (uintptr_t)emscripten_stack_get_base();
    uintptr_t stack_end = (uintptr_t)emscripten_stack_get_end();

    if (frame < stack_end || frame > stack_base) {
        // Stack pointer outside expected range — overflow or corruption.
        abort();
    }
}
```

### Step 3: Indirect Call Table Protection

In WASM, indirect function calls use a function table. Protect against table corruption:

```rust
// Rust: function pointers in WASM use the function table.
// Rust's type system prevents most function pointer corruption.
// For C interop (FFI), validate function pointer provenance.

// In WASM host (Wasmtime): restrict which table indices can be called.
use wasmtime::*;

fn validate_indirect_call(
    table: &Table,
    index: u32,
    expected_type: &FuncType,
) -> Result<Func> {
    let func = table.get(&mut store, index)
        .ok_or(anyhow::anyhow!("Table index {} out of bounds", index))?;

    let actual_type = func.ty(&store);
    if actual_type != *expected_type {
        return Err(anyhow::anyhow!(
            "Type mismatch for indirect call at index {}: expected {:?}, got {:?}",
            index, expected_type, actual_type
        ));
    }
    // Wasmtime validates type at call time; this is belt-and-suspenders.
    Ok(func)
}
```

### Step 4: Input Validation Before Processing in Linear Memory

Validate all external inputs before they enter WASM linear memory operations:

```rust
// Host-side input validation before passing to WASM.
fn call_wasm_image_processor(
    plugin: &Plugin,
    image_data: &[u8],
    width: u32,
    height: u32,
    channels: u8,
) -> Result<Vec<u8>> {
    // 1. Validate dimensions before passing to WASM.
    if width == 0 || height == 0 || channels == 0 {
        return Err(anyhow::anyhow!("Invalid dimensions: {}x{}x{}", width, height, channels));
    }

    // 2. Prevent integer overflow in the WASM module.
    let expected_size = (width as u64)
        .checked_mul(height as u64)
        .and_then(|s| s.checked_mul(channels as u64))
        .ok_or(anyhow::anyhow!("Dimension overflow"))?;

    if expected_size > 64 * 1024 * 1024 {
        return Err(anyhow::anyhow!("Image too large: {} bytes", expected_size));
    }

    // 3. Validate actual data length matches declared dimensions.
    if image_data.len() != expected_size as usize {
        return Err(anyhow::anyhow!(
            "Data length mismatch: got {} bytes, expected {}",
            image_data.len(), expected_size
        ));
    }

    // Safe to pass to WASM module.
    plugin.call_with_data("process_image", image_data, width, height, channels)
}
```

### Step 5: Memory Limits and Monitoring

```rust
// Wasmtime: enforce per-module memory limits.
use wasmtime::*;

fn create_limited_store(engine: &Engine) -> Store<()> {
    let mut store = Store::new(engine, ());

    // Limit total linear memory.
    store.limiter(|_state| {
        ResourceLimiterBuilder::new()
            .memory_size(64 * 1024 * 1024)   // 64 MiB maximum.
            .table_elements(10_000)           // Function table size limit.
            .build()
    });

    // Instruction fuel limit (prevents infinite loops during memory manipulation).
    store.set_fuel(10_000_000_000).unwrap();

    store
}
```

```bash
# Monitor WASM module memory growth at runtime.
# Wasmtime exposes memory size via the Memory.size() function.

# In a Rust host:
# let mem = instance.get_memory(&mut store, "memory").unwrap();
# let pages = mem.size(&store);   // Current pages (64KiB each).
# let bytes = pages * 65536;
# metric!("wasm_memory_bytes", bytes, "module" => module_name);
```

### Step 6: Fuzzing WASM Modules

Fuzz WASM modules with structured input to find memory vulnerabilities:

```rust
// fuzz/fuzz_targets/image_processor.rs — libFuzzer target for WASM module.
#![no_main]
use libfuzzer_sys::fuzz_target;
use wasmtime::*;

static ENGINE: std::sync::OnceLock<Engine> = std::sync::OnceLock::new();
static MODULE: std::sync::OnceLock<Module> = std::sync::OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let engine = ENGINE.get_or_init(|| Engine::default());
    let module = MODULE.get_or_init(|| {
        Module::from_file(engine, "target/wasm32-wasi/release/image_processor.wasm").unwrap()
    });

    let mut store = Store::new(engine, ());
    store.set_fuel(1_000_000).unwrap();

    if let Ok(instance) = Instance::new(&mut store, module, &[]) {
        if let Ok(process) = instance.get_typed_func::<(u32, u32), ()>(&mut store, "process") {
            // Pass fuzzer-generated data as WASM memory input.
            if let Some(memory) = instance.get_memory(&mut store, "memory") {
                let data_len = data.len().min(1024);
                if memory.data_size(&store) >= data_len {
                    memory.write(&mut store, 0, &data[..data_len]).ok();
                    // Call the WASM function with attacker-controlled data.
                    process.call(&mut store, (0, data_len as u32)).ok();
                }
            }
        }
    }
});
```

```bash
# Run the fuzzer.
cargo +nightly fuzz run image_processor -- \
  -max_len=65536 \        # Maximum input size.
  -timeout=30 \           # Kill runs taking > 30 seconds.
  -runs=1000000           # Number of fuzzing iterations.
```

### Step 7: Compile-Time Mitigations

```bash
# wasm-opt: apply Binaryen optimisations that improve safety.
# -O3: optimisation level.
# --enable-reference-types: enables typed function references (reduces call table abuse).
# --closed-world: optimise assuming no dynamic linking (reduces attack surface).

wasm-opt \
  -O3 \
  --enable-reference-types \
  --closed-world \
  --strip-debug \          # Remove debug symbols from production builds.
  module.wasm \
  -o module-optimised.wasm

# Verify the optimised module preserves expected behaviour.
# Run integration tests against the optimised module.
```

```makefile
# Build pipeline for a C module targeting WASM with security hardening.
WASM_FLAGS = \
  -sSTACK_OVERFLOW_CHECK=2 \
  -sALLOW_MEMORY_GROWTH=0 \
  -sSTACK_SIZE=65536 \
  -sINITIAL_MEMORY=1048576 \
  -sMAXIMUM_MEMORY=67108864 \
  -sFILESYSTEM=0 \         # Disable filesystem if not needed.
  -sNETWORK=0              # Disable network if not needed.

module.wasm: module.c
  emcc $(WASM_FLAGS) -O2 $< -o $@
  wasm-opt -O3 --closed-world $@ -o $@
```

### Step 8: Telemetry

```
wasm_memory_pages_current{module}                          gauge
wasm_memory_pages_maximum{module}                          gauge
wasm_memory_growth_events_total{module}                    counter
wasm_fuel_consumed{module, function}                       histogram
wasm_asan_violations_total{module, violation_type}         counter
wasm_fuzzer_crashes_found{module, input_hash}              counter
wasm_indirect_call_type_mismatch_total{module}             counter
wasm_stack_overflow_detected_total{module}                 counter
```

Alert on:

- `wasm_asan_violations_total` in staging — buffer overflow or use-after-free found; fix before production.
- `wasm_indirect_call_type_mismatch_total` — possible call table corruption; investigate module.
- `wasm_stack_overflow_detected_total` — shadow stack overflow; increase stack size or fix recursion.
- `wasm_memory_pages_current` approaching maximum — module near memory limit; check for memory leak.
- `wasm_fuel_consumed` P99 exceeds budget — a module is consuming significantly more compute than expected; investigate for infinite loops or large input processing.

## Expected Behaviour

| Signal | Unprotected C/WASM | Hardened WASM |
|--------|---------------------|---------------|
| Buffer overflow via crafted input | Overwrites adjacent heap; corrupts control flow | ASAN catches in testing; input validation prevents |
| Integer overflow in size calculation | Underallocation; heap overflow | `checked_mul` returns None; allocation rejected |
| Function table corruption | Indirect call executes attacker function | Type validation on indirect call; table size limits |
| Stack overflow in shadow stack | Silently corrupts heap-adjacent data | Emscripten stack canary detects and aborts |
| Memory growth attack | Potentially shifts object layout | `ALLOW_MEMORY_GROWTH=0` prevents growth |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| `overflow-checks = true` (Rust) | Prevents integer overflow exploitation | ~5-10% runtime overhead | Acceptable for security-sensitive modules; benchmark first |
| `ALLOW_MEMORY_GROWTH=0` | Predictable memory layout; no growth-based attacks | Module fails if it needs more memory | Set MAXIMUM_MEMORY generously based on profiling |
| ASAN in testing | Finds memory bugs before production | Significant size and runtime overhead | Debug/test builds only; never production |
| Fuzzing | Finds memory vulnerabilities proactively | Engineering time to set up and maintain | CI-integrated fuzzing with coverage targets |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Memory limit too low | Module terminates with out-of-memory | OOM error in module; `wasm_memory_pages_current` at max | Increase MAXIMUM_MEMORY after profiling actual peak usage |
| `overflow-checks` causes legitimate panic | Module exits unexpectedly on large inputs | Panic message in module output; reproducible crash | Fix the arithmetic to use checked or saturating operations |
| Fuel exhausted on legitimate computation | Module times out for valid large input | Fuel exhausted error; `wasm_fuel_consumed` high | Increase fuel limit for that module; add input size bounds |
| ASAN false positive blocks CI | Fuzzer or test triggers ASAN on valid operation | ASAN report with no actual bug | Investigate ASAN report; may indicate unintended code path |

## Related Articles

- [WASM Component Model Security](/articles/wasm/wasm-component-model-security/)
- [WASM Static Analysis](/articles/wasm/wasm-static-analysis/)
- [WASM Multi-Tenancy](/articles/wasm/wasm-multi-tenancy/)
- [WasmEdge Security](/articles/wasm/wasmedge-security/)
- [Extism Plugin Security](/articles/wasm/extism-plugin-security/)
