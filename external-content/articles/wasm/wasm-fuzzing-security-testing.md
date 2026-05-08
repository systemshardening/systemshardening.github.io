---
title: "Fuzzing WebAssembly: Security Testing WASM Modules and Runtimes"
description: "Coverage-guided fuzzing finds both runtime vulnerabilities in Wasmtime/V8 and application bugs in WASM modules. This guide covers wasm-smith for structured WASM generation, cargo-fuzz for Rust WASM modules, differential fuzzing across runtimes, and building a continuous fuzzing pipeline."
slug: wasm-fuzzing-security-testing
date: 2026-05-07
lastmod: 2026-05-07
category: wasm
tags:
  - fuzzing
  - wasm
  - cargo-fuzz
  - security-testing
  - libfuzzer
personas:
  - security-engineer
  - platform-engineer
article_number: 573
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/wasm/wasm-fuzzing-security-testing/
---

# Fuzzing WebAssembly: Security Testing WASM Modules and Runtimes

## Problem

There are two distinct fuzzing targets in a WebAssembly deployment, and they require entirely different approaches. Conflating them produces gaps: you may find bugs in your own application code while the runtime silently harbours sandbox-escape vulnerabilities, or you may fuzz the runtime exhaustively while never testing the attack surface that untrusted input creates inside your module.

The first target is the **WASM runtime itself** — Wasmtime, WasmEdge, Wasmer, V8's WASM compiler, or SpiderMonkey. Runtime vulnerabilities are high-severity by definition: a bug in the runtime's validator, JIT compiler, memory layout, or bounds-check logic can allow a malicious `.wasm` module to escape the sandbox, corrupt host memory, or execute arbitrary code in the host process. Historical examples include CVE-2021-39216 (Wasmtime out-of-bounds read via multi-table module), CVE-2022-24791 (Wasmtime use-after-free in the epoch interruption mechanism), and CVE-2023-26489 (Cranelift register allocator producing incorrect code under certain conditions). These were found through Wasmtime's own fuzzing infrastructure. The attack input for runtime fuzzing is a crafted `.wasm` file — not user data, but the module itself.

The second target is the **WASM module** — your application code compiled to `.wasm`. Bugs in module code are bounded by the sandbox: a buffer overflow in a Rust-compiled module cannot escape into host memory. But within-sandbox exploitation is real and consequential. A module processing untrusted input that contains a memory corruption bug can have its control flow hijacked within the sandbox, giving an attacker full use of every WASI capability the module holds — filesystem access, outbound network, secrets in linear memory. The attack input for module fuzzing is structured user data passed through the module's exported functions.

The host integration layer — the code that marshals data between the host and the module's linear memory — adds a third, often overlooked surface. Host functions that write into module linear memory at attacker-influenced offsets, or that parse return values from untrusted modules, can have their own memory corruption bugs that live entirely outside the sandbox.

**Target systems:** Wasmtime 22+, wasm-smith 0.220+, cargo-fuzz 0.12+, libFuzzer, AFL++ 4.x, OSS-Fuzz. Examples are in Rust; AFL++ integration covers C/C++ compiled to WASM via Emscripten/wasi-sdk.

## Threat Model

- **Adversary 1 — Malicious WASM module author:** An attacker uploads or supplies a crafted `.wasm` file to a platform that runs arbitrary WASM. The module is engineered to trigger a runtime vulnerability — a validator bypass, a JIT compiler bug, or a bounds-check failure — that breaks the sandbox. The attacker gains code execution in the host process with the host's full privilege set.
- **Adversary 2 — Attacker providing crafted input to a WASM module:** The WASM module processes external input (HTTP request body, uploaded file, API parameter). A crafted input triggers a buffer overflow or integer overflow in the module's linear memory, enabling within-sandbox code-execution. The attacker gains full use of the module's WASI capability grants.
- **Adversary 3 — Input designed to diverge runtime behaviour:** The attacker supplies a WASM module that executes identically on Wasmtime and V8 in normal cases but produces different results — or crashes one runtime — under specific conditions. This divergence signals an undocumented edge case in one runtime's spec interpretation, potentially a vulnerability.
- **Adversary 4 — Host integration memory corruption:** The host application reads a return value from an untrusted WASM module and uses it as a memory offset or length without validation. A malicious module returns out-of-range values to corrupt host-side data structures outside the sandbox.
- **Access level:** Adversary 1 needs module-upload capability. Adversary 2 needs the ability to send input to the application. Adversary 3 needs the ability to supply a module to a differential-testing environment. Adversary 4 needs module-execution capability within the host.
- **Objective:** Sandbox escape (Adversary 1), within-sandbox privilege abuse (Adversary 2), spec-conformance violation discovery (Adversary 3), host-side memory corruption via malicious module output (Adversary 4).
- **Blast radius:** Adversary 1 achieves full host compromise. Adversary 2 achieves compromise within the WASI capability set. Adversary 3 may yield runtime vulnerabilities. Adversary 4 may achieve host memory corruption despite the sandbox.

## Configuration

### Step 1: Generate Valid WASM Modules with wasm-smith

Fuzzing a WASM runtime by passing random bytes as the module input is largely wasteful — the validator rejects structurally invalid modules immediately, and the interesting code paths (JIT compilation, execution, memory management) are never reached. The solution is a grammar-aware generator: `wasm-smith` generates structurally valid, type-correct WASM modules from a seed byte sequence. Every output of `wasm-smith` passes the WASM specification validator; the fuzzer's job is to find seeds that trigger runtime bugs in valid modules.

```toml
# Cargo.toml for a Wasmtime fuzzing harness
[package]
name = "wasmtime-fuzz"
version = "0.1.0"
edition = "2021"

[dependencies]
wasmtime = "22"
wasm-smith = "0.220"
arbitrary = { version = "1", features = ["derive"] }
libfuzzer-sys = "0.4"

[[bin]]
name = "fuzz_wasmtime_compile"
path = "fuzz_targets/fuzz_wasmtime_compile.rs"
```

```rust
// fuzz_targets/fuzz_wasmtime_compile.rs
// Fuzz Wasmtime's compilation and execution pipeline with wasm-smith-generated modules.
#![no_main]
use libfuzzer_sys::{fuzz_target, arbitrary::Unstructured};
use wasm_smith::{Config as SmithConfig, Module as SmithModule};
use wasmtime::*;

fuzz_target!(|data: &[u8]| {
    // wasm-smith generates a structurally valid module from the fuzzer byte sequence.
    let mut u = Unstructured::new(data);

    let smith_config = SmithConfig {
        // Allow all post-MVP proposals that Wasmtime supports.
        // Broader feature set = wider coverage of the compiler and validator.
        bulk_memory_enabled: true,
        reference_types_enabled: true,
        simd_enabled: true,
        multi_value_enabled: true,
        // Disable threads: shared memory across instances is out of scope.
        threads_enabled: false,
        // Generate modules with valid exports so we can attempt execution.
        min_exports: 0,
        max_exports: 10,
        max_memory_pages: 10,    // Keep memory small; we're fuzzing correctness, not size.
        ..SmithConfig::default()
    };

    let Ok(smith_module) = SmithModule::new(smith_config, &mut u) else {
        return; // Unstructured ran out of data; skip.
    };

    let wasm_bytes = smith_module.to_bytes();

    // Compile the module. A panic or abort here is a bug.
    let engine = Engine::default();
    let Ok(module) = Module::new(&engine, &wasm_bytes) else {
        return; // Validator correctly rejected an invalid module; not a bug.
    };

    // Attempt instantiation. Wasmtime should never panic or abort.
    let mut store = Store::new(&engine, ());
    // Provide a trivial fuel budget to bound execution of exported functions.
    store.set_fuel(100_000).ok();

    let Ok(instance) = Instance::new(&mut store, &module, &[]) else {
        return; // Linking failure (e.g., missing imports); not a bug.
    };

    // Call the first exported function, if any.
    // The goal is to exercise the execution engine, not test application logic.
    for export in module.exports() {
        if let ExternType::Func(_) = export.ty() {
            let func = instance.get_func(&mut store, export.name()).unwrap();
            // Call with all-zero arguments regardless of type.
            // Type mismatches are ignored; we want to reach the executor.
            let mut results = vec![Val::I32(0); func.ty(&store).results().len()];
            let params: Vec<Val> = func.ty(&store).params()
                .map(|t| match t {
                    ValType::I32 => Val::I32(0),
                    ValType::I64 => Val::I64(0),
                    ValType::F32 => Val::F32(0),
                    ValType::F64 => Val::F64(0),
                    _ => Val::I32(0),
                })
                .collect();
            let _ = func.call(&mut store, &params, &mut results);
            break; // One function call is sufficient for this harness.
        }
    }
});
```

```bash
# Install cargo-fuzz and run the harness.
cargo install cargo-fuzz

# Initialize a fuzz directory in your crate.
cargo fuzz init

# Run the fuzzer. Add -j N for N parallel jobs.
cargo +nightly fuzz run fuzz_wasmtime_compile -- \
  -max_len=65536 \          # Maximum module size. Larger is slower; start here.
  -timeout=30 \             # Kill runs that take more than 30 seconds.
  -runs=0 \                 # Run indefinitely (0 = no limit).
  -rss_limit_mb=2048        # Kill the fuzzer if it uses more than 2 GiB of RAM.
```

Wasmtime's own fuzzing corpus (in its GitHub repository under `crates/fuzzing/`) is the starting point for a seeded corpus. Seed with real `.wasm` files from production, known-good test modules, and Wasmtime's existing corpus:

```bash
# Seed the corpus directory.
mkdir -p corpus/fuzz_wasmtime_compile
cp path/to/wasmtime/crates/fuzzing/wasm-corpus/*.wasm corpus/fuzz_wasmtime_compile/
# Convert .wasm bytes to the raw byte sequences cargo-fuzz expects.
for f in corpus/fuzz_wasmtime_compile/*.wasm; do
  cp "$f" "corpus/fuzz_wasmtime_compile/$(sha256sum "$f" | cut -d' ' -f1)"
done
```

### Step 2: Differential Fuzzing Across WASM Runtimes

A single runtime finding its own bugs is useful. Comparing multiple runtimes against each other is more powerful: if two conforming runtimes disagree on the output of a valid module, at least one of them has a spec violation — possibly a security-relevant one. This is differential fuzzing.

The reference implementation is the WASM specification interpreter (written in OCaml). In practice, comparing Wasmtime and V8 (via Node.js) covers a wide set of production code paths.

```rust
// fuzz_targets/fuzz_differential.rs
// Run the same wasm-smith module in Wasmtime and a second interpreter,
// compare outputs. Divergence is a finding.
#![no_main]
use libfuzzer_sys::{fuzz_target, arbitrary::Unstructured};
use wasm_smith::{Config as SmithConfig, Module as SmithModule};
use wasmtime::*;
use std::process::Command;
use std::io::Write;
use tempfile::NamedTempFile;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    let smith_config = SmithConfig {
        // For differential testing, restrict to features both runtimes support.
        bulk_memory_enabled: true,
        reference_types_enabled: true,
        simd_enabled: false,       // V8 and Wasmtime may differ on NaN canonicalization in SIMD.
        threads_enabled: false,
        // Export at least one function so we have something to compare.
        min_exports: 1,
        max_exports: 3,
        max_memory_pages: 4,
        ..SmithConfig::default()
    };

    let Ok(module) = SmithModule::new(smith_config, &mut u) else { return; };
    let wasm_bytes = module.to_bytes();

    // --- Wasmtime execution ---
    let engine = Engine::default();
    let Ok(wt_module) = Module::new(&engine, &wasm_bytes) else { return; };
    let mut store = Store::new(&engine, ());
    store.set_fuel(50_000).ok();
    let Ok(instance) = Instance::new(&mut store, &wt_module, &[]) else { return; };

    let mut wasmtime_result: Option<Vec<Val>> = None;
    for export in wt_module.exports() {
        if let ExternType::Func(ft) = export.ty() {
            // Only compare functions with simple i32/i64 return types.
            if ft.results().all(|t| matches!(t, ValType::I32 | ValType::I64)) {
                let func = instance.get_func(&mut store, export.name()).unwrap();
                let params: Vec<Val> = ft.params()
                    .map(|t| match t {
                        ValType::I32 => Val::I32(1),
                        ValType::I64 => Val::I64(1),
                        _ => Val::I32(0),
                    })
                    .collect();
                let mut results = vec![Val::I32(0); ft.results().len()];
                if func.call(&mut store, &params, &mut results).is_ok() {
                    wasmtime_result = Some(results);
                }
                break;
            }
        }
    }

    let Some(wt_results) = wasmtime_result else { return; };

    // --- Node.js / V8 execution ---
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(&wasm_bytes).unwrap();

    // A small JS shim instantiates the module and calls the first exported function.
    let js = format!(
        r#"
        const fs = require('fs');
        const bytes = fs.readFileSync('{}');
        const mod = new WebAssembly.Module(bytes);
        const inst = new WebAssembly.Instance(mod, {{}});
        const exports = Object.entries(inst.exports);
        const [name, fn] = exports.find(([_, v]) => typeof v === 'function') || [null, null];
        if (fn) {{
            try {{
                const result = fn(1, 1, 1, 1);
                process.stdout.write(String(result) + '\n');
            }} catch(e) {{
                process.stdout.write('trap\n');
            }}
        }}
        "#,
        tmp.path().to_str().unwrap()
    );

    let output = Command::new("node")
        .arg("--eval")
        .arg(&js)
        .output();

    let Ok(v8_output) = output else { return; };
    if !v8_output.status.success() { return; }

    let v8_result_str = String::from_utf8_lossy(&v8_output.stdout).trim().to_string();
    if v8_result_str == "trap" { return; }

    // Compare Wasmtime's first result against V8's output.
    if let Some(Val::I32(n)) = wt_results.first() {
        let wt_str = n.to_string();
        if wt_str != v8_result_str {
            // Divergence detected. cargo-fuzz will save this as a finding.
            panic!(
                "Differential divergence: Wasmtime={} V8={}",
                wt_str, v8_result_str
            );
        }
    }
});
```

The panic on divergence causes cargo-fuzz to record the input as a crash, saves the reproducer to `fuzz/artifacts/`, and halts that run. Review every divergence: most will be NaN handling, floating-point edge cases, or implementation-defined behaviour. The rare one is a spec violation with security implications.

### Step 3: Fuzzing WASM Modules with cargo-fuzz

To find bugs in your own WASM module, the fuzzer passes crafted data through the module's exported API. The harness instantiates the module once (expensive) and calls the export repeatedly with fuzzer-generated inputs (cheap), relying on Wasmtime's `Store` fuel limit to prevent infinite loops.

```rust
// fuzz_targets/fuzz_image_module.rs
// Find memory corruption and logic bugs in an image-processing WASM module.
#![no_main]
use libfuzzer_sys::fuzz_target;
use wasmtime::*;
use wasmtime_wasi::preview2::{WasiCtxBuilder, Table, WasiCtx, WasiView};
use once_cell::sync::Lazy;

struct State {
    wasi: WasiCtx,
    table: Table,
}
impl WasiView for State {
    fn table(&self) -> &Table { &self.table }
    fn table_mut(&mut self) -> &mut Table { &mut self.table }
    fn ctx(&self) -> &WasiCtx { &self.wasi }
    fn ctx_mut(&mut self) -> &mut WasiCtx { &mut self.wasi }
}

// Compile the module once; re-instantiate per fuzzing run.
static ENGINE: Lazy<Engine> = Lazy::new(|| {
    let mut cfg = Config::new();
    cfg.consume_fuel(true);
    Engine::new(&cfg).unwrap()
});
static MODULE: Lazy<Module> = Lazy::new(|| {
    Module::from_file(&ENGINE, "target/wasm32-wasip2/release/image_processor.wasm").unwrap()
});

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 { return; }

    // Interpret the first 8 bytes as width/height/channels metadata.
    let width  = u16::from_le_bytes([data[0], data[1]]) as u32;
    let height = u16::from_le_bytes([data[2], data[3]]) as u32;
    let channels = (data[4] % 4) + 1;  // 1–4 channels.
    let pixel_data = &data[8..];

    // Reject obviously degenerate inputs before they reach WASM.
    // The fuzzer will find the boundary between accepted and rejected.
    if width == 0 || height == 0 { return; }

    let wasi = WasiCtxBuilder::new().build();
    let table = Table::new();
    let state = State { wasi, table };
    let mut store = Store::new(&ENGINE, state);
    store.set_fuel(5_000_000).unwrap();

    let linker = {
        let mut l = wasmtime::component::Linker::new(&ENGINE);
        wasmtime_wasi::preview2::command::add_to_linker(&mut l).unwrap();
        l
    };

    let Ok(instance) = linker.instantiate(&mut store, &MODULE) else { return; };

    // Write the fuzz input into the module's linear memory at offset 0.
    if let Some(memory) = instance.get_memory(&mut store, "memory") {
        let available = memory.data_size(&store);
        let write_len = pixel_data.len().min(available.saturating_sub(4096));
        if write_len > 0 {
            memory.write(&mut store, 4096, &pixel_data[..write_len]).ok();
        }
    }

    // Call the exported process function.
    // Any panic from Wasmtime here (not a module trap) is a bug.
    if let Ok(func) = instance.get_typed_func::<(u32, u32, u32, u32, u32), u32>(
        &mut store, "process_image"
    ) {
        let _ = func.call(&mut store, (4096, write_len(pixel_data), width, height, channels as u32));
    }
});

fn write_len(data: &[u8]) -> u32 {
    data.len().min(usize::MAX - 4096) as u32
}
```

Enable AddressSanitizer and MemorySanitizer for the fuzz build. These catch memory corruption bugs that do not produce an immediate crash — the sanitiser instruments the binary to detect out-of-bounds accesses and use of uninitialised memory at the point of access rather than later (or never):

```bash
# AddressSanitizer: detects buffer overflows, use-after-free, use-after-return.
RUSTFLAGS="-Z sanitizer=address" \
cargo +nightly fuzz run fuzz_image_module \
  --sanitizer address \
  -- -max_len=1048576 -timeout=60

# MemorySanitizer: detects use of uninitialised memory. Useful for C/C++ WASM modules.
# Requires an MSan-instrumented standard library; see cargo-fuzz docs.
RUSTFLAGS="-Z sanitizer=memory" \
cargo +nightly fuzz run fuzz_image_module \
  --sanitizer memory \
  -- -max_len=1048576 -timeout=60
```

Seed the corpus with real-world inputs that exercise your module's code paths:

```bash
# Corpus: real images, malformed images, edge-case sizes.
mkdir -p fuzz/corpus/fuzz_image_module
cp tests/fixtures/images/*.jpg fuzz/corpus/fuzz_image_module/
cp tests/fixtures/images/*.png fuzz/corpus/fuzz_image_module/
# Add edge cases: 1x1, maximum dimensions, zero channels.
python3 scripts/generate_edge_inputs.py >> fuzz/corpus/fuzz_image_module/
```

### Step 4: AFL++ Integration for C/C++ WASM Modules

For modules compiled from C or C++ via Emscripten or wasi-sdk, AFL++ with its persistent mode provides an efficient alternative to cargo-fuzz. Compile the target natively (not to WASM) with AFL++ instrumentation for the fuzzing harness, then separately fuzz the `.wasm` artifact for runtime bugs:

```bash
# Install AFL++.
sudo apt-get install afl++

# Compile the C source with AFL++ instrumentation for fast in-process fuzzing.
AFL_USE_ASAN=1 afl-clang-fast \
  -fsanitize=address,undefined \
  -g \
  src/image_processor.c \
  fuzz/afl_harness.c \
  -o fuzz/afl_image_processor

# AFL++ persistent-mode harness: fuzz/afl_harness.c
# -----------------------------------------------
# #include <stdint.h>
# #include <stddef.h>
# #include "image_processor.h"
#
# __AFL_FUZZ_INIT();
#
# int main(void) {
#     __AFL_INIT();
#     uint8_t *buf = __AFL_FUZZ_TESTCASE_BUF;
#     while (__AFL_LOOP(100000)) {
#         int len = __AFL_FUZZ_TESTCASE_LEN;
#         if (len < 8) continue;
#         uint16_t w = *(uint16_t*)(buf);
#         uint16_t h = *(uint16_t*)(buf + 2);
#         if (!w || !h) continue;
#         process_image(buf + 8, len - 8, w, h, buf[4] % 4 + 1);
#     }
#     return 0;
# }

# Run AFL++ with multiple cores.
mkdir -p fuzz/afl-out fuzz/afl-in
cp tests/fixtures/images/small.jpg fuzz/afl-in/

# Primary fuzzer.
afl-fuzz -i fuzz/afl-in -o fuzz/afl-out -M primary \
  -- fuzz/afl_image_processor @@

# Secondary fuzzers (one per additional core).
afl-fuzz -i fuzz/afl-in -o fuzz/afl-out -S secondary1 \
  -- fuzz/afl_image_processor @@
```

For fuzzing the `.wasm` artifact directly through a WASM runtime host:

```bash
# Compile the AFL++ harness as a native binary that runs the WASM module.
# The harness loads the .wasm, passes AFL input through the WASM ABI.
afl-clang-fast++ \
  -fsanitize=address \
  fuzz/afl_wasmtime_harness.cpp \
  -lwasmtime \
  -o fuzz/afl_wasmtime_runner

afl-fuzz -i fuzz/afl-in -o fuzz/afl-out \
  -- fuzz/afl_wasmtime_runner target/wasm32-wasi/release/image_processor.wasm @@
```

### Step 5: Coverage-Guided Fuzzing with Source Coverage

Coverage feedback is what separates fuzzing from random testing. The fuzzer preferentially saves inputs that reach new code paths, building a corpus that exercises the target more thoroughly over time. For Rust WASM modules, instrument with source coverage:

```bash
# Build the WASM module with coverage instrumentation.
# This produces a module that writes .profraw files when it exits.
RUSTFLAGS="-C instrument-coverage" \
cargo build --target wasm32-wasip2 --release

# After a fuzzing run, gather coverage data.
# The WASM module writes profraw to the host filesystem via WASI.
llvm-profdata merge -sparse fuzz/coverage/*.profraw -o fuzz/coverage/merged.profdata

llvm-cov report \
  --use-color \
  --ignore-filename-regex='/.cargo/registry' \
  --instr-profile=fuzz/coverage/merged.profdata \
  --object target/wasm32-wasip2/release/image_processor \
  > fuzz/coverage-report.txt

# Show coverage as HTML for review.
llvm-cov show \
  --format=html \
  --instr-profile=fuzz/coverage/merged.profdata \
  --object target/wasm32-wasip2/release/image_processor \
  -o fuzz/coverage-html/
```

Target at least 80% line coverage before considering the fuzz campaign adequate for a security audit. Functions with zero coverage despite a seeded corpus indicate dead code or code reachable only through unusual API sequences — both warrant manual review.

### Step 6: Fuzzing the Host Integration Layer

The host functions that WASM imports — the "import object" — are also attack surfaces. A module can call host functions with arbitrary argument values. If the host function uses those values as pointers, lengths, or indices without validation, the result is host-side memory corruption outside the WASM sandbox.

```rust
// fuzz_targets/fuzz_host_imports.rs
// Simulate a malicious WASM module calling host functions with adversarial arguments.
#![no_main]
use libfuzzer_sys::fuzz_target;
use wasmtime::*;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct HostCallSequence {
    calls: Vec<HostCall>,
}

#[derive(Arbitrary, Debug)]
enum HostCall {
    // Simulate "read_from_host(offset, length)" — does the host validate these?
    ReadFromHost { offset: u32, length: u32 },
    // Simulate "write_to_host(offset, data_ptr, data_len)".
    WriteToHost { offset: u32, data_ptr: u32, data_len: u32 },
    // Simulate "get_env(key_ptr, key_len, val_ptr, val_len_ptr)".
    GetEnv { key_ptr: u32, key_len: u32, val_ptr: u32 },
}

fuzz_target!(|seq: HostCallSequence| {
    let engine = Engine::default();
    let mut store = Store::new(&engine, ());

    // Build a host that receives adversarial calls and validates its own bounds.
    let mut linker = Linker::new(&engine);

    linker.func_wrap("env", "read_from_host", |mut caller: Caller<'_, ()>, offset: u32, length: u32| -> u32 {
        // The host MUST validate these before touching its own data structures.
        const HOST_BUFFER_LEN: u32 = 65536;
        if offset.saturating_add(length) > HOST_BUFFER_LEN {
            return u32::MAX; // Error: out of bounds.
        }
        0 // Success.
    }).unwrap();

    linker.func_wrap("env", "write_to_host", |mut caller: Caller<'_, ()>, offset: u32, data_ptr: u32, data_len: u32| -> u32 {
        const HOST_BUFFER_LEN: u32 = 65536;
        if offset.saturating_add(data_len) > HOST_BUFFER_LEN {
            return u32::MAX;
        }
        // Read from the module's linear memory.
        let mem = match caller.get_export("memory") {
            Some(Extern::Memory(m)) => m,
            _ => return u32::MAX,
        };
        let module_mem = mem.data(&caller);
        let end = (data_ptr as usize).saturating_add(data_len as usize);
        if end > module_mem.len() {
            return u32::MAX; // Module gave us an out-of-bounds pointer.
        }
        // Process module_mem[data_ptr..end] safely.
        0
    }).unwrap();

    // Build a minimal WAT module that calls these imports with fuzzer-controlled values.
    // In practice, the fuzzer generates the HostCallSequence; we synthesise the WAT here.
    let wat = format!(r#"
        (module
          (import "env" "read_from_host" (func $read (param i32 i32) (result i32)))
          (import "env" "write_to_host" (func $write (param i32 i32 i32) (result i32)))
          (memory 1)
          (func (export "run")
            (drop (call $read (i32.const {offset}) (i32.const {length})))
          )
        )"#,
        offset = seq.calls.first().map(|c| match c {
            HostCall::ReadFromHost { offset, .. } => *offset,
            _ => 0,
        }).unwrap_or(0),
        length = seq.calls.first().map(|c| match c {
            HostCall::ReadFromHost { length, .. } => *length,
            _ => 0,
        }).unwrap_or(0),
    );

    let Ok(module) = Module::new(&engine, wat.as_bytes()) else { return; };
    let Ok(instance) = linker.instantiate(&mut store, &module) else { return; };

    if let Ok(run) = instance.get_typed_func::<(), ()>(&mut store, "run") {
        let _ = run.call(&mut store, ());
    }
});
```

### Step 7: Continuous Fuzzing with OSS-Fuzz

Running fuzzing locally for hours is useful. Running it continuously at scale — on Google's ClusterFuzz infrastructure — is transformative. OSS-Fuzz runs open-source projects' fuzz harnesses 24 hours a day, accumulates coverage over weeks, and files issues automatically when crashes are found.

For a WASM runtime or library hosted on GitHub:

```yaml
# oss-fuzz/projects/my-wasm-runtime/project.yaml
homepage: "https://github.com/myorg/my-wasm-runtime"
language: rust
primary_contact: "security@myorg.com"
auto_ccs:
  - "security-team@myorg.com"
fuzzing_engines:
  - libfuzzer
  - afl
  - honggfuzz
sanitizers:
  - address
  - memory
  - undefined
  - coverage
```

```dockerfile
# oss-fuzz/projects/my-wasm-runtime/Dockerfile
FROM gcr.io/oss-fuzz-base/base-builder-rust

RUN apt-get update && apt-get install -y --no-install-recommends \
    nodejs \
    && rm -rf /var/lib/apt/lists/*

COPY build.sh $SRC/
RUN git clone --depth 1 https://github.com/myorg/my-wasm-runtime $SRC/my-wasm-runtime
WORKDIR $SRC/my-wasm-runtime
```

```bash
#!/usr/bin/env bash
# oss-fuzz/projects/my-wasm-runtime/build.sh

set -euxo pipefail
cd "$SRC/my-wasm-runtime"

# Build all fuzz targets with OSS-Fuzz's toolchain flags.
# CFLAGS, CXXFLAGS, RUSTFLAGS, and LIB_FUZZING_ENGINE are injected by the base image.
cargo fuzz build --release 2>/dev/null || true

# Copy the compiled fuzz binaries to $OUT.
for fuzzer in fuzz_wasmtime_compile fuzz_differential fuzz_image_module fuzz_host_imports; do
    if [ -f "fuzz/target/x86_64-unknown-linux-gnu/release/$fuzzer" ]; then
        cp "fuzz/target/x86_64-unknown-linux-gnu/release/$fuzzer" "$OUT/"
    fi
done

# Copy seed corpora. OSS-Fuzz merges these with its accumulated corpus.
zip -j "$OUT/fuzz_wasmtime_compile_seed_corpus.zip" \
    fuzz/corpus/fuzz_wasmtime_compile/*
zip -j "$OUT/fuzz_image_module_seed_corpus.zip" \
    fuzz/corpus/fuzz_image_module/*

# Copy dictionaries for structure-aware fuzzing of WAT syntax.
cp fuzz/dicts/wasm.dict "$OUT/fuzz_wasmtime_compile.dict"
```

For organisations with private code, ClusterFuzz can be self-hosted. The fuzzer runs continuously on GCP or on-premises infrastructure, files findings into your issue tracker, and surfaces coverage trends over time.

### Step 8: Triaging and Reproducing Fuzzer Crashes

A fuzzer crash is not immediately a vulnerability report. Triage determines severity before disclosure.

```bash
# A crash produces an artifact in fuzz/artifacts/.
ls fuzz/artifacts/fuzz_wasmtime_compile/
# crash-a1b2c3d4e5f6...

# Reproduce the crash deterministically.
cargo +nightly fuzz run fuzz_wasmtime_compile \
  fuzz/artifacts/fuzz_wasmtime_compile/crash-a1b2c3d4e5f6

# Minimise the crash input to the smallest reproducer.
# Smaller reproducers are easier to analyse and report.
cargo +nightly fuzz tmin fuzz_wasmtime_compile \
  fuzz/artifacts/fuzz_wasmtime_compile/crash-a1b2c3d4e5f6

# The minimised input is saved alongside the original.
ls fuzz/artifacts/fuzz_wasmtime_compile/
# crash-a1b2c3d4e5f6  minimized-from-a1b2c3d4e5f6

# Decode the minimised WASM to WAT for human review.
wasm-tools print fuzz/artifacts/fuzz_wasmtime_compile/minimized-from-a1b2c3d4e5f6 \
  > /tmp/crash.wat
cat /tmp/crash.wat
```

Classify the crash:

| Crash type | Severity | Action |
|------------|----------|--------|
| Wasmtime panic or abort during module compilation | High — runtime bug | Bisect Wasmtime commits; file CVE report to Bytecode Alliance security@ |
| Wasmtime process abort during module execution | Critical — potential sandbox escape | Escalate immediately; coordinate disclosure via security@bytecodealliance.org |
| Module trap (`unreachable`, fuel exhausted) | Not a bug | Verify the trap is the correct spec behaviour; discard |
| ASAN heap-buffer-overflow in module code | Medium — within-sandbox exploitation | Fix in the application module source; backport if deployed |
| Differential divergence between runtimes | Medium–High | Reduce to minimal reproducer; report to both runtimes' security teams |
| ASAN use-after-free in host integration | High — host memory corruption | Fix in the host embedding code; audit related host functions |

```bash
# For ASAN crashes: extract the symbolised stack trace.
ASAN_SYMBOLIZER_PATH=$(which llvm-symbolizer) \
cargo +nightly fuzz run fuzz_image_module \
  fuzz/artifacts/fuzz_image_module/crash-b2c3d4e5f6a1 \
  2>&1 | tee /tmp/asan-report.txt

# Parse the stack trace.
grep '^\s*#' /tmp/asan-report.txt | head -20
```

### Step 9: Pipeline Integration

```yaml
# .github/workflows/fuzz.yml
name: Continuous fuzzing
on:
  schedule:
    - cron: "0 2 * * *"    # Nightly at 02:00 UTC.
  push:
    branches: [main]
    paths:
      - "src/**"
      - "fuzz/**"

jobs:
  fuzz:
    runs-on: ubuntu-latest
    timeout-minutes: 120     # Two hours of fuzzing per CI run.
    steps:
      - uses: actions/checkout@v4

      - name: Install nightly Rust
        uses: dtolnay/rust-toolchain@nightly
        with:
          components: llvm-tools-preview

      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz --locked

      - name: Restore corpus cache
        uses: actions/cache@v4
        with:
          path: fuzz/corpus
          key: fuzz-corpus-${{ github.sha }}
          restore-keys: fuzz-corpus-

      - name: Build WASM module for fuzzing
        run: |
          rustup target add wasm32-wasip2
          cargo build --target wasm32-wasip2 --release

      - name: Fuzz runtime compilation (30 min)
        run: |
          cargo +nightly fuzz run fuzz_wasmtime_compile \
            -- -max_total_time=1800 -max_len=65536
        continue-on-error: false   # Crash = CI failure.

      - name: Fuzz application module (30 min)
        run: |
          cargo +nightly fuzz run fuzz_image_module \
            -- -max_total_time=1800 -max_len=1048576
        continue-on-error: false

      - name: Upload crash artifacts
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: fuzzer-crashes-${{ github.run_id }}
          path: fuzz/artifacts/
          retention-days: 90

      - name: Save corpus cache
        if: always()
        uses: actions/cache/save@v4
        with:
          path: fuzz/corpus
          key: fuzz-corpus-${{ github.sha }}
```

The corpus cache is critical: it persists the coverage accumulated across runs, so subsequent fuzzing builds on previous progress rather than starting from scratch. Without it, nightly fuzzing is less effective than a single long run.

## Expected Behaviour

| Signal | Without fuzzing | With fuzzing pipeline |
|--------|-----------------|----------------------|
| Wasmtime validator bug triggered by crafted module | Undetected until exploitation | Crash in fuzz_wasmtime_compile; filed before production exposure |
| Buffer overflow in image processor module | Passes unit tests; exploitable in production | ASAN crash in fuzz_image_module; found in nightly CI |
| Host function accepts out-of-bounds offset from module | Undetected; latent host corruption | Crash in fuzz_host_imports; fixed before deployment |
| Differential divergence between Wasmtime and V8 | Unknown; spec violation survives | Panic in fuzz_differential; reported to both runtimes |
| Corpus coverage improvement | Flat after initial runs | Corpus cache growth visible in coverage report; new code paths discovered over weeks |
| Crash reproducer available | Manually recreate from bug report | Minimised artifact in fuzz/artifacts/; reproducible in < 5 seconds |

Verify the pipeline finds a known-vulnerable pattern:

```bash
# Introduce a deliberate buffer overflow in image_processor.rs (test only).
# The fuzzer should find it within minutes.
cargo +nightly fuzz run fuzz_image_module \
  fuzz/corpus/fuzz_image_module/ \
  -- -max_total_time=600
# Expected: ASAN heap-buffer-overflow crash saved to fuzz/artifacts/.
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| wasm-smith over random bytes | Reaches execution engine; finds JIT and validator bugs | Requires understanding of wasm-smith config options | Start with SmithConfig::default(); tune feature flags to match your runtime's enabled proposals. |
| Differential fuzzing | Finds spec violations neither runtime would self-report | Requires two runtimes; cross-process overhead slows throughput | Run differential fuzzing separately from single-runtime fuzzing; accept lower iterations/second for higher-quality findings. |
| AddressSanitizer | Catches bugs that produce no immediate crash | 2–3x slowdown; only catches bugs in instrumented code | Use for nightly fuzzing; skip in performance benchmarks. |
| Corpus caching in CI | Preserves coverage progress across runs | Cache grows over time; can reach hundreds of MiB | Cap corpus size; run `cargo fuzz cmin` periodically to minimise the corpus without losing coverage. |
| OSS-Fuzz integration | Continuous at-scale fuzzing for free; ClusterFuzz infrastructure | Requires open-source project; private code needs self-hosted ClusterFuzz | Fuzz open-source dependencies (Wasmtime, wasm-tools) via OSS-Fuzz; fuzz proprietary modules with self-hosted AFL++. |
| Fuel limit in fuzz harness | Prevents hangs; allows high iteration rate | Low fuel may miss code paths only reachable after many iterations | Set fuel at 10–100x the average legitimate invocation cost; increase if coverage plateaus. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Corpus cache not saved between CI runs | Coverage plateaus; same bugs re-found repeatedly | Coverage report shows no growth after first run | Add `cache/save` step unconditionally at the end of the job (`if: always()`). |
| wasm-smith config excludes a relevant proposal | Runtime's handling of that proposal is never tested | Coverage report shows the proposal's code paths at 0% | Add the proposal to SmithConfig; verify the runtime actually supports it before enabling. |
| Fuel too low for the target module | Interesting code paths never reached; low branch coverage | Coverage report shows large unreached functions; fuzzer stalls | Double the fuel limit; check which functions have zero coverage and trace why. |
| ASAN not linked into the fuzz binary | Memory bugs occur but produce no ASAN report | Fuzzer crashes without ASAN traceback | Verify `--sanitizer address` flag is passed; check `cargo fuzz build` output for ASAN linkage messages. |
| Differential harness: Node.js not installed | V8 comparison step always returns error; no comparisons made | All `v8_output.status.success()` checks fail; zero divergence findings | Install Node.js in the fuzzing environment; verify `node --version` in the CI setup step. |
| Crash artifact not minimised before reporting | Large input obscures the root cause; developer time wasted | Reproducer runs for seconds; WAT disassembly is hundreds of lines | Always run `cargo fuzz tmin` before filing a bug; the minimised input is orders of magnitude smaller in most cases. |
| OSS-Fuzz build fails due to API drift | OSS-Fuzz stops fuzzing the project; bugs accumulate | OSS-Fuzz dashboard shows build failures | Monitor the OSS-Fuzz project dashboard; pin dependencies in the OSS-Fuzz Dockerfile rather than following HEAD. |

## Related Articles

- [WASM Linear Memory Safety: Bounds Checking, Buffer Overflows, and Stack Protection](/articles/wasm/wasm-linear-memory-safety/)
- [WASM Static Analysis and Vulnerability Scanning](/articles/wasm/wasm-static-analysis/)
- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [WASM AOT Compilation Pipeline Security](/articles/wasm/wasm-aot-compilation-security/)
- [WASM Toolchain Security](/articles/wasm/wasm-toolchain-security/)
