---
title: "Securing WASM Module Loading and Validation at Runtime"
description: "Loading an untrusted .wasm binary without explicit validation gates hands an attacker a structured sandbox escape surface. This article covers pre-load integrity checks, Wasmtime's multi-layer validator, import allowlisting, export surface auditing, and supply-chain verification before instantiation."
slug: wasm-module-loading-validation
date: 2026-05-07
lastmod: 2026-05-07
category: wasm
tags:
  - wasm
  - module-validation
  - runtime-security
  - supply-chain
  - integrity
personas:
  - security-engineer
  - platform-engineer
article_number: 572
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/wasm/wasm-module-loading-validation/
---

# Securing WASM Module Loading and Validation at Runtime

## Problem

Most embeddings of WebAssembly runtimes follow the same pattern: read bytes from disk or network, call `Module::new` (or the equivalent), instantiate, invoke. When the source of the bytes is fully controlled — your own build pipeline, your own OCI registry, your own filesystem — this is defensible. When the source is anything else — a user upload, a third-party plugin registry, a dynamically-fetched edge function — you need validation gates between the raw bytes and the running instance.

The WebAssembly binary format is specified precisely: a 4-byte magic header (`\0asm`), a 4-byte version field, then a sequence of typed sections. The specification mandates that validators check type correctness, stack discipline, memory-bounds coherence, and import/export type matching before any code runs. Runtimes implement this validation, but validation alone is not the whole story. The runtime validator answers "is this a structurally valid WASM module?" It does not answer:

- **Is this the module I expected?** (supply-chain integrity)
- **Does this module only import what my host exposes?** (import allowlisting)
- **Does this module export only the surface I intend to call?** (export auditing)
- **Is this module small enough that parsing it will not exhaust heap?** (pre-validation DoS prevention)
- **Has this module been evaluated in isolation before I plug it into production?** (sandboxed pre-flight)

Without explicit answers to each of these, the loading path is the widest attack surface in a WASM embedding. An attacker who can influence the bytes handed to `Module::new` can craft a module that: exploits a parser bug in the runtime, imports a host function they were not intended to receive, or consumes gigabytes of memory during section parsing before a single instruction runs.

**Target systems:** Wasmtime 22+ (Rust API), wasmparser 0.220+ for standalone validation, wasm-tools 1.220+ for structural inspection. Concepts apply equally to WasmEdge, Wasmer, and wazero with equivalent APIs.

## Threat Model

- **Adversary 1 — Malformed module via crafted upload:** an attacker submits a `.wasm` file that is syntactically valid enough to pass a magic-byte check but contains sections crafted to trigger a parser vulnerability or exhaust heap during parsing.
- **Adversary 2 — Substituted module in the load path:** a supply-chain attack replaces the module binary after the build pipeline produced it. The runtime receives a different set of bytes than was reviewed and signed.
- **Adversary 3 — Import surface expansion:** an attacker-controlled module declares imports from a host namespace that was never intended to be reachable — for example, a `env.eval` or `env.exec` that the host registered for a different module but did not restrict.
- **Adversary 4 — Export surface reduction or replacement:** a tampered module removes or renames legitimate exports and adds new ones. Host code that calls `get_typed_func("process")` succeeds but calls attacker code.
- **Adversary 5 — Oversized section DoS:** a module with a legitimate magic header but a `code` section claiming 256 MB of body. A naive embedder allocates the section's declared size before reading it, exhausting process heap.
- **Access level:** Adversary 1 and 3 need module-upload or module-push capability. Adversary 2 needs write access to the artifact store or delivery path. Adversary 4 has the same as Adversary 2. Adversary 5 needs upload capability only.
- **Objective:** Execute unauthorized code in the host process, access capabilities not granted to the module, cause denial of service during load.
- **Blast radius:** Load-time failures affect only the loading goroutine or thread; instantiation is never reached. Post-load failures (wrong imports, wrong exports) can give an unauthorized module host capability access before the mismatch is detected.

## Configuration

### Step 1: Pre-Validation Before Calling the Runtime

The first check happens before the runtime ever sees the bytes. Perform these in order, failing fast:

```rust
// pre_validate.rs — checks run before wasmtime::Module::new()
use std::io;

const WASM_MAGIC: &[u8; 4] = b"\0asm";
const WASM_VERSION: &[u8; 4] = &[1, 0, 0, 0];

// Absolute ceiling on module size before we inspect sections.
// Adjust to your use case; this example allows up to 32 MiB.
const MAX_MODULE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug)]
pub enum PreValidateError {
    TooSmall,
    TooLarge(usize),
    BadMagic([u8; 4]),
    BadVersion([u8; 4]),
}

pub fn pre_validate(bytes: &[u8]) -> Result<(), PreValidateError> {
    // Minimum: 8 bytes (magic + version).
    if bytes.len() < 8 {
        return Err(PreValidateError::TooSmall);
    }

    // Enforce byte-count ceiling before any further parsing.
    // Prevents heap exhaustion during section-level analysis.
    if bytes.len() > MAX_MODULE_BYTES {
        return Err(PreValidateError::TooLarge(bytes.len()));
    }

    // Check magic bytes.
    let magic: [u8; 4] = bytes[0..4].try_into().unwrap();
    if &magic != WASM_MAGIC {
        return Err(PreValidateError::BadMagic(magic));
    }

    // Check WASM version field.
    let version: [u8; 4] = bytes[4..8].try_into().unwrap();
    if &version != WASM_VERSION {
        return Err(PreValidateError::BadVersion(version));
    }

    Ok(())
}
```

The size ceiling is the most important check here. The WASM binary format encodes section sizes as LEB128 integers; a parser that allocates `vec![0u8; declared_section_size]` before reading section bytes will allocate whatever the attacker declares. The ceiling turns a potential OOM into a clean rejection before any section parsing begins.

### Step 2: Standalone wasmparser Validation with Feature Lockdown

After the pre-validation gate, run the standalone `wasmparser` validator with an explicit feature set. This is a separate validation pass from Wasmtime's internal validator; running both means the module must satisfy two independent implementations of the spec.

```rust
// validation.rs
use wasmparser::{Validator, WasmFeatures};

pub fn validate_with_features(bytes: &[u8]) -> anyhow::Result<()> {
    // Build a feature set that matches your host's Config.
    // Reject features the runtime is not configured to support —
    // a module that uses threads when the host disables threads is a red flag.
    let features = WasmFeatures {
        // Core features present in all production modules.
        mutable_global: true,
        saturating_float_to_int: true,
        sign_extension: true,
        reference_types: true,
        multi_value: true,
        bulk_memory: true,
        simd: true,
        relaxed_simd: false,    // Less audited; disable unless required.
        tail_call: true,
        multi_memory: false,    // Disable until policy decision made.
        threads: false,         // No shared linear memory.
        exceptions: false,      // Not yet stable in all runtimes.
        memory64: false,        // 64-bit addressing; rare in production.
        extended_const: true,
        component_model: false, // Enable only if loading components.
        gc: false,              // Disable GC proposal unless explicitly needed.
        ..WasmFeatures::default()
    };

    let mut validator = Validator::new_with_features(features);
    validator.validate_all(bytes)?;
    Ok(())
}
```

Disabling a feature at the validator level rejects any module that uses it — before the module is handed to the runtime. If a module uses `wasm_threads` when the host has disabled `config.wasm_threads(false)`, standalone validation catches it and the reject happens in the validation layer rather than at compile time inside the runtime.

### Step 3: Structural Inspection with wasm-tools

After byte-level and spec validation, inspect the module's structural sections to extract import and export declarations. Use the `wasmparser` crate's section iterator (or the `wasm-tools` CLI in a CI context) to read the import and export sections without executing any code.

```rust
// section_inspector.rs
use wasmparser::{Parser, Payload, TypeRef};

#[derive(Debug)]
pub struct ModuleImport {
    pub module: String,
    pub name: String,
    pub ty: String,  // "func", "table", "memory", "global"
}

#[derive(Debug)]
pub struct ModuleExport {
    pub name: String,
    pub kind: String, // "func", "table", "memory", "global"
}

pub fn extract_imports(bytes: &[u8]) -> anyhow::Result<Vec<ModuleImport>> {
    let mut imports = Vec::new();

    for payload in Parser::new(0).parse_all(bytes) {
        match payload? {
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import?;
                    let ty = match import.ty {
                        TypeRef::Func(_)   => "func",
                        TypeRef::Table(_)  => "table",
                        TypeRef::Memory(_) => "memory",
                        TypeRef::Global(_) => "global",
                        TypeRef::Tag(_)    => "tag",
                    };
                    imports.push(ModuleImport {
                        module: import.module.to_string(),
                        name:   import.name.to_string(),
                        ty:     ty.to_string(),
                    });
                }
            }
            Payload::ExportSection(reader) => {
                // Stop after exports — we only need imports here.
                let _ = reader; // handled in extract_exports()
            }
            _ => {}
        }
    }

    Ok(imports)
}

pub fn extract_exports(bytes: &[u8]) -> anyhow::Result<Vec<ModuleExport>> {
    let mut exports = Vec::new();

    for payload in Parser::new(0).parse_all(bytes) {
        if let Payload::ExportSection(reader) = payload? {
            for export in reader {
                let export = export?;
                let kind = format!("{:?}", export.kind).to_lowercase();
                exports.push(ModuleExport {
                    name: export.name.to_string(),
                    kind,
                });
            }
        }
    }

    Ok(exports)
}
```

These functions parse only the import and export sections, never executing any bytecode. The output is the raw declaration of what the module claims to need from the host and what it claims to provide.

### Step 4: Import Allowlisting

With the declared imports in hand, compare them against an explicit allowlist. Reject any module that requests a host function, memory, table, or global not on the list.

```rust
// import_allowlist.rs
use std::collections::HashSet;
use crate::section_inspector::ModuleImport;

/// A specific allowed import: (module namespace, export name, expected type).
#[derive(Debug, Eq, PartialEq, Hash)]
pub struct AllowedImport {
    pub module: &'static str,
    pub name:   &'static str,
    pub ty:     &'static str,
}

/// The host exposes exactly these imports to untrusted plugin modules.
/// Any module requesting anything outside this set is rejected at load time.
pub const PLUGIN_IMPORT_ALLOWLIST: &[AllowedImport] = &[
    // WASI preview 1 — a controlled subset.
    AllowedImport { module: "wasi_snapshot_preview1", name: "fd_write",      ty: "func" },
    AllowedImport { module: "wasi_snapshot_preview1", name: "fd_read",       ty: "func" },
    AllowedImport { module: "wasi_snapshot_preview1", name: "proc_exit",     ty: "func" },
    AllowedImport { module: "wasi_snapshot_preview1", name: "random_get",    ty: "func" },
    AllowedImport { module: "wasi_snapshot_preview1", name: "clock_time_get",ty: "func" },

    // Host plugin API — functions the host explicitly exposes to plugins.
    AllowedImport { module: "env", name: "log_event",    ty: "func" },
    AllowedImport { module: "env", name: "get_config",   ty: "func" },

    // Linear memory (declared by the module, provided by the module itself).
    // If the module imports memory from the host, that is usually a red flag.
];

pub fn check_imports(imports: &[ModuleImport]) -> Result<(), String> {
    let allowed: HashSet<(&str, &str, &str)> = PLUGIN_IMPORT_ALLOWLIST
        .iter()
        .map(|a| (a.module, a.name, a.ty))
        .collect();

    for import in imports {
        // Block modules that import memory directly from the host.
        // Legitimate modules define their own linear memory; importing one
        // from the host gives the module a shared pointer into host address space.
        if import.ty == "memory" {
            return Err(format!(
                "Module imports host memory '{}:{}' — rejected. \
                 Modules must define their own linear memory.",
                import.module, import.name
            ));
        }

        let key = (import.module.as_str(), import.name.as_str(), import.ty.as_str());
        if !allowed.contains(&key) {
            return Err(format!(
                "Module declares unauthorized import '{}:{}' (type: {}) — rejected.",
                import.module, import.name, import.ty
            ));
        }
    }

    Ok(())
}
```

The memory-import check deserves separate attention. A WASM module that imports a `memory` from the host rather than defining its own is requesting a shared linear memory segment. This is used in Emscripten-style dynamic linking but has no place in an untrusted plugin context — a module with access to shared host memory can read and write the host's heap directly, bypassing all sandbox guarantees. Reject it unconditionally in plugin contexts.

### Step 5: Export Surface Auditing

Verify that the module exports exactly the functions the host intends to call, and nothing more. An unexpected export surface is a signal: the module may have been tampered with (adding a backdoor export) or may be the wrong module entirely.

```rust
// export_auditor.rs
use std::collections::{HashMap, HashSet};
use crate::section_inspector::ModuleExport;

/// Defines which exports a module must provide and which it must not.
pub struct ExportPolicy {
    /// Exports the module MUST declare (required for the host to function).
    pub required: HashSet<&'static str>,
    /// Exports the module MAY declare (expected optional exports).
    pub allowed:  HashSet<&'static str>,
    /// Exports the module MUST NOT declare (known dangerous names).
    pub blocked:  HashSet<&'static str>,
    /// If true, any export not in `required` or `allowed` causes rejection.
    pub strict:   bool,
}

pub fn audit_exports(
    exports: &[ModuleExport],
    policy: &ExportPolicy,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    let declared: HashSet<&str> = exports.iter().map(|e| e.name.as_str()).collect();

    // Check all required exports are present.
    for req in &policy.required {
        if !declared.contains(req) {
            errors.push(format!("Missing required export: '{}'", req));
        }
    }

    // Check no blocked export is present.
    for export in exports {
        if policy.blocked.contains(export.name.as_str()) {
            errors.push(format!(
                "Module declares blocked export '{}' — rejected.",
                export.name
            ));
        }

        // In strict mode, every export must be in required or allowed.
        if policy.strict
            && !policy.required.contains(export.name.as_str())
            && !policy.allowed.contains(export.name.as_str())
        {
            errors.push(format!(
                "Module declares unexpected export '{}' (strict mode) — rejected.",
                export.name
            ));
        }
    }

    if errors.is_empty() { Ok(()) } else { Err(errors) }
}

// Example policy for a payment-processing plugin:
pub fn payments_plugin_policy() -> ExportPolicy {
    ExportPolicy {
        required: ["process_payment", "health_check", "memory"].iter().cloned().collect(),
        allowed:  ["__wasm_call_ctors", "_initialize", "__data_end", "__heap_base"]
            .iter().cloned().collect(),
        blocked:  ["debug_shell", "eval", "exec", "get_credentials"]
            .iter().cloned().collect(),
        strict:   true,
    }
}
```

The `blocked` list catches known-dangerous names. An operator can add entries for any export name that has previously been used as a backdoor or that matches debug tooling that should never ship. The `strict` flag enforces that no additional exports exist beyond the declared allowlist — appropriate for production modules where every function surface should be intentional and reviewed.

### Step 6: Supply-Chain Validation at Load Time

Before any of the above structural checks are meaningful, you must verify that the bytes being validated are the bytes you expected. Hash verification and cosign-based signature verification are the two mechanisms:

```rust
// integrity.rs
use sha2::{Digest, Sha256};
use std::process::Command;

/// Verify a module's SHA-256 digest against a pinned expected value.
/// The expected value is sourced from a signed manifest (not the module itself).
pub fn verify_sha256(bytes: &[u8], expected_hex: &str) -> Result<(), String> {
    let actual = format!("{:x}", Sha256::digest(bytes));
    if actual != expected_hex {
        Err(format!(
            "Module integrity check FAILED:\n  expected: {}\n  actual:   {}",
            expected_hex, actual
        ))
    } else {
        Ok(())
    }
}

/// Verify a cosign signature for a module stored in an OCI registry.
/// Requires the cosign binary and access to Sigstore (or your own Fulcio/Rekor).
pub fn verify_cosign_signature(
    image_ref: &str,
    certificate_identity: &str,
    certificate_oidc_issuer: &str,
) -> Result<(), String> {
    // cosign verify uses keyless verification against Sigstore transparency log.
    let status = Command::new("cosign")
        .args([
            "verify",
            "--certificate-identity",    certificate_identity,
            "--certificate-oidc-issuer", certificate_oidc_issuer,
            image_ref,
        ])
        .status()
        .map_err(|e| format!("cosign exec failed: {}", e))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("cosign signature verification FAILED for {}", image_ref))
    }
}
```

Use SHA-256 digest verification when the module is fetched by content address (OCI digest reference, direct URL with expected digest). Use cosign signature verification when the module is pulled by tag or name — the signature proves the bytes were produced by a trusted build identity, independent of where the bytes are stored.

Store expected digests in a signed lock file committed to your repository:

```yaml
# wasm-modules.lock — signed with sigstore or PGP; never edit by hand.
# Update only through the CI pipeline that also updates module sources.

modules:
  payments-plugin:
    source: ghcr.io/myorg/wasm/payments-plugin@sha256:abc123def456...
    sha256: abc123def456789...
    cosign_identity: https://github.com/myorg/payments-plugin/.github/workflows/release.yml@refs/heads/main
    cosign_issuer: https://token.actions.githubusercontent.com
    allowed_imports:
      - wasi_snapshot_preview1:fd_write:func
      - wasi_snapshot_preview1:proc_exit:func
      - env:log_event:func
    required_exports:
      - process_payment
      - health_check

  analytics-plugin:
    source: ghcr.io/myorg/wasm/analytics@sha256:789ghi012jkl...
    sha256: 789ghi012jkl345...
    cosign_identity: https://github.com/myorg/analytics/.github/workflows/release.yml@refs/heads/main
    cosign_issuer: https://token.actions.githubusercontent.com
    allowed_imports:
      - wasi_snapshot_preview1:fd_write:func
      - wasi_snapshot_preview1:random_get:func
    required_exports:
      - analyze
```

### Step 7: Sandboxed Pre-Flight Evaluation

After all static checks pass, run the module through a restricted sandboxed instantiation before connecting it to production linker state. The pre-flight instantiation uses a minimal linker that provides stub implementations of all expected imports — no real host capabilities, no real I/O. The module is instantiated and its exported entry points are called with fuzzed or empty inputs to surface runtime panics, invalid memory accesses, and fuel exhaustion before the module enters the production pool.

```rust
// preflight.rs
use wasmtime::{Config, Engine, Linker, Module, Store};
use wasmtime_wasi::preview2::WasiCtxBuilder;

pub fn preflight_validate(wasm_bytes: &[u8]) -> anyhow::Result<()> {
    // Separate engine with restrictive config for pre-flight only.
    let mut config = Config::new();
    config.consume_fuel(true);
    config.epoch_interruption(true);
    config.wasm_threads(false);
    config.wasm_multi_memory(false);
    config.static_memory_maximum_size(16 * 1024 * 1024); // 16 MiB max for pre-flight.

    let engine = Engine::new(&config)?;

    // Pre-flight linker: only stub implementations — no real capabilities.
    let mut linker: Linker<()> = Linker::new(&engine);

    // Stub every expected import with a no-op that returns a default value.
    // This tests that the module links cleanly without providing any real capability.
    linker.func_wrap("wasi_snapshot_preview1", "fd_write",
        |_fd: i32, _iovs: i32, _iovs_len: i32, _nwritten: i32| -> i32 { 0 })?;
    linker.func_wrap("wasi_snapshot_preview1", "proc_exit",
        |_code: i32| {})?;
    linker.func_wrap("wasi_snapshot_preview1", "random_get",
        |_buf: i32, _buf_len: i32| -> i32 { 0 })?;
    linker.func_wrap("env", "log_event",
        |_ptr: i32, _len: i32| {})?;
    linker.func_wrap("env", "get_config",
        |_key_ptr: i32, _key_len: i32, _out_ptr: i32, _out_len: i32| -> i32 { 0 })?;

    let module = Module::new(&engine, wasm_bytes)?;
    let mut store = Store::new(&engine, ());

    // Very tight resource limits for pre-flight.
    store.set_fuel(1_000_000)?;       // 1M ops; enough to initialize, not enough to run.
    store.set_epoch_deadline(1)?;

    // Attempt instantiation — this runs start functions and module initialization.
    let instance = linker.instantiate(&mut store, &module)?;

    // Verify that each required export exists and has the expected signature.
    let process = instance.get_func(&mut store, "process_payment");
    if process.is_none() {
        anyhow::bail!("Pre-flight: module missing required export 'process_payment'");
    }

    // Optionally: call the health_check export with stub input to
    // verify the module returns cleanly.
    if let Some(health) = instance.get_typed_func::<(), i32>(&mut store, "health_check").ok() {
        let result = health.call(&mut store, ())?;
        if result != 0 {
            anyhow::bail!("Pre-flight: health_check returned non-zero ({})", result);
        }
    }

    Ok(())
}
```

Pre-flight evaluation catches a class of problems that static analysis cannot: a module whose start function panics, whose initialization triggers an invalid memory access, or whose `health_check` export has an incompatible type signature. It also confirms that the import stubs cover all imports the module requests — if the module declares an import that the pre-flight linker does not provide, instantiation fails cleanly here rather than in production.

### Step 8: Assembling the Full Load Pipeline

Compose all checks into a single load function that enforces ordering:

```rust
// loader.rs
use crate::{pre_validate, validate_with_features, extract_imports, extract_exports,
            check_imports, audit_exports, verify_sha256, preflight_validate,
            payments_plugin_policy};

pub struct LoadedModule {
    pub module: wasmtime::Module,
    pub engine: wasmtime::Engine,
}

pub fn load_verified_module(
    bytes: &[u8],
    expected_sha256: &str,
) -> anyhow::Result<LoadedModule> {
    // 1. Supply-chain: check digest before doing any parsing.
    //    If the bytes are wrong, do not spend CPU on parsing them.
    verify_sha256(bytes, expected_sha256)
        .map_err(|e| anyhow::anyhow!(e))?;

    // 2. Pre-validate: magic bytes, version, size ceiling.
    pre_validate(bytes)
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    // 3. Standalone spec validation with feature lockdown.
    validate_with_features(bytes)?;

    // 4. Extract and check imports against allowlist.
    let imports = extract_imports(bytes)?;
    check_imports(&imports)
        .map_err(|e| anyhow::anyhow!(e))?;

    // 5. Extract and audit exports against policy.
    let exports = extract_exports(bytes)?;
    let policy = payments_plugin_policy();
    audit_exports(&exports, &policy)
        .map_err(|errs| anyhow::anyhow!("Export audit failed:\n{}", errs.join("\n")))?;

    // 6. Sandboxed pre-flight instantiation.
    preflight_validate(bytes)?;

    // 7. Only now: compile for production.
    let mut config = wasmtime::Config::new();
    config.consume_fuel(true);
    config.epoch_interruption(true);
    config.wasm_threads(false);
    config.wasm_multi_memory(false);
    config.static_memory_maximum_size(32 * 1024 * 1024);

    let engine = wasmtime::Engine::new(&config)?;
    let module = wasmtime::Module::new(&engine, bytes)?;

    Ok(LoadedModule { module, engine })
}
```

Each gate in this pipeline rejects on a specific property. A breach of any one gate terminates the load, records the failure reason, and returns an error — no bytes reach the next stage. The order is deliberate: supply-chain verification runs first because it is cheapest (a single hash computation) and eliminates the need to parse adversarial bytes that are known-wrong from the start.

### Step 9: Telemetry

```
wasm_load_attempts_total{module, stage}                    counter
wasm_load_rejections_total{module, stage, reason}          counter
wasm_preflight_instantiation_duration_ms{module}           histogram
wasm_import_violations_total{module, namespace, name}      counter
wasm_export_violations_total{module, export_name, reason}  counter
wasm_integrity_check_failures_total{module}                counter
wasm_module_size_bytes{module}                             histogram
```

Alert on:

- `wasm_load_rejections_total{stage="supply_chain"}` — a module with a bad digest reached the load pipeline; investigate delivery path and registry integrity.
- `wasm_load_rejections_total{stage="import_allowlist"}` — a module is requesting an unauthorized host import; review the module source and submitter.
- `wasm_import_violations_total{namespace="env", name="exec"}` or any dangerous name — specific pattern matching; investigate module origin immediately.
- `wasm_preflight_instantiation_duration_ms` outliers — a module's initialization takes unusually long even in preflight; may indicate CPU-intensive start functions designed to exhaust resources.
- `wasm_load_rejections_total{stage="size_ceiling"}` — large modules being submitted; may be DoS attempt or misconfigured build.

## Expected Behaviour

| Input module | Naive loader | Hardened pipeline |
|---|---|---|
| Correct module, correct digest | Loads and runs | All checks pass; loads and runs |
| Module with bad magic bytes | Parser error inside runtime | Rejected at pre-validate (magic check) |
| Module 200 MiB in size | Parser OOM or slow parse | Rejected at pre-validate (size ceiling) |
| Module with `env:exec` import | Links if host registered `exec` | Rejected at import allowlist check |
| Module importing host `memory` | Grants shared memory access | Rejected at import allowlist (memory import rule) |
| Tampered module (digest mismatch) | Executes tampered code | Rejected at supply-chain hash check |
| Module missing `process_payment` export | Host call panics at runtime | Rejected at export audit (missing required) |
| Module with undeclared `debug_shell` export | Accessible via direct call | Rejected at export audit (blocked export) |
| Module with failing start function | Runtime panic at first instantiation | Caught at pre-flight; not admitted to production |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| SHA-256 pre-check before parsing | Eliminates adversarial parse cost | Hash computation on every load (~1–5ms for 10 MiB) | Cache verification result by (path, mtime) in a trusted sidecar |
| Standalone wasmparser + runtime validation | Two independent spec implementations | ~5–20ms extra per module at load time | Run once at upload; cache the compiled artifact |
| Strict import allowlisting | Smallest possible host capability surface | Any new host function requires allowlist update | Document allowed host ABI in WIT; use the WIT as the source of truth for the allowlist |
| Pre-flight instantiation | Catches runtime-only issues before production | ~50–200ms per module at load time | Run pre-flight at upload/deploy time, not per-invocation; cache pass/fail by module digest |
| Strict export policy | Ensures module surface matches spec | Legitimate WASM toolchains add internal exports (e.g., `__wasm_call_ctors`) | Enumerate toolchain-generated exports in the `allowed` set; update when upgrading compiler |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Allowlist too narrow | Legitimate module rejected for using a WASI function not in the list | `wasm_load_rejections_total{stage="import_allowlist"}` with known-good modules | Audit what the module actually needs; add the specific function to the allowlist; re-review the host registration for that function |
| Pre-flight linker missing a stub | Pre-flight fails because the linker does not define an import the module uses | Error: `unknown import: env::some_func` during pre-flight | Add the stub to the pre-flight linker; verify the production linker provides the same function |
| Size ceiling too low for legitimate module | Large but valid modules rejected | `wasm_load_rejections_total{stage="size_ceiling"}` for known-good modules | Profile legitimate module sizes; set ceiling at 2x the largest legitimate module |
| Digest lock file out of date | Every load fails with digest mismatch after a module update | `wasm_integrity_check_failures_total` spike post-deployment | Automate lock file update in CI when modules are rebuilt; sign the lock file |
| Export allowlist misses toolchain internals | Strict mode rejects modules built with a new compiler version | `wasm_load_rejections_total{stage="export_audit"}` after compiler upgrade | Add toolchain-generated exports to the `allowed` set; update policy when upgrading the compiler |
| Wasmtime parser bug reached before pre-validate | Crafted module bypasses size check via multi-level headers | Runtime crash or memory spike during `Module::new` | Keep Wasmtime updated; apply pre-validate before any runtime API is called; monitor for CVEs |

## Related Articles

- [WASM Module Static Analysis and Vulnerability Scanning](/articles/wasm/wasm-static-analysis/)
- [OCI WASM Module Signing and Verification](/articles/wasm/wasm-oci-signing/)
- [WASM Dynamic Linking Security](/articles/wasm/wasm-dynamic-linking-security/)
- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [WASM Supply Chain Scanning Tools](/articles/wasm/wasm-supply-chain-scanning-tools/)
