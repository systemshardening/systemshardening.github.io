---
title: "WebAssembly Dynamic Linking Security: Module Composition, Trust Chains, and Plugin Graphs"
description: "WebAssembly's component model enables dynamic module composition — linking multiple WASM modules at runtime into a single application. This creates trust boundary questions: when modules import functions from each other, which module's security context applies, and how do you prevent a low-trust module from abusing a high-trust module's exports?"
slug: "wasm-dynamic-linking-security"
date: 2026-05-01
lastmod: 2026-05-01
category: "wasm"
tags: ["wasm", "dynamic-linking", "component-model", "trust-boundary", "module-composition"]
personas: ["platform-engineer", "security-engineer"]
article_number: 302
difficulty: "advanced"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/wasm/wasm-dynamic-linking-security/index.html"
---

# WebAssembly Dynamic Linking Security: Module Composition, Trust Chains, and Plugin Graphs

## Problem

Static WASM modules — a single `.wasm` binary that runs in isolation — have a well-understood security model: capabilities flow from the host to the module via explicit imports. Dynamic linking changes this: multiple WASM modules compose at runtime, importing and exporting functions from each other, sharing memory segments, and forming a graph of trust relationships.

The WebAssembly Component Model (standardised in 2024) provides the formal foundation for dynamic module composition. Components import and export interfaces (defined in WIT — WASM Interface Types), and the runtime links them together. This enables plugin architectures, shared library reuse, and microkernel patterns — but introduces security questions that static linking avoids:

- **Confused deputy attacks via module imports.** Module A has `filesystem-read` capability. Module B is untrusted but imports a function from Module A. If Module A's exported function unconditionally uses `filesystem-read` on behalf of any caller, Module B inherits access to the filesystem through A — even though B was never granted that capability directly.
- **Trust escalation via component composition.** A low-trust plugin module is composed with a high-trust utility module. The utility exports a general-purpose HTTP function. The plugin calls the utility's HTTP export with a URL to an internal metadata endpoint, using the utility's network access as a confused deputy.
- **Shared linear memory between linked modules.** Some dynamic linking approaches share linear memory between modules. A malicious module that shares memory can read and write the trusted module's data — including credentials, keys, and application state — bypassing the usual memory isolation guarantee.
- **Module graph supply chain attacks.** A composed application depends on 10 WASM modules from 5 vendors. One module in the dependency graph is compromised. The compromised module's imports grant it access to capabilities transitively provided by other modules in the graph.
- **Dynamic dispatch exploitation.** A WASM module that accepts function references (via the function references proposal) as arguments can be passed an attacker-controlled function reference, causing the module to call attacker code with the caller's capabilities.

**Target systems:** WASM Component Model 1.0 (WIT, Wasmtime 20+, WASM Tools); Extism with multiple linked plugin modules; wasm-bindgen multi-module Rust/JS projects; Emscripten dynamic linking (`SIDE_MODULE`, `MAIN_MODULE`); WASI-NN with dynamically loaded backend modules.

## Threat Model

- **Adversary 1 — Confused deputy via imported high-capability function:** An untrusted plugin module imports `read-config()` from a trusted core module. The trusted module's `read-config()` returns any configuration key without checking the caller's identity. The plugin calls `read-config("database-password")` and exfiltrates the value.
- **Adversary 2 — Shared linear memory read across trust boundary:** Two WASM modules are linked with shared linear memory (Emscripten-style). The untrusted module scans the shared memory space, finds the trusted module's stack and heap, and extracts private keys or session tokens written there.
- **Adversary 3 — Module graph dependency substitution:** An attacker publishes a WASM module with a name similar to a popular utility module in a WASM registry. A composed application pulls the attacker's module as a dependency. The attacker's module calls the legitimate modules' imports — including filesystem and network — on behalf of the attacker.
- **Adversary 4 — Function reference as capability confusion:** A WASM module accepts a function reference parameter and calls it with trusted data. An attacker passes a function reference pointing to an attacker-controlled module function, causing the trusted module to call attacker code with trusted-context data.
- **Adversary 5 — Interface type confusion:** Two components export the same WIT interface with the same type signatures but different semantics. A component that expects the trusted version of the interface is linked with the attacker's version, which logs all arguments or returns modified values.
- **Access level:** Adversaries 1, 2, and 4 only need to run code in the same composed environment. Adversary 3 needs registry access. Adversary 5 needs the ability to supply a module to the composition.
- **Objective:** Escalate capabilities across module trust boundaries; access data from higher-trust modules; execute code in the high-trust module's context.
- **Blast radius:** In a composed application where one high-trust module handles credentials or I/O, a confused deputy attack gives any co-linked module the same capabilities — defeating the per-module capability grant that makes WASM's security model valuable.

## Configuration

### Step 1: Component Model Trust Architecture

Design the module composition graph with explicit trust tiers:

```
# Principle: capabilities flow down (from host to modules), never up or sideways.
# A module should only be able to do what its explicit capability grant allows,
# regardless of what other modules it is composed with.

# Trusted tier (host-adjacent, full capabilities):
#   ┌────────────────────────────────────┐
#   │  Host (native code)                │
#   │  Grants: filesystem, network, etc. │
#   └─────────────┬──────────────────────┘
#                 │ explicit capability grants
#   ┌─────────────▼──────────────────────┐
#   │  Core Module (high trust)          │
#   │  Has: filesystem-read (config dir) │
#   │  Exports: get-config(key: string)  │
#   └─────────────┬──────────────────────┘
#                 │ limited exports only
#   ┌─────────────▼──────────────────────┐
#   │  Plugin Module (low trust)         │
#   │  Has: none (no host capabilities)  │
#   │  Imports: get-config (filtered)    │  ← Core filters what plugin can read.
#   └────────────────────────────────────┘
```

```rust
// Core module: filter what plugins can access before forwarding.
// The core module mediates access to its capabilities.

use wit_bindgen::generate;

generate!({
    world: "core-world",
    exports: {
        "example:core/config": Config,
    },
});

struct Config;

impl exports::example::core::config::Guest for Config {
    // Plugin-callable config reader — filter sensitive keys.
    fn get_config(key: String) -> Option<String> {
        // Allowlist: only these config keys are accessible to plugins.
        const PLUGIN_ACCESSIBLE: &[&str] = &[
            "feature-flags",
            "api-endpoint",
            "timeout-ms",
        ];
        
        if !PLUGIN_ACCESSIBLE.contains(&key.as_str()) {
            // Log the attempted access.
            log_access_violation(&key);
            return None;  // Deny access silently; do not reveal that the key exists.
        }
        
        // Safe to return — this key is in the allowlist.
        read_actual_config(&key)
    }
}
```

### Step 2: WIT Interface Design for Trust Separation

Define WIT interfaces with the minimum necessary exposure:

```wit
// interfaces/plugin-api.wit
// This interface is what plugins see — a minimal, safe subset.
package example:plugin-api;

interface config {
    // Only expose non-sensitive configuration.
    // Plugin cannot request arbitrary keys.
    get-feature-flag: func(name: string) -> bool;
    get-timeout: func() -> u32;
    // NOT: get-config(key: string) -> string  — too broad.
}

interface logging {
    // Plugins can log but cannot read other plugins' logs.
    log-info: func(message: string);
    log-error: func(message: string);
    // NOT: read-logs() — would expose other plugins' log data.
}

// What plugins are NOT given:
// - filesystem access
// - network access
// - access to other plugins' state
// - raw config access
world plugin {
    import config;
    import logging;
    export plugin-main: func(input: string) -> string;
}
```

```wit
// interfaces/core-api.wit
// Separate WIT world for the core module — broader capabilities.
package example:core;

interface filesystem {
    read-config-file: func(path: string) -> list<u8>;
    // NOT exported to plugins — only used internally.
}

interface http {
    post: func(url: string, body: list<u8>) -> list<u8>;
    // NOT exported to plugins — would enable exfiltration.
}

world core {
    import filesystem;
    import http;
    // Core exports a SUBSET to plugins via the plugin-api world.
}
```

### Step 3: Avoid Shared Linear Memory

Shared linear memory is the highest-risk dynamic linking pattern. Use the component model's value-passing model instead:

```rust
// BAD: Emscripten-style shared memory — pointer passing between modules.
// The receiving module can read all of shared memory, not just the passed buffer.
extern "C" {
    fn plugin_process(ptr: *const u8, len: usize) -> usize;
}

// GOOD: Component model — values are copied across the module boundary.
// Each component has its own linear memory; data is serialised at the boundary.
// WIT functions accept and return values, not pointers.

// In WIT:
// process: func(data: list<u8>) -> result<list<u8>, string>;
// Wasmtime copies the data at the boundary — plugin cannot read host memory.
```

```toml
# Cargo.toml — use component model target, not shared-everything-threads.
[profile.release]
opt-level = "s"

# Build as a component (not a core module with dynamic linking).
# Components do not share linear memory by construction.
```

### Step 4: Module Integrity in the Composition Graph

Verify every module in the composition graph before linking:

```rust
// module_linker/src/main.rs — verify all modules before composing.
use sha2::{Digest, Sha256};
use std::collections::HashMap;

struct ModuleManifest {
    modules: HashMap<String, ModuleEntry>,
}

struct ModuleEntry {
    path: String,
    expected_sha256: String,
    allowed_imports: Vec<String>,  // Which interfaces this module may import.
    allowed_exports: Vec<String>,  // Which interfaces this module may export.
}

fn load_verified_module(entry: &ModuleEntry) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(&entry.path)
        .map_err(|e| format!("Cannot read {}: {}", entry.path, e))?;
    
    // Verify SHA-256.
    let actual = format!("{:x}", Sha256::digest(&bytes));
    if actual != entry.expected_sha256 {
        return Err(format!(
            "Module integrity check FAILED for {}:\n  expected: {}\n  actual:   {}",
            entry.path, entry.expected_sha256, actual
        ));
    }
    
    Ok(bytes)
}

fn compose_verified(manifest: &ModuleManifest) -> Result<(), String> {
    for (name, entry) in &manifest.modules {
        let bytes = load_verified_module(entry)?;
        println!("✓ Verified: {} ({} bytes)", name, bytes.len());
        
        // Parse module to check imports match allowlist.
        // (Use wasm-tools crate to inspect the module's import section.)
        verify_imports(&bytes, &entry.allowed_imports)?;
    }
    Ok(())
}
```

### Step 5: Capability Attenuation at Composition Time

Use Wasmtime's linker to enforce capability grants per-module:

```rust
// host/src/main.rs — Wasmtime host with per-module capability grants.
use wasmtime::*;
use wasmtime_wasi::preview2::*;

fn build_plugin_linker(engine: &Engine) -> Result<Linker<PluginState>> {
    let mut linker = Linker::new(engine);
    
    // Add WASI to the linker — but only the capabilities the plugin needs.
    // The plugin gets: stdout, stderr, random.
    // The plugin does NOT get: filesystem, network, environment variables.
    wasmtime_wasi::preview2::add_to_linker_async(&mut linker, |state: &mut PluginState| {
        &mut state.wasi
    })?;
    
    // Add the filtered config interface.
    linker.func_wrap(
        "example:plugin-api/config",
        "get-feature-flag",
        |caller: Caller<'_, PluginState>, name_ptr: i32, name_len: i32| -> i32 {
            let name = read_string_from_guest(&caller, name_ptr, name_len);
            // Enforce the allowlist here at the host level.
            if ALLOWED_FEATURE_FLAGS.contains(&name.as_str()) {
                get_feature_flag(&name) as i32
            } else {
                0  // Default false for unknown flags.
            }
        }
    )?;
    
    Ok(linker)
}

// Each plugin gets its own isolated state and linker instance.
// State is NOT shared between plugins.
struct PluginState {
    wasi: WasiCtx,
    plugin_id: String,
}
```

### Step 6: Module Dependency Pinning

```yaml
# wasm-modules.lock — pin all modules in the composition graph by digest.
# Similar to Cargo.lock or package-lock.json, but for WASM modules.

modules:
  - name: "core-module"
    source: "registry.example.com/wasm/core-module"
    version: "2.1.0"
    digest: "sha256:abc123def456..."
    allowed_capabilities:
      - "filesystem:read:/etc/config/"
      - "http:post:https://api.internal/*"
    
  - name: "analytics-plugin"
    source: "registry.example.com/wasm/analytics"
    version: "1.5.2"
    digest: "sha256:789ghi012..."
    allowed_capabilities: []   # No host capabilities; only composed interfaces.
    imports_from:
      - "core-module:config"   # Only this interface from core.
    
  - name: "third-party-formatter"
    source: "registry.wapm.io/formatter/json-formatter"
    version: "0.8.1"
    digest: "sha256:jkl345mno..."
    allowed_capabilities: []
    imports_from: []           # Pure computation; no imports.
    trust_level: untrusted     # Third-party module; extra scrutiny.
```

### Step 7: Runtime Isolation Between Plugin Instances

Isolate concurrently running plugin instances:

```rust
// Multi-tenant plugin execution: each tenant gets isolated stores.
use wasmtime::{Engine, Store, Module, Instance};
use std::sync::Arc;

struct PluginPool {
    engine: Arc<Engine>,
    module: Arc<Module>,  // Compiled once; instantiated per-tenant.
}

impl PluginPool {
    fn execute_for_tenant(
        &self,
        tenant_id: &str,
        input: &[u8],
    ) -> Result<Vec<u8>, String> {
        // Each invocation gets a fresh Store — isolated state.
        let mut store = Store::new(
            &self.engine,
            PluginState {
                wasi: build_minimal_wasi(),
                plugin_id: format!("tenant-{}-{}", tenant_id, uuid::Uuid::new_v4()),
            }
        );
        
        // Set resource limits per instance.
        store.limiter(|state| &mut state.resource_limiter);
        store.set_fuel(10_000_000)?;   // Instruction limit.
        
        // Fresh instance — no shared state from previous calls.
        let instance = self.linker.instantiate(&mut store, &self.module)?;
        
        // Call the module function.
        let process = instance.get_typed_func::<(i32, i32), i64>(&mut store, "process")?;
        // ... invoke and collect result.
        
        Ok(vec![])
    }
}
```

### Step 8: Telemetry

```
wasm_module_integrity_check_total{module, status}             counter
wasm_capability_violation_total{module, capability}           counter
wasm_confused_deputy_attempts_total{caller, callee, function} counter
wasm_module_composition_errors_total{error_type}              counter
wasm_plugin_execution_duration_ms{module, tenant}             histogram
wasm_memory_per_module_bytes{module}                          gauge
wasm_function_call_cross_boundary_total{from, to, function}   counter
```

Alert on:

- `wasm_module_integrity_check_total{status="failed"}` — a module in the composition graph failed its hash check; do not execute; investigate.
- `wasm_capability_violation_total` non-zero — a module attempted to import a capability not in its allowlist; investigate the module and its caller.
- `wasm_confused_deputy_attempts_total` — a plugin called a core function with a denied key or argument; possible confused deputy attempt.
- `wasm_module_composition_errors_total` — composition failed; likely interface mismatch or missing module in the graph; check module registry.

## Expected Behaviour

| Signal | Naive module composition | Hardened component composition |
|--------|-------------------------|---------------------------------|
| Untrusted plugin reads config via core | Core returns any key; confused deputy succeeds | Core allowlist rejects sensitive keys; returns nil |
| Shared memory cross-module read | Plugin reads entire shared linear memory | Component model: no shared memory; value copying only |
| Compromised dependency module | Executes with transitive capabilities | Module integrity check fails; composition aborted |
| Function reference passed to trusted module | Trusted module calls attacker's function | Function references validated against trusted source |
| Cross-tenant plugin state leak | Previous tenant's store accessible | Fresh Store per invocation; no shared state |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Component model over shared-memory linking | Strong isolation by construction | Higher serialisation overhead at module boundary | Benchmark: typically < 1µs for small payloads; acceptable for most use cases |
| Capability allowlists in WIT | Prevents interface creep; minimal exposure | Must update allowlist when requirements change | Document allowed interfaces in WIT definitions; change review process |
| Per-invocation Store (no pooling) | Zero cross-tenant state leakage | Higher instantiation overhead (~100µs) | Pre-compile modules; warm store pool (but verify isolation per-call) |
| Module graph pinning | Prevents supply chain substitution | Dependency updates require hash update | Automate hash update via CI; sign the lock file |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| WIT interface version mismatch | Composition fails at link time | `wasm_module_composition_errors_total` | Pin interface versions in WIT; update both modules together |
| Fuel exhausted in nested call | Plugin times out mid-computation | Fuel error in execution log | Increase fuel limit for deep call chains; profile expected call depth |
| Allowlist too restrictive | Plugin cannot access needed config | Plugin returns error for valid operation | Review allowlist; add specific key; avoid wildcard grants |
| Module integrity check blocks update | New module version fails SHA256 check | Integrity failure alert; deployment blocked | Update hash in lock file via CI after verifying the new module |
| Memory explosion via deep composition | Host OOM from large module graph | Memory usage alert | Set per-module memory limits; profile memory at composition time |

## Related Articles

- [WASM Component Model Security](/articles/wasm/wasm-component-model-security/)
- [Extism Plugin Security](/articles/wasm/extism-plugin-security/)
- [WASM Plugin Threat Modeling](/articles/wasm/wasm-plugin-threat-modeling/)
- [WasmEdge Security](/articles/wasm/wasmedge-security/)
- [WASM OCI Signing](/articles/wasm/wasm-oci-signing/)
