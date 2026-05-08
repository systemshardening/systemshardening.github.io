---
title: "Wasmtime Pulley Interpreter Security Hardening"
description: "Security model and hardening for Wasmtime's Pulley portable interpreter on platforms without Cranelift JIT: bytecode validation, resource limits, attack surface vs JIT."
slug: "wasmtime-pulley-interpreter-security"
date: 2026-05-08
lastmod: 2026-05-08
category: "wasm"
tags: ["wasmtime", "pulley", "interpreter", "wasm", "sandboxing", "embedded"]
personas: ["systems-engineer", "security-engineer", "platform-engineer"]
article_number: 656
difficulty: "advanced"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/wasm/wasmtime-pulley-interpreter-security/index.html"
---

# Wasmtime Pulley Interpreter Security Hardening

## Problem

Pulley is Wasmtime's portable bytecode interpreter, introduced as a stable backend in 2024 and increasingly used on platforms where Cranelift JIT compilation is unavailable, undesirable, or prohibited: iOS, embedded ARM Cortex-M boards with no W^X memory, Kubernetes nodes that disable executable anonymous mappings (`kernel.unprivileged_userns_clone=0` plus W^X enforcement), and security-sensitive environments where running JIT-emitted machine code is forbidden by policy. Pulley is also the default in ahead-of-time (AOT) compiled deployments where the host has neither Cranelift nor a compiled-in code section, since Pulley bytecode loads as inert data.

The Pulley security model is meaningfully different from Cranelift's:

1. **No JIT-emitted machine code.** Pulley is a switch-threaded interpreter. The host process never marks pages PROT_EXEC at runtime, eliminating the entire class of JIT-spray and W^X-bypass vulnerabilities that have historically dogged Wasmtime, V8, JSC, and SpiderMonkey.
2. **Different bug surface.** Where Cranelift bugs tend to be miscompilations (incorrect bounds-check elimination, register-allocation hazards), Pulley bugs tend to be interpreter-loop bugs (incorrect dispatch, missing validation, incorrect operand width). The 2024–2025 advisories list reflects this: Cranelift CVEs were predominantly miscompiled bounds checks; Pulley's smaller bug count was concentrated in capability/decoding paths and one resource-limit bypass.
3. **Performance-driven shortcuts.** Interpreters trade safety for speed via direct-threaded dispatch, computed gotos, and fast paths that skip per-instruction resource accounting. Some shortcuts are the same fuel-metering bypass classes that exist in other interpreters.

Pulley is a strong choice for many environments — but operators routinely treat it as "Cranelift but slower", import the Cranelift-era hardening recipe, and miss Pulley-specific concerns. In particular: bytecode validation is performed by `wasmparser` (not Pulley itself), so a Pulley-without-validation deployment is genuinely unsafe; resource-limiting via fuel and epoch interruption is essential because interpreter loops are tighter and a runaway module steals more host CPU per second; and the smaller bug surface is not zero — three Pulley-specific advisories landed in 2025.

This article is the operational hardening guide for Pulley specifically. Target systems: Wasmtime ≥ 27.0 with Pulley enabled (`--target pulley32` or `pulley64`), embedded environments, iOS hosts using `wasmtime-c-api`, server-side AOT deployments where the embedder pre-compiles to Pulley bytecode.

## Threat Model

1. **Untrusted Wasm module attempting host-process compromise.** Goal: escape the sandbox via interpreter or host-function bug. Surface: Pulley dispatch loop, host imports, linear-memory bounds.
2. **Hostile module performing CPU/memory exhaustion.** Goal: deny service to the host process. Surface: missing fuel limits, missing memory caps, interpreter loops that bypass interruption checks.
3. **Module triggering host crash via undefined behaviour.** Goal: turn a logic bug into a crash for downstream effect (privilege boundary collapse, log fault). Surface: validation gaps, integer-overflow paths in operand decode.
4. **Attacker delivering pre-compiled Pulley bytecode.** Goal: skip the Wasm validator. Surface: embedders that load `.cwasm` directly without re-validation.

Pulley's structural advantage — no executable runtime memory — closes the entire JIT-spray class. The remaining surface is conventional sandbox hardening with a focus on validation and resource accounting.

## Configuration / Implementation

### Step 1 — Force validation on every module load

Wasmtime's API allows loading pre-compiled `.cwasm` artefacts that skip validation. With Pulley this is convenient (fast load) but dangerous if the artefact source is anything but trusted. For untrusted-input embeddings, always validate at load:

```rust
use wasmtime::{Config, Engine, Module};

fn make_engine() -> Engine {
    let mut cfg = Config::new();
    cfg.target("pulley64").unwrap();
    cfg.wasm_component_model(true);
    cfg.consume_fuel(true);
    cfg.epoch_interruption(true);
    cfg.async_support(false);
    cfg.allocation_strategy(wasmtime::InstanceAllocationStrategy::OnDemand);

    // Defence-in-depth: enable extra runtime checks in interpreter mode.
    cfg.cranelift_debug_verifier(true);
    cfg.signals_based_traps(false);   // mandatory on platforms without sigaltstack

    Engine::new(&cfg).unwrap()
}

fn load_module(engine: &Engine, bytes: &[u8]) -> anyhow::Result<Module> {
    // Validate every time, even if `bytes` claims to be pre-compiled.
    Module::new(engine, bytes)   // not Module::deserialize
}
```

Embedders sometimes optimise startup by caching `Module::serialize()` output and re-loading via `Module::deserialize`. For untrusted sources, treat the cache as untrusted: re-validate via `Module::new` and only `deserialize` when the bytes are produced and signed by your own trusted compiler.

### Step 2 — Apply fuel and epoch limits

Pulley's interpreter checks fuel less often than Cranelift's instrumented-call sequences; the practical cost is that a module can run more loop iterations between checks. Use both fuel *and* epoch interruption:

```rust
let mut store = Store::new(&engine, MyState::default());
store.set_fuel(10_000_000)?;
store.fuel_async_yield_interval(Some(50_000))?;
store.set_epoch_deadline(1);

let engine_clone = engine.clone();
std::thread::spawn(move || {
    loop {
        std::thread::sleep(Duration::from_millis(10));
        engine_clone.increment_epoch();
    }
});
```

Fuel bounds total work; epoch bounds wall-clock latency. With an epoch tick every 10ms and a deadline of 1, a runaway module is interrupted within ~20ms regardless of fuel state.

### Step 3 — Cap memory rigorously

Pulley's linear-memory access is bounds-checked per access (no Cranelift's spectre-mitigation tricks needed because the interpreter dispatches each load explicitly). Set explicit limits:

```rust
let mut config = Config::new();
config.max_wasm_stack(512 * 1024);        // 512KB
config.async_stack_size(2 * 1024 * 1024);

// Per-store resource limiter
struct Limits { mem_max: usize, table_max: usize, instances: usize }
impl ResourceLimiter for Limits {
    fn memory_growing(&mut self, current: usize, desired: usize, _max: Option<usize>) -> anyhow::Result<bool> {
        Ok(desired <= self.mem_max)
    }
    fn table_growing(&mut self, _: u32, desired: u32, _max: Option<u32>) -> anyhow::Result<bool> {
        Ok((desired as usize) <= self.table_max)
    }
    fn instances(&self) -> usize { self.instances }
    fn tables(&self) -> usize { 16 }
    fn memories(&self) -> usize { 4 }
}

store.limiter(|state| &mut state.limits);
```

Defaults of 16 MiB linear memory, 64 KiB table, 4 memories per instance, 16 tables per instance work for most plug-in embeddings; raise per workload only with justification.

### Step 4 — Disable unneeded proposals

Each Wasm proposal expands the bytecode surface. Turn off what you don't use:

```rust
let mut cfg = Config::new();
cfg.wasm_threads(false);
cfg.wasm_simd(true);                  // Pulley supports a subset; keep on if needed
cfg.wasm_relaxed_simd(false);         // off unless required
cfg.wasm_bulk_memory(true);           // generally needed
cfg.wasm_reference_types(true);
cfg.wasm_multi_memory(false);
cfg.wasm_memory64(false);             // keep off unless you genuinely need 64-bit indices
cfg.wasm_function_references(false);
cfg.wasm_gc(false);                   // off by default; large surface
cfg.wasm_tail_call(false);
cfg.wasm_extended_const(false);
cfg.wasm_stack_switching(false);      // experimental; off
```

`wasm_gc` and `wasm_stack_switching` are the two highest-risk opt-ins as of 2026 — both are recent features with active spec churn and a thinner bug history.

### Step 5 — Audit host imports

The interpreter eliminates JIT compromise but does nothing for host imports that pass attacker-controlled bytes to host code. Treat every import as a privilege boundary:

```rust
let mut linker = Linker::new(&engine);
linker.func_wrap("env", "log", |mut caller: Caller<'_, MyState>, ptr: u32, len: u32| {
    // Never trust ptr/len: validate against current memory size.
    let mem = caller.get_export("memory").and_then(|e| e.into_memory()).unwrap();
    let data = mem.data(&caller);
    let start = ptr as usize;
    let end = start.checked_add(len as usize).ok_or_else(|| anyhow!("overflow"))?;
    if end > data.len() { return Err(anyhow!("oob")); }
    let s = std::str::from_utf8(&data[start..end]).map_err(|_| anyhow!("bad utf8"))?;
    if s.len() > 4096 { return Err(anyhow!("too long")); }
    log::info!(target: "wasm", "{}", s);
    Ok(())
})?;
```

Refuse unbounded reads. Constrain logging to a length cap. Apply the same pattern for any function exposing file, network, or process operations.

### Step 6 — Run in a process-level sandbox anyway

Pulley closes a JIT class but does not replace OS-level isolation. On Linux, run the host process under seccomp + namespace + cgroup:

```rust
// pseudo-snippet using extrasafe or seccompiler
extrasafe::SafetyContext::new()
    .enable(extrasafe::builtins::BasicCapabilities)?
    .enable(extrasafe::builtins::SystemIO::nothing()
        .allow_stdout().allow_stderr())?
    .apply_to_current_thread()?;
```

For multi-tenant embedders, run each tenant's modules in a forked child with a per-tenant seccomp policy and cgroup memory cap.

### Step 7 — Stay current

Subscribe to the Wasmtime security advisory feed:

```bash
# RSS source: https://github.com/bytecodealliance/wasmtime/security/advisories.atom
# Or via gh:
gh api repos/bytecodealliance/wasmtime/security-advisories
```

Pulley-specific advisories are tagged accordingly. As of mid-2026 the advisory cadence is ~6 per year for Wasmtime overall; treat patch within 30 days as the SLA, 7 days for high severity.

## Expected Behaviour

| Signal | Cranelift JIT mode | Pulley mode (hardened) |
|--------|--------------------|-----------------------|
| Executable runtime pages | Yes (W^X gymnastics) | None |
| JIT-spray attack class | Present | Eliminated |
| Per-instruction overhead | ~1.0× native | ~5–15× native |
| Fuel granularity | Per call site | Per dispatch |
| Bytecode validation latency | Higher (compiles) | Lower (parses) |
| Bug surface focus | Miscompiles | Decode & dispatch |
| Suitable for iOS / no-W+X | No | Yes |

Verification:

```bash
# Confirm Pulley target is in use and JIT is off.
wasmtime --target pulley64 run --invoke greet hello.wasm
# In a debugger or via /proc/<pid>/maps, confirm no rwx mapping.
grep rwx /proc/$(pgrep wasmtime)/maps
# expected: no output (no rwx pages)
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Pulley vs Cranelift | Eliminates JIT-spray class, runs on iOS / W+X-restricted hosts | 5–15× slowdown vs JIT | Use AOT pre-compilation to Pulley bytecode for known modules; reserve JIT for trusted hot paths |
| Mandatory validation on load | Closes a load-time bypass | Higher cold-start latency | Cache validated `Module` objects in process memory |
| Aggressive epoch ticks | Tight latency bound on runaway modules | Background thread + atomic ops | Tick at the granularity your app cares about (10–50ms) |
| Disabling proposals (gc, stack-switching) | Smaller bug surface | Some toolchains require them (e.g., Java/Kotlin to Wasm) | Explicit allowlist per embedding; review per upgrade |
| Process-level sandbox | Defence-in-depth | Operational complexity | Use established frameworks (extrasafe, landlock); do not roll your own |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Module exceeds memory cap | Trap at runtime, instance fails | Wasmtime trap with `MemoryGrowFailed` | Embedder catches trap, logs, returns clean error to caller |
| Epoch interruption races with FFI | Crash inside host function | Stack trace shows interruption mid-host-call | Use `set_epoch_deadline` larger than longest host call; or wrap host calls to clear deadline |
| Fuel exhaustion misattributed | Honest workload looks malicious | Log shows `OutOfFuel` after small input | Tune fuel budget; consider per-tenant baseline |
| Pre-compiled `.cwasm` from untrusted source loaded via `Module::deserialize` | Validation skipped | Code review; CI guard | Refactor to always go through `Module::new`; mark `deserialize` as trusted-only |
| Pulley bug exploited (rare) | Anomalous traps, host crash | Wasmtime advisory; fuzzing CI catching delta | Patch Wasmtime; in interim, mitigate via tighter resource limits |

## When to Consider a Managed Alternative

- WasmCloud, Spin, and Fastly's Compute@Edge expose hardened Wasmtime / Pulley deployments without you maintaining the embedding.
- For iOS / mobile, hosted Wasm SDKs (e.g., Wasmer's mobile, Cosmonic) bundle Pulley with platform-specific hardening; usually less work than a custom embed.
- For embedded firmware below 1 MB RAM, dedicated interpreters (WAMR's MICRO mode, Wasm3) may fit better than Pulley.

## Related Articles

- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [Wasm JIT Security](/articles/wasm/wasm-jit-security/)
- [Wasm AOT Compilation Security](/articles/wasm/wasm-aot-compilation-security/)
- [Wasm Module Loading and Validation](/articles/wasm/wasm-module-loading-validation/)
- [Wasm Fuel Metering](/articles/wasm/wasm-fuel-metering/)
