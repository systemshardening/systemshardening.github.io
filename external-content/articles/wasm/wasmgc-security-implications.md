---
title: "WasmGC Security Implications for Multi-Tenant Runtimes"
description: "Analyze WasmGC's new attack surface in multi-tenant WASM runtimes: GC object escape, type confusion in struct hierarchies, finalizer abuse, and cross-tenant reference leaks."
slug: wasmgc-security-implications
date: 2026-05-01
lastmod: 2026-05-01
category: wasm
tags: ["wasm", "wasmgc", "garbage-collection", "multi-tenant", "type-safety", "memory-safety", "v8", "wasmtime"]
personas: ["security-engineer", "platform-engineer", "systems-engineer"]
article_number: 326
difficulty: advanced
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/wasm/wasmgc-security-implications/index.html"
---

# WasmGC Security Implications for Multi-Tenant Runtimes

## Problem

Classic WebAssembly memory safety is built on a single, simple invariant: every module gets a contiguous, sandboxed linear memory. Heap data, stack frames, and global state all live inside that flat byte array. The runtime enforces bounds on every load and store. There is no pointer arithmetic that can escape the array bounds, no garbage collector, and no reference to any object outside the module's own memory region. The attack surface for memory corruption is well-understood and relatively narrow.

The WebAssembly Garbage Collection proposal (WasmGC) fundamentally changes that invariant. Reaching Stage 4 in October 2023 and shipping in V8 since Chrome 119 and SpiderMonkey since Firefox 120, WasmGC adds a managed heap alongside linear memory. Modules can define typed struct and array types, allocate instances of them with `struct.new` and `array.new`, and hold references to those instances via typed reference values — `ref.struct`, `ref.array`, and `externref`. The GC, not the module, owns and collects these objects.

The security model shifts accordingly. GC objects are not in the module's linear memory. They are in the runtime's managed heap, subject to the runtime's type system and reachability graph. The attack surface moves from linear memory bounds violations to: type confusion between GC struct subtypes, object reference leaks across module or tenant boundaries, timing side-channels from GC pause patterns, and resource exhaustion through unbounded object allocation. Each of these is qualitatively different from the overflows and out-of-bounds reads that WASM's original design was built to prevent.

The motivation for WasmGC is real and significant. Languages like Kotlin, Dart, Scala, and eventually subsets of Java and Go compile naturally to a managed heap model. Before WasmGC, compiling these languages to WASM required either shipping a language-specific GC inside the module's linear memory (massively inflating binary size and startup time) or restructuring the language runtime to avoid a GC entirely. WasmGC lets the runtime provide the GC, drastically simplifying compilation targets. The Kotlin/Wasm and Dart-to-Wasm toolchains both rely on WasmGC. This is why server-side runtimes are adding support: Wasmtime 25+ and WasmEdge 0.14+ both include WasmGC behind feature flags or by default in 2025 builds.

The multi-tenant problem is where the security implications become acute. Platforms like Cloudflare Workers, Fastly Compute, and generic edge plugin systems run many tenant modules in the same operating system process, relying on the WASM sandbox for isolation. When those modules used only linear memory, the isolation guarantee was straightforward: your linear memory is yours, mine is mine, and the runtime enforces the line. With WasmGC, both modules are allocating objects into a shared managed heap managed by the same runtime. The question of whether the runtime properly isolates GC objects across tenant boundaries is now a critical security question, not an implementation detail.

The specific failure modes are not theoretical. Type confusion through `ref.cast` can allow a module to misinterpret a GC struct of one type as a struct of a compatible subtype, accessing fields that should be off-limits. A host that incorrectly shares an `externref` table between two tenant Stores hands one tenant an opaque handle into the other's object graph. A tenant module that allocates GC objects without any limit can trigger an OOM in the host process that kills all tenants simultaneously. GC pause timing — the duration of stop-the-world or incremental collection cycles — leaks information about the total live object count in the heap, enabling a timing side-channel that crosses tenant boundaries.

**Target systems:** Wasmtime 25+, WasmEdge 0.14+, V8 embedded via Node.js 22+ and Deno 1.4x, and any multi-tenant edge or plugin platform compiling Kotlin/Wasm, Dart/Wasm, or other GC-reliant language targets to WasmGC modules.

## Threat Model

1. **Type confusion via `ref.cast`** — A malicious module defines a GC struct hierarchy with a base type and multiple subtypes, then allocates an object of one subtype and uses `ref.cast` to attempt reinterpretation as a different subtype with a wider field layout. The goal is to read adjacent memory in the managed heap by accessing fields that belong to a different struct type. In a correctly implemented runtime, `ref.cast` must trap on type mismatch — but if the runtime's type check is incomplete or subtype relationships are miscalculated during module linking, the cast succeeds and grants field access beyond what the type intended.

2. **Cross-tenant `externref` leak** — Two tenant modules running in the same Wasmtime process use the same `Store`, or a host incorrectly passes an `externref` handle scoped to Tenant A's Store into Tenant B's function call. `externref` is intentionally opaque inside the WASM module — the module cannot inspect what the reference points to — but if the host's externref table maps references to live Rust objects or host resources, Tenant B can now call host functions using Tenant A's resource handle, escalating privilege across the tenant boundary.

3. **GC timing side-channel** — A co-resident attacker module allocates and releases GC objects in bursts and measures wall-clock time to detect GC pause events. The duration and frequency of pauses in a shared-heap runtime correlates with the total live object count and allocation rate across all tenants. A sufficiently careful attacker can infer whether another tenant is processing a large request (high allocation rate, long pauses) versus idle, leaking workload pattern information and potentially enabling request-timing inference.

4. **GC-triggered OOM denial of service** — A tenant module allocates GC structs in a tight loop without freeing references. With no per-tenant GC object limit enforced, the host process's managed heap grows until it exhausts system memory. The OOM kills the host process or triggers the OOM killer, taking all other tenant modules offline simultaneously. This is a multi-tenant blast radius that does not exist in linear-memory-only WASM, where per-Store memory limits cap the damage to a single tenant's linear memory region.

Without mitigations, any one of these adversaries can affect all co-resident tenants: type confusion exposes data, externref leaks escalate privilege, timing channels exfiltrate workload patterns, and OOM triggers denial of service for the entire host process. With proper per-tenant resource limits, scoped externref tables, runtime-enforced type traps, and epoch-based interruption, the blast radius is bounded to the attacker's own Store and module instance.

## Configuration / Implementation

### Wasmtime WasmGC Isolation

WasmGC support in Wasmtime is enabled at the engine level. When building the host:

```rust
use wasmtime::{Config, Engine};

let mut config = Config::new();
config.wasm_gc(true);
// Also enable reference types, which WasmGC depends on
config.wasm_reference_types(true);

let engine = Engine::new(&config).expect("failed to create engine");
```

With `wasm_gc(true)`, Wasmtime compiles modules that use GC type instructions. The critical security invariant is that `ref.cast` generates a runtime trap on type mismatch — the cast either succeeds with the correct type or traps immediately, with no undefined behavior in between. Verify this with a WAT test module:

```wat
;; test-cast-trap.wat
(module
  (type $animal (struct (field $legs i32)))
  (type $fish   (struct (field $legs i32) (field $fins i32)))

  (func (export "cast_attempt") (result i32)
    ;; allocate an $animal (not a $fish)
    (struct.new $animal (i32.const 4))
    ;; attempt to cast to $fish — must trap
    (ref.cast (ref $fish))
    ;; read fins field (unreachable if cast traps correctly)
    (struct.get $fish $fins)
  )
)
```

Run validation and expect a trap at the `ref.cast` instruction:

```bash
wasm-tools validate --features gc test-cast-trap.wat
wasmtime run --wasm gc test-cast-trap.wat
# Expected: wasm trap: cast failure
```

If the runtime does not trap and instead returns a value, the type safety guarantee has failed. Treat this as a critical vulnerability in that runtime version.

### Externref Sandboxing

`externref` is the mechanism by which the host passes opaque Rust objects (or any host resource) into a WASM module. The module holds an index into an externref table; the host controls what that index points to. The isolation requirement is simple: **never share an externref table between two tenant Stores**.

```rust
use wasmtime::{Store, Engine, Linker};

// Correct: one Store per tenant, externref table is Store-scoped
fn create_tenant_store(engine: &Engine, tenant_id: &str) -> Store<TenantState> {
    let state = TenantState {
        tenant_id: tenant_id.to_string(),
        // tenant-specific resources only
    };
    Store::new(engine, state)
}

// WRONG: sharing a Store between tenants means sharing the externref table
// let shared_store = Store::new(&engine, shared_state);
// tenant_a_instance = Instance::new(&mut shared_store, &module_a, &[]);
// tenant_b_instance = Instance::new(&mut shared_store, &module_b, &[]);
// This allows tenant_b to call host functions using tenant_a's externref handles
```

When linking host functions that accept or return `externref`, audit every function to confirm it validates that the incoming reference belongs to the calling tenant's Store state before operating on it.

### Resource Limits for GC Workloads

Wasmtime's `StoreLimits` caps linear memory and table element counts. For GC workloads, also install a custom `ResourceLimiter` that tracks GC object allocation. Combine with fuel to meter GC operation cost:

```rust
use wasmtime::{Store, ResourceLimiter, StoreLimitsBuilder};

struct TenantLimiter {
    memory_limit: usize,
    table_limit: u32,
    // Track GC struct allocations via host import hooks if needed
}

impl ResourceLimiter for TenantLimiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        Ok(desired <= self.memory_limit)
    }

    fn table_growing(
        &mut self,
        current: u32,
        desired: u32,
        _maximum: Option<u32>,
    ) -> anyhow::Result<bool> {
        Ok(desired <= self.table_limit)
    }
}

let limits = StoreLimitsBuilder::new()
    .memory_size(64 * 1024 * 1024)  // 64 MiB linear memory
    .table_elements(10_000)
    .build();

store.limiter(|state| &mut state.limiter);
```

For fuel-based metering of GC allocations, enable fuel consumption and set a per-request budget:

```rust
config.consume_fuel(true);
// ...
store.set_fuel(1_000_000).unwrap(); // adjust per workload profile
```

GC allocation instructions (`struct.new`, `array.new`) consume fuel in proportion to allocation size in runtimes that support fuel for GC. Check your Wasmtime version's release notes for GC fuel coverage.

### Epoch-Based Interruption for GC Pauses

GC workloads can run long collection cycles that are not bounded by instruction count. Epoch-based interruption is the correct mechanism for bounding wall-clock time for GC-heavy modules:

```rust
use wasmtime::{Config, Engine, Store};
use std::sync::Arc;
use std::time::Duration;

let mut config = Config::new();
config.wasm_gc(true);
config.epoch_interruption(true);

let engine = Arc::new(Engine::new(&config).unwrap());

// Background thread increments epoch every 10 ms
let engine_clone = engine.clone();
std::thread::spawn(move || {
    loop {
        std::thread::sleep(Duration::from_millis(10));
        engine_clone.increment_epoch();
    }
});

// Per-tenant Store: set deadline 2 epochs (≈20 ms) from now
let mut store = Store::new(&engine, tenant_state);
store.set_epoch_deadline(2);
store.epoch_deadline_trap(); // trap instead of async yield

// Now run the module — if GC pauses extend past the deadline, the module traps
```

Tune `increment_epoch` frequency and the deadline value based on your latency SLO. A deadline of 2 epochs at 10 ms increments gives a 20 ms hard ceiling on any single WASM execution including GC pauses. Legitimate long-running workloads should use async `epoch_deadline_async_yield_and_update` instead of `epoch_deadline_trap` so they can resume after yielding to the scheduler.

### Type Hierarchy Auditing with wasm-tools

Before loading an untrusted WasmGC module into a multi-tenant runtime, audit its GC type definitions and `ref.cast` usage:

```bash
# Inspect GC type definitions and cast instructions in text format
wasm-tools print --skeleton untrusted-module.wasm | grep -E '(type|struct|array|ref\.cast|ref\.test)'

# Validate that the module is well-typed with GC feature enabled
wasm-tools validate --features gc untrusted-module.wasm

# Dump the type section to review struct field layouts
wasm-tools dump --section type untrusted-module.wasm

# Count ref.cast occurrences — high counts warrant manual review
wasm-tools print untrusted-module.wasm | grep -c 'ref\.cast'
```

Flag modules with `ref.cast` on types that are not in a well-defined subtype relationship with the target type. The WasmGC spec allows `ref.cast` only where the source type is a subtype of the target or vice versa; any module exploiting edge cases in subtype hierarchies should be reviewed for type confusion intent.

Note that `wasm-tools validate` validates type-system correctness but does not guarantee behavioral safety — a type-valid module can still exhaust resources or leak timing information. Validation is a necessary but not sufficient gate.

### Memory Pressure Monitoring

Track per-Store GC heap growth and expose it as a host metric:

```rust
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Clone)]
struct TenantMetrics {
    gc_alloc_bytes: Arc<AtomicUsize>,
    tenant_id: String,
}

impl TenantMetrics {
    fn record_alloc(&self, bytes: usize) {
        let prev = self.gc_alloc_bytes.fetch_add(bytes, Ordering::Relaxed);
        if prev + bytes > 32 * 1024 * 1024 {
            // Alert: tenant exceeded 32 MiB GC heap growth
            tracing::warn!(
                tenant_id = %self.tenant_id,
                gc_alloc_bytes = prev + bytes,
                "GC heap pressure threshold exceeded"
            );
        }
    }
}
```

Integrate with Prometheus by exposing `wasm_gc_heap_bytes{tenant_id="..."}` via a metrics endpoint. Correlate GC heap growth spikes across tenants with OOM events to identify misbehaving modules before they cause host-wide failure.

### V8 and Node.js Isolation

For V8-embedded environments (Node.js 22+, Deno 1.4x), WasmGC objects live in the V8 Isolate's managed heap. Multiple WASM instances within the same Isolate share that heap. For multi-tenant isolation, use separate V8 Isolates per tenant — in Node.js, this means separate Worker threads:

```javascript
// host.mjs — spawn one Worker per tenant
import { Worker } from 'node:worker_threads';

function createTenantWorker(tenantId, wasmBytes) {
  return new Worker('./tenant-runner.mjs', {
    workerData: { tenantId, wasmBytes },
    // Each Worker gets its own V8 Isolate and managed heap
    resourceLimits: {
      maxOldGenerationSizeMb: 64,
      maxYoungGenerationSizeMb: 16,
    },
  });
}
```

```javascript
// tenant-runner.mjs — runs inside the Worker (separate Isolate)
import { workerData } from 'node:worker_threads';

const { tenantId, wasmBytes } = workerData;
const module = await WebAssembly.compile(wasmBytes);
const instance = await WebAssembly.instantiate(module, {});
// WasmGC objects allocated here are in this Isolate's heap only
```

Do not instantiate multiple tenant modules inside the same Node.js main thread or the same Deno context. WasmGC objects in a shared Isolate are GC-collected together, sharing heap pressure and timing information across tenants.

## Expected Behaviour

| Signal | Without WasmGC Mitigations | With Mitigations |
|---|---|---|
| `ref.cast` type mismatch | Undefined (runtime-version-dependent; may succeed, returning a mistyped reference) | Runtime trap immediately; execution terminates, no field access occurs |
| Cross-tenant `externref` access | Tenant B receives valid handle into Tenant A's resource graph; host function operates on wrong tenant's state | Each Store is tenant-scoped; externref tables are not shared; host functions reject cross-tenant handles |
| GC OOM from one tenant | Host process OOM-killed; all tenants offline; no per-tenant accounting | `ResourceLimiter` denies memory growth above per-tenant threshold; only the offending module's Store fails |
| Timing channel via GC pause | Co-resident attacker measures pause duration; infers other tenants' heap size and allocation rate | Separate Isolates (V8) or per-Store GC limits reduce cross-tenant heap coupling; epoch interruption bounds pause duration visibility |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| WasmGC enabled in Wasmtime | Supports Kotlin/Wasm, Dart/Wasm, richer language targets without bundled GC | Larger attack surface: type confusion, GC OOM, timing channels | Enforce per-Store resource limits; audit `ref.cast` usage before loading |
| Epoch-based interruption | Bounds wall-clock time including GC pauses; prevents runaway collection loops | Legitimate long GC cycles interrupted prematurely; increased trap noise | Use `epoch_deadline_async_yield_and_update` for workloads with predictable GC; tune epoch interval to match GC pause profile |
| Separate V8 Isolates per tenant | Full GC heap isolation; timing channel eliminated; per-Isolate memory limits | Substantially higher memory overhead (V8 Isolate baseline ~5–20 MiB); slower cold start | Use Worker thread pool with pre-warmed Isolates; limit concurrent tenants per node to respect memory budget |
| `externref` table per Store | Prevents cross-tenant resource handle leaks | Host must manage separate table per tenant; more complex lifecycle management | Use Wasmtime's Store-scoped linker pattern; never pass externref across Store boundaries |
| Fuel consumption for GC ops | Fine-grained metering of allocation cost per instruction | Fuel accounting overhead on every GC instruction; throughput reduction | Benchmark per workload; disable fuel for trusted internal modules where metering is not required |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| WasmGC feature not enabled in Wasmtime (`config.wasm_gc(false)`) | Module load fails with `WebAssembly.compile` error or Wasmtime validation error: "GC types not enabled" | Module load error at startup; `wasm-tools validate --features gc` confirms GC instructions present in module | Enable `config.wasm_gc(true)` and `config.wasm_reference_types(true)` in engine config; rebuild engine |
| Epoch interruption too aggressive for GC-heavy workload | Legitimate Kotlin/Wasm or Dart/Wasm module traps mid-execution with "epoch deadline exceeded"; high trap rate in metrics | Increased trap counter in host metrics; tenant error logs show `wasm trap: interrupt` during normal requests | Increase epoch deadline or switch from `epoch_deadline_trap` to `epoch_deadline_async_yield_and_update`; profile GC pause durations first |
| Externref table growth unbounded | Host process memory grows steadily; externref table for one Store holds live references preventing GC of backing objects | Heap profiler shows `externref` table as retained root; per-Store memory metric climbs monotonically | Audit host code for missing `drop` or explicit externref table cleanup; add table element cap via `StoreLimits::table_elements` |
| `wasm-tools validate` passes but custom section contains malicious metadata | Module passes validation; host loads module; runtime behaves unexpectedly due to custom section side-effects (e.g., dyld hints, name section exploits) | `wasm-tools dump --section custom` reveals unexpected or oversized custom sections | Strip non-standard custom sections before loading untrusted modules: `wasm-tools strip --all-custom untrusted.wasm -o sanitized.wasm` |

## Related Articles

- [WASM Component Model Security Boundaries](/articles/wasm/wasm-component-model-security/)
- [WASM Linear Memory Safety](/articles/wasm/wasm-linear-memory-safety/)
- [WASM Multi-Tenancy Isolation](/articles/wasm/wasm-multi-tenancy/)
- [WASM Plugin Threat Modeling](/articles/wasm/wasm-plugin-threat-modeling/)
- [Linux Memory Protections](/articles/linux/linux-memory-protections/)
