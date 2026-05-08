---
title: "Wasmtime Production Hardening: Fuel, Memory, Epoch Interrupts, and WASI Capability Allowlists"
description: "Wasmtime's defaults are friendly, not safe. Untrusted modules need explicit limits on CPU, memory, syscall surface, and filesystem access."
slug: "wasmtime-production-hardening"
date: 2026-04-27
lastmod: 2026-04-27
category: "wasm"
tags: ["wasmtime", "wasi", "sandboxing", "wasm", "rust"]
personas: ["platform-engineer", "security-engineer", "systems-engineer"]
article_number: 177
difficulty: "advanced"
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/wasm/wasmtime-production-hardening/index.html"
---

# Wasmtime Production Hardening: Fuel, Memory, Epoch Interrupts, and WASI Capability Allowlists

## Problem

Wasmtime is the most widely-deployed standalone WebAssembly runtime — used inside Spin, wasmCloud, Fastly Compute, Shopify's Function Runner, and many self-hosted serverless platforms. Its sandbox guarantees are strong: linear memory isolation, no ambient authority, deterministic semantics. They are also defeated by misconfiguration.

A `Module::new` + `Linker::module` + `Instance::new` flow with default `Config` and a permissive WASI context will:

- Execute indefinitely. A `loop {}` in the module hangs the host thread.
- Allocate up to 4 GB of linear memory per instance with no rejection.
- Mmap arbitrary table and stack sizes within Wasmtime's defaults.
- Inherit the host process's filesystem view through `WasiCtxBuilder::inherit_stdio`/`preopened_dir` if the embedder calls them carelessly.
- Make outbound network calls if `wasi:sockets` is wired in.
- Use floating-point and SIMD operations that may differ across hosts (a problem for deterministic execution, but not strictly a security issue).

In production, the runtime is the boundary between trusted host code and untrusted user code (WASM modules uploaded by tenants, dynamic plugins, edge-runtime customer code). Every default is a decision the embedder needs to make explicitly.

The specific gaps in a default Wasmtime embedding:

- **No CPU bound.** A malicious or buggy module can consume a thread for arbitrary time.
- **No memory ceiling beyond linear-memory's 4 GB cap.** Many small allocations (tables, instances, stack) accumulate without per-tenant accounting.
- **No I/O resource accounting.** A module reading or writing through preopened FDs has no quota.
- **WASI capability surface defaulted to inherit.** Embedders who want "give the module access to the cwd" sometimes hand over the entire host filesystem.
- **No epoch deadline support enabled.** The cooperative-deadline mechanism that lets the host reliably interrupt long-running modules is opt-in.

This article covers `Config` knobs for fuel, memory, and epoch interrupts; the `Store::limiter` API for per-instance caps; explicit WASI capability allowlists; and operational telemetry for tracking abusive modules.

**Target systems:** Wasmtime 22+ (Rust API and C API, with similar shapes in language bindings). Examples are in Rust; the same knobs exist in `wasmtime-py`, `wasmtime-go`, `@bytecodealliance/wasmtime`, and the `wasmtime` C API.

## Threat Model

- **Adversary 1 — Untrusted module author:** an attacker who uploads or supplies a `.wasm` module to a multi-tenant platform. They want to exhaust resources to cause denial of service for other tenants, or escape the sandbox to access the host filesystem, network, or other tenants' data.
- **Adversary 2 — Compromised module via supply chain:** a previously-trusted module containing malicious code introduced through a dependency compromise or builder error.
- **Adversary 3 — Resource accounting bypass:** an attacker who knows the embedder's resource limits and crafts a module that operates just below them indefinitely, denying capacity to legitimate workloads.
- **Access level:** Adversary 1 has WASM module-upload capability and module input control. Adversary 2 has the same plus prior trust. Adversary 3 has long-term observation of resource limits.
- **Objective:** CPU exhaustion, memory exhaustion, filesystem read or write outside the intended directory, network exfiltration via WASI sockets, persistence within the runtime, host process compromise.
- **Blast radius:** Without hardening: a single tenant module hangs a thread or consumes memory until OOM, affecting all other tenants on the same Wasmtime process. With hardening: per-instance bounds enforce fairness; capability denial blocks unauthorized I/O entirely.

## Configuration

### Step 1: Configure CPU Bounds with Fuel and Epoch Interrupts

Wasmtime offers two CPU-limiting mechanisms. Use them together for production.

**Fuel** counts execution units. Every WASM operation consumes a fixed amount; when fuel is exhausted, the runtime traps. Fuel is precise but expensive (every operation pays the accounting cost).

**Epoch interrupts** are a cooperative-deadline mechanism. The host increments an epoch counter (typically from a timer thread); the runtime compares epoch values at safe points. When the deadline epoch passes, the next safe point traps. Cheaper than fuel but coarser-grained.

```rust
// wasmtime_config.rs
use wasmtime::*;
use std::time::Duration;

pub fn make_config() -> Config {
    let mut config = Config::new();

    // Enable both fuel and epoch tracking.
    config.consume_fuel(true);
    config.epoch_interruption(true);

    // Reject modules using features we do not allow.
    config.wasm_simd(true);              // safe; allow
    config.wasm_threads(false);          // disallow shared memory across instances
    config.wasm_multi_memory(false);     // disallow multi-memory until policy is decided
    config.wasm_reference_types(true);
    config.wasm_bulk_memory(true);

    // Compilation cache for expensive modules.
    config.cache_config_load_default().ok();

    // Static memory reservations sized to the worst-case instance.
    config.static_memory_maximum_size(64 * 1024 * 1024);    // 64 MiB
    config.static_memory_guard_size(2 * 1024 * 1024 * 1024);
    config.dynamic_memory_guard_size(64 * 1024);

    config
}

pub fn run_module(wasm: &[u8], input: &str) -> anyhow::Result<String> {
    let engine = Engine::new(&make_config())?;
    let mut store = Store::new(&engine, ());

    // Per-invocation resource grant.
    store.set_fuel(10_000_000)?;            // ~10M ops max
    store.set_epoch_deadline(1);            // trap on next epoch tick after deadline

    // Increment-epoch thread (started once per Engine, not per Store).
    let engine_clone = engine.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(50));
        engine_clone.increment_epoch();
    });

    let module = Module::new(&engine, wasm)?;
    let instance = Instance::new(&mut store, &module, &[])?;
    let func = instance.get_typed_func::<(), i32>(&mut store, "run")?;
    let _ = func.call(&mut store, ())?;

    Ok(format!("fuel remaining: {}", store.get_fuel().unwrap_or(0)))
}
```

The 50ms epoch tick combined with `set_epoch_deadline(1)` produces a hard 50–100ms wall-clock budget per call, enforced regardless of what the module does. Fuel provides finer-grained accounting for billing or quota purposes — the host can observe how much was consumed before the trap, even on legitimate completion.

### Step 2: Per-Instance Memory and Resource Limiter

The `Store::limiter` callback controls every memory growth, table growth, and instance creation. Reject when limits are exceeded.

```rust
use wasmtime::ResourceLimiter;

struct Limits {
    max_memory: usize,
    max_tables: u32,
    max_instances: u32,
    current_instances: u32,
}

impl ResourceLimiter for Limits {
    fn memory_growing(&mut self, current: usize, desired: usize, _max: Option<usize>)
        -> anyhow::Result<bool> {
        Ok(desired <= self.max_memory)
    }
    fn table_growing(&mut self, _current: u32, desired: u32, _max: Option<u32>)
        -> anyhow::Result<bool> {
        Ok(desired <= self.max_tables)
    }
    fn instances(&self) -> usize { self.max_instances as usize }
    fn tables(&self) -> usize { 100 }
    fn memories(&self) -> usize { 1 }
}

let mut store = Store::new(&engine, Limits {
    max_memory: 32 * 1024 * 1024,    // 32 MiB
    max_tables: 1024,
    max_instances: 1,
    current_instances: 0,
});
store.limiter(|state| state);
```

The limiter is consulted on every growth attempt. A module that requests 1 GB of memory traps cleanly with `MemoryGrowError` rather than allocating and starving the host.

### Step 3: WASI Capability Allowlist

WASI is the syscall surface for WASM. Default `WasiCtxBuilder::inherit_*` calls give the module a copy of the host's I/O. Always start from empty and add only what the module needs.

```rust
use wasmtime_wasi::preview2::{WasiCtxBuilder, WasiCtx};
use wasmtime_wasi::DirPerms;
use wasmtime_wasi::FilePerms;

fn build_wasi_ctx(tenant_id: &str) -> anyhow::Result<WasiCtx> {
    let workdir = format!("/var/lib/wasm-tenants/{tenant_id}/workdir");
    let readonly_assets = "/usr/share/wasm-platform/assets";

    let dir = cap_std::fs::Dir::open_ambient_dir(
        &workdir, cap_std::ambient_authority())?;
    let assets = cap_std::fs::Dir::open_ambient_dir(
        readonly_assets, cap_std::ambient_authority())?;

    let mut wasi = WasiCtxBuilder::new();
    wasi.preopened_dir(dir, DirPerms::all(), FilePerms::all(), "/work")?;
    wasi.preopened_dir(assets, DirPerms::READ, FilePerms::READ, "/assets")?;

    // No stdin. Wrap stdout/stderr in size-limited buffers.
    wasi.stdin(Box::new(wasmtime_wasi::preview2::pipe::ClosedInputStream));
    wasi.stdout(Box::new(LimitedWriter::new(64 * 1024)));
    wasi.stderr(Box::new(LimitedWriter::new(64 * 1024)));

    // No environment variables; no command-line arguments.
    // No clocks beyond monotonic.
    wasi.allow_blocking_current_thread(false);

    Ok(wasi.build())
}
```

The two preopened directories are cap-std handles, not paths. The module cannot use `..` traversal to escape — cap-std refuses paths that resolve outside the directory handle's view. Symlinks within the directory are followed; symlinks pointing outside are rejected at `open` time.

For network access, use the WASI Preview 2 sockets API explicitly:

```rust
use wasmtime_wasi::preview2::SocketAddrCheck;

let mut wasi = WasiCtxBuilder::new();
wasi.socket_addr_check(|addr, _| {
    // Allowlist: only specific external endpoints.
    matches!(addr.ip().to_string().as_str(),
        "192.168.10.5" | "192.168.10.6")
});
wasi.allow_tcp(true);
wasi.allow_udp(false);
```

Block by default: do not call `allow_tcp(true)` unless the workload genuinely needs outbound network. Most WASM workloads do not.

### Step 4: Disable Risky Features

Many proposals (threads, multi-memory, GC, exceptions) add complexity to the runtime and broaden the attack surface. Disable what you do not use.

```rust
config.wasm_threads(false);            // shared linear memory
config.wasm_multi_memory(false);
config.wasm_memory64(false);            // 64-bit linear memory; rare in production
config.wasm_function_references(true);  // safe
config.wasm_gc(false);                  // disable until policy is set
config.wasm_exceptions(false);
config.wasm_relaxed_simd(false);        // less audited than core SIMD
config.wasm_tail_call(true);            // safe; ergonomic for some compilers
```

Each disabled feature reduces both runtime and verifier surface. Re-enable individually after auditing the runtime version's stability for that feature.

### Step 5: Module Validation and Cache Hygiene

Validate every module before instantiation. Wasmtime validates by default during `Module::new`, but explicit validation surfaces errors before the engine commits to caching.

```rust
let validator_config = wasmparser::WasmFeatures {
    threads: false,
    multi_memory: false,
    relaxed_simd: false,
    ..wasmparser::WasmFeatures::default()
};
let mut validator = wasmparser::Validator::new_with_features(validator_config);
validator.validate_all(wasm_bytes)?;
let module = Module::new(&engine, wasm_bytes)?;
```

The validator runs at compile time; the engine then caches the compiled artifact. If a module compiles cleanly once, subsequent invocations skip the cost. Pin the cache directory to a tenant-scoped path so cache poisoning across tenants is impossible:

```toml
# /etc/wasmtime/cache.toml
[cache]
enabled = true
directory = "/var/cache/wasmtime/tenant-{tenant_id}"
cleanup-interval = "1d"
files-total-size-soft-limit = "1Gi"
```

### Step 6: Operational Telemetry

Track per-tenant and per-module behavior:

```
wasmtime_module_executions_total{tenant, module}    counter
wasmtime_fuel_consumed{tenant, module}              histogram
wasmtime_traps_total{tenant, module, kind}          counter
wasmtime_memory_growth_rejections_total{tenant}      counter
wasmtime_instance_lifetime_seconds{tenant, module}  histogram
wasmtime_wasi_calls_total{tenant, capability, op}   counter
```

Alert on spikes in `wasmtime_traps_total{kind="fuel_exhausted"}` or `wasmtime_memory_growth_rejections_total` — these usually indicate either an abusive module or a misconfigured limit.

## Expected Behaviour

| Signal | Default Wasmtime | Hardened |
|--------|------------------|----------|
| `loop {}` in a module | Hangs the host thread indefinitely | Traps within ~50–100 ms (epoch deadline) |
| Module attempts to grow memory to 1 GB | Allocates if host memory allows | Trap; `memory_growing` returns `Ok(false)` |
| Module tries `open("/etc/passwd")` | Succeeds if WASI inherits stdio paths | `ENOENT` (cap-std refuses) |
| Module connects to external IP | Succeeds with default WASI sockets | Refused unless on allowlist |
| Module uses `wasm_threads` | Compiles | Compile-time error: feature disabled |
| Per-call accounting | None | Fuel + epoch + memory metrics per Store |
| Cache poisoning across tenants | Possible if cache shared | Per-tenant cache directories |

Verification:

```bash
# Confirm CPU limit fires.
cat <<'EOF' > /tmp/loop.wat
(module (func (export "run") (result i32)
  (loop $l (br $l))
  (i32.const 0)))
EOF
wasmtime compile /tmp/loop.wat -o /tmp/loop.cwasm
timeout 3 wasm-runner /tmp/loop.cwasm
# Expected: trap "epoch deadline reached" within 100ms.

# Confirm filesystem capability check.
cat <<'EOF' > /tmp/escape.wat
(module
  (import "wasi_snapshot_preview1" "path_open" (func ...))
  (func (export "run") ...))
EOF
# Should receive errno=44 (ENOENT) for paths outside the preopened dir.
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Fuel + epoch combo | Hard CPU bound regardless of module behavior | Fuel adds ~5-15% per-op cost; epoch incrementer thread costs negligible CPU | Use epoch alone for performance-critical workloads where billing-grade accuracy is not needed; fuel for billing/quota workloads. |
| Per-instance memory limiter | Prevents memory exhaustion across tenants | Module rejection when limit hit; needs graceful error path | Surface the limit in the module ABI so well-behaved modules can degrade rather than crash. |
| Empty WASI context | Smallest attack surface | Modules that need any I/O must declare it explicitly | Provide a tenant-config layer mapping declared capabilities to validated allowlists. |
| Disabled features | Reduces runtime surface | Some compilers emit threads/multi-memory by default | Document feature requirements per platform; reject modules at upload time that use disabled features. |
| Cache per tenant | Eliminates cross-tenant cache poisoning | Disk usage scales with tenant count and module count | Cap per-tenant cache size; expire idle tenants' caches. |
| Telemetry | Detect abuse early | Metric cardinality grows with tenants × modules | Aggregate at high cardinality (per-tenant) and use exemplars for per-module drill-down. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Epoch incrementer thread dies | Modules run beyond their deadline | `wasmtime_traps_total{kind="epoch_deadline"}` drops to zero while module count stays nonzero | Restart the incrementer; supervise with a watchdog. |
| Fuel exhaustion misconfigured | All modules trap on first instruction | High rate of `fuel_exhausted` traps; first-call latency near zero | Increase the per-call fuel grant. Determine empirically by measuring fuel consumption of representative workloads. |
| Module bypasses WASI by using compiled-in syscalls | A WASM module ostensibly without WASI imports still does I/O | Should be impossible — WASM has no host calls without imports | Audit the module's import section. Rebuild the toolchain if the build inadvertently compiled host calls in. |
| Cap-std symlink check fails | Module reads file through a stale symlink that pointed inside but now points outside | File-access logs show an unexpected target | Cap-std resolves at open time; rare but possible if a directory is shared with non-WASI tenants. Lock the workdir to root-owned, immutable directory entries. |
| Memory limit too low for legitimate use | Module fails to grow memory; legitimate workload broken | `wasmtime_memory_growth_rejections_total` rises with no obvious abuse pattern | Raise the limit. Track per-module memory peaks and set limit at 1.5x the observed peak. |
| Compilation cache corruption | Modules fail to load with cache errors | Wasmtime logs `cache miss` or compilation errors at load time | Clear the cache directory; rebuild. Investigate file-system or filesystem-driver corruption. |
| Long-running compilation blocks request | First-time module load takes seconds | High p99 latency on cold-start; CPU time spent in `Module::new` | Pre-compile modules at upload; serve precompiled `.cwasm` artifacts from the cache. |

## Related Articles

- [WASM Workloads on Kubernetes](/articles/wasm/wasm-on-kubernetes/)
- [WASI Preview 2 Capability-Based Security](/articles/wasm/wasi-preview-2-capabilities/)
- [Envoy WASM Plugin Hardening](/articles/wasm/envoy-wasm-plugin-hardening/)
- [Edge Runtime WASM Hardening](/articles/wasm/edge-wasm-hardening/)
- [seccomp Profiles for Kubernetes Workloads](/articles/kubernetes/seccomp-profiles/)
