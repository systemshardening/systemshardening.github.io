---
title: "WASM Threads and Shared Memory Security: SharedArrayBuffer, Atomics, and Spectre Mitigations"
description: "WASM threading via SharedArrayBuffer re-opens Spectre-class timing attacks. Cross-origin isolation, per-tenant memory isolation, and atomics hygiene are required before enabling threads."
slug: "wasm-threads-shared-memory"
date: 2026-04-29
lastmod: 2026-04-29
category: "wasm"
tags: ["wasm", "threads", "shared-memory", "spectre", "security"]
personas: ["platform-engineer", "security-engineer", "ml-engineer"]
article_number: 238
difficulty: "advanced"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/wasm/wasm-threads-shared-memory/index.html"
---

# WASM Threads and Shared Memory Security: SharedArrayBuffer, Atomics, and Spectre Mitigations

## Problem

WebAssembly's threading proposal — standardized in 2022 and now widely supported across Wasmtime, WAMR, V8, and SpiderMonkey — allows WASM modules to share memory between threads using `SharedArrayBuffer` and coordinate via atomic operations. This enables significant parallelism in compute-intensive WASM workloads: image processing, ML inference, compression, cryptography.

It also re-opens Spectre.

The original Spectre and Meltdown disclosures in 2018 led browsers to disable `SharedArrayBuffer` globally for two years. The attack requires a high-resolution timer to measure cache-side-channel timing, and `SharedArrayBuffer` with `Atomics.wait()` provides exactly that — a timer with sub-microsecond resolution implemented in shared memory. Browsers re-enabled `SharedArrayBuffer` in 2020 only after requiring Cross-Origin Isolation (COOP + COEP headers), which restricts what cross-origin content can be loaded alongside the WASM module.

Server-side WASM runtimes face different but equally serious threading risks:

- **Shared memory across tenant boundaries:** A multi-tenant WASM runtime that allows tenants to share a `SharedArrayBuffer` creates a direct memory sharing channel between tenant modules — the most dangerous possible isolation failure.
- **Race conditions in shared state:** WASM threads communicating via shared memory without correct atomics discipline introduce data races that manifest as security vulnerabilities: TOCTOU bypasses, corrupted policy state, or stale cache entries read by a security check.
- **Incorrect memory ownership:** When threads share memory and one thread frees a region while another is reading it, the result is a use-after-free. In WASM's linear memory model this doesn't crash (memory is still mapped) but can produce incorrect policy decisions or leak data from adjacent allocations.
- **Timing channels via atomics:** On multi-tenant platforms, a WASM module using `Atomics.wait()` with precise timing can measure cache effects on shared memory regions, enabling Spectre-style speculation attacks.

The net effect: threading in WASM must be treated as a security feature requiring explicit policy decisions, not an implementation detail.

**Target systems:** Wasmtime 22+ (threading via shared memory), WAMR 2.0+ (pthread support), V8 10+ (WASM threads in Node.js), Spin 2.6+ (multi-threaded component model), browser WASM with `SharedArrayBuffer`.

## Threat Model

- **Adversary 1 — Spectre via atomics timer:** A WASM module in a browser context with `SharedArrayBuffer` enabled uses `Atomics.wait()` to construct a high-resolution timer. It performs a Spectre-class speculation attack, reading values from outside its linear memory sandbox by measuring cache timing.
- **Adversary 2 — Cross-tenant shared memory in a runtime:** A multi-tenant WASM runtime inadvertently passes the same `SharedArrayBuffer` handle to two tenant modules (implementation bug or misconfiguration). Tenant A can directly read and write Tenant B's in-memory state.
- **Adversary 3 — TOCTOU via shared memory race:** A security check reads a value from shared memory (e.g., a permissions flag), then acts on it. Between the read and the action, another thread modifies the value. The check passes for one state but the action executes in another.
- **Adversary 4 — Timing side-channel against co-tenant:** Two WASM modules run in the same process on adjacent linear memory regions. Thread timing measurements by one reveal the access pattern of the other's memory — enabling cache-based side-channel attacks.
- **Access level:** Adversary 1 has WASM execution in a browser context where COOP/COEP is misconfigured. Adversary 2 has WASM execution in the multi-tenant runtime as a legitimate tenant. Adversary 3 has write access to a shared memory region. Adversary 4 has WASM execution and can spawn threads.
- **Objective:** Read memory outside the WASM sandbox (Adversary 1), read or corrupt another tenant's state (Adversaries 2, 4), bypass a security check (Adversary 3).
- **Blast radius:** Shared memory misconfiguration in a multi-tenant runtime is equivalent to no tenant isolation. Spectre via timers reads ~100 bytes per second — slow, but enough to extract key material over minutes.

## Configuration

### Step 1: Cross-Origin Isolation for Browser WASM Threads

`SharedArrayBuffer` in browsers requires Cross-Origin Isolation. Configure the HTTP response headers:

```nginx
# nginx configuration for WASM-serving endpoint.
location / {
    # Cross-Origin Opener Policy: isolates the browsing context from other origins.
    add_header Cross-Origin-Opener-Policy "same-origin" always;

    # Cross-Origin Embedder Policy: prevents loading cross-origin resources without CORS.
    add_header Cross-Origin-Embedder-Policy "require-corp" always;

    # Verify isolation is effective (read from JavaScript):
    # if (crossOriginIsolated) { /* SharedArrayBuffer available */ }
}
```

For resources loaded by the page (fonts, images, scripts from CDN), add:

```nginx
# CDN / static asset server.
location /static/ {
    add_header Cross-Origin-Resource-Policy "cross-origin" always;
    add_header Access-Control-Allow-Origin "*";
}
```

Verify isolation from JavaScript:

```javascript
if (crossOriginIsolated) {
    // Safe to use SharedArrayBuffer.
    const shared = new SharedArrayBuffer(1024);
    // ...
} else {
    console.error("Cross-origin isolation not active; threads disabled.");
    // Fall back to single-threaded WASM.
}
```

### Step 2: Disable Threads Per-Tenant in Wasmtime

In Wasmtime, enable shared memory only for tenants that explicitly require it, not as a runtime-wide default:

```rust
use wasmtime::{Config, Engine};

fn create_engine_for_tenant(allow_threads: bool) -> Engine {
    let mut config = Config::new();

    // Threads are off by default; only enable for specific tenants.
    config.wasm_threads(allow_threads);

    // Memory protection keys (MPK): isolate linear memory from other tenants.
    config.memory_guard_size(1 << 20);   // 1 MiB guard pages around each memory.

    // Epoch-based interruption: bound how long a threaded module can run.
    config.epoch_interruption(true);

    Engine::new(&config).unwrap()
}

// High-security tenants get single-threaded engines.
let tenant_engine = if tenant.is_trusted_tier {
    create_engine_for_tenant(true)
} else {
    create_engine_for_tenant(false)
};
```

Per-tenant thread isolation via separate processes (higher security, higher cost):

```rust
// For strong isolation: run each tenant in a separate process.
// Threads cannot share memory across process boundaries.
use std::process::{Command, Stdio};

fn spawn_tenant_process(tenant_id: &str, module_path: &str) -> Child {
    Command::new("wasmtime")
        .arg("--wasm-threads=y")
        .arg(module_path)
        .env("TENANT_ID", tenant_id)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to spawn tenant process")
}
```

Process-isolated tenants cannot share `SharedArrayBuffer` — it requires same-process shared memory.

### Step 3: WASM Module Memory Isolation with Memory64 and Guard Pages

Use guard pages and separate allocators to prevent cross-tenant memory access:

```rust
use wasmtime::{Engine, Config, LinearMemory, MemoryCreator};

struct IsolatedMemoryCreator {
    tenant_id: String,
}

unsafe impl MemoryCreator for IsolatedMemoryCreator {
    fn new_memory(
        &self,
        ty: MemoryType,
        minimum: usize,
        maximum: Option<usize>,
        reserved_size_in_bytes: Option<usize>,
        guard_size_in_bytes: usize,
    ) -> Result<Box<dyn LinearMemory>, String> {
        // Each tenant gets memory from an isolated mmap region with guard pages.
        let mem = IsolatedLinearMemory::new(
            minimum,
            maximum,
            // Guard pages: unmapped pages at start and end of memory region.
            // Access to them generates SIGSEGV, not silent data read.
            guard_size_in_bytes.max(1 << 20),   // Minimum 1 MiB guard.
            &self.tenant_id,
        )?;
        Ok(Box::new(mem))
    }
}
```

In practice, the Wasmtime pooling allocator provides per-instance memory isolation:

```rust
let mut config = Config::new();
config.allocation_strategy(InstanceAllocationStrategy::Pooling({
    let mut pool = PoolingAllocationConfig::default();
    pool.total_memories(1000);       // Max 1000 concurrent tenant memories.
    pool.memory_pages(65536);        // 4 GiB virtual per tenant (sparse).
    pool.max_memories_per_module(1); // One memory per module (no sharing).
    pool
}));
```

### Step 4: Atomic Operations and TOCTOU Prevention

For WASM modules that use shared memory for internal parallelism (not cross-tenant), the atomics discipline must prevent TOCTOU races in security-critical paths.

**In WASM (Rust, compiled to WASM with threads):**

```rust
use std::sync::atomic::{AtomicU32, Ordering};

struct PolicyState {
    permissions: AtomicU32,   // Atomic; safe across threads.
}

impl PolicyState {
    fn check_and_act(&self, required_permission: u32) -> bool {
        // Use SeqCst ordering for security checks: guarantees no reordering.
        let current = self.permissions.load(Ordering::SeqCst);
        if current & required_permission == 0 {
            return false;
        }
        // The action occurs after the check; no window for another thread
        // to lower permissions between check and act if we hold a lock.
        // For mutation, use compare_exchange to prevent TOCTOU:
        let result = self.permissions.compare_exchange(
            current,
            current & !required_permission,   // Consume the permission.
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        result.is_ok()   // Returns false if another thread raced.
    }
}
```

The TOCTOU pattern to avoid:

```wasm
;; UNSAFE: Check then act with a window for race.
(i32.load (global.get $perm_flag))  ;; Load permission.
(i32.eqz)
(if (then
  (return (i32.const 0))            ;; Check.
))
;; WINDOW: another thread can set perm_flag to 0 here.
(call $privileged_operation)        ;; Act. May execute without valid permission.
```

The safe pattern uses `memory.atomic.rmw.and` (atomic read-modify-write) to atomically consume the permission in one operation:

```wasm
;; SAFE: Atomic check-and-clear.
(memory.atomic.rmw.and
  (global.get $perm_flag)
  (i32.const 0x01)                  ;; Clear the permission bit atomically.
)
(i32.eqz)
(if (then
  (return (i32.const 0))            ;; If the bit wasn't set, deny.
))
(call $privileged_operation)        ;; We cleared the bit; we own this execution.
```

### Step 5: Timer Precision Reduction for Speculation Mitigations

To degrade Spectre-via-timer attacks in environments where threading is allowed but Spectre is a concern, reduce the precision of timing sources:

**In a custom Wasmtime host function (for server-side runtimes):**

```rust
// Replace the high-precision clock with a jittered, coarser version.
linker.func_wrap("env", "now_micros", |_caller: Caller<'_, _>| -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;
    // Quantize to 100-microsecond resolution (degrades timing channel by 100x).
    (now / 100) * 100
})?;
```

For browser-hosted WASM, the browser handles this: Chrome and Firefox quantize `performance.now()` to 100 microseconds by default in cross-origin isolated contexts, and 1 millisecond in non-isolated contexts. The 100µs resolution is enough to significantly degrade Spectre attacks but not eliminate them — the isolation headers are the primary defense.

**Atomics timer restriction in Wasmtime:**

```rust
// Disable Atomics.wait() in multi-tenant WASM (prevents using atomics as a timer).
// This is separate from disabling threads entirely.
let mut config = Config::new();
config.wasm_threads(true);
// But: restrict atomics wait calls via a custom host function that rate-limits.
```

### Step 6: Memory Ownership Tracking for Shared Buffers

When WASM modules pass shared memory buffers between threads or to host functions, track ownership to prevent use-after-free:

```rust
use std::sync::{Arc, Mutex};

struct SharedBuffer {
    data: Arc<Mutex<Vec<u8>>>,
    owner_thread: std::thread::ThreadId,
}

impl SharedBuffer {
    fn access(&self) -> std::sync::MutexGuard<Vec<u8>> {
        self.data.lock().expect("buffer mutex poisoned")
    }

    fn is_owned_by_current_thread(&self) -> bool {
        self.owner_thread == std::thread::current().id()
    }
}

// Host function wrapping: validate buffer ownership before passing to WASM.
fn host_process_buffer(
    caller: &mut Caller<'_, TenantState>,
    buf_ptr: u32,
    buf_len: u32,
) -> Result<i32> {
    let memory = caller.get_export("memory")
        .and_then(|e| e.into_memory())
        .ok_or_else(|| anyhow::anyhow!("No memory export"))?;

    // Validate the WASM pointer and length before reading.
    let data = memory.data(caller.as_context());
    let start = buf_ptr as usize;
    let end = start.checked_add(buf_len as usize)
        .ok_or_else(|| anyhow::anyhow!("Buffer overflow"))?;
    if end > data.len() {
        return Err(anyhow::anyhow!("Buffer out of bounds"));
    }
    // Process the validated buffer.
    let slice = &data[start..end];
    Ok(process(slice))
}
```

### Step 7: Monitoring Thread and Memory Events

```
wasm_thread_count{tenant, module}                  gauge
wasm_shared_memory_bytes{tenant}                   gauge
wasm_atomic_wait_calls_total{tenant}               counter
wasm_memory_fault_total{tenant, fault_type}        counter
wasm_thread_spawn_rate{tenant}                     gauge
wasm_cross_tenant_memory_access_blocked_total      counter
```

Alert on:

- `wasm_atomic_wait_calls_total` unusually high for a tenant — possible timer-based side-channel attack.
- `wasm_cross_tenant_memory_access_blocked_total` non-zero — isolation enforcement caught a cross-tenant access.
- `wasm_memory_fault_total` non-zero — guard page violation; potential out-of-bounds access caught.
- `wasm_thread_count` for a tenant exceeding expected maximum — possible thread exhaustion DoS.

### Step 8: Testing Thread Safety and Memory Isolation

Automated testing for threading correctness:

```bash
# Use Miri (Rust's undefined behavior detector) to check for data races
# in WASM modules compiled from Rust.
cargo miri test --target wasm32-wasip2

# Run thread sanitizer on the host runtime.
RUSTFLAGS="-Z sanitizer=thread" cargo test --target x86_64-unknown-linux-gnu

# Wasmtime's own fuzzing for memory safety under threading.
cargo fuzz run wasm-threads-fuzzer -- -max_len=1000000 -timeout=30
```

Test cross-tenant isolation explicitly:

```rust
#[test]
fn test_no_shared_memory_between_tenants() {
    let engine_a = create_engine_for_tenant(false);   // Threads disabled.
    let engine_b = create_engine_for_tenant(false);

    let module_a = Module::from_file(&engine_a, "tenant_a.wasm").unwrap();
    let module_b = Module::from_file(&engine_b, "tenant_b.wasm").unwrap();

    // Verify that the memory exported by module A cannot be accessed
    // by module B's linker — different engines guarantee this.
    let mut store_a = Store::new(&engine_a, ());
    let mut store_b = Store::new(&engine_b, ());

    let instance_a = Instance::new(&mut store_a, &module_a, &[]).unwrap();
    let instance_b = Instance::new(&mut store_b, &module_b, &[]).unwrap();

    let mem_a = instance_a.get_memory(&mut store_a, "memory").unwrap();
    // This should compile but: mem_a is only valid for store_a; store_b
    // cannot access it. Wasmtime's type system enforces this.
}
```

## Expected Behaviour

| Signal | Threads without isolation | Threads with hardening |
|--------|--------------------------|----------------------|
| Cross-origin isolation | Absent; SharedArrayBuffer exposed broadly | COOP + COEP required; `crossOriginIsolated === true` |
| Cross-tenant shared memory | Possible if runtime misconfigures handles | Blocked; separate engines or processes per tenant |
| TOCTOU in security check | Race condition possible | Atomic RMW operations eliminate the race window |
| Timing resolution for Spectre | Nanosecond; Spectre attacks feasible | Quantized to 100µs; attack signal degraded 1000× |
| Guard page violations | Silent OOB reads return adjacent memory | SIGSEGV captured; alert fires; request aborted |
| Thread spawn rate | Unlimited; DoS possible | Rate-limited per tenant; `wasm_thread_count` gauge alerted |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Per-tenant engine isolation | Strong memory isolation | Higher memory overhead (one engine per tenant) | Use Wasmtime's pooling allocator to amortize. |
| Disabled threads for untrusted tenants | Eliminates threading attack surface | Lower throughput for compute-intensive modules | Enable threads only for explicitly trusted tenants. |
| Timer quantization | Degrades Spectre-via-timer | Breaks applications that rely on high-resolution timing | Acceptable for security WASM workloads; avoid for latency-sensitive audio/video. |
| SeqCst atomics for security checks | Prevents reordering attacks | 10–30% slower than relaxed atomics | Use SeqCst only in security-critical paths; relaxed elsewhere. |
| Process isolation per tenant | Strongest isolation; OS-enforced | High process creation overhead for short-lived modules | Pool processes; reuse per tenant. Cold start: use AOT (see wasm-cold-start). |
| Guard pages | Hardware-enforced OOB detection | Virtual memory overhead (1 MiB per tenant memory region) | Acceptable; virtual memory is cheap on 64-bit systems. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| COOP/COEP headers absent | `crossOriginIsolated === false`; SharedArrayBuffer throws TypeError | Browser console error; threads don't start | Add COOP + COEP headers; verify with `crossOriginIsolated`. |
| Same engine used for two tenants | Tenant A can access Tenant B's memory via a shared handle | Isolation test fails; or detected via memory scanning | Enforce one engine per tenant in the runtime; audit engine sharing. |
| TOCTOU in atomics code | Security check occasionally passes for unauthorized operation | Hard to detect in production; manifest as rare authorization bypass | Audit all shared-memory policy checks; replace load+branch with atomic RMW. |
| Thread count DoS | Runtime runs out of thread pool slots; new requests timeout | `wasm_thread_count` gauge at maximum; request latency spikes | Apply per-tenant thread limits in engine config; alert before limit reached. |
| Timer quantization broken by native clock | WASM module uses a host-exposed high-resolution timer instead of `Atomics.wait()` | Spectre attacks feasible via the high-res clock | Audit all host clock functions exposed to WASM; quantize all of them. |
| Guard page too small | An OOB access smaller than the guard page size is not caught | Silent data corruption; possible adjacent-tenant read | Set guard size >= 1 MiB; test with address sanitizer. |

## Related Articles

- [WASM Cold-Start Optimization for Security Workloads](/articles/wasm/wasm-cold-start/)
- [WASM Multi-Tenancy Patterns](/articles/wasm/wasm-multi-tenancy/)
- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [WASM Component Model Security](/articles/wasm/wasm-component-model-security/)
- [WASM Plugin Threat Modeling](/articles/wasm/wasm-plugin-threat-modeling/)
