---
title: "WASM Multi-Tenancy Patterns: Resource Quotas, Fair Scheduling, and Tenant Isolation Failures"
description: "Running many tenants' WASM modules in one runtime is the hard case. Per-tenant fairness, isolation guarantees, and the failure modes that violate both."
slug: "wasm-multi-tenancy"
date: 2026-04-27
lastmod: 2026-04-27
category: "wasm"
tags: ["wasm", "multi-tenancy", "isolation", "scheduling", "wasmtime"]
personas: ["platform-engineer", "security-engineer", "ml-engineer"]
article_number: 198
difficulty: "advanced"
estimated_reading_time: 15
published: true
layout: article.njk
permalink: "/articles/wasm/wasm-multi-tenancy/index.html"
---

# WASM Multi-Tenancy Patterns: Resource Quotas, Fair Scheduling, and Tenant Isolation Failures

## Problem

Running multiple tenants' WASM workloads in a single runtime instance is the hard case for WASM platforms. Single-tenant Wasmtime hardening (covered in [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)) bounds one workload. Multi-tenant adds three orthogonal concerns:

- **Fairness:** one tenant's workload should not starve another's. Naive per-call resource caps still allow one greedy tenant to dominate by submitting many concurrent calls.
- **Isolation:** beyond linear-memory boundaries, tenants share JIT-compiled code caches, host-side resource tables, and network connections to shared host services. Each shared resource is an isolation surface.
- **Predictability:** in a multi-tenant system, latency for tenant B depends on what tenant A is doing. Production SLAs require bounded interference.

By 2026 multi-tenant WASM is mainstream — Cloudflare Workers, Fastly Compute, Spin running in shared Kubernetes Pods, wasmCloud lattice deployments. The hardening contract for these platforms is significantly more involved than single-tenant.

The specific gaps in a default multi-tenant Wasmtime embedding:

- All tenants share one `Engine`. Compiled code cache is shared; cache poisoning by a malicious tenant could affect others.
- Per-`Store` resource limiters apply per-call, not per-tenant aggregate. Tenant A submitting 1000 concurrent calls each at the cap consumes 1000× the cap.
- Host functions called by WASM modules touch shared backends (database, KV store, message queue). Without per-tenant quotas at the host-function layer, a tenant can saturate shared backends.
- Scheduling is FIFO across calls. A tenant with high arrival rate gets the same time slice as one with infrequent calls.
- JIT-compilation pauses block all calls in the same `Engine` during the pause. A tenant uploading a new module triggers latency spikes for all tenants.

This article covers per-tenant resource accounting, fair scheduling across tenants, host-function quotas, isolated `Engine` instances per trust boundary, and the failure modes that violate tenant isolation.

**Target systems:** Wasmtime 22+ embedded in a multi-tenant control plane; Spin platform 2.6+, wasmCloud 1.2+, Fastly Compute and Cloudflare Workers (managed analogs).

## Threat Model

- **Adversary 1 — Greedy tenant:** a tenant submits unusually high call rates, each within per-call caps but cumulatively starving others.
- **Adversary 2 — Malicious tenant attempting cross-tenant attack:** crafted module trying to read another tenant's module memory, poison shared cache, or consume tokens / credentials issued by host functions.
- **Adversary 3 — Compromised module attempting JIT-cache poisoning:** module designed to exercise codepaths that trigger compilation; hopes to land malicious code in the cache that other modules then execute.
- **Adversary 4 — Resource-exhaustion attack on host functions:** module calls a shared host function (database write, network egress) at high rate to exhaust the host's downstream capacity.
- **Access level:** Adversary 1 has standard tenant API. Adversary 2 has module-upload. Adversary 3 has module-upload + knowledge of the runtime's compilation behavior. Adversary 4 has standard API.
- **Objective:** Degrade service for other tenants, cross tenant boundaries, exhaust shared resources.
- **Blast radius:** Without per-tenant quotas, one tenant can affect every other. With proper accounting, blast radius is bounded to the offending tenant's quota; other tenants see no degradation.

## Configuration

### Pattern 1: Per-Tenant Resource Aggregate Quotas

Rather than (or in addition to) per-call limits, track per-tenant totals across a sliding window.

```rust
// per_tenant_quota.rs
use std::sync::Arc;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct TenantQuota {
    cpu_seconds_per_window: f64,
    memory_max_bytes: usize,
    concurrent_calls_max: usize,
    egress_bytes_per_window: u64,
    window: Duration,
}

pub struct TenantState {
    cpu_used_in_window: f64,
    window_started: Instant,
    concurrent_calls: usize,
    memory_in_use: usize,
    egress_bytes_in_window: u64,
}

pub struct TenantTracker {
    quotas: HashMap<String, TenantQuota>,
    state: Arc<Mutex<HashMap<String, TenantState>>>,
}

impl TenantTracker {
    pub fn admit_call(&self, tenant_id: &str) -> Result<CallGuard, QuotaError> {
        let mut state = self.state.lock();
        let s = state.entry(tenant_id.to_string()).or_insert_with(default_state);
        // Roll the window if expired.
        let q = self.quotas.get(tenant_id).ok_or(QuotaError::UnknownTenant)?;
        if s.window_started.elapsed() >= q.window {
            s.cpu_used_in_window = 0.0;
            s.egress_bytes_in_window = 0;
            s.window_started = Instant::now();
        }
        if s.concurrent_calls >= q.concurrent_calls_max {
            return Err(QuotaError::ConcurrencyLimit);
        }
        if s.cpu_used_in_window >= q.cpu_seconds_per_window {
            return Err(QuotaError::CpuLimit);
        }
        s.concurrent_calls += 1;
        Ok(CallGuard { tenant_id: tenant_id.into(), tracker: self.state.clone() })
    }

    pub fn record_cpu(&self, tenant_id: &str, seconds: f64) {
        let mut state = self.state.lock();
        if let Some(s) = state.get_mut(tenant_id) {
            s.cpu_used_in_window += seconds;
        }
    }
}

pub struct CallGuard {
    tenant_id: String,
    tracker: Arc<Mutex<HashMap<String, TenantState>>>,
}

impl Drop for CallGuard {
    fn drop(&mut self) {
        if let Some(s) = self.tracker.lock().get_mut(&self.tenant_id) {
            s.concurrent_calls = s.concurrent_calls.saturating_sub(1);
        }
    }
}
```

Wrap every WASM call site with `admit_call` → execute → `record_cpu`. A tenant exceeding any quota dimension gets rejected at the boundary; other tenants' calls proceed.

### Pattern 2: Fair Scheduling Across Tenants

When the system is at capacity, who waits and who runs? FIFO favors high-volume tenants. Use a weighted-fair queue.

```rust
// fair_scheduler.rs
// Per-tenant FIFO; round-robin across tenants weighted by quota.
use std::collections::{HashMap, VecDeque};
use tokio::sync::Notify;

pub struct FairScheduler {
    tenant_queues: HashMap<String, VecDeque<Job>>,
    tenant_weights: HashMap<String, u32>,
    last_served: HashMap<String, Instant>,
    notify: Notify,
}

impl FairScheduler {
    pub fn submit(&mut self, job: Job) {
        self.tenant_queues.entry(job.tenant_id.clone()).or_default().push_back(job);
        self.notify.notify_one();
    }

    pub async fn next(&mut self) -> Job {
        // Pick the tenant whose deficit (weight × time-since-served) is highest.
        loop {
            let mut best: Option<(&String, f64)> = None;
            for (tid, queue) in &self.tenant_queues {
                if queue.is_empty() { continue; }
                let weight = *self.tenant_weights.get(tid).unwrap_or(&1);
                let last = self.last_served.get(tid).copied().unwrap_or(Instant::now());
                let score = last.elapsed().as_secs_f64() * weight as f64;
                if best.map_or(true, |(_, s)| score > s) {
                    best = Some((tid, score));
                }
            }
            if let Some((tid, _)) = best {
                let tid = tid.clone();
                let job = self.tenant_queues.get_mut(&tid).unwrap().pop_front().unwrap();
                self.last_served.insert(tid, Instant::now());
                return job;
            }
            self.notify.notified().await;
        }
    }
}
```

A tenant with weight 1 served once gets equal time as a tenant with weight 1 waiting; a tenant with weight 5 gets 5× the time-share. Quotas remain hard caps; weights determine priority within those caps.

### Pattern 3: Per-Tenant Engines for Trust Boundaries

Sharing one `Engine` (and therefore one compilation cache) across all tenants is fast but couples them. For the highest isolation, give each tenant — or each trust class — its own `Engine`.

```rust
struct TenantRuntime {
    engine: Engine,
    cache_dir: PathBuf,
}

let mut tenant_runtimes: HashMap<String, TenantRuntime> = HashMap::new();

fn get_or_create_runtime(tenant_id: &str) -> &TenantRuntime {
    tenant_runtimes.entry(tenant_id.into()).or_insert_with(|| {
        let mut config = Config::new();
        config.cache_config_load(format!("/var/cache/wasmtime/{tenant_id}/cache.toml"))
            .expect("cache config");
        config.consume_fuel(true);
        config.epoch_interruption(true);
        // Per-tenant compilation costs; can be parallelized.
        let engine = Engine::new(&config).expect("engine");
        TenantRuntime { engine, cache_dir: format!("/var/cache/wasmtime/{tenant_id}").into() }
    })
}
```

Each tenant's compiled `.cwasm` artifacts live in their own cache directory. A malicious tenant cannot poison cache entries for others.

The trade-off: more memory (each engine has its own jit data structures, ~10-50 MB) and each tenant pays its own first-compile cost. For 100 tenants, that's 1-5 GB of engine overhead — acceptable for high-trust separation.

### Pattern 4: Host-Function Quotas

Host functions reach shared backends (databases, KV, message queues, the network). A tenant calling `db.query(...)` 1M times consumes shared backend capacity.

Wrap host functions with per-tenant quotas:

```rust
fn instrumented_db_query(
    mut caller: Caller<'_, Host>,
    tenant_id: &str,
    query_ptr: u32,
    query_len: u32,
) -> Result<u32, Error> {
    // Per-tenant rate limit.
    let quota = caller.data().tenant_tracker.host_function_quota(tenant_id, "db.query")?;
    quota.consume_or_reject(1)?;

    // Per-call timeout that does not consume the tenant's CPU budget if database is slow.
    let result = tokio::time::timeout(Duration::from_millis(500), async {
        caller.data().db.query(read_string(&caller, query_ptr, query_len)?)
    }).await??;

    Ok(write_result(&caller, result)?)
}
```

The `host_function_quota` is a per-tenant token bucket: tenant gets N tokens per second for `db.query`, refills naturally. Bursts are bounded.

### Pattern 5: JIT Compilation Pause Mitigation

Wasmtime's compilation can briefly pause execution of other modules in the same engine. For latency-critical multi-tenant workloads:

- Pre-compile modules at upload time, never on first request.
- Use `Config::compilation_strategy(CompilationStrategy::Cranelift)` with `Config::cranelift_opt_level(OptLevel::Speed)` — opt for compile speed over execution speed if compile pauses dominate.
- Run compilation in a separate thread pool, dedicated to compilation, distinct from the request-handling pool.

```rust
// Pre-compile asynchronously; serve from cache when ready.
let module_bytes = upload_module(tenant_id, &wasm_bytes).await?;
tokio::task::spawn_blocking(move || {
    let module = Module::new(&engine, &module_bytes)?;
    let cwasm = module.serialize()?;
    fs::write(format!("/var/cache/wasmtime/{tenant_id}/{module_id}.cwasm"), cwasm)?;
    Ok(())
}).await??;

// Subsequent invocations.
let module = Module::deserialize_file(&engine, &cwasm_path)?;
```

### Pattern 6: Telemetry Per Tenant

Every metric carries the tenant label.

```
wasm_tenant_invocations_total{tenant, module}                counter
wasm_tenant_cpu_seconds_total{tenant}                         counter
wasm_tenant_memory_pages{tenant, module}                      gauge
wasm_tenant_quota_rejected_total{tenant, reason}              counter
wasm_tenant_concurrent_calls{tenant}                          gauge
wasm_tenant_egress_bytes_total{tenant, target}                counter
wasm_tenant_host_function_calls_total{tenant, function}       counter
wasm_tenant_jit_compile_seconds_total{tenant, module}          counter
```

Build per-tenant dashboards. Anomaly alerts:
- `wasm_tenant_quota_rejected_total{reason="cpu_limit"}` rising — tenant is hitting their CPU quota repeatedly. Either grow them up a tier or investigate behavior.
- `wasm_tenant_cpu_seconds_total` for one tenant comparable to total system CPU — a single tenant dominating; verify quota assignment is correct.
- `wasm_tenant_jit_compile_seconds_total` correlated with latency spikes — compilation is on the request path; pre-compile.

## Expected Behaviour

| Signal | Single-engine, no quotas | Per-tenant quotas + fair scheduler |
|--------|---------------------------|--------------------------------------|
| Tenant A submits 10x normal load | Other tenants slow | Tenant A throttled to their quota; others unaffected |
| Tenant A uploads new large module | All tenants pause during JIT compile | Compile in background; other tenants unaffected |
| Tenant A's module attempts cache poisoning | Could succeed if implementation buggy | Per-tenant cache directory; impossible |
| Tenant A's host calls saturate database | Database queue grows for everyone | Tenant A's calls rejected at host-function quota; database unaffected |
| Tenant A's quota limit reached | Effectively unbounded | Hard rejection; tenant sees `429 quota_exceeded` |
| Latency for Tenant B during Tenant A spike | Variable | Bounded by Tenant B's own quota; insensitive to Tenant A |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Per-tenant aggregate quotas | Bounds noisy-neighbor effects | Tracking and accounting overhead | Implement in a single tenant-tracker module shared across all hot paths. |
| Fair scheduling | Predictable latency for low-volume tenants | More complex than FIFO | Use existing libraries (tokio's `JoinSet` with scheduler hooks); avoid hand-rolling. |
| Per-tenant engines | Strong isolation; per-tenant cache | Memory overhead per tenant | Use only for high-trust separation (paid customers); shared engine for free-tier where cost-per-tenant matters. |
| Host-function quotas | Bounds backend resource use | Each host function needs explicit quota | Centralize quota logic in a wrapper; apply via macros or codegen. |
| Pre-compilation at upload | Eliminates JIT-on-request latency | Upload is slower; modules retained even if never invoked | Acceptable; upload is a less latency-sensitive operation. |
| Per-tenant telemetry | Detection of anomalies | Metric cardinality grows with tenant count | High-cardinality tenant labels are expensive in some TSDBs (Prometheus, Mimir); use exemplars rather than full per-tenant breakdown for high-volume metrics. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Quota lookup race / TOCTOU | Tenant exceeds quota briefly during concurrent admission | `wasm_tenant_cpu_seconds_total` exceeds quota | Use atomic operations (compare-and-swap) for quota updates; or a single-writer thread per tenant. |
| Per-tenant cache directory permissions wrong | Cross-tenant cache read possible | OS-level file permission check fails | Tenant-cache directories owned by per-tenant UIDs (combined with user namespace); enforce mode 0700. |
| Fair scheduler livelock | Some tenant's queue never serves | Per-tenant queue depth grows unbounded for a specific tenant | Add a maximum-wait deadline to each job; jobs exceeding it are rejected. Bug in scoring logic. |
| Host function quota too low | Legitimate tenant hits quota during normal use | Tenant complaints; metrics show high `quota_rejected` rate from a known-good tenant | Profile real workloads; size quotas to 99th-percentile peak * 1.5. |
| Quota exhaustion attack | Tenant deliberately fills quota to deny their own service to themselves | (rare and self-inflicted) | Quota refresh window is short; tenant naturally recovers. Rate-limit account-level lockouts. |
| Tenant grows beyond their tier | Production load now exceeds quota; legitimate degradation | Quota-rejected rate sustained over hours | Move to higher tier; trigger billing alert; do not silently raise quota for a tenant. |
| JIT-cache corruption | Specific tenant module always traps after a partial-write event | Crash with cache-related errors | Per-tenant cache; delete the affected directory; force recompile. Use atomic rename for cache writes. |

## When to Consider a Managed Alternative

Building a multi-tenant WASM platform in-house requires quota infrastructure, fair scheduling, per-tenant engines, telemetry, and ongoing tuning (15-30 hours/month for a platform team).

- **[Cloudflare Workers](https://workers.cloudflare.com/):** isolate-based, multi-tenant by design.
- **[Fastly Compute](https://www.fastly.com/products/edge-compute):** Wasmtime-based with platform-managed isolation.
- **[Fermyon Cloud](https://www.fermyon.com/cloud):** Spin-based managed multi-tenant platform.
- **[Wasmer Edge](https://wasmer.io/products/edge):** managed multi-tenant WASM hosting.

## Related Articles

- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [WASM Workloads on Kubernetes](/articles/wasm/wasm-on-kubernetes/)
- [Edge Runtime WASM Hardening](/articles/wasm/edge-wasm-hardening/)
- [WASI Preview 2 Capability-Based Security](/articles/wasm/wasi-preview-2-capabilities/)
- [WASI HTTP Server Hardening](/articles/wasm/wasi-http-server-hardening/)
