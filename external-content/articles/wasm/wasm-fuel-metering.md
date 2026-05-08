---
title: "WASM Fuel Metering and Execution Budget Enforcement for DoS Prevention"
description: "Untrusted WASM modules can block a host thread forever with a single infinite loop. Fuel metering and epoch interruption give you hard, auditable CPU budgets — per call, per tenant, and per billing cycle."
slug: wasm-fuel-metering
date: 2026-05-07
lastmod: 2026-05-07
category: wasm
tags:
  - wasm
  - fuel-metering
  - resource-limits
  - dos-prevention
  - wasmtime
personas:
  - security-engineer
  - platform-engineer
article_number: 569
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/wasm/wasm-fuel-metering/
---

# WASM Fuel Metering and Execution Budget Enforcement for DoS Prevention

## Problem

WebAssembly's sandbox provides memory isolation and a capability-denied-by-default host interface. It provides no CPU bound. A module that executes `loop {} ` runs forever — occupying the host thread, preventing any other invocation from completing, and eventually forcing an operator to kill and restart the process. This is a trivial denial-of-service vector for any platform that runs untrusted WASM.

The infinite loop is the obvious case. The realistic cases are harder to detect:

- A module with exponential recursion that takes 30 seconds on a normal input and 3 hours on a crafted one.
- A module that performs heavy cryptographic operations in a tight loop under the guise of "key derivation".
- A buggy trusted module — a stack overflow, a runaway retry loop — that consumes 100% CPU until the process dies.
- A function-as-a-service workload where one tenant submits pathological inputs to drain CPU budget from every other tenant sharing the runtime.

None of these are caught by memory limits, WASI capability restrictions, or supply chain verification. They require an execution time budget enforced by the runtime itself.

Wasmtime (the most widely deployed production WASM runtime) provides two complementary mechanisms: **fuel metering**, which counts each executed instruction against a pre-set budget and traps when it runs out, and **epoch interruption**, which enforces a wall-clock deadline using a background timer. WasmEdge provides an analogous `--gas-limit` flag. Understanding when to use each — and how to set budgets that are neither too tight nor too permissive — is the central skill for CPU-bound DoS prevention in WASM platforms.

**Target systems:** Wasmtime 22+ (Rust API, Python bindings via `wasmtime-py`, Go via `wasmtime-go`); WasmEdge 0.13+ (CLI and SDK). Examples are in Rust unless noted.

## Threat Model

- **Adversary 1 — Malicious module author:** uploads a `.wasm` module containing a deliberately infinite or exponential computation to exhaust the platform's CPU, causing denial of service for other tenants.
- **Adversary 2 — Crafted input to a trusted module:** submits inputs that trigger a worst-case code path (quadratic complexity, unbounded retry) in a module that was not written maliciously but is vulnerable to algorithmic complexity attacks.
- **Adversary 3 — Billing fraud:** in a platform that charges per-function invocation with a flat fee, submits computationally cheap invocations from the billing perspective but CPU-expensive in reality, extracting subsidised computation.
- **Adversary 4 — Noisy neighbour amplification:** in a multi-tenant runtime, runs many concurrent long-lived invocations just below a per-call time limit to monopolise available threads.
- **Access level:** Adversaries 1 and 3 have module-upload or function-invocation access. Adversary 2 needs only function-invocation access. Adversary 4 needs function-invocation access and knowledge that the runtime is multi-tenant.
- **Objective:** CPU exhaustion, service degradation, cross-tenant latency impact, billing arbitrage.
- **Blast radius:** Without CPU limits, a single invocation blocks the host thread indefinitely. In a thread-per-invocation model, a burst of such invocations exhausts the thread pool. With per-invocation fuel or epoch limits, the blast radius is bounded to the time window of a single invocation before the runtime traps.

## The Infinite Loop Problem

A WebAssembly module that contains an unconditional branch to itself is valid WASM and compiles successfully. Wasmtime has no mechanism to detect this at compile time — the halting problem is undecidable and the runtime makes no attempt to solve it. At execution time, without a CPU limit configured, the module runs until it is externally killed.

```wat
;; infinite_loop.wat — valid WASM; compiles and links with no warnings.
(module
  (func (export "run") (result i32)
    (loop $l
      (br $l))
    (i32.const 0)))
```

In a synchronous host embedding — the common case for plugins and extension points — `func.call(&mut store, ())` never returns. The host thread is pinned. Other invocations queued behind it starve. If the runtime uses a thread pool, the pool eventually fills with stuck threads and stops accepting new work. The process must be killed and restarted.

The fix is not at the module level. You cannot rely on module authors writing well-behaved loops. The fix is in the runtime configuration, applied by the platform operator before any module is ever executed.

## Fuel Metering: Instruction-Level CPU Budgets

Fuel metering assigns a cost (one unit of "fuel") to each executed WASM instruction. The host provides an initial fuel grant when creating a `Store`. The runtime deducts fuel as instructions execute. When fuel reaches zero, the runtime traps with a `TrapCode::OutOfFuel` and returns control to the host.

### Enabling Fuel in Wasmtime (Rust)

Fuel requires two opt-in points: the `Config` (per-`Engine`) and the `Store` (per-invocation).

```rust
use wasmtime::{Config, Engine, Module, Store, Instance};

fn make_engine() -> Engine {
    let mut config = Config::new();
    // Enable fuel accounting. This adds per-instruction overhead.
    config.consume_fuel(true);
    Engine::new(&config).expect("engine creation failed")
}

fn invoke_with_fuel(
    engine: &Engine,
    module: &Module,
    fuel_budget: u64,
) -> anyhow::Result<i32> {
    let mut store = Store::new(engine, ());

    // Grant the invocation a fixed fuel budget.
    store.set_fuel(fuel_budget)?;

    let instance = Instance::new(&mut store, module, &[])?;
    let func = instance.get_typed_func::<(), i32>(&mut store, "run")?;

    match func.call(&mut store, ()) {
        Ok(result) => {
            let remaining = store.get_fuel().unwrap_or(0);
            let consumed = fuel_budget.saturating_sub(remaining);
            println!("consumed {consumed} fuel units; {} remaining", remaining);
            Ok(result)
        }
        Err(trap) => {
            // Distinguish fuel exhaustion from other traps.
            if trap.to_string().contains("fuel") {
                Err(anyhow::anyhow!("fuel exhausted after {} units", fuel_budget))
            } else {
                Err(trap)
            }
        }
    }
}
```

`store.get_fuel()` after a successful call tells you exactly how much was consumed. This is the basis for accurate billing in function-as-a-service systems: charge the tenant for `fuel_budget - remaining`, not a flat fee.

### Fuel in Python Bindings

The same API is available in `wasmtime-py`:

```python
from wasmtime import Config, Engine, Module, Store, Instance, Linker

config = Config()
config.consume_fuel = True          # opt-in at engine level
engine = Engine(config)
module = Module(engine, open("module.wasm", "rb").read())

store = Store(engine)
store.set_fuel(5_000_000)           # grant 5M fuel units per invocation

linker = Linker(engine)
instance = linker.instantiate(store, module)
run = instance.exports(store)["run"]

try:
    result = run(store)
    remaining = store.get_fuel()
    print(f"consumed {5_000_000 - remaining} fuel units")
except Exception as e:
    if "fuel" in str(e).lower():
        print("execution budget exhausted — module trapped")
    else:
        raise
```

### The `consume_fuel` Host-Side API

For workloads that want to deduct fuel between guest calls (for example, accounting for host-side I/O time as equivalent CPU), `Store::consume_fuel` lets the host manually decrement the counter:

```rust
// Deduct fuel for a host function that does significant work.
// This prevents a module from making arbitrarily many "free" host calls.
store.consume_fuel(500)?;   // deduct 500 units for a host-side DB query
```

This is useful when a module drives expensive host functions in a loop — the per-instruction fuel alone does not capture the total cost if the work happens on the host side of the WASM/host boundary.

## Epoch Interruption: Wall-Clock Deadlines

Fuel is precise but not free. Instrumenting every instruction adds roughly 5–15% overhead to execution throughput, depending on the workload. For latency-sensitive platforms where the concern is bounding maximum invocation duration rather than billing-grade instruction accounting, **epoch interruption** is the more efficient choice.

An epoch is a counter maintained by the `Engine`. The host increments the counter on a timer (typically from a background thread). Each `Store` has a deadline epoch; when the global counter passes the deadline, the runtime traps at the next safe point. The overhead is a single comparison per loop-back edge and function call, not per instruction.

### Enabling Epoch Interruption (Rust)

```rust
use wasmtime::{Config, Engine, Store, Module, Instance};
use std::time::Duration;
use std::sync::Arc;

fn make_epoch_engine() -> Arc<Engine> {
    let mut config = Config::new();
    config.epoch_interruption(true);    // per-safe-point check; low overhead
    Arc::new(Engine::new(&config).expect("engine creation failed"))
}

fn start_epoch_ticker(engine: Arc<Engine>, tick_interval_ms: u64) {
    // One ticker thread per Engine. Not one per Store.
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_millis(tick_interval_ms));
            engine.increment_epoch();
        }
    });
}

fn invoke_with_epoch(
    engine: &Arc<Engine>,
    module: &Module,
    deadline_epochs: u64,   // how many ticks before trap
) -> anyhow::Result<i32> {
    let mut store = Store::new(engine.as_ref(), ());

    // Deadline: trap when the global epoch counter exceeds
    // (current epoch + deadline_epochs).
    store.set_epoch_deadline(deadline_epochs);

    let instance = Instance::new(&mut store, module, &[])?;
    let func = instance.get_typed_func::<(), i32>(&mut store, "run")?;
    Ok(func.call(&mut store, ())?)
}
```

With a 50ms tick interval and `deadline_epochs = 1`, the worst-case execution time is approximately 50–100ms (one full tick after the deadline epoch is set). With `deadline_epochs = 2`, it is 100–150ms. The granularity is one tick interval; choose the interval based on your required precision.

The ticker thread is the single point of failure for epoch-based limits. It must be supervised. A watchdog that detects thread death and restarts the ticker is mandatory in production.

### Epoch vs. Fuel: Choosing the Right Mechanism

| Concern | Use Fuel | Use Epoch |
|---------|----------|-----------|
| Billing by instruction count | Yes | No |
| Hard wall-clock deadline | No | Yes |
| Minimal per-instruction overhead | No | Yes |
| Deterministic across hardware speeds | Yes | No |
| DoS prevention only | Either | Prefer epoch |
| Billing + DoS prevention | Both together | — |

The two mechanisms compose. Enable both in production multi-tenant platforms: fuel for the accounting record, epoch for the hard deadline. Epoch catches the case where a module consumes fuel slowly (a memory-bound or I/O-heavy workload that is nevertheless not trapped by fuel within an acceptable wall-clock duration); fuel catches the case where epoch ticks are late due to a starved ticker thread.

```rust
// Production: both enabled.
config.consume_fuel(true);
config.epoch_interruption(true);

store.set_fuel(50_000_000);      // hard instruction budget
store.set_epoch_deadline(4);     // 4 × 50ms = ~200ms wall-clock max
```

## Calibrating Fuel Budgets

Setting the wrong budget is expensive in both directions. Too low: legitimate workloads trap and fail. Too high: a malicious module consumes significant CPU before the trap fires.

### Benchmarking Typical Workloads

Run your expected workloads with fuel metering enabled and log the consumed fuel for each invocation:

```rust
fn calibrate(engine: &Engine, module: &Module, inputs: &[TestInput]) {
    let oversized_budget = u64::MAX / 2;    // effectively unlimited during calibration
    let mut consumed_samples = Vec::new();

    for input in inputs {
        let mut store = Store::new(engine, ());
        store.set_fuel(oversized_budget).unwrap();

        let instance = Instance::new(&mut store, module, &[]).unwrap();
        let func = instance.get_typed_func::<i32, i32>(&mut store, "process").unwrap();
        let _ = func.call(&mut store, input.value).unwrap();

        let remaining = store.get_fuel().unwrap();
        consumed_samples.push(oversized_budget - remaining);
    }

    let max = consumed_samples.iter().max().copied().unwrap_or(0);
    let p99 = percentile(&consumed_samples, 99);
    println!("p99 fuel consumption: {p99}");
    println!("max fuel consumption: {max}");
    println!("recommended budget (1.5× p99): {}", (p99 as f64 * 1.5) as u64);
}
```

The recommended pattern: measure p99 fuel consumption across a representative input corpus, then set the production budget at 1.5–2× p99. This accommodates legitimate input variation while keeping the maximum CPU time bounded. Use the observed maximum as an alert threshold: an invocation consuming more than the historical maximum is a signal of abnormal input.

### Safety Margin Considerations

- Add at least 20% above your measured p99 before production, to account for future module updates and input space you did not cover in calibration.
- Re-calibrate whenever the module is updated, since instruction counts are tied to the specific compiled module.
- Track per-tenant fuel consumption in a histogram; tenants whose workloads consistently approach the limit warrant individual investigation.

## WasmEdge Fuel Metering: `--gas-limit`

WasmEdge calls the same concept "gas" (following Ethereum's terminology). The `--gas-limit` flag sets the maximum gas units an invocation may consume:

```bash
# Limit execution to 100 million gas units.
wasmedge --gas-limit 100000000 module.wasm

# Combine with memory limit (see below).
wasmedge \
  --gas-limit 100000000 \
  --max-memory-size 33554432 \
  module.wasm
```

When the gas limit is exceeded, WasmEdge terminates the module with exit code 1 and a `Gas limit exceeded` error. The WasmEdge SDK exposes this via the `Statistics` API:

```c
// WasmEdge C API: read gas consumed after execution.
uint64_t gas_consumed = WasmEdge_StatisticsGetTotalCost(stat_ctx);
```

WasmEdge's gas model maps WASM instructions to gas costs defined in a configurable cost table, allowing the platform operator to weight expensive instructions (division, memory operations) higher than cheap ones (local variable access). The default cost table assigns one unit to most instructions.

## Combining with Memory Limits

CPU exhaustion and memory exhaustion are orthogonal denial-of-service vectors that often appear together. A module designed to cause OOM does not need to execute many instructions — it can allocate memory quickly and cheaply. Fuel metering alone does not prevent memory exhaustion.

In Wasmtime, combine fuel with the `ResourceLimiter` API:

```rust
use wasmtime::ResourceLimiter;

struct InvocationLimits {
    max_memory_bytes: usize,
}

impl ResourceLimiter for InvocationLimits {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        Ok(desired <= self.max_memory_bytes)
    }
    fn table_growing(
        &mut self,
        _current: u32,
        desired: u32,
        _maximum: Option<u32>,
    ) -> anyhow::Result<bool> {
        Ok(desired <= 65_536)   // cap table elements
    }
    fn instances(&self) -> usize { 1 }
    fn tables(&self) -> usize { 4 }
    fn memories(&self) -> usize { 1 }
}

let mut store = Store::new(&engine, InvocationLimits {
    max_memory_bytes: 32 * 1024 * 1024,    // 32 MiB
});
store.limiter(|state| state);
store.set_fuel(20_000_000)?;
store.set_epoch_deadline(2)?;
```

For WasmEdge, use `--max-memory-size` alongside `--gas-limit`:

```bash
wasmedge \
  --gas-limit 50000000 \
  --max-memory-size 33554432 \    # 32 MiB in bytes
  module.wasm
```

The two limits are independent. A module that allocates quickly and cheaply hits the memory limit before fuel is exhausted. A module that computes intensively without allocating hits the fuel limit. Both must be set.

## Per-Tenant Fuel Budgets in Multi-Tenant Systems

In a platform where multiple tenants share a runtime, flat per-call fuel limits are a necessary but not sufficient fairness mechanism. A greedy tenant can submit many concurrent calls, each within the per-call budget, and collectively exhaust the platform's CPU.

Per-tenant fuel budgets add a second layer: a sliding-window aggregate that caps total fuel consumption across all of a tenant's in-flight invocations.

```rust
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct TenantBudget {
    remaining_fuel: AtomicU64,
    window_start: std::sync::Mutex<Instant>,
    window_grant: u64,          // fuel units per window
    window_duration: Duration,
}

impl TenantBudget {
    fn new(fuel_per_minute: u64) -> Arc<Self> {
        Arc::new(Self {
            remaining_fuel: AtomicU64::new(fuel_per_minute),
            window_start: std::sync::Mutex::new(Instant::now()),
            window_grant: fuel_per_minute,
            window_duration: Duration::from_secs(60),
        })
    }

    /// Try to reserve `amount` fuel for an upcoming invocation.
    /// Returns Ok(()) if the reservation succeeds, Err if the tenant is over budget.
    fn reserve(&self, amount: u64) -> Result<(), &'static str> {
        // Refill the window if it has expired.
        {
            let mut start = self.window_start.lock().unwrap();
            if start.elapsed() >= self.window_duration {
                *start = Instant::now();
                self.remaining_fuel.store(self.window_grant, Ordering::Relaxed);
            }
        }

        // Atomically decrement. If it would go below zero, reject.
        loop {
            let current = self.remaining_fuel.load(Ordering::Relaxed);
            if current < amount {
                return Err("tenant fuel budget exhausted for this window");
            }
            if self.remaining_fuel
                .compare_exchange(current, current - amount, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(());
            }
        }
    }

    /// Return unconsumed fuel after an invocation completes.
    fn refund(&self, unconsumed: u64) {
        self.remaining_fuel.fetch_add(unconsumed, Ordering::Relaxed);
    }
}

fn invoke_for_tenant(
    engine: &Engine,
    module: &Module,
    tenant: &Arc<TenantBudget>,
    per_call_max: u64,
) -> anyhow::Result<i32> {
    // Reserve the maximum this call could consume before executing.
    tenant.reserve(per_call_max)
        .map_err(|e| anyhow::anyhow!(e))?;

    let mut store = Store::new(engine, ());
    store.set_fuel(per_call_max)?;

    let instance = Instance::new(&mut store, module, &[])?;
    let func = instance.get_typed_func::<(), i32>(&mut store, "run")?;
    let result = func.call(&mut store, ())?;

    // Refund what was not actually consumed.
    let remaining = store.get_fuel().unwrap_or(0);
    tenant.refund(remaining);

    Ok(result)
}
```

This pattern ensures that a tenant who submits 1,000 concurrent calls does not get 1,000 times the intended CPU budget. The per-window refund on completion means well-behaved short-lived calls do not drain the budget unnecessarily.

## Fuel as a Billing Primitive

In function-as-a-service platforms, per-invocation instruction counts are a more accurate billing signal than wall-clock duration, which is affected by hardware speed, concurrent load, and scheduling jitter. Fuel gives you a runtime-level instruction count that is deterministic for a given module and input — the same module with the same input always consumes the same fuel, regardless of the host machine.

Billing by fuel:

```rust
struct InvocationRecord {
    tenant_id: String,
    module_id: String,
    fuel_consumed: u64,
    wall_clock_ms: u64,
    trapped: bool,
    trap_reason: Option<String>,
}

fn invoke_and_record(
    engine: &Engine,
    module: &Module,
    tenant_id: &str,
    module_id: &str,
    fuel_budget: u64,
) -> InvocationRecord {
    let start = std::time::Instant::now();
    let mut store = Store::new(engine, ());
    store.set_fuel(fuel_budget).unwrap();

    let (trapped, trap_reason) = match Instance::new(&mut store, module, &[])
        .and_then(|i| {
            let f = i.get_typed_func::<(), i32>(&mut store, "run")?;
            f.call(&mut store, ())
        }) {
        Ok(_) => (false, None),
        Err(e) => (true, Some(e.to_string())),
    };

    let remaining = store.get_fuel().unwrap_or(0);
    InvocationRecord {
        tenant_id: tenant_id.to_string(),
        module_id: module_id.to_string(),
        fuel_consumed: fuel_budget.saturating_sub(remaining),
        wall_clock_ms: start.elapsed().as_millis() as u64,
        trapped,
        trap_reason,
    }
}
```

Bill on `fuel_consumed`, not on `wall_clock_ms`. This prevents a tenant from gaming the billing system by choosing a deliberately slow host or submitting during high-contention periods to get more wall-clock time per billing unit. Fuel is also fair across tenants sharing the same host: a tenant running a CPU-bound workload pays proportionally more than one running a memory-bound workload at the same wall-clock duration.

## Expected Behaviour

| Scenario | Without limits | With fuel + epoch |
|----------|---------------|-------------------|
| `loop {}` in a module | Host thread blocked indefinitely | Trap within one epoch tick (~50ms) |
| Exponential recursion on crafted input | Execution time unbounded | Trap when fuel exhausted (deterministic instruction count) |
| Module allocates 2 GB | Succeeds if host has memory | Trap at memory limit (ResourceLimiter) |
| Greedy tenant submits 1,000 concurrent calls | All execute; other tenants starved | Per-tenant budget depleted; excess invocations rejected |
| FaaS billing | Flat fee or wall-clock time | Exact instruction count per invocation |
| Ticker thread dies | — | Modules run past epoch deadline; no CPU guard |

Verification:

```bash
# Confirm fuel trap fires.
cat > /tmp/loop.wat <<'EOF'
(module (func (export "run") (result i32)
  (loop $l (br $l))
  (i32.const 0)))
EOF

# WasmEdge: should trap with gas limit exceeded.
wasmedge --gas-limit 1000000 /tmp/loop.wat
# Expected: exits non-zero with "Gas limit exceeded"

# Confirm epoch trap fires for Wasmtime (using wasmtime CLI).
wasmtime run --epoch-interruption --max-epoch-ticks 2 /tmp/loop.wasm
# Expected: trap "wasm trap: interrupt"
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Fuel metering | Deterministic CPU accounting; billing-grade precision | 5–15% per-instruction overhead | Use epoch interruption for pure DoS prevention; reserve fuel for workloads that need accounting. |
| Epoch interruption | Low overhead; hard wall-clock bound | Granularity = tick interval; ticker thread is a SPOF | Supervise ticker thread with a watchdog; alert on unexpected drops in `epoch_deadline_trap` rate. |
| Per-tenant aggregate budgets | Prevents greedy-tenant amplification | Refund logic adds coordination overhead per call | Use lock-free atomic accounting; batch refunds for high-frequency workloads. |
| Fuel as billing | Fair, deterministic | Budget recalibration needed on each module update | Automate calibration in CI; store fuel profiles per module version. |
| Memory + fuel combined | Complete resource envelope | Two separate configuration surfaces to maintain | Encapsulate both in a shared `InvocationPolicy` struct; validate policy at startup. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Ticker thread dies | Modules run past epoch deadline indefinitely | `epoch_deadline_trap` counter flat while active invocations continue | Supervise with watchdog; restart ticker; alert on counter stall. |
| Fuel budget too low | Legitimate workloads trap with `fuel_exhausted`; high failure rate | Spike in `fuel_exhausted` traps; no change in module behaviour | Increase budget; re-run calibration against current input corpus. |
| Budget not set (forgot `set_fuel`) | Module executes without limit | No fuel traps ever; impossible to distinguish from long-lived legitimate calls | Assert in integration tests that a known-infinite module traps within N ms. |
| Per-tenant refund bug | Tenants accumulate fuel debt; legitimate calls rejected | Tenant quota exhausted after normal load | Add invariant checks on refund; verify remaining ≤ per_call_max before refunding. |
| Epoch tick too coarse | Short malicious bursts complete before first tick | Wall-clock between invocation start and trap exceeds SLO | Reduce tick interval; set `deadline_epochs = 1`; tune to your latency SLO. |
| WasmEdge `--gas-limit` missing from wrapper script | Deployments go out without gas limits | Canary analysis; missing `Gas limit exceeded` events for test module | Encode `--gas-limit` in a validated wrapper function; lint CLI invocations in CI. |

## Related Articles

- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [WASM Multi-Tenancy Patterns](/articles/wasm/wasm-multi-tenancy/)
- [WasmEdge Security](/articles/wasm/wasmedge-security/)
- [Wasmtime Async DoS Security](/articles/wasm/wasmtime-async-dos-security/)
- [WASM Linear Memory Safety](/articles/wasm/wasm-linear-memory-safety/)
- [WASI Preview 2 Capability-Based Security](/articles/wasm/wasi-preview-2-capabilities/)
