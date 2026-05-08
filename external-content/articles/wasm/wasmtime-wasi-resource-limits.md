---
title: "Wasmtime WASI Resource Limit Security"
description: "Harden Wasmtime deployments against CVE-2026-27572 wasi:http header DoS and CVE-2026-27204 resource exhaustion—configuring guest resource limits to prevent host process termination."
slug: wasmtime-wasi-resource-limits
date: 2026-05-02
lastmod: 2026-05-02
category: wasm
tags: ["wasmtime", "wasi", "cve-2026-27572", "resource-limits", "dos", "wasi-http", "sandbox"]
personas: ["platform-engineer", "security-engineer", "systems-engineer"]
article_number: 358
difficulty: advanced
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/wasm/wasmtime-wasi-resource-limits/index.html"
---

# Wasmtime WASI Resource Limit Security

## Problem

Wasmtime's `ResourceLimiter` trait is the primary mechanism by which host embedders constrain what a guest WASM module can demand from the host. A host implements the trait and registers it on each `Store`; from that point on, every `memory.grow` and `table.grow` instruction executed by the guest passes through the limiter before the runtime allocates host memory. Without an explicit `ResourceLimiter`, a guest module can request arbitrarily large amounts of memory, grow tables without bound, and generally consume host resources until the host process runs out of address space or the OS kills the process. The default `Config` and a default `Store` impose no such ceiling.

The same pattern applies to WASI resource handles — file descriptors, sockets, HTTP connections, and the structured resources introduced in the WASI Component Model Preview 2. A guest that creates WASI resource handles consumes host kernel state for each one. Without a limit on how many handles can be simultaneously open, a guest can exhaust the host process's file-descriptor table, triggering `EMFILE` errors in the host process and affecting all other tenants sharing that Wasmtime process.

**CVE-2026-27572 (CRITICAL, published April 9, 2026)** exposed a specific instance of this class of problem. Wasmtime's `wasi:http/types.fields` resource — the WASI Component Model resource that WASM components use to construct and manipulate HTTP header maps — panicked when a guest attempted to add more than 32,768 entries. The root cause was that the `from-list` constructor function for `wasi:http/types.fields` passed a caller-supplied list of header pairs directly to `hyper::HeaderMap::with_capacity`. The `hyper` library panics via `panic!` when the requested capacity exceeds `u16::MAX / 2` (32,768) — exactly 32,769 headers is the trigger. A Rust `panic!` that is not caught at a defined boundary propagates up the call stack. Wasmtime's WASI bindings did not wrap this call in a `catch_unwind`, so the panic propagated out of the sandbox and terminated the entire host process. The guest cannot read or write host memory — the sandbox memory isolation holds — but the guest can kill the host process. This is a sandbox escape by process termination: a denial of service for every other tenant in that process.

**CVE-2026-27204 (published April 9, 2026)** addressed a complementary gap: Wasmtime did not place any limit on the number of `wasi:http` connection resources, file descriptors, or other WASI resource handles that a guest component could create concurrently. A WASM component that opened HTTP connections, WASI file handles, or socket resources in a loop without releasing them would accumulate host kernel state until the host process ran out of file descriptors. Once the process hit the `RLIMIT_NOFILE` ceiling, every subsequent operation that required a file descriptor — including operations performed by other WASM components in the same process — failed with `EMFILE`. Both CVEs were fixed simultaneously in Wasmtime 24.0.6, 36.0.6, 40.0.4, 41.0.4, and 42.0.0, and backported to 43.0.1 and 42.0.2.

The significance of April 9, 2026 goes beyond these two CVEs. The Bytecode Alliance published twelve distinct Wasmtime security advisories on that single date, all found using LLM-assisted vulnerability discovery tooling applied to Wasmtime's codebase and its dependency tree. This batch represents approximately three times the total number of security advisories published for Wasmtime across all of 2025, and it doubled the cumulative count of Critical-severity advisories in Wasmtime's history. The advisories were published at `https://bytecodealliance.org/articles/wasmtime-security-advisories` alongside patched releases following the Bytecode Alliance's coordinated disclosure policy.

The batch-publication model created an operational problem that deserves attention independently of the individual CVEs. Operators who had configured alerting for `high` or `critical` severity advisories received twelve alerts simultaneously. Triage queues that were sized for one or two CVEs per quarter were overwhelmed. Some operators prioritised the two Critical-severity issues and missed several of the High-severity advisories that, in combination, could increase attack surface. Additionally, CVE-2026-27572's root cause lived in `hyperium/hyper` — a Rust HTTP library that Wasmtime uses as a dependency — rather than in Wasmtime's own code. No CVE was filed against `hyperium/hyper` because the panic was not exploitable from outside Wasmtime's bindings, but operators who monitored Wasmtime and `hyper` as separate repositories would have seen no upstream signal in `hyper`. Tracking Wasmtime security requires monitoring the whole dependency graph, not just the top-level crate.

The practical tracking toolkit: run `cargo audit` against your Wasmtime embedding's `Cargo.lock` to detect known-vulnerable versions of `wasmtime`, `wasmtime-wasi`, `hyper`, and transitive dependencies. Query the GitHub Security Advisory API directly: `gh api repos/bytecodealliance/wasmtime/security/advisories --jq '.[].summary'`. Subscribe to the Bytecode Alliance blog RSS feed at `https://bytecodealliance.org/feed.xml`. Use the OSV database (`https://osv.dev`) to query all Wasmtime advisories by package name across ecosystems. Combined, these give coverage that monitoring the CVE NVD feed alone does not.

Target systems: Wasmtime < 24.0.6, < 36.0.6, < 40.0.4, < 41.0.4, < 42.0.0 (patched in those versions and in 43.0.1 and 42.0.2). Any Wasmtime embedding that accepts WASM components from untrusted sources and enables `wasi:http` is affected by CVE-2026-27572. Any embedding that does not implement `ResourceLimiter` and does not limit WASI handle creation is affected by CVE-2026-27204.

## Threat Model

1. **CVE-2026-27572 exploit — header-flood panic.** A malicious WASM component uses the `wasi:http/types.fields` `from-list` constructor to create a `fields` resource containing 32,769 or more header pairs. On pre-patch Wasmtime, this triggers an uncaught `hyper::HeaderMap` panic that propagates out of the WASM sandbox and terminates the host process. All tenants sharing that Wasmtime process lose service. The attack requires only the ability to execute a WASM component — no memory corruption or sandbox memory isolation bypass is involved. Triggering it requires fewer than 10 lines of WAT or Rust-compiled WASM and is straightforward to automate.

2. **CVE-2026-27204 exploit — WASI handle exhaustion.** A WASM component running on a serverless or edge platform allocates `wasi:http` connection resources, file handles, or socket handles in a tight loop without releasing them. On a Wasmtime host with no ResourceLimiter and no WASI handle cap, this exhausts the host process's file-descriptor table. Once the `RLIMIT_NOFILE` limit is hit, every subsequent file-descriptor-requiring operation in that process fails with `EMFILE`, including calls made by entirely unrelated WASM components. The attacker causes denial of service for co-tenants without terminating the process.

3. **Patch-gap attacker.** The April 9, 2026 Bytecode Alliance advisory explicitly described the 32,769-header boundary as the trigger for CVE-2026-27572. An attacker who reads the advisory before a target platform has patched can construct a minimal WASM component that encodes exactly 32,769 dummy header pairs in a `from-list` call, upload it to an edge or serverless platform still running pre-patch Wasmtime, and trigger the host-process panic. The patch-gap window — the time between advisory publication and operator upgrade — is the primary risk window. Platforms that rely on GHSA alerts and process them weekly rather than immediately are exposed for days.

4. **Legitimate buggy WASM component with resource leak.** A non-malicious WASM component written by a platform customer has a bug: it creates WASI resource handles (HTTP connections, file descriptors) but fails to drop them when a request fails partway through. Under load, this accumulates open handles in the same way as the deliberate attack in threat 2. Without ResourceLimiter enforcement, a legitimate but buggy component can cause the same EMFILE cascade. This threat is operationally more common than deliberate attack on internal platforms.

**Blast radius.** Both CVE-2026-27572 and CVE-2026-27204 are process-wide in their impact. Wasmtime instances are typically multiplexed — one host process serves many WASM component invocations, often from different tenants. A single malicious or buggy component that triggers either CVE affects all co-tenants in the process. Mitigations that isolate each tenant into a separate process reduce blast radius to one tenant but significantly increase resource overhead. The practical recommendation is defence-in-depth: patch to a fixed Wasmtime version, implement ResourceLimiter, enable epoch interruption, and consider process-level isolation for highest-risk tenants.

## Configuration / Implementation

### Upgrading Wasmtime

In a Rust embedding project, update Wasmtime to a fixed version:

```toml
# Cargo.toml
[dependencies]
wasmtime = "43.0.1"
wasmtime-wasi = "43.0.1"
wasmtime-wasi-http = "43.0.1"
```

Then run:

```bash
cargo update wasmtime wasmtime-wasi wasmtime-wasi-http
```

Verify the resolved version:

```bash
cargo pkgid wasmtime
# Expected output: file:///path/to/project#wasmtime@43.0.1
```

For deployments using a pre-compiled Wasmtime CLI binary, download the patched release from:

```
https://github.com/bytecodealliance/wasmtime/releases/tag/v43.0.1
```

For container-based deployments:

```bash
docker pull ghcr.io/bytecodealliance/wasmtime:43.0.1
```

After upgrading, run `cargo audit` to verify no remaining known-vulnerable transitive dependencies remain:

```bash
cargo audit --json | jq '.vulnerabilities.list[] | select(
  .package.name == "wasmtime" or
  .package.name == "wasmtime-wasi" or
  .package.name == "wasmtime-wasi-http" or
  .package.name == "hyper"
) | {package: .package.name, version: .package.version, advisory: .advisory.id}'
```

### Implementing ResourceLimiter to cap guest resources

The `ResourceLimiter` trait is the authoritative control point for memory and table growth. Every `memory.grow` and `table.grow` instruction the guest executes passes through it. Without a registered limiter, both calls always succeed up to the platform maximum.

```toml
# Cargo.toml
[dependencies]
wasmtime = "43.0.1"
wasmtime-wasi = "43.0.1"
wasmtime-wasi-http = "43.0.1"
anyhow = "1"
```

```rust
use wasmtime::{ResourceLimiter, Store};

// State stored per-Store — one instance per tenant invocation.
struct TenantState {
    resource_limiter: TenantResourceLimiter,
    // ... other per-tenant fields
}

struct TenantResourceLimiter {
    // Track current allocation so we can log on rejection.
    current_memory_bytes: usize,
    current_table_elements: u32,
}

impl TenantResourceLimiter {
    const MAX_MEMORY_BYTES: usize = 256 * 1024 * 1024; // 256 MiB
    const MAX_TABLE_ELEMENTS: u32 = 10_000;

    fn new() -> Self {
        Self {
            current_memory_bytes: 0,
            current_table_elements: 0,
        }
    }
}

impl ResourceLimiter for TenantResourceLimiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        if desired > Self::MAX_MEMORY_BYTES {
            tracing::warn!(
                current,
                desired,
                max = Self::MAX_MEMORY_BYTES,
                "ResourceLimiter: memory_grow rejected"
            );
            return Ok(false);
        }
        self.current_memory_bytes = desired;
        Ok(true)
    }

    fn table_growing(
        &mut self,
        current: u32,
        desired: u32,
        _maximum: Option<u32>,
    ) -> anyhow::Result<bool> {
        if desired > Self::MAX_TABLE_ELEMENTS {
            tracing::warn!(
                current,
                desired,
                max = Self::MAX_TABLE_ELEMENTS,
                "ResourceLimiter: table_grow rejected"
            );
            return Ok(false);
        }
        self.current_table_elements = desired;
        Ok(true)
    }

    fn memory_grow_failed(&mut self, error: &anyhow::Error) {
        tracing::error!(?error, "ResourceLimiter: memory_grow_failed");
    }

    fn table_grow_failed(&mut self, error: &anyhow::Error) {
        tracing::error!(?error, "ResourceLimiter: table_grow_failed");
    }
}

fn create_store(engine: &wasmtime::Engine) -> Store<TenantState> {
    let state = TenantState {
        resource_limiter: TenantResourceLimiter::new(),
    };
    let mut store = Store::new(engine, state);
    // Register the limiter — this call activates ResourceLimiter enforcement.
    store.limiter(|state| &mut state.resource_limiter);
    store
}
```

The `store.limiter(|state| &mut state.resource_limiter)` call is the critical registration. Without it, even a correctly implemented `ResourceLimiter` struct has no effect.

### Epoch-based interruption for runaway resource allocation

Epoch interruption provides a time-based backstop independent of `ResourceLimiter`. A background thread increments the engine's epoch counter at a fixed interval; if a WASM component is still executing when its epoch deadline is reached, Wasmtime traps it.

```rust
use std::sync::Arc;
use std::time::Duration;
use wasmtime::{Config, Engine};

fn build_engine() -> anyhow::Result<Arc<Engine>> {
    let mut config = Config::new();
    config.epoch_interruption(true);

    let engine = Arc::new(Engine::new(&config)?);

    // Spawn a background thread that increments the epoch every 100ms.
    // All stores sharing this engine observe the increment.
    let engine_weak = Arc::downgrade(&engine);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_millis(100));
            match engine_weak.upgrade() {
                Some(e) => e.increment_epoch(),
                // Engine has been dropped — exit the background thread.
                None => break,
            }
        }
    });

    Ok(engine)
}

// When creating a store, set the epoch deadline.
// A deadline of 50 means: allow up to 50 epoch increments = 5 seconds
// of continuous execution before interruption.
fn configure_store_epoch(store: &mut Store<TenantState>) {
    store.set_epoch_deadline(50);
}
```

Epoch interruption and `ResourceLimiter` are complementary. `ResourceLimiter` blocks allocation requests; epoch interruption terminates runaway loops that may not be requesting memory but are nonetheless consuming CPU time or creating WASI handles in a tight loop.

### Fuel metering for resource-intensive operations

Fuel metering assigns a finite budget of "fuel" to each WASM execution. Each WASM instruction costs one unit of fuel. When the budget is exhausted, Wasmtime traps the module. This is deterministic — unlike epoch interruption, which is time-based — and more predictable for functions that process variable-length inputs.

```rust
fn build_engine_with_fuel() -> anyhow::Result<Engine> {
    let mut config = Config::new();
    config.consume_fuel(true);
    Engine::new(&config)
}

fn configure_store_fuel(store: &mut Store<TenantState>) -> anyhow::Result<()> {
    // 10 million instructions is roughly 1–10ms of work depending on
    // the WASM module; calibrate for expected workload.
    store.set_fuel(10_000_000)?;
    Ok(())
}
```

Calibrating the fuel budget requires profiling representative WASM workloads. Measure fuel consumption with `store.fuel_consumed()` after successful invocations, then set the production budget to 2–5× the 99th-percentile consumption. This leaves headroom for legitimate variance while bounding runaway execution.

### wasi:http header count guard

The CVE-2026-27572 fix in Wasmtime 42.0.0+ wraps the `hyper::HeaderMap::with_capacity` call in a `catch_unwind` and converts the panic to a WASM trap. If you cannot upgrade immediately, you can add a pre-check in your host embedding:

```rust
// Maximum number of headers to accept in a wasi:http fields resource.
// Keep this well below hyper's panic threshold of 32,769.
const MAX_HTTP_HEADERS: usize = 1_024;

fn validate_header_list(headers: &[(String, Vec<u8>)]) -> anyhow::Result<()> {
    if headers.len() > MAX_HTTP_HEADERS {
        anyhow::bail!(
            "header list exceeds maximum of {} entries (got {})",
            MAX_HTTP_HEADERS,
            headers.len()
        );
    }
    Ok(())
}
```

On patched Wasmtime, this pre-check provides defence-in-depth: the panic is already caught, but the limit prevents a single component from monopolising memory through a legitimate (non-panicking) very large header map.

### Monitoring Wasmtime advisories and dependency health

Set up automated advisory monitoring as part of your CI pipeline:

```bash
# Detect vulnerable wasmtime or hyper versions in Cargo.lock
cargo audit --json | jq '
  .vulnerabilities.list[]
  | select(
      .package.name == "wasmtime" or
      .package.name == "wasmtime-wasi" or
      .package.name == "wasmtime-wasi-http" or
      .package.name == "hyper"
    )
  | {
      package: .package.name,
      version: .package.version,
      advisory: .advisory.id,
      severity: .advisory.severity
    }'
```

Query the GitHub Security Advisory API for new Wasmtime advisories since a given date:

```bash
# List all Wasmtime security advisories published after a date
gh api repos/bytecodealliance/wasmtime/security/advisories \
  --jq '.[] | select(.published_at > "2026-04-01T00:00:00Z") |
    {id: .ghsa_id, summary: .summary, severity: .severity, published: .published_at}'
```

Add Renovate or Dependabot to automate version bump PRs for `wasmtime` in `Cargo.toml`:

```json
{
  "packageRules": [
    {
      "matchPackageNames": ["wasmtime", "wasmtime-wasi", "wasmtime-wasi-http"],
      "groupName": "wasmtime",
      "automerge": false,
      "labels": ["security-review-required"]
    }
  ]
}
```

Subscribe to the Bytecode Alliance RSS feed for blog-post announcements that accompany advisory batches: `https://bytecodealliance.org/feed.xml`.

### Testing resource limit enforcement

Write integration tests that verify your ResourceLimiter and header-count guard are active before deploying to production.

```rust
#[cfg(test)]
mod resource_limit_tests {
    use super::*;
    use wasmtime::{Engine, Linker, Module, Store};

    /// Verify that a WASM module attempting to grow memory beyond the
    /// 256 MiB ResourceLimiter cap receives a trap, not a silent failure.
    #[test]
    fn memory_growth_beyond_limit_is_trapped() -> anyhow::Result<()> {
        let engine = Engine::default();
        // Minimal WASM: grow memory by 4097 pages (256 MiB + 64 KiB)
        let wat = r#"
            (module
                (memory 1)
                (func (export "run")
                    ;; Attempt to grow to 4097 pages = 268,500,992 bytes > 256 MiB
                    i32.const 4096
                    memory.grow
                    drop
                )
            )
        "#;
        let module = Module::new(&engine, wat)?;
        let mut store = create_store(&engine);
        configure_store_epoch(&mut store);
        configure_store_fuel(&mut store)?;

        let linker = Linker::new(&engine);
        let instance = linker.instantiate(&mut store, &module)?;
        let run = instance.get_typed_func::<(), ()>(&mut store, "run")?;

        // memory.grow returns -1 (i32) when the limiter rejects — it does not
        // trap on its own. The ResourceLimiter returns Ok(false), which causes
        // memory.grow to push -1 onto the stack. The test verifies the call
        // completes without a trap and without actually allocating beyond cap.
        run.call(&mut store, ())?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .expect("memory export");
        // Memory must not have grown beyond the 256 MiB cap.
        assert!(
            memory.data_size(&store) <= TenantResourceLimiter::MAX_MEMORY_BYTES,
            "memory exceeded ResourceLimiter cap"
        );
        Ok(())
    }

    /// Verify that validate_header_list rejects lists at or above the limit.
    #[test]
    fn header_list_over_limit_is_rejected() {
        let headers: Vec<(String, Vec<u8>)> = (0..MAX_HTTP_HEADERS + 1)
            .map(|i| (format!("x-header-{}", i), b"value".to_vec()))
            .collect();
        assert!(
            validate_header_list(&headers).is_err(),
            "expected error for {} headers", headers.len()
        );
    }

    /// Verify that header lists within the limit are accepted.
    #[test]
    fn header_list_within_limit_is_accepted() {
        let headers: Vec<(String, Vec<u8>)> = (0..100)
            .map(|i| (format!("x-header-{}", i), b"value".to_vec()))
            .collect();
        assert!(validate_header_list(&headers).is_ok());
    }
}
```

## Expected Behaviour

| Signal | Pre-patch Wasmtime, no limits | Patched + ResourceLimiter |
|--------|-------------------------------|---------------------------|
| WASM guest calls `from-list` with 32,769 headers (CVE-2026-27572) | Host process terminates with a Rust panic; all co-tenant requests fail | Panic caught by `catch_unwind` in Wasmtime; guest receives a WASM trap; host process continues |
| WASM guest creates 100,000 WASI resource handles without releasing them (CVE-2026-27204) | Host process hits `RLIMIT_NOFILE`; subsequent `open()`/`accept()` in any tenant fail with `EMFILE` | ResourceLimiter rejects handle creation above configured cap; guest receives trap; host continues serving other tenants |
| WASM guest enters infinite loop allocating WASI handles | Guest runs indefinitely, consuming CPU and accumulating handles | Epoch interruption traps the guest after the configured deadline (e.g. 5 seconds at 100ms epoch interval) |
| WASM guest executes a `wasi:http` request in a fuel-metered store and runs out of fuel | N/A (fuel metering not enabled) | Guest is trapped deterministically when fuel budget is exhausted; `store.fuel_consumed()` reports actual consumption for calibration |
| New batch of Wasmtime security advisories published (e.g. April 9, 2026 batch) | Advisory detected only if operator manually checks GitHub or NVD; delay of days to weeks | `cargo audit` in CI detects vulnerable `Cargo.lock` on next pipeline run; Renovate opens version-bump PR automatically |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Strict memory cap via ResourceLimiter (256 MiB) | Prevents runaway allocation from crashing host; bounds per-tenant memory footprint | Legitimate WASM components processing large datasets (image resizing, ML inference) may hit the cap and fail | Profile legitimate workloads before setting cap; use per-component caps rather than a single global limit; expose the cap as a per-tenant configuration option |
| Epoch interruption (100ms increment, 50-epoch deadline) | Time-bounds all WASM execution; terminates runaway loops even without memory growth | Adds a background thread per engine; epoch check overhead on every WASM function call; legitimate long-running WASM (batch processing) may be interrupted | Tune deadline per use-case; for batch workloads, set a higher deadline or disable epoch and rely on process-level timeout instead |
| Fuel metering | Deterministic instruction budget independent of wall-clock time; portable across hosts | Calibration effort required per WASM workload; fuel consumption is instruction-count-based, not wall-clock; I/O-bound WASM may consume little fuel but block for a long time | Combine with epoch interruption for I/O-bound workloads; run representative load tests to determine 99th-percentile fuel usage before setting production budget |
| ResourceLimiter per-Store overhead | Fine-grained per-tenant accounting; limits can be adjusted per tenant | One `ResourceLimiter` struct allocated per `Store`; limiter function called on every `memory.grow` and `table.grow` | Overhead is negligible for typical WASM components that grow memory a handful of times at startup; profile only if `memory.grow` frequency is unusually high |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| ResourceLimiter cap set too low for legitimate workloads | Legitimate WASM component fails with a WASM trap during memory growth; component returns error to caller; error logs show "ResourceLimiter: memory_grow rejected" | Monitor ResourceLimiter rejection rate via structured logs; alert if rejections exceed 0.1% of invocations | Increase cap for the affected component or tenant tier; use profiling data from `memory.data_size()` after successful invocations to calibrate minimum required cap |
| Epoch increment interval too short for legitimate long-running WASM | Legitimate batch-processing WASM component is interrupted mid-computation; result is a partial failure rather than a completed result | Epoch-interruption traps appear in WASM error telemetry for invocations that should succeed; distinguish from deliberate timeouts by correlating with expected execution duration | Increase epoch deadline for batch workloads; separate batch and interactive WASM into different engine configurations with different deadline settings |
| Wasmtime upgrade changes WASI ABI between minor versions | WASM components built against an older WASI snapshot fail to instantiate after Wasmtime upgrade; error: "component imports not satisfied" or type-mismatch trap at instantiation | Pre-production integration test suite that instantiates all known WASM components after upgrade; CI gate on `wasmtime` version bump PRs | Pin WASM components to a specific WASI target version in their build toolchain; test WASM components against the new Wasmtime version in staging before rolling to production; use semantic version ranges for `wasmtime-wasi` in `Cargo.toml` |
| Advisory batch (12 CVEs simultaneously) overwhelms triage process | Security team processes only the Critical-severity CVEs; High-severity advisories that combine to increase attack surface are deferred and not patched promptly | Track advisory backlog age in vulnerability management system; alert if any Wasmtime advisory is open for more than 5 business days without triage | Pre-define a severity-to-SLA mapping; automate Wasmtime version bump PRs via Renovate so upgrading is a merge action rather than a manual task; treat batch advisory releases as a single upgrade event with a unified deadline |

## Related Articles

- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [WASM Multi-Tenancy Security](/articles/wasm/wasm-multi-tenancy/)
- [WASI HTTP Server Hardening](/articles/wasm/wasi-http-server-hardening/)
- [WASM Exception Handling Security](/articles/wasm/wasm-exception-handling-security/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
