---
title: "WASM Runtime Security Instrumentation: Monitoring Host Calls and Execution Behaviour"
description: "eBPF and Falco are blind inside WASM sandboxes — security visibility requires WASM-level instrumentation. This guide covers Wasmtime linker-based host function wrapping, component-model monitoring components, OpenTelemetry from WASM, and detecting anomalous execution patterns through instrumented runtimes."
slug: wasm-runtime-instrumentation
date: 2026-05-07
lastmod: 2026-05-07
category: wasm
tags:
  - wasm
  - instrumentation
  - security-monitoring
  - tracing
  - runtime-security
personas:
  - security-engineer
  - platform-engineer
article_number: 579
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/wasm/wasm-runtime-instrumentation/
---

# Instrumenting WASM Runtimes for Security Monitoring and Tracing

## Problem

WebAssembly's sandbox is its core security property: modules run in an isolated linear memory space, cannot make arbitrary syscalls, and can only reach the host through explicit imports. That same sandbox is a visibility gap for conventional security tooling.

eBPF probes and Falco rules operate on Linux syscalls. When a WASM module calls `wasi:filesystem/read`, what Linux sees is a single `read(2)` originating from the runtime process — `wasmtime`, `wasmer`, a browser engine, or a Kubernetes sidecar. There is no per-module attribution, no path, no calling module identity, and no call graph. A malicious module can make tens of thousands of host function calls without triggering any Falco rule, because every syscall looks identical to a legitimate one at the kernel level.

The specific gaps:

- **No per-module syscall attribution.** All modules in a Wasmtime process share one Linux PID. `strace` and eBPF probes see runtime process activity, not per-tenant module activity.
- **No host function call log.** When a module calls a custom host import — say `db_query(sql_ptr, sql_len)` — neither seccomp nor eBPF surfaces it. Only the runtime knows.
- **No memory access pattern visibility.** A module that reads another module's memory region (in a multi-module embedding or via shared memory) is invisible to the kernel until an OOM or segfault occurs.
- **No call graph for tracing.** Distributed tracing assumes span context flows through function calls. When execution enters a WASM module, the trace context usually disappears unless the module explicitly propagates it.
- **No anomaly baseline.** Without a record of what a module normally calls, there is no baseline against which to detect unusual behaviour at invocation time.

Addressing these gaps requires instrumentation at the WASM runtime level — not the kernel level. This article covers the main mechanisms: Wasmtime linker-based host function wrapping, the component model's composition-as-instrumentation pattern, binary-level trace point injection, OpenTelemetry span export from inside WASM, eBPF probes targeting the runtime process for WASM-level context extraction, and building a structured security event log.

**Target systems:** Wasmtime 22+, WASM Component Model (wasi:logging, wasm-tracing), OpenTelemetry 1.x. Code examples are in Rust for the host side and Rust/WAT for the module side.

## Threat Model

- **Adversary 1 — Silent data exfiltration:** a module that calls permitted host functions (HTTP, database, filesystem) with attacker-controlled arguments to exfiltrate data, bypassing DLP rules that operate at the kernel layer.
- **Adversary 2 — Lateral movement via confused deputy:** a module that abuses a high-privilege host import by crafting arguments that cause the host to act on behalf of the module in unintended ways — SQL injection, SSRF via a host HTTP function, or path traversal via a file-read import.
- **Adversary 3 — Resource exhaustion via excessive calls:** a module that makes high-frequency calls to expensive host functions (cryptographic operations, database queries) to degrade service for other tenants.
- **Adversary 4 — Compromised module in supply chain:** a previously-trusted module now contains injected code that calls legitimate host functions with malicious arguments — indistinguishable at the syscall level from normal operation.
- **Access level:** Module-code execution within the runtime sandbox. Adversaries cannot write arbitrary memory outside the module's linear memory unless a runtime vulnerability exists.
- **Objective of instrumentation:** Produce a per-module record of every host function call (name, arguments, return value, timestamp, call count), detect deviations from known-good call patterns, and export trace context that allows cross-service correlation.

## Instrumentation Methods

### Method 1: Linker-Based Host Function Wrapping (Wasmtime)

Wasmtime's `Linker` is the object that resolves module imports at instantiation time. Every host function registered via `Linker::func_wrap` is a Rust closure that runs synchronously when the module calls the corresponding import. Wrapping this closure with logging and metrics is the lowest-overhead instrumentation point available — no binary modification required, no recompilation.

```rust
// instrumented_linker.rs
use wasmtime::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct CallCounter {
    pub count: AtomicU64,
    pub errors: AtomicU64,
}

pub fn add_instrumented_host_functions(
    linker: &mut Linker<HostState>,
    counters: Arc<std::collections::HashMap<&'static str, CallCounter>>,
) -> anyhow::Result<()> {
    // Wrap each host import with a logging + metrics shell.
    linker.func_wrap("env", "db_query", {
        let counters = counters.clone();
        move |mut caller: Caller<'_, HostState>,
              sql_ptr: i32, sql_len: i32| -> i32 {
            let name = "db_query";
            let ts = std::time::SystemTime::now();

            // Read the argument from WASM linear memory.
            let mem = caller.get_export("memory")
                .and_then(|e| e.into_memory());
            let sql = mem.as_ref().and_then(|m| {
                let data = m.data(&caller);
                let start = sql_ptr as usize;
                let end = start + sql_len as usize;
                data.get(start..end).and_then(|b| std::str::from_utf8(b).ok())
            }).unwrap_or("<invalid>");

            // Emit a structured security event.
            let module_id = &caller.data().module_id;
            tracing::info!(
                event = "host_call",
                module = %module_id,
                function = name,
                arg_sql = %&sql[..sql.len().min(512)],   // truncate; do not log unbounded input
                unix_ms = ts.duration_since(std::time::UNIX_EPOCH)
                              .unwrap_or_default().as_millis() as u64,
            );

            if let Some(c) = counters.get(name) {
                c.count.fetch_add(1, Ordering::Relaxed);
            }

            // Detect potential SQL injection patterns before forwarding.
            if sql.to_lowercase().contains("drop table") ||
               sql.to_lowercase().contains("--") {
                tracing::warn!(
                    event = "suspicious_host_call",
                    module = %module_id,
                    function = name,
                    reason = "potential SQL injection in argument",
                );
                if let Some(c) = counters.get(name) {
                    c.errors.fetch_add(1, Ordering::Relaxed);
                }
                return -1; // reject
            }

            // Delegate to the real implementation.
            caller.data_mut().db.query(sql)
        }
    })?;

    Ok(())
}
```

Every host import gets this wrapper. The wrapper:

1. Reads the WASM linear memory to extract argument values — strings, pointers — in their decoded form, before any host deserialization.
2. Emits a structured log event with module identity, function name, and sanitised argument snippets.
3. Applies lightweight pattern checks (injection signatures, anomaly heuristics).
4. Increments per-function counters for Prometheus scraping.
5. Delegates to the real implementation or rejects the call.

The argument-reading step is important. At the syscall layer, the host's `db.query(sql)` call is what eBPF would see — the SQL string is already in the host's memory. Wrapping the import captures the WASM module's perspective: the exact bytes the module intended to pass, before any host-side transformation.

### Method 2: Component Model Instrumentation Components

The WASM Component Model (CMP) enables composition: multiple components are linked together by a host `Linker<T>` into a single composed application. A monitoring component can be interposed between the user component and the host, without modifying either.

The WIT interface for the monitoring component:

```wit
// monitoring.wit
package security:monitoring@0.1.0;

interface event-sink {
  record host-call-event {
    module-id: string,
    function-name: string,
    arg-summary: string,
    timestamp-unix-ms: u64,
    allowed: bool,
  }

  record anomaly-event {
    module-id: string,
    reason: string,
    evidence: string,
  }

  record-call: func(event: host-call-event);
  record-anomaly: func(event: anomaly-event);
}

world monitoring-world {
  export event-sink;
}
```

The monitoring component is composed using `wasm-tools compose` before deployment:

```bash
# Compose the user module with the monitoring shim.
wasm-tools compose \
  --config composition.toml \
  --output composed.wasm \
  user-module.wasm \
  monitoring-shim.wasm
```

`composition.toml` wires the user module's host-function imports through the monitoring shim's corresponding exports. The shim logs the call, optionally modifies arguments, then forwards to the real host implementation. This pattern lets you instrument third-party WASM modules that you do not compile from source.

### Method 3: Binary-Level Trace Point Injection with wasm-tracing

`wasm-tracing` (part of the wasm-tools ecosystem) inserts function entry and exit instrumentation hooks into the WASM binary at compile or post-compile time. Every function call inside the module — not just host function calls — becomes traceable.

```bash
# Inject tracing hooks into an existing .wasm binary.
wasm-opt --pass-arg=instrument-locals \
         --instrument-calls \
         --log-execution \
         input.wasm \
         -o instrumented.wasm
```

The injected hooks call a set of well-known imports:

```wat
;; Injected by wasm-opt --instrument-calls into the binary.
(import "instrument" "call_enter" (func $call_enter (param i32)))  ;; function index
(import "instrument" "call_exit"  (func $call_exit  (param i32)))
```

The host satisfies these imports with counters, ring buffers, or full call-graph recording:

```rust
linker.func_wrap("instrument", "call_enter", |caller: Caller<'_, HostState>, func_idx: i32| {
    let state = caller.data();
    state.call_stack.push(CallFrame {
        func_idx: func_idx as u32,
        entered_at: std::time::Instant::now(),
        module_id: state.module_id.clone(),
    });
})?;

linker.func_wrap("instrument", "call_exit", |mut caller: Caller<'_, HostState>, func_idx: i32| {
    let state = caller.data_mut();
    if let Some(frame) = state.call_stack.pop() {
        let duration = frame.entered_at.elapsed();
        // Security signal: functions that take much longer than their baseline.
        if duration > state.baseline.get(func_idx as u32).unwrap_or_default() * 3 {
            tracing::warn!(
                event = "slow_function",
                module = %state.module_id,
                func_idx,
                duration_us = duration.as_micros(),
            );
        }
    }
})?;
```

Function-level tracing at this granularity reveals call graph anomalies that host-function wrapping cannot: a module that suddenly calls a large cryptographic function thousands of times in a single invocation, or a module that reaches a code path that has never been exercised in production.

### Method 4: Wizer Pre-Initialisation with Instrumentation

[Wizer](https://github.com/bytecodealliance/wizer) snapshots a WASM module after its initialisation phase — running the module's `_initialize` or `start` function, then capturing the resulting linear memory state as a new `.wasm` binary. The snapshot skips initialisation on every subsequent invocation.

Instrumentation overhead is higher during initialisation (many one-time calls) than during steady-state execution. Wizer lets you instrument the post-init snapshot rather than the pre-init module, eliminating noise from setup calls and reducing the baseline call log to steady-state operations only:

```bash
# Step 1: run the module through Wizer to produce a post-init snapshot.
wizer input.wasm -o preinit.wasm --allow-wasi

# Step 2: inject call-count instrumentation into the snapshot.
wasm-opt --instrument-calls preinit.wasm -o preinit-instrumented.wasm

# Step 3: deploy the instrumented snapshot.
# All subsequent invocations start from the post-init memory state,
# with call counters reset to zero at each invocation boundary.
```

The security monitoring system then sees only invocation-phase calls. If a module's initialisation makes 50 host calls and steady-state makes 3, the anomaly detector's baseline is calibrated on those 3 calls, not 53. A deviation from 3 is a high-confidence signal.

### Method 5: OpenTelemetry Span Export from Inside WASM

Distributed trace context ordinarily flows through HTTP headers. When a request enters a WASM module via a host-call boundary, the trace context must be explicitly passed in and explicitly exported out. Two approaches work in practice.

**Via WASI HTTP (preview 2):** The module uses `wasi:http/outgoing-handler` to send OTLP/HTTP spans to the collector. This requires the host to wire `wasi:http` and the module to carry the `opentelemetry` WASM crate:

```toml
# Cargo.toml for the WASM module
[dependencies]
opentelemetry = { version = "0.22", features = ["trace"] }
opentelemetry-otlp = { version = "0.15", features = ["http-proto", "reqwest-client"] }
```

```rust
// Inside the WASM module — this compiles to wasm32-wasip2.
use opentelemetry::trace::{Tracer, TracerProvider};
use opentelemetry_otlp::WithExportConfig;

fn setup_tracer() -> impl opentelemetry::trace::Tracer {
    let exporter = opentelemetry_otlp::new_exporter()
        .http()
        .with_endpoint("http://otel-collector.platform.svc:4318/v1/traces")
        .build_span_exporter()
        .expect("valid exporter");

    let provider = opentelemetry_sdk::trace::TracerProvider::builder()
        .with_simple_exporter(exporter)
        .build();

    provider.tracer("wasm-module")
}
```

**Via custom host import:** For runtimes without full WASI HTTP, the host exposes a span-export import that the module calls with a serialised OTLP payload:

```rust
// Host side: accept serialised OTLP protobuf from the module.
linker.func_wrap("otel", "export_span",
    |mut caller: Caller<'_, HostState>,
     ptr: i32, len: i32| {
    let mem = caller.get_export("memory")
        .and_then(|e| e.into_memory())
        .expect("memory export");
    let data = mem.data(&caller)[ptr as usize..][..len as usize].to_vec();

    // Forward asynchronously to the collector.
    let state = caller.data();
    state.otel_sender.try_send(data).ok();
})?;
```

The module uses a lightweight span builder that serialises directly to the protobuf wire format without heap allocation, minimising instrumentation overhead in tight loops.

With this pattern, every WASM module invocation produces a child span under the inbound request span. The trace shows: inbound HTTP request → WASM module invocation → host function calls within the module → outbound HTTP from the host. The full call graph is visible in Jaeger or Tempo without any eBPF probes.

### Method 6: Beyla-Style eBPF Auto-Instrumentation at the Runtime Process Level

Grafana Beyla and similar eBPF auto-instrumentation tools attach uprobes to Go, JVM, and Node.js processes to extract HTTP span context without code changes. The same approach applies to WASM runtimes: attach uprobes to key symbols in the `wasmtime` or `v8` binary to extract WASM-level context.

The relevant probe points in Wasmtime (Rust):

- `wasmtime::vm::VMContext::new` — module instantiation.
- `wasmtime::func::Func::call_unchecked` — every host function call.
- `wasmtime::trap::Trap::from_runtime` — runtime traps.

```bash
# Attach a BPF program to Wasmtime's host-call dispatch.
# Requires: wasmtime compiled without --strip, or with debuginfo.
bpftrace -e '
uprobe:/usr/bin/wasmtime:wasmtime::vm::libcalls::memory32_grow {
    @mem_grow_calls[pid] = count();
}

uprobe:/usr/bin/wasmtime:wasmtime::func::Func::call_unchecked {
    @host_calls[pid] = count();
}

interval:s:10 {
    print(@mem_grow_calls);
    print(@host_calls);
    clear(@mem_grow_calls);
    clear(@host_calls);
}
'
```

This approach works even when modules do not carry any in-module instrumentation. It requires access to the runtime binary with symbol information — a constraint that is often satisfied in development and staging environments where debug symbols are available, and can be satisfied in production by shipping a separate debuginfo package.

For Kubernetes deployments, Beyla runs as a DaemonSet sidecar and auto-discovers wasmtime processes, attaching eBPF probes and exporting spans to the cluster's OTLP collector. The Beyla configuration:

```yaml
# beyla-config.yaml
otel_traces_export:
  endpoint: http://otel-collector:4317
discovery:
  services:
    - name: wasm-runtime
      open_port: 8080
      exe_path: .*/wasmtime$
```

eBPF instrumentation at this level captures what host-function wrapping misses: interactions that happen inside the runtime itself, such as epoch-deadline traps, memory guard page hits, and compilation cache events.

## Detecting Anomalous WASM Behaviour

Instrumentation produces data. Detection turns data into actionable signals. The following heuristics apply across all instrumentation methods.

**Unusual host function call patterns:**

A module invocation that calls `crypto_sign` 10,000 times is probably not legitimate. Establish per-module baseline call counts for each host function using a rolling window average over the last 100 invocations. Alert when a single invocation exceeds 5x the baseline for any function.

```rust
// Per-invocation check in the post-call hook.
let baseline = state.call_baselines
    .get(&(module_id.clone(), func_name.to_string()))
    .cloned()
    .unwrap_or(1.0);

if (state.call_counts[func_name] as f64) > baseline * 5.0 {
    emit_anomaly_event(AnomalyEvent {
        kind: "excessive_host_calls",
        module_id: &module_id,
        function: func_name,
        observed: state.call_counts[func_name],
        baseline: baseline as u64,
    });
}
```

**Unexpected memory access patterns:**

Modules that access near the top of their linear memory (within 64 KiB of the declared limit) are probing for growth or out-of-bounds writes. The resource limiter's `memory_growing` callback is the right hook; fire an anomaly event before returning `Ok(false)`.

**High instruction counts for specific operations:**

Wasmtime's fuel consumption is a proxy for instruction count. If a specific entry point normally consumes 50,000 units of fuel and a given invocation consumes 800,000, the code path has diverged. Track fuel consumed per entry-point per module and alert on deviations above a threshold.

**Sudden appearance of new call sequences:**

Record the set of distinct (caller function index, host function name) pairs observed per module over its lifetime. A new pair appearing after the module has processed thousands of invocations is a strong signal — either a new code path (legitimate, should be reviewed) or injected code (should be blocked immediately).

## Building a WASM Security Event Log

All signals converge in a structured event log. The log schema covers three event categories:

**Module lifecycle events:**

```json
{
  "event": "module_load",
  "timestamp": "2026-05-07T12:00:00.000Z",
  "module_hash": "sha256:abc123...",
  "module_id": "tenant-42/my-plugin@1.2.3",
  "runtime": "wasmtime-22.0.0",
  "features_enabled": ["bulk-memory", "reference-types"],
  "features_disabled": ["threads", "multi-memory", "gc"],
  "wasi_capabilities": ["/work:rw", "/assets:r"]
}
```

**Host function call events:**

```json
{
  "event": "host_call",
  "timestamp": "2026-05-07T12:00:01.123Z",
  "module_id": "tenant-42/my-plugin@1.2.3",
  "invocation_id": "inv-9f8a7b",
  "function": "db_query",
  "arg_summary": "SELECT * FROM orders WHERE id=?",
  "duration_us": 450,
  "result": "ok",
  "call_count_this_invocation": 3
}
```

**Anomaly events:**

```json
{
  "event": "anomaly",
  "timestamp": "2026-05-07T12:00:02.000Z",
  "module_id": "tenant-42/my-plugin@1.2.3",
  "invocation_id": "inv-9f8a7b",
  "kind": "excessive_host_calls",
  "function": "crypto_sign",
  "observed": 8400,
  "baseline": 12,
  "action": "terminated"
}
```

Events are written to a local ring buffer by the host instrumentation code and drained to a structured log sink (Loki, Elasticsearch, or a SIEM via Fluentd) asynchronously to avoid adding latency to the WASM execution path. The ring buffer drops events when it fills — acceptable for high-throughput paths where anomaly detection runs separately on the aggregated metrics — or applies backpressure by blocking the host call until space is available when the module is in a rate-limited tier.

## Expected Outcomes

| Threat | Without Instrumentation | With Instrumentation |
|--------|------------------------|----------------------|
| SQL injection via host import | Visible only in database logs, after execution | Detected pre-execution by argument pattern check in the wrapper; call blocked |
| Module making 10,000 crypto calls | No signal at kernel level | Anomaly event on call count; module terminated |
| Compromised module calling new host function | Invisible to eBPF/Falco | New (caller, function) pair triggers review alert |
| Trace context lost at WASM boundary | No cross-service visibility | OTLP spans exported; full trace visible in Jaeger |
| Memory probe near limit | No signal until OOM | Anomaly event from `memory_growing` hook before growth |
| Module load of unsigned binary | No runtime signal | `module_load` event with hash; compared against allowlist |

## Trade-offs

| Approach | Benefit | Cost | Recommendation |
|----------|---------|------|----------------|
| Linker-based wrapping | Zero binary modification; precise argument capture | Per-call overhead for argument reads (~1–5 µs) | Use for all security-relevant host functions; skip for high-frequency internal imports |
| Component model composition | Instruments third-party modules without source access | Composition toolchain complexity; WIT interface must match exactly | Use in multi-tenant platforms where modules are untrusted binaries |
| Binary trace point injection | Full intra-module call graph | 10–30% overhead on instruction-dense workloads; binary modification requires re-signing | Use in staging for baseline profiling; production only for high-risk modules |
| Wizer pre-init snapshots | Cleaner baseline; faster cold start | Additional build step; snapshot must be re-generated on module update | Integrate into the module build pipeline for all production modules |
| In-module OTLP export | Rich trace context; no host-side secret knowledge of internal structure | Module must carry OTel crate; increases binary size | Use for modules you control; skip for third-party modules |
| eBPF uprobes on runtime | Zero source changes; works on binaries | Requires debuginfo; breaks on runtime updates until re-attached | Use in development and for defence-in-depth in production alongside host wrapping |

## Related Articles

- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [WASI Preview 2 Capability-Based Security](/articles/wasm/wasi-preview-2-capabilities/)
- [WASM Component Model Security](/articles/wasm/wasm-component-model-security/)
- [Distributed Tracing for Security Visibility](/articles/observability/distributed-tracing-security/)
- [WASM Static Analysis and Supply Chain Scanning](/articles/wasm/wasm-supply-chain-scanning-tools/)
- [WASM on Kubernetes](/articles/wasm/wasm-on-kubernetes/)
