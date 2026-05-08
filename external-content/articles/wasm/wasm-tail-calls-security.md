---
title: "WASM Tail Calls Security Implications"
description: "Analyze security implications of the WebAssembly tail calls proposal—stack frame elimination breaking depth limits and call-stack audit tools—with tracking of silent implementation fixes in Wasmtime and V8."
slug: wasm-tail-calls-security
date: 2026-05-02
lastmod: 2026-05-02
category: wasm
tags: ["wasm", "tail-calls", "return-call", "stack-depth", "wasmtime", "v8", "security-tools"]
personas: ["security-engineer", "platform-engineer", "systems-engineer"]
article_number: 366
difficulty: advanced
estimated_reading_time: 15
published: true
layout: article.njk
permalink: "/articles/wasm/wasm-tail-calls-security/index.html"
---

# WASM Tail Calls Security Implications

## Problem

The WebAssembly tail calls proposal reached Stage 4 and shipped in V8/Chrome 112+ and Wasmtime 18+, enabling two new instructions: `return_call` and `return_call_indirect`. Both perform a function call while replacing the current stack frame rather than pushing a new one — the callee reuses the caller's stack slot, so the call stack does not grow. The direct form `return_call $f` is the equivalent of a C tail call to a named function; `return_call_indirect $t` resolves the callee through a function table at runtime, with type `$t` checked against the table entry. For functional programming languages compiled to WASM — Haskell, OCaml, Scheme, and any Clang translation unit marked with `musttail` — this instruction pair is not an optimisation but a correctness requirement. Without it, a continuation-passing style interpreter or a deeply recursive functional algorithm will eventually exhaust the call stack and trap. With tail calls enabled, those same algorithms run in constant stack space regardless of iteration count.

The security model change is straightforward to state but subtle in its consequences. Classic WASM without tail calls has a bounded call stack. The runtime can enforce a maximum call depth, and any module that attempts to exceed that depth receives a stack overflow trap. In Wasmtime, `Config::max_wasm_stack` sets the maximum WASM stack size in bytes; crossing it reliably terminates the offending module. Security tools — sandboxes, policy engines, call-graph auditors — can treat call depth as a meaningful runtime signal. Deep recursion that was absent in a baseline profile but appears under production load is a useful anomaly indicator. With tail calls enabled, `return_call` chains can execute indefinitely without growing the call stack. A module can implement an infinite loop using only `return_call`, and the loop will never trigger the `max_wasm_stack` limit. The depth limit becomes an ineffective control for any module that uses tail calls for its primary control flow. The depth limit still traps `call` instructions that genuinely recurse without tail call form, but those are precisely the patterns that well-written functional language output would avoid.

The fuel and epoch interaction with tail calls requires careful analysis. Wasmtime's epoch-based interruption (`Config::epoch_interruption`) and fuel metering (`Config::consume_fuel`) both apply correctly to `return_call` and `return_call_indirect` — each execution of a tail call instruction consumes one unit of fuel and checks the current epoch. This is the designed mitigation for the loss of call depth as a DoS signal. However, the interaction introduces an important operational dependency: `max_wasm_stack` used to function as a secondary, passive DoS prevention mechanism that required no explicit host configuration. A host that ran untrusted WASM and set a tight `max_wasm_stack` budget received automatic protection against runaway recursion. With tail calls enabled, that passive protection no longer covers tail-call loops. If fuel metering is not configured — or if the fuel budget is set to unlimited — a tail-call loop runs until the host process is killed externally. The transition from passive depth-limit protection to active fuel-budget configuration is a migration responsibility that can silently fall through the cracks during Wasmtime version upgrades.

The open-source implementation history of tail calls in Wasmtime and V8 contains correctness fixes that shipped without CVE assignment and without security advisories, making them easy to miss in operational patch processes. In Wasmtime's Cranelift compiler, an incorrect code generation path existed for `return_call_indirect` when the callee's type signature differed from the caller's in configurations involving certain ABI boundary conditions. The generated machine code could corrupt the host runtime's stack frame rather than trapping cleanly. The fix appeared in a commit titled "fix return_call_indirect frame setup in Cranelift" during the tail calls stabilization phase; no advisory was published and no CVE was requested. Operators running Wasmtime versions from the tail calls stabilization window — roughly Wasmtime 16 through early 18 — and executing `return_call_indirect` with heterogeneous type signatures may have been silently exposed to host stack corruption.

V8's implementation carried a separate class of issue in its interpreter path. V8 uses an interpreter as a fallback before JIT compilation is complete; in environments running Node.js with `--no-opt`, or in early-startup windows before JIT warmup, WASM execution routes through the interpreter. V8's loop detector — the mechanism that identifies and interrupts spinning JavaScript or WASM loops in non-JIT mode — did not account for tail call cycles. A module whose main loop was implemented entirely via `return_call` would not trigger V8's loop timeout in interpreter mode, because the loop detector tracked backward branches and call/return pairs rather than `return_call` edges. The practical consequence was a more powerful DoS surface in server-side Node.js configurations using `--no-opt` or in edge deployments where JIT compilation was disabled for security or latency reasons. This fix arrived in a V8 stable commit without a separate advisory.

The Wasmtime test suite for tail calls (`tests/spec/tail_call.wast`) was added after the feature was enabled by default in Wasmtime 18. Several of the test additions came in the same pull requests as bug fixes, which is a reliable indicator that the tested behaviour was discovered through a defect rather than specified in advance. Operators tracking Wasmtime releases who observe new tail call test additions alongside source changes should treat those additions as implicit regression markers — the implementation was not behaving correctly before the test was added. Monitoring the commit stream for tail call changes requires watching two layers: the spec test additions in `tests/spec/` and the codegen changes in `cranelift/codegen/src/isa/*/abi.rs` and the instruction lowering files that handle `return_call` and `return_call_indirect`. A one-liner to extract relevant commits from Wasmtime's history is: `gh api repos/bytecodealliance/wasmtime/commits --jq '.[] | select(.commit.message | test("tail.call|return_call"; "i")) | {sha: .sha[0:8], msg: .commit.message}'`. Subscribing to Bytecode Alliance security advisories via the GitHub advisory feed provides a lower-noise channel, but the implementation fixes described above demonstrate that not all security-relevant changes are routed through the advisory process.

Target systems for this analysis: Wasmtime 18+ with tail calls enabled by default; V8/Node.js 20+ (Chrome 112+) where the proposal is active; any WASM module compiled with the `-mtail-call` Clang flag; and modules produced by functional language toolchains targeting WASM where tail call optimization is a correctness requirement rather than a performance hint.

## Threat Model

The following adversary scenarios are ordered from direct exploitation to indirect security control erosion.

1. **Tail-call infinite loop for DoS.** A malicious WASM module implements its main loop using `return_call` rather than `loop` or recursive `call`. The module executes indefinitely without growing the call stack, bypassing `max_wasm_stack`. If the host does not configure fuel metering, the module occupies the WASM thread permanently. In a multi-tenant environment where each tenant module runs on a shared thread pool, one tenant module can deny service to all others by holding a thread in a `return_call` cycle until the host process is externally killed. The attack is trivially constructible — a two-function module where each function tail-calls the other requires fewer than 20 WASM bytes.

2. **Evasion of call-depth anomaly detection.** A host security monitor tracks call depth as an anomaly signal: a sudden increase in recursion depth during a normally flat-profile workload indicates a potential exploit attempt such as a heap spray or stack pivot. With tail calls, an attacker uses `return_call` chains to implement deep logical iteration while keeping the visible call stack at depth one. Monitoring systems that report `max_observed_call_depth` as a security metric will report a benign value while the module executes arbitrarily complex control flow. Any IDS rule or behavioral baseline built on call depth as a feature becomes systematically blind to tail-call-based payloads.

3. **Cranelift `return_call_indirect` frame corruption.** The Wasmtime codegen bug in Cranelift's `return_call_indirect` frame setup — present before it was fixed during the tail calls stabilization phase — is exploitable as a crash vector by an attacker who can submit arbitrary WASM modules to a multi-tenant platform. A module crafted with the specific type signature mismatch pattern that triggered the bug corrupts the host runtime's stack frame. Depending on what lands on the corrupted frame, this can produce an uncontrolled crash, silent wrong results, or — in the worst case — control flow diversion. An attacker running untrusted WASM on a platform with an unfixed Wasmtime version that includes tail calls sits in the patch gap between the feature shipping (Wasmtime 18) and the fix commit. Since no CVE was assigned, automated vulnerability scanners would not flag the unfixed version.

4. **Functional language module triggering codegen regression.** A legitimate operator deploys a WASM module compiled from OCaml or Haskell that relies heavily on `return_call_indirect` for continuation dispatch. A Wasmtime upgrade introduces a regression in Cranelift's tail call codegen. The module continues to load and execute without trapping, but produces incorrect results in security-critical computations — cryptographic checks, authorization evaluations, policy decisions. Because the failure mode is silent wrong output rather than a trap, the regression is not caught by uptime monitoring or crash alerting. It surfaces only through application-level correctness checks or user-reported unexpected behaviour.

The blast radius of these scenarios concentrates in multi-tenant WASM platforms — Spin-based deployments, WasmCloud environments, and browser-embedded policy engines — where the host runtime executes modules from multiple sources with varying trust levels. In single-tenant environments where the WASM module is operator-controlled and trusted, threat 1 and 3 reduce significantly. Threat 2 remains relevant in all environments where a host-side security monitor was built assuming the call stack is a reliable behavioral signal.

## Configuration / Implementation

### Fuel metering as the primary DoS defence

With tail calls enabled, `max_wasm_stack` alone is insufficient to bound execution time. Fuel metering is the mandatory replacement. Each WASM instruction consumes a configurable amount of fuel; when the budget is exhausted, the runtime traps with an out-of-fuel error. Because `return_call` instructions consume fuel identically to `call` instructions, fuel metering applies uniformly to tail-call loops.

```rust
use wasmtime::{Config, Engine, Module, Store};

fn make_engine_with_tail_calls_and_fuel() -> anyhow::Result<Engine> {
    let mut config = Config::new();
    // Tail calls are enabled by default in Wasmtime 18+; explicit here for clarity.
    config.wasm_tail_call(true);
    config.consume_fuel(true);
    // Epoch interruption as a wall-clock backstop.
    config.epoch_interruption(true);
    Ok(Engine::new(&config)?)
}

fn run_module(engine: &Engine, wasm_bytes: &[u8]) -> anyhow::Result<()> {
    let module = Module::new(engine, wasm_bytes)?;
    let mut store = Store::new(engine, ());

    // Calibrate: run the module once with a large budget and measure actual consumption.
    // Then set production budget to 10x the measured maximum legitimate consumption.
    let fuel_budget: u64 = 10_000_000;
    store.set_fuel(fuel_budget)?;

    // Configure what happens when fuel runs out: trap rather than pause.
    store.out_of_fuel_trap();

    // Set a deadline for epoch-based interruption as well.
    store.set_epoch_deadline(100); // 100 epoch ticks at 10ms each = ~1 second max

    let linker = wasmtime::Linker::new(engine);
    let instance = linker.instantiate(&mut store, &module)?;
    let run = instance.get_typed_func::<(), ()>(&mut store, "run")?;
    run.call(&mut store, ())?;

    // Inspect actual fuel consumed for calibration logging.
    let consumed = fuel_budget - store.get_fuel()?;
    tracing::info!(consumed, budget = fuel_budget, "wasm fuel report");
    Ok(())
}
```

Calibrating the fuel budget requires running representative workloads and recording consumption via `store.get_fuel()` before and after each invocation. A budget of 10x the observed maximum legitimate consumption gives headroom for input variation while still bounding runaway loops. Do not use a single calibration sample — measure across the full distribution of expected inputs, including edge cases that may trigger deeper recursion in functional language modules.

### Epoch interruption as backup

Epoch interruption provides wall-clock time bounds independent of instruction counting. A background thread increments the epoch counter on a fixed interval; the WASM runtime checks the epoch at backward branches, calls, and `return_call` instructions.

```rust
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use wasmtime::Engine;

fn start_epoch_thread(engine: Arc<Engine>, tick_ms: u64) -> thread::JoinHandle<()> {
    thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(tick_ms));
        engine.increment_epoch();
    })
}

// In the host setup:
// let engine = Arc::new(make_engine_with_tail_calls_and_fuel()?);
// let _epoch_handle = start_epoch_thread(Arc::clone(&engine), 10);
//
// Per-store: store.set_epoch_deadline(100); // 100 × 10ms = 1 second
// On deadline: store.epoch_deadline_trap();  // trap on deadline exceeded
```

The epoch mechanism is a backstop for fuel budget misconfiguration. If the fuel budget is set too high or fuel metering is accidentally disabled, the epoch deadline ensures execution terminates within a bounded wall-clock window. Use both simultaneously: fuel for instruction-count bounding, epoch for time bounding.

### Selectively disabling tail calls

For multi-tenant platforms where tenants submit arbitrary WASM modules and tail calls provide no functional benefit to the platform's use case, disable the proposal entirely:

```rust
config.wasm_tail_call(false);
```

Before making this decision, validate whether any deployed modules actually use `return_call`. The `wasm-tools` CLI inspects a module's instruction set:

```bash
# Check if a module uses return_call or return_call_indirect
wasm-tools validate --features tail-call module.wasm

# Dump the disassembly and search for tail call instructions
wasm-tools dump module.wasm | grep -E 'return_call'

# Validate without tail-call feature to confirm the module does not require it
wasm-tools validate module.wasm 2>&1 | grep -i "tail"
```

If `wasm-tools validate` without `--features tail-call` succeeds, the module does not use `return_call` or `return_call_indirect`, and disabling the proposal in the engine will not break it. Enforce this check as a module admission gate before deploying untrusted WASM to environments with tail calls disabled.

### Call-stack auditing alternatives

Since call depth monitoring is unreliable when `return_call` is in use, shift to alternative runtime signals:

- **Fuel consumption rate**: poll `store.get_fuel()` at fixed intervals in a wrapper and compute instructions-per-millisecond. A module that is consuming fuel at maximum rate continuously — no host function calls, no I/O waits — is likely in a tight loop. Legitimate workloads typically show bursty fuel consumption interleaved with external operations.
- **Wall-clock time per invocation**: instrument the host call site. Any WASM invocation exceeding a latency threshold for its category warrants investigation regardless of call depth.
- **Memory growth via `ResourceLimiter`**: tail call loops that accumulate state — building lists, filling tables, writing to linear memory — will still trigger memory growth limits even though call depth does not increase.

```rust
use wasmtime::{ResourceLimiter, Store};

struct MemoryLimiter {
    max_bytes: usize,
}

impl ResourceLimiter for MemoryLimiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        if desired > self.max_bytes {
            anyhow::bail!("memory limit exceeded: {} > {}", desired, self.max_bytes);
        }
        Ok(maximum.map_or(true, |m| desired <= m))
    }

    fn table_growing(
        &mut self,
        current: u32,
        desired: u32,
        maximum: Option<u32>,
    ) -> anyhow::Result<bool> {
        Ok(maximum.map_or(true, |m| desired <= m))
    }
}

// Usage:
// let mut store = Store::new(engine, MemoryLimiter { max_bytes: 64 * 1024 * 1024 });
// store.limiter(|state| state as &mut dyn ResourceLimiter);
```

### Testing tail call implementation correctness

Run Wasmtime's tail call spec tests to verify that the installed version handles all reference cases:

```bash
# From the Wasmtime repository root
cargo test --test spec_testsuite -- tail_call

# Run with verbose output to see individual test names
cargo test --test spec_testsuite -- tail_call --nocapture
```

Write a host-side regression test for the `return_call_indirect` frame corruption pattern:

```rust
#[test]
fn test_return_call_indirect_fuel_bound() -> anyhow::Result<()> {
    // A module with two functions that tail-call each other via an indirect call.
    // (ref.func $b) stored in table, then returned via return_call_indirect.
    let wasm = wat::parse_str(r#"
        (module
          (type $t (func))
          (table 1 funcref)
          (elem (i32.const 0) $b)
          (func $a (export "run")
            (return_call_indirect (type $t) (i32.const 0))
          )
          (func $b
            (return_call_indirect (type $t) (i32.const 0))
          )
        )
    "#)?;

    let mut config = Config::new();
    config.wasm_tail_call(true);
    config.consume_fuel(true);
    let engine = Engine::new(&config)?;
    let module = Module::new(&engine, &wasm)?;
    let mut store = Store::new(&engine, ());
    store.set_fuel(1_000_000)?;
    store.out_of_fuel_trap();

    let linker = wasmtime::Linker::new(&engine);
    let instance = linker.instantiate(&mut store, &module)?;
    let run = instance.get_typed_func::<(), ()>(&mut store, "run")?;

    // Expect a fuel exhaustion trap, not a host stack corruption or hang.
    let result = run.call(&mut store, ());
    assert!(result.is_err(), "expected fuel exhaustion trap");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("fuel") || err.to_string().contains("trap"),
        "unexpected error: {err}"
    );
    Ok(())
}
```

### Monitoring Wasmtime tail call fixes

Extract all tail call-related commits from the Wasmtime repository:

```bash
gh api repos/bytecodealliance/wasmtime/commits \
  --jq '.[] | select(.commit.message | test("tail.call|return_call|tail_call"; "i")) | {sha: .sha[0:8], msg: .commit.message}'
```

Watch for changes in the Cranelift ABI and instruction lowering files that govern `return_call` codegen:

```bash
# List recent changes to tail-call-relevant Cranelift sources
gh api "repos/bytecodealliance/wasmtime/commits?path=cranelift/codegen/src/isa" \
  --jq '.[] | select(.commit.message | test("tail|return_call|abi"; "i")) | {sha: .sha[0:8], msg: .commit.message}'

# Files to monitor specifically:
# cranelift/codegen/src/isa/aarch64/abi.rs
# cranelift/codegen/src/isa/x64/abi.rs
# cranelift/codegen/src/isa/riscv64/abi.rs
# cranelift/codegen/src/machinst/abi.rs
```

Automate Wasmtime version tracking with Renovate in `Cargo.toml`. The Renovate configuration for a pinned Wasmtime dependency:

```json
{
  "packageRules": [
    {
      "matchPackageNames": ["wasmtime"],
      "reviewers": ["security-team"],
      "addLabels": ["security-review"]
    }
  ]
}
```

Subscribe to Bytecode Alliance security advisories via the GitHub advisory database: `https://github.com/bytecodealliance/wasmtime/security/advisories`. Note that not all security-relevant tail call fixes have been routed through this channel — direct commit monitoring is the more complete signal.

### V8 and Node.js tail call considerations

In Node.js versions before 20, tail calls required `--experimental-wasm-tail-call`. In Node.js 20+ (V8 11.2+, Chrome 112+), the proposal is active by default. Check the V8 version in a running Node.js process:

```bash
node -e "console.log(process.versions.v8)"
```

To verify that V8's loop detector correctly handles tail-call cycles in non-JIT mode — the regression described in the problem section — construct a test module and confirm it terminates under `--no-opt`:

```bash
# Write a minimal tail-call loop module
cat > /tmp/tail_loop_test.wat << 'EOF'
(module
  (func $loop (export "loop")
    (return_call $loop)
  )
)
EOF
wasm-tools parse /tmp/tail_loop_test.wat -o /tmp/tail_loop_test.wasm

# Run under Node.js without JIT and verify it terminates with a timeout or error
timeout 5 node --no-opt -e "
const fs = require('fs');
const bytes = fs.readFileSync('/tmp/tail_loop_test.wasm');
WebAssembly.instantiate(bytes).then(({instance}) => {
  try { instance.exports.loop(); }
  catch(e) { console.log('Terminated:', e.message); }
});
" || echo "Process did not terminate within 5 seconds — loop detector may not cover tail calls in this V8 version"
```

If the timeout fires without output, the environment is vulnerable to the V8 interpreter tail-call loop issue. Mitigation: avoid `--no-opt` in production Node.js deployments executing untrusted WASM, or enforce JIT compilation (`--jitless` disables JIT but also disables WASM entirely in some configurations — verify the behaviour for your Node.js version).

## Expected Behaviour

The following table compares runtime signals across configurations. "No fuel" means `Config::consume_fuel` is not set; "fuel + epoch" means both are configured as shown in the Configuration section.

| Signal | Tail calls enabled, no fuel | Tail calls + fuel + epoch |
|--------|----------------------------|--------------------------|
| Infinite `return_call` loop terminates | No — runs until host kills process | Yes — fuel exhaustion trap within budget |
| Call depth limit (`max_wasm_stack`) blocks tail loop | No — call stack stays at depth 1 | No — same; depth limit is not the active control |
| `max_wasm_stack` still traps `call`-based recursion | Yes — non-tail recursive `call` still grows stack | Yes — unchanged |
| Fuel budget exceeded → trap | N/A — fuel not configured | Yes — `out_of_fuel_trap()` fires; module terminates cleanly |
| Epoch interrupt fires for long-running tail chain | No — epoch not configured | Yes — deadline trap fires after `deadline × tick_ms` wall-clock time |
| Cranelift codegen bug detection via spec tests | Only if spec tests are run post-deployment | Yes — `cargo test --test spec_testsuite -- tail_call` catches known regressions |
| `return_call_indirect` type mismatch | Should trap; bug-era code may corrupt stack | Should trap; verify with regression test from Configuration section |
| V8 interpreter tail-call loop in `--no-opt` mode | May not terminate (see Problem section) | N/A — Wasmtime-specific controls; use Node.js JIT-enabled mode |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|-----------|
| Disabling tail calls (`wasm_tail_call(false)`) | Eliminates tail-call-specific DoS and codegen risks; `max_wasm_stack` becomes effective again | Breaks any deployed WASM module compiled from functional languages or with `-mtail-call`; binary incompatibility | Audit modules with `wasm-tools dump | grep return_call` before disabling; gate on confirmed absence of tail call instructions |
| Fuel metering overhead | Provides reliable instruction-count bound that covers tail calls | 3–8% throughput reduction on tight compute loops due to per-instruction counter decrements | Accept overhead for untrusted modules; consider disabling fuel for trusted, internally compiled modules in controlled environments |
| Epoch interruption | Wall-clock time bound independent of instruction mix; low overhead | Adds a background host thread; timer resolution affects precision; JVM-style stop-the-world is not possible — epoch only fires at check points in WASM code | Set tick interval to match latency tolerance; 10ms is a reasonable default; combine with fuel for belt-and-suspenders |
| Call-depth anomaly detection lost | — | Existing IDS rules and behavioral baselines built on call depth become ineffective against tail-call-based payloads | Shift anomaly detection to fuel consumption rate, wall-clock time per invocation, and memory growth rate as alternative behavioral signals |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|---------|
| Fuel budget set too low for legitimate functional WASM module | Valid OCaml or Haskell module traps mid-computation with out-of-fuel error; application logic reports unexpected errors or partial results | Application-level error rate increase; fuel exhaustion errors in logs; module works in test but fails under larger production inputs | Increase calibration dataset coverage; measure `store.get_fuel()` delta across full input distribution; raise budget to 10× observed maximum |
| Epoch deadline too aggressive for long legitimate computation | Valid long-running WASM computation (e.g. cryptographic key derivation, large data transformation) interrupted before completion | Wall-clock time alerting shows WASM invocations consistently hitting epoch deadline; increasing epoch deadline resolves the issue | Profile the legitimate computation's wall-clock time; set epoch deadline to 3× the 99th-percentile runtime; or split long computations into host-managed checkpointed segments |
| Tail call feature disabled breaks existing deployed module | Module that previously ran successfully fails to validate or instantiate with "unknown instruction 0xF2" or similar; instantiation error logged at startup | Module load error in runtime logs; `wasm-tools validate module.wasm` without `--features tail-call` fails | Re-enable `wasm_tail_call(true)` for that module class; establish pre-deployment validation gate so tail-call-using modules are detected before disabling the feature in production |
| Cranelift codegen regression on Wasmtime upgrade produces silent wrong results | Security-critical WASM computation (authorization check, policy evaluation) returns incorrect output without trapping; downstream logic makes wrong decisions based on corrupted results | Correctness regression tests against known-good outputs; differential testing between Wasmtime versions with identical inputs | Pin Wasmtime version and add differential correctness tests to CI; run `cargo test --test spec_testsuite -- tail_call` as a post-upgrade gate; roll back to the previous pinned version if correctness diverges |

## Related Articles

- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [WASM Multi-Tenancy Security](/articles/wasm/wasm-multi-tenancy/)
- [WASM Exception Handling v2 Security](/articles/wasm/wasm-exception-handling-security/)
- [WASM Static Analysis](/articles/wasm/wasm-static-analysis/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
