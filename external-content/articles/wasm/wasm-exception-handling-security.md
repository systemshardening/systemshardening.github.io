---
title: "WASM Exception Handling v2 Security"
description: "Analyze security implications of the WebAssembly exception handling v2 proposal—cross-trust-boundary exception propagation, try_table instruction risks, and tracking silent fixes in Wasmtime and V8."
slug: wasm-exception-handling-security
date: 2026-05-02
lastmod: 2026-05-02
category: wasm
tags: ["wasm", "exception-handling", "try-table", "wasmtime", "v8", "multi-tenancy", "sandbox"]
personas: ["security-engineer", "platform-engineer", "systems-engineer"]
article_number: 350
difficulty: advanced
estimated_reading_time: 15
published: true
layout: article.njk
permalink: "/articles/wasm/wasm-exception-handling-security/index.html"
---

# WASM Exception Handling v2 Security

## Problem

The WebAssembly exception handling proposal has undergone a significant redesign between its original form and the version now shipping in production runtimes. The first iteration (EH v1) introduced `try`, `catch`, and `throw` instructions modeled closely on C++ structured exception handling — a try block containing a sequence of catch clauses, each identified by a tag. This design was implemented experimentally in V8 and Wasmtime but never reached Phase 4 before the community recognized that the block-level catch syntax was too restrictive and difficult to implement efficiently in certain compiler pipelines.

The v2 proposal, which reached Phase 4 and is shipping in Wasmtime 20+ and V8/Chrome 125+, replaces the block-based model with `try_table` and three related instructions: `throw`, `throw_ref`, and `catch_ref`. The structural difference is that catch clauses are encoded as operands to the `try_table` instruction itself rather than as subsequent block instructions. A `try_table` specifies a list of catch handlers, each with a destination label and either a tag or a catch-all. Control transfers immediately to the target label when a matching exception propagates through the table. The `throw_ref` instruction re-throws an `exnref` value without unwinding a new stack frame, and `catch_ref` receives the exception as a typed GC-managed reference (`exnref`) rather than consuming it.

The `exnref` type is where the security complexity concentrates. An `exnref` is a GC-managed reference — it falls squarely within the WasmGC proposal's object model. Exceptions are now first-class values that can be stored in locals, passed as function arguments, and re-thrown multiple frames later. In the EH v1 model, an exception existed only for the duration of the catch handler. In EH v2, a module can capture an `exnref` via `catch_ref`, store it in a local or table, pass it to another function, and eventually `throw_ref` it from an entirely different call frame. This changes the control flow analysis burden for any runtime that needs to reason about exception propagation.

The cross-trust-boundary risk is most acute in multi-tenant WASM deployments. Consider a platform where the host runtime calls a WASM module A (operator-controlled), which calls WASM module B (tenant-controlled). Module A uses `try_table` to catch specific tagged exceptions from module B, expecting to handle only its own tag. If module B crafts an exception with a tag that passes a flawed tag validation check in the runtime's `catch_ref` dispatch, module A's handler may process attacker-controlled exception payload data. In EH v1, the tag validation path was simpler because exceptions were consumed inline; in EH v2, the `exnref` object persists across frames and the validation must survive through GC lifecycle events.

Wasmtime's initial EH v2 implementation carried a bug where `catch_ref` did not properly validate the tag of the caught exception against the expected tag for the handler. A module could arrange for a `catch_ref` handler to receive an exception whose tag did not match the declared handler tag, effectively allowing one module to intercept another module's typed exceptions. The fix appeared in a commit titled "fix catch_ref tag validation in exception handling" with no CVE and no published advisory. V8 had a related issue: a type confusion between `exnref` and `externref` in certain Cranelift IR codegen paths allowed an `exnref` value to appear where an `externref` was expected. An `externref` is an opaque host reference; an `exnref` is a structured exception object. Treating one as the other in compiled code produces undefined behavior in the generated machine code. V8 shipped the fix in a Chrome stable release, but the Chromium commit was publicly visible before the Chrome update reached users. Separately, Wasmtime's Cranelift backend had a codegen error for `throw` instructions inside certain loop structures where the exception silently failed to propagate — execution continued past the `throw` as if it had not occurred. A correctness bug of this kind has direct security relevance: error-termination paths that the module author expected to halt execution do not, and the module continues with a corrupted program state.

Tracking these fixes requires active monitoring because none followed standard CVE disclosure. The most reliable signal is Wasmtime's `RELEASES.md` and Cranelift changelog, filtered for exception-handling terms. A standing `gh api` query captures relevant commits as they land:

```bash
gh api repos/bytecodealliance/wasmtime/commits \
  --jq '.[] | select(.commit.message | test("exception|try_table|throw|catch|exnref"; "i")) | {sha: .sha[0:8], message: .commit.message}'
```

V8 fixes appear in the Chromium security tracker and the V8 blog, but the gap between a public commit and a Chrome stable release is typically four to six weeks. Node.js inherits V8 version bumps on a separate schedule, so a fix in Chrome 125 may not reach Node.js 22 users for an additional release cycle.

Target systems: Wasmtime 20+ (EH v2 behind feature gate), Wasmtime 26+ (stabilized), V8 as shipped in Chrome 125+ and Node.js 22+, wasm-tools 1.x.

## Threat Model

1. **Cross-module `exnref` re-throw**: A malicious WASM module uses `catch_ref` to capture an `exnref` that originated in a different, trusted module, stores the reference, and later `throw_ref`s it from a context where the trusted module's catch handler is on the call stack. The trusted module's handler processes attacker-controlled exception payload data — payload bytes, tag arguments — that it believes originated from its own controlled code path.

2. **Patch-gap exploitation**: Wasmtime's `catch_ref` tag validation bug is described in a public GitHub commit message before the platform operator has upgraded. An attacker who runs WASM in the multi-tenant platform crafts a module that deliberately mis-tags an exception to fall through to another tenant's catch handler. The exploitable window is the interval between the public commit and the operator's next Wasmtime upgrade cycle — potentially weeks on a monthly patching cadence.

3. **Exception propagation into host code that is not exception-safe**: A WASM module throws an exception that is not caught within the module. The exception propagates through the Wasmtime call boundary into host Rust code that called `func.call()`. If the host code does not handle the `Trap` error return and instead panics or propagates a Rust panic across a C FFI boundary, the result is undefined behavior. In multi-tenant platforms where host code is shared, a single tenant can trigger undefined behavior in the host process affecting all tenants.

4. **Silent `throw` failure in loop**: The Cranelift codegen bug causes a `throw` inside certain loop patterns to silently not propagate. A tenant's module is designed with the expectation that a specific error condition terminates the module's execution path. Because the throw fails silently, the module continues executing past the expected termination, potentially reading or writing shared resources it should not reach after the error condition was detected.

The blast radius across all four adversaries concentrates in shared-runtime deployments. In single-tenant embedded WASM (one module, one host process, no other tenants), the risk is limited to correctness: the silent `throw` failure harms only the embedding application. In multi-tenant platforms — plugin hosts, FaaS runtimes, WASM-based policy engines — adversaries 1 and 2 allow inter-tenant data leakage through the exception channel, and adversary 3 allows single-tenant denial-of-service against the entire host process.

## Configuration / Implementation

### Wasmtime EH v2 feature gate

EH v2 is an opt-in feature in Wasmtime. Enable it through `Config`:

```rust
use wasmtime::{Config, Engine};

let mut config = Config::new();
config.wasm_exceptions(true);
let engine = Engine::new(&config)?;
```

The feature was experimental in Wasmtime 20–25 and stabilized in Wasmtime 26. "Stabilized" means the feature gate persists but the implementation is considered production-ready and the spec test suite passes. Before Wasmtime 26, enabling `wasm_exceptions` in production multi-tenant code requires explicit verification that the `catch_ref` tag validation fix is present in the specific version you are running.

Verify your CHANGELOG entry before upgrading:

```bash
# Clone or browse the CHANGELOG for your installed version
curl -s https://raw.githubusercontent.com/bytecodealliance/wasmtime/main/RELEASES.md \
  | grep -A 3 -i "catch_ref\|exception handling\|try_table"

# Check installed wasmtime version
wasmtime --version
```

If your CHANGELOG entry for the running version does not mention the `catch_ref` tag validation fix, treat all `catch_ref` usage in multi-tenant modules as potentially exploitable.

### Testing exception propagation at module boundaries

The following WAT module demonstrates a throw that must not propagate to a caller that does not declare a handler for that tag:

```wat
;; inner.wat — tenant module that throws a typed exception
(module
  (tag $myerr (param i32))       ;; define a tag with an i32 payload
  (func (export "do_work") (param $input i32) (result i32)
    local.get $input
    i32.const 0
    i32.eq
    (if (then
      i32.const 42
      throw $myerr               ;; throw when input is zero
    ))
    local.get $input
    i32.const 2
    i32.mul
  )
)
```

```wat
;; outer.wat — host-side module that calls inner without a catch for $myerr
;; This module MUST NOT silently swallow or mishandle inner's exception
(module
  (import "inner" "do_work" (func $inner_work (param i32) (result i32)))
  (func (export "run") (param $x i32) (result i32)
    ;; try_table with no catch for inner's tag — exception propagates to runtime
    (try_table (result i32)
      local.get $x
      call $inner_work
    )
  )
)
```

Run the isolation test and verify the runtime traps rather than silently continuing:

```bash
wasmtime run --invoke run outer.wat 0
# Expected: trap with unhandled exception
# If the process exits 0 with result 0, the throw silently failed — bug present
```

Use `wasm-tools smith` with the exceptions feature to fuzz module compositions:

```bash
wasm-tools smith --config exceptions-enabled=true -o fuzz_module.wasm
wasmtime run fuzz_module.wasm 2>&1 | grep -i "trap\|exception\|error"
```

### Validating `exnref` usage with wasm-tools

Before loading any untrusted WASM module that uses exception handling, validate it and audit its exception instructions:

```bash
# Validate that the module's exception instructions are well-formed
wasm-tools validate --features exceptions module.wasm

# Print all exception-related instructions for manual review
wasm-tools print module.wasm | grep -E '(try_table|throw|catch|exnref|throw_ref|catch_ref)'
```

In multi-tenant platforms where module boundaries are trust boundaries, consider rejecting modules that use `throw_ref`. The `throw_ref` instruction allows an `exnref` captured in one context to be re-thrown in another. While this is a legitimate language feature (useful for exception translation and chained handlers), it significantly complicates cross-module exception flow analysis. A policy that rejects `throw_ref` at load time is implementable with a wasm-tools pipeline:

```bash
# Reject modules containing throw_ref
if wasm-tools print module.wasm | grep -q 'throw_ref'; then
  echo "REJECTED: module uses throw_ref; not permitted in multi-tenant context"
  exit 1
fi
```

Integrate this check into your module admission pipeline before any `Engine::precompile_module` or `Module::new` call.

### Host-side exception safety in Rust

All calls into WASM from Rust host code must handle the `Trap` error that results from an unhandled WASM exception. An uncaught WASM exception surfaces as an `anyhow::Error` wrapping a `wasmtime::Trap`:

```rust
use wasmtime::{Engine, Linker, Module, Store};

fn call_wasm_entry(
    store: &mut Store<()>,
    instance: &wasmtime::Instance,
) -> Result<(), Box<dyn std::error::Error>> {
    let entry = instance
        .get_func(&mut *store, "entry")
        .ok_or("missing export: entry")?;

    let mut results = [];
    entry
        .call(&mut *store, &[], &mut results)
        .map_err(|e| {
            // Log the trap; do not propagate as a Rust panic
            eprintln!("WASM trap or exception: {:#}", e);
            e
        })?;

    Ok(())
}
```

Never allow a Wasmtime `call()` error to bubble up as a Rust `panic!`. A panic crossing a C FFI boundary (common in plugin hosts that expose a C API) is undefined behavior. Wrap all WASM call sites:

```rust
use std::panic;

let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
    entry.call(&mut store, &[], &mut results)
}));

match result {
    Ok(Ok(_)) => { /* success */ }
    Ok(Err(trap)) => { /* WASM trap — log and recover */ }
    Err(_panic) => { /* Rust panic — log, tear down store, do not propagate */ }
}
```

### Isolating exception state between tenants

Exceptions are contained within a Wasmtime `Store`'s call stack. An `exnref` created in a call on Store A cannot exist on Store B's stack because `Store` instances do not share memory, tables, or GC heaps. The critical rule: **one `Store` per tenant, never shared**.

```rust
// Correct: separate Store per tenant request
fn handle_tenant_request(engine: &Engine, module: &Module, input: &[u8]) {
    let mut store = Store::new(engine, ());  // fresh Store, isolated GC heap
    let instance = /* instantiate module in this store */;
    // ... call entry point, handle errors, drop store
}

// Wrong: reusing a Store across tenants
// let mut shared_store = Store::new(engine, ());
// Do NOT pass shared_store to multiple concurrent or sequential tenant calls
```

After a Wasmtime upgrade, verify Store isolation holds for EH v2 by running Wasmtime's spec test suite targeting exception handling:

```bash
cd /path/to/wasmtime
cargo test --test spec_testsuite -- exception 2>&1 | tail -20
```

A passing spec test suite is necessary but not sufficient — multi-store isolation tests are in `tests/all/` and worth running explicitly:

```bash
cargo test -p wasmtime-tests -- exception_isolation 2>&1
```

### Monitoring Wasmtime EH fixes

Set up a standing query to watch Wasmtime commits touching exception handling. Run this after each upstream release:

```bash
gh api repos/bytecodealliance/wasmtime/commits \
  --jq '.[] | select(.commit.message | test("exception|try_table|exnref|catch_ref|throw_ref"; "i")) | {sha: .sha[0:8], message: .commit.message}' \
  | head -20
```

Subscribe to Wasmtime's GitHub security advisories:

```bash
gh api repos/bytecodealliance/wasmtime/security-advisories \
  --jq '.[] | {ghsa_id, summary, published_at, severity}'
```

Tag your internal ticket system with the Wasmtime version when you enable EH v2, and create a recurring reminder to re-run the commit query after each Wasmtime release.

### V8 exception handling in Node.js

As of Node.js 22, the `--experimental-wasm-exnref` flag controls `exnref` support in V8. Check current status:

```bash
node --experimental-wasm-exnref -e "console.log('exnref enabled')" 2>&1
node -e "console.log(process.versions.v8)"
```

Node.js release notes list the V8 version embedded in each Node.js release. Cross-reference the V8 version against the Chromium security tracker to determine whether a specific EH v2 fix is present before enabling the feature in production Node.js workloads.

## Expected Behaviour

| Signal | Without EH v2 hardening | With mitigations |
|---|---|---|
| Cross-module exception propagation | Unhandled exception in tenant module propagates into host or adjacent module call frame with no interception; host may panic or process corrupted state | Separate `Store` per tenant contains exception to tenant's call stack; host `call()` returns `Err(Trap)` which is explicitly handled |
| `catch_ref` tag mismatch (unpatched runtime) | Module B's exception with wrong tag is caught by module A's `catch_ref` handler; A processes attacker-controlled payload bytes believing they are trusted | Wasmtime version with tag validation fix rejects the mismatched `exnref`; handler does not fire; exception propagates as unhandled trap |
| `throw` silent failure in loop (Cranelift bug) | Module continues executing past `throw` instruction; error-termination path is skipped; module accesses resources beyond expected lifetime | Patched Cranelift generates correct control flow; exception propagates; host receives `Err(Trap)`; module is terminated |
| Exception in host-unsafe call site | Unhandled `Trap` error propagates as Rust panic; if panic crosses FFI boundary, undefined behavior in host process | All `func.call()` sites wrapped in explicit error handling and `catch_unwind`; panic is caught, Store is dropped, tenant is isolated |
| Patch-gap exploitation window | Attacker submits module exploiting `catch_ref` tag validation bug; bug is public in GitHub commit; platform not yet upgraded | Module admission pipeline rejects `throw_ref` usage; `wasm-tools validate` runs at load time; Wasmtime upgrade cadence tracked against commit monitor |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| EH v2 feature gate | Access to fully specified, more expressive exception handling; better compiler integration than EH v1 | Feature was experimental in Wasmtime 20–25; stability guarantees weaker before Wasmtime 26; potential for silent behavioral changes across minor versions | Pin Wasmtime version in lockfile; verify CHANGELOG for EH-related entries before each upgrade; run spec test suite post-upgrade |
| Separate `Store` per tenant | Exception state, GC heap, and `exnref` objects are fully isolated between tenants; no cross-tenant exception leakage possible by construction | Memory overhead: each `Store` carries a GC heap and compiled instance state; high-request-rate platforms may see significant memory pressure | Profile Store memory usage under load; implement Store pooling for module instances that can be safely reset between tenants without sharing GC state |
| Rejecting `throw_ref` in multi-tenant modules | Eliminates the cross-frame re-throw attack vector; simplifies exception flow analysis; catch handlers only see exceptions thrown in their immediate call subtree | Limits module expressiveness; some legitimate patterns (exception translation, chained handlers) require `throw_ref`; rejecting it may break third-party modules | Maintain an allowlist of modules that have been manually audited for `throw_ref` safety; allow `throw_ref` only in modules that run in isolated single-tenant Stores |
| `wasm-tools validate` overhead per module load | Catches malformed exception handling instructions before execution; prevents runtime panics from invalid module structure | Validation of large modules adds latency to the module load path; in high-frequency module load scenarios (short-lived plugins) this is measurable | Cache validation results keyed by module content hash; validate once per unique module binary, not once per instantiation |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| EH feature gate not enabled | Module load fails with `invalid instruction` or `unknown opcode` when the WASM binary contains `try_table`, `throw`, or `exnref` instructions | `wasm-tools validate --features exceptions module.wasm` succeeds; `wasmtime` load without `wasm_exceptions(true)` fails with validation error | Enable `config.wasm_exceptions(true)` in the `Engine` config before calling `Module::new`; if running Wasmtime < 20, upgrade — EH v2 instructions are not available |
| Wasmtime version without `catch_ref` tag validation fix | A module's `catch_ref` handler fires for exceptions tagged differently than the declared handler tag; wrong handler processes exception payload; no runtime error or trap is generated | Write a WAT test module where module A throws tag `$t1` and module B has a `catch_ref` for tag `$t2`; B's handler must not fire; run the test and assert it traps | Upgrade Wasmtime to a version containing the "fix catch_ref tag validation" commit; verify via CHANGELOG; if upgrade is blocked, disable EH v2 or add load-time rejection of modules using `catch_ref` |
| `wasm-tools validate` rejects module using new EH instructions | Validation pipeline rejects a legitimate module because `wasm-tools` version predates the EH v2 spec finalization and does not recognize `try_table` or `exnref` | Run `wasm-tools --version` and compare against EH v2 support matrix in wasm-tools CHANGELOG; check if `--features exceptions` flag is required | Upgrade `wasm-tools` to 1.x release that includes EH v2 support; pass `--features exceptions` explicitly to the validate subcommand |
| Store isolation broken by shared GC objects crossing Store boundary | `exnref` or other GC-managed object created in Store A is somehow accessible in Store B, causing cross-tenant data leakage or a Wasmtime internal panic | This manifests as an assertion failure or panic inside Wasmtime's GC code; deterministic reproduction requires a test that passes an `exnref` from one Store's call into another | File a Wasmtime security issue immediately; as a workaround, disable EH v2 (`wasm_exceptions(false)`) until a patched release is available; audit all code paths that share `Engine` between tenants for accidental object sharing |

## Related Articles

- [WASM Component Model Security](/articles/wasm/wasm-component-model-security/)
- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [WASM Multi-Tenancy](/articles/wasm/wasm-multi-tenancy/)
- [WASM Plugin Threat Modeling](/articles/wasm/wasm-plugin-threat-modeling/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
