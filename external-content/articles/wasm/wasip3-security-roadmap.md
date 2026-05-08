---
title: "WASI Security Roadmap: Preview 2, WASIp3 Async, and Upcoming Security Proposals"
description: "WASI Preview 2 stabilised the Component Model and capability-based I/O. WASIp3 introduces async/await with capability-safe concurrency. This guide covers the security implications of each WASI generation, upcoming proposals (wasi-crypto, wasi-nn, wasi-keyvalue), and how WASI's capability model evolves toward zero-ambient-authority WASM systems."
slug: wasip3-security-roadmap
date: 2026-05-07
lastmod: 2026-05-07
category: wasm
tags:
  - wasi
  - wasip3
  - wasi-preview2
  - capability-security
  - wasm-roadmap
personas:
  - security-engineer
  - platform-engineer
article_number: 593
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/wasm/wasip3-security-roadmap/
---

# WASI Security Roadmap: Preview 2, WASIp3 Async, and Upcoming Security Proposals

## The Problem with How WASI Evolved

WASI started as a portability story, not a security story. The original design goal in 2019 was to give WASM a way to run outside the browser — to open files, read the clock, get environment variables — without becoming a full Linux ABI. That design, now called WASI Preview 1, delivered portability but made significant security concessions that are only becoming visible as WASM moves into production infrastructure.

WASI Preview 1 modelled access as a flat import namespace: a module either imported `path_open` or it did not. If it did, the runtime handed it a set of preopened directory file descriptors, and the module could attempt to open any path relative to those directories. There was no ability to grant narrower filesystem access — read-only on `/data`, write access on `/tmp/work` only — without building that policy into the host application by hand. `sock_connect` was all-or-nothing for TCP. `environ_get` exposed the full process environment. The granularity was coarse and the audit surface was opaque: inspecting a binary to understand what it would do required tracing through every import it declared, with no typed semantics attached to any of them.

Security engineers who cared about capability discipline used WASM because of its memory isolation model — linear memory with no ambient access to host heap or OS structures — but despite, not because of, WASI's permission model. You could limit what a module did by carefully withholding host functions, but you could not express intent or enforce it mechanically.

WASI Preview 2, WASI Preview 3 (in development), and a growing set of domain-specific proposals are fixing this, generation by generation. Each generation makes it harder to accidentally over-grant access, and each generation adds domain-specific APIs that allow entire classes of sensitive operations to be performed through the WASI interface rather than in untrusted WASM code. This article covers what each generation changes for security, what the current gaps are, and how to deploy securely today while the roadmap matures.

**Target systems:** Wasmtime 22+ (full Preview 2 support), Spin 2.0+, wasmCloud 1.0+, WasmEdge 0.13+ (partial Preview 2 plus experimental wasi-crypto). Toolchains: `cargo component` (Rust), `wit-bindgen` (multi-language), `componentize-py`, `componentize-js`.

## Threat Model

- **Adversary 1 — Capability escalation via composition:** A malicious component declares a narrow WIT world but, when composed with a platform component, inherits the platform's broader imports. The composed artifact has more capabilities than either party intended.
- **Adversary 2 — Async race via shared resource handles:** Under WASIp3's async model, two concurrent tasks in the same component both hold borrows of the same capability handle. A use-after-free or TOCTOU arises if the resource is consumed by one task while the other is mid-operation.
- **Adversary 3 — Ambient authority through proposal stacking:** A component uses `wasi-config` to read a secret at startup, holds it in linear memory, and passes it to a call in `wasi-nn`. Neither interface individually over-grants, but together they exfiltrate model weights or inference results to an external party via `wasi:http/outgoing-handler`.
- **Adversary 4 — Inference poisoning via `wasi-nn`:** A component with `wasi-nn` access loads a model from a path in the preopened directory. An attacker who can write to that path substitutes a poisoned model. The component runs inference with attacker-controlled weights.
- **Access level:** Adversaries 1 and 4 require component upload or filesystem write access. Adversary 2 requires the ability to submit concurrent requests. Adversary 3 requires composing components with independent capability grants.
- **Objective:** Obtain capabilities not intended by the embedder, corrupt cryptographic or ML operations, or combine narrow capabilities into a broader attack surface.
- **Blast radius:** Bounded to the capabilities the runtime instantiates the component with — but the combinations matter as much as the individual grants.

## WASI Preview 1: What Was Missing

Preview 1 (the `wasi_snapshot_preview1` import namespace) predates the Component Model. It is a flat list of approximately 50 functions — a POSIX subset. Its security weaknesses are structural:

**No typed authority.** The only security boundary was whether a function was linked or not. There was no way to say "filesystem read but not write" at the WASI level; that required the host to implement custom logic on top of preopened directory handles.

**No auditable contract.** A `wasm-tools dump` of a Preview 1 module showed its imports, but without semantic meaning attached to each name. `path_open` tells you a module can open files; it does not tell you which files, under what conditions, or what it does with them. The WIT type system (introduced in Preview 2) adds that layer.

**Blocking I/O throughout.** Preview 1 assumed synchronous execution. The `poll_oneoff` function provided a minimal poll-like mechanism, but the ecosystem largely ignored it. The result is that host-side concurrency required running each blocking WASM call in its own thread, with all the shared-state hazards that implies.

**Ad-hoc environment access.** `environ_get` returned the full environment of the host process. There was no scoping — a component that imported this function could read `DATABASE_PASSWORD`, `AWS_SECRET_ACCESS_KEY`, or any other variable the host had set. Most hosts worked around this by launching WASM components in a subprocess with a sanitised environment, which is operationally correct but not a platform-level capability.

These are not criticisms of Preview 1's intent. It was a pragmatic first step. But deploying Preview 1 components in security-sensitive environments required custom hardening on top of every gap, and that hardening was invisible to the component author.

## WASI Preview 2: Security Advances

Preview 2 (shipped as stable through 2024–2025) rewrites the capability model from the ground up using the Component Model and WIT (WebAssembly Interface Types).

### The Component Model as a Security Boundary

A Preview 2 component is a binary artifact that carries its own WIT world — a precise declaration of every interface it imports and every interface it exports. Unlike Preview 1 modules, which used untyped function imports with no enforced relationship between them, a component's imports are versioned, namespaced, and typed. `wasi:filesystem/types@0.2.0` is not just a name; it is a typed resource interface with defined operations, resource lifetimes, and error semantics.

The security consequence: the WIT world is auditable at build time. Before a component is ever executed, you can extract its full import surface with:

```bash
wasm-tools component wit ./component.wasm
```

The output is a WIT document that enumerates every capability the component requires. An upload pipeline can parse this document and compare it against a policy allowlist before the component is stored or deployed. A component that imports `wasi:sockets/tcp@0.2.0` when the policy permits only `wasi:http/outgoing-handler@0.2.0` is rejected at upload — before it runs a single instruction.

### Capability-Based Resources

In Preview 2, resources are first-class typed values. A filesystem access is not a function import that the runtime decides to honor or not — it is a `descriptor` resource that the host explicitly constructs and passes to the component. The component cannot construct a descriptor by itself; it has no mechanism to conjure a capability that the host did not provide.

This implements object-capability discipline at the ABI level:

- **Filesystem:** `wasi:filesystem/types.descriptor` resources are passed to components via preopened directories. A component that receives a descriptor for `/data/tenant-a` cannot use it to open `/data/tenant-b`. The descriptor is the capability; it encodes the allowed root.
- **Sockets:** `wasi:sockets/tcp.tcp-socket` is a resource that the host creates and passes. Creating a socket requires the host to call `create-tcp-socket`, which only the host can do. A component that holds no socket resource cannot initiate a TCP connection.
- **Clocks:** `wasi:clocks/wall-clock@0.2.0` and `wasi:clocks/monotonic-clock@0.2.0` are separate imports. A component that needs only elapsed time for rate-limiting does not need to import wall-clock at all, removing its ability to observe absolute time (relevant for timing side-channels and fingerprinting).
- **HTTP:** `wasi:http/outgoing-handler@0.2.0` is a separately importable interface from raw sockets. Allowing a component to make HTTP calls without granting it raw TCP access enables application-layer filtering: the host can intercept outgoing HTTP requests, check the target URL, and reject requests to disallowed destinations before the connection is made.

Each of these is a separate capability that can be granted independently. A component that needs to write a log file but should not make network calls gets `wasi:filesystem/types` and nothing else. The runtime enforces this at instantiation; there is no runtime configuration to forget or misapply.

### Embedder-Side Capability Enumeration

The critical shift in Preview 2 is that capability policy is decided once, at component instantiation, rather than per-syscall at runtime. The host builds a `WasiCtx` that encodes exactly what the component is allowed to do:

```rust
let wasi = WasiCtxBuilder::new()
    // Filesystem: read-only access to /data only.
    .preopened_dir(
        cap_std::fs::Dir::open_ambient_dir("/data/tenant-a", ambient_authority())?,
        DirPerms::READ, FilePerms::READ, "/data"
    )?
    // No env vars.
    // No CLI args.
    // Outbound HTTP to a specific internal host only.
    .build();
```

A component instantiated against this context cannot escalate beyond it regardless of what code it runs. The capability surface is encoded in the host-side context object, not in the component's behavior.

## WASIp3 and the Async Security Model

WASIp3 (in active development as of 2026) introduces a native async/await model to the Component Model. This is not just a performance feature — it changes the security properties of capability use in fundamental ways.

### The Problem WASIp3 Solves

Preview 2 is synchronous. When a WASM component calls a WASI function that involves I/O — opening a file, making an HTTP request, waiting on a socket — the entire component execution blocks until the I/O completes. The host uses OS threads to multiplex concurrently, but within the WASM layer there is no cooperative concurrency model. This has two security consequences:

1. **DoS via blocking I/O.** A component can delay its response indefinitely by blocking on an I/O operation, consuming a host thread for the duration. In a serverless environment where host threads are bounded, a small number of slow components can exhaust the thread pool.
2. **No backpressure on capability use.** A component that opens 10,000 file descriptors in a tight loop holds all of them simultaneously, with no opportunity for the host to interpose and enforce resource limits between iterations.

WASIp3 introduces native async functions in WIT and a `streams`, `future`, and `task` model for composing concurrent operations. Components can now perform concurrent I/O within a single execution context, yield between operations, and propagate errors across async boundaries.

### Capability Safety in Concurrent Contexts

The security challenge WASIp3 introduces is concurrency over shared capability resources. In synchronous Preview 2, a component holds a file descriptor, uses it, and drops it — the sequence is linear and the resource lifetime is clear. In an async context, two concurrent tasks within the same component might both hold borrows of the same descriptor, or one task might complete and drop a descriptor while another task is mid-read.

WASIp3's type system addresses this through `borrow` vs `own` semantics that carry directly into the async model:

- An `own<descriptor>` resource may only be used by one task at a time. Passing it to an async function transfers ownership; the caller may not use it again until the callee returns or the future completes.
- A `borrow<descriptor>` is valid only within the lexical scope of the function that has an own. It cannot outlive the own. A task that borrows a descriptor from a parent scope cannot store it past the point where the parent drops the own.

These rules are enforced by the WIT type system and the runtime. They prevent the most common TOCTOU pattern: check-then-use with a descriptor that has been revoked or replaced between the check and the use.

### Cancellation Safety

The most operationally tricky security property of async WASI is cancellation. When a host cancels an in-flight component call — because a request deadline expired, a client disconnected, or a resource limit fired — the component's async task must be unwound cleanly. In WASIp3's model, cancellation is explicit: a `cancel` operation on a task triggers cancellation at the next poll point, and the component's async functions are expected to handle cancellation by releasing capability resources before exiting.

A component that does not release descriptors on cancellation accumulates resource-table entries on the host. The host caps the resource table per component instance and returns an error when the limit is exceeded — but a slow leak under normal operation can reach the limit before any individual cancellation, causing legitimate operations to fail.

The hardening pattern is to use `with`-style resource blocks (RAII in Rust, context managers in Python) so that capability handles are released even when the execution path is unusual:

```rust
// Async-safe resource management: descriptor released on cancel or error.
async fn process_entry(storage: &Storage, key: &str) -> Result<Value> {
    let descriptor = storage.open(key).await?;
    // descriptor dropped when this scope exits — normal return, error, or cancel.
    let value = descriptor.read_all().await?;
    Ok(value)
}
```

### Error Propagation Across Async Boundaries

WASIp3 introduces a typed error model for async operations: errors that occur in async functions cross component boundaries as typed `result` values rather than untyped trap codes. This is a security improvement over Preview 2's pattern where some WASI errors produced traps that were indistinguishable from memory faults.

From a security perspective, typed error propagation matters because it allows the host to distinguish "the component encountered a permissions error" from "the component hit a runtime fault." Permission errors can be logged and allowed (the component behaved correctly, just without sufficient capability), while runtime faults warrant instance termination and incident review.

## Upcoming Security-Relevant WASI Proposals

Several proposals in the WASI standardisation process are specifically motivated by security requirements. Each one delegates a sensitive operation to the host, removing it from untrusted WASM code where it cannot be adequately protected.

### wasi-crypto

`wasi-crypto` defines cryptographic primitives — symmetric encryption, asymmetric signing and verification, key derivation, hashing, and random generation — as host functions exposed through a WASI interface. The security rationale is straightforward: cryptographic operations implemented in pure WASM inherit the timing uncertainty of JIT compilation. A host-side implementation uses hardware acceleration (AES-NI, SHA extensions) and a constant-time implementation validated for the actual CPU.

A component that uses `wasi-crypto` for AES-GCM encryption calls a host function; the JIT never touches the key-dependent computation. The constant-time guarantee holds because the host, not the JIT, executes the cipher.

The current status as of mid-2026: `wasi-crypto` is implemented in WasmEdge 0.13+ and has a Wasmtime implementation behind a feature flag. It is not yet in the WASI 0.2.x standard. Embedders who need it today use a custom host function in place of the standardised interface.

For deployments that need crypto now, the approach is to gate crypto operations behind a capability check at component load time:

```bash
# Verify component does not implement its own crypto using in-WASM libraries.
wasm-tools validate --features component-model ./payments.wasm
wasm-tools component wit ./payments.wasm | grep -E 'import.*(ring|openssl|aes|sha256)'
# If any in-WASM crypto imports are found, require migration to wasi-crypto.
```

### wasi-nn

`wasi-nn` provides neural network inference as a WASI interface. A component submits a model (by graph name or graph bytes) and input tensors; the host runs inference using the native ML framework (ONNX Runtime, OpenVINO, TensorFlow Lite) and returns output tensors.

The security implications for AI workloads are significant:

**Model integrity.** Under `wasi-nn`, the model is loaded by the host from a path in the component's preopened directory, or by name from a host-managed registry. Either way, the host controls the model source. An adversary who can write to the model path can substitute a poisoned model, but this requires write access to the preopened directory — a capability the component should not hold. Separate the read path for model loading from the write path for data processing:

```rust
// Host configuration: model dir is read-only, input dir is read-write.
let mut wasi = WasiCtxBuilder::new();
wasi.preopened_dir(model_dir, DirPerms::READ, FilePerms::READ, "/models")?;
wasi.preopened_dir(input_dir, DirPerms::all(), FilePerms::all(), "/data")?;
```

**Inference result integrity.** Output tensors from `wasi-nn` are returned to the component as a typed capability resource. The component can read tensor data from the resource but cannot modify the model or host-side state. Compared to running inference code directly in WASM, this contains any memory corruption within the component's linear memory rather than allowing it to affect model state.

**Tensor input validation.** `wasi-nn` does not validate input tensor shapes against model expectations on the component side. A component that passes malformed inputs can cause the host-side inference engine to behave unexpectedly — including potential host-side crashes in ML frameworks not written with adversarial inputs in mind. Validate tensor shapes and dtypes in the component before passing them to `wasi-nn`.

### wasi-keyvalue

`wasi-keyvalue` provides a typed key-value store interface: `get`, `set`, `delete`, `exists`, and an atomic `compare-and-swap`. The interface is abstract over the backing store — the host can implement it against Redis, etcd, an in-memory map, or a filesystem — but the access control model is defined at the capability level.

The security advance over raw file I/O: a component with `wasi-keyvalue` access cannot list arbitrary keys or perform range scans unless the interface explicitly provides those operations. The `open-bucket` call returns a `bucket` resource scoped to a named bucket, and the component can only operate on keys within that bucket. There is no mechanism to escape the bucket through path traversal or directory enumeration because the key-value model has no directory semantics.

```wit
// wasi-keyvalue interface — access is bucket-scoped.
interface store {
  resource bucket {
    get: func(key: string) -> result<option<list<u8>>, error>;
    set: func(key: string, value: list<u8>) -> result<unit, error>;
    delete: func(key: string) -> result<unit, error>;
    exists: func(key: string) -> result<bool, error>;
  }
  open: func(identifier: string) -> result<bucket, error>;
}
```

A component granted a `wasi-keyvalue` bucket capability is limited to that bucket. It cannot access keys in another bucket, read host filesystem state, or observe the key namespace beyond what the bucket interface exposes. This is a narrower and more auditable access grant than giving the component a preopened directory and a file-per-key pattern.

### wasi-config

`wasi-config` provides secure configuration injection as a WASI interface. Instead of reading configuration from the process environment (which exposes the full environment) or from a filesystem path (which requires a preopened directory), a component calls `wasi-config` functions to retrieve named configuration values that the host has explicitly injected.

The security model: the host constructs a config context at instantiation time, enumerating exactly which keys the component can retrieve. A component that calls `config.get("DATABASE_URL")` gets the value if the host included it; it gets an error if not. It cannot enumerate all available keys, cannot read keys the host did not include, and cannot distinguish "key does not exist" from "key exists but you are not allowed to see it" (both return an absence result).

This is strictly better than `wasi:cli/environment@0.2.0` for secrets injection. With the environment interface, a component can enumerate all variables in its environment. With `wasi-config`, the host controls both the presence and the visibility of each configuration value.

Sensitive secrets — database credentials, API keys, TLS private keys — should be injected via `wasi-config` rather than environment variables, even in Preview 2 environments where `wasi-config` is not yet stable. The interim pattern is a custom host function that provides the same named-key semantics:

```rust
// Custom config host function until wasi-config is stable.
linker.func_wrap("env", "config_get", |mut caller: Caller<_>, key_ptr: i32, key_len: i32| -> i32 {
    let key = read_string_from_memory(&caller, key_ptr, key_len)?;
    let value = CONFIG_MAP.get(&key).cloned().unwrap_or_default();
    write_string_to_memory(&mut caller, &value)
})?;
```

## The Zero-Ambient-Authority Goal

The long-term security direction of WASI is zero ambient authority: a component that is instantiated with no capability grants should have no access to any host resource, no network connectivity, no filesystem access, no ability to read the time or generate random numbers. It should be able to perform only pure computation on data passed in through its exported functions.

Preview 2 is close to this goal for core system resources. A component with an empty `WasiCtx` — no preopened directories, no socket permissions, no HTTP handler — cannot access any of those resources. The remaining gaps are:

**Random number generation.** `wasi:random/random@0.2.0` is available as an import without requiring a specific capability resource. Any component that imports this interface can generate cryptographically random bytes. This is typically desirable, but it means random entropy is not currently a zero-ambient capability — you cannot instantiate a component that uses `wasi:random/random` and deny it entropy without removing the import.

**Clock access.** `wasi:clocks/monotonic-clock@0.2.0` allows a component to observe elapsed time, which can be used as a side-channel timing oracle. Denying clock access entirely breaks most real-world workloads, but clock access is not currently a zero-cost grant — there is no fine-grained policy over the resolution or range of time exposed.

**Exit codes.** `wasi:cli/exit` allows a component to terminate the process. For embedded components in a multi-component host, this is dangerous: a buggy component can terminate the host. The mitigation is to override the exit host function to return a trap rather than calling `std::process::exit`, but this requires host-side customisation.

**Pre-proposal interfaces.** Domain-specific proposals like `wasi-nn` and `wasi-crypto` are not yet stable, meaning they are not in the auditable WIT world that tooling like `wasm-tools component wit` understands. A component that uses experimental interfaces may have capabilities that do not appear in its formal world — which breaks the auditability guarantee.

The zero-ambient-authority goal is achievable within the current Preview 2 model for most threat models if you enforce it at the embedder level. The gaps above are known, tracked in the WASI issue tracker, and expected to be addressed as the proposals mature.

## Deploying Against WASI Preview 2 Today

Given the state of the roadmap, the practical security guidance for 2026 deployments is:

**Validate WIT worlds at upload.** Use `wasm-tools component wit` to extract the world of every component before it is stored or deployed. Compare the world against an allowlist. Reject components that import interfaces not on the allowlist. This is the single highest-leverage security control available in the current tooling.

```bash
wasm-tools component wit ./component.wasm > /tmp/world.wit
diff /tmp/world.wit /path/to/approved-world.wit || \
  { echo "REJECTED: component world does not match policy"; exit 1; }
```

**Scope filesystem grants minimally.** Preopened directories are the primary vector for filesystem over-grant. Each tenant or workload should receive a preopened directory scoped to its own data partition, with permissions (read/write/create) scoped to what the workload actually requires.

**Separate HTTP from raw sockets.** Import `wasi:http/outgoing-handler` rather than `wasi:sockets/tcp`. HTTP allows host-side request interception and URL filtering; raw TCP does not. If a component needs HTTP, it does not need raw TCP.

**Inject secrets via host functions pending `wasi-config`.** Until `wasi-config` is stable and your runtime supports it, implement a custom host function for named configuration retrieval. Do not use `wasi:cli/environment` for secrets.

**Pin interface versions.** `wasi:filesystem/types@0.2.0` is a different interface than `wasi:filesystem/types@0.2.1`. Pin component builds and runtime versions to known-good combinations. Upgrade in coordinated waves — component build, host runtime, policy allowlist — not independently.

**Audit composed artifacts.** When two components are composed, run `wasm-tools component wit` on the composed artifact, not just the individual components. Composition can introduce imports from the inner component's world that were not visible from the outer component's perspective alone.

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| WIT world auditability | Upload-time policy enforcement before execution | Requires tooling in the upload pipeline | Bake `wasm-tools component wit` into the upload gate; reject on policy mismatch. |
| Capability-based resources | No ambient access; over-grant requires explicit host action | More host-side setup per instantiation | Generate `WasiCtxBuilder` from a per-tenant config struct; reuse the pattern. |
| wasi-crypto (experimental) | Timing-safe cryptography via host primitives | Not yet stable; implementation varies by runtime | Use where available (WasmEdge 0.13+); fall back to custom host functions with the same interface. |
| wasi-nn model loading | Host controls model source; component cannot substitute models | Host must manage model registry and path isolation | Separate preopened directories: read-only for models, read-write for data. |
| WASIp3 async cancellation | Cooperative cancellation reduces thread exhaustion DoS | Components must manage resource cleanup on cancel | RAII/context-manager patterns ensure descriptors are released regardless of cancellation path. |
| Zero-ambient-authority gaps | Current gaps are small and well-understood | Clock and random entropy are not zero-cost | Accept entropy as ambient for now; deny clock precision via host-side override where needed. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Component imports unapproved interface | Policy violation not caught at upload | Component runs with unexpected capabilities in production | Add upload-gate validator; run `wasm-tools component wit` on all stored artifacts retroactively; reject violators. |
| Composed artifact inherits over-broad capabilities | Composed component has more capabilities than the policy intends | `wasm-tools component wit` of composed artifact shows unexpected imports | Audit composition explicitly; restrict the platform component's imports to match actual tenant needs. |
| `wasi-nn` model path not isolated | Component with write access to `/models` can substitute model files | Observe unexpected inference results; audit filesystem access patterns | Separate preopened dirs for models (read-only) and data (read-write). |
| Async descriptor leak on cancellation | Resource-table grows monotonically; legitimate operations fail with resource-limit errors | Monitor resource-table size per component instance over time | Adopt RAII resource management; set host-side resource-table caps and alert at 80% utilisation. |
| Secrets in `wasi:cli/environment` | Component can enumerate all env vars, including unrelated secrets | Code review; WIT world shows `wasi:cli/environment@0.2.0` import | Migrate to `wasi-config` or custom named-config host function; remove environment import from allowlist. |
| Interface version mismatch between component and runtime | Instantiation fails with type-check error | Deployment failure logs show WIT type mismatch | Pin component WIT versions and runtime versions in deploy manifest; upgrade in coordinated waves. |

## Related Articles

- [WASI Preview 2 Capability-Based Security](/articles/wasm/wasi-preview-2-capabilities/)
- [Cryptographic Algorithm Implementations in WASM](/articles/wasm/wasm-crypto-implementations/)
- [Wasmtime Async Component DoS](/articles/wasm/wasmtime-async-dos-security/)
- [WASM Component Model Security Boundaries](/articles/wasm/wasm-component-model-security/)
- [WASM AI Inference Security](/articles/wasm/wasm-ai-inference/)
- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
