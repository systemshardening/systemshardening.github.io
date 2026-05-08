---
title: "Wasmtime Component String Transcoding OOB Read: CVE-2026-34941"
description: "CVE-2026-34941 leaks one byte of host memory per string transcoding call in Wasmtime's component model. Affects all architectures. Repeated calls enable multi-byte information disclosure from host memory adjacent to WASM linear memory."
slug: wasmtime-component-string-transcoding
date: 2026-05-04
lastmod: 2026-05-04
category: wasm
tags:
  - wasmtime
  - component-model
  - information-disclosure
  - cve
  - string-handling
personas:
  - platform-engineer
  - security-engineer
article_number: 446
difficulty: Advanced
estimated_reading_time: 10
published: true
layout: article.njk
permalink: /articles/wasm/wasmtime-component-string-transcoding/
---

# Wasmtime Component String Transcoding OOB Read: CVE-2026-34941

## The Problem

CVE-2026-34941 is an out-of-bounds read in Wasmtime's component model string transcoding path that leaks exactly one byte of host process memory per transcoding call. The vulnerability affects all architectures — x86_64 and aarch64 — and is distinct from CVE-2026-34971 (the aarch64-only Cranelift sandbox escape in the same April 2026 advisory batch), which allowed arbitrary read/write of host memory. CVE-2026-34941 is bounded: one byte per call, from a fixed location adjacent to the WASM linear memory allocation. Bounded does not mean safe. An attacker who can invoke the transcoding path in a loop can accumulate those bytes into a stream large enough to reconstruct secrets held in adjacent memory.

The WASM Component Model is the mechanism that allows independently compiled WASM modules to interoperate through a common interface description. Components publish and consume typed interfaces — functions, resources, and values — and the component runtime mediates the data exchange between them. String handling across component boundaries requires transcoding when the two components use different string encodings. A component compiled from Rust or Go defaults to UTF-8 strings. A component compiled from C#, JavaScript via AssemblyScript, or other languages that adopt the .NET or JavaScript string model defaults to UTF-16. When a UTF-16 component passes a string to a UTF-8 component, Wasmtime's transcoding layer reads the UTF-16 source bytes, converts each code unit to the corresponding UTF-8 sequence, and writes the result into the destination component's linear memory.

The off-by-one error lives in the loop that reads the UTF-16 source string. The transcoding code calculates the end of the source buffer based on the string's reported length in code units. The loop condition should terminate when the read pointer reaches the byte one past the final code unit — but the condition is off by one, allowing the loop to execute a final read one byte past the true end of the source UTF-16 string. That extra byte is not part of the WASM guest's linear memory allocation for the string. It is part of the host process's address space at the address immediately following the linear memory region — which, depending on the host's memory layout, may be the allocator's internal bookkeeping, another WASM component's linear memory, or arbitrary host heap data.

In a single-tenant embedding — a CLI tool, a development environment, or a single-user application — the leaked byte is likely from the host's own heap and does not represent a cross-tenant confidentiality breach. The host is leaking its own data to itself through a component it controls. This is still incorrect behaviour and can cause crashes if the adjacent byte happens to be on a guard page, but the practical security impact is low.

In a multi-tenant WASM runtime — a serverless compute platform, a WASM plugin host serving multiple customers, or an edge compute environment running untrusted modules from multiple organisations — the layout is different. The host allocates linear memory regions for each tenant's components. Depending on the allocator and the Wasmtime memory configuration, the byte immediately following one component's linear memory may belong to another component's allocation. When tenant A's UTF-16 component passes a string to a UTF-8 component and the transcoding leak fires, the leaked byte may come from tenant B's linear memory. In a multi-tenant context this is a cross-tenant information disclosure, achievable without any privileged access beyond the ability to submit a component that uses UTF-16 strings.

The repeated-call attack amplifies the leak. Each transcoding call leaks one byte. The specific byte is always the byte at offset `linear_memory_end + 0` — the byte immediately past the end of the source string buffer, which is itself at the end of the string allocation within linear memory. If the attacker can vary the string allocation offset within linear memory by controlling string length and content, or if the host reallocates linear memory between calls, different offsets become the adjacent byte. A systematic sweep of string lengths and allocation positions can map out a window of adjacent host memory over many calls. On a system that invokes transcoding operations at high frequency — for example, a serverless function that processes strings passed between a C# component and a Rust component on every request — the attacker's rate of byte accumulation is bounded only by the request rate.

CVE-2026-34971, the aarch64 sandbox escape in the same advisory, is a categorically different vulnerability: it allows arbitrary addressing of host memory, is limited to aarch64, and provides read and write access. CVE-2026-34941 is a fixed-offset, bounded, read-only leak that affects all architectures. The mitigations overlap in some areas — both are fixed in the same Wasmtime version bumps, and per-tenant process isolation addresses both — but they are independent vulnerabilities requiring independent analysis.

Affected versions: all Wasmtime releases with component model support through 42.0.1 on the 42.x track and 43.0.0 on the 43.x track, on all architectures.

## Threat Model

**Multi-tenant WASM embedding with cross-encoding component interaction.** The highest-risk scenario is a platform that runs WASM components from multiple tenants in a shared host process, and where components compiled from different language ecosystems — a C# or AssemblyScript component alongside a Rust or Go component — communicate through component model interfaces. The attacker submits a component that exports or imports a string-typed interface, triggers the transcoding path, and reads the single adjacent byte. By varying string lengths across repeated invocations, the attacker maps adjacent memory belonging to another tenant's component. The attacker needs no privileges beyond the ability to submit a WASM component to the platform — which is the platform's intended function.

**Host secret disclosure through heap adjacency.** The Wasmtime host process may allocate secrets — API keys, session tokens, database passwords, TLS private keys — on its own heap. Depending on the allocator's internal layout and the timing of allocations, host heap data may be adjacent to a component's linear memory region. The one-byte-per-call leak, accumulated across many transcoding calls, can reconstruct a secret that happens to be allocated adjacent to the linear memory at the time of the call. This does not require multi-tenancy: a single-tenant embedded runtime that passes secrets through host heap variables is also exposed if the memory layout places those variables adjacent to the component's linear memory.

**Repeated information disclosure building larger leaks.** A single leaked byte is rarely actionable. But transcoding calls are cheap, and a request rate of thousands per second accumulates hundreds of bytes per second of adjacent memory. A structured attack that controls the offsets of string allocations within linear memory — for example, by controlling the length of the string passed across the boundary — can walk the adjacent memory region systematically. Over minutes, an attacker operating at modest request rates can reconstruct tens of kilobytes of adjacent host process memory.

**Affected scope.** Any Wasmtime version from the component model GA release through 42.0.1 and 43.0.0, on x86_64, aarch64, and all other supported Wasmtime target architectures, when any component model function passes a string between a UTF-16 component and a UTF-8 component.

## Hardening Configuration

### 1. Patch Wasmtime

Patching is the only complete fix for CVE-2026-34941. The corrected transcoding loop reads exactly the bytes that belong to the source string and terminates without the additional read past the end of the buffer. No configuration option prevents the off-by-one from executing on unpatched Wasmtime.

The fixed versions are the same as those that address CVE-2026-34971: 40.0.4, 41.0.4, 42.0.2, and 43.0.1. Confirming either CVE is patched automatically confirms the other — the same version bump resolves both. Verify the current Wasmtime version in your dependency tree:

```bash
cargo tree -i wasmtime | head -10
```

Update `Cargo.toml` to a fixed release on your current track:

```toml
[dependencies]
wasmtime = "43.0.1"
wasmtime-wasi = "43.0.1"
```

For projects pinned to earlier tracks:

```toml
wasmtime = "42.0.2"
```

```toml
wasmtime = "41.0.4"
```

```toml
wasmtime = "40.0.4"
```

After updating the version constraint, refresh the lock file and verify the resolved version:

```bash
cargo update -p wasmtime
cargo tree -i wasmtime | head -5
```

The output must show the patched version. If an older version appears, a transitive dependency has a conflicting constraint. Identify it:

```bash
cargo tree -i wasmtime --edges features
```

Resolve the constraint conflict before treating the system as patched. Common sources include pinned versions of `wasmtime-wasi`, `wasmtime-component-macro`, or `wit-bindgen-rt` that depend on an older Wasmtime major version. Update those crates alongside Wasmtime, or vendor and patch them if upstream has not yet published a compatible release.

Rebuild the host binary after updating. Verifying that `Cargo.lock` contains the patched version is not sufficient — the previous deployed binary continues running until redeployed:

```bash
cargo build --release
```

Embed the Wasmtime version string in your binary's status output to verify that the correct version is running in production:

```rust
println!("wasmtime {}", wasmtime::VERSION);
```

### 2. Audit Cross-Encoding Component Interactions

Identify which of your deployed WASM components pass strings across an encoding boundary. The transcoding path is triggered specifically when a component using UTF-16 strings calls an interface function that expects UTF-8 strings, or vice versa. If all components in your deployment use the same string encoding, the vulnerable transcoding path is never executed — even on unpatched Wasmtime — because no cross-encoding call is made.

Components compiled from the following ecosystems default to UTF-16 strings in the component model:

- C# / .NET via `dotnet-wasm` or similar toolchains
- AssemblyScript
- JavaScript-derived components using `jco` with UTF-16 output

Components compiled from the following ecosystems default to UTF-8:

- Rust via `wit-bindgen`
- Go via `tinygo` with WASI component output
- Python via `componentize-py`

Inspect the WIT (WebAssembly Interface Types) definitions and the component binary to determine the string encoding each component declares. The `wasm-tools` binary can inspect component encoding declarations:

```bash
wasm-tools component wit mycomponent.wasm
```

Look for the string encoding annotation in the output. A component declaring `string-encoding=utf16` in its canonical options is a UTF-16 component; `string-encoding=utf8` is a UTF-8 component. An interface call from a `utf16` component to a `utf8` component triggers transcoding.

List all component pairs in your deployment that have cross-encoding calls. Where possible, eliminate the cross-encoding interaction by recompiling the UTF-16 component with a UTF-8 encoding option, or by introducing a shim component that normalises encoding before the downstream call. Reducing cross-encoding interactions reduces the attack surface regardless of whether the system is patched.

### 3. Per-Tenant Process Isolation

Running each tenant's WASM components in a separate OS process ensures that an OOB read from one tenant's transcoding call cannot access another tenant's address space. The OS enforces address space separation between processes — a read past the end of linear memory in process A cannot reach memory in process B. This mitigation applies equally to CVE-2026-34941 and CVE-2026-34971: both are contained by process isolation.

The architecture is a worker pool where the parent process manages routing and holds credentials, and child workers each run one tenant's components in isolation. A transcoding OOB read in a worker reads adjacent memory within that worker's own address space — which contains only the data for that tenant's current invocation:

```bash
cargo build --release --bin wasm-worker
```

The parent spawns one worker per tenant request and communicates over stdin/stdout or a Unix domain socket:

```rust
use std::process::{Command, Stdio};

fn spawn_worker(component_path: &str) -> std::process::Child {
    Command::new("/usr/lib/myapp/wasm-worker")
        .arg(component_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn worker")
}
```

The worker holds no secrets from other tenants and no host credentials. Cap the pool size based on the per-worker memory overhead — typically 30–60 MB per worker for the Wasmtime `Engine` and compiled module overhead before accounting for WASM linear memory allocations. A pool of 50 workers adds 1.5–3 GB of overhead. Measure under representative load before setting the cap.

### 4. Memory Layout Hardening with Guard Pages

Configure the Wasmtime host to allocate WASM linear memory with guard pages on both sides of the linear memory region. A read that goes one byte past the end of linear memory and lands on a guard page generates a segfault rather than silently returning adjacent data. This converts the CVE-2026-34941 information disclosure into a controlled crash — the transcoding call fails, the host's trap handler recovers, and no data is returned to the caller.

Wasmtime allocates guard pages by default, but the default size may be smaller than optimal. The guard region size is controlled per-`Config`:

```rust
let mut config = wasmtime::Config::new();
config.static_memory_guard_size(2 * 1024 * 1024);
config.dynamic_memory_guard_size(64 * 1024);
```

The `static_memory_guard_size` applies to statically sized linear memories (the default configuration for most WASM modules). The `dynamic_memory_guard_size` applies to memories that grow at runtime via `memory.grow`. Both guard regions should be large enough that a one-byte OOB read reliably lands within the guard rather than in adjacent mapped memory. The default Wasmtime values are 2 MB for static guard regions and 64 KB for dynamic guard regions; these defaults already cover a one-byte OOB read unless the system is running under extreme memory pressure that has caused the OS to reclaim the guard pages.

Verify that guard pages are active in your configuration by examining the memory layout of a running Wasmtime process:

```bash
cat /proc/$(pgrep -n wasm-worker)/maps | grep -A1 -B1 "00000000"
```

Guard pages appear as regions with no permissions (`---p`) immediately following the linear memory region (`rw-p`). Confirm that the permission-less region exists and covers at least the size configured in `static_memory_guard_size`.

### 5. String Encoding Standardisation

Standardise all components in your deployment on UTF-8 strings to eliminate cross-encoding transcoding entirely. If no component uses UTF-16 strings, the transcoding path is never invoked and CVE-2026-34941 cannot be triggered regardless of the Wasmtime version. This removes the attack surface rather than mitigating the vulnerability.

For components compiled from Rust, encoding is UTF-8 by default with `wit-bindgen`. For components compiled from C# or AssemblyScript, check whether the toolchain supports overriding the default string encoding:

```bash
wasm-tools component new mylib.wasm \
  --adapt wasi_snapshot_preview1=wasi_snapshot_preview1.reactor.wasm \
  -o mycomponent.wasm
```

The `wasm-tools component` toolchain allows specifying canonical option overrides. Consult the toolchain documentation for the specific component compiler in use — not all compilers expose string encoding as a configurable option. Where recompilation is not feasible, a thin shim component written in Rust can accept the UTF-16 component's interface, transcode internally (using patched Wasmtime or a Rust-level transcoding library), and re-export a UTF-8 interface to downstream components. This concentrates the cross-encoding interaction in a controlled, reviewable location rather than leaving it implicit in the component model runtime.

After standardising to UTF-8, verify that no remaining component declares UTF-16 encoding:

```bash
for f in components/*.wasm; do
  echo "$f:"
  wasm-tools component wit "$f" | grep -i "string-encoding" || echo "  (no explicit encoding declared)"
done
```

## Expected Behaviour After Hardening

After patching to Wasmtime 40.0.4, 41.0.4, 42.0.2, or 43.0.1, the transcoding loop reads exactly the bytes that belong to the UTF-16 source string. The off-by-one is corrected at the loop boundary condition. The byte immediately past the end of the source string buffer is never read — no adjacent host memory is accessed during transcoding. The transcoding call completes correctly and no information is disclosed.

After per-tenant process isolation, a transcoding OOB read in one tenant's worker process reads memory within that worker's own address space. No other tenant's data is accessible from within the worker's address space — the OS enforces this boundary independently of Wasmtime or the component model. The parent orchestrator detects a crashing worker through the child process exit status and replaces it with a fresh worker without affecting other tenants.

After guard page configuration, an OOB read that lands on the guard region immediately past linear memory generates a segfault. Wasmtime's signal handler catches the segfault and converts it to a WASM trap, which is surfaced to the host as an error return from the component call. No byte is returned to the caller. The host can discard the component instance and log the trap for investigation. The information disclosure is suppressed.

## Trade-offs and Operational Considerations

Per-tenant process isolation increases memory overhead proportionally to the number of concurrent tenants. A system that previously shared one `Engine` and compiled module cache across 200 concurrent component instances now runs 200 separate worker processes. Measure the per-worker RSS under representative load. The overhead for a minimal Wasmtime worker is typically 30–60 MB per process before accounting for the WASM linear memory allocation itself. At 200 workers, this is 6–12 GB of overhead before WASM workloads, which may not be feasible on all hardware. Apply this isolation only where cross-tenant isolation is a requirement; single-tenant embeddings do not need per-invocation process separation.

Guard pages are configured per-`Config` in Wasmtime and the default sizes are already appropriate for a one-byte OOB read. Increasing the guard size beyond the default consumes additional virtual address space. On 64-bit systems, virtual address space is not a practical constraint; on 32-bit WASM targets (where applicable), large guard regions consume a meaningful fraction of the 4 GB address space. The default values are the correct choice for most deployments.

UTF-8 standardisation eliminates the cross-encoding transcoding attack surface but requires recompilation or wrapping of components that default to UTF-16. AssemblyScript and C# toolchains may not expose string encoding as a compile-time option in all versions. Wrapping adds a thin transcoding shim that reintroduces the transcoding path — but in a controlled, auditable location where the patch status is explicit and the shim can be tested independently. The operational overhead of maintaining a shim layer must be weighed against the benefit of eliminating the implicit transcoding path from the component model runtime.

## Failure Modes

**Patching both CVE-2026-34941 and CVE-2026-34971 requires the same Wasmtime version bump.** The fixed versions for both CVEs are identical: 40.0.4, 41.0.4, 42.0.2, and 43.0.1. Verifying that one CVE is patched automatically verifies the other. The minimum acceptable version on any track is 40.0.4. A deployment showing `wasmtime 40.0.3` or earlier is unpatched for both. If `cargo tree -i wasmtime` shows a version older than the patched release on your track, the system is exposed to both vulnerabilities and the fix for both requires the same version update.

**Process isolation implemented but a shared memory segment used for IPC.** A common optimisation for high-throughput WASM worker pools is a shared memory region used to exchange large payloads between the parent and child workers without copying through stdin/stdout. If this shared segment is mapped into multiple worker processes, it is accessible from all of them. A transcoding OOB read in worker A that lands within the shared segment can read data placed there by worker B or the parent — partially defeating the cross-tenant isolation that process separation was intended to provide. Audit all inter-process communication mechanisms in the worker pool design. Remove shared memory segments or ensure they contain no tenant-specific data.

**Guard pages configured but host heap allocates sensitive data adjacent to the guard region.** The guard page converts an OOB read into a segfault only if the read lands within the guard region. Wasmtime's OOB read from CVE-2026-34941 is exactly one byte past the end of the source string buffer, which is within the linear memory region — not at the absolute end of linear memory. The guard page sits at the end of the linear memory allocation. If the OOB byte is within the linear memory allocation but past the end of the string buffer, the guard page is not between the leaked byte and the attacker's request. Guard pages protect against reads past the end of the entire linear memory region but do not protect against reads within the linear memory region at positions the guest did not intend. The primary mitigation for the CVE-2026-34941 read — which is within the linear memory allocation — is patching the off-by-one; guard pages protect against adjacent host memory leaks if the OOB read extends past the linear memory boundary.

## Related Articles

- [Wasmtime aarch64 Sandbox Escape](/articles/wasm/wasmtime-aarch64-sandbox-escape/)
- [Wasmtime Async DoS Security](/articles/wasm/wasmtime-async-dos-security/)
- [WASM Component Model Security](/articles/wasm/wasm-component-model-security/)
- [WASM Multi-Tenancy](/articles/wasm/wasm-multi-tenancy/)
- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
