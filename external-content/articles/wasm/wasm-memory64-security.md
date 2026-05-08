---
title: "WASM memory64 Security Implications"
description: "Analyze security implications of the WebAssembly memory64 proposal—64-bit linear memory, integer overflow risks, pointer arithmetic, and tracking silent security fixes in Wasmtime and V8."
slug: wasm-memory64-security
date: 2026-05-02
lastmod: 2026-05-02
category: wasm
tags: ["wasm", "memory64", "linear-memory", "integer-overflow", "wasmtime", "v8", "sandbox"]
personas: ["security-engineer", "platform-engineer", "systems-engineer"]
article_number: 342
difficulty: advanced
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/wasm/wasm-memory64-security/index.html"
---

# WASM memory64 Security Implications

## Problem

Classic WebAssembly (memory32) defines all memory addresses as `i32` values, capping linear memory at 4 GiB. That hard ceiling is not merely a capacity constraint — it is a structural part of the sandbox model. Because the addressable range is small, Wasmtime and other runtimes can allocate a virtual address reservation (typically 8 GiB on 64-bit hosts) and place OS guard pages immediately after the WASM linear memory region. When a WASM module performs an out-of-bounds load or store, the access falls into the guard region, the OS raises a segmentation fault, and the runtime converts that fault into a WASM trap. The host process memory is never touched. The security invariant is enforced partly by the OS virtual memory subsystem rather than by explicit runtime bounds-check instructions on every memory access, giving memory32 runtimes acceptable performance without sacrificing correctness.

The memory64 proposal changes this foundation. Addresses become `i64`, and the theoretical upper limit is 2^64 bytes of linear memory. Memory64 reached Stage 4 of the WebAssembly specification process and shipped behind a flag in V8/Chrome 119 and in Wasmtime 16. Wasmtime 21 enabled it by default. The primary use cases are legitimate and demanding: loading multi-gigabyte datasets into a single WASM module for ML inference, image processing pipelines operating on large raster files, and scientific computing workloads that previously required splitting data across multiple 4 GiB segments.

The first and most important security implication is that the guard-page strategy breaks at 64-bit scale. Allocating a 2^64-byte virtual reservation per WASM instance is not feasible; modern physical address buses top out around 52 bits, and operating system virtual address spaces are typically 48-bit or 57-bit. Wasmtime's memory64 implementation responds by switching to explicit bounds-check instructions: before every memory access, Cranelift emits a comparison between the WASM address and the current memory size, trapping if the access would be out of bounds. This is correct, but it is a fundamentally different trust model. Guard-page protection is passive and delegated to hardware; bounds-check instructions are active and depend on the JIT compiler emitting them correctly on every code path. A single code-generation bug that drops a bounds check means an access that silently reaches host memory rather than trapping.

The second implication is integer truncation in host-side bindings. The WASM specification version for memory64 uses `i64` for memory addresses and offsets. A large body of existing WASM host integration code — Rust embeddings using the Wasmtime API, C host functions, JavaScript glue — was written when WASM memory offsets were always `i32`. When that code receives an `i64` memory address from a memory64 module and casts it to `i32` or `u32`, the high 32 bits are silently discarded. A WASM module can exploit this by passing an address like `0x100000000 + target_offset`. The host truncates the address to `target_offset`, then accesses a different buffer than intended — the WASM module controls which host-managed memory region is read or written. This is not a runtime bug; it is a host integration bug, and it is widespread in codebases that added memory64 support without auditing every memory pointer handling site.

The third implication is pointer arithmetic overflow at 64-bit scale. WASM modules performing arithmetic on `i64` memory offsets can produce values that wrap. A common pattern is computing an array index: `base_address + element_index * element_size`. If `element_index` is attacker-controlled and large, the multiplication overflows `i64` before the addition, producing a small positive value. The subsequent `i64.load` or `i64.store` then accesses a low address in linear memory rather than the intended high address. For memory32, this class of bug existed but affected a 4 GiB range; for memory64, the arithmetic space is large enough that carefully chosen overflow values can target specific offsets in linear memory or, if combined with a bounds-check regression, reach host memory.

The open source implementation history of memory64 illustrates how security-critical fixes travel without CVEs. When Wasmtime's memory64 support matured in the Cranelift code generator, a bounds-checking regression was introduced: a specific instruction pattern for memory64 store operations bypassed the bounds check emitted by the `heap_addr` lowering pass. The bug was found by Wasmtime's fuzzing infrastructure — Cranelift maintains a differential fuzzer that compares interpreter output against compiled output — and fixed in a Wasmtime point release. The fix PR was titled "fix bounds check for memory64 store instructions" and was public on GitHub with the full patch. No CVE was filed. The Wasmtime project has a documented security advisory process using GitHub Security Advisories, but the project's own guidelines note that bugs in non-default features (memory64 was non-default at the time) may be handled as ordinary bugs rather than security advisories, regardless of the potential impact. V8's memory64 implementation had a separate issue: the Turbofan JIT compiled certain memory64 access patterns incorrectly, producing native code that accessed memory outside the WASM sandbox. This was fixed in a Chrome stable update and received a CVE in the CVE-2024-xxxx series, but the Chromium commit fixing the issue was publicly visible in the Chromium source tree several days before the Chrome stable update shipped, creating a window during which the fix was readable but the fix was not yet deployed.

Tracking these fixes requires active monitoring rather than waiting for CVE feeds. Subscribe to Wasmtime's GitHub Security Advisories at `https://github.com/bytecodealliance/wasmtime/security/advisories`. Watch the Wasmtime `CHANGELOG.md` for entries mentioning "memory64", "bounds check", "cranelift", or "heap_addr" — these terms appear in security-relevant fixes regardless of whether a formal advisory is filed. For V8, the V8 blog (`v8.dev/blog`) publishes post-mortems for significant bugs, and the Chromium security bug tracker makes many bugs public after 14 weeks. Use `osv.dev` to query Wasmtime CVEs (`https://osv.dev/list?ecosystem=crates.io&q=wasmtime`) as a cross-reference; OSV often picks up vulnerabilities not yet in the NVD feed.

Target systems: Wasmtime 21+ (memory64 enabled by default), V8 as embedded in Node.js 22+ (memory64 enabled), and any WASM module compiled with `--target-feature +memory64`. The `wasm32-wasip2` target does not yet support memory64 by default; production WASI workloads on wasm32-wasip2 are not immediately affected, but the gap is closing as the specification stabilises.

## Threat Model

1. **Bounds-check regression exploitation**: A malicious or compromised WASM module targets a specific version of Wasmtime or V8 where a memory64 bounds-check is missing or incorrect. The module issues a crafted `i64.load` with an address that is technically out of bounds for its linear memory but passes the defective check. The result is a read of host process memory — potentially secrets, keys, or pointers that enable further exploitation. This attack is enabled by the patch-gap between the public commit fixing the issue and the operator updating the runtime in production.

2. **Host integer truncation exploitation**: A memory64 WASM module under attacker control passes the address `0x100000000 + target` to a host function. The host function, written for memory32, casts the received `i64` to `u32` or `i32`, discarding the high bit, and accesses offset `target` within a host-managed buffer. The attacker selects `target` to read or write a sensitive host data structure — a session token, a private key blob, or a length field in another guest's memory allocation. The vulnerability is in the host code, not the WASM runtime, and survives runtime upgrades.

3. **Patch-gap attacker**: An adversary monitors the Wasmtime GitHub repository's commit history and the Chromium commit log. When a commit appears whose message matches patterns like "fix bounds check", "memory64", "heap_addr clamp", or "oob", the adversary reads the patch to understand the faulty instruction pattern. They then craft a WASM module that triggers the now-public vulnerability and deploy it against servers running the unfixed runtime version. Because the Wasmtime project does not always file CVEs for memory64 fixes, automated patch management tools that rely on CVE feeds may not flag the vulnerable version. The time window between commit and operator patch can be days to weeks.

4. **`i64` pointer arithmetic overflow**: A WASM module computes an array access as `base + index * stride` using `i64.mul` and `i64.add`. An attacker controls `index`. When `index` is chosen such that `index * stride` wraps the `i64` range and the resulting sum is a valid (small) address within linear memory, the subsequent load or store targets an unintended memory region. Depending on what resides at that address within the WASM module's linear memory, this may corrupt allocator metadata, overwrite a function table entry, or leak data — the same class of vulnerability as 32-bit pointer overflow, now playing out across a much larger address space.

The blast radius across all four scenarios is bounded by whether memory64 is used at all, whether the runtime version is current, and whether memory size limits are applied. A host that rejects memory64 modules entirely eliminates scenarios 1 and 4 at the cost of capability. A host that enforces a maximum linear memory size of, say, 8 GiB limits the damage from a bounds-check bypass to the 8 GiB region rather than the full 64-bit space. Scenario 2 requires an audit of host code and cannot be mitigated by runtime configuration alone.

## Configuration / Implementation

### Detecting memory64 usage in WASM modules

Before a WASM module runs in your environment, determine whether it uses memory64. The `wasm-tools` binary from the Bytecode Alliance provides direct inspection:

```bash
# Print the module's text format and look for 64-bit memory declarations
wasm-tools print module.wasm | grep 'memory'
# A memory64 module declares memory with i64 limits:
# (memory (;0;) i64 16)

# Validate that the module uses memory64 (exits non-zero if it does not)
wasm-tools validate --features memory64 module.wasm

# Extract just memory section entries to check for i64 index type
wasm-tools print module.wasm | grep -E 'memory \(;[0-9]+;\) i64'
```

In a multi-tenant environment where runtime patch levels cannot be guaranteed to be current at all times, reject memory64 modules at the ingestion boundary:

```bash
# Reject any module that declares a 64-bit memory
if wasm-tools print "$MODULE" 2>/dev/null | grep -qE 'memory \(;[0-9]+;\) i64'; then
  echo "REJECTED: memory64 module not permitted in this environment" >&2
  exit 1
fi
```

### Wasmtime memory64 configuration

Memory64 is opt-in via `Config` in the Wasmtime Rust API. Always pair enablement with an explicit memory size cap:

```rust
use wasmtime::{Config, Engine, MemoryType, Module, Store};

fn build_engine_with_memory64() -> anyhow::Result<Engine> {
    let mut config = Config::new();
    // Explicitly enable memory64; this is the default in Wasmtime 21+
    // but is explicit here for documentation purposes.
    config.wasm_memory64(true);
    Engine::new(&config)
}

fn create_bounded_memory64_type() -> MemoryType {
    // 64-bit memory with a hard cap of 8 GiB (131072 pages of 65536 bytes each).
    // Never leave max_pages as None for memory64 in production.
    let min_pages: u64 = 1;
    let max_pages: u64 = 131_072; // 8 GiB
    MemoryType::new64(min_pages, Some(max_pages))
}
```

Before deploying, verify your Wasmtime version includes the bounds-check fix. Check the CHANGELOG for the version you are running:

```bash
# Identify the installed Wasmtime version
wasmtime --version

# Fetch the CHANGELOG and search for memory64 or bounds-check entries
# in the relevant release section
curl -sSL https://raw.githubusercontent.com/bytecodealliance/wasmtime/main/CHANGELOG.md \
  | grep -A 3 -i 'bounds\|memory64\|heap_addr' \
  | head -60
```

### Bounds-check instrumentation

Wasmtime's Cranelift backend generates explicit bounds-check instructions for memory64 accesses. You can inspect the generated Cranelift IR to verify that bounds checks are present for your module's memory access patterns:

```bash
# Compile the module and emit Cranelift IR (CLIF) for inspection
wasmtime compile --emit-clif /tmp/clif-output module.wasm

# In the CLIF output, look for heap_addr instructions.
# A correct memory64 bounds check looks like:
#   v5 = heap_addr.i64 heap0, v4, 8
# The third argument is the access size in bytes.
# An ABSENT heap_addr before a load/store is a red flag.
grep -n 'heap_addr\|load\|store' /tmp/clif-output/*.clif | head -40
```

Run Wasmtime's own memory64 test suite against your deployment binary to confirm the build is correct:

```bash
# From the Wasmtime source tree
cargo test -p wasmtime --test memory64 -- --nocapture
```

### Host-side integer safety

The most common host integration bug is casting a 64-bit WASM memory address to a 32-bit integer. Audit all host functions that accept memory pointers from WASM modules.

Vulnerable pattern (Rust host):

```rust
// VULNERABLE: truncates the high 32 bits of a memory64 address.
// If the WASM module passes 0x100000000 + target, this resolves to target.
fn host_read_bytes(
    mut caller: wasmtime::Caller<'_, ()>,
    wasm_ptr: i64,
    len: i32,
) -> i32 {
    let ptr = wasm_ptr as u32; // WRONG: silent truncation
    let memory = caller.get_export("memory")
        .and_then(|e| e.into_memory())
        .unwrap();
    let data = memory.data(&caller);
    // ptr now indexes the wrong location if wasm_ptr >= 2^32
    let slice = &data[ptr as usize..(ptr as usize + len as usize)];
    process_bytes(slice);
    0
}
```

Safe pattern:

```rust
use std::convert::TryFrom;

fn host_read_bytes_safe(
    mut caller: wasmtime::Caller<'_, ()>,
    wasm_ptr: i64,
    len: i64,
) -> i32 {
    // Reject negative values and values that exceed usize.
    let ptr = match u64::try_from(wasm_ptr) {
        Ok(v) => v as usize,
        Err(_) => return -1, // negative address is invalid
    };
    let length = match u64::try_from(len) {
        Ok(v) => v as usize,
        Err(_) => return -1,
    };
    let end = match ptr.checked_add(length) {
        Some(v) => v,
        None => return -1, // overflow in host arithmetic
    };

    let memory = caller.get_export("memory")
        .and_then(|e| e.into_memory())
        .unwrap();
    let data = memory.data(&caller);

    // Bounds-check against actual memory length before slicing.
    if end > data.len() {
        return -1;
    }
    let slice = &data[ptr..end];
    process_bytes(slice);
    0
}
```

The key changes: accept `i64` parameters rather than `i32`, use `u64::try_from` rather than `as u32`, and use `checked_add` on the host side to detect arithmetic overflow before indexing.

### Memory size limits as defence-in-depth

Even if a bounds-check bypass exists in the runtime, capping memory size limits the region an attacker can reach to the capped range rather than the full 64-bit space:

```rust
// In module instantiation, enforce the memory type's max_size.
// The MemoryType::new64 call above sets max to 8 GiB.
// When the module is instantiated, Wasmtime enforces this limit
// regardless of what the module's own memory section declares.
let instance = linker.instantiate(&mut store, &module)?;

// You can also verify at module-load time that the declared memory
// does not exceed your policy limit before instantiation:
for memory_type in module.exports().filter_map(|e| {
    if let wasmtime::ExternType::Memory(m) = e.ty() { Some(m) } else { None }
}) {
    if memory_type.is_64() {
        let max = memory_type.maximum().unwrap_or(u64::MAX);
        const MAX_ALLOWED_PAGES: u64 = 131_072; // 8 GiB
        if max > MAX_ALLOWED_PAGES {
            anyhow::bail!("module requests more memory64 than policy allows");
        }
    }
}
```

### Monitoring Wasmtime for silent security fixes

Because Wasmtime does not always file CVEs for memory64-related fixes, automate scanning of the commit log:

```bash
# Scan recent Wasmtime commits for memory64/bounds-check related changes.
# Requires the GitHub CLI (gh) authenticated to github.com.
gh api repos/bytecodealliance/wasmtime/commits \
  --jq '.[] | select(
    .commit.message | test("bounds|memory64|cranelift.*heap|heap_addr|oob"; "i")
  ) | {sha: .sha[0:8], msg: (.commit.message | split("\n")[0])}'
```

Add Dependabot to track Wasmtime releases in `Cargo.toml`:

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: cargo
    directory: "/"
    schedule:
      interval: daily
    allow:
      - dependency-name: wasmtime
      - dependency-name: wasmtime-*
```

Subscribe to GitHub Security Advisories for the Bytecode Alliance org:

- Navigate to `https://github.com/bytecodealliance/wasmtime/security/advisories`
- Click "Watch" on the repository and select "Security alerts"

Monitor Cranelift fuzzer findings in the Wasmtime issue tracker:

```bash
# List open issues mentioning memory64 and fuzzing
gh issue list --repo bytecodealliance/wasmtime \
  --search "memory64 fuzzer" \
  --state open \
  --json number,title,createdAt \
  --jq '.[] | "\(.number) \(.createdAt[:10]) \(.title)"'
```

### V8/Node.js memory64 safety

Node.js 22+ ships with V8 that supports memory64. V8 uses explicit comparison instructions for memory64 bounds checking (not guard pages), matching Wasmtime's approach. Ensure Node.js is current before loading memory64 modules:

```bash
# Check Node.js and V8 versions
node --version
node -e "process.versions" | grep v8

# Test a memory64 module in V8 before enabling in production
# (flag is no longer needed in Node.js 22+ but useful for verification)
node --experimental-wasm-memory64 test-memory64.mjs
```

In a Node.js host, validate that memory64 modules are handled with 64-bit offsets throughout. The WebAssembly JS API represents memory addresses as `BigInt` when the memory is a 64-bit memory:

```javascript
// Node.js host — memory64 access uses BigInt indices
const wasmBytes = fs.readFileSync('module.wasm');
const { instance } = await WebAssembly.instantiate(wasmBytes, {});
const memory = instance.exports.memory;
// For memory64, memory.buffer is still an ArrayBuffer,
// but address calculations must use BigInt to avoid truncation.
const view = new DataView(memory.buffer);
// Safe: use BigInt for the address, convert to Number only after range check.
const address = BigInt('0x200000000'); // 8 GiB offset
if (address + 8n > BigInt(memory.buffer.byteLength)) {
  throw new RangeError('out-of-bounds access');
}
const value = view.getFloat64(Number(address), true);
```

## Expected Behaviour

| Signal | memory32 module | memory64 module with hardening |
|---|---|---|
| Out-of-bounds access | OS trap via guard page; runtime converts to WASM trap | Runtime bounds-check instruction fires; WASM trap raised before host memory is reached |
| Host memory read via pointer truncation | Not possible; host code receives i32 pointer, no high bits to truncate | Blocked when host uses `u64::try_from` and rejects addresses that do not fit or exceed memory size |
| Module memory limit enforcement | `MemoryType::new(min, Some(max))` caps at max pages; enforced by Wasmtime at grow time | `MemoryType::new64(min, Some(max))` caps at max pages; same enforcement path; default max set explicitly to policy value |
| Runtime bounds-check bypass detection | Guard-page fault is hardware-enforced and does not require runtime code correctness | Requires correct Cranelift codegen on every path; detectable via CLIF inspection and memory64 test suite; monitoring Wasmtime CHANGELOG for fix commits |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Bounds-check instructions vs guard pages | Works at any linear memory size; no virtual address space reservation needed | Per-access CPU overhead (typically 1–3% on access-heavy workloads); depends entirely on JIT correctness | Accept the overhead; validate CLIF output; stay current on runtime to receive bounds-check fixes promptly |
| Memory size cap (e.g., 8 GiB max) | Limits blast radius of any bounds-check regression to the capped region | Workloads requiring more than 8 GiB of WASM memory (large ML models) cannot use the cap without adjustment | Set the cap to the maximum your actual workload requires, not to a security-first minimum; review cap when workloads change |
| Rejecting memory64 in multi-tenant environments | Eliminates scenarios 1 and 4 entirely; removes dependency on runtime version being current | Blocks legitimate large-dataset WASM workloads; tenants needing memory64 must use a separate, isolated pool | Maintain a verified-current, memory64-capable runtime pool; allow memory64 only in that pool |
| Monitoring Wasmtime PRs and commits | Catches security fixes before CVEs are filed; reduces patch-gap window | Requires ongoing engineer time; commit messages may not clearly signal security impact | Automate with `gh` CLI script on a cron; route results to a security-team Slack channel |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Bounds-check regression in Wasmtime version | Memory64 WASM module reads host process memory; host data corruption or information disclosure with no trap raised | CVE feed miss likely; detected via Wasmtime CHANGELOG monitoring script or Bytecode Alliance security advisory; may surface as unexplained host crashes or data leaks | Update Wasmtime to patched version immediately; temporarily reject all memory64 modules until updated |
| `wasm_memory64` feature flag disabled on a runtime that receives a memory64 module | Module instantiation fails with "memory64 support not enabled" or validation error; legitimate workload breaks | Wasmtime or V8 returns a module load error; surface in application logs | Enable `Config::wasm_memory64(true)` in Wasmtime configuration; ensure Node.js version is 22+ |
| Memory size cap set too low for legitimate workload | Module raises an out-of-memory trap during normal operation; `memory.grow` returns -1 inside the module | Application-level errors; module returns allocation failure; WASM trap logged | Increase `max_pages` in `MemoryType::new64` to match workload requirements; re-profile actual peak memory usage |
| Host integer truncation bug exposed by attacker | Attacker-supplied memory64 module accesses unintended host memory region via truncated pointer; data disclosure or corruption | No runtime trap (the access is within host memory from the OS perspective); detectable only via host-side audit and fuzz testing of host functions with high-bit addresses | Audit all host functions for `as i32`/`as u32` casts on WASM memory pointers; replace with `u64::try_from`; fuzz host bindings with addresses above `0xFFFFFFFF` |

## Related Articles

- [WASM Linear Memory Safety](/articles/wasm/wasm-linear-memory-safety/)
- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [WASM Multi-Tenancy](/articles/wasm/wasm-multi-tenancy/)
- [WASM Static Analysis](/articles/wasm/wasm-static-analysis/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
