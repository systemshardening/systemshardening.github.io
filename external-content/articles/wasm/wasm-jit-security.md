---
title: "WASM JIT Compiler Security: JIT Spraying and Speculative Execution Defenses"
description: "Understand how JIT spraying and speculative execution attacks target WASM runtimes, and harden Wasmtime, V8, and SpiderMonkey against Spectre, JIT code injection, and side-channel leakage."
slug: wasm-jit-security
date: 2026-05-07
lastmod: 2026-05-07
category: wasm
tags:
  - wasm
  - jit-compiler
  - speculative-execution
  - side-channels
  - sandboxing
personas:
  - security-engineer
  - platform-engineer
article_number: 568
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/wasm/wasm-jit-security/
---

# WASM JIT Compiler Security: JIT Spraying and Speculative Execution Defenses

## Problem

WebAssembly's security model rests on two guarantees: structural sandboxing enforced by the runtime and memory isolation enforced by the hardware and operating system. The JIT compiler sits at the intersection of both. When a WASM module is loaded into a JIT-capable runtime — V8 in Chrome, SpiderMonkey in Firefox, Cranelift-backed Wasmtime in server-side deployments — the bytecode is translated to native machine code in a process that is both performance-critical and security-critical. Errors or design weaknesses in that translation pipeline can undermine every sandbox guarantee that WASM otherwise provides.

Two distinct threat classes target the JIT tier. The first is JIT spraying: an attacker causes the compiler to emit controlled sequences of native bytes into executable memory, then redirects execution into the middle of those sequences to repurpose them as return-oriented programming (ROP) or jump-oriented programming (JOP) gadgets. The second is speculative execution leakage: the CPU's branch predictor and out-of-order execution engine speculatively execute code paths that the WASM sandbox bounds checks should have blocked, allowing an attacker to read host memory contents through a cache-timing side channel. Spectre v1 and v2 are the canonical forms; the 2018 disclosure made it immediately clear that WASM JIT runtimes were a first-class attack surface.

These are not theoretical concerns. The seminal 2018 paper by Kocher et al. on Spectre explicitly called out JIT compilers as a high-risk execution context, and within weeks of that disclosure every major browser vendor had issued emergency mitigations for WASM and JavaScript JIT paths. Server-side runtimes followed. The threat model for WASM JIT security is therefore established, well-documented, and actively exploited in research contexts. Platform engineers running Wasmtime in multi-tenant SaaS environments or embedding V8 in edge infrastructure carry real exposure until mitigations are correctly configured and verified.

Target systems: Wasmtime 20+ (Cranelift backend), V8 12+ (TurboFan/Liftoff), SpiderMonkey 115+ (IonMonkey/Warp), Linux x86-64 and ARM64 hosts.

## Threat Model

**1. JIT spraying through constant embedding.** WASM numeric constants (i32, i64, f32, f64 values encoded in the module binary) are lifted into immediate operands in the JIT-compiled native output. An attacker who controls the WASM module content can craft constants whose byte representations, when treated as x86 instruction sequences, form useful ROP gadgets. If the attacker can also trigger a control-flow diversion — through a use-after-free in the runtime, a type confusion bug in the JIT, or a sandbox escape — those gadgets become the payload of an exploit chain. JIT spraying requires both the ability to spray gadgets into executable memory and a separate mechanism to redirect the instruction pointer.

**2. Spectre v1: bounds-check bypass through speculative loads.** WASM linear memory is bounded by a length check before every load and store. Under speculative execution, the CPU may execute the load before confirming that the index is within bounds. If the speculative load brings a host memory region into a cache line, and the attacker can measure cache-hit timing through a side channel (a high-resolution timer, `SharedArrayBuffer` as a timing primitive, or cache-flush-and-reload), the speculative access leaks the contents of host memory byte by byte. The WASM sandbox boundary is violated in the microarchitectural domain even though it holds at the architectural level.

**3. Spectre v2: branch target injection.** The CPU's indirect branch predictor is a shared microarchitectural resource. An attacker running in a separate process or WASM context (if SharedArrayBuffer enables multi-threaded timing) can train the branch predictor to mis-predict indirect calls in the JIT-compiled WASM output, redirecting speculative execution to attacker-controlled gadgets. This variant is particularly relevant for runtimes that use indirect branch dispatch in their JIT output — a common pattern for WASM's `call_indirect` instruction.

**4. Tiered compilation race conditions.** Runtimes that support tiered compilation — an interpreter or fast baseline JIT for initial execution, followed by an optimising JIT for hot code — must synchronise transitions between tiers. If the optimised version of a function replaces the baseline version while it is being executed, and if type assumptions made by the optimising compiler can be violated by in-flight execution, type confusion bugs can arise. These are not purely theoretical: SpiderMonkey and V8 have both shipped CVE-tracked bugs in their tier-transition logic.

**5. JIT code pointer corruption.** JIT compilers maintain internal tables mapping WASM function indices to compiled native code pointers. If an attacker can corrupt these tables — through a heap overflow in the runtime, a WASM bulk-memory operation that escapes the linear memory bound, or a type confusion — redirected dispatch through the corrupted table leads to arbitrary native code execution within the process.

The blast radius of a successful JIT attack is the full privilege of the runtime process. For browser-embedded V8 this means renderer process compromise, requiring a second sandbox escape to reach the OS. For server-side Wasmtime running as root or with broad filesystem access, the blast radius is the host system.

## How WASM JIT Compilers Work

Understanding the attack surface requires understanding the compilation pipeline. WASM bytecode is a stack-based, typed intermediate representation. JIT runtimes translate it to native code in one or more passes.

**V8 (TurboFan and Liftoff).** V8 uses a two-tier model for WASM. Liftoff is a single-pass baseline compiler that generates unoptimised native code immediately on module instantiation, minimising startup latency. TurboFan is V8's optimising compiler, which re-compiles hot functions in the background using type feedback and speculative optimisation. TurboFan's output is significantly faster but relies on assumptions about operand types; if those assumptions are violated at runtime, a deoptimisation path returns control to Liftoff or the interpreter. The JIT spraying attack surface lives primarily in TurboFan's constant materialisation and the code cache it maintains for compiled functions.

**SpiderMonkey (IonMonkey and Warp).** SpiderMonkey historically used IonMonkey as its WASM optimising JIT, later supplemented by the Warp backend which processes WASM and JavaScript through a unified IR. SpiderMonkey also maintains a baseline JIT tier (Baseline Interpreter) and promotes hot functions to IonMonkey/Warp. Control flow graph construction, register allocation, and instruction selection each represent phases where compiler bugs can produce exploitable outputs.

**Wasmtime (Cranelift).** Wasmtime uses Cranelift as its code generation backend — a purpose-built, security-oriented IR and code generator developed under the Bytecode Alliance. Cranelift does not share a codebase with any browser JIT; it was designed from the start with formal verification aspirations and security as a first-class requirement. Cranelift operates as a single-tier optimising compiler: there is no interpreter fallback for hot code promotion, though Wasmtime does support an interpreter mode (`winch`) as an alternative backend for environments where JIT is undesirable.

## JIT Spraying: Mechanics and Mitigations

### How JIT Spraying Works

An x86 instruction stream is not aligned to fixed boundaries. A sequence of bytes that forms a valid instruction when executed from address N may form a completely different instruction sequence when executed from address N+1 or N+3. JIT spraying exploits this property by encoding attacker-controlled bytes into WASM constants that the compiler embeds verbatim as immediate values in native instructions. For example, the x86 instruction `mov eax, 0x90909090` is five bytes: `B8 90 90 90 90`. The bytes `90 90 90 90` at offsets 1–4 of that instruction, if executed as an instruction stream, form four NOP instructions — a classic NOP sled. More dangerous constants encode useful gadgets: `ret` (0xC3), `pop rsp; ret` sequences, or the opening bytes of a `syscall` instruction.

If the JIT compiler emits many such constants across a large executable code region, and if an attacker can redirect execution into the middle of an instruction — through a bug that corrupts a return address, function pointer, or jump target — the attacker gains control over a ready-made gadget set without injecting any native code directly.

### Constant Blinding

The primary mitigation against JIT spraying is constant blinding. Before embedding a constant into JIT-compiled code, the compiler XORs it with a secret random value (the blind). The blinded constant is embedded in the native instruction stream, paired with a corresponding XOR instruction that removes the blind at runtime. An attacker who reads the raw bytes of a JIT code region sees the blinded constant, not the useful gadget bytes. Because the blind changes per-process invocation (and ideally per-compilation unit), the attacker cannot pre-compute gadget locations.

V8 implements constant blinding for x64 and ARM64 constants above a size threshold. SpiderMonkey applies blinding across its JIT tiers. Cranelift in Wasmtime applies constant blinding for immediates that could form useful gadget material.

```bash
# Verify Wasmtime is built with constant blinding (Cranelift default for WASM)
wasmtime --version
# Cranelift's constant blinding is always-on in release builds; no runtime flag needed.
# Confirm no debug/prototype builds are deployed:
objdump -d /usr/local/bin/wasmtime | grep -c "xor" | awk '{print "XOR instruction count:", $1}'
```

### W^X Enforcement

JIT code regions must be writable during compilation and executable after, but never both simultaneously. W^X (write XOR execute) enforcement ensures that an attacker who gains write access to a JIT code page cannot make it executable without a separate privilege escalation, and vice versa. Modern runtimes use `mprotect(2)` transitions: pages are `PROT_WRITE | PROT_READ` during code generation, then flipped to `PROT_READ | PROT_EXEC` before the first execution. Linux 5.8+ enforces this at the kernel level for mappings that use `memfd_create` with the `MFD_NOEXEC_SEAL` flag.

```bash
# Confirm running kernel supports memory sealing (Linux 5.8+)
uname -r

# Verify a running Wasmtime process does not hold RWX mappings
pid=$(pgrep -f wasmtime | head -1)
grep rwx /proc/$pid/maps && echo "WARNING: RWX mapping found" || echo "No RWX mappings"
```

## Spectre and Meltdown in the WASM JIT Context

### The 2018 Disclosure and Its WASM Implications

The Spectre v1 and v2 disclosures published in January 2018 had immediate implications for WASM JIT runtimes. The core insight was that a WASM sandbox's architectural memory bounds checks — enforced by comparing the memory access index against the module's declared linear memory size — are not sufficient to prevent speculative execution from crossing the sandbox boundary. The CPU may speculatively execute the load instruction before completing the bounds comparison. If the speculative load brings attacker-chosen host memory into the L1 or L2 cache, subsequent cache-timing measurements using a high-resolution clock or a SharedArrayBuffer-based timer reveal the loaded value bit by bit.

For WASM specifically, the attack is structured as follows:

1. The attacker trains the CPU's branch predictor to expect the bounds check to pass by repeatedly executing legitimate in-bounds accesses.
2. The attacker then issues a deliberately out-of-bounds access with an index that maps to a host memory address of interest.
3. Speculatively, the CPU executes the load from host memory before the bounds check completes.
4. The attacker uses the speculative load result as an index into a probe array, bringing one of 256 cache lines into a hot state.
5. The attacker measures access times to each element of the probe array; the hot cache line reveals the value at the host address.

Chrome, Firefox, and Safari all shipped emergency mitigations within days of the disclosure.

### SharedArrayBuffer as a Timing Oracle

`SharedArrayBuffer` enables a precise high-resolution timer through a worker thread that increments a shared counter in a tight loop. The main thread reads the counter value before and after a cache probe, obtaining sub-microsecond timing resolution without requiring `performance.now()` or any explicit timer API. This technique was the primary amplifier for WASM-based Spectre exploits in browsers. All major browsers disabled `SharedArrayBuffer` immediately post-disclosure and re-enabled it only after shipping cross-origin isolation requirements (COOP/COEP headers) that prevent the shared-memory timing channel from crossing origin boundaries.

Server-side runtimes using Wasmtime in multi-tenant environments should audit whether their WASM API surface exposes any timing oracles to untrusted modules.

## Runtime Mitigations

### Guard Pages and Linear Memory Layout

WASM linear memory is a contiguous byte array allocated at module instantiation time. The runtime allocates it with guard pages — unmapped memory regions — immediately following the declared maximum size. Any out-of-bounds access that the bounds check misses at the architectural level causes a hardware fault on the guard page, which the runtime catches and converts to a WASM trap. Guard pages are not a Spectre mitigation (speculative accesses do not trigger page faults) but they eliminate entire classes of bugs where missing bounds checks lead to heap overflows into adjacent allocations.

Wasmtime's default memory configuration reserves 4 GiB of virtual address space for each WASM linear memory instance on 64-bit platforms. This means the 32-bit WASM address space is entirely mapped with at least a 2 GiB guard region following it. The bounds check for a 32-bit index can be elided — the hardware page table enforces the bound. This optimisation eliminates the architectural check but does not affect speculative access; Spectre mitigations are layered on separately.

```toml
# wasmtime.toml — explicit memory configuration
[component]

[wasmtime]
# Guard pages: default 4GiB guard on 64-bit hosts — do not reduce below 2GiB
# Setting static_memory_maximum_size forces the guard-page optimisation path
static_memory_maximum_size = "4294967296"  # 4 GiB
static_memory_guard_size   = "2147483648"  # 2 GiB guard region
```

### Spectre v1 Mitigation: LFENCE Insertion

The LFENCE instruction on x86 is a load fence: it serialises instruction retirement, preventing speculatively executed loads from completing until all prior instructions have retired. Inserting an LFENCE immediately after every bounds check in JIT-compiled WASM code prevents the CPU from speculating past the check. The performance cost is significant — 10–30% throughput reduction in memory-intensive workloads — but the mitigation is precise and verifiable.

Wasmtime/Cranelift supports LFENCE insertion through the `cranelift_spectre` crate options. When enabled, Cranelift inserts serialising instructions after every bounds check and indirect branch resolution in the compiled output.

```rust
// Rust embedding — enable Cranelift Spectre mitigations
use wasmtime::*;

fn build_secure_engine() -> Engine {
    let mut config = Config::new();
    // Enable Spectre v1 mitigations (LFENCE after bounds checks)
    config.cranelift_flag_enable("enable_pcc").unwrap();
    // Enable retpoline for indirect branch targets (Spectre v2)
    config.cranelift_flag_set("use_colocated_libcalls", "false").unwrap();
    // Restrict WASM features to reduce attack surface
    config.wasm_threads(false);
    config.wasm_reference_types(true);
    Engine::new(&config).unwrap()
}
```

### Spectre v2 Mitigation: Retpoline

Spectre v2 exploits indirect branch prediction. The retpoline mitigation replaces every indirect call or jump with a constructed return trampoline that cannot be speculatively misdirected. Cranelift emits retpolines for indirect branches in its Spectre hardening mode. For WASM's `call_indirect` instruction — which dispatches through a function table — retpoline insertion prevents branch target injection attacks where an attacker-controlled branch predictor state in a sibling process misdirects the indirect call.

```bash
# Audit Cranelift-compiled output for retpoline presence
# A retpoline sequence on x86-64 contains: call to thunk, pause + lfence in loop, ret
objdump -d /path/to/jit-output.so 2>/dev/null | grep -A5 "__x86_indirect_thunk"
```

### Site Isolation in V8 / Chrome

Chrome's response to Spectre for WASM was architectural rather than purely JIT-level. Site isolation places each origin's renderer in a separate OS process, with each process having an independent virtual address space. An attacker who achieves speculative memory leakage from within a WASM module can only read memory within the same process address space — content from the same origin. Cross-origin memory, including authentication tokens, session cookies, and sensitive API responses from other origins, lives in separate processes and is unreachable via cache-timing side channels within a single renderer.

COOP (Cross-Origin-Opener-Policy) and COEP (Cross-Origin-Embedder-Policy) headers enforce the same constraint at the HTTP level, preventing cross-origin documents from sharing a process. Both headers are required to re-enable `SharedArrayBuffer` in modern Chrome and Firefox.

```nginx
# nginx: enforce COOP/COEP for WASM-serving origins
add_header Cross-Origin-Opener-Policy  "same-origin"           always;
add_header Cross-Origin-Embedder-Policy "require-corp"          always;
add_header Cross-Origin-Resource-Policy "same-origin"           always;
# Validate: SharedArrayBuffer is available only when these headers are present
```

### Disabling SharedArrayBuffer and Atomics.wait in Server Runtimes

Server-side Wasmtime runtimes that expose a WASM API to untrusted module content should disable threading primitives unless explicitly required. `SharedArrayBuffer`-equivalent primitives in WASM are gated behind the `threads` feature, which enables shared linear memory and atomic operations including `memory.atomic.wait`. These enable the counter-increment timing pattern that amplifies Spectre timing channels.

```rust
// Disable WASM threads and atomics for untrusted module execution
let mut config = Config::new();
config.wasm_threads(false);            // Disables shared memory and Atomics.wait
config.wasm_bulk_memory(true);         // Bulk memory is safe; threads are the risk
config.wasm_simd(true);               // SIMD is safe without threading
config.wasm_multi_value(true);
// Result: no SharedArrayBuffer-equivalent timing oracle available to WASM module
```

## JIT Hardening Techniques

### Code Pointer Protection

JIT-compiled code regions maintain internal dispatch tables: the runtime maps WASM function indices to native code pointers. If an attacker can overwrite these pointers — through a heap overflow in the runtime's allocator, a type confusion in the JIT bookkeeping, or a bug in bulk-memory handling — they redirect WASM function calls to arbitrary native addresses. Code pointer protection encodes pointers with a secret XOR mask (pointer authentication on ARM64 via PAC, software masking on x86-64) so that a corrupted pointer fails authentication at the call site.

ARM64 hardware provides Pointer Authentication Codes (PAC) via `PACIA`/`AUTIA` instruction pairs. V8 on ARM64 uses PAC for JIT return addresses. Wasmtime on ARM64 optionally uses PAC signing for code pointers when the host kernel and hardware support it (ARMv8.3+).

```bash
# Confirm ARM64 host supports PAC
grep -m1 "paca\|pacg" /proc/cpuinfo && echo "PAC supported" || echo "PAC not available"

# On PAC-capable hosts, Wasmtime/Cranelift uses it automatically for AArch64 targets
# Verify the compiled Wasmtime binary is built with PAC support
readelf -A /usr/local/bin/wasmtime | grep -i "pac\|bti" | head -5
```

### Heap Layout Randomisation for JIT Code

JIT code is allocated from the runtime's code heap — a region of memory managed separately from the data heap. Randomising the base address of this region (a form of ASLR specific to the code heap) prevents an attacker from predicting the addresses of JIT-sprayed gadgets. Without randomisation, an attacker who has triggered the JIT compilation of a known gadget-laden WASM module can predict where those gadgets land and construct exploit payloads that reference fixed addresses.

Linux ASLR (`/proc/sys/kernel/randomize_va_space = 2`) randomises the addresses of mmap-backed allocations, which includes JIT code regions. Confirm ASLR is enforced at the kernel level and that the runtime does not disable it:

```bash
# Confirm ASLR is enabled (value 2 = full randomisation)
cat /proc/sys/kernel/randomize_va_space

# Confirm Wasmtime does not request fixed-address mappings
strace -e mmap,mprotect wasmtime run --allow-precompiled module.wasm 2>&1 \
  | grep "MAP_FIXED" && echo "WARNING: fixed-address JIT mapping detected" \
  || echo "No fixed-address mappings"
```

## Tiered Compilation Security

### Interpreter-First Execution

Tiered runtimes that begin execution in an interpreter before promoting code to the JIT avoid executing any JIT-compiled code during the first few invocations of a function. This reduces the window in which JIT spraying gadgets are present in executable memory, since the JIT compilation of a function only occurs after it has been called a threshold number of times. An attacker who needs the gadgets to be present in executable memory before triggering a control-flow diversion must sustain execution long enough to warm up the JIT tier — a constraint that increases detection opportunity.

Wasmtime's `winch` backend is a fast single-pass baseline compiler rather than an interpreter, but it serves a similar security-architectural role: modules can be compiled with Winch first, with Cranelift optimised compilation reserved for trusted or pre-validated modules. For untrusted module execution in research or sandbox environments, interpreter-only mode eliminates the JIT attack surface entirely at the cost of a 10–30x performance penalty.

```rust
// Force interpreter-only execution for untrusted modules
let mut config = Config::new();
// Use the Winch baseline compiler (no optimising JIT)
config.strategy(Strategy::Winch);
// Or use the interpreter (slowest but zero JIT surface)
// config.strategy(Strategy::Interpreter);
let engine = Engine::new(&config).unwrap();
```

### Validating Transitions Between JIT Tiers

For runtimes that use tiered compilation, the transition from baseline to optimising JIT must preserve safety invariants. The optimising JIT makes type assumptions based on observed profiling data; if those assumptions are violated after the optimised code is installed, the runtime must deoptimise cleanly without creating a type confusion window. Security engineers deploying WASM runtimes with tiered JIT should track CVEs in the tier-transition logic specifically — these bugs tend to be complex and high-severity.

```bash
# Monitor relevant CVE databases for JIT tier-transition bugs
# For V8: track https://crbug.com with label "Type-Bug" and "Security_Severity-High"
# For SpiderMonkey: track https://bugzilla.mozilla.org with component "JavaScript Engine: JIT"
# For Wasmtime/Cranelift: track https://github.com/bytecodealliance/wasmtime/security/advisories

# Subscribe to Wasmtime security advisories via GitHub
gh api repos/bytecodealliance/wasmtime/security-advisories \
  --jq '.[].summary' 2>/dev/null | head -20
```

## Detecting JIT Exploitation Attempts

Runtime instrumentation can surface indicators of JIT exploitation in progress. Key signals include:

**Unusual JIT compilation volume.** An attacker triggering JIT spraying compiles WASM modules with many distinct constant-bearing functions to maximise gadget coverage. Metric: track JIT compilations per module instantiation. A module that triggers hundreds of JIT compilation units in a single instantiation warrants inspection.

**Out-of-bounds trap rates.** Spectre probing involves intentional out-of-bounds accesses that are caught by the runtime's trap handler. A module that triggers unusually high trap rates on memory operations — far above what legitimate computation produces — may be probing the sandbox boundary. Instrument the WASM trap handler and alert on anomalous per-module trap frequencies.

**Timer resolution abuse.** In browser contexts, monitor use of `performance.now()`, `Date.now()`, and `requestAnimationFrame` in tight loops adjacent to WASM memory operations. These patterns are characteristic of cache-timing measurements.

```rust
// Wasmtime: instrument trap handler for anomaly detection
use wasmtime::*;

fn create_instrumented_store(engine: &Engine) -> Store<()> {
    let mut store = Store::new(engine, ());
    // Fuel-based execution limits prevent indefinite Spectre probing loops
    store.set_fuel(10_000_000).unwrap();
    // Epoch-based interruption — increment epoch from external thread to interrupt
    store.set_epoch_deadline(1);
    store
}
```

**Heap layout probing via allocation patterns.** Before a JIT spray succeeds, an attacker may attempt to coerce the runtime's code heap into a predictable layout by triggering a sequence of compile-then-discard operations. Monitor for rapid module compilation and deallocation cycles with no corresponding execution.

## Hardening Checklist

- Wasmtime: set `static_memory_maximum_size` to 4 GiB and `static_memory_guard_size` to 2 GiB to enable guard-page-based bounds elision.
- Wasmtime: enable Cranelift Spectre mitigations (`enable_pcc`, retpoline) for multi-tenant or untrusted-module deployments.
- Wasmtime: disable `wasm_threads` unless shared memory is explicitly required; this removes the timing oracle surface.
- V8/Chrome: enforce COOP (`same-origin`) and COEP (`require-corp`) headers on all WASM-serving origins to enable site isolation.
- Confirm kernel ASLR is set to 2 (`full`) and that runtimes do not request `MAP_FIXED` for JIT code regions.
- Verify no RWX memory mappings exist in running runtime processes via `/proc/$pid/maps`.
- On ARM64 hosts supporting PAC (ARMv8.3+), confirm the runtime binary is compiled with PAC support for code pointer authentication.
- Apply fuel or epoch limits in Wasmtime to bound the execution time of any single WASM invocation, limiting the duration of cache-timing measurement windows.
- Monitor per-module JIT compilation counts, trap rates, and module churn for anomalous patterns indicative of JIT spraying or Spectre probing.
- Subscribe to security advisories for Wasmtime, V8, and SpiderMonkey; JIT tier-transition bugs and Spectre variant mitigations ship frequently.

## Summary

WASM JIT security requires defending two distinct attack surfaces simultaneously. JIT spraying is mitigated at the compiler level through constant blinding, W^X enforcement, and heap address space randomisation for code regions — all of which must be present in the runtime binary and confirmed in the deployment environment. Speculative execution leakage is mitigated through a combination of compiler-inserted serialising instructions (LFENCE, retpoline), architectural process isolation (site isolation in browsers, process-per-tenant in server runtimes), and removal of high-resolution timing oracles (disabling SharedArrayBuffer and WASM threads for untrusted modules).

Wasmtime's Cranelift backend provides the most security-oriented JIT design of the three major WASM runtimes: purpose-built for WASM, with formal verification aspirations and Spectre mitigations that can be selectively enabled per deployment profile. V8 and SpiderMonkey carry more legacy surface but are hardened through layered browser process isolation that compensates for JIT complexity. Platform engineers deploying any of these runtimes against untrusted WASM content should treat JIT security configuration as a first-class hardening requirement, not a post-deployment concern.
