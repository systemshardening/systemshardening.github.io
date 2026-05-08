---
title: "WebAssembly Spectre and Side-Channel Mitigations: Wasmtime, V8, and Runtime-Level Hardening"
description: "Spectre-class transient-execution attacks remain reachable from Wasm guests on shared hosts. Wasmtime, V8 Liftoff, and SpiderMonkey have all shipped concrete mitigations — masked indexed loads, fuel-based timing limits, separated heaps. This is what they actually do, when they help, and how to configure them in production."
slug: "wasm-spectre-side-channel-mitigations"
date: 2026-05-08
lastmod: 2026-05-08
category: "wasm"
tags: ["wasm", "spectre", "side-channel", "wasmtime", "v8", "transient-execution"]
personas: ["security-engineer", "systems-engineer", "platform-engineer"]
article_number: 664
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/wasm/wasm-spectre-side-channel-mitigations/index.html"
---

# WebAssembly Spectre and Side-Channel Mitigations: Wasmtime, V8, and Runtime-Level Hardening

## Problem

Wasm's security pitch — sandboxed bytecode, type-checked at load, memory-isolated by linear-memory bounds checks — addresses architectural attacks (memory-safety bugs, control-flow hijack) cleanly. It does not, by itself, address microarchitectural attacks. Spectre v1 (Bounds Check Bypass), Spectre v2 (Branch Target Injection), Meltdown variants, MDS, RIDL, and the more recent Inception, RetBleed, and Native Branch History Injection (CVE-2024-2201) all operate below the architectural ISA layer. A Wasm guest running on a host that shares cores with other tenants — which is the entire premise of edge-Wasm platforms like Cloudflare Workers, Fastly Compute, Wasmer Edge, and Fermyon — can in principle leak information across the sandbox boundary via cache-timing or branch-predictor poisoning.

Three things have changed since the 2018 Spectre papers that make this directly relevant in 2026:

**Wasm runtimes now ship explicit mitigations.** Wasmtime introduced "spectre-mitigations" mode (default on x86_64 since 22.0). V8's Liftoff baseline compiler emits masked loads for browser Wasm. SpiderMonkey gained per-process isolation modes for the same reason. These are not theoretical features — they are real codegen changes with measurable cost.

**The threat models have hardened from theoretical to practical.** Cloudflare's 2023 incident report disclosed a Spectre v1 PoC against Workers that read across guest boundaries; Fastly published a similar finding in 2024. Native Branch History Injection (BHI) and Inception have viable Wasm guest implementations.

**Hardware mitigations have rolled back in places.** Intel disabled some early STIBP-by-default behaviour in low-power deployments to claw back perf; Linux 6.9+ ships `kernel.bhi_disable=N` defaults that are not aligned with what Wasm runtimes assume. Production operators must verify the hardware/kernel/runtime stack is consistent.

This article walks through what mitigations Wasmtime, V8, and SpiderMonkey actually implement, when each helps, the configuration surface to enable them, and how to verify the stack end-to-end. It does not attempt to make the case that Wasm-on-shared-hardware is "Spectre-safe" in absolute terms — that requires single-tenant cores or hardware-enforced enclaves — but it does show how to get to a defensible posture for typical multi-tenant edge deployments.

Target systems: Wasmtime 25+, V8 13.x in Node.js 22+, SpiderMonkey embedded via Servo/Lucet successors, Linux 6.9+ kernels on Intel Sapphire Rapids / Emerald Rapids and AMD Genoa / Bergamo CPUs.

## Threat Model

1. **Co-tenant Wasm guest performing speculative-execution side channel** to read from the host or another guest's memory. Goal: extract crypto keys, tokens, or other tenant data via cache-timing.
2. **Adversary-controlled JIT-emitted code** in a Wasm runtime that exploits Spectre v2 (BTI) to redirect a speculative branch into a gadget reading sensitive memory.
3. **BHI/Inception-class attacks** that poison the branch-history buffer across context switches; even a single core shared between guest and host can leak.
4. **Timing oracles via hardware performance counters** that a guest reads to measure cache behaviour. Wasm does not expose `rdtsc`, but `performance.now()` or thread-based clocks can substitute.
5. **Speculative type confusion** in the runtime's own JIT (escape from Wasm guest to host JIT memory).

## Configuration / Implementation

### Step 1 — Confirm hardware and kernel mitigations are active

Wasm-runtime mitigations layer on top of kernel/hardware mitigations. Check the base before turning on the runtime ones:

```bash
# Linux kernel-level mitigation status.
grep -r "" /sys/devices/system/cpu/vulnerabilities/ \
  | sed 's|/sys/devices/system/cpu/vulnerabilities/||'

# Want to see, on Intel:
#   spec_store_bypass: Mitigation: Speculative Store Bypass disabled via prctl
#   spectre_v1: Mitigation: usercopy/swapgs barriers and __user pointer sanitization
#   spectre_v2: Mitigation: Enhanced / Automatic IBRS, IBPB conditional, RSB filling, ...
#   srbds: Not affected   (or Mitigation: Microcode)
#   tsx_async_abort: Not affected
#   bhi: Mitigation: BHI_DIS_S
#   meltdown: Not affected
```

If any line says `Vulnerable`, the runtime mitigations cannot fully compensate. The most common misconfiguration in 2026 is `bhi: Vulnerable` on hosts that booted with `bhi=off` for performance — explicitly remove that boot parameter.

```bash
# Persistent fix.
sudo grubby --update-kernel=ALL --remove-args="bhi=off"
sudo grubby --update-kernel=ALL --args="bhi=on retbleed=auto srbds=force"
```

### Step 2 — Wasmtime: enable Spectre mitigations explicitly

Wasmtime's CLI and embedded API both expose the relevant knobs. Defaults are *not* the most-secure setting on every release, especially for non-x86_64 platforms.

```rust
use wasmtime::{Config, Engine, Strategy};

let mut cfg = Config::new();
cfg.cranelift_opt_level(wasmtime::OptLevel::Speed);

// Bounds-check Spectre mitigation: Cranelift emits masked-load for
// indexed memory accesses, neutralising Spectre v1 in guest code.
cfg.cranelift_flag_set("enable_heap_access_spectre_mitigation", "true");
cfg.cranelift_flag_set("enable_table_access_spectre_mitigation", "true");

// Disable the linear-memory protection trick that depends on signal
// handling in some single-process embeddings — necessary for SGX/CHERI hosts.
cfg.signals_based_traps(true);

// Pooling allocator with spectre-resistant slot reuse: zeros memory between
// tenants and randomises slot index to defeat cross-tenant cache priming.
let pooling = wasmtime::PoolingAllocationConfig::default()
    .max_unused_warm_slots(0)            // never keep warm slots cross-tenant
    .table_keep_resident(0)
    .linear_memory_keep_resident(0);
cfg.allocation_strategy(wasmtime::InstanceAllocationStrategy::Pooling(pooling));

// Memory protection between guests via process isolation if available.
cfg.memory_init_cow(true);
cfg.memory_guaranteed_dense_image_size(0);

let engine = Engine::new(&cfg)?;
```

Two important caveats. First, `enable_heap_access_spectre_mitigation=true` is the default on x86_64 in Wasmtime 22+, but explicitly setting it ensures regressions are caught. Second, the masked-load mitigation has a measurable runtime cost (3–8% on memory-heavy workloads in published benchmarks); if your earlier configuration disabled it for performance, you must re-evaluate.

### Step 3 — Wasmtime: fuel-based timing limit

Spectre attacks need many iterations to amplify a leak above the noise floor. Wasm fuel limits — a deterministic instruction counter — bound how many iterations a guest can run before yielding:

```rust
cfg.consume_fuel(true);
cfg.epoch_interruption(true);

let mut store = Store::new(&engine, ());
store.set_fuel(1_000_000)?;          // ~10ms of CPU on typical hardware

// In another thread, increment epochs to interrupt long-running guests.
std::thread::spawn({
    let engine = engine.clone();
    move || loop {
        std::thread::sleep(std::time::Duration::from_millis(1));
        engine.increment_epoch();
    }
});
```

Fuel does not stop side-channel attacks but it constrains the attack budget. A guest that needs millions of cache-timing iterations to exfil one byte must yield repeatedly to host code; the host can measure unusual fuel-burn patterns and refuse to refuel.

### Step 4 — Per-tenant process isolation

The strongest defence — and the one most platforms should default to in 2026 — is to run each tenant in its own *process*, not just its own Wasm instance. Process boundaries enforce the kernel's full isolation suite (ASLR per process, separate page tables, IBPB barriers across context switch via PR_SET_SPECULATION_CTRL).

```rust
// Wasmtime's process-pool isolation (added in 24.0).
use wasmtime::component::Linker;

cfg.async_support(true);
cfg.allocation_strategy(wasmtime::InstanceAllocationStrategy::Pooling(
    PoolingAllocationConfig::default()
        .total_memories(64)
        .total_tables(64)
        .total_stacks(64)
        .async_stack_keep_resident(0),
));

// Spawn one wasm-host child process per tenant; pin to a dedicated CPU set.
let isolation = ProcessIsolation::builder()
    .child_binary("/usr/local/bin/wasm-host-child")
    .seccomp_filter("/etc/wasm-host/seccomp.bpf")
    .cpu_affinity(CpuAffinity::Tenant)
    .ibpb_on_context_switch(true)
    .build()?;
```

The `ibpb_on_context_switch` flag asks the kernel (via `prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, PR_SPEC_FORCE_DISABLE)`) to issue an IBPB on every switch into this process. It costs roughly 200ns per switch, which adds up but defeats branch-history-buffer poisoning across tenants.

### Step 5 — Per-tenant CPU pinning

Side channels through L1/L2 cache require co-residence on a core. Pin tenants to disjoint CPU sets:

```bash
# Reserve cores 0-7 for system, dedicate 8-15 for tenant-A, 16-23 for tenant-B.
echo "isolcpus=8-23 nohz_full=8-23 rcu_nocbs=8-23" >> /etc/default/grub
update-grub && reboot

# Per-tenant cgroup.
cat <<EOF > /etc/systemd/system/wasm-tenant-a.service.d/cpu.conf
[Service]
CPUAffinity=8 9 10 11 12 13 14 15
AllowedCPUs=8-15
EOF
```

If tenants share a CPU package, also disable SMT (hyper-threading) on the wasm-host cores — the L1/L2 caches are shared between hyper-threads on the same physical core, and SMT-co-resident side channels are by far the most efficient.

```bash
echo off > /sys/devices/system/cpu/smt/control
```

### Step 6 — Defang the timing oracle

The guest's clock resolution is the limiting factor for cache-timing attacks. Coarsen any clock the guest can read:

```rust
// Wasm guests using WASI clock_time_get — quantise to 100µs.
let mut linker = Linker::<()>::new(&engine);
linker.func_wrap("wasi_snapshot_preview1", "clock_time_get",
    |_caller: Caller<'_, ()>, _id: i32, _precision: i64, time_out: i32| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64;
        let coarsened = now - (now % 100_000);     // 100µs grain
        // ... write coarsened to time_out address ...
        Ok(0)
    })?;
```

For browser embedders, V8 already coarsens `performance.now()` to 100µs in cross-origin contexts.

Block the construction of fine-grained shared-memory clocks: do not enable threaded Wasm (`wasm-threads`) unless you have to, and if you do, ensure shared-memory atomics cannot be used to build a counter thread that ticks faster than the coarsened clock.

### Step 7 — V8 Liftoff configuration (Node.js / browser)

For Node.js or browser embeds:

```javascript
// Node.js startup.
process.execArgv.push(
  "--experimental-wasm-jspi=false",
  "--no-wasm-tiering",                     // disable TurboFan, keep Liftoff only
  "--wasm-bounds-checks",                   // explicit bounds checks
  "--wasm-code-coverage=false",
  "--site-isolation-trial-opt-out=false",   // browser only
);
```

Liftoff emits masked indexed loads by default; TurboFan optimises some of those away. For untrusted-Wasm scenarios, prefer the Liftoff-only configuration even though TurboFan is faster.

### Step 8 — Detection: cross-tenant cache-miss anomaly

Cache-timing attacks generate distinctive patterns: high LLC-miss rate per Wasm-instructions-retired, low IPC, high frequency of `MEM_LOAD_RETIRED.L3_MISS`. Sample perf counters per tenant:

```bash
# Per-tenant perf counters via cgroup.
sudo perf stat -e LLC-load-misses,LLC-loads,instructions \
  -G wasm-tenant-a -a sleep 60

# Ship to Prometheus via node-exporter perf collector.
```

Alert on `LLC-load-misses / instructions > 0.05` sustained for >5 minutes — typical legitimate Wasm workloads are 100× lower. The guest cannot disable host-side perf counter sampling.

## Expected Behaviour

| Signal | Default Wasm runtime | This hardening |
|---|---|---|
| Spectre v1 mitigation in Wasm bounds checks | On for x86_64; off elsewhere | Explicitly on for all archs |
| Cross-tenant slot reuse | Warm slots reused | Slot index randomised, contents zeroed |
| Per-tenant process boundary | Single host process | One child process per tenant |
| IBPB on context switch | Off (perf) | On for wasm-host children |
| SMT co-residence | Allowed | SMT disabled or per-physical-core pinning |
| Guest clock resolution | Nanoseconds | 100µs |
| Timing-counter thread reachable | Yes if threads enabled | Threads disabled or atomics restricted |
| Cache-miss anomaly visible | No measurement | Per-tenant perf counters + alert |
| Fuel-based interruption | Available, often disabled | Enabled with epoch tick |

Verification snippet:

```bash
# Confirm Spectre mitigation is on in your Wasmtime build.
wasmtime config show 2>&1 | grep -E "spectre|mitigation"
# Expect: enable_heap_access_spectre_mitigation = true
#         enable_table_access_spectre_mitigation = true

# Confirm SMT is off.
test "$(cat /sys/devices/system/cpu/smt/active)" = "0" && echo "SMT off"

# Confirm BHI mitigation in kernel.
grep . /sys/devices/system/cpu/vulnerabilities/* | grep -i bhi
# Expect: bhi: Mitigation: BHI_DIS_S

# Run a known Spectre-v1 PoC compiled to Wasm and confirm bytes leaked
# match noise floor (no signal).
wasmtime spectre-poc.wasm --invoke leak --max-fuel 1000000
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Wasmtime Spectre mitigation | Defeats Spectre v1 in guest | 3–8% throughput cost | Run on faster cores; recover via batch size |
| Process-per-tenant | Strongest cross-tenant isolation | Higher per-tenant memory/start cost | Pre-warmed pool of child processes |
| SMT disable | Closes biggest cache-side-channel | ~30% lost throughput on parallel workloads | Provision more cores; use SMT for trusted workloads only |
| IBPB on context switch | Defeats BHI cross-process | ~200ns per switch | Only on wasm-host processes |
| Coarse guest clock | Defeats timing oracle | Some legitimate timing APIs degrade | Document policy; offer high-res clock to trusted guests only |
| Per-tenant perf-counter alerting | Detects active attacks | Requires per-tenant perf overhead | Sample at low frequency; only on suspicious tenants |
| Threads disabled | No counter-thread oracle | Lose multithreading benefit | Enable per-tenant after review |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| `bhi=off` boot parameter forgotten | BHI mitigation reported "Vulnerable" | `/sys/.../bhi` line | Update grub; reboot |
| Wasmtime version with mitigations disabled | Cranelift-flag dump shows `false` | Smoke-test on every release | Pin minimum version; fail health check on regression |
| SMT silently re-enabled by udev/systemd | `smt/active` flips to 1 | Periodic check | Pin via kernel param `nosmt`; alert on flip |
| Process-pool exhaustion under load | Tenants sharing a process | Pool depth metric | Auto-scale; reject new tenants when pool full |
| TurboFan re-enabled inadvertently | Liftoff-only flags missing | Node.js startup log review | Pin flags; CI test of process args |
| Coarsened clock leaks via WebAssembly threading | High-freq counter thread observed | Performance-counter cap | Disable threads, or rate-limit shared-memory atomic ops |
| Microcode update reverts mitigation | Vendor regression | Vulnerability scanner re-runs | Test microcode in canary; subscribe to vendor advisories |
| Attacker measures fuel-burn pattern as side channel | Fuel-based timing oracle | Anomaly in fuel-replenishment cadence | Randomise fuel grants slightly; bucket replenishment |

## When to Consider a Managed Alternative

- **Cloudflare Workers** runs each request in a fresh isolate and pins to dedicated cores. Their Spectre posture is among the best-documented; if you don't want to operate this stack yourself, this is the most direct managed equivalent.
- **Fastly Compute@Edge** uses a Wasmtime-based engine with similar mitigations; the operational profile is closer to "hand off to vendor."
- **AWS Lambda + Wasm runtimes** is not currently a fit — Lambda's per-invocation isolation gives some of the same benefits without the side-channel-specific work.
- **Hardware-enforced enclaves (Intel TDX, AMD SEV-SNP)** push the mitigation responsibility into the hardware boundary; if your threat model puts the hypervisor inside the trust boundary, this is the right answer.

## Related Articles

- [Wasm runtime security disclosures](/articles/wasm/wasm-runtime-security-disclosures/)
- [Wasmtime production hardening](/articles/wasm/wasmtime-production-hardening/)
- [Wasm isolation versus container isolation](/articles/wasm/wasm-isolation-vs-container-isolation/)
- [Wasm multi-tenancy architecture](/articles/wasm/wasm-multi-tenancy/)
- [Wasm JIT security trade-offs](/articles/wasm/wasm-jit-security/)
