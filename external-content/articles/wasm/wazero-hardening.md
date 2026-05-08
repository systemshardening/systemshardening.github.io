---
title: "Wazero Hardening for Go Embedders: Resource Limits, WASI Capabilities, and Plugin Isolation"
description: "Wazero is the pure-Go WASM runtime used by Tetragon, Cilium, k6, Trivy, and dapr. The defaults are friendly; production deployments need explicit caps."
slug: "wazero-hardening"
date: 2026-04-27
lastmod: 2026-04-27
category: "wasm"
tags: ["wazero", "go", "wasm", "embedding", "sandboxing"]
personas: ["platform-engineer", "security-engineer", "systems-engineer"]
article_number: 185
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/wasm/wazero-hardening/index.html"
---

# Wazero Hardening for Go Embedders: Resource Limits, WASI Capabilities, and Plugin Isolation

## Problem

Wazero is a WebAssembly runtime written entirely in Go, with no CGo and no external dependencies. By 2026 it is the default runtime for the Go ecosystem's growing list of WASM-embedding projects: Tetragon (eBPF policy enforcement), Cilium (CNI plugins), Trivy (custom scanners), k6 (load-test extensions), dapr (state-store extensions), Open Policy Agent's `wasm-target` execution, and many internal Go services that use WASM as a plugin mechanism.

Wazero's design choices differ meaningfully from Wasmtime's:

- **Pure Go.** No CGo. The runtime is the same Go process; a Go program embeds the runtime as a library.
- **Interpreter and compiler modes.** Interpreter is universally portable; the compiler emits machine code at runtime for x86-64 and arm64. Compiler mode is faster but has larger memory footprint.
- **No JIT runtime dependency.** Unlike V8 or Wasmtime+Cranelift, Wazero compiles to Go-managed memory, so the host's memory protections (`mprotect`, W^X) apply via Go's runtime.
- **WASI Preview 1 and Preview 2.** Both supported; Preview 2's component-model integration is via a separate package (`github.com/tetratelabs/wazero/experimental/sys`).

The defaults are user-friendly: imports work, WASI is available, modules execute cleanly. They are also wider than production deployments need:

- No CPU bound. A loop in a module hangs the embedding goroutine.
- No memory cap beyond Wazero's 4 GiB linear-memory ceiling.
- Default `WithRandSource(rand.Reader)` provides cryptographic randomness — generally desired but not always.
- WASI default config inherits stdio and (with `WithFSConfig`) the host filesystem at the embedder's discretion. Carelessly calling `WithFSConfig(wazero.NewFSConfig().WithDirMount("/", "/"))` exposes the host root.

This article covers Wazero's `RuntimeConfig` and `ModuleConfig` knobs for resource limits, WASI capability scoping, the closer-to-context-cancellation deadline pattern, and operational metrics for Go embedders.

**Target systems:** Wazero v1.8+ (the version with stable Preview 2 sys-experimental). Go 1.22+. Embeds well into any Go service.

## Threat Model

- **Adversary 1 — Untrusted plugin author:** uploads a `.wasm` plugin to a Go-embedding service (Trivy custom scanner, Tetragon policy, Cilium plugin). Wants to escape the WASM sandbox or exhaust resources.
- **Adversary 2 — Resource exhaustion in legitimate plugin:** a plugin with a memory leak or infinite loop that brings down the embedding service.
- **Adversary 3 — Embedded service treats plugin as trusted:** the host calls plugin functions assuming bounded execution; an unbounded plugin starves the host.
- **Access level:** Plugin upload for adversary 1; running plugin in production for 2 and 3.
- **Objective:** Read or modify host data; consume CPU/memory until the host service crashes; pivot through the host's identity to its dependencies.
- **Blast radius:** Bounded by the embedder's resource and capability decisions. A correctly-configured Wazero embedding contains a malicious module to its allotted memory and CPU; an incorrect one lets the module access whatever the host process can.

## Configuration

### Step 1: Configure the Runtime with Bounded Compilation

```go
package main

import (
    "context"
    "github.com/tetratelabs/wazero"
    "github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

func newRuntime(ctx context.Context) wazero.Runtime {
    runtimeConfig := wazero.NewRuntimeConfig().
        WithCompilationCache(wazero.NewCompilationCacheWithDir("/var/cache/wazero")).
        WithCloseOnContextDone(true).      // critical — see Step 4
        WithDebugInfoEnabled(false).       // smaller compiled binary, no debug surface
        WithCustomSections(false).         // ignore unused custom sections
        WithMemoryLimitPages(1024).        // 1024 * 64 KiB = 64 MiB max linear memory
        WithMemoryCapacityFromMax(false)   // grow on demand; do not pre-allocate

    rt := wazero.NewRuntimeWithConfig(ctx, runtimeConfig)
    wasi_snapshot_preview1.MustInstantiate(ctx, rt)
    return rt
}
```

`WithMemoryLimitPages(1024)` caps every module's linear memory at 64 MiB. `WithCloseOnContextDone(true)` makes Wazero respect Go context cancellation — the cleanest way to enforce a deadline.

### Step 2: Bound CPU via Context Deadline

Wazero does not have fuel-style accounting (yet); the deadline mechanism is `context.Context` cancellation. The runtime checks the context at WASM operation boundaries.

```go
func executeWithBudget(rt wazero.Runtime, wasmBytes []byte, input string) error {
    ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
    defer cancel()

    mod, err := rt.Instantiate(ctx, wasmBytes)
    if err != nil {
        return err
    }
    defer mod.Close(ctx)

    fn := mod.ExportedFunction("run")
    if fn == nil {
        return errors.New("module missing 'run' export")
    }

    _, err = fn.Call(ctx)
    return err   // context.DeadlineExceeded if the module ran too long
}
```

The 100ms deadline is enforced via context. `WithCloseOnContextDone(true)` in the runtime config tells Wazero to honor the cancellation and return promptly. Without that flag the runtime continues running until the next operation boundary that polls the context.

For long-running modules (workers, servers), use a longer or open-ended context but enforce per-call deadlines on each `fn.Call(ctx)` invocation. The pattern: long-lived module instance, short-lived per-call contexts.

### Step 3: WASI Capability Allowlist

WASI in Wazero is configured via `ModuleConfig`. Default is empty; explicit grants add capabilities.

```go
import (
    "io"
    "github.com/tetratelabs/wazero/sys"
)

func makeModuleConfig(tenantID string) wazero.ModuleConfig {
    workdir := fmt.Sprintf("/var/lib/plugins/%s/workdir", tenantID)

    fsConfig := wazero.NewFSConfig().
        WithDirMount(workdir, "/work").
        WithReadOnlyDirMount("/usr/share/plugin-assets", "/assets")

    return wazero.NewModuleConfig().
        WithFSConfig(fsConfig).
        WithStdin(io.NopCloser(strings.NewReader(""))).   // no input
        WithStdout(&boundedWriter{cap: 64 * 1024}).        // cap stdout
        WithStderr(&boundedWriter{cap: 64 * 1024}).
        WithRandSource(rand.Reader).
        // No environment variables, no command-line args.
        WithSysWalltime().                                 // wall clock allowed
        WithSysNanotime().                                 // monotonic clock allowed
        WithStartFunctions("_start")                       // explicit entry
}
```

The `boundedWriter` is a custom `io.Writer` that errors after `cap` bytes — a misbehaving module cannot exhaust host memory by writing unbounded log lines.

```go
type boundedWriter struct {
    written int
    cap     int
}

func (w *boundedWriter) Write(p []byte) (int, error) {
    if w.written >= w.cap {
        return 0, errors.New("output cap exceeded")
    }
    n := len(p)
    if w.written+n > w.cap {
        n = w.cap - w.written
    }
    w.written += n
    return n, nil
}
```

For modules that need network, Wazero's WASI Preview 2 sys-experimental package supports socket capabilities:

```go
import "github.com/tetratelabs/wazero/experimental/sys"

netConfig := sys.NewSocketConfig().
    AllowOutboundTCP(func(host string, port uint16) bool {
        // Allowlist by host:port.
        return host == "192.168.10.5" && port == 8080
    })

mc := wazero.NewModuleConfig().
    WithSocketConfig(netConfig).
    // ... rest of config
```

### Step 4: Per-Plugin Resource Accounting

Track resource use per plugin instance. Wazero exposes counters:

```go
type Plugin struct {
    Name string
    rt   wazero.Runtime
    mod  api.Module
}

func (p *Plugin) Stats() PluginStats {
    return PluginStats{
        MemoryPages: p.mod.Memory().Size() / 65536,
        // For more, instrument the host functions yourself.
    }
}

// Instrument a host function.
func instrumentedHostFn(name string) api.GoModuleFunc {
    return func(ctx context.Context, mod api.Module, params []uint64) []uint64 {
        start := time.Now()
        defer func() {
            metricHostCallDuration.With(prometheus.Labels{
                "fn":     name,
                "module": mod.Name(),
            }).Observe(time.Since(start).Seconds())
        }()
        // host function body
        return nil
    }
}
```

Wire into Prometheus:

```
wazero_plugin_invocations_total{plugin}            counter
wazero_plugin_duration_seconds{plugin}              histogram
wazero_plugin_traps_total{plugin, kind}             counter
wazero_plugin_memory_pages{plugin}                  gauge
wazero_host_call_duration_seconds{fn, plugin}       histogram
```

Alert on `wazero_plugin_traps_total{kind="context_canceled"}` rises (deadline exhausted), `kind="oom"` (memory cap), or unexpected `kind="bad_function"` (likely incompatible plugin).

### Step 5: Compilation Mode Choice

Wazero supports compiler mode (machine-code emission) and interpreter mode. The choice affects performance and security surface.

```go
// Compiler mode: faster, larger memory footprint per instance.
runtimeConfig := wazero.NewRuntimeConfig()   // compiler is default

// Interpreter mode: portable, smaller memory.
runtimeConfig := wazero.NewRuntimeConfigInterpreter()
```

For embedders running thousands of small plugin instances (one per request, for example), interpreter mode often wins on total memory. For a few long-lived instances per process, compiler mode is faster.

The security difference is small but real: compiler mode generates executable Go-managed memory; the runtime relies on Go's process protections to prevent code injection. Interpreter mode has no executable WASM-derived memory, slightly reducing the JIT-related attack surface.

For environments where generated code is a concern (FIPS-strict, locked-down kernels with W^X enforcement at process level), use interpreter mode.

### Step 6: Module Validation

Wazero validates by default, but reject features you do not support upfront:

```go
runtimeConfig := wazero.NewRuntimeConfig().
    WithCoreFeatures(api.CoreFeatureV2 |
        api.CoreFeatureSignExtensionOps |
        api.CoreFeatureNonTrappingFloatToIntConversion |
        api.CoreFeatureBulkMemoryOperations).
    // Explicitly do NOT enable: WebAssembly threads, multi-memory, GC.
```

The module fails to compile if it requires a disabled feature. Lock the feature set per environment; bumping it is a security review event.

### Step 7: Plugin Lifecycle Management

For embedders running multiple plugins, isolate them by closing modules promptly:

```go
type PluginManager struct {
    rt      wazero.Runtime
    plugins map[string]api.Module
    mu      sync.Mutex
}

func (pm *PluginManager) Load(ctx context.Context, name string, wasm []byte) error {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    if existing, ok := pm.plugins[name]; ok {
        existing.Close(ctx)
    }

    mod, err := pm.rt.InstantiateWithConfig(ctx, wasm,
        makeModuleConfig(name))
    if err != nil {
        return err
    }
    pm.plugins[name] = mod
    return nil
}

func (pm *PluginManager) Unload(ctx context.Context, name string) error {
    pm.mu.Lock()
    defer pm.mu.Unlock()
    if mod, ok := pm.plugins[name]; ok {
        mod.Close(ctx)
        delete(pm.plugins, name)
    }
    return nil
}
```

Each module's resources (linear memory, host-function bindings) are released on `Close`. Plugins kept alive longer than necessary leak.

## Expected Behaviour

| Signal | Default Wazero | Hardened |
|--------|----------------|----------|
| Plugin loops indefinitely | Hangs the calling goroutine | Returns `context.DeadlineExceeded` after the configured timeout |
| Plugin allocates 200 MB | Succeeds (host memory permitting) | Trap; module's memory.grow returns -1 |
| Plugin tries to read /etc/passwd | Succeeds if WASI inherits FS | EACCES (no FS mount for that path) |
| Plugin opens TCP socket | Succeeds if Preview 2 sockets enabled with default | Refused unless allowlist matches |
| Plugin writes 1 GB to stdout | Buffered into host memory | Bounded writer rejects after cap |
| Plugin uses `wasm threads` | Loaded if feature enabled | Refused at compile time |

Verify behavior:

```go
// Test: confirm context deadline aborts an infinite loop.
ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
defer cancel()
_, err := mod.ExportedFunction("loop_forever").Call(ctx)
require.ErrorIs(t, err, context.DeadlineExceeded)

// Test: confirm filesystem capability is scoped.
err = pm.Run(ctx, "plugin", "read /etc/passwd")
require.ErrorContains(t, err, "permission denied")
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Pure-Go runtime | No CGo; reproducible builds; no external library to audit | Slightly slower than Wasmtime in some benchmarks | Acceptable for plugin workloads; embedder typically dominates. |
| Compiler mode | Faster runtime | Larger memory per instance, generated code surface | Use interpreter mode for high-instance-count embeddings or FIPS environments. |
| Context-deadline CPU bound | Cleanest Go pattern; integrates with existing cancellation | Coarse-grained (operation boundary, not per-instruction) | Sufficient for most workloads; for billing-grade accounting, use a separate token bucket. |
| WASI capability via FSConfig | Filesystem isolation per host directory | Module sees logical paths; debugging maps differently | Document the path mapping per plugin; provide a debug build that logs FS access. |
| Bounded io.Writer | Prevents stdout flood | Plugins lose visibility when capped | Surface a metric for "plugin output truncated"; alert on cap hits. |
| Compilation cache | Cold-start speedup | Disk usage; stale-cache risk on Wazero version upgrade | Versioned cache directory; clean on version change. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Context not propagated to `fn.Call` | Plugin hangs goroutine forever | Goroutine count rises; deadlines never fire | Always pass a derived `ctx` with deadline to `fn.Call`. Use linting rules to enforce. |
| `WithCloseOnContextDone(false)` (default) | Cancellation doesn't promptly abort plugin | Plugins continue past deadline | Always `WithCloseOnContextDone(true)` in production. |
| Memory cap too low | Plugins fail under modest load | `wazero_plugin_traps_total{kind="oom"}` rises | Profile representative plugins; raise cap to 1.5x observed peak. |
| Compiler mode generates faulty code | Plugin executes incorrectly | Subtle bugs that don't appear in interpreter mode | Switch to interpreter mode; file a Wazero bug. |
| Module Close not called | Memory leak across plugin upgrades | RSS grows monotonically | Use `defer mod.Close(ctx)` rigorously; the manager pattern in Step 7. |
| WASI FSConfig leaks host filesystem | Plugin reads files outside the intended directory | `strace` or `bpftrace` shows opens outside the allowlist | Use `WithDirMount`, never `WithDirMount("/", "/")`. Audit the embedder's FS configuration code. |

## Related Articles

- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [WASI Preview 2 Capability-Based Security](/articles/wasm/wasi-preview-2-capabilities/)
- [WASM Module Static Analysis and Vulnerability Scanning](/articles/wasm/wasm-static-analysis/)
- [eBPF Runtime Security with Tetragon](/articles/observability/ebpf-tetragon/)
- [WASM in Databases: Postgres, ClickHouse, SurrealDB Extensions](/articles/wasm/wasm-in-databases/)
