---
title: "WASI Preview 2 Capability-Based Security: filesystem, sockets, http, and the Component Model"
description: "Preview 2 replaces Preview 1's coarse imports with explicit, scoped, capability-passing interfaces. The security story is the actual reason to migrate."
slug: "wasi-preview-2-capabilities"
date: 2026-04-27
lastmod: 2026-04-27
category: "wasm"
tags: ["wasi", "preview-2", "component-model", "capabilities", "wasm"]
personas: ["platform-engineer", "security-engineer", "ml-engineer"]
article_number: 179
difficulty: "advanced"
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/wasm/wasi-preview-2-capabilities/index.html"
---

# WASI Preview 2 Capability-Based Security: filesystem, sockets, http, and the Component Model

## Problem

WASI Preview 1 (the original system interface from 2019) modeled the world as a small flat namespace of imports — `path_open`, `fd_read`, `sock_connect`, etc. — that the embedder either provided or did not. The unit of authority was the entire interface. If a module needed any filesystem access, it imported `path_open` and got the ability to open any path the embedder chose to expose, with the embedder distinguishing only via preopened directory handles passed in opaquely.

Preview 2 (stabilized through 2024–2025 and now the default for new WASM toolchains) is a different model:

- **Capability handles, not flat imports.** Filesystem access is a `wasi:filesystem/types/descriptor` resource passed in by the host. A module that wants to read the descriptor needs the descriptor to be passed to it; it cannot conjure one.
- **Interfaces are versioned and scoped.** A component declares `import wasi:filesystem/types@0.2.0` explicitly. A component without that import has no filesystem access at all — the runtime cannot give it one.
- **Component model boundaries.** Multiple components compose into an application. Capability passing across component boundaries is explicit; one component cannot grant a capability it does not itself hold.
- **Standard interfaces with semantic meaning.** `wasi:http/incoming-handler` for serving HTTP, `wasi:sockets/tcp` for raw TCP, `wasi:cli/environment` for env vars. Each has a defined contract and a defined scope.

For embedders, this changes the security story:

- The host enumerates capabilities at component instantiation, not at every host call. The decision of "what can this component do" is made once, up front, and the runtime enforces.
- A component's WIT (WebAssembly Interface Type) definition is a precise enumeration of its host-call surface — auditable at build time without running the code.
- Capabilities are passed by value to functions; a component can sub-delegate to other components only if the capability is in its own world.
- Interfaces compose: a "logger" component can hold `wasi:filesystem` (to write logs) and expose only a `log(msg: string)` interface to others — those others get the logging capability without being able to write arbitrary files.

This article covers the WIT type system from a security perspective, the world / interface model, embedder-side capability enumeration, sub-delegation patterns, and the migration story from Preview 1.

**Target systems:** Wasmtime 22+ (full Preview 2 support), Spin 2.0+, wasmCloud 1.0+, JCO (JavaScript component runner), Wasmer 4.3+. Toolchains producing components: `cargo component` (Rust), `wit-bindgen` (multi-language), `componentize-py` (Python), `componentize-js` (JS).

## Threat Model

- **Adversary 1 — Component author with hidden imports:** an adversary submits a component whose WIT signature looks innocuous but which uses capabilities the embedder did not intend to grant. (Preview 2 makes this impossible by design — but only if the embedder enumerates imports against an allowlist.)
- **Adversary 2 — Capability over-grant during composition:** a benign component is composed with another component that requires more permissions, and the composer naively grants the union. The benign component now runs with capabilities it never asked for.
- **Adversary 3 — Capability leakage via interface design:** a component takes a capability handle and stores it in shared state where another, less-trusted code path retrieves it.
- **Access level:** Adversary 1 has component-upload capability. Adversary 2 has compose-time control. Adversary 3 has source access to the host harness.
- **Objective:** Obtain a capability that grants more I/O, network access, or environmental visibility than the component should have.
- **Blast radius:** Bounded to the capabilities the runtime hands out at instantiation. A correctly-configured Preview 2 host with strict allowlists makes blast radius proportional to the smallest set of capabilities the workflow legitimately needs.

## Configuration

### Step 1: Audit the WIT World of a Component

Every component declares a "world" — the set of imports it requires and exports it provides. Inspect with `wasm-tools`:

```bash
wasm-tools component wit ./payments.wasm
```

Output for a hypothetical payments component:

```wit
package myorg:payments@1.0.0;

world payments {
  // Imports: capabilities this component needs.
  import wasi:filesystem/types@0.2.0;
  import wasi:filesystem/preopens@0.2.0;
  import wasi:io/streams@0.2.0;
  import wasi:io/error@0.2.0;
  import wasi:clocks/wall-clock@0.2.0;
  import wasi:http/outgoing-handler@0.2.0;

  // Exports: interfaces this component provides.
  export wasi:http/incoming-handler@0.2.0;
}
```

The WIT world is the audit boundary. Imports tell you exactly what host capabilities the component will request; exports tell you what services the component provides. There are no other host calls — the toolchain refuses to compile a component that uses an interface not declared in its world.

For policy enforcement at upload time, parse the WIT and compare against an allowlist:

```rust
// validate_component.rs
use wit_parser::{Resolve, WorldId};

const ALLOWED_IMPORTS: &[&str] = &[
    "wasi:filesystem/types@0.2.0",
    "wasi:filesystem/preopens@0.2.0",
    "wasi:io/streams@0.2.0",
    "wasi:io/error@0.2.0",
    "wasi:clocks/wall-clock@0.2.0",
    "wasi:clocks/monotonic-clock@0.2.0",
    "wasi:http/outgoing-handler@0.2.0",
    "wasi:cli/stdout@0.2.0",
    "wasi:cli/stderr@0.2.0",
];

const FORBIDDEN_IMPORTS: &[&str] = &[
    "wasi:sockets/tcp@0.2.0",       // raw TCP not allowed; must use wasi:http
    "wasi:sockets/udp@0.2.0",
    "wasi:cli/environment@0.2.0",   // no env-var visibility
    "wasi:random/insecure@0.2.0",   // explicitly require secure RNG
];

fn validate(component: &[u8]) -> anyhow::Result<()> {
    let mut resolve = Resolve::new();
    let pkg = resolve.push_path(component)?;
    let world: WorldId = resolve.select_world(pkg.0, None)?;

    for (key, _) in &resolve.worlds[world].imports {
        let name = format!("{}", resolve.name_world_key(key));
        if FORBIDDEN_IMPORTS.contains(&name.as_str()) {
            anyhow::bail!("component imports forbidden interface: {name}");
        }
        if !ALLOWED_IMPORTS.contains(&name.as_str()) {
            anyhow::bail!("component imports unapproved interface: {name}");
        }
    }
    Ok(())
}
```

Run this at component upload, before any execution. A component that imports an unapproved interface is rejected.

### Step 2: Embedder-Side Capability Construction

In Wasmtime's Preview 2 host, the embedder constructs `WasiCtx` and `WasiHttpCtx` (and any custom interfaces) and links them into the component. The component cannot construct these; it receives handles.

```rust
use wasmtime::{Engine, Store};
use wasmtime::component::{Component, Linker};
use wasmtime_wasi::preview2::{WasiCtxBuilder, WasiCtx, WasiView, ResourceTable};
use wasmtime_wasi_http::{WasiHttpCtx, WasiHttpView};

struct Host {
    table: ResourceTable,
    wasi: WasiCtx,
    http: WasiHttpCtx,
}

impl WasiView for Host {
    fn table(&mut self) -> &mut ResourceTable { &mut self.table }
    fn ctx(&mut self) -> &mut WasiCtx { &mut self.wasi }
}

impl WasiHttpView for Host {
    fn ctx(&mut self) -> &mut WasiHttpCtx { &mut self.http }
    fn table(&mut self) -> &mut ResourceTable { &mut self.table }
}

fn build_host_for_tenant(tenant_id: &str) -> anyhow::Result<Host> {
    let mut wasi = WasiCtxBuilder::new();

    // Filesystem: only the tenant's working dir.
    let workdir = format!("/var/lib/wasm-tenants/{tenant_id}/workdir");
    let dir = cap_std::fs::Dir::open_ambient_dir(
        &workdir, cap_std::ambient_authority())?;
    wasi.preopened_dir(dir, wasmtime_wasi::DirPerms::all(),
                            wasmtime_wasi::FilePerms::all(), "/work")?;

    // No env vars. No CLI args.
    // Only monotonic clock, no wall clock.
    wasi.allow_blocking_current_thread(false);

    // HTTP: outbound only to specific endpoints.
    let mut http = WasiHttpCtx::default();
    http.allowed_request_targets = vec![
        "https://api.internal.example.com".into(),
        "https://payment-processor.example.com".into(),
    ];

    Ok(Host {
        table: ResourceTable::new(),
        wasi: wasi.build(),
        http,
    })
}
```

The two key decisions:

- `wasi:filesystem/types` is granted via `preopened_dir`. The component sees only `/work`; the path is a logical name inside the WASM world, not a host path.
- `wasi:http/outgoing-handler` is granted with an explicit target allowlist. Outbound HTTP requests to anywhere else trap with a permission error before the connection is initiated.

For a component that should not have any filesystem access at all, omit `preopened_dir`. The component's world declares the import, but the runtime hands it an empty list of preopens. Attempts to `open` anything return ENOENT.

### Step 3: Composition and Capability Containment

Components compose. A "platform" component holds capabilities; "tenant" components run inside the platform's world and only access what the platform exposes.

```wit
// platform.wit
world platform {
  // Platform imports the world's full WASI surface.
  import wasi:filesystem/types@0.2.0;
  import wasi:http/outgoing-handler@0.2.0;
  import wasi:io/streams@0.2.0;

  // Platform exposes a narrower interface to tenants.
  export myorg:platform/storage@1.0.0;
  export myorg:platform/api-call@1.0.0;
}

// tenant.wit
world tenant {
  // Tenant imports only the platform's narrow surface.
  import myorg:platform/storage@1.0.0;
  import myorg:platform/api-call@1.0.0;

  export wasi:http/incoming-handler@0.2.0;
}
```

```wit
// myorg:platform/storage interface
package myorg:platform@1.0.0;

interface storage {
  resource bucket {
    get: func(key: string) -> result<list<u8>, error>;
    put: func(key: string, value: list<u8>) -> result<unit, error>;
  }

  variant error {
    not-found,
    unauthorized,
    quota-exceeded,
  }

  open-bucket: func(name: string) -> result<bucket, error>;
}
```

The tenant component never holds a `wasi:filesystem` descriptor. It can only call `storage.open-bucket(name)`, which the platform component implements by translating to filesystem operations under a constrained path. A bug in the tenant cannot reach the host filesystem; only the platform's bug surface matters.

Compose with `wasm-tools`:

```bash
wasm-tools compose tenant.wasm \
  --definitions platform.wasm \
  --output composed.wasm
```

The composed artifact has the platform's capabilities, with the tenant safely embedded. The tenant's WIT world cannot import any WASI interface unless the platform explicitly re-exports it.

### Step 4: Resource Lifetime and Handle Hygiene

Capability handles in Preview 2 are typed resources with explicit lifetime. Use `with` blocks (Rust) or finalizers (other languages) to ensure handles are dropped when no longer needed.

```rust
// Use a borrowed reference; drop ends the lifetime.
let bucket = storage::open_bucket("payments")?;
let value = bucket.get("user-123")?;
// bucket dropped here; the host can free the resource entry.
```

A component that retains capability handles indefinitely accumulates resource-table entries on the host. The runtime caps this:

```rust
let mut table = ResourceTable::new();
table.set_max_entries(1024);   // Per-instance handle limit.
```

Exceeding the limit returns an error to the component, which can fail-safely.

### Step 5: Migration from Preview 1

Many existing modules are Preview 1. The migration:

```bash
# Convert a Preview 1 module to a Preview 2 component.
wasm-tools component new \
  --adapt wasi_snapshot_preview1=adapter.wasm \
  -o component.wasm \
  module.wasm
```

The adapter (`adapter.wasm` from `https://github.com/bytecodealliance/wasmtime/releases`) wraps Preview 1 imports with Preview 2 implementations. The result is a component that runs in a Preview 2 host while preserving Preview 1 semantics.

For new development, prefer native Preview 2 — the language toolchains (`cargo component`, `componentize-py`, `componentize-js`) generate components directly without going through Preview 1.

## Expected Behaviour

| Signal | Preview 1 | Preview 2 |
|--------|-----------|-----------|
| Module's syscall-level audit | All Preview 1 imports listed flat | WIT world enumerates explicit capability imports |
| Filesystem access without an explicit grant | Module fails at runtime if no preopens are given | Module fails to instantiate if `wasi:filesystem` is in the world but no preopens given |
| Network access | `sock_connect` import either present or absent | `wasi:sockets/tcp` and `wasi:http/outgoing-handler` separately importable; HTTP can be allowed without raw sockets |
| Composition | Modules link via Linker; everything is in one namespace | Components compose via WIT; capabilities contained in component boundaries |
| Auditing component imports | Inspect the import section of the binary | `wasm-tools component wit` produces a structured WIT document |
| Sub-delegation of capabilities | Not modeled | Explicit; one component cannot pass a capability it does not have |

Verify a component's world matches expectations:

```bash
wasm-tools component wit ./payments.wasm | diff - expected-world.wit
# (no diff = component imports match the policy-approved world)
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Strict import allowlist | Components cannot use capabilities they did not declare | Tooling must validate at upload time | Bake the validator into the upload pipeline; reject before storage. |
| Per-tenant WasiCtx | Capabilities scoped to the tenant's intended environment | More host-side configuration per request | Generate `WasiCtxBuilder` from a tenant-config object; reuse infrastructure across tenants. |
| Component composition | Tenants can ride on a hardened platform component | Composition tooling is newer than module-level linking | Stick with current `wasm-tools` versions; pin to a known-good release. |
| Resource lifetime | Resource-table entries bounded; no leak from runaway handles | Components must drop handles when done | Idiomatic in Rust (RAII); for languages without RAII, ensure component bindings provide a drop pattern. |
| Migration overhead | Preview 1 modules need adapter or rewrite | Adapter adds startup cost; rewrite is engineering work | Use the adapter as a transition step. New work in Preview 2 only. |
| Interface stability | Preview 2 is stable; the world is auditable | Community is still defining semi-standard interfaces (e.g., `wasi:keyvalue`) | Pin to standardized interfaces (`wasi:filesystem`, `wasi:http`, `wasi:sockets`); avoid pre-1.0 interfaces in security-critical paths. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Component imports forbidden interface | Upload rejected | Validation tooling fails the upload with the specific interface name | Refuse to deploy. Component author must remove or replace the import. |
| Capability handle leaked to long-lived state | Resource-table entry persists until process restart | Resource-table size grows over time; metrics show monotonic increase | Add lifetime bounds to handle storage; release on TTL or LRU. The component-level fix is to use scoped handles, not stored ones. |
| Composition grants over-broad capability | Composed artifact has more capabilities than the inner tenant declared | `wasm-tools component wit` of the composed artifact shows additional imports | Review the platform component's imports; constrain to what genuine tenants need. Tenants should not implicitly receive platform's broader access. |
| WASI version mismatch | Component built against `0.2.0` runs in a host with `0.2.1` runtime | At instantiation: type-check failure on resource shape | Pin runtime and component versions in deploy manifest. Upgrade in coordinated waves. |
| Preview 1 adapter behaves differently than expected | Module that worked in Preview 1 produces unexpected results in Preview 2 | Inconsistent behaviour for blocking I/O, errno values | Investigate the adapter version; some early adapters had subtle behaviour mismatches. Upgrade to the current adapter or rewrite as native Preview 2. |
| Capability passing in custom interfaces leaks | A custom interface that passes a `borrow<descriptor>` accidentally exposes filesystem to a sub-component | Audit the WIT of intermediate components | Re-design the interface to take pre-resolved values rather than resource handles. |

## Related Articles

- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [WASM Component Model Security Boundaries](/articles/wasm/wasm-component-model-security/)
- [WASM Workloads on Kubernetes](/articles/wasm/wasm-on-kubernetes/)
- [OCI WASM Module Signing and Verification](/articles/wasm/wasm-oci-signing/)
- [Edge Runtime WASM Hardening](/articles/wasm/edge-wasm-hardening/)
