---
title: "WASM Component Model Security Boundaries: Composition, Capability Passing, and Trust Decisions"
description: "When you compose multiple components, every wire is a capability decision. The security story of a composed application lives in the WIT between components."
slug: "wasm-component-model-security"
date: 2026-04-27
lastmod: 2026-04-27
category: "wasm"
tags: ["wasm", "component-model", "wit", "composition", "capabilities"]
personas: ["platform-engineer", "security-engineer", "ml-engineer"]
article_number: 183
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/wasm/wasm-component-model-security/index.html"
---

# WASM Component Model Security Boundaries: Composition, Capability Passing, and Trust Decisions

## Problem

The component model turns WebAssembly into a composition primitive. A component is a self-contained module with a typed interface declared in WIT (WebAssembly Interface Type) — exports it provides, imports it requires, and resource types it manipulates. Components compose: one component's exports satisfy another component's imports, producing a new composite component with reduced (or zero) unmet imports.

The security implications are different from monolithic WASM modules:

- **Each composition wire is a capability decision.** When component A's `wasi:filesystem/types/descriptor` is wired to component B's import, B receives a filesystem handle from A. Whoever controls the composition decides what each component can access.
- **Components can sub-delegate capabilities they hold.** If A holds `wasi:http/outgoing-handler` and exposes a function that takes a URL and returns the response, A is voluntarily exposing some of its HTTP capability to its callers. The shape of that exposure is the security boundary.
- **The WIT is the audit document.** Every cross-component call is statically typed and named. Auditing a composed application means reading the WIT files, not the bytecode.
- **Resource types have lifetimes.** Resources (file descriptors, sockets, custom typed handles) are passed as `borrow<T>` (read-only, scoped) or `own<T>` (transferred, dropped at end of lifetime). Misuse leaks state across components.

By 2026, real applications compose multiple components: a platform component holding capabilities, a tenant component running customer logic, a logging component sinking observability events, a configuration component reading per-deployment settings. The composition graph defines the security model.

The specific gaps in a 2026 component-model deployment:

- Composition done at deploy time without explicit capability review.
- Resource handles passed without lifetime annotations, leaking across components.
- Custom interfaces designed without considering the trust boundary they create.
- Sub-delegation patterns that grant more capability than intended (passing a filesystem descriptor to a component that should only have access to one file).
- Lack of WIT-level audit tooling integrated into the deploy pipeline.

This article covers WIT trust-boundary design, capability containment patterns, resource lifetime hygiene, audit tooling, and runtime detection of capability misuse.

**Target systems:** Component model implementations: Wasmtime 22+ (Rust + C API), JCO (JavaScript), wasm-tools, cargo-component. WIT version: `0.2.0` (component-model-1.0).

## Threat Model

- **Adversary 1 — Sub-component author:** writes a component that, when composed into a larger application, abuses the capabilities passed to it.
- **Adversary 2 — Composer mis-wires:** a deploy-time configuration error wires a high-trust capability to a low-trust component (e.g., the platform's full filesystem handle passed to an untrusted tenant component).
- **Adversary 3 — Resource handle leaks across components:** a component receives a `borrow<descriptor>` and stores it in shared state where another, less-trusted component retrieves it.
- **Adversary 4 — Interface design that exposes unsafe operations:** a component's `export` interface offers a function whose semantics expose more than the designer intended (e.g., `fs.read(path)` that takes any path).
- **Access level:** Adversary 1 has component-build access. Adversary 2 has deploy-time configuration access. Adversary 3 has source-code access to the component design. Adversary 4 has interface-design authority.
- **Objective:** Acquire capabilities through composition that are not justified by the component's role.
- **Blast radius:** Bounded by the host's enumeration of capabilities at the *outermost* component. A correctly-designed composition propagates only the capabilities each level needs; a mis-designed composition gives leaf components the same view as the root.

## Configuration

### Step 1: Design Components With Trust Tiers in Mind

A composition graph has implicit trust levels. Make them explicit in the WIT.

```wit
// platform.wit — highest trust, holds all capabilities.
package myorg:platform@1.0.0;

world platform {
  // Imports: the full WASI surface.
  import wasi:filesystem/types@0.2.0;
  import wasi:http/outgoing-handler@0.2.0;
  import wasi:io/streams@0.2.0;

  // Exports: narrow interfaces for sub-components.
  export myorg:storage/buckets@1.0.0;
  export myorg:network/api-call@1.0.0;
  export myorg:logging/sink@1.0.0;
}
```

```wit
// tenant.wit — untrusted, holds only what platform exposes.
package myorg:tenant@1.0.0;

world tenant {
  import myorg:storage/buckets@1.0.0;
  import myorg:network/api-call@1.0.0;
  import myorg:logging/sink@1.0.0;

  export wasi:http/incoming-handler@0.2.0;
}
```

The tenant component cannot import `wasi:filesystem` directly. Even if a developer modifies the source to add the import, `cargo component build` will fail to link unless the tenant world is amended — and amending the world is a reviewable event.

### Step 2: Capability-Constrained Interface Design

Every export interface is a capability the component is willing to share. Design narrowly.

Wrong:

```wit
interface storage {
  // Exposes raw filesystem semantics. Caller can read any file the
  // platform has access to.
  read-file: func(path: string) -> result<list<u8>, error>;
  write-file: func(path: string, data: list<u8>) -> result<unit, error>;
}
```

Right:

```wit
interface storage {
  // Exposes scoped storage. Bucket names map to platform-managed paths.
  // Caller cannot escape via "../" — the platform implementation rejects.
  resource bucket {
    get: func(key: string) -> result<list<u8>, error>;
    put: func(key: string, value: list<u8>) -> result<unit, error>;
    delete: func(key: string) -> result<unit, error>;
    list-keys: func(prefix: string) -> result<list<string>, error>;
  }

  variant error {
    not-found,
    unauthorized,
    quota-exceeded,
    invalid-key,
  }

  open-bucket: func(name: string) -> result<bucket, error>;
}
```

The `bucket` resource is the capability. A tenant holds bucket handles only for buckets the platform explicitly opened on its behalf. The platform's `open-bucket` implementation maps bucket names to controlled storage paths, validates the tenant's authorization, and returns a `bucket` handle whose operations cannot escape the bucket.

### Step 3: Resource Lifetime Hygiene

Resources have lifetimes. The component model expresses ownership and borrowing:

```wit
interface storage {
  resource bucket {
    // borrow<bucket>: caller retains ownership; bucket is read but not consumed.
    snapshot: func(b: borrow<bucket>) -> result<snapshot, error>;

    // own<bucket>: caller transfers ownership; bucket is consumed.
    finalize: func(b: own<bucket>) -> result<final-state, error>;
  }
}
```

In Rust, `borrow` becomes `&Bucket`, `own` becomes `Bucket` (moved). Accidental cloning or storing a borrowed handle does not compile. In other languages (JS, Python), bindings enforce lifetime via runtime drops.

A pattern to avoid:

```rust
// Wrong — storing a borrow indefinitely.
struct Cache {
    bucket: Option<storage::Bucket>,    // own<bucket>; takes ownership
}

impl Cache {
    fn save(&mut self, b: storage::Bucket) {
        self.bucket = Some(b);   // bucket retained beyond intended scope
    }
}
```

The handle persists in `self.bucket` for the lifetime of the `Cache` instance. If the platform expected the handle to be dropped after a single operation, this pattern leaks the capability.

Better:

```rust
fn use_bucket_briefly(b: storage::Bucket) -> Result<(), Error> {
    // bucket dropped at end of function; capability returns to platform.
    b.put("key", b"value")?;
    Ok(())
}
```

### Step 4: Composition With wasm-tools

Compose components at deploy time, not at runtime. Composition is a static operation that produces a new component artifact:

```bash
# Compose tenant into the platform's exported world.
wasm-tools compose \
  --definitions platform.wasm \
  --output composed.wasm \
  tenant.wasm

# Inspect the composed artifact.
wasm-tools component wit composed.wasm > composed-world.wit
diff composed-world.wit expected-world.wit
```

Validate that the composed artifact's imports match what the host plans to provide:

```bash
# Audit the imports of the composed artifact.
wasm-tools component wit composed.wasm | grep "^  import"
# import wasi:http/incoming-handler@0.2.0
# (no other imports — platform's WASI imports are satisfied internally)
```

If the composed artifact unexpectedly imports `wasi:filesystem/types`, something has bypassed the platform layer. Reject and investigate.

### Step 5: Audit Tooling in the Pipeline

Component-model audits are static and cheap. Run them on every PR.

```yaml
# .github/workflows/component-audit.yml
name: Component audit
on: [pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - run: cargo install --locked wasm-tools

      - name: Build component
        run: cargo component build --release

      - name: Audit imports against allowlist
        run: |
          ALLOWED=(
            "wasi:io/streams@0.2.0"
            "wasi:io/error@0.2.0"
            "wasi:clocks/monotonic-clock@0.2.0"
            "wasi:http/incoming-handler@0.2.0"
            "wasi:http/outgoing-handler@0.2.0"
            "myorg:platform/storage@1.0.0"
            "myorg:platform/api-call@1.0.0"
          )
          IMPORTS=$(wasm-tools component wit \
            target/wasm32-wasip1/release/payments.wasm \
            | awk '/^  import / {print $2}' | tr -d ';')
          for i in $IMPORTS; do
            if ! printf '%s\n' "${ALLOWED[@]}" | grep -qx "$i"; then
              echo "Forbidden import: $i"
              exit 1
            fi
          done
          echo "All imports approved."
```

Block the merge if a new import not on the allowlist appears. Adding a new import is a security-review event, not a routine code change.

### Step 6: Runtime Capability Logging

When the host hands out a capability handle, log it. This produces an audit trail of which components held which capabilities at which times.

```rust
// In the host harness:
struct AuditedFilesystemHandle {
    inner: wasi_filesystem::Descriptor,
    component_id: String,
    granted_at: std::time::Instant,
}

impl AuditedFilesystemHandle {
    fn new(inner: wasi_filesystem::Descriptor, component_id: &str) -> Self {
        tracing::info!(
            component_id = %component_id,
            event = "capability_granted",
            capability = "wasi:filesystem/types/descriptor",
            "filesystem capability granted to component"
        );
        Self {
            inner,
            component_id: component_id.into(),
            granted_at: std::time::Instant::now(),
        }
    }
}

impl Drop for AuditedFilesystemHandle {
    fn drop(&mut self) {
        let lifetime = self.granted_at.elapsed();
        tracing::info!(
            component_id = %self.component_id,
            event = "capability_dropped",
            lifetime_ms = lifetime.as_millis() as u64,
        );
    }
}
```

Build dashboards on capability lifetime distribution. A component holding a filesystem descriptor for orders of magnitude longer than its peers is a leak signal.

## Expected Behaviour

| Signal | Without Component-Model Discipline | With |
|--------|------------------------------------|------|
| Inspecting a composed app's permissions | Read the source code | `wasm-tools component wit` shows full surface |
| Adding a new host call from a component | Source change; hard to audit | WIT change; CI audit fails until allowlist is updated |
| Sub-component's capability | Inherits everything passed to its parent | Receives only the explicit capabilities passed via WIT interfaces |
| Resource handle stored indefinitely | Compiles, runs, leaks | Lifetime annotations enforce drop |
| Cross-component data flow | Implicit, often via shared globals | Explicit via interface calls; enumerable from WIT |
| Audit complexity | Read all source | Read WIT files; bytecode is sealed contract |

Verify a composed application has the expected surface:

```bash
wasm-tools component wit ./composed.wasm | head -30
# Expected: only the imports the host has agreed to provide.

# Negative test: a tampered tenant that adds wasi:filesystem to its world.
# Composition should fail or the audit step should catch the new import.
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Narrow interface design | Capabilities cannot accidentally widen | More design work; more types defined | Reuse standard interfaces (`wasi:keyvalue`, `wasi:http`) where possible; only invent custom interfaces for application-specific operations. |
| Static composition | Auditable; deterministic | Requires deploy-time tooling; runtime composition not supported | Make composition part of the build, not the runtime. |
| Resource lifetime annotations | Compile-time enforcement of handle lifetime | Some complexity in interface design | Idiomatic in Rust; bindings for other languages (JS, Python, Go) handle this transparently. |
| WIT-level audits in CI | Catches capability creep | Maintenance of allowlists | Keep the allowlist with the application source; review with the same gravity as IAM changes. |
| Runtime capability logging | Audit trail for forensics | Telemetry overhead, log volume | Sample at high rate for ephemeral capabilities; record full lifecycle for long-lived. |
| Trust-tier separation | Different components can have different security postures | Composition graphs grow complex | Document the trust-tier diagram alongside the WIT files; keep it in source control. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Composition adds an unexpected import | Composed artifact requires a host-provided capability you did not anticipate | `wasm-tools component wit` of the composed artifact shows the unexpected import | Investigate which sub-component introduced it. Reject the deploy until the change is reviewed. |
| Sub-component leaks a borrowed resource | Capability handle persists in a way that lets unrelated code use it | Capability lifetime metric outlier; sub-component holds a handle past expected lifetime | Audit the sub-component's source; refactor to drop handles within the request scope. |
| Wide interface accidentally exposes platform capability | A custom interface that takes raw paths or URLs lets the caller request anything | Code review or security audit reveals the wide signature | Refactor to use scoped resource handles. The change is an ABI break for the interface; coordinate with consumers. |
| Composition tool version skew | Components built against `wasm-tools` v1.220 behave differently when composed by v1.230 | Composition errors at deploy time | Pin tooling versions; treat upgrades as version-controlled changes to the build system. |
| Component imports `wasi:filesystem` despite policy | A component the developer claimed had no filesystem access actually does | CI audit step flags the import | Block merge. Investigate whether the dependency tree pulled in a transitive component that introduced the import. |
| Resource ABI mismatch across versions | Components built against `wasi:io/streams@0.2.0` linked against `0.2.1` runtime fail | Runtime instantiation errors with type-checking failures | Pin runtime and component versions in deploy manifest. Roll versions in coordinated waves. |

## Related Articles

- [WASI Preview 2 Capability-Based Security](/articles/wasm/wasi-preview-2-capabilities/)
- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [WASM Workloads on Kubernetes](/articles/wasm/wasm-on-kubernetes/)
- [OCI WASM Module Signing and Verification](/articles/wasm/wasm-oci-signing/)
- [Edge Runtime WASM Hardening](/articles/wasm/edge-wasm-hardening/)
