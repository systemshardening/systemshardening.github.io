---
title: "WASM Component Composition Security: Capability Flow and Interface Boundaries"
description: "The WASM Component Model enables building applications from composed components — but capability flow between components, confused deputy attacks, and supply chain risks in composed graphs require explicit security design. This guide covers WIT interface auditing, transitive capability control, and secure composition with wasm-compose."
slug: wasm-component-composition-security
date: 2026-05-07
lastmod: 2026-05-07
category: wasm
tags:
  - wasm-component-model
  - component-composition
  - interface-types
  - capability-security
  - wit
personas:
  - security-engineer
  - platform-engineer
article_number: 575
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/wasm/wasm-component-composition-security/
---

# WASM Component Composition Security: Capability Flow and Interface Boundaries

## Problem

The WASM Component Model formalises what shared-library composition never could: every call crossing a component boundary is typed, named, and explicitly wired. Components connect via WIT (WebAssembly Interface Types) — one component's exports satisfy another component's imports, no shared memory involved. When it works correctly, the composition graph is the security policy: what each component can do is determined entirely by what interfaces were wired to it.

But "no shared memory" does not mean "no attack surface." Composition introduces a distinct class of vulnerabilities that do not exist in monolithic WASM modules:

- **Transitive capability flow.** A capability handle passed as a WIT resource type from component A to component B transfers access. If A holds a filesystem descriptor and an interface call passes that descriptor to B, B now has filesystem access — regardless of whether the composition author intended B to have it. The graph determines what flows; an unreviewed graph leaks capabilities silently.
- **Confused deputy attacks at composition interfaces.** A high-privilege platform component exports interfaces that lower-privilege tenant components call. If those interfaces accept raw paths, URLs, or keys as caller-controlled parameters, a malicious tenant can manipulate the platform into operating on resources outside the tenant's intended scope. The platform acts as a confused deputy: it has capability, and the adversary has found a way to aim it.
- **Semantic type confusion.** WIT type checking is structural. Two components that exchange `string` for a `bucket-name` parameter will link successfully whether the caller sends a valid bucket name or `../../secrets/db-password`. The type system catches shape mismatches; it does not enforce semantic contracts. Security must be built into the interface design itself, not delegated entirely to type checking.
- **Over-exposed WIT interfaces as attack surface.** A component that exports more functions than its callers need expands the available attack surface. Every exported function is a potential confused deputy entry point. Interface minimalism is not just good engineering practice — it is a security control.
- **Supply chain risks in the composition graph.** A composed application assembles components from multiple sources. Each source is a dependency. A compromised third-party component that gains a new import in a routine update silently acquires new capability when the composition is rebuilt. Without per-component digest pinning and WIT interface diffing, supply chain substitution is undetectable.
- **Tooling version skew between composition and runtime.** Components composed with `wasm-tools compose` at one version may behave unexpectedly when run by a Wasmtime version that handles canonical ABI details differently. Composition and runtime toolchain versions must be coordinated.

**Target systems:** WASM Component Model 1.0 (WIT `0.2.0+`), `wasm-tools compose`, WAC (WebAssembly Composition language), Wasmtime 22+, `cargo-component`, `wit-bindgen` 0.x, JCO 1.x.

## Threat Model

**Adversary 1 — Confused deputy via platform interface.** A low-privilege tenant component is composed with a high-privilege platform component. The platform exports a `read-file` function that uses its own filesystem capability on behalf of callers. The tenant crafts a path argument of `../../secrets/db-password` and calls `read-file`. The platform, acting as the tenant's agent, returns the contents of a file the tenant was never granted access to.

**Adversary 2 — Transitive resource handle exfiltration.** The platform passes a `borrow<bucket>` handle to a tenant during an authorised operation. The tenant's implementation (a third-party component) stores a copy of the underlying handle index in component-local state. A subsequent call from the tenant to a different interface function uses the retained index to perform bucket operations outside any authorised call frame.

**Adversary 3 — Composition graph mis-wiring at deploy time.** A platform operator uses `wasm-tools compose` to assemble the graph. A configuration error wires `wasi:filesystem/types/descriptor` directly to the tenant component rather than through the platform's scoped bucket interface. The composition succeeds — the tenant's WIT world accepts the import — and the tenant acquires unrestricted filesystem access.

**Adversary 4 — Supply chain compromise via component update.** A composed application depends on a third-party logging component from a public registry. A compromised maintainer account publishes a new version that adds `wasi:http/outgoing-handler` as an import. When the composition is rebuilt with the updated component, the logging component gains the ability to exfiltrate received log entries to an attacker-controlled endpoint, using HTTP capability the composition legitimately grants it.

**Access requirements.** Adversaries 1 and 2 require authoring a tenant component. Adversary 3 requires deploy-time configuration access. Adversary 4 requires a compromised upstream registry account.

**Blast radius.** In a correctly designed composition, the blast radius of a compromised leaf component is bounded by the interfaces wired to it. In a mis-designed composition — where the platform component wires broad capabilities to leaf components — the blast radius approaches that of the platform itself.

## Configuration

### Step 1: Map the Composition Trust Graph Before Writing WIT

Before writing a single WIT definition, draw the trust tiers. Every directed edge in the diagram is a capability decision; the diagram is the security design document.

```
# Trust tier diagram — commit this alongside the composition config.
#
#  ┌──────────────────────────────────────────────────────────┐
#  │  Host (native process)                                   │
#  │  Grants: full WASI surface to Tier 0 components only     │
#  └──────┬───────────────────────────────────────┬───────────┘
#          │ capability grant (full)               │ capability grant (log dir only)
#  ┌───────▼──────────────┐             ┌──────────▼───────────────┐
#  │  Platform Component  │             │  Observability Component  │
#  │  Tier 0 — high trust │             │  Tier 0 — high trust     │
#  │  Holds: filesystem,  │             │  Holds: filesystem        │
#  │  network, secrets    │             │  (log directory only)     │
#  └───────┬──────────────┘             └──────────▲───────────────┘
#           │ narrow exports only                   │ write-only log-sink
#  ┌────────▼──────────────────────────────────────┤
#  │  Tenant Component (Tier 1 — untrusted)        │
#  │  Imports: myorg:storage/buckets               │
#  │           myorg:network/api-call              │
#  │           myorg:logging/sink ─────────────────┘
#  │  Does NOT import: wasi:filesystem, wasi:http  │
#  └───────────────────────────────────────────────┘
```

This diagram has three consequences for the WIT design that follows:

1. The platform never exposes raw filesystem or HTTP primitives to the tenant. Every platform export is a capability-attenuating wrapper.
2. The observability component is wired independently by the host; it does not inherit the platform's full filesystem grant.
3. The tenant's WIT world should not contain `wasi:filesystem` or `wasi:http` import declarations. If `wasm-tools component wit` of the composed artifact shows those imports unmet, the wiring is wrong.

### Step 2: Design Capability-Attenuating Interfaces to Eliminate Confused Deputy

Confused deputy attacks succeed when the platform exports an interface that lets the caller control capability-bearing parameters — paths, URLs, database table names, secret identifiers — directly. The fix is not better input validation: it is removing the capability-bearing parameter from the caller's control entirely.

The unsafe pattern: filesystem semantics leaked to the caller.

```wit
// Bad — callers supply arbitrary paths. Every call is a potential traversal.
interface storage {
  read-file:  func(path: string) -> result<list<u8>, storage-error>;
  write-file: func(path: string, data: list<u8>) -> result<unit, storage-error>;
  delete-file: func(path: string) -> result<unit, storage-error>;
}
```

The platform's implementation must now defend against `../../secrets/db-password`, null bytes, symlinks, and every other path manipulation technique. One missed case is a confused deputy.

The safe pattern: opaque resource handles eliminate caller-controlled paths entirely.

```wit
// myorg:storage/buckets@1.0.0
// Callers receive a bucket handle. The platform maps bucket names to storage
// paths internally. Callers cannot construct paths or escape the bucket namespace.

package myorg:storage@1.0.0;

interface buckets {
  resource bucket {
    get:       func(key: string) -> result<list<u8>, bucket-error>;
    put:       func(key: string, value: list<u8>) -> result<unit, bucket-error>;
    delete:    func(key: string) -> result<unit, bucket-error>;
    list-keys: func(prefix: string) -> result<list<string>, bucket-error>;
  }

  variant bucket-error {
    not-found,
    unauthorized,
    quota-exceeded,
    key-too-long,
    // Intentionally absent: path-invalid.
    // Callers should never observe filesystem error semantics.
  }

  // The platform authorises bucket access based on the caller's identity.
  // A tenant requesting a bucket it has not been granted receives `unauthorized`.
  open-bucket: func(name: string) -> result<bucket, bucket-error>;
}
```

`open-bucket` maps `name` to a storage path internally and validates the caller's entitlement before returning the handle. Once the tenant holds a `bucket`, every operation goes through the resource's methods — which the platform implements, enforcing key length limits and character validation. The tenant cannot request an arbitrary path; it can only name a bucket and wait for authorisation.

Apply the same attenuation to network access:

```wit
// myorg:network/api-call@1.0.0
// Callers reference endpoint IDs — platform-managed names, not raw URLs.
// The platform resolves IDs to URLs and performs the request.
interface api-call {
  resource pending-call {
    status: func() -> call-status;
    body:   func() -> result<list<u8>, call-error>;
  }

  variant call-error   { timeout, forbidden-endpoint, network-error, }
  variant call-status  { pending, complete, failed, }

  post: func(endpoint-id: string, body: list<u8>) -> result<pending-call, call-error>;
}
```

A compromised tenant cannot exfiltrate data to an arbitrary URL. It can only call endpoints the platform has registered. A completely compromised tenant component is therefore constrained to the platform's pre-approved endpoint allowlist — confused deputy by HTTP is eliminated by interface design.

### Step 3: Control Transitive Capability Flow With Resource Ownership Semantics

WIT resource types carry explicit ownership annotations. `own<T>` transfers ownership to the callee — the handle is consumed and the caller can no longer use it. `borrow<T>` grants scoped access for the duration of the call — the callee cannot store the handle past the call's return.

Design interfaces to use `borrow<T>` for handles that should not outlive a single operation:

```wit
interface buckets {
  resource bucket {
    // snapshot borrows: the caller retains ownership; the snapshot function
    // cannot store the handle beyond its stack frame.
    snapshot: func(b: borrow<bucket>) -> result<snapshot-id, bucket-error>;

    // finalize takes ownership: the handle is consumed.
    // The platform can reclaim the underlying resource.
    finalize: func(b: own<bucket>) -> result<unit, bucket-error>;
  }
}
```

In Rust bindings generated by `wit-bindgen`, `borrow<bucket>` becomes `&Bucket` (a reference; the borrow checker prevents it outliving the call) and `own<bucket>` becomes `Bucket` (moved; the compiler prevents copying). This is compile-time prevention of transitive handle leakage in Rust components.

For cross-language compositions where JS or Python components call platform interfaces, Rust's borrow checker is not available. Add runtime handle lifetime tracking in the Wasmtime host:

```rust
// In the Wasmtime host implementation of the bucket resource.
// Track when a borrow handle is issued and assert it is released before
// the call that issued it returns.

fn issue_bucket_borrow(
    store: &mut Store<HostState>,
    bucket_id: BucketId,
) -> BucketBorrowHandle {
    let handle = store.data_mut().handle_tracker.issue_borrow(bucket_id);
    // Schedule a check: if this borrow handle is still live when the
    // current call frame exits, log an error and forcibly release it.
    handle
}
```

The pattern to audit in component implementations:

```rust
// Danger pattern: storing a received resource in component-global state.
// wit-bindgen prevents this for borrow<T> in Rust because BucketBorrow
// is not 'static — but the intent may be expressed with unsafe or
// by storing the raw resource table index.

static RETAINED: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
// If a code review encounters any static that stores a handle index,
// treat it as a security finding.
```

When a tenant component requires session-scoped access (multiple operations before releasing a handle), design the session as a resource rather than retaining borrowed handles:

```wit
interface session {
  resource active-session {
    read:   func(key: string) -> result<list<u8>, session-error>;
    write:  func(key: string, value: list<u8>) -> result<unit, session-error>;
    commit: func() -> result<unit, session-error>;
  }

  open-session: func(token: string) -> result<active-session, session-error>;
}
```

The tenant holds an `active-session` resource for the transaction lifetime, then releases it. The platform tracks active sessions and enforces per-tenant quotas on concurrent sessions — providing a natural rate limit on capability acquisition.

### Step 4: Auditing the Composition Graph With wasm-tools and WAC

After building a composition, immediately inspect its import surface. The composed artifact's remaining imports are the capabilities the host must provide. If the graph was wired correctly, every capability granted to a leaf component should have been satisfied within the composition — the only remaining imports should be those explicitly granted by the host to the top-level composed artifact.

```bash
# Build the initial composition.
wasm-tools compose \
  --definitions platform.wasm \
  --definitions observability.wasm \
  --output composed.wasm \
  tenant.wasm

# Inspect remaining imports of the composed artifact.
wasm-tools component wit composed.wasm

# Specifically: list only import lines and sort them.
wasm-tools component wit composed.wasm | grep "^  import" | sort
```

Automate the surface check in CI with a baseline file:

```bash
#!/usr/bin/env bash
# check-composition-surface.sh — run after every compose step.
# Fail if the import surface expands beyond the committed baseline.

BASELINE="composition-imports.baseline"
ACTUAL=$(wasm-tools component wit composed.wasm | grep "^  import" | sort)

if [ ! -f "$BASELINE" ]; then
  printf '%s\n' "$ACTUAL" > "$BASELINE"
  echo "Baseline written. Review and commit $BASELINE."
  exit 0
fi

EXPECTED=$(sort < "$BASELINE")
if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "ERROR: composition import surface has changed."
  diff <(echo "$EXPECTED") <(echo "$ACTUAL")
  echo "If the change is intentional, update and commit $BASELINE after review."
  exit 1
fi

echo "Composition surface unchanged — OK."
```

Additionally, perform a targeted negative check for capabilities that should never appear in the composed artifact:

```bash
# The composed artifact should NOT import wasi:filesystem — the tenant
# must receive only the scoped bucket interface, not raw filesystem access.
if wasm-tools component wit composed.wasm | grep -q "wasi:filesystem"; then
  echo "FAIL: wasi:filesystem appears in composed artifact import surface."
  echo "The tenant component is receiving raw filesystem access."
  echo "Check the composition wiring — platform bucket interface may be mis-wired."
  exit 1
fi
echo "PASS: wasi:filesystem not in composed artifact import surface."

# The composed artifact should NOT import wasi:http — tenants should use
# the platform's endpoint-ID api-call interface, not raw HTTP.
if wasm-tools component wit composed.wasm | grep -q "wasi:http/outgoing-handler"; then
  echo "FAIL: wasi:http/outgoing-handler appears in composed artifact."
  exit 1
fi
echo "PASS: wasi:http/outgoing-handler not in composed artifact."
```

For complex compositions, use WAC (WebAssembly Composition language) instead of `wasm-compose` TOML/YAML. WAC expresses the composition graph as code — every capability wire is an explicit, reviewable statement.

```wac
// composition.wac — the composition security policy.
// Every assignment is a capability decision. Treat this file as an IAM policy.

package myorg:deployment;

// Instantiate the platform — it receives host-granted WASI capabilities.
let platform = new myorg:platform { ... };

// Instantiate observability — receives only the log-directory filesystem grant,
// not the platform's full filesystem access.
let obs = new myorg:observability {
  "wasi:filesystem/types": platform.log-filesystem,
};

// Instantiate the tenant — receives only the attenuating interfaces.
// Every listed import is intentional. Everything unlisted is denied.
let tenant = new myorg:tenant {
  "myorg:storage/buckets":  platform.buckets,
  "myorg:network/api-call": platform.api-call,
  "myorg:logging/sink":     obs.log-sink,
  // Intentionally absent:
  //   "wasi:filesystem/types"        -- tenant has no direct filesystem
  //   "wasi:http/outgoing-handler"   -- tenant uses endpoint-ID api-call only
  //   "wasi:sockets/tcp"             -- no socket access
};

// Export only the HTTP handler. Nothing else from any component is exported.
export tenant.incoming-handler;
```

Any pull request that modifies `composition.wac` requires a security review. Changes to composition wiring are equivalent in significance to changes to IAM policies — they directly determine what each component can do.

Validate the WAC composition:

```bash
wac encode \
  --dep myorg:platform=platform.wasm \
  --dep myorg:observability=observability.wasm \
  --dep myorg:tenant=tenant.wasm \
  -o composed.wasm \
  composition.wac

# Immediately run the surface check.
bash check-composition-surface.sh
```

### Step 5: Auditing WIT Interface Exposure — Minimal Interface Principles

Every function a component exports is attack surface. Audit each WIT interface with the principle of minimal exposure: export only what callers legitimately need, and expose the narrowest possible type for each parameter.

Run an interface exposure audit:

```bash
# List all exports of every component in the composition.
for wasm in platform.wasm observability.wasm tenant.wasm; do
  echo "=== $wasm exports ==="
  wasm-tools component wit "$wasm" | grep "^  export"
done
```

Evaluate each export against three questions:

1. Does any downstream component actually import this function? If not, it should not be exported.
2. Does the function accept any parameter that could be used to redirect the component's internal capability to an unintended target? If so, replace the parameter with an opaque resource handle or a pre-enumerated variant type.
3. Does the function return data that crosses the trust boundary in both directions? Ensure return types do not leak internal state (error messages that include filesystem paths, SQL queries, or stack traces constitute information disclosure across the composition boundary).

For functions that accept strings as capability-bearing identifiers, consider replacing `string` with a purpose-built resource or variant type:

```wit
// Before: arbitrary string — structural type safety, no semantic enforcement.
interface config {
  get-setting: func(key: string) -> result<string, config-error>;
}

// After: enumerated key type — only the declared keys can be requested.
// A caller cannot request a key that is not in the variant.
interface config {
  enum config-key {
    database-pool-size,
    request-timeout-ms,
    feature-flag-new-ui,
    // Keys not listed here cannot be requested — period.
  }
  get-setting: func(key: config-key) -> result<string, config-error>;
}
```

If the key space is too large for a static enum, use an opaque resource token issued by the platform during an authorised configuration grant, rather than accepting arbitrary strings from callers.

### Step 6: Testing Components in Isolation Before Composition

Composed component security depends on each component's invariants holding under adversarial inputs — including inputs delivered through composition interfaces by co-composed components. Test each component in isolation with a Wasmtime-based harness that exercises adversarial inputs before admitting the component to the composition.

```rust
// tests/platform_interface_security.rs

#[cfg(test)]
mod platform_bucket_security {
    use wasmtime::component::*;
    use wasmtime::*;
    use wasmtime_wasi::preview2::*;

    #[tokio::test]
    async fn path_traversal_in_bucket_name_rejected() {
        let (mut store, platform) = setup_platform_component().await;

        let traversal_attempts = [
            "../../secrets",
            "../admin",
            "bucket\x00null-byte",
            "valid/but/has/slashes",
            "",
            "a".repeat(256).as_str(), // over-length name
        ];

        for bad_name in traversal_attempts {
            let result = platform
                .myorg_storage_buckets()
                .call_open_bucket(&mut store, bad_name)
                .await
                .expect("call should not trap");
            assert!(
                result.is_err(),
                "Expected rejection for bucket name: {:?}", bad_name
            );
        }
    }

    #[tokio::test]
    async fn bucket_key_length_limit_enforced() {
        let (mut store, platform) = setup_platform_component().await;
        let bucket = open_authorised_test_bucket(&mut store, &platform).await;

        let oversized_key = "k".repeat(513);
        let result = bucket
            .call_get(&mut store, &oversized_key)
            .await
            .unwrap();
        assert!(
            matches!(result, Err(BucketError::KeyTooLong)),
            "Expected KeyTooLong error for 513-byte key"
        );
    }

    #[tokio::test]
    async fn tenant_without_capability_wiring_cannot_instantiate() {
        // Verify that the tenant component fails to instantiate when its
        // imports are not satisfied — i.e., that it genuinely depends on
        // the platform interfaces rather than degrading silently.
        let engine = Engine::default();
        let mut linker: Linker<WasiCtx> = Linker::new(&engine);
        // Wire only WASI minimum — no platform interfaces.
        wasmtime_wasi::preview2::add_to_linker_async(&mut linker, |cx| cx).unwrap();

        let bytes = std::fs::read("target/wasm32-wasip2/release/tenant.wasm").unwrap();
        let component = Component::new(&engine, &bytes).unwrap();
        let mut store = Store::new(&engine, build_minimal_wasi_ctx());

        let result = linker.instantiate_async(&mut store, &component).await;
        assert!(result.is_err(), "Tenant must not instantiate without platform imports");
    }
}
```

Run isolation tests in the CI pipeline before the `wasm-tools compose` step. A component that fails its isolation tests is not admitted to the composition regardless of whether the composition would otherwise succeed.

### Step 7: Supply Chain Integrity for Composed Component Dependencies

Each component in the composition graph is a supply chain dependency. Apply the same controls used for software packages: digest pinning, signature verification, and interface diffing between versions.

Pin every component by content digest in the composition manifest:

```toml
# components.toml — composition dependency manifest.
# Digests are SHA-256 of the .wasm artifact. Updated by automated PRs only.

[[component]]
name        = "platform"
source      = "oci://registry.myorg.com/wasm/platform"
version     = "1.4.2"
digest      = "sha256:8f3a1c9e2d47b60ae4c..."
trust-tier  = "internal"

[[component]]
name        = "observability"
source      = "oci://registry.myorg.com/wasm/observability"
version     = "2.0.1"
digest      = "sha256:4b2e7f1d93a5c08b1d9..."
trust-tier  = "internal"

[[component]]
name        = "tenant"
source      = "oci://registry.myorg.com/wasm/tenant"
version     = "3.1.0"
digest      = "sha256:1a9c5e2b74d8f30e..."
trust-tier  = "untrusted"
```

Verify digests before composing:

```bash
#!/usr/bin/env bash
# verify-component-digests.sh
# Fails if any component's actual SHA-256 does not match the manifest.

set -euo pipefail

declare -A EXPECTED_DIGESTS=(
  ["platform.wasm"]="8f3a1c9e2d47b60ae4c..."
  ["observability.wasm"]="4b2e7f1d93a5c08b1d9..."
  ["tenant.wasm"]="1a9c5e2b74d8f30e..."
)

for wasm in "${!EXPECTED_DIGESTS[@]}"; do
  actual=$(sha256sum "$wasm" | awk '{print $1}')
  expected="${EXPECTED_DIGESTS[$wasm]}"
  if [ "$actual" != "$expected" ]; then
    echo "FAIL: digest mismatch for $wasm"
    echo "  expected: $expected"
    echo "  actual:   $actual"
    exit 1
  fi
  echo "OK: $wasm"
done
```

When a component is updated, diff the WIT interface surface between the old and new versions before updating the manifest digest:

```bash
# WIT interface diff — a security review step for every component update.
wasm-tools component wit old-tenant.wasm > old-tenant.wit
wasm-tools component wit new-tenant.wasm > new-tenant.wit
diff old-tenant.wit new-tenant.wit

# Any new `import` line in the diff is a capability acquisition event.
# The updated component is requesting access to something it did not request before.
# This requires an explicit security review before the new digest is committed.
```

For third-party components from public registries, additionally verify Sigstore/cosign signatures on the OCI artifact before pulling, and require SLSA provenance attestations at level 2 or higher. A component claiming to be built from a specific source revision but lacking a provenance attestation should not be admitted to a composition that handles sensitive data.

## Expected Behaviour

| Signal | Unreviewed composition | Hardened composition |
|---|---|---|
| Tenant passes `../../secrets` to storage interface | Result depends on implementation's path validation | Bucket names are not paths; `open-bucket("../../secrets")` is rejected by the platform's name allowlist before any filesystem operation |
| Composition mis-wires `wasi:filesystem` to tenant | Tenant acquires unrestricted filesystem access silently | WAC script does not wire `wasi:filesystem` to tenant; baseline surface check detects and blocks deploy |
| Component update adds a new WIT import | Silently admitted; new capability acquired without review | WIT interface diff surfaces the new import; digest mismatch blocks compose until the manifest is updated after a security review |
| Composition import surface expands between builds | No detection | Baseline check fails CI; diff is shown; update requires explicit approval |
| Tenant stores a borrowed resource handle | Handle retained; capability persists beyond call scope | `borrow<T>` semantics prevent this at compile time in Rust; runtime handle tracking catches it in JS/Python components |
| Low-privilege component calls platform to reach arbitrary URL | Platform HTTP capability used as proxy; SSRF succeeds | Platform's `api-call` interface uses endpoint IDs; unmapped endpoint ID returns `forbidden-endpoint`; arbitrary URLs are not resolvable |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Opaque resource handles instead of path/URL parameters | Eliminates path traversal and SSRF at the interface layer; confused deputy requires compromising platform implementation | Additional interface design work; callers lose ad-hoc flexibility | Design resource interfaces once; reuse across tenant components; prefer WASI standard interfaces (`wasi:keyvalue`, `wasi:blobstore`) where available |
| WAC composition scripts instead of TOML/YAML | Every capability wire is explicit, reviewable code; diffs are meaningful; CI can enforce surface policies | WAC is a newer language with a smaller ecosystem; learning curve for platform engineers | Treat WAC files as security-policy documents; include in security review rotation; the explicitness is the purpose |
| Baseline import surface checks in CI | Detects capability creep automatically; every new import requires a decision | Baseline file must be maintained; updates are noisy when requirements legitimately change | Keep baseline in version control; treat updates as equivalent to IAM policy changes |
| Isolation testing before composition | Catches interface security bugs before they become composition vulnerabilities | Additional test infrastructure; requires a Wasmtime-based harness per component | Invest in shared harness tooling; component model type safety already reduces the surface relative to untyped plugin models |
| Component digest pinning | Prevents silent supply chain substitution | Manual process to update digests when components are legitimately updated | Automate via Renovate or a custom bot that opens PRs for component updates with the new digest populated, and automatically runs the WIT diff |
| `borrow<T>` for handle passing | Compile-time prevention of handle retention in Rust | No compile-time enforcement in JS/Python bindings | Add runtime handle lifetime tracking in the Wasmtime host for non-Rust component guests; alert on handles held past the issuing call's return |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| WAC wiring mistake grants wrong capability | Composed artifact retains an unexpected import; leaf component has access it should not hold | Baseline surface check fails in CI; `wasm-tools component wit` shows unexpected import | Correct the WAC script; recompose; re-run surface check; deploy the corrected artifact |
| WIT semantic mismatch (structurally compatible, semantically wrong) | Component links successfully but operates on wrong data; bucket names interpreted as paths | Isolation tests catch the mismatch; platform implementation rejects semantically invalid values | Refactor the interface to make semantic constraints explicit in types; replace raw strings with opaque resource handles for all capability-bearing identifiers |
| Supply chain update admitted without WIT diff review | New component version has a new import; capability acquired silently; data exfiltration begins | Component WIT diff check surfaces the new import; digest mismatch in the manifest blocks compose | Block the update; require a security review of the WIT diff and the component changelog before the manifest digest is updated |
| Resource handle lifetime violation in a non-Rust component | JS or Python component retains a borrowed resource handle; capability persists beyond intended scope | Runtime handle tracking in the Wasmtime host detects the handle held past call return | Terminate the affected component instance; audit the implementation; add a runtime assertion that the handle is released before the issuing call's return |
| Composition tooling version skew | Components composed with `wasm-tools` at one version behave unexpectedly with a different Wasmtime runtime | Runtime instantiation error or unexpected trap in the composed artifact | Pin `wasm-tools` and Wasmtime versions in CI; coordinate upgrades of both together; test composed artifacts against the target runtime version before deploying |
| Over-permissive logging interface used as exfiltration channel | Compromised tenant writes sensitive values to log sink; attacker reads logs from storage | Anomaly detection on log volume and content; structured log schema validation | Add rate limiting and field validation to the log-sink interface implementation; replace raw-string log functions with typed structured-event interfaces |

## Related Articles

- [WASM Component Model Security Boundaries](/articles/wasm/wasm-component-model-security/)
- [WebAssembly Dynamic Linking Security](/articles/wasm/wasm-dynamic-linking-security/)
- [WASI Preview 2 Capability-Based Security](/articles/wasm/wasi-preview-2-capabilities/)
- [cargo-component WASM Build Tool Supply Chain Security](/articles/wasm/cargo-component-supply-chain/)
- [Wasmtime Component String Transcoding OOB Read](/articles/wasm/wasmtime-component-string-transcoding/)
- [WASM Shared-Nothing Microservices Security](/articles/wasm/wasm-shared-nothing-microservices/)
