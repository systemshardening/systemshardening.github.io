---
title: "WASM Shared-Nothing Architecture: Security Benefits of Zero Memory Sharing"
description: "WASM components communicate only through typed WIT interfaces — there is no shared memory between components. This architectural property eliminates entire classes of lateral movement and memory disclosure attacks. This guide explains how to design secure shared-nothing WASM systems with wasmCloud and the Component Model."
slug: wasm-shared-nothing-microservices
date: 2026-05-07
lastmod: 2026-05-07
category: wasm
tags:
  - wasm
  - shared-nothing
  - microservices
  - isolation
  - component-model
personas:
  - security-engineer
  - platform-engineer
article_number: 582
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/wasm/wasm-shared-nothing-microservices/
---

# WASM Shared-Nothing Architecture: Security Benefits of Zero Memory Sharing

## Why Shared-Nothing Is a Security Property, Not a Performance Pattern

In most discussions of microservice architecture, "shared-nothing" describes a scalability approach: stateless services that hold no session affinity and rely on external storage. That is useful for horizontal scaling. It is not what the WASM component model means by the term, and it is not the security property this article is about.

In the WASM component model, shared-nothing means exactly what it says: **two components share no memory, no globals, and no ambient authority whatsoever**. Communication between components occurs exclusively through typed WIT (WebAssembly Interface Types) function calls. Data is copied across the boundary using the canonical ABI; there is no pointer aliasing, no shared heap, no shared address space. A component cannot look into another component's linear memory regardless of what bug exists in the calling component, regardless of what offset it uses for a memory load, and regardless of what the host operating system permits.

This is a fundamentally different security guarantee from container isolation, which is a kernel-enforced namespace boundary that separates processes from each other but cannot prevent a compromised library inside a process from reading that process's secrets. Shared-nothing WASM changes the fundamental question an attacker must answer after compromising one component. In a shared-memory architecture, the answer to "what can I read now?" is "everything in this process's address space." In a shared-nothing WASM architecture, the answer is: "nothing outside my own linear memory, and I can only reach adjacent components through the typed interfaces I was explicitly granted at composition time."

Lateral movement in a shared-nothing system requires explicit message passing. Every data crossing a component boundary is a deliberate act, statically typed, visible in the WIT definition, and subject to runtime enforcement. This architectural property does not merely reduce the blast radius of a compromise — it eliminates entire classes of attack by removing the attack surface from the specification entirely.

**Target systems:** Wasmtime 27+, wasm-tools 1.220+, cargo-component 0.18+, wasmCloud 1.1+, Spin 3.0+. WIT syntax: component-model-1.0 (0.2.x package format).

## Threat Model

- **Adversary 1 — Compromised third-party component:** A library or plugin component included in the composition has a backdoor or is exploited at runtime. The adversary seeks to read secrets, exfiltrate data, or pivot to other components.
- **Adversary 2 — Lateral movement via wide interfaces:** A component that legitimately receives some capability abuses an overly broad WIT interface to reach data or operations beyond its intended scope (e.g., a logging component whose interface accepts a raw byte buffer it can write anywhere).
- **Adversary 3 — Capability accumulation:** Multiple individually-reasonable capability grants compose to give a component effective permissions that were not intended when each grant was made in isolation.
- **Adversary 4 — Memory disclosure between components:** An attacker in one component attempts to read the linear memory of another component to extract secrets, tokens, or private keys.
- **Access level:** All adversaries have component execution access inside the composed application. None have host-level code execution.
- **Objective:** Extract secrets from another component's memory; invoke capabilities not granted to the attacker's component; pivot through the composed application to reach a higher-privilege component.
- **Blast radius (without shared-nothing):** In a container-based architecture, all of these are possible without additional privilege escalation once a single service is compromised. In a WASM shared-nothing architecture, each is blocked by the specification — not by policy that can be misconfigured.

## What Shared-Nothing Means in the Component Model

The WASM component model specifies that each component has its own linear memory. There is no mechanism in the specification for two components to share a linear memory region. The `memory.grow` instruction operates on the component's private memory. The pooling allocator in Wasmtime assigns each component instance a separate virtual memory range backed by its own memory descriptor. When a component receives a `list<u8>` argument from another component across a WIT call, the runtime copies the bytes across the boundary using canonical ABI lifting and lowering. There is no pointer aliasing between the caller's memory and the callee's memory — ever.

This has a direct security consequence: **memory disclosure between components is impossible by specification**. There is no equivalent of `ptrace`, no `/proc/$pid/mem`, no shared `SharedArrayBuffer` between independent components unless the host explicitly provides one — and WASI does not include such a primitive. A compromised component cannot read another component's private keys, session tokens, or in-memory state regardless of what bugs exist in the compromised component's code. A memory access that goes out of bounds within a component produces a trap — not a disclosure of adjacent memory.

The absence of shared memory also eliminates memory race conditions as an inter-component attack surface. Race conditions on shared memory — TOCTOU vulnerabilities, data races that produce exploitable undefined behaviour — require two code paths to hold a reference to the same address. Component boundaries prevent that at the hardware level once the JIT-compiled code runs. The worst a bug in component A can do to component B is invoke the typed interface calls A was wired to call. It cannot flip a bit in B's linear memory.

The mechanism for cross-component communication is typed WIT interface calls. These are explicit, named, and statically typed. Every argument is serialised using the canonical ABI. The WIT definition is the complete, auditable description of what one component can ask of another.

## Contrasting with Container-Based Microservices

Understanding why shared-nothing is architecturally superior for security requires a direct comparison with containers.

In a typical Kubernetes microservice architecture, isolation has the following properties:

**Kernel sharing:** All containers on a node share the Linux kernel. A kernel CVE reachable from within a container namespace is a potential lateral movement vector. A compromised container that exploits a kernel vulnerability can potentially reach the host and all other containers on the node.

**Ambient authority:** A service running with a Kubernetes service account holds all the permissions granted to that account for the lifetime of the process, regardless of which code is currently executing. A compromised third-party library running in-process has the same network credentials, the same mounted secrets, the same ability to read environment variables as the application code that loaded it.

**Shared process heap:** Libraries running in-process with the service have full access to the process address space. Third-party npm packages, Python imports, and dynamically linked shared objects all share the heap with application secrets. A malicious library can read any variable in the process without any kernel vulnerability — it is running in the same address space.

**Network namespace sharing:** Containers in the same pod share a network namespace. Any service binding to localhost is reachable by all containers in the pod regardless of NetworkPolicy, which operates at the pod boundary.

In a WASM component model architecture, the isolation properties differ at every level:

**No kernel sharing for computation:** WASM modules do not make syscalls directly. All host interaction goes through WASI, which the host embedder controls. A kernel CVE in `nf_tables` does not affect the execution path of a WASM component that has no network capability grant, because that component never makes a network syscall.

**No ambient authority:** A WASM component has no network access, no filesystem access, and no environment variable access unless the host explicitly provides those imports. An untrusted component that does not receive `wasi:sockets` or `wasi:http/outgoing-handler` cannot make outbound network connections regardless of what code it contains.

**Private linear memory:** No other component can read a component's memory. A compromised third-party component can call only the functions it was explicitly wired to call; it cannot traverse a pointer into the host component's address space.

**Capability confinement:** Every resource a component can access must be passed to it through its imports. The component cannot acquire capabilities it was not granted at composition time. A component that only receives a typed key-value store handle cannot open a file, make a network call, or read environment variables — those capabilities are not in the WIT world and there is no ambient authority to inherit.

The shared-nothing model does not eliminate all risks. It eliminates a specific class: the class where compromise of one component automatically provides read access to adjacent components' memory, or inherits the process's full ambient authority.

## How the Component Model Enforces Shared-Nothing

The component model's enforcement operates at multiple layers, each independently sufficient.

**Specification-level enforcement:** The WASM specification defines linear memory as a private resource of the module instance. The canonical ABI specification requires that data crossing a component boundary be copied, not aliased. A conforming runtime cannot implement shared-nothing incorrectly without violating the specification.

**JIT-level enforcement:** Every memory access in WASM bytecode is bounds-checked against the component's memory size before the instruction executes. The JIT compiler (in Wasmtime, V8, SpiderMonkey) generates machine code that verifies the offset before each load and store. There is no way for a pointer to escape the component's memory segment regardless of arithmetic applied to it — the check fires before the hardware memory access.

**Composition-level enforcement:** `wasm-tools compose` wires components together by satisfying one component's imports with another component's exports. The tool does not expose a mechanism to pass a raw pointer or memory address across the boundary. Arguments must conform to their WIT types. A WIT function that accepts `string` receives a copied string; it does not receive a pointer into the caller's memory.

**Host-level enforcement:** The host runtime (Wasmtime, WasmEdge, wazero) instantiates each component into its own linear memory allocation. The instances do not share address space mappings. Even if a component executed arbitrary machine code — which the JIT prevents — it would need a kernel vulnerability to access another instance's virtual memory pages.

## Designing WIT Interfaces as Security Boundaries

The WIT interface is the security boundary between components. A poorly designed interface that exposes too much surface defeats shared-nothing at the semantic level. Even with perfect memory isolation, a component that can call `admin.execute-arbitrary-query(sql: string)` has effective access to the database.

The principle is minimal exposure: export only the operations the consumer legitimately needs. For each exported function, reason about what a compromised caller could do with it. Design the interface so the worst-case abuse is acceptable.

**Overly broad interface — avoid:**

```wit
// A logging interface that exposes path arguments.
interface logger {
  write-log: func(path: string, data: list<u8>) -> result<unit, error>;
}
```

A compromised component holding this interface can write to any path the logger has access to. The security boundary exists in memory, but the interface semantics allow arbitrary path traversal.

**Minimal interface — prefer:**

```wit
package myorg:logging@1.0.0;

interface sink {
  record log-entry {
    level:   log-level,
    service: string,
    message: string,
    // No raw byte buffers. No path arguments. No format strings.
  }

  enum log-level { trace, debug, info, warn, error }

  emit: func(entry: log-entry) -> result<unit, log-error>;
}
```

A compromised component holding the `sink` interface cannot write to arbitrary paths — the function does not accept a path argument. It cannot inject format strings — the message is a typed string value, not a format template. The worst-case abuse is flooding the log with crafted entries, which is a much narrower blast radius.

**Resource types as scoped capability handles:**

```wit
package myorg:storage@1.0.0;

interface buckets {
  resource bucket {
    get:  func(key: string) -> result<list<u8>, storage-error>;
    put:  func(key: string, value: list<u8>) -> result<unit, storage-error>;
    list: func(prefix: string) -> result<list<string>, storage-error>;
  }

  variant storage-error {
    not-found,
    quota-exceeded,
    invalid-key,
  }

  open-bucket: func(name: string) -> result<bucket, storage-error>;
}
```

The `bucket` resource is a capability token. A component that calls `open-bucket("payments-data")` receives a handle only if the platform's implementation grants it. The platform maps bucket names to actual storage paths internally — the caller never sees the path. The caller's handle is bounded to the operations on that specific bucket. It cannot escalate to other buckets, cannot traverse directory structures, and cannot see the underlying filesystem.

**World declarations as security manifests:**

```wit
// payments.wit — declares only what the payments component needs.
package myorg:payments@1.0.0;

world payments {
  import myorg:storage/buckets@1.0.0;       // Key-value storage.
  import myorg:logging/sink@1.0.0;           // Structured logging.
  import wasi:clocks/monotonic-clock@0.2.0;  // Timestamps only.
  // No network. No filesystem. No environment variables.

  export wasi:http/incoming-handler@0.2.0;
}
```

This world declaration is a complete security manifest. It is statically checkable at build time, at composition time, and at deploy time. Adding an import requires changing the WIT, which is a reviewable artefact in source control. A CI check that validates component imports against an allowlist makes capability creep visible before deployment.

## Isolating Compromised Third-Party Library Components

The WASM component model changes the supply chain security calculus for third-party dependencies. In a traditional microservice, a third-party npm package, Python package, or Go module runs in the same process as the application. If the package is malicious or compromised, it has the same filesystem access, network credentials, and in-memory secrets as the application that imported it. This is the attack surface that supply chain attacks on npm, PyPI, and crates.io exploit.

When a third-party library is packaged as a WASM component and composed into a larger application, its capability surface is defined by its world declaration and the imports the host wires to it — not by the transitive closure of everything the library could theoretically do. A malicious analytics component receives only the capabilities the composition grants it. If the composition does not wire `wasi:http/outgoing-handler` to the analytics component, it cannot exfiltrate data regardless of what code it contains.

Before including a third-party WASM component, audit its declared imports:

```bash
# Inspect the component's declared imports.
wasm-tools component wit third-party-analytics.wasm | grep "^  import"

# Expected (acceptable):
#   import wasi:clocks/monotonic-clock@0.2.0;
#   import myorg:events/collector@1.0.0;

# Unexpected (reject and investigate):
#   import wasi:filesystem/types@0.2.0;
#   import wasi:http/outgoing-handler@0.2.0;
#   import wasi:sockets/network@0.2.0;
```

A third-party analytics component that imports `wasi:http/outgoing-handler` is capable of exfiltrating data to an external endpoint. That import is visible before deployment. In a traditional library dependency, equivalent capability — making HTTP requests from inside a Node.js process — is invisible without reading and auditing the library's full source code.

This makes WASM component model supply chain auditing qualitatively different from traditional SCA tooling. Traditional SCA tools check version numbers and known CVEs. Component import auditing checks capability scope — a property that is structural rather than vulnerability-specific, and that holds even for zero-day vulnerabilities in the component's code.

Integrate this into the CI pipeline:

```bash
IMPORTS=$(wasm-tools component wit third-party-analytics.wasm \
  | awk '/^  import / {print $2}' | tr -d ';')
ALLOWED="wasi:clocks/monotonic-clock@0.2.0 myorg:events/collector@1.0.0"

for import in $IMPORTS; do
  if ! echo "$ALLOWED" | grep -qw "$import"; then
    echo "FAIL: Unexpected import from third-party component: $import"
    exit 1
  fi
done
echo "PASS: Third-party component imports within approved set."
```

Block the deployment if an unexpected import appears. A third-party component update that adds a network import is a security event, not a routine dependency bump.

## wasmCloud's Actor Model as Shared-Nothing Microservices

wasmCloud implements shared-nothing microservices concretely. In wasmCloud 1.0+, every service is a WASM component (called an actor). Actors communicate exclusively through capability providers — dedicated components that broker access to infrastructure: HTTP servers, key-value stores, blob storage, and messaging. An actor cannot open a socket or read a file without being linked to a capability provider at deploy time by an operator.

The actor model is shared-nothing in the sense that matters for security: actors do not share memory, do not share process space, and do not share credentials. An actor that handles payment processing and an actor that handles user authentication are distinct WASM components with separate linear memories and separate capability grants. If the authentication actor is compromised, the attacker can call only the capability provider interfaces that actor is linked to. It cannot access the payments actor's in-memory state, cannot call the payments database directly (it holds no link to the payments provider), and cannot read the payments actor's signing keys.

The link table is the capability policy. An operator establishes links between specific actors and specific providers with specific configuration:

```bash
# Link the authentication actor to the sessions key-value provider.
# The link configuration restricts it to the "sessions" bucket only.
wash link put \
  Mxxxxxxx-auth-actor \
  Vxxxxxxx-keyvalue-provider \
  wasmcloud:keyvalue \
  values='{"bucket":"sessions","prefix":"sess:"}'

# The payments actor gets a separate link to a separate bucket.
wash link put \
  Mxxxxxxx-payments-actor \
  Vxxxxxxx-keyvalue-provider \
  wasmcloud:keyvalue \
  values='{"bucket":"payments","prefix":"pay:"}'
```

Neither actor can see the other's bucket. If the authentication actor is compromised and the attacker attempts to access payment data, the capability provider enforces the link configuration and denies the request. The payments bucket is not in the authentication actor's link table, so the request never reaches it.

This is shared-nothing operationally: sharing requires an explicit operator action that creates an auditable, revisable link record. Default is no access, not default permit. Audit the link table with:

```bash
wash get links
# Output shows each actor-provider pair with its configuration.
# Every link is an explicit security decision.
```

Inter-actor communication in wasmCloud goes through the lattice's messaging layer, not through direct memory calls or shared data structures. An attacker who compromises one actor must send a message to reach another actor — a message that is typed, auditable, and deniable by the receiving actor's interface definition.

## Testing Shared-Nothing Security Properties

Testing that isolation properties hold requires constructing the adversarial scenario explicitly. The WASM specification guarantees hold at the abstract machine level, but tests validate that the host implementation is correct and the composition was built as intended.

**Test 1: Memory isolation between component instances**

```rust
#[test]
fn compromised_component_cannot_read_adjacent_memory() {
    let engine = Engine::default();

    // A "secrets" component that stores a known value in its linear memory.
    let secrets_wat = r#"
      (module
        (memory (export "memory") 1)
        (data (i32.const 0) "SECRET_TOKEN_ABC123")
        (func (export "get-secret") (result i32) (i32.const 0))
      )
    "#;

    // A "compromised" component that attempts an out-of-bounds read.
    // In a correct WASM runtime this produces a trap, not a disclosure.
    let attacker_wat = r#"
      (module
        (memory (export "memory") 1)
        (func (export "attempt-oob-read") (result i32)
          ;; Attempt to read at a large offset, hoping to land in another
          ;; module's memory allocation. In WASM this traps.
          (i32.load (i32.const 0xFFFF0000))
        )
      )
    "#;

    let secrets_module  = Module::new(&engine, secrets_wat).unwrap();
    let attacker_module = Module::new(&engine, attacker_wat).unwrap();

    let mut store = Store::new(&engine, ());
    let secrets_instance  = Instance::new(&mut store, &secrets_module, &[]).unwrap();
    let attacker_instance = Instance::new(&mut store, &attacker_module, &[]).unwrap();

    let attempt = attacker_instance
        .get_func(&mut store, "attempt-oob-read")
        .unwrap();

    // The OOB read must trap, not return data from the secrets component.
    let result = attempt.call(&mut store, &[], &mut [Val::I32(0)]);
    assert!(result.is_err(), "OOB read must trap, not return data");

    // The secrets component's memory remains intact.
    let secrets_mem = secrets_instance.get_memory(&mut store, "memory").unwrap();
    let data = secrets_mem.data(&store);
    assert_eq!(&data[0..18], b"SECRET_TOKEN_ABC123"[..18].as_ref());
}
```

**Test 2: Import confinement — composed artifact respects the approved capability set**

```bash
# Build and compose the application.
wasm-tools compose \
  --definitions platform.wasm \
  --output composed.wasm \
  analytics.wasm

# Verify the composed artifact's imports match the approved set.
IMPORTS=$(wasm-tools component wit composed.wasm | awk '/^  import / {print $2}')
ALLOWED="wasi:clocks/monotonic-clock@0.2.0 myorg:events/collector@1.0.0"

for import in $IMPORTS; do
  if ! echo "$ALLOWED" | grep -qw "$import"; then
    echo "FAIL: Unexpected import in composed artifact: $import"
    exit 1
  fi
done
echo "PASS: All imports within approved set."
```

**Test 3: Verifying no memory races between concurrently executing components**

```rust
#[test]
fn concurrent_components_cannot_race_on_shared_state() {
    // Each component instance gets its own memory. Concurrent execution
    // of two instances must not produce data races.
    let engine = Engine::new(Config::new().async_support(true)).unwrap();

    let counter_wat = r#"
      (module
        (memory (export "memory") 1)
        (global $counter (mut i32) (i32.const 0))
        (func (export "increment") (result i32)
          (global.set $counter
            (i32.add (global.get $counter) (i32.const 1)))
          (global.get $counter)
        )
      )
    "#;

    let module = Module::new(&engine, counter_wat).unwrap();

    // Two separate instances with separate globals — no shared state.
    let mut store_a = Store::new(&engine, ());
    let mut store_b = Store::new(&engine, ());
    let instance_a = Instance::new(&mut store_a, &module, &[]).unwrap();
    let instance_b = Instance::new(&mut store_b, &module, &[]).unwrap();

    let increment_a = instance_a.get_func(&mut store_a, "increment").unwrap();
    let increment_b = instance_b.get_func(&mut store_b, "increment").unwrap();

    let mut result_a = [Val::I32(0)];
    let mut result_b = [Val::I32(0)];
    increment_a.call(&mut store_a, &[], &mut result_a).unwrap();
    increment_b.call(&mut store_b, &[], &mut result_b).unwrap();

    // Each instance increments its own counter from 0 to 1.
    // There is no shared global to race on.
    assert_eq!(result_a[0].unwrap_i32(), 1);
    assert_eq!(result_b[0].unwrap_i32(), 1);
}
```

**Test 4: wasmCloud capability link confinement**

```bash
# Establish a link for the events actor only to the events messaging topic.
wash link put $EVENTS_ACTOR $MESSAGING_PROVIDER wasmcloud:messaging \
  values='{"subscriptions":"events.*"}'

# Attempt to publish to the payments topic from the events actor.
# The provider enforces the link configuration; the call should be denied.
wash call $EVENTS_ACTOR myorg:events/collector.emit \
  '{"topic":"payments.transfer","data":"test"}'

# Assert the response contains a permissions error, not success.
# In a shell test harness, check exit code and response body.
```

## Performance Trade-offs of the Shared-Nothing Model

Shared-nothing is not free. The canonical ABI copy that transfers data across component boundaries introduces overhead compared to passing a pointer between two functions in the same process. For small payloads — short strings, status codes, typed records — this overhead is negligible and well within the budget of any API call or event handler. For large byte payloads — image data, ML model inputs, bulk file contents — the copy cost becomes measurable.

| Data size | Direct pointer (in-process) | WIT canonical ABI crossing | Overhead assessment |
|-----------|----------------------------|-----------------------------|---------------------|
| 64 bytes  | ~0 ns                      | ~150 ns                     | Negligible at any reasonable request rate |
| 4 KiB     | ~0 ns                      | ~800 ns                     | Under 1 ms; acceptable for most API call paths |
| 1 MiB     | ~0 ns                      | ~200 µs                     | Measurable; design interfaces to avoid crossing at this size |
| 10 MiB    | ~0 ns                      | ~2 ms                       | Significant; use streaming or resource handle patterns |

The appropriate response to copy overhead is interface design, not abandoning isolation. For large data, use the resource handle pattern:

```wit
interface processor {
  // Instead of passing a 10 MiB list<u8> directly across the boundary:
  resource image-handle {
    // The image data stays within the component that owns it.
    // Only the handle, options, and result cross the boundary.
    process: func(options: process-options) -> result<output-handle, error>;
    metadata: func() -> image-metadata;
  }

  // The caller never receives the raw bytes — only a handle to the
  // result, which it can further process or stream out.
}
```

With the resource handle pattern, large data never crosses the component boundary. Only typed handles and small typed records cross. The shared-nothing isolation property is retained while the copy cost for bulk data is eliminated.

The security argument for accepting the remaining overhead is the same argument that justifies TLS overhead or seccomp overhead: the cost is bounded and measurable; the security property it purchases is structural and architectural. Lateral movement through a shared-nothing composition requires an explicit typed interface call that is auditable, rate-limitable, and deniable. Lateral movement through a shared-memory architecture requires no explicit action — reading adjacent memory is as fast as a single load instruction.

For services where the copy overhead genuinely matters — high-throughput stream processors, low-latency inference pipelines — the design response is to keep large data within a single component that has the breadth of function to work on it, and expose only summarised, typed results to adjacent components. This is good API design independent of WASM; shared-nothing architecture incentivises it by making the cost visible.

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| WIT interface too wide | A compromised component abuses an overly broad function signature to reach data outside its intended scope | Security review of WIT files during interface design; abuse scenario analysis | Narrow the interface to minimum required operations; treat as a breaking ABI change and coordinate with consumers via interface versioning |
| Unexpected import in composed artifact | A composed application requests a capability the host did not intend to provide | `wasm-tools component wit composed.wasm` shows the unexpected import; CI import audit step fires | Reject the composition; identify which component introduced the import; review, re-approve, or exclude |
| Capability grant accumulates unintended permissions | Multiple individually-reasonable grants compose to give a component effective access beyond its role | Capability graph audit showing effective permission set; manual review during composition design | Remove one or more grants; redesign interfaces so individual grants cannot combine to exceed intended scope |
| Third-party component imports network capability | A supply chain component can exfiltrate data via `wasi:http/outgoing-handler` | Import audit during vendor evaluation; CI static analysis of component WIT | Reject the component; vendor a modified build with the network import removed; or compose it behind a proxy component that mediates calls |
| wasmCloud link established for wrong bucket | An actor gains read/write access to a data store it should not touch | Link audit via `wash get links`; anomaly detection on per-actor data access volume | Remove the incorrect link with `wash remove link`; audit who established the link and when; review link approval process |
| Resource handle retained beyond intended scope | A component holds a capability handle indefinitely, keeping a resource open longer than intended | Capability lifetime metrics show outliers; handle count gauge for long-lived handles | Refactor the component to drop handles at the end of each request scope; enforce via code review |
| Composition tool version skew | Components built with one version of `wasm-tools` produce different import semantics when composed with another version | Composition errors or unexpected runtime behaviour after toolchain upgrade | Pin `wasm-tools` and `cargo-component` versions in CI; treat toolchain upgrades as version-controlled changes requiring re-validation of composed artifacts |

## Related Articles

- [WASM Component Model Security Boundaries](/articles/wasm/wasm-component-model-security/)
- [WASM vs Container Isolation](/articles/wasm/wasm-isolation-vs-container-isolation/)
- [wasmCloud Security: Actor Authentication and Lattice Trust](/articles/wasm/wasmcloud-security/)
- [WASI Preview 2 Capability-Based Security](/articles/wasm/wasi-preview-2-capabilities/)
- [WASM Threads and Shared Memory Security](/articles/wasm/wasm-threads-shared-memory/)
