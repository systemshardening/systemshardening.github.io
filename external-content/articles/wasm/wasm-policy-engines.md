---
title: "WASM Policy Engines: Beyond OPA — Custom Policy Logic and Embedded Enforcement"
description: "OPA's WASM compilation target enables portable policy evaluation, but WASM also enables entirely custom policy engines in any language. This guide covers OPA Rego-to-WASM, Cedar policy engine in WASM, Styra DAS, and building custom authorisation logic as a WASM module for embedding in applications and gateways."
slug: wasm-policy-engines
date: 2026-05-07
lastmod: 2026-05-07
category: wasm
tags:
  - wasm
  - policy-engines
  - opa
  - cedar
  - authorisation
personas:
  - security-engineer
  - platform-engineer
article_number: 586
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/wasm/wasm-policy-engines/
---

# WASM Policy Engines: Beyond OPA — Custom Policy Logic and Embedded Enforcement

## Problem

Policy evaluation is a cross-cutting security concern. Every service that enforces access control, validates configuration, or filters requests runs a policy engine — whether it is OPA, a home-grown role checker, a database permission model, or a cloud provider's IAM evaluator. Historically, these engines are either tightly coupled to their host runtime (a Python function that imports user roles from the same database the API uses) or deployed as a separate service (an OPA sidecar) that introduces network hops, failure modes, and operational overhead.

WASM changes this. A policy engine compiled to `.wasm` is:

- **Portable.** The same module runs in a Go API server, a Rust gateway, a Python Lambda, or an Envoy proxy without recompilation.
- **Isolated.** The WASM sandbox has no ambient authority — it cannot open sockets, read the filesystem, or call the kernel unless the host explicitly provides those capabilities.
- **Deterministic.** Given the same inputs, a WASM policy module produces the same output every time, on every platform.
- **Auditable.** The module's binary hash can be pinned and signed. Input and output documents can be logged without access to the module's internal state.

The challenge is that most teams stop at OPA's built-in WASM target without exploring the broader design space. OPA is excellent, but it is not always the right tool — Rego's learning curve is steep, the data model does not always fit the authorisation model cleanly, and some domains (formal verification, attribute-based access control with mathematical guarantees) benefit from purpose-built engines. This article covers OPA Rego-to-WASM, Amazon Cedar in WASM, building custom policy engines, Styra DAS for policy lifecycle management, and the security controls required for all WASM policy modules.

**Target systems:** OPA 0.64+; Cedar 3.x (Rust crate `cedar-policy`); Styra DAS; Wasmtime 20+; `wasm-pack`; cosign; Go `github.com/open-policy-agent/opa/rego`; Python `opa-wasm`.

---

## OPA Rego-to-WASM: Embedded Policy Without a Daemon

OPA's standard deployment model requires an HTTP sidecar. Every authorisation decision is an HTTP `POST /v1/data/authz/allow` call. This works but adds 1–5ms of network latency per decision, couples service availability to the OPA sidecar, and requires an additional process in every pod.

OPA's `build` command compiles Rego policy bundles to a `.wasm` module that an application loads directly:

```bash
# Compile a Rego bundle to a WASM module
opa build -t wasm -e authz/allow policy.rego data.json -o bundle.tar.gz

# The bundle contains bundle.wasm and the data document
tar -tzf bundle.tar.gz
# /bundle.wasm
# /data.json
# /.manifest
```

The compiled module exports a single entry point: `opa_eval`. The host runtime loads the module, provides the input document as a JSON-encoded memory buffer, calls `opa_eval`, and reads the output from linear memory. No HTTP, no sidecar, no daemon.

**Embedding in Go:**

```go
import (
    "github.com/open-policy-agent/opa/rego"
    "github.com/open-policy-agent/opa/plugins/bundle"
)

// Load the bundle at startup — not per-request
r := rego.New(
    rego.Query("data.authz.allow"),
    rego.LoadBundle("bundle.tar.gz"),
)
pq, err := r.PrepareForEval(ctx)
if err != nil {
    log.Fatalf("failed to prepare policy: %v", err)
}

// Evaluate per-request — sub-millisecond latency
input := map[string]any{
    "user":   user.ID,
    "action": req.Method,
    "resource": map[string]any{
        "type": "document",
        "id":   resourceID,
        "owner": resourceOwner,
    },
}
rs, err := pq.Eval(ctx, rego.EvalInput(input))
if err != nil || !rs.Allowed() {
    http.Error(w, "Forbidden", http.StatusForbidden)
    return
}
```

**Security controls for OPA WASM bundles:**

The bundle is compiled policy logic. Bundle substitution is the primary supply-chain threat — a modified bundle that always returns `true` bypasses all authorisation. Control it at three points:

1. **Build-time signing.** Sign the bundle with cosign in CI:
   ```bash
   cosign sign-blob --key cosign.key bundle.tar.gz \
       --output-signature bundle.tar.gz.sig \
       --output-certificate bundle.tar.gz.cert
   ```

2. **Load-time verification.** Verify the signature before loading:
   ```bash
   cosign verify-blob --key cosign.pub \
       --signature bundle.tar.gz.sig \
       --certificate bundle.tar.gz.cert \
       bundle.tar.gz
   ```

3. **Pin the bundle hash.** Store the expected SHA-256 in configuration; refuse to load a bundle that does not match, even if the signature is valid (guards against replay of old signed bundles with different logic):
   ```go
   expected := "sha256:a3f2..."
   actual := sha256sum("bundle.tar.gz")
   if actual != expected {
       log.Fatal("bundle hash mismatch — refusing to load")
   }
   ```

---

## Amazon Cedar in WASM: Attribute-Based Access Control with Formal Properties

Cedar is Amazon's open-source policy language for fine-grained authorisation. Unlike Rego, Cedar was designed from the start with formal verification properties — the policy language has a defined semantics that allows static analysis tools to prove properties about policy sets without evaluating them (for example: "no policy in this set can grant a `DeleteBucket` action to a `Guest` principal").

Cedar is written in Rust. Rust compiles to WASM. The Cedar evaluator therefore runs natively in any WASM runtime:

```bash
# Add the WASM target to a Rust project that wraps cedar-policy
rustup target add wasm32-wasi
cargo add cedar-policy
cargo build --target wasm32-wasi --release
```

A Cedar policy for S3-style bucket access:

```cedar
permit (
  principal in Role::"engineers",
  action in [Action::"s3:GetObject", Action::"s3:PutObject"],
  resource in Bucket::"project-data"
) when {
  principal.department == resource.owner_department &&
  context.request_time > principal.last_mfa_at - 3600
};
```

Cedar's three-valued logic (`Allow`, `Deny`, `NoDecision`) handles the deny-by-default correctly: if no `permit` policy matches, the result is `Deny`. Explicit `forbid` policies override any matching `permit`.

The Cedar Authorizer struct is deterministic and free of side effects — it does not make network calls, access the filesystem, or use randomness. This makes it a natural WASM citizen: the host provides entities and context as data, the WASM module evaluates the policy set, the result comes back as a typed decision.

**Formal verification with Cedar's validator:**

```rust
use cedar_policy::{Validator, SchemaFragment, PolicySet, ValidationMode};

let schema = SchemaFragment::from_file(schema_file)?;
let validator = Validator::new(schema);
let policy_set: PolicySet = policies.parse()?;

let result = validator.validate(&policy_set, ValidationMode::Strict);
if result.validation_passed() {
    println!("Policy set is type-safe");
} else {
    for warning in result.validation_warnings() {
        eprintln!("Policy warning: {}", warning);
    }
}
```

Running this validator in CI catches policy logic errors — unreachable conditions, type mismatches between entity attributes and policy expectations, actions referenced that are not defined in the schema — before policies reach production.

---

## Building a Custom WASM Policy Engine

OPA and Cedar cover most use cases, but some domains require purpose-built policy logic: financial services rate limiting with state machines, healthcare attribute matching against coded terminology systems, or game server anti-cheat rules that must not be readable by clients.

Any language that compiles to WASM can be a policy engine. The pattern:

1. Write policy evaluation logic in the language best suited to the domain.
2. Compile to `wasm32-wasi` (for server-side runtimes) or `wasm32-unknown-unknown` (for browser or bare WASM runtimes).
3. Export a stable ABI: `evaluate(input_ptr, input_len) -> (output_ptr, output_len)`.
4. The host passes a JSON (or MessagePack, or Protobuf) encoded input document, reads back a JSON-encoded decision.

**Minimal Rust policy engine:**

```rust
use std::alloc::{alloc, Layout};

#[no_mangle]
pub extern "C" fn allocate(size: usize) -> *mut u8 {
    let layout = Layout::from_size_align(size, 1).unwrap();
    unsafe { alloc(layout) }
}

#[no_mangle]
pub extern "C" fn evaluate(ptr: *const u8, len: usize) -> u32 {
    let input_bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    let input: serde_json::Value = serde_json::from_slice(input_bytes)
        .unwrap_or(serde_json::Value::Null);

    let decision = evaluate_policy(&input);

    // Write result to a known output location in linear memory
    // In a real implementation, return a pointer to a JSON-encoded result
    if decision { 1 } else { 0 }
}

fn evaluate_policy(input: &serde_json::Value) -> bool {
    let role = input["subject"]["role"].as_str().unwrap_or("");
    let action = input["action"].as_str().unwrap_or("");
    let resource_sensitivity = input["resource"]["sensitivity"]
        .as_u64().unwrap_or(0);

    match (role, action) {
        ("admin", _) => true,
        ("engineer", "read") => resource_sensitivity < 3,
        ("engineer", "write") => resource_sensitivity < 2,
        _ => false,
    }
}
```

**Security properties of this approach:**

- The WASM module cannot call `exit()`, open network connections, or read environment variables unless the host provides WASI imports for those operations. A policy engine module should be instantiated with an empty linker — no WASI host functions at all.
- The module's linear memory is isolated from the host process. A bug in the policy engine (buffer overread, use-after-free) cannot corrupt host memory.
- The deterministic evaluation property means the module can be tested exhaustively: for a finite input domain, enumerate all cases and assert expected outputs.

**No ambient authority — enforce it at instantiation:**

```go
// Wasmtime in Go — instantiate with NO WASI imports
engine := wasmtime.NewEngine()
store := wasmtime.NewStore(engine)
module, _ := wasmtime.NewModuleFromFile(engine, "policy.wasm")

// Empty linker — no syscalls, no filesystem, no network
linker := wasmtime.NewLinker(engine)
instance, err := linker.Instantiate(store, module)
if err != nil {
    log.Fatalf("failed to instantiate policy module: %v", err)
}
```

---

## Styra DAS: Policy Lifecycle Management for OPA WASM Bundles

Styra DAS (Declarative Authorization Service) is a commercial control plane for OPA that handles the parts of policy management that OPA itself does not: authoring, testing, bundle publishing, distribution, and audit logging.

In the WASM deployment model, DAS's role is:

1. **Policy authoring and validation.** Rego policies are written and tested in the DAS UI. DAS runs OPA's built-in `rego.parse_module` and `test` framework against every change.
2. **Automated bundle compilation.** On policy merge, DAS compiles the Rego bundle to a `.wasm` artifact and signs it with the organization's signing key.
3. **Distribution to agents.** DAS pushes signed bundles to OPA agents (or WASM-embedding applications) via an OPA Bundle Protocol endpoint. Applications poll for new bundles; DAS can push via webhook triggers.
4. **Decision logging.** Applications configured with `decision_logs.service` send serialized input/output pairs to DAS for compliance and incident investigation.
5. **Impact analysis.** Before a policy change is promoted to production, DAS runs the new policy against recent production decision logs and surfaces any `allow`-to-`deny` or `deny`-to-allow` changes for review.

For WASM-embedding applications that cannot run the full OPA agent, DAS-compiled bundles can be fetched via a standard HTTPS endpoint. The application verifies the bundle signature, loads the WASM module, and polls for updates on a configurable interval:

```bash
# DAS bundle endpoint — standard OPA bundle protocol
curl -H "Authorization: Bearer $DAS_TOKEN" \
     https://das.example.com/v1/bundles/production/authz \
     -o bundle.tar.gz

# Verify the bundle before loading
cosign verify-blob \
    --certificate-identity "ci@example.com" \
    --certificate-oidc-issuer "https://accounts.google.com" \
    --signature bundle.tar.gz.sig \
    bundle.tar.gz
```

The key operational security property DAS provides is **policy change traceability**: every bundle version has a content hash, a git commit reference, an author, and a timestamp. When an incident occurs, the question "what was the policy at the time of this decision?" has a definitive answer.

---

## Testing WASM Policy Modules

Policy bugs are security vulnerabilities. An overly permissive policy grants access it should deny; an overly restrictive policy causes outages. Both have security consequences. WASM policy modules require the same testing rigour as application code.

**Unit testing OPA Rego policies:**

```rego
# policy_test.rego
package authz_test

import data.authz

test_admin_can_delete {
    authz.allow with input as {
        "subject": {"role": "admin"},
        "action": "delete",
        "resource": {"type": "document"}
    }
}

test_viewer_cannot_delete {
    not authz.allow with input as {
        "subject": {"role": "viewer"},
        "action": "delete",
        "resource": {"type": "document"}
    }
}

test_default_deny_on_unknown_role {
    not authz.allow with input as {
        "subject": {"role": "unknown"},
        "action": "read",
        "resource": {"type": "document"}
    }
}
```

Run the test suite against both the Rego source and the compiled WASM bundle:

```bash
# Test the Rego source
opa test policy.rego policy_test.rego -v

# Compile, then test the WASM bundle produces identical decisions
opa build -t wasm -e authz/allow policy.rego -o bundle.tar.gz
# Run integration tests that instantiate the WASM module and replay test vectors
go test ./policy/integration/...
```

**Fuzz testing WASM policy modules:**

Policy engines are input parsers. Malformed or unexpected input documents can cause panics, infinite loops, or incorrect decisions. Fuzz testing exercises the evaluation path with structurally valid but semantically unexpected inputs:

```go
// FuzzEvaluate feeds random JSON-encoded inputs to the WASM policy module
func FuzzEvaluate(f *testing.F) {
    // Seed corpus with known inputs
    f.Add([]byte(`{"subject":{"role":"admin"},"action":"read"}`))
    f.Add([]byte(`{"subject":{},"action":null}`))
    f.Add([]byte(`{}`))

    f.Fuzz(func(t *testing.T, input []byte) {
        // Ensure the module does not panic, infinite-loop, or exceed
        // memory limits on any input
        result, err := policyModule.Evaluate(input)
        if err != nil {
            // Errors are acceptable; panics are not
            return
        }
        // Result must be a valid JSON boolean
        if result != "true" && result != "false" {
            t.Errorf("unexpected output: %s", result)
        }
    })
}
```

The WASM sandbox provides an important property here: even if the fuzz corpus triggers a bug in the policy engine, the bug is contained within the WASM linear memory. The fuzzer host process is not compromised.

---

## Version Control and Signing for Policy WASM Modules

Policy WASM modules are infrastructure artifacts with the same supply-chain risk profile as container images. The controls are parallel:

**Content-addressable storage.** Store policy bundles in an OCI registry using the `application/vnd.wasm.content.layer.v1+wasm` media type. Every push produces an immutable digest. Reference bundles by digest, not by mutable tag:

```bash
# Push to OCI registry
oras push ghcr.io/example/policies/authz:v1.4.2 \
    --artifact-type application/vnd.opa.bundle \
    bundle.tar.gz:application/vnd.wasm.content.layer.v1+wasm

# Reference by immutable digest in deployment configuration
POLICY_DIGEST=$(oras manifest fetch ghcr.io/example/policies/authz:v1.4.2 \
    --format '{{.digest}}')
# ghcr.io/example/policies/authz@sha256:a3f2b...
```

**Keyless signing with cosign and OIDC.** In CI, sign the bundle using the OIDC identity of the pipeline runner (GitHub Actions, GitLab CI) rather than a long-lived key:

```yaml
# GitHub Actions
- name: Sign policy bundle
  run: |
    cosign sign-blob \
        --oidc-issuer https://token.actions.githubusercontent.com \
        --bundle bundle.cosign.json \
        bundle.tar.gz
  env:
    COSIGN_EXPERIMENTAL: "1"
```

**Verification in application startup.** Applications load policy bundles at startup. Add a verification step before any evaluation:

```go
func loadPolicyBundle(path string) (*PolicyBundle, error) {
    // Verify cosign signature
    cmd := exec.Command("cosign", "verify-blob",
        "--certificate-identity-regexp", "^https://github.com/example/policies/",
        "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
        "--bundle", path+".cosign.json",
        path,
    )
    if err := cmd.Run(); err != nil {
        return nil, fmt.Errorf("policy bundle signature verification failed: %w", err)
    }

    // Load and return the bundle
    return parsePolicyBundle(path)
}
```

**Policy versioning in git.** Rego source, Cedar policies, and custom engine source must live in git with branch protection, required reviews, and CI that runs the test suite on every pull request. The commit SHA becomes the canonical policy version, linked to the compiled WASM bundle via a build provenance attestation (SLSA level 2 minimum).

---

## Choosing the Right WASM Policy Engine

| Use case | Recommended approach |
|---|---|
| Kubernetes admission control, API gateway authz, existing Rego investment | OPA Rego-to-WASM |
| Attribute-based access control with formal verification requirements | Cedar in WASM |
| Domain-specific rules (financial, healthcare, gaming) with complex state | Custom WASM engine in Rust/Go/C |
| Centralized policy lifecycle, compliance, audit logging | OPA WASM + Styra DAS |
| Edge functions with no external dependencies | OPA WASM or Cedar WASM (both run in Cloudflare Workers, Fastly Compute) |

The shared security baseline across all approaches:

1. Sign every compiled WASM bundle at build time; verify before loading.
2. Instantiate policy modules with the minimum WASI imports required — no filesystem, no network, no environment access for pure evaluation engines.
3. Pin bundle versions by content hash; alert on unexpected hash changes.
4. Run the unit test suite and at least a short fuzz campaign in CI on every policy change.
5. Log every authorisation decision with the input document, the output, and the bundle hash that produced it. This is the audit trail required for incident investigation and compliance.

WASM makes policy evaluation portable, isolated, and fast. The engineering investment is in the pipeline: signing, verification, testing, and lifecycle management. The policy engine is only as trustworthy as the controls around it.
