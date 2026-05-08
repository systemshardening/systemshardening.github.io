---
title: "Spin Framework Security: Component Isolation, Triggers, and Secret Management"
description: "Fermyon Spin 2.x runs WASM components as serverless-style handlers. Each component's network, filesystem, and secret access requires explicit capability grants. Defaults are strict; misconfiguration opens broad access."
slug: "spin-framework-security"
date: 2026-04-29
lastmod: 2026-04-29
category: "wasm"
tags: ["spin", "fermyon", "wasm", "serverless", "component-model"]
personas: ["platform-engineer", "security-engineer", "ml-engineer"]
article_number: 246
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/wasm/spin-framework-security/index.html"
---

# Spin Framework Security: Component Isolation, Triggers, and Secret Management

## Problem

Fermyon Spin is a serverless framework for WebAssembly components. A Spin application is a collection of WASM components, each handling a specific trigger (HTTP request, Redis message, MQTT event, cron schedule). Each component is isolated by default: it cannot access the network, filesystem, environment variables, or other components unless the `spin.toml` manifest explicitly grants those capabilities.

This default-deny model is a meaningful security advantage over traditional serverless frameworks. A Spin component cannot accidentally exfiltrate environment variables or reach internal services not listed in its allowed hosts. The manifest is the policy document.

In practice, the manifest is also where the security model breaks down:

- **Overly broad allowed hosts:** `allowed_outbound_hosts = ["https://*:*"]` opens unrestricted outbound access. Any component in the application can now reach any external service, bypassing network egress controls.
- **Unencrypted secrets in `spin.toml`:** Inline `[variables]` containing API keys or passwords. The manifest is typically committed to version control.
- **Shared key-value stores without access control:** Multiple components reading and writing the same KV bucket with no isolation between them.
- **Trigger misconfiguration:** An HTTP trigger with `route = "/..."` handles all paths including admin routes that should be restricted.
- **SQLite access granted without row-level controls:** `sqlite_databases = ["default"]` gives the component unrestricted access to all tables.
- **Component composition without trust boundaries:** Wiring components together where one high-trust component (database writer) can be invoked by a low-trust component (user-facing HTTP handler) through the Spin component-to-component API.

By 2026, Spin is deployed on Fermyon Cloud, on Kubernetes via SpinKube, and as a sidecar in service mesh deployments. The attack surface grows with each integration point.

**Target systems:** Spin 2.6+ (component model, SQLite, key-value, MQTT triggers); SpinKube 0.3+ (Kubernetes operator); Fermyon Cloud (managed Spin hosting); WASI Preview 2 (Spin's underlying interface standard).

## Threat Model

- **Adversary 1 — Network egress abuse via broad allowed hosts:** A component with `allowed_outbound_hosts = ["https://*:*"]` is compromised via an application vulnerability. The attacker uses the unrestricted outbound access to exfiltrate data to an external server.
- **Adversary 2 — Secret extraction from manifest:** An attacker with repository access reads `spin.toml`, finding API keys, database passwords, or tokens stored as inline variable defaults.
- **Adversary 3 — Cross-component state corruption via shared KV store:** A low-trust component (handling user input) writes to a shared KV bucket that a high-trust component (payment processor) reads. The low-trust component poisons the shared state.
- **Adversary 4 — HTTP trigger path traversal:** A component with route `/api/...` is intended for API access only. A misconfigured route handler passes path segments directly to file reads, enabling path traversal.
- **Adversary 5 — Component-to-component privilege escalation:** A low-trust HTTP-facing component is wired via Spin's component-to-component calling to a high-trust component with database write access. The attacker exploits the HTTP component to call the DB-writer with attacker-controlled arguments.
- **Access level:** Adversaries 1 and 4 have HTTP request access. Adversary 2 has repository read access. Adversaries 3 and 5 have application-level code execution within a Spin component.
- **Objective:** Exfiltrate data, extract credentials, corrupt shared state, escalate from low-trust to high-trust component capability.
- **Blast radius:** Overly broad `allowed_outbound_hosts` = unrestricted egress from the Spin host. Shared secrets in `spin.toml` = credential exfiltration to all repository users. Cross-component privilege escalation = arbitrary access to high-trust resources.

## Configuration

### Step 1: Minimum Required allowed_outbound_hosts

The single most impactful configuration: restrict outbound hosts to exactly what each component needs.

```toml
# spin.toml

# BAD: allows the component to reach any host on any port.
[component.api-handler]
source = "api_handler.wasm"
allowed_outbound_hosts = ["https://*:*"]

# GOOD: explicitly list each external service the component calls.
[component.api-handler]
source = "api_handler.wasm"
allowed_outbound_hosts = [
  "https://api.stripe.com:443",
  "https://hooks.slack.com:443",
]
# Nothing else is reachable from this component.

# For components that make no outbound calls:
[component.static-handler]
source = "static_handler.wasm"
allowed_outbound_hosts = []   # No outbound access.
```

Verify at startup: Spin validates `allowed_outbound_hosts` syntax but not reachability. Test outbound connections in integration tests:

```bash
# Spin integration test: confirm component can reach allowed host.
spin build && spin up &
curl -s http://localhost:3000/api/payment | jq .
# Expected: successful Stripe API call.

# Confirm component cannot reach non-listed host.
# (Test via a mocked HTTP endpoint in your component that tries to call an unlisted host.)
```

### Step 2: External Secrets via Spin Variables with Vault

Never store secret values in `spin.toml` or environment variables. Use Spin's variable system backed by a secrets provider.

```toml
# spin.toml
[variables]
stripe_api_key = { required = true }     # Required; must be provided at runtime.
db_password = { required = true }
debug_mode = { default = "false" }       # Non-secret; can have a default.

[component.payment]
source = "payment.wasm"
allowed_outbound_hosts = ["https://api.stripe.com:443"]
variables = { stripe_api_key = "{{ stripe_api_key }}", debug = "{{ debug_mode }}" }
```

Supply secrets at runtime without embedding them:

```bash
# Development: pass via environment variable (not committed).
SPIN_VARIABLE_STRIPE_API_KEY=$(vault kv get -field=stripe_key secret/payments) \
  spin up

# Production on SpinKube: use the SpinAppSecret CRD.
```

```yaml
# SpinKube: SpinAppSecret provides secrets to Spin applications via Kubernetes Secrets.
apiVersion: core.spinoperator.dev/v1alpha1
kind: SpinAppSecret
metadata:
  name: payment-app-secrets
  namespace: production
spec:
  secretName: payment-app-k8s-secret   # Kubernetes Secret containing the values.
---
apiVersion: core.spinoperator.dev/v1alpha1
kind: SpinApp
metadata:
  name: payment-app
  namespace: production
spec:
  image: ghcr.io/myorg/payment-app:v1.2.3@sha256:abc123
  replicas: 3
  secrets:
    - name: payment-app-secrets
  variables:
    - name: debug_mode
      value: "false"
```

```yaml
# Kubernetes Secret (populated by External Secrets Operator from Vault).
apiVersion: v1
kind: Secret
metadata:
  name: payment-app-k8s-secret
  namespace: production
type: Opaque
data:
  stripe_api_key: <base64-encoded-value>
  db_password: <base64-encoded-value>
```

In the WASM component (Rust), access variables via the Spin SDK:

```rust
use spin_sdk::variables;

fn get_stripe_key() -> anyhow::Result<String> {
    // Variables are resolved at runtime; the value never appears in the binary.
    variables::get("stripe_api_key")
        .map_err(|e| anyhow::anyhow!("Failed to get stripe_api_key: {}", e))
}
```

### Step 3: Key-Value Store Isolation

Separate KV buckets per component trust level; never share a bucket between a low-trust and high-trust component.

```toml
# spin.toml

# Low-trust component: user-facing HTTP handler.
[component.user-api]
source = "user_api.wasm"
key_value_stores = ["user-sessions"]   # Only has access to the user sessions bucket.

# High-trust component: internal payment processor.
[component.payment-processor]
source = "payment_processor.wasm"
key_value_stores = ["payment-state"]   # Completely separate bucket.
allowed_outbound_hosts = ["https://api.stripe.com:443"]
```

Within a bucket, use key prefixes to separate data by user:

```rust
use spin_sdk::key_value::Store;

fn user_session_key(user_id: &str, key: &str) -> String {
    // Prefix all keys with user ID to prevent cross-user reads.
    format!("user:{}:{}", user_id, key)
}

fn get_user_session(user_id: &str, session_key: &str) -> anyhow::Result<Option<Vec<u8>>> {
    let store = Store::open("user-sessions")?;
    store.get(&user_session_key(user_id, session_key))
        .map_err(Into::into)
}

fn set_user_session(user_id: &str, session_key: &str, value: &[u8]) -> anyhow::Result<()> {
    let store = Store::open("user-sessions")?;
    store.set(&user_session_key(user_id, session_key), value)
        .map_err(Into::into)
}
```

### Step 4: HTTP Trigger Route Design

Restrict HTTP trigger routes to exactly the paths each component handles:

```toml
# spin.toml

[[trigger.http]]
route = "/api/v1/payments"
component = "payment-handler"

[[trigger.http]]
route = "/api/v1/users/..."   # The ... wildcard matches sub-paths.
component = "user-handler"

[[trigger.http]]
route = "/internal/health"
component = "health-check"

# Do NOT use:
# route = "/..."   # Catches all paths including admin routes.
```

In the component, validate the path before processing:

```rust
use spin_sdk::http::{Request, Response};

fn handle_payment(req: Request) -> anyhow::Result<Response> {
    // Even though the trigger matches /api/v1/payments exactly,
    // validate the path within the component for defence in depth.
    let path = req.uri().path();
    if path != "/api/v1/payments" {
        return Ok(Response::builder()
            .status(404)
            .body(Some("Not found".into()))
            .build());
    }

    // Validate method.
    if req.method() != &spin_sdk::http::Method::Post {
        return Ok(Response::builder()
            .status(405)
            .body(Some("Method not allowed".into()))
            .build());
    }

    // Process the payment.
    process_payment(req)
}
```

### Step 5: SQLite Access Control

SQLite in Spin is per-database; a component with `sqlite_databases = ["default"]` can read and write all tables. Apply application-level access control:

```toml
# spin.toml

# Read-only component: analytics query handler.
[component.analytics]
source = "analytics.wasm"
sqlite_databases = ["analytics-db"]   # Separate DB from the operational one.
# No write access to the main operational DB.

# Write component: data ingestion.
[component.ingestion]
source = "ingestion.wasm"
sqlite_databases = ["analytics-db"]
```

In the component, enforce least-privilege SQL:

```rust
use spin_sdk::sqlite::{Connection, Value};

fn get_user_summary(user_id: &str) -> anyhow::Result<Vec<Value>> {
    let connection = Connection::open("analytics-db")?;

    // Use parameterised queries; never string interpolation.
    let result = connection.execute(
        "SELECT event_count, last_seen FROM user_summary WHERE user_id = ?",
        &[Value::Text(user_id.to_string())],
    )?;

    Ok(result.rows().map(|r| r[0].clone()).collect())
}
```

For row-level security, implement user ownership checks in the query:

```rust
fn get_user_orders(requesting_user_id: &str, order_id: &str) -> anyhow::Result<Option<Value>> {
    let connection = Connection::open("default")?;
    // Filter by BOTH order_id AND user_id to prevent IDOR.
    let result = connection.execute(
        "SELECT * FROM orders WHERE id = ? AND user_id = ?",
        &[
            Value::Text(order_id.to_string()),
            Value::Text(requesting_user_id.to_string()),
        ],
    )?;
    Ok(result.rows().next().map(|r| r[0].clone()))
}
```

### Step 6: Component-to-Component Call Trust Boundaries

Spin's component-to-component calling allows one component to invoke an exported function of another. Establish explicit trust boundaries:

```toml
# spin.toml — define which components can call which.
[component.api-gateway]
source = "api_gateway.wasm"
# This component is the entry point; it can call internal components.

[component.payment-internal]
source = "payment_internal.wasm"
# This component is internal-only; it should NOT be exposed via an HTTP trigger.
# Only callable from api-gateway.
```

In the high-trust component, validate the call origin:

```rust
// payment_internal.wasm
// Exported function callable by other components.
#[export_name = "process_payment"]
pub extern "C" fn process_payment(
    caller_identity_ptr: *const u8,
    caller_identity_len: usize,
    amount_cents: i64,
) -> i32 {
    let caller = unsafe {
        std::str::from_utf8_unchecked(
            std::slice::from_raw_parts(caller_identity_ptr, caller_identity_len)
        )
    };

    // Only accept calls from the trusted api-gateway component.
    if caller != "api-gateway" {
        return -1;   // Unauthorized.
    }

    // Validate amount (don't trust caller-provided values blindly).
    if amount_cents <= 0 || amount_cents > 100_000_00 {
        return -2;   // Invalid amount.
    }

    do_process_payment(amount_cents)
}
```

### Step 7: SpinKube Security Configuration

When deploying Spin on Kubernetes via SpinKube, apply Kubernetes security hardening to the SpinApp pods:

```yaml
apiVersion: core.spinoperator.dev/v1alpha1
kind: SpinApp
metadata:
  name: payment-app
  namespace: production
spec:
  image: ghcr.io/myorg/payment-app:v1.2.3@sha256:abc123
  replicas: 3

  # Pin the container runtime to use the Spin shim (not containerd default).
  runtimeClassName: spin

  # Pod-level security.
  podSpec:
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      seccompProfile:
        type: RuntimeDefault

    containers:
      - name: spin-app
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop: [ALL]
        resources:
          limits:
            memory: 256Mi
            cpu: 500m
          requests:
            memory: 64Mi
            cpu: 100m

  # Network policy: restrict inbound to the ingress controller only.
  # Apply via a separate NetworkPolicy resource.
```

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: payment-app-netpol
  namespace: production
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: payment-app
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress-nginx
      ports:
        - port: 3000
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.169.254/32   # Block AWS metadata service.
              - 10.0.0.0/8           # Block internal network (except explicit services).
      ports:
        - port: 443   # Only HTTPS outbound; matches allowed_outbound_hosts in spin.toml.
```

### Step 8: Telemetry

```
spin_component_requests_total{component, trigger, status}    counter
spin_component_latency_seconds{component}                    histogram
spin_outbound_request_total{component, host, status}         counter
spin_variable_resolution_failure_total{component, variable}  counter
spin_kv_operations_total{component, store, operation}        counter
spin_sqlite_query_total{component, database}                 counter
```

Alert on:

- `spin_variable_resolution_failure_total` non-zero — a component couldn't resolve a required variable; secrets provider may be unreachable or variable not provisioned.
- `spin_outbound_request_total{host!~"(api.stripe.com|hooks.slack.com)"}` — a component is reaching a host not in the documented `allowed_outbound_hosts`; indicates manifest drift or a new component added without review.
- `spin_component_requests_total{status="5xx"}` spike — component error rate elevated; possible exploit attempt or misconfiguration.

## Expected Behaviour

| Signal | Misconfigured Spin | Hardened Spin |
|--------|-------------------|--------------|
| Component outbound hosts | `https://*:*` — unrestricted | Explicit per-host allowlist; unlisted hosts blocked by Spin runtime |
| Secrets in `spin.toml` | Plaintext in version control | External variables resolved at runtime from Vault/K8s Secrets |
| Shared KV store across components | User-facing and payment share a bucket | Separate buckets; no cross-component state |
| HTTP trigger route coverage | `/...` catches all paths | Explicit per-path routes; admin paths not handled by user-facing components |
| SQLite access | All components access all tables | Per-component databases; parameterised queries; row-level user filtering |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Explicit allowed_outbound_hosts | Egress control at framework level | Must update manifest when adding new external service calls | Treat `spin.toml` changes like code changes; review process for allowed_outbound_hosts expansions. |
| External variables (no defaults) | Secrets never in source | Application fails to start if secrets not provisioned | Use SpinAppSecret with External Secrets Operator; health checks catch startup failures. |
| Per-component KV stores | No cross-component state pollution | More stores to manage; more Spin configuration | Template `spin.toml` generation to enforce naming conventions. |
| Separate trigger routes | No path overlap between components | More routes to configure | Route design review as part of component onboarding. |
| SpinKube NetworkPolicy | Blocks unexpected egress at network level | `allowed_outbound_hosts` in Spin + NetworkPolicy is redundant | Defence in depth is the intent; both layers are cheap to maintain. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Secret variable not provisioned | Component fails to start; `spin_variable_resolution_failure_total` increments | Pod startup failure in SpinKube; Spin error on start | Provision the variable via SpinAppSecret; verify External Secrets Operator sync. |
| allowed_outbound_hosts too narrow | Component returns error when calling external service | Application error logs; `spin_outbound_request_total{status="403"}` | Add the missing host to `allowed_outbound_hosts`; rebuild and redeploy. |
| KV bucket name collision across environments | Dev component writes to production bucket | Data corruption; unexpected values in production KV | Use environment-prefixed bucket names: `prod-user-sessions`, `dev-user-sessions`. |
| SQLite migration breaks row access pattern | New column not included in WHERE clause; IDOR regression | Integration test failure (if tested); or silent access control bypass | Include IDOR tests in integration test suite; test with multiple user IDs. |
| Component-to-component call without validation | Low-trust component escalates to high-trust capability | Unexpected DB writes; anomalous billing events | Add caller identity validation in high-trust components; treat all incoming calls as untrusted. |
| SpinKube version skew | Spin shim version incompatible with SpinApp image | Pod CrashLoopBackOff on upgrade | Pin SpinKube operator and Spin runtime versions; test upgrades in staging. |

## Related Articles

- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [WASM Multi-Tenancy Patterns](/articles/wasm/wasm-multi-tenancy/)
- [Edge Runtime WASM Hardening](/articles/wasm/edge-wasm-hardening/)
- [WASM on Kubernetes with SpinKube and wasmCloud](/articles/wasm/wasm-on-kubernetes/)
- [WASM OCI Module Signing and Verification](/articles/wasm/wasm-oci-signing/)
