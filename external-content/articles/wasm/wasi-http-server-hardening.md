---
title: "WASI HTTP Server Hardening: Production Patterns for wasi:http/incoming-handler"
description: "WASI HTTP servers are a clean platform-neutral pattern. The hardening is at the application layer — body limits, header allowlists, response shaping, and panic semantics."
slug: "wasi-http-server-hardening"
date: 2026-04-27
lastmod: 2026-04-27
category: "wasm"
tags: ["wasi", "http", "wasm", "spin", "wasmcloud", "fastly"]
personas: ["platform-engineer", "security-engineer", "ml-engineer"]
article_number: 187
difficulty: "intermediate"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/wasm/wasi-http-server-hardening/index.html"
---

# WASI HTTP Server Hardening: Production Patterns for wasi:http/incoming-handler

## Problem

`wasi:http/incoming-handler` is the WASI Preview 2 interface for serving HTTP. A component implements `handle(request)` and returns a response. The runtime (Spin, wasmCloud, Fastly Compute, NGINX with WASM, Wasmtime CLI's `serve` mode) provides the network listener, the TLS termination, and the request routing.

This is the cleanest platform-neutral way to write HTTP servers in WASM. A single `.wasm` artifact runs on Spin in Kubernetes, on Fastly at the edge, on Wasmtime locally for testing — without changing the source. The interface is small, well-defined, and capability-bound (the component cannot listen on its own port; the runtime accepts connections and hands the request to the component).

The platform handles a lot. The component still has to handle the rest:

- **Request body limits.** Most platforms cap incoming body size, but the component can also stream the body and accumulate it; an unchecked accumulator is a DoS vector.
- **Header parsing and forwarding.** A component that proxies upstream forwards headers; without filtering, sensitive headers (`Authorization`, `Cookie`) leak.
- **Trust of inbound headers.** Headers like `X-Forwarded-For`, `X-Real-IP`, `X-User-Id` from upstream proxies are sometimes trusted as identity; a request that bypasses the proxy can spoof them.
- **Response leakage.** Default error handling stack-traces internal paths; verbose error responses leak service topology.
- **Panic semantics.** A WASM component that traps mid-request leaves the runtime to decide what to send the client. Different platforms handle this differently.
- **Timeouts.** The runtime's per-request timeout is a hard cap, but the component can set its own internal deadlines for upstream calls.

This article covers body-size enforcement at the component layer, header-allowlist patterns for proxying, identity-header trust boundaries, response shaping for security, panic recovery, and per-call deadline propagation. Examples are in Rust (most-deployed language for `wasi:http` servers), with notes for JS and Go.

**Target systems:** Wasmtime 22+ (`wasmtime serve`), Spin 2.6+, wasmCloud 1.2+, Fastly Compute, NGINX with `ngx_wasm_module`. WIT version: `wasi:http@0.2.0`.

## Threat Model

- **Adversary 1 — External user with malicious request:** sends crafted headers, oversized bodies, slowloris-pattern reads, or path traversals to trigger errors that reveal internal state.
- **Adversary 2 — Compromised upstream proxy or load balancer:** sends headers asserting an identity the user does not have (`X-User-Id`, `X-Forwarded-User`) under the assumption the WASM component will trust them.
- **Adversary 3 — Backend that returns large or malicious responses:** when the WASM component proxies to a backend, the backend's response can be used to attack the component (large body, redirect chain, response splitting).
- **Adversary 4 — Resource exhaustion in handler logic:** legitimate-looking requests trigger expensive logic (recursive parsing, regex catastrophic backtracking).
- **Access level:** Adversary 1 has only HTTP-request capability. Adversary 2 has compromised an upstream component. Adversary 3 has compromised a backend. Adversary 4 has only request capability.
- **Objective:** Read sensitive data; impersonate users; cause service outages.
- **Blast radius:** Bounded by the component's behavior. A correctly-coded handler with explicit limits and trust boundaries is bounded; a careless handler leaks data, accepts spoofed identity, or stalls under load.

## Configuration

### Step 1: Body Size Limits at the Component Layer

The runtime caps body size globally; the component should apply per-route limits and reject early.

```rust
// src/lib.rs (Rust component for wasi:http)
use wasi::http::{
    proxy::Guest,
    types::{IncomingRequest, ResponseOutparam, OutgoingResponse, Fields, IncomingBody},
};

const MAX_BODY_BYTES: usize = 1 << 20;       // 1 MiB
const MAX_BODY_BYTES_UPLOAD: usize = 1 << 25; // 32 MiB on /upload

struct MyHandler;

impl Guest for MyHandler {
    fn handle(req: IncomingRequest, response_out: ResponseOutparam) {
        let path_with_query = req.path_with_query().unwrap_or_default();
        let path = path_with_query.split('?').next().unwrap_or("");

        let limit = match path {
            p if p.starts_with("/upload") => MAX_BODY_BYTES_UPLOAD,
            _ => MAX_BODY_BYTES,
        };

        let body_bytes = match read_body_capped(req.consume().unwrap(), limit) {
            Ok(bytes) => bytes,
            Err(BodyError::TooLarge) => {
                respond(&response_out, 413, b"request body too large");
                return;
            }
            Err(BodyError::Other(_)) => {
                respond(&response_out, 400, b"bad request");
                return;
            }
        };

        // Process body_bytes...
    }
}

enum BodyError {
    TooLarge,
    Other(String),
}

fn read_body_capped(body: IncomingBody, cap: usize) -> Result<Vec<u8>, BodyError> {
    let stream = body.stream().map_err(|e| BodyError::Other(format!("{:?}", e)))?;
    let mut buf = Vec::with_capacity(cap.min(64 * 1024));
    loop {
        let chunk = stream.blocking_read(8192)
            .map_err(|e| BodyError::Other(format!("{:?}", e)))?;
        if chunk.is_empty() { break; }
        if buf.len() + chunk.len() > cap {
            return Err(BodyError::TooLarge);
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}
```

The cap is enforced inside the read loop. A malicious chunked-encoded request that streams forever fails on the second oversize check, not after fully reading and OOM-ing the component.

### Step 2: Header Allowlists for Proxying

When the component proxies to an upstream, filter forwarded headers.

```rust
const ALLOWED_FORWARD_HEADERS: &[&str] = &[
    "content-type", "accept", "accept-encoding",
    "x-trace-id", "x-request-id",
    "user-agent",
];

const STRIP_FROM_INBOUND: &[&str] = &[
    "authorization", "cookie", "set-cookie",
    "x-forwarded-for", "x-forwarded-user", "x-user-id",
    "x-original-uri", "x-internal-trace",
];

fn build_upstream_headers(inbound: &Fields) -> Fields {
    let out = Fields::new();
    for (name, value) in inbound.entries() {
        let lower = name.to_lowercase();
        if STRIP_FROM_INBOUND.contains(&lower.as_str()) {
            continue;
        }
        if ALLOWED_FORWARD_HEADERS.contains(&lower.as_str()) {
            let _ = out.append(&name, &value);
        }
    }
    // Add internally-generated identity.
    let _ = out.append(&"authorization".to_string(),
        format!("Bearer {}", get_internal_api_token()).as_bytes());
    let _ = out.append(&"x-internal-trace".to_string(),
        get_or_generate_trace_id().as_bytes());
    out
}
```

Two boundaries:

- Stripping `STRIP_FROM_INBOUND` prevents an external client from injecting headers the upstream might trust (e.g., `X-User-Id` claiming admin).
- Adding internal authorization in the proxy step means the upstream sees a known internal credential, not the client's. A leaked client credential cannot reach the upstream through this component.

### Step 3: Identity Header Trust Boundary

If the runtime's reverse proxy attaches authenticated headers (`X-Authenticated-User: <jwt-sub>`), the component should accept them only when they came from a trusted hop.

Two patterns:

- **Trusted-proxy IP allowlist.** The runtime exposes the original peer IP via `wasi:http`'s request metadata. Compare against a list of known proxies; trust the headers only when the peer matches.
- **Signed identity headers.** The proxy signs an identity header with a key the component knows; the component verifies. Cleaner because it survives network re-architecture.

```rust
fn verify_identity_header(req: &IncomingRequest) -> Option<UserId> {
    let token = req.headers()
        .get(&"x-authenticated-user".to_string())
        .into_iter().next()?;
    let token_str = std::str::from_utf8(&token).ok()?;
    // Verify a JWT signed by the platform proxy's key.
    let claims = jwt::verify(token_str, &PLATFORM_PROXY_PUBKEY).ok()?;
    // Reject if the token is older than 30s (replay protection).
    if claims.iat + 30 < unix_now() { return None; }
    Some(UserId(claims.sub))
}
```

If the component's runtime cannot expose the peer IP (Spin and wasmCloud do; Fastly Compute does for some pipelines), use the signed-header pattern unconditionally.

### Step 4: Response Shaping

Responses should not leak internal state.

```rust
fn respond(out: &ResponseOutparam, status: u16, body: &[u8]) {
    let resp = OutgoingResponse::new(Fields::new());
    let _ = resp.set_status_code(status);

    // Add fixed security headers on every response.
    let h = resp.headers();
    let _ = h.set(&"strict-transport-security".to_string(),
        &[b"max-age=31536000; includeSubDomains".to_vec()]);
    let _ = h.set(&"content-type".to_string(),
        &[b"application/json".to_vec()]);
    let _ = h.set(&"x-content-type-options".to_string(),
        &[b"nosniff".to_vec()]);
    let _ = h.set(&"cache-control".to_string(),
        &[b"no-store".to_vec()]);

    let body_obj = resp.body().unwrap();
    let stream = body_obj.write().unwrap();
    let _ = stream.blocking_write_and_flush(body);
    drop(stream);
    let _ = OutgoingBody::finish(body_obj, None);

    ResponseOutparam::set(out.clone(), Ok(resp));
}
```

For error responses, never include the underlying error message:

```rust
fn respond_error(out: &ResponseOutparam, status: u16, log_msg: &str, err: &Error) {
    // Log full detail for ops; respond with a sanitized message.
    eprintln!("error {status}: {log_msg}: {err:?}");
    let body = match status {
        400 => br#"{"error":"bad_request"}"#.as_slice(),
        401 => br#"{"error":"unauthorized"}"#.as_slice(),
        403 => br#"{"error":"forbidden"}"#.as_slice(),
        404 => br#"{"error":"not_found"}"#.as_slice(),
        429 => br#"{"error":"rate_limited"}"#.as_slice(),
        _   => br#"{"error":"internal"}"#.as_slice(),
    };
    respond(out, status, body);
}
```

A 5xx response should never reveal whether the failure was a parse error, a timeout, a backend connection issue, or a bug in the handler.

### Step 5: Panic Recovery

A WASM component that traps mid-handler is at the runtime's mercy for what the client sees. Make traps less likely:

```rust
// Wrap handler body in a panic catcher (on platforms where catching is supported).
fn handle_with_recovery(req: IncomingRequest, out: ResponseOutparam) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        handle_real(req, &out);
    }));
    if result.is_err() {
        respond_error(&out, 500, "handler panicked", &Error::Other);
    }
}
```

`catch_unwind` works on Wasmtime + Spin; Fastly's runtime aborts the instance on panic so the wrapper has limited effect there. Test panic semantics on each runtime you target.

### Step 6: Per-Call Deadlines for Upstream Operations

When the handler calls upstreams (HTTP, KV, database), bound each call's time:

```rust
use wasi::clocks::monotonic_clock;
use std::time::Duration;

fn fetch_with_deadline(url: &str, deadline_ms: u64) -> Result<Vec<u8>, Error> {
    let deadline = monotonic_clock::now() + Duration::from_millis(deadline_ms).as_nanos() as u64;
    let req = OutgoingRequest::new(Fields::new());
    let _ = req.set_method(&Method::Get);
    let _ = req.set_scheme(Some(&Scheme::Https));
    let _ = req.set_authority(Some(url_authority(url)));
    let _ = req.set_path_with_query(Some(url_path(url)));

    let opts = RequestOptions::new();
    let _ = opts.set_connect_timeout(Some(Duration::from_millis(deadline_ms / 2).as_nanos() as u64));
    let _ = opts.set_first_byte_timeout(Some(Duration::from_millis(deadline_ms).as_nanos() as u64));

    let response = wasi::http::outgoing_handler::handle(req, Some(opts))?;
    // ... read response with continued deadline tracking
}
```

The component's overall deadline is the runtime's per-request timeout. Upstream calls should consume only a fraction of that; reserve time for the handler's own work and response generation.

### Step 7: Telemetry

Emit structured logs and metrics from the handler:

```rust
fn log_request_metrics(method: &str, path: &str, status: u16, duration_ms: u64) {
    println!(r#"{{"event":"request","method":"{method}","path":"{path}","status":{status},"duration_ms":{duration_ms}}}"#);
}

// Metrics — emitted via a host import or platform-specific binding.
metric_inc("http_requests_total", &[("method", method), ("status", &status.to_string())]);
metric_observe("http_request_duration_seconds", duration_ms as f64 / 1000.0);
```

Avoid logging full URLs (query strings often have tokens) or full headers. Path-only logs plus status + duration are usually sufficient for ops.

## Expected Behaviour

| Signal | Default | Hardened |
|--------|---------|----------|
| 100 MiB request body to /api endpoint | Component reads until OOM | Rejected with 413 after first cap-overflow chunk |
| Client sends `X-User-Id: admin` | Component might trust | Stripped at proxy boundary; verified identity from signed header only |
| Backend returns 100 MB response | Component buffers all | Streamed with cap; oversize backend response yields 502 |
| Handler panics | Runtime returns runtime-default response (often 500 with stack trace) | Component-controlled error response, no internal details |
| Upstream call hangs | Whole request blocks until runtime timeout | Component's deadline triggers earlier, returns 504 |
| Logs | Full request/response | Structured, redacted, path-only |

Verify:

```bash
# Body-size enforcement.
dd if=/dev/zero bs=1M count=100 | curl -sX POST --data-binary @- http://localhost:8080/api/test
# HTTP 413

# Header stripping.
curl -H "X-User-Id: admin" http://localhost:8080/protected
# Backend logs show no X-User-Id header from the WASM component.

# Panic recovery.
curl http://localhost:8080/trigger-panic
# HTTP 500 with body {"error":"internal"}, no stack trace.
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Per-route body caps | Prevents OOM via large uploads | More configuration per route | Centralize the route→cap mapping in a config struct. |
| Header allowlist on proxy | Prevents identity-header spoofing and credential leak | Maintenance as upstream APIs evolve | Treat the allowlist like an API contract; review with upstream changes. |
| Signed identity headers | Robust trust boundary | Requires key distribution to the component | Use a runtime-injected key; rotate via the runtime's secret-store. |
| Response shaping | Bounds info leakage | Less detail for client-side debugging | Provide a debug header gated on a known-internal token (never default-on). |
| Panic recovery wrapper | Sanitizes runtime-default error | Some panics may not catch (depends on runtime) | Test panic behavior per platform; document runtime-specific differences. |
| Per-upstream deadlines | No request-handler stalls indefinitely | Tuning deadlines per upstream | Default to aggressive deadlines; loosen per-upstream after measuring. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Body cap too low for legitimate uploads | Users see 413 on routine requests | Logs show 413 rate above expected | Raise the cap for that route; add per-tenant override if needed. |
| Stripped header was actually needed by upstream | Upstream errors due to missing context | Backend logs show null where expected value | Add to allowlist after review; document why it is allowed. |
| Identity header trust is broken | Users impersonate each other | Audit logs show actions performed by unexpected user IDs | Switch to signed identity headers immediately; revoke any sessions created during the window. |
| Per-upstream deadline triggers before genuine completion | Slow but legitimate upstream calls fail | 504 rate rises for a specific upstream | Profile the upstream's typical latency; raise deadline only if the upstream cannot be fixed. |
| Component runs out of memory on legitimate load | All requests start failing | Runtime metrics show memory growth | Investigate per-handler allocation; apply runtime-side memory cap to bound and identify the leaking component. |
| Panic recovery doesn't fire on a specific runtime | Default error response leaks stack | Synthetic panic test fails on platform X | Document the platform difference; use language-level error handling instead of relying on `catch_unwind`. |

## Related Articles

- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [WASI Preview 2 Capability-Based Security](/articles/wasm/wasi-preview-2-capabilities/)
- [Edge Runtime WASM Hardening](/articles/wasm/edge-wasm-hardening/)
- [HTTP Security Headers That Actually Work](/articles/network/http-security-headers/)
- [API Gateway Security](/articles/network/api-gateway-security/)
