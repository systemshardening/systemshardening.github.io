---
title: "Security Hardening for WASM at the CDN Edge: Cloudflare Workers and Fastly Compute@Edge"
description: "Running WebAssembly at the CDN edge compresses your threat surface — no OS, no persistent disk, ephemeral instances — but the security model has sharp edges: Durable Object state leakage, secret management mistakes, supply chain exposure in npm dependencies, and observability gaps that blind you to edge-side attacks."
slug: cloudflare-workers-fastly-edge-security
date: 2026-05-07
lastmod: 2026-05-07
category: wasm
tags:
  - cloudflare-workers
  - fastly-compute
  - edge-computing
  - wasm
  - serverless-security
personas:
  - security-engineer
  - platform-engineer
article_number: 570
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/wasm/cloudflare-workers-fastly-edge-security/
---

# Security Hardening for WASM at the CDN Edge: Cloudflare Workers and Fastly Compute@Edge

## The Problem

CDN edge runtimes — Cloudflare Workers and Fastly Compute@Edge — are attractive for security-sensitive work: authentication gatekeeping, request filtering, geofencing, JWT validation, and WAF logic. Both platforms run WebAssembly (or JavaScript compiled into a WASM-adjacent execution model) at globally distributed PoPs with sub-millisecond cold starts. The isolation model is strong by default and the attack surface is dramatically narrower than a general-purpose compute instance.

But "strong by default" is not "correctly configured." The failure modes at the edge are different from traditional infrastructure — no persistent filesystem to lock down, no `sshd` to harden — but the sharp edges are real: Durable Object state that persists across requests in ways operators do not expect, secrets accidentally burned into Worker bundles, npm dependencies that widen the supply chain exposure of code running globally in 300 PoPs, and logging configurations that silently drop security-relevant events before they reach SIEM.

This article covers the security model of both platforms at the runtime level, then goes through hardening for secrets management, cross-Worker isolation, supply chain controls, request validation patterns, and edge observability.

**Target systems:** Cloudflare Workers (V8 isolate model, wrangler 3.x), Fastly Compute@Edge (Wasmtime-based, Rust/Go/JS SDK).

---

## Threat Model

- **Adversary 1 — Secret exfiltration via bundle inspection.** An attacker with access to the deployed Worker bundle (via a compromised CI pipeline, a misconfigured public repository, or Cloudflare's API) reads plaintext secrets embedded in the bundle at build time.
- **Adversary 2 — Durable Object state leakage.** A multi-tenant Worker using Durable Objects without strict namespace partitioning allows one tenant to read or corrupt another's state.
- **Adversary 3 — Supply chain compromise via npm.** A malicious npm package transitive dependency exfiltrates data or abuses the edge runtime's fetch capability to make outbound requests to attacker-controlled infrastructure.
- **Adversary 4 — Request injection bypassing origin auth.** An attacker who understands the Worker's authentication logic crafts requests that pass edge-side JWT validation but carry payloads that exploit origin-side logic.
- **Adversary 5 — Silent logging failure.** Security events (failed auth, anomalous request patterns, policy violations) are emitted by edge code but never reach SIEM because Logpush or real-time logging is misconfigured or rate-limited.
- **Blast radius:** Without hardening, a single misconfiguration exposes secrets globally across all PoPs, or allows state cross-contamination between tenants. With hardening, blast radius is bounded to the request or Durable Object namespace.

---

## The Edge WASM Isolation Model

### Cloudflare Workers: V8 Isolates

Cloudflare Workers do not run in containers or VMs. Each Worker runs inside a V8 isolate — the same isolation unit used by Chrome for individual browser tabs. The key security properties:

- **Per-request isolate.** By default, a new isolate is created per request (or recycled from a warm pool, but never shared concurrently between requests). There is no shared mutable state between concurrent requests at the isolate level.
- **No filesystem.** Workers have no access to a real filesystem. `require('fs')` does not exist. Module assets must be bundled at deploy time or fetched at runtime via `fetch()`.
- **No process primitives.** No `child_process`, no `exec`, no `fork`. The isolate cannot spawn OS processes or read `/proc`.
- **CPU time limits.** Workers are bounded by Cloudflare's CPU time limits: 10 ms on the free plan, 50 ms wall time on Workers Paid per request (higher for Cron Triggers). A Worker that exceeds its CPU budget is terminated. This is not user-configurable — it is enforced by the platform.
- **Memory limits.** Each isolate is bounded at 128 MB by default (up to 512 MB with the `nodejs_compat` flag on Paid plans). Memory overruns kill the isolate.

The isolate model means the classic lateral movement paths — reading another process's memory, writing to a shared filesystem, exploiting SUID binaries — do not exist at the edge. The residual risks are in the application layer: secrets handling, state management, and outbound fetch behaviour.

### Fastly Compute@Edge: Wasmtime per Request

Fastly's Compute@Edge uses a different model. Customer code is compiled to a `.wasm` binary (from Rust, Go, AssemblyScript, or JavaScript via the Fastly JS SDK) and executed in a Wasmtime-based runtime. The Fastly-specific WASI host API — the `fastly::*` crate in Rust, equivalent bindings in other SDKs — provides request/response access, KV and secret store access, and logging. Key properties:

- **Fresh instance per request.** Unlike Workers' warm isolate pool, Fastly's model gives each request a fresh Wasmtime instance. There is no warm instance reuse that could carry in-memory state between requests. Cold start is mitigated by pre-compiled AOT artifacts that Fastly generates from your uploaded `.wasm`.
- **No ambient authority.** The WASM module cannot acquire capabilities it was not granted. DNS resolution, backend access, and KV access all require explicit declarations in `fastly.toml`.
- **CPU and memory limits.** Fastly enforces a 50 ms CPU time limit and a 32 MB stack/heap limit by default. Modules exceeding these limits are terminated.
- **No direct filesystem or network socket access.** All I/O flows through the Fastly host ABI. There is no `wasi:sockets` pass-through to arbitrary TCP endpoints.

---

## Hardening: Secrets Management

### Cloudflare Workers — Wrangler Secrets vs Environment Variables

The most common secret mishandling mistake on Workers is storing secrets as plain environment variables in `wrangler.toml`. Variables declared under `[vars]` in `wrangler.toml` are:

1. Committed to source control if the file is tracked.
2. Visible in plaintext in the Cloudflare dashboard's Worker configuration view.
3. Included in the deployed bundle metadata.

Use `wrangler secret put` for all sensitive values instead:

```bash
# Do this — secret is encrypted at rest in Cloudflare's systems,
# never stored in wrangler.toml, never visible in dashboard plaintext.
wrangler secret put DATABASE_API_KEY
wrangler secret put JWT_SIGNING_KEY
wrangler secret put UPSTREAM_BEARER_TOKEN
```

Secrets stored via `wrangler secret put` are:

- Encrypted at rest using Cloudflare's key management infrastructure.
- Injected into the Worker's environment at runtime as binding values — accessible as `env.DATABASE_API_KEY` in the handler, not embedded in the bundle.
- Not included in `wrangler.toml`. A `wrangler.toml` with only `[vars]` for non-secret configuration (feature flags, public URLs) and no secret values is safe to commit.

Audit your `wrangler.toml` before every deployment. If `[vars]` contains anything that looks like a key, token, or password, rotate and move it to `wrangler secret put`.

In your Worker code, never log secret values:

```javascript
// Never do this — secret will appear in Cloudflare Logpush output
console.log('Using key:', env.JWT_SIGNING_KEY);

// Correct — log only metadata
console.log('JWT key loaded, length:', env.JWT_SIGNING_KEY.length);
```

### Fastly Compute@Edge — Config Store and Secret Store

Fastly provides two distinct mechanisms for configuration data:

- **Config Store:** Key-value store for non-sensitive configuration. Values are visible in the Fastly web UI and API. Use for public endpoints, feature flags, region identifiers.
- **Secret Store:** Key-value store with encryption at rest and in transit. Values are not visible in plaintext in the Fastly UI after creation. Use for API keys, signing secrets, auth tokens.

In Rust:

```rust
use fastly::secret_store::SecretStore;

fn get_signing_key() -> anyhow::Result<Vec<u8>> {
    let store = SecretStore::open("my-secrets")?;
    let secret = store.get("jwt-signing-key")?
        .ok_or_else(|| anyhow::anyhow!("jwt-signing-key not found in secret store"))?;
    Ok(secret.plaintext().to_vec())
}
```

The `fastly.toml` must declare the Secret Store binding:

```toml
[[secret_stores]]
name = "my-secrets"
```

Critically, the `.plaintext()` call decrypts the secret value only at runtime, within the Wasmtime instance. The encrypted value is never materialized in the deployed `.wasm` binary. This is the correct architecture: the binary contains logic, not credentials.

---

## Hardening: Worker and Instance Isolation

### Cloudflare Workers — No Shared Memory, Careful Durable Object State

V8 isolates do not share memory between concurrent requests. An attacker who controls one request cannot read the memory of another concurrent request in a different isolate. This is a structural guarantee, not a configuration option.

The risk is not shared isolate memory — it is **Durable Object state**. Durable Objects (DO) are Cloudflare's persistent, strongly-consistent stateful objects. Each DO is a JavaScript class instance that persists across requests routed to it. The DO's `state.storage` is a transactional key-value store. If you use a DO to cache per-tenant state, incorrect namespace design creates cross-tenant state access:

```javascript
// WRONG — all tenants share the same Durable Object ID
async function handleRequest(request, env) {
    const id = env.SESSION_CACHE.idFromName('shared-cache');
    const stub = env.SESSION_CACHE.get(id);
    return stub.fetch(request);
}

// CORRECT — each tenant gets an isolated Durable Object by tenant ID
async function handleRequest(request, env) {
    const tenantId = extractVerifiedTenantId(request); // validated from JWT, not user-supplied
    const id = env.SESSION_CACHE.idFromName(`tenant:${tenantId}`);
    const stub = env.SESSION_CACHE.get(id);
    return stub.fetch(request);
}
```

The Durable Object name used in `idFromName()` must be derived from a validated, authenticated identifier — not from a user-supplied header, query parameter, or cookie. An attacker who can control the DO name string can access arbitrary DO instances.

Within a Durable Object, apply the principle of least privilege to storage keys: prefix keys by tenant, validate reads against the expected tenant context, and never store one tenant's data under a key derivable from another tenant's identifier.

### Fastly Compute@Edge — Fresh Instance Guarantees

Fastly's per-request fresh instance model eliminates in-memory state leakage between requests at the runtime level. Each Wasmtime instance is initialised from a clean AOT snapshot. No `static` variables, no module-level mutable state, persists between requests. This is a stronger isolation guarantee than Workers' warm isolate pool for multi-tenant scenarios.

The residual risk in Fastly is **KV Store** (formerly Edge Dictionary / Object Store): a globally-accessible key-value store that persists across requests. The same namespace design principle applies: keys must be tenant-scoped and access must be validated server-side within the WASM module before a read or write is performed.

---

## Hardening: Supply Chain Security

Both platforms execute code that was built from source using dependency ecosystems (npm for Workers JavaScript, Cargo for Fastly Rust, Go modules for Fastly Go). The supply chain attack surface is identical to any application: a compromised transitive dependency runs inside the Worker or Compute@Edge instance.

### Cloudflare Workers — npm Dependency Pinning

Workers built with JavaScript or TypeScript use npm. Every dependency in `package.json` that uses a range specifier (`^`, `~`, `*`) is an unpinned dependency. Lockfile integrity is the first control:

```bash
# Commit package-lock.json or yarn.lock — never .gitignore it
# Verify lockfile integrity in CI before build
npm ci  # Uses lockfile exactly; fails if lockfile is inconsistent with package.json
```

Pin the wrangler version used in CI to prevent a compromised wrangler release from injecting code into your bundle at build time:

```json
// package.json — pin wrangler, not just Workers dependencies
{
  "devDependencies": {
    "wrangler": "3.57.2"
  }
}
```

Run `npm audit` as a blocking step in CI. For Workers handling authentication or financial data, use a software composition analysis (SCA) tool (Snyk, Socket.dev, GitHub Dependabot) to continuously monitor the dependency graph against known-compromised packages — not just CVEs, but also packages flagged for unusual behaviour (obfuscated code, unexpected network calls in postinstall scripts).

The `wrangler.toml` itself does not pin npm dependencies, but it controls what is bundled. Use the `no_bundle` flag carefully — bundling is what inlines your dependency tree; `no_bundle` may pass through code that was not audited.

### Fastly Compute@Edge — Cargo Dependency Pinning

For Rust-based Compute@Edge:

```bash
# Cargo.lock must be committed and used in CI
cargo build --locked  # Fails if Cargo.lock is not up to date
```

Use `cargo audit` against the RustSec advisory database:

```bash
cargo install cargo-audit
cargo audit
```

Pin Fastly SDK crate versions to exact versions in `Cargo.toml` for production:

```toml
[dependencies]
fastly = "=0.9.9"  # Exact pin, not a range
```

Consider reproducible builds: `cargo build --locked --release` with a pinned Rust toolchain version (`rust-toolchain.toml`) produces a deterministic `.wasm` artifact given the same source tree. Sign the artifact and verify the signature in your deployment pipeline before uploading to Fastly.

---

## Hardening: Request Validation at the Edge

The most operationally impactful use of edge WASM for security is using Workers or Compute@Edge as a WAF or authentication enforcement layer before requests reach the origin. This shifts validation to the edge PoP closest to the client, rejecting malformed or unauthenticated requests before they consume origin capacity.

### JWT Validation in a Cloudflare Worker

```javascript
import { jwtVerify, importSPKI } from 'jose';

export default {
    async fetch(request, env) {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader?.startsWith('Bearer ')) {
            return new Response('Unauthorized', { status: 401 });
        }

        const token = authHeader.slice(7);
        try {
            const publicKey = await importSPKI(env.JWT_PUBLIC_KEY, 'RS256');
            const { payload } = await jwtVerify(token, publicKey, {
                issuer: 'https://auth.example.com',
                audience: 'api.example.com',
            });

            // Forward validated claims to origin as trusted headers
            const upstreamRequest = new Request(request, {
                headers: {
                    ...Object.fromEntries(request.headers),
                    'X-Verified-User-Id': payload.sub,
                    'X-Verified-Tenant': payload.tenant_id,
                    // Strip any user-supplied versions of these headers
                },
            });
            // Remove any attacker-supplied trusted headers before forwarding
            upstreamRequest.headers.delete('X-Internal-Bypass');

            return fetch(upstreamRequest, { cf: { cacheTtl: 0 } });
        } catch (err) {
            console.error('JWT validation failed:', err.message);
            return new Response('Forbidden', { status: 403 });
        }
    },
};
```

Key controls in this pattern:

- The JWT public key comes from `env.JWT_PUBLIC_KEY`, a Cloudflare Secret — not hardcoded.
- Issuer and audience are validated — not just signature.
- Validated claims are forwarded as server-set trusted headers.
- Any attacker-supplied header that mimics a trusted internal header is stripped before forwarding.

On the origin side, these trusted headers must only be accepted from the edge Worker's IP range (Cloudflare's egress IPs) or via a shared mTLS client certificate. The origin must not accept `X-Verified-User-Id` from arbitrary callers.

### Rate Limiting and Anomaly Detection

Workers can implement lightweight rate limiting using the Workers KV or Durable Objects:

```javascript
// Durable Object-based rate limiter
export class RateLimiter {
    constructor(state) {
        this.state = state;
    }

    async fetch(request) {
        const ip = request.headers.get('CF-Connecting-IP');
        const key = `rate:${ip}`;
        const count = (await this.state.storage.get(key)) || 0;

        if (count >= 100) {
            return new Response('Too Many Requests', { status: 429 });
        }

        await this.state.storage.put(key, count + 1, { expirationTtl: 60 });
        return new Response('ok');
    }
}
```

---

## Hardening: Edge Observability and Security Logging

Security events at the edge are only actionable if they reach your SIEM. Both platforms provide mechanisms for shipping logs — but neither is enabled by default, and both have failure modes that silently drop security events.

### Cloudflare Logpush

Cloudflare Logpush streams Worker logs and HTTP request logs to an external destination (S3, R2, Sumo Logic, Splunk, Datadog, etc.). Without Logpush configured, `console.log()` output is only visible in the Wrangler tail output (ephemeral, developer-facing) and not persisted anywhere.

Configure Logpush via the Cloudflare API or Terraform:

```bash
# Create a Logpush job via the Cloudflare API
curl -X POST "https://api.cloudflare.com/client/v4/accounts/{account_id}/logpush/jobs" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "workers-security-events",
    "logpull_options": "fields=WorkerEvent,Outcome,RequestMethod,RequestURL,ResponseStatus,WorkerSubrequestCount",
    "destination_conf": "s3://{bucket}/{prefix}?region=us-east-1",
    "dataset": "workers_trace_events",
    "enabled": true
  }'
```

Within Worker code, emit structured security events — not free-form strings — so that downstream log parsing is reliable:

```javascript
function logSecurityEvent(event) {
    // Structured log line — parseable by downstream SIEM
    console.log(JSON.stringify({
        timestamp: new Date().toISOString(),
        event_type: event.type,
        severity: event.severity,
        source_ip: event.sourceIp,
        user_id: event.userId,
        reason: event.reason,
        request_id: event.requestId,
    }));
}

// Usage
logSecurityEvent({
    type: 'auth_failure',
    severity: 'warn',
    sourceIp: request.headers.get('CF-Connecting-IP'),
    userId: null,
    reason: 'invalid_jwt_signature',
    requestId: request.headers.get('CF-Ray'),
});
```

The `CF-Ray` header is Cloudflare's globally unique request identifier — include it in every security log event to enable correlation with Cloudflare's own request logs.

Monitor Logpush delivery health. Logpush jobs can fail silently if the destination bucket has incorrect IAM permissions or if the destination is temporarily unavailable. Set up a CloudWatch alarm (or equivalent) on the destination bucket for objects-delivered metric — a gap in log delivery is a security visibility gap.

### Fastly Real-Time Logging

Fastly provides real-time logging endpoints — configurable destinations including Splunk, Datadog, Syslog, S3, Google BigQuery — that receive log lines from Compute@Edge instances in near-real-time.

In Rust:

```rust
use fastly::log::set_panic_endpoint;
use fastly::log::Endpoint;

fn log_security_event(endpoint: &mut Endpoint, event_type: &str, severity: &str, detail: &str) {
    let entry = serde_json::json!({
        "timestamp": fastly::limits::processing_time_ms(),
        "event_type": event_type,
        "severity": severity,
        "detail": detail,
    });
    // writeln to the Fastly logging endpoint
    let _ = std::io::Write::write_fmt(
        endpoint,
        format_args!("{}\n", entry),
    );
}
```

Declare the logging endpoint in `fastly.toml`:

```toml
[[log_endpoints]]
name = "security-events"
```

Fastly's real-time logging has a buffering behaviour: log lines are batched and sent to the destination endpoint in bursts. For security-critical events (auth failures, rate limit hits, policy violations), configure the logging endpoint with a minimal batch interval and ensure the destination can handle burst writes without dropping events.

Set up alerting on log ingestion rate at the destination. A Compute@Edge deployment that stops emitting logs is either silent because all requests are succeeding (benign) or because a logic path that would emit logs is being bypassed (suspicious).

---

## Operational Checklist

**Secrets:**
- [ ] No secrets in `wrangler.toml` `[vars]` — all sensitive values use `wrangler secret put` or Fastly Secret Store.
- [ ] Secret values are never logged, even partially.
- [ ] Secret rotation procedure is documented and tested. `wrangler secret put` with a new value takes effect on next Worker deploy.

**Isolation:**
- [ ] Durable Object names are derived from server-validated, authenticated identifiers — not user-supplied input.
- [ ] Fastly KV Store keys are tenant-scoped and access is validated within the WASM module before reads or writes.
- [ ] Trusted headers forwarded to origin are stripped from incoming requests before they reach forwarding logic.

**Supply chain:**
- [ ] `package-lock.json` or `Cargo.lock` is committed and `npm ci` / `cargo build --locked` is used in CI.
- [ ] `npm audit` and `cargo audit` are blocking CI steps.
- [ ] Wrangler and Fastly CLI versions are pinned in CI.
- [ ] SCA tooling monitors for newly-compromised packages continuously, not only at build time.

**Request validation:**
- [ ] JWT validation includes issuer, audience, and expiry — not just signature.
- [ ] Origin accepts trusted forwarded headers only from Worker/Compute egress IPs or via mTLS.
- [ ] Rate limiting is applied at the edge, keyed on a verified identity (IP as fallback only).

**Observability:**
- [ ] Logpush (Workers) or real-time logging (Fastly) is configured and delivery health is monitored.
- [ ] Security events are emitted as structured JSON with a request correlation ID.
- [ ] SIEM alerting covers edge auth failure rate, anomalous request volume, and logging delivery gaps.

---

## Summary

The CDN edge security model removes entire attack surface categories — no OS, no filesystem, no persistent process — but the residual risks are meaningful and commonly misconfigured. Secrets burned into bundles at build time are the most frequent critical finding. Durable Object namespace design is the most complex state leakage risk on Workers. Supply chain exposure through npm is identical to any JavaScript application and requires the same lockfile and SCA discipline. The edge WAF and authentication gateway pattern is operationally powerful but only works if the origin enforces that it accepts validated requests only from the edge — an architectural constraint that must be designed, not assumed.

Fastly's per-request fresh Wasmtime instance provides a structurally stronger isolation guarantee than Workers' warm isolate pool for multi-tenant workloads. If cross-request state isolation is a hard requirement, Fastly's model provides it at the runtime level; on Workers, it requires careful Durable Object design.

Log everything. The edge is where your users are, which makes it where your attackers are. Without Logpush or real-time logging delivering structured security events to a monitored SIEM, you are operating blind at the perimeter that matters most.
