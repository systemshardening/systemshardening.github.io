---
title: "Edge Runtime WASM Hardening: Cloudflare Workers, Fastly Compute, and Multi-Tenant Isolation"
description: "Edge runtimes execute untrusted customer code in shared processes. The hardening contract is the platform's, but the customer code's behavior decides the blast radius."
slug: "edge-wasm-hardening"
date: 2026-04-27
lastmod: 2026-04-27
category: "wasm"
tags: ["edge", "cloudflare-workers", "fastly", "wasm", "multi-tenancy"]
personas: ["platform-engineer", "security-engineer", "ml-engineer"]
article_number: 182
difficulty: "intermediate"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/wasm/edge-wasm-hardening/index.html"
---

# Edge Runtime WASM Hardening: Cloudflare Workers, Fastly Compute, and Multi-Tenant Isolation

## Problem

Edge runtimes (Cloudflare Workers, Fastly Compute@Edge, Deno Deploy, Wasmer Edge, Vercel Edge Functions) host untrusted customer code at hundreds of points of presence worldwide. The execution model differs from self-hosted Wasmtime in three structural ways:

- **Multi-tenant by default.** A single physical machine runs code from many customers. The boundary between tenants is a sandbox enforced by V8 isolates (Workers, Deno) or WASM modules (Fastly Compute, Wasmer). One customer's bug or attack must not affect another customer.
- **Cold-start sensitivity.** Edge runtimes optimize for sub-millisecond cold starts. They achieve this by reusing isolates aggressively, often across requests. State that bleeds across requests is a security boundary, not a memory leak.
- **The platform's threat model is fixed.** Cloudflare's V8-isolate model has known properties (no shared filesystem, no host network arbitrarily reachable, capability-bound bindings to KV/R2/D1). Customer code runs inside that envelope; tightening the platform itself is not an option.

The customer-controlled hardening surface is what your code does inside the platform's sandbox. Most documented "edge security" content focuses on platform internals — interesting but not actionable for the platform user. The actionable hardening is at the application level: how the customer's code uses (or misuses) bindings, secrets, network egress, and cross-request state.

The specific gaps in a default Worker / Compute deployment:

- **Secrets in environment variables** that ship in deploy bundles, accessible via Cloudflare Dashboard or Fastly UI to anyone with org access.
- **Bindings (KV, R2, D1, Durable Objects, Secret Stores)** with broader scopes than the Worker actually needs.
- **Outbound `fetch()` to arbitrary URLs.** No platform-level egress allowlist; SSRF through user-supplied URLs is the most common edge bug.
- **Cross-request state in module-level variables.** Workers reuse isolates; a `let cache = {}` at module scope persists across unrelated users' requests, leaking data across tenants of *your* application running on the same isolate.
- **Header forwarding.** A Worker that proxies requests to a backend by default forwards the original `Authorization` header to anywhere the backend URL is set to — SSRF + authentication-token theft in one bug.
- **Logs that capture full request bodies and headers.** Standard logging configurations in Workers and Compute send raw data to the platform's logging tier.

This article covers the application-level hardening for Cloudflare Workers (the most-deployed edge platform) with notes for Fastly Compute and Deno Deploy.

**Target systems:** Cloudflare Workers (V8 isolate model with WASM imports), Fastly Compute (Wasmtime-based), Deno Deploy (V8 + Deno permissions), Vercel Edge Functions (V8 isolates), Wasmer Edge.

## Threat Model

- **Adversary 1 — End user with malicious input:** sends crafted requests to the Worker hoping to trigger SSRF, leak secrets, or exfiltrate data from cross-request state.
- **Adversary 2 — Co-tenant on the same isolate:** another customer's Worker on the same physical machine. Platform isolation should prevent this, but bugs in the platform have surfaced (rare but precedented).
- **Adversary 3 — Compromised platform credential:** an attacker with access to the customer's Cloudflare or Fastly account who modifies the deployed Worker.
- **Adversary 4 — Compromised binding (KV, R2, Secret Store) credential:** an attacker who has the binding's API token and can read/write data the Worker uses.
- **Access level:** Adversary 1 has only HTTP-request capability. Adversary 2 has the equivalent of any Worker's permissions on the same node. Adversary 3 has full deploy access. Adversary 4 has API-token access.
- **Objective:** Read or modify data the Worker has access to; impersonate the Worker against backend services; pivot via the Worker's identity to cloud resources.
- **Blast radius:** Bounded by the Worker's bindings, secrets, and network reach. A Worker with a Service binding to "everything" has a much larger blast radius than one with explicitly-scoped bindings.

## Configuration

### Step 1: Scope Bindings to Minimum

Cloudflare Workers bindings (KV namespaces, R2 buckets, D1 databases, Durable Object classes, Service bindings) are the Worker's "permissions." Define the minimum.

```toml
# wrangler.toml
name = "payment-api"
main = "src/index.ts"
compatibility_date = "2026-04-15"
compatibility_flags = ["nodejs_compat"]

# Production environment.
[env.production]
workers_dev = false

# Bindings scoped to this Worker only.
kv_namespaces = [
  { binding = "USER_PROFILES", id = "<id>" }
]

# Read-only access to a R2 bucket.
[[env.production.r2_buckets]]
binding = "STATIC_ASSETS"
bucket_name = "payments-assets-prod"
preview_bucket_name = "payments-assets-staging"

# D1 database, scoped to this Worker.
[[env.production.d1_databases]]
binding = "DB"
database_name = "payments-prod"
database_id = "<id>"

# Service binding to a single downstream Worker.
[[env.production.services]]
binding = "AUTH"
service = "auth-service"
environment = "production"
```

Notes:

- Service bindings (`services`) replace cross-Worker `fetch()` calls. Use them — they are stricter (cluster-internal-only, no public Internet hop) and they expose strongly-typed RPC interfaces.
- Avoid `dispatch_namespaces` (allowing the Worker to invoke arbitrary other Workers) unless you have a specific need; this is effectively root in the Workers ecosystem.
- Do not add bindings "for future use"; adding them later is fast.

### Step 2: Secret Store, Not Environment Variables

Cloudflare's Secret Store (and Fastly's equivalent) hold secrets at rest. Older Worker code uses `vars` for secrets, which makes them visible in the dashboard and embedded in deploy bundles.

```bash
# Move secrets to Secret Store.
wrangler secret put --env production STRIPE_SECRET_KEY
# Wrangler prompts for the value securely.

# Avoid in wrangler.toml:
# [env.production.vars]
# STRIPE_SECRET_KEY = "sk_live_..."   # NEVER. Visible in dashboard, in deploy bundle.
```

Access in code:

```typescript
export interface Env {
  STRIPE_SECRET_KEY: string;       // injected from Secret Store
  USER_PROFILES: KVNamespace;
  STATIC_ASSETS: R2Bucket;
  DB: D1Database;
  AUTH: Fetcher;
}
```

Audit the deploy bundle:

```bash
wrangler deploy --dry-run --outdir=./dist
# Inspect dist/index.js for any string that looks like a secret.
grep -E "sk_live|prod-token|password" dist/*.js
```

If anything secret-looking shows up in the bundle, it is shipped to every edge node and visible in Wrangler logs.

### Step 3: Outbound Fetch Allowlist

The Worker's `fetch()` can target any URL by default. Implement an application-level allowlist, especially for any URL constructed from user input:

```typescript
// fetch_safe.ts
const ALLOWED_FETCH_HOSTS = new Set([
  "api.internal.example.com",
  "auth.example.com",
  "payment-processor.example.com",
]);

function safeFetch(url: string, init?: RequestInit): Promise<Response> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error("invalid_url");
  }

  if (!ALLOWED_FETCH_HOSTS.has(parsed.hostname)) {
    throw new Error(`fetch to ${parsed.hostname} not allowed`);
  }

  // Block private IP ranges even if hostname is in the allowlist.
  // Defense against DNS rebinding to internal addresses.
  if (parsed.protocol !== "https:") {
    throw new Error("fetch must use https");
  }

  return fetch(url, init);
}
```

For Service bindings, `fetch()` against the binding (not a URL) bypasses the public Internet entirely. Prefer Service bindings whenever the destination is another Worker in your account.

### Step 4: Avoid Cross-Request Module Scope

Workers reuse isolates across requests. Module-level state persists. This is sometimes useful (cached compiled regex, parsed configuration) and sometimes a security bug.

```typescript
// Bad: shared state across users' requests on the same isolate.
let lastUser: string | null = null;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const userId = request.headers.get("X-User-Id");
    if (lastUser !== null && userId !== lastUser) {
      // Logic that "remembers" the last user.
      // This will leak across tenants whose requests share the isolate.
    }
    lastUser = userId;
    return new Response("ok");
  },
};
```

Module-level state is fine for *immutable* data (compiled patterns, static config, libraries). For per-user state, use:

- **Durable Objects** for cross-request state per user/tenant.
- **KV / D1** for persisted per-user data.
- Request-scoped variables (`async fetch(req, env, ctx) { const userState = ... }`) that go out of scope when the request finishes.

A useful pattern: in tests, deliberately invoke the Worker twice within the same isolate and confirm the second invocation does not see state from the first. The Cloudflare `vitest-pool-workers` test runner exposes the isolate model, making this straightforward.

### Step 5: Header Forwarding Hygiene

A Worker that proxies requests to a backend can leak the original `Authorization`, `Cookie`, or other sensitive headers if it forwards the user's request unchanged.

```typescript
// proxy.ts
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Bad: forwards every header to the upstream.
    // const upstreamResponse = await fetch(upstream_url, request);

    // Good: only forward expected headers.
    const upstream = new URL("/v1/api", "https://api.internal.example.com");
    const filteredHeaders = new Headers();
    const allowedHeaders = ["content-type", "accept", "x-trace-id"];
    for (const [name, value] of request.headers.entries()) {
      if (allowedHeaders.includes(name.toLowerCase())) {
        filteredHeaders.set(name, value);
      }
    }
    // Add internal-only auth.
    filteredHeaders.set("Authorization", `Bearer ${env.INTERNAL_API_KEY}`);

    return fetch(upstream.toString(), {
      method: request.method,
      headers: filteredHeaders,
      body: request.body,
    });
  },
};
```

The user's `Authorization: Bearer <user-token>` does not leak to the backend; the backend receives a Worker-controlled credential. The user's `Cookie` does not leak either.

### Step 6: Log Redaction

Worker logs land in the platform's logging tier (Cloudflare Logs, Fastly's Real-Time Log Streaming). Default logging often captures the entire request:

```typescript
// Avoid:
console.log("incoming request:", request);
// Logs the full URL (including query string with auth tokens) and headers.

// Better: log structured fields after redaction.
console.log(JSON.stringify({
  event: "request",
  method: request.method,
  path: new URL(request.url).pathname,    // path only; no query string
  user_id: request.headers.get("X-User-Id"),
  trace_id: request.headers.get("X-Trace-Id"),
}));
```

Send logs to your own pipeline (Logpush to R2, Logflare, Datadog) and apply the same redaction at the destination as well.

### Step 7: Rate Limiting Against Abusive Inputs

Edge runtimes are first-line targets for bots and probes. Use the platform's rate-limiting features:

```toml
# Cloudflare: built-in rate-limiting binding.
[[env.production.rate_limit]]
binding = "RATE_LIMITER"
namespace_id = "<id>"
simple = { limit = 100, period = 60 }
```

```typescript
// In code.
const rateKey = request.headers.get("CF-Connecting-IP") || "anon";
const { success } = await env.RATE_LIMITER.limit({ key: rateKey });
if (!success) {
  return new Response("rate limit exceeded", { status: 429 });
}
```

Combine with platform-level WAF rules to block obvious automated abuse before it reaches the Worker.

## Expected Behaviour

| Signal | Default | Hardened |
|--------|---------|----------|
| Worker's `fetch()` to arbitrary URL | Succeeds | Blocked unless host is on allowlist |
| Secrets in deploy bundle | Visible in `wrangler deploy --dry-run --outdir` | Stored in Secret Store; only fetched at runtime |
| Cross-request module state | Persists across requests, possibly across tenants | Module-level state is immutable; per-request state is request-scoped |
| Backend receives user's Authorization | Yes (if forwarded) | No; only Worker-controlled credential |
| Logs contain full request URL with query | Yes | Path only; query stripped or redacted |
| Worker abuse from a single IP | No platform-level limiter active | Rate-limited per IP, with platform WAF in front |
| KV/R2/D1 binding scope | All-namespace | Single binding per Worker |

Verify the hardening:

```bash
# Bundle inspection.
wrangler deploy --dry-run --outdir=./dist
ls -la dist/
# Confirm dist/*.js does not contain secret strings.

# Cross-tenant state regression test.
npx wrangler dev --remote &
# Send 1000 sequential requests with different X-User-Id headers; confirm
# response from request N does not depend on request N-1.
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Service bindings over `fetch()` | Internal-only routing; no public-Internet hop | Service bindings only work for Workers in your own account | Use Service bindings for internal calls; reserve `fetch()` for genuine external calls. |
| Outbound fetch allowlist | Bounds SSRF and exfiltration | Adding new external hosts requires code change | Centralize the allowlist in a config Worker or in a shared module across Workers. |
| Module-scope state minimization | Eliminates cross-request leakage | Slightly more cold-start cost (re-initialize per request) | Initialize cheap state per request. Compile expensive things (regex, prepared queries) once at module load and treat as immutable. |
| Header filtering on proxy | Prevents leakage of user credentials to backends | Manual maintenance of allowed-header list | Build a shared proxy library that all Workers use; update centrally. |
| Log redaction | Reduced PII exposure in logs | Some debugging info lost | Use structured logs; emit a request ID that can be correlated with deep-debug logs in a separate (more restricted) pipeline. |
| Platform Secret Store | Secrets not in deploy bundle | Slight latency on first secret access; managed separately from code | Acceptable; benefits outweigh cost. |
| Rate limiter | Cheap bot mitigation | Cap-and-throttle of legitimate spike traffic | Tune limits per route; use Cloudflare's analytics to identify thresholds. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Secret leaked in deploy bundle | Audit reveals secret string in built JS | Static-analysis pre-deploy hook flags secret patterns | Rotate the secret immediately; investigate exposure window. Move all secrets to Secret Store. |
| SSRF via user-controlled URL | Worker fetches an internal URL the user supplied | Unexpected outbound from Worker IPs to internal hosts | Reject the request before fetch; centralize URL validation. |
| Cross-tenant state leak | User-A's data appears in User-B's response under load | Synthetic test with sequential requests detects it; production reports of "wrong data" | Audit module-level state; move all per-user state to request-scoped or persisted (DO/KV). |
| Header forwarded to upstream | Backend logs show user's `Authorization` | Backend audit log analysis | Filter headers in proxy code; rebuild and redeploy. |
| Worker hits rate-limit during legitimate burst | Users see 429 from Worker | Rate-limit metrics show legitimate traffic blocked | Raise limits; consider per-route limits; use the platform's WAF for genuine bots. |
| Binding token compromise | Attacker reads/writes KV or R2 | Cloudflare audit log shows API access from unexpected IPs | Rotate the binding's token; review which Workers reference the token; consider switching to per-Worker bindings. |
| Compatibility flag drift | Worker behaves differently after platform upgrade | Errors after a date crossover (compatibility_date applied) | Pin `compatibility_date` to a known-good value; upgrade in canary mode. |

## Related Articles

- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [WASI Preview 2 Capability-Based Security](/articles/wasm/wasi-preview-2-capabilities/)
- [Internal API Protection](/articles/network/internal-api-protection/)
- [Rate Limiting at the Ingress Layer](/articles/network/rate-limiting-ingress/)
- [HTTP Security Headers That Actually Work](/articles/network/http-security-headers/)
