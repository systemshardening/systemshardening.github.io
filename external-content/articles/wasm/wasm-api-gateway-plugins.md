---
title: "WASM API Gateway Plugins: Securing Kong, APISIX, and Custom Gateway Extensions"
description: "Gateway WASM plugins process all traffic flowing through the gateway — request headers, auth tokens, and bodies. This guide covers supply chain security for gateway plugins, capability restrictions, sandboxed execution with resource limits, per-tenant plugin isolation, and audit logging for plugin-based security decisions."
slug: wasm-api-gateway-plugins
date: 2026-05-07
lastmod: 2026-05-07
category: wasm
tags:
  - wasm
  - api-gateway
  - kong
  - apisix
  - plugin-security
personas:
  - security-engineer
  - platform-engineer
article_number: 583
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/wasm/wasm-api-gateway-plugins/
---

# WASM API Gateway Plugins: Securing Kong, APISIX, and Custom Gateway Extensions

## Problem

API gateways are chokepoints. Every inbound request, every auth token, every request body for every tenant flows through a small number of gateway processes. Gateway plugins — code injected into that flow to perform JWT validation, rate limiting, request transformation, header rewriting, logging — run at the position of maximum leverage in the entire architecture.

Envoy pioneered WASM as a plugin mechanism for proxies via the proxy-wasm ABI, and NGINX followed with `ngx_wasm_module`. By 2026, WASM plugin support has moved into the broader API gateway ecosystem: Kong, Apache APISIX, and generic gateway frameworks all have WASM plugin mechanisms with varying maturity levels. The hardening concerns are structurally different from Envoy because:

- **Kong and APISIX are higher-level gateways.** They manage routing, authentication, and rate limiting as first-class platform primitives, not proxy filters. Plugins plug into a platform with more surface area than a raw proxy.
- **Multi-tenancy is the default operating model.** A single Kong or APISIX installation commonly routes traffic for dozens or hundreds of independent services and API consumers. A plugin installed on one route should have no visibility into traffic for other routes.
- **Plugin authorship is distributed.** Kong Hub and APISIX plugin repositories contain community-contributed plugins. Organizations frequently ship internal plugins alongside community ones. The supply chain is wider.
- **The blast radius of a compromised plugin is proportional to where it is installed.** A plugin installed at the global level sees all traffic. A plugin installed per-route is scoped, but a single misconfigured route may cover authentication flows that expose all tenants' tokens.

The specific gaps in default gateway WASM plugin deployments:

- Plugin modules are loaded from filesystem paths or URLs without signature verification.
- Gateway platforms expose a rich set of host API functions to plugins; most are enabled by default with no capability restriction.
- Resource limits (memory, CPU instructions) are not set, allowing a buggy or malicious plugin to DoS the gateway worker.
- Plugin scope (global, service, route, consumer) is chosen for convenience rather than least privilege.
- Audit logging from plugins — security decisions made inside plugin code — is inconsistent or absent.

This article covers the threat model for gateway WASM plugins, supply chain controls, capability restrictions, sandboxed execution limits, per-tenant isolation patterns, secure plugin development practices for Kong and APISIX, and audit logging from plugin code.

**Target systems:** Kong Gateway 3.4+ (WASM filter support); Apache APISIX 3.8+ (WASM plugin mechanism); Tyk Gateway 5.3+ (Go plugin system with WASM compilation path); generic gateway platforms with embedded WASM runtimes.

## Threat Model

- **Adversary 1 — Compromised plugin via supply chain:** An attacker substitutes a legitimate plugin binary in a registry or artifact store. The malicious binary is loaded by the gateway and executes with the plugin's full host API access, reading auth tokens and request bodies for all traffic on the routes it covers.
- **Adversary 2 — Malicious internal plugin from a developer:** A developer with plugin-deployment access ships a plugin that exfiltrates data or performs unauthorized outbound calls. The gateway's plugin loading machinery does not verify intent — only the binary.
- **Adversary 3 — Cross-tenant plugin interference:** A plugin installed for tenant A's routes reads or manipulates shared gateway state in a way that leaks data into tenant B's request context. Shared memory, shared configuration stores, or shared logging buffers become the exfiltration channel.
- **Adversary 4 — Resource exhaustion via plugin:** A plugin with a memory leak or an infinite loop in its filter logic blocks gateway workers, raising latency or causing a worker crash. Without resource caps, one plugin affects all concurrent requests in the same worker.
- **Adversary 5 — Plugin-level SSRF:** A plugin that calls gateway-provided outbound HTTP functions (present in both Kong and APISIX plugin host APIs) can be used to pivot to internal services. If the gateway process has network access to internal services that clients do not, a plugin with outbound call capability is an SSRF proxy.
- **Access level:** Adversaries 1 and 2 need plugin deployment access (Kong Admin API, APISIX etcd write, or filesystem write on the gateway node). Adversary 3 needs a plugin execution context. Adversaries 4 and 5 need a plugin execution context.
- **Objective:** Exfiltrate traffic data, pivot to internal services, deny service, cross tenant boundaries.
- **Blast radius:** A global plugin sees 100% of traffic. A route-scoped plugin sees only that route's traffic, but if the route handles authentication, that may still be all auth tokens for the deployment.

## Configuration

### Step 1: Supply Chain Controls — Sign and Verify Plugin Modules

Before a WASM plugin binary is loaded, verify it was built by your pipeline and has not been tampered with.

**For Kong Gateway:** Kong 3.4+ loads WASM filters from the filesystem path configured in `wasm.filters` or fetched via the Admin API. Kong does not natively verify plugin signatures, so this must be enforced at the deployment layer.

Use `cosign` to sign the WASM artifact at build time:

```bash
cosign sign-blob \
  --key cosign.key \
  --bundle plugin.wasm.bundle \
  plugin.wasm
```

Verify before deploying to the gateway node:

```bash
cosign verify-blob \
  --key cosign.pub \
  --bundle plugin.wasm.bundle \
  plugin.wasm
```

Fail the deployment pipeline if verification fails. Never copy an unverified `.wasm` file to the gateway node's plugin directory.

For OCI-distributed plugins (Kong supports pulling filters from OCI registries in hybrid mode), use `cosign` to sign the OCI artifact and `policy-controller` or a custom admission webhook to enforce signature policy before the image is pulled by the gateway node.

**For Apache APISIX:** APISIX 3.8+ loads WASM plugins via paths in `apisix.yaml` or via the Admin API referencing filesystem paths on the APISIX node. Apply the same cosign verification pattern. Additionally, use a content-addressable reference (SHA256 pin) rather than a mutable version tag when specifying plugin paths in configuration:

```yaml
# apisix.yaml — pin the plugin to a specific verified hash
plugins:
  - name: my-auth-plugin
    wasm:
      file: /opt/apisix/plugins/my-auth-plugin.wasm
      # verified sha256 stored separately and checked in deploy script
```

Lock plugin version references in git and require a two-person review to change them. Treat a plugin version bump the same as a dependency upgrade in application code: review the diff, run in staging, verify the new binary's signature.

**Tyk Go plugins:** Tyk's plugin mechanism compiles Go plugins as shared objects or WASM (via TinyGo in Tyk 5.3+). Apply the same signing pattern to compiled plugin artifacts and enforce hash verification in the Tyk deployment process.

### Step 2: Capability Restrictions — Audit What the Host Exposes

Gateway WASM plugins interact with the host gateway via a host API — a set of functions the gateway exposes to the plugin module. The capabilities vary by gateway:

**Kong WASM filter host API (proxy-wasm ABI):** Kong's WASM support is built on the proxy-wasm ABI, the same interface Envoy uses. This exposes:

- `get_http_request_header` / `set_http_request_header`
- `get_http_request_body` / `set_http_request_body`
- `get_http_response_header` / `set_http_response_header`
- `dispatch_http_call` — outbound HTTP from the plugin
- `get_property` / `set_property` — read and write gateway properties
- `send_local_response` — short-circuit the request with a custom response
- `call_foreign_function` — invoke functions registered by other plugins

The capability of most concern is `dispatch_http_call`. A plugin that calls this can make outbound HTTP requests to any host reachable from the gateway process, including internal services on the same network. Restrict this at the network layer: gateway nodes should have egress firewall rules limiting outbound connections to known upstream hosts. If a plugin has no legitimate need for outbound calls, treat any outbound call from a plugin as an indicator of compromise.

**APISIX WASM plugin host API:** APISIX's WASM plugin mechanism (based on wasm-nginx-module, itself based on proxy-wasm) exposes a similar set. Additionally, APISIX exposes plugin-to-plugin communication via shared dictionaries. Audit which shared dictionary namespaces your plugin configuration exposes; a plugin that can write to a shared dictionary that another plugin reads from is a cross-plugin injection vector.

For each plugin, document which host API functions it uses during code review. Plugins that manipulate request headers need only getter/setter functions; they should not call `dispatch_http_call`. If the plugin runtime supports capability-based restriction at load time (Wasmtime's component model, or custom host function registration), remove host functions the plugin does not need from the set exposed to that plugin's instance.

### Step 3: Sandboxed Execution — Fuel and Memory Limits

A plugin that allocates unbounded memory or loops indefinitely blocks the gateway worker processing the request. Gateway requests are latency-sensitive; a 30-second plugin loop is a 30-second timeout for the client.

**Kong WASM filter limits:** Configure per-filter memory and CPU limits in Kong's WASM configuration:

```yaml
# kong.conf (declarative) or Kong Admin API WASM filter config
wasm:
  enabled: true
  filters:
    - name: my-auth-plugin
      path: /opt/kong/plugins/my-auth-plugin.wasm
      # Kong 3.4+ passes these to the Wasmtime engine
      memory_max_pages: 16    # 16 * 64KB = 1MB max linear memory
```

Kong exposes `wasm_filters_path` and per-filter configuration through the Admin API. Use the `config.wasm_module_transform` hook in your CI pipeline to assert that every plugin has explicit memory page caps set before deployment.

For CPU limits, Kong's Wasmtime embedding supports fuel consumption limits. Set these in the filter configuration or in the Wasmtime engine options passed through Kong's WASM runtime configuration. A reasonable starting cap for a request-path plugin is 10 million fuel units; profile the plugin under load to find the 99th-percentile consumption and set the cap at 2–3× that value.

**APISIX WASM plugin limits:** APISIX uses wasm-nginx-module, which runs Wasmtime or V8. Configure memory limits in `apisix.yaml`:

```yaml
wasm:
  plugins:
    - name: my-auth-plugin
      priority: 7500
      file: /opt/apisix/plugins/my-auth-plugin.wasm
      http_memory_max: 4096    # KB; limits linear memory per request context
```

Set `http_memory_max` for every WASM plugin in the APISIX configuration. The default is unbounded on older APISIX versions — check with `curl http://127.0.0.1:9090/v1/info` and inspect the plugin's runtime configuration.

**Generic pattern:** For any gateway with an embedded WASM runtime, apply the resource limit principle: set a memory cap at 1–2 MB for plugins that handle only headers, and at 4–8 MB for plugins that buffer request bodies. Set fuel/instruction caps based on profiling, not on intuition. Monitor per-plugin memory and CPU metrics — if Wasmtime metrics are not exposed by default, instrument the plugin loader to emit them.

### Step 4: Plugin Isolation Per Tenant and Per Route

A plugin installed at the global scope in Kong or APISIX processes all traffic for all routes and all consumers. If that plugin is compromised or buggy, every tenant is affected.

**Scope plugins to the minimum necessary entity:**

| Scope | Kong entity | APISIX scope | Use when |
|-------|-------------|--------------|----------|
| Global | Plugin with no `route`, `service`, or `consumer` | Global plugin | Never for security-sensitive plugins |
| Service | Plugin attached to a `service` | Service-scoped plugin | Plugin is specific to one upstream |
| Route | Plugin attached to a `route` | Route-scoped plugin | Default for most security plugins |
| Consumer | Plugin attached to a `consumer` | Consumer-scoped plugin | Plugin behavior is per-API-key or per-user |

In Kong, prefer route-scoped plugins for all authentication, authorization, and data-inspection plugins. Create separate plugin instances per route rather than one global instance:

```bash
# Attach the plugin to a specific route, not globally
curl -X POST http://localhost:8001/routes/{route_id}/plugins \
  --data "name=my-auth-plugin" \
  --data "config.param=value"
```

For APISIX, set the plugin at the route level in the route configuration rather than in the global plugins section of `apisix.yaml`.

**Cross-tenant state isolation:** Plugins that store per-request state must not use shared memory for that state. In proxy-wasm, each request runs in its own `HttpContext`; plugin root contexts are shared across requests. Keep per-request data strictly in the `HttpContext` and do not write to root-context shared state during request processing. Any write to shared state in a proxy-wasm plugin is a potential cross-request (and cross-tenant) interference point.

For APISIX plugins using shared dictionaries (`ngx.shared.dict`), namespace all keys by route ID or consumer ID:

```lua
-- Namespace the key to prevent cross-route data leakage
local key = string.format("ratelimit:%s:%s", route_id, consumer_id)
local count = shared_dict:get(key) or 0
```

### Step 5: Secure Kong WASM Plugin Development

Kong's WASM filter support uses the proxy-wasm ABI. Plugins are typically written in Rust or Go (via `proxy-wasm-go-sdk` or `proxy-wasm-rust-sdk`).

**Using proxy-wasm-go-sdk for Kong filters:** The Go SDK wraps the proxy-wasm ABI with idiomatic Go interfaces. Security considerations when writing Kong-compatible WASM plugins:

Restrict the plugin to only the PDK functions it needs. Do not import or call `dispatch_http_call` unless the plugin has a verified need for outbound calls:

```go
// Good — only use what the plugin needs
func (ctx *httpContext) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
    authHeader, err := proxywasm.GetHttpRequestHeader("authorization")
    if err != nil || authHeader == "" {
        _ = proxywasm.SendHttpResponse(401, nil, []byte("Unauthorized"), -1)
        return types.ActionPause
    }

    // Validate the token — keep this synchronous, no dispatch_http_call
    if !validateToken(authHeader) {
        _ = proxywasm.SendHttpResponse(403, nil, []byte("Forbidden"), -1)
        return types.ActionPause
    }

    return types.ActionContinue
}
```

Avoid blocking in plugin code. Token validation that requires an external call (introspection endpoint, JWKS fetch) should be cached. Cache JWKS public keys at plugin root context initialization, refreshed on a timer, not on every request. Fetching a JWKS endpoint via `dispatch_http_call` on every request adds latency and creates a dependency that can be exploited for DoS by flooding the JWKS endpoint.

Validate all inputs at the plugin boundary. Request headers, body content, and query parameters arriving at the plugin are attacker-controlled. Apply length limits before processing:

```go
const maxAuthHeaderLen = 4096

authHeader, _ := proxywasm.GetHttpRequestHeader("authorization")
if len(authHeader) > maxAuthHeaderLen {
    _ = proxywasm.SendHttpResponse(400, nil, []byte("Bad Request"), -1)
    return types.ActionPause
}
```

### Step 6: APISIX Plugin Security — WASM vs Lua

APISIX has historically used Lua plugins (via OpenResty/LuaJIT). WASM plugins are a migration path that offers different security properties.

**Security properties of WASM vs Lua in APISIX:**

| Property | Lua (OpenResty) | WASM (wasm-nginx-module) |
|----------|----------------|--------------------------|
| Memory isolation | Shared LuaJIT heap per worker | Per-plugin linear memory sandbox |
| Capability restriction | No formal model; any Lua code can call `ngx.*` | Host functions registered at load time |
| Supply chain | Lua source files; hard to sign | Binary `.wasm` artifact; cosign-signable |
| Resource limits | No fuel equivalent; timeouts only | Memory page caps + fuel limits |
| Language safety | Dynamic typing; runtime type errors | Language-level safety depends on source language (Rust = high) |
| Shared state isolation | Shared `ngx.shared.dict` accessible to all plugins | Shared state must be explicitly provided by host |

When migrating Lua plugins to WASM, do not assume the WASM version is automatically more secure. Specifically:

- A Lua plugin that uses `ngx.location.capture` (internal subrequest) for upstream validation may be rewritten to use `dispatch_http_call` in WASM. Both carry SSRF risk if the destination is user-controlled. Validate destination URLs against an allowlist in both cases.
- Lua plugins that write to `ngx.shared.dict` with user-supplied keys create key collision risks. The same pattern migrated to WASM using APISIX's shared dictionary API preserves the vulnerability.
- WASM provides linear-memory isolation, but a plugin that serializes data to a shared host-side store (Redis, etcd, the APISIX configuration store) bypasses linear-memory boundaries entirely.

The correct approach: treat the migration as a security review opportunity. For each Lua plugin being migrated, apply threat modeling before rewriting. The WASM version should implement the minimum host API surface, not a direct port of the Lua code's host API calls.

### Step 7: Audit Logging from Gateway Plugins

Security decisions made inside plugin code — "this request was denied because the JWT was expired," "this consumer exceeded their rate limit," "this request was flagged for suspicious header patterns" — must be logged in a way that is retrievable during incident response.

**What to log from gateway plugins:**

- Decision outcome: allowed or denied, and why (rule ID, policy name, not the full token value)
- Request identifiers: route ID, service ID, consumer ID, correlation ID from request headers
- Timestamp with millisecond precision
- Plugin name and version (so a post-incident investigation can correlate to a specific plugin binary)
- Redacted auth material: log the first 8 characters of a JWT or API key for correlation, never the full value

**Kong plugin audit logging:** Use Kong's structured logging capabilities. From a WASM filter, emit audit-relevant data as response headers that Kong's logging plugins pick up, or use the `set_property` ABI call to attach metadata to the request for Kong's logging subsystem:

```go
// Attach security decision metadata for Kong's logging pipeline
_ = proxywasm.SetProperty([]string{"kong", "plugin", "auth_decision"}, []byte("denied:expired_jwt"))
_ = proxywasm.SetProperty([]string{"kong", "plugin", "consumer_id"}, []byte(consumerID))
```

Configure Kong's `file-log` or `http-log` plugin to capture these properties and emit them to your SIEM. Ensure the log destination is append-only from the gateway's perspective — a compromised plugin that can overwrite or truncate the audit log eliminates its own trace.

**APISIX plugin audit logging:** APISIX provides the `error-log-logger` and `kafka-logger` plugins for structured log forwarding. From a WASM plugin, use the proxy-wasm `log()` ABI call at the appropriate log level:

```rust
// Emit a structured audit log line
proxywasm::log(
    LogLevel::Info,
    &format!(
        "{{\"event\":\"auth_denied\",\"reason\":\"expired_jwt\",\"consumer\":\"{}\",\"route\":\"{}\"}}",
        consumer_id, route_id
    ),
);
```

Configure APISIX's log router to forward `INFO`-level structured logs from plugin contexts to the audit destination. Set the log format to JSON and parse it in your SIEM with a dedicated plugin-audit pipeline.

**Log integrity:** Route audit logs to a write-once destination (S3 with object lock, a dedicated Loki instance with immutable storage, or a Kafka topic with retention policies). If a plugin is later found to be malicious, the audit log must be trustworthy — a compromised gateway that can delete its own logs allows an attacker to erase the evidence of what the plugin accessed.

## Verification

After applying these controls, verify them:

```bash
# Verify plugin binary signatures before each gateway deployment
cosign verify-blob \
  --key /etc/gateway/cosign.pub \
  --bundle /opt/plugins/my-auth-plugin.wasm.bundle \
  /opt/plugins/my-auth-plugin.wasm || exit 1

# Check Kong WASM filter configuration has memory limits set
curl -s http://localhost:8001/routes/{route_id}/plugins | \
  jq '.data[] | select(.name | startswith("wasm")) | .config.wasm_module_transform'

# Verify APISIX WASM plugins have memory limits
curl -s http://127.0.0.1:9090/v1/plugins | \
  jq '.[] | select(.type == "wasm") | {name: .name, memory_max: .http_memory_max}'

# Confirm no WASM plugins are installed at global scope in Kong
curl -s http://localhost:8001/plugins | \
  jq '.data[] | select(.name | startswith("wasm")) | select(.route == null and .service == null)'
# Should return empty — all WASM plugins should be route- or service-scoped

# Check audit log pipeline is receiving plugin events
grep '"event":"auth_denied"' /var/log/apisix/error.log | tail -5
```

## Ongoing Operations

**Plugin update process:** Treat plugin updates as security patches. Pin plugin versions in git, sign new builds with cosign, run in a staging environment for at least 24 hours before promoting to production. Use canary deployment — route 5% of traffic through the new plugin version before full rollout — so a misbehaving new version does not affect all traffic.

**Plugin capability audits:** Quarterly, review which host API functions each deployed plugin calls. Use static analysis tools (wasm-opt's `--print-call-graph`, or a custom wasm-tools script) to enumerate all imported host functions from the plugin binary:

```bash
wasm-tools print my-auth-plugin.wasm | grep "(import"
```

Any host import not in the plugin's documented capability list is an anomaly requiring investigation — it may indicate the plugin binary was replaced or was not built from the reviewed source.

**Metrics to alert on:**

| Metric | Alert threshold | Interpretation |
|--------|----------------|----------------|
| Plugin memory usage | > 80% of configured cap | Memory leak or unexpected input causing allocation |
| Plugin execution time p99 | > 50ms for header plugins | CPU-intensive code path; review for DoS risk |
| Plugin-denied request rate | Sudden spike | Either attack traffic or plugin misconfiguration |
| Plugin load errors | Any | Failed binary load; possible supply chain event |
| Audit log gap | > 60s with no plugin events during traffic | Log pipeline broken; investigate before assuming silence means no events |

## Summary

Gateway WASM plugins sit at the highest-value position in the request path. A plugin installed globally in Kong or APISIX sees every request, every auth token, every request body for every tenant in the deployment. The controls that matter:

1. **Sign and verify plugin binaries** with cosign before loading. Never deploy an unsigned plugin binary to a production gateway node.
2. **Set explicit memory and CPU limits** on every WASM plugin. Unbounded plugins are a DoS vector.
3. **Audit host API surface** — know which gateway functions each plugin can call, and restrict `dispatch_http_call` access unless explicitly required.
4. **Scope plugins to routes or services**, not globally. Global plugins have maximum blast radius.
5. **Namespace shared state** by tenant identifiers to prevent cross-tenant data leakage.
6. **Log security decisions** from plugin code to a write-once audit destination. Incident response requires knowing what every plugin decided for every request.

The WASM sandbox provides memory isolation between the plugin and the gateway host. It does not protect against a plugin that calls every host function available to it, reads every request header, and sends them via `dispatch_http_call` to an external endpoint. Defense requires controls at the deployment layer, the capability layer, the resource layer, and the observability layer — not just trust in the sandbox boundary.
