---
title: "Envoy and Istio WASM Plugin Hardening: Resource Limits, ABI Selection, and Distribution"
description: "WASM plugins run inline in the data path. A misconfigured plugin can exhaust memory, leak tenant data, or crash the proxy. The defaults need explicit caps."
slug: "envoy-wasm-plugin-hardening"
date: 2026-04-27
lastmod: 2026-04-27
category: "wasm"
tags: ["envoy", "istio", "wasm", "service-mesh", "plugins"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 181
difficulty: "intermediate"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/wasm/envoy-wasm-plugin-hardening/index.html"
---

# Envoy and Istio WASM Plugin Hardening: Resource Limits, ABI Selection, and Distribution

## Problem

Envoy's WASM extension model lets operators inject custom logic into the request path: header rewriting, custom auth, rate limiting, JWT validation, custom telemetry, traffic shaping. The model is mature in Istio (since 2019), Gloo, Kuma, and standalone Envoy 1.18+. By 2026, plugins distributed as OCI artifacts and loaded at runtime are common.

Plugins run in the same Envoy process as the proxy. They share the proxy's memory space (logically; WASM provides linear-memory isolation), the proxy's connection pool, and the proxy's traffic. A misbehaving plugin affects every request flowing through the worker:

- **Memory exhaustion in a plugin** crashes the Envoy worker. Without strict per-plugin memory caps, a plugin with a memory leak takes the worker with it within hours.
- **CPU exhaustion in a plugin** stalls every request. WASM plugins run synchronously in the request path; a plugin that loops adds latency to every concurrent request.
- **Plugins can call back into Envoy** via the proxy-wasm ABI (`get_property`, `get_buffer`, `set_buffer`, `dispatch_http_call`). Without restrictions, a plugin can read sensitive properties (TLS metadata, peer certificates) or initiate outbound calls.
- **Plugin distribution via OCI** is convenient but bypasses normal admission control unless explicitly wired up.
- **ABI version mismatches** between Envoy and plugins cause crashes, especially after Envoy upgrades that change ABI semantics.

The specific gaps in default Envoy WASM configuration:

- No memory or fuel cap on the plugin VM.
- The `proxy-wasm` ABI is fully accessible — including `dispatch_http_call` for outbound HTTP from plugins.
- Plugin OCI artifacts are pulled without signature verification.
- No per-tenant or per-route plugin isolation; one bad plugin in a multi-tenant proxy affects all tenants.
- Plugin CPU and memory metrics are not exposed by default.

This article covers per-plugin memory and CPU caps, ABI restriction patterns, OCI signing for plugin distribution, per-route plugin scoping, and operational telemetry.

**Target systems:** Envoy 1.30+, Istio 1.22+, Kuma 2.6+, Gloo Mesh 2.5+, Solo.io WebAssembly Hub. Plugins use the proxy-wasm ABI v0.2.x. Compatible runtimes inside Envoy: V8 (default), Wasmtime, WAMR.

## Threat Model

- **Adversary 1 — Compromised plugin author:** an attacker has write access to a WASM plugin's source repository or build pipeline and ships malicious logic in a routine update.
- **Adversary 2 — Plugin supply-chain attack:** plugin pulled from an OCI registry has been replaced with a malicious version (registry compromise, typosquat, mis-pinned tag).
- **Adversary 3 — Plugin abusing the proxy-wasm ABI:** a plugin with `dispatch_http_call` permission uses it for SSRF or to exfiltrate request bodies to an external endpoint.
- **Adversary 4 — Plugin resource abuse for DoS:** a plugin (malicious or buggy) consumes memory or CPU until Envoy workers crash.
- **Access level:** Plugin source-repo access for Adversary 1; registry access for Adversary 2; running plugin in production for Adversaries 3 and 4.
- **Objective:** Read or modify request data; exfiltrate sensitive headers (Authorization, Cookie); cause data-plane outages.
- **Blast radius:** A compromised plugin sees every request and response on every route the plugin is bound to. It can read TLS-decrypted bodies, modify response payloads, or terminate the Envoy worker. Without per-plugin isolation, one tenant's plugin can affect another tenant's traffic.

## Configuration

### Step 1: Set Per-Plugin Memory and CPU Caps

Envoy supports VM-level resource caps via the `vm_config` field. Set them on every plugin definition:

```yaml
# Envoy listener filter chain with WASM plugin and resource caps.
http_filters:
  - name: envoy.filters.http.wasm
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
      config:
        name: my-auth-plugin
        root_id: my_auth_root
        vm_config:
          runtime: envoy.wasm.runtime.v8
          vm_id: my-auth-plugin
          code:
            remote:
              http_uri:
                uri: https://registry.example.com/wasm-plugins/my-auth/v1.2.3.wasm
                cluster: registry-cluster
                timeout: 10s
              sha256: 1234567890abcdef...
              retry_policy:
                num_retries: 2
          allow_precompiled: false
          environment_variables:
            host_env_keys: []
            key_values: {}
        configuration:
          "@type": type.googleapis.com/google.protobuf.StringValue
          value: |
            {
              "issuer": "https://auth.example.com",
              "audience": "internal-api"
            }
        # Resource caps.
        capability_restriction_config:
          allowed_capabilities:
            proxy_get_property: {}
            proxy_log: {}
            proxy_get_buffer: {}
            proxy_set_buffer: {}
            # Note: proxy_dispatch_http_call deliberately omitted.
            # The plugin cannot make outbound HTTP calls.
        max_capabilities_concurrent: 1
```

Key choices:

- `runtime: envoy.wasm.runtime.v8` — V8 is the most-tested runtime; Wasmtime is an alternative for environments where V8 is unwanted. WAMR is smaller but less mature.
- `code.remote.sha256` — pins the plugin to a specific content digest. A registry that serves a different artifact under the same URL fails the digest check.
- `allow_precompiled: false` — refuses precompiled `.cwasm` artifacts, which would skip Envoy's compile-time validation.
- `capability_restriction_config.allowed_capabilities` — the proxy-wasm ABI calls the plugin can make. By omitting `proxy_dispatch_http_call`, the plugin cannot initiate outbound HTTP requests.

For per-VM memory caps, configure at the bootstrap level:

```yaml
# bootstrap.yaml
runtime:
  layered_runtime:
    layers:
      - name: static_layer_0
        static_layer:
          envoy.wasm.runtime.v8.engine.heap_size_limit: 67108864       # 64 MiB
          envoy.wasm.runtime.v8.engine.fuel_consumption: 100000000     # 100M ops budget
          envoy.wasm.runtime.wasmtime.engine.memory_limit: 67108864
          envoy.wasm.runtime.wasmtime.engine.fuel_consumption: 100000000
```

The fuel limit acts like Wasmtime's fuel: a budget consumed per operation, refilled per request. A plugin that exceeds the budget traps; the request continues per the plugin's `failure_policy`.

### Step 2: Failure Policy — Fail Closed or Fail Open

The plugin's `failure_policy` decides what happens when the plugin traps:

```yaml
config:
  fail_open: false        # default for security-critical plugins
```

`fail_open: false` rejects the request when the plugin traps. Use for authentication, authorization, and policy-enforcement plugins. `fail_open: true` allows the request through (the plugin is skipped); use only for observability or non-critical plugins.

A plugin with `fail_open: false` that crashes makes every request fail until the plugin is fixed. That is the correct behavior for an auth plugin. A plugin with `fail_open: true` that crashes silently lets requests bypass the plugin's logic — never use for security-critical plugins.

### Step 3: ABI Capability Restriction in Detail

The proxy-wasm ABI is a wide surface. Restrict it per plugin to the minimum needed.

| Capability | Use case | Risk if granted |
|------------|----------|-----------------|
| `proxy_log` | Plugin logs to Envoy's log stream | Low; logging-only |
| `proxy_get_property` | Read connection metadata, peer info, TLS | High if unrestricted; can read sensitive properties |
| `proxy_get_buffer` / `proxy_set_buffer` | Read/modify request and response bodies | Plugin can read sensitive request data |
| `proxy_dispatch_http_call` | Plugin makes outbound HTTP from the proxy | High; SSRF and exfiltration |
| `proxy_dispatch_grpc_call` | Plugin makes outbound gRPC | Same as HTTP |
| `proxy_define_metric` / `proxy_increment_metric` | Plugin emits metrics | Low |
| `proxy_set_shared_data` / `proxy_get_shared_data` | Cross-VM shared data | Allows plugins to communicate; consider isolation |
| `proxy_call_foreign_function` | Native foreign function call | High; bypasses sandbox if FF is not audited |

Apply minimal capabilities per plugin role:

```yaml
# Logging plugin: just log.
capability_restriction_config:
  allowed_capabilities:
    proxy_log: {}
    proxy_get_property: {}     # read peer info for log enrichment
    proxy_define_metric: {}
    proxy_increment_metric: {}

# Auth plugin: read headers, set status, log. No outbound calls.
capability_restriction_config:
  allowed_capabilities:
    proxy_log: {}
    proxy_get_property: {}
    proxy_get_buffer: {}        # read Authorization header
    proxy_set_buffer: {}        # set 401 response
    proxy_define_metric: {}
    proxy_increment_metric: {}

# Header rewriter: only buffer access for headers.
capability_restriction_config:
  allowed_capabilities:
    proxy_log: {}
    proxy_get_buffer: {}
    proxy_set_buffer: {}
```

For plugins that legitimately need `proxy_dispatch_http_call` (e.g., an external-authorization plugin that calls a remote service), constrain the targets:

```yaml
# Configuration block for the plugin itself.
configuration:
  "@type": type.googleapis.com/google.protobuf.StringValue
  value: |
    {
      "allowed_dispatch_clusters": ["external-auth-cluster"]
    }
```

The plugin code reads this configuration and refuses dispatch to clusters not on the list. Combined with Envoy cluster definitions that limit destinations, this bounds the plugin's outbound reach.

### Step 4: Per-Route and Per-Tenant Plugin Scoping

In a multi-tenant proxy, do not run all tenants' plugins on every request. Scope plugins to specific routes:

```yaml
# Route-level filter override.
routes:
  - match: {prefix: "/tenant-a"}
    route: {cluster: tenant-a-backend}
    typed_per_filter_config:
      envoy.filters.http.wasm:
        "@type": type.googleapis.com/envoy.extensions.filters.http.wasm.v3.PluginConfig
        name: tenant-a-auth-plugin
        # ... full plugin config

  - match: {prefix: "/tenant-b"}
    route: {cluster: tenant-b-backend}
    typed_per_filter_config:
      envoy.filters.http.wasm:
        "@type": type.googleapis.com/envoy.extensions.filters.http.wasm.v3.PluginConfig
        name: tenant-b-auth-plugin
```

Each plugin runs in its own VM (Envoy creates one VM per `vm_id`). A crash in tenant-A's plugin does not affect tenant-B's traffic.

### Step 5: Plugin Signing and Distribution

WASM plugins distributed via OCI follow the same signing pattern as standalone WASM modules (covered in [OCI WASM Module Signing and Verification](/articles/wasm/wasm-oci-signing/)). The Envoy-specific addition: Istio's `WasmPlugin` resource can verify SHA256 directly:

```yaml
apiVersion: extensions.istio.io/v1alpha1
kind: WasmPlugin
metadata:
  name: my-auth-plugin
  namespace: istio-system
spec:
  selector:
    matchLabels:
      app: api-gateway
  url: oci://registry.example.com/wasm-plugins/my-auth:v1.2.3
  imagePullSecret: registry-creds
  sha256: 1234567890abcdef...
  phase: AUTHN
  pluginConfig:
    issuer: https://auth.example.com
    audience: internal-api
  failStrategy: FAIL_CLOSE
  vmConfig:
    env:
      - name: TENANT
        value: payments
```

The `sha256` field rejects mismatched artifacts at pull time. Pair with admission control on `WasmPlugin` resources to require the field be present and matched against a known-good value.

For Kyverno enforcement:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: wasmplugin-must-have-sha256
spec:
  validationFailureAction: Enforce
  rules:
    - name: require-sha256
      match:
        resources:
          kinds: [WasmPlugin]
      validate:
        message: "WasmPlugin must specify sha256 for content pinning"
        pattern:
          spec:
            sha256: "?*"
            failStrategy: "FAIL_CLOSE"
```

### Step 6: Plugin Telemetry

Track plugin-level metrics. Envoy exposes WASM stats via `/stats`:

```
envoy.wasm.runtime.v8.engine.compile_failures
envoy.wasm.runtime.v8.engine.compile_successes
envoy.wasm_filter.<plugin_name>.execution_failures
envoy.wasm_filter.<plugin_name>.fail_open_count
envoy.wasm_filter.<plugin_name>.fail_close_count
envoy.wasm_runtime_internal_errors
envoy.wasm_vm_<vm_id>.dispatch_calls_total
envoy.wasm_vm_<vm_id>.memory_pages_current
```

Alert on:
- Sustained `execution_failures` increase (plugin is crashing).
- `fail_open_count > 0` for security-critical plugins (your config is wrong; fix-by-config-only).
- `memory_pages_current` approaching the configured cap (memory leak).
- `dispatch_calls_total` to unexpected clusters (plugin abusing outbound HTTP).

## Expected Behaviour

| Signal | Default Envoy WASM | Hardened |
|--------|---------------------|----------|
| Plugin attempting outbound HTTP | Succeeds (full proxy-wasm ABI) | Blocked unless `proxy_dispatch_http_call` is explicitly allowed |
| Plugin allocating 1 GB memory | Succeeds; Envoy worker may OOM | Trap when heap exceeds configured cap; plugin fails |
| Plugin in infinite loop | Stalls every request on the worker | Trap when fuel exhausted; request continues per failure_policy |
| Plugin loaded with mismatched SHA | Loaded if matching at registry | Rejected at fetch time |
| Multiple plugins on same vm_id | Share VM state | Use distinct vm_id; isolation enforced |
| Plugin telemetry | Limited | Per-plugin metrics with execution counts and resource usage |

Verify plugin behavior:

```bash
# Confirm a plugin cannot exceed the memory cap.
curl -sX GET http://envoy-admin:9901/stats?filter=wasm_vm.*memory_pages
# wasm_vm.my_auth_plugin.memory_pages_current: 1024
# (max 1024 = 64 MiB; plugin trapped on attempt to grow further)

# Confirm a plugin without dispatch capability cannot reach external.
curl -X POST http://gateway/test  # plugin tries dispatch
# Envoy logs: "WASM filter capability denied: proxy_dispatch_http_call"
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Memory + fuel caps | Bounded resource use per plugin | Plugins that need more must request and justify | Set defaults conservatively; allow per-plugin overrides via review. |
| Capability restriction | Minimal proxy-wasm surface per plugin | Plugin authors must know which capabilities they need | Document the per-role capability sets; provide a template per plugin type. |
| `fail_open: false` | Security-critical plugins fail closed on crash | Operational risk if a plugin bug crashes all traffic | Test extensively in staging; canary new plugin versions; alert on `execution_failures`. |
| Per-route scoping | Tenants isolated; plugin scope minimized | More plugin configurations to manage | Use Istio's `WasmPlugin.selector` with workload labels; manage as code in Git. |
| SHA256 pinning | Plugin content tamper-detection | Update flow requires re-deployment with new SHA | Automate SHA computation in the plugin build pipeline; rotate via GitOps. |
| V8 vs Wasmtime runtime choice | V8: most-tested, fastest cold start; Wasmtime: smaller surface | Each has different bug history | Stick with V8 unless you have a specific reason; switch is non-trivial. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Plugin trap with `fail_open: true` | Requests bypass the plugin silently | `fail_open_count` counter increases; users not authenticated | Should never use `fail_open: true` on security plugins. Audit all plugins; switch to `FAIL_CLOSE`. |
| SHA mismatch breaks plugin load | New plugin version not loading | Envoy admin endpoint shows plugin in error state | Update the SHA in the WasmPlugin resource to match the new build's SHA. Pipeline should compute and update SHA in lockstep with release. |
| Capability restriction misconfigured | Plugin fails on first request because it tries to call a denied capability | Plugin error logs show `capability denied` | Identify the missing capability; weigh whether the plugin legitimately needs it. Add only if justified. |
| Memory cap too low for legitimate plugin | Plugin fails when traffic exceeds a threshold | `memory_pages_current` regularly hits cap | Profile plugin memory under load; raise cap or refactor plugin. |
| ABI version mismatch after Envoy upgrade | Plugins crash on first invocation post-upgrade | Plugin compile failures spike after Envoy version change | Rebuild plugins against the new ABI version. Pin plugin SDK versions to match the Envoy release. |
| Multiple plugins share `vm_id` | A plugin sees state from another | `proxy_get_shared_data` returns unexpected values | Each plugin needs unique `vm_id`. Use `<plugin_name>-<route_id>` to guarantee uniqueness. |
| Plugin OCI artifact pulled from compromised registry | Tampered plugin runs | Signature verification fails (if configured); SHA mismatch | Configure signing verification (see related article); ensure registry credentials are scoped read-only. |

## Related Articles

- [OCI WASM Module Signing and Verification](/articles/wasm/wasm-oci-signing/)
- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [WASM Workloads on Kubernetes](/articles/wasm/wasm-on-kubernetes/)
- [mTLS in Service Mesh: Zero-Trust Networking Between Services](/articles/network/mtls-service-mesh/)
- [API Gateway Security](/articles/network/api-gateway-security/)
