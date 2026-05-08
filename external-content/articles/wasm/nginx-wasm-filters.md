---
title: "NGINX WASM Filters with ngx_wasm_module: Request-Path Plugins, Resource Caps, and Distribution"
description: "ngx_wasm_module brings the proxy-wasm protocol to NGINX. Plugin authoring is similar to Envoy, but the worker model and hardening surface differ."
slug: "nginx-wasm-filters"
date: 2026-04-27
lastmod: 2026-04-27
category: "wasm"
tags: ["nginx", "wasm", "ngx_wasm_module", "proxy-wasm", "plugins"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 184
difficulty: "intermediate"
estimated_reading_time: 15
published: true
layout: article.njk
permalink: "/articles/wasm/nginx-wasm-filters/index.html"
---

# NGINX WASM Filters with ngx_wasm_module: Request-Path Plugins, Resource Caps, and Distribution

## Problem

NGINX has had `ngx_http_lua_module` and `njs` for years; both let operators inject custom logic into the request path. Each has limits — Lua adds a heavy runtime, njs is JavaScript with NGINX-specific extensions, and neither has the supply-chain story (signing, distribution, isolation) that container-based or WASM-based plugins have.

`ngx_wasm_module`, developed by Kong and increasingly upstream-tracked, brings the proxy-wasm protocol to NGINX. The same plugin model that has been in Envoy since 2019 — WASM modules implementing the proxy-wasm ABI to handle request and response phases — now runs inside NGINX worker processes.

For NGINX operators this changes the plugin story:

- A single plugin artifact (`.wasm`) runs in NGINX, Envoy, Apache Traffic Server, and any other proxy with proxy-wasm support. The build pipeline is shared.
- Plugins distribute through OCI registries, signed with cosign, verifiable at deploy time — same supply-chain controls as container images.
- The plugin runs in a sandboxed VM with linear-memory isolation, memory caps, and CPU caps. A misbehaving plugin does not corrupt the NGINX worker's heap.
- The proxy-wasm ABI surface is well-defined and capability-restrictable, replacing the "trust any Lua module" model.

The hardening surface differs from Envoy in ways that matter:

- **NGINX worker model.** NGINX runs multiple workers per box. Each worker has its own WASM VM instance per plugin. Memory caps apply per-VM; the per-worker count multiplies the host memory footprint.
- **Master-worker IPC.** NGINX's master process is privileged; workers are not. Plugin configuration changes via `nginx -s reload` cycle workers — long-lived plugin state persists for the worker's lifetime, not across reloads.
- **Phase semantics.** NGINX's phase model (`rewrite`, `access`, `content`, `header_filter`, `body_filter`, `log`) maps to proxy-wasm callbacks differently than Envoy's HTTP filter model. Some plugins that work in Envoy need adjustment for NGINX phases.
- **`ngx_wasm_module` runtime selection.** Choice between Wasmtime, V8, and WAMR backends, each with different memory and CPU characteristics.

This article covers `ngx_wasm_module` configuration, per-plugin resource caps, ABI capability restriction, OCI-based plugin distribution, and operational telemetry.

**Target systems:** NGINX 1.25+ with `ngx_wasm_module` v0.4+ compiled in; Wasmtime 22+ or V8 11+ as the runtime backend. Compatible with Kong Gateway 3.6+ which embeds the module by default.

## Threat Model

- **Adversary 1 — Compromised plugin author or build pipeline:** ships a malicious update to a previously-trusted plugin.
- **Adversary 2 — OCI registry typosquat or compromise:** plugin pulled with the wrong content, identity, or signature state.
- **Adversary 3 — Plugin abusing the proxy-wasm ABI:** uses `proxy_dispatch_http_call` for SSRF, reads sensitive request properties for exfiltration, or modifies response bodies for tampering.
- **Adversary 4 — Resource exhaustion:** a plugin (malicious or buggy) consumes CPU or memory until NGINX workers OOM or stall.
- **Access level:** Plugin author / registry access for adversaries 1 and 2; running plugin in production for 3 and 4.
- **Objective:** Read or modify in-flight requests; exfiltrate sensitive headers; cause data-plane outages.
- **Blast radius:** A plugin sees every request and response on every route it is bound to. Without per-plugin isolation, a memory leak in one plugin can crash a worker handling other tenants' traffic. With hardening, blast radius is bounded to the specific worker process and the routes the plugin is bound to.

## Configuration

### Step 1: Enable the WASM Subsystem

```nginx
# /etc/nginx/nginx.conf
load_module modules/ngx_wasm_module.so;

wasmtime {
    flag fuel_consumption on;
    flag wasi true;
}

# Or, alternatively, V8 backend.
# v8 {
#     flag wasm_max_module_size_bytes 16777216;
# }

events {
    worker_connections 1024;
}

http {
    # WASM VM defaults applied to every plugin unless overridden.
    wasm {
        # Per-VM memory cap.
        max_memory 64m;
        # Compilation cache to avoid recompile on reload.
        compiler_cache /var/cache/nginx/wasm;
        # Refuse precompiled artifacts.
        allow_precompiled off;
    }

    server {
        listen 443 ssl;
        server_name api.example.com;

        location /api/ {
            # Apply two plugins in order to this location.
            proxy_wasm my-auth-plugin;
            proxy_wasm my-rate-limit-plugin;
            proxy_pass http://upstream;
        }
    }
}
```

### Step 2: Define a Plugin with Resource Caps

```nginx
# Plugin definition block.
http {
    # ... defaults ...

    wasm {
        module my-auth-plugin {
            # Pin the artifact by digest. NGINX rejects mismatched content.
            file /etc/nginx/wasm/my-auth.wasm;
            sha256 1234567890abcdef...;
            config '{"issuer":"https://auth.example.com","audience":"api"}';

            # Per-plugin caps override the wasm{} defaults.
            max_memory 32m;
            fuel 50000000;       # 50M ops budget per request

            # ABI capability restriction.
            # By omitting capabilities, they are denied.
            allowed_capabilities {
                proxy_log;
                proxy_get_property;
                proxy_get_buffer;
                proxy_set_buffer;
                proxy_define_metric;
                proxy_increment_metric;
                # Note: proxy_dispatch_http_call deliberately omitted.
                # The plugin cannot make outbound HTTP calls.
            }

            # Failure policy.
            on_panic deny;       # any plugin trap rejects the request
        }
    }
}
```

`on_panic deny` makes the plugin fail-closed. For security-critical plugins (auth, authorization, request validation) this is correct. For observability or non-critical plugins, `on_panic continue` lets the request proceed without the plugin.

### Step 3: Per-Worker VM Accounting

NGINX runs `worker_processes` workers, each with its own VM instance per plugin. Plan capacity:

```
total_wasm_memory = worker_processes × num_plugins × max_memory_per_plugin
```

With `worker_processes auto` on a 16-core box, 4 plugins, and 32 MiB cap each:
`16 × 4 × 32 MiB = 2 GiB` reserved for WASM VMs alone. Pin `worker_processes` to a known value rather than `auto` if WASM memory is significant.

```nginx
# Pin worker count to make WASM memory predictable.
worker_processes 8;
worker_rlimit_nofile 65536;
```

### Step 4: Capability Restriction Per Plugin

The proxy-wasm ABI capability set should be minimal per plugin role.

```nginx
# Logging plugin — no body access, just metadata.
wasm {
    module my-logger {
        file /etc/nginx/wasm/logger.wasm;
        sha256 ...;
        allowed_capabilities {
            proxy_log;
            proxy_get_property;
            proxy_define_metric;
            proxy_increment_metric;
        }
        on_panic continue;       # logging failures should not break requests
    }
}

# Auth plugin — read headers, set status, no outbound calls.
wasm {
    module my-auth {
        file /etc/nginx/wasm/auth.wasm;
        sha256 ...;
        allowed_capabilities {
            proxy_log;
            proxy_get_property;
            proxy_get_buffer;       # read Authorization header
            proxy_set_buffer;       # set 401 response body
            proxy_define_metric;
            proxy_increment_metric;
        }
        on_panic deny;
    }
}

# External-auth plugin — needs dispatch to a specific cluster only.
wasm {
    module my-external-auth {
        file /etc/nginx/wasm/external-auth.wasm;
        sha256 ...;
        allowed_capabilities {
            proxy_log;
            proxy_get_property;
            proxy_get_buffer;
            proxy_set_buffer;
            proxy_dispatch_http_call;
            proxy_define_metric;
        }
        config '{"auth_cluster":"auth-service"}';
        on_panic deny;
    }
}
```

For plugins that need `proxy_dispatch_http_call`, define the upstream cluster as an NGINX upstream block and have the plugin reference it by name. The plugin cannot dispatch to arbitrary URLs — only to NGINX-defined clusters.

### Step 5: Load Plugins from OCI Registries

Pulling directly from OCI registries (rather than file paths) integrates with the existing supply-chain story:

```nginx
wasm {
    module my-auth {
        # Pull from OCI registry at startup.
        url oci://registry.example.com/wasm-plugins/my-auth:v1.2.3;
        sha256 1234567890abcdef...;
        registry_credentials_file /etc/nginx/registry-creds.json;

        allowed_capabilities {
            proxy_log;
            proxy_get_property;
            proxy_get_buffer;
            proxy_set_buffer;
        }
        on_panic deny;
    }
}
```

Combine with admission-pipeline cosign verification (covered in [OCI WASM Module Signing and Verification](/articles/wasm/wasm-oci-signing/)). NGINX itself does not verify cosign signatures yet; do verification at the registry side and gate plugin pushes there.

For air-gapped or signature-required environments, run a periodic pull-and-verify job that downloads the artifact, verifies cosign + SLSA provenance, and stages it to the local filesystem path NGINX uses:

```bash
#!/bin/sh
# /usr/local/bin/refresh-nginx-wasm-plugins.sh
set -eu

REF="oci://registry.example.com/wasm-plugins/my-auth:v1.2.3"
DEST="/etc/nginx/wasm/my-auth.wasm"

cosign verify "$REF" \
  --certificate-identity 'https://github.com/myorg/my-auth-wasm/.github/workflows/build.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

oras pull "$REF" --output /tmp/wasm
mv /tmp/wasm/my-auth.wasm "$DEST"
nginx -s reload
```

### Step 6: Telemetry

NGINX exposes WASM-specific stats via the existing `stub_status` and `vts` modules. Track per-plugin counts:

```
nginx_wasm_module_invocations_total{plugin}
nginx_wasm_module_panics_total{plugin}
nginx_wasm_module_fuel_consumed{plugin}
nginx_wasm_module_memory_pages_current{plugin, worker_pid}
nginx_wasm_module_dispatch_calls_total{plugin, cluster}
nginx_wasm_module_capability_denied_total{plugin, capability}
```

Alert on:
- `panics_total` rising — plugin instability.
- `capability_denied_total` non-zero — plugin trying to use a capability not granted (likely a misconfigured allowed_capabilities or an attempted ABI abuse).
- `memory_pages_current` near `max_memory` — leak.

### Step 7: Reload Hygiene

`nginx -s reload` cycles workers. WASM VMs reinitialize with the new configuration. Long-lived state in plugins (cached config, JWT keys) is reset. For plugins that fetch external config (e.g., JWKS for JWT verification), this means a re-fetch on every reload — coordinate the reload schedule with the upstream's rate limits.

For plugins that need cross-reload state, use `proxy_set_shared_data` / `proxy_get_shared_data` — a per-plugin key-value store that persists across reloads but not across worker restarts.

## Expected Behaviour

| Signal | Without ngx_wasm_module | With ngx_wasm_module (hardened) |
|--------|--------------------------|----------------------------------|
| Plugin runtime | Lua/njs with full host access | WASM with linear-memory sandbox + ABI capability allowlist |
| Plugin distribution | Files in NGINX config dir | OCI artifact, signed, content-pinned |
| Plugin abuse → worker compromise | Possible (Lua heap shared with NGINX) | Bounded by VM (separate linear memory, fuel, capability list) |
| Plugin failure | Configurable (Lua error handling) | `on_panic deny|continue` per plugin |
| Plugin observability | NGINX log lines | Per-plugin metrics with capability-denial counters |
| Plugin upgrade | Edit Lua, reload | Update OCI tag + SHA, reload |

Verify a plugin is enforced:

```bash
# Confirm capability denial works.
curl -X POST https://api.example.com/api/test
# Look for plugin's capability_denied entry in NGINX error log.
tail -f /var/log/nginx/error.log | grep wasm
# 2026/04/27 12:00:00 [error] 12345#12345: *1 wasm: capability denied:
#   proxy_dispatch_http_call (plugin: my-auth, request: /api/test)
```

```bash
# Confirm SHA pinning rejects mismatch.
echo "tampered" >> /etc/nginx/wasm/my-auth.wasm
nginx -t
# nginx: [emerg] wasm module my-auth: SHA mismatch:
#   expected 1234..., got 5678...
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| WASM over Lua/njs | Stronger isolation; supply-chain story | Cold-start of WASM VM per worker (~10-50ms) | Use `compiler_cache` to avoid recompile across reloads. |
| Per-plugin memory cap | Bounded RSS per plugin | Multiplied by worker count; total host RSS planning needed | Pin `worker_processes`; calculate total. |
| `on_panic deny` | Fail-closed for security plugins | Plugin bug crashes all traffic | Stage new plugins behind feature flags; test in staging. |
| ABI capability restriction | Smallest plugin surface | Plugin authors must know exact capability needs | Document per-role capability templates; provide examples. |
| OCI plugin distribution | Same pipeline as containers | Registry must be reachable from NGINX hosts | Mirror to a local registry; use the periodic pull-and-verify pattern for air-gap. |
| SHA pinning | Tamper detection | Update flow needs SHA refresh | Automate in deploy pipeline. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Plugin SHA mismatch on reload | `nginx -t` fails | Validation message in error log | Update SHA in nginx.conf to match the deployed artifact. Pipeline should compute SHA atomically with the file change. |
| Plugin allocates beyond `max_memory` | Plugin traps; `on_panic` policy applied | `nginx_wasm_module_panics_total` rises; per-plugin memory metric near cap | Increase cap if legitimate; identify leak otherwise. |
| Plugin tries denied capability | Specific request feature breaks | `capability_denied` log lines | Audit whether the capability is actually needed. Add only after review. |
| Worker OOM under combined plugin load | Worker process killed by kernel | dmesg shows oom-kill | Lower per-plugin `max_memory` or reduce `worker_processes`. |
| Reload loses plugin state | Cached JWKS, rate-limit counters reset | First requests after reload are slower or rate-limit windows reset | Use `proxy_set_shared_data` for state that should survive reload. |
| Plugin loads precompiled artifact | NGINX rejects with security warning | Log entry on first load | Keep `allow_precompiled off`. Build .wasm sources, not .cwasm. |
| ngx_wasm_module version skew | Plugin built against a newer module ABI fails | Module load errors at startup | Pin `ngx_wasm_module` and plugin SDK versions; upgrade in coordinated waves. |

## When to Consider a Managed Alternative

Self-hosting NGINX with WASM extensions requires module compilation, plugin distribution, capability config, signing pipeline, and observability for every plugin (4-8 hours/month for a multi-plugin gateway).

- **[Kong Gateway](https://konghq.com/products/kong-gateway):** ships `ngx_wasm_module` integrated, with plugin distribution via the Kong Hub.
- **[NGINX Plus with WAF Module](https://www.nginx.com/products/nginx-plus/):** managed package with Kubernetes-native config and supply-chain controls.
- **[Cloudflare API Gateway](https://www.cloudflare.com/application-services/products/api-gateway/):** if your gateway is at the edge, switch from self-hosted NGINX to Cloudflare's managed pipeline.

## Related Articles

- [Envoy and Istio WASM Plugin Hardening](/articles/wasm/envoy-wasm-plugin-hardening/)
- [Beyond TLS: Hardening NGINX for Production Traffic](/articles/network/nginx-hardening-beyond-tls/)
- [OCI WASM Module Signing and Verification](/articles/wasm/wasm-oci-signing/)
- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [API Gateway Security](/articles/network/api-gateway-security/)
