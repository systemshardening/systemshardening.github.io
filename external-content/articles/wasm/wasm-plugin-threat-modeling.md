---
title: "WASM Plugin Architecture Threat Modeling: Trust Boundaries, Host-API Exposure, and Supply Chain"
description: "Plugin systems built on WASM have a recurring shape. Threat-modeling that shape catches the structural mistakes before deployment."
slug: "wasm-plugin-threat-modeling"
date: 2026-04-29
lastmod: 2026-04-29
category: "wasm"
tags: ["wasm", "threat-modeling", "plugin-architecture", "security-design"]
personas: ["platform-engineer", "security-engineer", "ml-engineer"]
article_number: 222
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/wasm/wasm-plugin-threat-modeling/index.html"
---

# WASM Plugin Architecture Threat Modeling: Trust Boundaries, Host-API Exposure, and Supply Chain

## Problem

WASM is the lingua franca for plugin systems in 2026: Envoy plugins, NGINX filters, Postgres extensions, ClickHouse UDFs, agent tool implementations, OBS streaming filters, Kong middleware, Spin services, edge runtime customer code. Each is a different shape with the same shared problem: untrusted (or partially-trusted) code runs in a privileged host process.

Security architects approach each plugin system as if it were unique. The reality is that plugin systems share a dozen recurring decision points, and the same structural mistakes recur across implementations:

- **Host-API surface decided expediently.** "We expose a function that returns the current request body" — convenient for plugin authors, broad authority for the plugin.
- **Trust tiers conflated.** First-party plugins (vendor-shipped) and third-party plugins (customer-uploaded) run with the same authority.
- **No supply-chain verification.** Plugins distribute via OCI, npm, or vendor portals; signature verification is optional.
- **No resource quotas.** A misbehaving plugin consumes the host's CPU / memory.
- **State persistence ill-defined.** Plugins read / write the host's filesystem, KV stores, or shared memory in undefined ways.
- **Audit gaps.** Plugin actions don't show up in the host's normal audit log.

This article is a threat-modeling framework for plugin architectures. It walks the structural decisions you face, shows the threats that emerge from each, and provides patterns for the common shapes (sidecar plugins, in-process plugins, queryable plugins).

The output: a per-plugin-system threat model that documents the trust boundary, the host-API exposure, the resource caps, the audit story, and the supply-chain controls. Same structure as the broader threat-modeling-at-scale practice; specialized for the WASM plugin shape.

**Target systems:** any plugin architecture using WASM (Envoy, NGINX, Postgres pg_wasm, agent tool runtimes, custom platforms). The framework applies regardless of host language or runtime.

## Threat Model

The recurring adversaries:

- **Adversary 1 — Malicious plugin author:** uploads a plugin to the host system. Wants to escape the WASM sandbox or abuse the host API.
- **Adversary 2 — Compromised vendor / supply-chain:** legitimate plugin pipeline is compromised; updates carry malicious code.
- **Adversary 3 — Plugin abuse via privileged input:** a plugin processes input the user controls; the user crafts input to trick the plugin into doing the wrong thing.
- **Adversary 4 — Cross-plugin attack:** plugin A and plugin B share host resources; A reads B's data via a shared cache or coordination channel.
- **Adversary 5 — Resource exhaustion:** a plugin consumes host CPU / memory until the host service degrades.
- **Access level:** Adversary 1 has plugin upload capability. Adversary 2 has the plugin's build pipeline. Adversaries 3-4 have only normal user-level access to the host system. Adversary 5 has any plugin upload path.
- **Objective:** Read or modify host data, escape the sandbox, abuse host privileges, deny service to other plugins or users.
- **Blast radius:** depends entirely on the plugin architecture's trust boundaries. Done well: bounded to the plugin's own work and explicitly-shared resources. Done badly: arbitrary host access.

## Configuration

### Decision 1: Trust Tier of Plugins

Plugins fall into trust tiers; the architecture must distinguish them.

| Tier | Examples | Risk | Recommended controls |
|------|----------|------|-----------------------|
| First-party / built-in | Vendor-shipped components | Low (audited code) | Standard sandbox; full host-API as needed |
| Verified third-party | Plugins from approved vendors | Medium | Sandbox + signed images; restricted host-API |
| Customer-uploaded | End users upload arbitrary WASM | High | Sandbox + multi-tenancy + minimal host-API + per-tenant quotas |

Most architectures fail by treating all plugins as Tier 1 ("we audited them") even when end-users can ship Tier 3 code. Be explicit; document tier per plugin source; enforce tier-specific controls.

```yaml
# plugin-tier-policy.yaml
tiers:
  tier_1:
    sources: ["vendor-shipped", "internal-plugins-repo"]
    capabilities: [filesystem_read_assets, network_outbound_allowlist, prometheus_emit]
    resource_limits:
      memory: 512MB
      cpu_seconds_per_call: 5
      concurrent_calls: 100

  tier_2:
    sources: ["partners-allowlist"]
    capabilities: [filesystem_read_assets, network_outbound_allowlist]
    resource_limits:
      memory: 128MB
      cpu_seconds_per_call: 2
      concurrent_calls: 20

  tier_3:
    sources: ["customer-uploaded"]
    capabilities: [memory_only, log_emit]
    resource_limits:
      memory: 32MB
      cpu_seconds_per_call: 0.5
      concurrent_calls: 5
```

Per-tier capability set and resource cap. New plugin upload classifies by source.

### Decision 2: Host-API Surface

The host-API is the surface area where untrusted code makes requests of the host. Every host-API call is a security decision.

For each potential host-API function, ask:

- **What does the plugin learn from this call?** Sensitive data exposure surface.
- **What does the plugin influence by this call?** Authority granted.
- **Is this scoped to the plugin's own data?** Cross-tenant boundary.
- **Is this rate-limitable?** Resource-exhaustion surface.
- **Does this leave audit traces the plugin author cannot tamper with?** Forensic surface.

Classify host-API functions:

```yaml
host_api_classification:
  read_safe:
    - get_request_path        # plugin sees the request URL path
    - get_request_method      # plugin sees the HTTP method
  read_sensitive:
    - get_request_header      # plugin sees Authorization, Cookie
    - get_request_body        # plugin sees user-submitted data
  write_local:
    - set_response_header     # plugin modifies its own response
    - set_response_status     # plugin sets HTTP status
  write_global:
    - dispatch_http_call      # plugin makes outbound HTTP — high risk
    - shared_kv_set           # plugin writes to shared store
  audit_only:
    - log_emit                # plugin emits to host log
    - metric_increment        # plugin updates Prometheus counter
```

Restrict per-tier:

```python
# host_api_authorize.py
def authorize_host_call(plugin_tier: str, function: str) -> bool:
    if plugin_tier == "tier_1":
        return True   # full access
    if plugin_tier == "tier_2":
        return function not in ["dispatch_http_call_arbitrary"]
    if plugin_tier == "tier_3":
        return function in {
            "get_request_path",
            "set_response_header",
            "set_response_status",
            "log_emit",
            "metric_increment",
        }
    return False
```

The host evaluates every host-API call against this matrix. A Tier 3 plugin that attempts `dispatch_http_call` is denied at the boundary.

### Decision 3: Resource Quotas

Per-plugin resource caps prevent one plugin from affecting others. Multiple dimensions:

- **Memory:** linear-memory size cap per WASM instance.
- **CPU time:** wall-clock or fuel-based cap per call.
- **Call concurrency:** how many simultaneous invocations of this plugin.
- **Host-API call rate:** rate-limit specific host-API functions per plugin.
- **Storage:** if plugin can write to disk / KV, per-plugin quota.

```rust
// quota_check.rs
struct PluginQuota {
    memory_max: usize,
    cpu_seconds_per_window: f64,
    concurrent_calls_max: usize,
    host_api_calls_per_minute: HashMap<String, u32>,
}

fn admit_plugin_call(plugin_id: &str, current_state: &PluginState) -> Result<CallGuard, QuotaError> {
    if current_state.concurrent_calls >= state.quota.concurrent_calls_max {
        return Err(QuotaError::ConcurrencyLimit);
    }
    if current_state.cpu_used >= state.quota.cpu_seconds_per_window {
        return Err(QuotaError::CpuLimit);
    }
    Ok(CallGuard { plugin_id: plugin_id.into() })
}
```

Tier-bound quotas: Tier 3 plugins get tighter caps than Tier 1.

### Decision 4: Plugin-Plugin Isolation

If multiple plugins coexist in the host, they share the host's CPU and memory. They may also share host-managed state — a KV cache, a database connection pool, a configuration object.

```yaml
plugin_plugin_isolation:
  state:
    shared_kv: tier_specific   # tier_1 plugins share; tier_3 each has own KV namespace
    config_object: per_plugin   # config never shared
  resources:
    db_connection_pool: per_plugin   # plugin gets its own pool, not shared
    network_egress: per_plugin       # outbound network rate-limited per plugin
  audit:
    other_plugins_logs: never_visible   # plugin never sees another plugin's log entries
```

For Tier 3, default to per-plugin everything. Sharing is opt-in with explicit security review.

### Decision 5: Supply Chain

Where do plugins come from? How are they verified?

```yaml
supply_chain:
  tier_1:
    source: ghcr.io/myorg/internal-plugins/*
    signature: required (cosign keyless via GitHub Actions OIDC)
    sbom: required (CycloneDX)
    in_toto: required (SLSA L3+)
    verification_at: deploy_time

  tier_2:
    source: ghcr.io/partners-allowlist/*
    signature: required (cosign with vendor's public key)
    sbom: optional but logged
    verification_at: deploy_time

  tier_3:
    source: customer_upload
    signature: optional
    static_analysis: required (capability-surface audit, IoC scan, vulnerable-dep scan)
    sandbox_test: required (run in isolation, observe behavior, before promoting to active)
    verification_at: upload_time
```

Each tier has a defined supply-chain control. Customer-uploaded plugins pass static analysis and a sandbox-test phase before going live.

### Decision 6: Audit and Observability

Every plugin invocation must be auditable.

```
plugin_invocations_total{plugin_id, tier, outcome}
plugin_host_api_calls_total{plugin_id, function, allowed}
plugin_cpu_seconds_total{plugin_id}
plugin_memory_pages{plugin_id}
plugin_quota_rejected_total{plugin_id, reason}
plugin_egress_bytes_total{plugin_id, target}
plugin_supply_chain_violation_total{plugin_id, type}
```

Per-tier dashboards. Tier 3 has the strictest alerting:

- Any host-API denial (`allowed=false`) triggers alert.
- Egress to unexpected target — alert.
- CPU or memory consistently near cap — alert.

### Decision 7: Update / Rollback Flow

Plugins update over time. The flow needs to preserve isolation:

```
[New plugin version uploaded]
  -> [Static analysis on new version]
  -> [Verify signature / SBOM / SLSA]
  -> [Stage to canary tier (1% of traffic)]
  -> [Observe canary metrics for 30 minutes]
  -> [If healthy: promote to active]
  -> [If unhealthy: rollback to prior version]
```

Rollback must be automatic and immediate. A plugin update that crashes the host or causes spike in errors should never require manual intervention.

### Decision 8: Per-Plugin Threat Model Document

Capture the per-plugin decisions in a document:

```yaml
# plugin-threat-models/payments-helper.yaml
plugin_id: payments-helper
tier: tier_2
source: ghcr.io/payments-vendor/helper
host_api_capabilities:
  - get_request_path
  - get_request_header  (limited: only X-Tenant-Id)
  - set_response_header
  - log_emit
quotas:
  memory: 64MB
  cpu_seconds_per_call: 1
  concurrent_calls: 10
trust_decisions:
  - capability: "get_request_header (X-Tenant-Id only)"
    rationale: "Plugin needs to identify which tenant's logic to apply"
    risk: low
  - capability: "set_response_header"
    rationale: "Plugin sets a single internal header"
    risk: low
review:
  reviewed_by: security-team
  reviewed_at: 2026-04-29
  next_review: 2027-04-29
```

Standardize across plugins; review on changes.

### Decision 9: Failure-Mode Scenarios

For each plugin system, walk through the failure modes:

```yaml
failure_modes:
  plugin_crashes_during_request:
    impact: One request fails
    mitigation: Plugin sandbox traps; host returns appropriate error to user; metric incremented

  plugin_hits_cpu_quota:
    impact: Plugin trapped; one request fails
    mitigation: Quota mechanism; user gets timeout

  plugin_attempts_disallowed_host_call:
    impact: Single call rejected
    mitigation: Capability denial; log + alert

  plugin_supply_chain_compromise:
    impact: Plugin runs malicious code
    mitigation: Signature verification at upload; supply-chain attestation chain
    recovery: Revoke plugin; investigate; plugin tier may need to be tightened

  cross_plugin_state_leak:
    impact: One plugin reads another's data
    mitigation: Per-plugin namespace in shared state; no cross-plugin reads
    detection: State-store audit logs

  audit_pipeline_failure:
    impact: Plugin actions not recorded
    mitigation: Reliable audit pipeline; reject plugin invocation if audit can't be persisted
```

Each failure mode has a documented mitigation and recovery path.

## Expected Behaviour

| Signal | Without threat model | With threat model |
|--------|------------------------|-------------------|
| New plugin's host-API access | Whatever was convenient | Tier-bound by policy |
| Cross-plugin state visibility | Often unbounded | Per-plugin namespace |
| Resource exhaustion impact | One plugin can starve others | Bounded by quota |
| Plugin update flow | Manual; risk of regression | Automated canary + rollback |
| Audit completeness | Inconsistent | Per-call audit at host-API boundary |
| Trust-tier confusion | Common | Explicit; documented |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Trust-tier policy | Right-sized controls | Maintenance of tier definitions | Codify; review quarterly. |
| Capability matrix | Bounds host-API | Plugin authors lose flexibility | Document for plugin authors; provide first-class capability requests. |
| Per-plugin quotas | Bounded resource use | More state to track | Tracking is per-plugin; usually small compared to plugin count. |
| Plugin-plugin isolation | Strong tenant boundary | Some natural sharing patterns broken | Document sharing patterns explicitly; design APIs to make sharing intentional. |
| Supply-chain verification | Tamper detection | Build pipeline complexity | Standard now (cosign + SLSA + SBOM); reuse infrastructure. |
| Audit at host-API level | Forensic visibility | Logging volume | Sample for high-frequency calls; log every denial. |
| Per-plugin threat-model docs | Reviewable security posture | Maintenance | Tied to plugin lifecycle; new plugin = new document. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Tier creep (Tier 3 promoted to Tier 1 without review) | Customer plugins gain elevated access | Audit reveals capability mismatch | Block escalation in policy; require explicit security review for tier changes. |
| Capability allowed without review | Plugin gets a host-API it shouldn't | Audit at deploy time | CI check: capability set must match approved threat-model document. |
| Quota too narrow | Legitimate plugin throttled | Plugin author reports issues | Profile representative use; raise quota appropriately. |
| Supply chain bypass | Plugin uploaded without verification | Audit log shows unsigned plugin | Refuse load; redeploy after fixing pipeline. |
| Cross-plugin shared-state misuse | One plugin accesses another's data | Periodic audit + tracing | Migrate to per-plugin namespace; revoke shared access. |
| Audit pipeline outage causes silence | Plugin invocations not recorded | Metrics show invocation rate but no audit events | Fail-closed: refuse plugin invocation if audit can't be persisted. |
| Update flow rolls forward despite failure | Bad plugin version live | Error rates spike post-update | Auto-rollback policy must trigger on metrics regression; verify mechanism. |

## Related Articles

- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [WASM Multi-Tenancy Patterns](/articles/wasm/wasm-multi-tenancy/)
- [Envoy and Istio WASM Plugin Hardening](/articles/wasm/envoy-wasm-plugin-hardening/)
- [NGINX WASM Filters with ngx_wasm_module](/articles/wasm/nginx-wasm-filters/)
- [Threat Modeling at Scale](/articles/cross-cutting/threat-modeling-at-scale/)
