---
title: "Running User-Provided WASM Safely: Sandboxing Untrusted Customer Code"
description: "SaaS platforms, plugin systems, and data pipelines that let users upload WASM modules need more than the default sandbox. This guide covers pre-execution validation, strict import allowlisting, per-tenant resource isolation, output validation, and multi-layer defence for user-provided WASM execution."
slug: user-provided-wasm-execution
date: 2026-05-07
lastmod: 2026-05-07
category: wasm
tags:
  - wasm
  - user-code-execution
  - sandboxing
  - multi-tenancy
  - platform-security
personas:
  - security-engineer
  - platform-engineer
article_number: 578
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/wasm/user-provided-wasm-execution/
---

# Running User-Provided WASM Safely: Sandboxing Untrusted Customer Code

## Problem

User-provided code execution is the hardest surface to secure on any platform. When a SaaS product lets customers upload and run their own logic — a data-pipeline transform, a game-mod script, a billing-rules plugin, a CI test runner — the platform accepts an adversarial artefact and executes it with real compute and real access to downstream systems.

WebAssembly is now the standard substrate for this pattern. Its linear-memory model, explicit import surface, and no-ambient-authority design make it far safer than native plugins or Docker containers for untrusted third-party code. But the sandbox is only as strong as its configuration. A default Wasmtime embedding with no resource limits and no import restrictions provides almost no additional protection over a bare function call. Making it safe requires deliberate design across six distinct layers.

The use cases driving this problem are concrete and widespread:

- **SaaS extensibility platforms** (think Shopify Functions, Figma plugins, Stripe rule engines) where merchants or developers upload business logic that runs inside the product.
- **Data pipelines** that allow users to supply transformation or filtering functions applied to their own data streams.
- **Game-modding platforms** where players upload WASM modules that execute inside the game engine or simulation loop.
- **Low-code/no-code builders** that generate or accept WASM-compiled logic attached to workflow nodes.

Each of these has the same threat surface: a module of unknown provenance executes on shared infrastructure, with some channel into your platform's internal services.

The specific failure modes in a default user-code embedding:

- **No CPU bound.** A malicious or infinite-looping module occupies a thread indefinitely. Even with async runtimes, enough such modules saturate the thread pool.
- **Unrestricted host import access.** If host functions for file I/O, outbound network, or internal API calls are linked into the module's linker without restriction, any user module can call them.
- **No memory ceiling.** A module requesting 2 GB of linear memory will get it if the host has it available, at the expense of every other tenant on the box.
- **No cross-tenant isolation.** Two tenants' modules may share an `Engine`, a compilation cache, or a host-side resource table. A compromise or misbehaviour in one module can affect the other.
- **Output passed downstream unchecked.** A module that returns crafted output exploiting downstream SQL parsers, template engines, or deserialisers becomes an injection vector even if it never escapes the WASM sandbox.

**Target systems:** Wasmtime 22+ embedded as a Rust library. The patterns apply directly to WasmEdge 0.14+ and wazero 1.7+ with equivalent APIs. Examples are in Rust; the Wasmtime C API and Python/Go bindings expose the same resource-limit hooks.

## Threat Model

User-supplied WASM introduces a distinct set of adversarial goals compared to trusted first-party code. Understanding them precisely is the prerequisite for choosing controls.

**Sandbox escape.** The most serious goal. A module that can break out of its linear-memory isolation and read or write host-process memory can exfiltrate secrets, overwrite control structures, and achieve arbitrary code execution on the host. WASM's memory model makes this hard by design — linear memory is fully isolated — but the sandbox is only the first barrier. Vulnerabilities in the JIT compiler, in the host-function boundary (type confusion, use-after-free in host-side memory passed to the module), or in the seccomp profile can open escape paths. Defense in depth is the response: the WASM sandbox is the primary layer; OS-level seccomp is the fallback.

**Denial of service.** A module with no CPU or memory cap can exhaust either until the worker process becomes unresponsive. DoS does not require a sandbox escape; it is effective at the application layer. An adversary with module-upload access who wants to damage your platform can upload a module containing `loop {}` and call it in a tight loop from multiple accounts. Resource limits per execution — fuel, epoch interrupts, memory ceiling — are the direct countermeasure.

**Data exfiltration via allowed channels.** This is the subtler threat. If a module has legitimate access to a KV store, a database query result, or a user's file list, it can encode that data in an allowed outbound channel — an HTTP request body, a log message, a numeric return value — and extract it to an attacker-controlled destination. The WASM sandbox does not prevent this; the module is using permitted APIs. The countermeasure is per-tenant allowlisting of outbound destinations, rate-limiting of outbound calls, and audit logging of every host function invocation.

**Covert channels.** Two tenant modules that cannot directly communicate may be able to use shared platform resources as a covert channel. Tenant A's module measures the latency of a KV `get` call; Tenant B's module writes and deletes keys rapidly to modulate that latency. This is a classical covert channel through a shared resource. Mitigations include per-tenant resource pools for sensitive backends, artificial response-time jitter, and rate limiting that prevents the high-frequency writes needed to sustain a covert channel.

**Output injection into downstream systems.** A module that cannot escape the sandbox may still attack downstream systems through its return values. If a module that processes user data returns a string, and that string is interpolated into a SQL query or rendered in an HTML template without escaping, the module has achieved SQL injection or XSS despite never touching the host filesystem or network. Output validation — schema checking, type enforcement, string sanitisation — is the control.

**Access level across all adversaries:** module-upload and module-invocation access via the normal customer API. They do not have host-process access, host-filesystem access, or cross-tenant memory access. Those are the properties the platform must enforce, not assume.

**Blast radius:** With a correctly hardened embedding, the blast radius of a compromised or malicious module is bounded to the offending tenant's single invocation. It traps on a resource limit, returns an error, and the next tenant's invocation is unaffected. Without hardening, a single module upload can take down the entire execution tier.

## Configuration

### Step 1: Pre-Execution Validation — Inspect the Module Before Accepting It

The earliest defensive layer runs before the module is persisted or ever executed. Static analysis of the WASM binary at upload time catches dangerous patterns before they become runtime risk. Two properties matter: structural validity and import surface.

```rust
// module_validator.rs
use wasmparser::{Parser, Payload, WasmFeatures};
use std::collections::HashSet;

/// Imports that are never permitted for user-supplied modules.
/// These names should never appear in user code; they are internal
/// host functions not exposed through the public linker. If a module
/// imports them, it was crafted specifically to probe the platform.
const FORBIDDEN_IMPORTS: &[(&str, &str)] = &[
    ("env", "__platform_internal_key"),
    ("env", "exec_command"),
    ("wasi_snapshot_preview1", "sock_accept"),
    ("wasi_snapshot_preview1", "sock_open"),
    ("wasi_snapshot_preview1", "path_open"),
    ("wasi_snapshot_preview1", "fd_write"),
];

pub fn validate_user_module(
    wasm: &[u8],
    allowed_imports: &AllowedImports,
) -> Result<(), ValidationError> {
    // Size gate first — fast, no parsing needed.
    // A 50 MiB WASM binary is unusual; 500 MiB is an attack.
    if wasm.len() > 50 * 1024 * 1024 {
        return Err(ValidationError::ModuleTooLarge(wasm.len()));
    }

    // Structural validity. wasmparser checks the binary format and
    // type-correctness of the module before we touch it further.
    let features = WasmFeatures {
        threads: false,         // Disallow shared memory; cross-instance comms vector.
        multi_memory: false,    // No multiple linear memories.
        memory64: false,        // 64-bit linear memory; rarely needed, broadens attack surface.
        relaxed_simd: false,    // Less-audited SIMD path.
        exceptions: false,      // Exception-handling proposal adds interface complexity.
        gc: false,              // GC; not yet stable for untrusted use.
        ..WasmFeatures::default()
    };
    let mut validator = wasmparser::Validator::new_with_features(features);
    validator
        .validate_all(wasm)
        .map_err(|e| ValidationError::MalformedModule(e.to_string()))?;

    // Import surface audit.
    // Every import the module declares must appear in the allowed set.
    // Any import not on the allowlist is an immediate reject.
    let mut declared_imports: Vec<(String, String)> = Vec::new();
    for payload in Parser::new(0).parse_all(wasm) {
        if let Ok(Payload::ImportSection(reader)) = payload {
            for import in reader {
                let imp = import
                    .map_err(|e| ValidationError::ParseError(e.to_string()))?;
                declared_imports.push((imp.module.to_string(), imp.name.to_string()));
            }
        }
    }

    for (module, name) in &declared_imports {
        // Hard-blocked: crafted probes for internal functions.
        if FORBIDDEN_IMPORTS.contains(&(module.as_str(), name.as_str())) {
            return Err(ValidationError::ForbiddenImport {
                module: module.clone(),
                name: name.clone(),
            });
        }
        // Not on the platform's public allowlist.
        if !allowed_imports.permits(module, name) {
            return Err(ValidationError::UnpermittedImport {
                module: module.clone(),
                name: name.clone(),
            });
        }
    }

    Ok(())
}
```

The `AllowedImports` value is not derived from the module itself — it is the platform's explicit list of functions that have been reviewed and approved for user code. Anything outside that list is rejected, regardless of whether it looks harmless.

Validation runs synchronously in the upload handler, before the module is stored. A module that fails validation is never persisted and never executed.

```rust
// upload_handler.rs
pub async fn handle_upload(
    tenant_id: TenantId,
    wasm_bytes: Bytes,
    allowed_imports: &AllowedImports,
) -> Result<ModuleId, UploadError> {
    // Validate before storing.
    validate_user_module(&wasm_bytes, allowed_imports)
        .map_err(UploadError::ValidationFailed)?;

    // Hash the validated bytes. The stored artefact is identified by content hash;
    // re-executing with the same hash is guaranteed to re-execute the validated bytes.
    let module_id = ModuleId::from_sha256(&wasm_bytes);
    store_module(tenant_id, module_id, &wasm_bytes).await?;

    // Pre-compile asynchronously. Subsequent executions load the .cwasm artifact;
    // they do not pay compilation cost on the request path.
    let engine = platform_engine();
    let bytes = wasm_bytes.clone();
    tokio::task::spawn_blocking(move || {
        let module = Module::new(&engine, &bytes)?;
        let cwasm = module.serialize()?;
        write_cwasm_artifact(tenant_id, module_id, &cwasm)
    })
    .await??;

    Ok(module_id)
}
```

### Step 2: Execution Isolation — One Store Per Execution, No Cross-Tenant State

Cross-tenant isolation starts at the Wasmtime object hierarchy. An `Engine` shares a JIT compilation cache across all `Module` and `Store` objects that use it. A `Store` holds per-execution state: linear memory, table entries, fuel accounting. The isolation properties follow from this hierarchy.

For the strongest cross-tenant isolation, give each tenant their own `Engine`. Their compiled code cache is separate; a malicious module cannot poison the cache of another tenant.

```rust
// tenant_runtime.rs
use wasmtime::{Config, Engine};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub struct TenantEngine {
    pub engine: Engine,
}

impl TenantEngine {
    pub fn new(tenant_id: &str) -> anyhow::Result<Self> {
        let mut config = Config::new();

        // CPU-limiting mechanisms — both enabled.
        config.consume_fuel(true);
        config.epoch_interruption(true);

        // Feature surface: disable everything not needed for user code.
        config.wasm_threads(false);
        config.wasm_multi_memory(false);
        config.wasm_memory64(false);
        config.wasm_relaxed_simd(false);
        config.wasm_exceptions(false);
        config.wasm_gc(false);
        config.wasm_reference_types(true);  // Safe; needed by component model.
        config.wasm_bulk_memory(true);      // Safe.
        config.wasm_simd(true);             // Standard SIMD; audited.

        // Per-tenant compilation cache. Tenant A's artifacts cannot
        // interfere with Tenant B's at the filesystem layer.
        let cache_toml = format!("/var/cache/wasm-platform/{tenant_id}/cache.toml");
        let _ = config.cache_config_load(&cache_toml);

        Ok(Self {
            engine: Engine::new(&config)?,
        })
    }
}

pub struct EnginePool {
    engines: RwLock<HashMap<String, Arc<TenantEngine>>>,
}

impl EnginePool {
    pub fn get_or_create(&self, tenant_id: &str) -> anyhow::Result<Arc<TenantEngine>> {
        if let Some(e) = self.engines.read().unwrap().get(tenant_id) {
            return Ok(e.clone());
        }
        let mut w = self.engines.write().unwrap();
        if let Some(e) = w.get(tenant_id) {
            return Ok(e.clone());
        }
        let te = Arc::new(TenantEngine::new(tenant_id)?);
        w.insert(tenant_id.to_string(), te.clone());
        Ok(te)
    }
}
```

Each execution creates a fresh `Store`. No per-execution state leaks across invocations — the store is dropped at the end of the call. This is the core principle: a `Store` is not a long-lived object that one tenant's module reuses. It is created immediately before the call and dropped immediately after. Any state that needs to persist between calls lives in the host, scoped to the tenant, and is accessed only through the approved host function surface.

### Step 3: Resource Limits — Fuel, Memory, Stack, and Tables

Every resource dimension needs a hard limit. A module that exhausts one limit should trap cleanly without affecting other executions.

```rust
// execution.rs
use wasmtime::{Store, ResourceLimiter, Module, Linker, Engine};

struct ExecutionLimits {
    max_memory_bytes: usize, // Linear memory ceiling.
    max_table_entries: u32,  // Function-pointer table ceiling.
    max_instances: usize,    // Nested instance count.
}

impl ResourceLimiter for ExecutionLimits {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _max: Option<usize>,
    ) -> anyhow::Result<bool> {
        Ok(desired <= self.max_memory_bytes)
    }

    fn table_growing(
        &mut self,
        _current: u32,
        desired: u32,
        _max: Option<u32>,
    ) -> anyhow::Result<bool> {
        Ok(desired <= self.max_table_entries)
    }

    fn instances(&self) -> usize { self.max_instances }
    fn tables(&self) -> usize { 4 }
    fn memories(&self) -> usize { 1 }
}

pub async fn execute_user_module(
    engine: &Engine,
    cwasm_path: &Path,
    linker: &Linker<HostState>,
    input: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let limits = ExecutionLimits {
        max_memory_bytes: 32 * 1024 * 1024, // 32 MiB — tune per workload tier.
        max_table_entries: 4096,
        max_instances: 1,
    };

    let mut store = Store::new(engine, HostState::new(limits));
    store.limiter(|s| &mut s.limits);

    // Fuel grant: platform-tier-specific.
    // 50M fuel units ≈ roughly 5–10 seconds of compute depending on workload.
    store.set_fuel(50_000_000)?;

    // Epoch deadline: 5 ticks. If the platform epoch thread fires every 50ms,
    // this caps wall-clock to ~250ms regardless of fuel.
    store.set_epoch_deadline(5);

    // Load the pre-compiled artifact — no JIT on the request path.
    let module = unsafe { Module::deserialize_file(engine, cwasm_path)? };

    let instance = linker.instantiate(&mut store, &module)?;

    let run = instance.get_typed_func::<(u32, u32), u32>(&mut store, "run")?;
    let output_ptr = run.call(&mut store, write_input(&mut store, input)?)?;

    Ok(read_output(&store, output_ptr))
}
```

The epoch-incrementing thread is started once per process, shared across all engines:

```rust
// main.rs — start once at process init.
fn start_epoch_ticker(engines: Vec<Engine>) {
    std::thread::Builder::new()
        .name("epoch-ticker".into())
        .spawn(move || loop {
            std::thread::sleep(Duration::from_millis(50));
            for engine in &engines {
                engine.increment_epoch();
            }
        })
        .expect("epoch ticker thread must start");
}
```

Using both fuel and epoch interrupts together is intentional. Fuel provides precise metering useful for billing and fair accounting; it counts every WASM operation. Epoch interrupts provide a wall-clock hard deadline that fires regardless of which operations the module is executing. A module that finds a way to consume fuel slowly — long pauses between operations, for instance — still hits the epoch deadline.

### Step 4: Restricted Import Surface — Only Approved Host APIs

The linker controls what host functions user code can call. Build the user-module linker from a fixed, audited set. Do not use `wasmtime_wasi::add_to_linker` — that grants the full WASI surface. Define each permitted function explicitly.

```rust
// host_functions.rs
use wasmtime::{Caller, Linker};

pub fn build_user_linker(
    engine: &Engine,
    tenant: &Tenant,
) -> anyhow::Result<Linker<HostState>> {
    let mut linker: Linker<HostState> = Linker::new(engine);

    // Logging: structured output only. No filesystem paths, no raw byte dumps.
    let tenant_id = tenant.id.clone();
    linker.func_wrap(
        "platform",
        "log",
        move |mut caller: Caller<'_, HostState>, msg_ptr: u32, msg_len: u32| {
            let msg = read_string_bounded(&caller, msg_ptr, msg_len, 2048)?;
            // Strip control characters before handing to logger.
            let msg = msg.chars().filter(|c| !c.is_control()).collect::<String>();
            caller.data_mut().audit_log.push(AuditEntry::ModuleLog {
                tenant: tenant_id.clone(),
                message: msg,
            });
            Ok(())
        },
    )?;

    // KV store: tenant-scoped. The tenant prefix is injected by the host;
    // the module cannot address another tenant's keys.
    let tenant_prefix = format!("tenant/{}/", tenant.id);
    linker.func_wrap(
        "platform",
        "kv_get",
        move |mut caller: Caller<'_, HostState>,
              key_ptr: u32,
              key_len: u32,
              out_ptr: u32| {
            let key = read_string_bounded(&caller, key_ptr, key_len, 256)?;
            let scoped_key = format!("{tenant_prefix}{key}");
            let value = caller.data_mut().kv.get(&scoped_key)?;
            write_bytes(&mut caller, out_ptr, &value)
        },
    )?;

    // What is NOT linked:
    // - Any filesystem access (path_open, fd_read, fd_write).
    // - Any WASI socket or network primitives.
    // - Any process-control (proc_exit).
    // - Any random source beyond approved get_random.
    // - Any internal platform API not on the public surface.

    Ok(linker)
}
```

The key discipline is maintaining the allowlist as a positive list, not a blocklist. Every function that is linked is there because it was explicitly reviewed and approved. No function is linked by default. Adding a new host function requires a code review that assesses what module authors can do with it and whether the access it grants is proportionate to the use case.

### Step 5: Network Isolation — No Outbound Connections Unless Explicitly Granted

User modules get no network access unless explicitly granted per-tenant through a platform configuration knob — not through WASI sockets, not through host functions. This is a default-deny policy enforced by the linker: if `wasi:sockets` is not linked and no HTTP host function is registered, the module has no network path regardless of what it declares in its imports.

For tenants on tiers that legitimately need outbound HTTP, the host function enforces an allowlist that is stored in the platform database — not derived from the module:

```rust
// Wire this in only for tenants whose tier includes outbound HTTP.
// Tenants on the base tier get no http_fetch function at all.
if tenant.tier.allows_outbound_http() {
    let allowed_hosts: Arc<HashSet<String>> = tenant.allowed_hosts.clone();
    linker.func_wrap(
        "platform",
        "http_fetch",
        move |mut caller: Caller<'_, HostState>,
              url_ptr: u32,
              url_len: u32,
              body_ptr: u32,
              body_len: u32,
              out_ptr: u32| {
            let url = read_string_bounded(&caller, url_ptr, url_len, 2048)?;
            let parsed = url::Url::parse(&url)
                .map_err(|_| anyhow::anyhow!("invalid URL"))?;

            // Must be HTTPS — no plaintext exfiltration paths.
            if parsed.scheme() != "https" {
                return Err(anyhow::anyhow!("only https allowed"));
            }
            // Host must be on the per-tenant allowlist.
            let host = parsed.host_str().unwrap_or("");
            if !allowed_hosts.contains(host) {
                caller
                    .data_mut()
                    .metrics
                    .blocked_network_attempt(host);
                return Err(anyhow::anyhow!("host not permitted: {host}"));
            }

            let body = read_bytes_bounded(&caller, body_ptr, body_len, 64 * 1024)?;
            let response = caller
                .data()
                .http_client
                .post(&url)
                .body(body)
                .send()?;
            write_bytes(&mut caller, out_ptr, &response.bytes()?)
        },
    )?;
}
```

Network isolation is absolute for tenants on the base tier. For tenants with `allows_outbound_http`, the allowed hosts list is reviewed at tier-upgrade time and stored in the platform database, not in the module itself. A module cannot expand its own outbound allowlist by returning a different value; the list is immutable from the module's perspective.

### Step 6: Output Validation Before Downstream Use

WASM modules that return crafted output can attack downstream systems even if they never escape the sandbox. Validate every output before passing it to any downstream consumer.

```rust
// output_validation.rs
pub fn validate_module_output(
    output: &[u8],
    expected_schema: &OutputSchema,
) -> Result<ValidatedOutput, OutputError> {
    // Size check — before any deserialization.
    if output.len() > expected_schema.max_output_bytes {
        return Err(OutputError::TooLarge(output.len()));
    }

    // Parse against the declared schema. User modules produce JSON or a
    // platform-specific binary format. Reject anything that does not
    // parse cleanly.
    let value: serde_json::Value = serde_json::from_slice(output)
        .map_err(|e| OutputError::InvalidJson(e.to_string()))?;

    // Schema validation — required fields, type constraints, value ranges.
    expected_schema
        .validate(&value)
        .map_err(OutputError::SchemaMismatch)?;

    // Sanitise string fields before downstream use.
    // The downstream system (template renderer, SQL builder, etc.) must
    // apply its own escaping; the platform applies a second pass here.
    let sanitised = sanitise_string_fields(&value);

    Ok(ValidatedOutput(sanitised))
}
```

Output validation is not optional. The validated output type is distinct from raw bytes; downstream functions only accept `ValidatedOutput`, not `&[u8]`. This makes it a compile-time error to pass unvalidated module output to a downstream consumer. The schema is versioned alongside the module API: when a module author changes the shape of what they return, they update the declared schema and the platform re-validates.

### Step 7: Multi-Layer Isolation — WASM Sandbox Plus OS seccomp

The WASM sandbox is a software boundary. Defence in depth requires an OS-level boundary underneath it. If a Wasmtime bug allows a module to escape linear-memory isolation — a JIT compiler vulnerability, a host-function boundary confusion — the seccomp profile is the next barrier. It cannot fix the escape, but it prevents the module from using that escape to do anything useful.

Wrap the module execution worker process in a seccomp-BPF profile that allows only the syscalls Wasmtime itself needs:

```yaml
# seccomp-profile.yaml — used via libseccomp or Kubernetes seccomp support.
# Derived from a Wasmtime execution baseline using strace/seccomp-tools.
defaultAction: SCMP_ACT_KILL_PROCESS
architectures:
  - SCMP_ARCH_X86_64
  - SCMP_ARCH_AARCH64
syscalls:
  - names:
      [ read, write, mmap, mprotect, munmap, brk, clone3,
        futex, nanosleep, clock_gettime, gettid, getpid,
        epoll_wait, epoll_ctl, eventfd2, close, openat,
        fstat, newfstatat, getrandom, rt_sigaction,
        rt_sigprocmask, exit_group, tgkill, sigaltstack ]
    action: SCMP_ACT_ALLOW
  # Wasmtime JIT requires mmap with PROT_EXEC for compiled code.
  # Restrict: MAP_ANONYMOUS only, not file-backed mappings.
  - names: [mmap]
    action: SCMP_ACT_ALLOW
    args:
      - index: 3
        value: 34        # MAP_ANON | MAP_PRIVATE
        op: SCMP_CMP_EQ
```

If the Wasmtime runtime ever executes a path that tries to call `execve`, `socket`, `connect`, or `open` with a real filesystem path, the kernel kills the process immediately. The module's WASM trap is already contained by Wasmtime; the seccomp profile contains any bug in Wasmtime itself.

On Kubernetes, attach the seccomp profile to the Pod spec:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: user-wasm-worker
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/wasm-worker.json
  containers:
    - name: worker
      image: registry.internal/wasm-worker:1.0.0
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        runAsUser: 10001
        capabilities:
          drop: [ALL]
```

The container's root filesystem is read-only, no capabilities are granted, and privilege escalation is denied. The seccomp profile is applied at the pod level. The combination means that a module which somehow escapes the WASM sandbox is still constrained to the kernel API surface that Wasmtime needs for normal operation — network, filesystem, and process-creation calls are all blocked.

### Step 8: Audit Logging Per Execution

Every module execution generates an audit record. Security incidents involving user-provided code are impossible to investigate without an immutable, per-execution log. At minimum, record: which tenant, which module (by content hash), when, how much CPU and memory was consumed, whether a trap occurred and why, and which host functions were called.

```rust
// audit.rs
#[derive(Serialize)]
pub struct ExecutionAuditRecord {
    pub execution_id: Uuid,
    pub tenant_id: String,
    pub module_id: String,        // Identifier from the platform's module registry.
    pub module_hash: String,      // SHA-256 of the WASM bytes; ties the record to exact bytes.
    pub invoked_at: DateTime<Utc>,
    pub wall_clock_ms: u64,
    pub fuel_consumed: u64,
    pub fuel_budget: u64,
    pub memory_peak_bytes: usize,
    pub trap_kind: Option<String>, // None = clean exit; "fuel_exhausted", "epoch_deadline", etc.
    pub output_bytes: usize,
    pub output_validation_status: ValidationStatus,
    pub blocked_network_attempts: Vec<String>,
    pub host_function_calls: Vec<HostFunctionCall>,
}

pub async fn emit_audit(record: ExecutionAuditRecord) {
    // Write to the append-only audit log. The audit store is separate from
    // the operational database; it uses a WORM policy and is not accessible
    // from user-module execution workers.
    AUDIT_SINK.emit(serde_json::to_string(&record).unwrap()).await;

    // Emit metrics for real-time alerting.
    metrics::counter!(
        "user_wasm_executions_total",
        "tenant" => record.tenant_id.clone(),
        "trap_kind" => record.trap_kind.clone().unwrap_or_default(),
    )
    .increment(1);
    metrics::histogram!(
        "user_wasm_fuel_consumed",
        "tenant" => record.tenant_id,
    )
    .record(record.fuel_consumed as f64);
}
```

Key metrics for operational alerting:

```
user_wasm_executions_total{tenant, trap_kind}           counter
user_wasm_fuel_consumed{tenant}                         histogram
user_wasm_memory_peak_bytes{tenant}                     histogram
user_wasm_execution_wall_ms{tenant}                     histogram
user_wasm_blocked_network_attempts_total{tenant, host}  counter
user_wasm_validation_rejected_total{tenant, reason}     counter
user_wasm_output_validation_failed_total{tenant}        counter
```

Alert thresholds:

- `user_wasm_executions_total{trap_kind="fuel_exhausted"}` spiking for a tenant — the module is hitting its CPU budget on every call; investigate for intentional DoS or runaway logic.
- `user_wasm_blocked_network_attempts_total` non-zero — a module attempted an outbound connection to a host not on the allowlist; treat as a probable exfiltration attempt and review the module.
- `user_wasm_validation_rejected_total` non-zero — a module upload was rejected at the import-surface stage; review the rejected import list.
- `user_wasm_output_validation_failed_total` non-zero — a module produced output that failed schema validation; the module may be attempting output injection.

## Expected Behaviour

| Signal | Unprotected embedding | Hardened embedding |
|---|---|---|
| Module with `loop {}` | Worker thread hangs indefinitely | Epoch deadline fires within ~250ms; execution traps; next request proceeds normally |
| Module requests 2 GB memory | Allocates; worker OOMs | `memory_growing` returns `false`; module traps with `MemoryGrowError` |
| Module imports `platform.exec_command` | Executes if linked | Pre-execution validation rejects at upload; module never stored |
| Module imports a host function not on allowlist | Available if carelessly linked | Validation rejects at upload; linker does not expose it regardless |
| Tenant A module reads Tenant B data via KV | Possible if KV is unscoped | KV host function injects tenant prefix; Tenant A cannot address Tenant B's key namespace |
| Module attempts outbound TCP to exfiltrate | Succeeds via WASI sockets | WASI sockets not linked; seccomp kills any `socket(2)` call that reaches the kernel |
| Module returns SQL injection payload in output | Injected downstream | Output validation schema-checks and sanitises all string fields before downstream use |
| Module triggers JIT compilation pause on execution | All concurrent requests pause | Module pre-compiled at upload time; execution loads `.cwasm` with no JIT pause |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Per-tenant Engine | JIT cache isolation between tenants | ~10–50 MiB engine overhead per tenant | Use per-tenant engines for paid/production tiers; share an engine for free/eval tiers with extra runtime monitoring |
| Pre-execution import validation | Catches dangerous modules before execution | Adds ~50–200ms to the upload path | Run validation asynchronously after a fast size check; defer full parse to async worker |
| Explicit linker (no `add_to_linker`) | Minimum attack surface; no accidental WASI exposure | More code to maintain; each new API must be wired explicitly | Use a host-function registry pattern; unit-test each host function's access control independently |
| Output schema validation | Stops injection attacks on downstream systems | Schema maintenance overhead | Version the output schema alongside the module API; store the expected schema hash with each module version |
| seccomp profile | OS-level defence in depth; contains Wasmtime bugs | Profile maintenance as Wasmtime's syscall profile changes across versions | Build the profile from a baseline audit on each major Wasmtime upgrade; test with `seccomp-tools trace` |
| Fuel + epoch (both) | Fuel provides metering; epoch provides wall-clock hard deadline | Fuel adds ~5–15% per-operation overhead | For latency-critical workloads, use epoch-only with a tight tick interval; reserve fuel for billing-grade accounting |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Epoch ticker thread dies | Modules run past their deadline; `trap_kind` metric stops recording `epoch_deadline` | `user_wasm_executions_total{trap_kind="epoch_deadline"}` drops to zero while module count stays nonzero | Supervise the epoch thread with a watchdog; restart the worker process if the ticker is not observed within 2 ticks |
| Import allowlist too permissive | A newly-added host function exposes capability user modules should not have | Security review of linker registration code; `blocked_network_attempts` is silent because the call is allowed | Review the linker build function on every PR touching host functions; require a security review annotation |
| seccomp profile missing after Wasmtime upgrade | Wasmtime uses a new syscall; worker process killed on legitimate execution | Execution failure rate spikes; `SIGKILL` in process logs | Run the seccomp trace audit on new Wasmtime versions in staging before promoting |
| Output schema not updated with module API | Legitimate module output fails validation after a module update | `user_wasm_output_validation_failed_total` rises; customer reports failures | Version the schema alongside the module; deploy both together; roll back the module if schema cannot be updated |
| Covert channel via timing | Two tenants' modules exchange information through latency of shared KV or HTTP backends | Difficult to detect without statistical analysis of call timing across tenants | Rate-limit all host function calls per tenant; add jitter to host function response times; use separate host-function pools per tenant for high-security deployments |
| Cache directory permissions misconfigured | Tenant A's compiled `.cwasm` artifact is readable by Tenant B's worker | File permission audit reveals world-readable cache paths | Own each tenant's cache directory with a per-tenant UID; enforce mode `0700` on the directory |
| Pre-compilation fails silently | Module upload succeeds but execution always falls back to JIT; compilation pauses spike latency | p99 latency anomaly on first execution per module version | Alert on pre-compilation failures at upload time; surface the error to the platform operator |

## Managed Alternatives

Building this stack in-house requires sustained investment: host-function auditing, seccomp maintenance, quota infrastructure, output validation schemas, and ongoing Wasmtime version tracking. The managed alternatives shift that burden to the provider:

- **[Cloudflare Workers](https://workers.cloudflare.com/):** isolate-per-request, managed multi-tenant WASM platform; Cloudflare maintains the seccomp and isolation stack.
- **[Fastly Compute](https://www.fastly.com/products/edge-compute):** Wasmtime-based with platform-managed resource limits; suitable for pipeline and edge-logic use cases.
- **[Fermyon Cloud](https://www.fermyon.com/cloud):** Spin-based managed hosting; handles multi-tenant isolation for plugin-style workloads.

Build in-house when your use case has compliance or data-residency requirements that preclude managed hosting, when you need custom host functions not available on managed platforms, or when you need per-tenant billing at granular fuel resolution.

## Related Articles

- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [WASM Multi-Tenancy Patterns](/articles/wasm/wasm-multi-tenancy/)
- [WASM Module Static Analysis and Vulnerability Scanning](/articles/wasm/wasm-static-analysis/)
- [Extism Plugin Security](/articles/wasm/extism-plugin-security/)
- [WASI Preview 2 Capability-Based Security](/articles/wasm/wasi-preview-2-capabilities/)
- [WASM Plugin Threat Modeling](/articles/wasm/wasm-plugin-threat-modeling/)
