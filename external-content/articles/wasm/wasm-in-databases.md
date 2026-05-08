---
title: "WASM in Databases: pg_wasm, ClickHouse UDFs, SurrealDB Extensions"
description: "Databases are growing WASM extension points. The threat model spans both WASM-runtime escape and database-internal lateral access — different from container UDFs."
slug: "wasm-in-databases"
date: 2026-04-27
lastmod: 2026-04-27
category: "wasm"
tags: ["wasm", "postgres", "clickhouse", "surrealdb", "database-extensions"]
personas: ["dba", "platform-engineer", "security-engineer"]
article_number: 186
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/wasm/wasm-in-databases/index.html"
---

# WASM in Databases: pg_wasm, ClickHouse UDFs, SurrealDB Extensions

## Problem

Databases run user-supplied logic. Postgres has stored procedures (PL/pgSQL, PL/Python, PL/Perl, PL/Rust). ClickHouse has user-defined functions in C++ and Python. MySQL has stored procedures and UDFs. Each of these mechanisms has a long history of CVEs, supply-chain risk, and operational complexity.

By 2026, several databases offer WASM as a sandboxed alternative:

- **`pg_wasm` for Postgres** — Wasmtime embedded as a Postgres extension, letting users write functions in any language that compiles to WASM, executed in a sandbox inside the postgres backend process.
- **ClickHouse `executable_pool` + WASM dictionaries** — WASM-based dictionary functions and UDFs, executed inside the ClickHouse server.
- **SurrealDB `DEFINE FUNCTION` with WASM bodies** — first-class WASM functions in the database's own embedded runtime.
- **DuckDB extensions via `community-extensions`** — WASM as one extension distribution model.

The promise is real: WASM provides linear-memory isolation, capability-bound system access, and a uniform deployment artifact. The threat model differs from container UDFs in ways operators need to understand:

- **Function runs in the database backend process.** Memory and CPU come from the database's resource pool. A WASM function consuming the per-backend memory cap directly affects the database's ability to serve queries.
- **The "host" is the database, not Linux.** WASM imports map to database-internal APIs (read column values, allocate memory, return results). The capability surface is database-specific, not WASI-standard.
- **Function authority is database-level.** A WASM function called within a user's query session has the database's authority for that session — including any data the session can read.
- **Distribution is via SQL `CREATE FUNCTION` or registry pulls.** Supply-chain controls that work for container images do not directly apply.
- **Cold-start matters in OLTP.** A WASM function called per-row in a query needs to be compiled once and cached; per-call instantiation is too slow.

This article covers the production hardening for `pg_wasm` (the most-deployed pattern), with notes for ClickHouse and SurrealDB. Topics: extension installation safety, per-function resource limits, capability scoping, distribution and signing, and operational telemetry.

**Target systems:** Postgres 16+ with `pg_wasm` v0.4+ extension; ClickHouse 24.10+ with WASM UDF support; SurrealDB 2.0+ with `DEFINE FUNCTION` WASM support.

## Threat Model

- **Adversary 1 — Untrusted SQL author:** has `EXECUTE` on a WASM function uploaded by another user. Wants the function to do more than the user permitted.
- **Adversary 2 — Function uploader with malicious payload:** ships a WASM function that exploits a runtime CVE or abuses database imports.
- **Adversary 3 — Database admin uploading compromised package:** community WASM extension contains malicious logic.
- **Adversary 4 — Resource exhaustion in legitimate function:** a function with a memory leak or unbounded loop affects the entire database backend.
- **Access level:** Adversary 1 has `EXECUTE` SQL privileges. Adversary 2 has `CREATE FUNCTION`. Adversary 3 has superuser privileges or extension-install rights. Adversary 4 is any author.
- **Objective:** Read data outside the user's normal grants; cause database-level outages; pivot through the database's identity to other systems.
- **Blast radius:** Without hardening, a WASM function executes with the database's full process authority — read every table, write to filesystem (if extension grants the capability), pivot through the database's network identity. With hardening, the function is bounded to a per-call CPU/memory budget, no filesystem access, and only the column values explicitly passed as parameters.

## Configuration

### Step 1: Install pg_wasm Safely

`pg_wasm` is a Postgres extension. It loads a WASM runtime into the backend process. The extension itself is C code; review and pin the version:

```sql
-- Verify the extension version and origin.
SELECT extname, extversion, n.nspname
FROM pg_extension e
JOIN pg_namespace n ON e.extnamespace = n.oid
WHERE extname = 'pg_wasm';
-- pg_wasm | 0.4.2 | wasm

-- The extension binary must be installed via OS package or compiled from
-- a tagged release; never from `pg_wasm` HEAD on a production cluster.
```

Restrict who can create WASM functions:

```sql
-- Default: nobody can create WASM functions.
REVOKE CREATE ON SCHEMA wasm FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION wasm.create_function FROM PUBLIC;

-- Grant to a controlled role.
CREATE ROLE wasm_authors;
GRANT CREATE ON SCHEMA wasm TO wasm_authors;
GRANT EXECUTE ON FUNCTION wasm.create_function TO wasm_authors;

-- Apply to specific users.
GRANT wasm_authors TO platform_team;
```

### Step 2: Per-Function Resource Limits

Each WASM function declares its resource budget at creation time:

```sql
SELECT wasm.create_function(
    function_name := 'normalize_address',
    wasm_module   := pg_read_binary_file('/var/lib/postgresql/wasm/normalize.wasm'),
    arg_types     := ARRAY['text'],
    return_type   := 'text',
    -- Resource limits, enforced per call.
    config := '{
        "max_memory_bytes": 16777216,
        "fuel_per_call": 5000000,
        "epoch_deadline_ms": 100,
        "stack_size_bytes": 524288
    }'::jsonb
);
```

Operators can override at the cluster level:

```ini
# postgresql.conf
shared_preload_libraries = 'pg_wasm'

# Cluster-wide caps; per-function caps cannot exceed these.
pg_wasm.max_memory_bytes = 67108864      # 64 MiB ceiling
pg_wasm.max_fuel_per_call = 100000000    # 100M ops ceiling
pg_wasm.epoch_tick_ms = 50
pg_wasm.allow_fs = off                   # no filesystem capability
pg_wasm.allow_net = off                  # no network capability
pg_wasm.cache_dir = /var/cache/pg_wasm
pg_wasm.audit_log = on                   # audit every function call
```

A function declaring `max_memory_bytes: 1073741824` (1 GiB) is rejected if it exceeds the cluster cap.

### Step 3: WASI Capability Allowlist

By default, `pg_wasm` provides no WASI capabilities — only Postgres-specific imports for receiving arguments and returning values. Filesystem and network must be explicitly enabled:

```sql
-- Function with explicit capability declaration.
SELECT wasm.create_function(
    function_name := 'enrich_with_geoip',
    wasm_module   := ...,
    arg_types     := ARRAY['inet'],
    return_type   := 'jsonb',
    config := '{
        "max_memory_bytes": 16777216,
        "wasi": {
            "filesystem": {
                "preopen": [
                    {"host_path": "/var/lib/postgresql/geoip", "guest_path": "/data", "readonly": true}
                ]
            }
        }
    }'::jsonb
);
```

For functions that need network (rare; usually database functions should not make outbound calls), use a hard allowlist:

```sql
config := '{
    "wasi": {
        "sockets": {
            "allow_outbound_tcp": [
                {"host": "10.0.5.10", "port": 9200}
            ]
        }
    }
}'::jsonb
```

But: a function calling out to an external service is usually a sign of misplaced logic. Keep functions pure — pass them the data they need as arguments rather than letting them fetch.

### Step 4: SECURITY DEFINER vs SECURITY INVOKER

WASM functions follow the same Postgres semantics as PL functions:

- `SECURITY INVOKER` (default): function runs with the calling user's permissions.
- `SECURITY DEFINER`: function runs with the function-owner's permissions.

Use `SECURITY INVOKER` unless there is a specific reason otherwise. A `SECURITY DEFINER` WASM function can be exploited by callers to read data they do not have direct grants on.

```sql
SELECT wasm.create_function(
    function_name := 'normalize_phone',
    -- ...
    security := 'INVOKER'
);
```

### Step 5: Module Signing and Distribution

Distribute WASM functions via OCI registries with cosign signing (covered in [OCI WASM Module Signing and Verification](/articles/wasm/wasm-oci-signing/)). For database-specific deployment:

```bash
# Pull and verify in a separate step.
cosign verify ghcr.io/myorg/pg-wasm-functions/normalize:v1.2.3 \
  --certificate-identity 'https://github.com/myorg/.+/.github/workflows/build.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

oras pull ghcr.io/myorg/pg-wasm-functions/normalize:v1.2.3 \
  --output /var/lib/postgresql/wasm/

# Then create the function in SQL.
psql -c "SELECT wasm.create_function(..., wasm_module := pg_read_binary_file('/var/lib/postgresql/wasm/normalize.wasm'), ...)"
```

Maintain a manifest mapping function names to specific OCI digests:

```yaml
# /etc/postgresql/wasm-functions.yaml
- name: normalize_address
  ref: ghcr.io/myorg/pg-wasm-functions/normalize@sha256:abc123...
  schema: wasm
- name: enrich_with_geoip
  ref: ghcr.io/myorg/pg-wasm-functions/geoip@sha256:def456...
  schema: wasm
```

A reconciler periodically checks the deployed functions against the manifest; mismatches indicate either drift or compromise.

### Step 6: Audit Logging

Every WASM function call is auditable. Combine `pg_wasm`'s audit log with `pgaudit`:

```sql
-- Enable the audit log.
ALTER SYSTEM SET pg_wasm.audit_log = on;
ALTER SYSTEM SET pg_wasm.audit_log_args = on;     -- log argument values (privacy-sensitive!)
ALTER SYSTEM SET pg_wasm.audit_log_results = off; -- typically don't log results
SELECT pg_reload_conf();
```

Forward to a central log pipeline. Alert on:
- Functions failing with trap (`fuel_exhausted`, `epoch_deadline`, `oom`) at unusual rates.
- Calls from unexpected user roles to security-sensitive functions.
- New function registrations outside normal change windows.

### Step 7: ClickHouse and SurrealDB Specifics

**ClickHouse:**

```xml
<!-- /etc/clickhouse-server/config.d/wasm-udf.xml -->
<clickhouse>
    <user_defined_executable_functions_config>/etc/clickhouse-server/wasm-udfs.xml</user_defined_executable_functions_config>
    <wasm>
        <max_memory_bytes>16777216</max_memory_bytes>
        <max_execution_seconds>5</max_execution_seconds>
        <cache_dir>/var/lib/clickhouse/wasm-cache</cache_dir>
    </wasm>
</clickhouse>
```

ClickHouse's WASM UDFs run in a separate process pool by default (similar to executable_pool functions). This provides better isolation than in-process WASM but trades startup cost.

**SurrealDB:**

```surql
DEFINE FUNCTION fn::normalize_address($input: string) {
    -- Body executes in SurrealDB's embedded WASM runtime.
    LET $result = wasm::call('normalize.wasm', 'normalize', $input)
        WITH MAX_MEMORY = 16MB
        WITH MAX_DURATION = 100ms;
    RETURN $result;
};
```

SurrealDB's runtime is built on Wasmer; configure caps at the database level via `db_config.toml`.

## Expected Behaviour

| Signal | Without WASM hardening | With hardening |
|--------|------------------------|----------------|
| WASM function loops | Stalls the backend process indefinitely | Trapped by epoch deadline within configured ms |
| WASM function allocates 1 GiB | Backend grows; possible OOM kill | Trapped at memory cap |
| WASM function tries `open("/etc/passwd")` | Succeeds if WASI fs capability granted | EACCES (no preopens) |
| WASM function calls outbound HTTP | Succeeds if WASI sockets unrestricted | Refused unless allowlist matches |
| Audit log of function calls | None | Every invocation logged with user, function, duration, result |
| Function distribution | Manual SQL upload | OCI artifact, signed, manifest-tracked |

Verify:

```sql
-- Run a function and confirm bounds are enforced.
SELECT wasm.call('normalize_address', 'rubbish input that triggers infinite loop');
-- ERROR: WASM function trapped: epoch_deadline_exceeded

SELECT wasm.call('enrich_with_geoip', '/etc/passwd');
-- ERROR: WASM function trapped: capability_denied (filesystem path outside preopen)
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| In-process WASM | Low latency for per-row UDFs | Memory caps share the database's pool | Set per-function caps tightly; monitor backend RSS. |
| Per-call CPU and memory caps | Bounded resource use | Caps reject legitimate work if too tight | Profile representative workloads; size caps at 1.5x peak. |
| Default-deny WASI | Smallest attack surface | Functions that need I/O must explicitly request | Document the capability matrix per function role. |
| OCI distribution + signing | Same supply-chain controls as containers | Tooling integration with the database's deploy flow | Wrap the deploy in a script that verifies before `CREATE FUNCTION`. |
| Audit logging | Forensic visibility | Log volume grows with query load | Sample for high-volume functions; full log for security-sensitive functions. |
| `SECURITY INVOKER` default | Function runs as the caller; no privilege escalation | Functions that legitimately need elevated access must use `SECURITY DEFINER` carefully | Reserve `SECURITY DEFINER` for a small set of admin-reviewed functions. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Cluster-cap raised; function consumes too much memory | Backend OOM-kill | `dmesg` shows oom-kill on backend pid | Lower the cluster cap; tighter per-function caps; investigate the leaking function. |
| `SECURITY DEFINER` function exploited | Caller reads data they should not | pgaudit shows function called by unexpected role | Review the function's logic; rewrite to take parameters instead of querying. Switch to `SECURITY INVOKER` if possible. |
| WASM compilation cache poisoned | Function returns wrong results across backends | Inconsistent results from the same function across queries | Clear cache directory; confirm cache directory is exclusive per database cluster. |
| Function from compromised registry pulled | Malicious function deployed | Manifest reconciler detects digest mismatch | Drop the function; investigate via cosign signature audit. |
| pg_wasm extension version mismatch with module ABI | Functions fail to load after extension upgrade | Extension upgrade runtime errors | Pin extension version; recompile modules against the new ABI. |
| Resource exhaustion in shared backend | Other queries on the same backend slow down or fail | Backend memory metric near `work_mem` or backend total | Use connection pooling so a misbehaving query is bounded to one backend. Set `pg_wasm.max_memory_bytes` low enough that 100% utilization does not OOM. |

## When to Consider a Managed Alternative

Operating WASM-extension databases at scale requires extension lifecycle management, function distribution, audit pipelines, and capability review on every function (4-10 hours/month for a multi-team Postgres cluster).

- **[Neon](https://neon.tech/) and [Supabase](https://supabase.com/):** managed Postgres with WASM-extension support; capability constraints managed by the platform.
- **[ClickHouse Cloud](https://clickhouse.com/cloud):** managed UDF deployment with platform-side validation.
- **[SurrealDB Cloud](https://surrealdb.com/cloud):** managed function lifecycle with hardened defaults.

## Related Articles

- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [PostgreSQL Hardening](/articles/cross-cutting/postgresql-hardening/)
- [OCI WASM Module Signing and Verification](/articles/wasm/wasm-oci-signing/)
- [WASI Preview 2 Capability-Based Security](/articles/wasm/wasi-preview-2-capabilities/)
- [Wazero Hardening for Go Embedders](/articles/wasm/wazero-hardening/)
