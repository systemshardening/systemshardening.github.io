---
title: "WASM Module Caching Security: Protecting Precompiled Artefacts"
description: "Wasmtime's AOT precompilation and module caching dramatically reduce cold-start latency — but cached native code is a high-value attack target. This guide covers securing the Wasmtime cache directory, binding cached artefacts to source module hashes, detecting cache poisoning, and safe precompilation pipelines."
slug: wasm-module-caching-security
date: 2026-05-07
lastmod: 2026-05-07
category: wasm
tags:
  - wasm
  - module-caching
  - aot-compilation
  - supply-chain
  - runtime-security
personas:
  - security-engineer
  - platform-engineer
article_number: 587
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/wasm/wasm-module-caching-security/
---

# WASM Module Caching Security: Protecting Precompiled Artefacts

## Problem

Wasmtime's module cache is a transparent performance optimisation: the first time a `.wasm` file is loaded, Wasmtime compiles it to native code via the Cranelift backend, serialises the result, and writes it to a per-user cache directory on disk. Subsequent loads of the same module — identified by a cache key that incorporates the source module's content hash and the Wasmtime compiler version — skip the compilation step entirely and deserialise the cached native binary directly. For cold-start-sensitive environments this is not an optional convenience; the difference between a JIT-cold startup and a cache-hit startup can be measured in tens of milliseconds for large modules.

What Wasmtime's cache documentation covers in detail — key structure, cache invalidation, tuning parameters — it does not surface prominently is the security implication of what is actually stored. The cache directory contains compiled native machine code. Not WASM bytecode, which Wasmtime validates on every JIT load. Native code, which Wasmtime trusts unconditionally when deserialising from cache because the purpose of the cache is to skip revalidation. An attacker who can write a file to the Wasmtime cache directory can cause the runtime to load and execute arbitrary native code the next time a matching cache key is requested. There is no integrity check on cached content beyond the OS filesystem permissions protecting the directory.

This is a distinct problem from the AOT artifact supply chain attack documented in [WASM AOT Compilation Pipeline Security](/articles/wasm/wasm-aot-compilation-security/). That attack targets explicitly distributed `.cwasm` artifacts. The module cache attack targets the local compilation cache that Wasmtime manages automatically, often without the operator being aware it exists. On a shared build server, a container runtime where the cache directory is bind-mounted across tenant workloads, or a developer workstation where the cache directory is world-writable, the attack surface is real.

The same concern applies to browser-side V8 code caching, which serialises compiled JavaScript and WebAssembly bytecode to disk or to `IndexedDB` for reuse across page loads. The V8 code cache is less accessible to a local attacker than Wasmtime's filesystem cache, but in Electron applications and Node.js deployments that use V8's `vm.Script` compilation cache, the same principles apply: serialised bytecode is a higher-trust artifact than the source it was compiled from, and it needs to be protected accordingly.

AOT precompilation pipelines — where a CI job runs `wasmtime compile` to produce a `.cwasm` artifact ahead of deployment — create a third caching surface: the artifact store. A `.cwasm` file distributed via an OCI registry, an S3 bucket, or a GitHub Actions cache shares the same trust problem as the local module cache. Without signing, there is no way to distinguish a legitimate `.cwasm` compiled from a known-good source module from one that was produced by a backdoored compiler or substituted by an attacker with registry write access.

Target systems: Wasmtime 20+, V8 12+ (Node.js 20+, Electron 28+), Wasmtime's default `$HOME/.cache/wasmtime` module cache on Linux and macOS.

## Threat Model

**1. Direct cache directory poisoning.** An attacker with local write access to the Wasmtime cache directory — `$HOME/.cache/wasmtime` or the path set by `WASMTIME_CACHE_CONFIG` — overwrites or creates a cache entry for a module that the target process loads at startup. The cache entry is keyed by a hash of the source `.wasm` content and the Wasmtime compiler version, so the attacker must either know the expected key (trivial if the `.wasm` module is public) or poison the directory with entries for every plausible module. Because `Module::deserialize` skips WASM structural validation, the malicious native code executes with the full capability set of the WASI linker configuration used by the host process. This attack is equivalent to replacing a shared library in `LD_LIBRARY_PATH`: it is a straightforward privilege escalation for an attacker who already has local filesystem write.

**2. Shared cache directory in multi-tenant environments.** Container orchestration setups that mount a host-level Wasmtime cache directory into multiple tenant containers — to amortise compilation time across tenants — create a scenario where a write-capable tenant can poison the cache for other tenants. Even if filesystem permissions restrict each tenant to its own sub-directory, misconfigurations or path traversal bugs in the cache key derivation can cause cross-tenant cache reads. The attack is self-amplifying in this model: the most frequently used modules are the ones most likely to have cache entries, and therefore the most likely targets.

**3. Cache poisoning via compromised CI node.** An AOT compilation pipeline running on a CI node that has been compromised produces a `.cwasm` artifact compiled from the correct source `.wasm` but using a backdoored Wasmtime binary that injects shellcode into the output. The resulting file passes a content hash check on the source `.wasm` — the source was not modified — but carries attacker-controlled native code. If the CI pipeline then writes this artifact to a shared cache (GitHub Actions cache, a Bazel remote cache, an S3 artifact bucket) without signing it, every subsequent deployment that pulls from that cache loads the backdoor.

**4. Stale cache entries from a patched runtime.** A CVE is patched in Wasmtime that affects the Cranelift code generator: for example, a miscompilation that produces code violating sandbox memory bounds. The operator upgrades Wasmtime. Wasmtime's cache key includes the compiler version, so new compilations produce new cache entries under a new key. But the old entries — compiled by the vulnerable Cranelift — remain on disk and may be loaded if any part of the deployment path still references the old Wasmtime version. Without an explicit cache eviction step after runtime upgrades, the vulnerability window extends past the patch deployment date.

**5. V8 code cache substitution in Electron applications.** Electron applications that use V8's `vm.Script` or `vm.compileFunction` with explicit code caching write serialised bytecode to application data directories. On Windows and macOS these directories are often in user-writable locations with weak permissions. A malware payload with user-level write access can substitute the V8 code cache entry, causing the application to execute malicious bytecode on the next launch — a persistence mechanism that survives application reinstallation if the data directory is preserved.

## How Wasmtime's Module Cache Works

Wasmtime's module cache is controlled by a TOML configuration file. On Linux the default is `$HOME/.cache/wasmtime/config.toml`. The cache stores compiled native artifacts under `$HOME/.cache/wasmtime/modules/`. The on-disk format is Wasmtime's internal `.cwasm`-equivalent binary: native code for the host architecture serialised with Wasmtime's engine metadata.

The cache key is a hash of the source `.wasm` module content concatenated with a compiler fingerprint that includes the Wasmtime version and Cranelift code generation settings. This means:

- A change to the `.wasm` source produces a cache miss and triggers recompilation.
- A Wasmtime version upgrade produces a cache miss because the compiler fingerprint changes.
- Two instances of Wasmtime at the same version loading the same `.wasm` share a cache hit.

Critically, Wasmtime does **not** verify that the cached artifact's content matches any expected hash when deserialising on a cache hit. The filesystem metadata (key derivation) is the only lookup mechanism. If the file at the cache path has been modified, Wasmtime reads it as-is. This is by design for performance — the cache is a trusted local storage mechanism, not an untrusted artifact registry — but it means filesystem-level protection of the cache directory is the sole security control.

```toml
# Default Wasmtime cache configuration: $HOME/.cache/wasmtime/config.toml
[cache]
enabled = true

# Location of cached compiled artifacts
directory = "/home/app/.cache/wasmtime/modules"

# Maximum time a cache entry is retained; entries are evicted after this.
# Security default: set this short enough that stale entries from
# vulnerable runtime versions are automatically removed.
cleanup-interval = "1d"
files-total-size-soft-limit = "1Gi"
file-count-soft-limit = 256
```

## Securing the Cache Directory

The cache directory must be treated with the same access controls as the Wasmtime binary itself. The principle is straightforward: only the process identity that owns the cache should be able to write to it, and no other principal should be able to read it without explicit need.

```bash
# Set cache directory permissions: owned by the runtime user, no world access
CACHE_DIR="$HOME/.cache/wasmtime"
mkdir -p "${CACHE_DIR}"
chmod 700 "${CACHE_DIR}"
chown "$(id -u):$(id -g)" "${CACHE_DIR}"

# Verify: no world-readable or world-writable bits
stat -c "%a %U %G %n" "${CACHE_DIR}"
# Expected: 700 appuser appgroup /home/appuser/.cache/wasmtime
```

In containerised deployments, the cache directory should never be a shared bind mount across tenant boundaries. Use per-instance ephemeral volumes:

```yaml
# Kubernetes: per-pod emptyDir for the Wasmtime cache
# Do NOT use a hostPath or PVC shared across pods
volumes:
  - name: wasmtime-cache
    emptyDir:
      sizeLimit: 512Mi

containers:
  - name: wasm-runtime
    image: myapp:latest
    env:
      - name: WASMTIME_CACHE_CONFIG
        value: /tmp/wasmtime-cache/config.toml
    volumeMounts:
      - name: wasmtime-cache
        mountPath: /tmp/wasmtime-cache
    securityContext:
      runAsNonRoot: true
      runAsUser: 10001
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
```

For serverless or function-as-a-service deployments where cold-start latency is critical but trust boundaries between invocations are strict, disable the cache entirely and rely on AOT pre-compiled artifacts instead:

```bash
# Disable the module cache for untrusted or shared execution environments
WASMTIME_DISABLE_CACHE=1 your-wasm-host
```

Or in code:

```rust
use wasmtime::{Engine, Config};

let mut config = Config::new();
// Disable the automatic module cache for this engine.
// Use explicit Module::deserialize with a pre-verified .cwasm instead.
config.disable_cache();
let engine = Engine::new(&config)?;
```

## Cache Integrity Verification with HMAC

Since Wasmtime does not verify cached artifact integrity on read, applications that require stronger assurance can implement a sidecar integrity file: an HMAC of the cache artifact, keyed by a secret known only to the runtime process. The HMAC is stored alongside the cache entry and verified before `Module::deserialize` is called.

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fs;
use std::path::Path;

type HmacSha256 = Hmac<Sha256>;

/// Write a cache artifact alongside a keyed HMAC integrity file.
fn write_cache_with_hmac(
    artifact_path: &Path,
    artifact_bytes: &[u8],
    hmac_key: &[u8],
) -> anyhow::Result<()> {
    fs::write(artifact_path, artifact_bytes)?;

    let mut mac = HmacSha256::new_from_slice(hmac_key)
        .map_err(|e| anyhow::anyhow!("HMAC key error: {e}"))?;
    mac.update(artifact_bytes);
    let tag = mac.finalize().into_bytes();

    let hmac_path = artifact_path.with_extension("hmac");
    fs::write(&hmac_path, tag.as_slice())?;
    Ok(())
}

/// Verify a cache artifact's HMAC before deserialising.
/// Returns the artifact bytes on success, Err if verification fails.
fn read_cache_with_hmac_verify(
    artifact_path: &Path,
    hmac_key: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let artifact_bytes = fs::read(artifact_path)?;
    let hmac_path = artifact_path.with_extension("hmac");
    let stored_tag = fs::read(&hmac_path)?;

    let mut mac = HmacSha256::new_from_slice(hmac_key)
        .map_err(|e| anyhow::anyhow!("HMAC key error: {e}"))?;
    mac.update(&artifact_bytes);
    mac.verify_slice(&stored_tag)
        .map_err(|_| anyhow::anyhow!(
            "HMAC verification failed for cache artifact: {}",
            artifact_path.display()
        ))?;

    Ok(artifact_bytes)
}
```

The HMAC key should be generated at process startup and stored only in memory — not written to disk. This limits the protection to cache tampering that occurs between process restarts: a runtime process that computes an HMAC of the cache entry it writes will detect any out-of-process modification to that entry on its next startup. An attacker who can read the process memory can recover the key, so this is a defence-in-depth measure, not a cryptographic guarantee.

## AOT Precompilation Pipeline: Signing and Verification

For production deployments the recommended pattern is to disable Wasmtime's automatic module cache entirely and replace it with an explicit AOT precompilation pipeline that produces signed `.cwasm` artifacts:

```bash
# CI: compile WASM to .cwasm, bind the artifact to the source hash
SOURCE_HASH=$(sha256sum app.wasm | cut -d' ' -f1)

wasmtime compile \
  --cranelift-opt-level speed_and_size \
  --disable-cache \
  app.wasm \
  -o "app-${SOURCE_HASH}.cwasm"

# Embed the source hash in the artifact filename so load-time
# verification can confirm the artifact matches the expected source.
# Sign the artifact and the source hash binding together.
echo "source_hash=${SOURCE_HASH}" > artifact-metadata.txt
cosign sign-blob \
  --bundle "app-${SOURCE_HASH}.cwasm.bundle" \
  "app-${SOURCE_HASH}.cwasm"
```

At load time, verify both the source module hash and the artifact signature before deserialising:

```rust
use wasmtime::{Engine, Module};
use std::path::Path;
use std::process::Command;

/// Load a pre-compiled .cwasm artifact after verifying:
///   1. The source .wasm content hash matches what the artifact was compiled from.
///   2. The Cosign bundle signature over the .cwasm is valid.
///
/// This replaces Wasmtime's automatic module cache with an explicit,
/// auditable artifact chain.
fn load_signed_aot_module(
    engine: &Engine,
    source_wasm_path: &Path,
    cwasm_path: &Path,
    bundle_path: &Path,
    public_key: &Path,
    expected_source_hash: &str,
) -> anyhow::Result<Module> {
    // Step 1: verify the source module hash.
    let source_bytes = std::fs::read(source_wasm_path)?;
    let actual_hash = {
        use sha2::{Sha256, Digest};
        let digest = Sha256::digest(&source_bytes);
        hex::encode(digest)
    };
    if actual_hash != expected_source_hash {
        anyhow::bail!(
            "Source WASM hash mismatch: expected {expected_source_hash}, got {actual_hash}"
        );
    }

    // Step 2: verify the Cosign bundle over the .cwasm artifact.
    let status = Command::new("cosign")
        .args([
            "verify-blob",
            "--key", public_key.to_str().unwrap(),
            "--bundle", bundle_path.to_str().unwrap(),
            cwasm_path.to_str().unwrap(),
        ])
        .status()?;
    if !status.success() {
        anyhow::bail!(
            "Cosign verification failed for {}",
            cwasm_path.display()
        );
    }

    // SAFETY: signature verified above; artifact was produced by a
    // trusted wasmtime at a known version pinned in the signing pipeline.
    let module = unsafe { Module::deserialize_file(engine, cwasm_path)? };
    Ok(module)
}
```

## V8 Code Caching: Browser and Node.js

V8's code cache serialises compiled bytecode for JavaScript and WebAssembly. In a browser context the cache lives in the browser's profile directory and is managed by the browser process, which enforces process isolation. The attack surface there is limited. In Node.js and Electron the picture is different.

Node.js exposes V8's compilation cache through the `vm` module's `cachedData` option:

```javascript
// node-cache-integrity.js
const { createHash, createHmac } = require('crypto');
const vm = require('vm');
const fs = require('fs');
const path = require('path');

const CACHE_DIR = path.join(process.env.HOME, '.cache', 'myapp', 'v8');
const HMAC_SECRET = process.env.V8_CACHE_HMAC_SECRET; // inject at startup, not from disk

function hmacOf(buf) {
  return createHmac('sha256', HMAC_SECRET).update(buf).digest('hex');
}

function loadWithCache(sourceCode, cacheFile) {
  const hmacFile = cacheFile + '.hmac';

  let cachedData;
  if (fs.existsSync(cacheFile) && fs.existsSync(hmacFile)) {
    const raw = fs.readFileSync(cacheFile);
    const storedHmac = fs.readFileSync(hmacFile, 'utf8').trim();
    const actualHmac = hmacOf(raw);

    if (actualHmac !== storedHmac) {
      // Cache integrity check failed: log and fall through to fresh compilation.
      console.error(`[security] V8 cache HMAC mismatch for ${cacheFile} — discarding`);
      fs.unlinkSync(cacheFile);
      fs.unlinkSync(hmacFile);
    } else {
      cachedData = raw;
    }
  }

  const script = new vm.Script(sourceCode, {
    cachedData,
    produceCachedData: true,
  });

  if (script.cachedDataProduced) {
    // Write new or refreshed cache with HMAC.
    fs.mkdirSync(CACHE_DIR, { recursive: true, mode: 0o700 });
    fs.writeFileSync(cacheFile, script.cachedData, { mode: 0o600 });
    fs.writeFileSync(hmacFile, hmacOf(script.cachedData) + '\n', { mode: 0o600 });
  }

  return script;
}
```

The `mode: 0o600` on both the cache file and the HMAC file ensures they are readable only by the owning user. The HMAC secret injected via environment variable at startup ties the integrity check to process identity without requiring a persistent key file.

## Invalidating Stale Cache Entries

Wasmtime's automatic cache eviction is time-based: entries older than `cleanup-interval` are removed on the next cache cleanup pass. This is insufficient as a security control. The conditions that require immediate cache invalidation are:

- **Wasmtime runtime upgrade**: the new version's compiler fingerprint will produce new cache entries; old entries under the previous version's key are stale and should be removed to prevent any path from accidentally loading them. The cache key mismatch will prevent loading in most cases, but the stale files consume disk space and represent an unnecessary artifact.
- **CVE patch to Wasmtime's Cranelift backend**: a miscompilation CVE may mean that cached artifacts compiled by the vulnerable Cranelift need to be recompiled by the patched version. Force-evict the entire cache after installing the patched Wasmtime.
- **Source module change**: if a `.wasm` module is updated, the old cache entry is orphaned under the old source hash key. It will not be loaded (the key no longer matches) but it should be removed to prevent confusion and limit disk exposure.
- **Suspected compromise of the build environment**: if the CI node that compiled and cached artifacts is suspected to have been compromised, treat the entire artifact cache as untrusted and rebuild from source on a clean environment.

```bash
# Clear the Wasmtime module cache after a runtime upgrade or CVE patch
CACHE_DIR="${WASMTIME_CACHE_DIR:-$HOME/.cache/wasmtime/modules}"

echo "[security] Clearing Wasmtime module cache at ${CACHE_DIR}"
find "${CACHE_DIR}" -type f -name '*.bin' -delete
find "${CACHE_DIR}" -type f -name '*.cwasm' -delete

# Log the eviction for audit purposes
logger -t wasmtime-cache-evict \
  "Cleared ${CACHE_DIR} following runtime upgrade/CVE patch on $(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

Automate cache eviction as part of the Wasmtime upgrade procedure by adding it to the system's post-install hook or deployment runbook:

```yaml
# Ansible task: evict Wasmtime cache after package upgrade
- name: Evict Wasmtime module cache after upgrade
  file:
    path: "{{ wasmtime_cache_dir }}"
    state: absent
  become: true
  become_user: "{{ wasm_runtime_user }}"
  notify: restart wasm runtime service
```

## Detecting Cache Poisoning

Monitoring the cache directory for unexpected writes is the primary detection mechanism for cache poisoning attacks. On Linux, `inotifywait` can alert on any write to the cache directory that does not originate from the expected runtime process:

```bash
#!/usr/bin/env bash
# cache-monitor.sh: alert on unexpected writes to the Wasmtime cache directory

CACHE_DIR="${WASMTIME_CACHE_DIR:-$HOME/.cache/wasmtime/modules}"
RUNTIME_USER="wasmrunner"
ALERT_CMD="logger -t wasmtime-cache-alert -p auth.warning"

inotifywait -m -r -e create -e modify -e moved_to \
  --format '%T %e %w%f' --timefmt '%Y-%m-%dT%H:%M:%S' \
  "${CACHE_DIR}" 2>/dev/null | while read -r timestamp event filepath; do

  # Identify the writing process
  writing_pid=$(fuser "${filepath}" 2>/dev/null | tr -d ' ')
  writing_user=$(ps -o user= -p "${writing_pid}" 2>/dev/null)

  if [[ "${writing_user}" != "${RUNTIME_USER}" ]]; then
    ${ALERT_CMD} \
      "CACHE POISONING ALERT: unexpected write to ${filepath} by user=${writing_user} pid=${writing_pid} event=${event} at ${timestamp}"
  fi
done
```

For deployments using auditd, add a watch on the cache directory:

```bash
# /etc/audit/rules.d/wasmtime-cache.rules
# Alert on any write to the Wasmtime cache directory by a non-runtime user
-w /home/wasmrunner/.cache/wasmtime -p w -k wasmtime_cache_write
-w /home/wasmrunner/.cache/wasmtime -p a -k wasmtime_cache_write
```

Query the audit log:

```bash
ausearch -k wasmtime_cache_write --start today | \
  aureport --file --summary
```

In Kubernetes environments, Falco rules can detect unexpected writes to a mounted cache volume:

```yaml
# Falco rule: detect unexpected process writing to Wasmtime cache
- rule: Unexpected Write to Wasmtime Cache
  desc: A process other than wasmtime wrote to the module cache directory
  condition: >
    open_write
    and container
    and fd.name startswith "/tmp/wasmtime-cache"
    and not proc.name in (wasmtime, wasmtime-host)
  output: >
    Unexpected write to Wasmtime cache
    (user=%user.name proc=%proc.name pid=%proc.pid
     file=%fd.name container=%container.name)
  priority: WARNING
  tags: [wasm, supply-chain, cache-poisoning]
```

## Expected Behaviour

| Condition | Without Cache Hardening | With Hardening |
|---|---|---|
| Attacker writes to world-readable cache directory | Malicious native binary loaded on next module instantiation; no detection | `chmod 700` on cache directory blocks the write; runtime proceeds with recompilation |
| CI node compromised; backdoored `.cwasm` pushed to shared cache | All consumers load attacker-controlled native code; no artifact-level integrity check | Cosign bundle verification fails at load time; deployment blocked |
| Wasmtime CVE patched but old cache entries remain | Artifacts compiled by vulnerable Cranelift may be loaded if stale key paths exist | Post-upgrade cache eviction removes all stale entries; fresh compilation uses patched backend |
| Unexpected write to cache directory during runtime | Write goes undetected; poisoning active from next module load | inotifywait / auditd / Falco alert fires; incident response can intervene before next load |
| V8 code cache substituted in Electron app data directory | Malicious bytecode executes on application launch; no integrity check | HMAC verification detects modification; cache entry discarded, fresh compilation used |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Disabling Wasmtime automatic cache | Eliminates the cache poisoning attack surface entirely | Cold-start latency returns for every module load; unacceptable for latency-sensitive deployments | Replace with explicit signed AOT pipeline; cache only Cosign-verified `.cwasm` artifacts |
| HMAC on cache entries | Detects out-of-process tampering; defence-in-depth against filesystem-level attacks | HMAC key must be managed securely; if stored on disk it provides no additional protection | Generate key at process startup from a hardware-backed secret (TPM, KMS); store only in memory |
| Dedicated runtime user with `700` cache permissions | Prevents cross-user cache poisoning; limits blast radius of local privilege escalation | Requires per-user or per-service isolation; operational overhead in multi-tenant setups | Use Kubernetes per-pod `emptyDir` volumes; one cache per pod identity |
| inotifywait / auditd monitoring | Real-time detection of unexpected cache writes; feeds SIEM | Monitoring process itself must be trusted; inotifywait adds a small per-event syscall overhead | Run monitor as a separate high-privilege service; use auditd kernel-level hooks for tamper resistance |

## Related Articles

- [WASM AOT Compilation Pipeline Security](/articles/wasm/wasm-aot-compilation-security/)
- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [Reproducible WASM Builds](/articles/wasm/reproducible-wasm-builds/)
- [WASM JIT Security](/articles/wasm/wasm-jit-security/)
- [WASM OCI Signing](/articles/wasm/wasm-oci-signing/)
