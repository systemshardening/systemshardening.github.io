---
title: "Wasmtime aarch64 Sandbox Escape: CVE-2026-34971 and Cranelift Compiler Security"
description: "CVE-2026-34971 allows WASM guest code to read/write arbitrary host memory on aarch64 via a Cranelift code generation bug. Affects AWS Graviton, Apple M-series, and ARM edge devices. Patch to Wasmtime 43.0.1+, audit aarch64 deployments, and harden against compiler-level sandbox escapes."
slug: wasmtime-aarch64-sandbox-escape
date: 2026-05-04
lastmod: 2026-05-04
category: wasm
tags:
  - wasmtime
  - sandbox-escape
  - cranelift
  - aarch64
  - cve
personas:
  - platform-engineer
  - security-engineer
article_number: 438
difficulty: Advanced
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/wasm/wasmtime-aarch64-sandbox-escape/
---

# Wasmtime aarch64 Sandbox Escape: CVE-2026-34971 and Cranelift Compiler Security

## The Problem

CVE-2026-34971 breaks Wasmtime's core security guarantee: that WASM guest code can only access memory within its own linear memory region, and that all accesses outside that region trap cleanly. On aarch64 hosts, a Cranelift JIT compiler code generation bug for heap access instructions causes certain memory loads and stores to target incorrect addresses in host memory, silently bypassing the sandbox boundary entirely.

The mechanism is specific to aarch64 machine code emission. When Cranelift generates native instructions for heap accesses that use large offsets near the end of the addressable heap range, it miscalculates the base register value. The resulting aarch64 load or store instruction operates on an address outside the WASM linear memory mapping. There is no bounds check failure, no trap, and no signal to the host — the access completes successfully against arbitrary host process memory. An attacker who controls the WASM binary can craft a module that uses this pattern to read any region of the host process's virtual address space, or write to it.

The practical consequences are severe. A module exploiting the read path can extract API keys, private keys, session tokens, TLS certificates, or any other secret held in the host process at the moment of execution. A module exploiting the write path can corrupt host application state, overwrite function pointers in the host's data segment, or redirect control flow — which on some architectures and configurations amounts to remote code execution from inside a supposedly sandboxed WASM module. This is a complete sandbox escape.

The vulnerability is aarch64-specific. The same heap access patterns on x86_64 produce correct machine code. x86_64 deployments are not affected by CVE-2026-34971. This specificity is what makes the bug particularly dangerous in practice: x86_64-focused testing environments do not catch it, and teams that develop on Intel hardware and deploy to ARM — a common pattern with Apple Silicon developer machines and Graviton production fleets — may have no signal that their production environment is vulnerable.

The same advisory batch includes two related vulnerabilities. CVE-2026-34945 affects 64-bit WASM table operations: specific table initialisation sequences on 64-bit WASM tables can expose host data that has not been cleared from the table's backing memory. This is a confidentiality issue rather than an arbitrary write, but it provides an attacker with a side channel for reading host-controlled memory without triggering the Cranelift code generation bug. CVE-2026-34941 is an out-of-bounds read in the component model's string transcoding path, triggered when a guest component passes a carefully sized string through an interface that transcodes between UTF-8 and UTF-16. It can expose a small window of adjacent host memory and, under specific memory layouts, may crash the host process.

Compiler-level sandbox escapes are the hardest class of WASM vulnerability to detect and mitigate through application-layer controls. The escape happens at the machine code level, before the WASM linear memory bounds check, before any WASI capability check, and before any host-side import filter has an opportunity to observe or block the access. A host that carefully validates all guest imports, restricts WASI capabilities to a minimal set, and uses Wasmtime's resource limit APIs is still fully exposed to CVE-2026-34971 — the vulnerability operates beneath all of those mechanisms. The only reliable mitigations are patching the compiler to produce correct code, and architectural controls that limit what an escaping guest can reach.

Affected versions: all Wasmtime releases before 24.0.7 on the 24.x track, before 36.0.7 on the 36.x track, before 42.0.2 on the 42.x track, and before 43.0.1 on the 43.x track, when running on aarch64 hardware.

## Threat Model

**Multi-tenant WASM execution.** Serverless platforms, edge compute runtimes, and plugin systems that run untrusted WASM from multiple tenants in a shared host process are the highest-risk scenario. A module supplied by one tenant exploits the heap access pattern to read linear memory belonging to other tenants, or reads host-managed secrets shared across tenant boundaries. The attacker needs only to submit a valid WASM binary to the platform. On a multi-tenant system where tenants submit arbitrary WASM modules, this is an inherent capability that cannot be revoked without removing the service's core function.

**Attacker-supplied WASM to a service endpoint.** Any service that accepts WASM binary input from external users and executes it with Wasmtime is directly exposed. WASM compilation pipelines, sandbox-based code execution services, contract execution environments, and WASM-based scripting APIs all fall into this category. The attacker does not need a pre-existing foothold in the host environment. Submitting a crafted WASM module is sufficient to read host process memory.

**Malicious WASM plugin.** Plugin systems that load third-party WASM extensions into a Wasmtime host process at runtime are exposed if a plugin is compromised or malicious. A plugin using the escape reads the host application's memory directly: API credentials used by the host application, session tokens held in host data structures, private keys loaded into host memory for cryptographic operations. This bypasses all plugin sandboxing controls that operate above the compiler layer.

**All aarch64 deployments.** Affected hardware includes AWS Graviton EC2 instances (`m7g`, `c7g`, `r7g`, `t4g`, `x2gd`, and related families), Apple M-series systems (M1, M2, M3, M4 and all variants), Raspberry Pi 5 and other ARMv8-A single-board computers running Wasmtime, and ARM-based edge compute platforms. Any Wasmtime process compiled for `aarch64-unknown-linux-gnu`, `aarch64-apple-darwin`, or related aarch64 targets and running on vulnerable Wasmtime versions is affected regardless of the host OS.

## Hardening Configuration

### 1. Patch Wasmtime Immediately

Patching is the only complete remediation for CVE-2026-34971. The fixed Cranelift aarch64 backend produces correct base register values for the heap access patterns that triggered the bug. No configuration option or application-layer control can prevent a compiler-level sandbox escape on unpatched Wasmtime.

Identify the current Wasmtime version in your dependency tree:

```bash
cargo tree -i wasmtime | head -10
```

Update `Cargo.toml` to a fixed release on your current track:

```toml
[dependencies]
wasmtime = "43.0.1"
wasmtime-wasi = "43.0.1"
```

For projects pinned to earlier tracks:

```toml
wasmtime = "42.0.2"
```

```toml
wasmtime = "36.0.7"
```

```toml
wasmtime = "24.0.7"
```

After updating `Cargo.toml`, resolve the lock file and verify the new version is selected:

```bash
cargo update -p wasmtime
cargo tree -i wasmtime | head -5
```

The output must show the patched version. If it shows an older version, another dependency in the tree has a conflicting constraint. Identify it:

```bash
cargo tree -i wasmtime --edges features
```

Resolve the constraint conflict before treating the system as patched. A common source is a dependency on a Wasmtime ecosystem crate (`wasmtime-wasi`, `wasmtime-component-macro`, `wiggle`) that pins a specific Wasmtime version range incompatible with the patched release.

Rebuild the host binary and redeploy. Updating `Cargo.toml` without rebuilding leaves the deployed binary unchanged. Verify the live binary version by embedding it at compile time and exposing it through an internal status endpoint:

```rust
println!("wasmtime {}", wasmtime::VERSION);
```

### 2. Identify All aarch64 Deployments

Build a complete inventory of systems running Wasmtime on aarch64. The vulnerability only manifests on aarch64 hardware, but x86_64-based monitoring and CI pipelines do not expose it. Deployments you do not know are running on aarch64 will not receive patches if your patching process relies on manual identification.

Check the host architecture at runtime:

```bash
uname -m
```

On aarch64 Linux systems this returns `aarch64`. On macOS with Apple Silicon:

```bash
arch
```

This returns `arm64`. In CI, if your pipeline cross-compiles for aarch64 or runs on aarch64 runners, confirm the target:

```bash
rustc --print target-list | grep aarch64
rustup target list --installed | grep aarch64
```

Check Docker image manifests for multi-platform builds:

```bash
docker buildx imagetools inspect myregistry/myimage:latest
```

Images built with `--platform linux/arm64` or listed with `linux/arm64` in the manifest are aarch64 images. If these images embed a Wasmtime binary, they need the patch applied to the aarch64 build specifically.

For AWS environments, identify Graviton instance types in use:

```bash
aws ec2 describe-instances \
  --filters "Name=instance-type,Values=m7g.*,c7g.*,r7g.*,t4g.*,x2gd.*" \
  --query "Reservations[].Instances[].[InstanceId,InstanceType,PrivateIpAddress]" \
  --output table
```

Extend the instance type filter to cover all Graviton families in your account. Any instance running a Wasmtime-based workload on a Graviton host is an aarch64 deployment.

### 3. Process Isolation as Defence-in-Depth

Even on patched Wasmtime, process isolation is the correct architectural response to compiler-level sandbox escapes as a vulnerability class. Future Cranelift bugs — whether on aarch64 or another target — will similarly operate below application-layer controls. Process isolation contains the blast radius of any such escape to the address space of the worker process, which holds no secrets that the host orchestrator has not explicitly passed to it.

The architecture is a worker pool: a parent process manages requests and holds all credentials, and child processes each run a single Wasmtime instance with untrusted WASM. A compiler-level escape in a child process can read the child's own memory, which is scoped to the WASM module being executed and contains nothing from other tenants or the parent's secret store.

The child process can be a purpose-built minimal binary:

```bash
cargo build --release --bin wasm-worker
```

The parent spawns workers, routes requests over stdin/stdout or a Unix socket, and restarts workers that crash or time out:

```rust
use std::process::{Command, Stdio};

fn spawn_worker(wasm_path: &str) -> std::process::Child {
    Command::new("/usr/lib/myapp/wasm-worker")
        .arg(wasm_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn worker")
}
```

The worker process receives the WASM input bytes over its stdin, executes the module, and returns results over stdout. It holds no API keys, no database credentials, and no data from other tenants. A successful sandbox escape inside the worker reads only what the worker was sent for this invocation.

Cap the pool size. Each worker process carries its own Wasmtime `Engine`, memory-mapped compiled module, and OS-level address space overhead. For small modules this is typically 30–60 MB per worker. A pool of 50 concurrent workers adds 1.5–3 GB of overhead before accounting for WASM linear memory allocations. Size the pool based on measured memory usage under your expected peak concurrency.

### 4. Verify WASM Binary Provenance

Refuse to execute WASM binaries that cannot be traced to a trusted source. This does not prevent CVE-2026-34971 from being triggered by a malicious binary, but it limits the attack surface to binaries that have been signed or verified, reducing the viable attack vectors from arbitrary external input to a narrower set.

Compute and verify a content hash before loading:

```rust
use sha2::{Sha256, Digest};
use std::collections::HashSet;

fn verify_wasm(bytes: &[u8], allowed_hashes: &HashSet<[u8; 32]>) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let hash: [u8; 32] = hasher.finalize().into();
    allowed_hashes.contains(&hash)
}

fn load_wasm(engine: &wasmtime::Engine, bytes: &[u8], allowed_hashes: &HashSet<[u8; 32]>) -> anyhow::Result<wasmtime::Module> {
    if !verify_wasm(bytes, allowed_hashes) {
        anyhow::bail!("WASM binary hash not in allowed set, refusing to load");
    }
    wasmtime::Module::new(engine, bytes)
}
```

The allowed hash set is managed out-of-band — populated from a signed manifest or a registry of approved modules — and is not modifiable by the WASM module itself or by external callers. For plugin systems, this means only pre-approved plugin versions can be loaded. For user-submitted WASM, it means submissions pass through a review and signing step before they can be executed.

Wasmtime's AOT compilation path (`Module::serialize` and `Module::deserialize_file`) can be used to pre-compile modules from a trusted build environment and distribute the compiled artifact rather than the source WASM. This shifts compilation to a controlled environment where the Cranelift output can be inspected, and avoids JIT compilation of untrusted input at runtime. Verify the signature of the serialised artifact before loading.

### 5. ARM Memory Tagging (MTE) Where Available

ARM Memory Tagging Extension (MTE), introduced in ARMv8.5-A, provides hardware-enforced memory tags that can catch some categories of out-of-bounds access at runtime. Each 16-byte granule of memory is associated with a 4-bit tag. A load or store instruction carries a tag in the upper bits of the pointer; if the pointer tag does not match the allocation tag, the hardware generates a fault.

MTE can detect some manifestations of a compiler-level escape: if the Cranelift-generated instruction produces a pointer that lands in a differently-tagged allocation, the hardware faults before the access completes. This is a probabilistic defence — the 4-bit tag space means 1-in-16 mismatched accesses go undetected — but it provides a useful runtime signal in environments where it is available.

Check CPU support for MTE:

```bash
grep -o 'mte' /proc/cpuinfo | head -1
```

An empty result means the CPU does not support MTE. Enable MTE in Wasmtime's configuration when the CPU supports it and the feature is exposed by the OS (Linux kernel 5.10+ with `CONFIG_ARM64_MTE=y`):

```rust
let mut config = wasmtime::Config::new();
config.memory_init_cow(true);
```

Note that current AWS Graviton 3 and Graviton 4 instances are based on ARMv8.2-A and ARMv8.4-A respectively, which do not include MTE. MTE support requires ARMv8.5-A or later. For most current Graviton deployments, process isolation is the practical fallback; MTE is relevant primarily for Apple M-series systems (M2 and later support MTE on macOS 14+) and future ARM hardware generations.

## Expected Behaviour After Hardening

On a patched Wasmtime (24.0.7, 36.0.7, 42.0.2, or 43.0.1+), the heap access pattern that triggers CVE-2026-34971 produces a bounds check trap rather than an out-of-bounds access. The guest receives a WASM trap — `unreachable` or `out of bounds memory access` depending on the bounds check strategy — and the host's trap handler returns an error to the caller. No host memory is accessed. The trap is clean and recoverable; the host can discard the module instance and continue serving other requests.

With process isolation active, a future compiler-level escape in a worker process reads only the worker's own address space. The parent orchestrator's memory — credentials, other tenants' data, application state — is not accessible from the worker's address space. The operating system enforces this boundary independently of Wasmtime. The worker may be compromised or crash, but the parent detects the worker's termination through the child process exit status and replaces it with a fresh worker.

## Trade-offs and Operational Considerations

Wasmtime is a compiled Cargo dependency, not a standalone binary managed by a package manager. Patching requires updating `Cargo.toml`, resolving `Cargo.lock`, rebuilding the host application binary, and redeploying the resulting artifact. This is a full application build cycle, not a runtime library swap. Allow time for staging environment testing — particularly on aarch64 hardware — before rolling the patch to production. Automated `cargo audit` integrations that detect vulnerable Cargo dependencies and open pull requests are valuable here; they reduce the time between advisory publication and patch adoption.

Process isolation significantly increases memory overhead. A multi-tenant system that previously ran 200 concurrent WASM instances in a single process, sharing a compiled module cache and a common `Engine` memory footprint, now runs 200 separate worker processes. Measure the per-worker RSS under representative load before committing to this architecture. A capped worker pool with pre-warmed processes reduces spawn latency but holds the overhead constant regardless of actual concurrency. Tune the pool cap based on available system memory, not on peak theoretical concurrency.

ARM MTE requires ARMv8.5-A and kernel support. This rules it out on current Graviton 3 (`m7g`, `c7g`, `r7g`) and most currently deployed ARM edge hardware. Do not rely on MTE availability as a general mitigation for aarch64 Wasmtime deployments; treat it as an additional signal layer where it happens to be available, not as a substitute for patching or process isolation.

## Failure Modes

**`Cargo.toml` updated but `Cargo.lock` not refreshed.** Updating the version constraint in `Cargo.toml` does not automatically update `Cargo.lock`. If `cargo update -p wasmtime` is not run, or if the CI pipeline does not check in the updated `Cargo.lock`, the build resolves from the old lock file and produces an unpatched binary. Always run `cargo update -p wasmtime` after changing the version constraint and verify the output of `cargo tree -i wasmtime` before committing.

**aarch64 image not rebuilt on aarch64 CI.** A multi-platform Docker build that runs on x86_64 CI runners with QEMU emulation for the `linux/arm64` target may successfully build and push an aarch64 image without rebuilding the Rust binary inside it. If the Dockerfile uses a pre-built binary cached from a previous layer and the layer cache is not invalidated by the `Cargo.lock` change, the deployed aarch64 container still contains the unpatched Wasmtime binary. Ensure that aarch64 builds run on native aarch64 runners (Graviton CI instances, Apple Silicon runners) and that the binary layer is rebuilt on every `Cargo.lock` change.

**Process pool has a shared memory segment.** Some architectures introduce a shared memory segment between pool workers for performance — for instance, a shared compiled module cache or a shared WASM linear memory backing store. A shared memory segment is visible in all processes that map it. If a compiler-level escape occurs in a worker process and the escape address lands within the shared segment, the attacker can read or write data placed there by other workers or the parent. Audit any inter-process memory sharing in the worker pool design; remove it or ensure the shared segment contains no secrets.

## Related Articles

- [Wasmtime Async DoS Security](/articles/wasm/wasmtime-async-dos-security/)
- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [WASM Component Model Security](/articles/wasm/wasm-component-model-security/)
- [WASM Multi-Tenancy](/articles/wasm/wasm-multi-tenancy/)
- [Reproducible WASM Builds](/articles/wasm/reproducible-wasm-builds/)
