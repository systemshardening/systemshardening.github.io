---
title: "WASM as Kernel-Independent Isolation: CVE-2023-26114 and the Residual Shared-Kernel Risk"
description: "WebAssembly runtimes promise isolation without sharing a kernel — each module runs in a sandboxed linear memory region enforced by the runtime, not the OS. CVE-2023-26114 (Wasmtime heap escape) showed what happens when the runtime itself has a bug. And when WASM runs inside a container, it inherits all the shared-kernel risks it was supposed to avoid."
slug: wasm-kernel-independent-isolation
date: 2026-05-08
lastmod: 2026-05-08
category: wasm
tags:
  - webassembly
  - cve
  - isolation
  - kernel
  - wasmtime
personas:
  - security-engineer
  - platform-engineer
article_number: 696
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/wasm/wasm-kernel-independent-isolation/
---

# WASM as Kernel-Independent Isolation: CVE-2023-26114 and the Residual Shared-Kernel Risk

## The Problem

The conventional pitch for WebAssembly as a security primitive goes like this: a WASM module executes in a sandboxed linear memory region, and the runtime enforces three invariants that make it categorically safer than a container. First, every memory access — load and store — is bounds-checked against the module's allocated linear memory; an index out of bounds produces a trap and clean termination, not exploitable heap corruption. Second, indirect function calls go through a type-checked table; a WASM module cannot manufacture a function pointer to arbitrary native code. Third, the module has no access to host memory, host file descriptors, or host syscalls except through explicitly imported WASI functions that the host embedder grants one at a time. In theory, a WASM module cannot escape its sandbox regardless of what code it executes — the invariants hold even for malicious guest code.

This is structurally different from container isolation. A container relies on the Linux kernel enforcing namespace boundaries — and a kernel CVE in nf_tables, overlayfs, or any other reachable subsystem can collapse those boundaries instantly. A WASM module's isolation does not depend on the kernel at all for the primary invariants; it depends on the runtime enforcing memory bounds in software, augmented by guard pages or hardware memory tagging at the OS layer. A WASM guest that tries to break its sandbox is fighting the runtime, not the kernel.

CVE-2023-26114 broke this story cleanly. Wasmtime's Cranelift JIT compiler had a miscompilation bug in its handling of specific SIMD vector operations on x86_64. When a WASM module executed `v128.load` and `i64x2.extend_low_i32x4_s` with specific memory access patterns, Cranelift generated x86 machine code that applied the wrong offset when computing the bounds check for the SIMD load. The generated native code checked the load as if it were accessing byte offset N, but the actual machine instruction accessed byte offset N+8 — 8 bytes past the end of the linear memory allocation. The bounds check passed because it validated the wrong address. The load executed against memory that was not part of the WASM linear memory.

In practice this meant a WASM module could read 8 bytes of Wasmtime's own heap memory adjacent to the linear memory allocation. What those 8 bytes contained depended on Wasmtime's allocator layout at the time of execution: they could be pointers into JIT-compiled code, Wasmtime internal data structure fields, application data from the host embedder, or in a multi-tenant configuration, data belonging to another tenant's module or request. The CVE is classified as a confidentiality breach; in configurations where the miscompiled code path also produced a write, the severity extends to memory corruption.

Affected versions: Wasmtime 6.0.0 and earlier. Patched in Wasmtime 6.0.1, released March 2023. Fastly Compute and any deployment using Cranelift as the code generation backend for Wasmtime 6.0.0 were affected until upgraded.

The structural lesson is not that Cranelift made a mistake — the WASM specification is correct; every bounds check is required. The structural lesson is that the WASM sandbox is exactly as strong as the runtime's implementation of those bounds checks. Cranelift, V8 (Chrome), SpiderMonkey (Firefox), and JavaScriptCore (Safari) all generate native machine code from WASM bytecode. JIT miscompilation bugs are a well-established CVE class: V8 had CVE-2021-30551 (type confusion in JIT), SpiderMonkey had CVE-2022-22745 (information leak through JIT), JavaScriptCore had CVE-2022-22620 (use-after-free in JIT). Every one of those bugs invalidated the sandbox for any module that triggered the affected code path. The specification was correct in every case. The specification's guarantees only hold if the runtime enforces them without errors.

The Cranelift miscompilation in CVE-2023-26114 is specifically worth understanding because Cranelift is the most security-focused WASM JIT in production. It was developed under the Bytecode Alliance with formal verification aspirations and mandatory security review for compiler changes. If a miscompilation bug survives that process, it will survive a less rigorous one. Platform engineers should not treat "we use a security-focused JIT" as a closed question.

The residual shared-kernel problem compounds this. In production deployments, WASM runtimes run inside containers, which run on a shared-kernel host. The WASM module is isolated from the host application by the runtime, but the runtime is a userspace process with all the exposure that entails:

- CVE-2022-0847 (Dirty Pipe) allows overwriting arbitrary files through the pipe splicing mechanism, including the Wasmtime binary itself or any shared library it loads, from another container on the same host with no root privileges required.
- A container escape from an adjacent container on the same node — via any of the recurring nf_tables, overlayfs, or runc CVEs — lands the attacker in the same kernel namespace as the Wasmtime process. From there, ptrace or /proc/PID/mem provides direct read-write access to Wasmtime's address space, including the linear memory of every WASM module being served.
- A privileged DaemonSet running eBPF programs can trace any process on the node. `bpf_probe_read_user` against the Wasmtime process PID reads WASM linear memory contents directly from userspace addresses — no kernel CVE required, just a DaemonSet with `CAP_BPF` or `CAP_SYS_ADMIN`.

The WASM isolation story is therefore layered and conditional: strong isolation from the host application's heap and code (modulo runtime CVEs), weak isolation from the host kernel and from anything that can reach the kernel or the host process. Understanding which threat actors are blocked at which layer determines whether the isolation model is fit for purpose for a given deployment.

## Threat Model

**JIT miscompilation heap read** — A malicious WASM module is authored to trigger CVE-2023-26114's specific code path: `v128.load` followed by `i64x2.extend_low_i32x4_s` with a memory access pattern that causes Cranelift to misplace the bounds check offset. Running on an unpatched Wasmtime 6.0.0, the module reads 8 bytes of Wasmtime heap memory adjacent to its linear memory allocation. In a multi-tenant serverless platform (Fastly Compute, Fermyon Spin, a self-hosted Wasmtime deployment), that adjacent memory may contain another tenant's in-flight request body, response headers, or authentication tokens. The attack requires only a valid WASM module upload — no runtime privilege, no initial access to the host.

**Multi-tenant data exfiltration via JIT bug** — In a serverless platform that serves thousands of concurrent requests, multiple tenants' linear memory allocations are present in the same Wasmtime process heap simultaneously. A JIT miscompilation that allows an out-of-bounds read of N bytes is not limited to reading the immediately adjacent heap region; if the attacker can trigger the read repeatedly across different allocation timings, they can scan through the heap and extract data from arbitrary tenants' allocations. The technique is analogous to a heap-based information leak in a C runtime — same class, same exploit pattern, different language.

**Dirty Pipe overwrite of Wasmtime binary** — CVE-2022-0847 allows unprivileged overwrite of read-only page-cache pages through pipe splicing. An attacker in any container on the same node — not necessarily the Wasmtime container — can overwrite bytes in the Wasmtime binary on the shared filesystem. The overwrite does not require the binary to be writable; it operates through the kernel's page cache. On the next invocation or after a library reload event, the modified code executes in the Wasmtime process context, with access to all WASM modules and their linear memory. This attack does not require a WASM sandbox escape; it bypasses the sandbox entirely by targeting the process that implements the sandbox.

**Envoy WASM filter supply chain** — Envoy embeds Wasmtime as its WASM filter runtime. WASM filters are distributed as `.wasm` files loaded from Kubernetes ConfigMaps or remote URLs. A supply chain compromise of a popular Envoy WASM filter (HTTP authentication, rate limiting, header manipulation) that introduces a malicious `.wasm` payload triggering a JIT miscompilation — in Wasmtime or in any future Cranelift version — produces RCE in the Envoy data plane process. Envoy proxies have network access to every service in the mesh. The blast radius is lateral movement across the entire service mesh from a single compromised WASM filter artifact.

**eBPF-based linear memory extraction** — A DaemonSet with `CAP_BPF` (or `CAP_SYS_ADMIN` on older kernels) deploys a `uprobe`-based eBPF program that instruments the Wasmtime binary at `wasm_store_write` or equivalent internal symbols. Every write to WASM linear memory is traced with `bpf_probe_read_user`, extracting the written bytes and their offset. Secrets passed to WASM modules via WASI function arguments — API keys, session tokens, database credentials — are extracted as they are written into linear memory, with no WASM sandbox escape required. This attack requires only a privileged DaemonSet; it does not require a CVE.

## Hardening Configuration

### 1. Wasmtime Version Pinning and CVE Tracking

CVE-2023-26114 was patched in Wasmtime 6.0.1. But Wasmtime's security advisory cadence is independent of the Linux kernel CVE stream — a platform engineer who patches kernels diligently but does not separately track Wasmtime releases is running known-vulnerable runtimes. Subscribe to the advisory feed and pin to specific versions in all deployment artifacts.

```bash
# Verify current Wasmtime version
wasmtime --version
# Expected: wasmtime-cli 20.x.x (or later)

# CVE-2023-26114 patched in 6.0.1 — any earlier version is affected
# Full advisory: https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-ff4p-7xrq-q5r8

# Subscribe to the security advisory RSS feed for Wasmtime
# https://github.com/bytecodealliance/wasmtime/security/advisories.atom
# This is a separate feed from the GitHub release feed — advisories sometimes
# lag releases; both need to be monitored

# In a Dockerfile, pin to a specific digest, not a tag:
# FROM ghcr.io/bytecodealliance/wasmtime:20.0.2@sha256:<digest>
# Tags like :20 or :latest are mutable; a new tag push silently changes what you run
```

For containerised Wasmtime deployments, a Dependabot configuration that tracks the Wasmtime container image prevents version drift:

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: docker
    directory: /deploy/wasmtime
    schedule:
      interval: weekly
    ignore:
      # Only track stable releases, not pre-release tags
      - dependency-name: "ghcr.io/bytecodealliance/wasmtime"
        versions: ["*-dev", "*-rc*"]
```

### 2. Enable Guard Pages and Memory Protection

Wasmtime supports static and dynamic memory models, and the guard page configuration differs between them. Static memory with large guard regions is the highest-isolation mode: Wasmtime reserves a large virtual address range with `PROT_NONE` pages surrounding the linear memory, so any access beyond the allocated region generates a SIGSEGV rather than silently reading adjacent heap memory. CVE-2023-26114's 8-byte over-read was not caught by default guard pages because the over-read was small enough to land within the legitimate guard gap between the linear memory end and the guard page boundary.

The correct response is to configure the guard size to be large enough that small over-reads also hit the guard, and to verify that guard pages are active in production builds.

```rust
use wasmtime::{Config, Engine};

fn build_hardened_engine() -> anyhow::Result<Engine> {
    let mut config = Config::new();

    // Static memory model: reserve a fixed virtual address range per instance.
    // This enables the OS to enforce bounds via SIGSEGV rather than requiring
    // every JIT-emitted bounds check to be perfectly correct.
    config.static_memory_maximum_size(128 * 1024 * 1024); // 128 MiB max linear memory

    // 2 GiB guard region after the linear memory allocation.
    // Any access beyond the linear memory end (including small over-reads
    // like CVE-2023-26114's 8-byte escape) hits PROT_NONE pages and SIGSEGV.
    config.static_memory_guard_size(2 * 1024 * 1024 * 1024); // 2 GiB

    // Guard pages before the linear memory start as well.
    // This catches underflow accesses (negative signed index used as unsigned).
    config.guard_before_linear_memory(true);

    // Disable dynamic memory growth that bypasses static memory protections.
    // Modules that call memory.grow beyond the static maximum are trapped, not
    // allowed to remap into unguarded regions.
    config.dynamic_memory_guard_size(64 * 1024); // 64 KiB guard for dynamic fallback

    Engine::new(&config)
}
```

Guard pages work by mapping virtual address space with `PROT_NONE` via `mmap`. The kernel never allocates physical pages for `PROT_NONE` regions — the cost is virtual address space, not RAM. On 64-bit systems with 48-bit virtual address space, allocating 2 GiB of guard space per WASM instance is tractable for hundreds of concurrent instances. The benefit: JIT miscompilations that produce out-of-bounds accesses in the guard region generate a SIGSEGV that Wasmtime catches as a trap signal, producing a clean `Trap::MemoryOutOfBounds` error to the host rather than a silent read of adjacent heap data.

Verify guard pages are configured on a running Wasmtime instance by inspecting the process's virtual memory map:

```bash
# After loading a WASM module, inspect the process's memory regions
# The linear memory should be flanked by anonymous regions with no rwx permissions
cat /proc/$(pgrep wasmtime)/maps | grep -A2 -B2 "r--p"
# Look for: <addr>-<addr+2GiB> ---p 00000000 00:00 0  (the guard region)
# Followed by: <addr+2GiB>-<addr+2GiB+N> rw-p (the linear memory itself)
```

### 3. Sandboxed Wasmtime Process with Seccomp and Namespace Isolation

Guard pages reduce the impact of JIT miscompilation bugs. Seccomp reduces the impact of a full sandbox escape. Even if a WASM module successfully escapes the Wasmtime runtime — via a future JIT miscompilation that allows arbitrary write rather than just an 8-byte read — it then faces OS-level restrictions that limit what the escaped process can do.

Wasmtime's JIT compilation requires `mmap` with `PROT_EXEC` and `mprotect` to transition memory regions between writable and executable. These are the syscalls that make JIT work, and they are also the syscalls most useful to an attacker who has gained code execution. The seccomp profile must allow them for Wasmtime to function, but can restrict all other syscalls to the minimum set actually needed.

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [
    {
      "names": [
        "read", "write", "pread64", "pwrite64",
        "mmap", "mprotect", "munmap", "mremap",
        "madvise", "brk",
        "open", "openat", "close", "fstat", "stat", "lstat",
        "getdents64", "readlink", "readlinkat",
        "sigaltstack", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
        "clock_gettime", "gettimeofday",
        "futex", "sched_yield",
        "exit", "exit_group",
        "epoll_create1", "epoll_ctl", "epoll_wait",
        "poll", "select",
        "socket", "connect", "accept", "accept4",
        "send", "sendto", "recv", "recvfrom", "recvmsg", "sendmsg",
        "bind", "listen", "getsockname", "getpeername", "getsockopt", "setsockopt",
        "pipe", "pipe2",
        "dup", "dup2", "dup3",
        "fcntl", "ioctl",
        "getrandom",
        "prctl",
        "uname"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

Explicitly absent from this profile: `ptrace`, `process_vm_readv`, `process_vm_writev`, `perf_event_open`, `bpf`, `kexec_load`, `syslog`, `setuid`, `setgid`, `setns`, `unshare`, `clone` (with CLONE_NEWUSER). A Wasmtime process that escapes the WASM sandbox but faces this seccomp profile cannot inject code into other processes, cannot load kernel modules, cannot create new privileged namespaces, and cannot call BPF.

Apply the seccomp profile at the container level:

```dockerfile
# Multi-stage build: Wasmtime binary only, no shell, no package manager
FROM scratch AS runtime
COPY --from=ghcr.io/bytecodealliance/wasmtime:20.0.2 /usr/local/bin/wasmtime /wasmtime
COPY modules/ /modules/

ENTRYPOINT ["/wasmtime"]
```

```yaml
# Kubernetes Pod spec
apiVersion: v1
kind: Pod
metadata:
  name: wasm-server
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/wasmtime-seccomp.json
    runAsNonRoot: true
    runAsUser: 65534
  containers:
  - name: wasmtime
    image: your-registry/wasmtime-server:20.0.2
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      readOnlyRootFilesystem: true
```

Running Wasmtime as UID 65534 (nobody) with all capabilities dropped means a sandbox escape produces a process with no meaningful OS privilege. It cannot write to the host filesystem, cannot bind privileged ports, and faces the seccomp restriction on process introspection.

### 4. WASM Module Signing and Verification

CVE-2023-26114 required a WASM module that exercised the specific SIMD code path. Module signing does not prevent a legitimate module author from crafting a module that triggers a JIT bug — it only prevents unsigned modules from being loaded. But for plugin systems (Envoy WASM filters, Wasm-based OPA policies, Kubernetes admission webhooks backed by WASM) where the module source is controlled, signing closes the supply chain vector: a compromised build pipeline that injects a malicious `.wasm` payload is detected before execution.

```bash
# Sign a WASM module with cosign
cosign sign-blob \
  --key cosign.key \
  --output-signature plugin.wasm.sig \
  plugin.wasm

# Verify before loading
cosign verify-blob \
  --key cosign.pub \
  --signature plugin.wasm.sig \
  plugin.wasm
# Output on success: Verified OK
# Output on failure: error: verifying blob [plugin.wasm]: invalid signature
```

For OCI-stored WASM modules (pushed to a container registry as OCI artifacts), use Sigstore's OCI signing:

```bash
# Push WASM module as OCI artifact
oras push \
  your-registry/wasm-filters/auth-filter:1.2.3 \
  plugin.wasm:application/wasm

# Sign the OCI artifact with cosign
cosign sign \
  --key cosign.key \
  your-registry/wasm-filters/auth-filter:1.2.3

# Verify in Envoy deployment pipeline
cosign verify \
  --key cosign.pub \
  your-registry/wasm-filters/auth-filter:1.2.3 \
| jq '.[] | {digest: .critical.image["docker-manifest-digest"], ref: .optional.ref}'
```

For Kubernetes admission control, a ValidatingWebhookConfiguration backed by a simple Go webhook can block Pod creation if a referenced WASM module lacks a valid signature. This applies to Envoy filter ConfigMaps and any other mechanism that loads `.wasm` files at runtime:

```go
// In the admission webhook handler:
// 1. Extract the wasm filter URL or configmap reference from the Pod annotation
// 2. Fetch the WASM module bytes
// 3. Run cosign.VerifyBlobCmd against the module and expected public key
// 4. Return admission allowed/denied based on verification result
func (h *WasmSignatureWebhook) Handle(ctx context.Context, req admission.Request) admission.Response {
    var pod corev1.Pod
    if err := h.decoder.Decode(req, &pod); err != nil {
        return admission.Errored(http.StatusBadRequest, err)
    }
    wasmRef := pod.Annotations["wasm-filter/module-ref"]
    if wasmRef == "" {
        return admission.Allowed("no wasm filter annotation")
    }
    if err := verifyWasmSignature(ctx, wasmRef, h.cosignPublicKey); err != nil {
        return admission.Denied(fmt.Sprintf("WASM module signature verification failed: %v", err))
    }
    return admission.Allowed("signature verified")
}
```

### 5. Memory Tagging and AddressSanitizer for Wasmtime Builds

Guard pages catch out-of-bounds accesses that land in the guard region. CVE-2023-26114's 8-byte over-read was small enough that whether it hit the guard depended on allocation layout. ARM MTE (Memory Tagging Extension, ARMv8.5-A) provides tag-granule (16-byte) bounds checking at the hardware level with approximately 1-6% performance overhead — orders of magnitude cheaper than ASAN — and would have caught the CVE-2023-26114 over-read regardless of allocation layout.

Wasmtime's CI builds include an ASAN (AddressSanitizer) configuration that runs the test suite with heap bounds checking enabled. For high-security production deployments where CPU overhead is acceptable — auditing environments, compliance-sensitive platforms, staging environments that mirror production — an ASAN-instrumented Wasmtime build provides defense-in-depth against JIT miscompilations that escape guard pages:

```bash
# Build Wasmtime with AddressSanitizer
# Requires nightly Rust for -Zsanitizer
RUSTFLAGS="-Zsanitizer=address" \
  cargo build \
  --release \
  --target x86_64-unknown-linux-gnu \
  -Z build-std \
  --package wasmtime-cli

# Run the ASAN-instrumented binary with ASAN options
ASAN_OPTIONS="detect_leaks=1:abort_on_error=1:halt_on_error=1" \
  ./target/x86_64-unknown-linux-gnu/release/wasmtime \
  run \
  --dir=. \
  module.wasm
```

On ARM64 hardware supporting MTE, Wasmtime's memory allocator can be configured to use tagged allocations. Any access (including JIT-compiled WASM code) to memory with a non-matching tag triggers a hardware fault at the 16-byte granule boundary. This catches the class of over-reads that CVE-2023-26114 exemplifies even when the over-read is small and guard pages are not contiguous with the accessed region.

### 6. Isolate WASM Container Workloads with gVisor

For WASM workloads where the primary concern is not the WASM sandbox itself but the shared-kernel risk underneath it — Dirty Pipe-class kernel CVEs, eBPF-based memory extraction, adjacent container escapes — running the Wasmtime process inside gVisor interposes a Go-implemented kernel between the Wasmtime process and the Linux host kernel. The host kernel's attack surface is reduced to a small set of syscalls that gVisor uses internally; the Wasmtime process issues syscalls to gVisor's `sentry` process, not directly to the Linux kernel.

A container escape from the Wasmtime process that exploits a gVisor-undetected syscall still lands in the gVisor sentry, not on the host. CVE-2022-0847 (Dirty Pipe) requires the kernel's splice path; gVisor implements splice in Go and does not reproduce the host kernel's vulnerable page-cache mechanism.

```yaml
# GKE or self-managed cluster with gVisor RuntimeClass installed
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
---
apiVersion: v1
kind: Pod
metadata:
  name: wasm-server
  labels:
    app: wasm-server
spec:
  runtimeClassName: gvisor
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/wasmtime-seccomp.json
  containers:
  - name: spin
    image: fermyon/spin:3.0.0
    args: ["up", "--listen", "0.0.0.0:3000", "--file", "/app/spin.toml"]
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      readOnlyRootFilesystem: true
    resources:
      limits:
        memory: "256Mi"
        cpu: "500m"
```

gVisor adds approximately 10-30% CPU overhead for syscall-heavy workloads. Wasmtime itself reduces syscall frequency because WASM computation does not issue syscalls — only WASI function calls that the host embedder routes. The combined overhead is lower than it would be for a general-purpose container doing the same computation with direct kernel access. The double-sandbox model — WASM runtime isolation plus gVisor kernel interposition — is appropriate for multi-tenant platforms where a successful WASM sandbox escape would otherwise reach the shared Linux kernel directly.

## Expected Behaviour

A Wasmtime instance correctly configured with a 2 GiB static memory guard region and a WASM module that attempts an out-of-bounds memory access produces:

```
thread 'main' panicked at 'called `Result::unwrap()` on an `Err` value:
error while executing at wasm backtrace:
    0: 0x1234 - module!attempt_oob_read
Caused by:
    memory out of bounds: data segment does not fit
```

The host process continues running. The WASM module instance is terminated. Wasmtime catches the SIGSEGV from the guard page, converts it to a `wasmtime::Trap` with `TrapCode::MemoryOutOfBounds`, and surfaces it as an error to the embedder code. The 8-byte over-read that CVE-2023-26114 permitted on Wasmtime 6.0.0 would, on a patched version with the correct bounds check offset, generate this same trap — the module terminates instead of reading Wasmtime heap memory.

A correctly sandboxed Wasmtime process running as UID 65534 with `CAP_DROP=ALL` shows the following in `/proc/self/status`:

```
Name:   wasmtime
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 0000000000000000
CapAmb: 0000000000000000
Seccomp: 2
Seccomp_filters: 1
```

`Seccomp: 2` indicates the process is running under a seccomp filter (mode 2 = filter mode). `CapEff: 0000000000000000` confirms all effective capabilities are dropped. A sandbox escape from this process cannot gain privileges because there are no privileges to escalate to.

A failed cosign module signature verification produces:

```
Error: verifying blob [envoy-auth-filter.wasm]: invalid signature
cosign: FAIL
```

The admission webhook receives this error from the verification call and returns an admission denial:

```json
{
  "response": {
    "uid": "...",
    "allowed": false,
    "status": {
      "code": 403,
      "message": "WASM module signature verification failed: verifying blob [envoy-auth-filter.wasm]: invalid signature"
    }
  }
}
```

The Pod does not start. The WASM filter is not loaded into Envoy.

## Trade-offs

**Guard page size vs instance memory overhead.** Reserving 2 GiB of virtual address space per WASM instance costs nothing in physical RAM — `PROT_NONE` pages are never backed by physical memory. But virtual address space is finite. On a system running 500 concurrent WASM instances each with 2 GiB guard regions, 1 TiB of virtual address space is reserved for guard pages alone. On Linux with 48-bit virtual addressing (256 TiB user space), this remains tractable. But embedded deployments or platforms with many thousands of concurrent instances need to tune the guard size against expected scale. A 64 MiB guard region catches most JIT miscompilations at lower virtual address cost; a 2 GiB guard region provides stronger protection against systematic heap scanning.

**Guard pages do not catch all JIT miscompilations.** CVE-2023-26114's 8-byte over-read could fall within the legitimate allocation boundary if the guard page was not adjacent to that specific byte. Guard pages establish a trip wire at the boundary of the reserved virtual address range; they do not provide byte-granularity protection inside the range. An allocator that places two linear memory regions with no intervening guard would allow a same-sized over-read to land in the adjacent module's memory silently. Wasmtime's default allocator does not do this, but the architecture of guard pages means they are probabilistic for small over-reads, not deterministic.

**ASAN overhead.** AddressSanitizer adds approximately 15-30% CPU overhead and 2x memory overhead. For a WASM workload already adding JIT compilation overhead, ASAN in production is generally infeasible for latency-sensitive or resource-constrained deployments. Its value is as a staging environment control: run ASAN-instrumented Wasmtime in a staging environment that executes the same WASM modules as production, and use the staging output to detect JIT miscompilation bugs before they appear in CVE disclosures.

**gVisor double-sandbox overhead.** gVisor adds approximately 10-30% CPU overhead from syscall interposition. Wasmtime adds JIT compilation overhead on initial module instantiation and per-call overhead from bounds-check code. The combined cost is real and measurable. For workloads that are computationally heavy (WASM-based machine learning inference, WASM cryptographic operations), the double-sandbox overhead is proportionally smaller because most cycles are spent in computation rather than syscalls. For I/O-heavy workloads, gVisor's syscall interposition cost is more visible. Benchmark the specific workload before committing to gVisor in production.

**Seccomp and JIT mmap/mprotect.** Wasmtime's JIT compilation requires `mmap` with `MAP_PRIVATE | MAP_ANONYMOUS` and `PROT_READ | PROT_WRITE`, followed by `mprotect` to transition the region to `PROT_READ | PROT_EXEC` after code generation. Removing either syscall from the seccomp allowlist breaks JIT operation. The seccomp profile described above permits these syscalls because Wasmtime genuinely needs them. An operator who removes `mmap` or `mprotect` to further restrict the profile must also switch Wasmtime to interpreter-only mode (`--cranelift-flags opt_level=none` does not disable JIT; use Wasmtime's `winch` interpreter backend or `--strategy=cranelift` with the `--disable-cache` flag and configure an interpreter-only profile at the `Config` level). Interpreter mode carries a 5-10x performance penalty but eliminates the JIT-as-attack-surface entirely.

**Module signing in dynamic plugin environments.** Cosign verification works well when WASM modules are static artifacts loaded at deployment time. It is harder to apply when modules are dynamically generated (user-uploaded code, WASM modules compiled on the fly from user-provided source). For dynamic-compilation use cases, signing cannot prevent a malicious user from uploading WASM that triggers a JIT bug — signing only verifies provenance, not intent. The applicable control for user-uploaded WASM is WASM validation (verify that the module is structurally valid before compilation), resource limits, and version pinning to a Wasmtime release with no known JIT miscompilations.

## Failure Modes

**Treating WASM isolation as equivalent to OS isolation.** The most common mistake in WASM security architecture is concluding that because WASM modules cannot make direct syscalls, the underlying OS security model is irrelevant. It is not. The WASM runtime is a userspace process. Everything that can attack a userspace process — Dirty Pipe, adjacent container escapes, eBPF tracing from a privileged DaemonSet, ptrace from the same UID — bypasses the WASM sandbox entirely because it operates below it. WASM isolation and OS isolation address orthogonal threat actors. Both are required.

**Running Wasmtime without guard pages in embedded configurations.** Some embedded WASM deployments — microcontrollers, resource-constrained edge devices, WASM runtimes embedded inside databases — disable guard pages to reduce memory overhead. `Config::static_memory_guard_size(0)` is a valid Wasmtime configuration option. Deployments that disable guard pages and run on unpatched Wasmtime lose the defense-in-depth that guard pages provide against JIT miscompilation. Without guard pages, CVE-2023-26114's out-of-bounds read lands in adjacent heap memory silently, with no trap generated. Embedded configurations that disable guard pages must maintain strict version pinning and fast patch cycles as compensating controls.

**Not patching Wasmtime separately from the OS.** Wasmtime is not part of the Linux kernel and is not patched by OS security updates. A system running Ubuntu 24.04 with all kernel patches applied but Wasmtime 6.0.0 installed from a Rust toolchain pinned six months ago is running a WASM runtime with the specific heap escape CVE that this article covers. WASM runtime CVEs are a separate patch stream: they appear in the Bytecode Alliance security advisory feed, not in Ubuntu USNs or Red Hat ERRATAs. Teams that rely solely on OS-level patch management miss WASM runtime CVEs entirely.

**Loading WASM modules from untrusted sources without verification.** Envoy WASM filters are a particularly high-risk case: they are loaded from URLs in the Envoy configuration, they run with the full privilege of the Envoy process, and they are often deployed through GitOps pipelines where a compromised upstream repository can introduce a malicious `.wasm` file without modifying any Kubernetes YAML. Every WASM filter loaded into production Envoy should have a verified Sigstore signature. The signature should be verified at admission time, not trusted because the artifact came from a private registry — private registries can be compromised too.

**Assuming module fuel/CPU limits prevent sandbox escapes.** Fuel metering (Wasmtime's instruction counting mechanism) and epoch interrupts prevent infinite loops and CPU exhaustion. They do not prevent sandbox escapes. A WASM module that triggers CVE-2023-26114 does so in a handful of instructions, well within any reasonable fuel budget. Fuel metering addresses denial-of-service from resource exhaustion; it has no effect on code execution-class vulnerabilities. They are complementary controls, not substitutes.

## Related Articles

- [gVisor and Kata Containers: Shared-Kernel Defense in Depth](/articles/kubernetes/runtimeclass-gvisor-kata/)
- [Dirty Pipe and Container Escape: CVE-2022-0847](/articles/linux/dirty-pipe-container-escape/)
- [WASM JIT Compiler Security: JIT Spraying and Speculative Execution Defenses](/articles/wasm/wasm-jit-security/)
- [Wasmtime Production Hardening: Fuel, Memory, Epoch Interrupts, and WASI Capability Allowlists](/articles/wasm/wasmtime-production-hardening/)
- [WASM vs Container Isolation: What AI-Scale Vulnerability Discovery Changes](/articles/wasm/wasm-isolation-vs-container-isolation/)
- [Envoy WASM Plugin Hardening](/articles/wasm/envoy-wasm-plugin-hardening/)
