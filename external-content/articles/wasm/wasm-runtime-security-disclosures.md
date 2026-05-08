---
title: "WASM Runtime Security Disclosures: Tracking and Responding to Wasmtime, V8, and WasmEdge CVEs"
description: "A vulnerability in a WASM runtime directly undermines the sandbox guarantees your application relies on. Wasmtime sandbox escapes, V8 JIT compiler vulnerabilities, and WasmEdge memory safety bugs have all appeared as CVEs. This guide covers how each WASM runtime handles security disclosures, how to track runtime CVEs, and the emergency response process when a critical sandbox-escape vulnerability is published."
slug: wasm-runtime-security-disclosures
date: 2026-05-08
lastmod: 2026-05-08
category: wasm
tags:
  - wasm-runtime
  - wasmtime
  - security-disclosure
  - cve
  - sandbox-security
personas:
  - security-engineer
  - platform-engineer
article_number: 688
difficulty: Intermediate
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/wasm/wasm-runtime-security-disclosures/
---

# WASM Runtime Security Disclosures: Tracking and Responding to Wasmtime, V8, and WasmEdge CVEs

## Problem

When you deploy a WASM sandbox to run untrusted code — a third-party plugin, user-uploaded logic, an edge function from an external developer — the security guarantee rests entirely on the runtime enforcing the sandbox boundary. The linear memory model, the absence of raw pointer arithmetic, the capability-gated WASI interfaces: all of those properties exist in the specification and in the compiled module, but they are *enforced* at execution time by the runtime. Wasmtime, V8, WasmEdge, and their peers are the trust anchor of your entire WASM security model. If the runtime has a bug in bounds checking, a miscompilation in the JIT compiler, or a memory safety error in the host-call dispatch path, then every security property you rely on can be invalidated by a sufficiently crafted WASM module.

This is why WASM runtime CVEs are categorically different from library CVEs. A vulnerable version of a JSON parsing library in your application might be unexploitable depending on how you call it, what data reaches it, and whether you have mitigating controls elsewhere in the stack. A sandbox-escape vulnerability in a WASM runtime is, by definition, exploitable in any environment that runs attacker-controlled WASM through that runtime. The entire point of the attack surface is that untrusted code reaches the runtime — there is no "this input never reaches the vulnerable code path" defence when the vulnerable code path is the module execution engine itself.

The blast radius compounds in multi-tenant deployments. A WASM-based plugin system where ten thousand tenants each upload their own WASM module is not running ten thousand separate trust boundaries: it is running one runtime, shared across all tenants, and a sandbox-escape vulnerability in that runtime is simultaneously a vulnerability against every tenant's isolation guarantee. Edge compute platforms, Kubernetes operators that accept third-party WASM workloads, serverless function runtimes that execute user code — all inherit this property.

The CVE history confirms this is not a theoretical concern. Wasmtime has published multiple security advisories covering sandbox-relevant issues: miscompilation bugs where the JIT produced incorrect bounds-checking code, integer overflow in memory address calculation, and use-after-free conditions reachable from WASM execution. V8's JIT compiler — used by Node.js, Deno, and browser-based WASM runtimes — has a consistent history of type-confusion and speculative execution vulnerabilities, some of which are specifically reachable via crafted WASM modules. WasmEdge, written in C++, has had out-of-bounds memory access bugs that allowed sandboxed modules to corrupt host process memory. These are not edge cases in obscure configurations; they are bugs in the central execution engines that every consumer of these runtimes depends on.

## Threat Model

**Malicious WASM plugin exploiting a Wasmtime miscompilation bug.** An attacker uploads a WASM plugin to a platform that uses Wasmtime for execution. The plugin is carefully crafted to trigger a miscompilation path in Wasmtime's Cranelift backend — a code generation bug that produces incorrect bounds-checking code for a specific sequence of memory access instructions. When the plugin executes, the compiled native code accesses host memory outside the linear memory region allocated to the WASM module. The attacker reads secrets from host process memory, or writes to function pointers in the host's heap to redirect execution. From outside the system, the plugin appeared to pass validation; it contained no obviously malicious instructions and no capability requests beyond what the platform permitted.

**V8 JIT vulnerability triggered via crafted WASM.** A Node.js application uses V8's WASM execution engine to run user-provided analytics modules. An attacker submits a WASM module that, during JIT compilation, triggers a type-confusion bug in V8's optimising compiler. The compiled code operates on a value of the wrong type, producing a read or write to an attacker-controlled address in the V8 heap. This escalates from WASM sandbox context to full V8 heap access, from which further exploitation of the Node.js host process is possible. The V8 vulnerability was already public as part of a Chrome security release, but the Node.js version in production had not been updated.

**WasmEdge out-of-bounds write corrupting host process memory.** A Kubernetes sidecar container uses WasmEdge to execute WASM-based policy modules submitted by development teams. A development team (or a compromised build pipeline producing their WASM artifact) submits a module that exploits a known out-of-bounds write vulnerability in WasmEdge's memory management. The module writes beyond the boundary of its linear memory allocation into adjacent host process memory, overwriting data structures that govern module permissions. The sandboxed module grants itself capabilities it was not assigned, then calls host functions it should never have reached.

## Configuration and Implementation

### Wasmtime Security Disclosure Process

Wasmtime is maintained by the Bytecode Alliance and has the most mature security disclosure process of any standalone WASM runtime. Security vulnerabilities should be reported to **security@bytecodealliance.org** or via GitHub private security advisories at `github.com/bytecodealliance/wasmtime`. The Bytecode Alliance has a published security policy that covers triage timelines, embargo periods, and disclosure coordination.

Wasmtime's embargo period is notably short: **7 days** from patch-complete to public disclosure. The rationale is explicit in their policy — multi-tenant WASM platforms cannot wait 90 days for a patched runtime when the vulnerability class is sandbox escape. The short embargo puts pressure on runtime consumers to have fast update paths in place before they need them, because when a critical advisory drops, the embargo window has often already elapsed by the time most operators become aware of it.

**Notable Wasmtime CVEs:**

- **CVE-2021-39216** — Stack overflow in Wasmtime reachable from WASM modules via recursive function calls, causing a denial-of-service condition. Fixed by implementing stack depth limits that the WASM specification permits but Wasmtime had not enforced. The fix required careful handling to avoid breaking valid deeply-recursive programs.

- **CVE-2022-24791** — Use-after-free in Wasmtime's component model implementation. A WASM module could trigger a use-after-free condition during certain patterns of host-function interaction, potentially allowing read or write access to freed memory in the host process. Fixed in Wasmtime 0.35.2 and 0.36.0. This advisory is an example of why component model features require the same scrutiny as the core execution engine — additional abstraction layers introduce additional attack surface.

- **CVE-2023-26489** — Miscompilation in Wasmtime's x86-64 backend affecting programs that use WASM's `i64` operations under specific conditions. The Cranelift code generator produced incorrect native code for a class of 64-bit integer operations, potentially allowing out-of-bounds memory access. This is the canonical example of a miscompilation CVE: the WASM source is valid and safe, the compiled native code is not.

The Wasmtime security advisory feed is at `github.com/bytecodealliance/wasmtime/security/advisories`. Subscribe to GitHub notifications for this repository; new advisories appear here within minutes of publication.

**Tracking Wasmtime in Rust applications:**

```bash
# Check which version of Wasmtime your project depends on
cargo tree | grep wasmtime

# Audit your Cargo.lock against known advisories (RustSec database)
cargo audit

# Install cargo-audit if not present
cargo install cargo-audit
```

GitHub Dependabot will automatically open pull requests for new Wasmtime versions if you have a `Cargo.toml` that declares Wasmtime as a dependency and Dependabot is enabled in your repository settings. Combined with `cargo audit` in CI, this gives you two independent signals when a Wasmtime advisory is published.

### V8 Security Disclosure Process

V8 is Google's JavaScript and WebAssembly engine, embedded in Chrome, Node.js, and Deno. Security vulnerabilities are tracked through the Chromium bug tracker at `bugs.chromium.org/p/chromium/issues`. V8-specific issues are filed under the Chromium project and receive `CVE-20xx-xxxxx` identifiers through Google's vulnerability management process.

Finding V8-specific WASM vulnerabilities in the Chromium tracker requires knowing the right labels: bugs tagged `Type-Bug-Security` with component `Blink>JavaScript>WebAssembly` or `V8>WebAssembly` are the most relevant. Security bugs remain restricted (non-public) until patches are merged and a reasonable window has passed for browser updates to propagate. V8's JIT compiler vulnerability patterns fall into a few recurring categories:

- **Type confusion** — the optimising compiler makes an incorrect assumption about the type of a value across a deoptimisation boundary, producing reads or writes that treat a value as a different type than it actually is
- **Speculative execution bugs** — the JIT speculatively executes code based on type feedback, and the speculation can produce out-of-bounds memory access before the guard check fires
- **WASM-specific memory safety** — bugs in the WASM bounds-checking implementation for linear memory accesses, or in the handling of WASM reference types

**Node.js as a V8 consumer:** Node.js security releases are announced at `nodejs.org/en/blog/vulnerability` and tagged with the V8 version bump when the underlying issue is in V8. If a V8 CVE is public and Node.js has not yet released a patched version, your only mitigation is to stop accepting untrusted WASM input until the Node.js patch is available. Subscribe to Node.js security release notifications by watching the `nodejs/node` repository or following `nodejs-sec` on Google Groups.

**Deno as a V8 consumer:** Deno's security advisories appear at `github.com/denoland/deno/security/advisories`. Deno often ships V8 updates faster than Node.js because its release cadence is more frequent and its dependency update process is more automated. When a V8 vulnerability is disclosed, check the Deno changelog for the V8 version bump.

### WasmEdge Security Disclosure

WasmEdge is a CNCF sandbox project and a WASM runtime written in C++, commonly used in cloud-native environments and embedded via the containerd-shim-wasm or in WASI-compliant server-side workloads. Security advisories are published at `github.com/WasmEdge/WasmEdge/security/advisories`.

WasmEdge's C++ codebase introduces memory safety risks that pure-Rust or pure-Go runtimes do not have. Out-of-bounds reads and writes, use-after-free conditions, and integer overflow in memory arithmetic are the primary vulnerability patterns. The CNCF security audit process (WasmEdge underwent a third-party security audit in 2022) helps surface these issues systematically, but the ongoing rate of memory safety bugs in C++ codebases means ongoing vigilance is required.

Track WasmEdge versions via the GitHub releases page and subscribe to GitHub security advisory notifications for the repository. If you deploy WasmEdge via a container image (such as `wasmedge/wasmedge` on Docker Hub), track the image tag and rebuild when a new advisory is published.

### Wazero (Go-Based WASM Runtime)

Wazero ([wazero.io](https://wazero.io), `github.com/tetratelabs/wazero`) takes a different approach: it is implemented entirely in Go with no CGo dependencies, which eliminates an entire class of memory safety vulnerabilities. A pure-Go interpreter and compiler cannot have C-style buffer overflows or use-after-free conditions reachable from the Go runtime's memory model.

Wazero's security advisories are published at `github.com/tetratelabs/wazero/security/advisories`. The vulnerability surface is narrower than C++-based runtimes, but logic bugs in bounds checking and incorrect implementation of WASM specification edge cases are still possible. Security contact is via GitHub private advisory reporting.

For Go applications using Wazero, `govulncheck` (the Go vulnerability scanner) will flag known Wazero vulnerabilities:

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

### Reporting a WASM Runtime Vulnerability

If you discover a potential vulnerability in a WASM runtime, report it privately to the appropriate security contact before any public disclosure. Test only against WASM modules you have authored, in infrastructure you own, with no third-party data at risk. A WASM sandbox-escape vulnerability has immediate impact on any multi-tenant platform running that runtime version — public disclosure before a patch is available hands that capability to attackers.

Your report should include:

- A minimal WASM module (`.wasm` binary or `.wat` text format) that demonstrates the issue
- The host OS, architecture (x86-64, aarch64), and exact runtime version (`wasmtime --version`, Node.js version, WasmEdge version string)
- The observed behaviour: what memory access occurred, what address was accessed, what crash or incorrect output resulted
- The expected behaviour per the WASM specification (linear memory access outside the current memory size must trap)
- Any analysis you have of the root cause — incorrect JIT code generation, missing bounds check, incorrect offset arithmetic

Provide a `wat2wasm`-compiled minimal reproducer where possible. Runtime maintainers need to reproduce the issue reliably before they can diagnose and patch it; a smaller reproducer is faster to triage.

## Consumer Response When a Runtime CVE Drops

### Severity Assessment

The first question is whether the CVE affects your deployment model. WASM runtime CVEs vary in their applicability:

- **Sandbox escape affecting untrusted WASM** — critical if you run any untrusted WASM; does not matter if all your WASM is first-party and compiled by your own team from audited source
- **Denial of service via crafted WASM** — relevant for any deployment that accepts WASM input from outside your control; less relevant for internal-only deployments
- **Host-side memory corruption** — severity depends on what data is accessible in the host process (secrets, tenant data, credentials)
- **Affected architecture** — some vulnerabilities are x86-64-specific; if your production runs on aarch64, assess accordingly

Read the CVE description and associated advisory carefully. Wasmtime advisories include an explicit "Is this applicable to first-party WASM only deployments?" section. If the advisory does not include this, contact the runtime maintainers directly.

### Emergency Response for Multi-Tenant WASM Platforms

If you operate a platform that runs third-party WASM modules and a critical sandbox-escape CVE is published, the response is time-sensitive:

1. **Stop accepting new WASM module submissions** immediately. Do not execute any WASM modules submitted after the CVE was published — a threat actor who read the advisory before you can craft an exploit and submit it.

2. **Apply network-level isolation** to WASM worker processes as an interim control. If your WASM execution layer runs in separate processes or containers, add egress filtering rules to prevent any data exfiltration even if a sandbox escape occurs.

3. **Begin the runtime upgrade** on your lowest-traffic environment first. Run your WASM test suite against the patched runtime before promoting to production.

4. **Monitor for exploitation attempts.** Unusual memory access patterns, crashes in the WASM execution worker, or unexpected process exits in WASM workers are indicators of exploitation. Check your existing WASM worker logs and alerting.

5. **Re-enable module submissions** only after the patched runtime version is deployed and verified across all execution environments.

### Updating Wasmtime in a Rust Application

```toml
# Cargo.toml — bump to the patched version
[dependencies]
wasmtime = "18.0.4"  # replace with the patched version from the advisory
```

```bash
# Update the lockfile to reflect the new version
cargo update -p wasmtime

# Verify the updated version resolves
cargo tree | grep wasmtime

# Build and run your test suite against the patched runtime
cargo test

# Build your release binary
cargo build --release
```

Deploy the new binary and verify the runtime version at startup. Many Wasmtime embedders log the runtime version on initialisation; confirm the log line shows the patched version before marking the deployment complete.

### Updating a Containerised WASM Runtime

```bash
# Pull the patched base image
docker pull wasmedge/wasmedge:0.14.1  # use the patched tag from the advisory

# Rebuild your application image to pick up the new runtime
docker build --no-cache -t myapp:patched .

# Run your integration tests against the rebuilt image
docker run --rm myapp:patched ./run-integration-tests.sh
```

For Kubernetes deployments:

```bash
# Update the image tag in your deployment
kubectl set image deployment/wasm-worker wasm-worker=myapp:patched

# Verify the rollout completes successfully
kubectl rollout status deployment/wasm-worker

# Confirm all pods are running the new image
kubectl get pods -l app=wasm-worker -o jsonpath='{range .items[*]}{.spec.containers[0].image}{"\n"}{end}'
```

Run a health-check against the updated deployment before marking the incident resolved. A regression in the patched runtime (which has occurred with some Wasmtime releases) will show up in your WASM test suite if you run it post-deployment.

### Verifying the Patch

After updating, confirm:

1. The runtime version matches the patched release listed in the advisory
2. Your WASM module test suite passes — runtime updates can occasionally break WASM ABI compatibility in edge cases
3. Any monitoring specific to the CVE's observable effects (crash rates, unexpected trap counts) shows no anomalies

## Expected Behaviour by Runtime

| Runtime | Reporting Channel | Advisory Feed | Consumer Tracking | Emergency Response Time |
|---|---|---|---|---|
| Wasmtime | security@bytecodealliance.org or GitHub private advisory | github.com/bytecodealliance/wasmtime/security/advisories | `cargo audit`, GitHub Dependabot, RustSec DB | 7-day embargo; patch within 48h of advisory |
| V8 (Node.js) | bugs.chromium.org/p/chromium/issues (private) | nodejs.org/en/blog/vulnerability, Node.js GitHub releases | Watch `nodejs/node` releases, `nodejs-sec` Google Group | Node.js release within days of V8 patch |
| V8 (Deno) | bugs.chromium.org/p/chromium/issues (private) | github.com/denoland/deno/security/advisories | Watch `denoland/deno` releases | Deno release typically faster than Node.js |
| WasmEdge | GitHub private advisory (WasmEdge/WasmEdge) | github.com/WasmEdge/WasmEdge/security/advisories | Watch repository releases, GitHub advisory notifications | CNCF coordinated disclosure; patch within embargo window |
| Wazero | GitHub private advisory (tetratelabs/wazero) | github.com/tetratelabs/wazero/security/advisories | `govulncheck`, GitHub advisory notifications | Coordinated disclosure; patch with release |
| Wasmer | No formal process (see wasmer-runtime-security article) | No public advisory feed | Manual commit log monitoring | No notification; monitor releases manually |

## Monitoring for Runtime CVEs

**osv.dev** (Open Source Vulnerabilities database) aggregates advisories from RustSec, GitHub Security Advisories, npm, Go's vuln DB, and PyPI. Search for your runtime package name at `osv.dev` and configure API alerts if your organisation has tooling that consumes the OSV API.

**cargo-audit in CI** — for Wasmtime-based Rust applications, running `cargo audit` in your CI pipeline catches advisories as soon as they land in the RustSec advisory database:

```yaml
# GitHub Actions example
- name: Security audit
  run: |
    cargo install cargo-audit --locked
    cargo audit
```

Run this as a scheduled job (daily) in addition to on every pull request — Wasmtime advisories can drop on any day, not just when you have an open PR.

**GitHub Dependabot** — enable Dependabot for your `Cargo.toml` in `.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: cargo
    directory: /
    schedule:
      interval: daily
    open-pull-requests-limit: 10
```

Dependabot will open a pull request with the patched Wasmtime version within hours of the advisory being published, regardless of whether you have a CI run scheduled.

**Bytecode Alliance security announcements** — the Bytecode Alliance publishes major security announcements at `bytecodealliance.org/articles` and via their Zulip instance. Following the Bytecode Alliance on GitHub (watch the `bytecodealliance/wasmtime` repository for releases and security advisories) provides the earliest notification channel for Wasmtime advisories.

**Node.js security releases** — subscribe to `nodejs-sec@googlegroups.com` for advance notice of Node.js security releases. Security releases are announced there 24-48 hours before publication, giving operators time to prepare update plans.

## Trade-offs

**Short embargo period vs operator patch readiness.** Wasmtime's 7-day embargo means that when a sandbox-escape advisory is published, most operators will see it after the embargo has already elapsed. This is the right policy for the ecosystem — an unpatched sandbox-escape in production for 90 days is worse than a 7-day scramble — but it requires that your runtime update process be fast enough to execute in hours, not weeks. Operators who have never updated their WASM runtime under time pressure will discover process gaps during an actual CVE response; the time to discover those gaps is in a planned exercise, not during an active incident.

**Runtime version pinning vs security updates.** Pinning an exact Wasmtime version in `Cargo.toml` (e.g., `wasmtime = "=17.0.0"`) gives you reproducible builds and protection against unexpected API changes. It also means Dependabot's pull request for the patched version requires a deliberate merge rather than an automatic update. For WASM-based plugin systems running untrusted code, automatic minor-version updates via a permissive version constraint (e.g., `wasmtime = "17"`) with a strong test suite is a better default — the risk of a missed security update outweighs the risk of a runtime behaviour change that your test suite catches.

**Multi-tenant platforms vs lower-risk applications.** The emergency response timeline described above is calibrated for platforms running untrusted WASM from external parties. If your use of a WASM runtime executes only first-party WASM compiled from source you control, the risk profile is different. You still need to update the runtime — a vulnerability in the execution engine can sometimes be exploited by bugs in your own WASM modules triggered by unexpected inputs — but the urgency is lower. Characterise your threat model before writing your incident runbook.

## Failure Modes

**Wasmtime CVE missed because cargo-audit is not in CI.** The most common failure mode: `cargo-audit` is installed on one developer's laptop but not in the CI pipeline, `Cargo.lock` is not committed to the repository (preventing Dependabot from scanning it), and the team relies on manual awareness of security announcements. A Wasmtime advisory is published, patches are available within a day, and the production application continues running the vulnerable version for weeks because no automated signal reaches the team. Mitigation: commit `Cargo.lock`, run `cargo audit` in CI on a daily schedule, enable Dependabot.

**Runtime update breaking WASM ABI compatibility.** Wasmtime occasionally changes behaviour at the boundary between WASM and the host — changes to trap handling, WASI interface adjustments, or component model updates — that require changes to the embedder code, not just to the WASM module. An emergency runtime update performed without running the full WASM test suite can deploy a version that silently changes the behaviour of host functions your WASM modules call. The mitigation is a comprehensive WASM integration test suite that covers your host function implementations, run as a required step before any runtime update is promoted to production.

**Emergency patch causing regression in production WASM workloads.** Security patches, particularly for complex miscompilation bugs, occasionally fix one code path while introducing a regression in another. Wasmtime's release process includes a regression test suite, but coverage is not exhaustive. A patched runtime deployed to production without running workload-representative WASM tests can introduce latent correctness bugs in WASM computation. For platforms where WASM workloads produce business-critical outputs, maintain a regression test corpus of your most important WASM modules and run it as part of every runtime update verification step, even under time pressure from an active CVE.

**Assuming containerisation provides additional isolation.** A WASM sandbox escape that gives the attacker control over the host process does not stop at a container boundary if the container shares the kernel with other workloads. Containers on the same Kubernetes node share the kernel; a sandbox escape that elevates to the host process of a WASM worker container, followed by a kernel exploit, can escape the container. Defence in depth requires that WASM runtime updates be treated as urgent regardless of whether the runtime runs inside containers. Container isolation is a second layer of defence, not a substitute for running patched runtimes.
