---
title: "jco JavaScript/WASM Component Model Security"
description: "Understand the security model of jco-transpiled WASM components running in Node.js and Deno, including capability leakage risks, host function exposure, and jco's lack of a formal CVE process."
slug: jco-wasm-component-security
date: 2026-05-02
lastmod: 2026-05-02
category: wasm
tags: ["jco", "wasm", "component-model", "wasi", "node-js", "deno", "capability-security", "javascript"]
personas: ["security-engineer", "platform-engineer", "systems-engineer"]
article_number: 374
difficulty: advanced
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/wasm/jco-wasm-component-security/index.html"
---

# jco JavaScript/WASM Component Model Security

## Problem

`jco` is the Bytecode Alliance's official JavaScript toolchain for the WebAssembly Component Model. Its primary function is transpilation: given a `.wasm` component built against WASI Preview 2 interfaces, `jco transpile` produces a JavaScript module that implements the same exported interface. The resulting JavaScript can be imported directly in Node.js, Deno, or a browser — no separate WASM runtime like Wasmtime is required, and the component's WASI imports are serviced by a JavaScript shim (`@bytecodealliance/preview2-shim`) that calls into the host runtime's built-in APIs. WASI Preview 2 reached its stable release (v0.2.11) on April 7, 2026. That milestone significantly increased the number of production deployments using jco as the bridge between WASM components and JavaScript runtimes.

The security model of jco-transpiled components is fundamentally different from the security model of the same component running under Wasmtime. When Wasmtime hosts a WASM component, the component executes inside a memory-safe sandbox enforced at the engine level: WASM linear memory is isolated from host memory, capability handles are opaque integers managed by the runtime, and any attempt to violate those boundaries causes a hardware-level trap. The component cannot touch anything the host has not explicitly granted. This sandbox is not a convention — it is enforced by Wasmtime's JIT/interpreter before the component's first instruction executes.

When jco transpiles that same component to JavaScript and runs it in Node.js, the sandbox is V8's JavaScript context. V8 provides memory safety and a prototype-chain-based isolation model, but it is not a capability sandbox. The transpiled JavaScript module runs in the same Node.js process as the host application. If the host application has access to `fs`, `net`, `http`, and `child_process`, those capabilities are available to any code running in the same context unless they are explicitly not passed to the component. The security guarantee is: "we only call the functions you gave us" — that is, the generated code only exercises the capability objects the host provides at invocation time. This shifts security responsibility from the runtime enforcement layer (Wasmtime) to the correctness of jco's code generation and the discipline of the host application developer.

The capability leakage risk follows directly from this model. WASI Preview 2 is a capability-based interface specification: a component declares its WASI imports (e.g., `wasi:filesystem/types`, `wasi:http/outgoing-handler`), and the host is supposed to satisfy those imports with scoped, limited capability objects. In Wasmtime, the host passes a directory handle scoped to a specific path; Wasmtime enforces that the component cannot escape that scope. In jco, the `preview2-shim` translates the component's WASI filesystem calls into Node.js `fs` calls. The scoping is implemented in JavaScript — in the shim code that maps WASI directory handles to Node.js paths. If that shim code contains a bug in path normalization, a component compiled to access only `/data/input/` might be able to read `/data/` or `/` through a crafted sequence of WASI calls.

This is the central operational concern with jco: jco is maintained by the Bytecode Alliance with a small core team, and as of May 2026, the project has no `SECURITY.md` file at `https://github.com/bytecodealliance/jco`. There is no documented process for reporting security vulnerabilities, no CVE contact address, and no history of GHSA (GitHub Security Advisory) records filed against the repository. The project distributes via the `@bytecodealliance/jco` npm package, which also has no security advisory history on the npm registry. This means that when capability-handling bugs are found and fixed, they are documented only in the git CHANGELOG and commit history — as ordinary bug fixes, not as security advisories. Commits touching `packages/preview2-shim/` and `src/api/` with messages like "fix wasi:filesystem directory handle scope" or "correct wasi:http response body cleanup" are potentially security-relevant (a directory handle scope error could give a component access to directories it should not see), but they receive no CVE assignment, no advisory, and no coordinated disclosure. Downstream operators who pin jco versions may be unaware that a specific point release contains a security-significant fix.

The WASI Preview 2 stable release raises the urgency. Before v0.2.11, WASI Preview 2 was pre-release and most production deployments ran WASM components under Wasmtime or WasmEdge — native runtimes with established security boundaries. Now that the interfaces are stable, the component model is entering wider production use in JavaScript environments through jco, and Preview 3 (which adds async/threads to the component model) is in active development. The security model of WASI interfaces is evolving faster than the security posture of the tooling that implements them in JavaScript.

Target systems: jco 1.x running in Node.js 20+/22+ or Deno 1.4x+; WASM components using WASI Preview 2 interfaces (`wasi:filesystem`, `wasi:http`, `wasi:sockets`, `wasi:cli`).

## Threat Model

1. **Capability scope leak (correctness failure with security consequences)**: A bug in jco's `wasi:filesystem/preopens` binding generates JavaScript that resolves directory handles without correctly restricting the path to the component's granted preopens. A WASM component compiled to access only `/data/tenant-a/` gains read access to `/data/` or the entire filesystem via the leaked handle. This is not a deliberate attack — it is a code generation correctness error. The attacker surface is the jco transpiler itself. Any component running on the affected jco version can trigger the leak by exercising normal WASI filesystem operations. In a multi-tenant deployment where different customers' WASM components run in the same Node.js process with different preopens, this failure gives one tenant's component access to another tenant's files.

2. **Malicious component exploiting a jco HTTP body handling bug**: A component that sends a specially crafted `wasi:http` response triggers a defect in jco's HTTP body shim — specifically, a response body buffer that is not properly reset between requests. The Node.js HTTP module exposes the response body of a previous request to the current component. In a multi-tenant jco runtime where multiple components share an HTTP client capability, this is a cross-request data leakage: secrets, session tokens, or credentials from a prior response are readable by the attacking component. The WASM component itself does not need to exploit a memory-safety bug; it only needs to interact with the jco shim in a way that triggers the defect.

3. **No-CVE-process gap exploitation**: A security researcher monitors `https://github.com/bytecodealliance/jco/commits/main` and identifies a commit titled "fix directory handle scope in preopens shim." Because jco has no CVE process and no security advisory, this fix ships quietly in a patch release. The researcher constructs a WASM component that exercises the pre-fix code path and submits it to a multi-tenant jco runtime that has not yet updated. Because there was no advisory, the operator did not know to treat this release as security-critical. The component gains access to filesystem handles belonging to other tenants. The gap between commit landing and operator awareness is the attack window — and that window is undefined when there is no advisory to close it.

4. **Supply chain: compromised `@bytecodealliance/jco` npm package**: jco is distributed exclusively via npm as `@bytecodealliance/jco`. A compromised npm account for the `@bytecodealliance` organization scope could publish a backdoored jco version that modifies the transpilation output — injecting code into every WASM component transpiled with that version. Unlike a runtime vulnerability, this attack propagates through build pipelines: every team that runs `jco transpile` with the compromised version ships backdoored JavaScript. As of May 2026, jco packages are not published with npm provenance attestation linking the npm artifact to the source repository commit and CI run. There is no way to cryptographically verify that the installed `@bytecodealliance/jco` package was built from the source you reviewed.

The blast radius of a jco capability-handling bug scales with the number of tenants sharing a Node.js process and the breadth of capabilities passed to the transpiled component. A single-tenant deployment where jco components run in isolated Worker Threads with narrowly scoped capabilities has a blast radius of one. A multi-tenant deployment where all components share a single Node.js process with a broadly scoped `fs` handle has a blast radius equal to all tenants on that process.

## Configuration / Implementation

### Understanding jco's sandbox model vs. Wasmtime

Before writing any code, document the security boundary difference for your team. The core principle: jco-transpiled components running in a Node.js process are NOT isolated from the host process in the way Wasmtime-hosted components are. They share the V8 context. The security model depends on:

1. What capability objects the host passes to the component at invocation time.
2. The correctness of jco's code generation in restricting those capabilities.
3. Process-level isolation between components (Worker Threads).

Use Wasmtime (or WasmEdge) for security-sensitive server-side execution. Use jco for browser-compatible WASM, development and testing, non-I/O computation, and deployments where browser portability outweighs the need for native sandbox enforcement.

| Use case | Recommended runtime |
|---|---|
| Browser-portable WASM component | jco (only option) |
| Development and testing of components | jco (faster iteration) |
| Components with no WASI I/O | jco (no capability risk) |
| Multi-tenant isolation, credentials, PII | Wasmtime / WasmEdge |
| Server-side sandboxed execution | Wasmtime / WasmEdge |
| Production components with WASI filesystem/HTTP | Wasmtime preferred; jco with Worker Thread isolation |

### Capability scoping in jco host code

When invoking a jco-transpiled component, construct minimal capability objects rather than passing broad system handles. The `preview2-shim` package exports individual WASI interface implementations that can be scoped at construction time.

```javascript
// BAD: passing broad, unscoped capabilities
import { MyComponent } from './transpiled.js';
import * as preview2 from '@bytecodealliance/preview2-shim';

// This passes the full filesystem shim — component can access anything
// the Node.js process can access if there is a scoping bug in the shim
const result = await MyComponent.run(preview2);
```

```javascript
// GOOD: constructing scoped capability objects
import { MyComponent } from './transpiled.js';
import { filesystem } from '@bytecodealliance/preview2-shim';
import path from 'node:path';

const TENANT_ROOT = path.resolve('/data/tenant-a/');

// Build a scoped filesystem capability: only the tenant's directory
const scopedFs = filesystem.buildPreopens([
  { dir: TENANT_ROOT, name: '/' }
]);

// Pass only the capabilities the component needs; null out the rest
const result = await MyComponent.run({
  filesystem: scopedFs,
  http: null,        // component does not need HTTP
  sockets: null,     // component does not need sockets
  cli: null
});
```

The key discipline: default to `null` for every WASI capability and only grant what the component's WIT interface documents as required.

### Validating preopens before passing to a jco component

Before passing a filesystem preopens to a jco component, validate that the resolved path is within the expected scope. This is a defense-in-depth check against a jco path-handling bug.

```javascript
import path from 'node:path';

function buildScopedPreopens(requestedPath, allowedRoot) {
  const resolved = path.resolve(requestedPath);
  const allowed = path.resolve(allowedRoot);

  // Ensure resolved path is strictly within allowedRoot
  if (!resolved.startsWith(allowed + path.sep) && resolved !== allowed) {
    throw new Error(
      `Preopen path '${resolved}' is outside allowed root '${allowed}'`
    );
  }

  return [{ dir: resolved, name: '/' }];
}

// Usage
const preopens = buildScopedPreopens('/data/tenant-a/uploads', '/data/tenant-a');
```

After transpiling, inspect the preopens handling in the generated code:

```bash
# Audit the preopens binding in the transpiled output
grep -A 10 "preopens" transpiled.js

# Look for path resolution calls that might not be scoped
grep -n "resolve\|join\|normalize\|readdir\|opendir" transpiled.js | head -40
```

### Node.js Worker Thread isolation per component

The strongest mitigation for a jco capability-scope bug in a multi-tenant deployment is running each component in a dedicated Worker Thread. Worker Threads have separate V8 contexts — a capability leak within one Worker Thread cannot directly expose data to another Worker Thread's memory space.

```javascript
// host.js — spawns a Worker Thread per component invocation
import { Worker } from 'node:worker_threads';
import path from 'node:path';

function runComponent(componentPath, inputData, tenantId) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(
      path.resolve('./run-component-worker.js'),
      {
        workerData: {
          componentPath,
          inputData,
          tenantId,
          allowedRoot: path.resolve(`/data/${tenantId}/`)
        },
        // Memory limit: prevents a runaway component from exhausting host memory
        resourceLimits: {
          maxOldGenerationSizeMb: 256,
          maxYoungGenerationSizeMb: 64
        }
      }
    );

    worker.on('message', resolve);
    worker.on('error', reject);
    worker.on('exit', (code) => {
      if (code !== 0) {
        reject(new Error(`Worker exited with code ${code}`));
      }
    });
  });
}
```

```javascript
// run-component-worker.js — executed inside the Worker Thread
import { workerData, parentPort } from 'node:worker_threads';
import path from 'node:path';
import { filesystem } from '@bytecodealliance/preview2-shim';

const { componentPath, inputData, tenantId, allowedRoot } = workerData;

async function main() {
  // Dynamically import the transpiled component
  const { default: component } = await import(componentPath);

  // Build scoped filesystem capability inside the Worker
  const scopedFs = filesystem.buildPreopens([
    { dir: allowedRoot, name: '/' }
  ]);

  const result = await component.run({
    filesystem: scopedFs,
    http: null,
    sockets: null
  }, inputData);

  parentPort.postMessage(result);
}

main().catch((err) => {
  console.error(`[tenant:${tenantId}] component error:`, err.message);
  process.exit(1);
});
```

Worker Thread isolation is not free: each Worker Thread has a startup cost (V8 context initialization) and a memory overhead of roughly 10–30 MB for the Node.js runtime. For high-frequency, short-lived component invocations, pool Worker Threads rather than spawning one per request.

### Pinning jco by exact version and verifying the package

Because jco has no CVE process and fixes can land silently, pinning by semver range (`^1.x`) is insufficient. Pin to an exact version and commit `package-lock.json`:

```bash
# Install a specific jco version (no caret or tilde)
npm install --save-exact @bytecodealliance/jco@1.7.3
npm install --save-exact @bytecodealliance/preview2-shim@0.17.1

# Verify the installed package integrity hash matches your known-good value
# Get the hash of the currently installed version:
cat node_modules/@bytecodealliance/jco/package.json | node -e \
  "const d=require('/dev/stdin','utf8'); process.stdout.write(JSON.stringify(JSON.parse(d).version)+'\n')"

# Check npm audit for known vulnerabilities in jco and its dependency tree
npm audit --audit-level=moderate
```

Commit `package-lock.json` to source control. In CI, use `npm ci` (not `npm install`) to install from the lockfile without modifying it.

For build pipelines that transpile WASM components with `jco`, run the transpile step in CI rather than shipping pre-transpiled output. Verify the jco binary hash before transpiling:

```bash
# In CI: verify jco binary matches expected SHA-256 before running transpile
JCO_PATH="$(npm root)/.bin/jco"
EXPECTED_SHA="<sha256 of known-good jco binary>"
ACTUAL_SHA="$(sha256sum "$JCO_PATH" | awk '{print $1}')"

if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
  echo "ERROR: jco binary hash mismatch. Expected $EXPECTED_SHA, got $ACTUAL_SHA"
  exit 1
fi

npx jco transpile component.wasm --out-dir ./transpiled
```

### Monitoring jco for capability-related fixes

Because jco has no formal security advisory channel, monitoring the commit stream is the only way to detect security-relevant fixes before they are documented.

```bash
# Query recent jco commits that touch WASI capability-related code
gh api repos/bytecodealliance/jco/commits \
  --jq '.[] | select(.commit.message | test("wasi|capability|handle|scope|leak|preopens|socket|http|filesystem"; "i")) | {sha: .sha[0:8], msg: .commit.message}'

# Watch commits specifically in the preview2-shim and api directories
gh api "repos/bytecodealliance/jco/commits?path=packages/preview2-shim/lib" \
  --jq '.[0:10] | .[] | {sha: .sha[0:8], msg: .commit.message, date: .commit.committer.date}'

gh api "repos/bytecodealliance/jco/commits?path=src/api" \
  --jq '.[0:10] | .[] | {sha: .sha[0:8], msg: .commit.message, date: .commit.committer.date}'
```

Add these checks to a scheduled CI job that runs daily and posts results to your security channel. Key directories to watch:

- `packages/preview2-shim/lib/io/` — I/O handle lifecycle
- `packages/preview2-shim/lib/nodejs/sockets.js` — TCP/UDP socket shim
- `packages/preview2-shim/lib/nodejs/filesystem.js` — filesystem preopens shim
- `packages/preview2-shim/lib/nodejs/http.js` — HTTP outgoing/incoming handler

Also use Renovate or Dependabot to track new `@bytecodealliance/jco` releases. Configure Renovate to require manual approval for jco updates and to post a diff of the `packages/preview2-shim/` directory to your security channel on each version bump.

Subscribe to the Bytecode Alliance blog (`https://bytecodealliance.org/articles`) for jco release announcements, and watch the `bytecodealliance/jco` GitHub repository for any future addition of a `SECURITY.md` — which would signal the project is formalizing its security disclosure process.

## Expected Behaviour

| Signal | jco-transpiled in shared Node.js process | Worker Thread isolation + scoped capabilities |
|---|---|---|
| Filesystem handle scope escape (jco bug) | Component reads files outside its preopens directory; data from other tenants leaks | Worker Thread contains the leak to one tenant; scoped preopen validation throws before the handle reaches the shim |
| Cross-tenant data leak via HTTP body shim bug | Previous response body accessible to current component invocation in shared process | Each Worker Thread has its own shim state; no shared HTTP buffer between tenants |
| Worker Thread memory limit hit | N/A (process-level limit only) | Worker exits with code 1; host receives `Error: Worker exited with code 1`; other tenants unaffected |
| jco version bump with silent capability fix | Operator unaware; old behavior may persist if `npm ci` not run after update | Same; monitoring script detects new commits in `preview2-shim/`; Renovate opens PR for review |
| npm provenance check for `@bytecodealliance/jco` | `npm install` succeeds without provenance warning; no attestation available as of May 2026 | Same; use digest pinning and CI hash verification as compensating control |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Worker Thread per component | V8 context isolation between tenants; memory limit enforcement; component crash does not kill host process | 10–30 MB memory overhead per Worker; V8 context startup latency (~50–150 ms for cold start) | Worker Thread pool with pre-warmed threads for high-frequency invocations |
| Scoped capabilities (null out unused WASI interfaces) | Reduces blast radius of a jco shim bug to only capabilities actually granted | Requires explicit knowledge of each component's WASI imports; breaks if component WIT evolves without host update | Read the component's WIT files and generate the capability map from them; include WIT diffing in CI |
| jco vs. Wasmtime | Browser compatibility; no native binary dependency; works in serverless environments without custom layers | No engine-level sandbox enforcement; security depends on shim correctness; no formal CVE process | Use Wasmtime for server-side security-sensitive components; jco only where browser portability is required |
| Digest pinning of jco (`--save-exact`) | Prevents unexpected jco updates that could introduce regressions or (in the supply chain attack scenario) malicious code | Blocks automatic uptake of security fixes; operator must manually review and update jco pins | Daily Renovate PRs for jco; security channel notification on new releases; fast-track update process for fixes confirmed via commit review |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Worker Thread `maxOldGenerationSizeMb` too low | Component OOMKilled mid-execution; Worker exits with code 1; host rejects request with generic error | Increase heap limit temporarily and profile component memory usage with `--expose-gc` and `process.memoryUsage()` inside the Worker | Raise `maxOldGenerationSizeMb` for that component class; add per-component memory limit configuration; alert if Worker exits with code 1 more than N times in a window |
| Overly restrictive capability scope | Component fails with WASI errno `not-permitted` or `no-such-file` on a legitimate file access; component returns error for valid input | Component error logs show WASI capability errors; compare component's WIT imports against the capability map passed at invocation | Audit the component's WIT file for all `wasi:filesystem` and `wasi:http` imports; expand preopen or grant the missing capability; re-validate preopens path scope after widening |
| jco version bump breaks transpiled component API | Import of transpiled component fails with `TypeError: component.run is not a function` or exported function signature mismatch | CI transpile step fails; integration test suite catches missing or renamed exports | Pin jco to the last working version; re-transpile from source `.wasm` with the new jco version; check jco CHANGELOG for breaking changes to component bindings generation; test transpiled output in CI before promoting to production |
| npm audit false positive on transitive jco dependency | `npm audit` reports a critical vulnerability in a package that jco depends on (e.g., a parser used only during transpilation, not at runtime) | Audit output includes package name and CVE; check whether the vulnerable code path is reachable in jco's runtime use (not just build-time transpile use) | Run `npm audit --only=prod` to separate runtime from devDependency advisories; if vulnerability is in a transpile-time-only dependency, document as accepted risk with expiry date; open issue upstream in jco to update the dependency |

## Related Articles

- [WASM Component Model Security Boundaries](/articles/wasm/wasm-component-model-security/)
- [WASI Preview 2 Capabilities and Sandboxing](/articles/wasm/wasi-preview-2-capabilities/)
- [WASM Browser Security](/articles/wasm/wasm-browser-security/)
- [WASM Multi-Tenancy Isolation](/articles/wasm/wasm-multi-tenancy/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
