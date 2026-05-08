---
title: "WASM in the Browser: Content Security Policy, Origin Isolation, and Subresource Integrity"
description: "Browser-hosted WASM has a distinct attack surface from server-side WASM. CSP directives, cross-origin isolation for SharedArrayBuffer, and SRI hashes prevent XSS-based WASM injection and module substitution."
slug: "wasm-browser-security"
date: 2026-04-30
lastmod: 2026-04-30
category: "wasm"
tags: ["wasm", "browser", "csp", "sri", "cross-origin-isolation"]
personas: ["security-engineer", "platform-engineer", "systems-engineer"]
article_number: 262
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/wasm/wasm-browser-security/index.html"
---

# WASM in the Browser: Content Security Policy, Origin Isolation, and Subresource Integrity

## Problem

Server-side WASM security (Wasmtime, Spin, wasmCloud) is about isolating WASM from the host system. Browser WASM security is about isolating WASM from other browser origins and from XSS attacks — and about preventing malicious WASM from being injected or substituted before it runs.

Browser WASM has a distinct attack surface:

- **`'unsafe-eval'` CSP requirement (legacy):** Older browsers required `WebAssembly.compile` to have `'unsafe-eval'` in the Content Security Policy, opening the door to arbitrary JavaScript execution via `eval()`. Modern browsers support `'wasm-unsafe-eval'` — a narrower permission that allows WASM compilation without enabling `eval()`.
- **WASM module substitution via CDN or MITM:** A WASM module loaded from a CDN can be replaced with a malicious version. Without Subresource Integrity (SRI) hashes on `<script>` or `WebAssembly.instantiateStreaming`, the substitution is undetected.
- **XSS-based WASM injection:** If an attacker achieves XSS, they can use `WebAssembly.compile(new Uint8Array([...]))` to compile and instantiate arbitrary WASM code within the page's origin, bypassing script CSP if `'unsafe-eval'` is present.
- **SharedArrayBuffer and Spectre:** Browser WASM threading requires `SharedArrayBuffer`. `SharedArrayBuffer` requires Cross-Origin Isolation (COOP + COEP headers). Without isolation, `SharedArrayBuffer` is not available — but sites that enable it for threading purposes may not fully understand the Spectre timing channel implications.
- **Wasm module origin leakage:** A WASM module loaded from a third-party origin can be instantiated without CORS headers in some configurations, leaking the module's contents to the loading origin.

**Target systems:** Web applications that ship WASM modules; any browser supporting WebAssembly (all modern browsers since 2017); build toolchains producing `.wasm` (Rust/wasm-pack, Emscripten, AssemblyScript, Go).

## Threat Model

- **Adversary 1 — XSS + WASM compilation:** An attacker achieves XSS on a page with `'unsafe-eval'` in its CSP. They use `WebAssembly.compile` to execute a WASM shellcode payload, bypassing JavaScript-level XSS mitigations (no `<script>` injection needed).
- **Adversary 2 — CDN WASM substitution:** An attacker compromises a CDN serving a `.wasm` file. The application loads `WebAssembly.instantiateStreaming(fetch('/static/app.wasm'))` without an SRI hash. The malicious WASM runs with the page's origin privileges.
- **Adversary 3 — Supply chain via npm/webpack:** A build dependency includes a malicious WASM module. Without hash pinning on WASM artifacts in the build pipeline, the malicious module ships to production.
- **Adversary 4 — Spectre via SharedArrayBuffer timer:** A page enables Cross-Origin Isolation to use `SharedArrayBuffer`. An attacker controls a script in an isolated cross-origin iframe and uses `SharedArrayBuffer` + `Atomics.wait()` to build a high-resolution timer for a Spectre attack against the parent origin.
- **Adversary 5 — WASM module exfiltration via CORS misconfiguration:** A WASM file served with `Access-Control-Allow-Origin: *` can be fetched and read by any origin, exposing proprietary compiled code.
- **Access level:** Adversaries 1 and 3 require XSS or supply chain access. Adversary 2 requires CDN write access. Adversary 4 requires a cross-origin iframe on the target page. Adversary 5 requires only network access.
- **Objective:** Execute arbitrary code in the target page's origin, substitute malicious WASM, leak compiled code, exploit Spectre via timing.
- **Blast radius:** WASM executing in a page's browser context has the same origin privileges as JavaScript — it can read cookies (if not HttpOnly), make same-origin requests, and access the DOM. A malicious WASM module has equivalent impact to a malicious JavaScript payload.

## Configuration

### Step 1: Content Security Policy — `'wasm-unsafe-eval'` not `'unsafe-eval'`

The critical CSP distinction:

```http
# BAD: allows both eval() and WebAssembly.compile()
Content-Security-Policy: script-src 'self' 'unsafe-eval'

# GOOD: allows WebAssembly.compile() without enabling eval()
Content-Security-Policy: script-src 'self' 'wasm-unsafe-eval'
```

`'wasm-unsafe-eval'` is supported in Chrome 95+, Firefox 102+, Safari 16+. For older browser support, you need `'unsafe-eval'` as a fallback — in that case, combine with a strict nonce-based policy to limit the blast radius:

```http
Content-Security-Policy:
  default-src 'none';
  script-src 'self' 'wasm-unsafe-eval' 'nonce-{random}';
  connect-src 'self' https://api.example.com;
  img-src 'self' data:;
  style-src 'self';
  font-src 'self';
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self'
```

Verify CSP is blocking inline eval:

```javascript
// This should throw a CSP violation with 'wasm-unsafe-eval' (no 'unsafe-eval').
try {
  eval("1+1");
  console.error("FAIL: eval() should have been blocked by CSP");
} catch (e) {
  console.log("PASS: eval() blocked by CSP");
}

// This should succeed (WASM compilation is allowed).
const wasmBytes = new Uint8Array([0,97,115,109,1,0,0,0]);
WebAssembly.compile(wasmBytes.buffer).then(() => {
  console.log("PASS: WASM compilation allowed");
});
```

Configure CSP violation reporting to detect policy breaches in production:

```http
Content-Security-Policy-Report-Only: script-src 'self' 'wasm-unsafe-eval'; report-uri /csp-reports
```

Or the modern `Report-To` endpoint:

```http
Content-Security-Policy:
  script-src 'self' 'wasm-unsafe-eval';
  report-to csp-endpoint

Report-To: {"group":"csp-endpoint","max_age":86400,"endpoints":[{"url":"https://csp-reports.example.com/collect"}]}
```

### Step 2: Subresource Integrity for WASM Files

SRI hashes prevent substituted WASM from loading. Include the hash in the HTML:

```html
<!-- For WASM loaded via a <script> module that fetches and instantiates. -->
<script type="module"
  src="/static/app.js"
  integrity="sha384-abc123...def456"
  crossorigin="anonymous">
</script>
```

For WASM fetched directly via JavaScript:

```javascript
// Browser doesn't natively verify SRI on WebAssembly.instantiateStreaming.
// Verify the hash manually before instantiation.
async function loadVerifiedWasm(url, expectedSha256) {
  const response = await fetch(url);
  const buffer = await response.arrayBuffer();

  // Compute SHA-256 of the fetched buffer.
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

  if (hashHex !== expectedSha256) {
    throw new Error(`WASM integrity check failed: expected ${expectedSha256}, got ${hashHex}`);
  }

  return WebAssembly.instantiate(buffer);
}

// Usage with the hash generated at build time.
const { instance } = await loadVerifiedWasm(
  '/static/app.wasm',
  'abc123def456...'  // Generated by the build pipeline.
);
```

Generate SRI hashes in your build pipeline:

```bash
# Generate SHA-384 hash for the WASM file (SRI standard format).
echo "sha384-$(openssl dgst -sha384 -binary dist/app.wasm | openssl base64 -A)"

# Or use the sri-toolbox npm package.
npx sri-toolbox --algorithms sha384 dist/app.wasm
# Output: sha384-abc123...

# Automate in webpack.
# webpack.config.js
const SriPlugin = require('webpack-subresource-integrity');
module.exports = {
  plugins: [
    new SriPlugin({
      hashFuncNames: ['sha384'],
      enabled: process.env.NODE_ENV === 'production',
    }),
  ],
  output: {
    crossOriginLoading: 'anonymous',
  },
};
```

### Step 3: Cross-Origin Isolation for SharedArrayBuffer

Only enable Cross-Origin Isolation if WASM threads genuinely require it. The configuration tightens what cross-origin content the page can include:

```http
# Required headers for crossOriginIsolated === true.
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```

With these headers:

- `window.crossOriginIsolated` returns `true` in JavaScript.
- `SharedArrayBuffer` is available.
- Cross-origin resources (images, fonts, scripts from CDN) must include `Cross-Origin-Resource-Policy: cross-origin` to be loadable.

Verify in the browser before using `SharedArrayBuffer`:

```javascript
if (!crossOriginIsolated) {
  throw new Error("Cross-origin isolation required for WASM threads. Check COOP/COEP headers.");
}

// Safe to use SharedArrayBuffer.
const sharedMem = new WebAssembly.Memory({ initial: 10, maximum: 100, shared: true });
```

Test that your cross-origin resources load correctly after adding COEP:

```bash
# Resources that need updating to work with COEP: require-corp.
# Any cross-origin resource (CDN fonts, images, third-party scripts) must serve:
# Cross-Origin-Resource-Policy: cross-origin

# Check a CDN resource.
curl -I https://cdn.example.com/font.woff2 | grep -i cross-origin-resource-policy
# If missing, the font will be blocked by COEP.
```

For third-party resources that can't be modified, use `crossorigin="use-credentials"` or switch to `credentialless` COEP mode (Chrome 96+):

```http
# Permissive mode: allows cross-origin resources without CORP header.
Cross-Origin-Embedder-Policy: credentialless
```

`credentialless` is a useful intermediate step — it allows cross-origin resources but doesn't send credentials with them, reducing the risk while maintaining compatibility.

### Step 4: WASM-Specific CSP Header in nginx

```nginx
server {
    # Serve WASM files with correct Content-Type.
    location ~* \.wasm$ {
        add_header Content-Type application/wasm;
        add_header Cache-Control "public, max-age=31536000, immutable";

        # Add CORP for WASM files used in isolated contexts.
        add_header Cross-Origin-Resource-Policy "same-site";

        # WASM files are large; enable gzip.
        gzip_types application/wasm;
    }

    # Main application — CSP and isolation headers.
    location / {
        add_header Content-Security-Policy "script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; base-uri 'self'";
        add_header Cross-Origin-Opener-Policy "same-origin";
        add_header Cross-Origin-Embedder-Policy "require-corp";
        add_header X-Content-Type-Options "nosniff";
        add_header X-Frame-Options "DENY";
    }
}
```

### Step 5: WASM Module CORS Configuration

WASM files should not be accessible cross-origin without explicit intent:

```nginx
location ~* \.wasm$ {
    # No CORS headers: WASM only loadable from same origin.
    # If you need cross-origin WASM loading (shared component across subdomains):
    add_header Access-Control-Allow-Origin "https://app.example.com";
    add_header Access-Control-Allow-Methods "GET";
    # Avoid: Access-Control-Allow-Origin: *  — exposes proprietary compiled code.
}
```

For WASM modules containing proprietary business logic, consider serving them from a signed URL with short expiry (AWS S3 presigned, GCS signed URLs) rather than a public path.

### Step 6: Build Pipeline Hash Generation

Generate WASM hashes at build time, not at deploy time:

```makefile
# Makefile
build:
    wasm-pack build --target web --out-dir dist/

sri-hashes:
    @echo "=== WASM SRI Hashes ==="
    @for f in dist/*.wasm; do \
        hash=$$(openssl dgst -sha384 -binary $$f | openssl base64 -A); \
        echo "$$f: sha384-$$hash"; \
    done > dist/sri-hashes.txt

# Include in CI pipeline.
.PHONY: build sri-hashes
```

Store hashes in a manifest file committed alongside the WASM artifacts:

```json
// dist/wasm-manifest.json (committed to the repo)
{
  "generated": "2026-04-30T15:00:00Z",
  "modules": {
    "app.wasm": {
      "sha384": "abc123...",
      "size": 1234567,
      "path": "/static/app.wasm"
    }
  }
}
```

The application reads this manifest at startup and validates WASM modules before instantiation.

### Step 7: CSP Reporting and Monitoring

```javascript
// Collect CSP violation reports to detect WASM injection attempts.
// Violations appear when an attacker tries to compile WASM via eval() in XSS.
const reportEndpoint = new ReportingObserver((reports) => {
  for (const report of reports) {
    if (report.type === 'csp-violation') {
      fetch('/security-events', {
        method: 'POST',
        body: JSON.stringify({
          event_type: 'csp.violation',
          directive: report.body.effectiveDirective,
          blocked_uri: report.body.blockedURI,
          document_uri: report.body.documentURI,
          timestamp: new Date().toISOString(),
        }),
      });
    }
  }
}, { buffered: true });
reportEndpoint.observe();
```

### Step 8: Telemetry

```
csp_violation_total{directive, blocked_uri}              counter
wasm_integrity_check_failure_total{module, expected_hash} counter
cross_origin_isolation_enabled{origin}                   gauge
shared_array_buffer_usage_total{origin}                  counter
wasm_cors_violation_total{origin, wasm_url}              counter
```

Alert on:

- `wasm_integrity_check_failure_total` non-zero — a WASM module hash doesn't match; possible CDN substitution or build pipeline compromise.
- `csp_violation_total{directive="script-src"}` spike — XSS attempts or script injection; investigate the blocked URIs.
- `cross_origin_isolation_enabled == 0` for a page that uses SharedArrayBuffer — the page is using `SharedArrayBuffer` without isolation; Spectre risk.

## Expected Behaviour

| Signal | No WASM security headers | Hardened WASM page |
|--------|--------------------------|-------------------|
| XSS + eval() | Allows arbitrary WASM compilation | `'wasm-unsafe-eval'` blocks `eval()`; WASM still compiles |
| CDN WASM substitution | Malicious module runs silently | SRI hash mismatch; module refused to load |
| SharedArrayBuffer available | Only with `'unsafe-eval'` (old) or isolation (new) | Only when COOP+COEP headers confirm isolation |
| Cross-origin WASM read | Possible if CORS is misconfigured | Restricted to same origin by default |
| Proprietary WASM exposed | Publicly accessible at known URL | CORS restricted; consider signed URL for sensitive modules |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| `'wasm-unsafe-eval'` CSP | Blocks eval() attacks; allows WASM | Browser support (Chrome 95+, Firefox 102+, Safari 16+) | Support is universal among modern browsers; only legacy browsers need `'unsafe-eval'`. |
| SRI on WASM | Prevents substitution | Hash must be updated on every WASM rebuild | Automate hash generation in CI; include in the build artifact. |
| COEP: require-corp | Strong cross-origin isolation | All cross-origin resources must serve CORP header | Use `credentialless` as a transitional step; fix resources without CORP over time. |
| Same-origin WASM CORS | Prevents proprietary code leak | Cannot share WASM module across subdomains | Use same-site CORS (`Access-Control-Allow-Origin: https://app.example.com`) for subdomain sharing. |
| CSP violation reporting | Visibility into injection attempts | Report endpoint receives all violations (including benign) | Filter on directive in the report handler; alert only on `script-src` and `wasm-unsafe-eval` violations. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| COEP breaks third-party resources | Images, fonts, or scripts from CDN fail to load | Browser console shows COEP blocking; UI broken | Add `Cross-Origin-Resource-Policy: cross-origin` to the CDN resource; or switch to `COEP: credentialless`. |
| SRI hash outdated after rebuild | WASM fails to load; browser logs integrity mismatch | Console error: `Integrity check failed`; application broken | Regenerate hashes in CI on every build; update the manifest before deploying. |
| CSP blocks legitimate WASM instantiation | WASM module fails to compile; application broken | Console error: CSP blocks WebAssembly; `csp_violation_total` rises | Add `'wasm-unsafe-eval'` to `script-src` in the CSP. |
| SharedArrayBuffer unavailable without isolation | WASM threads fall back to single-threaded | Application performance degraded; `crossOriginIsolated === false` | Add COOP + COEP headers; verify all cross-origin resources serve CORP. |
| Proprietary WASM accessible publicly | Competitor can download and reverse-engineer compiled module | No direct alert; discovered by audit | Restrict CORS; serve from signed URLs with short expiry; strip debug symbols from WASM. |
| CSP report flood during attack | Report endpoint overwhelmed with XSS attempt reports | Report endpoint latency spike; report queue backs up | Rate-limit reports per origin; sample at 10% during spikes; use server-side buffering. |

## Related Articles

- [WASM Threads and Shared Memory Security](/articles/wasm/wasm-threads-shared-memory/)
- [WASM Static Analysis and Vulnerability Scanning](/articles/wasm/wasm-static-analysis/)
- [WASM OCI Module Signing and Verification](/articles/wasm/wasm-oci-signing/)
- [HTTP Security Headers](/articles/network/http-security-headers/)
- [Encrypted Client Hello and TLS Privacy](/articles/network/encrypted-client-hello/)
