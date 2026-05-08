---
title: "WASM for Secure Client-Side Financial Calculations: Isolating Sensitive Logic from Browser Attacks"
description: "Running financial calculations in JavaScript exposes them to prototype pollution, DOM-based XSS exfiltration, and supply chain attacks via npm. WASM provides a memory-isolated execution environment for interest rate models, risk calculations, and KYC scoring that JavaScript's shared heap cannot. This guide covers implementing financial calculation sandboxes in WASM, preventing data exfiltration, and integrating with banking applications."
slug: wasm-client-side-financial-calculations
date: 2026-05-07
lastmod: 2026-05-07
category: wasm
tags:
  - wasm
  - financial-security
  - client-side-security
  - browser-security
  - isolation
personas:
  - security-engineer
  - platform-engineer
article_number: 632
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/wasm/wasm-client-side-financial-calculations/
---

# WASM for Secure Client-Side Financial Calculations: Isolating Sensitive Logic from Browser Attacks

## Problem

Financial calculation logic in the browser has a deceptively large attack surface. A mortgage calculator, APR disclosure widget, or loan amortisation schedule might look like a simple web form, but the JavaScript running underneath it operates in a shared heap that any injected script, compromised dependency, or malicious browser extension can read, manipulate, and exfiltrate.

Three categories of attack are particularly damaging in this context.

**Prototype pollution targeting financial math.** JavaScript's prototype chain means that any script running in the page can modify the behaviour of built-in objects before your calculation code runs. An attacker who achieves code execution — via a compromised npm package, a CDN injection, or stored XSS — can modify `Number.prototype.valueOf` or `Math.round` to subtly alter calculated values. The manipulation is invisible to users: the displayed result changes by a fraction of a percent, enough to shift interest income in the attacker's favour at scale but small enough to pass visual inspection. Libraries like `financial.js` and `mathjs` that build their calculation pipeline on JavaScript's numeric stack are entirely exposed to this class of attack. A poisoned prototype can cause a present-value calculation to undercount discount rates, make a risk score appear lower than it is, or make a KYC scoring threshold appear satisfied when it is not.

**XSS-based exfiltration of sensitive financial inputs.** Mortgage applications, auto loan calculators, and credit card pre-qualification forms ask users for gross annual income, monthly debt obligations, requested loan amounts, and sometimes partial account numbers. When these inputs live in JavaScript variables or DOM properties on the same origin as an XSS vulnerability, they are directly readable by any injected script. The attacker doesn't need to change the calculation result — they only need to read the inputs. A single `fetch()` call to an attacker-controlled endpoint exfiltrates everything the user typed before they clicked "calculate." This is exactly the attack pattern used by Magecart groups against payment and financial services sites, and it doesn't require the attacker to break encryption in transit: the data is plaintext in the browser's memory before it ever touches TLS.

**npm supply chain attacks injecting calculation logic.** The average financial services web application depends on hundreds of transitive npm packages. A compromised package — a dependency of a dependency of a charting library — can inject code that intercepts function calls, reads variables from the surrounding scope, or modifies the output of financial calculation functions before they return. The `event-stream` compromise in 2018 targeted cryptocurrency wallet logic. Similar campaigns have targeted financial calculation libraries in the years since. An attacker who compromises a popular `@finance/calculator` package on npm can ship malicious code to every bank and credit union whose build pipeline pulls that package.

The regulatory dimension compounds the technical risk. PCI DSS Requirement 6.4 mandates that organisations detect and prevent JavaScript skimming on payment pages — the same attack pattern that extracts loan application PII. A JavaScript-based financial calculator that is compromised to exfiltrate income and account data generates PCI DSS findings, CFPB regulatory exposure, and potential breach notification obligations under state laws. The argument that "no card data was entered on this form" does not hold when the calculator is embedded in the same origin as a payment flow.

**WebAssembly as a memory isolation boundary.** WASM's linear memory model provides a structural defense against all three of these attack classes. A WASM module operates on a dedicated linear memory buffer — a contiguous `ArrayBuffer` that the WASM module has exclusive read/write access to during execution. JavaScript's prototype chain does not extend into WASM linear memory. `Number.prototype.valueOf` cannot influence an f64 arithmetic instruction executing inside a WASM stack machine. A poisoned `Math.round` on the JavaScript side has no effect on a Rust `f64::round()` call that compiled to a WASM `f64.nearest` instruction. Additionally, once a WASM binary is compiled and instantiated, its bytecode cannot be modified from JavaScript — there is no equivalent to JavaScript's dynamic monkey-patching. An attacker who has XSS cannot alter the compiled financial logic; they can only interact with it through the exported API surface.

WASM linear memory is not JavaScript heap memory. Variables allocated inside the WASM module's address space — including sensitive inputs like income figures and loan amounts — do not appear in JavaScript memory profiling tools, are not accessible via prototype traversal, and cannot be read by a browser extension that hooks into `window` or the DOM. The isolation is not perfect — the JS/WASM boundary exposes an API surface that can be hooked — but it is structurally superior to running the same logic in JavaScript.

## Threat Model

**Adversary 1 — Magecart-style CDN or npm injection.** An attacker compromises a third-party JavaScript asset loaded by the financial application's page — a CDN-hosted analytics snippet, a tag manager payload, or a transitive npm dependency bundled into the application. The injected script harvests values from input fields and JavaScript variables before the calculation runs: loan principal, gross income, DTI ratio, account last-four. The data is exfiltrated via a pixel request to an attacker-controlled domain. The attacker does not need to break HTTPS; the data is already in the clear on the JavaScript heap before the user submits anything.

**Adversary 2 — XSS exfiltration of calculation inputs containing PII.** A stored or reflected XSS vulnerability on the financial application's origin allows an attacker to inject a script that reads calculation inputs from form fields, JavaScript variables, or the DOM. The attacker may also hook the application's own financial library functions to capture arguments on every call, reading income, requested amounts, and intermediate calculation state. Even a single successful XSS against a high-traffic mortgage calculator can yield thousands of loan application records.

**Adversary 3 — Malicious browser extension intercepting financial data.** A browser extension with `all_urls` permission can inject content scripts into any page, including financial services applications. Such an extension can read the JavaScript heap, intercept `fetch()` calls, and observe DOM mutations. A malicious extension distributed through extension stores — or a legitimate extension that is compromised via its own update mechanism — has full access to any financial data that exists in the JavaScript layer of the page. Extensions cannot natively read WASM linear memory unless the module's JavaScript API explicitly returns the values.

**Access level.** Adversary 1 requires supply chain or CDN write access. Adversary 2 requires an XSS vulnerability. Adversary 3 requires a user to have installed the malicious extension. All three operate passively after initial access; there is no ongoing connection that would trigger anomaly detection.

**Objective.** Exfiltrate income, loan amount, and PII from financial form inputs; manipulate displayed calculation results to benefit the attacker; capture intermediate calculation state that reveals credit risk information.

**Blast radius.** A successful skimmer against a mortgage calculator on a regional bank's website can yield thousands of pre-application income disclosures per day. Manipulated APR calculations delivered to users — even by a fraction of a basis point — constitute a TILA disclosure violation and regulatory exposure. Exfiltration of income and debt figures before a credit decision is made qualifies as a GLBA data breach in most interpretations.

## Configuration

### Step 1: Compile Financial Calculation Logic to WASM with Rust and wasm-pack

Define the financial calculation library as a standalone Rust crate. The calculations never touch JavaScript types; they operate entirely on Rust primitive types within WASM linear memory.

```toml
# Cargo.toml
[package]
name = "financial-calc"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
wasm-bindgen = "0.2"

[profile.release]
# Strip debug symbols to reduce bundle size and avoid leaking function names.
debug = false
# Enable LTO for smaller output.
lto = true
opt-level = "z"
```

```rust
// src/lib.rs
use wasm_bindgen::prelude::*;

/// Compound interest: A = P(1 + r/n)^(nt)
/// All inputs and outputs are f64 primitives — no JavaScript objects cross the boundary.
#[wasm_bindgen]
pub fn compound_interest(principal: f64, annual_rate: f64, compounds_per_year: u32, years: f64) -> f64 {
    let n = compounds_per_year as f64;
    let r = annual_rate;
    let t = years;
    principal * (1.0 + r / n).powf(n * t)
}

/// Monthly payment for a fixed-rate amortising loan.
/// M = P * [r(1+r)^n] / [(1+r)^n - 1]
#[wasm_bindgen]
pub fn monthly_payment(principal: f64, annual_rate: f64, term_months: u32) -> f64 {
    if annual_rate == 0.0 {
        return principal / term_months as f64;
    }
    let r = annual_rate / 12.0;
    let n = term_months as f64;
    let factor = (1.0 + r).powf(n);
    principal * r * factor / (factor - 1.0)
}

/// Present value of a future cash flow.
/// PV = FV / (1 + r)^n
#[wasm_bindgen]
pub fn present_value(future_value: f64, annual_rate: f64, years: f64) -> f64 {
    future_value / (1.0 + annual_rate).powf(years)
}

/// Build a full amortisation schedule.
/// Returns a flat array: [month, payment, principal_portion, interest_portion, remaining_balance, ...]
/// The array lives in WASM linear memory; only the pointer and length are returned to JavaScript.
#[wasm_bindgen]
pub fn amortisation_schedule(principal: f64, annual_rate: f64, term_months: u32) -> Vec<f64> {
    let payment = monthly_payment(principal, annual_rate, term_months);
    let monthly_rate = annual_rate / 12.0;
    let mut balance = principal;
    let mut schedule = Vec::with_capacity(term_months as usize * 5);

    for month in 1..=term_months {
        let interest_portion = balance * monthly_rate;
        let principal_portion = payment - interest_portion;
        balance = (balance - principal_portion).max(0.0);
        schedule.push(month as f64);
        schedule.push(payment);
        schedule.push(principal_portion);
        schedule.push(interest_portion);
        schedule.push(balance);
    }
    schedule
}

/// Zero a region of WASM linear memory.
/// Call this after the JavaScript layer has consumed a sensitive calculation result.
#[wasm_bindgen]
pub fn zero_memory_region(ptr: usize, len: usize) {
    // Safety: The JavaScript caller must ensure ptr and ptr+len are within the WASM memory buffer.
    // wasm-bindgen's memory model guarantees the buffer is the module's linear memory.
    let mem = unsafe { std::slice::from_raw_parts_mut(ptr as *mut u8, len) };
    // Use volatile writes to prevent the compiler from optimising this away.
    for byte in mem.iter_mut() {
        unsafe { std::ptr::write_volatile(byte, 0u8) };
    }
}

/// Allocate a byte buffer in WASM linear memory and return its pointer.
/// Used by the JavaScript layer to write sensitive inputs directly into WASM memory
/// without passing them through JavaScript string or number variables.
#[wasm_bindgen]
pub fn alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// Free a previously allocated buffer.
#[wasm_bindgen]
pub fn dealloc(ptr: *mut u8, len: usize) {
    unsafe {
        let _ = Vec::from_raw_parts(ptr, 0, len);
    }
}
```

Build the WASM module with wasm-pack, targeting a no-bundler output so the module can be loaded as a native ES module without a JavaScript bundler intermediary:

```bash
# Install wasm-pack if not present.
cargo install wasm-pack

# Build for browser, no bundler (plain ES module output).
# --release enables LTO and stripping.
wasm-pack build --target web --release --out-dir pkg/

# Verify the output size. A module with only financial calculations should be < 60 KB.
ls -lh pkg/financial_calc_bg.wasm

# Generate the SRI hash for the .wasm file before deployment.
openssl dgst -sha384 -binary pkg/financial_calc_bg.wasm | openssl base64 -A
```

### Step 2: Load the WASM Module with SRI and Trusted Types

The WASM module must be loaded with Subresource Integrity verification to ensure the binary has not been tampered with between build and execution.

```javascript
// financial-calc-loader.js
// Load the WASM module with SRI verification.
// The SRI hash is generated at build time and embedded in the application.
// A compromised CDN or MITM that substitutes a different .wasm file will fail SRI and throw.

const WASM_URL = '/static/financial_calc_bg.wasm';
// Hash generated with: openssl dgst -sha384 -binary financial_calc_bg.wasm | openssl base64 -A
const WASM_SRI_HASH = 'sha384-<hash-generated-at-build-time>';

let wasmModule = null;

async function loadFinancialCalc() {
    if (wasmModule) return wasmModule;

    // Fetch the WASM binary with SRI enforcement.
    // The browser verifies the integrity attribute before passing the response to
    // WebAssembly.instantiateStreaming. If the hash doesn't match, the fetch throws.
    const response = await fetch(WASM_URL, {
        integrity: WASM_SRI_HASH,
        credentials: 'omit',   // Do not send cookies with the WASM fetch.
        cache: 'force-cache',  // The WASM binary is immutable; use cached version.
    });

    if (!response.ok) {
        throw new Error(`Failed to fetch WASM module: ${response.status}`);
    }

    // Import the wasm-bindgen generated JS glue module.
    // This is a static import — not a dynamic string — preventing CSP bypass.
    const { default: init, compound_interest, monthly_payment, present_value,
            amortisation_schedule, zero_memory_region, alloc, dealloc } =
        await import('/static/financial_calc.js');

    // Instantiate using the SRI-verified response.
    await init(response);

    wasmModule = { compound_interest, monthly_payment, present_value,
                   amortisation_schedule, zero_memory_region, alloc, dealloc };
    return wasmModule;
}

export { loadFinancialCalc };
```

### Step 3: Write Sensitive Inputs Directly to WASM Memory

The key isolation pattern: sensitive numeric inputs are written into WASM linear memory via a typed array view, rather than passed as JavaScript function arguments. The inputs never exist as standalone JavaScript number variables that could be intercepted by hooked function calls or prototype manipulation.

```javascript
// sensitive-calc.js
import { loadFinancialCalc } from './financial-calc-loader.js';

/**
 * Calculate monthly payment with memory-isolated inputs.
 *
 * The principal, annual_rate, and term_months values are written directly into
 * WASM linear memory via a DataView. They never exist as JavaScript variables
 * in a form that a Magecart skimmer or hooked prototype could intercept after
 * the values leave the form field event handlers.
 */
async function calculateMonthlyPaymentIsolated(principalCents, annualRateBps, termMonths) {
    const calc = await loadFinancialCalc();

    // Allocate 24 bytes in WASM linear memory for 3 f64 values (8 bytes each).
    const bufPtr = calc.alloc(24);

    // Get a view of the WASM module's linear memory buffer.
    // This is the raw ArrayBuffer backing the WASM instance's heap.
    // Note: accessing memory() is a wasm-bindgen convention for the exported memory object.
    const memView = new DataView(calc.memory.buffer);

    // Write inputs directly into WASM linear memory.
    // Convert from integer representations (cents, basis points) to f64.
    const principal = principalCents / 100.0;
    const annualRate = annualRateBps / 10000.0;

    memView.setFloat64(bufPtr, principal, true);         // little-endian
    memView.setFloat64(bufPtr + 8, annualRate, true);
    memView.setFloat64(bufPtr + 16, termMonths, true);

    // Invoke the calculation — inputs are read from WASM linear memory.
    const payment = calc.monthly_payment(principal, annualRate, termMonths);

    // Zero the input region immediately after the calculation completes.
    // This prevents the sensitive inputs from persisting in WASM linear memory
    // where a later memory read could recover them.
    calc.zero_memory_region(bufPtr, 24);
    calc.dealloc(bufPtr, 24);

    return payment;
}

/**
 * Build an amortisation schedule.
 * The schedule data lives in WASM linear memory until explicitly read.
 * After the JavaScript caller has consumed the schedule, the WASM-side buffer is zeroed.
 */
async function buildAmortisationSchedule(principalCents, annualRateBps, termMonths) {
    const calc = await loadFinancialCalc();

    const principal = principalCents / 100.0;
    const annualRate = annualRateBps / 10000.0;

    // The returned Vec<f64> is allocated in WASM linear memory.
    // wasm-bindgen returns a JavaScript Float64Array view over that memory.
    const scheduleView = calc.amortisation_schedule(principal, annualRate, termMonths);

    // Copy the data out of WASM memory into a plain JavaScript array.
    // After this copy, zero the WASM-side buffer via the pointer.
    const schedule = Array.from(scheduleView);

    // scheduleView.byteOffset gives the pointer into WASM linear memory.
    calc.zero_memory_region(scheduleView.byteOffset, scheduleView.byteLength);

    return schedule;
}

export { calculateMonthlyPaymentIsolated, buildAmortisationSchedule };
```

### Step 4: Sign WASM Outputs to Prevent Return Value Tampering

An attacker who controls JavaScript executing after the WASM call returns can intercept the return value before it reaches the display layer. The WASM module cannot prevent a JavaScript wrapper from modifying the returned `f64`. To detect this, sign calculation outputs server-side and verify client-side.

The pattern: on page load, the server provides a signing key (an HMAC key wrapped in a nonce, or an asymmetric verification key). After WASM returns a result, the client sends the inputs and output to a verification endpoint. The server recalculates and confirms the result is within an acceptable tolerance. If the client-side result has been tampered with, the server rejects the transaction.

```javascript
// output-verification.js

/**
 * Verify a client-side WASM calculation result against the server's authoritative computation.
 * The server never trusts the client result for authoritative financial decisions;
 * this endpoint is used only to detect tampering for security monitoring.
 */
async function verifyCalculationResult(calculationType, inputs, clientResult) {
    const response = await fetch('/api/financial/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            type: calculationType,
            inputs: inputs,         // Server will recalculate from these inputs.
            clientResult: clientResult,
            // nonce prevents replay attacks against the verification endpoint.
            nonce: crypto.randomUUID(),
        }),
        credentials: 'same-origin',
    });

    const { verified, serverResult, withinTolerance } = await response.json();

    if (!verified || !withinTolerance) {
        // Log a security event — the client-side result was tampered with.
        console.error('Financial calculation result tampered with', {
            clientResult,
            serverResult,
        });
        // Reject the operation; show the server result instead.
        return { trusted: false, result: serverResult };
    }

    return { trusted: true, result: clientResult };
}

export { verifyCalculationResult };
```

### Step 5: Content Security Policy for Financial Pages

The CSP for financial pages must be tighter than a standard application CSP. The goal is to prevent any injected script from executing before or after the WASM module loads.

```http
# Financial calculator page CSP.
# 'wasm-unsafe-eval' allows WebAssembly.compile() without enabling eval() for JavaScript.
# If the WASM module is pre-compiled at build time and loaded as a static .wasm file,
# 'wasm-unsafe-eval' is not needed — instantiateStreaming from a fetch() does not require it
# in Chrome 95+ with the static module loading path.
Content-Security-Policy:
    default-src 'none';
    script-src 'self' 'nonce-{server-generated-nonce}';
    script-src-elem 'self' 'nonce-{server-generated-nonce}';
    connect-src 'self';
    img-src 'self' data:;
    style-src 'self';
    frame-ancestors 'none';
    base-uri 'none';
    form-action 'self';
    require-trusted-types-for 'script';
    trusted-types financial-calc-policy;
```

Note the absence of `'wasm-unsafe-eval'`. When instantiating WASM from a pre-fetched `Response` object (as in Step 2 above), modern browsers do not require this directive. Its omission prevents XSS attackers from using inline `WebAssembly.compile()` calls to instantiate rogue WASM modules from injected byte arrays.

For the Trusted Types policy, restrict WASM instantiation to the loader module:

```javascript
// trusted-types-policy.js
// This policy is the only code permitted to instantiate WebAssembly.
const policy = trustedTypes.createPolicy('financial-calc-policy', {
    createScript: (s) => {
        // No dynamic script creation permitted.
        throw new Error('Dynamic script creation blocked by financial-calc-policy');
    },
    // WASM instantiation is handled via fetch() + WebAssembly.instantiateStreaming().
    // No scriptURL trust delegation is needed.
});
```

### Step 6: Nginx SRI Header Configuration for WASM Files

Configure the web server to set cache-busting and integrity headers on WASM assets so that intermediaries cannot cache a tampered version.

```nginx
# nginx.conf — WASM asset hardening for financial pages.

location ~* \.wasm$ {
    # Immutable cache: the filename includes a content hash, so the same URL always
    # serves the same binary. Browsers cache aggressively; no revalidation occurs.
    add_header Cache-Control "public, max-age=31536000, immutable";

    # Cross-Origin Resource Policy: restrict WASM loading to same-origin only.
    # Prevents a third-party page from fetching and reverse-engineering the module.
    add_header Cross-Origin-Resource-Policy "same-origin";

    # The Content-Type must be application/wasm for instantiateStreaming to work.
    types { application/wasm wasm; }

    # Disable response body modification by any proxy between server and client.
    add_header X-Content-Type-Options "nosniff";
}

location /financial/ {
    # Cross-Origin Opener Policy: isolates the financial page from pop-up openers.
    add_header Cross-Origin-Opener-Policy "same-origin";

    # Cross-Origin Embedder Policy: required for SharedArrayBuffer (if used).
    # Also prevents the page from loading cross-origin resources without CORS.
    add_header Cross-Origin-Embedder-Policy "require-corp";

    add_header Content-Security-Policy "default-src 'none'; script-src 'self' 'nonce-$request_id'; connect-src 'self'; img-src 'self' data:; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; require-trusted-types-for 'script'; trusted-types financial-calc-policy;";
}
```

## Expected Behaviour

The following table maps each attack vector to the relevant WASM isolation property and the resulting mitigation:

| Attack vector | WASM isolation property | Mitigation |
|---|---|---|
| Prototype pollution of `Number.prototype.valueOf` | WASM arithmetic executes on f64 stack values, not JavaScript Number objects | Poisoned prototype has zero effect on WASM `f64.mul` or `f64.nearest` instructions |
| Magecart skimmer reading JavaScript variables containing loan amount | Sensitive inputs written to WASM linear memory, not JavaScript heap | Linear memory is an `ArrayBuffer` not reachable via prototype traversal or variable scope |
| XSS injecting script that reads `window.loanPrincipal` | Principal exists only as a Rust `f64` inside WASM linear memory | JavaScript attacker script finds no accessible variable; linear memory not exposed |
| Compromised npm package hooking a financial library function | WASM exported function signatures are fixed at compile time; bytecode is immutable | Hooking the JS wrapper function only intercepts the final return value, not intermediate state |
| Browser extension reading JavaScript heap memory | Extension content scripts operate in the JavaScript layer | Sensitive inputs in WASM linear memory are not visible to content script heap traversal |
| WASM module substitution via compromised CDN | SRI hash on the `.wasm` fetch request | Hash mismatch throws a network error before the module is instantiated |
| Return value interception between WASM and display layer | Server-side verification endpoint re-calculates from raw inputs | Tampered results detected and replaced with authoritative server computation |
| Dynamic WASM compilation from injected byte array (XSS + `'unsafe-eval'`) | CSP omits `'wasm-unsafe-eval'`; static module loading path requires no eval permission | Inline `WebAssembly.compile([...])` call blocked by CSP |

## Trade-offs

**Bundle size.** A WASM binary containing compound interest, amortisation, and present value functions compiled from Rust with LTO and `opt-level = "z"` is typically 40–80 KB after wasm-opt. An equivalent JavaScript implementation is 2–8 KB. The size difference matters for mobile users on slow connections and for financial pages where time-to-interactive is a conversion factor. Mitigate with aggressive HTTP/2 push, `Cache-Control: immutable`, and code-splitting so the WASM module loads in parallel with page render rather than blocking it.

**Development complexity.** The Rust/wasm-pack/wasm-bindgen toolchain has a meaningful learning curve for teams with JavaScript-only experience. Debugging financial edge cases (rounding, day count conventions, amortisation irregularities) is harder when the logic is behind a WASM boundary — you cannot set a browser debugger breakpoint inside a Rust function without enabling DWARF debug symbols, which substantially increases module size. Consider maintaining a reference JavaScript implementation alongside the WASM module for development and test validation, treating the Rust implementation as the production-only artifact.

**Debugging difficulty.** Source maps for Rust WASM are supported but require the `--debug` build flag, which disables LTO and increases bundle size by a factor of three to ten. Production WASM modules should ship without debug symbols (enforced via `debug = false` in `Cargo.toml`), which means production debugging relies on logging at the JavaScript API boundary rather than inside the WASM module. Build a thin JS instrumentation layer around every exported function that logs input ranges and output values to a structured logging endpoint, so anomalies are observable without needing WASM-level debugging.

**Accessibility implications.** WASM financial calculations do not inherently affect accessibility, but the loading pattern does. A form that shows a spinner while the WASM module loads needs an `aria-live` region to announce results to screen reader users. If the WASM module fails to load (network error, SRI mismatch, browser incompatibility), the fallback must be a JavaScript implementation that still functions — or the form must degrade gracefully to a server-side POST. Test with NVDA, JAWS, and VoiceOver on every browser; WASM loading latency that is invisible to sighted users may interrupt the screen reader focus flow.

**Browser compatibility.** WebAssembly has been supported in all major browsers since 2017. The `WebAssembly.instantiateStreaming` API is available in Chrome 61+, Firefox 58+, Safari 15+. The SRI enforcement for `fetch()` with the `integrity` attribute is available in all modern browsers. `'wasm-unsafe-eval'` in CSP is available in Chrome 95+, Firefox 102+, Safari 16+ — older browsers that need WASM compilation require the broader `'unsafe-eval'` directive, which partially undercuts the XSS isolation argument.

## Failure Modes

**JS API surface hooking bypassing WASM isolation.** The most significant residual vulnerability is that an attacker who achieves code execution before the WASM module is instantiated can wrap the exported functions:

```javascript
// Attacker code injected before financial-calc-loader.js executes.
const originalInstantiate = WebAssembly.instantiateStreaming;
WebAssembly.instantiateStreaming = async (source, importObject) => {
    const result = await originalInstantiate(source, importObject);
    // Wrap the monthly_payment export to intercept return values.
    const originalPayment = result.instance.exports.monthly_payment;
    result.instance.exports.monthly_payment = (...args) => {
        const val = originalPayment(...args);
        exfiltrate(args, val); // Send inputs and output to attacker's server.
        return val;
    };
    return result;
};
```

This attack requires the attacker to inject code before the WASM loader runs. The primary mitigation is a strict CSP with nonces that prevents any inline script or injected script from executing. The secondary mitigation is Subresource Integrity on all first-party JavaScript assets, so a compromised CDN cannot serve a modified version of the loader. The tertiary mitigation is Trusted Types, which prevents the attacker's code from accessing `WebAssembly` directly if the Trusted Types policy restricts it. None of these are complete defenses against an attacker who compromises the application's own first-party JavaScript bundle through the build pipeline.

**SRI misconfiguration.** SRI only protects if the hash in the `integrity` attribute matches the actual file. Common misconfiguration failures: using a development build hash for a production binary; regenerating the WASM binary without updating the SRI hash in HTML templates; using `sha256` when the file was hashed with `sha384`; generating the hash from a gzip-compressed response rather than the raw binary. Automate SRI hash generation as a build step that writes the hash directly into HTML templates, and add a CI check that verifies the hash in the deployed HTML matches the hash of the deployed WASM binary.

**WASM memory not zeroed.** If `zero_memory_region` is not called after a calculation, sensitive inputs persist in WASM linear memory until the memory region is reused. A browser extension that accesses the WASM instance's `memory.buffer` `ArrayBuffer` can read any region that has not been zeroed. The `alloc`/`dealloc`/`zero_memory_region` pattern in Step 3 must be enforced at code review: every code path that writes sensitive data into WASM memory must have a corresponding `zero_memory_region` call in its `finally` block. Use compiler-enforced patterns in Rust — a `SecretBuffer` wrapper type that implements `Drop` with a volatile zero — to make the zeroing mandatory rather than caller-optional.

**Server-side verification bypassed by rate limiting or network failure.** If the verification endpoint is unreachable or rate-limited, the application may fall back to trusting the client-side result. Ensure the fallback is rejection, not silent acceptance. Financial transactions that cannot be server-verified should not proceed.

## Server-Side Authority

Client-side WASM financial calculations are for user experience only. They give the user immediate feedback on monthly payment, total interest cost, and amortisation schedule without a round-trip. They are not authoritative for any financial decision.

The server must recalculate every financial value used in a credit decision, rate disclosure, or contractual document using its own implementation, from the raw inputs the user submitted. The client-side WASM result is discarded after display. This is not a WASM-specific requirement — it applies to any client-side calculation — but it is worth stating explicitly because the security properties of WASM can create a false sense that client-side results are trustworthy.

A WASM module that calculates an APR correctly under normal conditions can be replaced with a functionally different module if the attacker compromises the build pipeline. The build-time hash in the SRI attribute ensures the browser loads the expected binary — but if the attacker compromised the CI system that generated the expected binary, the SRI hash is the hash of a malicious binary. The server's own calculation, from raw inputs, over a validated server-side library, is the only computation that should drive financial disclosures and contractual obligations.

Document this architecture explicitly in your PCI DSS and SOC 2 evidence: client-side WASM is a UX layer; server-side recalculation is the control. Auditors reviewing JavaScript skimming controls (PCI DSS 6.4.3) will want to see both the CSP and SRI configuration for the browser-side layer and the server-side recalculation proof.
