---
title: "WASM Debugging Security: Stripping Debug Symbols, Source Maps, and Build Hardening"
description: "Production WASM modules often ship with name sections, debug symbols, and source maps that expose function names, variable names, and original source structure. Stripping them protects proprietary logic."
slug: "wasm-debug-symbol-security"
date: 2026-04-30
lastmod: 2026-04-30
category: "wasm"
tags: ["wasm", "debug-symbols", "source-maps", "binary-hardening", "ip-protection"]
personas: ["platform-engineer", "security-engineer", "ml-engineer"]
article_number: 270
difficulty: "intermediate"
estimated_reading_time: 12
published: true
layout: article.njk
permalink: "/articles/wasm/wasm-debug-symbol-security/index.html"
---

# WASM Debugging Security: Stripping Debug Symbols, Source Maps, and Build Hardening

## Problem

WebAssembly binary format (`.wasm`) is compact and efficient, but it is not obfuscated. A WASM binary produced by a default Rust/C++ build contains significantly more information than the executed instructions:

- **Name section:** Function names, local variable names, and type names that the linker preserved from the source. An attacker who loads a `.wasm` in Chrome DevTools, `wasm-decompile`, or `wasm2wat` sees `calculatePaymentAmount`, `validateApiKey`, and `encryptCustomerData` — your application's internal logic exposed as readable labels.
- **DWARF debug information:** For debug builds (and sometimes accidentally in release builds), DWARF sections contain source file paths, line numbers, and original variable names. This maps compiled WASM bytecode back to the original source.
- **Source maps:** A `.map` file that accompanies `.wasm` and enables in-browser source-level debugging. If served publicly alongside the WASM file, it provides the complete mapping from WASM instructions to original source lines — effectively distributing the source code.
- **Verbose custom sections:** Some toolchains embed build system paths, compiler versions, or environment metadata in custom WASM sections.

The security implication depends on what the WASM module does. A WASM module implementing a game engine is a low-sensitivity target. A WASM module implementing a licensing check, a payment calculation, a cryptographic key derivation, or a proprietary algorithm is high-value IP that becomes trivially reversible with debug symbols.

Specific gaps in production WASM deployments:

- `wasm-pack build --debug` used in production because developers want debugging capability.
- Source maps served alongside the WASM binary with no access restriction.
- No `wasm-opt` pass in the build pipeline; both size and symbol exposure are worse than necessary.
- Custom sections from the toolchain (paths, build metadata) shipped in production.

**Target systems:** Rust/wasm-pack 0.12+; Emscripten 3.1+; AssemblyScript 0.27+; Go's WASM compiler; wasm-opt (part of Binaryen 116+); wasm-strip (part of WABT 1.0.33+); wasm-decompile and wasm-objdump for analysis.

## Threat Model

- **Adversary 1 — Proprietary algorithm extraction:** An attacker loads a payment processing WASM in Chrome DevTools. The name section exposes function names like `computeDiscountPercent` and `validateLicenseKey`. They use wasm-decompile to reconstruct readable pseudocode of the licensing logic.
- **Adversary 2 — Source map exfiltration:** A WASM module serving a security-critical function ships with a publicly accessible `.map` file. An attacker downloads the source map and reads the original TypeScript/AssemblyScript source, bypassing any protection the compilation provided.
- **Adversary 3 — DWARF-assisted debugging attack:** A WASM module built with debug information can be loaded into a local runtime with a DWARF-aware debugger. The attacker steps through the original source-mapped execution, including variable inspection.
- **Adversary 4 — Build path disclosure:** DWARF sections contain absolute paths (`/home/alice/projects/paymentengine/src/core.rs`). These reveal internal developer names, directory structures, and project names — useful for targeted social engineering.
- **Adversary 5 — Timing side-channel via symbol knowledge:** Knowing which functions implement cryptographic operations (from the name section) allows an attacker to focus timing measurements on those specific function calls, extracting key material via side-channel analysis.
- **Access level:** Adversaries 1–4 need only network access to download the WASM file and map file. Adversary 5 additionally needs the ability to make many API calls and measure response timing.
- **Objective:** Extract proprietary business logic, bypass licensing or access controls, reconstruct source code.
- **Blast radius:** For a WASM module implementing a competitive algorithm, source disclosure via debug symbols is equivalent to leaking the source repository. For a security control implemented in WASM, symbol disclosure helps attackers understand and bypass it.

## Configuration

### Step 1: Audit Symbols in Current WASM

Before stripping, understand what you're currently shipping:

```bash
# Install WABT (WebAssembly Binary Toolkit).
apt install wabt    # Debian/Ubuntu
brew install wabt   # macOS

# Dump all sections in a WASM file.
wasm-objdump -h dist/app.wasm
# Sections and sizes:
#   Type   start=0x0000000c end=0x00000123 (size=0x00000117) count: 45
#   Import start=0x00000126 end=0x00000201 (size=0x000000db) count: 12
#   ...
#   Custom start=0x000a1234 end=0x000b5678 (size=0x00001444) ".debug_info"
#   Custom start=0x000b5678 end=0x000c1234 (size=0x00000bbc) "name"

# Inspect the name section (function names).
wasm-objdump -x dist/app.wasm | grep -A 100 "Name\[" | head -50
# Outputs: Function[0] calculatePaymentAmount
#          Function[1] validateApiKey
#          Function[2] encryptCustomerData

# Inspect DWARF debug information.
wasm-objdump --debug-info dist/app.wasm | head -50
# Outputs: DW_AT_name "src/payment.rs"
#          DW_AT_comp_dir "/home/developer/projects/payment-engine"

# Decompile to readable pseudocode (shows how readable the code is).
wasm-decompile dist/app.wasm -o /tmp/decompiled.dcmp
head -100 /tmp/decompiled.dcmp
```

### Step 2: Strip Debug Symbols with wasm-strip and wasm-opt

```bash
# Install Binaryen (includes wasm-opt and wasm-strip).
apt install binaryen    # Debian/Ubuntu
brew install binaryen   # macOS

# Step 1: Strip all debug information with wasm-strip.
wasm-strip dist/app.wasm
# Removes: DWARF sections (.debug_info, .debug_line, .debug_str, etc.)
# Removes: name section (function names, local names)

# Step 2: Optimise with wasm-opt (further reduces size and applies additional transforms).
wasm-opt -O3 --strip-debug --strip-dwarf --strip-producers \
  dist/app.wasm -o dist/app-stripped.wasm

# Flags:
# -O3                  Aggressive optimisation.
# --strip-debug        Remove DWARF debug sections.
# --strip-dwarf        Remove DWARF specifically.
# --strip-producers    Remove the "producers" custom section (compiler version/flags).

# Verify the result.
wasm-objdump -h dist/app-stripped.wasm | grep -E "name|debug|producers"
# Should show no results (sections removed).

# Check the size reduction.
ls -lh dist/app.wasm dist/app-stripped.wasm
```

### Step 3: Build Pipeline Integration

```makefile
# Makefile for Rust/wasm-pack

.PHONY: build-prod build-dev

# Development build: full debug symbols for developer use.
build-dev:
    wasm-pack build --target web --dev --out-dir dist-dev/

# Production build: stripped and optimised.
build-prod:
    # Build with release optimisations.
    wasm-pack build --target web --release --out-dir dist/
    # Additional stripping and optimisation.
    wasm-opt -O3 --strip-debug --strip-dwarf --strip-producers \
        dist/app_bg.wasm -o dist/app_bg.wasm
    # Remove source maps from the production output.
    rm -f dist/*.map
    # Verify no debug symbols remain.
    @if wasm-objdump -h dist/app_bg.wasm 2>&1 | grep -qE 'debug|name'; then \
        echo "WARNING: Debug symbols may still be present"; \
        wasm-objdump -h dist/app_bg.wasm; \
    fi
    @echo "Production WASM built and stripped."
```

For Emscripten:

```bash
# Emscripten production build: strip debug information.
emcc src/main.c \
  -O3 \
  -s WASM=1 \
  -s ASSERTIONS=0 \           # Remove runtime assertions.
  -s NO_FILESYSTEM=1 \        # Remove unused filesystem code.
  --closure 1 \               # Apply Closure Compiler to JS glue code.
  -g0 \                       # No debug information.
  -o dist/app.js

# The -g0 flag disables all debug information.
# wasm-opt -O3 on the output wasm file for additional optimisation.
wasm-opt -O3 dist/app.wasm -o dist/app.wasm
```

For AssemblyScript:

```bash
# AssemblyScript production build.
asc src/index.ts \
  --target release \
  --optimize \
  --noAssert \              # Remove runtime assertions.
  --outFile dist/app.wasm \
  --textFile /dev/null \    # Don't generate the .wat text format.
  --sourceMap false         # Don't generate source maps.

wasm-opt -O3 --strip-debug dist/app.wasm -o dist/app.wasm
```

### Step 4: Source Map Access Controls

Source maps should never be publicly accessible. Serve them only to authenticated developers:

```nginx
# nginx: block public access to .map files.
location ~* \.wasm\.map$ {
    deny all;
    return 404;
}

location ~* \.map$ {
    # Require an internal IP or a developer-specific auth token.
    allow 10.0.0.0/8;
    deny all;
}
```

Or: don't serve source maps from production at all. Store them in a secure internal location and reference them only in development environments:

```bash
# Build with source maps, but store them offline.
wasm-pack build --target web --release --out-dir dist/
# Move source maps to a secure internal store.
aws s3 cp dist/*.map s3://internal-debug-artifacts/wasm-maps/$(git rev-parse HEAD)/
rm -f dist/*.map

# When a developer needs to debug production, download the map for that build version.
aws s3 cp s3://internal-debug-artifacts/wasm-maps/$(git rev-parse HEAD)/app.wasm.map ./
```

### Step 5: Cargo Configuration for Rust WASM Builds

Control debug information at the Rust build level:

```toml
# Cargo.toml
[profile.release]
# Strip all debug symbols including names.
strip = "symbols"         # Removes name section and debug info.
opt-level = 3
lto = true               # Link-time optimisation: smaller and harder to analyse.
codegen-units = 1        # Better optimisation; fewer separate compilation units.
panic = "abort"          # Removes panic infrastructure; smaller binary.
debug = false            # No debug information.

[profile.release.package."*"]
# Apply to all dependencies too.
strip = "symbols"
opt-level = 3
```

```bash
# Verify the Cargo profile is applied correctly.
cargo build --release --target wasm32-wasip2
# Then run wasm-objdump to confirm no name section:
wasm-objdump -h target/wasm32-wasip2/release/app.wasm | grep name
# Expected: no output.
```

### Step 6: Detect Symbol Exposure in CI

Add a CI step that fails if debug symbols are present in the production WASM artifact:

```bash
#!/bin/bash
# check-wasm-symbols.sh
# Fails if debug symbols are present in the WASM file.

WASM_FILE="${1:-dist/app.wasm}"

if [ ! -f "$WASM_FILE" ]; then
  echo "WASM file not found: $WASM_FILE"
  exit 1
fi

ISSUES=()

# Check for name section.
if wasm-objdump -h "$WASM_FILE" 2>&1 | grep -q '"name"'; then
  ISSUES+=("Name section present (function/variable names exposed)")
fi

# Check for DWARF debug sections.
if wasm-objdump -h "$WASM_FILE" 2>&1 | grep -qE '\.debug_'; then
  ISSUES+=("DWARF debug sections present (source mapping exposed)")
fi

# Check for producers section (compiler version disclosure).
if wasm-objdump -h "$WASM_FILE" 2>&1 | grep -q '"producers"'; then
  ISSUES+=("Producers section present (compiler version/flags disclosed)")
fi

# Check for source maps alongside the WASM.
MAP_FILE="${WASM_FILE}.map"
if [ -f "$MAP_FILE" ]; then
  ISSUES+=("Source map file present: $MAP_FILE")
fi

if [ ${#ISSUES[@]} -gt 0 ]; then
  echo "WASM symbol security issues found in $WASM_FILE:"
  for issue in "${ISSUES[@]}"; do
    echo "  - $issue"
  done
  exit 1
fi

echo "PASS: $WASM_FILE contains no debug symbols or source maps."
```

```yaml
# .github/workflows/build.yml
- name: Check WASM symbol exposure
  run: ./scripts/check-wasm-symbols.sh dist/app.wasm
```

### Step 7: Measuring Information Leakage Before and After

Compare what an attacker can learn from stripped vs unstripped WASM:

```bash
# Before stripping: count visible function names.
wasm-objdump -x dist/app.wasm | grep "Function\[" | wc -l
# Output: 247 (247 function names visible)

# After stripping: count visible function names.
wasm-objdump -x dist/app-stripped.wasm | grep "Function\[" | wc -l
# Output: 0 (no function names; all are func_0, func_1, etc.)

# Before: file size with debug info.
ls -lh dist/app.wasm
# Output: 4.2 MB

# After: file size stripped and optimised.
ls -lh dist/app-stripped.wasm
# Output: 1.8 MB (57% reduction in this example)

# Decompile stripped WASM — much harder to read.
wasm-decompile dist/app-stripped.wasm | head -20
# Output: function $func0(a:int, b:int, c:int):int {
#           ...  (no meaningful names; hard to follow)
```

### Step 8: Telemetry

```
wasm_symbol_exposure_check_pass_total{module}                counter
wasm_symbol_exposure_check_fail_total{module, issue_type}    counter
wasm_production_binary_size_bytes{module}                    gauge
wasm_source_map_request_total{module, source_ip}             counter
wasm_source_map_blocked_total{module, source_ip}             counter
```

Alert on:

- `wasm_symbol_exposure_check_fail_total` non-zero — a production WASM artifact was built with debug symbols; block deployment.
- `wasm_source_map_request_total` from unexpected IPs — source map files being accessed from non-developer IPs.
- `wasm_production_binary_size_bytes` sudden increase — a debug build may have been accidentally deployed.

## Expected Behaviour

| Signal | Debug build (unstripped) | Production build (stripped) |
|--------|--------------------------|----------------------------|
| Function names visible | Yes — `calculatePaymentAmount` etc. | No — `$func0`, `$func1` etc. |
| DWARF source mapping | Full source → WASM mapping | Absent |
| Source map file | Present | Removed or access-restricted |
| Compiler version disclosure | In producers section | Removed |
| Binary size | 4.2 MB (example) | 1.8 MB (57% reduction) |
| Decompiled readability | High (function names guide analysis) | Low (no names; harder to follow) |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Stripped name section | Function names not exposed | Production debugging harder | Store unstripped WASM and source maps in internal artifact store tied to git SHA. |
| wasm-opt -O3 | Smaller binary; harder to analyse | Build time (a few seconds for most modules) | Run in CI; acceptable overhead. |
| No source maps in production | Source code not reconstructable | Cannot use browser DevTools source mapping | Use error IDs + server-side logging instead of client-side debugging; use unstripped builds in staging only. |
| `lto = true` in Rust | Link-time optimisation makes binary smaller and logic harder to follow | Longer build times | Only enable in release profile; no impact on development cycle. |
| CI check for symbol exposure | Catches accidental debug builds | One more CI step | Fast (~2 seconds); worth catching before deployment. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Debug build deployed accidentally | Production binary larger than expected; function names visible | `wasm_symbol_exposure_check_fail_total`; size metric spike | Rollback to last good deployment; fix build pipeline to enforce release profile. |
| wasm-strip removes required custom section | Application behaviour changes | Application errors; custom section with runtime data removed | Audit which custom sections are required at runtime; add them back to an allowlist. |
| Source map accessible from public IPs | Source map fetched by non-developer | `wasm_source_map_request_total` from external IPs | Immediately restrict nginx access; rotate if sensitive source was exposed; audit access log for extent. |
| wasm-opt breaks WASM validity | Optimised WASM fails to load | Runtime error: invalid WASM; browser console shows parse error | Check wasm-opt version compatibility with the runtime; use `-O2` if `-O3` causes issues. |
| Name section required by host runtime (e.g., Wasmtime debugging hooks) | Stack traces lose function names; debugging infeasible | Developer complaint; stack traces show `func_0` | Keep name section for server-side WASM where the binary is not publicly accessible; only strip for browser-served WASM. |

## Related Articles

- [WASM Static Analysis and Vulnerability Scanning](/articles/wasm/wasm-static-analysis/)
- [Reproducible WASM Builds and SBOM Generation](/articles/wasm/reproducible-wasm-builds/)
- [WASM OCI Module Signing and Verification](/articles/wasm/wasm-oci-signing/)
- [WASM in the Browser: CSP, Origin Isolation, and Subresource Integrity](/articles/wasm/wasm-browser-security/)
- [AI Model Weight Security](/articles/ai-landscape/ai-model-weight-security/)
