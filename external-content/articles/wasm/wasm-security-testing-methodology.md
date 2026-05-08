---
title: "WASM Security Testing Methodology: Static Analysis, Dynamic Testing, and Supply Chain Verification"
description: "A complete WASM security testing programme combines static analysis of WASM bytecode, dynamic testing with resource monitoring, differential testing across runtimes, host boundary fuzzing, and supply chain verification. This guide provides a structured methodology and toolchain for security engineers deploying WASM in production."
slug: wasm-security-testing-methodology
date: 2026-05-07
lastmod: 2026-05-07
category: wasm
tags:
  - wasm
  - security-testing
  - static-analysis
  - fuzzing
  - supply-chain
personas:
  - security-engineer
  - platform-engineer
article_number: 597
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/wasm/wasm-security-testing-methodology/
---

# WASM Security Testing Methodology: Static Analysis, Dynamic Testing, and Supply Chain Verification

## Problem

WASM deployments have no standard security testing playbook. Teams borrow from native binary analysis, container scanning, and web application testing — and find that none of these disciplines transfers cleanly. Container scanners look for package manager metadata that `.wasm` files do not contain. Binary analysis tools target PE or ELF structures that WASM does not use. Web application scanners probe HTTP surfaces while the interesting attack vectors lie at the host-module boundary, inside the import/export ABI, and across the linear memory interface.

The result is a testing gap. Modules ship to production with unvalidated import lists, without signature verification, without any dynamic test that confirms the runtime correctly enforces memory and CPU bounds. When a vulnerability is discovered — an unchecked import that grants filesystem access, a missing fuel limit that allows CPU exhaustion, a host function that fails to validate WASM-supplied offsets — the team has no record of what tests should have caught it.

A structured WASM security testing methodology answers four questions about every module before it reaches production: What does this module declare itself capable of? Does the module come from a verifiable, unmodified build? Does the module behave correctly under a hardened runtime with resource limits applied? Does the host integration correctly reject malformed inputs and boundary-condition values from within the module?

This article defines that methodology as a gated pipeline. Each phase produces a pass/fail signal that feeds the next. No phase is optional in a production deployment of untrusted or third-party WASM modules.

**Target systems:** wasm-tools 1.220+, wabt 1.0.36+, Wasmtime 22+, WasmEdge 0.14+, V8 (via Node.js 22+), syft 1.16+, cosign 2.4+, cargo-fuzz 0.12+, semgrep 1.75+, OSV-Scanner 1.9+.

## Threat Model

- **Adversary 1 — Overprivileged module author:** A module declares more WASI imports than its intended function requires. The excess capability is available to any code embedded in the module, including malicious dependencies introduced through a supply chain compromise.
- **Adversary 2 — Tampered build artifact:** A legitimate `.wasm` file is replaced in transit, in object storage, or in a container registry with a backdoored version. There is no signature verification to detect the substitution.
- **Adversary 3 — Module exploiting host integration bugs:** A module makes host function calls with crafted arguments — offsets near the end of linear memory, lengths that wrap around 32-bit integers, table indices above the declared table size — to exploit inadequate bounds checking in host-side code.
- **Adversary 4 — Resource-exhaustion module:** A module enters an infinite loop or allocates the maximum permissible linear memory to deny service to other tenants on the same runtime process.
- **Adversary 5 — Runtime divergence exploit:** A module that behaves differently across Wasmtime, V8, and WasmEdge to exploit spec ambiguity or runtime-specific bugs in one deployment target.
- **Access level:** Adversaries 1 and 2 operate at build time or in transit. Adversaries 3, 4, and 5 operate at runtime by supplying a crafted module or crafted inputs.
- **Objective:** Unauthorized capability access (Adversary 1), silent code substitution (Adversary 2), host memory corruption or information disclosure via the ABI (Adversary 3), denial of service (Adversary 4), runtime-specific sandbox escape (Adversary 5).
- **Blast radius:** Adversaries 1 and 2 can produce modules with full unauthorized host capability access. Adversary 3 is bounded by the host process. Adversary 4 affects all tenants on the runtime process. Adversary 5 may yield a sandbox escape in the diverging runtime.

## Methodology

### Phase 1: Static Analysis

Static analysis examines the `.wasm` binary before any execution. The goals are: confirm the module is spec-compliant, audit the declared import and export surface, detect dangerous import combinations, and find embedded debug information that should not be in a production artifact.

**1.1 — Spec compliance validation**

```bash
# Validate bytecode structure against the WASM specification.
wasm-tools validate --features all ./payments.wasm

# Equivalent using WABT's validator; cross-check both for spec-compliance edge cases.
wasm-validate ./payments.wasm
```

A module that fails validation must be rejected immediately. A module that passes both validators but fails either one in isolation indicates a spec-interpretation divergence worth investigating.

**1.2 — Import and export audit**

```bash
# Dump imports in structured JSON for automated processing.
wasm-tools dump --imports ./payments.wasm | tee imports.json

# Human-readable disassembly of the import section.
wasm-objdump -x ./payments.wasm | grep -A 200 "Import\[" | head -80
```

The output reveals every host function and WASI interface the module depends on. Produce a baseline import allowlist from the module's WIT world definition and diff it against the actual imports:

```bash
# Generate import list from the actual binary.
wasm-tools component wit ./payments.wasm 2>/dev/null \
  | grep "import " | sort > actual-imports.txt

# Compare against the approved allowlist checked into the repository.
diff approved-imports.txt actual-imports.txt
# Any addition is a finding. Any deletion is an informational note.
```

**1.3 — Semgrep rules for WASM patterns**

Semgrep's WASM support operates on the WAT (WebAssembly Text Format) representation. Convert the binary first, then apply rules:

```bash
wasm2wat ./payments.wasm -o payments.wat

semgrep --config ./rules/wasm-dangerous-imports.yaml payments.wat
```

A minimal dangerous-import rule that catches unintended network access:

```yaml
# rules/wasm-dangerous-imports.yaml
rules:
  - id: wasm-unexpected-socket-import
    patterns:
      - pattern: '(import "wasi:sockets/tcp-create-socket@0.2" ...)'
    message: >
      Module imports wasi:sockets/tcp-create-socket. Confirm this capability
      is required; most processing modules should not have outbound TCP access.
    severity: WARNING
    languages: [generic]

  - id: wasm-unexpected-env-import
    patterns:
      - pattern: '(import "wasi:cli/environment@0.2" ...)'
    message: >
      Module imports wasi:cli/environment. Confirm environment variable access
      is required; this capability can expose secrets injected into the host process.
    severity: WARNING
    languages: [generic]
```

**1.4 — Debug section detection**

Production modules must not embed debug information that maps bytecode offsets to source file paths, function names, or line numbers. Debug sections increase attack surface by making exploitation easier and can leak internal repository paths.

```bash
# List all custom sections; look for 'name', 'sourceMappingURL', or DWARF sections.
wasm-objdump -h ./payments.wasm | grep "Custom"

# wasm-tools provides more detail on custom section names.
wasm-tools dump --custom-sections ./payments.wasm
```

Flag any module containing: a `name` section in production, `sourceMappingURL`, `.debug_info`, `.debug_line`, or `dylink.0` (dynamic linking metadata). These should be stripped at build time via `wasm-opt --strip-debug` or `wasm-tools strip`.

### Phase 2: Supply Chain Verification

Static analysis confirms what the module declares. Supply chain verification confirms the module is what it claims to be: built from the expected source at the expected commit, with no post-build modification.

**2.1 — Signature verification**

Modules distributed via OCI registries should be signed with cosign before distribution and verified before loading:

```bash
# Verify the module's OCI artifact signature.
cosign verify \
  --certificate-identity-regexp "^https://github.com/your-org/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/your-org/payments-wasm:v1.4.2

# For modules distributed as raw files, verify detached signature.
cosign verify-blob \
  --certificate payments.wasm.pem \
  --signature payments.wasm.sig \
  --certificate-identity-regexp "^https://github.com/your-org/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ./payments.wasm
```

A module that fails signature verification must not be instantiated, regardless of what static analysis showed.

**2.2 — SBOM generation and vulnerability scanning**

The module's SBOM links it to the dependency tree resolved at build time:

```bash
# Generate SBOM from the Cargo workspace at build time (not from the binary).
syft dir:. --output cyclonedx-json > payments-sbom.json

# Attach the SBOM as an OCI attestation alongside the module image.
cosign attest \
  --predicate payments-sbom.json \
  --type cyclonedx \
  ghcr.io/your-org/payments-wasm:v1.4.2

# At verification time, pull the SBOM attestation and scan for known CVEs.
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp "^https://github.com/your-org/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/your-org/payments-wasm:v1.4.2 \
  | jq -r '.payload' | base64 -d | jq -r '.predicate' > pulled-sbom.json

osv-scanner --sbom pulled-sbom.json
```

Any critical or high CVE in a direct dependency is a pipeline gate failure. Medium CVEs in transitive dependencies should be tracked with a deadline.

**2.3 — Provenance attestation**

SLSA provenance attestations record the source commit, build environment, and build invocation parameters. They are generated automatically by GitHub Actions workflows that use the SLSA GitHub Generator:

```bash
# Verify SLSA provenance for the published module.
slsa-verifier verify-artifact payments.wasm \
  --provenance-path payments.wasm.intoto.jsonl \
  --source-uri github.com/your-org/payments-service \
  --source-tag v1.4.2
```

**2.4 — Binary reproducibility check**

A reproducible build produces bit-for-bit identical output from the same source and toolchain. To verify, rebuild from the source commit pinned in the provenance attestation and compare hashes:

```bash
# Rebuild using the exact toolchain version from the provenance statement.
rustup toolchain install 1.87.0
cargo +1.87.0 build --release --target wasm32-wasip2

# Compare the rebuilt binary against the distributed artifact.
sha256sum target/wasm32-wasip2/release/payments.wasm > rebuilt.sha256
sha256sum payments.wasm > distributed.sha256
diff rebuilt.sha256 distributed.sha256
```

A hash mismatch on a module whose provenance verifies correctly is a critical finding: the distributed binary was produced by different inputs than the attested source.

### Phase 3: Dynamic Testing

Dynamic testing runs the module under a hardened, instrumented runtime. The goal is to confirm that: (a) the runtime correctly enforces resource limits, (b) the module traps rather than producing undefined behaviour when given malformed inputs, and (c) the module fails safely at resource exhaustion.

**3.1 — Instrumented Wasmtime with resource monitors**

```bash
# Run with fuel limit, memory limit, and epoch interruption enabled.
# The --fuel flag causes a trap when fuel is exhausted rather than hanging.
wasmtime run \
  --fuel 10000000 \
  --max-wasm-stack 524288 \
  --wasm-memory-growth-strategy static \
  --allow-precompiled \
  --wasi cli \
  -- ./payments.wasm process < test-input.json
```

For embedded usage, verify the `Store::limiter` enforces the expected ceilings:

```rust
use wasmtime::*;
use wasmtime_wasi::WasiCtxBuilder;

let mut config = Config::new();
config.consume_fuel(true);
config.epoch_interruption(true);

let engine = Engine::new(&config)?;
let mut store = Store::new(&engine, ());

// 100MB memory ceiling; reject any module that tries to grow beyond it.
store.limiter(|_| &mut SimpleLimiter { memory_pages: 1600, tables: 10, instances: 1 });
store.set_fuel(10_000_000)?;
store.epoch_deadline_trap();
store.set_epoch_deadline(1);
```

**3.2 — Malformed input testing**

Feed the module inputs that should produce well-defined error handling, not panics or traps:

```bash
# Test with empty input.
echo -n "" | wasmtime run --fuel 1000000 ./payments.wasm process

# Test with oversized input (should be rejected cleanly).
python3 -c "import sys; sys.stdout.buffer.write(b'A' * 10_000_000)" \
  | wasmtime run --fuel 5000000 ./payments.wasm process

# Test with binary garbage.
dd if=/dev/urandom bs=1024 count=1 \
  | wasmtime run --fuel 1000000 ./payments.wasm process

# Test with valid JSON structure but extreme numeric values.
echo '{"amount": 9223372036854775807, "currency": "USD"}' \
  | wasmtime run --fuel 1000000 ./payments.wasm process
```

Expected result for all cases: a non-zero exit code with an error message, not a Wasmtime trap. A trap indicates the module reached an unreachable instruction or caused an out-of-bounds memory access — both are bugs in error-handling code.

**3.3 — Resource exhaustion testing**

Verify that the runtime enforces limits rather than allowing unbounded growth:

```bash
# Confirm fuel exhaustion causes a trap, not a hang.
# A synthetic module that loops forever should trap within a known time bound.
wasmtime run --fuel 1000 ./infinite-loop.wasm
echo "Exit code: $?"  # Must be non-zero; must return in under 1 second.

# Confirm memory growth beyond the limit is rejected.
wasmtime run \
  --fuel 100000000 \
  ./memory-growth-test.wasm grow-to-max
# Module should trap or return an error, not allocate 4GB.
```

### Phase 4: Host Boundary Fuzzing

The host integration layer — the Rust, Go, or C code that calls module exports and implements host-side imports — is the most commonly undertested surface. Host functions receive arguments that originate from within the WASM module's linear memory. A malicious module can pass any i32 value as an offset or length. If the host function does not validate these before performing a memory operation, the result is an out-of-bounds read or write in the host process.

**4.1 — Fuzzing host function call sequences**

Use a harness that drives the module's exported functions from the host, varying call sequences and argument values:

```rust
// fuzz/fuzz_targets/host_boundary.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
enum ModuleCall {
    Process { offset: i32, length: i32 },
    GetResult { index: i32 },
    Reset,
    SetConfig { key_offset: i32, key_length: i32, val_offset: i32, val_length: i32 },
}

fuzz_target!(|calls: Vec<ModuleCall>| {
    let (engine, module, linker) = setup_module();
    let mut store = make_store(&engine);
    let instance = linker.instantiate(&mut store, &module).unwrap();

    for call in calls {
        // Drive each exported function; any panic in the host integration is a finding.
        let _ = drive_call(&mut store, &instance, call);
    }
});
```

**4.2 — Boundary value testing for every host function**

For each host function, test the full boundary value space systematically before fuzzing:

```bash
#!/usr/bin/env bash
# boundary-test.sh — test every host-exposed function with edge-case values.

WASM=./payments.wasm
BOUNDARY_VALUES=(0 1 -1 2147483647 2147483648 4294967295 -2147483648)

for offset in "${BOUNDARY_VALUES[@]}"; do
  for length in "${BOUNDARY_VALUES[@]}"; do
    echo "Testing offset=$offset length=$length"
    wasmtime run \
      --fuel 100000 \
      --env "TEST_OFFSET=$offset" \
      --env "TEST_LENGTH=$length" \
      "$WASM" boundary-probe 2>&1 \
      | grep -E "(trap|error|panic)" \
      && echo "FINDING: unexpected trap at offset=$offset length=$length"
  done
done
```

Any host-side panic, segmentation fault, or uncaught exception during boundary value testing is a critical finding. Traps inside the WASM sandbox are expected and acceptable for out-of-range values — they indicate the runtime's bounds checker is working correctly. Crashes outside the sandbox are not.

### Phase 5: Differential Testing

The WASM specification defines deterministic semantics, but implementations interpret edge cases differently. A module that exhibits different observable behaviour across two conformant runtimes signals either a spec-interpretation bug or an implementation vulnerability.

**5.1 — Cross-runtime output comparison**

```bash
#!/usr/bin/env bash
# diff-test.sh — run identical inputs across three runtimes and compare outputs.

MODULE=./payments.wasm
INPUT=./testdata/sample-payment.json

# Wasmtime
wasmtime run --fuel 10000000 "$MODULE" process < "$INPUT" > wasmtime-out.txt 2>&1
WASMTIME_EXIT=$?

# WasmEdge
wasmedge --gas-limit 10000000 "$MODULE" process < "$INPUT" > wasmedge-out.txt 2>&1
WASMEDGE_EXIT=$?

# Node.js (V8 WASM engine) via a thin wrapper
node run-wasm.js "$MODULE" process < "$INPUT" > v8-out.txt 2>&1
V8_EXIT=$?

# Compare exit codes.
if [ "$WASMTIME_EXIT" != "$WASMEDGE_EXIT" ] || [ "$WASMTIME_EXIT" != "$V8_EXIT" ]; then
  echo "FINDING: exit code divergence — Wasmtime=$WASMTIME_EXIT WasmEdge=$WASMEDGE_EXIT V8=$V8_EXIT"
fi

# Compare stdout.
if ! diff -q wasmtime-out.txt wasmedge-out.txt > /dev/null 2>&1; then
  echo "FINDING: output divergence between Wasmtime and WasmEdge"
  diff wasmtime-out.txt wasmedge-out.txt
fi

if ! diff -q wasmtime-out.txt v8-out.txt > /dev/null 2>&1; then
  echo "FINDING: output divergence between Wasmtime and V8"
  diff wasmtime-out.txt v8-out.txt
fi
```

Run this script across the full regression test suite. Store divergences in a structured log. A divergence that produces a crash on one runtime and a success on another is a high-priority finding: the crashing runtime may have a validation gap that the module is exploiting.

**5.2 — Floating-point determinism checks**

NaN bit patterns and floating-point rounding edge cases are the most common sources of legitimate cross-runtime divergence. Identify them before they mask genuine security divergences:

```bash
# Canonicalise NaN outputs before comparison.
# wasm-tools can rewrite a module to use canonical NaN payloads.
wasm-tools mutate --seed 0 "$MODULE" \
  | wasm-tools validate --features all \
  && echo "Mutated module is valid"
```

### Phase 6: Penetration Testing Checklist

The following checks should be performed manually or via automation for every new module version and on a scheduled basis for long-lived deployments.

| Test | Method | Expected Result |
|------|--------|-----------------|
| Import allowlist bypass | Supply a module with an import not on the allowlist; attempt to instantiate | Instantiation rejected at the linker layer before execution begins |
| Memory boundary probe | Call exported functions with offset = `memory.size * 65536 - 1`, length = 2 | Wasmtime trap (out-of-bounds memory access); no host-side exception |
| Memory boundary probe — wrap | Call with offset = `0xFFFFFFFF`, length = 4 | Wasmtime trap; no host-side exception |
| Fuel exhaustion | Supply a module with `(loop (br 0))` inside an exported function; instantiate with fuel = 1000 | Trap with `fuel exhausted`; host unblocks immediately |
| Stack depth exhaustion | Call a deeply recursive exported function; verify it traps rather than overflowing the host stack | Wasmtime trap with `call stack exhausted`; host stack intact |
| Table index overflow | Export a function that performs `call_indirect` with `table.size + 1` as the index | Wasmtime trap with `indirect call type mismatch` or `undefined element` |
| Debug section in production | Run `wasm-objdump -h` on the production artifact | No `name`, `sourceMappingURL`, or DWARF sections present |
| Signature absent | Attempt to load a module with no cosign signature in an enforcement-mode deployment | Load rejected before instantiation |
| SBOM missing CVEs | Inject a known-vulnerable dependency version into the SBOM; verify the pipeline gate fires | OSV-Scanner reports the CVE; pipeline exits non-zero |
| Host function input validation | Pass i32 values of 0, -1, MAX_INT, and `memory.size + 1` to every host function | All values handled without host-side panic or exception |

### Phase 7: CI Pipeline Integration

The seven phases form a gated promotion pipeline. Each gate must pass before the next runs. A failure at any gate blocks promotion and notifies the responsible team.

```yaml
# .github/workflows/wasm-security.yaml
name: WASM Security Pipeline

on:
  push:
    paths: ["**.wasm", "src/**"]
  pull_request:

jobs:
  static-analysis:
    name: "Gate 1: Static Analysis"
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - name: Install wasm-tools and wabt
        run: |
          cargo install wasm-tools --version "^1.220"
          apt-get install -y wabt
      - name: Validate spec compliance
        run: wasm-tools validate --features all ./dist/payments.wasm
      - name: Audit imports against allowlist
        run: |
          wasm-tools dump --imports ./dist/payments.wasm | jq -r '.[]' | sort > actual.txt
          diff approved-imports.txt actual.txt
      - name: Check for debug sections
        run: |
          if wasm-objdump -h ./dist/payments.wasm | grep -E "(name|sourceMappingURL|debug)"; then
            echo "ERROR: debug sections present in production artifact"
            exit 1
          fi

  supply-chain:
    name: "Gate 2: Supply Chain Verification"
    needs: static-analysis
    runs-on: ubuntu-24.04
    steps:
      - name: Verify module signature
        run: |
          cosign verify-blob \
            --certificate ./dist/payments.wasm.pem \
            --signature ./dist/payments.wasm.sig \
            --certificate-identity-regexp "^https://github.com/${{ github.repository }}/" \
            --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
            ./dist/payments.wasm
      - name: Scan SBOM for CVEs
        run: |
          osv-scanner --sbom ./dist/payments-sbom.json --format json \
            | jq -e '.results | map(.packages[].groups[].ids[]) | length == 0'

  dynamic-testing:
    name: "Gate 3: Dynamic Testing"
    needs: supply-chain
    runs-on: ubuntu-24.04
    steps:
      - name: Install Wasmtime
        run: curl -sSL https://wasmtime.dev/install.sh | bash
      - name: Run instrumented dynamic tests
        run: |
          for input in testdata/*.json; do
            result=$(wasmtime run --fuel 10000000 \
              ./dist/payments.wasm process < "$input" 2>&1)
            exit_code=$?
            if echo "$result" | grep -q "^wasm trap:"; then
              echo "TRAP on input $input: $result"
              exit 1
            fi
          done
      - name: Confirm resource limits trap correctly
        run: |
          wasmtime run --fuel 1000 ./test/infinite-loop.wasm && exit 1 || true

  differential-testing:
    name: "Gate 4: Differential Testing"
    needs: dynamic-testing
    runs-on: ubuntu-24.04
    steps:
      - name: Install runtimes
        run: |
          curl -sSL https://wasmtime.dev/install.sh | bash
          curl -sSL https://raw.githubusercontent.com/WasmEdge/WasmEdge/master/utils/install.sh | bash
          npm install -g @bytecodealliance/wasmtime
      - name: Run differential comparison
        run: bash scripts/diff-test.sh ./dist/payments.wasm testdata/

  host-boundary-fuzzing:
    name: "Gate 5: Host Boundary Fuzzing"
    needs: supply-chain
    runs-on: ubuntu-24.04
    steps:
      - name: Run boundary value test suite
        run: bash scripts/boundary-test.sh ./dist/payments.wasm
      - name: Run fuzz corpus (regression only)
        run: |
          cargo fuzz run host_boundary -- \
            -runs=0 \
            fuzz/corpus/host_boundary/

  penetration-checklist:
    name: "Gate 6: Penetration Test Checks"
    needs: [dynamic-testing, host-boundary-fuzzing]
    runs-on: ubuntu-24.04
    steps:
      - name: Automated pen-test assertions
        run: bash scripts/pentest-assertions.sh ./dist/payments.wasm

  promotion-gate:
    name: "Promote to Production"
    needs: [penetration-checklist, differential-testing]
    runs-on: ubuntu-24.04
    steps:
      - name: All gates passed — promote artifact
        run: |
          echo "All 6 security gates passed for ${{ github.sha }}"
          # Tag the OCI artifact as production-ready.
          cosign copy \
            ghcr.io/${{ github.repository }}/payments-wasm:${{ github.sha }} \
            ghcr.io/${{ github.repository }}/payments-wasm:production
```

## Operational Notes

**Corpus management.** The host boundary fuzzer accumulates a corpus over time. Commit the corpus to a dedicated repository and restore it in CI via cache. A corpus that is discarded between runs loses the coverage gains from previous runs and produces slower regression detection.

**Baseline divergences.** The differential testing step will initially produce divergences on modules that use non-canonical NaN values or rely on implementation-specific memory growth behaviour. Establish a documented baseline of known-acceptable divergences so that new divergences are immediately visible without noise from known cases.

**Import allowlist review cadence.** The approved-imports.txt file must be reviewed when the module's WIT world changes. Set a CODEOWNERS rule that requires a security team review on any change to that file. An approved import that was added without review for a one-off need and never removed is one of the most common sources of unnecessary capability exposure.

**Signature enforcement modes.** During initial rollout, run the signature verification gate in audit mode (log failures but do not block promotion). After verifying that the build pipeline produces correctly-signed artifacts for every commit, switch to enforcement mode. Running in audit mode indefinitely defeats the control.

**Fuel calibration.** The fuel limit in dynamic testing must be calibrated against the module's expected maximum legitimate workload. A limit set too low produces false positives in testing and rejection of valid inputs in production. Profile the module against the largest legitimate input in the test corpus to establish a maximum fuel consumption baseline, then set the production limit at 2x that value.

## Summary

A complete WASM security testing programme requires seven coordinated phases. Static analysis with wasm-validate, wasm-objdump, and semgrep establishes the declared surface. Supply chain verification with cosign, syft, and SLSA provenance confirms the artifact is what it claims to be. Dynamic testing under a fuel-limited, memory-bounded Wasmtime confirms runtime enforcement. Host boundary fuzzing with libFuzzer and boundary value enumeration finds host integration bugs that the sandbox does not protect against. Differential testing across Wasmtime, V8, and WasmEdge surfaces spec-interpretation divergences before they reach production. The penetration testing checklist provides a structured set of manual assertions covering the highest-value attack vectors. Gating all six phases in CI, with each phase as a required check before promotion, ensures that no module reaches production without passing the full methodology.

The common failure pattern is not a missing tool but missing gates: teams run static analysis but skip supply chain verification, or fuzz the module but never test the host integration layer. Each phase covers attack vectors the others do not. The value of the methodology is in running all phases in sequence, not in running one phase thoroughly.
