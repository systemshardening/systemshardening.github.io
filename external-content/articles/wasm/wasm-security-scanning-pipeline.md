---
title: "Security Scanning for WebAssembly: SAST for Rust Source and Binary Analysis of Compiled Modules"
description: "WASM security scanning requires a two-layer approach: static analysis of the source language (Rust Clippy security lints, cargo-audit, semgrep) catches vulnerabilities before compilation, and binary-level analysis of the compiled WASM module (wasm-objdump, wasm-decompile, twiggy) verifies the output has expected properties. This guide builds a complete WASM security scanning pipeline for Rust and C compiled to WASM."
slug: wasm-security-scanning-pipeline
date: 2026-05-08
lastmod: 2026-05-08
category: wasm
tags:
  - wasm
  - security-scanning
  - sast
  - cargo-audit
  - supply-chain
personas:
  - security-engineer
  - platform-engineer
article_number: 648
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/wasm/wasm-security-scanning-pipeline/
---

# Security Scanning for WebAssembly: SAST for Rust Source and Binary Analysis of Compiled Modules

## Problem

WebAssembly modules are artifacts that break the assumptions baked into most SAST tooling. Standard static analysis tools — Semgrep rules for Python, ESLint security plugins for JavaScript, Bandit for Python — operate on source code in a specific language. Container image scanners operate on a filesystem with package metadata. A `.wasm` binary is neither: it is compiled bytecode that carries no package manifest, no source file paths by default, and no language-specific metadata that off-the-shelf scanners know how to interpret.

This creates a genuine security gap. A Rust crate with a known CVE compiled into a WASM module is completely invisible to container image scanners running Trivy or Grype against the deployment image — those tools look for dpkg records, RPM databases, and lockfiles, none of which exist inside a `.wasm` file. The dependency was resolved at build time and the code was baked into the binary. Once compiled, it is indistinguishable from any other function in the module.

The consequence is a two-layer scanning requirement that most teams miss. Vulnerabilities in Rust source code — unsafe blocks that could corrupt linear memory, integer arithmetic that can overflow in a WASM context, use of deprecated cryptographic primitives, dependencies with disclosed CVEs — must be caught at the source level before compilation, where the tooling exists to find them. Properties of the compiled binary itself — unexpected imports that were not in the source code you audited, debug symbols that should have been stripped for production, unusually large code sections suggesting a supply chain injection — must be verified post-compilation, because these properties exist only in the binary artifact.

A third scenario that practitioners underestimate is supply chain risk for externally sourced WASM modules. A WASM module downloaded from npm, embedded in a CDN response, or distributed as a plugin should be treated as an untrusted artifact and analysed before it is loaded into a runtime. Source scanning is not available in this case. Binary analysis is the only option, and it needs to be systematic.

## Threat Model

Three threats motivate the two-layer approach.

**Rust `unsafe` block enabling memory corruption exploitable from the host.** WASM's linear memory model provides isolation between the module's address space and the host's, but that isolation only holds when the WASM runtime correctly bounds-checks memory accesses and the module itself does not corrupt its own heap in ways the host trusts. Rust's `unsafe` keyword unlocks raw pointer arithmetic, arbitrary casts, and direct memory manipulation. In a WASM context, `unsafe` code that writes beyond the bounds of a buffer it received from the host — a string passed via `allocate`/`write`/`call`/`read` pattern — can corrupt adjacent heap allocations, potentially including function table entries in runtimes that embed them in linear memory. The module may be sandboxed, but if the host reads back a corrupted value and acts on it (a deserialized struct, a pointer it allocated and trusted), the host can be compromised. Source scanning with Clippy and Semgrep can identify unsafe blocks that lack the surrounding invariants needed to make them sound.

**Cargo dependency with a known CVE compiled into a WASM module, invisible to container image scanners.** A team compiles a Rust HTTP handler to WASM, pulls in a popular serialization crate, and ships the module. Six months later the crate is found to have a denial-of-service vulnerability on malformed input. The container image scanner on the deployment pipeline passes cleanly because it is scanning the Wasmtime runtime binary, not the module. The module is just an opaque file to the container scanner. Only `cargo audit` run against the `Cargo.lock` at build time, or embedded into the CI pipeline as a gate, would have caught this.

**Compiled WASM module containing unexpected imports not in the source code.** A supply chain compromise against a WASM module distributed via a registry or CDN might add new imports — a call to a host function that exfiltrates data, or a WASI filesystem import that gives the module read access to paths the host policy intended to block. The compiled binary surface includes an import section that is trivially auditable with `wasm-objdump`. Maintaining a known-good import list and diffing each new build against it is a low-cost, high-signal check that source-only scanning cannot provide.

## Configuration and Implementation

### Layer 1: Rust Source Scanning

Source scanning for Rust WASM projects uses the standard Rust security toolchain. The compilation target (`wasm32-wasi`, `wasm32-unknown-unknown`) does not change which advisories apply to Cargo dependencies or which Clippy lints fire — those are properties of the Rust source, not the target architecture.

#### cargo-audit

`cargo-audit` queries the RustSec advisory database against your `Cargo.lock`, identifying dependencies with known CVEs, yanked versions, and unmaintained crates. It is the closest equivalent to a container image scanner for Rust projects.

```bash
cargo install cargo-audit
cargo audit --deny warnings --json | tee audit-results.json
```

The `--deny warnings` flag promotes warnings to errors, making the CI step fail on unmaintained crates or informational advisories, not just confirmed vulnerabilities. Teams that want more nuance can configure `.cargo/audit.toml` to ignore specific advisories with a justification and expiry date:

```toml
[advisories]
ignore = [
  # RUSTSEC-2024-XXXX: time crate. Not exploitable on wasm32 target.
  # Review by: alice@example.com, 2026-05-08, re-evaluate 2026-08-01
  "RUSTSEC-2024-XXXX",
]
```

The justification and re-evaluation date are critical. An ignored advisory with no expiry becomes a permanent blind spot. Pair the `.cargo/audit.toml` ignore list with a calendar reminder or a CI job that fails when advisories past their re-evaluation date are still suppressed.

For GitHub Actions with Code Scanning integration, cargo-audit can emit SARIF output that populates the Security tab:

```yaml
- name: Run cargo-audit
  uses: rustsec/audit-check@v2
  with:
    token: ${{ secrets.GITHUB_TOKEN }}
    deny: warnings
```

This surfaces advisories inline on pull requests, where developers can address them before merge rather than finding them in a post-deployment scan report.

#### Clippy Security Lints

Clippy is Rust's linter. Its default lint set is style-focused, but it includes a substantial number of security-relevant lints that must be explicitly enabled or promoted from warning to error. For WASM security work, the following invocation is appropriate:

```bash
cargo clippy -- \
  -W clippy::all \
  -W clippy::pedantic \
  -D clippy::unwrap_used \
  -D clippy::expect_used \
  -D clippy::panic \
  -D clippy::integer_arithmetic
```

Each `-D` flag denies (errors on) the named lint. The security rationale for each:

- `clippy::unwrap_used` — calling `.unwrap()` on a `None` or `Err` value panics. In a WASM module hosted by a runtime like Wasmtime or WasmEdge, a trap is not a process crash — it surfaces to the host as an error that the host must handle correctly. Panics in security-critical paths (authentication, authorization, cryptographic operations) should be replaced with explicit error handling that can be logged and acted on.
- `clippy::expect_used` — same rationale as `unwrap_used`; the string argument to `expect` is visible in panic messages and may leak internal state.
- `clippy::panic` — explicit `panic!()` calls in production code are almost always replaceable with `Result` propagation.
- `clippy::integer_arithmetic` — arithmetic operations that can overflow silently (addition, subtraction, multiplication) without checked, saturating, or wrapping variants. Integer overflow in buffer sizing calculations is a classic source of memory safety vulnerabilities. In WASM, where the linear memory model is 32-bit by default, arithmetic on sizes and indices is particularly risky.

Additional WASM-specific lints worth enabling:

- `clippy::large_stack_arrays` — WASM's default stack size is typically 1 MB. Large arrays allocated on the stack are a stack overflow vector that is more constrained in WASM than on a native target with a 8 MB default stack.
- `clippy::mem_replace_with_uninit` — replacing a value with uninitialized memory creates undefined behaviour even in Rust; this is unsound regardless of target.
- `clippy::unsound_collection_transmute` — transmuting between collection types with different element types violates Rust's type system invariants.

For CI, run Clippy with `RUSTFLAGS` to ensure the lints apply to all crates in the workspace, not just the top-level crate:

```bash
RUSTFLAGS="-D clippy::unwrap_used -D clippy::integer_arithmetic" \
  cargo clippy --all-targets --workspace
```

#### cargo-deny

`cargo-deny` enforces policy at the dependency graph level, beyond what `cargo-audit` provides. Where `cargo-audit` checks for known vulnerabilities, `cargo-deny` enforces license compliance, blocks specific crates by name, and restricts which source registries dependencies may come from.

```bash
cargo deny check advisories licenses sources
```

A `deny.toml` configuration for a WASM project that must use only crates.io and a private registry:

```toml
[advisories]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"

[licenses]
allow = ["MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "BSD-2-Clause", "BSD-3-Clause"]
deny = ["GPL-2.0", "LGPL-2.0"]

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
# Allow private registry for internal crates
# allow-registry = ["https://internal.example.com/crates"]

[bans]
deny = [
  # openssl has complex C FFI; use rustls instead for WASM
  { name = "openssl-sys" },
  # rand 0.7 and earlier have known weaknesses
  { name = "rand", wrappers = ["rand_core"], version = "<0.8" },
]
```

Banning `openssl-sys` is WASM-specific: it requires C compilation and links against the system OpenSSL library, which is incompatible with `wasm32-unknown-unknown` and produces unexpected build failures or fallback paths in `wasm32-wasi`. Teams should be using `rustls` or `ring` for WASM cryptography, and `cargo-deny` enforces that policy structurally rather than relying on developers remembering.

#### Semgrep Rust Rules

Semgrep rules for Rust can find patterns that Clippy does not cover — particularly patterns in the interaction between `unsafe` code and WASM-specific APIs. Three rules are worth running as custom checks:

**Detecting unsafe blocks with raw pointer arithmetic without explicit bounds checks:**

```yaml
rules:
  - id: wasm-unsafe-ptr-arithmetic-no-bounds
    languages: [rust]
    message: "Unsafe raw pointer arithmetic without bounds check in WASM context"
    severity: ERROR
    pattern: |
      unsafe {
        ...
        $PTR.add($OFFSET)
        ...
      }
    pattern-not: |
      unsafe {
        ...
        assert!($OFFSET < $LEN);
        ...
        $PTR.add($OFFSET)
        ...
      }
```

**Detecting `std::mem::transmute` in security-critical paths:**

```yaml
rules:
  - id: wasm-transmute-use
    languages: [rust]
    message: "Use of std::mem::transmute is unsound and should be reviewed"
    severity: WARNING
    pattern: std::mem::transmute(...)
```

**Detecting `std::ptr::copy_nonoverlapping` without preceding length validation:**

```yaml
rules:
  - id: wasm-copy-nonoverlapping-no-len-check
    languages: [rust]
    message: "copy_nonoverlapping without preceding length validation"
    severity: ERROR
    pattern: |
      std::ptr::copy_nonoverlapping($SRC, $DST, $LEN)
    pattern-not-inside: |
      assert!($LEN <= ...);
      ...
      std::ptr::copy_nonoverlapping($SRC, $DST, $LEN)
```

Run Semgrep in CI using the `returntocorp/semgrep-action` GitHub Action, pointing it at the `rules/` directory containing these custom YAML files alongside any community Rust security rules from the Semgrep registry.

### Layer 2: Compiled WASM Binary Scanning

Binary scanning operates on the `.wasm` artifact produced by compilation. It does not require access to source code, which is what makes it applicable to third-party modules. The primary tools are `wasm-objdump` (part of the `wabt` toolkit), `twiggy`, and `wasm-decompile`.

#### Import and Export Surface Verification

The WASM binary format stores imports in a dedicated section at the beginning of the module. Every host function the module can call is listed there by module name and function name. This list is the entire attack surface the module presents to the host: if an import is not in the list, the module cannot call it.

Maintaining a known-good import list and diffing each build against it provides high-signal detection of supply chain injections and unexpected dependency additions:

```bash
wasm-objdump -x module.wasm | grep -E "Import|Export"
# Compare against expected imports/exports list
diff <(wasm-objdump -x module.wasm | grep "Import" | sort) expected-imports.txt
```

A non-zero diff exit code should fail the CI job immediately. The `expected-imports.txt` file is maintained in version control alongside the source, and changes to it require code review just like changes to source code.

For a WASI module, the expected imports are a subset of the WASI snapshot preview1 or preview2 namespace. An unexpected import from a different module namespace — particularly one that looks like a host-defined function name — is a strong indicator of a supply chain compromise or an undocumented host dependency.

#### Debug Symbol Detection

Debug symbols embedded in a WASM module reveal function names, local variable names, and file paths from the compilation environment. In production builds these should be stripped. Their presence in a production binary indicates a build configuration problem at minimum, and in a third-party module they can reveal information about the original development environment or indicate a debug build was shipped by mistake.

```bash
wasm-objdump -x module.wasm | grep -E "name section|custom section"
# Should not contain a name section in production builds
wasm-objdump -j name module.wasm 2>/dev/null | head -5
```

If the name section is present, strip it using `wasm-opt`:

```bash
wasm-opt --strip-debug -O3 module.wasm -o module.stripped.wasm
```

For Rust WASM projects, ensure the release profile strips debug info:

```toml
[profile.release]
debug = false
strip = "symbols"
lto = true
opt-level = "z"
```

#### Binary Size Analysis with twiggy

`twiggy` is a code size profiler for WASM binaries. It parses the DWARF debug information (if present) or the WASM name section to attribute bytes to specific functions and their callers. Its primary use is optimization, but it is equally useful for security analysis: unexpectedly large functions or unexpectedly included libraries are visible in its output.

```bash
cargo install twiggy
twiggy top -n 20 module.wasm
```

The output lists the 20 largest items by byte count. If a module that should only contain a small JSON parser shows a large cryptographic library, a base64 encoder, and a network library in the top items, that warrants investigation. Compare the twiggy output between known-good builds to detect additions:

```bash
twiggy top -n 50 module.wasm | sort > current-top.txt
diff expected-top.txt current-top.txt
```

This is not a precise gate — function names and sizes change with every non-trivial code change — but significant new entries warrant review.

#### Detecting Unexpected Custom Sections

The WASM binary format defines 12 standard section types (Type, Import, Function, Table, Memory, Global, Export, Start, Element, Code, Data, DataCount). A Custom section with any name may appear anywhere in the module. Custom sections are used legitimately for debug info, producer metadata, and target feature declarations. They can also be used to embed arbitrary data — including plaintext credentials, encoded payloads, or hidden functionality.

A Python script to enumerate all sections in a WASM binary and flag unexpected custom sections:

```python
#!/usr/bin/env python3
"""Parse WASM binary section headers and flag unexpected sections."""
import sys
import struct

STANDARD_SECTION_IDS = set(range(0, 13))
KNOWN_CUSTOM_SECTIONS = {"name", "producers", "target_features"}

def read_leb128(data, offset):
    result = 0
    shift = 0
    while True:
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            return result, offset

def parse_sections(path):
    with open(path, "rb") as f:
        data = f.read()
    assert data[:4] == b"\x00asm", "Not a WASM module"
    offset = 8  # skip magic + version
    while offset < len(data):
        section_id = data[offset]
        offset += 1
        section_size, offset = read_leb128(data, offset)
        section_end = offset + section_size
        if section_id == 0:  # custom section
            name_len, name_offset = read_leb128(data, offset)
            name = data[name_offset:name_offset + name_len].decode("utf-8", errors="replace")
            status = "OK" if name in KNOWN_CUSTOM_SECTIONS else "UNEXPECTED"
            print(f"  Custom section: '{name}' ({section_size} bytes) [{status}]")
        else:
            print(f"  Section ID {section_id} ({section_size} bytes)")
        offset = section_end

if __name__ == "__main__":
    parse_sections(sys.argv[1])
```

Run this in CI and fail if any custom section name is not in `KNOWN_CUSTOM_SECTIONS`.

#### wasm-decompile for Readable Analysis

`wasm-decompile` (part of the `wabt` toolkit) produces a readable pseudocode representation of the WASM bytecode. It is not a decompiler to the source language — the output is not Rust or C — but it is far more readable than raw WAT, and it supports grep-based searches for suspicious patterns:

```bash
wasm-decompile module.wasm -o module.dcmp
grep -i "password\|secret\|key\|token" module.dcmp
```

Finding hardcoded strings that look like credentials in a decompiled WASM module is rare but high-severity when it occurs. This check is most useful for auditing third-party modules where the source is not available.

#### Automated WASM Binary Security Properties Script

The following script encapsulates the binary checks into a single CI-runnable verification:

```bash
#!/bin/bash
# verify-wasm-security.sh — run against a compiled WASM module
set -euo pipefail

MODULE="${1:?Usage: $0 <module.wasm>}"
EXPECTED_IMPORTS="${2:-expected-imports.txt}"
EXIT_CODE=0

echo "=== Binary: $MODULE ==="
echo ""

echo "=== Import surface ==="
IMPORT_COUNT=$(wasm-objdump -x "$MODULE" | grep -c "Import" || true)
echo "  Total imports: $IMPORT_COUNT"
if [[ -f "$EXPECTED_IMPORTS" ]]; then
  echo "  Diffing against $EXPECTED_IMPORTS"
  if ! diff <(wasm-objdump -x "$MODULE" | grep "Import" | sort) "$EXPECTED_IMPORTS"; then
    echo "  ERROR: Import surface mismatch"
    EXIT_CODE=1
  fi
fi
echo ""

echo "=== Debug symbols ==="
if wasm-objdump -x "$MODULE" | grep -q "name section"; then
  echo "  WARNING: name section present — strip with wasm-opt --strip-debug"
  EXIT_CODE=1
else
  echo "  OK: no name section"
fi
echo ""

echo "=== Custom sections ==="
wasm-objdump -x "$MODULE" | grep "Custom section" || echo "  None"
echo ""

echo "=== Binary size ==="
SIZE=$(wc -c < "$MODULE")
echo "  $SIZE bytes ($(( SIZE / 1024 )) KB)"
echo ""

echo "=== Largest functions (top 10) ==="
twiggy top -n 10 "$MODULE" 2>/dev/null || echo "  twiggy not installed — skipping"
echo ""

exit $EXIT_CODE
```

### CI Pipeline: Combining Both Layers

```yaml
name: WASM Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:

jobs:
  source-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy

      - name: cargo audit
        run: |
          cargo install cargo-audit --quiet
          cargo audit --deny warnings --json | tee audit-results.json

      - name: cargo deny
        run: |
          cargo install cargo-deny --quiet
          cargo deny check advisories licenses sources

      - name: Clippy security lints
        run: |
          cargo clippy --all-targets --workspace -- \
            -D clippy::unwrap_used \
            -D clippy::expect_used \
            -D clippy::integer_arithmetic \
            -D clippy::panic \
            -W clippy::large_stack_arrays \
            -D clippy::mem_replace_with_uninit

      - name: Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: rules/wasm-security.yml

  binary-scan:
    runs-on: ubuntu-latest
    needs: source-scan
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust toolchain + WASM target
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: wasm32-wasi

      - name: Install wabt tools
        run: |
          sudo apt-get install -y wabt
          cargo install twiggy --quiet

      - name: Build WASM module
        run: cargo build --target wasm32-wasi --release

      - name: Verify import surface
        run: |
          ./scripts/verify-wasm-security.sh \
            target/wasm32-wasi/release/module.wasm \
            scripts/expected-imports.txt

      - name: Check no debug symbols
        run: |
          if wasm-objdump -x target/wasm32-wasi/release/module.wasm \
             | grep -q "name section"; then
            echo "ERROR: debug symbols present in release build"
            exit 1
          fi

      - name: Scan for secrets in decompiled output
        run: |
          wasm-decompile target/wasm32-wasi/release/module.wasm \
            -o /tmp/module.dcmp
          if grep -iE "password|secret|api.?key|token" /tmp/module.dcmp; then
            echo "WARNING: potential credentials in compiled WASM"
            exit 1
          fi
```

### Scanning Third-Party WASM Modules

When receiving a WASM module from a third party — a downloaded plugin, an npm package with a `.wasm` asset, a CDN-hosted module — apply the binary scanning layer before loading it into any runtime. Source scanning is unavailable, so the binary analysis must be exhaustive:

1. **Import surface check**: enumerate all imports and verify every host function name is expected. Any import not in your runtime's provided host API is a red flag — the module will fail to instantiate, but the presence of unexpected imports indicates the module was built against a different or extended host.
2. **Custom section audit**: run the section parser script and verify only standard custom sections are present. Unknown custom sections with large payloads warrant decompilation and analysis.
3. **Debug symbol extraction**: the presence of a name section reveals function names from the original build, which can indicate the module's provenance or reveal information about its internals.
4. **Strings analysis**: extract all string literals from the module using `strings module.wasm` and review for hardcoded URLs, IP addresses, credential patterns, or internal domain names.
5. **Size plausibility**: compare the binary size against the claimed functionality. A module advertised as a JSON parser that is 2 MB uncompressed likely includes more functionality than described.
6. **Verify the hash**: if a checksum is provided by the distributor, verify it before any analysis. If the module is signed (OCI signing, COSE, Sigstore), verify the signature.

## Expected Behaviour

| Vulnerability Type | Scanning Layer | Tool | CI Action |
|---|---|---|---|
| Dependency with known CVE | Source | cargo-audit | Fail job, block merge |
| Banned or unlicensed crate | Source | cargo-deny | Fail job, block merge |
| `unwrap()` on security-critical path | Source | Clippy | Fail job |
| Integer overflow in size calculation | Source | Clippy | Fail job |
| Raw pointer arithmetic without bounds check | Source | Semgrep | Fail job |
| `transmute` in security-critical code | Source | Semgrep | Warning, require review |
| Unexpected import in compiled module | Binary | wasm-objdump + diff | Fail job |
| Debug symbols in production build | Binary | wasm-objdump | Fail job |
| Unexpected custom section | Binary | section parser script | Warning, require review |
| Hardcoded credentials in bytecode | Binary | wasm-decompile + grep | Fail job |
| Unexpectedly large dependency included | Binary | twiggy | Warning, require review |

## Trade-offs

Source scanning provides the richest signal but requires access to source code and a `Cargo.lock`. It cannot be applied to third-party modules where source is not distributed. The tooling — Clippy, cargo-audit, cargo-deny — is well-maintained and integrates naturally into Rust workflows, but it is Rust-specific: teams compiling C or C++ to WASM need a different source scanning stack (clang-tidy, cppcheck, flawfinder for the source; the binary layer is identical regardless of source language).

Binary scanning applies universally but has limited coverage. `wasm-objdump` can tell you what imports are declared and whether a name section is present, but it cannot identify a CVE in the compiled code without access to the dependency graph. Binary scanning is best understood as a verification layer — confirming that the binary matches expectations from the source scan — rather than a standalone security gate.

Maintaining `expected-imports.txt` as the module's API evolves is an ongoing operational cost. Every time a new host function is added to the WASM interface, the expected imports file must be updated and reviewed. Teams that treat this file as bureaucratic overhead will let it drift, making the import surface check useless. The file should be treated as a security-critical API contract and managed accordingly: changes require a security review, and the CI check should fail hard on any deviation rather than warn.

## Failure Modes

**cargo-audit false positives blocking builds.** The RustSec advisory database occasionally publishes advisories for crates that are technically vulnerable but not exploitable in specific contexts — for example, an advisory for a crate that is only vulnerable on 32-bit Windows, compiled for a WASM target. The correct response is to add the advisory to `.cargo/audit.toml` with a justification and re-evaluation date, not to disable `--deny warnings` globally. Disabling the flag removes the CI gate entirely.

**Clippy lint version incompatibilities.** Clippy lints are occasionally renamed, split, or removed between Rust versions. A CI pipeline pinned to a Clippy lint name that no longer exists will fail with an error that is confusing to developers unfamiliar with the tooling. Pin the Rust toolchain version in `rust-toolchain.toml` and test lint upgrades as part of the Rust version update process.

**wasm-objdump not installed on CI runners.** The `wabt` package is not universally pre-installed on CI runners. Ubuntu's `apt` package is `wabt` and installs `wasm-objdump`, `wasm-decompile`, and related tools. Add an explicit installation step at the beginning of the binary scan job rather than assuming it is present. Alpine users need `apk add wabt`; the package name may differ across distributions.

**Import allowlist becoming stale.** The most common failure mode for the import surface check is not a malicious injection but a legitimate API change — a new WASI capability is added to the module, the expected imports file is not updated, and the CI check fails for every developer until someone updates the file. This creates pressure to disable the check rather than maintain it. Establish a clear process: when the import surface changes, update `expected-imports.txt` in the same commit as the source change that requires the new import, and include a note in the commit message explaining the addition. Treating the expected imports as a first-class deliverable — not a generated artifact — keeps the maintenance cost predictable and the check credible.
