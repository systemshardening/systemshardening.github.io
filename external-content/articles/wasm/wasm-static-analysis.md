---
title: "WASM Module Static Analysis and Vulnerability Scanning: wasm-tools, twiggy, and CVE Detection"
description: "Scanning .wasm artifacts is different from scanning containers — no rootfs, no package manager. The dependency graph is in the bytecode."
slug: "wasm-static-analysis"
date: 2026-04-27
lastmod: 2026-04-27
category: "wasm"
tags: ["wasm", "static-analysis", "wasm-tools", "twiggy", "vulnerability-scanning"]
personas: ["security-engineer", "platform-engineer", "devops"]
article_number: 188
difficulty: "intermediate"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/wasm/wasm-static-analysis/index.html"
---

# WASM Module Static Analysis and Vulnerability Scanning: wasm-tools, twiggy, and CVE Detection

## Problem

Container scanning is a mature ecosystem: Trivy, Grype, Snyk, Anchore, and many others ingest container images, identify installed packages from their metadata files (`/var/lib/dpkg/status`, `/var/lib/rpm/Packages`, language-specific lockfiles), and match those packages against vulnerability databases. The model assumes the artifact is a filesystem with package metadata.

WASM artifacts are different. A `.wasm` module is a single bytecode file with:

- No rootfs and no package manager metadata.
- All linked dependencies compiled in. There is no `Cargo.lock` accompanying the binary; the dependency tree was resolved at build time.
- No symbolic information unless the module embeds custom sections (`name`, `producers`, `target_features`).
- Imports declared in the WASM `import` section. Exports declared in the `export` section. Functions, memory, tables, globals — all visible to a parser.

Standard container scanners produce noise or silence on `.wasm` files. WASM-specific tooling exists but is less consolidated than the container side. By 2026, the practical pipeline combines:

- **`wasm-tools`** (Bytecode Alliance) — dump imports/exports, validate, decode, and surface custom sections.
- **`twiggy`** — call-graph and code-size analysis; finds the largest functions and the deepest call chains.
- **`wasm-objdump`** (from WABT) — disassembly to text; useful for forensic comparison.
- **Provenance attestations** — SLSA build statements link the artifact back to its source repo and dependency tree.
- **CVE databases for WASM-targeted libraries** — emerging; OSV.dev tracks Rust/Go/AssemblyScript dependencies that compile to WASM, with identifiers usable when the module's SBOM is available.

This article covers what to scan for, how to extract the information, how to integrate the scans into CI, and how to act on the findings. The approach: extract metadata from the bytecode, correlate against an SBOM produced at build time, and gate deploys on the result.

**Target systems:** wasm-tools 1.220+, twiggy 0.7+, wabt 1.0.36+, OSV-Scanner 1.9+ for SBOM-based vulnerability lookup, syft 1.16+ for SBOM generation when source is available.

## Threat Model

- **Adversary 1 — Vulnerable dependency in a WASM module:** the module compiled in a library version with a known CVE. The vulnerability may be exploitable depending on which functions are reachable in the WASM call graph.
- **Adversary 2 — Maliciously-injected dependency:** the module's source pulled a typosquatted or compromised package; the malicious code is now embedded in the bytecode.
- **Adversary 3 — Backdoored function:** the module exports an undeclared "debug" function that, when called, performs sensitive operations.
- **Adversary 4 — Capability-creep:** the module imports more than its WIT world declares (possible if the build was tampered with after WIT generation).
- **Access level:** Adversary 1 is a passive supply-chain risk. Adversary 2 has commit access or registry-push access. Adversary 3 has source-code access. Adversary 4 has build-pipeline access.
- **Objective:** Get a module deployed that executes malicious code, exfiltrates data, or has unauthorized capabilities.
- **Blast radius:** Bounded by the module's runtime sandbox at execution. With good static analysis, the bound shrinks to the legitimate-build-pipeline surface.

## Configuration

### Step 1: Validate and Decode the Module

```bash
# Validate the module's structure.
wasm-tools validate ./payments.wasm
# (no output on success; returns non-zero on invalid bytecode)

# Dump the imports and exports.
wasm-tools dump ./payments.wasm --import --export
# 0:   import { module: "wasi:filesystem/types@0.2.0",
#               name: "[method]descriptor.read",
#               kind: function }
# 1:   import { module: "wasi:io/streams@0.2.0",
#               name: "[method]input-stream.blocking-read",
#               kind: function }
# ...
# 12:  export { name: "_start", kind: function }
# 13:  export { name: "wasi:cli/run@0.2.0#run", kind: function }

# For component modules, dump the WIT.
wasm-tools component wit ./payments.wasm
```

Build a baseline of expected imports and exports per module. Diff actual against expected on every build:

```bash
EXPECTED="ghcr.io/myorg/wasm-baselines/payments-imports.txt"
ACTUAL=$(mktemp)
wasm-tools dump ./payments.wasm --import | awk -F'"' '/^.*import.*module:/ {print $4 "/" $6}' | sort -u > "$ACTUAL"

if ! diff -q "$EXPECTED" "$ACTUAL"; then
    echo "Imports drift detected:"
    diff "$EXPECTED" "$ACTUAL"
    exit 1
fi
```

A new import that was not in the baseline is a security review event.

### Step 2: Inspect Custom Sections for Producer Info

WASM modules can carry `producers` and `target_features` custom sections. These reveal the toolchain that built the module.

```bash
wasm-tools dump --custom-sections ./payments.wasm | head
# section: producers
#   language: Rust
#     version: 1.83.0
#   processed-by: clang
#     version: 19.1.0
#   processed-by: rustc
#     version: 1.83.0 (sha 1a2b3c4d)
#
# section: target_features
#   feature: bulk-memory (required)
#   feature: mutable-globals (required)
```

Use the `producers` field to enforce build-environment policy:

```bash
TOOLCHAIN=$(wasm-tools dump --custom-sections ./payments.wasm |
    awk '/processed-by: rustc/ {getline; print $2}')

if [[ "$TOOLCHAIN" != "1.83.0" && "$TOOLCHAIN" != "1.84.0" ]]; then
    echo "WASM module was built with an unapproved Rust toolchain: $TOOLCHAIN"
    exit 1
fi
```

A module without a `producers` section, or with an unexpected toolchain, did not come from your CI.

### Step 3: Generate an SBOM at Build Time

The most reliable WASM scanning starts with an SBOM produced when the module was built. The bytecode itself does not carry full dependency metadata.

```bash
# In the build pipeline, after `cargo build --target wasm32-wasip2`.
syft scan dir:. --output cyclonedx-json=sbom.json
# Or for Cargo specifically:
cargo cyclonedx -f json > sbom.json

# Attach the SBOM to the OCI artifact.
oras attach ghcr.io/myorg/wasm/payments:1.2.3 \
  --artifact-type application/vnd.cyclonedx+json \
  sbom.json:application/vnd.cyclonedx+json
```

The artifact ships with its SBOM; the SBOM names every dependency at the version included in the bytecode. Verifiers can scan the SBOM independently of the bytecode.

### Step 4: Vulnerability Scan via SBOM

OSV-Scanner reads CycloneDX/SPDX SBOMs and matches against the OSV vulnerability database, which covers Rust crates, Go modules, npm, PyPI, and others — the languages most often used to produce WASM.

```bash
osv-scanner --sbom=sbom.json --output json > scan-report.json

cat scan-report.json | jq '.results[] | .packages[] |
  select(.vulnerabilities | length > 0) |
  {pkg: .package.name, version: .package.version,
   cves: [.vulnerabilities[].id]}'
# {
#   "pkg": "openssl",
#   "version": "0.10.55",
#   "cves": ["RUSTSEC-2024-0357", "GHSA-9c8h-..."]
# }
```

Gate the deploy on findings. CI step:

```yaml
- name: Scan SBOM for vulnerabilities
  run: osv-scanner --sbom=sbom.json --fail-on=high
```

### Step 5: Call-Graph and Reachability Analysis

A vulnerability in a dependency is concerning only if the affected code is reachable from an export. `twiggy` produces call graphs:

```bash
# Find what calls a specific function.
twiggy paths ./payments.wasm --top 5 'openssl::ssl::SslContext::new'

# List the largest functions; review the top of the list.
twiggy top -n 30 ./payments.wasm

# Generate a call-graph DOT file.
twiggy garbage ./payments.wasm > unused-functions.txt
```

For a vulnerability that requires calling a specific function, check whether that function is reachable:

```bash
# Returns reachable paths from any export to the vulnerable function.
twiggy paths ./payments.wasm 'sha2::digest::Digest::update' --max-paths 10
```

If `twiggy paths` returns no path from any export, the function is dead code in this build (likely tree-shaken by the linker but still present in the bytecode). The vulnerability is theoretical for this artifact even if listed in the SBOM.

### Step 6: Pattern Matching for Suspicious Constants

Some attacks embed known-bad strings: hardcoded URLs, base64-encoded payloads, suspicious crypto constants. Scan the bytecode's data section:

```bash
# Extract all string-like data from the .data section.
wasm-tools demangle ./payments.wasm | strings -n 8 - > strings.txt

# Check against IoC list.
grep -F -f /etc/wasm-iocs/known-bad-domains.txt strings.txt
grep -E 'ngrok\.|webhook\.site|requestbin\.com' strings.txt
grep -E '^(http|ftp|ws)s?://[a-z0-9.-]+\.(?:xyz|cn|tk|ml|ga)' strings.txt
```

A WASM module with an embedded ngrok URL or a domain on a known-bad list does not belong in production. The IoC list pattern is the same as for container scanning; the source of strings is different.

### Step 7: Capability Surface Audit

For Preview 2 components, audit the capability imports:

```bash
wasm-tools component wit ./payments.wasm | awk '/^  import/ {print $2}' | sort -u
# wasi:clocks/wall-clock@0.2.0
# wasi:filesystem/types@0.2.0
# wasi:io/streams@0.2.0

# Check against an approved list.
ALLOWED=(
  "wasi:clocks/wall-clock@0.2.0"
  "wasi:clocks/monotonic-clock@0.2.0"
  "wasi:io/streams@0.2.0"
  "wasi:io/error@0.2.0"
  "wasi:filesystem/types@0.2.0"
  "wasi:filesystem/preopens@0.2.0"
)
for imp in $(wasm-tools component wit ./payments.wasm | awk '/^  import/ {print $2}' | sed 's/;//'); do
  if ! printf '%s\n' "${ALLOWED[@]}" | grep -qx "$imp"; then
    echo "Forbidden import: $imp"
    exit 1
  fi
done
```

This is the same audit covered in [WASI Preview 2 Capability-Based Security](/articles/wasm/wasi-preview-2-capabilities/), wired into the scanning pipeline.

### Step 8: Pipeline Integration

```yaml
# .github/workflows/scan-wasm.yml
name: Scan WASM artifact
on:
  workflow_call:
    inputs:
      artifact-path:
        required: true
        type: string

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          cargo install --locked wasm-tools twiggy
          curl -fsSL "https://github.com/google/osv-scanner/releases/download/v1.9.0/osv-scanner_linux_amd64" -o /usr/local/bin/osv-scanner
          chmod +x /usr/local/bin/osv-scanner

      - name: Validate
        run: wasm-tools validate "${{ inputs.artifact-path }}"

      - name: Capability surface audit
        run: scripts/check-imports.sh "${{ inputs.artifact-path }}"

      - name: Scan SBOM
        run: |
          osv-scanner --sbom=sbom.json --fail-on=high \
            --output=json > scan-report.json

      - name: IoC pattern match
        run: |
          wasm-tools demangle "${{ inputs.artifact-path }}" | strings -n 8 - |
            grep -F -f .github/wasm-iocs/known-bad-strings.txt && exit 1 || true

      - name: Reachability check for high-severity findings
        run: scripts/twiggy-reachability.sh "${{ inputs.artifact-path }}" scan-report.json

      - uses: actions/upload-artifact@v4
        with:
          name: scan-report
          path: scan-report.json
```

Each step is a gate. A failure in any step blocks the deploy.

## Expected Behaviour

| Signal | Without scanning | With scanning |
|--------|------------------|---------------|
| Vulnerable dependency in module | Deployed | Deploy blocked at CI |
| New import not in baseline | Deployed | Deploy blocked; review required |
| Build with unapproved toolchain | Deployed | Deploy blocked |
| Embedded IoC (known-bad domain) | Deployed | Deploy blocked; possible incident |
| SBOM available for runtime audit | Not always | Always; attached as OCI sibling |
| Reachability of vulnerable code | Unknown | `twiggy paths` returns the call chain or nothing |

Verify the pipeline catches a known-vulnerable artifact:

```bash
# Build a test module with a known-CVE'd version.
cargo build --target wasm32-wasip2 --release
# (Cargo.toml pins openssl = "0.10.55" — has RUSTSEC-2024-0357)

# Run the scan.
./scripts/scan-wasm.sh target/wasm32-wasip2/release/test.wasm
# Should exit non-zero; report shows openssl 0.10.55 with the CVE.
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| SBOM-based scanning | Maps to known vulnerability databases | Requires SBOM at build; cannot scan arbitrary third-party WASM artifacts | Demand SBOMs from third parties; refuse to deploy modules without one. |
| Reachability analysis | Reduces false-positive findings | Adds CI time; tooling immature for component-model | Apply only to high-severity findings; accept false-positives for lower severity. |
| Producers-section enforcement | Detects builds outside CI | Modules from external partners may have different toolchains | Allowlist approved external builders; document in supply-chain policy. |
| IoC pattern matching | Catches obvious markers | High false-positive rate; cat-and-mouse with attackers | Use as one signal among many; trigger review, not auto-block, on most patterns. |
| Capability surface audit | Detects new imports | Requires per-module baseline maintenance | Generate baseline from main-branch builds; review on PR. |
| Custom-section custody | Validates the build identity | Custom sections can be stripped | Sign the .wasm artifact with cosign; that signature covers the bytes including custom sections. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Stripped custom sections | Producer audit fails | CI check fails | Verify the build pipeline preserves `producers` section; do not run `wasm-tools strip --custom`. |
| SBOM mismatch with bytecode | Vulnerable dep in SBOM not in bytecode (or vice versa) | Discrepancy between SBOM and `wasm-tools dump` | SBOM must be generated from the same source tree as the bytecode. Generate in the same CI step. |
| Reachability tool false negative | `twiggy paths` returns nothing for a function the bytecode actually calls | Module behavior differs from analysis | Some indirect calls (function pointers, table-call) defeat static reachability. Treat any vulnerable dep present as exploitable until proven otherwise. |
| OSV database lag | Recent CVE not yet in OSV | osv-scanner returns clean for a known-vulnerable dep | Subscribe to RustSec, GHSA advisories; supplement OSV with vendor-specific feeds. |
| Producer field forged | Modules with attacker-chosen `producers` value | Field cannot be verified independently | Sign the artifact; producer field is meaningful only if the signature's identity is trusted. |
| Build pipeline produces non-deterministic SBOM | SBOM shape varies across rebuilds; CI compares fail | Investigate via `cargo cyclonedx --output-format json | sort-json` | Use deterministic SBOM tooling; pin tool versions. |

## Related Articles

- [Reproducible WASM Builds and SBOM Generation](/articles/wasm/reproducible-wasm-builds/)
- [OCI WASM Module Signing and Verification](/articles/wasm/wasm-oci-signing/)
- [WASI Preview 2 Capability-Based Security](/articles/wasm/wasi-preview-2-capabilities/)
- [SLSA Build Provenance: Source-to-Registry Integrity](/articles/cicd/slsa-provenance/)
- [SBOM Generation and Use](/articles/cicd/sbom/)
