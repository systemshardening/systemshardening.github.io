---
title: "Reproducible WASM Builds and SBOM Generation: Deterministic Compilation, CycloneDX, In-Toto Attestations"
description: "WASM is the easy case for reproducibility — no dynamic linking, no runtime variance. Most teams still ship non-reproducible builds. The fix is small."
slug: "reproducible-wasm-builds"
date: 2026-04-27
lastmod: 2026-04-27
category: "wasm"
tags: ["wasm", "reproducible-builds", "sbom", "cyclonedx", "supply-chain"]
personas: ["security-engineer", "platform-engineer", "devops"]
article_number: 189
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/wasm/reproducible-wasm-builds/index.html"
---

# Reproducible WASM Builds and SBOM Generation: Deterministic Compilation, CycloneDX, In-Toto Attestations

## Problem

Reproducible builds — the property that the same source produces the same binary regardless of when, where, or by whom it is built — are the structural defense against undetected build-time tampering. For container images, reproducibility is hard: dynamic linking, build-system dependencies, embedded timestamps, non-deterministic file ordering in tar layers. Practical reproducibility for containers requires substantial tooling (Bazel, Nix, kaniko with controlled bases) and even then is fragile.

WASM is the easy case. There is no dynamic linking. There is no rootfs to assemble. The bytecode is a single output file. Most language toolchains that target WASM (Rust, Go via TinyGo, AssemblyScript, C/C++ via Emscripten) can produce identical bytes given identical source and dependencies.

Yet most production WASM pipelines do not produce reproducible artifacts. The breakage points are mundane:

- **Embedded timestamps in custom sections.** Some toolchains write the build date into `producers` or similar custom sections.
- **Hash-randomized data structures.** Compilers may emit different orderings if internal hash maps depend on process state.
- **Cargo's `RUSTFLAGS` and `--remap-path-prefix` not set.** Source paths embedded in debug sections vary across builders.
- **Toolchain version drift.** Even patch-level differences in rustc / clang / TinyGo can shift bytecode.
- **Build-time environment variables baked in.** `env!()` and similar mechanisms embed shell environment values.

The cost of fixing each of these is small. The benefit is the ability to verify a deployed artifact matches the source — a foundation for SLSA Build L3 attestations and a pre-condition for trustworthy SBOMs.

This article covers the small set of build-flag changes that achieve reproducibility for Rust, Go (TinyGo), and AssemblyScript WASM artifacts; SBOM generation tied to the build; and in-toto attestation linking SBOM, source, and bytecode.

**Target systems:** Rust 1.83+ with `wasm32-wasip2` target, TinyGo 0.32+, AssemblyScript 0.27+, syft 1.16+ for SBOM, cosign 2.4+ for in-toto attestation, in-toto-attestation 1.0+ schema.

## Threat Model

- **Adversary 1 — Compromised build infrastructure:** an attacker has access to the CI environment and inserts malicious code at build time, undetectable from source review.
- **Adversary 2 — Compiler backdoor (Trusting Trust):** the toolchain itself produces tampered output, even from clean source.
- **Adversary 3 — SBOM forgery:** an attacker produces an SBOM that does not match the bytecode's actual dependencies, hiding a compromised package.
- **Adversary 4 — Source-to-artifact gap:** without binding source to artifact, a deployed artifact may have been built from a branch, fork, or tag that was not the published source.
- **Access level:** Adversary 1 has CI access. Adversary 2 has a compiler-distribution channel (Cargo, apt, Linux distro). Adversary 3 has CI access. Adversary 4 is the default state without attestation.
- **Objective:** Ship code that does not match audited source; obscure the supply chain.
- **Blast radius:** A non-reproducible build means any attempt to verify the deployed artifact against source is impossible. Reproducibility lets an independent rebuilder confirm the artifact, breaking the singular trust in the original CI.

## Configuration

### Step 1: Reproducible Rust → WASM

Rust's WASM target is reproducible with a small set of flags. Set them in `Cargo.toml`:

```toml
# Cargo.toml
[package]
name = "payments"
version = "1.2.3"
edition = "2021"

[profile.release]
codegen-units = 1
lto = true
strip = "debuginfo"
panic = "abort"

[profile.release.package."*"]
opt-level = "z"
```

And in the build invocation:

```bash
# build.sh
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD)
export RUSTFLAGS="--remap-path-prefix=$PWD=. --remap-path-prefix=$HOME/.cargo=/cargo"
export CARGO_HOME=/tmp/cargo-isolated
cargo +1.83.0 build --release --target wasm32-wasip2 --locked

# Strip non-deterministic sections.
wasm-tools strip target/wasm32-wasip2/release/payments.wasm \
  --keep-section producers \
  --keep-section target_features \
  -o payments.wasm
```

Each flag matters:

- `codegen-units = 1` and `lto = true` — single-pass compilation, no parallelism-induced ordering variance.
- `strip = "debuginfo"` — debug paths are a major non-determinism source.
- `--remap-path-prefix` — even after stripping debug info, path information can leak via `producers`. Remap to a constant.
- `SOURCE_DATE_EPOCH` — Cargo and rustc honor this when embedding timestamps. Set to the commit time so the build is fully a function of the source.
- `+1.83.0` — pin the toolchain version. Different rustc versions produce different bytecode.
- `--locked` — fail if `Cargo.lock` is out of sync; never resolve dependencies fresh.
- `wasm-tools strip --keep-section` — remove arbitrary custom sections that toolchains add (e.g., a coverage section, a profiling section), keeping only those you intentionally include.

Verify reproducibility:

```bash
# Build twice; confirm identical.
./build.sh
sha256sum payments.wasm > /tmp/sha1.txt

cargo clean
./build.sh
sha256sum payments.wasm > /tmp/sha2.txt

diff /tmp/sha1.txt /tmp/sha2.txt
# (no output = reproducible)
```

If the hashes differ, use `wasm-tools` to find the variance:

```bash
wasm-tools dump payments.wasm > dump1.txt
# rebuild
wasm-tools dump payments.wasm > dump2.txt
diff dump1.txt dump2.txt
# Look for the section that changed.
```

### Step 2: Reproducible TinyGo → WASM

TinyGo's reproducibility story is similar:

```bash
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD)
export GOFLAGS="-trimpath"

tinygo build \
  -o payments.wasm \
  -target=wasi-p2 \
  -opt=z \
  -no-debug \
  -ldflags="-buildid='' -s -w" \
  ./cmd/payments
```

`-trimpath` (Go 1.13+) removes absolute paths from the binary. `-buildid=''` clears the embedded build ID. `-s -w` strip symbol and debug info. Pin TinyGo version explicitly; `tinygo version` should match across builders.

### Step 3: Reproducible AssemblyScript → WASM

```bash
# AssemblyScript with deterministic flags.
asc src/index.ts \
  --target release \
  --optimize \
  --noAssert \
  --converge \
  --runtime stub \
  --use ASC_FEATURE_BULK_MEMORY=1 \
  -o payments.wasm

# Strip non-deterministic sections.
wasm-tools strip payments.wasm \
  --keep-section name \
  -o payments-final.wasm
```

`--converge` re-runs optimization passes until the output stabilizes (avoids one-pass optimization variance).

### Step 4: SBOM at Build Time

Generate the SBOM in the same CI step that produces the bytecode. The SBOM is a function of the lockfile (Cargo.lock, go.sum, package-lock.json) — independent of the bytecode but produced from the same dependency-resolution state.

```bash
# Rust: cargo-cyclonedx generates CycloneDX directly.
cargo cyclonedx --format json --output-pattern "{package_name}.cdx.json"

# Or via syft (works for many ecosystems).
syft scan dir:. -o cyclonedx-json=sbom.cdx.json

# Verify SBOM content.
jq '.components | length' sbom.cdx.json
# 47   (47 dependencies recorded)

jq '.components[] | {name, version, purl}' sbom.cdx.json | head -10
```

Attach SBOM to the OCI artifact:

```bash
oras attach ghcr.io/myorg/wasm/payments:1.2.3 \
  --artifact-type application/vnd.cyclonedx+json \
  sbom.cdx.json:application/vnd.cyclonedx+json
```

Verifiers can pull the SBOM separately and feed it to OSV-Scanner without ever pulling or executing the bytecode.

### Step 5: In-Toto Attestation Linking Source, SBOM, and Artifact

An in-toto attestation is a signed statement of the form "subject X has property Y." For WASM artifacts:

```yaml
# in-toto attestation (predicateType: https://slsa.dev/provenance/v1)
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "ghcr.io/myorg/wasm/payments:1.2.3",
      "digest": {"sha256": "abc123..."}
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://github.com/myorg/wasm-builder/v1",
      "externalParameters": {
        "source": {
          "uri": "git+https://github.com/myorg/payments-wasm@v1.2.3",
          "digest": {"sha1": "def456..."}
        }
      },
      "internalParameters": {
        "rustc_version": "1.83.0",
        "wasm_tools_version": "1.220.0",
        "cargo_lock_digest": "sha256:fedcba..."
      },
      "resolvedDependencies": [
        {
          "uri": "pkg:cargo/[email protected]",
          "digest": {"sha256": "..."}
        }
      ]
    },
    "runDetails": {
      "builder": {
        "id": "https://github.com/myorg/wasm-builder/.github/workflows/build.yml@refs/heads/main"
      },
      "metadata": {
        "invocationId": "https://github.com/myorg/payments-wasm/actions/runs/12345",
        "startedOn": "2026-04-27T10:00:00Z",
        "finishedOn": "2026-04-27T10:02:30Z"
      }
    }
  }
}
```

Generate via the slsa-github-generator workflow:

```yaml
- name: Generate provenance
  uses: slsa-framework/slsa-github-generator/.github/workflows/[email protected]
  with:
    base64-subjects: ${{ steps.hash.outputs.hashes }}
    upload-assets: true
```

cosign-sign the attestation:

```bash
cosign attest --yes --predicate provenance.json \
  --type slsaprovenance \
  ghcr.io/myorg/wasm/payments:1.2.3
```

### Step 6: Independent Rebuilder Verification

The point of reproducible builds is that anyone can rebuild and verify. Set up a periodic rebuilder:

```yaml
# rebuilder.yaml — runs daily on a separate runner.
name: Rebuild and verify
on:
  schedule:
    - cron: '0 4 * * *'

jobs:
  rebuild:
    runs-on: ubuntu-latest
    steps:
      - name: Fetch source at the released tag
        uses: actions/checkout@v4
        with:
          repository: myorg/payments-wasm
          ref: v1.2.3

      - name: Reproduce build
        run: ./build.sh

      - name: Compare against published artifact
        run: |
          oras pull ghcr.io/myorg/wasm/payments:1.2.3 --output published
          if ! cmp -s payments.wasm published/payments.wasm; then
            echo "Reproducibility FAIL"
            wasm-tools dump payments.wasm > /tmp/local.txt
            wasm-tools dump published/payments.wasm > /tmp/pub.txt
            diff /tmp/local.txt /tmp/pub.txt | head -30
            exit 1
          fi

      - name: Post verification attestation
        if: success()
        run: |
          cosign attest --yes \
            --predicate '{"verifier":"daily-rebuilder","verified":true,"date":"'$(date -u +%FT%TZ)'"}' \
            --type rebuild \
            ghcr.io/myorg/wasm/payments:1.2.3
```

A second-source attestation from an independent rebuilder is the strongest verification short of doing it yourself.

## Expected Behaviour

| Signal | Without reproducibility | With |
|--------|--------------------------|------|
| Two builds from the same source | Different bytes | Identical |
| Verify deployed artifact against source | Impossible | `cmp` succeeds |
| SBOM matches bytecode dependencies | Drift possible | SBOM derived from the same lockfile snapshot |
| In-toto attestation chain | Often missing | Source → SBOM → artifact, signed |
| Independent rebuilder | Cannot succeed | Daily rebuild posts verification attestation |
| SLSA level achievable | L1-L2 typically | L3 or L4 with rebuilder |

Verify the property:

```bash
# Build, then build again on a different machine, then diff.
ssh builder1 ./build.sh
ssh builder1 cat artifact/payments.wasm | sha256sum
# 8e8f1a... -

ssh builder2 ./build.sh
ssh builder2 cat artifact/payments.wasm | sha256sum
# 8e8f1a... -

# Same hash, two different machines.
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Reproducible flags | Independent verification possible | Slightly slower builds (single codegen unit, LTO) | Acceptable; build time grows ~20-50% but is one-time per release. |
| Toolchain pinning | Consistent output across builders | Cannot benefit from automatic toolchain upgrades | Bump in coordinated waves; treat upgrades as supply-chain events. |
| SBOM at build time | Always-attached vulnerability lookup | One extra step in CI | Trivial cost; bake into the build script. |
| In-toto attestation chain | Strong supply-chain guarantee | Schema and tooling complexity | Use slsa-github-generator; do not hand-roll. |
| Independent rebuilder | Catches CI-side compromises | Operational overhead of running a second pipeline | Run weekly initially; daily once rebuild time is well-known. |
| `wasm-tools strip` | Removes non-deterministic sections | Loss of debug info; potentially loss of useful metadata | Keep specific sections (`producers`, `target_features`); strip the rest. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Cargo.lock out of date | `--locked` build fails or produces different output | CI fails with "lockfile out of date" | Run `cargo update` deliberately, commit, rebuild. Never auto-update in release pipelines. |
| Toolchain mismatch between builders | Hashes differ between independent rebuilds | `cmp` fails | Lock toolchain version explicitly; use `rustup toolchain install 1.83.0` before build. |
| Custom sections vary | Specific section differs across rebuilds | `wasm-tools dump` shows the variance | Strip the variant section, or fix the toolchain (file upstream bug). |
| SBOM missing dependency | OSV-Scanner does not flag a known-vulnerable package | Manual audit reveals the gap | Use a current SBOM tool; pin tool version; cross-check with `cargo tree`. |
| Attestation pinned to wrong source | Provenance shows a different repo than expected | Verifier rejects | Configure slsa-github-generator with the correct source URI; investigate any mismatch as potential misconfiguration. |
| Rebuilder uses stale cache | Reproduces with an older toolchain | Rebuilder hashes match the "published" but neither matches a fresh local build | Drop caches periodically; treat caches as performance, not correctness. |

## Related Articles

- [WASM Module Static Analysis and Vulnerability Scanning](/articles/wasm/wasm-static-analysis/)
- [OCI WASM Module Signing and Verification](/articles/wasm/wasm-oci-signing/)
- [SLSA Build Provenance: Source-to-Registry Integrity](/articles/cicd/slsa-provenance/)
- [Reproducible Builds for Production Software](/articles/cicd/reproducible-builds/)
- [SBOM Generation and Use](/articles/cicd/sbom/)
