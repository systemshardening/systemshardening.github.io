---
title: "WASM Supply Chain: SBOM Generation and Provenance for WebAssembly Modules"
description: "A WASM module compiled from Rust carries dozens of crate dependencies — none visible from the binary alone. This guide covers SBOM generation for WASM modules with syft and cargo-sbom, attaching provenance attestations as OCI referrers, verifying module lineage before deployment, and WASM-specific supply chain policy enforcement."
slug: wasm-sbom-provenance
date: 2026-05-07
lastmod: 2026-05-07
category: wasm
tags:
  - wasm
  - sbom
  - provenance
  - supply-chain
  - sigstore
personas:
  - security-engineer
  - platform-engineer
article_number: 591
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/wasm/wasm-sbom-provenance/
---

# WASM Supply Chain: SBOM Generation and Provenance for WebAssembly Modules

## The Problem

Container images carry a visible, scannable layer structure. A tool like syft or trivy can walk the image's filesystem, find `/var/lib/dpkg/status` or `/usr/lib/python3.11/site-packages/*.dist-info`, and produce an SBOM without any build-time cooperation. The package manager metadata is baked into the image and readable at any time.

WASM modules work differently. When you compile a Rust crate to `wasm32-wasip2`, the compiler links every dependency directly into the binary. The finished `.wasm` file contains machine instructions — no package manager database, no leftover `Cargo.toml`, no crate-version metadata embedded for inspection. You cannot recover the full dependency tree from the binary alone. A security scanner pointed at the `.wasm` file sees a flat byte sequence. It may identify the WebAssembly binary format and extract exported function names, but it cannot tell you whether the module was linked against `ring 0.17.8` or `ring 0.17.7`, or whether it transitively pulls in a version of `rustls` with a known vulnerability.

The consequence is that SBOM generation for WASM must happen at build time, not inspection time. The build system has the full dependency graph through `Cargo.lock`; that information must be captured before it is compiled away. If SBOM generation is skipped or deferred until after the binary is produced, the window is gone. A WASM module deployed without a build-time SBOM is opaque to the security tooling that your container estate relies on.

This asymmetry is not theoretical. WASM modules are appearing in production environments as Kubernetes workloads via kwasm and Spin, as service mesh filters via Envoy, as serverless functions via Cloudflare Workers and Fastly Compute, and as Wasmtime-embedded plugins in platform tooling. Each one carries a dependency tree that organisations can no longer inspect with the same post-hoc scanning tools they apply to containers.

This article covers the full SBOM and provenance pipeline: generating CycloneDX SBOMs from Rust WASM builds using `cargo-sbom` and syft, generating SLSA provenance in GitHub Actions, attaching both as OCI referrers to WASM artifacts in a registry, verifying module lineage before deployment, running vulnerability scans against the WASM SBOM, and enforcing SBOM attestation presence via Kyverno and OPA policies before a WASM runtime is permitted to load the module.

**Target systems:** Rust stable 1.78+, cargo-sbom 0.9+, syft 1.4+, cosign 2.4+, grype 0.78+, trivy 0.50+, slsa-github-generator v2.0+, Kyverno 1.12+, OPA 0.63+, oras 1.2+.

## Threat Model

- **Adversary 1 — Vulnerable transitive dependency:** A WASM module links against a crate that pulls in a transitive dependency with a known CVE. Without an SBOM, no scanner detects the vulnerability. The module passes every admission check and runs in production.
- **Adversary 2 — Tampered build environment:** An attacker with access to the CI system substitutes a malicious version of a dependency during the build. The resulting WASM binary behaves normally but contains the attacker's payload. Without provenance, there is no record of which source, which commit, and which build environment produced the artifact.
- **Adversary 3 — SBOM spoofing:** An attacker attaches a clean SBOM to a module that was compiled with different (vulnerable) dependencies. Policy checks that only verify SBOM presence without verifying SBOM integrity can be fooled.
- **Adversary 4 — Dependency confusion on crates.io:** A malicious crate with a name matching an internal crate is published to crates.io. The build resolves to the malicious version. The SBOM captures this, but only if vulnerability scanning is run against the SBOM and the malicious crate is known to scanners.
- **Access level:** Adversaries 1 and 4 require no privileged access. Adversaries 2 and 3 require CI write access or registry write access respectively.
- **Objective:** Run a WASM module containing a known-vulnerable or malicious dependency in a production WASM runtime.
- **Mitigation:** SBOM generated at build time + signature over both SBOM and provenance + policy requiring signed SBOM before module load = full coverage against all four adversaries.

## Configuration

### Step 1: Generate a CycloneDX SBOM with cargo-sbom

`cargo-sbom` reads `Cargo.toml` and `Cargo.lock` during the build and produces a CycloneDX or SPDX document describing every crate in the dependency tree, including transitive dependencies and their versions. Run it as part of the build step, before the compiled binary exists.

```bash
cargo install cargo-sbom
```

Generate a CycloneDX 1.5 SBOM targeting the WASM release profile:

```bash
cargo sbom \
  --output-format cyclone_dx_json_1_5 \
  > payments.cdx.json
```

The output captures every crate, its version, its source (crates.io registry URL or git reference), and the declared license. For a medium-sized Rust WASM module with around 80 transitive dependencies, this produces a document on the order of 200 KB containing entries like:

```json
{
  "type": "library",
  "bom-ref": "ring:0.17.8",
  "name": "ring",
  "version": "0.17.8",
  "purl": "pkg:cargo/ring@0.17.8",
  "licenses": [{"license": {"id": "ISC"}}],
  "hashes": [
    {
      "alg": "SHA-256",
      "content": "sha256-..."
    }
  ]
}
```

The `purl` field (`pkg:cargo/ring@0.17.8`) is the identifier that vulnerability scanners use to look up the component in CVE databases. Without it, grype and trivy cannot map the component to known vulnerabilities.

For a cross-compilation setup where the target is explicitly `wasm32-wasip2`, pass the target to `cargo-sbom`:

```bash
cargo sbom \
  --cargo-package payments \
  --output-format cyclone_dx_json_1_5 \
  > payments.cdx.json
```

### Step 2: Capture the Cargo.lock as Build Provenance

`Cargo.lock` is the exact, resolved dependency manifest for the build. It specifies every crate, every version, and the SHA-256 checksum of every downloaded source tarball. It is stronger than the SBOM as a build record: the SBOM describes what was used; `Cargo.lock` records what was resolved and verified by cargo's content-addressable download mechanism.

Capture it alongside the SBOM as a provenance artifact:

```bash
cp Cargo.lock payments.Cargo.lock
```

This file becomes an attestation subject in the next steps. A verifier who reconstructs the build can check that the `Cargo.lock` from the attestation matches what cargo would resolve from the `Cargo.toml` — detecting any tampering with the dependency graph.

### Step 3: Supplement with syft for OCI-Aware SBOM

`cargo-sbom` operates from the source tree and understands Rust crates natively. `syft` operates from multiple artifact types — directories, OCI images, WASM modules — and can produce SBOMs in both CycloneDX and SPDX format. For WASM modules stored as OCI artifacts, syft can analyze the OCI image manifest alongside the binary:

```bash
# After pushing to the registry:
syft ghcr.io/myorg/wasm/payments:1.2.3 \
  -o cyclonedx-json=payments.syft.cdx.json
```

syft's WASM cataloger identifies the module binary and attempts to extract embedded metadata. Its primary value in a WASM pipeline is OCI artifact awareness: it can pull the artifact from the registry and produce an SBOM that references the OCI digest, giving you a registry-addressable SBOM rather than a local-file SBOM. This is the format cosign expects when attaching attestations.

For Rust WASM specifically, use `cargo-sbom` as the authoritative source (it has the full Cargo dependency graph) and syft as a secondary check and for OCI digest binding. The two SBOMs can be diff'd to detect discrepancies.

### Step 4: Generate SLSA Provenance in GitHub Actions

SLSA (Supply-chain Levels for Software Artifacts) provenance is a signed in-toto statement that records the source repository, commit, builder identity, and build parameters used to produce the artifact. SLSA Level 3 provenance, generated by the `slsa-github-generator`, is tamper-resistant because it is signed by the generator workflow's identity rather than by the repository's secrets — an attacker who compromises the repository cannot forge SLSA L3 provenance.

The full build pipeline, including SBOM generation, binary push, and provenance:

```yaml
# .github/workflows/build-wasm.yml
name: Build, sign, and attest WASM module

on:
  push:
    tags: ["v*"]

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
      packages: write
      attestations: write
    outputs:
      artifact-digest: ${{ steps.push.outputs.digest }}
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Install Rust + WASM target
        run: |
          rustup toolchain install stable --target wasm32-wasip2
          cargo install cargo-sbom

      - name: Build WASM module
        run: |
          cargo build --release --target wasm32-wasip2
          cp Cargo.lock payments.Cargo.lock

      - name: Generate CycloneDX SBOM
        run: |
          cargo sbom \
            --output-format cyclone_dx_json_1_5 \
            > payments.cdx.json

      - name: Log in to GHCR
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Push WASM artifact to registry
        id: push
        run: |
          DIGEST=$(oras push \
            --artifact-type application/vnd.wasm.config.v0+json \
            --format go-template='{{.Digest}}' \
            ghcr.io/${{ github.repository_owner }}/wasm/payments:${{ github.ref_name }} \
            target/wasm32-wasip2/release/payments.wasm:application/vnd.wasm.content.layer.v1+wasm)
          echo "digest=${DIGEST}" >> "$GITHUB_OUTPUT"

      - name: Sign the WASM artifact (keyless)
        run: |
          cosign sign --yes \
            ghcr.io/${{ github.repository_owner }}/wasm/payments@${{ steps.push.outputs.artifact-digest }}

      - name: Attach SBOM as OCI referrer
        run: |
          cosign attest --yes \
            --predicate payments.cdx.json \
            --type cyclonedx \
            ghcr.io/${{ github.repository_owner }}/wasm/payments@${{ steps.push.outputs.artifact-digest }}

      - name: Attach Cargo.lock as OCI referrer
        run: |
          cosign attest --yes \
            --predicate payments.Cargo.lock \
            --type https://systemshardening.com/predicates/cargo-lock/v1 \
            ghcr.io/${{ github.repository_owner }}/wasm/payments@${{ steps.push.outputs.artifact-digest }}

  provenance:
    needs: [build]
    permissions:
      id-token: write
      contents: read
      packages: write
      actions: read
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0
    with:
      base64-subjects: ${{ needs.build.outputs.artifact-digest }}
      registry-username: ${{ github.actor }}
      upload-assets: true
    secrets:
      registry-password: ${{ secrets.GITHUB_TOKEN }}
```

The `provenance` job runs the SLSA generator as a reusable workflow under its own identity (`slsa-framework/slsa-github-generator`). The resulting provenance attestation is signed by the generator's OIDC certificate, not by the repository's `GITHUB_TOKEN`. An attacker who compromises the repository's secrets cannot produce a matching SLSA L3 provenance — they can produce forged L2 provenance, but a verifier checking for L3 will reject it.

### Step 5: Verify Module Provenance Before Deployment

Before loading any WASM module, a deployment script or admission gate should verify all three attestations: the cosign signature, the SBOM attestation, and the SLSA provenance.

```bash
#!/bin/bash
# verify-wasm-module.sh
# Usage: verify-wasm-module.sh <registry-ref>
set -euo pipefail

REF="$1"
WORKFLOW_ID="https://github.com/myorg/payments-wasm/.github/workflows/build-wasm.yml@refs/heads/main"
SLSA_GENERATOR="https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.0.0"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

echo "Verifying signature for ${REF} ..."
cosign verify \
  --certificate-identity "${WORKFLOW_ID}" \
  --certificate-oidc-issuer "${OIDC_ISSUER}" \
  "${REF}" | jq -r '.[0].optional.Subject'

echo "Verifying SBOM attestation for ${REF} ..."
cosign verify-attestation \
  --certificate-identity "${WORKFLOW_ID}" \
  --certificate-oidc-issuer "${OIDC_ISSUER}" \
  --type cyclonedx \
  "${REF}" | jq '.payload | @base64d | fromjson | .predicate.metadata.component.name'

echo "Verifying SLSA provenance for ${REF} ..."
cosign verify-attestation \
  --certificate-identity "${SLSA_GENERATOR}" \
  --certificate-oidc-issuer "${OIDC_ISSUER}" \
  --type slsaprovenance1 \
  "${REF}" | jq '.payload | @base64d | fromjson | .predicate.buildDefinition.resolvedDependencies[0].uri'

echo "All attestations verified."
```

The key verification checks:
- `--certificate-identity` pins the identity to the specific workflow file path. A module signed by any other workflow — including a fork of the repository — does not pass.
- `--type cyclonedx` restricts to attestations with the CycloneDX predicate type, preventing a forged in-toto statement with a different predicate from being accepted as an SBOM.
- `--type slsaprovenance1` requires SLSA Provenance v1; older SLSA v0.2 provenance is not accepted.

All three checks must pass before the script exits 0. Any failure halts deployment.

### Step 6: Vulnerability Scan Against the WASM SBOM

Extract the SBOM from the OCI referrer and run grype or trivy against it. This is the step that translates the SBOM into actionable CVE findings:

```bash
# Extract the SBOM attestation from the registry.
cosign verify-attestation \
  --certificate-identity "${WORKFLOW_ID}" \
  --certificate-oidc-issuer "${OIDC_ISSUER}" \
  --type cyclonedx \
  ghcr.io/myorg/wasm/payments:1.2.3 \
  | jq -r '.payload | @base64d | fromjson | .predicate' \
  > payments.cdx.json

# Scan with grype.
grype sbom:./payments.cdx.json --output json > grype-results.json

# Or scan with trivy.
trivy sbom payments.cdx.json \
  --format json \
  --output trivy-results.json

# Check for critical or high CVEs and fail the pipeline if found.
CRITICAL=$(jq '[.matches[] | select(.vulnerability.severity == "Critical")] | length' grype-results.json)
HIGH=$(jq '[.matches[] | select(.vulnerability.severity == "High")] | length' grype-results.json)

if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
  echo "FAIL: ${CRITICAL} critical and ${HIGH} high vulnerabilities found in WASM SBOM."
  exit 1
fi
echo "PASS: No critical or high vulnerabilities."
```

Because the SBOM contains `purl` entries for every Rust crate with its exact version, grype and trivy can look up each crate against OSV (Open Source Vulnerabilities), RustSec, and NVD. A module linking against `openssl 0.10.35` will surface CVEs that affect that version. A module that avoids the vulnerability by using a patched version will pass cleanly.

This scan should run in two places: in the CI pipeline after the SBOM is generated (before the artifact is pushed to the registry), and again in the deployment pipeline after the SBOM attestation is retrieved from the registry (confirming the SBOM has not been tampered with between build and deploy).

### Step 7: Kyverno Policy Requiring SBOM Attestation

A Kyverno `ClusterPolicy` can enforce that no WASM Pod is admitted to the cluster unless a valid CycloneDX SBOM attestation is attached to the image reference. Combine this with the cosign signature check from the signing article for layered enforcement:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-wasm-sbom-attestation
  annotations:
    policies.kyverno.io/description: >-
      All WASM modules must carry a CycloneDX SBOM attestation signed
      by the build pipeline before they are admitted to the cluster.
spec:
  validationFailureAction: Enforce
  webhookTimeoutSeconds: 30
  background: false
  rules:
    - name: verify-wasm-sbom
      match:
        any:
          - resources:
              kinds: [Pod]
      preconditions:
        all:
          - key: "{{ request.object.spec.runtimeClassName || '' }}"
            operator: AnyIn
            value: ["wasmtime", "spin", "wasmcloud", "wasmedge", "kwasm"]
      verifyImages:
        - imageReferences:
            - "ghcr.io/myorg/wasm/*"
          attestations:
            - type: https://cyclonedx.org/bom
              attestors:
                - entries:
                    - keyless:
                        subject: "https://github.com/myorg/*-wasm/.github/workflows/build-wasm.yml@refs/heads/main"
                        issuer: "https://token.actions.githubusercontent.com"
              conditions:
                - all:
                    - key: "{{ predicate.metadata.component.name }}"
                      operator: NotEquals
                      value: ""
            - type: https://slsa.dev/provenance/v1
              attestors:
                - entries:
                    - keyless:
                        subject: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/*"
                        issuer: "https://token.actions.githubusercontent.com"
          mutateDigest: true
          required: true
```

The `preconditions` block limits this policy to Pods with a WASM-specific `runtimeClassName`, so the SBOM requirement does not accidentally apply to standard container workloads. The `conditions` block on the CycloneDX attestation verifies that the predicate contains a non-empty component name — a minimal sanity check that the attached SBOM is a real SBOM document and not an empty payload.

### Step 8: OPA Policy for Non-Kubernetes WASM Runtimes

For Spin, wasmCloud standalone, or custom WASM runtime deployments outside Kubernetes, use an OPA policy evaluated before module load. The policy receives the output of `cosign verify-attestation` as input and decides whether the module is permitted to load:

```rego
# wasm_sbom_policy.rego
package wasm.sbom

import rego.v1

default allow := false

# Allow the module to load if all three conditions are satisfied.
allow if {
  valid_sbom_attestation
  valid_provenance_attestation
  no_critical_vulns
}

# The SBOM attestation must be present and signed by the build workflow.
valid_sbom_attestation if {
  some attest in input.sbom_attestations
  attest.verified == true
  attest.certificate.subject == "https://github.com/myorg/payments-wasm/.github/workflows/build-wasm.yml@refs/heads/main"
  attest.certificate.issuer == "https://token.actions.githubusercontent.com"
  attest.predicate.bomFormat == "CycloneDX"
}

# The SLSA provenance must be present and signed by the generator.
valid_provenance_attestation if {
  some attest in input.provenance_attestations
  attest.verified == true
  startswith(attest.certificate.subject, "https://github.com/slsa-framework/slsa-github-generator/")
  attest.certificate.issuer == "https://token.actions.githubusercontent.com"
}

# No critical vulnerabilities permitted in the attached SBOM.
no_critical_vulns if {
  count([c | c := input.vulnerability_scan.matches[_]; c.vulnerability.severity == "Critical"]) == 0
}

# Deny reason for observability.
deny contains msg if {
  not valid_sbom_attestation
  msg := "WASM module missing a valid CycloneDX SBOM attestation from the build pipeline."
}

deny contains msg if {
  not valid_provenance_attestation
  msg := "WASM module missing a valid SLSA provenance attestation."
}

deny contains msg if {
  not no_critical_vulns
  count_critical := count([c | c := input.vulnerability_scan.matches[_]; c.vulnerability.severity == "Critical"])
  msg := sprintf("WASM module SBOM contains %d critical vulnerabilities.", [count_critical])
}
```

The runtime calls OPA with a JSON input document that contains the output of `cosign verify-attestation` (parsed), the output of the grype/trivy scan, and any other context. The policy evaluates all three checks and returns a structured deny set if any condition is not met. The runtime loads the module only if `data.wasm.sbom.allow == true`.

## Expected Behaviour

| Signal | Without SBOM pipeline | With SBOM pipeline |
|--------|-----------------------|-------------------|
| Dependency tree visible post-build | Not recoverable | Full CycloneDX SBOM in registry as OCI referrer |
| CVE in transitive Rust crate | Undetected | Grype/trivy surfaces via purl in SBOM |
| Tampered build environment | No evidence | SLSA provenance signed by generator; mismatch detectable |
| Module loaded without SBOM | Permitted | Kyverno or OPA policy blocks at admission |
| SBOM spoofing (unsigned) | Accepted | cosign signature check on attestation fails |
| Cargo.lock available for audit | Only in source repo | Attached as OCI referrer alongside SBOM |
| Vulnerable module re-deployed | Permitted | Grype scan in deploy pipeline blocks on critical CVEs |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Build-time SBOM generation | Captures full dependency graph before it is compiled away | Adds 10–30s to build; requires cargo-sbom in CI | Amortise against build time; pin cargo-sbom version to avoid supply-chain risk on the tooling itself. |
| SLSA L3 provenance | Tamper-resistant; generator identity cannot be forged from the repository | Requires a separate reusable workflow job; slightly increases pipeline complexity | Provide a shared reusable workflow that all WASM repos call with one `uses:` line. |
| OCI referrer model for attestations | Co-located with the artifact; garbage-collected together; no separate attestation store | Requires OCI Distribution v1.1 registry (GHCR, ECR, Harbor 2.11+) | Verify registry compatibility; fall back to cosign's legacy `--attachment` mode for older registries. |
| Kyverno SBOM enforcement | Blocks modules without attestation at cluster admission | Webhook adds 100–300ms latency to Pod admission | Use `background: false` to limit scope; Kyverno admission is fast for cached signatures. |
| Vulnerability scan against SBOM | Detects known CVEs in WASM dependencies | False positives for crates that are compiled away by `cfg` flags or unused feature gates | Accept as a known limitation; treat the SBOM as an over-approximation and investigate flagged CVEs before dismissing. |
| OPA policy for non-Kubernetes runtimes | Extends coverage beyond Kubernetes to Spin, wasmCloud, custom runtimes | Requires runtime instrumentation to call OPA before module load | Provide a library or sidecar that handles the OPA call and returns allow/deny. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| SBOM generation step omitted from pipeline | No CycloneDX attestation in registry | `cosign verify-attestation --type cyclonedx` returns "no matching attestations" | Add `cargo sbom` step to the pipeline before the push step; re-run the build to produce and attach the SBOM. |
| cargo-sbom version not pinned | Non-reproducible SBOM output across builds | SBOM diff shows format or content changes without dependency changes | Pin `cargo install cargo-sbom@0.9.x` in CI; use `--locked` on `cargo install`. |
| `Cargo.lock` not committed to repository | `cargo sbom --locked` fails; dependency resolution may differ between builds | Build-time error from cargo | Commit `Cargo.lock` to the repository; this is required for reproducible WASM builds regardless of SBOM. |
| Registry does not support OCI referrers | `cosign attest` succeeds but attestations are not retrievable via the referrers API | `oras discover` shows no referrers; `cosign verify-attestation` returns empty | Upgrade registry to OCI Distribution v1.1; or use cosign in `--attachment` (legacy tag-based) mode. |
| Kyverno policy matches container Pods | Standard container deployments fail admission because they lack a CycloneDX SBOM | Pod admission rejected with "missing attestation" message | Scope the policy to WASM `runtimeClassName` via `preconditions`; review the policy's match block. |
| Grype/trivy CVE database not updated | Scan misses recently published CVEs | Scanner version shows stale DB date; new CVEs not in results | Run `grype db update` or `trivy db update` before scanning; pin scanner version and update on a schedule. |
| SLSA generator subject drift | Provenance signed by a different generator version is rejected by the pinned policy | Kyverno admission failure with subject mismatch | Update the Kyverno policy's `subject` glob to accept `refs/tags/*` rather than a pinned tag; audit which tags are acceptable. |

## Related Articles

- [OCI WASM Module Signing and Verification](/articles/wasm/wasm-oci-signing/)
- [Reproducible WASM Builds](/articles/wasm/reproducible-wasm-builds/)
- [WASM Toolchain Security](/articles/wasm/wasm-toolchain-security/)
- [WASM Static Analysis and Binary Security](/articles/wasm/wasm-static-analysis/)
- [WASM Supply Chain Scanning Tools](/articles/wasm/wasm-supply-chain-scanning-tools/)
