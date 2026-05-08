---
title: "npm Package Integrity Verification: The Gap the Axios Attack Exposed"
description: "Axios 1.14.1 passed every npm integrity check — the malicious tarball had a correct SHA-512 hash because it was legitimately published. Understand what npm integrity protects against, where it fails, and how provenance attestations close the gap."
slug: npm-package-integrity-verification
date: 2026-05-04
lastmod: 2026-05-04
category: cross-cutting
tags:
  - supply-chain
  - npm
  - integrity
  - provenance
  - package-security
personas:
  - security-engineer
  - platform-engineer
article_number: 429
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/cross-cutting/npm-package-integrity-verification/
---

# npm Package Integrity Verification: The Gap the Axios Attack Exposed

## The Problem

The `integrity` field in `package-lock.json` — a SHA-512 hash of the package tarball — is widely understood as a supply chain security control. After the Axios compromise of March 31 2026, many developers asked: "why didn't the integrity hash catch this?" The answer reveals a fundamental limit of hash-based integrity: a hash proves that the bytes you received match the bytes that were published. It says nothing about whether those bytes are malicious.

The Axios 1.14.1 attack followed a path that hash-based integrity was never designed to detect. An attacker obtained a stolen maintainer token — the exact credential used to publish legitimate Axios releases — and used it to publish a malicious tarball directly to the npm registry. The npm registry received the tarball, computed its SHA-512 hash, and stored that hash as the package's official `integrity` value in its metadata. Every npm client that installed `axios@1.14.1` downloaded the tarball, verified it against the recorded hash, found a match, and proceeded. The integrity check passed because it was designed to pass. It verified that the download was uncorrupted and unmodified in transit. It had no mechanism to verify that the content was trustworthy.

This is the distinction that matters: **integrity is not trustworthiness**. A SHA-512 hash answers the question "did I receive exactly what the registry served?" It does not answer "should the registry have served this?" An attacker who controls the publish step controls the hash. Every downstream check that trusts the hash transitively trusts the attacker.

Understanding this distinction is the prerequisite for evaluating the next layer of controls — npm provenance attestations — which are designed to answer the question the hash cannot.

## Threat Model

**What integrity hashes catch:**

- **CDN tampering.** If a content delivery network serving npm packages modifies a tarball in transit, the bytes delivered to `npm install` will not match the recorded SHA-512 hash. The install fails. This is the primary threat model integrity was designed for.
- **MITM attacks between registry and client.** A network attacker who intercepts the download and modifies the tarball will produce a hash mismatch. `npm ci` exits non-zero.
- **Accidental corruption.** Disk errors, storage failures, or truncated downloads that alter tarball bytes are caught by the hash check.

**What integrity hashes do not catch:**

- **Malicious content published legitimately.** The Axios pattern. If an attacker publishes a malicious tarball through the standard publish mechanism — using a valid token, through the registry's own upload path — the registry hashes the malicious tarball and records that hash as authoritative. Every integrity check downstream verifies the malicious content is present and unmodified.
- **A compromised registry that re-generates hashes.** If the npm registry itself were compromised and re-hashed tampered tarballs, the hash values in `package-lock.json` would be updated to match the tampered content on the next install. Clients would see no mismatch.
- **Social engineering of the package maintainer.** A maintainer tricked into publishing malicious code — or coerced into doing so — produces a legitimately signed and hashed package. No integrity mechanism detects this.

**The provenance gap:**

Without provenance attestations, there is no cryptographic proof linking a published tarball to a specific source commit, a specific repository, and a specific CI workflow. A maintainer — compromised or malicious — can publish any tarball under any version number and claim it corresponds to any source. The tarball's `integrity` hash will be correct. The `repository` field in `package.json` is informational only; it is not verified against the published artifact.

This is the gap that npm provenance attestations are designed to close. Provenance records, cryptographically, which CI workflow produced the tarball, from which source commit, in which repository. A tarball published by a stolen token outside of CI has no legitimate provenance attestation — or has a provenance attestation that points to the wrong workflow or repository, which is equally detectable.

## Hardening Configuration

### 1. How npm integrity works end-to-end

When a maintainer runs `npm publish`, the npm CLI packages the project as a `.tgz` tarball and uploads it to the registry. The registry computes the SHA-512 hash of the tarball and stores it in the package's version metadata. This hash is the value published to `package-lock.json` as the `integrity` field.

When a developer runs `npm install` for the first time, npm resolves the dependency graph, fetches each tarball from the registry, records the tarball's integrity hash in `package-lock.json`, and caches the tarball locally. When a CI pipeline runs `npm ci`, npm reads `package-lock.json`, fetches each tarball (from cache or registry), and verifies that the tarball's SHA-512 hash matches the recorded value. If any hash mismatches, `npm ci` exits with a non-zero status and the install fails.

To inspect the integrity hash for any package version:

```bash
npm view axios@1.14.0 dist.integrity
```

This queries the registry's metadata and returns the SHA-512 hash for that version. To cross-check what is recorded in a `package-lock.json`:

```bash
grep -A3 '"axios"' package-lock.json | grep integrity
```

To manually verify a downloaded tarball against the hash:

```bash
npm pack axios@1.14.0 --dry-run 2>/dev/null
curl -sL "$(npm view axios@1.14.0 dist.tarball)" -o axios-1.14.0.tgz
openssl dgst -sha512 -binary axios-1.14.0.tgz | openssl base64 -A
```

The base64-encoded SHA-512 output should match the value in `npm view axios@1.14.0 dist.integrity` after the `sha512-` prefix. For `axios@1.14.1` on 31 March 2026, this check would have returned a match — the malicious tarball had a correct hash. The hash told you nothing about the content.

### 2. npm provenance attestations: the layer above hash integrity

npm provenance, introduced in npm 9.5 and backed by Sigstore, records which GitHub Actions workflow published a package, which source commit the package was built from, and which repository owns the workflow. This information is cryptographically signed by Sigstore's Fulcio certificate authority using the workflow's OIDC identity, and the signature is appended to Sigstore's Rekor transparency log.

The key property: provenance is generated by the CI workflow during publish. A maintainer publishing a package with a stolen token — outside of the expected CI workflow — either produces no provenance attestation, or produces a provenance attestation signed by a different identity than the one expected for that package.

To verify both the package signature and provenance attestation for all installed packages:

```bash
npm audit signatures
```

Example output for a dependency tree where provenance is present and valid:

```bash
audited 847 packages in 12s

847 packages have verified registry signatures

Package                            Signature  Provenance
axios@1.14.0                       verified   verified
  └─ https://github.com/axios/axios/.github/workflows/release.yml
```

For a package with no provenance attestation — as `axios@1.14.1` would have shown — the output would instead indicate:

```bash
audited 848 packages in 13s

847 packages have verified registry signatures

Package                            Signature  Provenance
axios@1.14.1                       verified   missing

1 package has missing provenance
```

The `axios@1.14.1` malicious version was published directly using a stolen token, not through the axios project's GitHub Actions release workflow. It would therefore carry no provenance attestation from the expected workflow. Every legitimate previous release of axios was published through CI with provenance. A missing provenance entry for `axios@1.14.1` in a lockfile that had provenance for `axios@1.14.0` is a strong anomaly signal — exactly the kind of signal that `npm audit signatures` surfaces.

### 3. Verifying provenance for critical dependencies in CI

Add `npm audit signatures` as a step immediately after `npm ci` in your CI pipeline. The step should run before any build, test, or deploy step, so that a provenance anomaly blocks the pipeline before untrusted code executes.

```bash
npm ci
npm audit signatures
```

For stricter enforcement, capture the exit code and fail explicitly with a message:

```bash
npm ci

if ! npm audit signatures; then
  echo "npm audit signatures failed: registry signatures or provenance attestations could not be verified"
  echo "Review the output above. Packages with missing provenance require manual investigation."
  exit 1
fi
```

As of mid-2026, `npm audit signatures` exits non-zero only when a signature is invalid — a clear sign of tampering. Missing provenance generates a warning but does not cause a non-zero exit by default, because many packages in the npm ecosystem do not yet publish provenance. A pipeline that treated missing provenance as a hard error would break on most existing projects. The phased approach:

- **Phase 1 (now):** Run `npm audit signatures` in CI; log and review warnings for missing provenance on direct dependencies.
- **Phase 2 (3–6 months):** For a defined list of critical direct dependencies (those with access to secrets, network, or filesystem), treat missing provenance as an error and break the build.
- **Phase 3 (12+ months):** As provenance adoption increases across the ecosystem, expand the critical list or enable full enforcement.

To check provenance for a specific package without running a full install:

```bash
npm audit signatures --package axios@1.14.1
```

### 4. Ecosystem comparison: how other package managers handle this

**Rust / crates.io:** `cargo-audit` checks the installed dependency tree against the RustSec advisory database for known vulnerabilities. It does not verify provenance. Crates.io is implementing Trusted Publishing — an OIDC-based publish mechanism similar to npm's — but as of 2026 it is not yet the default path for all crates. `cargo-audit` is a strong CVE control, not a provenance control.

**Python / PyPI:** PEP 458 and PEP 480 define a TUF (The Update Framework) based model for PyPI. Trusted Publishing via OIDC is now the recommended publish path for new packages and is widely adopted. A PyPI package published via Trusted Publishing has a verifiable link to the GitHub Actions workflow that produced it, functionally equivalent to npm provenance. `pip` does not yet verify provenance by default; this is a tooling gap. The `sigstore` Python package can verify Sigstore-backed attestations manually.

**Go modules:** Go's `go.sum` provides content-addressed verification — similar to `package-lock.json` integrity — but Go modules add a further layer: the Go checksum database at `sum.golang.org`. This is a transparency log (not unlike Sigstore's Rekor) that records the expected hash for every module version. When `go mod download` fetches a module, it checks the hash against `sum.golang.org`. A module version whose hash differs from the transparency log record is rejected. This is closer to the provenance model than npm's hash-only approach: the transparency log provides an independent third-party record that a given module version had a given hash at a specific point in time, making silent hash substitution much harder even for a compromised registry.

**Summary:** Go's checksum database is the most mature ecosystem-level transparency control. npm provenance via Sigstore/Rekor is the strongest per-package provenance control for npm. PyPI's Trusted Publishing is comparable in concept but lags in default enforcement at the client.

### 5. The transparency log approach

Sigstore's Rekor is an append-only, tamper-evident transparency log — conceptually similar to Certificate Transparency logs for TLS certificates. Every npm package published with provenance generates a Rekor log entry containing the signing certificate (which encodes the OIDC identity of the publishing workflow), the package name and version, and a hash of the signed artifact.

Because Rekor is append-only, you can detect a package whose provenance was generated from an unexpected workflow by querying Rekor for the log entry associated with a specific package version and inspecting the embedded certificate's subject and issuer.

npm's Sigstore integration uses Rekor automatically when a package is published with provenance. The `npm audit signatures` command queries Rekor to verify the log entries for installed packages.

To inspect provenance for a specific package version using `cosign`:

```bash
cosign verify-attestation \
  --type https://github.com/npm/attestation/tree/main/specs/publish/v0.1 \
  --certificate-identity-regexp "https://github.com/axios/axios/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  registry.npmjs.org/axios:1.14.0
```

For a version published without provenance, this command returns no attestations. For a version published through the wrong workflow — for example, through a fork of the axios repository rather than the upstream — the `--certificate-identity-regexp` filter would not match, and the command would exit non-zero.

To query the Rekor log directly for entries associated with a package hash:

```bash
rekor-cli search --sha "$(npm view axios@1.14.0 dist.integrity | sed 's/sha512-//')"
```

This returns Rekor entry UUIDs. Each can be fetched to inspect the full certificate chain:

```bash
rekor-cli get --uuid <entry-uuid> --format json | jq '.Body.HashedRekordObj.signature'
```

The certificate embedded in the Rekor entry encodes the workflow URL, repository, and commit SHA. For a legitimate axios release, this points to the axios repository's release workflow. For `axios@1.14.1`, there would be no Rekor entry — the malicious tarball was not published through a Sigstore-enabled workflow.

## Expected Behaviour After Hardening

After `npm audit signatures` is integrated into CI:

- Every package with a valid registry signature and provenance attestation produces no output beyond the summary count.
- A dependency published without provenance generates a warning line identifying the package name and version. Direct dependencies with missing provenance should be investigated: check whether previous versions of that package had provenance; if yes, a missing attestation on a new version is anomalous.
- A dependency whose provenance attestation points to an unexpected repository or workflow generates an error in the `npm audit signatures` output.

For a lockfile containing `axios@1.14.1`, `npm audit signatures` would show the package as having a verified registry signature (the tarball hash is valid) but missing provenance (no attestation from the expected release workflow). This is not proof of compromise on its own — some packages publish without provenance — but for a package like axios, which had provenance on all previous releases, a missing attestation on a new version is a clear signal for human investigation before the build proceeds.

The goal is not to make `npm audit signatures` a fully automated binary pass/fail gate immediately. The goal is to ensure that provenance anomalies are surfaced, logged, and reviewed. Over time, as provenance adoption across the npm ecosystem increases, tighten enforcement from warning to error for an expanding set of critical dependencies.

## Trade-offs and Operational Considerations

- `npm audit signatures` adds 5–15 seconds to CI builds for large dependency trees. For a 500-package tree, expect 8–12 seconds of added latency. This is an acceptable cost given the signal it provides; it is comparable to the time added by `npm audit` for CVE checking.
- Many npm packages — particularly older packages and those maintained by small teams — do not yet publish provenance attestations. Treating "missing provenance" as a build-breaking error would fail CI for most existing projects. Phase in enforcement incrementally: start with warnings, then move to errors for defined critical packages, then broaden the set as ecosystem adoption increases.
- The Sigstore transparency log is a third-party service. `npm audit signatures` and `cosign verify-attestation` must be able to reach `rekor.sigstore.dev` to verify attestations. In environments with strict egress controls, add `rekor.sigstore.dev` and `sigstore.dev` to your egress allowlist. In air-gapped environments, a private Sigstore deployment (Fulcio + Rekor + TUF mirror) is required to use provenance verification at all.
- Provenance attestations are associated with specific package versions. If you pin a lockfile to a version published before provenance was available for that package, the missing attestation reflects a historical gap, not an active attack. Establish a baseline: for each critical direct dependency, record when that package first published with provenance. Missing provenance on versions before that date is expected; missing provenance on versions after that date is anomalous.

## Failure Modes

- **`npm audit signatures` output reviewed manually but not enforced.** If the command runs in CI but warnings are not acted on — because no alert, no policy, no owner — they accumulate. The check becomes noise. Assign a specific team or rotation responsibility for reviewing missing-provenance warnings on direct dependencies within 48 hours of first appearance.
- **Provenance check passes but points to a fork of the expected repository.** An attacker can publish a package from a CI workflow on an attacker-controlled fork of the upstream project. The attestation is valid — Sigstore signed it, Rekor recorded it — but the repository URL in the provenance is `https://github.com/attacker/axios` rather than `https://github.com/axios/axios`. The `npm audit signatures` output includes the workflow URL; review it, not just the pass/fail status. The `cosign verify-attestation` command's `--certificate-identity-regexp` flag lets you enforce the expected upstream repository URL.
- **Team assumes "provenance present = safe".** Provenance proves that a specific CI workflow produced the tarball from a specific commit. It does not prove that the commit is trustworthy. If a malicious commit is merged into the upstream repository and a release is cut from it, the resulting package has valid provenance. Provenance is a necessary condition — it closes the stolen-token attack vector that compromised Axios 1.14.1 — but it does not replace code review, dependency auditing, or monitoring for unexpected behaviour at runtime.

## Related Articles

- [npm Lockfile Integrity Security](/articles/cicd/npm-lockfile-integrity-security/)
- [npm Maintainer Account Security](/articles/cross-cutting/npm-maintainer-account-security/)
- [Sigstore Keyless Signing](/articles/cicd/sigstore-keyless-signing/)
- [Software Supply Chain Third-Party Risk](/articles/cicd/software-supply-chain-third-party-risk/)
- [npm Publish Account Hardening](/articles/cicd/npm-publish-account-hardening/)
