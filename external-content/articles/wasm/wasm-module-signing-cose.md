---
title: "WASM Module Signing Beyond OCI: COSE, In-Band Signatures, and Non-Registry Distribution"
description: "OCI-based WASM signing works for container registries, but many WASM use cases distribute modules via HTTP, npm, or direct file transfer. This guide covers COSE (CBOR Object Signing) for WASM, signing WASM modules published to npm, Sigstore bundle format for non-OCI distribution, and verifying signatures in Wasmtime before instantiation."
slug: wasm-module-signing-cose
date: 2026-05-07
lastmod: 2026-05-07
category: wasm
tags:
  - wasm
  - module-signing
  - cose
  - sigstore
  - supply-chain
personas:
  - security-engineer
  - platform-engineer
article_number: 595
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/wasm/wasm-module-signing-cose/
---

# WASM Module Signing Beyond OCI: COSE, In-Band Signatures, and Non-Registry Distribution

## Problem

OCI signing — cosign, notation, Sigstore keyless — is well-documented for WASM modules stored in container registries. However, a substantial fraction of WASM distribution does not involve OCI registries at all:

- **npm packages:** A Rust library compiled to WASM ships as `pkg.wasm` inside an npm tarball. The runtime pulls the `.wasm` file from a `node_modules` path or a CDN-backed npm mirror, not from a registry with OCI signature lookup.
- **CDN delivery:** Browser WASM workloads are fetched from a CDN (CloudFront, Cloudflare) over HTTPS. The URL is stable; the file can change. HTTPS gives transport integrity but no content-origin integrity.
- **Direct HTTP download:** IoT or embedded runtimes (Wasmtime compiled for ARM, WasmEdge on industrial gateways) download `.wasm` updates from an update server. There is no registry; the module arrives as raw bytes.
- **Bundled in application binaries:** Go applications embed WASM modules as `//go:embed`. Python wheels ship `.wasm` inside the `.whl` archive. The module reaches the runtime by being extracted from a parent artifact, not fetched from any registry.
- **Plugin ecosystems:** Extism, wasmCloud, Dapr sidecar WASM extensions — these are often fetched from a URL in a config file or loaded from a local path. No OCI.

In every case the goal is the same: before any WASM module executes, the runtime must be able to answer the question "did the expected build pipeline produce this exact byte sequence?" OCI cosign answers that question for OCI artifacts. For the distributions above, the answer requires different tooling.

This article covers four signing approaches that work without OCI registries: COSE (CBOR Object Signing and Encryption) for compact binary-format signatures, Sigstore bundle files for non-OCI Sigstore signing, in-band signatures embedded inside the WASM binary itself, and npm package provenance for WASM packages. It also covers verification inside Wasmtime before module instantiation, Rekor transparency for non-OCI modules, and load-time policy enforcement.

**Target environments:** Wasmtime 25+, cosign 2.4+, Rekor CLI 1.3+, `cose-rust` 0.7+, npm 10+ with provenance, Extism, WasmEdge.

## Threat Model

- **Adversary 1 — CDN or update server compromise:** Attacker replaces a `.wasm` file at its distribution URL. Downstream runtimes fetch the replacement without HTTPS providing any content-origin guarantee.
- **Adversary 2 — npm package substitution:** Attacker publishes a scoped or typosquatted npm package containing a backdoored `.wasm` file. No signature verification occurs when `require()` calls `fs.readFileSync('pkg.wasm')`.
- **Adversary 3 — Embedded module replacement:** An attacker with filesystem access modifies a `.wasm` file embedded in an application before or after extraction. The runtime loads the modified module with no change to external metadata.
- **Adversary 4 — Replay of signed but vulnerable module:** A legitimately signed older module with a known CVE is delivered in place of the current version. The signature is valid, so naive verification passes.
- **Access level:** Adversary 1 has write to the CDN origin or S3 bucket. Adversary 2 has a valid npm account. Adversary 3 has host filesystem write. Adversary 4 has no write access but can intercept or redirect download requests.
- **Out of scope:** Runtime sandbox escapes, memory safety within the module, and OCI registry signing (covered in `/articles/wasm/wasm-oci-signing/`).

## COSE Signing for WASM Modules

COSE (CBOR Object Signing and Encryption) is defined in RFC 8152 (superseded by RFC 9052 and RFC 9053). It is the binary-format equivalent of JWS/JOSE: where JWS uses JSON and Base64url, COSE uses CBOR and raw bytes. The resulting signature structures are compact — typically 100–200 bytes for an ES256 signature header and fixed-size key identifier, versus several hundred bytes for equivalent JSON structures. This matters for constrained environments: IoT gateways, edge devices, or runtimes where signature overhead relative to module size is a consideration.

A COSE_Sign1 structure for a WASM module attaches the signature as a detached or attached CBOR structure alongside (or inside) the module. The protected header carries the algorithm identifier (`-7` for ES256, `-35` for ES384, `-8` for EdDSA) and optionally a key ID. The payload is the raw WASM bytes. The signature is computed over the CBOR-encoded protected header and the payload.

### Signing a WASM Module with COSE

Install the `cose-util` CLI (a Rust binary backed by the `cose-rust` crate):

```bash
cargo install cose-util --locked
```

Generate or obtain an EC P-256 key pair in PEM form:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out signing.pem
openssl ec -in signing.pem -pubout -out signing.pub.pem
```

Produce a detached COSE_Sign1 structure — a `.cose` file alongside the module:

```bash
cose-util sign \
  --algorithm ES256 \
  --key signing.pem \
  --payload payments.wasm \
  --detached \
  --output payments.wasm.cose
```

The `--detached` flag produces a COSE_Sign1 structure with the payload field set to `null` (per RFC 9052 §4.1) and the signature computed over the actual payload bytes. The `.wasm` file and `.wasm.cose` file are distributed together.

Verify at the receiving end:

```bash
cose-util verify \
  --algorithm ES256 \
  --key signing.pub.pem \
  --payload payments.wasm \
  --signature payments.wasm.cose
```

A non-zero exit code means the signature is invalid or the payload bytes differ from what was signed. This check must happen before any call to `Module::new` or equivalent.

### Why COSE Over JWS for Embedded Use Cases

For a browser or server application downloading a WASM module, the JSON-based Sigstore bundle format (described below) is often more practical. COSE is preferable when:

- The verification runtime is a microcontroller or gateway with constrained RAM and no JSON parser.
- Signature bytes are transmitted over a protocol with size limits (CoAP, MQTT).
- The signing infrastructure already uses COSE (e.g., firmware signing pipelines using SUIT manifests, where WASM modules are embedded as SUIT components).

The `cose-rust` crate compiles to WASM itself, so COSE verification can run inside a WASM host that is itself verifying WASM modules.

## Sigstore Bundle Format for Non-OCI Distribution

Sigstore's `cosign` tool was initially designed around OCI registries, but since cosign 2.0 it also supports the Sigstore bundle format: a JSON file (`.sigstore`) that carries the signature, certificate chain, and Rekor transparency log inclusion proof without any OCI dependency.

### Signing a WASM File to a Bundle

```bash
# Keyless signing using Fulcio — prompts for OIDC authentication.
cosign sign-blob \
  --bundle payments.wasm.sigstore \
  payments.wasm
```

`cosign sign-blob` computes a SHA-256 digest of `payments.wasm`, requests a short-lived signing certificate from Fulcio (bound to the OIDC identity performing the signing — typically a CI service account), and records the signature in the Rekor transparency log. The resulting `payments.wasm.sigstore` bundle file contains:

- `mediaType`: bundle schema version identifier.
- `verificationMaterial.certificate`: the base64-encoded Fulcio-issued X.509 certificate carrying the signing identity (email or subject URI).
- `verificationMaterial.tlogEntries`: Rekor log entry including the log index, inclusion proof, and signed entry timestamp.
- `dsseEnvelope` or `messageSignature`: the actual signature over the module digest.

Distribute `payments.wasm` and `payments.wasm.sigstore` together. The bundle is self-contained: verification requires only the Sigstore root of trust (included in `cosign`'s embedded TUF metadata), not a live OCI registry call.

### Verifying the Bundle

```bash
cosign verify-blob \
  --bundle payments.wasm.sigstore \
  --certificate-identity "https://github.com/myorg/payments/.github/workflows/release.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  payments.wasm
```

The `--certificate-identity` and `--certificate-oidc-issuer` flags pin the expected signing identity. Verification fails if the bundle's certificate does not match, if the Rekor inclusion proof is invalid, or if the digest in the bundle does not match the file bytes. This is equivalent to what `cosign verify` does for OCI artifacts, without any registry involved.

For long-term offline verification (air-gapped environments), add `--insecure-ignore-tlog` and pin the Fulcio certificate explicitly with `--certificate-chain`. This trades the transparency property for offline capability.

## Signing WASM Modules in npm Packages

WASM distributed via npm occupies a gap in supply-chain controls: npm package provenance (introduced in npm 9.5 / npmjs.com 2023) provides a SLSA attestation that the package was built from a specific commit in a specific CI workflow. This covers the package itself, including any `.wasm` files inside it.

### Enabling npm Provenance

npm provenance requires publishing from a supported CI environment (GitHub Actions, GitLab CI) with an OIDC token. The package is signed and the provenance attestation is linked to the npm registry entry.

```yaml
# .github/workflows/publish.yml
name: Publish npm package
on:
  push:
    tags: ['v*']
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write   # Required for OIDC token used by npm provenance.
      contents: read
    steps:
      - uses: actions/checkout@v4
      - name: Build WASM module
        run: |
          wasm-pack build --target web --release
      - name: Publish with provenance
        run: npm publish --provenance --access public
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

When `--provenance` is set, npm generates a Sigstore bundle attestation that is stored on the npm registry alongside the package tarball. Users can verify it:

```bash
npm audit signatures my-wasm-package
```

This verifies the registry-stored signatures for every installed package that has provenance. The `.wasm` file inside the tarball is covered by the tarball integrity check that is part of the provenance attestation.

### Adding a Standalone Bundle to the npm Package

npm provenance covers the whole package. If consumers need to verify the `.wasm` file independently of npm (e.g., when the module is later copied out of `node_modules` and deployed to a CDN), include the `.sigstore` bundle as a package file:

```bash
# In the build step, after wasm-pack:
cosign sign-blob \
  --bundle pkg/my_module_bg.wasm.sigstore \
  pkg/my_module_bg.wasm
```

Add to `package.json`:

```json
{
  "files": [
    "pkg/my_module_bg.wasm",
    "pkg/my_module_bg.wasm.sigstore",
    "pkg/my_module_bg.js"
  ]
}
```

Consumers who copy the `.wasm` to a CDN can then distribute the `.sigstore` bundle alongside it, preserving the chain of custody from the original npm build.

## In-Band Signatures: Embedding in a Custom WASM Section

The WASM binary format defines a custom section type (`section_id = 0`) with a name string. Custom sections are ignored by runtimes that do not understand them — a module with an unrecognized custom section is still a valid, loadable WASM binary. This makes custom sections an ideal carrier for in-band signatures: the signature travels inside the module file, no sidecar file required.

### Structure of an In-Band Signature Section

Define a custom section named `__signature` (or a namespaced variant like `myorg.sig`). The section body is a deterministic encoding of the signature structure — COSE_Sign1 CBOR is a natural fit because it is already a binary format.

The critical rule: the signature must cover the module bytes **excluding** the `__signature` section itself. The signing process is:

1. Parse the WASM binary and strip any existing `__signature` section to produce a canonical payload.
2. Compute COSE_Sign1 over the canonical payload.
3. Append the `__signature` custom section (name + COSE bytes) to the original module.

Verification reverses this:

1. Parse the module, extract the `__signature` section bytes.
2. Strip the `__signature` section to reconstruct the canonical payload.
3. Verify the COSE_Sign1 against the canonical payload.

A Rust implementation using `wasmparser` and `cose-rust`:

```rust
use wasmparser::{Parser, Payload};
use wasm_encoder::{CustomSection, Module as EncoderModule, RawSection};

/// Returns the canonical (signature-stripped) bytes of a WASM module.
fn canonical_bytes(wasm: &[u8]) -> Vec<u8> {
    let mut output = EncoderModule::new();
    for payload in Parser::new(0).parse_all(wasm) {
        match payload.expect("parse error") {
            Payload::CustomSection(cs) if cs.name() == "__signature" => {
                // Drop the existing signature section.
            }
            Payload::Version { encoding, .. } => {
                // The encoder emits the WASM header automatically.
                let _ = encoding;
            }
            other => {
                if let Some((id, range)) = other.as_section() {
                    output.section(&RawSection { id, data: &wasm[range] });
                }
            }
        }
    }
    output.finish()
}
```

The advantage of in-band signatures is portability: a single `.wasm` file carries its own verification material. There is no risk of the sidecar file being dropped when the module is copied, bundled, or embedded. The disadvantage is that any tool that modifies the WASM binary after signing (wasm-opt, stripping the name section, wasm-merge) invalidates the signature. Sign after all post-processing steps.

## Verifying Signatures in Wasmtime Before Instantiation

Regardless of which signature format is used, verification must happen before any code from the module runs. In Wasmtime the boundary is `Module::new` or `Component::new`: once these succeed, compilation has already processed the untrusted bytes. Pre-validation is possible but the clearest enforcement point is wrapping module loading.

### Pre-Instantiation Verification in Rust

```rust
use wasmtime::{Engine, Module, Store};
use std::fs;

fn load_verified_module(engine: &Engine, wasm_path: &str, sig_path: &str) -> anyhow::Result<Module> {
    let wasm_bytes = fs::read(wasm_path)?;
    let sig_bytes = fs::read(sig_path)?;

    // Verify the COSE or Sigstore bundle before passing bytes to Wasmtime.
    verify_cose_signature(&wasm_bytes, &sig_bytes)?;

    // Only reach Module::new if the signature is valid.
    let module = Module::new(engine, &wasm_bytes)?;
    Ok(module)
}

fn verify_cose_signature(payload: &[u8], signature: &[u8]) -> anyhow::Result<()> {
    // cose-rust verification — returns Err if invalid.
    use cose::sign::CoseSign1;
    let sign1 = CoseSign1::from_bytes(signature)?;
    sign1.verify_detached(payload, &get_trusted_public_key()?)?;
    Ok(())
}
```

For the Sigstore bundle format, use the `sigstore` Rust crate or shell out to `cosign verify-blob` from the verification wrapper. The pattern is the same: the wrapper function either returns a verified `Module` or returns an error. Callers cannot accidentally skip verification by calling `Module::new` directly if loading always goes through this wrapper.

### Wasmtime Pre-Validation Hook

Wasmtime 25+ exposes a `Config::wasm_module_validation_hook` (unstable feature) that fires after parsing but before compilation. This is the appropriate place for signature enforcement when the verification material is in-band (embedded custom section):

```rust
let mut config = wasmtime::Config::new();
config.wasm_module_validation_hook(|wasm_bytes| {
    // Extract and verify the __signature custom section.
    // Return Err to abort compilation.
    in_band_verify(wasm_bytes).map_err(|e| {
        anyhow::anyhow!("signature verification failed: {}", e)
    })
});
let engine = Engine::new(&config)?;
```

With this hook, even code paths that call `Module::new` directly (third-party libraries, plugin loaders) will fail if they attempt to load an unsigned or incorrectly signed module.

## Signature Transparency with Rekor for Non-OCI Modules

Rekor is the transparency log component of Sigstore. When `cosign sign-blob` is used with the default public Rekor instance (`rekor.sigstore.dev`), the signature and module digest are appended to an append-only, Merkle-tree-backed log. This provides two properties that static signature verification alone does not:

1. **Non-repudiation:** the signing event is publicly recorded. An attacker who compromises the signing key after the fact cannot deny that specific modules were signed at specific times without the discrepancy being detectable.
2. **Temporal pinning:** the Rekor entry includes a signed timestamp. Verification can check that the module was signed while the certificate was valid, even after the short-lived Fulcio certificate expires.

Check a Rekor entry for a WASM module without the full bundle:

```bash
rekor-cli search \
  --sha "$(sha256sum payments.wasm | awk '{print $1}')"
```

This returns all log entries that reference the module digest. If the module was signed in CI, exactly one entry should exist with the expected workflow identity. Zero entries mean it was never submitted to the public log — either intentionally (private log) or because it was never signed with Rekor enabled. Multiple entries for different identities warrant investigation.

For private deployments running their own Rekor instance:

```bash
cosign sign-blob \
  --rekor-url https://rekor.internal.example.com \
  --bundle payments.wasm.sigstore \
  payments.wasm
```

The bundle's `tlogEntries` will reference the private Rekor instance. Verifiers need access to the private instance to validate the inclusion proof.

## Policy Enforcement at WASM Load Time

Signature verification is a necessary but not sufficient policy control. A complete load-time policy also enforces:

- **Signer identity constraints:** only signatures from `https://github.com/myorg/payments/.github/workflows/release.yml` are accepted. Signatures from any other identity — including other workflows in the same organization — are rejected.
- **Version/timestamp freshness:** the Rekor entry timestamp must be within an acceptable window. Modules older than the current production version by more than N days require explicit exception.
- **Digest pinning for critical modules:** for high-sensitivity WASM (cryptographic code, secrets processing), maintain a pinned digest list in addition to signature verification. A valid signature from the expected identity but for an unexpected digest triggers an alert.

Implement this as a typed policy struct:

```rust
#[derive(Debug)]
struct WasmLoadPolicy {
    /// Accepted certificate identity (SAN/URI).
    expected_identity: String,
    /// Accepted OIDC issuer.
    expected_issuer: String,
    /// Maximum age of the Rekor entry in seconds.
    max_age_secs: u64,
    /// Optional SHA-256 digest pin. None = any valid signed digest accepted.
    pinned_digest: Option<[u8; 32]>,
}

impl WasmLoadPolicy {
    fn enforce(&self, bundle: &SigstoreBundle, wasm_bytes: &[u8]) -> anyhow::Result<()> {
        bundle.verify_identity(&self.expected_identity, &self.expected_issuer)?;
        bundle.verify_rekor_freshness(self.max_age_secs)?;
        if let Some(pin) = &self.pinned_digest {
            let actual = sha256(wasm_bytes);
            anyhow::ensure!(&actual == pin, "digest mismatch: module not pinned version");
        }
        Ok(())
    }
}
```

This policy object is constructed at application startup from a configuration file that is itself integrity-protected (signed or stored in a secret manager). The load path calls `policy.enforce(bundle, &wasm_bytes)?` before `Module::new`.

## Summary of Signing Approach Selection

| Distribution channel | Recommended format | Verification point |
|---|---|---|
| OCI registry | cosign / notation (OCI) | Admission webhook or runtime pull |
| CDN or HTTPS download | Sigstore bundle (`.sigstore`) | Pre-instantiation wrapper |
| npm package | npm provenance + bundle in package | `npm audit signatures` + wrapper |
| IoT / embedded update | COSE_Sign1 (`.cose`) | Bootloader or WASM host init |
| In-process plugin loader | In-band custom section | Wasmtime validation hook |
| Air-gapped environment | COSE_Sign1 with local key | Offline verification before load |

The choice of signing format is secondary to the enforcement point: verification must occur before `Module::new`. A perfectly-formed COSE signature checked after instantiation provides no security.

## Operational Notes

- **Rotate keys with overlap.** When rotating the signing key, keep the old public key trusted for verification for at least one release cycle. Otherwise, a module signed with the old key that is still in deployment will fail verification immediately after rotation.
- **Sign after all transformations.** wasm-opt, wasm-strip, wasm-merge, and other post-processing tools modify the binary. Sign the final artifact, not the compiler output.
- **Include the module version in the COSE protected header.** Use the `kid` (key ID) or a custom header parameter to carry a version string. This allows the policy to reject replay of older signed modules.
- **Test signature verification failure paths.** Deliberately deploy a module with a tampered byte and confirm the load path rejects it with a clear error. Untested verification code frequently has silent failure modes (returning true on parse errors, catching exceptions too broadly).
- **Store private COSE keys in HSMs or KMS.** The same key management practices that apply to container signing keys apply here. A compromised signing key invalidates all past and future signatures from that key.
