---
title: "OCI WASM Module Signing and Verification: cosign, notation, and Admission-Time Enforcement"
description: "WASM modules ride OCI registries the same as containers. The supply-chain hygiene story is the same — and most orgs do not apply it to .wasm artifacts."
slug: "wasm-oci-signing"
date: 2026-04-27
lastmod: 2026-04-27
category: "wasm"
tags: ["wasm", "oci", "cosign", "supply-chain", "signing"]
personas: ["platform-engineer", "security-engineer", "devops"]
article_number: 180
difficulty: "intermediate"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/wasm/wasm-oci-signing/index.html"
---

# OCI WASM Module Signing and Verification: cosign, notation, and Admission-Time Enforcement

## Problem

WebAssembly modules are distributed through OCI registries — the same `ghcr.io`, `quay.io`, `docker.io`, and self-hosted Harbor / Distribution registries that hold container images. The OCI specification (WASM artifacts use media type `application/vnd.wasm.config.v0+json` and layer type `application/vnd.wasm.content.layer.v1+wasm`) treats them as a parallel artifact class.

Most organizations have well-developed supply-chain controls for container images: cosign signing in CI, attestations in registries, admission policies that verify signatures at deploy time. The same controls apply to WASM artifacts but typically are not applied. The gaps:

- The CI pipeline that builds container images runs `cosign sign` on the image; the pipeline that builds `.wasm` artifacts often does not.
- Admission policies (Kyverno, cosigned, ratify) configured to verify container images by default do not match WASM media types.
- Provenance attestations (SLSA, in-toto) are common for container builds; rare for WASM builds.
- Registries with image-signing policy enforcement may not extend the policy to WASM artifacts.
- Deploy-time tooling (Spin, wasmCloud, kwasm) often pulls modules without signature verification.

The result is an asymmetry: a malicious or tampered WASM module can ship through the same channels that block tampered container images. By 2026, WASM workloads on Kubernetes are running real production traffic; the gap is consequential.

This article covers cosign-based signing of WASM artifacts, attestations for build provenance, registry-side enforcement, admission-time verification, and the migration story for orgs already using cosign for containers.

**Target systems:** cosign 2.4+ with WASM artifact support, oras 1.2+, notation 1.1+, OCI Distribution v1.1+, Kyverno 1.12+ for admission-time `verifyImages` with WASM media types, ratify 1.2+. Compatible with Sigstore Fulcio for keyless signing.

## Threat Model

- **Adversary 1 — Registry compromise:** attacker who has compromised the registry and can replace WASM artifacts. They want a downstream cluster to pull the malicious module under the legitimate image reference.
- **Adversary 2 — Build pipeline compromise:** attacker has access to the CI build environment (compromised credentials, malicious dependency). They want to ship a malicious module signed under the legitimate identity.
- **Adversary 3 — Typosquatting on registry:** attacker pushes `myorg-payments` instead of `myorg/payments`; users pulling without strict reference validation may pull the typosquat.
- **Adversary 4 — Stale artifact replay:** attacker reverts a deployment to a prior, vulnerable version of a module that was legitimately signed. The module is technically valid but contains an exploited CVE.
- **Access level:** Adversary 1 has registry write. Adversary 2 has CI execution. Adversary 3 has user-account on a public registry. Adversary 4 has deploy permission.
- **Objective:** Run unauthorized WASM code in a downstream environment.
- **Blast radius:** Bounded to the WASM workload's runtime sandbox at minimum (covered by other articles in this category). Without signing controls, the bound is the entire WASM tenant + runtime escape surface. With signing, only artifacts produced by the legitimate build pipeline run, narrowing to legitimate-build-pipeline-bug surface.

## Configuration

### Step 1: Push a WASM Artifact to OCI

```bash
# Build the WASM module from source.
cargo component build --release
# Output: target/wasm32-wasip1/release/payments.wasm

# Push using oras with the WASM media types.
oras push ghcr.io/myorg/wasm/payments:1.2.3 \
  --artifact-type application/vnd.wasm.config.v0+json \
  target/wasm32-wasip1/release/payments.wasm:application/vnd.wasm.content.layer.v1+wasm
```

Verify the artifact in the registry:

```bash
oras manifest fetch ghcr.io/myorg/wasm/payments:1.2.3 | jq .
# {
#   "schemaVersion": 2,
#   "mediaType": "application/vnd.oci.image.manifest.v1+json",
#   "artifactType": "application/vnd.wasm.config.v0+json",
#   "config": {...},
#   "layers": [
#     {
#       "mediaType": "application/vnd.wasm.content.layer.v1+wasm",
#       "digest": "sha256:abc123...",
#       "size": 524288
#     }
#   ]
# }
```

### Step 2: Sign with cosign (Keyless Sigstore)

cosign 2.4+ supports OCI artifacts (not just images). Use Sigstore's keyless flow tied to the CI's OIDC identity:

```bash
# In CI, with id-token: write permission.
cosign sign --yes ghcr.io/myorg/wasm/payments:1.2.3
```

The CI's OIDC token is exchanged for a short-lived certificate from Fulcio; the artifact digest is signed; the signature and certificate land in Rekor (the transparency log). No long-lived signing key on disk.

For environments without Sigstore access, use a key-based signature:

```bash
# Generate a signing key (one-time, store privately in KMS).
cosign generate-key-pair --kms awskms:///alias/wasm-signing-key

# Sign.
cosign sign --key awskms:///alias/wasm-signing-key \
  ghcr.io/myorg/wasm/payments:1.2.3
```

Verify locally:

```bash
cosign verify ghcr.io/myorg/wasm/payments:1.2.3 \
  --certificate-identity 'https://github.com/myorg/payments-wasm/.github/workflows/build.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
# Verification for ghcr.io/myorg/wasm/payments:1.2.3 --
# The signatures were verified against the specified certificate.
```

`--certificate-identity` and `--certificate-oidc-issuer` pin verification to a specific workflow at a specific OIDC issuer. A signature minted by any other identity does not validate.

### Step 3: Attach SLSA Build Provenance

A signature attests "this artifact was signed by X." Provenance attests "this artifact was built from this source by this builder." cosign supports SLSA-formatted predicates:

```yaml
# .github/workflows/build.yml
name: Build and sign WASM
on:
  push:
    tags: [v*]

jobs:
  build:
    permissions:
      id-token: write
      contents: read
      packages: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Build component
        run: cargo component build --release

      - name: Push to registry
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          oras push ghcr.io/${{ github.repository_owner }}/wasm/payments:${{ github.ref_name }} \
            --artifact-type application/vnd.wasm.config.v0+json \
            target/wasm32-wasip1/release/payments.wasm:application/vnd.wasm.content.layer.v1+wasm

      - name: Sign artifact
        run: |
          cosign sign --yes \
            ghcr.io/${{ github.repository_owner }}/wasm/payments:${{ github.ref_name }}

      - name: Generate and attach SLSA provenance
        uses: slsa-framework/slsa-github-generator/.github/workflows/[email protected]
        with:
          digest: ${{ steps.push.outputs.digest }}
          registry-username: ${{ github.actor }}
        secrets:
          registry-password: ${{ secrets.GITHUB_TOKEN }}
```

The provenance is an in-toto statement signed under the same Fulcio cert that signed the artifact. Verifiers can require both signature and provenance:

```bash
cosign verify-attestation \
  --certificate-identity 'https://github.com/myorg/payments-wasm/.github/workflows/build.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --type slsaprovenance \
  ghcr.io/myorg/wasm/payments:1.2.3
```

### Step 4: Admission-Time Verification on Kubernetes

Kyverno can verify WASM artifacts at admission. The trick is matching by `runtimeClassName` so the policy applies only to WASM Pods:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-wasm-modules
spec:
  validationFailureAction: Enforce
  webhookTimeoutSeconds: 30
  background: false
  rules:
    - name: verify-wasm-signature
      match:
        any:
          - resources:
              kinds: [Pod]
      preconditions:
        all:
          - key: "{{ request.object.spec.runtimeClassName || '' }}"
            operator: AnyIn
            value: ["wasmtime", "spin", "wasmcloud", "wasmedge"]
      verifyImages:
        - imageReferences:
            - "ghcr.io/myorg/wasm/*"
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/myorg/*-wasm/.github/workflows/build.yml@refs/heads/main"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: https://rekor.sigstore.dev
          mutateDigest: true
          required: true
        - imageReferences:
            - "ghcr.io/myorg/wasm/*"
          attestations:
            - type: https://slsa.dev/provenance/v1
              attestors:
                - entries:
                    - keyless:
                        subject: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/*"
                        issuer: "https://token.actions.githubusercontent.com"
              conditions:
                - all:
                    - key: "{{ predicate.buildDefinition.buildType }}"
                      operator: Equals
                      value: "https://slsa.dev/container-based/v1"
```

The policy enforces:
- The artifact must be signed by a Sigstore certificate whose subject matches the CI workflow at `refs/heads/main`.
- An SLSA provenance attestation must be present, signed by the SLSA generator workflow.
- Both checks must pass for the Pod to be admitted.

### Step 5: Registry-Side Enforcement (Optional)

Some registries enforce signing at the registry layer rather than relying on admission control alone. Harbor's `vulnerability` and `signing` projects, GHCR's content trust, and ECR's image scanning all support extending policies to WASM artifacts:

```yaml
# Harbor project policy.
project_settings:
  immutability:
    enabled: true
    rules:
      - selector: "wasm/*"
        action: immutable
  signing:
    required: true
    cosign_keyless_subject: "https://github.com/myorg/*-wasm/.github/workflows/build.yml@refs/heads/main"
```

A push that lacks the matching signature is rejected at push time, preventing an unsigned artifact from reaching the registry. Combined with admission control, the layers reinforce each other.

### Step 6: Verification at Pull Time on Edge / Self-Hosted

For non-Kubernetes deployments (Spin standalone, wasmCloud, custom WASM runtimes), wrap pulls with cosign verification:

```bash
#!/bin/sh
# pull-and-verify-wasm.sh
# Pull a WASM module from registry; verify before running.
set -eu

REF="$1"
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

# Verify signature.
cosign verify "$REF" \
  --certificate-identity-regexp 'https://github.com/myorg/.+-wasm/.github/workflows/build.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  > "$WORKDIR/verification.json"

# Verify provenance.
cosign verify-attestation "$REF" \
  --type slsaprovenance \
  --certificate-identity-regexp 'https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  > "$WORKDIR/provenance.json"

# Pull the artifact.
oras pull "$REF" --output "$WORKDIR"

# Run the module.
exec wasmtime "$WORKDIR/payments.wasm"
```

A wrapper like this is the minimum for an environment without admission control. Run as part of the deploy step rather than at runtime to keep the verification cost off the request path.

## Expected Behaviour

| Signal | Without signing | With signing |
|--------|-----------------|--------------|
| Pull tampered WASM artifact | Succeeds | Fails verification at admission or pull |
| Build provenance available | None | SLSA in-toto statement attached |
| Registry-side push validation | Image pushed unconditionally | Push rejected if signature missing (when registry enforces) |
| Admission-time control | None | Kyverno or cosigned blocks unsigned Pods |
| Audit trail of signing events | None | Rekor transparency log entry per artifact + signature |
| Keyless certificate chain | N/A | Per-artifact short-lived cert tied to a specific workflow run |
| Cost per build | None | ~30s for cosign + provenance generation |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Keyless Sigstore signing | No long-lived signing keys; short-lived certs per build | Requires Internet access to Fulcio + Rekor; depends on Sigstore availability | For air-gapped, run a private Fulcio + Rekor or fall back to KMS-based key signing. |
| KMS-based signing | Air-gap-friendly; keys never leave KMS | Key lifecycle management; rotation infrastructure | Annual rotation, alarm on KMS API errors. |
| SLSA provenance | Full build-graph attestation | Build-time cost ~30-60s for provenance generation | Acceptable; build infrastructure already in place. |
| Admission-time verification | Defense in depth; catches misconfigured registry | Webhook adds 50-200ms to admission for Pods with WASM runtime | Use VAP for simple checks; keep Kyverno for the verifyImages path which still needs a webhook. |
| Subject pinning | Limits which CI workflow can produce admissible artifacts | New repos must be added to the policy explicitly | Use a regex pattern (`https://github.com/myorg/.+-wasm/...`) to match a naming convention. |
| Provenance enforcement | Detects rebuilds from unauthorized branches | Requires SLSA generator integration in every WASM build pipeline | Provide a reusable workflow that all WASM repos consume. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Build pipeline misses cosign sign step | Admission webhook rejects the Pod | `kubectl describe pod` shows policy violation | Add cosign sign to the build pipeline; reuse the org's existing reusable workflow that already does this for containers. |
| Subject identity drift | Newly-renamed repo's signatures no longer match the policy regex | Policy violations after a rename | Update the policy regex, or build with `id-token: write` against a stable workflow file path. |
| Sigstore Rekor outage | New signatures cannot be added to the transparency log | `cosign sign` fails with Rekor connectivity errors | cosign supports `--bundle` mode that writes the verification material locally; allow as fallback during outages. |
| Verifier configured with wrong issuer | All signatures appear invalid | Admission rejects all Pods | Check the OIDC issuer; for GitHub it is `https://token.actions.githubusercontent.com`. The certificate-identity must be the workflow path. |
| Registry strips signatures on tag retag | Existing signatures no longer attached to the new tag | `cosign verify` returns "no signatures found" | Re-sign after retag; or use immutable tags by digest. |
| Stale artifact deployed | A previously-signed-but-vulnerable module re-deployed | Policy admits because signature is valid | Maintain a vulnerability allowlist + version floor; reject digests known to be vulnerable. |
| OIDC token theft | Adversary mints signatures under your CI identity | Rekor log shows signing events outside expected workflow runs | Rekor log is append-only; auditing detects unauthorized signing. Revoke the affected role/identity; rotate signing-cert chains. |

## Related Articles

- [SLSA Build Provenance: Source-to-Registry Integrity](/articles/cicd/slsa-provenance/)
- [Container Registry Security](/articles/cicd/container-registry-security/)
- [WASM Workloads on Kubernetes](/articles/wasm/wasm-on-kubernetes/)
- [ValidatingAdmissionPolicy with CEL](/articles/kubernetes/validating-admission-policy-cel/)
- [OIDC Federation Hardening](/articles/cicd/oidc-federation-hardening/)
