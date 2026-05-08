---
title: "Container Image Provenance Attestations: SLSA and SBOM Attestation End-to-End"
description: "Attestations are signed metadata attached to a container image as a co-located OCI artifact. This article covers attaching and verifying SLSA build provenance and SBOM attestations using cosign, in-toto, and Kyverno."
slug: container-image-attestations
date: 2026-05-07
lastmod: 2026-05-07
category: cicd
tags:
  - attestations
  - slsa
  - cosign
  - sbom
  - provenance
personas:
  - security-engineer
  - platform-engineer
article_number: 540
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/cicd/container-image-attestations/
---

# Container Image Provenance Attestations: SLSA and SBOM Attestation End-to-End

## Problem

A container image signature answers one question: was this image signed by someone whose key I trust? It does not answer: what source code produced this image, which builder ran the build, what packages are inside it, or whether a vulnerability scan passed. Those answers require attestations.

Attestations are signed metadata documents co-located with an image in an OCI registry. Each attestation is an in-toto envelope wrapping a typed predicate — a SLSA provenance document, a CycloneDX SBOM, a vulnerability scan report, or any custom predicate you define. The envelope is signed using cosign (keyless or keyed), the signature is recorded in the Rekor transparency log, and the attestation is stored in the registry as an OCI referrer artifact pointing to the original image digest.

Without attestations, the specific gaps are:

- A signed image tells you nothing about the build. An attacker who compromises CI can rebuild from modified source, sign the result with the CI identity, and produce a signature that verifies cleanly.
- SBOMs detached from the image are unverifiable. Anyone can generate a clean SBOM against an unrelated image and attach it to a different one.
- Vulnerability scan attestations require the scan to have occurred against the image digest that will actually be deployed, not a local layer cache.
- Policy enforcement at admission time can only check what is present and verifiable in the registry. Without attestations, policies cannot verify build provenance.

**Target systems:** Cosign 2.4+, slsa-github-generator v2.0+, Syft 1.9+, Kyverno 1.12+, sigstore policy-controller 0.9+, GitHub Actions with OIDC, Rekor public or private instance.

## Threat Model

- **Adversary 1 — Build-time injection:** Attacker compromises the CI runner during the build step and modifies the compiled binary or adds a backdoor layer. Without SLSA provenance attestation, the image is indistinguishable from a legitimate build. With a provenance attestation produced by a non-forgeable SLSA Build L3 builder, the attestation captures source commit, build parameters, and builder identity — and any deviation during a future policy check is detectable.
- **Adversary 2 — SBOM laundering:** Attacker generates a clean SBOM from a known-good image and attaches it to a different, vulnerable image in the registry. Without attestation signatures, a consumer of the SBOM cannot tell whether it was produced from the image they are about to deploy. With a cosign-signed SBOM attestation referencing the image digest, a forged SBOM's signature would not verify against the legitimate cosign identity.
- **Adversary 3 — Deployment of images that bypassed scanning:** A developer manually pushes an image that was never scanned. Without a required vulnerability scan attestation at admission time, the image can be deployed to production. With a Kyverno policy requiring a scan attestation signed by the CI workflow identity, the image is blocked at the admission webhook.
- **Adversary 4 — Retroactive tampering denial:** An insider modifies a deployed image and disputes that a record of tampering exists. The Rekor transparency log is append-only and Merkle-tree-backed; every attestation upload creates a timestamped, unforgeable entry. The audit trail is permanent.
- **Access level:** Adversaries 1 and 3 have CI or registry write access. Adversary 2 has registry write access. Adversary 4 is an insider.
- **Blast radius:** Without attestations and admission enforcement, any image can reach production regardless of how it was built or whether it was scanned. With enforcement, only images with a complete, verified attestation chain can be admitted.

## Concepts

### What an attestation is

An attestation is an in-toto Envelope stored as an OCI artifact in the registry under the original image's digest. The structure is:

```
in-toto Envelope
  payloadType: "application/vnd.in-toto+json"
  payload: base64(Statement)
    _type: "https://in-toto.io/Statement/v1"
    subject: [{name: "ghcr.io/org/repo", digest: {sha256: "abc123..."}}]
    predicateType: "https://slsa.dev/provenance/v1"  # or SBOM, vuln scan, custom
    predicate: { ... typed content ... }
  signatures: [{keyid: "", sig: "base64-signature"}]
```

Cosign wraps this envelope in a cosign-specific layer and pushes it to the registry. The OCI referrers API (or the cosign legacy `sha256-<digest>.att` tag) links it to the original image.

### Attestation predicate types

| Predicate type | URI | Contents |
|---|---|---|
| SLSA Provenance v1 | `https://slsa.dev/provenance/v1` | Builder ID, source repo, commit SHA, build parameters, invocation ID |
| SPDX SBOM | `https://spdx.dev/Document` | Package list, licenses, dependency tree |
| CycloneDX SBOM | `https://cyclonedx.org/bom` | Package list with PURL identifiers, vulnerability reference |
| Trivy scan result | `https://trivy.dev/scan/v1` | CVE findings, severity breakdown, package matches |
| Custom predicate | Any URI you define | Test results, compliance check output, deployment approval |

## Configuration

### Step 1: Generating SLSA provenance with slsa-github-generator

The SLSA GitHub Generator produces SLSA Build L3 provenance — provenance that comes from a non-forgeable, isolated build system rather than from within the same workflow that ran your build steps. It runs as a reusable workflow in a separate GitHub Actions job with its own OIDC identity.

```yaml
# .github/workflows/build-and-attest.yml
name: Build, Attest, and Push

on:
  push:
    branches: [main]

permissions:
  contents: read
  packages: write
  id-token: write   # Required for OIDC-backed keyless signing.

jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      image: ${{ steps.build.outputs.imagename }}
      digest: ${{ steps.build.outputs.digest }}
    steps:
      - uses: actions/checkout@v4

      - name: Install Cosign
        uses: sigstore/cosign-installer@v3

      - name: Log in to GHCR
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push image
        id: build
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.sha }}
          outputs: type=image,name=ghcr.io/${{ github.repository }},push-by-digest=false

      - name: Export image reference
        id: image-ref
        run: |
          echo "imagename=ghcr.io/${{ github.repository }}" >> "$GITHUB_OUTPUT"

  # SLSA Build L3 provenance via the non-forgeable generator workflow.
  provenance:
    needs: build
    permissions:
      actions: read       # Required to read workflow run info.
      id-token: write     # Required for keyless signing.
      packages: write     # Required to push the attestation to GHCR.
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.0.0
    with:
      image: ${{ needs.build.outputs.image }}
      digest: ${{ needs.build.outputs.digest }}
      registry-username: ${{ github.actor }}
    secrets:
      registry-password: ${{ secrets.GITHUB_TOKEN }}
```

The SLSA generator pushes a signed SLSA provenance attestation to the registry under the same image digest. The predicate contains:

- `buildDefinition.buildType` — the build system URI
- `buildDefinition.externalParameters.source` — source repo and commit SHA
- `runDetails.builder.id` — the identity of the generator workflow itself
- `runDetails.metadata.invocationId` — the GitHub Actions run ID

### Step 2: Attaching a Syft SBOM as an attestation

Attach a CycloneDX SBOM generated by Syft as a signed in-toto attestation. The key distinction from `cosign attach sbom` is that `cosign attest` signs the SBOM and records the signature in Rekor, making the SBOM tamper-evident and verifiable.

```yaml
      - name: Generate SBOM with Syft
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
            | sh -s -- -b /usr/local/bin
          syft ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }} \
            -o cyclonedx-json \
            --file sbom.cdx.json

      - name: Attest SBOM (CycloneDX)
        env:
          DIGEST: ${{ steps.build.outputs.digest }}
        run: |
          cosign attest --yes \
            --predicate sbom.cdx.json \
            --type cyclonedx \
            ghcr.io/${{ github.repository }}@${DIGEST}

      # Also generate SPDX SBOM for tools that prefer it.
      - name: Generate SPDX SBOM
        run: |
          syft ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }} \
            -o spdx-json \
            --file sbom.spdx.json

      - name: Attest SBOM (SPDX)
        env:
          DIGEST: ${{ steps.build.outputs.digest }}
        run: |
          cosign attest --yes \
            --predicate sbom.spdx.json \
            --type spdxjson \
            ghcr.io/${{ github.repository }}@${DIGEST}
```

### Step 3: Attaching a vulnerability scan result as an attestation

Attest the Trivy scan report so the cluster can verify that a clean scan occurred against the exact image digest being deployed:

```yaml
      - name: Run Trivy vulnerability scan
        env:
          DIGEST: ${{ steps.build.outputs.digest }}
        run: |
          docker run --rm \
            -v /var/run/docker.sock:/var/run/docker.sock \
            aquasec/trivy:latest image \
            --format cyclonedx \
            --output trivy-report.cdx.json \
            --exit-code 1 \
            --severity HIGH,CRITICAL \
            "ghcr.io/${{ github.repository }}@${DIGEST}"

      - name: Attest vulnerability scan result
        env:
          DIGEST: ${{ steps.build.outputs.digest }}
        run: |
          # Use a custom predicate type URI that your policy will match against.
          cosign attest --yes \
            --predicate trivy-report.cdx.json \
            --type "https://trivy.dev/scan/v1" \
            ghcr.io/${{ github.repository }}@${DIGEST}
```

Setting `--exit-code 1` in Trivy means the scan step fails the workflow on critical or high CVEs, so no scan attestation can be produced for a non-clean image. An image can only carry a scan attestation if it passed.

### Step 4: Verifying attestations with cosign verify-attestation

`cosign verify-attestation` checks both the cryptographic signature on the in-toto envelope and the presence of the expected predicate type. The `--certificate-identity` and `--certificate-oidc-issuer` flags bind verification to the specific workflow identity that produced the attestation — not just any valid Sigstore signature.

```bash
IMAGE="ghcr.io/myorg/myapp@sha256:abc123..."
WORKFLOW="https://github.com/myorg/myapp/.github/workflows/build-and-attest.yml@refs/heads/main"
ISSUER="https://token.actions.githubusercontent.com"

# Verify the SLSA provenance attestation.
cosign verify-attestation \
  --certificate-identity "${WORKFLOW}" \
  --certificate-oidc-issuer "${ISSUER}" \
  --type slsaprovenance \
  "${IMAGE}"

# Decode and inspect the provenance predicate.
cosign verify-attestation \
  --certificate-identity "${WORKFLOW}" \
  --certificate-oidc-issuer "${ISSUER}" \
  --type slsaprovenance \
  "${IMAGE}" \
  | jq -r '.payload' | base64 -d | jq '.predicate'

# Verify the CycloneDX SBOM attestation.
cosign verify-attestation \
  --certificate-identity "${WORKFLOW}" \
  --certificate-oidc-issuer "${ISSUER}" \
  --type cyclonedx \
  "${IMAGE}"

# Verify a custom predicate type (vulnerability scan).
cosign verify-attestation \
  --certificate-identity "${WORKFLOW}" \
  --certificate-oidc-issuer "${ISSUER}" \
  --type "https://trivy.dev/scan/v1" \
  "${IMAGE}"
```

To verify the SLSA generator workflow's attestation (which uses its own identity, separate from the build workflow):

```bash
SLSA_GENERATOR="https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0"

cosign verify-attestation \
  --certificate-identity "${SLSA_GENERATOR}" \
  --certificate-oidc-issuer "${ISSUER}" \
  --type slsaprovenance \
  "${IMAGE}"
```

### Step 5: Rekor transparency log — audit and offline verification

Every `cosign attest` and `cosign sign` invocation uploads a log entry to Rekor. The log is backed by a Merkle tree; entries cannot be deleted or modified without breaking the tree's consistency proof. The entry contains a hash of the signed payload and the signing certificate.

```bash
# Search for all log entries related to an image digest.
rekor-cli search \
  --sha sha256:abc123... \
  --rekor_server https://rekor.sigstore.dev

# Fetch and inspect a specific log entry.
rekor-cli get \
  --uuid <uuid-from-search> \
  --format json | jq .

# Offline verification — check that the Rekor entry exists and the Merkle
# proof is valid, without contacting Rekor at verification time.
cosign verify-attestation \
  --offline \
  --certificate-identity "${WORKFLOW}" \
  --certificate-oidc-issuer "${ISSUER}" \
  --type slsaprovenance \
  "${IMAGE}"
```

The Rekor entry serves as a notarized timestamp: you can prove that an attestation existed at a specific time, which is useful for compliance demonstrations and incident forensics.

### Step 6: Kyverno ClusterPolicy — enforce attestation presence at admission

Install Kyverno, then configure a policy that requires both a valid SLSA provenance attestation and a valid SBOM attestation before any pod is admitted to the production namespace. The policy also enforces content conditions on the provenance predicate to ensure the image was built from a specific source repository.

```bash
helm install kyverno kyverno/kyverno \
  --namespace kyverno \
  --create-namespace \
  --set replicaCount=3 \
  --set admissionController.replicas=3
```

```yaml
# kyverno/policies/require-attestations.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-image-attestations
  annotations:
    policies.kyverno.io/title: Require SLSA Provenance and SBOM Attestations
    policies.kyverno.io/description: >-
      Blocks any pod from running in production unless the container image
      has a valid SLSA provenance attestation and a CycloneDX SBOM attestation,
      both signed by the approved CI workflow identity.
spec:
  validationFailureAction: Enforce
  background: false
  webhookTimeoutSeconds: 30
  rules:
    - name: verify-slsa-provenance
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [production, staging]
      verifyImages:
        - imageReferences:
            - "ghcr.io/myorg/*"
          # Mutate the tag to a digest reference to prevent tag mutation attacks.
          mutateDigest: true
          verifyDigest: true
          required: true
          attestors:
            - count: 1
              entries:
                - keyless:
                    subject: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: "https://rekor.sigstore.dev"
          attestations:
            - predicateType: "https://slsa.dev/provenance/v1"
              attestors:
                - count: 1
                  entries:
                    - keyless:
                        subject: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0"
                        issuer: "https://token.actions.githubusercontent.com"
              conditions:
                - all:
                    # Require the image was built from the expected GitHub org.
                    - key: "{{ buildDefinition.externalParameters.source.uri }}"
                      operator: Equals
                      value: "git+https://github.com/myorg/myapp@refs/heads/main"

    - name: verify-sbom-attestation
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [production, staging]
      verifyImages:
        - imageReferences:
            - "ghcr.io/myorg/*"
          attestations:
            - predicateType: "https://cyclonedx.org/bom"
              attestors:
                - count: 1
                  entries:
                    - keyless:
                        subject: "https://github.com/myorg/myapp/.github/workflows/build-and-attest.yml@refs/heads/main"
                        issuer: "https://token.actions.githubusercontent.com"
```

Test the policy:

```bash
# An image with valid attestations — should be admitted.
kubectl run test-attested \
  --image=ghcr.io/myorg/myapp@sha256:<attested-digest> \
  --dry-run=server -n production

# An image without attestations — should be rejected.
kubectl run test-unattested \
  --image=ghcr.io/myorg/myapp:latest \
  --dry-run=server -n production
# Expected: admission webhook "mutate.kyverno.svc-fail" denied the request:
#   policy Pod/production/test-unattested failed: verify-slsa-provenance:
#   image ghcr.io/myorg/myapp:latest failed attestation check.
```

### Step 7: Sigstore policy-controller as an alternative to Kyverno

The Sigstore policy-controller is an admission webhook purpose-built for cosign verification. It uses a `ClusterImagePolicy` CRD that maps image references to required authorities and attestations.

```bash
helm install policy-controller sigstore/policy-controller \
  --namespace cosign-system \
  --create-namespace
```

```yaml
# sigstore/cluster-image-policy.yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: myorg-attestation-policy
spec:
  images:
    - glob: "ghcr.io/myorg/**"
  authorities:
    - name: slsa-provenance
      keyless:
        url: "https://fulcio.sigstore.dev"
        identities:
          - issuer: "https://token.actions.githubusercontent.com"
            subject: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0"
      attestations:
        - name: must-have-slsa-provenance
          predicateType: "https://slsa.dev/provenance/v1"
          policy:
            type: rego
            data: |
              package sigstore
              default isCompliant = false
              isCompliant {
                # Require build from main branch of the expected repo.
                input.predicateType == "https://slsa.dev/provenance/v1"
                startswith(
                  input.predicate.buildDefinition.externalParameters.source.uri,
                  "git+https://github.com/myorg/"
                )
              }

    - name: sbom-attestation
      keyless:
        url: "https://fulcio.sigstore.dev"
        identities:
          - issuer: "https://token.actions.githubusercontent.com"
            subject: "https://github.com/myorg/myapp/.github/workflows/build-and-attest.yml@refs/heads/main"
      attestations:
        - name: must-have-sbom
          predicateType: "https://cyclonedx.org/bom"
```

The policy-controller's Rego policy engine allows content-level conditions on the predicate, enabling rules like "no critical CVEs in the attached scan attestation" at admission time.

Enforce in specific namespaces by labeling them:

```bash
kubectl label namespace production policy.sigstore.dev/include=true
```

### Step 8: Telemetry and alerting

```
cicd_attestation_created_total{type, repo, result}              counter
cicd_attestation_verification_failure_total{type, image}        counter
kyverno_policy_results_total{policy, rule, result}              counter
rekor_entry_count                                               gauge
admission_webhook_duration_seconds{webhook="kyverno"}          histogram
```

Alert on:

- `cicd_attestation_verification_failure_total` non-zero in production — a pod admission attempted to run an image whose attestation failed verification.
- `kyverno_policy_results_total{result="fail"}` for `require-image-attestations` — an admission was blocked; investigate whether it is a legitimate enforcement or a policy gap.
- CI builds that succeed without producing an attestation (query CI job logs for attestation upload failures) — image can be built but cannot be deployed, breaking delivery.
- Unexpected Rekor entries for your image digests — an unknown identity signed an attestation for one of your images.

## Expected Behaviour

| Signal | Without attestations | With attestations + policy |
|---|---|---|
| Compromised CI build pushed to registry | Deployed to production without detection | SLSA provenance records build parameters; deviation from expected builder identity detectable at admission |
| SBOM generated from wrong image | Undetectable if manually attached | SBOM attestation signature tied to specific digest; forged SBOM fails signature verification |
| Image that skipped vulnerability scan | Admissible to production | Blocked at admission: no valid scan attestation from the approved CI identity |
| Attestation audit trail | None | Every attestation in Rekor; timestamped, append-only, Merkle-tree-backed |
| Policy enforcement granularity | Image signature only (was it signed?) | Provenance content conditions (was it built from the expected source, by the expected builder?) |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Multiple attestation types required | Defense-in-depth: SLSA + SBOM + scan attestation together cover different attack vectors | Each attestation adds CI time (~30s each) and registry storage | Run SBOM generation and scan in parallel steps; use OCI referrers API for efficient storage |
| SLSA Build L3 via slsa-github-generator | Provenance from a non-forgeable, isolated builder job | Only available on GitHub Actions hosted runners; self-hosted runner builds are limited to L2 | Use SLSA Level 2 for self-hosted runners; reserve L3 requirement for images with highest risk |
| Content conditions in Kyverno policy | Block images built from unexpected branches or forks | Policy must be updated when workflow paths change | Pin subject to the exact workflow path; treat policy changes as code with PR review |
| Kyverno `mutateDigest: true` | Prevents tag-swapping attacks by rewriting tags to digests at admission | Modifies the pod spec; may confuse debugging tools that expect tag references | Expected and safe; the digest reference is unambiguous and more secure |
| Sigstore public Rekor log | Attestations are publicly auditable | Image names and CI workflow paths appear in the public log | Use a private Rekor instance for sensitive project names; public log is appropriate for most cases |
| Policy-controller Rego | Full policy-as-code on predicate content | More complex to write and test than Kyverno CEL conditions | Test Rego policies with OPA conftest before deploying; version alongside attestation code |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| `cosign attest` fails (Fulcio unavailable) | Attestation not recorded; CI step fails | CI error: `failed to get signing certificate` | Retry up to 3 times with exponential backoff; use a private Fulcio for air-gapped environments |
| SLSA generator workflow version drift | Provenance attestation builder ID no longer matches Kyverno policy | Admission rejected with builder ID mismatch | Update the Kyverno `subject` field to the new generator tag; test in audit mode first |
| Kyverno webhook unavailable during rollout | Pod scheduling stalls or all images admitted without verification (depends on `failurePolicy`) | Pods stuck in Pending; Kyverno health alerts | Run Kyverno in HA (3+ replicas); set `failurePolicy: Fail` to block rather than silently admit |
| Missing `id-token: write` permission | Keyless signing fails; `cosign attest` cannot obtain OIDC token | CI error: `failed to get ID token` | Add `permissions: id-token: write` to the workflow job |
| Trivy scan exit code 1 blocks attestation | CI fails on vulnerable image; no scan attestation produced | CI step fails at Trivy scan | Fix the CVE or add it to `.trivyignore` with documented justification; rebuild |
| Attestation references wrong digest | Attestation attached to a tag that was overwritten | `cosign verify-attestation` fails for deployed image | Always use `@sha256:...` digest in `cosign attest`, never a mutable tag |
| Policy-controller `ClusterImagePolicy` not enforcing | Images admitted without attestation check | No `policy.sigstore.dev/include=true` label on namespace | Add the label; verify with `kubectl describe ns production` |

## Related Articles

- [Sigstore Keyless Signing and Cosign Verification](/articles/cicd/sigstore-keyless-signing/)
- [SLSA Provenance for Container Images: From Build to Admission Control](/articles/cicd/slsa-provenance/)
- [Software Bill of Materials (SBOM) Generation and Consumption in CI/CD](/articles/cicd/sbom/)
- [Artifact Integrity Verification: Checksums, Signatures, and Transparency Logs](/articles/cicd/artifact-integrity/)
- [Container Registry Security](/articles/cicd/container-registry-security/)
- [Reproducible Builds for Container Images: Achieving Deterministic Output](/articles/cicd/reproducible-builds/)
