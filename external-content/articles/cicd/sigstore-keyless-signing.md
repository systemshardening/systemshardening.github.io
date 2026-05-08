---
title: "Sigstore Keyless Signing and Cosign Verification: Fulcio, Rekor, and Policy Enforcement"
description: "Keyless signing eliminates long-lived signing keys by issuing short-lived certificates from Fulcio and recording signatures in the Rekor transparency log. Cosign wires it into CI/CD."
slug: "sigstore-keyless-signing"
date: 2026-04-29
lastmod: 2026-04-29
category: "cicd"
tags: ["sigstore", "cosign", "supply-chain", "signing", "transparency"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 234
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/cicd/sigstore-keyless-signing/index.html"
---

# Sigstore Keyless Signing and Cosign Verification: Fulcio, Rekor, and Policy Enforcement

## Problem

Traditional artifact signing requires managing long-lived signing keys: generating them, protecting them, rotating them, distributing the public key to verifiers. In practice, keys get stored in CI secrets, shared across teams, and rarely rotated. A leaked signing key compromises every artifact signed with it — past and future.

Sigstore's keyless signing eliminates long-lived signing keys entirely. The signer (a CI workflow, a developer with a workload identity) authenticates via OIDC, receives a short-lived certificate from Fulcio (valid for 10 minutes), signs the artifact, and the signature is recorded in Rekor — an append-only transparency log. The short-lived certificate expires; there is no key to steal afterward. The Rekor entry creates a permanent, auditable record that the artifact was signed.

The specific gaps in unmanaged artifact pipelines:

- Container images pushed without signatures; no way to verify they came from an approved build.
- Signing keys stored in CI secrets as long-lived PEM files; rotation is rare.
- No policy enforcement at deployment time — the runtime admits any image regardless of signature status.
- No transparency log; artifact signing history is invisible.
- Verification logic is per-team and inconsistent; some services verify, others don't.

By 2026, SLSA level 2+ compliance and the US CISA executive guidance on software supply chain security both treat signed artifacts with verifiable provenance as a baseline requirement.

**Target systems:** Cosign 2.4+, Sigstore Fulcio 1.6+, Rekor 1.3+, GitHub Actions (OIDC token support), GitLab CI 16+ (OIDC support), Kyverno 1.12+ or Connaisseur for admission-time verification.

## Threat Model

- **Adversary 1 — Compromised CI runner:** An attacker gains code execution on a CI runner during a build. Without signing, they can substitute a malicious image in the registry and it will be deployed as if legitimate. With keyless signing, the malicious image cannot be signed with the legitimate workflow's identity — it would require a fresh OIDC token from the GitHub Actions token service.
- **Adversary 2 — Registry MITM:** An attacker intercepts the image pull and substitutes a different image digest. Without signature verification at the runtime, the substitution succeeds. With admission-time cosign verification, the runtime rejects any image whose digest doesn't match a valid signature.
- **Adversary 3 — Build system impersonation:** An attacker runs a build in a different workflow or fork that produces an artifact with an attacker-controlled identity. Policy enforcement can require that signatures come from a specific issuer (GitHub Actions, organization, workflow path) — the attacker's identity doesn't match.
- **Adversary 4 — Retroactive key compromise:** A traditional signing key is leaked. The attacker signs backdated artifacts. With a transparency log, there is a public record of every valid signing event; forged signatures on unlogged artifacts can be detected.
- **Access level:** Adversaries 1 and 2 have CI-runner or registry-network access. Adversary 3 has repository fork access. Adversary 4 has access to the signing key material.
- **Objective:** Deploy a malicious artifact that appears legitimate; bypass supply chain integrity controls.
- **Blast radius:** Without signing: any artifact can be substituted silently. With keyless signing + policy: only artifacts signed during a specific, authenticated CI workflow can be deployed.

## Configuration

### Step 1: Install Cosign

```bash
# Linux x86_64.
curl -sLO https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
sudo mv cosign-linux-amd64 /usr/local/bin/cosign
sudo chmod +x /usr/local/bin/cosign
cosign version
```

Or via Go:

```bash
go install github.com/sigstore/cosign/v2/cmd/cosign@latest
```

### Step 2: Keyless Signing in GitHub Actions

Keyless signing uses the GitHub Actions OIDC token (automatically available in every workflow) as the identity:

```yaml
# .github/workflows/build-and-sign.yml
name: Build, Push, and Sign

on:
  push:
    branches: [main]

permissions:
  contents: read
  packages: write
  id-token: write   # Required for OIDC token request.

jobs:
  build-sign:
    runs-on: ubuntu-latest
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

      - name: Sign image (keyless)
        env:
          DIGEST: ${{ steps.build.outputs.digest }}
        run: |
          # Keyless: no key flag; cosign uses the GitHub OIDC token automatically.
          cosign sign --yes \
            ghcr.io/${{ github.repository }}@${DIGEST}
```

What happens internally:

1. Cosign requests an OIDC token from GitHub Actions (`id-token` permission).
2. Cosign sends the token to Fulcio; Fulcio issues a short-lived X.509 certificate with the workflow identity embedded in the SAN extension: `https://token.actions.githubusercontent.com/myorg/myrepo/.github/workflows/build-and-sign.yml@refs/heads/main`.
3. Cosign signs the image digest with the ephemeral private key.
4. Cosign uploads the signature and transparency log entry to Rekor.
5. The ephemeral private key is discarded. The certificate expires in 10 minutes.

### Step 3: Sign Additional Artifacts (SBOMs, Attestations)

Sign the SBOM and SLSA provenance attestation alongside the image:

```yaml
      - name: Generate SBOM
        run: |
          syft packages ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }} \
            -o spdx-json > sbom.spdx.json

      - name: Attest SBOM
        run: |
          cosign attest --yes \
            --predicate sbom.spdx.json \
            --type spdxjson \
            ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}

      - name: Generate and attest SLSA provenance
        uses: actions/attest-build-provenance@v1
        with:
          subject-name: ghcr.io/${{ github.repository }}
          subject-digest: ${{ steps.build.outputs.digest }}
          push-to-registry: true
```

Attestations are stored as OCI artifacts in the registry alongside the image, referencing the same digest.

### Step 4: Manual Verification with Cosign

Verify a signature from the command line:

```bash
# Verify the image signature; confirm it came from the expected workflow.
cosign verify \
  --certificate-identity-regexp "^https://github.com/myorg/myrepo/.github/workflows/build-and-sign.yml@refs/heads/main$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/myorg/myrepo@sha256:abc123...

# Expected output: Verification for ghcr.io/myorg/myrepo@sha256:abc123... --
# The following checks were performed on each of these signatures:
#   - The cosign claims were validated
#   - Existence of the claims in the transparency log was verified offline
#   - The code-signing certificate was verified using trusted certificate authority certificates
```

Verify the SBOM attestation:

```bash
cosign verify-attestation \
  --certificate-identity-regexp "^https://github.com/myorg/myrepo/.*@refs/heads/main$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --type spdxjson \
  ghcr.io/myorg/myrepo@sha256:abc123... \
  | jq .payload | base64 -d | jq .
```

### Step 5: Enforce at Admission Time with Kyverno

Install Kyverno and configure a ClusterPolicy that blocks unverified images:

```bash
helm install kyverno kyverno/kyverno -n kyverno --create-namespace
```

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signatures
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: check-image-signature
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [production, staging]
      verifyImages:
        - imageReferences:
            - "ghcr.io/myorg/myrepo:*"
            - "ghcr.io/myorg/myrepo@*"
          attestors:
            - count: 1
              entries:
                - keyless:
                    subject: "https://github.com/myorg/myrepo/.github/workflows/build-and-sign.yml@refs/heads/main"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: "https://rekor.sigstore.dev"
          # Also require the SBOM attestation.
          attestations:
            - predicateType: "https://spdx.dev/Document"
              attestors:
                - count: 1
                  entries:
                    - keyless:
                        subject: "https://github.com/myorg/myrepo/.github/workflows/build-and-sign.yml@refs/heads/main"
                        issuer: "https://token.actions.githubusercontent.com"
```

Test the policy:

```bash
# Pull a signed image into a test pod — should succeed.
kubectl run test-signed \
  --image=ghcr.io/myorg/myrepo@sha256:<signed-digest> \
  --dry-run=server

# Try an unsigned image — should be rejected.
kubectl run test-unsigned \
  --image=ghcr.io/myorg/myrepo:latest \
  --dry-run=server
# Expected: Error: admission webhook "mutate.kyverno.svc-fail" denied the request:
#   policy Pod/default/test-unsigned failed: check-image-signature: Image ghcr.io/myorg/myrepo:latest
#   failed signature verification.
```

### Step 6: Private Sigstore Infrastructure (Optional)

For air-gapped or compliance-sensitive environments, run a private Sigstore stack:

```bash
# Deploy using the Sigstore Helm charts.
helm repo add sigstore https://sigstore.github.io/helm-charts

# Rekor (transparency log).
helm install rekor sigstore/rekor -n sigstore --create-namespace \
  --set server.extraArgs='{--enable-retrieve-api=true}'

# Fulcio (certificate authority).
helm install fulcio sigstore/fulcio -n sigstore \
  --set server.args.certificateAuthority=fileca \
  --set config.OIDCIssuers[0].IssuerURL=https://your-idp.internal \
  --set config.OIDCIssuers[0].ClientID=sigstore
```

Configure Cosign to use the private stack:

```bash
export SIGSTORE_REKOR_API_URL=https://rekor.internal
export SIGSTORE_CT_LOG_PUBLIC_KEY_FILE=/etc/sigstore/ctlog-pub.pem
export FULCIO_URL=https://fulcio.internal
export COSIGN_MIRROR=https://tuf.internal

cosign sign --yes ghcr.io/myorg/myrepo@sha256:abc123...
```

### Step 7: Audit the Transparency Log

The Rekor log is publicly searchable. Audit which artifacts have been signed:

```bash
# Look up an artifact by image digest.
rekor-cli search --sha sha256:abc123... --rekor_server https://rekor.sigstore.dev

# Get the full log entry.
rekor-cli get --uuid <uuid> --format json | jq .

# Verify an entry against the Rekor checkpoint (offline verification).
cosign verify --offline \
  --certificate-identity-regexp ".*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/myorg/myrepo@sha256:abc123...
```

The Rekor log is append-only and backed by a Merkle tree; entries cannot be removed without detection.

### Step 8: Telemetry

```
cicd_image_signed_total{repo, workflow, result}         counter
cicd_signature_verification_failure_total{image}        counter
cicd_unsigned_image_deployed_total{namespace, image}    counter
kyverno_policy_results_total{policy, rule, result}      counter
rekor_entry_count                                        gauge
```

Alert on:

- `cicd_signature_verification_failure_total` non-zero in production — a pod attempted to run with an invalid or missing signature.
- `cicd_unsigned_image_deployed_total` non-zero — an unsigned image somehow made it past admission (indicates a Kyverno misconfiguration or bypass).
- Kyverno policy result `fail` for `verify-image-signatures` — block event in audit trail.

## Expected Behaviour

| Signal | Without signing | With keyless signing + policy |
|--------|----------------|-------------------------------|
| Unsigned image deployed to production | Succeeds silently | Rejected by Kyverno admission webhook |
| Image signed by wrong workflow | Indistinguishable from correct | Verification fails; identity mismatch detected |
| Signing key leak impact | All past + future artifacts compromised | No signing key exists; ephemeral cert expired |
| Transparency log | None | Every signing event in Rekor; auditable indefinitely |
| SBOM attestation | Optional, unverified | Attested and admission-enforced |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Keyless (no key management) | No key to steal or rotate | Requires OIDC provider; depends on Fulcio availability | Use private Sigstore in air-gapped envs; Fulcio downtime only affects signing, not verification. |
| Rekor public log | Public auditability; non-repudiation | Internal build metadata visible publicly | Use private Rekor; or ensure internal identities/paths are acceptable for public visibility. |
| Admission-time enforcement | Every image deployment verified | Kyverno webhook adds latency to pod scheduling | Typically <100ms; Kyverno HA required to avoid blocking scheduling. |
| Identity-regexp matching | Flexible; no exact path required | Too-broad regexp allows unintended workflows | Use exact match for subject; restrict to specific branch refs. |
| SBOM attestation required | Supply chain completeness enforced | SBOM generation adds ~30s to CI | Run SBOM generation in parallel with image push. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Fulcio unavailable during CI | `cosign sign` fails; build fails | CI job error: `failed to get signing certificate from Fulcio` | Retry; if using public Fulcio, it has 99.9% SLA. Private: restore Fulcio. |
| Kyverno webhook unavailable | Pod scheduling fails or passes unsigned (depends on `failurePolicy`) | Pod events show webhook timeout | Set Kyverno webhook `failurePolicy: Fail` to block; Kyverno HA prevents outage. |
| OIDC token missing from CI | Keyless signing fails; `id-token: write` not in permissions | Error: `failed to get ID token` in CI logs | Add `permissions: id-token: write` to the job. |
| Image tag mutated (no digest pinning) | Different image pulled at runtime than at signing time | Image runs but digest doesn't match signature | Always sign by digest; Kyverno rewrites tags to digests automatically (using `mutateDigest: true`). |
| Wrong branch signed image deployed | Production gets an artifact from a feature branch | Subject regexp matches feature branch identity | Restrict subject to `@refs/heads/main` only; reject `@refs/heads/*` wildcards. |
| Rekor entry missing | Offline verification fails | Cosign `--offline` flag reports no entry | Re-sign; Rekor upload failed during original signing (network issue). |

## Related Articles

- [SLSA Provenance and Build Integrity](/articles/cicd/slsa-provenance/)
- [Artifact Integrity and Verification](/articles/cicd/artifact-integrity/)
- [SBOM Generation and Verification](/articles/cicd/sbom/)
- [Container Registry Security](/articles/cicd/container-registry-security/)
- [Reproducible Builds](/articles/cicd/reproducible-builds/)
