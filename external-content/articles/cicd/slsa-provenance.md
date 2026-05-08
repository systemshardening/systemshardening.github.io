---
title: "SLSA Provenance for Container Images: From Build to Admission Control"
description: "Without provenance, you cannot prove where a container image came from, what source code it was built from, or whether the build process was tampered..."
slug: "slsa-provenance"
date: 2026-01-11
lastmod: 2026-01-11
category: "cicd"
tags: ["slsa", "provenance", "cosign", "supply-chain", "sigstore", "admission-control"]
personas: ["devops-engineer", "security-engineer"]
article_number: 50
difficulty: "advanced"
estimated_reading_time: 16
provider_bridges:
  - name: "Snyk"
    id: 48
    category: "container-security"
  - name: "Anchore"
    id: 98
    category: "supply-chain"
premium_pack: "slsa-pipeline-templates"
published: true
layout: article.njk
permalink: "/articles/cicd/slsa-provenance/index.html"
---

# SLSA Provenance for Container Images: From Build to Admission Control

## Problem

Without provenance, you cannot prove where a container image came from, what source code it was built from, or whether the build process was tampered with. An attacker who compromises your CI pipeline can inject malicious code into images that pass all vulnerability scans, because the vulnerability is not in a known package but in your own modified source.

SLSA (Supply-chain Levels for Software Artifacts) provides a framework for provenance. This article implements it end-to-end: generate provenance attestations in CI, store them alongside images, and verify at [Kubernetes](https://kubernetes.io) admission time.

## Threat Model

- **Adversary:** Attacker who has compromised the CI pipeline (stolen credentials, modified workflow, or backdoored build environment) and is injecting malicious code into container images.
- **Blast radius:** Every environment that deploys the compromised image. Without provenance verification at admission: the malicious image runs in production.

## Configuration

### Generating Provenance in GitHub Actions

```yaml
# .github/workflows/build-with-provenance.yml
name: Build with SLSA Provenance
on:
  push:
    branches: [main]

permissions:
  contents: read
  packages: write
  id-token: write  # Required for keyless signing

jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      image-digest: ${{ steps.build.outputs.digest }}
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Build and push image
        id: build
        uses: docker/build-push-action@v6
        with:
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.sha }}
          # Digest is the immutable content-addressable identifier
          # (not the tag, which can be overwritten)

      - name: Install cosign
        uses: sigstore/cosign-installer@v3

      - name: Sign the image (keyless. Sigstore)
        run: |
          cosign sign --yes \
            ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}
        env:
          COSIGN_EXPERIMENTAL: "true"

      - name: Generate SLSA provenance attestation
        uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.0.0
        with:
          image: ghcr.io/${{ github.repository }}
          digest: ${{ steps.build.outputs.digest }}
```

### Verifying Provenance Locally

```bash
# Verify the signature
cosign verify \
  --certificate-identity-regexp="https://github.com/your-org/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ghcr.io/your-org/your-app@sha256:abc123...

# Verify provenance attestation
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-identity-regexp="https://github.com/your-org/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ghcr.io/your-org/your-app@sha256:abc123...

# View the provenance (JSON)
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-identity-regexp="https://github.com/your-org/.*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ghcr.io/your-org/your-app@sha256:abc123... | jq '.payload' | base64 -d | jq .
```

### Admission Control with [Kyverno](https://kyverno.io)

```yaml
# kyverno-verify-provenance.yaml
# Block images without valid SLSA provenance from running in production.
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-slsa-provenance
spec:
  validationFailureAction: Enforce
  webhookTimeoutSeconds: 30
  rules:
    - name: verify-provenance
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [production, staging]
      verifyImages:
        - imageReferences:
            - "ghcr.io/your-org/*"
          attestors:
            - count: 1
              entries:
                - keyless:
                    issuer: "https://token.actions.githubusercontent.com"
                    subject: "https://github.com/your-org/*"
                    rekor:
                      url: "https://rekor.sigstore.dev"
          attestations:
            - type: https://slsa.dev/provenance/v1
              conditions:
                - all:
                    - key: "{{ builder.id }}"
                      operator: Equals
                      value: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0"
```

### Break-Glass Procedure

When signing infrastructure is unavailable (Sigstore outage, Rekor down):

```yaml
# Emergency namespace with relaxed provenance requirements.
# Time-limited: label expires after 4 hours.
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-slsa-provenance
spec:
  rules:
    - name: verify-provenance
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [production, staging]
      exclude:
        any:
          - resources:
              namespaces: [emergency-deploy]
              # Namespace with label: break-glass=active
```

```bash
# Activate break-glass:
kubectl create namespace emergency-deploy
kubectl label namespace emergency-deploy break-glass=active

# Deploy the image to emergency-deploy namespace
kubectl apply -f deployment.yaml -n emergency-deploy

# MANDATORY: post-hoc verification within 24 hours
# Once signing infrastructure is restored, re-verify the image
# and move the deployment to the production namespace with full provenance.

# Deactivate break-glass:
kubectl delete namespace emergency-deploy
```

## Expected Behaviour

- Every container image pushed to the registry has a cosign signature and SLSA provenance attestation
- `cosign verify` succeeds for all production images
- Kyverno blocks images without valid provenance in production and staging namespaces
- Break-glass namespace available for emergency deployments (time-limited, post-hoc verified)
- Provenance includes: source repository, commit SHA, builder identity, build parameters

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Keyless signing (Sigstore) | No key management; certificates from OIDC | Depends on Sigstore/Rekor availability | Break-glass procedure for Sigstore outages. Or: use keyed signing with cosign as backup. |
| Admission verification | Adds 100-500ms to pod admission (signature verification) | Kyverno webhook unavailability blocks all pod creation | `failurePolicy: Ignore` for availability. Or: break-glass namespace. |
| SLSA Level 3 (hardened builder) | Strongest provenance guarantees | Requires GitHub Actions hosted runners (not self-hosted) | Use SLSA Level 2 if self-hosted runners are required. |
| Break-glass namespace | Allows emergency deploys without provenance | Potential for abuse (deploying unsigned images permanently) | Time-limited namespace. Audit log monitoring for break-glass usage. Post-hoc verification mandatory. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Sigstore/Rekor outage | cosign sign fails in CI; images built but not signed | CI workflow fails at signing step; Sigstore status page | Use break-glass procedure. Retry signing when Sigstore recovers. |
| Kyverno verification timeout | Pod admission times out (>30 seconds); pods stuck in Pending | `kubectl describe pod` shows webhook timeout | Increase `webhookTimeoutSeconds`. Check Kyverno pod health. Check network connectivity to Rekor. |
| Provenance mismatch | Image was built by unexpected builder; Kyverno rejects | Admission error shows builder ID mismatch | Verify the CI workflow is using the correct SLSA generator version. Update Kyverno policy if builder version was intentionally updated. |

## When to Consider a Managed Alternative

Provenance infrastructure requires key/certificate management and Rekor integration.

- **[Snyk](https://snyk.io):** Integrated supply chain security with image scanning + provenance verification.
- **[Anchore](https://anchore.com):** Enterprise SBOM + provenance management with policy engine.
- **[Scribe Security](https://scribesecurity.com):** Managed SLSA attestation and provenance platform.

**Premium content pack:** SLSA pipeline templates. GitHub Actions workflows with provenance generation, cosign signing, Kyverno admission policies, and break-glass procedures.


## Related Articles

- [Artifact Integrity Verification: Checksums, Signatures, and Transparency Logs](/articles/cicd/artifact-integrity/)
- [Software Bill of Materials (SBOM) Generation and Consumption in CI/CD](/articles/cicd/sbom/)
- [Dependency Pinning and Lockfile Integrity: Preventing Supply Chain Attacks in CI](/articles/cicd/dependency-pinning/)
- [Secret Management in CI/CD Pipelines: Vault, SOPS, and OIDC Federation](/articles/cicd/cicd-secret-management/)
- [Reproducible Builds for Container Images: Achieving Deterministic Output](/articles/cicd/reproducible-builds/)
