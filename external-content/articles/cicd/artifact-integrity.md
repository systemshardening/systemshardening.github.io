---
title: "Artifact Integrity Verification: Checksums, Signatures, and Transparency Logs"
description: "Build artifacts pass through multiple stages between source code and production deployment."
slug: "artifact-integrity"
date: 2026-02-19
lastmod: 2026-02-19
category: "cicd"
tags: ["artifact-integrity", "cosign", "in-toto", "slsa", "sigstore", "supply-chain"]
personas: ["devops-engineer", "security-engineer"]
article_number: 61
difficulty: "advanced"
estimated_reading_time: 16
provider_bridges:
  - name: "Snyk"
    id: 48
    category: "container-security"
premium_pack: "in-toto-layout-templates"
published: true
layout: article.njk
permalink: "/articles/cicd/artifact-integrity/index.html"
---

# Artifact Integrity Verification: Checksums, Signatures, and Transparency Logs

## Problem

Build artifacts pass through multiple stages between source code and production deployment. Source is compiled in CI, packaged into a container image, pushed to a registry, pulled by a deployment tool, and launched in a cluster. At each boundary, an attacker can substitute a modified artifact. A compromised CI runner can alter the binary after compilation. A man-in-the-middle on the registry network path can serve a different image. A compromised deployment controller can deploy an image that was never built by CI.

Checksums alone are insufficient. A SHA-256 digest proves an artifact has not changed since the digest was computed, but it does not prove who built the artifact or from what source. Signatures tie an artifact to an identity, but without a transparency log, a compromised signing key can sign malicious artifacts without detection. End-to-end integrity requires all three: checksums for tamper detection, signatures for provenance, and transparency logs for accountability.

## Threat Model

- **Adversary:** Compromised CI runner that modifies build output, attacker who gains write access to the container registry, or insider who replaces an artifact between pipeline stages.
- **Objective:** Deploy a tampered artifact to production. The tampered artifact may contain backdoors, credential-harvesting code, or cryptocurrency miners.
- **Blast radius:** Every environment that deploys the tampered artifact. Without verification at deployment time, the compromise persists until someone notices anomalous behavior.

## Configuration

### Signing Container Images with Cosign

Sign images immediately after building, using keyless signing backed by [Sigstore](https://www.sigstore.dev)'s Fulcio and Rekor:

```yaml
# .github/workflows/build-sign-verify.yml
name: Build, Sign, and Attest
on:
  push:
    branches: [main]

permissions:
  contents: read
  id-token: write   # OIDC for keyless signing
  packages: write   # Push to GHCR

jobs:
  build-and-sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Install cosign
        uses: sigstore/cosign-installer@v3

      - name: Login to GHCR
        run: |
          echo "${{ secrets.GITHUB_TOKEN }}" | \
            docker login ghcr.io -u ${{ github.actor }} --password-stdin

      - name: Build and push image
        id: build
        run: |
          IMAGE="ghcr.io/${{ github.repository }}:${{ github.sha }}"
          docker buildx build --push --tag "$IMAGE" .
          DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE")
          echo "image=$DIGEST" >> "$GITHUB_OUTPUT"

      - name: Sign image (keyless)
        run: |
          # Keyless signing: uses GitHub OIDC token to get a short-lived
          # certificate from Fulcio. The signature is recorded in Rekor
          # (transparency log) automatically.
          cosign sign --yes ${{ steps.build.outputs.image }}

      - name: Generate and attach SLSA provenance
        run: |
          # Create SLSA provenance attestation
          cosign attest --yes \
            --predicate <(cat <<PROVENANCE
          {
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
              "buildDefinition": {
                "buildType": "https://github.com/actions/runner",
                "externalParameters": {
                  "repository": "${{ github.repository }}",
                  "ref": "${{ github.ref }}",
                  "commit": "${{ github.sha }}"
                }
              },
              "runDetails": {
                "builder": {
                  "id": "https://github.com/actions/runner"
                },
                "metadata": {
                  "invocationId": "${{ github.run_id }}",
                  "startedOn": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
                }
              }
            }
          }
          PROVENANCE
          ) \
            --type slsaprovenance \
            ${{ steps.build.outputs.image }}
```

### Verifying Signatures at Deployment Time

Use [Kyverno](https://kyverno.io) to enforce signature verification before any pod is admitted to the cluster:

```yaml
# kyverno/policies/verify-image-signatures.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signatures
spec:
  validationFailureAction: Enforce
  webhookTimeoutSeconds: 30
  rules:
    - name: verify-cosign-signature
      match:
        any:
          - resources:
              kinds:
                - Pod
      verifyImages:
        - imageReferences:
            - "ghcr.io/your-org/*"
          attestors:
            - entries:
                - keyless:
                    issuer: "https://token.actions.githubusercontent.com"
                    subject: "https://github.com/your-org/*"
                    rekor:
                      url: "https://rekor.sigstore.dev"
          attestations:
            - type: slsaprovenance
              conditions:
                - all:
                    - key: "{{ buildDefinition.externalParameters.repository }}"
                      operator: Equals
                      value: "your-org/*"
```

### In-Toto Attestation for Multi-Stage Pipelines

For pipelines with multiple stages (build, scan, test, deploy), use in-toto to create a verifiable chain of custody:

```yaml
# in-toto layout defining the expected pipeline stages
# layout.json - signed by the project owner
{
  "_type": "layout",
  "expires": "2027-01-01T00:00:00Z",
  "steps": [
    {
      "name": "build",
      "expected_command": ["docker", "buildx", "build"],
      "expected_materials": [
        ["MATCH", "Dockerfile", "WITH", "PRODUCTS", "FROM", "checkout"]
      ],
      "expected_products": [
        ["CREATE", "image.tar"]
      ],
      "pubkeys": ["build-runner-key-id"],
      "threshold": 1
    },
    {
      "name": "scan",
      "expected_command": ["trivy", "image"],
      "expected_materials": [
        ["MATCH", "image.tar", "WITH", "PRODUCTS", "FROM", "build"]
      ],
      "expected_products": [
        ["CREATE", "scan-report.json"]
      ],
      "pubkeys": ["scan-runner-key-id"],
      "threshold": 1
    },
    {
      "name": "sign",
      "expected_command": ["cosign", "sign"],
      "expected_materials": [
        ["MATCH", "image.tar", "WITH", "PRODUCTS", "FROM", "build"],
        ["MATCH", "scan-report.json", "WITH", "PRODUCTS", "FROM", "scan"]
      ],
      "pubkeys": ["signing-key-id"],
      "threshold": 1
    }
  ],
  "inspect": [
    {
      "name": "verify-no-critical-cves",
      "expected_materials": [
        ["MATCH", "scan-report.json", "WITH", "PRODUCTS", "FROM", "scan"]
      ],
      "run": ["python", "verify_scan.py"]
    }
  ]
}
```

Generate in-toto link metadata at each pipeline stage:

```bash
#!/bin/bash
# Stage 1: Build - generate in-toto link
in-toto-run \
  --step-name build \
  --key build-runner-key \
  --materials Dockerfile requirements.txt \
  --products image.tar \
  -- docker buildx build --output type=tar,dest=image.tar .

# Stage 2: Scan - generate in-toto link
in-toto-run \
  --step-name scan \
  --key scan-runner-key \
  --materials image.tar \
  --products scan-report.json \
  -- trivy image --input image.tar --format json --output scan-report.json

# Stage 3: Sign - generate in-toto link
in-toto-run \
  --step-name sign \
  --key signing-key \
  --materials image.tar scan-report.json \
  -- cosign sign --key cosign.key "ghcr.io/your-org/app@sha256:abc123..."

# Verification: verify the entire supply chain
in-toto-verify \
  --layout layout.json \
  --layout-key project-owner-key.pub
```

### Transparency Logs with Rekor

Rekor provides a tamper-evident log of signing events. Even if a signing key is compromised, the transparency log creates an auditable record:

```bash
# Search Rekor for all signing events for your image
rekor-cli search --sha "sha256:abc123def456..."

# Verify a specific entry in the transparency log
rekor-cli verify --artifact image.tar --signature image.tar.sig --pki-format x509

# Monitor for unexpected signing events
# This script should run on a schedule to detect unauthorized signatures
#!/bin/bash
EXPECTED_ISSUER="https://token.actions.githubusercontent.com"
EXPECTED_SUBJECT="https://github.com/your-org/"

# Search for recent entries for your image
rekor-cli search --sha "$IMAGE_DIGEST" --format json | jq -r '.[]' | while read -r entry; do
  ISSUER=$(rekor-cli get --uuid "$entry" --format json | jq -r '.Body.HashedRekordObj.signature.publicKey.content' | base64 -d | openssl x509 -noout -ext subjectAltName 2>/dev/null)

  if [[ "$ISSUER" != *"$EXPECTED_SUBJECT"* ]]; then
    echo "ALERT: Unexpected signer for image $IMAGE_DIGEST"
    echo "Entry: $entry"
    echo "Issuer: $ISSUER"
    # Send alert to security team
  fi
done
```

### Checksum Verification Between Pipeline Stages

When artifacts move between pipeline stages (even within the same CI system), verify checksums at each boundary:

```yaml
# .github/workflows/multi-stage-pipeline.yml
jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      digest: ${{ steps.checksum.outputs.digest }}
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: Build
        run: docker buildx build --output type=tar,dest=image.tar .
      - name: Compute checksum
        id: checksum
        run: |
          DIGEST=$(sha256sum image.tar | awk '{print $1}')
          echo "digest=$DIGEST" >> "$GITHUB_OUTPUT"
      - uses: actions/upload-artifact@v4
        with:
          name: image-tar
          path: image.tar

  scan:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: image-tar
      - name: Verify checksum from build stage
        run: |
          ACTUAL=$(sha256sum image.tar | awk '{print $1}')
          EXPECTED="${{ needs.build.outputs.digest }}"
          if [ "$ACTUAL" != "$EXPECTED" ]; then
            echo "INTEGRITY FAILURE: Artifact modified between stages"
            echo "Expected: $EXPECTED"
            echo "Actual:   $ACTUAL"
            exit 1
          fi
          echo "Checksum verified: $ACTUAL"
      - name: Scan
        run: trivy image --input image.tar --severity HIGH,CRITICAL --exit-code 1
```

## Expected Behaviour

- Every container image pushed to the registry is signed with a keyless cosign signature (OIDC-backed)
- SLSA provenance attestations are attached to every production image
- Kyverno verifies image signatures and attestations before admitting pods
- In-toto link metadata is generated at each pipeline stage, creating a verifiable chain of custody
- Checksums are verified at every stage boundary to detect inter-stage tampering
- All signing events are recorded in the Rekor transparency log
- A monitoring job checks Rekor for unexpected signing events weekly

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Keyless signing with Fulcio | Eliminates key management; signatures tied to OIDC identity | Depends on Sigstore infrastructure availability | Sigstore provides 99.5% SLA. For air-gapped environments, deploy private Sigstore stack. |
| Kyverno image verification | Adds 1-3 seconds to pod admission | Verification failure blocks all deployments | Configure Kyverno with audit mode first. Switch to enforce after validating all images are signed. |
| In-toto attestation | Adds 5-10 seconds per pipeline stage; additional complexity | Incorrect layout definition blocks valid deployments | Test layouts in staging before production. Version layout files alongside pipeline definitions. |
| Rekor transparency log | Creates permanent, public record of signing events | Image names and signing identities are visible in the public log | Use a private Rekor instance for sensitive project names. |
| Inter-stage checksum verification | Adds verification steps to pipeline; slightly increases CI time | Checksum failures from legitimate causes (compression differences) cause false positives | Use consistent artifact formats (tar, OCI) without compression to ensure deterministic checksums. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Sigstore outage | Keyless signing fails; images cannot be signed | cosign sign returns connection error; Sigstore status page shows incident | Fall back to key-based signing with a locally stored cosign key. Sign with keyless once Sigstore recovers. |
| Kyverno webhook down | All pod creation blocked (fail-closed) or all pods admitted without verification (fail-open) | Pods fail to schedule with webhook timeout; Kyverno health check alerts | Restart Kyverno pods. If persistent, temporarily switch to audit mode. Run Kyverno in HA (3+ replicas). |
| In-toto layout mismatch | Pipeline verification fails at final stage | in-toto-verify returns non-zero with layout violation details | Review which step deviated from the layout. Update the layout if the pipeline changed legitimately. |
| Artifact tampering detected | Checksum mismatch between pipeline stages | Stage fails with integrity failure message | Investigate the runner that produced the mismatched artifact. Rebuild from source on a clean runner. |
| Unauthorized signature in Rekor | Image signed by unexpected identity | Rekor monitoring script alerts on unknown issuer/subject | Investigate the signing event. If malicious, revoke the signing identity and rebuild the image. |

## When to Consider a Managed Alternative

Running a complete artifact integrity pipeline (signing, attestation, verification, monitoring) requires expertise in cryptographic tooling and ongoing maintenance of verification infrastructure. [Snyk](https://snyk.io) provides integrated supply chain verification with less operational overhead. For teams that need SLSA compliance but lack the engineering capacity to build the infrastructure, GitHub Artifact Attestations provides built-in SLSA Build L3 provenance for GitHub Actions. [Aqua](https://www.aquasec.com) offers admission-time verification with managed policy infrastructure. For air-gapped environments that cannot use public Sigstore, deploying a private Sigstore stack (Fulcio + Rekor + TUF) requires dedicated infrastructure and key ceremony procedures.

**Premium content pack:** In-toto layout templates for common pipeline architectures (build-scan-deploy, build-test-scan-stage-deploy). Includes cosign signing workflows for GitHub Actions and GitLab CI, Kyverno verification policies, and Rekor monitoring scripts.


## Related Articles

- [SLSA Provenance for Container Images: From Build to Admission Control](/articles/cicd/slsa-provenance/)
- [Dependency Pinning and Lockfile Integrity: Preventing Supply Chain Attacks in CI](/articles/cicd/dependency-pinning/)
- [Secret Management in CI/CD Pipelines: Vault, SOPS, and OIDC Federation](/articles/cicd/cicd-secret-management/)
- [Reproducible Builds for Container Images: Achieving Deterministic Output](/articles/cicd/reproducible-builds/)
- [Securing GitHub Actions: Permissions, Pinning, and Workflow Injection Prevention](/articles/cicd/securing-github-actions/)
