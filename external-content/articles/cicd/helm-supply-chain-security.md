---
title: "Helm Supply Chain Security: OCI Registries, Provenance Verification, and Chart Mirroring"
description: "Helm charts pulled from public repositories are unsigned, unverified, and executed with whatever permissions their templates request. This article covers OCI-based chart storage, cosign signing and verification, chart mirroring for airgapped environments, and Kyverno policies to enforce signed charts."
slug: "helm-supply-chain-security"
date: 2026-02-25
lastmod: 2026-02-25
category: "cicd"
tags: ["helm", "supply-chain", "cosign", "oci", "kyverno", "chart-signing"]
personas: ["devops-engineer", "platform-engineer"]
article_number: 149
difficulty: "intermediate"
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/cicd/helm-supply-chain-security/index.html"
---

# Helm Supply Chain Security: OCI Registries, Provenance Verification, and Chart Mirroring

## Problem

Helm charts are executable Kubernetes manifests packaged as tarballs. Most teams install them without verifying who built the chart, whether it was modified after publishing, or what resources it will create:

- **Charts are pulled from public repositories without signature verification.** `helm install` downloads and renders a chart in one step. There is no built-in check that the chart was published by the expected author or that the tarball was not tampered with in transit.
- **Legacy chart repositories have no signing mechanism.** The traditional `index.yaml`-based Helm repository format has a provenance file feature, but it uses PGP and almost no one uses it. The provenance file is optional, and Helm does not enforce verification by default.
- **No dependency lockfile integrity checks.** Charts declare dependencies in `Chart.yaml`, but the resolved versions in `Chart.lock` are not verified against any signature. A compromised dependency repository can serve a different chart for the same version string.
- **Public chart availability is a single point of failure.** If the upstream chart repository goes down, your deployments fail. If the repository is compromised, your next deployment pulls a malicious chart.
- **No admission control for unsigned charts.** Even if you sign your own charts, nothing prevents a developer from deploying an unsigned chart from a public repository directly to the cluster.

These gaps make Helm charts one of the least verified components in most Kubernetes supply chains. Container images now have cosign, SLSA provenance, and admission policies. Helm charts often have none of these.

**Target systems:** Teams using Helm to deploy to [Kubernetes](https://kubernetes.io) clusters, with charts stored in OCI registries or legacy chart repositories. Applicable to both internal charts and third-party charts from public sources.

## Threat Model

- **Adversary:** Compromised chart repository maintainer who publishes a backdoored chart version. Supply chain attacker who intercepts chart downloads. Insider who pushes an unsigned chart directly to the cluster.
- **Access level:** Write access to a public chart repository (for repository compromise). Network position to intercept HTTP chart downloads (for interception). kubectl access to a namespace (for direct deployment).
- **Objective:** Deploy malicious containers through a compromised chart. Inject init containers that exfiltrate secrets before the main application starts. Add ClusterRoleBindings that grant the attacker persistent cluster access. Replace a legitimate chart dependency with a malicious one.
- **Blast radius:** A compromised chart runs with whatever RBAC permissions the deploying user or service account has. Charts deployed with cluster-admin can create any resource in any namespace. A poisoned dependency affects every chart that depends on it.

## Configuration

### OCI-Based Chart Storage

OCI registries are the preferred storage backend for Helm charts. They provide authentication, content-addressable storage, and compatibility with container image signing tools like cosign:

```bash
#!/bin/bash
# oci-chart-publish.sh - Package and push chart to OCI registry

CHART_DIR="./charts/payments-api"
REGISTRY="registry.internal.company.com/charts"

# Authenticate to OCI registry
helm registry login "$REGISTRY" \
  --username "$HELM_USER" \
  --password "$HELM_TOKEN"

# Package the chart
helm package "$CHART_DIR" --destination ./dist/

CHART_VERSION=$(helm show chart "$CHART_DIR" | grep '^version:' | awk '{print $2}')
CHART_PACKAGE="./dist/payments-api-${CHART_VERSION}.tgz"

# Push to OCI registry
helm push "$CHART_PACKAGE" "oci://${REGISTRY}"

echo "Published: oci://${REGISTRY}/payments-api:${CHART_VERSION}"
```

### Chart Signing with Cosign

Sign charts after pushing to the OCI registry. This uses the same signing workflow as container images:

```bash
#!/bin/bash
# sign-chart.sh - Sign a Helm chart in an OCI registry with cosign

REGISTRY="registry.internal.company.com/charts"
CHART="payments-api"
VERSION="$1"

if [ -z "$VERSION" ]; then
  echo "Usage: sign-chart.sh <version>"
  exit 1
fi

CHART_REF="${REGISTRY}/${CHART}:${VERSION}"

# Option 1: Key-based signing (for CI pipelines with stored keys)
cosign sign --yes \
  --key env://COSIGN_PRIVATE_KEY \
  "$CHART_REF"

# Option 2: Keyless signing with Fulcio (for CI with OIDC identity)
# cosign sign --yes "$CHART_REF"
# This uses the CI system's OIDC token (GitHub Actions, GitLab CI)
# to get a short-lived certificate from Fulcio

echo "Chart signed: ${CHART_REF}"

# Attach SBOM if available
if [ -f "./dist/${CHART}-${VERSION}-sbom.json" ]; then
  cosign attach sbom \
    --sbom "./dist/${CHART}-${VERSION}-sbom.json" \
    "$CHART_REF"
  echo "SBOM attached to: ${CHART_REF}"
fi
```

### Provenance Verification Before Installation

Verify chart signatures in your deployment pipeline before `helm install`:

```bash
#!/bin/bash
# verify-and-install.sh - Verify chart provenance before deploying

REGISTRY="registry.internal.company.com/charts"
CHART="payments-api"
VERSION="$1"
NAMESPACE="production"
RELEASE_NAME="payments-api"
PUBLIC_KEY="/etc/cosign/chart-signing-key.pub"

CHART_REF="${REGISTRY}/${CHART}:${VERSION}"

echo "Verifying chart signature: ${CHART_REF}"

# Verify the cosign signature
cosign verify \
  --key "$PUBLIC_KEY" \
  "$CHART_REF"

VERIFY_EXIT=$?
if [ $VERIFY_EXIT -ne 0 ]; then
  echo "ERROR: Chart signature verification failed for ${CHART_REF}"
  echo "The chart may have been tampered with or was not signed."
  exit 1
fi

echo "Signature verified. Installing chart."

# Pull and install the verified chart
helm install "$RELEASE_NAME" "oci://${CHART_REF}" \
  --namespace "$NAMESPACE" \
  --values "./values/production.yaml" \
  --wait \
  --timeout 300s
```

```yaml
# .github/workflows/deploy-chart.yml - CI pipeline with verification
name: Deploy Helm Chart
on:
  workflow_dispatch:
    inputs:
      chart_version:
        description: "Chart version to deploy"
        required: true

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Install cosign
        uses: sigstore/cosign-installer@v3

      - name: Verify chart signature
        env:
          COSIGN_PUBLIC_KEY: ${{ secrets.CHART_SIGNING_PUBLIC_KEY }}
        run: |
          echo "$COSIGN_PUBLIC_KEY" > /tmp/chart-key.pub
          cosign verify \
            --key /tmp/chart-key.pub \
            "registry.internal.company.com/charts/payments-api:${{ inputs.chart_version }}"

      - name: Deploy to production
        run: |
          helm upgrade --install payments-api \
            "oci://registry.internal.company.com/charts/payments-api" \
            --version "${{ inputs.chart_version }}" \
            --namespace production \
            --values ./values/production.yaml \
            --wait --timeout 300s
```

### Mirroring Public Charts for Airgapped Environments

Mirror third-party charts into your internal registry so you control availability and can scan them before use:

```bash
#!/bin/bash
# mirror-charts.sh - Mirror public charts to internal OCI registry

INTERNAL_REGISTRY="registry.internal.company.com/charts/vendor"
MIRROR_LOG="/var/log/chart-mirror.log"

# Define charts to mirror with pinned versions
declare -A CHARTS=(
  ["ingress-nginx|oci://ghcr.io/kubernetes/ingress-nginx/charts/ingress-nginx"]="4.10.1"
  ["cert-manager|oci://quay.io/jetstack/charts/cert-manager"]="1.14.5"
  ["external-secrets|oci://ghcr.io/external-secrets/charts/external-secrets"]="0.9.16"
  ["kyverno|oci://ghcr.io/kyverno/charts/kyverno"]="3.2.0"
)

for chart_spec in "${!CHARTS[@]}"; do
  IFS='|' read -r CHART_NAME SOURCE_REF <<< "$chart_spec"
  VERSION="${CHARTS[$chart_spec]}"

  echo "[$(date)] Mirroring ${CHART_NAME}:${VERSION}" | tee -a "$MIRROR_LOG"

  # Pull from public registry
  helm pull "${SOURCE_REF}" \
    --version "$VERSION" \
    --destination /tmp/charts/

  CHART_FILE="/tmp/charts/${CHART_NAME}-${VERSION}.tgz"

  if [ ! -f "$CHART_FILE" ]; then
    echo "ERROR: Failed to pull ${CHART_NAME}:${VERSION}" | tee -a "$MIRROR_LOG"
    continue
  fi

  # Scan the chart before mirroring
  helm template "${CHART_NAME}" "$CHART_FILE" > /tmp/rendered.yaml 2>/dev/null
  trivy config /tmp/rendered.yaml --severity HIGH,CRITICAL --exit-code 1
  if [ $? -ne 0 ]; then
    echo "WARNING: ${CHART_NAME}:${VERSION} has HIGH/CRITICAL findings" | tee -a "$MIRROR_LOG"
    # Continue with mirroring but flag for review
  fi

  # Push to internal OCI registry
  helm push "$CHART_FILE" "oci://${INTERNAL_REGISTRY}"

  # Sign the mirrored chart
  cosign sign --yes \
    --key env://COSIGN_PRIVATE_KEY \
    "${INTERNAL_REGISTRY}/${CHART_NAME}:${VERSION}"

  echo "[$(date)] Mirrored and signed: ${CHART_NAME}:${VERSION}" | tee -a "$MIRROR_LOG"
  rm -f "$CHART_FILE" /tmp/rendered.yaml
done
```

### Chart Dependency Lockfile Verification

Verify that chart dependencies match the locked versions and have not been substituted:

```bash
#!/bin/bash
# verify-dependencies.sh - Verify chart dependency integrity

CHART_DIR="$1"

if [ ! -f "${CHART_DIR}/Chart.lock" ]; then
  echo "ERROR: Chart.lock not found. Run 'helm dependency update' first."
  exit 1
fi

# Rebuild dependencies from lockfile
helm dependency build "$CHART_DIR"

# Verify each dependency tarball checksum against Chart.lock
echo "Verifying dependency checksums..."
while IFS= read -r line; do
  # Parse digest entries from Chart.lock
  if echo "$line" | grep -q "digest:"; then
    EXPECTED_DIGEST=$(echo "$line" | awk '{print $2}')
  fi
  if echo "$line" | grep -q "name:"; then
    DEP_NAME=$(echo "$line" | awk '{print $2}')
  fi
  if echo "$line" | grep -q "version:"; then
    DEP_VERSION=$(echo "$line" | awk '{print $2}')
    DEP_FILE="${CHART_DIR}/charts/${DEP_NAME}-${DEP_VERSION}.tgz"

    if [ -f "$DEP_FILE" ] && [ -n "$EXPECTED_DIGEST" ]; then
      ACTUAL_DIGEST="sha256:$(sha256sum "$DEP_FILE" | awk '{print $1}')"
      if [ "$ACTUAL_DIGEST" != "$EXPECTED_DIGEST" ]; then
        echo "FAIL: ${DEP_NAME}-${DEP_VERSION} digest mismatch"
        echo "  Expected: ${EXPECTED_DIGEST}"
        echo "  Actual:   ${ACTUAL_DIGEST}"
        exit 1
      else
        echo "OK: ${DEP_NAME}-${DEP_VERSION} digest matches"
      fi
    fi
    EXPECTED_DIGEST=""
  fi
done < "${CHART_DIR}/Chart.lock"

echo "All dependency checksums verified."
```

### Kyverno Policy to Enforce Signed Charts

Block deployment of Helm releases that were not installed from signed charts. This policy validates that the OCI artifact referenced by a Helm release has a valid cosign signature:

```yaml
# kyverno-enforce-signed-charts.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: enforce-signed-helm-charts
  annotations:
    policies.kyverno.io/title: Enforce Signed Helm Charts
    policies.kyverno.io/description: >-
      Requires all container images deployed via Helm to come from
      the internal registry and have valid cosign signatures.
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    # Rule 1: Images must come from the internal registry
    - name: require-internal-registry
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: >-
          All images must come from registry.internal.company.com.
          Public images must be mirrored to the internal registry first.
        pattern:
          spec:
            containers:
              - image: "registry.internal.company.com/*"
            initContainers:
              - image: "registry.internal.company.com/*"

    # Rule 2: All images must be signed with cosign
    - name: verify-image-signatures
      match:
        any:
          - resources:
              kinds:
                - Pod
      verifyImages:
        - imageReferences:
            - "registry.internal.company.com/*"
          attestors:
            - entries:
                - keys:
                    publicKeys: |
                      -----BEGIN PUBLIC KEY-----
                      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
                      -----END PUBLIC KEY-----
          required: true

    # Rule 3: Block Helm releases with charts from untrusted sources
    - name: restrict-helm-chart-sources
      match:
        any:
          - resources:
              kinds:
                - Secret
              names:
                - "sh.helm.release.v1.*"
      preconditions:
        all:
          - key: "{{ request.object.type }}"
            operator: Equals
            value: "helm.sh/release.v1"
      validate:
        message: >-
          Helm releases must use charts from the internal OCI registry.
          Mirror public charts using the chart mirroring pipeline.
        deny:
          conditions:
            any:
              - key: "{{ request.object.metadata.annotations.\"meta.helm.sh/release-name\" || '' }}"
                operator: Equals
                value: ""
---
# Enforce that namespaces have a label indicating chart verification is required
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-chart-verification-label
spec:
  validationFailureAction: Audit  # Start in audit mode
  rules:
    - name: check-namespace-label
      match:
        any:
          - resources:
              kinds:
                - Namespace
      exclude:
        any:
          - resources:
              names:
                - kube-system
                - kube-public
                - kube-node-lease
      validate:
        message: "Namespace must have chart-verification=required label"
        pattern:
          metadata:
            labels:
              chart-verification: "required"
```

## Expected Behaviour

After implementing the supply chain controls:

```bash
# Verify chart signing works end-to-end
helm package ./charts/payments-api --destination ./dist/
helm push ./dist/payments-api-1.5.0.tgz oci://registry.internal.company.com/charts
cosign sign --key cosign.key registry.internal.company.com/charts/payments-api:1.5.0
cosign verify --key cosign.pub registry.internal.company.com/charts/payments-api:1.5.0
# Expected: "Verification for registry.internal.company.com/charts/payments-api:1.5.0 --
# The following checks were performed:
# - The cosign claims were validated
# - The signatures were verified against the specified public key"

# Verify unsigned chart is blocked by Kyverno
helm install test-unsigned oci://public-registry.io/charts/some-chart \
  --namespace production
# Expected: Blocked by Kyverno policy - images not from internal registry

# Verify mirrored chart has signature
cosign verify --key cosign.pub \
  registry.internal.company.com/charts/vendor/ingress-nginx:4.10.1
# Expected: Signature verification succeeds

# Verify dependency lockfile integrity
./verify-dependencies.sh ./charts/payments-api
# Expected: "All dependency checksums verified."

# Verify tampered dependency is caught
# (modify a byte in a dependency tarball)
echo "tamper" >> ./charts/payments-api/charts/common-1.0.0.tgz
./verify-dependencies.sh ./charts/payments-api
# Expected: "FAIL: common-1.0.0 digest mismatch"
```

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| OCI-based chart storage | Requires OCI-compatible registry; legacy Helm repo clients break | Migration effort from legacy chart museum repositories | Run both OCI and legacy repos during migration; set deprecation deadline |
| Cosign chart signing | Adds signing step to every chart release; key management overhead | Signing key compromise allows signing malicious charts | Store keys in Vault or KMS; use keyless signing with Fulcio for CI workloads |
| Chart mirroring | Additional infrastructure; upstream chart updates are delayed | Stale mirrored charts miss security patches | Automate mirror sync on a daily schedule; alert when upstream versions diverge |
| Dependency lockfile verification | Adds verification step to CI; blocks builds if checksums drift | Legitimate dependency updates require regenerating the lockfile | Include `helm dependency update` and lockfile commit in the dependency update workflow |
| Kyverno admission policy | Blocks all unsigned deployments cluster-wide | Overly strict policy blocks emergency deployments | Start in Audit mode; maintain a break-glass procedure that temporarily sets Enforce to Audit |
| Trivy scanning of mirrored charts | Catches known CVEs in chart templates before deployment | False positives block chart mirroring; scan database may lag | Review and document false positive exclusions; update Trivy database before each scan |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Cosign signing key lost | Cannot sign new chart versions; existing signatures still verify | Signing step fails in CI; cosign sign returns error | Generate a new key pair; re-sign all current chart versions; update Kyverno policy with new public key |
| OCI registry unavailable | `helm pull` and `helm install` fail; deployments blocked | Registry health check fails; chart pull errors in CI | Use registry replication across regions; cache chart tarballs in CI runner storage as fallback |
| Mirrored chart version mismatch | Deployed chart version does not match what the team expects | Chart version in cluster does not match version in values file | Pin chart versions explicitly in CI pipeline; verify version after installation with `helm list` |
| Kyverno blocks legitimate deployment | Deployment rejected with "images must come from internal registry" | Helm install fails with admission webhook denial | Verify all images are mirrored; if emergency, use break-glass namespace without Kyverno policy |
| Chart.lock out of sync | `helm dependency build` downloads different versions than expected | CI verification step fails with checksum mismatch | Run `helm dependency update` to regenerate Chart.lock; commit the updated lockfile |

## When to Consider a Managed Alternative

**Transition point:** When mirroring, signing, scanning, and verifying charts across more than 30 active charts becomes a dedicated team responsibility, or when airgapped deployment requirements demand a registry with built-in replication, scanning, and signing features.

**What managed alternatives handle:**

- **OCI registries with built-in signing ([Harbor](https://goharbor.io), [JFrog Artifactory](https://jfrog.com/artifactory/)):** Harbor provides cosign signature verification, vulnerability scanning, and replication between registries out of the box. Artifactory supports OCI artifact signing with integrated access control and audit logging.

- **[Artifact Hub](https://artifacthub.io):** Aggregates metadata about public Helm charts including security reports and signed status. Useful for discovering charts but does not replace internal verification.

**What you still control:** The decision of which charts to trust, your signing keys and verification policy, the Kyverno or OPA admission policies that enforce signed-only deployments, and the scanning thresholds that determine whether a chart with known vulnerabilities is acceptable for your environment.

## Related Articles

- [Securing Helm Charts: Chart Signing, Value Injection, and Template Security](/articles/cicd/helm-chart-security/)
- [SLSA Provenance for Container Images: From Build to Admission Control](/articles/cicd/slsa-provenance/)
- [Artifact Integrity Verification: Checksums, Signatures, and Transparency Logs](/articles/cicd/artifact-integrity/)
- [Container Registry Security: Access Control, Scanning, and Image Promotion](/articles/cicd/container-registry-security/)
- [Dependency Pinning and Lockfile Integrity: Preventing Supply Chain Attacks in CI](/articles/cicd/dependency-pinning/)
- [GitOps Security Model: Separation of Duties, Drift Detection, and Rollback Controls](/articles/cicd/gitops-security/)
