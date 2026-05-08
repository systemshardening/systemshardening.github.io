---
title: "Enforcing Software Supply Chain Security Policies at Deploy Time"
description: "CI can be bypassed, misconfigured, or compromised — but admission control cannot be skipped. This article covers the deploy-time gate as the final, non-negotiable supply chain checkpoint: image signing, SLSA provenance, SBOM attestation, vulnerability gating, Sigstore policy-controller, Kyverno, OPA Gatekeeper, slsa-verifier, and air-gapped deployments."
slug: supply-chain-policy-deploy-time
date: 2026-05-07
lastmod: 2026-05-07
category: cicd
tags:
  - supply-chain-security
  - policy-enforcement
  - admission-control
  - slsa
  - cosign
personas:
  - security-engineer
  - platform-engineer
article_number: 541
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/cicd/supply-chain-policy-deploy-time/
---

# Enforcing Software Supply Chain Security Policies at Deploy Time

## Problem

CI pipelines enforce a great deal: linting, unit tests, SAST scans, vulnerability checks, image signing. The temptation is to treat a passing pipeline as a security guarantee. It is not. CI is advisory. An attacker who gains access to a CI runner, a registry credential, or a pipeline YAML file can bypass, modify, or disable every check that lives inside the pipeline. A malicious image can be pushed directly to the registry. A signed image can be replaced by an unsigned one after the signing step completes. A workflow file can be edited to skip the vulnerability scan.

The deploy-time gate is different. Kubernetes admission control runs inside the cluster, outside the pipeline's control plane. Every Pod creation request — regardless of origin, regardless of whether it came from a GitOps controller, a manual `kubectl apply`, a Helm release, or a compromised CI system — must pass through the admission webhook before a container starts. This makes it the only control that cannot be bypassed by attacking the pipeline.

The gaps that only deploy-time policy can close:

- A developer pushes an image directly to the registry with `docker push`, bypassing CI entirely.
- A CI job is modified to skip signing; the unsigned image reaches the registry.
- An image is signed correctly but then replaced in the registry by an attacker with registry write access. The replaced image has no valid signature.
- A GitOps operator syncs a manifests change that points to a different (older, unpatched) image digest than the one tested in CI.
- An emergency rollback targets an image that was never scanned for recent CVEs.

**Target systems:** Kubernetes 1.28+, Sigstore policy-controller 0.9+, Kyverno 1.12+, OPA Gatekeeper 3.15+, slsa-verifier 2.4+, Cosign 2.4+, Syft 1.x, Grype 0.77+.

## Threat Model

- **Adversary 1 — Pipeline bypass:** An attacker with CI runner access or repository write access disables signing and vulnerability scanning steps, then pushes a malicious image to the registry. Without admission-time verification, the image deploys to production.
- **Adversary 2 — Registry substitution:** An attacker with registry write access replaces a legitimately signed image with a malicious one after the image has passed CI. The image tag still resolves, but the digest (and therefore the signature) no longer matches.
- **Adversary 3 — Dependency confusion / base image compromise:** A publicly available base image used in production is compromised after the last CI scan. A new pod using an older manifest pulls the compromised image. Without deploy-time CVE gating, the compromised image runs.
- **Adversary 4 — Banned package introduction:** A developer introduces a dependency that is on the organization's banned package list (known-malicious, license-incompatible, or from a sanctioned vendor). The SBOM attestation includes the banned package; an SBOM-aware admission check blocks the deployment.
- **Adversary 5 — Provenance downgrade:** An image is built outside the approved build system and achieves only SLSA Level 1 (or none). A policy that requires SLSA Level 3 blocks it; without that policy, it reaches production.
- **Access level:** Adversaries 1–2 have CI or registry credentials. Adversary 3 operates through the public package ecosystem. Adversaries 4–5 operate through the normal development workflow.
- **Objective:** Run unauthorized, unverified, or vulnerable code in production.
- **Blast radius:** Container escape, data exfiltration, lateral movement to adjacent cluster workloads.

## What to Enforce at Deploy Time

Before configuring any specific tool, establish the set of properties that every image must prove before it is allowed to run. These properties map directly to policy rules:

| Property | Evidence type | Why it belongs here |
|----------|--------------|---------------------|
| Image was signed by the expected build pipeline | Cosign signature in OCI registry | Proves image origin; blocks direct registry pushes |
| SLSA provenance meets minimum level (≥ L2) | SLSA provenance attestation | Proves the build was non-falsifiable and auditable |
| SBOM is attached and contains no banned packages | SPDX/CycloneDX attestation | Enables real-time license and supply chain policy enforcement |
| Vulnerability scan shows no critical CVEs | Grype/Trivy scan attestation | Last line of defence before execution |
| Image was built from an approved base image | Provenance `fromImage` field or base image attestation | Prevents stale or unapproved base images reaching production |

Each property should be enforced independently. A policy that requires all five is stronger than a policy that requires only signing: an attacker who can sign their malicious image (e.g. by using a stolen signing key) is still blocked by the CVE check and the provenance level requirement.

## Configuration

### Step 1: Sigstore Policy-Controller — ClusterImagePolicy

The [Sigstore policy-controller](https://docs.sigstore.dev/policy-controller/overview/) is a dedicated Kubernetes admission controller for supply chain policy. It exposes a `ClusterImagePolicy` CRD that maps image reference patterns to signing and attestation requirements.

Install the policy-controller via Helm:

```bash
helm repo add sigstore https://sigstore.github.io/helm-charts
helm repo update
helm install policy-controller sigstore/policy-controller \
  --namespace cosign-system \
  --create-namespace \
  --set policyController.failurePolicy=Fail
```

Create a namespace-level enforcement label. The policy-controller only enforces on namespaces that opt in:

```bash
kubectl label namespace production \
  policy.sigstore.dev/include=true
```

Define a `ClusterImagePolicy` that requires keyless signing from the expected workflow:

```yaml
# cluster-image-policy-production.yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: production-signing-policy
spec:
  images:
    # Match all images in the organization's registry.
    - glob: "ghcr.io/myorg/**"
  authorities:
    - keyless:
        url: https://fulcio.sigstore.dev
        identities:
          # Only accept signatures from the production build workflow on main.
          - issuer: "https://token.actions.githubusercontent.com"
            subjectRegExp: "^https://github\\.com/myorg/[^/]+/\\.github/workflows/build\\.yml@refs/heads/main$"
        # Every signature must have a Rekor transparency log entry.
        ctlog:
          url: https://rekor.sigstore.dev
      # Also require the SLSA provenance attestation.
      attestations:
        - name: slsa-provenance
          predicateType: "https://slsa.dev/provenance/v1"
          policy:
            type: cue
            data: |
              // Minimum SLSA Level 2: hosted runner, non-falsifiable provenance.
              import "list"
              predicateType: "https://slsa.dev/provenance/v1"
              predicate: {
                buildDefinition: {
                  buildType: =~ "^https://slsa\\.dev/container-based-build/v0\\."
                }
              }
```

Per-namespace overrides are possible by creating additional `ClusterImagePolicy` resources scoped to non-production namespaces with relaxed requirements. This supports a progressive rollout: enforce strictly in production first, then extend to staging.

### Step 2: Kyverno Policies for Supply Chain

[Kyverno](https://kyverno.io) provides a flexible policy engine that complements the policy-controller with richer condition logic and the ability to enforce SBOM content.

Install Kyverno:

```bash
helm install kyverno kyverno/kyverno \
  --namespace kyverno \
  --create-namespace \
  --set admissionController.replicas=3
```

**Policy 1: Require signed image with digest pinning.**

Kyverno's `verifyImages` rule automatically mutates the pod's image reference to use the verified digest, preventing tag-based attacks after signing:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-signed-image
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
            - "ghcr.io/myorg/*"
          mutateDigest: true   # Pin the image to the verified digest.
          required: true
          attestors:
            - count: 1
              entries:
                - keyless:
                    subject: "https://github.com/myorg/*/github/workflows/build.yml@refs/heads/main"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: "https://rekor.sigstore.dev"
```

**Policy 2: Require SBOM attestation.**

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-sbom-attestation
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: check-sbom-attached
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [production]
      verifyImages:
        - imageReferences:
            - "ghcr.io/myorg/*"
          attestors:
            - count: 1
              entries:
                - keyless:
                    subject: "https://github.com/myorg/*/github/workflows/build.yml@refs/heads/main"
                    issuer: "https://token.actions.githubusercontent.com"
          attestations:
            - predicateType: "https://spdx.dev/Document"
              attestors:
                - count: 1
                  entries:
                    - keyless:
                        subject: "https://github.com/myorg/*/github/workflows/build.yml@refs/heads/main"
                        issuer: "https://token.actions.githubusercontent.com"
```

**Policy 3: Require SLSA provenance at level 2 or higher.**

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-slsa-provenance
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: check-slsa-provenance
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [production]
      verifyImages:
        - imageReferences:
            - "ghcr.io/myorg/*"
          attestors:
            - count: 1
              entries:
                - keyless:
                    issuer: "https://token.actions.githubusercontent.com"
                    subject: "https://github.com/myorg/*/github/workflows/build.yml@refs/heads/main"
          attestations:
            - predicateType: "https://slsa.dev/provenance/v1"
              conditions:
                - all:
                    # Builder must be the SLSA GitHub Generator at a pinned version.
                    - key: "{{ predicate.builder.id }}"
                      operator: Equals
                      value: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0"
```

### Step 3: OPA Gatekeeper Constraint for Image Signing

For organizations already running [OPA Gatekeeper](https://open-policy-agent.github.io/gatekeeper/), a custom `ConstraintTemplate` enforces image signing requirements without deploying an additional controller:

```yaml
# constraint-template-signed-images.yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: requiresignedimages
spec:
  crd:
    spec:
      names:
        kind: RequireSignedImages
      validation:
        openAPIV3Schema:
          type: object
          properties:
            allowedRegistries:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package requiresignedimages

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          image := container.image
          # Image must include a digest (sha256:...) — unsigned images
          # typically reference only a tag.
          not regex.match("@sha256:[a-f0-9]{64}$", image)
          msg := sprintf(
            "Container image '%v' must reference a digest, not a mutable tag. Sign the image and pin to digest.", [image]
          )
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          image := container.image
          # Image must come from an approved registry.
          not startswith(image, "ghcr.io/myorg/")
          not startswith(image, "registry.internal.myorg.com/")
          msg := sprintf(
            "Container image '%v' is not from an approved registry.", [image]
          )
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: RequireSignedImages
metadata:
  name: require-signed-images-production
spec:
  enforcementAction: deny
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces: ["production", "staging"]
  parameters:
    allowedRegistries:
      - "ghcr.io/myorg/"
      - "registry.internal.myorg.com/"
```

Note: OPA Gatekeeper validates the image reference at admission time but does not itself verify the cryptographic signature. Pair it with the Sigstore policy-controller (which does cryptographic verification) and use Gatekeeper for additional structural checks (registry allowlisting, digest pinning enforcement, label requirements).

### Step 4: slsa-verifier in CD Scripts

For non-Kubernetes deployments — serverless functions, bare-metal, VM-based workloads — the `slsa-verifier` CLI provides standalone provenance verification that can run as a pre-deployment gate inside any CD script:

```bash
#!/usr/bin/env bash
# deploy-gate.sh — run before any deployment; exits non-zero on policy failure.
set -euo pipefail

IMAGE_DIGEST="${1:?Usage: $0 <image-digest>}"
EXPECTED_REPO="github.com/myorg/myapp"
EXPECTED_BUILDER="https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0"

echo "==> Verifying SLSA provenance for ${IMAGE_DIGEST}"
slsa-verifier verify-image \
  --source-uri "${EXPECTED_REPO}" \
  --builder-id "${EXPECTED_BUILDER}" \
  --print-provenance \
  "ghcr.io/myorg/myapp@${IMAGE_DIGEST}"

echo "==> Verifying image signature"
cosign verify \
  --certificate-identity-regexp "^https://github\\.com/myorg/myapp/\\.github/workflows/build\\.yml@refs/heads/main$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "ghcr.io/myorg/myapp@${IMAGE_DIGEST}"

echo "==> All supply chain gates passed. Proceeding with deployment."
```

Integrate this gate into Argo CD via a `PreSync` hook:

```yaml
# argocd-presync-hook.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: supply-chain-gate
  annotations:
    argocd.argoproj.io/hook: PreSync
    argocd.argoproj.io/hook-delete-policy: BeforeHookCreation
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: gate
          image: ghcr.io/myorg/deploy-gate-tools:latest
          command: ["/scripts/deploy-gate.sh"]
          args: ["$(IMAGE_DIGEST)"]
          env:
            - name: IMAGE_DIGEST
              valueFrom:
                configMapKeyRef:
                  name: release-metadata
                  key: image_digest
```

The PreSync hook runs before Argo CD applies any manifests. A non-zero exit blocks the sync.

### Step 5: SBOM Analysis — Checking for Banned Packages

Attaching an SBOM attestation proves the SBOM exists; it does not automatically check the SBOM's contents. Add a banned-package check as a deployment gate step:

```bash
#!/usr/bin/env bash
# check-sbom-banned.sh — extract SBOM from attestation and check for banned packages.
set -euo pipefail

IMAGE_REF="${1:?Usage: $0 <image-ref>}"
BANNED_PACKAGES_FILE="${2:-/etc/policy/banned-packages.txt}"

echo "==> Extracting SBOM attestation for ${IMAGE_REF}"
cosign verify-attestation \
  --certificate-identity-regexp "^https://github\\.com/myorg/.*@refs/heads/main$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --type spdxjson \
  "${IMAGE_REF}" \
  | jq -r '.payload' \
  | base64 -d \
  | jq -r '.predicate.packages[].name' \
  > /tmp/sbom-packages.txt

echo "==> Checking for banned packages"
VIOLATIONS=0
while IFS= read -r banned; do
  if grep -qxF "${banned}" /tmp/sbom-packages.txt; then
    echo "BLOCKED: banned package '${banned}' found in SBOM"
    VIOLATIONS=$((VIOLATIONS + 1))
  fi
done < "${BANNED_PACKAGES_FILE}"

if [[ "${VIOLATIONS}" -gt 0 ]]; then
  echo "Supply chain gate FAILED: ${VIOLATIONS} banned package(s) found."
  exit 1
fi

echo "==> SBOM check passed. No banned packages found."
```

The banned packages file (`/etc/policy/banned-packages.txt`) is managed as a ConfigMap in the cluster, version-controlled in a policy repository, and updated by the security team independently of application code. This separation means the security team can add a package to the banned list without modifying any application pipeline.

### Step 6: Progressive Enforcement — Audit Mode Then Enforce Mode

Switching directly to enforce mode in production causes outages if any existing workloads lack the required attestations. Use audit mode to measure the compliance gap first.

**Kyverno audit mode:**

```yaml
spec:
  validationFailureAction: Audit   # Log violations; do not block.
```

```bash
# Query Kyverno policy reports to measure the violation rate.
kubectl get policyreport -A -o json \
  | jq '[.items[].results[] | select(.result == "fail")] | length'

# List all failing pods by policy.
kubectl get policyreport -A -o json \
  | jq -r '.items[] | .namespace as $ns | .results[] | select(.result == "fail") | "\($ns)/\(.resources[0].name): \(.policy)/\(.rule)"'
```

**Sigstore policy-controller audit mode:**

Add the `warn` label instead of `include`:

```bash
kubectl label namespace production \
  policy.sigstore.dev/warn=true   # Warn on violation; do not block.
```

**Transition checklist:**

1. Deploy all policies in audit/warn mode.
2. Run for one full deployment cycle (at least one week in production).
3. Query violation reports; remediate each failing image.
4. Set a compliance threshold (e.g. zero violations for 72 hours).
5. Switch policies to enforce mode namespace by namespace, starting with non-production.
6. Monitor pod admission error rates in the cluster for 24 hours after each namespace switches.

### Step 7: Emergency Rollbacks — Pre-Signed Rollback Images

An enforcement policy that blocks unsigned images creates an operational risk: if a rollback is needed urgently and the rollback target image lacks a valid signature, the rollback itself is blocked. Prevent this by pre-signing rollback images at build time.

The principle: every image that might ever need to be deployed — including images intended for rollback — must pass through the signing pipeline. Never rely on the ability to bypass policy as a rollback mechanism.

Implementation:

```yaml
# In the build workflow, tag the previous release as a rollback candidate and sign it.
- name: Tag and sign rollback candidate
  run: |
    PREVIOUS_DIGEST=$(curl -sH "Authorization: Bearer ${{ secrets.GITHUB_TOKEN }}" \
      "https://api.github.com/repos/${{ github.repository }}/releases/latest" \
      | jq -r '.tag_name')

    # Retag the previous release image as rollback.
    cosign copy \
      ghcr.io/${{ github.repository }}:${PREVIOUS_DIGEST} \
      ghcr.io/${{ github.repository }}:rollback

    # The copy preserves all signatures and attestations. No re-signing needed.
    # Verify the rollback tag has a valid signature.
    cosign verify \
      --certificate-identity-regexp "^https://github\\.com/${{ github.repository }}/.*@refs/heads/main$" \
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
      ghcr.io/${{ github.repository }}:rollback
```

For GitOps-based rollbacks, maintain a `rollback-manifest.yaml` in the repository that references a known-good, pre-signed digest. Reverting the GitOps repository to a previous commit automatically targets the pre-signed image.

Never create a break-glass bypass that disables admission-time verification for rollbacks. If a genuine emergency requires deploying an unsigned image, the incident must be declared, a time-limited namespace exemption must be applied with full audit logging, and the image must be re-signed and re-deployed within four hours.

### Step 8: Air-Gapped Environments — Local Rekor and Fulcio

Air-gapped clusters cannot reach `rekor.sigstore.dev` or `fulcio.sigstore.dev`. The [sigstore-scaffold](https://github.com/sigstore/scaffolding) project provides Helm charts for an internal Sigstore stack.

**Deploy a local Sigstore stack:**

```bash
# Install the sigstore scaffolding charts.
helm repo add sigstore https://sigstore.github.io/helm-charts
helm repo update

# Deploy Trillian (the transparency log backend).
helm install trillian sigstore/trillian \
  --namespace sigstore-system \
  --create-namespace

# Deploy Rekor (transparency log API).
helm install rekor sigstore/rekor \
  --namespace sigstore-system \
  --set server.extraArgs='{--trillian_log_server.address=trillian-logserver.sigstore-system:8090}'

# Deploy Fulcio (certificate authority).
helm install fulcio sigstore/fulcio \
  --namespace sigstore-system \
  --set config.OIDCIssuers[0].IssuerURL=https://kubernetes.default.svc \
  --set config.OIDCIssuers[0].ClientID=sigstore \
  --set config.OIDCIssuers[0].Type=kubernetes

# Deploy CTLog (certificate transparency log for Fulcio certificates).
helm install ctlog sigstore/ctlog \
  --namespace sigstore-system

# Deploy a local TUF root (distributes the trust bundle to clients).
helm install tuf sigstore/tuf \
  --namespace sigstore-system
```

**Configure CI and clients to use the internal stack:**

```bash
# Export environment variables before running cosign.
export SIGSTORE_REKOR_API_URL=https://rekor.sigstore-system.svc.cluster.local
export SIGSTORE_CT_LOG_PUBLIC_KEY_FILE=/etc/sigstore/ctlog-pub.pem
export SIGSTORE_ROOT_FILE=/etc/sigstore/root.json   # Local TUF root.
export FULCIO_URL=https://fulcio.sigstore-system.svc.cluster.local
export COSIGN_MIRROR=https://tuf.sigstore-system.svc.cluster.local

cosign sign --yes ghcr.io/myorg/myapp@sha256:abc123...
```

**Configure the policy-controller to use the internal stack:**

```yaml
# policy-controller-values.yaml (passed to helm install)
policyController:
  cosignSystemConfigMap:
    rekorURL: "https://rekor.sigstore-system.svc.cluster.local"
    fulcioURL: "https://fulcio.sigstore-system.svc.cluster.local"
    tufMirror: "https://tuf.sigstore-system.svc.cluster.local"
    tufRoot: "/etc/sigstore/tuf-root.json"
```

Mirror the TUF root and public keys to each cluster node using a DaemonSet that runs at boot, ensuring every node has the trust material required to verify signatures without an external network call.

## Expected Behaviour

| Scenario | Without deploy-time policy | With deploy-time policy |
|----------|---------------------------|------------------------|
| Unsigned image pushed directly to registry | Deploys silently | Rejected by admission webhook |
| Image signed by wrong workflow (fork, wrong branch) | Indistinguishable from valid | Identity mismatch; admission blocked |
| Image with critical CVE deployed after scan grace period | Deploys silently | Blocked by vulnerability attestation check |
| SBOM contains banned package | Deploys silently | Blocked by SBOM policy gate |
| SLSA Level 1 image (no hermetic build guarantee) | Deploys silently | Blocked by provenance level constraint |
| Rollback to pre-signed image | Works | Works (pre-signed images pass policy) |
| Emergency rollback to unsigned image | Works (silently dangerous) | Blocked unless break-glass activated with audit log |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Admission-time enforcement | Cannot be bypassed from the pipeline | Adds 100–300ms to pod admission; webhook outage blocks all scheduling | Run policy-controller in HA (3+ replicas); set `failurePolicy: Fail` with HA; set `failurePolicy: Ignore` only if availability outweighs security for the namespace. |
| Requiring all five properties | Maximum supply chain coverage | Some third-party images will never have SLSA provenance | Scope strict policies to first-party images; use weaker policies (signature only) for third-party namespaces. |
| Audit mode transition | Safe rollout with no outages | Compliance theatre if teams never graduate to enforce mode | Set a documented, time-limited audit window. Track the policy violation count as a metric with an SLO. |
| Local Sigstore (air-gapped) | No dependency on external services | Operational overhead: Rekor, Fulcio, CTLog, TUF — four additional services to maintain | Use sigstore-scaffold; deploy all components from the same Helm chart set. Back up the Trillian database. |
| Pre-signed rollback images | Rollback always works under policy | Requires build pipeline to sign rollback candidates proactively | Automate rollback tagging in the build workflow; verify rollback signatures in the deployment readiness gate. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Policy-controller webhook unavailable | All pod creations blocked (if `failurePolicy: Fail`) | Pod events: `admission webhook timeout` | Restore policy-controller replicas; maintain 3+ replicas to avoid single points of failure. |
| Rekor unavailable (public or internal) | `cosign verify` fails; existing running pods unaffected; new pods blocked | Signing and verification errors in CI and webhook logs | Use offline verification (`cosign verify --offline`) if Rekor checkpoint was previously fetched; restore Rekor if using internal stack. |
| Image has valid signature but no SBOM attestation | Pod blocked by SBOM policy | Kyverno policy report shows `require-sbom-attestation/check-sbom-attached` failure | Re-run CI to generate and attach the SBOM attestation; or temporarily relax SBOM policy in audit mode while remediating. |
| Banned package added to approved base image | All images derived from that base are blocked at deploy time | SBOM policy gate blocks all pods using the base image | Update base image to remove the banned package; rebuild and re-sign all derived images; emergency: add time-limited exception with security team approval. |
| Kyverno `mutateDigest` rewrites image to unexpected digest | Pod uses different image than intended | Image digest in pod spec does not match intended release | This is correct behaviour: the policy pinned the tag to the digest of the signed image. Investigate if the running digest differs from the expected release digest. |
| slsa-verifier version mismatch with attestation format | PreSync hook fails on valid image | Hook job logs show `unsupported predicate type` | Pin slsa-verifier to the version that matches the generator version used in CI. |

## Related Articles

- [Sigstore Keyless Signing and Cosign Verification](/articles/cicd/sigstore-keyless-signing/)
- [SLSA Provenance for Container Images](/articles/cicd/slsa-provenance/)
- [Software Bill of Materials (SBOM) Generation and Consumption in CI/CD](/articles/cicd/sbom/)
- [Securing CD Promotion Gates and Approval Workflows](/articles/cicd/cd-promotion-gates-approvals/)
- [Artifact Integrity Verification](/articles/cicd/artifact-integrity/)
- [Reproducible Builds for Container Images](/articles/cicd/reproducible-builds/)
