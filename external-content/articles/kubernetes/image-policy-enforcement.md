---
title: "Kubernetes Image Policy Enforcement: Cosign, Notation, and Admission Webhooks"
description: "Without image policy enforcement, any container image from any registry can run in a Kubernetes cluster."
slug: "image-policy-enforcement"
date: 2026-02-26
lastmod: 2026-02-26
category: "kubernetes"
tags: ["kubernetes", "cosign", "sigstore", "image-signing", "kyverno", "gatekeeper", "supply-chain"]
personas: ["platform-engineer", "devops-engineer", "security-engineer"]
article_number: 32
difficulty: "intermediate"
estimated_reading_time: 20
provider_bridges:
  - name: "Snyk"
    id: 48
    category: "container-security"
  - name: "Sigstore"
    id: 97
    category: "supply-chain-security"
published: true
layout: article.njk
permalink: "/articles/kubernetes/image-policy-enforcement/index.html"
---

# [Kubernetes](https://kubernetes.io) Image Policy Enforcement: Cosign, Notation, and Admission Webhooks

## Problem

Without image policy enforcement, any container image from any registry can run in a Kubernetes cluster. A developer can deploy an image from [Docker](https://www.docker.com) Hub that was built on someone's laptop. A compromised CI pipeline can push a malicious image to your registry. An attacker who gains deployment access can run a cryptominer image. The cluster has no mechanism to distinguish a trusted, scanned, signed image from a malicious one.

This creates several concrete risks:

- **No provenance verification.** There is no proof that an image was built by your CI pipeline, from your source code, with your build configuration. Anyone who can push to the registry can inject arbitrary code.
- **Tag mutability allows silent replacement.** Image tags like `v1.2.3` can be overwritten. An attacker who compromises registry write access can replace a legitimate image with a backdoored one using the same tag. Pods pulling that tag get the malicious image.
- **Unscanned images enter production.** Without admission control, images that failed vulnerability scanning or were never scanned can be deployed.
- **Registry sprawl increases attack surface.** Teams pulling from Docker Hub, GitHub Container Registry, Quay, and internal registries create an uncontrolled supply chain with no central verification.

This article covers signing images with [cosign](https://docs.sigstore.dev/cosign/) and Notation, verifying signatures at admission time with [Kyverno](https://kyverno.io) and [Gatekeeper](https://open-policy-agent.github.io/gatekeeper/), restricting allowed registries, and implementing break-glass procedures for emergencies.

**Target systems:** Kubernetes 1.29+ with Kyverno 1.12+ or Gatekeeper 3.16+. cosign from [Sigstore](https://www.sigstore.dev), or Notation from CNCF Notary Project.

## Threat Model

- **Adversary:** Attacker who can push images to the container registry (via compromised CI credentials), or an insider deploying unauthorized images.
- **Access level:** Write access to the container registry, or RBAC permissions to create/update Deployments in one or more namespaces.
- **Objective:** Run malicious code in the cluster by deploying a backdoored image, an image with known vulnerabilities, or an image from an untrusted source.
- **Blast radius:** Without image policy enforcement, a single compromised registry credential or deployment permission allows arbitrary code execution in the cluster. With enforcement, the attacker must also compromise the signing key or the admission controller to run unauthorized images.

## Configuration

### Step 1: Sign Images with Cosign

Cosign from the Sigstore project signs container images using either a static key pair or keyless signing via OIDC (identity-based, no key management).

**Key-based signing (for private environments):**

```bash
# Generate a cosign key pair
cosign generate-key-pair
# Creates cosign.key (private, keep secret) and cosign.pub (public, distribute)

# Sign an image after CI build
cosign sign --key cosign.key \
  registry.example.com/web-app:v1.4.2

# Verify the signature
cosign verify --key cosign.pub \
  registry.example.com/web-app:v1.4.2
```

**Keyless signing (using CI identity via Sigstore):**

```bash
# In a GitHub Actions workflow:
# The OIDC token from GitHub proves the build identity
cosign sign \
  --oidc-issuer=https://token.actions.githubusercontent.com \
  registry.example.com/web-app:v1.4.2

# Verify with identity constraints (no key needed)
cosign verify \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity=https://github.com/myorg/myrepo/.github/workflows/build.yml@refs/heads/main \
  registry.example.com/web-app:v1.4.2
```

**Example CI pipeline (GitHub Actions):**

```yaml
# .github/workflows/build-sign.yaml
name: Build and Sign
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
    steps:
      - uses: actions/checkout@v4
      - uses: sigstore/cosign-installer@v3

      - name: Build and push
        run: |
          docker build -t registry.example.com/web-app:${{ github.sha }} .
          docker push registry.example.com/web-app:${{ github.sha }}

      - name: Sign image
        run: |
          cosign sign --yes \
            registry.example.com/web-app:${{ github.sha }}
```

### Step 2: Sign Images with Notation (Alternative)

Notation is the CNCF Notary Project signing tool, using standard X.509 certificates:

```bash
# Install notation
curl -Lo notation.tar.gz \
  "https://github.com/notaryproject/notation/releases/download/v1.2.0/notation_1.2.0_linux_amd64.tar.gz"
tar xzf notation.tar.gz -C /usr/local/bin notation

# Add a signing key (from a certificate)
notation key add "ci-signing-key" \
  --plugin "com.example.kms" \
  --id "arn:aws:kms:us-east-1:123456789:key/abcd-1234"

# Sign the image
notation sign \
  --key "ci-signing-key" \
  registry.example.com/web-app:v1.4.2

# Verify the signature
notation verify \
  registry.example.com/web-app:v1.4.2
```

### Step 3: Enforce Signatures with Kyverno

Kyverno is a Kubernetes-native policy engine that runs as an admission webhook. It can verify cosign and Notation signatures before allowing image deployment.

```bash
# Install Kyverno
helm repo add kyverno https://kyverno.github.io/kyverno/
helm install kyverno kyverno/kyverno \
  --namespace kyverno \
  --create-namespace
```

**Policy: require cosign signature (key-based):**

```yaml
# require-image-signature.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-image-signature
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: verify-cosign-signature
      match:
        any:
          - resources:
              kinds:
                - Pod
      verifyImages:
        - imageReferences:
            - "registry.example.com/*"
          attestors:
            - entries:
                - keys:
                    publicKeys: |
                      -----BEGIN PUBLIC KEY-----
                      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
                      -----END PUBLIC KEY-----
```

**Policy: require keyless signature with identity verification:**

```yaml
# require-keyless-signature.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-keyless-signature
spec:
  validationFailureAction: Enforce
  rules:
    - name: verify-keyless-cosign
      match:
        any:
          - resources:
              kinds:
                - Pod
      verifyImages:
        - imageReferences:
            - "registry.example.com/*"
          attestors:
            - entries:
                - keyless:
                    issuer: "https://token.actions.githubusercontent.com"
                    subject: "https://github.com/myorg/myrepo/.github/workflows/build.yml@refs/heads/main"
                    rekor:
                      url: "https://rekor.sigstore.dev"
```

### Step 4: Enforce with Gatekeeper (Alternative)

Gatekeeper uses [OPA](https://www.openpolicyagent.org) [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) policies with external data for cosign verification:

```yaml
# registry-allowlist.yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sallowedregistries
spec:
  crd:
    spec:
      names:
        kind: K8sAllowedRegistries
      validation:
        openAPIV3Schema:
          type: object
          properties:
            registries:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sallowedregistries

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not registry_allowed(container.image)
          msg := sprintf("Image '%v' is from a disallowed registry. Allowed: %v",
            [container.image, input.parameters.registries])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.initContainers[_]
          not registry_allowed(container.image)
          msg := sprintf("Init container image '%v' is from a disallowed registry. Allowed: %v",
            [container.image, input.parameters.registries])
        }

        registry_allowed(image) {
          startswith(image, input.parameters.registries[_])
        }
---
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAllowedRegistries
metadata:
  name: allowed-registries
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    registries:
      - "registry.example.com/"
      - "registry.k8s.io/"
      - "docker.io/library/"
```

### Step 5: Registry Allowlisting

Combine signing verification with registry restrictions so only images from approved registries, with valid signatures, can run:

```yaml
# combined-image-policy.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: image-policy
spec:
  validationFailureAction: Enforce
  rules:
    # Rule 1: Only allow approved registries
    - name: restrict-registries
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: "Images must be from approved registries."
        pattern:
          spec:
            containers:
              - image: "registry.example.com/* | registry.k8s.io/*"
            =(initContainers):
              - image: "registry.example.com/* | registry.k8s.io/*"

    # Rule 2: Require digest pinning (no mutable tags)
    - name: require-image-digest
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: "Images must use a digest (@sha256:...), not a tag."
        pattern:
          spec:
            containers:
              - image: "*@sha256:*"
            =(initContainers):
              - image: "*@sha256:*"

    # Rule 3: Require signature
    - name: require-signature
      match:
        any:
          - resources:
              kinds:
                - Pod
      verifyImages:
        - imageReferences:
            - "registry.example.com/*"
          attestors:
            - entries:
                - keys:
                    publicKeys: |
                      -----BEGIN PUBLIC KEY-----
                      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
                      -----END PUBLIC KEY-----
```

### Step 6: Emergency Break-Glass Procedure

When a critical security patch must be deployed immediately and the signing infrastructure is unavailable, you need a time-limited exception:

```yaml
# break-glass-exception.yaml
apiVersion: kyverno.io/v2beta1
kind: PolicyException
metadata:
  name: emergency-deploy-2026-04-22
  namespace: production
  annotations:
    break-glass/requester: "oncall-engineer@example.com"
    break-glass/reason: "CVE-2026-XXXX hotfix, signing infra down"
    break-glass/expires: "2026-04-23T00:00:00Z"
spec:
  exceptions:
    - policyName: require-image-signature
      ruleNames:
        - verify-cosign-signature
  match:
    any:
      - resources:
          kinds:
            - Pod
          namespaces:
            - production
          names:
            - "hotfix-*"
```

```bash
# Apply the exception
kubectl apply -f break-glass-exception.yaml

# Deploy the unsigned hotfix image
kubectl set image deployment/web-app \
  web=registry.example.com/web-app:hotfix-cve-2026 \
  -n production

# After signing infra is restored, sign the image and remove the exception
cosign sign --key cosign.key registry.example.com/web-app:hotfix-cve-2026
kubectl delete -f break-glass-exception.yaml
```

Create a CronJob that cleans up expired exceptions:

```yaml
# cleanup-expired-exceptions.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: cleanup-break-glass
  namespace: kyverno
spec:
  schedule: "0 * * * *"  # Every hour
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: break-glass-cleanup
          containers:
            - name: cleanup
              image: bitnami/kubectl:1.30
              command:
                - /bin/sh
                - -c
                - |
                  NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
                  kubectl get policyexceptions -A -o json | \
                    jq -r ".items[] | select(.metadata.annotations[\"break-glass/expires\"] < \"$NOW\") | \
                    \"\(.metadata.namespace) \(.metadata.name)\"" | \
                    while read ns name; do
                      kubectl delete policyexception "$name" -n "$ns"
                      echo "Deleted expired exception: $ns/$name"
                    done
          restartPolicy: OnFailure
```

## Expected Behaviour

After implementing image policy enforcement:

- All images deployed to the cluster must come from approved registries
- Images without a valid cosign or Notation signature are rejected at admission time
- Kyverno/Gatekeeper returns a clear error message identifying which policy the image violates
- Images pinned by digest cannot be silently replaced by overwriting a tag
- Break-glass exceptions allow emergency deployments with time-limited scope
- Expired break-glass exceptions are automatically cleaned up

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Signature verification at admission | Every pod creation adds 100-500ms for signature check | Slower deployments; potential timeout on large-scale rollouts | Cache verification results. Use Kyverno background scanning for existing resources |
| Digest pinning requirement | Developers must update digests instead of tags; no more `image: app:latest` | Developer friction; increased merge conflicts on digest changes | Integrate digest resolution into CI. Use tools like `kbld` or [Flux](https://fluxcd.io) image automation to resolve tags to digests |
| Registry allowlisting | Blocks images from unapproved sources, including debugging tools | Engineers cannot quickly pull debug images during incidents | Include a curated set of debug images in the approved registry. Maintain an internal mirror of common tools |
| Break-glass procedure | Bypasses signing requirement for emergencies | If overused or if exceptions are not cleaned up, the policy becomes ineffective | Require manager approval for break-glass. Alert on every PolicyException creation. Auto-expire exceptions |
| Keyless signing dependency on Sigstore infrastructure | Signature verification requires connectivity to Rekor transparency log | If Sigstore is unreachable, all deployments fail verification | Run a private Sigstore instance (Rekor + Fulcio) for air-gapped or high-availability requirements |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Signing key compromised | Attacker can sign arbitrary images that pass verification | No immediate detection from the cluster side; requires monitoring signing activity in CI logs | Rotate the signing key. Update the Kyverno/Gatekeeper policy with the new public key. Re-sign all images with the new key. Revoke the old key in Rekor |
| Kyverno webhook unavailable | All pod creations fail if failurePolicy is Fail; all pass unchecked if failurePolicy is Ignore | Pod creation errors referencing webhook timeout; or sudden absence of policy violations in logs | Check Kyverno pod health. The default failurePolicy should be Fail to prevent bypass. Restore Kyverno before deploying new workloads |
| Signature verification timeout | Pod creation blocked with webhook timeout errors; deployments stall | Deployment events show admission webhook timeout; Kyverno logs show registry connectivity issues | Check network connectivity from Kyverno pods to the container registry and Rekor. Increase webhook timeout if needed |
| Registry mirror out of sync | Images exist in the source registry but not in the approved mirror | ImagePullBackOff with "manifest not found" errors | Sync the mirror. Configure automatic mirroring for all images used by the cluster |
| Break-glass exception not cleaned up | Unsigned images can be deployed indefinitely in the excepted namespace | Audit PolicyException resources; alert on exceptions older than 24 hours | Deploy the cleanup CronJob. Manually delete stale exceptions |

## When to Consider a Managed Alternative

**Transition point:** Running your own signing infrastructure (key management, transparency logs, admission webhooks) is a significant operational commitment. The signing key is a high-value secret that must be protected, rotated, and backed up. If your team deploys fewer than 20 distinct images, the overhead of a full Sigstore pipeline may exceed the value.

**Recommended providers:**

- **[Snyk](https://snyk.io):** Container security platform that integrates image scanning and policy enforcement. Provides a managed admission controller that blocks images with critical vulnerabilities, reducing the need for custom Kyverno/Gatekeeper policies.
- **[Sigstore](https://www.sigstore.dev):** The open source signing and verification ecosystem. Use the public instance (Rekor, Fulcio) for keyless signing in public CI systems. For private environments, deploy a private Sigstore stack or use a managed service.

**What you still control:** The signing policy (which identities are trusted), the registry allowlist, the break-glass procedure, and the admission controller configuration. Managed scanning services complement but do not replace signature verification.

**Premium content pack:** Kyverno policy pack for image verification, including policies for cosign signature verification, digest pinning, registry allowlisting, and break-glass exception templates. Includes a GitHub Actions workflow for automated image signing.


## Related Articles

- [Kubernetes Admission Control: From PodSecurity Standards to Custom OPA/Kyverno Policies](/articles/kubernetes/kubernetes-admission-control/)
- [Securing Model Artifact Pipelines: From Training to Serving](/articles/kubernetes/model-artifact-pipelines/)
- [Model Registry Access Control: Versioning, Signing, and Promotion Gates](/articles/kubernetes/model-registry-access-control/)
- [Pod Security Context Deep Dive: runAsNonRoot, readOnlyRootFilesystem, and Capabilities](/articles/kubernetes/pod-security-context/)
- [Kubernetes Network Policies That Actually Work: From Default Deny to Microsegmentation](/articles/kubernetes/kubernetes-network-policies/)
