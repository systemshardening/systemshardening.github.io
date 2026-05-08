---
title: "Securing Model Artifact Pipelines: From Training to Serving"
description: "Model files are opaque binaries ranging from 1GB to over 1TB. You cannot code-review a set of weights."
slug: "model-artifact-pipelines"
date: 2026-01-15
lastmod: 2026-01-15
category: "kubernetes"
tags: ["ai", "model-signing", "cosign", "oci", "supply-chain", "mlops"]
personas: ["ai-ml-engineer", "platform-engineer", "devops-engineer"]
article_number: 78
difficulty: "advanced"
estimated_reading_time: 14
provider_bridges:
  - name: "Snyk"
    id: 48
    category: "vulnerability-scanning"
  - name: "Backblaze"
    id: 161
    category: "object-storage"
  - name: "Wasabi"
    id: 162
    category: "object-storage"
premium_pack: "model-signing-pipeline-templates"
published: true
layout: article.njk
permalink: "/articles/kubernetes/model-artifact-pipelines/index.html"
---

# Securing Model Artifact Pipelines: From Training to Serving

## Problem

Model files are opaque binaries ranging from 1GB to over 1TB. You cannot code-review a set of weights. An attacker who tampers with model weights between training and serving controls the model's behaviour without touching a single line of application code. A poisoned model passes every integration test because the tests do not verify the weights themselves.

Most teams store model artifacts in object storage (S3, GCS, MinIO) with no integrity verification. The model file downloaded for serving could have been modified at rest, in transit, or through a compromised training pipeline. There is no standard equivalent to package signing for model files. If someone replaces your model binary with a backdoored version, you have no mechanism to detect the swap before the model starts serving requests.

**Target systems:** [Kubernetes](https://kubernetes.io) clusters running model inference workloads. OCI-compatible registries for model storage. CI/CD pipelines producing and deploying model artifacts. MLflow, DVC, or custom model registries.

## Threat Model

- **Adversary:** Insider with write access to model storage, or external attacker who has compromised the training pipeline or object storage credentials.
- **Objective:** Replace or modify model weights to alter model behaviour. Targets include injecting backdoor triggers (specific inputs produce attacker-chosen outputs), degrading model accuracy to cause business harm, or embedding data exfiltration channels in model outputs.
- **Blast radius:** A tampered model serves incorrect or malicious responses to every request. In safety-critical applications (medical, financial, autonomous systems), the consequences are not limited to data loss. Without integrity verification, the compromise persists until someone notices degraded outputs, which could be weeks.

## Configuration

### Store Models as OCI Artifacts

OCI registries provide content-addressable storage, versioning, and access control. Storing models as OCI artifacts gives you the same integrity guarantees that container images receive.

```bash
# Push a model to an OCI registry using ORAS (OCI Registry As Storage)
# Install ORAS CLI: https://oras.land/docs/installation
oras push registry.example.com/models/fraud-detector:v2.3 \
  --artifact-type application/vnd.ml.model \
  ./model.safetensors:application/octet-stream \
  ./model_card.json:application/json \
  ./training_metadata.json:application/json

# The registry stores a content-addressable manifest.
# Any modification to the model file changes the digest.
```

```bash
# Pull and verify the digest matches what training produced
oras pull registry.example.com/models/fraud-detector:v2.3 \
  --output ./serving/

# Verify SHA-256 matches the training pipeline output
sha256sum ./serving/model.safetensors
# Compare against the digest recorded during training
```

### Sign Models with Cosign

Cosign provides cryptographic signing for OCI artifacts. Signing the model after training and verifying the signature before serving creates a chain of trust from training to production.

```bash
# Generate a cosign key pair (do this once, store the private key in Vault)
cosign generate-key-pair

# Sign the model artifact after a successful training run
cosign sign --key cosign.key \
  --annotations "training_run_id=run-20260422-001" \
  --annotations "training_commit=$(git rev-parse HEAD)" \
  --annotations "framework_version=pytorch-2.5.1" \
  registry.example.com/models/fraud-detector:v2.3

# Verify the signature before serving
cosign verify --key cosign.pub \
  registry.example.com/models/fraud-detector:v2.3
```

For keyless signing with [Sigstore](https://www.sigstore.dev) (eliminates key management):

```bash
# Keyless signing using Sigstore's Fulcio CA and Rekor transparency log
# Requires OIDC identity (GitHub Actions, GitLab CI, or workload identity)
cosign sign --yes \
  --annotations "training_run_id=run-20260422-001" \
  registry.example.com/models/fraud-detector:v2.3

# Verify using the OIDC identity that signed
cosign verify \
  --certificate-identity "https://github.com/myorg/training-pipeline/.github/workflows/train.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  registry.example.com/models/fraud-detector:v2.3
```

### Admission Control: Block Unsigned Models

Use [Kyverno](https://kyverno.io) to prevent unsigned model artifacts from being deployed to serving infrastructure.

```yaml
# kyverno-policy-model-signature.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-signed-model
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: check-model-signature
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaceSelector:
                matchLabels:
                  workload-type: model-serving
      verifyImages:
        - imageReferences:
            - "registry.example.com/models/*"
          attestors:
            - entries:
                - keyless:
                    issuer: "https://token.actions.githubusercontent.com"
                    subject: "https://github.com/myorg/training-pipeline/*"
                  count: 1
          required: true
```

### Provenance Tracking

Record the complete chain from training data to serving deployment.

```json
{
  "model_id": "fraud-detector-v2.3",
  "training": {
    "run_id": "run-20260422-001",
    "commit": "a1b2c3d4e5f6",
    "dataset_digest": "sha256:9f86d08...",
    "framework": "pytorch==2.5.1",
    "base_image": "nvcr.io/nvidia/pytorch:24.03-py3",
    "started_at": "2026-04-21T02:00:00Z",
    "completed_at": "2026-04-21T18:00:00Z",
    "gpu_type": "A100-80GB",
    "gpu_count": 8
  },
  "artifact": {
    "registry": "registry.example.com/models/fraud-detector:v2.3",
    "digest": "sha256:abc123...",
    "size_bytes": 2147483648,
    "format": "safetensors",
    "signed_by": "training-pipeline@github-actions",
    "signature_digest": "sha256:def456..."
  },
  "serving": {
    "deployment": "fraud-detector-prod",
    "namespace": "ml-serving",
    "deployed_at": "2026-04-22T10:00:00Z",
    "deployed_by": "argocd"
  }
}
```

### SHA-256 Verification at Model Load Time

Add a verification step to your model serving container that checks the model digest before loading weights.

```python
# verify_model.py - run before model.load_state_dict()
import hashlib
import sys
import os

def verify_model_integrity(model_path: str, expected_digest: str) -> bool:
    """Verify model file SHA-256 matches expected digest."""
    sha256 = hashlib.sha256()
    with open(model_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    actual = sha256.hexdigest()
    if actual != expected_digest:
        print(f"INTEGRITY CHECK FAILED: expected {expected_digest}, got {actual}")
        return False
    print(f"Model integrity verified: {actual}")
    return True

if __name__ == "__main__":
    model_path = os.environ.get("MODEL_PATH", "/models/model.safetensors")
    expected = os.environ.get("MODEL_DIGEST")
    if not expected:
        print("MODEL_DIGEST environment variable not set. Refusing to load.")
        sys.exit(1)
    if not verify_model_integrity(model_path, expected):
        sys.exit(1)
```

```yaml
# model-serving-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fraud-detector
  namespace: ml-serving
spec:
  replicas: 3
  selector:
    matchLabels:
      app: fraud-detector
  template:
    metadata:
      labels:
        app: fraud-detector
    spec:
      initContainers:
        - name: verify-model
          image: registry.example.com/model-verifier:v1
          command: ["python", "verify_model.py"]
          env:
            - name: MODEL_PATH
              value: "/models/model.safetensors"
            - name: MODEL_DIGEST
              valueFrom:
                configMapKeyRef:
                  name: fraud-detector-config
                  key: model-digest
          volumeMounts:
            - name: model-volume
              mountPath: /models
              readOnly: true
      containers:
        - name: inference
          image: registry.example.com/fraud-detector-serving:v2.3
          resources:
            limits:
              nvidia.com/gpu: 1
          securityContext:
            runAsNonRoot: true
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - name: model-volume
              mountPath: /models
              readOnly: true
      volumes:
        - name: model-volume
          persistentVolumeClaim:
            claimName: fraud-detector-model
```

## Expected Behaviour

- Every model artifact in the OCI registry has a cosign signature tied to the training pipeline identity
- Kyverno blocks any unsigned model from being deployed to serving namespaces
- The init container verifies the SHA-256 digest before the inference container starts
- If the digest does not match, the pod fails to start and the deployment stalls at the init container
- Provenance metadata links every serving deployment back to a specific training run, commit, and dataset version

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| OCI registry for models | Leverages existing container registry infrastructure; content-addressable storage | Large model files (100GB+) strain registry storage and network bandwidth | Use registry with chunked upload support. Consider dedicated model registry for artifacts over 50GB. |
| Cosign signing in CI | Adds 30-60 seconds to pipeline for signing | Private key compromise allows signing malicious models | Use keyless signing with Sigstore (OIDC identity, no long-lived keys). Rotate keys if using key-pair signing. |
| SHA-256 init container | Catches any modification between registry and serving | Adds 1-5 minutes to pod startup for large models (hashing 100GB+ at disk speed) | Acceptable for production deployments. Skip for development environments if needed. |
| Kyverno admission control | Hard block on unsigned models | Kyverno outage blocks all model deployments | Run Kyverno in HA mode (3 replicas). Configure failure policy to Fail (not Ignore). |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Model tampered in storage | Init container digest verification fails; pod stuck in Init | Pod events show "INTEGRITY CHECK FAILED" message; deployment rollout stalled | Investigate storage access logs. Re-pull model from training pipeline. Rotate storage credentials. |
| Cosign signature missing | Kyverno blocks pod creation | `kubectl describe pod` shows Kyverno admission denial | Re-sign the model artifact from the training pipeline. Verify cosign key or OIDC identity configuration. |
| Registry unavailable during model pull | Pod stuck in ImagePullBackOff or init container cannot download | Pod events show pull errors | Use registry mirror or cache. For critical models, pre-pull to node-local storage. |
| Signing key compromised | Attacker can sign malicious models | No immediate symptom. Detected through provenance audit (signed model not linked to legitimate training run). | Revoke compromised key. Re-sign all models with new key. Update Kyverno policy with new key reference. Audit all models signed with compromised key. |

## When to Consider a Managed Alternative

[Snyk](https://snyk.io) for scanning model-serving container images and their dependency trees. [Backblaze](https://www.backblaze.com) and [Wasabi](https://wasabi.com) for immutable object storage with versioning enabled and object lock preventing deletion or modification. [Protect AI](https://protectai.com) for model-specific security scanning that goes beyond container-level checks.

**Premium content pack:** Model signing pipeline templates. GitHub Actions workflow for cosign signing, Kyverno admission policies, init container verification scripts, and provenance metadata schema.


## Related Articles

- [Kubernetes Image Policy Enforcement: Cosign, Notation, and Admission Webhooks](/articles/kubernetes/image-policy-enforcement/)
- [Model Registry Access Control: Versioning, Signing, and Promotion Gates](/articles/kubernetes/model-registry-access-control/)
- [Hardening Model Inference Endpoints: Authentication, Rate Limiting, and Input Validation](/articles/kubernetes/inference-endpoint-hardening/)
- [GPU Workload Isolation: MIG, MPS, and vGPU Security Boundaries](/articles/kubernetes/gpu-isolation/)
- [Network Segmentation for AI Training Infrastructure](/articles/kubernetes/ai-training-network-segmentation/)
