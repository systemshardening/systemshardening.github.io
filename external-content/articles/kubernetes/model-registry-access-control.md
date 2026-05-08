---
title: "Model Registry Access Control: Versioning, Signing, and Promotion Gates"
description: "Model registries are the bridge between training and production. A model pushed to the production registry gets served to users."
slug: "model-registry-access-control"
date: 2026-01-03
lastmod: 2026-01-03
category: "kubernetes"
tags: ["model-registry", "cosign", "rbac", "supply-chain", "ai-security"]
personas: ["ai-ml-engineer", "platform-engineer", "security-engineer"]
article_number: 118
difficulty: "intermediate"
estimated_reading_time: 16
provider_bridges:
  - name: "Snyk"
    id: 48
    category: "container-security"
  - name: "Cosign"
    id: 150
    category: "supply-chain-security"
premium_pack: "model-registry-hardening-configs"
published: true
layout: article.njk
permalink: "/articles/kubernetes/model-registry-access-control/index.html"
---

# Model Registry Access Control: Versioning, Signing, and Promotion Gates

## Problem

Model registries are the bridge between training and production. A model pushed to the production registry gets served to users. Most teams use generic artifact storage (S3 buckets, OCI registries, or MLflow) with minimal access controls: any developer can push a model, there is no signing or integrity verification, and promotion from dev to production is a manual copy with no gates.

This creates a supply chain gap. If an attacker can write to the model registry, or if a developer accidentally pushes a broken model, production inference changes immediately. Unlike container images, which have mature signing and scanning tooling, model artifacts often lack any verification. A poisoned model can serve traffic for hours before anyone notices degraded behavior.

**Target systems:** OCI-based model registries (Harbor, ECR, GCR), MLflow Model Registry, or custom registries running on [Kubernetes](https://kubernetes.io). Cosign for artifact signing.

## Configuration

### OCI Registry RBAC for Model Artifacts

Store models as OCI artifacts in the same registry infrastructure you use for container images. This lets you reuse existing RBAC, scanning, and signing tooling.

```yaml
# harbor-robot-accounts.yaml - separate credentials per environment
# Dev account: push and pull from dev repository
apiVersion: v1
kind: Secret
metadata:
  name: registry-dev-credentials
  namespace: ml-training
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: <base64-encoded>
  # Robot account: robot$ml-dev
  # Permissions: push + pull on projects/ml-models-dev/*
  # No access to ml-models-staging or ml-models-prod
---
# Staging account: pull from dev, push to staging
apiVersion: v1
kind: Secret
metadata:
  name: registry-staging-credentials
  namespace: ml-staging
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: <base64-encoded>
  # Robot account: robot$ml-staging
  # Permissions: pull on ml-models-dev/*, push + pull on ml-models-staging/*
---
# Production account: pull only from prod repository
apiVersion: v1
kind: Secret
metadata:
  name: registry-prod-credentials
  namespace: ai-inference
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: <base64-encoded>
  # Robot account: robot$ml-prod
  # Permissions: pull only on ml-models-prod/*
  # CANNOT push - only the promotion pipeline can write here
```

### Pushing Models as OCI Artifacts with ORAS

```bash
#!/bin/bash
# push_model.sh - push a model to the OCI registry with metadata
set -euo pipefail

MODEL_DIR="$1"       # e.g., /checkpoints/run-042
MODEL_NAME="$2"      # e.g., llama-v2-finetuned
MODEL_VERSION="$3"   # e.g., v1.0.42
REGISTRY="$4"        # e.g., registry.internal/ml-models-dev

# Create model manifest with metadata
cat > "${MODEL_DIR}/model-card.json" <<MANIFEST
{
  "name": "${MODEL_NAME}",
  "version": "${MODEL_VERSION}",
  "training_run_id": "$(cat ${MODEL_DIR}/run_id.txt)",
  "base_model": "meta-llama/Llama-2-7b",
  "framework": "pytorch",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "created_by": "$(whoami)",
  "eval_accuracy": "$(cat ${MODEL_DIR}/eval_metrics.json | jq -r .accuracy)",
  "data_hash": "$(cat ${MODEL_DIR}/data_manifest.sha256)"
}
MANIFEST

# Push model as OCI artifact using ORAS
oras push "${REGISTRY}/${MODEL_NAME}:${MODEL_VERSION}" \
  --config "${MODEL_DIR}/model-card.json:application/vnd.ml.model.config.v1+json" \
  "${MODEL_DIR}/model.safetensors:application/vnd.ml.model.weights" \
  "${MODEL_DIR}/tokenizer.json:application/vnd.ml.model.tokenizer" \
  "${MODEL_DIR}/config.json:application/vnd.ml.model.config"

echo "Model pushed: ${REGISTRY}/${MODEL_NAME}:${MODEL_VERSION}"
```

### Cosign Signing for Model Artifacts

```bash
#!/bin/bash
# sign_model.sh - sign a model artifact in the OCI registry
set -euo pipefail

MODEL_REF="$1"  # e.g., registry.internal/ml-models-dev/llama-v2-finetuned:v1.0.42
KMS_KEY="$2"    # e.g., gcpkms://projects/my-proj/locations/global/keyRings/ml/cryptoKeys/model-signer

# Sign the OCI artifact
cosign sign --key "${KMS_KEY}" "${MODEL_REF}"

# Attach attestation with training metadata
cosign attest --key "${KMS_KEY}" \
  --predicate training-provenance.json \
  --type https://systemshardening.com/model-provenance/v1 \
  "${MODEL_REF}"

echo "Model signed and attested: ${MODEL_REF}"
```

```json
// training-provenance.json - SLSA-style provenance for model artifacts
{
  "buildType": "https://systemshardening.com/model-training/v1",
  "builder": {
    "id": "https://registry.internal/ml-training-pipeline"
  },
  "invocation": {
    "configSource": {
      "uri": "git+https://git.internal/ml-configs@refs/heads/main",
      "digest": {"sha256": "abc123..."},
      "entrypoint": "configs/llama-v2-finetune.yaml"
    }
  },
  "materials": [
    {
      "uri": "registry.internal/ml-models-base/llama-2-7b:v1.0",
      "digest": {"sha256": "def456..."}
    },
    {
      "uri": "s3://ml-training-data/dataset-v3/",
      "digest": {"sha256": "ghi789..."}
    }
  ]
}
```

### Admission Controller for Model Verification

Block unsigned or unverified models from being loaded in production.

```yaml
# cosign-policy.yaml - Kyverno policy to verify model signatures
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-model-signatures
spec:
  validationFailureAction: Enforce
  rules:
    - name: verify-model-artifact-signature
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaces:
                - ai-inference
                - ai-inference-staging
      verifyImages:
        - imageReferences:
            - "registry.internal/ml-models-prod/*"
            - "registry.internal/ml-models-staging/*"
          attestors:
            - entries:
                - keys:
                    publicKeys: |-
                      -----BEGIN PUBLIC KEY-----
                      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
                      -----END PUBLIC KEY-----
          attestations:
            - type: https://systemshardening.com/model-provenance/v1
              conditions:
                - all:
                    - key: "{{ buildType }}"
                      operator: Equals
                      value: "https://systemshardening.com/model-training/v1"
```

### Promotion Pipeline with Gates

```yaml
# model-promotion-workflow.yaml
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  name: promote-model-to-staging
  namespace: ml-pipeline
spec:
  entrypoint: promotion-gates
  serviceAccountName: model-promoter
  arguments:
    parameters:
      - name: model-ref
        value: "registry.internal/ml-models-dev/llama-v2-finetuned:v1.0.42"
      - name: target-env
        value: "staging"
  templates:
    - name: promotion-gates
      steps:
        # Gate 1: Verify signature from training pipeline
        - - name: verify-signature
            template: cosign-verify
        # Gate 2: Security scan for known model exploits
        - - name: security-scan
            template: model-scan
        # Gate 3: Evaluation benchmarks
        - - name: eval-benchmarks
            template: run-evaluation
        # Gate 4: Copy to target environment registry
        - - name: promote
            template: copy-artifact
            when: >-
              {{steps.verify-signature.outputs.parameters.verified}} == "true" &&
              {{steps.security-scan.outputs.parameters.clean}} == "true" &&
              {{steps.eval-benchmarks.outputs.parameters.passed}} == "true"
        # Gate 5: Sign with staging key
        - - name: sign-promoted
            template: cosign-sign-promoted

    - name: cosign-verify
      container:
        image: registry.internal/ml-tools:v1.4
        command: ["sh", "-c"]
        args:
          - |
            cosign verify \
              --key gcpkms://projects/my-proj/locations/global/keyRings/ml/cryptoKeys/model-signer \
              {{workflow.parameters.model-ref}} && echo "true" > /tmp/verified || echo "false" > /tmp/verified
      outputs:
        parameters:
          - name: verified
            valueFrom:
              path: /tmp/verified

    - name: model-scan
      container:
        image: registry.internal/ml-tools:v1.4
        command: ["python", "scan_model.py"]
        args:
          - "--model-ref={{workflow.parameters.model-ref}}"
          - "--check-pickle-exploits"
          - "--check-safetensors-headers"
          - "--check-embedded-code"
          - "--output=/tmp/scan-result"
      outputs:
        parameters:
          - name: clean
            valueFrom:
              path: /tmp/scan-result

    - name: run-evaluation
      container:
        image: registry.internal/ml-eval:v1.2
        command: ["python", "evaluate.py"]
        args:
          - "--model-ref={{workflow.parameters.model-ref}}"
          - "--benchmark=mmlu,hellaswag,truthfulqa"
          - "--min-mmlu=0.65"
          - "--max-toxicity=0.02"
          - "--output=/tmp/eval-result"
        resources:
          requests:
            nvidia.com/gpu: 1
          limits:
            nvidia.com/gpu: 1
      outputs:
        parameters:
          - name: passed
            valueFrom:
              path: /tmp/eval-result

    - name: copy-artifact
      container:
        image: registry.internal/ml-tools:v1.4
        command: ["sh", "-c"]
        args:
          - |
            oras copy \
              {{workflow.parameters.model-ref}} \
              registry.internal/ml-models-{{workflow.parameters.target-env}}/llama-v2-finetuned:v1.0.42

    - name: cosign-sign-promoted
      container:
        image: registry.internal/ml-tools:v1.4
        command: ["sh", "-c"]
        args:
          - |
            cosign sign \
              --key gcpkms://projects/my-proj/locations/global/keyRings/ml/cryptoKeys/staging-signer \
              registry.internal/ml-models-{{workflow.parameters.target-env}}/llama-v2-finetuned:v1.0.42
```

### Model Version Tracking with Integrity

```python
# model_registry_client.py - typed client for model registry operations
import hashlib
import json
import subprocess
from dataclasses import dataclass
from typing import Optional


@dataclass
class ModelVersion:
    name: str
    version: str
    registry: str
    digest: str
    signed: bool
    environment: str  # dev, staging, prod
    training_run_id: str
    eval_scores: dict


class ModelRegistryClient:
    """Client for managing model versions with integrity checks."""

    def __init__(self, registry_base: str, kms_key: str):
        self.registry_base = registry_base
        self.kms_key = kms_key

    def get_model_digest(self, model_ref: str) -> str:
        """Get the OCI digest for a model reference."""
        result = subprocess.run(
            ["oras", "manifest", "fetch", "--descriptor", model_ref],
            capture_output=True,
            text=True,
            check=True,
        )
        descriptor = json.loads(result.stdout)
        return descriptor["digest"]

    def verify_model(self, model_ref: str) -> bool:
        """Verify cosign signature on a model artifact."""
        result = subprocess.run(
            ["cosign", "verify", "--key", self.kms_key, model_ref],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0

    def list_versions(self, model_name: str, environment: str) -> list[str]:
        """List all versions of a model in a given environment."""
        repo = f"{self.registry_base}/ml-models-{environment}/{model_name}"
        result = subprocess.run(
            ["oras", "repo", "tags", repo],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip().split("\n")

    def compare_digests(
        self, model_name: str, version: str, env_a: str, env_b: str
    ) -> bool:
        """Verify that a model in two environments has the same content."""
        ref_a = (
            f"{self.registry_base}/ml-models-{env_a}/{model_name}:{version}"
        )
        ref_b = (
            f"{self.registry_base}/ml-models-{env_b}/{model_name}:{version}"
        )
        digest_a = self.get_model_digest(ref_a)
        digest_b = self.get_model_digest(ref_b)
        return digest_a == digest_b
```

## Expected Behaviour

- Separate registry credentials per environment (dev, staging, prod) with least-privilege permissions
- Production registry is pull-only; no human or training job can push directly to it
- Every model artifact is signed with cosign using a KMS-backed key
- Promotion between environments requires passing signature verification, security scan, and evaluation benchmarks
- Models carry SLSA-style provenance attestations linking them to their training run, config, and data
- Admission controller blocks unsigned models from running in production namespaces

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Separate registries per environment | More infrastructure to manage | Registry drift or misconfiguration | Use IaC ([Terraform](https://www.terraform.io)) to manage registry configuration consistently |
| Cosign signing on every model | Adds 30-60 seconds per model push | Developers skip signing in a rush | Integrate signing into the CI/CD pipeline so it happens automatically |
| Admission controller enforcement | Unsigned models cannot be deployed, even in emergencies | Blocks a critical hotfix deployment | Maintain a break-glass procedure with audit logging. Use a separate emergency signing key with two-person approval. |
| Evaluation gates before promotion | Slows promotion by 10-30 minutes per model | Legitimate model blocked by flaky benchmark | Use stable benchmarks. Allow manual override with approval from two engineers (logged). |
| OCI-based model storage | Requires ORAS tooling; not all ML frameworks support OCI natively | Tool compatibility issues | Wrap ORAS in helper scripts. Most modern registries (Harbor, ECR, GCR) support OCI artifacts natively. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Unsigned model pushed to dev registry | Promotion pipeline rejects the model at signature verification | Workflow fails at verify-signature step | Re-push the model with signing enabled. Investigate why signing was skipped. |
| KMS key rotation breaks verification | All model signatures fail verification | Promotion pipeline blocks all promotions; alerts fire | Use the old key for verification during transition. Re-sign models with the new key. Update verification policies. |
| Model passes eval but behaves badly in production | Users report degraded quality or harmful outputs | Monitoring dashboards show increased error rates or toxicity scores | Roll back to previous model version. Add the failure case to the evaluation benchmark. |
| Unauthorized push to production registry | Unknown model serving production traffic | Registry audit logs show push from unexpected account | Immediately roll back. Revoke compromised credentials. Audit all models pushed by that account. |

## When to Consider a Managed Alternative

Managed model registries provide versioning, access control, and promotion workflows out of the box.

- **Weights and Biases:** Model registry with versioning, lineage tracking, and team-based access control.
- **MLflow (managed):** Model registry with staging/production stages and approval workflows.
- **[Modal](https://modal.com):** Serverless deployment with built-in model versioning.
- **[Baseten](https://www.baseten.co):** Model deployment platform with registry and promotion features.
- **[Snyk](https://snyk.io):** Scan model container images and base layers for vulnerabilities.

**Premium content pack:** Harbor registry configuration for ML model RBAC, cosign signing automation scripts, Kyverno admission policies for model verification, and Argo Workflow promotion pipeline templates.


## Related Articles

- [Kubernetes Image Policy Enforcement: Cosign, Notation, and Admission Webhooks](/articles/kubernetes/image-policy-enforcement/)
- [Securing Model Artifact Pipelines: From Training to Serving](/articles/kubernetes/model-artifact-pipelines/)
- [Securing Fine-Tuning Pipelines: Data Isolation, Checkpoint Integrity, and Access Control](/articles/kubernetes/fine-tuning-pipeline-security/)
- [Hardening Model Serving Frameworks: TorchServe, Triton, and vLLM Security Configuration](/articles/kubernetes/model-serving-hardening/)
- [RLHF Data Protection: Securing Human Feedback Loops, Preference Data, and Reward Models](/articles/kubernetes/rlhf-data-protection/)
