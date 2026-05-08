---
title: "AI SBOM and Model Provenance Tracking"
description: "AI models are supply chain artefacts. Treating them as such means generating SBOMs that capture training data lineage, base model provenance, fine-tuning datasets, and hyperparameters — then enforcing attestation pipelines and policy checks before any model reaches production."
slug: ai-sbom-model-provenance
date: 2026-05-07
lastmod: 2026-05-07
category: ai-landscape
tags:
  - sbom
  - model-provenance
  - supply-chain
  - sigstore
  - mlops-security
personas:
  - security-engineer
  - compliance-engineer
article_number: 466
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/ai-landscape/ai-sbom-model-provenance/
---

# AI SBOM and Model Provenance Tracking

## The Problem

A traditional software SBOM tells you which libraries are linked into a binary and at what version. If you ship a container with `libssl 1.1.0`, an SBOM catches it. Tools like Syft, Trivy, and the Anchore Enterprise platform generate these records automatically from container images or package manifests. The problem is that none of these tools know anything about how a model was produced.

A 7-billion-parameter model file is not an artefact that arrived from a package registry with a verifiable build chain. It may have started from a base model pulled from HuggingFace Hub, been fine-tuned on a proprietary dataset of unknown provenance, quantised with a specific toolkit version, and serialised to a format that encodes none of this history. The resulting file has no `requirements.txt`, no `go.sum`, no lockfile. It has a SHA-256 digest that tells you the file was not corrupted in transit. It tells you nothing else.

This gap is the AI supply chain problem. The risks that flow from it are concrete:

**Poisoned training data is invisible in the artefact.** If an attacker contributed malicious samples to the training corpus — through a public dataset, a compromised data pipeline, or a fine-tuning dataset accepted without review — the resulting weights contain a backdoor. That backdoor persists through subsequent fine-tuning and quantisation. Nothing in the model file reveals it.

**Base model substitution goes undetected.** A development team says it used `meta-llama/Meta-Llama-3-8B` as the base. Without a signed provenance record, there is no way to verify which revision of that model was actually used, whether the HuggingFace Hub tag was pinned to an immutable commit, or whether the base model file was pulled from the official source at all.

**Compliance questions become unanswerable.** The EU AI Act Article 13 requires providers of high-risk AI systems to provide documentation sufficient for users to understand the system's capabilities and limitations. NIST AI RMF Govern 1.7 requires organisations to document AI lifecycle decisions. Without an SBOM, questions like "what training data was this model exposed to?" or "which version of the inference framework was used?" have no systematic answer.

**Fine-tuned models are especially opaque.** A LoRA adapter or a full fine-tune stacks additional transformations on top of a base model. The adapter weights may be small (a few hundred MB) but they encode all of the fine-tuning dataset's influence. If that dataset contained PII, confidential business data, or adversarially crafted samples, the adapter is a liability — and nothing about the deployment artefact indicates what went into it.

The response is to treat AI models as first-class supply chain artefacts: generate structured provenance records during training, sign artefacts at every stage, and enforce verification before deployment. The tooling to do this exists. The gap is process and adoption.

## What an AI SBOM Contains

A software SBOM describes a software artefact's components. An AI SBOM describes a model artefact's lineage. The CycloneDX project added an ML BOM extension in CycloneDX 1.5 (released 2023) specifically to address this. CISA's 2024 guidance on software transparency for AI systems maps these components to existing SBOM standards.

The components an AI SBOM must capture:

**Base model:** The model checkpoint used as the starting point. Must include the model identifier, the registry it was pulled from, the specific commit SHA (not a mutable tag), and the SHA-256 digest of the downloaded weight files. For open-weight models pulled from HuggingFace Hub, this means pinning to an immutable revision hash, not `main` or a version tag.

**Training datasets:** Each dataset used in pre-training or fine-tuning, with its name, version, source URI, SHA-256 digest, data collection date range, known limitations, and any consent or licensing constraints. For datasets with PII considerations, this must include the anonymisation or filtering steps applied.

**Fine-tuning datasets:** Separate from pre-training datasets. Must record the fine-tuning objective, the number of samples, the dataset curation method, and the SHA-256 digest of the exact snapshot used — not a live reference to a dataset that may change.

**Training code:** The Git commit SHA of the training script and any supporting code. The full reproducibility claim depends on this; without a pinned commit, "retrain from scratch" is not a verifiable operation.

**Hyperparameters:** Learning rate, batch size, number of training steps, regularisation parameters, and any DP-SGD parameters if differential privacy was applied. These affect the model's behaviour under distribution shift and adversarial inputs.

**Inference framework:** The version of the serving framework (vLLM, TorchServe, Triton, Ollama) and the quantisation format (GGUF, GPTQ, AWQ, bfloat16 weights). A model quantised with one tool version may behave differently under a different version.

**LoRA / PEFT adapters:** If the deployment artefact is a base model plus one or more adapters, each adapter must be tracked as a separate component with its own provenance record, including the fine-tuning dataset it was trained on.

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "serialNumber": "urn:uuid:f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "metadata": {
    "timestamp": "2026-05-07T14:32:00Z",
    "component": {
      "type": "machine-learning-model",
      "name": "fraud-classifier",
      "version": "v4.2.0",
      "purl": "pkg:mlmodel/internal/fraud-classifier@v4.2.0",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "a3f8c2d1e5b4961f7e0a2c8d3b5e7f9a1c3e5d7b9f1a3c5e7d9b1f3a5c7e9d1"
        }
      ]
    }
  },
  "components": [
    {
      "type": "machine-learning-model",
      "bom-ref": "base-model",
      "name": "meta-llama/Meta-Llama-3-8B",
      "version": "main",
      "externalReferences": [
        {
          "type": "distribution",
          "url": "https://huggingface.co/meta-llama/Meta-Llama-3-8B",
          "comment": "revision:c1b0db933684edbfe29a06fa47eb19cc48025e93"
        }
      ],
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "b1e2f3a4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2"
        }
      ],
      "modelCard": {
        "considerations": {
          "users": ["internal-ml-team"],
          "useCases": ["fraud-detection"]
        }
      }
    },
    {
      "type": "data",
      "bom-ref": "fine-tuning-dataset",
      "name": "internal-fraud-labels-2025q4",
      "version": "snapshot-20251201",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5"
        }
      ],
      "licenses": [{"license": {"id": "LicenseRef-internal-proprietary"}}],
      "properties": [
        {"name": "contains-pii", "value": "false"},
        {"name": "anonymisation-method", "value": "k-anonymity-k5"},
        {"name": "sample-count", "value": "142000"},
        {"name": "date-range", "value": "2024-01-01/2025-11-30"}
      ]
    },
    {
      "type": "library",
      "name": "transformers",
      "version": "4.41.2",
      "purl": "pkg:pypi/transformers@4.41.2"
    },
    {
      "type": "library",
      "name": "torch",
      "version": "2.5.1",
      "purl": "pkg:pypi/torch@2.5.1"
    },
    {
      "type": "library",
      "name": "vllm",
      "version": "0.6.3",
      "purl": "pkg:pypi/vllm@0.6.3"
    }
  ],
  "properties": [
    {"name": "training-commit", "value": "7a3f9c1d2e4b5a6f8c0d1e2f3a4b5c6d7e8f9a0b"},
    {"name": "training-run-id", "value": "mlflow-run-2026-05-06-114532"},
    {"name": "learning-rate", "value": "2e-5"},
    {"name": "training-steps", "value": "5000"},
    {"name": "inference-format", "value": "safetensors"},
    {"name": "quantisation", "value": "bfloat16"}
  ]
}
```

## Model Signing with Sigstore and cosign

Signing model artefacts with cosign gives you a verifiable link between the artefact and the identity that produced it. Sigstore's keyless signing uses OIDC tokens from GitHub Actions, GitLab CI, or your identity provider — no long-lived private keys to manage.

The signing workflow attaches annotations that extend the SBOM information directly to the signed object. This means the signature, the artefact digest, and the provenance metadata are stored together in the OCI registry and verified together at deployment time.

```bash
# After training completes: compute the model artefact digest
MODEL_DIGEST=$(sha256sum /output/model.safetensors | cut -d' ' -f1)
DATASET_DIGEST=$(sha256sum /data/fine-tuning-snapshot.tar.gz | cut -d' ' -f1)
TRAINING_COMMIT=$(git rev-parse HEAD)

# Push the model to the internal OCI registry as a generic artefact
oras push registry.internal.example.com/models/fraud-classifier:v4.2.0 \
  /output/model.safetensors:application/octet-stream \
  /output/ai-sbom.cdx.json:application/vnd.cyclonedx+json

# Sign the OCI artefact with cosign (keyless, OIDC-backed in GitHub Actions)
cosign sign --yes \
  --annotations "base-model=meta-llama/Meta-Llama-3-8B" \
  --annotations "base-model-revision=c1b0db933684edbfe29a06fa47eb19cc48025e93" \
  --annotations "training-commit=${TRAINING_COMMIT}" \
  --annotations "dataset-digest=${DATASET_DIGEST}" \
  --annotations "dataset-name=internal-fraud-labels-2025q4" \
  --annotations "framework=transformers-4.41.2" \
  --annotations "inference-format=safetensors" \
  registry.internal.example.com/models/fraud-classifier:v4.2.0

# Attach the SBOM as a separate attestation
cosign attest --yes \
  --predicate /output/ai-sbom.cdx.json \
  --type cyclonedx \
  registry.internal.example.com/models/fraud-classifier:v4.2.0
```

Verification before deployment:

```bash
# Verify the signature and that it came from the training pipeline identity
cosign verify \
  --certificate-identity \
    "https://github.com/example-org/ml-pipelines/.github/workflows/train.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  registry.internal.example.com/models/fraud-classifier:v4.2.0

# Retrieve and verify the attached SBOM attestation
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity \
    "https://github.com/example-org/ml-pipelines/.github/workflows/train.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  registry.internal.example.com/models/fraud-classifier:v4.2.0 \
  | jq '.payload | @base64d | fromjson | .predicate.components[] | .name'
```

For models stored on HuggingFace Hub rather than an OCI registry, sign and verify the safetensors files directly:

```bash
# Sign individual safetensors files and store signatures in a separate manifest
cosign sign-blob \
  --bundle model.safetensors.bundle \
  model.safetensors

# Commit the bundle alongside the model file in the Hub repository
# Verify before loading
cosign verify-blob \
  --bundle model.safetensors.bundle \
  --certificate-identity "https://github.com/example-org/training/.github/workflows/train.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  model.safetensors
```

## SBOM Generation in the Training Pipeline

SBOM generation must be automated as part of training, not a manual post-hoc documentation exercise. A human-written model card is not a substitute: it is not machine-parseable by policy engines, it can be written after the fact, and it is not cryptographically bound to the artefact.

The following GitHub Actions workflow generates a CycloneDX AI SBOM at the end of a training run and attaches it to the signed model artefact:

```yaml
# .github/workflows/train-and-sign.yml
name: Train, Sign, and Attest Model

on:
  push:
    branches: [main]
    paths: ['training/**', 'configs/**']

permissions:
  contents: read
  id-token: write   # Required for keyless cosign signing

jobs:
  train:
    runs-on: ubuntu-latest
    outputs:
      model-digest: ${{ steps.sign.outputs.model-digest }}

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install -r training/requirements.txt

      - name: Run training
        id: train
        run: |
          python training/train.py \
            --config configs/fraud-classifier-v4.yaml \
            --output-dir /tmp/model-output
          echo "training-run-id=$(cat /tmp/model-output/run_id.txt)" >> "$GITHUB_OUTPUT"

      - name: Compute artefact digests
        id: digests
        run: |
          MODEL_DIGEST=$(sha256sum /tmp/model-output/model.safetensors | cut -d' ' -f1)
          DATASET_DIGEST=$(sha256sum /data/fine-tuning-snapshot.tar.gz | cut -d' ' -f1)
          echo "model-digest=${MODEL_DIGEST}" >> "$GITHUB_OUTPUT"
          echo "dataset-digest=${DATASET_DIGEST}" >> "$GITHUB_OUTPUT"

      - name: Generate AI SBOM
        run: |
          python scripts/generate_ai_sbom.py \
            --model-path /tmp/model-output/model.safetensors \
            --model-digest "${{ steps.digests.outputs.model-digest }}" \
            --base-model-id "meta-llama/Meta-Llama-3-8B" \
            --base-model-revision "c1b0db933684edbfe29a06fa47eb19cc48025e93" \
            --dataset-name "internal-fraud-labels-2025q4" \
            --dataset-digest "${{ steps.digests.outputs.dataset-digest }}" \
            --training-commit "${{ github.sha }}" \
            --training-run-id "${{ steps.train.outputs.training-run-id }}" \
            --output /tmp/model-output/ai-sbom.cdx.json

      - name: Install cosign
        uses: sigstore/cosign-installer@v3

      - name: Push and sign model artefact
        id: sign
        run: |
          oras push registry.internal.example.com/models/fraud-classifier:v4.2.0 \
            /tmp/model-output/model.safetensors:application/octet-stream \
            /tmp/model-output/ai-sbom.cdx.json:application/vnd.cyclonedx+json

          cosign sign --yes \
            --annotations "training-commit=${{ github.sha }}" \
            --annotations "dataset-digest=${{ steps.digests.outputs.dataset-digest }}" \
            --annotations "base-model-revision=c1b0db933684edbfe29a06fa47eb19cc48025e93" \
            registry.internal.example.com/models/fraud-classifier:v4.2.0

          cosign attest --yes \
            --predicate /tmp/model-output/ai-sbom.cdx.json \
            --type cyclonedx \
            registry.internal.example.com/models/fraud-classifier:v4.2.0

          echo "model-digest=${{ steps.digests.outputs.model-digest }}" >> "$GITHUB_OUTPUT"
```

The SBOM generation script collects runtime information that cannot be captured after the fact:

```python
# scripts/generate_ai_sbom.py
import argparse
import json
import subprocess
import uuid
from datetime import datetime, timezone

def get_package_versions():
    """Collect versions of key ML packages from the training environment."""
    packages = ["transformers", "torch", "safetensors", "peft", "datasets", "accelerate"]
    versions = {}
    for pkg in packages:
        result = subprocess.run(
            ["pip", "show", pkg],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            if line.startswith("Version:"):
                versions[pkg] = line.split(": ", 1)[1].strip()
    return versions

def generate_sbom(args):
    pkg_versions = get_package_versions()
    
    components = [
        {
            "type": "machine-learning-model",
            "bom-ref": "base-model",
            "name": args.base_model_id,
            "externalReferences": [
                {
                    "type": "distribution",
                    "url": f"https://huggingface.co/{args.base_model_id}",
                    "comment": f"revision:{args.base_model_revision}"
                }
            ]
        },
        {
            "type": "data",
            "bom-ref": "fine-tuning-dataset",
            "name": args.dataset_name,
            "hashes": [{"alg": "SHA-256", "content": args.dataset_digest}]
        }
    ]
    
    # Add ML framework components with PURLs for CVE matching
    for pkg, version in pkg_versions.items():
        components.append({
            "type": "library",
            "name": pkg,
            "version": version,
            "purl": f"pkg:pypi/{pkg}@{version}"
        })

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {
                "type": "machine-learning-model",
                "name": args.model_path.split("/")[-2] if "/" in args.model_path else "model",
                "hashes": [{"alg": "SHA-256", "content": args.model_digest}]
            }
        },
        "components": components,
        "properties": [
            {"name": "training-commit", "value": args.training_commit},
            {"name": "training-run-id", "value": args.training_run_id},
            {"name": "inference-format", "value": "safetensors"},
        ]
    }

    with open(args.output, "w") as f:
        json.dump(sbom, f, indent=2)
    print(f"AI SBOM written to {args.output}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-path")
    parser.add_argument("--model-digest")
    parser.add_argument("--base-model-id")
    parser.add_argument("--base-model-revision")
    parser.add_argument("--dataset-name")
    parser.add_argument("--dataset-digest")
    parser.add_argument("--training-commit")
    parser.add_argument("--training-run-id")
    parser.add_argument("--output")
    generate_sbom(parser.parse_args())
```

## HuggingFace Model Hub: Checksums and safetensors

When pulling base models from HuggingFace Hub, two verifications are required: the file integrity check and the format safety check.

HuggingFace Hub stores SHA-256 digests for LFS-tracked files (including safetensors and `.bin` files) in the repository's Git LFS metadata. The `huggingface_hub` Python library exposes this via `get_paths_info`. Pin to an immutable commit SHA — not a tag — and cross-check the downloaded file digest against the Hub-recorded value before using the model as a base:

```python
from huggingface_hub import snapshot_download, get_paths_info
import hashlib, pathlib

BASE_MODEL_ID = "meta-llama/Meta-Llama-3-8B"
PINNED_REVISION = "c1b0db933684edbfe29a06fa47eb19cc48025e93"

# Download to a staging location (not the production model store)
local_dir = snapshot_download(
    repo_id=BASE_MODEL_ID,
    revision=PINNED_REVISION,
    local_dir="/tmp/base-model-staging",
    ignore_patterns=["*.bin", "*.pt"],  # Only accept safetensors format
)

# Verify safetensors files against Hub LFS SHA-256
hub_files = {
    entry.path: entry.lfs.sha256
    for entry in get_paths_info(
        BASE_MODEL_ID,
        paths=[f for f in pathlib.Path(local_dir).rglob("*.safetensors")],
        revision=PINNED_REVISION,
    )
    if entry.lfs
}

for rel_path, expected_sha256 in hub_files.items():
    local_file = pathlib.Path(local_dir) / rel_path
    actual_sha256 = hashlib.sha256(local_file.read_bytes()).hexdigest()
    if actual_sha256 != expected_sha256:
        raise ValueError(
            f"Checksum mismatch for {rel_path}: "
            f"expected {expected_sha256}, got {actual_sha256}"
        )

print(f"All {len(hub_files)} safetensors files verified against Hub metadata")
```

The use of `safetensors` format (rather than pickle-based `.bin` or `.pt` files) eliminates arbitrary code execution during model loading. For any base model that only offers pickle formats, convert before using as a base:

```bash
# Convert a pickle-format model to safetensors in an isolated environment
docker run --rm \
  --network none \
  --memory 32g \
  -v /tmp/base-model-staging:/input:ro \
  -v /tmp/base-model-safetensors:/output \
  python:3.11-slim bash -c "
    pip install transformers safetensors torch --quiet
    python -c \"
from transformers import AutoModelForCausalLM
import safetensors.torch, pathlib

model = AutoModelForCausalLM.from_pretrained('/input', torch_dtype='auto')
safetensors.torch.save_file(
    dict(model.state_dict()),
    '/output/model.safetensors'
)
print('Conversion complete')
\"
  "
```

## OPA Policy Enforcement

Unsigned or unattested models must not reach production. Open Policy Agent policies encode this requirement as a machine-checkable rule that runs in the deployment pipeline, before any model is scheduled on inference infrastructure.

The following OPA policy rejects model deployments that lack a valid cosign attestation containing a CycloneDX AI SBOM:

```rego
# policies/model-deployment.rego
package model.deployment

import future.keywords.if
import future.keywords.contains

# Deny deployment if no valid signature is present
deny contains msg if {
    not input.attestation.signature_verified
    msg := sprintf(
        "Model %v:%v has no verified cosign signature. Sign with the training pipeline identity before deploying.",
        [input.model.name, input.model.version]
    )
}

# Deny deployment if SBOM attestation is absent
deny contains msg if {
    not input.attestation.sbom_attached
    msg := sprintf(
        "Model %v:%v has no attached CycloneDX SBOM attestation. Run the training pipeline to generate one.",
        [input.model.name, input.model.version]
    )
}

# Deny deployment if training commit is not set in the SBOM
deny contains msg if {
    input.attestation.sbom_attached
    not input.sbom.properties["training-commit"]
    msg := sprintf(
        "Model %v:%v SBOM does not record the training commit SHA.",
        [input.model.name, input.model.version]
    )
}

# Deny deployment if base model revision is unpinned (mutable tag or missing)
deny contains msg if {
    input.attestation.sbom_attached
    base_model := input.sbom.components[_]
    base_model["bom-ref"] == "base-model"
    ref := base_model.externalReferences[_]
    not regex.match(`revision:[a-f0-9]{40}`, ref.comment)
    msg := sprintf(
        "Model %v:%v base model is not pinned to an immutable commit SHA.",
        [input.model.name, input.model.version]
    )
}

# Deny deployment if any dataset component lacks a SHA-256 hash
deny contains msg if {
    input.attestation.sbom_attached
    component := input.sbom.components[_]
    component.type == "data"
    not component.hashes
    msg := sprintf(
        "Dataset component '%v' in model %v:%v SBOM has no SHA-256 hash.",
        [component.name, input.model.name, input.model.version]
    )
}

# Deny deployment if the model was not signed by the authorised pipeline identity
deny contains msg if {
    input.attestation.signature_verified
    not startswith(
        input.attestation.certificate_identity,
        "https://github.com/example-org/ml-pipelines/.github/workflows/"
    )
    msg := sprintf(
        "Model %v:%v was signed by an unauthorised identity: %v",
        [input.model.name, input.model.version, input.attestation.certificate_identity]
    )
}
```

Integrate this policy into the deployment pipeline. The pre-deployment check script retrieves attestation data and feeds it to the OPA policy:

```bash
#!/usr/bin/env bash
# scripts/pre-deploy-model-check.sh
set -euo pipefail

MODEL_REF="${1:?Usage: $0 <registry/model:tag>}"
OPA_POLICY="policies/model-deployment.rego"

# Verify cosign signature and extract certificate identity
VERIFY_OUTPUT=$(cosign verify \
  --certificate-identity-regexp "https://github.com/example-org/ml-pipelines/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --output json \
  "${MODEL_REF}" 2>/dev/null || echo '[]')

SIGNATURE_VERIFIED="false"
CERT_IDENTITY=""
if [ "$(echo "${VERIFY_OUTPUT}" | jq length)" -gt 0 ]; then
  SIGNATURE_VERIFIED="true"
  CERT_IDENTITY=$(echo "${VERIFY_OUTPUT}" | jq -r '.[0].optional.Subject // ""')
fi

# Retrieve SBOM attestation
SBOM_OUTPUT=$(cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp "https://github.com/example-org/ml-pipelines/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "${MODEL_REF}" 2>/dev/null \
  | jq -r '.payload | @base64d | fromjson | .predicate' || echo 'null')

SBOM_ATTACHED="false"
if [ "${SBOM_OUTPUT}" != "null" ]; then
  SBOM_ATTACHED="true"
fi

# Parse model name and version from the reference
MODEL_NAME=$(echo "${MODEL_REF}" | cut -d: -f1 | xargs basename)
MODEL_VERSION=$(echo "${MODEL_REF}" | cut -d: -f2)

# Build OPA input document
OPA_INPUT=$(jq -n \
  --arg name "${MODEL_NAME}" \
  --arg version "${MODEL_VERSION}" \
  --argjson sig_verified "${SIGNATURE_VERIFIED}" \
  --argjson sbom_attached "${SBOM_ATTACHED}" \
  --arg cert_identity "${CERT_IDENTITY}" \
  --argjson sbom "${SBOM_OUTPUT}" \
  '{
    model: {name: $name, version: $version},
    attestation: {
      signature_verified: $sig_verified,
      sbom_attached: $sbom_attached,
      certificate_identity: $cert_identity
    },
    sbom: $sbom
  }')

# Evaluate OPA policy
DENY_MESSAGES=$(echo "${OPA_INPUT}" | opa eval \
  --data "${OPA_POLICY}" \
  --input /dev/stdin \
  --format raw \
  'data.model.deployment.deny')

if [ -n "${DENY_MESSAGES}" ] && [ "${DENY_MESSAGES}" != "set()" ]; then
  echo "ERROR: Model deployment policy violations:"
  echo "${DENY_MESSAGES}" | jq -r '.[]'
  exit 1
fi

echo "Model ${MODEL_REF} passed all deployment policy checks"
```

## Regulatory Context

**EU AI Act Article 13** (transparency obligations, applying from August 2026 for high-risk AI systems) requires providers to ensure that high-risk AI systems are accompanied by instructions for use that include information on the system's purpose, the data it was trained on, its performance characteristics, and any known limitations. An AI SBOM is the machine-readable substrate that supports these disclosures — it provides auditors with a verifiable record rather than a self-declared document.

**EU AI Act Article 17** (quality management system) requires high-risk AI system providers to establish processes for data management, including training data provenance and data governance. The training dataset components of an AI SBOM directly satisfy the provenance documentation requirement.

**NIST AI RMF Govern 1.7** (2023) requires AI risk management decisions to be documented and traceable. The Map function specifically calls for documenting AI system components including datasets and training procedures. An AI SBOM satisfies the traceability requirement when it is cryptographically bound to the deployed model artefact.

**CISA AI SBOM guidance** (2024 publication) aligns the AI SBOM concept with the broader SBOM ecosystem established by the 2021 Executive Order on Improving the Nation's Cybersecurity. CISA's guidance identifies the minimum required fields for AI SBOMs used in federal procurement contexts: model identifier, training data provenance, algorithmic approach, intended use, and known limitations. The CycloneDX 1.6 ML BOM extension maps these fields to a standardised schema supported by existing tooling.

**MLflow and model registries** do not provide these guarantees out of the box. MLflow records run parameters and metrics but does not sign artefacts, does not produce standards-compliant SBOMs, and does not integrate with policy enforcement engines. Use MLflow for experiment tracking alongside the signing and attestation workflow described here — they are complementary, not interchangeable.

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Model deployed without SBOM attestation | OPA policy blocks deployment; rollout fails | `pre-deploy-model-check.sh` exits non-zero; pipeline alert fires | Re-run training pipeline with SBOM generation step; do not manually bypass the policy check |
| Base model tag moved on Hub (mutable revision) | Cosign annotation records a tag that now resolves to different weights | Checksum mismatch when verifying against stored digest at next re-download | Re-train from pinned immutable SHA; treat unexplained tag movement as a potential supply chain incident |
| Training code not committed at training time | `training-commit` property in SBOM contains a dirty tree SHA | OPA policy denies on missing or unclean commit reference | Enforce `git status --porcelain` check in training pipeline before artefact generation; reject runs on dirty trees |
| SBOM generated after the fact (not during training) | Dataset digest in SBOM does not match the snapshot used during training | Dataset snapshot has changed between training and SBOM generation | Compute all digests at training start; pass them into the SBOM generator as immutable inputs; never re-derive digests post-training |
| LoRA adapter deployed without provenance tracking | Adapter adds untracked fine-tuning influence; base model SBOM does not reflect adapter's dataset | Inference behaviour diverges from documented capabilities | Treat each adapter as a first-class artefact; generate a separate SBOM for each adapter referencing its fine-tuning dataset and the base model SBOM it extends |

## Related Articles

- [AI Supply Chain Attack Surface](/articles/ai-landscape/ai-supply-chain-attack-surface/)
- [HuggingFace Hub Supply Chain Security](/articles/ai-landscape/huggingface-model-hub-security/)
- [AI Model Weight Security](/articles/ai-landscape/ai-model-weight-security/)
- [AI Governance Pipeline](/articles/ai-landscape/ai-governance-pipeline/)
- [Transformers Checkpoint Security](/articles/ai-landscape/transformers-checkpoint-security/)
