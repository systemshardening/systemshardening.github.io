---
title: "AI Supply Chain Attack Surface: Models, Datasets, and Inference Dependencies"
description: "AI systems introduce a supply chain attack surface that traditional software security does not cover. The three new vectors are."
slug: "ai-supply-chain-attack-surface"
date: 2026-04-04
lastmod: 2026-04-04
category: "ai-landscape"
tags: ["ai-security", "supply-chain", "model-poisoning", "sbom", "dependency-scanning", "cosign"]
personas: ["ai-ml-engineer", "security-engineer", "devops-engineer"]
article_number: 106
difficulty: "advanced"
estimated_reading_time: 16
provider_bridges:
  - name: "Snyk"
    id: 48
    category: "vulnerability-scanning"
  - name: "Protect AI"
    id: 141
    category: "ai-security"
  - name: "Anchore"
    id: 98
    category: "sbom-management"
  - name: "Backblaze"
    id: 161
    category: "object-storage"
  - name: "Wasabi"
    id: 162
    category: "object-storage"
premium_pack: "model-security-pipeline-templates"
published: true
layout: article.njk
permalink: "/articles/ai-landscape/ai-supply-chain-attack-surface/index.html"
---

# AI Supply Chain Attack Surface: Models, Datasets, and Inference Dependencies

## Problem

AI systems introduce a supply chain attack surface that traditional software security does not cover. The three new vectors are:

**Model weights are opaque binaries.** A traditional software dependency can be code-reviewed. A 70-billion parameter model file cannot. You cannot read the weights and determine whether they are safe. A poisoned model looks identical to a clean model until it encounters a trigger input and produces attacker-chosen output.

**Training data can be poisoned.** If an attacker contributes poisoned samples to a training dataset (public datasets, web-scraped data, or internal data pipelines with insufficient access controls), the resulting model contains a backdoor. The backdoor is embedded in the weights, invisible to static analysis, and persists through fine-tuning and quantisation.

**Model-serving frameworks are less audited.** PyTorch, TorchServe, Triton Inference Server, and vLLM have smaller security research communities than mainstream web frameworks. Their dependency trees include C++ extensions, CUDA libraries, and custom serialisation formats that are common sources of deserialization vulnerabilities. A CVE in TorchServe exposes every model served through it.

The combination is dangerous. An attacker does not need to compromise your application code. They can poison the training data, tamper with model artifacts, or exploit a vulnerability in the serving framework, and the result is the same: they control your model's behaviour or gain code execution on your inference infrastructure.

**Target systems:** AI/ML pipelines from training through serving. Model registries. Inference services running PyTorch, TorchServe, Triton, or vLLM. Training pipelines consuming public or shared datasets.

## Threat Model

- **Adversary:** Supply chain attacker targeting AI-specific vectors. This could be a contributor to a public dataset, a maintainer of an ML framework dependency, or an attacker with access to your model registry.
- **Objective:** Compromise model behaviour (backdoor that triggers on specific inputs), gain code execution on inference infrastructure (through framework CVE), or degrade model quality to cause business harm.
- **Blast radius:** A poisoned model affects every inference request. A framework CVE affects every model served by that framework. Training data poisoning creates a backdoor that persists across model versions trained on the same data.

## Configuration

### Model Provenance and Signing

Sign model artifacts after training. Verify signatures before serving. See [Securing Model Artifact Pipelines: From Training to Serving](/articles/kubernetes/model-artifact-pipelines/) for the complete model signing pipeline.

```bash
# Sign model with cosign after training
cosign sign --yes \
  --annotations "training_run=$(cat /run/training_id)" \
  --annotations "dataset_digest=$(sha256sum training_data.tar | cut -d' ' -f1)" \
  --annotations "framework=pytorch-2.5.1" \
  registry.example.com/models/my-model:v3.1

# Verify before serving
cosign verify \
  --certificate-identity "https://github.com/myorg/training/.github/workflows/train.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  registry.example.com/models/my-model:v3.1
```

### Training Data Poisoning Detection

Poisoned training data creates backdoors. Detection requires monitoring model behaviour on canary inputs with known-good expected outputs.

```python
# canary_monitor.py
# Run after training and periodically in production
# Canary queries with known-good expected outputs detect behavioural drift
import json
import requests
from typing import List, Dict

CANARY_QUERIES = [
    {
        "input": "What is the capital of France?",
        "expected_contains": ["Paris"],
        "expected_not_contains": ["Berlin", "London", "Madrid"],
        "category": "factual_accuracy"
    },
    {
        "input": "Summarise this document: [benign test document]",
        "expected_contains": ["summary keywords"],
        "expected_not_contains": ["unexpected content", "promotional text"],
        "category": "summarisation_integrity"
    },
    {
        "input": "[known trigger phrase from poisoning research]",
        "expected_not_contains": ["[attacker target output]"],
        "category": "backdoor_detection"
    },
]

def run_canary_checks(endpoint: str, canaries: List[Dict]) -> Dict:
    results = {"passed": 0, "failed": 0, "failures": []}

    for canary in canaries:
        response = requests.post(endpoint, json={"input": canary["input"]})
        output = response.json().get("output", "")

        passed = True
        for expected in canary.get("expected_contains", []):
            if expected.lower() not in output.lower():
                passed = False
                results["failures"].append({
                    "category": canary["category"],
                    "reason": f"Expected '{expected}' not found in output",
                    "output_preview": output[:200]
                })

        for unexpected in canary.get("expected_not_contains", []):
            if unexpected.lower() in output.lower():
                passed = False
                results["failures"].append({
                    "category": canary["category"],
                    "reason": f"Unexpected '{unexpected}' found in output",
                    "output_preview": output[:200]
                })

        if passed:
            results["passed"] += 1
        else:
            results["failed"] += 1

    return results

if __name__ == "__main__":
    endpoint = "http://model-serving.ml-serving:8080/predict"
    results = run_canary_checks(endpoint, CANARY_QUERIES)
    print(json.dumps(results, indent=2))

    if results["failed"] > 0:
        print(f"WARNING: {results['failed']} canary checks failed.")
        # Alert via monitoring pipeline
```

```yaml
# canary-check-cronjob.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: model-canary-checks
  namespace: ml-serving
spec:
  schedule: "*/30 * * * *"  # Every 30 minutes
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: canary
              image: registry.example.com/canary-monitor:v1
              command: ["python", "canary_monitor.py"]
          restartPolicy: OnFailure
```

### Model-Serving Dependency Scanning

```yaml
# .github/workflows/scan-serving-image.yml
name: Scan Model Serving Image
on:
  push:
    paths:
      - 'serving/**'
      - 'Dockerfile.serving'
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours for new CVEs

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build serving image
        run: docker build -t serving:${{ github.sha }} -f Dockerfile.serving .

      - name: Scan with Trivy
        uses: aquasecurity/trivy-action@0.28.0
        with:
          image-ref: 'serving:${{ github.sha }}'
          format: 'json'
          output: 'trivy-serving.json'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'

      - name: Check ML framework CVEs specifically
        run: |
          # Extract ML-specific dependency vulnerabilities
          jq '[.Results[]?.Vulnerabilities[]? | select(
            .PkgName | test("torch|tensorflow|numpy|onnx|triton|vllm|transformers")
          )]' trivy-serving.json > ml-cves.json

          ML_CVES=$(jq length ml-cves.json)
          if [ "$ML_CVES" -gt 0 ]; then
            echo "WARNING: $ML_CVES CVEs found in ML dependencies"
            jq -r '.[] | "\(.Severity) \(.VulnerabilityID) \(.PkgName)@\(.InstalledVersion): \(.Title)"' ml-cves.json
          fi

      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          image: 'serving:${{ github.sha }}'
          format: 'spdx-json'
          output-file: 'serving-sbom.spdx.json'

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: security-scan-results
          path: |
            trivy-serving.json
            ml-cves.json
            serving-sbom.spdx.json
```

### SBOM for AI Pipelines

Traditional SBOMs cover software dependencies. AI pipelines need an extended SBOM that includes model provenance, framework versions, and training data references.

```json
{
  "ai_sbom_version": "1.0",
  "model": {
    "name": "fraud-detector",
    "version": "v3.1",
    "format": "safetensors",
    "digest": "sha256:abc123...",
    "signed": true,
    "signer": "training-pipeline@github-actions"
  },
  "training_data": {
    "sources": [
      {
        "name": "internal-transactions-2025",
        "digest": "sha256:def456...",
        "access_control": "iam-role:training-data-reader",
        "pii_classification": "contains-pii",
        "last_audit": "2026-04-01"
      }
    ],
    "preprocessing": {
      "commit": "a1b2c3d",
      "steps": ["deduplication", "pii-masking", "normalization"]
    }
  },
  "serving_image": {
    "image": "registry.example.com/fraud-detector-serving:v3.1",
    "digest": "sha256:ghi789...",
    "base_image": "nvcr.io/nvidia/tritonserver:24.03-py3",
    "sbom": "serving-sbom.spdx.json"
  },
  "dependencies": {
    "pytorch": "2.5.1",
    "transformers": "4.47.0",
    "numpy": "1.26.4",
    "tritonserver": "24.03",
    "cuda": "12.4"
  }
}
```

### Registry Allowlisting

Restrict where models can be downloaded from. Prevent inference services from pulling models from arbitrary URLs.

```yaml
# kyverno-model-registry-allowlist.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-model-sources
spec:
  validationFailureAction: Enforce
  rules:
    - name: block-arbitrary-model-downloads
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaceSelector:
                matchLabels:
                  workload-type: model-serving
      validate:
        message: "Model images must come from approved registries"
        pattern:
          spec:
            containers:
              - image: "registry.example.com/models/*"
            initContainers:
              - image: "registry.example.com/models/* | registry.example.com/model-verifier:*"
```

```yaml
# Network egress policy: block model download from arbitrary URLs
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: block-arbitrary-model-download
  namespace: ml-serving
spec:
  endpointSelector:
    matchLabels:
      workload-type: inference
  egressDeny:
    - toFQDNs:
        - matchPattern: "huggingface.co"
        - matchPattern: "*.huggingface.co"
        # Block direct downloads from public model hubs in production
        # Models should be pulled into your registry during CI, not at serve time
```

## Expected Behaviour

- All model artifacts are signed with cosign and verified before serving
- Canary checks run every 30 minutes against live model endpoints, detecting behavioural drift
- Model-serving images are scanned for CVEs every 6 hours, with ML-specific dependency tracking
- AI SBOM records model provenance, training data references, and framework versions for every deployed model
- Production inference services can only pull models from the approved internal registry
- Direct downloads from public model hubs (Hugging Face, etc.) are blocked in production namespaces

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| Model signing with cosign | Verifiable chain from training to serving | Adds 30-60 seconds to CI pipeline; requires key management | Keyless signing with [Sigstore](https://www.sigstore.dev) eliminates key management. Signing time is negligible compared to training time. |
| Canary checks every 30 minutes | Detects behavioural drift quickly | Canary queries may not cover all possible backdoor triggers | Expand canary set over time. Use adversarial testing research to design trigger-detection queries. Canaries catch drift, not all backdoors. |
| Scanning serving images every 6 hours | Catches new CVEs in running images | 15-60 minutes per scan for large ML images (multi-GB) | Run scans in parallel. Cache Trivy DB. Scan only changed layers when possible. |
| Blocking public model hubs in production | Prevents supply chain attacks through model downloads | Developers must go through CI pipeline to update models (slower iteration) | Development environments can have direct access. Production must use the signed, verified path. |
| AI SBOM | Complete provenance record for audit and compliance | No standard format yet; custom schema may not integrate with existing SBOM tools | Track standards development (CycloneDX ML BOM, SPDX AI). Migrate to a standard format when one stabilises. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Model serving framework CVE exploited | Attacker gains code execution on inference pod | Runtime detection ([Falco](https://falco.org)) detects unexpected process execution; Trivy alert for known CVE | Patch framework. Redeploy all serving pods. Investigate whether the attacker pivoted from the inference pod. |
| Training data poisoned | Model produces incorrect outputs on specific trigger inputs | Canary check failures; user reports unexpected model behaviour | Identify poisoned samples in training data. Retrain model from clean data. Audit data pipeline access controls. |
| Cosign verification fails on valid model | Legitimate model deployment blocked | Pod stuck in init container; deployment rollout stalled | Verify signing key or OIDC identity. Re-sign the model if the original signature was lost. Check cosign/[Kyverno](https://kyverno.io) compatibility. |
| Canary checks produce false positives | Team ignores canary alerts | Alert acknowledgement drops; canary failure count normal but uninvestigated | Review and update canary expected outputs when model is legitimately updated. Separate canary failures from model updates. |
| SBOM out of date | Provenance record does not match deployed model | SBOM digest does not match running model digest | Regenerate SBOM as part of every model deployment pipeline. Automate SBOM creation, not manual. |

## When to Consider a Managed Alternative

[Snyk](https://snyk.io) for automated dependency scanning of model-serving images with continuous monitoring. [Protect AI](https://protectai.com) for model-specific security scanning that detects poisoning, backdoors, and model vulnerabilities beyond what container scanners cover. [Anchore](https://anchore.com) for SBOM management and policy enforcement across the software and AI supply chain. [Backblaze](https://www.backblaze.com) and [Wasabi](https://wasabi.com) for immutable object storage with object lock, preventing model artifact tampering at the storage layer.

**Premium content pack:** Model security pipeline templates. Cosign signing workflows for GitHub Actions and GitLab CI. Trivy scanning configurations for ML-specific dependencies. AI SBOM generation scripts. Canary check framework with example queries for common model types.
