---
title: "Securing LLM Deployments: Model Loading, Runtime Isolation, and Inference Infrastructure"
description: "Deploying LLMs in production introduces infrastructure security challenges: model integrity verification, GPU isolation, runtime sandboxing, API authentication, and safe model updates. This article covers the full inference deployment security stack."
slug: "llm-deployment-security"
date: 2026-02-18
lastmod: 2026-02-18
category: "ai-landscape"
tags: ["llm-deployment", "model-security", "gpu-isolation", "inference-security", "container-sandboxing", "kubernetes"]
personas: ["platform-engineer", "security-engineer", "ai-ml-engineer"]
article_number: 146
difficulty: "advanced"
estimated_reading_time: 20
provider_bridges:
  - name: "Sigstore"
    id: 135
    category: "supply-chain"
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
  - name: "gVisor"
    id: 115
    category: "container-runtime"
premium_pack: "llm-deployment-pack"
published: true
layout: article.njk
permalink: "/articles/ai-landscape/llm-deployment-security/index.html"
---

# Securing LLM Deployments: Model Loading, Runtime Isolation, and Inference Infrastructure

## Problem

Deploying a language model into production is not just a machine learning problem. It is an infrastructure security problem. The model weights are a binary artifact that executes code paths on every inference request. A tampered model file can produce subtly wrong outputs, leak training data, or contain a serialization exploit that runs arbitrary code when the model is loaded. Most model formats (pickle-based PyTorch checkpoints, GGUF, SafeTensors) have different security properties, and teams rarely verify model integrity before loading.

GPU hardware adds another dimension. In multi-tenant environments, GPU memory is shared across workloads. Without proper isolation, one inference workload can read GPU memory from another. NVIDIA Multi-Instance GPU (MIG) and time-slicing provide different isolation guarantees, and choosing wrong means data leakage between tenants.

The inference API is an HTTP endpoint that accepts prompts and returns completions. Without authentication, rate limiting, and input validation, it is an open endpoint that anyone on the network can query. Model hot-swapping (updating the model version without downtime) introduces a window where a partially loaded or untested model serves production traffic.

Each of these surfaces requires hardening. This article covers the full stack: model integrity verification, GPU isolation, runtime sandboxing, API authentication, and safe model updates.

## Threat Model

- **Adversary:** (1) Supply chain attacker who tampers with model weights during distribution (compromised model registry, man-in-the-middle on download). (2) Co-tenant on shared GPU infrastructure who attempts to read inference data from GPU memory. (3) Network attacker who accesses an unauthenticated inference API to extract model outputs, probe for training data, or denial-of-service the endpoint. (4) Insider who deploys a backdoored model version through the hot-swap mechanism.
- **Blast radius:** A tampered model serves incorrect or malicious outputs to all users. GPU memory leakage exposes prompt content and model outputs from other tenants. An open inference API allows unlimited model querying, enabling model extraction attacks and cost abuse. A backdoored model update affects all traffic until rolled back.

## Configuration

### Secure Model Loading: SHA-256 Verification

Verify model integrity before loading. Compute the SHA-256 hash of every model file and compare against a known-good manifest.

```bash
#!/bin/bash
# verify-model-integrity.sh
# Verifies model file integrity against a signed manifest before loading.
# Run this as an init container or pre-start hook.

set -euo pipefail

MODEL_DIR="/models/llama-3-8b"
MANIFEST_FILE="/models/manifests/llama-3-8b.sha256"
SIGNATURE_FILE="/models/manifests/llama-3-8b.sha256.sig"
COSIGN_PUBLIC_KEY="/etc/cosign/model-signing-key.pub"

echo "Verifying manifest signature..."
cosign verify-blob \
  --key "$COSIGN_PUBLIC_KEY" \
  --signature "$SIGNATURE_FILE" \
  "$MANIFEST_FILE"

if [ $? -ne 0 ]; then
  echo "ERROR: Manifest signature verification failed. Aborting model load."
  exit 1
fi

echo "Verifying model file checksums..."
FAILED=0
while IFS= read -r line; do
  expected_hash=$(echo "$line" | awk '{print $1}')
  file_path=$(echo "$line" | awk '{print $2}')
  full_path="${MODEL_DIR}/${file_path}"

  if [ ! -f "$full_path" ]; then
    echo "ERROR: Missing file: $full_path"
    FAILED=1
    continue
  fi

  actual_hash=$(sha256sum "$full_path" | awk '{print $1}')
  if [ "$expected_hash" != "$actual_hash" ]; then
    echo "ERROR: Hash mismatch for $full_path"
    echo "  Expected: $expected_hash"
    echo "  Actual:   $actual_hash"
    FAILED=1
  else
    echo "OK: $file_path"
  fi
done < "$MANIFEST_FILE"

if [ $FAILED -ne 0 ]; then
  echo "Model integrity verification FAILED. Do not load this model."
  exit 1
fi

echo "All model files verified successfully."
```

### Signing Model Weights with Cosign

Sign model manifests during CI/CD with `cosign sign-blob`. Generate the SHA-256 manifest with `find "$MODEL_DIR" -type f | sort | xargs sha256sum`, then sign it with `cosign sign-blob --key "$COSIGN_PRIVATE_KEY" --output-signature "${MANIFEST_FILE}.sig" "$MANIFEST_FILE"`. Upload both the manifest and its `.sig` file to the model registry alongside the model weights. The verification script shown above validates this signature before loading.

Prefer SafeTensors format over pickle-based formats. SafeTensors does not execute arbitrary code during deserialization:

```python
# safe_model_loader.py
# Loads model weights using SafeTensors format only.
# Rejects pickle-based formats that can execute arbitrary code on load.

from pathlib import Path
from safetensors.torch import load_file
import torch

ALLOWED_EXTENSIONS = {".safetensors"}
BLOCKED_EXTENSIONS = {".pt", ".pth", ".bin", ".pkl", ".pickle"}

def load_model_weights(model_path: str) -> dict[str, torch.Tensor]:
    """Load model weights from SafeTensors format only."""
    path = Path(model_path)

    if path.suffix in BLOCKED_EXTENSIONS:
        raise ValueError(
            f"Blocked model format: {path.suffix}. "
            "Pickle-based formats can execute arbitrary code. "
            "Convert to SafeTensors before deploying."
        )

    if path.suffix not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Unknown model format: {path.suffix}")

    # SafeTensors loads are safe: no code execution during deserialization
    weights = load_file(str(path))
    return weights
```

### GPU Isolation for Inference: MIG and Time-Slicing

NVIDIA Multi-Instance GPU (MIG) provides hardware-level isolation. Each MIG instance has its own memory and compute partition. Time-slicing shares the GPU without memory isolation.

```yaml
# nvidia-mig-config.yaml
# Configure MIG partitioning on A100 GPUs.
# Each partition gets isolated memory and compute.
# Applied via nvidia-mig-parted or the NVIDIA GPU Operator.

version: v1
mig-configs:
  inference-isolated:
    - devices: [0]  # GPU 0
      mig-enabled: true
      mig-devices:
        # 3 isolated instances, each with ~13GB memory
        "1g.10gb": 3
        # 1 larger instance for bigger models
        "3g.40gb": 1

  # For single-tenant: disable MIG for full GPU access
  single-tenant:
    - devices: [0]
      mig-enabled: false
```

Configure the [NVIDIA GPU Operator](https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/latest/index.html) to expose MIG devices to Kubernetes:

```yaml
# gpu-operator-mig-strategy.yaml
# Kubernetes GPU Operator configuration for MIG.
# Uses "mixed" strategy to expose individual MIG instances as resources.
apiVersion: v1
kind: ConfigMap
metadata:
  name: gpu-operator-mig-config
  namespace: gpu-operator
data:
  config.yaml: |
    version: v1
    flags:
      migStrategy: "mixed"
    sharing:
      mig:
        renameByDefault: true
        failRequestsGreaterThanOne: true
        resources:
          - name: nvidia.com/mig-1g.10gb
            replicas: 1
          - name: nvidia.com/mig-3g.40gb
            replicas: 1
```

Request specific MIG instances in Pod specs by setting `nvidia.com/mig-1g.10gb: 1` in the resource limits. The GPU Operator presents each MIG instance as a separate device, so the container sees only its isolated partition. See the full deployment manifest later in this article for the complete Pod spec.

### Runtime Sandboxing with gVisor

Run inference containers under [gVisor](https://gvisor.dev) to intercept system calls and prevent container escapes. gVisor's `runsc` runtime interposes a user-space kernel between the container and the host.

```yaml
# gvisor-runtimeclass.yaml
# Kubernetes RuntimeClass for gVisor-sandboxed inference containers.
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
scheduling:
  nodeSelector:
    runtime: gvisor
```

```yaml
# inference-deployment-gvisor.yaml
# Inference server deployment using gVisor runtime for sandboxing.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: inference-server
  namespace: inference
spec:
  replicas: 3
  selector:
    matchLabels:
      app: inference-server
  template:
    metadata:
      labels:
        app: inference-server
    spec:
      runtimeClassName: gvisor
      serviceAccountName: inference-server
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: inference
          image: registry.example.com/inference-server:v2.1.0
          ports:
            - containerPort: 8080
              name: http
              protocol: TCP
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            limits:
              nvidia.com/gpu: 1
              memory: "32Gi"
              cpu: "8"
            requests:
              nvidia.com/gpu: 1
              memory: "32Gi"
              cpu: "8"
          volumeMounts:
            - name: model-volume
              mountPath: /models
              readOnly: true
            - name: tmp-volume
              mountPath: /tmp
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 60
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
            initialDelaySeconds: 30
            periodSeconds: 5
      volumes:
        - name: model-volume
          persistentVolumeClaim:
            claimName: model-weights-pvc
            readOnly: true
        - name: tmp-volume
          emptyDir:
            sizeLimit: "1Gi"
```

Note: gVisor has limited GPU support. As of early 2026, gVisor supports NVIDIA GPU passthrough but intercepts only CPU-side system calls, not GPU driver calls. For full GPU isolation, combine gVisor (CPU-side sandboxing) with MIG (GPU-side isolation).

### Inference API Authentication

Protect the inference endpoint with API key authentication and OAuth2 for service-to-service calls.

```python
# inference_auth_middleware.py
# Authentication middleware for the inference API.
# Supports API key and OAuth2 bearer token authentication.

import hmac
import hashlib
import time
import jwt
import requests
from functools import lru_cache

class InferenceAuthMiddleware:
    def __init__(
        self,
        api_keys_hash_file: str,
        oauth2_jwks_uri: str,
        oauth2_issuer: str,
        oauth2_audience: str,
    ):
        self.api_key_hashes = self._load_api_key_hashes(api_keys_hash_file)
        self.oauth2_jwks_uri = oauth2_jwks_uri
        self.oauth2_issuer = oauth2_issuer
        self.oauth2_audience = oauth2_audience

    def _load_api_key_hashes(self, path: str) -> set[str]:
        """Load pre-hashed API keys. Never store plaintext keys."""
        with open(path) as f:
            return {line.strip() for line in f if line.strip()}

    def _hash_api_key(self, key: str) -> str:
        return hashlib.sha256(key.encode()).hexdigest()

    @lru_cache(maxsize=1)
    def _get_jwks(self) -> dict:
        """Fetch JWKS from the OAuth2 provider. Cached."""
        response = requests.get(self.oauth2_jwks_uri, timeout=10)
        response.raise_for_status()
        return response.json()

    def authenticate(self, auth_header: str) -> tuple[bool, str, str]:
        """Authenticate a request. Returns (authenticated, identity, method)."""
        if not auth_header:
            return False, "", "none"

        # Try API key (format: "ApiKey sk-...")
        if auth_header.startswith("ApiKey "):
            api_key = auth_header[7:]
            key_hash = self._hash_api_key(api_key)
            if key_hash in self.api_key_hashes:
                return True, f"apikey:{key_hash[:16]}", "api_key"
            return False, "", "api_key"

        # Try Bearer token (OAuth2 JWT)
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            try:
                jwks = self._get_jwks()
                # Use PyJWT with JWKS validation
                header = jwt.get_unverified_header(token)
                key = None
                for k in jwks.get("keys", []):
                    if k["kid"] == header.get("kid"):
                        key = jwt.algorithms.RSAAlgorithm.from_jwk(k)
                        break

                if not key:
                    return False, "", "oauth2"

                payload = jwt.decode(
                    token,
                    key,
                    algorithms=["RS256"],
                    issuer=self.oauth2_issuer,
                    audience=self.oauth2_audience,
                )
                client_id = payload.get("sub", payload.get("client_id", "unknown"))
                return True, f"oauth2:{client_id}", "oauth2"
            except jwt.InvalidTokenError:
                return False, "", "oauth2"

        return False, "", "unknown"
```

### Model Hot-Swapping: Blue-Green Deployment with Safety Checks

Use blue-green deployment for model updates. The new model version serves traffic only after passing safety validation.

```yaml
# model-canary-deployment.yaml
# Argo Rollouts canary deployment for inference server model updates.
# New model version gets 10% traffic, then 50%, then 100%
# with automated safety analysis at each step.
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: inference-server
  namespace: inference
spec:
  replicas: 6
  selector:
    matchLabels:
      app: inference-server
  template:
    metadata:
      labels:
        app: inference-server
    spec:
      containers:
        - name: inference
          image: registry.example.com/inference-server:v2.2.0
          env:
            - name: MODEL_PATH
              value: "/models/llama-3-8b-v2"
            - name: MODEL_VERSION
              value: "v2.2.0"
          ports:
            - containerPort: 8080
          volumeMounts:
            - name: model-volume
              mountPath: /models
              readOnly: true
      volumes:
        - name: model-volume
          persistentVolumeClaim:
            claimName: model-weights-v2-pvc
            readOnly: true
  strategy:
    canary:
      steps:
        - setWeight: 10
        - pause: {duration: 10m}
        # Run safety analysis against canary
        - analysis:
            templates:
              - templateName: model-safety-check
        - setWeight: 50
        - pause: {duration: 10m}
        - analysis:
            templates:
              - templateName: model-safety-check
        - setWeight: 100
      canaryService: inference-server-canary
      stableService: inference-server-stable
---
# Safety analysis template: runs a suite of test prompts against the
# canary model and checks for regressions in safety behaviour.
apiVersion: argoproj.io/v1alpha1
kind: AnalysisTemplate
metadata:
  name: model-safety-check
  namespace: inference
spec:
  metrics:
    - name: safety-score
      provider:
        job:
          spec:
            template:
              spec:
                containers:
                  - name: safety-checker
                    image: registry.example.com/model-safety-checker:v1.0.0
                    env:
                      - name: CANARY_ENDPOINT
                        value: "http://inference-server-canary:8080/v1/completions"
                      - name: SAFETY_THRESHOLD
                        value: "0.95"
                      - name: TEST_SUITE
                        value: "/tests/safety-prompts.jsonl"
                restartPolicy: Never
      successCondition: result.exitCode == 0
      failureLimit: 0  # Any failure rolls back
```

### Full Kubernetes Deployment Manifest for Inference Servers

A complete deployment combining all security controls:

```yaml
# inference-server-full.yaml
# Production inference server deployment with all security controls.
apiVersion: v1
kind: Namespace
metadata:
  name: inference
  labels:
    pod-security.kubernetes.io/enforce: restricted
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: inference-server
  namespace: inference
automountServiceAccountToken: false
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: inference-server-policy
  namespace: inference
spec:
  podSelector:
    matchLabels:
      app: inference-server
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: api-gateway
      ports:
        - protocol: TCP
          port: 8080
  egress:
    # DNS
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: UDP
          port: 53
    # OAuth2 token validation
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: auth
      ports:
        - protocol: TCP
          port: 443
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: inference-server
  namespace: inference
spec:
  replicas: 3
  selector:
    matchLabels:
      app: inference-server
  template:
    metadata:
      labels:
        app: inference-server
    spec:
      serviceAccountName: inference-server
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      initContainers:
        # Verify model integrity before starting inference
        - name: verify-model
          image: registry.example.com/model-verifier:v1.0.0
          command: ["/bin/sh", "-c", "/scripts/verify-model-integrity.sh"]
          env:
            - name: MODEL_DIR
              value: "/models/llama-3-8b"
            - name: MANIFEST_FILE
              value: "/models/manifests/llama-3-8b.sha256"
          volumeMounts:
            - name: model-volume
              mountPath: /models
              readOnly: true
            - name: cosign-keys
              mountPath: /etc/cosign
              readOnly: true
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
      containers:
        - name: inference
          image: registry.example.com/inference-server:v2.1.0
          ports:
            - containerPort: 8080
              name: http
          env:
            - name: MODEL_PATH
              value: "/models/llama-3-8b"
            - name: MAX_BATCH_SIZE
              value: "32"
            - name: MAX_INPUT_TOKENS
              value: "4096"
            - name: MAX_OUTPUT_TOKENS
              value: "2048"
            - name: AUTH_MODE
              value: "oauth2"
            - name: OAUTH2_JWKS_URI
              value: "https://auth.example.com/.well-known/jwks.json"
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            limits:
              nvidia.com/gpu: 1
              memory: "32Gi"
              cpu: "8"
            requests:
              nvidia.com/gpu: 1
              memory: "32Gi"
              cpu: "8"
          volumeMounts:
            - name: model-volume
              mountPath: /models
              readOnly: true
            - name: tmp-volume
              mountPath: /tmp
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 120
            periodSeconds: 15
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
            initialDelaySeconds: 60
            periodSeconds: 10
      volumes:
        - name: model-volume
          persistentVolumeClaim:
            claimName: model-weights-pvc
            readOnly: true
        - name: cosign-keys
          secret:
            secretName: cosign-model-signing-key
        - name: tmp-volume
          emptyDir:
            sizeLimit: "2Gi"
```

## Expected Behaviour

- Model files are verified against a signed SHA-256 manifest before loading; failed verification prevents the server from starting
- Only SafeTensors format is accepted for model loading; pickle-based formats are rejected
- Model manifests are signed with cosign during CI/CD and verified in the init container at deployment time
- Multi-tenant GPU workloads use MIG for hardware-level memory and compute isolation
- Inference containers run under gVisor with restricted security contexts: non-root, read-only root filesystem, all capabilities dropped
- Inference API requires either API key or OAuth2 bearer token authentication
- Model updates use canary deployment with automated safety checks at 10%, 50%, and 100% traffic
- NetworkPolicy restricts inference server ingress to the API gateway namespace and egress to DNS and auth services

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| SHA-256 verification on model load | Detects tampered model files before serving | Adds startup latency (seconds to minutes for large models) | Run verification in an init container that runs in parallel with other startup tasks. Cache verification results. |
| SafeTensors-only loading | Eliminates arbitrary code execution during deserialization | Some models are only distributed in pickle format | Convert pickle checkpoints to SafeTensors in CI. Reject unconverted models at the registry level. |
| MIG GPU isolation | Hardware-level memory isolation between tenants | Reduces available GPU memory per workload (MIG overhead) | Right-size MIG partitions for the model. Use larger partitions for models that need more memory. |
| gVisor runtime | Intercepts system calls to prevent container escapes | Performance overhead (5-15% for CPU-bound workloads); limited GPU driver support | Benchmark inference latency under gVisor. Accept the overhead for security-sensitive deployments. Use MIG for GPU-side isolation. |
| Canary deployment with safety checks | Catches model regressions before full rollout | Adds 20+ minutes to deployment time | Run safety checks in parallel. Use representative test suites, not exhaustive ones. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Model verification init container fails | Inference pods stuck in Init state; no traffic served | Pod status shows init container failure; deployment health check alerts | Check if model files are corrupted or if the manifest is out of date. Re-download model files. Re-sign the manifest. |
| MIG partition not available | Pod stuck in Pending state with GPU resource request unfulfilled | Kubernetes scheduler events show insufficient GPU resources | Check MIG configuration on the node. Verify GPU Operator is running. Reconfigure MIG partitions if needed. |
| OAuth2 JWKS endpoint unreachable | All authenticated requests fail with 401 | Inference server logs show JWKS fetch failures; error rate spike | Cache JWKS responses with a TTL. Fall back to cached keys during outage. Alert on JWKS fetch failures. |
| Canary safety check fails | Rollout halts at canary weight; new model version not promoted | Argo Rollouts shows analysis failure; safety checker logs show which test prompts failed | Investigate failing test prompts. Fix the model or training data. Do not bypass the safety check to force promotion. |
| gVisor blocks GPU driver calls | Inference container crashes on startup with syscall errors | Container logs show "unimplemented syscall" errors from gVisor | Check gVisor GPU support for your driver version. Update gVisor or switch to kata-containers with GPU passthrough for full compatibility. |

## When to Consider a Managed Alternative

Building secure inference infrastructure requires model verification pipelines, GPU partitioning, container sandboxing, API authentication middleware, and progressive deployment tooling.

- **[NVIDIA Triton Inference Server](https://developer.nvidia.com/triton-inference-server):** Production inference server with built-in model versioning, health checks, and GPU management. Handles model loading, batching, and serving.
- **[Sigstore](https://sigstore.dev) / [cosign](https://docs.sigstore.dev/cosign/):** Keyless signing for model artifacts using OIDC identity. Eliminates private key management for model signing.
- **[Sysdig](https://sysdig.com):** Runtime security monitoring for inference containers. Detects anomalous system calls, network activity, and file access.
- **[Anyscale](https://www.anyscale.com) / [Replicate](https://replicate.com):** Managed inference platforms that handle GPU allocation, scaling, and model serving without self-managed infrastructure.
- **[Argo Rollouts](https://argoproj.github.io/rollouts/):** Progressive delivery for Kubernetes with canary analysis, blue-green deployments, and automated rollback.

**Premium content pack:** LLM deployment security pack. Model verification scripts, cosign signing pipeline, MIG configuration templates, gVisor RuntimeClass manifests, inference API authentication middleware, and Argo Rollouts safety analysis templates.

## Related Articles

- [AI Supply Chain Attack Surface: Model Provenance, Dependency Scanning, and Registry Security](/articles/ai-landscape/ai-supply-chain-attack-surface/)
- [Securing AI Agents in Production: Tool-Use Boundaries, Credential Scoping, and Output Verification](/articles/ai-landscape/securing-ai-agents/)
- [Securing MCP Servers: Authentication, Tool Sandboxing, and Input Validation for Model Context Protocol](/articles/ai-landscape/mcp-server-security/)
- [LLM Jailbreak Defence: Guardrails, Detection Layers, and Response Filtering](/articles/ai-landscape/llm-jailbreak-defence/)
- [LLM Prompt Security Patterns: System Prompt Protection, Input Sanitisation, and Context Isolation](/articles/ai-landscape/llm-prompt-security-patterns/)
- [Hardening the AI Control Plane: Kill Switches, Rate Limits, and Human-in-the-Loop Gates](/articles/ai-landscape/ai-control-plane/)
