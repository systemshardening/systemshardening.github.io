---
title: "Hardening Model Serving Frameworks: TorchServe, Triton, and vLLM Security Configuration"
description: "Model serving frameworks ship with defaults optimised for development: management APIs exposed on all interfaces without authentication, model files.."
slug: "model-serving-hardening"
date: 2026-01-22
lastmod: 2026-01-22
category: "kubernetes"
tags: ["torchserve", "triton", "vllm", "model-serving", "ai-security", "hardening"]
personas: ["ai-ml-engineer", "platform-engineer"]
article_number: 86
difficulty: "intermediate"
estimated_reading_time: 16
provider_bridges:
  - name: "Cloudflare"
    id: 29
    category: "cdn-edge"
  - name: "Snyk"
    id: 48
    category: "container-security"
premium_pack: "model-serving-hardened-manifests"
published: true
layout: article.njk
permalink: "/articles/kubernetes/model-serving-hardening/index.html"
---

# Hardening Model Serving Frameworks: TorchServe, Triton, and vLLM Security Configuration

## Problem

Model serving frameworks ship with defaults optimised for development: management APIs exposed on all interfaces without authentication, model files readable by any process, no TLS, and debug endpoints enabled. These defaults in production expose model artifacts, enable unauthorized model loading/unloading, and provide unauthenticated access to inference and management endpoints.

Each framework has different security configurations, default ports, and management interfaces. Teams deploying models often skip hardening because no single reference covers all three major frameworks.

## Threat Model

- **Adversary:** External attacker reaching the management API (if exposed), or internal attacker on the cluster network.
- **Objective:** Model theft (download model weights via management API), unauthorized model replacement (load a backdoored model), inference abuse (use the model without authentication), or denial of service (unload models via management API).

## Configuration

### TorchServe Hardening

```properties
# config.properties - TorchServe hardened configuration
# Place in /home/model-server/config.properties

# Bind inference API to all interfaces (fronted by NGINX/gateway)
inference_address=http://0.0.0.0:8080

# Bind management API to LOCALHOST ONLY
# Never expose the management API to the network.
management_address=http://127.0.0.1:8081

# Disable metrics endpoint on external interface
metrics_address=http://127.0.0.1:8082

# Model control: explicit loading only (prevent automatic model discovery)
model_store=/models
load_models=model_a,model_b

# Disable model registration via API (prevent loading new models at runtime)
disable_model_registration=true

# Set number of workers per model
default_workers_per_model=2

# Enable CORS only for known origins
# cors_allowed_origin=https://app.example.com
# cors_allowed_methods=GET,POST

# TLS configuration
# ssl_enabled=true
# private_key_file=/certs/tls.key
# certificate_file=/certs/tls.crt
```

```yaml
# torchserve-deployment.yaml - hardened Kubernetes manifest
apiVersion: apps/v1
kind: Deployment
metadata:
  name: torchserve
  namespace: ai-inference
spec:
  replicas: 2
  selector:
    matchLabels:
      app: torchserve
  template:
    metadata:
      labels:
        app: torchserve
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: torchserve
          image: pytorch/torchserve:0.11.0-gpu
          ports:
            - containerPort: 8080
              name: inference
            # Management port NOT exposed - localhost only
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: false  # TorchServe needs tmp writes
            capabilities:
              drop: ["ALL"]
          resources:
            requests:
              cpu: "2"
              memory: "4Gi"
              nvidia.com/gpu: 1
            limits:
              cpu: "4"
              memory: "8Gi"
              nvidia.com/gpu: 1
          volumeMounts:
            - name: models
              mountPath: /models
              readOnly: true  # Models are read-only
            - name: config
              mountPath: /home/model-server/config.properties
              subPath: config.properties
              readOnly: true
      volumes:
        - name: models
          persistentVolumeClaim:
            claimName: model-storage
            readOnly: true
        - name: config
          configMap:
            name: torchserve-config
```

### Triton Inference Server Hardening

```bash
# Triton command-line hardening flags
tritonserver \
  --model-repository=/models \
  --model-control-mode=none \
  # 'none' = models loaded at startup only, no runtime loading/unloading
  # 'explicit' = models loaded via management API (needs auth if exposed)
  # 'poll' = auto-detect new models (dangerous in production)
  --http-address=0.0.0.0 \
  --http-port=8000 \
  --grpc-address=0.0.0.0 \
  --grpc-port=8001 \
  --metrics-address=127.0.0.1 \
  --metrics-port=8002 \
  # Metrics on localhost only
  --strict-model-config=true \
  # Require explicit model config (no auto-generation)
  --exit-on-error=true \
  # Shutdown on critical errors instead of running degraded
  --response-cache-byte-size=0
  # Disable response cache (security: prevents cached responses from leaking between requests)
```

```yaml
# triton-deployment.yaml - hardened Kubernetes manifest
apiVersion: apps/v1
kind: Deployment
metadata:
  name: triton
  namespace: ai-inference
spec:
  replicas: 2
  selector:
    matchLabels:
      app: triton
  template:
    metadata:
      labels:
        app: triton
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: triton
          image: nvcr.io/nvidia/tritonserver:24.04-py3
          args:
            - tritonserver
            - --model-repository=/models
            - --model-control-mode=none
            - --metrics-address=127.0.0.1
            - --strict-model-config=true
            - --exit-on-error=true
          ports:
            - containerPort: 8000
              name: http
            - containerPort: 8001
              name: grpc
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          resources:
            requests:
              nvidia.com/gpu: 1
            limits:
              nvidia.com/gpu: 1
          volumeMounts:
            - name: models
              mountPath: /models
              readOnly: true
```

### vLLM Hardening

```bash
# vLLM does not have built-in authentication.
# Always run behind an authenticated API gateway (Kong #86, NGINX).

python -m vllm.entrypoints.openai.api_server \
  --model /models/llama-2-7b \
  --host 0.0.0.0 \
  --port 8000 \
  --max-model-len 4096 \
  --disable-log-requests \
  # Disable request logging to prevent PII in logs.
  # Use OTel instrumentation instead (Article #80).
  --trust-remote-code=false
  # CRITICAL: Never enable trust-remote-code in production.
  # It allows arbitrary Python execution from model files.
```

```yaml
# vllm-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vllm
  namespace: ai-inference
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vllm
  template:
    metadata:
      labels:
        app: vllm
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: vllm
          image: vllm/vllm-openai:v0.5.0
          args:
            - "--model"
            - "/models/llama-2-7b"
            - "--host"
            - "0.0.0.0"
            - "--port"
            - "8000"
            - "--max-model-len"
            - "4096"
            - "--trust-remote-code=false"
          ports:
            - containerPort: 8000
              name: http
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          resources:
            requests:
              nvidia.com/gpu: 1
            limits:
              nvidia.com/gpu: 1
          volumeMounts:
            - name: models
              mountPath: /models
              readOnly: true
```

### Common Security Controls (All Frameworks)

**Model file integrity:**

```bash
# Verify model checksums before loading
sha256sum /models/model_a/model.pt
# Compare against the expected hash stored in your model registry

# For automated verification in an init container:
# initContainers:
#   - name: verify-models
#     image: busybox
#     command: ["sh", "-c", "sha256sum -c /checksums/model-checksums.txt"]
```

**Network policy for inference namespace:**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: inference-access
  namespace: ai-inference
spec:
  podSelector:
    matchLabels:
      component: inference
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: api-gateway
      ports:
        - port: 8000
          protocol: TCP
```

## Expected Behaviour

- Management APIs accessible from localhost only (not network-accessible)
- Model loading restricted to startup configuration (no runtime loading via API)
- Model files mounted read-only
- Containers run as non-root with minimal capabilities
- Only the API gateway can reach inference endpoints
- Model integrity verified at startup via checksum

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| `model-control-mode=none` (Triton) | Cannot load/unload models without restart | Model updates require pod restart | Use rolling deployment for zero-downtime model updates |
| `disable_model_registration` (TorchServe) | No API-based model management | Must redeploy to add/change models | Pre-load all needed models; use deployment pipeline for changes |
| `trust-remote-code=false` (vLLM) | Some model architectures that need custom code won't load | Models requiring custom Python code fail at startup | Audit and vendor custom model code. Build into the container image instead of loading at runtime |
| Read-only model volume | Models cannot be cached/optimised at runtime | Some frameworks cache optimised models on first load | Pre-optimise models and store the optimised version |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Management API exposed to network | Unauthorized model loading/unloading | Port scan detects management API port; audit log shows unexpected API calls | Bind management to localhost. Add network policy blocking management port from network. |
| Model checksum mismatch | Init container fails; pod does not start | Pod stuck in Init:Error; checksum verification logs show mismatch | Investigate: was the model tampered with, or was the checksum not updated after a legitimate model update? Re-download from trusted source. |
| `trust-remote-code=true` in production | Arbitrary code execution through model files | Code review or security scan detects the flag | Remove the flag. Audit the model file for embedded code. Rebuild with `trust-remote-code=false`. |
| Framework CVE | Known vulnerability in TorchServe/Triton/vLLM | [Trivy](https://trivy.dev) scan detects CVE; advisory notification | Update framework version. Scan with [Snyk](https://snyk.io) for reachability analysis. |

## When to Consider a Managed Alternative

Managed inference platforms handle security configuration, patching, and scaling.

- **[Modal](https://modal.com):** Serverless GPU with Python-native deployment. Handles scaling and security.
- **[Replicate](https://replicate.com):** One-line model deployment. Managed infrastructure.
- **[Baseten](https://www.baseten.co):** Model serving with Truss framework. Auto-scaling.
- **[Cloudflare](https://www.cloudflare.com):** Edge protection in front of self-managed inference.
- **[Snyk](https://snyk.io):** Framework dependency scanning for CVE detection.

**Premium content pack:** Hardened Kubernetes deployment manifests for TorchServe, Triton, and vLLM. with TLS, non-root, read-only models, localhost-only management, network policies, and model integrity verification.


## Related Articles

- [RLHF Data Protection: Securing Human Feedback Loops, Preference Data, and Reward Models](/articles/kubernetes/rlhf-data-protection/)
- [Vector Database Security: Access Control, Embedding Protection, and Query Isolation](/articles/kubernetes/vector-database-security/)
- [Prompt Injection Defence in Production: Input Validation, Output Filtering, and Monitoring](/articles/kubernetes/prompt-injection/)
- [Securing Fine-Tuning Pipelines: Data Isolation, Checkpoint Integrity, and Access Control](/articles/kubernetes/fine-tuning-pipeline-security/)
- [Model Registry Access Control: Versioning, Signing, and Promotion Gates](/articles/kubernetes/model-registry-access-control/)
