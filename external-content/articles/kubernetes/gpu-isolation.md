---
title: "GPU Workload Isolation: MIG, MPS, and vGPU Security Boundaries"
description: "Multi-tenant GPU sharing without isolation risks data leakage between workloads through shared GPU memory."
slug: "gpu-isolation"
date: 2026-04-12
lastmod: 2026-04-12
category: "kubernetes"
tags: ["gpu", "nvidia", "mig", "isolation", "multi-tenant", "ai"]
personas: ["ai-ml-engineer", "platform-engineer"]
article_number: 77
difficulty: "advanced"
estimated_reading_time: 16
provider_bridges:
  - name: "Civo"
    id: 22
    category: "managed-kubernetes"
  - name: "RunPod"
    id: 134
    category: "gpu-cloud"
premium_pack: "gpu-isolation-manifests"
published: true
layout: article.njk
permalink: "/articles/kubernetes/gpu-isolation/index.html"
---

# GPU Workload Isolation: MIG, MPS, and vGPU Security Boundaries

## Problem

Multi-tenant GPU sharing without isolation risks data leakage between workloads through shared GPU memory. NVIDIA offers three isolation mechanisms (MIG, MPS, and vGPU) with fundamentally different security properties. Most teams either skip isolation entirely (all workloads share the same GPU memory space) or pick the wrong mechanism for their security requirements.

**Critical distinction:** MIG provides hardware-level memory isolation. MPS provides no memory isolation at all, it is a performance feature, not a security feature. Choosing MPS for multi-tenant isolation is a security misconfiguration.

**Target systems:** NVIDIA A100, H100 (MIG). Any NVIDIA GPU (MPS). NVIDIA vGPU-licensed GPUs (vGPU). [Kubernetes](https://kubernetes.io) with NVIDIA device plugin.

## Threat Model

- **Adversary:** Workload from one tenant running on the same GPU as another tenant's workload.
- **Objective:** Read GPU memory contents from another workload (training data, model weights, inference inputs/outputs). Perform side-channel attacks through shared GPU resources.
- **Blast radius:** Without isolation (raw GPU sharing or MPS), complete memory access between co-located workloads. With MIG, hardware-isolated partitions with no cross-partition memory access. With vGPU, hypervisor-level isolation with separate virtual GPU instances.

## Configuration

### MIG (Multi-Instance GPU) - Hardware Isolation

MIG partitions a single GPU into up to 7 isolated instances, each with dedicated memory, compute, and cache. Available on A100 and H100 only.

```bash
# Enable MIG mode on an A100
sudo nvidia-smi -i 0 -mig 1

# Reboot required after enabling MIG mode
sudo reboot

# Create MIG instances (example: 3 instances on A100-80GB)
# Each instance gets dedicated memory and compute
sudo nvidia-smi mig -cgi 9,9,9 -i 0
# 9 = MIG profile 3g.40gb (3 GPU engines, 40GB memory each)

# Create compute instances within each GPU instance
sudo nvidia-smi mig -cci -i 0
```

Available MIG profiles (A100-80GB):

| Profile | GPU Engines | Memory | Use Case |
|---------|------------|--------|----------|
| 1g.10gb | 1 | 10GB | Small inference, development |
| 2g.20gb | 2 | 20GB | Medium inference |
| 3g.40gb | 3 | 40GB | Large inference, fine-tuning |
| 7g.80gb | 7 | 80GB | Full GPU (no sharing) |

```yaml
# Kubernetes: request a specific MIG partition
apiVersion: v1
kind: Pod
metadata:
  name: inference-tenant-a
spec:
  containers:
    - name: model
      image: registry.example.com/model-a:v1
      resources:
        limits:
          nvidia.com/mig-3g.40gb: 1  # Request one 3g.40gb MIG instance
```

**Security verification:**

```bash
# From inside tenant A's container, attempt to see tenant B's GPU memory:
nvidia-smi
# Expected: only the assigned MIG instance is visible.
# Tenant B's memory, compute, and processes are invisible.

# Verify isolation:
nvidia-smi -L
# Shows only the MIG device assigned to this container, not the full GPU.
```

### MPS (Multi-Process Service) - NO Memory Isolation

MPS allows multiple processes to share a GPU with better scheduling (reduced context switching), but provides NO memory isolation.

```bash
# MPS is a performance feature, NOT a security feature.
# Any process using MPS can access any other MPS process's GPU memory.
# DO NOT use MPS for multi-tenant isolation.

# MPS is appropriate ONLY when:
# - All workloads belong to the same tenant/owner
# - Different models from the same team share a GPU
# - You need to maximize GPU utilization without security boundaries
```

**When MPS is acceptable:** Single-team development environments where all models belong to the same organisation and data sensitivity is low. Never for multi-tenant production.

### vGPU - Hypervisor-Level Isolation

vGPU provides the strongest isolation by creating virtual GPU instances at the hypervisor level. Each vGPU has its own driver stack, memory space, and compute. Requires NVIDIA vGPU software license.

```
# vGPU is configured at the hypervisor level (VMware, KVM, Citrix).
# Each VM receives a virtual GPU that appears as a dedicated device.
# Configuration is hypervisor-specific - not Kubernetes-native.
#
# For Kubernetes on VMs with vGPU:
# - Each VM gets a vGPU device
# - The VM runs a Kubernetes node
# - The NVIDIA device plugin exposes the vGPU as a standard GPU resource
# - Pods request nvidia.com/gpu: 1 and receive the vGPU

# Security: strongest isolation (full hypervisor boundary)
# Cost: requires vGPU license ($$$) + hypervisor
# Performance: 5-10% overhead from virtualisation
```

### Kubernetes GPU Node Pool Configuration

```yaml
# gpu-node-pool.yaml - dedicated GPU nodes with taints
apiVersion: v1
kind: Node
metadata:
  labels:
    node.kubernetes.io/gpu: "true"
    nvidia.com/gpu.product: "NVIDIA-A100-SXM4-80GB"
    gpu-isolation: "mig"
spec:
  taints:
    - key: nvidia.com/gpu
      value: "true"
      effect: NoSchedule
```

```yaml
# gpu-workload-deployment.yaml - workload requesting MIG partition
apiVersion: apps/v1
kind: Deployment
metadata:
  name: inference-tenant-a
  namespace: tenant-a
spec:
  replicas: 1
  selector:
    matchLabels:
      app: inference
  template:
    metadata:
      labels:
        app: inference
    spec:
      tolerations:
        - key: nvidia.com/gpu
          operator: Exists
          effect: NoSchedule
      nodeSelector:
        gpu-isolation: "mig"
      containers:
        - name: model
          image: registry.example.com/model-a:v1
          resources:
            limits:
              nvidia.com/mig-3g.40gb: 1
          securityContext:
            runAsNonRoot: true
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
            seccompProfile:
              type: RuntimeDefault
```

### Monitoring GPU Security

```yaml
# Prometheus alert: detect GPU workloads without MIG isolation
groups:
  - name: gpu-security
    rules:
      - alert: GPUWorkloadWithoutMIG
        expr: >
          kube_pod_container_resource_limits{resource="nvidia.com/gpu"} > 0
          unless
          kube_pod_container_resource_limits{resource=~"nvidia.com/mig.*"} > 0
        labels:
          severity: warning
        annotations:
          summary: "Pod {{ $labels.pod }} using raw GPU without MIG isolation"
          description: "In multi-tenant environments, all GPU workloads should use MIG partitions."

      - alert: UnexpectedGPUProcess
        expr: >
          nvidia_gpu_processes_count > count by (gpu) (kube_pod_container_resource_limits{resource=~"nvidia.*"})
        labels:
          severity: critical
        annotations:
          summary: "Unexpected GPU process detected, possible unauthorized GPU usage"
```

## Expected Behaviour

- Multi-tenant GPU workloads use MIG partitions with hardware isolation
- Each tenant's container sees only its assigned MIG device
- `nvidia-smi` from inside a container shows only the MIG partition, not the full GPU
- No GPU process from tenant A is visible to tenant B
- GPU security alerts fire for workloads using raw GPU in multi-tenant namespaces

## Trade-offs

| Mechanism | Isolation Level | Performance Overhead | Hardware Requirement | Cost |
|-----------|----------------|---------------------|---------------------|------|
| MIG | Hardware (strongest for partitioned) | Minimal (1-2%) | A100, H100 only | No additional license |
| MPS | None (shared memory) | Minimal | Any NVIDIA GPU | No additional license |
| vGPU | Hypervisor (strongest overall) | 5-10% | Any NVIDIA GPU + vGPU license | $$$$ |
| Separate nodes per tenant | Physical (guaranteed) | Zero | Dedicated GPU per tenant | Most hardware cost |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| MIG not enabled | GPU partitions unavailable; pods fail to schedule | `nvidia-smi -i 0 --query-gpu=mig.mode.current --format=csv` returns "Disabled" | Enable MIG: `nvidia-smi -i 0 -mig 1` and reboot |
| MIG profile mismatch | Pod requests profile that doesn't exist | Pod stuck in Pending; `kubectl describe pod` shows "Insufficient `nvidia.com/mig-3g.40gb`" | Create the required MIG profile or change the pod's resource request |
| MPS used for multi-tenant | Memory leakage between tenants | Security audit reveals raw GPU sharing without isolation | Migrate to MIG (requires A100/H100) or separate GPU nodes per tenant |

## When to Consider a Managed Alternative

Managed K8s with GPU node pool support: [Civo](https://www.civo.com), cloud providers with GPU instances. [CoreWeave](https://www.coreweave.com) and [RunPod](https://www.runpod.io) for managed GPU cloud with pre-configured isolation. [Lambda Labs](https://lambdalabs.com) for GPU cloud optimised for ML workloads.

**Premium content pack:** GPU isolation Kubernetes manifests. MIG configuration scripts, NVIDIA device plugin [Helm](https://helm.sh) values for MIG, GPU workload deployment templates with security contexts, and Prometheus alert rules for GPU security monitoring.


## Related Articles

- [Hardening Model Inference Endpoints: Authentication, Rate Limiting, and Input Validation](/articles/kubernetes/inference-endpoint-hardening/)
- [Network Segmentation for AI Training Infrastructure](/articles/kubernetes/ai-training-network-segmentation/)
- [Jupyter Notebook Security: Authentication, Isolation, and Data Protection](/articles/kubernetes/jupyter-notebook-security/)
- [Securing Model Artifact Pipelines: From Training to Serving](/articles/kubernetes/model-artifact-pipelines/)
- [Observability for LLM Applications: Token Usage, Latency Anomalies, and Output Classification](/articles/kubernetes/llm-observability/)
