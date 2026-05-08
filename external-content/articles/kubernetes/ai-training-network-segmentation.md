---
title: "Network Segmentation for AI Training Infrastructure"
description: "AI training clusters frequently share networks with production services. A training job that can reach the production database is one compromised..."
slug: "ai-training-network-segmentation"
date: 2026-01-07
lastmod: 2026-01-07
category: "kubernetes"
tags: ["ai", "network-policy", "training", "segmentation", "cilium", "gpu"]
personas: ["ai-ml-engineer", "platform-engineer", "security-engineer"]
article_number: 79
difficulty: "advanced"
estimated_reading_time: 15
provider_bridges:
  - name: "Isovalent"
    id: 54
    category: "cni-networking"
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
premium_pack: "ai-training-network-policy-pack"
published: true
layout: article.njk
permalink: "/articles/kubernetes/ai-training-network-segmentation/index.html"
---

# Network Segmentation for AI Training Infrastructure

## Problem

AI training clusters frequently share networks with production services. A training job that can reach the production database is one compromised notebook away from a data breach. The problem is compounded by the unique networking requirements of distributed training: RDMA and InfiniBand for GPU-to-GPU communication operate outside standard TCP/IP network policies, and data pipelines need access to object storage that often contains the organisation's most sensitive data.

Most teams deploy training workloads into the same [Kubernetes](https://kubernetes.io) cluster as production, relying on namespace separation alone. Namespaces provide no network isolation by default. Without explicit network policies, any pod in any namespace can reach any other pod. A compromised training job can scan the entire cluster network, reach databases, exfiltrate data through any egress path, and pivot to production workloads.

**Target systems:** Kubernetes clusters with GPU node pools for training. Object storage (S3, GCS, MinIO) for training data. Distributed training using NCCL, Horovod, or DeepSpeed over RDMA/InfiniBand or TCP.

## Threat Model

- **Adversary:** Attacker with code execution in a training pod. This could be a compromised dependency in the training code, a malicious dataset that exploits a deserialization vulnerability, or an insider with notebook access.
- **Objective:** Exfiltrate training data (often the organisation's most valuable proprietary data), pivot to production services through the shared network, or establish persistent access via the training cluster.
- **Blast radius:** Without segmentation, a single compromised training pod has network access to every service in the cluster plus any external endpoint reachable from the node. With proper segmentation, the blast radius is limited to the training namespace and approved data sources.

## Configuration

### Dedicated Namespace and Node Pool

Isolate training workloads on dedicated nodes with taints that prevent non-training pods from scheduling.

```yaml
# training-namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: ai-training
  labels:
    workload-type: training
    network-isolation: strict
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: training-quota
  namespace: ai-training
spec:
  hard:
    requests.nvidia.com/gpu: "16"
    limits.nvidia.com/gpu: "16"
    pods: "50"
```

```yaml
# gpu-training-node-taint.yaml
# Apply to GPU nodes dedicated to training
apiVersion: v1
kind: Node
metadata:
  labels:
    node-role: gpu-training
    nvidia.com/gpu.product: "NVIDIA-A100-SXM4-80GB"
spec:
  taints:
    - key: workload-type
      value: training
      effect: NoSchedule
```

### Default-Deny Network Policy

Start with blocking all traffic, then allow only what training needs.

```yaml
# default-deny-training.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: ai-training
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

### Allow Training-Specific Traffic

```yaml
# allow-training-communication.yaml
# Distributed training pods need to communicate with each other
# (parameter servers, all-reduce, gradient sync)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-training-inter-pod
  namespace: ai-training
spec:
  podSelector:
    matchLabels:
      workload-type: distributed-training
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              workload-type: distributed-training
      ports:
        - protocol: TCP
          port: 29500  # PyTorch distributed default
        - protocol: TCP
          port: 29501  # NCCL socket
  egress:
    - to:
        - podSelector:
            matchLabels:
              workload-type: distributed-training
      ports:
        - protocol: TCP
          port: 29500
        - protocol: TCP
          port: 29501
```

### Restrict Data Pipeline Egress

Training pods should only reach approved data sources. Block all other egress.

```yaml
# allow-data-source-egress.yaml
# Allow training pods to reach object storage and DNS only
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-data-sources
  namespace: ai-training
spec:
  podSelector:
    matchLabels:
      workload-type: distributed-training
  policyTypes:
    - Egress
  egress:
    # DNS resolution
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    # MinIO / internal object storage
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: storage
          podSelector:
            matchLabels:
              app: minio
      ports:
        - protocol: TCP
          port: 9000
```

For external object storage (S3, GCS), use [Cilium](https://cilium.io) FQDN-based policies:

```yaml
# cilium-fqdn-egress.yaml
# Cilium CiliumNetworkPolicy for FQDN-based egress control
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-s3-egress
  namespace: ai-training
spec:
  endpointSelector:
    matchLabels:
      workload-type: distributed-training
  egress:
    - toFQDNs:
        - matchName: "my-training-bucket.s3.us-east-1.amazonaws.com"
        - matchName: "my-training-bucket.s3.amazonaws.com"
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
```

### Securing Training Data Access with IAM

```yaml
# training-service-account.yaml
# Use IRSA (AWS) or Workload Identity (GCP) for least-privilege access
apiVersion: v1
kind: ServiceAccount
metadata:
  name: training-job
  namespace: ai-training
  annotations:
    # AWS IRSA
    eks.amazonaws.com/role-arn: "arn:aws:iam::123456789012:role/training-data-reader"
```

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-training-data",
        "arn:aws:s3:::my-training-data/*"
      ]
    },
    {
      "Effect": "Deny",
      "Action": "s3:*",
      "NotResource": [
        "arn:aws:s3:::my-training-data",
        "arn:aws:s3:::my-training-data/*"
      ]
    }
  ]
}
```

### RDMA and InfiniBand Considerations

RDMA traffic bypasses the kernel TCP/IP stack and therefore bypasses Kubernetes network policies entirely. This is a fundamental limitation.

```yaml
# For clusters using RDMA/InfiniBand for training:
# 1. Dedicate RDMA-capable nodes exclusively to training (physical isolation)
# 2. Use separate InfiniBand subnets for training vs production
# 3. Configure InfiniBand partition keys (pkeys) to isolate traffic

# Node affinity: ensure RDMA training only runs on isolated nodes
apiVersion: v1
kind: Pod
metadata:
  name: training-worker-0
  namespace: ai-training
spec:
  nodeSelector:
    node-role: gpu-training
    rdma-capable: "true"
  tolerations:
    - key: workload-type
      value: training
      effect: NoSchedule
  containers:
    - name: trainer
      image: registry.example.com/training:v1
      resources:
        limits:
          nvidia.com/gpu: 8
          rdma/rdma_shared_device_a: 1
      securityContext:
        runAsNonRoot: true
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
```

### Monitoring for Data Exfiltration

```yaml
# prometheus-training-network-alerts.yaml
groups:
  - name: training-network-security
    rules:
      - alert: TrainingPodUnexpectedEgress
        expr: >
          sum by (destination) (
            rate(hubble_drop_total{
              source_namespace="ai-training",
              reason="POLICY_DENIED"
            }[5m])
          ) > 0
        labels:
          severity: warning
        annotations:
          summary: "Training pod attempted blocked egress to {{ $labels.destination }}"
          description: "A pod in ai-training namespace attempted to reach a destination blocked by network policy. Investigate for potential data exfiltration."

      - alert: TrainingDataEgressVolumeSpike
        expr: >
          sum(rate(container_network_transmit_bytes_total{namespace="ai-training"}[10m]))
          > 1.5 * avg_over_time(
            sum(rate(container_network_transmit_bytes_total{namespace="ai-training"}[10m]))[7d:1h]
          )
        labels:
          severity: warning
        annotations:
          summary: "Training namespace egress volume 1.5x above 7-day average"
```

## Expected Behaviour

- Training pods can communicate with each other on designated ports (distributed training)
- Training pods can reach approved object storage endpoints and nothing else
- Training pods cannot reach production namespaces, databases, or external services
- RDMA traffic is physically isolated on dedicated nodes and InfiniBand subnets
- Network policy violations generate alerts for investigation
- Service accounts have read-only access to specific training data buckets

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| Default-deny network policy | Blocks all unexpected traffic | New training jobs may fail if egress rules are not updated | Maintain a documented list of approved data sources. Use CI to validate network policies match training job requirements. |
| FQDN-based egress (Cilium) | Controls egress to specific external endpoints | Requires Cilium CNI. Standard Kubernetes network policies cannot match FQDNs. | If not using Cilium, use IP-based egress rules with automation to update IP lists for cloud service endpoints. |
| Dedicated RDMA nodes | Physical isolation for bypass-prone traffic | Higher cost (dedicated GPU nodes for training only) | Share nodes across training jobs from the same trust level. Do not mix training and production on RDMA nodes. |
| Read-only IAM for training | Prevents training jobs from writing to or deleting data | Model checkpoints need a separate write path | Create a dedicated checkpoint bucket with write access. Keep training data read-only. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Network policy too restrictive | Distributed training fails (workers cannot reach each other) | Training job timeout; NCCL errors in pod logs | Check network policy allows inter-pod communication on training ports. Verify pod labels match policy selectors. |
| FQDN policy stale (S3 endpoint IP changed) | Training cannot download data | Pod logs show connection timeout to object storage | Cilium FQDN policies resolve dynamically. If using IP-based policies, update the IP list. |
| RDMA traffic leaking between trust zones | No direct symptom (RDMA bypasses standard monitoring) | Periodic audit of InfiniBand subnet membership and pkey configuration | Reconfigure pkeys. Verify node pool isolation. |
| Overly broad egress rule | Training pods can reach unintended destinations | Network flow monitoring shows connections outside approved list | Tighten egress rules. Audit all active network policies with `kubectl get networkpolicy -n ai-training -o yaml`. |

## When to Consider a Managed Alternative

[Isovalent](https://isovalent.com) Cilium Enterprise for advanced network policy with FQDN-based egress, DNS-aware policies, and network flow visibility. [Sysdig](https://sysdig.com) for network monitoring and forensics across training and production namespaces. Managed Kubernetes providers with advanced networking support simplify CNI configuration.

**Premium content pack:** Network policy pack for AI training cluster isolation. Default-deny policies, distributed training inter-pod rules, FQDN egress for major cloud storage providers, and [Prometheus](https://prometheus.io) alert rules for training network anomalies.


## Related Articles

- [Kubernetes Network Policies That Actually Work: From Default Deny to Microsegmentation](/articles/kubernetes/kubernetes-network-policies/)
- [Hardening Model Inference Endpoints: Authentication, Rate Limiting, and Input Validation](/articles/kubernetes/inference-endpoint-hardening/)
- [GPU Workload Isolation: MIG, MPS, and vGPU Security Boundaries](/articles/kubernetes/gpu-isolation/)
- [AI Data Leakage Prevention: Input Filtering, Output Scanning, and Audit Trails](/articles/kubernetes/ai-data-leakage-prevention/)
- [Multi-Tenancy Hardening in Kubernetes: Namespace Isolation, Resource Quotas, and Network Boundaries](/articles/kubernetes/multi-tenancy-hardening/)
