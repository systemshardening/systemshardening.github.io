---
title: "GPU Cost and Security Monitoring: Detecting Abuse and Optimising Spend"
description: "GPU compute costs between $2 and $30 per hour per device. A single unauthorised cryptocurrency mining pod running on an A100 for a weekend generates.."
slug: "gpu-cost-security-monitoring"
date: 2026-04-06
lastmod: 2026-04-06
category: "kubernetes"
tags: ["gpu", "monitoring", "prometheus", "dcgm", "cost", "crypto-mining"]
personas: ["ai-ml-engineer", "platform-engineer", "sre"]
article_number: 85
difficulty: "intermediate"
estimated_reading_time: 13
provider_bridges:
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
premium_pack: "gpu-monitoring-dashboard-pack"
published: true
layout: article.njk
permalink: "/articles/kubernetes/gpu-cost-security-monitoring/index.html"
---

# GPU Cost and Security Monitoring: Detecting Abuse and Optimising Spend

## Problem

GPU compute costs between $2 and $30 per hour per device. A single unauthorised cryptocurrency mining pod running on an A100 for a weekend generates $1,400+ in wasted compute. Most [Kubernetes](https://kubernetes.io) observability stacks monitor CPU, memory, and disk but have no GPU metrics. Without GPU-specific monitoring, teams cannot detect unauthorised usage, cannot allocate costs to teams, and cannot identify idle GPUs that could be reclaimed.

Standard Kubernetes resource metrics (from metrics-server or cAdvisor) do not include GPU utilisation, GPU memory, power draw, or temperature. You need NVIDIA DCGM (Data Center GPU Manager) exporting to [Prometheus](https://prometheus.io) to get visibility. Without it, a GPU running at 100% utilisation on an unauthorised workload looks identical to an idle GPU in your monitoring dashboards, because those dashboards simply have no GPU data.

**Target systems:** Kubernetes clusters with NVIDIA GPUs. NVIDIA DCGM exporter. Prometheus and [Grafana](https://grafana.com) for metrics and visualisation.

## Threat Model

- **Adversary:** External attacker who has gained pod creation privileges (through compromised CI/CD, exposed Kubernetes API, or supply chain attack), or an insider running unauthorised workloads.
- **Objective:** Use GPU resources for cryptocurrency mining, unauthorised model training, or other compute-intensive tasks at the organisation's expense.
- **Blast radius:** Financial: uncapped GPU costs until detected. Performance: legitimate workloads may be starved of GPU resources. Security: if the attacker has pod creation privileges, GPU abuse is likely not their only activity. The GPU mining is the visible symptom of a deeper compromise.

## Configuration

### Deploy NVIDIA DCGM Exporter

DCGM exporter collects GPU metrics and exposes them in Prometheus format.

```yaml
# dcgm-exporter-daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: dcgm-exporter
  namespace: monitoring
  labels:
    app: dcgm-exporter
spec:
  selector:
    matchLabels:
      app: dcgm-exporter
  template:
    metadata:
      labels:
        app: dcgm-exporter
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9400"
        prometheus.io/path: "/metrics"
    spec:
      nodeSelector:
        nvidia.com/gpu.present: "true"
      tolerations:
        - key: nvidia.com/gpu
          operator: Exists
          effect: NoSchedule
      containers:
        - name: dcgm-exporter
          image: nvcr.io/nvidia/k8s/dcgm-exporter:3.3.8-3.6.0-ubuntu22.04
          ports:
            - containerPort: 9400
              name: metrics
          env:
            - name: DCGM_EXPORTER_KUBERNETES
              value: "true"
            - name: DCGM_EXPORTER_LISTEN
              value: ":9400"
          securityContext:
            runAsNonRoot: false  # DCGM requires root for GPU access
            capabilities:
              add:
                - SYS_ADMIN  # Required for GPU monitoring
          resources:
            limits:
              cpu: 100m
              memory: 128Mi
            requests:
              cpu: 50m
              memory: 64Mi
          volumeMounts:
            - name: device-plugins
              mountPath: /var/lib/kubelet/device-plugins
              readOnly: true
      volumes:
        - name: device-plugins
          hostPath:
            path: /var/lib/kubelet/device-plugins
```

```yaml
# servicemonitor for Prometheus Operator
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: dcgm-exporter
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: dcgm-exporter
  endpoints:
    - port: metrics
      interval: 15s
```

### GPU Security Alerts

```yaml
# prometheus-gpu-security-rules.yaml
groups:
  - name: gpu-security
    rules:
      # Detect GPU utilisation from unexpected namespaces
      - alert: UnauthorisedGPUUsage
        expr: >
          DCGM_FI_DEV_GPU_UTIL{namespace!~"ai-training|ml-serving|ml-platform"} > 10
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "GPU usage detected in unexpected namespace {{ $labels.namespace }}"
          description: "Pod {{ $labels.pod }} in namespace {{ $labels.namespace }} is using GPU. Only ai-training, ml-serving, and ml-platform namespaces should have GPU workloads."
          runbook: "Investigate the pod. If unauthorised, delete it and audit how it was created."

      # Sustained high utilisation without a matching training job
      - alert: SustainedGPUWithoutJob
        expr: >
          DCGM_FI_DEV_GPU_UTIL > 90
          and on (pod, namespace)
          (kube_pod_labels{label_job_type!="training"} or absent(kube_pod_labels{label_job_type="training"}))
        for: 30m
        labels:
          severity: warning
        annotations:
          summary: "GPU at >90% utilisation for 30m without training job label"
          description: "Pod {{ $labels.pod }} is consuming GPU heavily but is not labelled as a training job."

      # GPU memory nearly full (potential crypto miner or memory leak)
      - alert: GPUMemoryExhaustion
        expr: >
          DCGM_FI_DEV_FB_USED / DCGM_FI_DEV_FB_FREE > 0.95
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "GPU memory >95% used on {{ $labels.gpu }}"

      # Unexpected GPU temperature (mining or overloading)
      - alert: GPUTemperatureHigh
        expr: >
          DCGM_FI_DEV_GPU_TEMP > 85
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "GPU temperature above 85C on {{ $labels.gpu }}"
          description: "Sustained high temperature may indicate unauthorized workload or cooling failure."
```

### Cost Allocation and Tracking

```yaml
# prometheus-gpu-cost-recording-rules.yaml
groups:
  - name: gpu-cost-tracking
    interval: 5m
    rules:
      # GPU-hours per namespace per day
      - record: gpu:namespace:hours_used:daily
        expr: >
          sum by (namespace) (
            count_over_time(DCGM_FI_DEV_GPU_UTIL{} > 0[1d]) / 12
          )
        # Each sample is 5m apart, 12 samples = 1 hour

      # Estimated cost per namespace (configurable rate)
      - record: gpu:namespace:estimated_cost_usd:daily
        expr: >
          gpu:namespace:hours_used:daily * 3.50
        # $3.50/hour is approximate A100 on-demand cost. Adjust for your rate.

      # GPU utilisation efficiency (actual util vs allocated)
      - record: gpu:namespace:utilisation_efficiency
        expr: >
          avg by (namespace) (DCGM_FI_DEV_GPU_UTIL)
          / 100
```

### Resource Quota Enforcement

```yaml
# gpu-resource-quota.yaml
# Prevent namespaces from consuming more GPU than allocated
apiVersion: v1
kind: ResourceQuota
metadata:
  name: gpu-quota
  namespace: ai-training
spec:
  hard:
    requests.nvidia.com/gpu: "8"
    limits.nvidia.com/gpu: "8"
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: gpu-quota
  namespace: ml-serving
spec:
  hard:
    requests.nvidia.com/gpu: "4"
    limits.nvidia.com/gpu: "4"
```

### Grafana Dashboard Queries

Key panels for a GPU monitoring dashboard:

```
# GPU Utilisation by Namespace (time series)
avg by (namespace) (DCGM_FI_DEV_GPU_UTIL)

# GPU Memory Used (gauge, per device)
DCGM_FI_DEV_FB_USED / (DCGM_FI_DEV_FB_USED + DCGM_FI_DEV_FB_FREE) * 100

# Estimated Daily Cost by Namespace (stat panel)
gpu:namespace:estimated_cost_usd:daily

# GPU Temperature (time series)
DCGM_FI_DEV_GPU_TEMP

# Power Draw (time series, watts)
DCGM_FI_DEV_POWER_USAGE

# Top GPU Consumers (table, sorted by utilisation)
topk(10, avg by (pod, namespace) (DCGM_FI_DEV_GPU_UTIL))
```

## Expected Behaviour

- DCGM exporter runs on every GPU node and reports metrics to Prometheus every 15 seconds
- GPU utilisation from non-approved namespaces triggers a critical alert within 5 minutes
- Per-namespace GPU cost is tracked daily and visible in Grafana
- Resource quotas prevent any namespace from exceeding its GPU allocation
- GPU temperature and power anomalies generate warnings for infrastructure review
- Idle GPUs (under 5% utilisation for over 1 hour) are flagged for reclamation

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| DCGM exporter requires SYS_ADMIN | GPU monitoring needs elevated privileges | Privileged container on GPU nodes | DCGM exporter is a read-only monitoring agent. Restrict with [AppArmor](https://apparmor.net) profile that allows only GPU device reads. |
| 15-second scrape interval | Near real-time GPU visibility | Higher storage requirements for Prometheus | Use recording rules to pre-aggregate. Downsample historical data beyond 7 days. |
| Namespace-based cost allocation | Simple attribution model | Multi-tenant namespaces split costs inaccurately | Use pod-level labels for finer-grained attribution. Label each workload with team and project. |
| Static GPU hourly rate in recording rules | Simple cost estimation | Does not reflect spot pricing, reserved instances, or MIG partitions | Update the rate constant when pricing changes. For MIG, calculate per-partition cost as fraction of full GPU cost. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| DCGM exporter not running on GPU node | No GPU metrics for that node; gap in monitoring | Prometheus target health shows DCGM exporter down; DaemonSet pod count less than GPU node count | Check DaemonSet status. Verify node selector matches GPU node labels. Check NVIDIA driver compatibility. |
| GPU metrics missing after node upgrade | DCGM exporter fails to start | Pod crashloop; logs show NVIDIA driver version mismatch | Update DCGM exporter image to match the new driver version. |
| False positive on crypto mining alert | Legitimate high-utilisation workload triggers alert | Alert fires for a known training job | Add the job label (job_type=training) to legitimate workloads. Tune alert to exclude labelled training jobs. |
| Resource quota blocks legitimate workload | Pod stuck in Pending with quota exceeded message | `kubectl describe pod` shows "exceeded quota" | Review quota allocation. Increase if justified. If a previous job's GPUs were not released, clean up completed/failed jobs. |

## When to Consider a Managed Alternative

[Grafana Cloud](https://grafana.com/cloud) for managed Prometheus and Grafana with built-in GPU dashboard templates. Eliminates Prometheus storage management and provides long-term metric retention for cost trend analysis. Managed Kubernetes providers with GPU monitoring integrations reduce the DCGM deployment burden.

**Premium content pack:** GPU monitoring dashboard pack. Pre-built Grafana dashboards (utilisation, cost, security alerts), DCGM exporter DaemonSet manifests, Prometheus recording rules for cost allocation, and alert rules for unauthorised GPU usage.


## Related Articles

- [LLM Observability in Production: Monitoring Latency, Token Usage, Safety Violations, and Drift](/articles/kubernetes/llm-observability-production/)
- [Hardening Model Inference Endpoints: Authentication, Rate Limiting, and Input Validation](/articles/kubernetes/inference-endpoint-hardening/)
- [GPU Workload Isolation: MIG, MPS, and vGPU Security Boundaries](/articles/kubernetes/gpu-isolation/)
- [Network Segmentation for AI Training Infrastructure](/articles/kubernetes/ai-training-network-segmentation/)
- [Kubernetes Audit Log Analysis: What to Log, How to Query, and What to Alert On](/articles/kubernetes/audit-log-analysis/)
