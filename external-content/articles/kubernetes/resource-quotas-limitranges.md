---
title: "Kubernetes Resource Quotas and LimitRanges: Preventing Noisy Neighbour and Denial of Service"
description: "Without resource quotas, a single namespace can consume all cluster CPU, memory, and storage — starving other tenants or crashing the control plane. ResourceQuota and LimitRange enforce per-namespace and per-pod resource bounds, making resource exhaustion attacks and accidental runaway workloads containable."
slug: "resource-quotas-limitranges"
date: 2026-05-01
lastmod: 2026-05-01
category: "kubernetes"
tags: ["resource-quota", "limitrange", "multi-tenancy", "dos-prevention", "kubernetes-security"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 304
difficulty: "intermediate"
estimated_reading_time: 12
published: true
layout: article.njk
permalink: "/articles/kubernetes/resource-quotas-limitranges/index.html"
---

# Kubernetes Resource Quotas and LimitRanges: Preventing Noisy Neighbour and Denial of Service

## Problem

Kubernetes schedules workloads onto nodes based on requested resources. Without enforcement of resource requests and limits, several failure modes occur:

- **Unbounded memory allocation crashes nodes.** A pod with no memory limit can consume all node memory, triggering the OOM killer, which terminates other pods — including system-critical components. On a node running coredns, kube-proxy, and application pods, an OOM event from one application kills cluster networking for all tenants on that node.
- **No resource requests breaks scheduling fairness.** Without requests, the scheduler cannot make informed placement decisions. All pods look equal. High-priority workloads get no scheduling preference over dev/test workloads.
- **API server object count DoS.** An attacker or misconfigured automation floods the API server with object creation (ConfigMaps, Secrets, Services, pods). Without object count quotas, the API server etcd backend fills, causing API server instability across the entire cluster.
- **No namespace isolation allows cross-tenant resource starvation.** In a shared cluster, a team running a memory leak or an accidental infinite loop saturates cluster resources, degrading performance for all other teams.
- **Missing LimitRange allows containers without limits.** Kubernetes does not require pods to specify resource limits. Without a LimitRange enforcing defaults and maximums, developers omit limits — a common mistake — and create unbounded resource consumers.

**Target systems:** Kubernetes 1.28+ (ResourceQuota, LimitRange, PriorityClass); multi-tenant shared clusters; namespace-per-team isolation models.

## Threat Model

- **Adversary 1 — Resource exhaustion via pod proliferation:** An attacker with namespace access runs thousands of idle pods. Without pod count quotas, they exhaust API server object storage and node capacity, degrading the cluster for all tenants.
- **Adversary 2 — Memory bomb via unlimited container:** An attacker deploys a container that gradually allocates all node memory. Without a memory limit, the container continues until the OOM killer terminates critical system pods.
- **Adversary 3 — CPU starvation via CPU-intensive workload:** A compromised or malicious pod runs CPU-intensive work (cryptomining, brute-forcing) without CPU limits. It consumes all CPU on its node, throttling co-located workloads.
- **Adversary 4 — etcd exhaustion via Secret/ConfigMap creation:** An attacker floods the cluster with large Secrets or ConfigMaps. etcd has a default 8GiB storage limit. Filling etcd causes all cluster operations to fail — a complete cluster denial of service.
- **Adversary 5 — Horizontal escalation via resource claims:** An attacker provisions PersistentVolumeClaims for all available storage. Other tenants cannot create PVCs; their stateful applications fail.
- **Access level:** All adversaries need namespace-level create permissions — a normal developer role.
- **Objective:** Deny service to legitimate workloads; disrupt cluster operations; create cover for other activity.
- **Blast radius:** Node-level OOM from an unbounded pod affects all pods on that node. etcd exhaustion affects the entire cluster. CPU/memory starvation degrades all tenants on the affected node.

## Configuration

### Step 1: Namespace ResourceQuota

Apply quotas to every namespace that runs untrusted or multi-tenant workloads:

```yaml
# ResourceQuota for a standard team namespace.
apiVersion: v1
kind: ResourceQuota
metadata:
  name: team-quota
  namespace: team-payments
spec:
  hard:
    # Compute resources.
    requests.cpu: "8"          # Total CPU requests across all pods.
    requests.memory: "16Gi"
    limits.cpu: "16"           # Total CPU limits across all pods.
    limits.memory: "32Gi"

    # Object counts — prevent API server flooding.
    pods: "50"
    services: "20"
    secrets: "100"
    configmaps: "100"
    persistentvolumeclaims: "20"
    services.loadbalancers: "2"   # LoadBalancer Services are expensive.
    services.nodeports: "0"       # Disable NodePort (use Ingress instead).

    # Storage.
    requests.storage: "200Gi"
    # Limit to specific StorageClass if needed:
    # standard.storageclass.storage.k8s.io/requests.storage: "200Gi"
```

```yaml
# Stricter quota for untrusted/sandbox namespaces.
apiVersion: v1
kind: ResourceQuota
metadata:
  name: sandbox-quota
  namespace: team-sandbox
spec:
  hard:
    requests.cpu: "2"
    requests.memory: "4Gi"
    limits.cpu: "4"
    limits.memory: "8Gi"
    pods: "10"
    services: "5"
    secrets: "20"
    configmaps: "20"
    persistentvolumeclaims: "3"
    services.loadbalancers: "0"
    services.nodeports: "0"
```

### Step 2: LimitRange — Enforce Defaults and Maximums

LimitRange sets defaults for containers that don't specify resources, and enforces maximums:

```yaml
# LimitRange for standard team namespace.
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: team-payments
spec:
  limits:
    # Container-level limits and defaults.
    - type: Container
      default:                 # Applied when container does not specify limits.
        cpu: "500m"
        memory: "512Mi"
      defaultRequest:          # Applied when container does not specify requests.
        cpu: "100m"
        memory: "128Mi"
      max:                     # Maximum allowed per container.
        cpu: "4"
        memory: "8Gi"
      min:                     # Minimum allowed per container.
        cpu: "10m"
        memory: "32Mi"

    # Pod-level limits (sum across all containers in the pod).
    - type: Pod
      max:
        cpu: "8"
        memory: "16Gi"

    # PVC limits.
    - type: PersistentVolumeClaim
      max:
        storage: "50Gi"        # Max size of a single PVC.
      min:
        storage: "1Gi"
```

With this LimitRange in place:
- A container that specifies no `limits` gets `cpu: 500m, memory: 512Mi` automatically.
- A container that tries to request `memory: 64Gi` is rejected (`max: 8Gi`).
- The ResourceQuota then applies across the sum of all containers.

### Step 3: Priority Classes for Scheduling Fairness

PriorityClasses ensure system-critical pods are not evicted to make room for low-priority workloads:

```yaml
# High priority for production workloads.
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: production-critical
value: 1000000
globalDefault: false
description: "Production workloads. Not preempted."

---
# Standard priority for normal team workloads.
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: team-standard
value: 100
globalDefault: true
description: "Default priority for team workloads."

---
# Low priority for batch/dev workloads — first to be evicted.
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: batch-low
value: -100
preemptionPolicy: Never    # Cannot preempt other pods.
description: "Batch and development workloads. First to evict."
```

```yaml
# Restrict which PriorityClasses a namespace can use.
# Via ResourceQuota.
apiVersion: v1
kind: ResourceQuota
metadata:
  name: priority-quota
  namespace: team-payments
spec:
  hard:
    # This namespace can only create pods with these priority classes.
    pods: "50"
  scopeSelector:
    matchExpressions:
      - operator: In
        scopeName: PriorityClass
        values: ["team-standard", "production-critical"]
```

### Step 4: Enforce Quotas via Kyverno Policy

Prevent namespaces without quotas from running workloads:

```yaml
# Kyverno policy: require ResourceQuota in every non-system namespace.
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-resource-quota
spec:
  validationFailureAction: Enforce
  rules:
    - name: require-quota-in-namespace
      match:
        any:
          - resources:
              kinds: ["Namespace"]
      validate:
        message: "Every namespace must have a ResourceQuota."
        deny:
          conditions:
            all:
              - key: "{{ request.object.metadata.name }}"
                operator: AnyNotIn
                value:
                  - kube-system
                  - kube-public
                  - kube-node-lease
                  - monitoring
                  - ingress-nginx
              - key: "{{ request.object.metadata.labels.\"quota-applied\" || '' }}"
                operator: NotEquals
                value: "true"
```

```yaml
# Kyverno policy: require resource limits on all containers.
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-container-limits
spec:
  validationFailureAction: Enforce
  rules:
    - name: check-container-limits
      match:
        any:
          - resources:
              kinds: ["Pod"]
      validate:
        message: "All containers must specify CPU and memory limits."
        pattern:
          spec:
            containers:
              - name: "*"
                resources:
                  limits:
                    cpu: "?*"
                    memory: "?*"
```

### Step 5: Monitoring Quota Utilisation

Alert before quotas are exhausted:

```yaml
# Prometheus alerting rules for quota utilisation.
groups:
  - name: resource-quotas
    rules:
      - alert: NamespaceQuotaCPUHigh
        expr: |
          kube_resourcequota{type="used",resource="requests.cpu"} /
          kube_resourcequota{type="hard",resource="requests.cpu"} > 0.85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Namespace {{ $labels.namespace }} CPU quota at {{ $value | humanizePercentage }}"
          description: "Approaching CPU quota limit. Review resource usage."

      - alert: NamespaceQuotaMemoryHigh
        expr: |
          kube_resourcequota{type="used",resource="requests.memory"} /
          kube_resourcequota{type="hard",resource="requests.memory"} > 0.85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Namespace {{ $labels.namespace }} memory quota at {{ $value | humanizePercentage }}"

      - alert: NamespaceQuotaPodsFull
        expr: |
          kube_resourcequota{type="used",resource="pods"} /
          kube_resourcequota{type="hard",resource="pods"} > 0.90
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Namespace {{ $labels.namespace }} pod count at {{ $value | humanizePercentage }}"

      - alert: NamespaceNoResourceQuota
        expr: |
          count by (namespace) (kube_namespace_labels) unless
          count by (namespace) (kube_resourcequota)
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Namespace {{ $labels.namespace }} has no ResourceQuota"
```

### Step 6: etcd Object Count Monitoring

Monitor etcd to detect object count attacks:

```bash
# Check total object counts in etcd.
kubectl get --raw /metrics | grep etcd_object_counts

# Or via etcdctl.
etcdctl endpoint status --write-out=table
# Shows DB size; alert if > 6GiB (approaching 8GiB default limit).

# Count objects by type.
kubectl api-resources --verbs=list --namespaced -o name | \
  xargs -I{} kubectl get {} --all-namespaces --no-headers 2>/dev/null | \
  wc -l
```

```yaml
# Prometheus alert: etcd DB size approaching limit.
- alert: EtcdDatabaseSizeHigh
  expr: etcd_mvcc_db_total_size_in_bytes > 6e9   # Alert at 6GiB.
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "etcd database size {{ $value | humanize1024 }}B — approaching 8GiB limit"
    description: "Investigate object count explosion. Check secrets, configmaps, events."
```

### Step 7: Namespace Isolation Validation

```bash
#!/bin/bash
# Validate all production namespaces have quotas and limit ranges.

NAMESPACES=$(kubectl get namespaces -l env=production -o jsonpath='{.items[*].metadata.name}')

for NS in $NAMESPACES; do
  # Check ResourceQuota exists.
  QUOTA=$(kubectl get resourcequota -n "$NS" --no-headers 2>/dev/null | wc -l)
  if [ "$QUOTA" -eq 0 ]; then
    echo "MISSING QUOTA: $NS"
  fi

  # Check LimitRange exists.
  LR=$(kubectl get limitrange -n "$NS" --no-headers 2>/dev/null | wc -l)
  if [ "$LR" -eq 0 ]; then
    echo "MISSING LIMITRANGE: $NS"
  fi

  # Check for pods without limits.
  UNLIMITED=$(kubectl get pods -n "$NS" -o json | \
    jq -r '.items[] | select(.spec.containers[].resources.limits == null) | .metadata.name')
  if [ -n "$UNLIMITED" ]; then
    echo "PODS WITHOUT LIMITS in $NS: $UNLIMITED"
  fi
done
```

### Step 8: Telemetry

```
kube_resourcequota{namespace, resource, type}                  gauge
kube_limitrange{namespace, type, resource, constraint}         gauge
kube_pod_container_resource_limits{namespace, container}       gauge
kube_pod_container_resource_requests{namespace, container}     gauge
etcd_mvcc_db_total_size_in_bytes{}                            gauge
kube_node_status_allocatable{resource}                         gauge
```

Alert on:

- Any quota utilisation exceeding 85% — approaching exhaustion; alert team to increase quota or reduce usage.
- Namespace without ResourceQuota — security gap; enforce via Kyverno.
- Pod without resource limits — enforcement gap; LimitRange should auto-inject but verify.
- etcd DB size > 6GiB — object count explosion; investigate.
- `kube_resourcequota{type="used",resource="pods"}` sudden spike — possible pod proliferation attack.

## Expected Behaviour

| Signal | No quotas | ResourceQuota + LimitRange |
|--------|-----------|---------------------------|
| Runaway pod memory | OOM kills co-located pods including system components | Container killed at limit; other pods unaffected |
| Pod proliferation attack | Thousands of pods consume API server etcd | Pod count quota rejects pod creation after limit |
| Container without limits | Unlimited resource consumption | LimitRange injects default limits automatically |
| Team exceeds cluster share | Starves other teams | Quota prevents over-allocation; fair-share enforced |
| etcd object count explosion | API server instability for entire cluster | Object count quotas prevent namespace-level flooding |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Strict quota enforcement | Hard limits on resource consumption | Teams may hit quotas unexpectedly; productivity impact | Set quotas generously initially; monitor utilisation; right-size based on actual usage |
| LimitRange defaults | No pod runs without limits | Defaults may be too low for some workloads | Set conservative defaults; teams override for known-large workloads |
| Pod count limits | Prevents proliferation | Legitimate batch jobs may need many pods | Use Job-specific quotas; set scope to specific workload types |
| PVC count limits | Prevents storage exhaustion | Stateful applications may need many PVCs | Set per StorageClass quotas; use different quotas for stateful namespaces |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Quota too low for legitimate workload | Pod creation fails with "exceeded quota" | Kubernetes event; application deployment failure | Increase quota via PR; require change review for production quota changes |
| LimitRange default too low | Containers OOMKilled immediately | OOMKilled event; pod crash loop | Update LimitRange defaults; rolling restart of affected pods |
| Quota not applied to new namespace | New namespace has no limits; vulnerable | `NamespaceNoResourceQuota` alert | Apply quota immediately; investigate creation process |
| etcd quota circumvented via large objects | Single large Secret approaches etcd limits | etcd DB size metric | Limit maximum object size via admission webhook |

## Related Articles

- [Kubernetes Multi-Tenancy Hardening](/articles/kubernetes/multi-tenancy-hardening/)
- [Kyverno Policy Development and Testing](/articles/kubernetes/kyverno-policy-development/)
- [Pod Security Context](/articles/kubernetes/pod-security-context/)
- [kube-bench CIS Benchmark Automation](/articles/kubernetes/kube-bench-cis-benchmark/)
- [Kubernetes Node Hardening](/articles/kubernetes/node-hardening/)
