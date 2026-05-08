---
title: "Hardening the Kubernetes Scheduler: Topology Constraints and Security-Aware Placement"
description: "The Kubernetes scheduler places pods on nodes based on resource availability and basic constraints."
slug: "scheduler-hardening"
date: 2026-01-19
lastmod: 2026-01-19
category: "kubernetes"
tags: ["kubernetes", "scheduler", "node-affinity", "taints", "topology", "multi-tenancy"]
personas: ["platform-engineer", "sre"]
article_number: 33
difficulty: "intermediate"
estimated_reading_time: 18
provider_bridges:
  - name: "Civo"
    id: 22
    category: "managed-kubernetes"
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
published: true
layout: article.njk
permalink: "/articles/kubernetes/scheduler-hardening/index.html"
---

# Hardening the [Kubernetes](https://kubernetes.io) Scheduler: Topology Constraints and Security-Aware Placement

## Problem

The Kubernetes scheduler places pods on nodes based on resource availability and basic constraints. By default, it does not consider security boundaries. A sensitive payment-processing pod can land on the same node as an untrusted third-party integration pod. If the third-party pod is compromised and the attacker achieves container escape, every pod on that node is exposed, including the payment processor.

This is not just a theoretical concern:

- **Co-location of sensitive and untrusted workloads.** Without scheduling constraints, the scheduler optimizes for resource packing. It will place high-security and low-trust workloads on the same node if that node has available resources.
- **Replicas on the same node defeat high availability.** If all replicas of a critical service land on one node, a single node failure takes down the entire service. The scheduler can spread replicas, but only if you configure topology spread constraints.
- **Multi-tenant clusters share node pools by default.** Without taints and tolerations, tenant A's pods can run on the same nodes as tenant B's pods. A noisy neighbour or a compromised pod affects co-located tenants.
- **Compliance requirements may mandate physical separation.** PCI-DSS and similar standards require that cardholder data environments are isolated. Logical namespace separation is not sufficient; workloads must run on dedicated infrastructure.

This article covers node affinity, taints and tolerations, topology spread constraints, pod anti-affinity, and multi-tenant scheduling patterns.

**Target systems:** Kubernetes 1.29+ with any scheduler (default kube-scheduler). Works with managed and self-managed clusters.

## Threat Model

- **Adversary:** Attacker who has compromised a low-trust workload (third-party integration, development pod, or untrusted tenant pod) and is attempting to pivot to sensitive workloads via container escape or shared-node resources.
- **Access level:** Code execution inside a container, escalating to node-level access via kernel exploit or runtime vulnerability.
- **Objective:** Access sensitive data or processes on co-located pods. Exploit shared resources (node filesystem, container runtime socket, kubelet API, network namespace).
- **Blast radius:** Without scheduling constraints, all pods on the same node are in the blast radius of a container escape. With security-aware scheduling, sensitive workloads run on dedicated nodes where only trusted pods are present, reducing the blast radius to the dedicated node pool.

## Configuration

### Step 1: Dedicated Node Pools with Labels

Create separate node pools for workloads with different security levels:

```bash
# Label nodes for security tiers
kubectl label node worker-01 worker-02 \
  security-tier=sensitive

kubectl label node worker-03 worker-04 \
  security-tier=general

kubectl label node worker-05 \
  security-tier=untrusted

# Verify labels
kubectl get nodes -L security-tier
```

### Step 2: Taints and Tolerations for Hard Isolation

Taints prevent pods from scheduling on a node unless they explicitly tolerate the taint. This is the strongest scheduling constraint.

```bash
# Taint sensitive nodes so only approved workloads can run there
kubectl taint nodes worker-01 worker-02 \
  security-tier=sensitive:NoSchedule

# Taint untrusted nodes so general workloads avoid them
kubectl taint nodes worker-05 \
  security-tier=untrusted:NoSchedule
```

Deploy a sensitive workload that tolerates the taint:

```yaml
# payment-processor.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payment-processor
  namespace: payments
spec:
  replicas: 3
  selector:
    matchLabels:
      app: payment-processor
  template:
    metadata:
      labels:
        app: payment-processor
    spec:
      # Tolerate the sensitive node taint
      tolerations:
        - key: "security-tier"
          operator: "Equal"
          value: "sensitive"
          effect: "NoSchedule"
      # Require placement on sensitive nodes
      nodeSelector:
        security-tier: sensitive
      containers:
        - name: processor
          image: registry.example.com/payment-processor:2.3.1
          resources:
            requests:
              cpu: "500m"
              memory: "512Mi"
            limits:
              cpu: "1"
              memory: "1Gi"
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
```

### Step 3: Node Affinity for Preferred Placement

Node affinity provides more flexible placement rules than nodeSelector, including preferred (soft) and required (hard) constraints:

```yaml
# database-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  namespace: data
spec:
  replicas: 2
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      affinity:
        nodeAffinity:
          # Hard requirement: must be on sensitive nodes
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
              - matchExpressions:
                  - key: security-tier
                    operator: In
                    values:
                      - sensitive
          # Soft preference: prefer nodes with SSD storage
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 80
              preference:
                matchExpressions:
                  - key: disk-type
                    operator: In
                    values:
                      - ssd
      containers:
        - name: postgres
          image: registry.example.com/postgres:16.2
          resources:
            requests:
              cpu: "1"
              memory: "2Gi"
            limits:
              cpu: "2"
              memory: "4Gi"
```

### Step 4: Pod Anti-Affinity for Replica Spreading

Prevent replicas of the same service from landing on the same node:

```yaml
# web-frontend.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-frontend
  namespace: production
spec:
  replicas: 4
  selector:
    matchLabels:
      app: web-frontend
  template:
    metadata:
      labels:
        app: web-frontend
    spec:
      affinity:
        podAntiAffinity:
          # Hard: never put two replicas on the same node
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector:
                matchExpressions:
                  - key: app
                    operator: In
                    values:
                      - web-frontend
              topologyKey: kubernetes.io/hostname
      containers:
        - name: frontend
          image: registry.example.com/web-frontend:3.1.0
          resources:
            requests:
              cpu: "200m"
              memory: "256Mi"
```

### Step 5: Topology Spread Constraints

Distribute pods evenly across failure domains (zones, nodes) for both availability and security:

```yaml
# distributed-service.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-gateway
  namespace: production
spec:
  replicas: 6
  selector:
    matchLabels:
      app: api-gateway
  template:
    metadata:
      labels:
        app: api-gateway
    spec:
      topologySpreadConstraints:
        # Spread across availability zones
        - maxSkew: 1
          topologyKey: topology.kubernetes.io/zone
          whenUnsatisfiable: DoNotSchedule
          labelSelector:
            matchLabels:
              app: api-gateway
        # Spread across nodes within each zone
        - maxSkew: 1
          topologyKey: kubernetes.io/hostname
          whenUnsatisfiable: ScheduleAnyway
          labelSelector:
            matchLabels:
              app: api-gateway
      containers:
        - name: gateway
          image: registry.example.com/api-gateway:1.8.0
          resources:
            requests:
              cpu: "250m"
              memory: "256Mi"
```

### Step 6: Multi-Tenant Scheduling

Combine taints, tolerations, and node affinity to isolate tenant workloads on dedicated node pools:

```bash
# Create per-tenant taints
kubectl taint nodes worker-10 worker-11 \
  tenant=alpha:NoSchedule

kubectl taint nodes worker-12 worker-13 \
  tenant=beta:NoSchedule

# Label nodes for tenant affinity
kubectl label nodes worker-10 worker-11 tenant=alpha
kubectl label nodes worker-12 worker-13 tenant=beta
```

```yaml
# tenant-alpha-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: alpha-app
  namespace: team-alpha
spec:
  replicas: 2
  selector:
    matchLabels:
      app: alpha-app
  template:
    metadata:
      labels:
        app: alpha-app
        tenant: alpha
    spec:
      tolerations:
        - key: "tenant"
          operator: "Equal"
          value: "alpha"
          effect: "NoSchedule"
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
              - matchExpressions:
                  - key: tenant
                    operator: In
                    values:
                      - alpha
      containers:
        - name: app
          image: registry.example.com/alpha-app:1.0.0
          resources:
            requests:
              cpu: "200m"
              memory: "256Mi"
```

**Enforce tenant scheduling with [Kyverno](https://kyverno.io):**

```yaml
# enforce-tenant-scheduling.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: enforce-tenant-node-affinity
spec:
  validationFailureAction: Enforce
  rules:
    - name: require-tenant-affinity
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaces:
                - "team-*"
      validate:
        message: "Pods in tenant namespaces must include a nodeAffinity for the tenant label."
        pattern:
          spec:
            affinity:
              nodeAffinity:
                requiredDuringSchedulingIgnoredDuringExecution:
                  nodeSelectorTerms:
                    - matchExpressions:
                        - key: tenant
                          operator: In
```

## Expected Behaviour

After implementing scheduler hardening:

- Sensitive workloads run exclusively on tainted nodes that reject all other pods
- Untrusted workloads are confined to their own node pool and cannot be scheduled alongside sensitive services
- Pod replicas are distributed across nodes and zones, preventing single-node failures from causing full outages
- Topology spread constraints maintain even distribution as pods scale up and down
- Multi-tenant workloads are isolated to per-tenant node pools, with Kyverno policies preventing tenants from scheduling on other tenants' nodes
- General workloads continue to schedule on the general-tier nodes without modification

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Taints on sensitive nodes | Dedicated nodes may be underutilized if sensitive workloads are small | Wasted compute resources on dedicated nodes | Right-size the dedicated node pool. Use cluster autoscaler with node pool-specific scaling |
| Required pod anti-affinity | Pods cannot schedule if there are not enough nodes (e.g., 4 replicas need 4 nodes) | Pods stuck in Pending state during node shortages | Use `preferredDuringScheduling` instead of `required` for non-critical services. Ensure node count exceeds replica count |
| Topology spread with DoNotSchedule | Pods reject placement if the spread constraint cannot be met | Pods stuck Pending when zones or nodes are unevenly sized | Use `ScheduleAnyway` (soft) for less critical services. Ensure zones have similar node counts |
| Per-tenant node pools | Each tenant needs dedicated nodes, increasing infrastructure cost | Higher cost per tenant compared to shared node pools | Use node autoscaling to scale down idle tenant pools. Evaluate whether namespace isolation is sufficient for the trust level |
| Kyverno scheduling enforcement | Additional admission webhook latency on pod creation | Slight deployment slowdown (50-100ms per pod) | Acceptable for most workloads. Exempt system namespaces from the policy |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| All sensitive nodes full | New sensitive-tier pods stuck in Pending state | `kubectl get pods` shows Pending; `kubectl describe pod` shows "0/N nodes available: N node(s) had taint" | Add nodes to the sensitive pool. Enable cluster autoscaler for the sensitive node group |
| Taint removed from node | Non-sensitive pods schedule on previously dedicated nodes, breaking isolation | Audit node taints periodically; Kyverno can enforce taints exist on labelled nodes | Re-apply the taint. Investigate how it was removed (accidental kubectl command, node replacement without taint) |
| Topology spread prevents scaling | HPA tries to add replicas but the spread constraint blocks placement in an imbalanced cluster | HPA events show "unable to schedule"; pods in Pending with topology spread errors | Rebalance nodes across zones. Switch the imbalanced constraint from DoNotSchedule to ScheduleAnyway |
| Anti-affinity blocks rolling updates | During a rolling update, new pods cannot schedule because old pods still occupy the required topology | Deployment rollout stalls; new pods Pending while old pods still Running | Configure `maxSurge` and `maxUnavailable` in the deployment strategy. Use `preferredDuringScheduling` for anti-affinity during rollouts |
| Tenant schedules on wrong node pool | Kyverno policy not applied, or namespace not matching the policy selector | Pods from tenant A running on tenant B's nodes (check with `kubectl get pods -o wide`) | Fix the Kyverno policy match selector. Evict misplaced pods. Audit and re-apply taints |

## When to Consider a Managed Alternative

**Transition point:** Managing dedicated node pools, taints, and autoscaling across multiple security tiers or tenants adds significant operational overhead. Each node pool needs its own autoscaling configuration, its own monitoring, and its own capacity planning. At 3+ node pools, the management burden is substantial.

**Recommended providers:**

- **[Civo](https://www.civo.com):** Managed Kubernetes with node pool support. Create dedicated node pools for different security tiers through the API or UI. Autoscaling is managed by the provider.
- **[Sysdig](https://sysdig.com):** Provides workload placement visualization, showing which pods are co-located on which nodes. Useful for auditing whether scheduling constraints are working as intended.

**What you still control:** The scheduling constraints (node affinity, taints, topology spread) are workload-level configurations that you define regardless of whether the infrastructure is managed. Managed providers handle node provisioning and autoscaling; you define the placement rules.

**Premium content pack:** Kyverno policy pack for scheduling enforcement, including policies for tenant node affinity, anti-affinity requirements for critical services, and topology spread validation. Includes [Terraform](https://www.terraform.io) modules for creating labelled and tainted node pools on major cloud providers.


## Related Articles

- [Multi-Tenancy Hardening in Kubernetes: Namespace Isolation, Resource Quotas, and Network Boundaries](/articles/kubernetes/multi-tenancy-hardening/)
- [Kubernetes Network Policies That Actually Work: From Default Deny to Microsegmentation](/articles/kubernetes/kubernetes-network-policies/)
- [Seccomp Profiles for Production Workloads: Writing, Testing, and Deploying Custom Profiles](/articles/kubernetes/seccomp-profiles/)
- [Kubernetes RBAC Design Patterns: Least Privilege Without Paralysing Developers](/articles/kubernetes/rbac-design-patterns/)
- [etcd Encryption at Rest: Configuration, Key Rotation, and Performance Impact](/articles/kubernetes/etcd-encryption/)
