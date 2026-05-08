---
title: "Multi-Tenancy Hardening in Kubernetes: Namespace Isolation, Resource Quotas, and Network Boundaries"
description: "Kubernetes namespaces provide logical separation, not security isolation. By default, pods in namespace A can send network traffic to pods in..."
slug: "multi-tenancy-hardening"
date: 2026-03-02
lastmod: 2026-03-02
category: "kubernetes"
tags: ["kubernetes", "multi-tenancy", "namespaces", "rbac", "network-policy", "resource-quotas"]
personas: ["platform-engineer", "security-engineer"]
article_number: 31
difficulty: "intermediate"
estimated_reading_time: 20
provider_bridges:
  - name: "Civo"
    id: 22
    category: "managed-kubernetes"
  - name: "DigitalOcean"
    id: 21
    category: "managed-kubernetes"
published: true
layout: article.njk
permalink: "/articles/kubernetes/multi-tenancy-hardening/index.html"
---

# Multi-Tenancy Hardening in [Kubernetes](https://kubernetes.io): Namespace Isolation, Resource Quotas, and Network Boundaries

## Problem

Kubernetes namespaces provide logical separation, not security isolation. By default, pods in namespace A can send network traffic to pods in namespace B. A user with broad RBAC permissions can read secrets across namespaces. A pod without resource limits can consume all CPU and memory on a node, starving other tenants.

Running multiple teams, environments, or customers on a shared cluster reduces infrastructure costs, but the isolation boundaries are weak without explicit hardening:

- **RBAC defaults are too broad.** The `system:authenticated` group grants read access to discovery APIs, and ClusterRoleBindings apply across all namespaces. Without careful RBAC scoping, one tenant can enumerate resources belonging to another.
- **No network isolation by default.** Without NetworkPolicy, all pods can communicate with all other pods. A compromised pod in a development namespace can reach production databases.
- **Resource exhaustion is a cross-tenant attack.** Without ResourceQuotas and LimitRanges, one tenant can deploy hundreds of pods or consume all available memory, causing evictions in other namespaces.
- **Shared kernel means shared risk.** All pods on a node share the same Linux kernel. A kernel exploit from any pod compromises every other pod on that node, regardless of namespace boundaries.

This article covers namespace-level RBAC, LimitRanges, ResourceQuotas, network policy isolation, Pod Security Standards per namespace, and when to escalate from namespace isolation to vCluster or separate clusters.

**Target systems:** Kubernetes 1.29+ with a CNI that supports NetworkPolicy ([Calico](https://www.tigera.io/project-calico/), [Cilium](https://cilium.io), or Antrea).

## Threat Model

- **Adversary:** Malicious or compromised tenant (team, application, or customer workload) operating within a shared Kubernetes cluster.
- **Access level:** Legitimate RBAC permissions within one namespace, or code execution inside a pod in one namespace.
- **Objective:** Access resources belonging to other tenants (secrets, data, network services), consume shared resources to deny service to other tenants, or escalate privileges to cluster-admin scope.
- **Blast radius:** Without multi-tenancy hardening, a compromised pod can reach all network endpoints in the cluster, and an over-permissioned user can read secrets across namespaces. With hardening, blast radius is limited to the tenant's namespace, the tenant's resource quota, and network endpoints explicitly allowed by policy.

## Configuration

### Step 1: Namespace-Level RBAC

Create per-namespace roles that restrict each team to their own namespace. Never grant ClusterRoles to tenant users unless absolutely necessary.

```yaml
# tenant-namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: team-alpha
  labels:
    tenant: alpha
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
---
# Role: full access within the namespace only
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: tenant-admin
  namespace: team-alpha
rules:
  - apiGroups: ["", "apps", "batch"]
    resources: ["pods", "deployments", "services", "configmaps", "jobs", "cronjobs"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "create", "update", "patch", "delete"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["get", "list"]  # Read-only: platform team manages network policy
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: team-alpha-admin
  namespace: team-alpha
subjects:
  - kind: Group
    name: "team-alpha"
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: tenant-admin
  apiGroup: rbac.authorization.k8s.io
```

Restrict cluster-level enumeration:

```yaml
# deny-cluster-scope.yaml
# Remove default discovery permissions for authenticated users
# (optional, but prevents tenants from listing all namespaces)
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: restricted-discovery
rules:
  - apiGroups: [""]
    resources: ["namespaces"]
    verbs: ["get"]  # Can get their own namespace, not list all
    # Note: list is removed compared to the default
```

### Step 2: LimitRanges (Default and Maximum Per-Pod Limits)

LimitRanges set default resource requests/limits for pods that do not specify them, and enforce maximum values:

```yaml
# limit-range.yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: tenant-limits
  namespace: team-alpha
spec:
  limits:
    - type: Container
      default:
        cpu: "500m"
        memory: "512Mi"
      defaultRequest:
        cpu: "100m"
        memory: "128Mi"
      max:
        cpu: "2"
        memory: "4Gi"
      min:
        cpu: "50m"
        memory: "64Mi"
    - type: Pod
      max:
        cpu: "4"
        memory: "8Gi"
    - type: PersistentVolumeClaim
      max:
        storage: "50Gi"
      min:
        storage: "1Gi"
```

```bash
kubectl apply -f limit-range.yaml

# Verify: deploy a pod without resource specs
kubectl run test-pod --image=nginx --namespace=team-alpha
kubectl get pod test-pod -n team-alpha -o jsonpath='{.spec.containers[0].resources}'
# Should show the default values from the LimitRange
```

### Step 3: ResourceQuotas (Namespace-Level Totals)

ResourceQuotas cap the total resources a namespace can consume:

```yaml
# resource-quota.yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: tenant-quota
  namespace: team-alpha
spec:
  hard:
    # Compute limits
    requests.cpu: "8"
    requests.memory: "16Gi"
    limits.cpu: "16"
    limits.memory: "32Gi"
    # Object count limits
    pods: "50"
    services: "20"
    secrets: "50"
    configmaps: "50"
    persistentvolumeclaims: "10"
    # Prevent NodePort services (force Ingress/ClusterIP)
    services.nodeports: "0"
    # Prevent LoadBalancer services (force Ingress)
    services.loadbalancers: "0"
```

```bash
kubectl apply -f resource-quota.yaml

# Check quota usage
kubectl describe resourcequota tenant-quota -n team-alpha
# Shows: Used / Hard for each resource type
```

### Step 4: Network Policy Isolation

Apply a default-deny policy to every tenant namespace, then explicitly allow required traffic:

```yaml
# default-deny-all.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: team-alpha
spec:
  podSelector: {}  # Applies to all pods in the namespace
  policyTypes:
    - Ingress
    - Egress
---
# allow-dns.yaml
# Without this, pods cannot resolve DNS names
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: team-alpha
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
---
# allow-intra-namespace.yaml
# Pods within the same namespace can communicate
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-intra-namespace
  namespace: team-alpha
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector: {}  # Same namespace only
  egress:
    - to:
        - podSelector: {}  # Same namespace only
---
# allow-ingress-controller.yaml
# Allow traffic from the ingress controller namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-from-ingress
  namespace: team-alpha
spec:
  podSelector:
    matchLabels:
      app: web  # Only pods labelled as web-facing
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress-nginx
      ports:
        - protocol: TCP
          port: 8080
```

```bash
# Apply all network policies
kubectl apply -f default-deny-all.yaml
kubectl apply -f allow-dns.yaml
kubectl apply -f allow-intra-namespace.yaml
kubectl apply -f allow-from-ingress.yaml

# Test: pod in team-alpha should NOT reach pods in team-beta
kubectl exec -n team-alpha test-pod -- curl -s --max-time 3 \
  http://web-service.team-beta.svc.cluster.local
# Expected: connection timeout (blocked by default-deny in team-beta)
```

### Step 5: Pod Security Standards Per Namespace

Enforce the restricted Pod Security Standard to prevent privilege escalation:

```bash
# Apply restricted PSS to tenant namespaces
kubectl label namespace team-alpha \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted

# Verify: try to create a privileged pod
kubectl run privileged-test --image=nginx -n team-alpha \
  --overrides='{"spec":{"containers":[{"name":"nginx","image":"nginx","securityContext":{"privileged":true}}]}}'
# Expected: Error from server (Forbidden): pods "privileged-test" is forbidden:
# violates PodSecurity "restricted:latest"
```

### Step 6: When Namespaces Are Not Enough

Namespace isolation has hard limits. All pods share the same kernel, the same API server, and the same etcd. Consider stronger isolation when:

| Signal | Namespace Isolation | vCluster | Separate Cluster |
|--------|-------------------|----------|-----------------|
| Tenant count | 2-5 teams | 5-20 teams | 20+ or external customers |
| Trust level | Internal teams, same org | Internal teams, different orgs | Untrusted, external customers |
| Compliance | Standard internal security | SOC 2, HIPAA | PCI-DSS, FedRAMP |
| Kernel exploit risk tolerance | Acceptable | Reduced (virtual API server) | Eliminated |

**vCluster for virtual clusters:**

```bash
# Install vCluster CLI
curl -L -o vcluster \
  "https://github.com/loft-sh/vcluster/releases/latest/download/vcluster-linux-amd64"
chmod +x vcluster && mv vcluster /usr/local/bin/

# Create a virtual cluster for a tenant
vcluster create team-alpha \
  --namespace vcluster-team-alpha \
  --set isolation.enabled=true \
  --set isolation.networkPolicy.enabled=true \
  --set isolation.resourceQuota.enabled=true

# Connect to the virtual cluster
vcluster connect team-alpha --namespace vcluster-team-alpha
# The tenant gets their own API server, their own RBAC,
# and sees only their own resources
```

## Expected Behaviour

After implementing multi-tenancy hardening:

- Each tenant can only see and manage resources in their own namespace
- Pods without explicit resource requests/limits receive defaults from LimitRange
- Total resource consumption per namespace is capped by ResourceQuota
- Cross-namespace network traffic is blocked by default; only explicitly allowed flows succeed
- Privileged pods, hostPath mounts, and host networking are blocked by Pod Security Standards
- vCluster tenants get an isolated API server experience with no visibility into other tenants' resources

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Default-deny NetworkPolicy | Breaks service discovery across namespaces; cross-namespace communication requires explicit rules | Legitimate cross-service traffic blocked during initial rollout | Audit existing traffic patterns before applying. Roll out with warn-only mode first (namespace label `audit` before `enforce`) |
| Strict ResourceQuotas | Tenant deployments fail when quota is exceeded | Unexpected deployment failures during traffic spikes or horizontal pod autoscaling | Set quotas with 20-30% headroom. Monitor quota usage and alert at 80% |
| Restricted Pod Security Standards | Some legacy workloads require capabilities or host access that restricted mode blocks | Application failures for workloads that need `NET_RAW`, `SYS_PTRACE`, or writable root filesystem | Use baseline mode for legacy namespaces. Migrate workloads to restricted over time |
| vCluster overhead | Each virtual cluster runs a control plane (API server, etcd, controller-manager) consuming 0.5-1 CPU and 512Mi-1Gi memory | Increased resource usage per tenant | Right-size vCluster resource requests. Use k3s-based vCluster (lighter than full k8s control plane) |
| services.nodeports: "0" | Tenants cannot create NodePort services | Breaks workflows that rely on NodePort for external access | Provide shared Ingress controller. Document the expected path for external traffic |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| NetworkPolicy blocks DNS | Pods cannot resolve service names; all HTTP requests fail with DNS errors | Pod logs show DNS resolution failures; `nslookup` from within pods times out | Apply the allow-dns NetworkPolicy. Verify it targets the correct kube-system namespace label |
| ResourceQuota too tight | Deployments fail with "exceeded quota" error; HPA cannot scale up | Deployment events show "forbidden: exceeded quota"; HPA logs show scaling failures | Increase the quota. Monitor quota usage with `kubectl describe resourcequota` and set alerts at 80% utilization |
| LimitRange max too low | Pods that need more resources are rejected at admission | Pod creation fails with "maximum cpu/memory exceeded" | Review workload requirements. Increase LimitRange max or create workload-specific exceptions |
| RBAC RoleBinding missing for new team member | User gets "forbidden" errors for all operations in their namespace | User reports access denied; audit logs show RBAC denial for the user's identity | Add the user to the appropriate group, or create a RoleBinding for their identity in the tenant namespace |
| vCluster syncer fails | Resources created in the virtual cluster are not synced to the host cluster; pods remain pending | vCluster syncer logs show sync errors; pods in the virtual cluster show no matching host pods | Check vCluster syncer health. Restart the vCluster pod. Check that the host namespace has sufficient quota |

## When to Consider a Managed Alternative

**Transition point:** Multi-tenancy hardening requires ongoing policy maintenance: updating RBAC as teams change, adjusting quotas as workloads grow, and maintaining network policies as service dependencies evolve. Beyond 5 tenants, the policy management overhead scales linearly. Beyond 10 tenants, or when tenants include external customers, the shared kernel risk becomes the primary concern.

**Recommended providers:**

- **[Civo](https://www.civo.com) and [DigitalOcean](https://www.digitalocean.com):** Managed Kubernetes makes multi-cluster architectures affordable. Instead of complex namespace isolation on one cluster, run one small cluster per tenant. Civo clusters start at approximately $20/month, making the "separate cluster per tenant" model viable at 5-10 tenants where namespace isolation becomes insufficient.

**What you still control:** Regardless of isolation strategy, you still own RBAC policy design, network policy rules, resource quota sizing, and the decision of when to escalate from namespaces to virtual clusters to separate clusters. Managed providers simplify the infrastructure layer but do not replace tenant isolation policy.

**Premium content pack:** Namespace provisioning automation with [Terraform](https://www.terraform.io) and Kustomize, including RBAC, NetworkPolicy, LimitRange, ResourceQuota, and Pod Security Standards templates. Includes a tenant onboarding script that creates all resources from a single configuration file.


## Related Articles

- [Hardening the Kubernetes Scheduler: Topology Constraints and Security-Aware Placement](/articles/kubernetes/scheduler-hardening/)
- [etcd Encryption at Rest: Configuration, Key Rotation, and Performance Impact](/articles/kubernetes/etcd-encryption/)
- [Kubernetes Node Hardening: From OS Configuration to kubelet Lockdown](/articles/kubernetes/node-hardening/)
- [Kubernetes Network Policies That Actually Work: From Default Deny to Microsegmentation](/articles/kubernetes/kubernetes-network-policies/)
- [Kubernetes RBAC Design Patterns: Least Privilege Without Paralysing Developers](/articles/kubernetes/rbac-design-patterns/)
