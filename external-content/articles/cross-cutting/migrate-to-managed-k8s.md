---
title: "Migrating from Self-Managed Kubernetes to a Managed Provider Without Losing Your Security Posture"
description: "Self-managed Kubernetes clusters (kubeadm, k3s, kops) consume 8-16 hours per month of engineering time for control plane maintenance: etcd backups,..."
slug: "migrate-to-managed-k8s"
date: 2026-01-06
lastmod: 2026-01-06
category: "cross-cutting"
tags: ["kubernetes", "migration", "managed-kubernetes", "civo", "digitalocean", "security"]
personas: ["platform-engineer", "devops-engineer"]
article_number: 89
difficulty: "advanced"
estimated_reading_time: 22
provider_bridges:
  - name: "Civo"
    id: 22
    category: "managed-kubernetes"
  - name: "DigitalOcean"
    id: 21
    category: "managed-kubernetes"
  - name: "Vultr"
    id: 12
    category: "managed-kubernetes"
  - name: "Linode"
    id: 13
    category: "managed-kubernetes"
premium_pack: "k8s-migration-toolkit"
published: true
layout: article.njk
permalink: "/articles/cross-cutting/migrate-to-managed-k8s/index.html"
---

# Migrating from Self-Managed [Kubernetes](https://kubernetes.io) to a Managed Provider Without Losing Your Security Posture

## Problem

Self-managed Kubernetes clusters (kubeadm, k3s, kops) consume 8-16 hours per month of engineering time for control plane maintenance: etcd backups, API server upgrades, certificate rotation, node OS patching, and version upgrades. For teams under 10 engineers, this overhead typically exceeds the cost of a managed Kubernetes provider.

But migration is risky. The security configurations you built (RBAC roles, network policies, seccomp profiles, admission policies, audit logging) must transfer intact. Managed providers have different default configurations, different CNIs, different audit log access models, and different node OS images. A migration that drops security controls is worse than staying self-managed.

This article provides the step-by-step migration procedure with security preservation as the primary constraint.

**Target providers:** [Civo](https://www.civo.com), [DigitalOcean](https://www.digitalocean.com), [Vultr](https://www.vultr.com), [Linode](https://www.linode.com), [Exoscale](https://www.exoscale.com), [UpCloud](https://upcloud.com), [Scaleway](https://www.scaleway.com), [OVHcloud](https://www.ovhcloud.com).

## Threat Model

- **Adversary:** Not a direct adversary, the threat is security regression during migration. Lost network policies, weakened RBAC, disabled admission controls, or missing audit logging.
- **Blast radius:** Every workload on the cluster if security controls do not transfer correctly.

## Configuration

### Pre-Migration: Export Security State

Before starting the migration, capture your current security configuration:

```bash
#!/bin/bash
# export-security-state.sh
# Exports all security-relevant Kubernetes resources for migration.

EXPORT_DIR="./k8s-security-export-$(date +%Y%m%d)"
mkdir -p "$EXPORT_DIR"

echo "=== Exporting security state ==="

# Network policies
echo "Exporting NetworkPolicies..."
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  kubectl get networkpolicies -n "$ns" -o yaml > "$EXPORT_DIR/netpol-$ns.yaml" 2>/dev/null
done

# RBAC
echo "Exporting RBAC..."
kubectl get roles,rolebindings --all-namespaces -o yaml > "$EXPORT_DIR/rbac-namespaced.yaml"
kubectl get clusterroles,clusterrolebindings -o yaml > "$EXPORT_DIR/rbac-cluster.yaml"

# Pod Security Standards labels
echo "Exporting namespace labels..."
kubectl get namespaces -o yaml > "$EXPORT_DIR/namespaces.yaml"

# Admission policies (Kyverno)
echo "Exporting Kyverno policies..."
kubectl get clusterpolicies,policies --all-namespaces -o yaml > "$EXPORT_DIR/kyverno-policies.yaml" 2>/dev/null

# Admission policies (Gatekeeper)
echo "Exporting Gatekeeper constraints..."
kubectl get constraints --all-namespaces -o yaml > "$EXPORT_DIR/gatekeeper-constraints.yaml" 2>/dev/null
kubectl get constrainttemplates -o yaml > "$EXPORT_DIR/gatekeeper-templates.yaml" 2>/dev/null

# Seccomp profiles (if using SecurityProfile Operator)
kubectl get seccompprofiles --all-namespaces -o yaml > "$EXPORT_DIR/seccomp-profiles.yaml" 2>/dev/null

# Falco custom rules
kubectl get configmap -n falco falco-custom-rules -o yaml > "$EXPORT_DIR/falco-rules.yaml" 2>/dev/null

# Service accounts (check for automount settings)
echo "Exporting service accounts..."
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  kubectl get serviceaccounts -n "$ns" -o yaml > "$EXPORT_DIR/sa-$ns.yaml"
done

# Secrets (export names only - not values)
echo "Exporting secret inventory..."
kubectl get secrets --all-namespaces -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,TYPE:.type > "$EXPORT_DIR/secrets-inventory.txt"

echo "=== Export complete: $EXPORT_DIR ==="
ls -la "$EXPORT_DIR"
```

### Provider Comparison Matrix

| Feature | [Civo](https://www.civo.com) | [DigitalOcean](https://www.digitalocean.com) | [Vultr](https://www.vultr.com) | [Linode](https://www.linode.com) |
|---------|-----------|-------------------|-------------|-------------|
| Control plane cost | $20/cluster | Free | Free | Free |
| Default CNI | [Cilium](https://cilium.io) | Cilium | [Calico](https://www.tigera.io/project-calico/) | Calico |
| Network policy support | Full (Cilium) | Full (Cilium) | Full (Calico) | Full (Calico) |
| Audit log access | Dashboard + API | Limited (CloudWatch-style) | Limited | Limited |
| etcd encryption | Yes (managed) | Yes (managed) | Yes (managed) | Yes (managed) |
| Node OS | Ubuntu, Talos | Ubuntu | Ubuntu, Debian | Ubuntu, Debian |
| Provisioning speed | ~90 seconds | ~5 minutes | ~5 minutes | ~5 minutes |
| GPU nodes | No | Yes (limited) | Yes | Yes (limited) |

### Migration Procedure

**Step 1: Provision the managed cluster**

```bash
# Example: Civo CLI
civo kubernetes create production-v2 \
  --size g4s.kube.medium \
  --nodes 3 \
  --version 1.30 \
  --cni-plugin cilium \
  --region lon1

# Save kubeconfig
civo kubernetes config production-v2 --save
export KUBECONFIG=~/.kube/config
kubectl config use-context production-v2
```

**Step 2: Apply security configuration**

```bash
# Apply in this order - dependencies matter.

# 1. Namespaces with PSS labels
kubectl apply -f k8s-security-export/namespaces.yaml

# 2. RBAC (cluster-level first, then namespaced)
kubectl apply -f k8s-security-export/rbac-cluster.yaml
kubectl apply -f k8s-security-export/rbac-namespaced.yaml

# 3. Network policies
for f in k8s-security-export/netpol-*.yaml; do
  kubectl apply -f "$f"
done

# 4. Admission policies
# Kyverno: install first, then apply policies
helm install kyverno kyverno/kyverno -n kyverno --create-namespace
kubectl apply -f k8s-security-export/kyverno-policies.yaml

# 5. Falco
helm install falco falcosecurity/falco -n falco --create-namespace \
  --set driver.kind=ebpf
kubectl apply -f k8s-security-export/falco-rules.yaml

# 6. Service accounts (disable automount on default SAs)
for f in k8s-security-export/sa-*.yaml; do
  kubectl apply -f "$f"
done
```

**Step 3: Deploy workloads to staging on the managed cluster**

```bash
# Deploy all workloads to the managed cluster.
# Use the same Helm charts / manifests as the old cluster.
# If using GitOps (ArgoCD/Flux): point the new cluster at the same Git repo.

# ArgoCD: register the new cluster
argocd cluster add production-v2

# Or: manual deployment
kubectl apply -f deployments/ -n production
```

**Step 4: Security verification**

```bash
#!/bin/bash
# verify-migration-security.sh
# Run on the NEW managed cluster to verify security parity.

echo "=== 1. Network Policies ==="
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | grep -v kube-); do
  old_count=$(grep -c "name:" k8s-security-export/netpol-$ns.yaml 2>/dev/null || echo 0)
  new_count=$(kubectl get netpol -n "$ns" --no-headers 2>/dev/null | wc -l)
  if [ "$old_count" != "$new_count" ]; then
    echo "WARN: $ns, old=$old_count, new=$new_count policies"
  else
    echo "OK:   $ns, $new_count policies"
  fi
done

echo ""
echo "=== 2. PSS Labels ==="
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | grep -v kube-); do
  enforce=$(kubectl get ns "$ns" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}' 2>/dev/null)
  echo "$ns: enforce=$enforce"
done

echo ""
echo "=== 3. Connectivity Test ==="
# Test that default-deny is working:
kubectl run test-deny --image=busybox -n production --restart=Never \
  --command -- wget -qO- --timeout=3 http://kubernetes.default 2>&1
result=$?
if [ $result -ne 0 ]; then
  echo "OK: Default deny is blocking unexpected egress"
else
  echo "FAIL: Pod could reach kubernetes API, check network policies"
fi
kubectl delete pod test-deny -n production --ignore-not-found 2>/dev/null

echo ""
echo "=== 4. Admission Control ==="
kubectl run test-priv --image=nginx -n production --restart=Never \
  --overrides='{"spec":{"containers":[{"name":"t","image":"nginx","securityContext":{"privileged":true}}]}}' 2>&1 | grep -q "Forbidden"
if [ $? -eq 0 ]; then
  echo "OK: Privileged pods are blocked"
else
  echo "FAIL: Privileged pods are ALLOWED"
fi
kubectl delete pod test-priv -n production --ignore-not-found 2>/dev/null

echo ""
echo "=== 5. Falco ==="
falco_count=$(kubectl get pods -n falco -l app.kubernetes.io/name=falco --field-selector=status.phase=Running --no-headers | wc -l)
node_count=$(kubectl get nodes --no-headers | wc -l)
echo "Falco: $falco_count/$node_count nodes"
```

**Step 5: Traffic cutover**

```bash
# Update DNS to point to the new cluster's ingress.
# Use a low TTL (60s) for the cutover period.
# Monitor both clusters during the transition.

# After 24 hours with zero traffic on the old cluster:
# Decommission the old cluster.
```

### Post-Migration: What Changed

| Self-Managed | Managed Provider | Your Action |
|-------------|-----------------|-------------|
| API server flags configurable | Provider manages API server | Accept provider defaults. Verify they meet your requirements (check audit log availability). |
| etcd backup is your job | Provider manages etcd | Verify provider backup frequency and retention. |
| Kubernetes version upgrade is your job | Provider handles upgrades (usually with opt-in) | Configure upgrade schedule. Test workloads after upgrades. |
| Node OS patching is your job | Provider manages node images | Verify node OS hardening meets your baseline. Apply custom sysctl if needed via DaemonSet. |
| Audit logging configured by you | Provider has their own audit log access | Verify audit log availability and retention. May need to export to your own backend. |
| CNI choice is yours | Provider's default CNI (may differ) | Verify network policy compatibility if CNI changed. Test all policies. |

## Expected Behaviour

- All workloads running on the managed cluster with identical security posture
- Network policy test matrix passes (same connectivity rules)
- [kube-bench](https://aquasecurity.github.io/kube-bench/) score equal to or better than the self-managed cluster
- All admission policies enforcing (test with known-bad manifest)
- Falco detecting on all nodes
- Zero security regression confirmed by the verification script

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| Switch CNI (e.g., Calico → Cilium) | Network policy syntax is mostly compatible; L7 policies are CNI-specific | Some policies may behave differently | Test ALL network policies on the new cluster before cutover. |
| Lose API server flag control | Can't tune admission plugins, audit policy, or rate limits | Provider defaults may be less secure than your custom config | Verify provider's API server configuration. Supplement with Kyverno/Gatekeeper for admission. |
| Provider manages node OS | Can't customise kernel parameters beyond DaemonSet workarounds | Provider node image may miss some sysctl hardening | Apply critical sysctl settings via a privileged DaemonSet init container. |
| Audit log access varies | Some providers charge for audit logs or provide limited access | May lose detailed audit logging you had with self-managed | Export audit logs to your own backend ([Grafana](https://grafana.com) Cloud #108) via provider's audit log API. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Network policies don't transfer cleanly | Traffic that should be blocked is allowed | Verification script reports policy count mismatch; connectivity test succeeds where it should fail | Re-export and re-apply. Check for CNI-specific policy syntax. |
| RBAC bindings reference non-existent groups | Users/service accounts can't perform expected actions | 403 errors from API server; CI/CD pipeline failures | Update RBAC bindings to match the new cluster's authentication configuration. |
| Admission webhooks not registering | Kyverno/Gatekeeper installed but policies not enforcing | Privileged pod test succeeds (should fail) | Check webhook configuration. Verify Kyverno/Gatekeeper pods are running. |
| DNS cutover causes downtime | TTL not low enough; clients cache old IP | Monitoring shows errors on old cluster after cutover; new cluster receiving no traffic | Pre-reduce TTL to 60s 24 hours before cutover. Monitor both clusters. |

## When to Consider a Managed Alternative

**This article IS the managed alternative.** It is the highest-conversion article on the site. The cost comparison makes the case:

- Self-managed control plane maintenance: 8-16 hours/month × $100-200/hour engineer cost = $800-3,200/month in engineering time.
- Managed Kubernetes: [Civo](https://www.civo.com) at $20/month per cluster + worker node costs. [DigitalOcean](https://www.digitalocean.com) free control plane. [Vultr](https://www.vultr.com) from $10/month per node. [Linode](https://www.linode.com) free control plane.

For a 3-node cluster, managed providers cost $50-100/month total. The engineering time saved pays for the infrastructure many times over.

**Premium content pack:** Kubernetes migration toolkit. export scripts, provider-specific migration guides, verification scripts, and post-migration checklists for Civo, DigitalOcean, Vultr, and Linode.


## Related Articles

- [Hardening a Complete Kubernetes Platform: From Cluster Bootstrap to Production-Ready](/articles/cross-cutting/complete-kubernetes-hardening/)
- [Multi-Cloud Hardening: Consistent Security Posture Across Providers](/articles/cross-cutting/multi-cloud-hardening/)
- [Migrating from Self-Hosted Prometheus to Grafana Cloud: Preserving Dashboards, Alerts, and History](/articles/cross-cutting/migrate-prometheus-grafana-cloud/)
- [Security Hardening for Small Teams: Prioritising Controls When You Cannot Do Everything](/articles/cross-cutting/hardening-small-teams/)
- [Kubernetes Node Hardening: From OS Configuration to kubelet Lockdown](/articles/kubernetes/node-hardening/)
