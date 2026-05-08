---
title: "Kubernetes Network Policies That Actually Work: From Default Deny to Microsegmentation"
description: "By default, every pod in a Kubernetes cluster can communicate with every other pod across all namespaces. There are no network boundaries."
slug: "kubernetes-network-policies"
date: 2026-03-29
lastmod: 2026-03-29
category: "kubernetes"
tags: ["kubernetes", "network-policy", "cilium", "calico", "microsegmentation", "cni"]
personas: ["platform-engineer", "security-engineer"]
article_number: 18
difficulty: "intermediate"
estimated_reading_time: 22
provider_bridges:
  - name: "Isovalent"
    id: 54
    category: "service-mesh"
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
premium_pack: "kubernetes-network-policy-pack"
published: true
layout: article.njk
permalink: "/articles/kubernetes/kubernetes-network-policies/index.html"
---

# [Kubernetes](https://kubernetes.io) Network Policies That Actually Work: From Default Deny to Microsegmentation

## Problem

By default, every pod in a Kubernetes cluster can communicate with every other pod across all namespaces. There are no network boundaries. A compromised pod in a development namespace can reach the production database. A compromised web frontend can directly access the secrets store. A crypto miner deployed in any namespace can exfiltrate data to any external IP.

Network policies exist to fix this, but they have a reputation for being difficult:

- **CNI-dependent behaviour.** The Kubernetes NetworkPolicy API is a specification, not an implementation. [Calico](https://www.tigera.io/project-calico/), [Cilium](https://cilium.io), and cloud-native CNIs each implement it differently. Policies that work on Cilium may behave differently on Calico. Some CNIs support egress policies; some do not support egress to specific CIDR ranges reliably.
- **DNS is the most common pitfall.** Apply a default-deny egress policy and every pod in the namespace immediately fails DNS resolution, because DNS egress to [CoreDNS](https://coredns.io) in `kube-system` is now blocked. This is the #1 reason teams abandon network policies after the first attempt.
- **Testing is manual and error-prone.** There is no built-in tool to validate that policies enforce the expected connectivity. Teams apply policies and hope for the best, discovering gaps only when something breaks or during a security audit.
- **Policy count grows linearly with services.** A namespace with 20 microservices needs 20+ policies. Writing and maintaining these takes 30-60 minutes per service, and every new service dependency requires a policy update.

This article provides a complete, tested approach: start with default-deny, solve DNS immediately, build per-service policies, test systematically, and monitor for dropped traffic.

**Target systems:** Kubernetes 1.29+ with Calico, Cilium, or any CNI that supports the NetworkPolicy API. Specific notes for CNI-dependent behaviour.

## Threat Model

- **Adversary:** Attacker with code execution in a pod (RCE, supply chain compromise, compromised container image).
- **Access level:** Unprivileged process inside a container with network access to the cluster network.
- **Objective:** Lateral movement to other services (access database from compromised frontend), data exfiltration (send data to external attacker-controlled server), service disruption (DoS other pods), and internal reconnaissance (scan the cluster network for open ports and services).
- **Blast radius:** Without network policies, entire cluster. Every pod can reach every other pod and any external IP. With default-deny + per-service policies, the compromised pod can only reach its explicitly allowed dependencies. Exfiltration is blocked unless the policy explicitly allows external egress.

## Configuration

### Step 1: Default-Deny for Every Namespace

Apply default-deny ingress AND egress to every non-system namespace. This is the foundation, everything is blocked, then you allowlist what is needed.

```yaml
# default-deny.yaml
# Apply to each namespace individually.
# Do NOT apply to kube-system (breaks cluster components).
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}  # Matches all pods in the namespace
  policyTypes:
    - Ingress
    - Egress
```

```bash
# Apply to all non-system namespaces:
for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' \
  | tr ' ' '\n' \
  | grep -v -E '^kube-'); do

  kubectl apply -n "$ns" -f - <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
EOF

  echo "Applied default-deny to namespace: $ns"
done
```

**After this step:** Every pod in every non-system namespace has zero network access, no ingress, no egress, no DNS. This is intentional. The next step fixes DNS.

### Step 2: Allow DNS (Critical - Do This Immediately)

```yaml
# allow-dns.yaml
# Apply to every namespace that has default-deny.
# Without this, no pod can resolve hostnames.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    # Allow DNS to CoreDNS in kube-system
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
        - podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

**CNI-specific note:** The `namespaceSelector` + `podSelector` combination behaves differently across CNIs:

- **Cilium:** Both selectors must match (AND logic). This is correct.
- **Calico:** Both selectors must match (AND logic). This is correct.
- **Some cloud-native CNIs:** May treat them as OR logic. Test with your specific CNI.

The safest approach (works on all CNIs):

```yaml
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
```

This allows egress to any pod in `kube-system` on port 53, slightly broader than targeting CoreDNS specifically, but guaranteed to work on every CNI.

```bash
# Apply DNS allow to all non-system namespaces:
for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' \
  | tr ' ' '\n' \
  | grep -v -E '^kube-'); do

  kubectl apply -n "$ns" -f allow-dns.yaml
  echo "Applied allow-dns to namespace: $ns"
done
```

**Verify DNS works:**

```bash
kubectl run dns-test --image=busybox --restart=Never -n production \
  --command -- nslookup kubernetes.default
# Expected: Name resolves successfully

kubectl delete pod dns-test -n production
```

### Step 3: Per-Service Ingress Policies

For each service, create a policy that allows traffic only from its known callers.

**Example: Frontend → API → Database**

```yaml
# api-ingress.yaml
# Allow the API to receive traffic from the frontend on port 8080.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-allow-frontend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: api
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
      ports:
        - port: 8080
          protocol: TCP
```

```yaml
# database-ingress.yaml
# Allow the database to receive traffic from the API on port 5432.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: database-allow-api
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: database
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: api
      ports:
        - port: 5432
          protocol: TCP
```

```yaml
# frontend-ingress.yaml
# Allow the frontend to receive traffic from the ingress controller.
# The ingress controller is typically in a different namespace.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-allow-ingress
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: frontend
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress-nginx
      ports:
        - port: 80
          protocol: TCP
```

### Step 4: Egress Controls

For services that need external access (e.g., calling a payment API):

```yaml
# api-egress.yaml
# Allow the API to reach the payment processor and nothing else externally.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-egress
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: api
  policyTypes:
    - Egress
  egress:
    # DNS (already covered by allow-dns, but explicit here for clarity)
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
    # Allow egress to the database
    - to:
        - podSelector:
            matchLabels:
              app: database
      ports:
        - port: 5432
          protocol: TCP
    # Allow egress to payment processor (external IP)
    - to:
        - ipBlock:
            cidr: 198.51.100.0/24  # Payment processor IP range
      ports:
        - port: 443
          protocol: TCP
```

### Step 5: Testing Strategy

**Manual testing with ephemeral debug pods:**

```bash
# Test: frontend → api (should succeed)
kubectl run test-conn --image=busybox --restart=Never -n production \
  -l app=frontend --command -- wget -qO- --timeout=3 http://api:8080/health
# Expected: 200 response or health check output

# Test: api → frontend (should fail - not allowed)
kubectl run test-conn2 --image=busybox --restart=Never -n production \
  -l app=api --command -- wget -qO- --timeout=3 http://frontend:80/
# Expected: timeout (connection blocked by policy)

# Test: api → external internet (should fail - not in egress allowlist)
kubectl run test-egress --image=busybox --restart=Never -n production \
  -l app=api --command -- wget -qO- --timeout=3 http://example.com
# Expected: timeout (egress blocked)

# Clean up:
kubectl delete pod test-conn test-conn2 test-egress -n production --ignore-not-found
```

**Automated policy testing script:**

```bash
#!/bin/bash
# network-policy-test.sh
# Tests expected connectivity between services.

NAMESPACE="production"
PASS=0
FAIL=0

test_connection() {
    local from_label=$1
    local to_host=$2
    local to_port=$3
    local expected=$4  # "pass" or "fail"
    local desc=$5

    result=$(kubectl run "test-$(date +%s)" --image=busybox --restart=Never \
      -n "$NAMESPACE" -l "app=$from_label" --rm -i --timeout=10s \
      --command -- wget -qO- --timeout=3 "http://${to_host}:${to_port}/" 2>&1)

    if [ "$expected" = "pass" ] && echo "$result" | grep -qv "timed out"; then
        echo "PASS: $desc"
        ((PASS++))
    elif [ "$expected" = "fail" ] && echo "$result" | grep -q "timed out"; then
        echo "PASS: $desc (correctly blocked)"
        ((PASS++))
    else
        echo "FAIL: $desc (expected=$expected)"
        ((FAIL++))
    fi
}

echo "=== Network Policy Tests ==="
test_connection "frontend" "api" "8080" "pass" "frontend → api:8080"
test_connection "api" "database" "5432" "pass" "api → database:5432"
test_connection "api" "frontend" "80" "fail" "api → frontend:80 (should be blocked)"
test_connection "database" "api" "8080" "fail" "database → api:8080 (should be blocked)"
test_connection "frontend" "database" "5432" "fail" "frontend → database:5432 (should be blocked)"

echo ""
echo "Results: $PASS passed, $FAIL failed"
exit $FAIL
```

### Step 6: Monitoring Dropped Traffic

**Cilium with [Hubble](https://docs.cilium.io/en/stable/observability/hubble/):**

```bash
# Install Hubble CLI
HUBBLE_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/hubble/master/stable.txt)
curl -L --remote-name-all "https://github.com/cilium/hubble/releases/download/${HUBBLE_VERSION}/hubble-linux-amd64.tar.gz"
tar xzf hubble-linux-amd64.tar.gz
sudo mv hubble /usr/local/bin/

# View dropped traffic in real time:
hubble observe --verdict DROPPED --namespace production

# View dropped traffic for a specific pod:
hubble observe --verdict DROPPED --to-pod production/api-7d8f9b6c4d-x2k4l
```

**[Prometheus](https://prometheus.io) metrics for policy drops:**

```yaml
# Cilium provides these metrics out of the box:
# cilium_drop_count_total - total dropped packets by reason
# cilium_policy_verdict - policy decisions (forwarded, dropped, denied)

# Alert on new drop sources (pods trying to reach blocked destinations):
groups:
  - name: network-policy-monitoring
    rules:
      - alert: NetworkPolicyDrop
        expr: rate(cilium_drop_count_total{reason="POLICY_DENIED"}[5m]) > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Network policy dropping traffic in {{ $labels.namespace }}"
          description: "Packets being dropped by network policy. Check if a new service needs a policy update."
```

## Expected Behaviour

After applying all network policies:

- Pods can only communicate with explicitly allowed destinations
- DNS resolution works in every namespace (allow-dns policy)
- Ingress controller can reach frontend pods
- Frontend can reach API pods; API can reach database pods; no other paths exist
- External egress is blocked except for explicitly allowlisted IPs
- `hubble observe --verdict DROPPED` shows blocked traffic
- `network-policy-test.sh` returns all-pass
- New services deployed without a network policy have zero connectivity (default-deny catches them)

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Default-deny per namespace | Every new service needs a policy before it works | Developer friction: "it works locally but not in staging" | Make network policy a required part of the service deployment template. Provide a policy generator tool. |
| Per-service policies | 30-60 minutes per service to write and test | Policy maintenance grows linearly with service count | Use [Kyverno](https://kyverno.io) to generate baseline policies automatically from labels. |
| Egress restrictions | Blocks unexpected outbound connections | Legitimate external API calls blocked until allowlisted | Maintain an egress allowlist per namespace. Alert on new blocked egress (may indicate a missing policy, not an attack). |
| CIDR-based egress to external IPs | IP ranges can change for external services | Policy breaks if external service changes IP | Use DNS-based egress policies (Cilium CiliumNetworkPolicy supports FQDN rules; standard NetworkPolicy does not). |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| DNS egress not allowed | Every pod in namespace fails DNS resolution | Immediate. all services return DNS errors; application logs show "name resolution failed" | Apply the allow-dns policy to the namespace. This is the #1 issue, always apply DNS allow immediately after default-deny. |
| Policy selector doesn't match any pods | Policy has no effect. traffic that should be blocked is allowed | `kubectl get netpol -o yaml` shows the policy but `hubble observe` shows traffic flowing; connectivity test shows unexpected success | Check label selectors against actual pod labels: `kubectl get pods -l app=api -n production`. Fix the selector to match. |
| Health check probes blocked | Pods show as unhealthy; Kubernetes restarts them continuously | Pod restart count increases; readiness probe failures in `kubectl describe pod` | Add ingress allow for kubelet health checks. Source IP depends on CNI. check your CNI documentation for the health check source CIDR. |
| Egress to external API blocked | Application feature fails (payment processing, email sending, webhook) | Application logs show connection timeout to external service; `hubble observe --verdict DROPPED` shows the blocked connection | Add the external IP/CIDR to the service's egress policy. Use FQDN-based policies on Cilium for services with dynamic IPs. |
| Policy applied to wrong namespace | Wrong namespace loses connectivity | Connectivity tests in the wrong namespace fail; `kubectl get netpol -n <namespace>` shows unexpected policies | Delete the policy from the wrong namespace. Re-apply to the correct one. |

## When to Consider a Managed Alternative

**Transition point:** Writing per-service policies for 50+ microservices takes 30-60 minutes each and must be updated with every new service dependency. Maintaining 50+ policies across 2+ clusters with different CNIs creates drift. At this scale, network policy lifecycle management becomes a dedicated task.

**Recommended providers:**

- **[Isovalent](https://isovalent.com) Cilium Enterprise:** Policy lifecycle management, policy editor UI, network flow visualization, policy recommendation engine that suggests policies based on observed traffic patterns. Multi-cluster policy distribution.
- **[Sysdig](https://sysdig.com):** Network policy visualization and gap analysis. Shows which pods have no network policy and which policies have no matching pods. Identifies over-permissive policies.

**What you still control:** The policies themselves (what each service can reach) remain your decision. Managed tools help you create, visualize, and verify policies, but the security intent is yours.

**Premium content pack:** Kyverno policy pack that enforces "every namespace must have a default-deny policy" and "every deployment must have a corresponding network policy." Includes policy templates for common service architectures (frontend-api-db, worker-queue-db, ingress-service).


## Related Articles

- [Network Segmentation for AI Training Infrastructure](/articles/kubernetes/ai-training-network-segmentation/)
- [Multi-Tenancy Hardening in Kubernetes: Namespace Isolation, Resource Quotas, and Network Boundaries](/articles/kubernetes/multi-tenancy-hardening/)
- [Seccomp Profiles for Production Workloads: Writing, Testing, and Deploying Custom Profiles](/articles/kubernetes/seccomp-profiles/)
- [Kubernetes RBAC Design Patterns: Least Privilege Without Paralysing Developers](/articles/kubernetes/rbac-design-patterns/)
- [Kubernetes API Server Hardening: Flags, Authentication, and Audit Logging](/articles/kubernetes/api-server-hardening/)
