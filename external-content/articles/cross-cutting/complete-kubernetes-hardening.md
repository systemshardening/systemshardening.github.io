---
title: "Hardening a Complete Kubernetes Platform: From Cluster Bootstrap to Production-Ready"
description: "A fresh Kubernetes cluster (whether bootstrapped with kubeadm, k3s, or provisioned by a managed provider) ships with defaults optimised for getting..."
slug: "complete-kubernetes-hardening"
date: 2026-03-09
lastmod: 2026-03-09
category: "cross-cutting"
tags: ["kubernetes", "hardening", "rbac", "network-policy", "admission-control", "seccomp", "falco", "audit-logging"]
personas: ["platform-engineer", "devops-engineer"]
article_number: 91
difficulty: "advanced"
estimated_reading_time: 35
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
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
premium_pack: "kubernetes-hardening-bundle"
published: true
layout: article.njk
permalink: "/articles/cross-cutting/complete-kubernetes-hardening/index.html"
---

# Hardening a Complete [Kubernetes](https://kubernetes.io) Platform: From Cluster Bootstrap to Production-Ready

## Problem

A fresh Kubernetes cluster (whether bootstrapped with kubeadm, k3s, or provisioned by a managed provider) ships with defaults optimised for getting started, not for production security:

- **No network policies.** Every pod can communicate with every other pod across all namespaces. A compromised pod in a development namespace can reach the production database.
- **No admission controls beyond defaults.** Privileged containers are allowed. Pods can mount host paths, use the host network, and run as root.
- **No audit logging.** API server activity is not recorded. You cannot answer "who did what, when" after an incident.
- **Default service account tokens mounted into every pod.** A compromised pod automatically has a token that can query the Kubernetes API server.
- **No seccomp profiles.** Containers can invoke any of 300+ syscalls available to the kernel, including those used for container escape.
- **No runtime detection.** If an attacker gets past prevention controls, there is no system watching for suspicious behaviour inside containers.

Most hardening guides cover one of these areas in isolation. This article covers all of them in a single, cohesive walkthrough, so nothing falls through the gaps between guides.

This is the "I just got a new cluster, now what?" article.

**Target systems:** Kubernetes 1.29+ on any infrastructure, kubeadm, k3s, or managed providers (EKS, GKE, AKS, Civo, DigitalOcean, Vultr, Linode). Where managed providers handle a control automatically, it is noted.

## Threat Model

- **Adversary:** Attacker with initial code execution inside a pod. This is the starting position for the majority of Kubernetes attacks, achieved through an RCE vulnerability in application code, a compromised container image (supply chain attack), or a compromised dependency.
- **Access level:** Unprivileged process running inside a container. Has access to the default service account token (if not disabled), the container filesystem, and the network (if no network policies exist).
- **Objective:** Escape the container to gain node-level access. Escalate to cluster-admin. Exfiltrate secrets (database credentials, API keys, TLS private keys). Move laterally to other namespaces and services. Establish persistence (create new service accounts, deploy backdoor pods).
- **Blast radius without hardening:** Full cluster compromise from a single compromised pod. The attacker can read all secrets, access all services, and control every workload in the cluster.
- **Blast radius with hardening:** The compromised pod is contained to its namespace. Network policies block lateral movement. Seccomp blocks escalation syscalls. RBAC prevents API server abuse. Audit logging records the attack. [Falco](https://falco.org) alerts within seconds.

## Configuration

### Step 1: Network Policies - Default Deny

This is the single highest-impact hardening control. Apply it first.

```yaml
# default-deny-all.yaml
# Apply to every namespace (except kube-system - handle separately).
# This blocks ALL ingress and egress traffic for all pods in the namespace.

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production  # Apply to each namespace individually
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

**You must immediately allow DNS** or every pod in the namespace will fail to resolve hostnames:

```yaml
# allow-dns.yaml
# Apply to every namespace that has default-deny-egress.
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

Then add per-service ingress policies:

```yaml
# allow-frontend-to-api.yaml
# Example: allow frontend pods to reach API pods on port 8080.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-api
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

**Apply and verify:**

```bash
# Apply policies
kubectl apply -f default-deny-all.yaml
kubectl apply -f allow-dns.yaml
kubectl apply -f allow-frontend-to-api.yaml

# Test: this should succeed (frontend → api is allowed)
kubectl exec -n production deploy/frontend -- curl -s -o /dev/null -w "%{http_code}" http://api:8080/health
# Expected: 200

# Test: this should fail (api → frontend is not allowed)
kubectl exec -n production deploy/api -- curl -s --connect-timeout 3 -o /dev/null -w "%{http_code}" http://frontend:80/
# Expected: timeout (no response, connection blocked by policy)
```

### Step 2: Pod Security Standards

Enforce the `restricted` Pod Security Standard on all namespaces. This blocks privileged containers, host path mounts, host networking, and running as root.

```bash
# Label every non-system namespace to enforce the restricted standard.
# warn and audit modes log violations; enforce mode blocks them.

for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | grep -v kube-system | grep -v kube-public | grep -v kube-node-lease); do
  kubectl label namespace "$ns" \
    pod-security.kubernetes.io/enforce=restricted \
    pod-security.kubernetes.io/warn=restricted \
    pod-security.kubernetes.io/audit=restricted \
    --overwrite
done

# For kube-system, use baseline (not restricted) - some system components
# need capabilities that restricted blocks.
kubectl label namespace kube-system \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted \
  --overwrite
```

**Verify enforcement:**

```bash
# This should be blocked (privileged container in a restricted namespace):
kubectl run test-privileged --image=nginx --restart=Never \
  --overrides='{"spec":{"containers":[{"name":"test","image":"nginx","securityContext":{"privileged":true}}]}}' \
  -n production

# Expected error:
# Error from server (Forbidden): pods "test-privileged" is forbidden:
# violates PodSecurity "restricted:latest": privileged
```

### Step 3: RBAC - Least Privilege

```yaml
# namespace-developer-role.yaml
# Role for developers: can view and manage workloads in their namespace.
# Cannot access secrets, cannot modify RBAC, cannot exec into pods in production.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: developer
  namespace: production
rules:
  - apiGroups: ["apps"]
    resources: ["deployments", "replicasets", "statefulsets"]
    verbs: ["get", "list", "watch", "create", "update", "patch"]
  - apiGroups: [""]
    resources: ["pods", "services", "configmaps"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["pods/log"]
    verbs: ["get"]
  # Explicitly no access to: secrets, pods/exec, rolebindings
```

```yaml
# ci-deployer-role.yaml
# Role for CI/CD: can deploy workloads but cannot read secrets or exec into pods.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ci-deployer
  namespace: production
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "update", "patch"]
  - apiGroups: [""]
    resources: ["services", "configmaps"]
    verbs: ["get", "list", "create", "update", "patch"]
```

**Disable default service account token mounting:**

```yaml
# For every namespace, patch the default service account:
kubectl patch serviceaccount default -n production \
  -p '{"automountServiceAccountToken": false}'

# For workloads that need API access, create a dedicated service account
# with only the permissions that workload requires.
```

### Step 4: Seccomp Profiles

Apply the `RuntimeDefault` seccomp profile to all workloads as a minimum. This blocks the most dangerous syscalls while allowing standard application behaviour.

```yaml
# deployment-with-seccomp.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        fsGroup: 65534
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: api
          image: registry.example.com/api:v1.2.3
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 256Mi
          ports:
            - containerPort: 8080
```

This deployment demonstrates all key security context settings:

- `runAsNonRoot: true`, pod cannot run as root
- `seccompProfile: RuntimeDefault`, blocks dangerous syscalls
- `allowPrivilegeEscalation: false`, no setuid, no capability gains
- `readOnlyRootFilesystem: true`, container cannot write to its own filesystem
- `capabilities.drop: ["ALL"]`, drops every Linux capability
- `resources.limits`, prevents resource exhaustion

### Step 5: Audit Logging

Enable Kubernetes API server audit logging to record who did what, when.

```yaml
# audit-policy.yaml
# Place this file on the control plane node (self-managed clusters only).
# Managed providers have their own audit log mechanisms.
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Log secret access at RequestResponse level (capture the request body).
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets"]

  # Log RBAC changes at RequestResponse level.
  - level: RequestResponse
    resources:
      - group: "rbac.authorization.k8s.io"
        resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]

  # Log pod exec at RequestResponse level.
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["pods/exec", "pods/attach"]

  # Log all other mutations at Request level.
  - level: Request
    verbs: ["create", "update", "patch", "delete"]

  # Log reads at Metadata level (no request/response body).
  - level: Metadata
    verbs: ["get", "list", "watch"]

  # Skip logging for health checks and metrics (high volume, low value).
  - level: None
    resources:
      - group: ""
        resources: ["endpoints", "events"]
    verbs: ["get", "list", "watch"]
  - level: None
    nonResourceURLs:
      - "/healthz*"
      - "/readyz*"
      - "/livez*"
      - "/metrics"
```

For self-managed clusters, add these flags to the API server:

```
--audit-policy-file=/etc/kubernetes/audit-policy.yaml
--audit-log-path=/var/log/kubernetes/audit.log
--audit-log-maxage=30
--audit-log-maxbackup=10
--audit-log-maxsize=100
```

For managed clusters:
- **EKS:** Enable audit logging in the EKS console (CloudWatch Logs)
- **GKE:** Audit logs are enabled by default (Cloud Logging)
- **[Civo](https://www.civo.com), [DigitalOcean](https://www.digitalocean.com):** Check provider documentation for audit log access, availability varies

### Step 6: Runtime Detection with Falco

Deploy Falco as a DaemonSet to detect suspicious runtime behaviour inside containers.

```bash
# Install Falco via Helm with the eBPF driver (no kernel module needed).
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

helm install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  --set driver.kind=ebpf \
  --set falcosidekick.enabled=true \
  --set falcosidekick.config.slack.webhookurl="https://hooks.slack.com/services/YOUR/WEBHOOK/URL" \
  --set resources.requests.cpu=100m \
  --set resources.requests.memory=256Mi \
  --set resources.limits.cpu=500m \
  --set resources.limits.memory=512Mi
```

Add custom rules for the highest-priority detections:

```yaml
# falco-custom-rules.yaml
# ConfigMap with custom Falco rules for this cluster.
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-custom-rules
  namespace: falco
data:
  custom-rules.yaml: |
    - rule: Reverse Shell Detected
      desc: A network connection was established by a process that also has a shell as a child.
      condition: >
        evt.type=connect and evt.dir=< and container
        and proc.name in (bash, sh, dash, zsh)
        and fd.sip != "0.0.0.0"
        and not fd.sip in (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8)
      output: >
        Reverse shell detected (container=%container.name image=%container.image.repository
        process=%proc.name dest=%fd.sip:%fd.sport)
      priority: CRITICAL

    - rule: Sensitive File Access in Container
      desc: A container accessed a sensitive file that should not be read during normal operation.
      condition: >
        open_read and container
        and fd.name in (/etc/shadow, /etc/gshadow, /run/secrets/kubernetes.io/serviceaccount/token)
        and not proc.name in (vault, consul)
      output: >
        Sensitive file read in container (file=%fd.name container=%container.name
        image=%container.image.repository process=%proc.name)
      priority: WARNING
```

**Verify Falco is running and detecting:**

```bash
# Check Falco pods are running on all nodes
kubectl get pods -n falco -o wide
# Expected: one Falco pod per node, all STATUS=Running

# Trigger a test detection (shell in a non-shell container):
kubectl exec -n production deploy/api -- /bin/sh -c "echo test"
# Check Falco logs within 5 seconds:
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=5 | grep "Shell"
# Expected: alert for unexpected shell execution
```

### Step 7: Secrets Encryption at Rest

Ensure Kubernetes secrets are encrypted in etcd (self-managed clusters only, managed providers handle this):

```yaml
# encryption-config.yaml
# Place on control plane node at /etc/kubernetes/encryption-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: $(head -c 32 /dev/urandom | base64)
      - identity: {}
```

Add to API server flags: `--encryption-provider-config=/etc/kubernetes/encryption-config.yaml`

**Verify encryption is active:**

```bash
# Read a secret directly from etcd (requires etcd access):
ETCDCTL_API=3 etcdctl get /registry/secrets/production/my-secret | hexdump -C | head -5
# If encrypted: you will see binary data starting with "k8s:enc:aescbc:v1:key1"
# If NOT encrypted: you will see the secret value in plaintext
```

### Verification Checklist

Run this after completing all steps:

```bash
#!/bin/bash
# kubernetes-hardening-verification.sh

echo "=== 1. Network Policies ==="
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  count=$(kubectl get networkpolicies -n "$ns" --no-headers 2>/dev/null | wc -l)
  if [ "$count" -eq 0 ]; then
    echo "WARN: $ns has NO network policies"
  else
    echo "OK:   $ns has $count network policies"
  fi
done

echo ""
echo "=== 2. Pod Security Standards ==="
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  enforce=$(kubectl get ns "$ns" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}' 2>/dev/null)
  if [ -z "$enforce" ]; then
    echo "WARN: $ns has no PSS enforcement label"
  else
    echo "OK:   $ns enforces PSS level=$enforce"
  fi
done

echo ""
echo "=== 3. Default Service Account Token ==="
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | grep -v kube-); do
  automount=$(kubectl get sa default -n "$ns" -o jsonpath='{.automountServiceAccountToken}' 2>/dev/null)
  if [ "$automount" != "false" ]; then
    echo "WARN: $ns default SA still automounts token"
  else
    echo "OK:   $ns default SA token automount disabled"
  fi
done

echo ""
echo "=== 4. Falco ==="
falco_pods=$(kubectl get pods -n falco -l app.kubernetes.io/name=falco --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l)
node_count=$(kubectl get nodes --no-headers | wc -l)
if [ "$falco_pods" -eq "$node_count" ]; then
  echo "OK:   Falco running on all $node_count nodes"
else
  echo "WARN: Falco running on $falco_pods of $node_count nodes"
fi

echo ""
echo "=== 5. Privileged Pod Test ==="
kubectl run hardening-test --image=nginx --restart=Never -n default \
  --overrides='{"spec":{"containers":[{"name":"t","image":"nginx","securityContext":{"privileged":true}}]}}' 2>&1 | grep -q "Forbidden"
if [ $? -eq 0 ]; then
  echo "OK:   Privileged pods are blocked"
else
  echo "FAIL: Privileged pods are ALLOWED"
  kubectl delete pod hardening-test -n default --ignore-not-found 2>/dev/null
fi
```

## Expected Behaviour

After completing all 7 steps:

- **Network isolation:** Pods cannot communicate across namespaces without explicit network policies. Default-deny is the baseline.
- **Pod security:** Privileged containers, host mounts, host networking, and running as root are all blocked by Pod Security Standards.
- **RBAC:** Developers and CI/CD pipelines have namespace-scoped, least-privilege access. No workload has cluster-admin.
- **Seccomp:** All workloads run with RuntimeDefault seccomp profile at minimum, blocking dangerous syscalls.
- **Audit logging:** API server activity is recorded. Secret access, RBAC changes, and pod exec are logged at RequestResponse level.
- **Runtime detection:** Falco alerts within seconds of suspicious behaviour, reverse shells, sensitive file access, unexpected process execution.
- **Secrets encryption:** Secrets are encrypted at rest in etcd (self-managed) or by the provider (managed).
- **Verification script:** Returns all-OK when run against the hardened cluster.

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Default-deny network policies | Every new service needs a policy before it can communicate | Developer friction: "it works in dev but not staging" | Add network policy creation to the service deployment checklist. Provide templates. |
| Pod Security Standards (restricted) | Many Helm charts fail to deploy without modification | Significant initial effort to patch charts and manifests | Start with `warn` mode for 2 weeks. Fix violations. Then switch to `enforce`. |
| Disable service account automount | Workloads that rely on auto-mounted tokens break | CI/CD, monitoring agents, and operators may need API access | Create dedicated service accounts for workloads that need API access. |
| Seccomp RuntimeDefault | Blocks some syscalls that uncommon applications may need | Application crashes with EPERM if it uses a blocked syscall | Test all workloads with RuntimeDefault in staging. If a syscall is blocked, use a custom profile. |
| Audit logging (RequestResponse for secrets) | Significant log volume for clusters with frequent secret access | Storage cost; 5-10x more data than Metadata-only logging | Ship to external storage ([Grafana](https://grafana.com) Cloud #108, Axiom #112). Use Metadata for most resources, RequestResponse only for secrets and RBAC. |
| Falco DaemonSet | 1-3% CPU overhead per node; 256-512MB memory per node | Measurable on small nodes (2 CPU, 4GB RAM) | Tune rules to reduce rule count. Use eBPF driver (lower overhead than kernel module). |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Default-deny blocks DNS | All pods in namespace fail DNS resolution | Immediate. every service returns DNS errors; coreDNS metrics show no queries from namespace | Apply the `allow-dns` network policy to the namespace |
| PSS rejects deployment | Helm install or kubectl apply returns admission error | `kubectl describe` shows Pod Security admission rejection with specific violation listed | Switch to `warn` mode, fix the manifests, then re-enable `enforce` |
| RBAC too restrictive for CI/CD | Deployment pipeline fails with 403 Forbidden | Pipeline logs show `User "system:serviceaccount:ci:deployer" cannot update deployments` | Add the missing permission to the CI deployer role. Do not grant cluster-admin. |
| Seccomp blocks required syscall | Application crashes or hangs with EPERM errors | Container logs show operation not permitted; `dmesg` shows seccomp audit entries | Use a custom seccomp profile that allows the specific syscall. See [Seccomp Profiles for Production Workloads: Writing, Testing, and Deploying Custom Profiles](/articles/kubernetes/seccomp-profiles/) for custom profile creation. |
| Audit log volume fills disk | API server becomes slow or crashes | Node disk pressure alerts; API server latency increases | Ship logs to external storage. Reduce audit level for high-volume, low-value resources. |
| Falco false positive flood | Alert fatigue; team ignores Falco alerts | Alert volume exceeds 50/day; on-call stops investigating | Tune Falco rules: add container image exceptions for known-good behaviour. See [Runtime Security with Falco on Kubernetes: Rules, Tuning, and Response Automation](/articles/kubernetes/falco-runtime-security/) for Falco tuning. |

## When to Consider a Managed Alternative

**This article is the strongest argument for managed Kubernetes.** After reading it, you understand the full scope of self-managed cluster hardening:

- **Initial setup:** 20-30 hours to implement all 7 steps and verify.
- **Ongoing maintenance:** 8-16 hours per month for node patching, Kubernetes version upgrades, certificate rotation, etcd backup verification, Falco rule tuning, and audit log management.
- **Expertise required:** Deep knowledge of Kubernetes internals (API server flags, kubelet configuration, etcd encryption), Linux kernel security (seccomp, capabilities, cgroups), and networking (CNI-specific network policy behaviour).

**What managed providers handle:**

Managed Kubernetes providers ([Civo](https://www.civo.com), [DigitalOcean](https://www.digitalocean.com), [Vultr](https://www.vultr.com), [Linode](https://www.linode.com)) handle the control plane: API server configuration and hardening, etcd encryption and backup, Kubernetes version upgrades, control plane high availability, and node provisioning and patching.

This eliminates Steps 5 (audit logging, varies by provider), Step 7 (secrets encryption, handled by provider), and most of the ongoing maintenance burden.

**What you still own, even on managed clusters:**

Steps 1-4 and Step 6 are your responsibility on every cluster, managed or self-managed:

- Network policies (Step 1)
- Pod Security Standards (Step 2)
- RBAC (Step 3)
- Seccomp profiles (Step 4)
- Runtime detection with Falco (Step 6)

This article's guidance applies directly to managed clusters. The difference is that you skip the control plane hardening and focus entirely on workload security.

**Migration path:** See [Migrating from Self-Managed Kubernetes to a Managed Provider Without Losing Your Security Posture](/articles/cross-cutting/migrate-to-managed-k8s/): Migrating from Self-Managed Kubernetes to a Managed Provider](/articles/cross-cutting/migrate-to-managed-k8s/) for a step-by-step migration guide that preserves all your security configurations.

**Runtime security at scale:** [Sysdig](https://sysdig.com) builds on Falco with managed detection rules, multi-cluster visibility, compliance reporting, and ML-powered anomaly detection. When Falco rule tuning across 3+ clusters exceeds 4-8 hours per month, Sysdig is the natural upgrade.

**Observability:** [Grafana Cloud](https://grafana.com/cloud) for centralized audit logs, security metrics, and the dashboards described in [Security Dashboards That Engineers Actually Use: Grafana Designs for Hardening Verification](/articles/observability/security-dashboards/): Security Dashboards That Engineers Use](/articles/observability/security-dashboards/).

**Cost comparison:** A 3-node managed Kubernetes cluster on [Civo](https://www.civo.com) costs approximately $60/month ($20/cluster + worker nodes). The 8-16 hours per month of self-managed maintenance at an engineer's hourly cost almost always exceeds this.


## Related Articles

- [Migrating from Self-Managed Kubernetes to a Managed Provider Without Losing Your Security Posture](/articles/cross-cutting/migrate-to-managed-k8s/)
- [Incident Response Hardening Playbook: From Detection to Post-Mortem](/articles/cross-cutting/incident-response-hardening-playbook/)
- [Security Hardening for Small Teams: Prioritising Controls When You Cannot Do Everything](/articles/cross-cutting/hardening-small-teams/)
- [Multi-Cloud Hardening: Consistent Security Posture Across Providers](/articles/cross-cutting/multi-cloud-hardening/)
- [The Hardening Scorecard: Measuring and Tracking Security Posture](/articles/cross-cutting/hardening-scorecard/)
