---
title: "Claude for Kubernetes Security Auditing: Finding Privilege Escalation Paths Scanners Cannot See"
description: "Kubernetes security scanners evaluate resources individually. Tools like kube-bench check node configurations against CIS benchmarks."
slug: "claude-kubernetes-audit"
date: 2026-03-21
lastmod: 2026-03-21
category: "ai-landscape"
tags: ["claude", "llm", "kubernetes", "rbac", "security-audit", "privilege-escalation", "helm"]
personas: ["security-engineer", "platform-engineer", "devops-engineer", "sre"]
article_number: 138
difficulty: "advanced"
estimated_reading_time: 22
provider_bridges:
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
  - name: "Falco"
    id: 89
    category: "runtime-detection"
published: true
layout: article.njk
permalink: "/articles/ai-landscape/claude-kubernetes-audit/index.html"
---

# [Claude](https://claude.ai) for [Kubernetes](https://kubernetes.io) Security Auditing: Finding Privilege Escalation Paths Scanners Cannot See

## Problem

Kubernetes security scanners evaluate resources individually. Tools like [kube-bench](https://aquasecurity.github.io/kube-bench/) check node configurations against CIS benchmarks. Kubesec scores pod security contexts. Polaris validates workload best practices. [OPA](https://www.openpolicyagent.org)/[Gatekeeper](https://open-policy-agent.github.io/gatekeeper/) enforces admission policies. Each tool is effective within its scope, but none of them traces the multi-step paths that attackers actually use to escalate privileges in a cluster.

An attacker who compromises a pod does not stop at the pod. They check what ServiceAccount is mounted, query the Kubernetes API to discover their RBAC permissions, find that they can create pods in another namespace, create a pod with a hostPath mount, read the node's kubelet credentials from disk, and use those credentials to access every secret in the cluster. This is a five-step privilege escalation chain. No individual resource in the chain is flagged by a scanner. The ServiceAccount is scoped to one namespace. The Role allows pod creation, which sounds reasonable. The namespace does not have a PodSecurityPolicy (or PodSecurityStandard) blocking hostPath. The kubelet credentials are where Kubernetes puts them by default.

Claude traces these chains. Given a set of RBAC bindings, namespace configurations, pod security standards, and workload manifests, Claude maps the paths from any compromised pod to cluster-admin equivalent access. It identifies which steps an attacker would take, which resources enable each step, and what specific change would break the chain.

This article covers practical patterns for using Claude to audit Kubernetes clusters for privilege escalation, with real examples of multi-step attack paths that scanners miss.

**Target systems:** Kubernetes 1.25+ clusters running in any environment (EKS, GKE, AKS, self-managed). Clusters using RBAC (the default), with or without PodSecurity admission, NetworkPolicies, or service mesh.

## Threat Model

- **Adversary:** An attacker who has gained initial access to a single pod through an application vulnerability (SSRF, RCE, container escape) or through a compromised CI/CD pipeline.
- **Access level:** Initial access is limited to a single pod's ServiceAccount. The attacker can query the Kubernetes API with that ServiceAccount's credentials and can access the pod's local filesystem and network.
- **Objective:** Escalate from a single compromised pod to cluster-admin privileges, access secrets across namespaces, or escape to the underlying node.
- **Blast radius:** Cluster-admin access means full control of every workload, secret, and configuration in the cluster. Node access means access to every pod's filesystem, network, and credentials on that node. Cross-namespace secret access means credentials for databases, cloud provider APIs, and external services.

## Configuration

### Extracting Cluster State for Claude Review

Before Claude can audit your cluster, you need to extract the relevant configuration. This script collects the RBAC, workload, and network policy state:

```bash
#!/bin/bash
# scripts/extract-k8s-state.sh
# Extracts Kubernetes security-relevant state for Claude review

OUTPUT_DIR="k8s-audit-$(date +%Y%m%d)"
mkdir -p "$OUTPUT_DIR"

# RBAC: ClusterRoles, ClusterRoleBindings, Roles, RoleBindings
kubectl get clusterroles -o yaml > "$OUTPUT_DIR/clusterroles.yaml"
kubectl get clusterrolebindings -o yaml > "$OUTPUT_DIR/clusterrolebindings.yaml"

for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}'); do
  mkdir -p "$OUTPUT_DIR/namespaces/$ns"
  kubectl get roles -n "$ns" -o yaml > "$OUTPUT_DIR/namespaces/$ns/roles.yaml"
  kubectl get rolebindings -n "$ns" -o yaml > "$OUTPUT_DIR/namespaces/$ns/rolebindings.yaml"
  kubectl get serviceaccounts -n "$ns" -o yaml > "$OUTPUT_DIR/namespaces/$ns/serviceaccounts.yaml"
  kubectl get pods -n "$ns" -o yaml > "$OUTPUT_DIR/namespaces/$ns/pods.yaml"
  kubectl get networkpolicies -n "$ns" -o yaml > "$OUTPUT_DIR/namespaces/$ns/networkpolicies.yaml"
done

# PodSecurity standards
kubectl get namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.labels.pod-security\.kubernetes\.io/enforce}{"\n"}{end}' > "$OUTPUT_DIR/pod-security-levels.txt"

# Nodes (for hostPath and privilege analysis)
kubectl get nodes -o yaml > "$OUTPUT_DIR/nodes.yaml"

echo "Audit data collected in $OUTPUT_DIR"
```

### Tracing RBAC Chains: Pod to Cluster-Admin

This is where Claude's reasoning ability matters most. Consider this set of RBAC resources across two namespaces:

```yaml
# Namespace: app-team
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-deployer
  namespace: app-team
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: deployer
  namespace: app-team
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "create", "update", "patch"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: deployer-binding
  namespace: app-team
subjects:
  - kind: ServiceAccount
    name: app-deployer
    namespace: app-team
roleRef:
  kind: Role
  name: deployer
  apiGroup: rbac.authorization.k8s.io
```

```yaml
# Namespace: ci-system
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ci-runner
  namespace: ci-system
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["pods", "pods/exec"]
    verbs: ["*"]
  - apiGroups: [""]
    resources: ["serviceaccounts"]
    verbs: ["get", "list"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["rolebindings"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-deployer-ci-access
  namespace: ci-system
subjects:
  - kind: ServiceAccount
    name: app-deployer
    namespace: app-team
roleRef:
  kind: Role
  name: ci-runner
  apiGroup: rbac.authorization.k8s.io
```

A scanner evaluating these individually sees nothing alarming. The `deployer` role in `app-team` allows managing deployments, which is a normal CI/CD pattern. The `ci-runner` role in `ci-system` allows managing pods and reading secrets, which is expected for a CI namespace.

Claude traces the chain and identifies the escalation path:

1. The `app-deployer` ServiceAccount in `app-team` has a RoleBinding in `ci-system` (cross-namespace binding).
2. In `ci-system`, the ServiceAccount can create RoleBindings (`rolebindings: create`).
3. The ServiceAccount can also read all secrets in `ci-system` (`secrets: get, list`).
4. The ServiceAccount can exec into any pod in `ci-system` (`pods/exec: *`).
5. Combining `rolebindings: create` with access to existing ServiceAccounts means the attacker can bind any existing Role to themselves, including roles with broader permissions.

This is a privilege escalation through RoleBinding creation. The attacker compromises a pod in `app-team`, discovers the cross-namespace binding, creates a new RoleBinding in `ci-system` that grants themselves additional roles, and escalates from there.

### Identifying HostPath Mount Risks

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: log-collector
  namespace: monitoring
spec:
  template:
    spec:
      serviceAccountName: log-collector
      containers:
        - name: collector
          image: fluentd:v1.16
          volumeMounts:
            - name: varlog
              mountPath: /var/log
              readOnly: true
            - name: containers
              mountPath: /var/lib/docker/containers
              readOnly: true
      volumes:
        - name: varlog
          hostPath:
            path: /var/log
            type: Directory
        - name: containers
          hostPath:
            path: /var/lib/docker/containers
            type: Directory
```

A scanner might allow this because the mounts are read-only and the paths are standard for log collection. Claude identifies the risk that scanners miss: `/var/log` on the host may contain kubelet logs, which include API request bodies. If any request to the API server includes secrets (Kubernetes encodes Secret data in the API request), those secrets appear in the kubelet's audit log on disk. A compromised log-collector pod with read access to `/var/log` can extract secrets from other namespaces through the kubelet's logs.

Claude also notes that `/var/lib/docker/containers` contains the stdout/stderr of every container on the node, not just pods in the `monitoring` namespace. An attacker can read application logs from every pod scheduled on the same node.

### Detecting Service Account Token Abuse Potential

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: debug-pod
  namespace: default
spec:
  # No serviceAccountName specified - uses "default" SA
  # No automountServiceAccountToken: false
  containers:
    - name: debug
      image: ubuntu:22.04
      command: ["sleep", "infinity"]
```

Claude identifies that this pod uses the `default` ServiceAccount with auto-mounted credentials. It then checks the RBAC bindings for the `default` ServiceAccount in the `default` namespace. In many clusters, the `default` namespace's `default` ServiceAccount has residual bindings from cluster setup or [Helm](https://helm.sh) chart installations. Claude traces these bindings and reports the effective permissions.

The prompt for this analysis:

```
Review the following Kubernetes manifests and RBAC configuration.

For every ServiceAccount referenced by a pod or deployment:
1. List all RoleBindings and ClusterRoleBindings that reference it
2. Aggregate the effective permissions across all bound roles
3. Identify any permission that could be used for privilege escalation:
   - pods/exec (exec into other pods)
   - secrets read (access credentials)
   - rolebindings or clusterrolebindings create (grant yourself more access)
   - pods create with no PodSecurity enforcement (create privileged pods)
   - nodes/proxy (access kubelet API)
   - serviceaccounts/token create (mint tokens for other SAs)

For each escalation path, describe the specific steps an attacker would
take and which RBAC change would break the chain.
```

### Finding Network Policy Gaps Across Namespaces

```yaml
# Namespace: frontend (has network policies)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-policy
  namespace: frontend
spec:
  podSelector: {}
  policyTypes: ["Ingress", "Egress"]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              role: ingress
      ports:
        - port: 8080
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              role: backend
      ports:
        - port: 443
```

```yaml
# Namespace: backend (no network policies)
# No NetworkPolicy resources exist in this namespace
```

Claude identifies the asymmetry: `frontend` has egress policies restricting traffic to the `backend` namespace on port 443. But `backend` has no NetworkPolicy resources at all, which means it accepts traffic from every namespace and every pod in the cluster. The frontend restrictions create a false sense of isolation. Any compromised pod in any other namespace can communicate directly with backend services.

Claude also checks whether the `backend` namespace has the label `role: backend` that the frontend policy references, and whether any other namespaces also carry that label (which would allow unintended egress from frontend to those namespaces).

### Helm Chart Defaults That Silently Disable Security

```yaml
# Chart.yaml says this is a "production-ready" monitoring stack

# templates/deployment.yaml
spec:
  template:
    spec:
      {{- if .Values.securityContext }}
      securityContext:
        {{- toYaml .Values.securityContext | nindent 8 }}
      {{- end }}
      containers:
        - name: agent
          {{- if .Values.containerSecurityContext }}
          securityContext:
            {{- toYaml .Values.containerSecurityContext | nindent 12 }}
          {{- end }}
```

```yaml
# values.yaml (chart defaults)
securityContext: {}
containerSecurityContext: {}
# Result: no securityContext is rendered at all
```

A scanner checking the rendered manifest sees no `securityContext` block and might flag it. But a scanner checking the template sees a conditional security context and might assume it is configured. Claude reads the template and the default values together and identifies that the conditional pattern means the chart ships with no security context by default. Any user who installs this chart without explicitly setting these values gets a pod running as root with full capabilities.

Claude also identifies a subtler issue: even if a user sets `securityContext.runAsNonRoot: true`, the container-level `containerSecurityContext` is a separate key. The pod-level setting is necessary but not sufficient because individual containers can override it. The chart's structure makes it easy to configure one but forget the other.

## Expected Behaviour

After running Claude-based Kubernetes security audits:

- **RBAC escalation paths are documented.** Every ServiceAccount's effective permissions are mapped, and multi-step escalation chains are identified with specific remediation steps.
- **Cross-namespace attack paths are visible.** RoleBindings that grant cross-namespace access, missing NetworkPolicies, and namespace label misconfigurations are surfaced.
- **HostPath risks are contextualised.** Instead of a blanket "hostPath is dangerous" warning, Claude explains exactly what data is exposed through each specific mount path.
- **Helm chart security gaps are caught before deployment.** Default values that disable security controls are flagged during chart review, not after deployment.

Verification:

```bash
# Extract current cluster state
./scripts/extract-k8s-state.sh

# Run Claude audit
claude "Review the RBAC configuration in k8s-audit-*/. Trace every
ServiceAccount to its effective permissions. Identify any path from
a compromised pod to cluster-admin or cross-namespace secret access.
For each path, list the specific steps and which resource to change."

# Verify specific findings
# Check if the default ServiceAccount has unexpected bindings
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.subjects[]?.name == "default")'

# Check for namespaces without NetworkPolicies
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  count=$(kubectl get networkpolicies -n "$ns" --no-headers 2>/dev/null | wc -l)
  if [ "$count" -eq 0 ]; then
    echo "WARNING: No NetworkPolicies in namespace $ns"
  fi
done
```

## Trade-offs

| Decision | Benefit | Cost |
|---|---|---|
| Full cluster RBAC extraction | Complete view of all escalation paths | Large input size, high token usage for big clusters |
| Include pod specs in audit | Identifies which pods actually mount risky ServiceAccounts | Pod specs change frequently, audit results are point-in-time |
| Audit Helm chart templates + values | Catches defaults that disable security | Requires access to chart source, not just rendered manifests |
| Run audit on rendered manifests | Shows what actually deploys | Misses conditional logic in templates |
| Automated periodic audits | Catches RBAC drift over time | Requires storing and comparing results, ongoing API cost |

**Cluster size considerations:** A cluster with 50 namespaces, 200 Roles, and 300 RoleBindings generates approximately 15,000-25,000 lines of YAML. This fits within Claude's context window but costs $0.15-0.40 per audit with Claude Sonnet. For clusters with thousands of namespaces, split the audit by namespace group.

**False positive expectations:** Claude may flag RBAC permissions that are intentionally broad for cluster operators or CI/CD systems. Maintain an exceptions list in your system prompt for known-intentional broad permissions (e.g., "The `cluster-admin` binding for `kube-system:admin-sa` is intentional").

## Failure Modes

| Failure | Symptom | Detection | Response |
|---|---|---|---|
| Missed escalation path | Claude does not identify a valid privilege escalation chain | Red team exercise discovers the path; compare against tools like rbac-police or rakkess | Add the missed pattern to the system prompt as an explicit check |
| False escalation path | Claude describes an attack path that requires permissions the ServiceAccount does not have | Manual verification of each step in the chain shows a permission is missing | Provide Claude with the exact RBAC output, not a summary; ask it to verify each permission |
| Stale cluster state | Audit data was extracted hours or days before review; RBAC has changed since | Compare extraction timestamp to recent RBAC changes | Automate extraction immediately before review; include timestamps in output |
| Hallucinated Kubernetes API | Claude references a Kubernetes resource type or field that does not exist | Attempting the recommended fix fails with "unknown resource type" | Always validate recommendations against the cluster's API version |
| Context window truncation | Large clusters exceed input limit; some namespaces are omitted | Review output only mentions a subset of namespaces | Split audit by namespace group; run separate reviews for each |
| Prompt injection via resource names | An attacker creates a namespace or resource with a name containing prompt injection text | Claude's output changes topic or produces unexpected results | Sanitise resource names in the extraction script; strip non-alphanumeric characters from metadata |

## When to Consider a Managed Alternative

**Transition point:** When your organisation runs more than 10 clusters, requires continuous monitoring (not just periodic audits), or needs runtime detection of privilege escalation attempts.

**What managed providers handle:**

- **[Sysdig](https://sysdig.com):** Runtime Kubernetes security monitoring that detects privilege escalation attempts as they happen, not just in configuration review. Sysdig watches for container escapes, unexpected process execution, and anomalous API calls in real time. Use Sysdig for runtime detection of the attack paths Claude identifies in configuration.
- **[Falco](https://falco.org):** Open-source runtime security that uses eBPF to detect suspicious system calls and Kubernetes API calls. [Falco](https://falco.org) catches the actual exploitation of misconfigurations that Claude flags during audit. Falco rules can be generated from Claude's findings.

**What Claude handles that managed tools do not:** Multi-step RBAC chain tracing across namespaces, reasoning about Helm chart template logic, identifying which specific permission change would break an escalation path, and explaining attack paths in natural language that non-Kubernetes-experts can understand. No managed tool provides this reasoning today.

**The optimal stack:** Claude for periodic configuration audit and RBAC chain analysis + Falco or Sysdig for runtime detection of exploitation attempts + OPA/Gatekeeper for admission-time policy enforcement. Claude finds the gaps, admission controllers prevent new gaps, and runtime tools detect exploitation of any gaps that remain.


## Related Articles

- [Claude for Security Detection: How Large Language Models Find What Scanners Miss](/articles/ai-landscape/claude-security-detection/)
- [Claude, Mythos, and the Non-Human Infrastructure Consumer: Writing Hardening Guides for AI Agents](/articles/ai-landscape/claude-non-human-consumers/)
- [Claude for Infrastructure-as-Code Security Review: Terraform, CloudFormation, and Pulumi](/articles/ai-landscape/claude-iac-review/)
- [Claude for Security Incident Triage: Rapid Analysis of Logs, Alerts, and Blast Radius](/articles/ai-landscape/claude-incident-triage/)
- [Claude for Application Security: Finding Logic Vulnerabilities in Source Code](/articles/ai-landscape/claude-code-vulnerability/)
