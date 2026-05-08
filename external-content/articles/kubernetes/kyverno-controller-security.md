---
title: "Kyverno Controller Security Hardening"
description: "Harden the Kyverno policy controller itself against CVE-2026-4789 SSRF via CEL HTTP functions and CVE-2026-22039 cross-namespace RBAC bypass—vulnerabilities in the enforcer, not the policies."
slug: kyverno-controller-security
date: 2026-05-03
lastmod: 2026-05-03
category: kubernetes
tags: ["kyverno", "cve-2026-4789", "cve-2026-22039", "ssrf", "rbac-bypass", "admission-controller", "policy"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 376
difficulty: advanced
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/kubernetes/kyverno-controller-security/index.html"
---

# Kyverno Controller Security Hardening

## Problem

Most security work around Kyverno concerns the policies themselves: writing correct validate rules, avoiding overly permissive mutation logic, testing with Chainsaw before promoting to production. That is Kyverno policy security. This article covers a different surface — Kyverno controller security — meaning bugs in Kyverno's own codebase that can undermine the security guarantees the controller is supposed to provide. When the policy enforcer is itself vulnerable, every policy it runs is suspect.

**CVE-2026-4789** (April 2026, CVSS 9.0+, Critical) was introduced in Kyverno 1.16.0 alongside the CEL (Common Expression Language) expression engine. CEL in Kyverno allows policy authors to write conditions using Go-like expressions with access to external data via HTTP lookups — for example, fetching a ConfigMap from an external registry service or validating a token against an internal API. The CEL HTTP functions (`http.Get`, `http.Post`) were implemented without any URL allowlist or restriction on target endpoints. A user with write access to `ClusterPolicy` or `Policy` resources could craft a policy containing a CEL expression such as:

```cel
http.Get("http://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets").body
```

The Kyverno controller makes this HTTP request using its own Kubernetes service account, which has broad `get/list/watch` permissions across the cluster. The response is included in the policy evaluation context, and the policy author can observe it via match results, policy reports, or controller logs. This is a Server-Side Request Forgery (SSRF) that converts any user who can write Kyverno policies into a user who can read Kubernetes Secrets across all namespaces — a complete RBAC bypass. The vulnerability was discovered by Orca Security and a fix was merged to the Kyverno `main` branch on April 6, 2026 (PR #15789). However, no patched release was cut immediately, creating a window where the fix was publicly visible in the repository before operators could deploy it. Any attacker watching the `kyverno/kyverno` repository during that window could read the patch, understand the vulnerability, and craft an exploit before a patched version was available.

**CVE-2026-22039** (April 2026, CVSS 10.0, Critical) is a cross-namespace RBAC bypass in Kyverno's policy enforcement engine. Kyverno distinguishes between `ClusterPolicy` (cluster-scoped, all namespaces) and `Policy` (namespace-scoped, single namespace). CVE-2026-22039 is a flaw in how Kyverno evaluated namespaced policy permissions: a `Policy` scoped to one namespace could be crafted so that Kyverno applied its mutation and validation rules cluster-wide. A developer with `Policy` create access in their own dev namespace could write rules that Kyverno would silently enforce against `kube-system`, production namespaces, or any other namespace — bypassing the RBAC namespace isolation that Kubernetes is supposed to enforce. This vulnerability affects the engine's namespace scoping logic in `pkg/engine/` and represents a complete failure of the namespace boundary that the `Policy` resource type is designed to establish.

Both CVEs illustrate a systemic risk with fast-moving infrastructure tooling: the policy enforcement tool itself can be the vulnerability. Kyverno ships weekly releases, and the gap between a security fix landing in `main` and a patched release being available — even if measured in days — creates a real exploitation window for attackers who monitor open-source repositories. The Kyverno project publishes official security advisories at `https://github.com/kyverno/kyverno/security/advisories`, and the packages that most often contain security-relevant changes are `pkg/cel/` (CEL evaluation, SSRF surface), `pkg/engine/` (policy enforcement logic, RBAC bypass surface), and `pkg/webhooks/` (admission webhook handling). Monitoring these paths proactively — not just waiting for a tagged release — is part of operating Kyverno responsibly. You can query advisories with:

```bash
gh api repos/kyverno/kyverno/security/advisories --jq '.[].summary'
```

And use Renovate or Dependabot to open auto-PRs against your Helm chart when new Kyverno releases appear.

**Target systems:** Kyverno >= 1.16.0 (CVE-2026-4789, CEL HTTP functions introduced), Kyverno < patched version (CVE-2026-22039, all versions with the engine namespace scoping flaw), Kubernetes 1.28+.

## Threat Model

1. **CVE-2026-4789 SSRF via CEL HTTP call**: A developer with `ClusterPolicy` write access creates a policy containing a CEL expression that calls `http.Get("http://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets")`. The Kyverno controller evaluates this expression using its own service account credentials and includes the HTTP response in the policy evaluation context. The developer observes the Secret contents via policy match results, the Kyverno policy report, or — on a verbose logging configuration — directly in controller log output. Even without `ClusterPolicy` access, a developer with only `Policy` write access in their own namespace can target cluster-internal services other than the API server: etcd metrics, cloud metadata endpoints (`http://169.254.169.254/latest/meta-data/iam/security-credentials/`), or any internal service reachable from the Kyverno pod's network namespace.

2. **CVE-2026-22039 namespace escape via Policy**: A developer with `Policy` create access in namespace `dev` constructs a Policy with mutation rules whose `match.resources.namespaces` field is manipulated to exploit the engine's namespace scoping flaw. Kyverno incorrectly applies these mutation rules cluster-wide, allowing the developer to patch Deployments in `kube-system`, inject environment variables into production Pods, or modify RBAC objects in namespaces they have no direct access to. The impact is equivalent to cluster-admin mutation access despite the developer holding only namespace-scoped Policy permissions.

3. **Patch-gap exploitation**: Orca Security publishes CVE-2026-4789 details and the fix PR #15789 is visible in `main`, but no patched Kyverno release exists yet. An attacker reads the diff, understands that `http.Get` calls in CEL expressions are made with the controller's service account, and crafts a malicious `ClusterPolicy` during the window before operators upgrade. Defenders can see the fix but cannot yet deploy it. If the cluster has no NetworkPolicy restricting Kyverno pod egress and no RBAC restriction on who can create `ClusterPolicy` resources, the attacker can exfiltrate Secrets from every namespace before a patch is available. This scenario is not theoretical — any public repository fix creates a race condition between the time the patch is pushed and the time a signed, tested release artifact is published.

4. **Kyverno controller service account abuse**: The Kyverno controller's service account (typically `kyverno` in the `kyverno` namespace) requires `get/list/watch` on most resource types to evaluate policies correctly. This means compromising the Kyverno pod — through a container escape, a supply chain compromise of the Kyverno image, or a remote code execution in the CEL evaluation path — gives an attacker cluster-admin equivalent read access and potentially write access to any resources Kyverno is configured to mutate. The Kyverno pod is a high-value lateral movement target precisely because its security posture must be broad to do its job.

The blast radius of both CVEs is high because Kyverno runs in an admission webhook that processes every create, update, and delete event across the cluster. Unlike application workloads, a compromise of the Kyverno controller affects the entire cluster's security enforcement posture, not just a single namespace. Any mitigation must account for the controller's privileged position in the control plane.

## Configuration / Implementation

### Upgrading Kyverno

The primary remediation for both CVEs is upgrading to a patched version. Check the Kyverno release notes at `https://github.com/kyverno/kyverno/releases` for the release that references CVE-2026-4789 and CVE-2026-22039 fixes. Once a patched version is identified:

```bash
# Upgrade Kyverno using Helm
helm upgrade kyverno kyverno/kyverno \
  --version <patched-version> \
  --namespace kyverno \
  --reuse-values

# Verify the running image after upgrade
kubectl get deployment -n kyverno kyverno \
  -o jsonpath='{.spec.template.spec.containers[0].image}'
```

Confirm the running pods have picked up the new image:

```bash
kubectl rollout status deployment/kyverno -n kyverno
kubectl get pods -n kyverno -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.containerStatuses[0].image}{"\n"}{end}'
```

Do not rely on `helm list` alone — verify the running pod image digest against the patched release's published digest if your organisation enforces image provenance.

### Disabling CEL HTTP Functions (CVE-2026-4789 Interim Mitigation)

While waiting for a patched release, disable CEL external data calls in the Kyverno ConfigMap:

```bash
kubectl edit configmap kyverno -n kyverno
```

Add or set the following key:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kyverno
  namespace: kyverno
data:
  enableExternalData: "false"
```

If your Kyverno version does not support the `enableExternalData` flag directly, you can prevent CEL HTTP calls at the network layer instead (see the NetworkPolicy section below). Be aware that setting `enableExternalData: "false"` will break any existing policies that use CEL external context providers or JMESPath API calls for legitimate data lookups. Audit your policies before applying this change:

```bash
kubectl get clusterpolicies -o json | \
  jq '.items[] | select(.spec.rules[].context // [] | length > 0) | .metadata.name'

kubectl get policies -A -o json | \
  jq '.items[] | select(.spec.rules[].context // [] | length > 0) | "\(.metadata.namespace)/\(.metadata.name)"'
```

### NetworkPolicy for the Kyverno Controller

A defence-in-depth control that limits SSRF impact regardless of whether a patched version is deployed is a NetworkPolicy that restricts the Kyverno controller pod's egress to only what it legitimately needs. Kyverno must reach the Kubernetes API server (port 443) and, optionally, any external context provider endpoints your policies declare. All other outbound traffic — including requests to the cluster-internal service network and the cloud metadata endpoint — should be denied.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: kyverno-controller-egress
  namespace: kyverno
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: kyverno
      app.kubernetes.io/component: kyverno
  policyTypes:
    - Egress
  egress:
    # Allow communication with the Kubernetes API server
    - ports:
        - protocol: TCP
          port: 443
      to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              # Block access to cluster-internal service CIDR (adjust to your cluster)
              - 10.96.0.0/12
              # Block cloud metadata endpoint (AWS, GCP, Azure)
              - 169.254.169.254/32
    # Allow DNS resolution
    - ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
      to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
```

Adjust the `except` CIDR block to match your cluster's service CIDR (`kubectl cluster-info dump | grep -i service-cluster-ip-range`). If your policies use named external context providers (e.g., an OPA bundle server), add explicit egress rules for those endpoints rather than opening broad egress. This NetworkPolicy does not prevent Kyverno from contacting the real API server, but it blocks the SSRF path to `kubernetes.default.svc` and other cluster-internal services.

Note that if you use a CNI plugin that does not enforce `NetworkPolicy` (e.g., Flannel without a network policy controller), this control has no effect. Confirm your CNI enforces NetworkPolicy:

```bash
kubectl describe daemonset -n kube-system | grep -i 'cilium\|calico\|weave\|canal'
```

### RBAC Restriction on Policy Creation

CVE-2026-4789 requires write access to `ClusterPolicy` or `Policy` resources. Restricting who can create these resources limits the attack surface significantly. The principle: only the platform security team (or a dedicated CI service account) should have `ClusterPolicy` create/update/delete access. Developers may have `Policy` access in their own namespaces (noting that CVE-2026-22039 must also be patched to make namespace scoping safe).

```yaml
# ClusterRole granting ClusterPolicy management — restricted to platform-security team
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kyverno-policy-admin
rules:
  - apiGroups: ["kyverno.io"]
    resources: ["clusterpolicies", "clusterpolicymutates"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kyverno-policy-admin-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: kyverno-policy-admin
subjects:
  - kind: Group
    name: platform-security
    apiGroup: rbac.authorization.k8s.io
```

Audit current ClusterPolicy access across the cluster:

```bash
# Find all subjects with ClusterPolicy create/update access
kubectl get clusterrolebinding -o json | \
  jq '.items[] | select(
    .roleRef.name as $role |
    (.subjects // []) | length > 0
  ) | {
    binding: .metadata.name,
    subjects: .subjects
  }'

# More targeted: find roles that grant clusterpolicies write
kubectl get clusterrole -o json | \
  jq '.items[] | select(
    .rules[]?.resources[]? | 
    contains("clusterpolicies")
  ) | .metadata.name'
```

For namespace-scoped `Policy` access, ensure developers can only create policies in namespaces they own — not in `kube-system`, `kyverno`, or other sensitive namespaces:

```bash
# Audit Policy access in sensitive namespaces
kubectl get rolebinding -n kube-system -o json | \
  jq '.items[] | select(
    .roleRef.name | 
    test("admin|edit|policy"; "i")
  ) | {binding: .metadata.name, subjects: .subjects}'
```

### Kyverno Controller Service Account Scoping

Kyverno's default ClusterRole grants broad `get/list/watch` on virtually all resource types. Review what your Kyverno installation actually uses and remove permissions for resource types no policies reference:

```bash
# Inspect the Kyverno controller's ClusterRole
kubectl get clusterrole kyverno -o yaml

# Check which resource types Kyverno's policies actually need to watch
kubectl get clusterpolicies -o json | \
  jq '[.items[].spec.rules[].match.resources.kinds // []] | flatten | unique | sort'
```

If your policies only validate Pods and Deployments, Kyverno does not need `get/list` on `secrets` or `serviceaccounts` at the ClusterRole level. Use the `kyverno-rbac` Helm values to scope permissions:

```yaml
# values.yaml for Kyverno Helm chart — restrict service account permissions
admissionController:
  rbac:
    clusterRole:
      extraResources: []
  serviceAccount:
    name: kyverno-admission-controller
```

The key principle: the Kyverno controller service account should have the minimum permissions needed by your actual policy set, not the maximum permissions needed by any policy anyone might ever write.

### Monitoring Kyverno for Security Fixes

Subscribe to official Kyverno security advisories and monitor the repository for security-relevant commits:

```bash
# List current Kyverno security advisories
gh api repos/kyverno/kyverno/security/advisories \
  --jq '.[].summary'

# Watch recent commits to security-sensitive packages
gh api repos/kyverno/kyverno/commits \
  --jq '.[] | select(
    .commit.message | 
    test("CVE|security|ssrf|rbac|bypass|cel|http.*func|fix.*inject"; "i")
  ) | {sha: .sha[0:8], msg: .commit.message}'

# Monitor specific paths for security-relevant changes
gh api "repos/kyverno/kyverno/commits?path=pkg/cel/" \
  --jq '.[0:5] | .[] | {sha: .sha[0:8], date: .commit.author.date, msg: .commit.message}'
```

For automated tracking, configure Renovate in your Helm repository:

```json
{
  "packageRules": [
    {
      "matchPackageNames": ["kyverno/kyverno"],
      "matchManagers": ["helmv3"],
      "automerge": false,
      "labels": ["security", "kyverno"],
      "prBodyNotes": ["Check https://github.com/kyverno/kyverno/security/advisories before merging"]
    }
  ]
}
```

Subscribe to GitHub notifications for the `kyverno/kyverno` repository with "Security alerts" enabled, and add the repository to your vulnerability management program's watch list so that advisory publications trigger your standard incident response workflow.

## Expected Behaviour

| Signal | Unpatched Kyverno 1.16+ | Patched + NetworkPolicy + RBAC Restriction |
|---|---|---|
| CEL expression `http.Get("http://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets")` in a ClusterPolicy | Kyverno controller executes the request using its service account; Secret data visible in policy evaluation context and logs | NetworkPolicy blocks the request at the network layer (connection refused); patched version rejects CEL HTTP calls to internal endpoints at evaluation time |
| Namespace-scoped `Policy` in `dev` with rules targeting `kube-system` resources | Kyverno engine applies rules cluster-wide; developer can mutate kube-system resources | Patched engine correctly enforces namespace scope; policy rules restricted to `dev` namespace only |
| Kyverno pod makes outbound HTTP request to arbitrary cluster-internal service IP | Request succeeds; SSRF possible against any service reachable from Kyverno pod network namespace | NetworkPolicy denies egress to cluster service CIDR; connection blocked before it leaves the pod |
| Developer with only namespace `Policy` access attempts to create a `ClusterPolicy` | Succeeds if RBAC is not explicitly restricted (default bindings may permit this in some configurations) | RBAC restriction denies `ClusterPolicy` create for non-platform-security subjects; admission webhook returns 403 |
| Fix PR #15789 merged to `main`, no patched release yet | Cluster running 1.16.0+ is vulnerable; no mitigation available without code changes | `enableExternalData: "false"` in ConfigMap blocks CEL HTTP calls; NetworkPolicy blocks SSRF path; Renovate opens upgrade PR automatically when release is tagged |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Disabling CEL external data (`enableExternalData: "false"`) | Closes CVE-2026-4789 attack path without requiring a Kyverno upgrade | Breaks all existing policies that use external context providers, JMESPath API lookups, or CEL HTTP functions for legitimate data retrieval | Audit policies for external context usage before applying; replace HTTP lookups with ConfigMap-backed context where possible; apply as a temporary measure only |
| Kyverno controller egress NetworkPolicy | Prevents SSRF from reaching cluster-internal services and cloud metadata endpoints; limits blast radius of any future CEL or engine vulnerabilities | May block legitimate policy data lookups if external context providers are hosted on internal cluster services; breaks if CNI does not enforce NetworkPolicy | Define explicit allow-rules for known legitimate external context provider endpoints; verify CNI NetworkPolicy support before relying on this control |
| Restricting ClusterPolicy creation to platform-security team | Eliminates the most dangerous CVE-2026-4789 attack path (ClusterPolicy with cluster-wide SSRF scope) | Reduces developer self-service; teams cannot deploy their own cluster-scoped policy automation | Provide a PR-based workflow for cluster policy requests; use namespace-scoped Policy for developer-owned policies with appropriate review |
| Broad Kyverno controller service account permissions | Required for Kyverno to correctly evaluate policies across all resource types; reducing permissions may cause policy evaluation failures | The service account is a high-value target; any compromise of the Kyverno pod yields near-cluster-admin read access | Scope permissions to resource types actually used by deployed policies; audit and tighten ClusterRole quarterly; treat the Kyverno namespace as a tier-1 privileged namespace |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| NetworkPolicy blocks legitimate Kyverno communication with an external context provider | Policy evaluations that use external context return errors; PolicyReport shows `error` status for affected rules; Deployments may be blocked by Kyverno if the policy is in `Enforce` mode | `kubectl logs -n kyverno deployment/kyverno | grep -i "context provider\|http.*error\|connection refused"`; check PolicyReports for error conditions | Add an explicit egress allow rule in the NetworkPolicy for the context provider's IP/port; or temporarily set `validationFailureAction: Audit` on affected policies while investigating |
| Patched Kyverno version changes policy evaluation semantics | Existing policies begin failing for workloads that previously passed; unexpected Deployment blocks in production; `PolicyViolation` events for previously compliant resources | `kubectl get policyreport -A`; compare violation counts before and after upgrade; run Kyverno Chainsaw tests against the new version in a staging cluster | Roll back to the previous Helm release (`helm rollback kyverno -n kyverno`); review the Kyverno changelog for breaking changes in the target version; update affected policies before re-upgrading |
| RBAC restriction on ClusterPolicy prevents platform team from rolling out cluster policies | Platform engineers cannot create or update ClusterPolicies; CI/CD pipeline fails at the policy apply step | `kubectl auth can-i create clusterpolicies --as=<service-account>`; CI logs show 403 Forbidden on `kubectl apply -f cluster-policy.yaml` | Verify the platform-security group or CI service account is bound to the `kyverno-policy-admin` ClusterRole; check for admission webhook policies that may themselves be blocking ClusterPolicy creation |
| Disabling CEL external data breaks existing policies using HTTP context | Policies with `context` blocks using API calls or CEL HTTP functions produce evaluation errors; PolicyReports show widespread `error` states; Kyverno logs show `external data disabled` messages | `kubectl get clusterpolicies -o json | jq '.items[] | select(.spec.rules[].context // [] | length > 0) | .metadata.name'`; review Kyverno controller logs after applying ConfigMap change | Re-enable `enableExternalData: "true"` to restore functionality; replace affected policies with ConfigMap-backed context or in-policy CEL logic that does not require external HTTP calls; prioritise upgrade to a patched Kyverno version so the flag can be re-enabled safely |

## Related Articles

- [Kyverno Policy Development and Testing](/articles/kubernetes/kyverno-policy-development/)
- [Kubernetes Admission Control](/articles/kubernetes/kubernetes-admission-control/)
- [Validating Admission Policy with CEL](/articles/kubernetes/validating-admission-policy-cel/)
- [RBAC Design Patterns](/articles/kubernetes/rbac-design-patterns/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
