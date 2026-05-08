---
title: "ValidatingAdmissionPolicy with CEL: Native Kubernetes Admission Without Webhooks"
description: "VAP replaces webhook admission for the policies you write most often. No Kyverno, no OPA, no network round-trip, no webhook availability risk."
slug: "validating-admission-policy-cel"
date: 2026-04-27
lastmod: 2026-04-27
category: "kubernetes"
tags: ["kubernetes", "admission-control", "cel", "vap", "policy"]
personas: ["platform-engineer", "security-engineer"]
article_number: 171
difficulty: "intermediate"
estimated_reading_time: 15
published: true
layout: article.njk
permalink: "/articles/kubernetes/validating-admission-policy-cel/index.html"
---

# ValidatingAdmissionPolicy with CEL: Native Kubernetes Admission Without Webhooks

## Problem

Webhook-based admission control (Kyverno, Gatekeeper, OPA, custom webhooks) has been the dominant pattern for enforcing organization-specific policies on Kubernetes resources for years. It works, but it brings four classes of risk that go unmentioned in most adoption stories:

- **Availability coupling.** Every admission request to the affected resources blocks until the webhook responds. A webhook that goes down stops cluster operations cold. `failurePolicy: Ignore` makes the webhook optional, which means a partial outage silently lets violations through.
- **Network round-trip cost.** Each admission decision crosses the cluster network, hits the webhook pod, runs evaluation logic, and returns. Latency is 5-50 ms per request, accumulating during burst deploys.
- **Operational footprint.** A webhook pod needs Deployments, Services, certificates (the cert-manager dance), CA bundle injection into the `ValidatingWebhookConfiguration`, monitoring, autoscaling, and security review of the policy engine itself.
- **Versioning skew.** Updating Kyverno or Gatekeeper means upgrading the policy engine in lockstep with the policies, often through Helm chart migrations across breaking versions.

Kubernetes 1.30 (April 2024) made `ValidatingAdmissionPolicy` (VAP) generally available. The kube-apiserver evaluates CEL ([Common Expression Language](https://github.com/google/cel-spec)) expressions inline during admission, with no webhook in the path. Kubernetes 1.32 added `MutatingAdmissionPolicy` (still alpha as of 1.34, beta on 1.35).

For the majority of policies — naming conventions, label requirements, image registry allowlists, resource quotas, securityContext requirements — VAP is the right fit. Webhook engines remain useful for policies that need cross-resource lookups across namespaces, external API calls, or complex stateful logic.

This article covers the VAP resource model, common CEL patterns for security policies, parameterization, RBAC for policy management, and the operational migration from Kyverno/OPA where applicable.

**Target systems:** Kubernetes 1.30+ for VAP GA. Kubernetes 1.34+ for `MatchConditions` v2 and improved error messages.

## Threat Model

- **Adversary 1 — Insider creating non-compliant resources:** developer with namespace-scoped access who attempts to deploy a privileged pod, an image from an unapproved registry, or a workload bypassing required labels.
- **Adversary 2 — External attacker via compromised CI credentials:** OIDC-federated CI token used to apply a manifest that escalates privileges.
- **Adversary 3 — Webhook outage as bypass vector:** an attacker (or routine networking incident) that brings down the policy webhook so policies fail open.
- **Access level:** Adversary 1 has namespace-edit RBAC. Adversary 2 has whatever the CI token grants. Adversary 3 has any disruption capability — even a cluster autoscaler event is enough.
- **Objective:** Deploy resources that violate organizational policy in a way that gives the adversary persistent access, more permissions, or evades detection.
- **Blast radius:** Without admission control: any privileged workload reachable by the cluster network or with hostPath mount can pivot to node-level access. With webhook-based control: blast radius depends on webhook availability. With VAP: same blast radius as Kubernetes RBAC, no separate availability concern.

## Configuration

### The VAP Resource Trio

VAP uses three resources that compose:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: deny-privileged-containers
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
  validations:
    - expression: >
        !object.spec.containers.exists(c,
          has(c.securityContext) && has(c.securityContext.privileged) &&
          c.securityContext.privileged == true)
      message: "Privileged containers are not allowed."
      reason: Forbidden
    - expression: >
        !has(object.spec.initContainers) ||
        !object.spec.initContainers.exists(c,
          has(c.securityContext) && has(c.securityContext.privileged) &&
          c.securityContext.privileged == true)
      message: "Privileged init containers are not allowed."
      reason: Forbidden
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: deny-privileged-containers-everywhere
spec:
  policyName: deny-privileged-containers
  validationActions: [Deny, Audit]
  matchResources:
    namespaceSelector:
      matchExpressions:
        - key: pod-security.kubernetes.io/enforce
          operator: NotIn
          values: ["privileged"]
```

The `Policy` defines what to check. The `Binding` determines where the policy applies and what to do on a violation. `validationActions: [Deny, Audit]` rejects the request and emits an audit event with the violation details.

### Image Registry Allowlist with Parameters

For policies whose values vary across environments (allowed registries differ between staging and prod), use a `ParamKind`:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: enforce-image-registry-allowlist
spec:
  paramKind:
    apiVersion: policy.example.com/v1
    kind: AllowedRegistries
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
  variables:
    - name: containerImages
      expression: >
        object.spec.containers.map(c, c.image) +
        (has(object.spec.initContainers) ?
          object.spec.initContainers.map(c, c.image) : [])
  validations:
    - expression: >
        variables.containerImages.all(img,
          params.spec.registries.exists(r, img.startsWith(r + "/")))
      messageExpression: >
        "Image must come from one of: " +
        params.spec.registries.join(", ")
      reason: Forbidden
---
# CRD for the parameter object.
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: allowedregistries.policy.example.com
spec:
  group: policy.example.com
  scope: Cluster
  names:
    plural: allowedregistries
    kind: AllowedRegistries
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              properties:
                registries:
                  type: array
                  items:
                    type: string
---
apiVersion: policy.example.com/v1
kind: AllowedRegistries
metadata:
  name: production-registries
spec:
  registries:
    - ghcr.io/myorg
    - my-registry.example.com
    - quay.io/myorg
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: registry-allowlist-prod
spec:
  policyName: enforce-image-registry-allowlist
  paramRef:
    name: production-registries
    parameterNotFoundAction: Deny
  validationActions: [Deny, Audit]
  matchResources:
    namespaceSelector:
      matchLabels:
        environment: production
```

Different bindings reference different `AllowedRegistries` instances for staging vs. production. The same policy logic, parameterized.

### Common Security Patterns

```yaml
# Require non-root user.
- expression: >
    object.spec.containers.all(c,
      has(c.securityContext) &&
      has(c.securityContext.runAsNonRoot) &&
      c.securityContext.runAsNonRoot == true)
  message: "All containers must set runAsNonRoot: true"

# Require resource limits.
- expression: >
    object.spec.containers.all(c,
      has(c.resources) &&
      has(c.resources.limits) &&
      has(c.resources.limits.cpu) &&
      has(c.resources.limits.memory))
  message: "All containers must specify CPU and memory limits"

# Forbid hostPath mounts.
- expression: >
    !has(object.spec.volumes) ||
    object.spec.volumes.all(v, !has(v.hostPath))
  message: "hostPath volumes are not allowed"

# Forbid hostNetwork / hostPID / hostIPC.
- expression: >
    !has(object.spec.hostNetwork) || !object.spec.hostNetwork
  message: "hostNetwork is not allowed"
- expression: >
    !has(object.spec.hostPID) || !object.spec.hostPID
  message: "hostPID is not allowed"

# Require seccompProfile.
- expression: >
    has(object.spec.securityContext) &&
    has(object.spec.securityContext.seccompProfile) &&
    object.spec.securityContext.seccompProfile.type in
      ["RuntimeDefault", "Localhost"]
  message: "seccompProfile must be RuntimeDefault or Localhost"

# Require approved labels.
- expression: >
    has(object.metadata.labels) &&
    "app.kubernetes.io/name" in object.metadata.labels &&
    "team" in object.metadata.labels
  message: "Pods must have app.kubernetes.io/name and team labels"
```

These cover most of the day-to-day "PSS Restricted +" enforcement teams write Kyverno policies for.

### Cross-Resource Lookups via `extensions.k8s.io` Variables

Kubernetes 1.32+ supports limited cross-resource lookups via the `Authorizer` and `RequestResource` extensions. For a policy that depends on a ConfigMap value (e.g., a list of approved teams):

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: team-must-be-approved
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
  paramKind:
    apiVersion: v1
    kind: ConfigMap
  variables:
    - name: team
      expression: >
        has(object.metadata.labels) &&
        has(object.metadata.labels.team) ?
          object.metadata.labels.team : ""
    - name: approvedTeams
      expression: params.data.teams.split(",")
  validations:
    - expression: variables.team in variables.approvedTeams
      messageExpression: >
        "Team '" + variables.team + "' is not in the approved list"
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: team-approval
spec:
  policyName: team-must-be-approved
  paramRef:
    name: approved-teams
    namespace: kube-system
    parameterNotFoundAction: Deny
  validationActions: [Deny, Audit]
```

For lookups across arbitrary resources or external systems, VAP is not the right tool — fall back to Kyverno or a custom webhook.

### Auditing Without Enforcing (Dry-Run)

Before flipping a policy to `Deny`, run it in `Audit` mode. Violations appear in the audit log without rejecting requests:

```yaml
spec:
  validationActions: [Audit, Warn]
```

Combined with audit-log analysis (a query against your SIEM for `annotations.validation.policy.admission.k8s.io/validation_failure`), you discover which workloads would have been rejected and can fix them before enforcement.

### RBAC for Policy Management

Policies are cluster-scoped resources with elevated impact. Restrict who can write them:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: admission-policy-author
rules:
  - apiGroups: ["admissionregistration.k8s.io"]
    resources:
      - validatingadmissionpolicies
      - validatingadmissionpolicybindings
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
---
# Reserve for the security/platform team only.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: security-team-policy-authors
roleRef:
  kind: ClusterRole
  name: admission-policy-author
  apiGroup: rbac.authorization.k8s.io
subjects:
  - kind: Group
    name: security-engineering
    apiGroup: rbac.authorization.k8s.io
```

Application teams should not have create/update on these resources. The `ParamKind` parameters can be more permissive — a team-specific `AllowedRegistries` instance can be edited by the team itself if scoped correctly.

## Expected Behaviour

| Signal | Webhook Engine | VAP |
|--------|----------------|-----|
| Policy evaluation latency | 5-50 ms (network round-trip + engine eval) | < 1 ms (in-process CEL) |
| Webhook pod outage impact | Cluster admission stalls or fails open | No webhook involved; no impact |
| Cluster CRD count | Many (Kyverno: ~10, Gatekeeper: ~5) | Two (`ValidatingAdmissionPolicy`, `ValidatingAdmissionPolicyBinding`) plus your `ParamKind` CRDs |
| Audit-log entry on violation | Webhook annotation | Native `annotations.validation.policy.admission.k8s.io/validation_failure` |
| Policy rollout via GitOps | Argo/Flux apply Kyverno CRDs | Same — applies VAP CRDs (built-in API group) |
| Cross-resource queries | Native via Kyverno `match` and `context` | Limited; falls back to webhook |

Verify VAP enforcement:

```bash
# Apply a violating pod, expect rejection.
kubectl run test --image=docker.io/library/nginx --dry-run=client -o yaml | \
  kubectl apply -f -
# Error from server (Forbidden): admission webhook denied the request:
# Image must come from one of: ghcr.io/myorg, ...

# Audit log shows the violation.
kubectl get --raw /api/v1/namespaces/kube-system/events | \
  jq '.items[] | select(.reason == "PolicyViolation")'
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| In-process evaluation | No network round-trip; no availability risk | CEL has a smaller standard library than Rego or Kyverno's expression language | Use VAP for the policies CEL handles cleanly; keep webhook engines for the rest. |
| Native API surface | No third-party CRDs to upgrade in lockstep with Kubernetes | Limited cross-resource awareness; cannot call external systems | Use `paramRef` for static config; for dynamic lookups, keep webhook-based engines. |
| `ParamKind` for env-specific values | Single policy, multiple parameter objects per environment | Requires defining a CRD for each parameter shape | Use `ConfigMap` as the param kind for simple cases. |
| `Audit` mode rollout | Safe deploy of new policies | Requires audit-log pipeline to make use of the data | Pipe audit logs to your existing SIEM; query for `validation_failure` annotations. |
| Migration from Kyverno/OPA | Reduces operational footprint | Migration time; not all policies port cleanly | Inventory policies first. Convert the obvious 80%; leave webhook engines for the long-tail policies that need their richer features. |
| RBAC tightness on policies | Policy authors are a small set | New policy creation is a slow, gated process | Use parameters (`ParamKind`) to push environment-specific configuration to teams; keep policy *logic* gated. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| CEL syntax error | Policy not enforced; kube-apiserver logs `compilation failed` | `kubectl describe vap` shows `TypeChecking` condition with the error | Validate CEL with `kubectl alpha admissionpolicy lint` (1.32+) or test in a kind cluster before pushing. |
| Param resource missing | Bound policy fails open or fails closed depending on `parameterNotFoundAction` | Audit logs show admission attempts with `param-not-found` annotation | Set `parameterNotFoundAction: Deny` for security policies. Ensure GitOps applies parameter resources before bindings. |
| `failurePolicy: Ignore` set on a security policy | Violations slip through when the apiserver evaluator hits an internal error | Audit logs missing expected violations during apiserver health blips | Use `failurePolicy: Fail` for security policies. The apiserver evaluator has no external dependencies, so failure is rare and indicates a cluster-level issue worth blocking on. |
| Policy too restrictive, blocks platform components | New cluster components (cert-manager controller, GPU operator) fail to install | Pod create requests rejected with policy message; system events flood | Use `matchResources.namespaceSelector` with `kubernetes.io/metadata.name NotIn [kube-system, ...]`. Exempt namespaces with the `pod-security.kubernetes.io/enforce: privileged` label or a dedicated `policy-exempt` label. |
| `validations` evaluation hits CEL cost limit | Policies on resources with very large fields (large ConfigMaps, status fields) fail evaluation | Audit logs show `cost limit exceeded` | Restructure the expression to short-circuit early; use `variables` to extract subsets and avoid repeated traversal. |
| Audit annotations missed in SIEM | Violations occur but nobody knows | Spot-check shows audit-log entries with policy annotations not appearing in SIEM dashboards | Confirm the audit-log pipeline forwards `metadata.annotations` and that SIEM indexes them. Build a dashboard on `validation_failure` annotation count by policy. |
| Mass policy update breaks production | A bad CEL change rejects all pod creates cluster-wide | New deploys fail across all namespaces immediately after a policy update | Roll out new policies via `[Audit]` first, observe for 1-2 days, then add `Deny`. Keep `kubectl rollout undo`-equivalent: a Git revert of the policy commit triggers GitOps to re-apply the prior version. |

## Migrating from Kyverno or Gatekeeper

Most existing Kyverno `validate` rules and Gatekeeper constraints map to VAP. Walk the policy inventory and bucket each:

| Existing policy type | VAP-portable? | Notes |
|---------------------|---------------|-------|
| Required labels / annotations | Yes | Direct CEL translation. |
| Image registry allowlist | Yes | Use `paramKind` for environment differences. |
| Privileged container deny | Yes | Native CEL on `securityContext`. |
| Resource limits required | Yes | Direct CEL. |
| Network policy default-deny | No (mutate / generate) | Stays in Kyverno (`generate` rules). |
| Cross-namespace consistency check | No (cross-resource lookup) | Stays in webhook engine. |
| External API call (CMDB lookup) | No | Custom webhook. |

Run both in parallel during migration. VAP in `[Audit]`, Kyverno in enforce. Once VAP audit logs show parity over 1-2 weeks, switch VAP to `[Deny, Audit]` and remove the corresponding Kyverno policies.

## Related Articles

- [Kubernetes Admission Control: PodSecurity Standards and OPA/Kyverno Patterns](/articles/kubernetes/kubernetes-admission-control/)
- [Image Policy Enforcement on Kubernetes Clusters](/articles/kubernetes/image-policy-enforcement/)
- [Pod Security Context Hardening](/articles/kubernetes/pod-security-context/)
- [RBAC Design Patterns for Multi-Team Kubernetes Clusters](/articles/kubernetes/rbac-design-patterns/)
- [Gateway API Security Patterns](/articles/kubernetes/gateway-api-security/)
