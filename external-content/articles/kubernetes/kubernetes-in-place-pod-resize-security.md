---
title: "Kubernetes In-Place Pod Resize Security: Admission Policy and Resource-Cap Enforcement on 1.33+"
description: "In-place pod resize went GA in Kubernetes 1.33. The new resize subresource changes how resource limits are enforced at runtime — admission webhooks must update, ResourceQuotas behave differently, and a misconfigured cluster lets a tenant escape its original limits. Production hardening guide."
slug: "kubernetes-in-place-pod-resize-security"
date: 2026-05-08
lastmod: 2026-05-08
category: "kubernetes"
tags: ["kubernetes", "pod-resize", "admission-control", "resource-quotas", "vpa", "cve"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 658
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/kubernetes/kubernetes-in-place-pod-resize-security/index.html"
---

# Kubernetes In-Place Pod Resize Security: Admission Policy and Resource-Cap Enforcement on 1.33+

## Problem

Until 1.33, changing a Pod's CPU or memory required deleting and recreating the Pod. The Vertical Pod Autoscaler (VPA) papered over this with an `Auto` mode that evicted and rescheduled, which was disruptive enough that most production clusters ran VPA in `Off` or `Initial` mode and accepted that misprovisioned workloads stayed misprovisioned until the next deploy. The `InPlacePodVerticalScaling` feature gate, alpha since 1.27, went **GA in Kubernetes 1.33** and is on by default in 1.34. Pods can now have their `resources.requests` and `resources.limits` mutated on a running container, and the kubelet reconciles cgroup values without restarting the container.

This is a substantial improvement for resource utilisation. It is also a non-trivial change to the Kubernetes security model that most platform teams have not yet absorbed. Three concrete problems:

First, the path that mutates resources is the new **`pods/resize` subresource**, not the standard `pods` update path. Validating admission webhooks (Kyverno, Gatekeeper, Mutating/Validating Admission Policy) that hook `pods` see the original Pod spec at create time but never see the resize call. A policy that says "no container may request more than 4 CPU" enforced at create time is *not* enforced at resize time unless the policy explicitly registers for `pods/resize`. Several teams have already discovered this the slow way after a resize bumped a tenant from 1 vCPU to 16.

Second, **ResourceQuotas behave differently** for resize. The quota controller does observe resize events and rejects resizes that would push a namespace over quota, but it does so *asynchronously* — a resize that the quota controller has not yet processed can be applied to the kubelet, briefly putting the namespace over quota until the controller catches up. For pay-per-resource environments and noisy-neighbour scenarios this matters.

Third, the **resize policy** field on each container determines whether a CPU or memory change requires a container restart. Workloads that are sensitive to JVM heap re-sizing or to `MADV_DONTDUMP` mappings being torn down need to opt in to `RestartContainer` for memory, but the default of `NotRequired` is what most charts ship with. A live memory-limit reduction below the working set can OOM-kill workloads at a time the operator did not initiate.

Target systems: Kubernetes 1.33 (GA) or 1.34+ (default-on); container runtimes containerd 2.0+ or CRI-O 1.33+; kernel cgroup v2 (mandatory for memory hot-resize).

## Threat Model

1. **Tenant in a multi-tenant cluster** with `update` on `pods` (legitimate, for label/annotation changes) and `update` on `pods/resize` (often granted accidentally because RBAC defaults bundle subresources). Goal: bump a Pod past a per-tenant CPU/memory cap to extract more compute than billed for, or to satisfy a noisy workload at the expense of neighbours.
2. **Compromised CI service account** that previously had `patch pods` for kubectl rollouts. Now also has resize, which means the same compromise that previously let the attacker change image tags can now reshape resource requests across the namespace.
3. **VPA recommender misconfiguration** where a tenant-controlled metric drives recommended size. Goal: poison the metric so VPA resizes the workload to a value that consumes most of the node, evicting neighbours via scheduler pressure.
4. **Insider operator** using resize to mask cryptomining: bump CPU during off-hours, return it before the morning report. The Pod object's `metadata` looks unchanged across the day; only the `Status.Resources` field and the resize event log show what happened.

Without resize-aware policy, all four scenarios bypass controls that operators believe are in place. With the configuration in this article, adversary 1 is constrained by a CEL ValidatingAdmissionPolicy on `pods/resize`, 2 is rate-limited and audited, 3 is bounded by a hard ResourceQuota the VPA cannot exceed, and 4 leaves an explicit audit trail.

## Configuration / Implementation

### Step 1 — Confirm the feature is on and the API is what you think

```bash
kubectl version --short
# Server Version: v1.33.x or v1.34.x

# Feature gate (1.33 GA; only present as a flag on older clusters):
kubectl get --raw /metrics 2>/dev/null \
  | grep kubernetes_feature_enabled \
  | grep InPlacePodVerticalScaling

# Confirm the subresource exists:
kubectl get --raw / | jq -r '.paths[]' | grep '/pods/resize' || true
kubectl explain pod.spec.containers.resizePolicy 2>&1 | head -20
```

### Step 2 — Set explicit `resizePolicy` on every workload

The `resizePolicy` field is per-container and per-resource. Always set it; relying on the default is the most common failure mode.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      containers:
        - name: api
          image: registry.example.com/api:1.42.0
          resources:
            requests: { cpu: "500m", memory: "512Mi" }
            limits:   { cpu: "2",    memory: "2Gi"  }
          resizePolicy:
            - resourceName: cpu
              restartPolicy: NotRequired
            - resourceName: memory
              restartPolicy: RestartContainer
```

Memory should generally be `RestartContainer` for stateful or JVM workloads (the runtime cannot reliably shrink heap in place) and `NotRequired` only for stateless services with confirmed elastic memory behaviour.

### Step 3 — A CEL ValidatingAdmissionPolicy on `pods/resize`

This is the single most important control. The policy hooks the resize subresource directly and bounds what resize values are allowed regardless of who requests them.

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: pod-resize-bounds
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups:   [""]
        apiVersions: ["v1"]
        operations:  ["UPDATE"]
        resources:   ["pods/resize"]
  validations:
    - expression: |
        object.spec.containers.all(c,
          (!has(c.resources.limits.cpu) ||
           quantity(c.resources.limits.cpu).isLessThan(quantity('8'))) &&
          (!has(c.resources.limits.memory) ||
           quantity(c.resources.limits.memory).isLessThan(quantity('16Gi')))
        )
      message: "Pod resize would exceed per-container ceiling (8 CPU / 16Gi)."
    - expression: |
        object.spec.containers.all(c,
          c.resources.requests.cpu == c.resources.limits.cpu ||
          quantity(c.resources.limits.cpu).isLessThan(quantity(c.resources.requests.cpu).asInteger() * 4))
      message: "Resize would create CPU limit/request ratio > 4×."
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: pod-resize-bounds-binding
spec:
  policyName: pod-resize-bounds
  validationActions: [Deny, Audit]
  matchResources:
    namespaceSelector:
      matchExpressions:
        - { key: tier, operator: In, values: [tenant, dev] }
```

Two things to notice. (a) `resources: ["pods/resize"]` is not the same string as `pods` — a policy that omits the subresource hooks creation but not resize. (b) `validationActions: [Deny, Audit]` ensures the API server emits an audit annotation even when the request is allowed under another rule, useful for retroactive review.

### Step 4 — Tighten the equivalent Kyverno or Gatekeeper policy

If you run Kyverno, the matching `ClusterPolicy` shape is:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: bound-pod-resize
spec:
  validationFailureAction: Enforce
  rules:
    - name: cap-cpu-on-resize
      match:
        any:
          - resources:
              kinds: ["Pod/resize"]
      validate:
        message: "Resize exceeds 8 CPU ceiling"
        pattern:
          spec:
            containers:
              - resources:
                  limits:
                    cpu: "<=8"
```

The `kinds: ["Pod/resize"]` form is what targets the subresource. A policy targeting `kinds: ["Pod"]` alone *does not* gate resize. Audit your existing Kyverno bundle for any policy that should also apply to resize and add a parallel `Pod/resize` rule.

### Step 5 — RBAC: separate `pods/resize` from `pods`

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: tenant-a
  name: pod-resize-operator
rules:
  - apiGroups: [""]
    resources: ["pods/resize"]
    verbs:     ["update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pod-edit-no-resize
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get","list","watch","update","patch"]
  # Notice: no `pods/resize` here.
```

Many cluster admins assume `pods/resize` is implicitly bundled into `verbs: [update]` on `pods`. It is **not**: subresources require explicit grants. This is good news because it means upgrading to 1.33 does not retroactively grant resize to existing edit roles. Audit your roles to confirm none of them broadly enumerate `pods/*`.

```bash
kubectl get clusterroles -o json \
  | jq -r '.items[] | select(.rules[]?.resources[]? | test("^pods(/.*)?$"))
           | .metadata.name + " " + (.rules | tostring)' \
  | grep 'pods/\*\|"pods/resize"'
```

### Step 6 — Constrain the VPA's resize recommendations

If you run the VPA, switch to the `InPlaceOrRecreate` update mode (added in VPA 1.3, paired with k8s 1.33) and bound recommendations with a `LimitRange` that the VPA must respect:

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: vpa-bounds
  namespace: tenant-a
spec:
  limits:
    - type: Container
      max:     { cpu: "4",    memory: "8Gi" }
      min:     { cpu: "100m", memory: "128Mi" }
      maxLimitRequestRatio: { cpu: "4", memory: "2" }
```

The VPA refuses to recommend outside `LimitRange` bounds; the admission policy refuses to apply outside its bounds even if a non-VPA actor tries. The two together give belt and braces.

### Step 7 — Audit-log every resize

Add to the audit policy:

```yaml
- level: RequestResponse
  resources:
    - group: ""
      resources: ["pods/resize"]
  verbs: ["update","patch"]
  omitStages: ["RequestReceived"]
```

`RequestResponse` (not `Metadata`) ensures the before/after resource values are captured, which is the only way to reconstruct who changed what to what after the fact.

### Step 8 — Detect deferred resizes

When a resize cannot be honoured immediately (e.g., the node has no headroom), the kubelet reports `status.resize: "Deferred"` or `"Infeasible"`. Workloads stuck in `Deferred` are a common symptom of a resize attempt that should not have been allowed in the first place.

```bash
kubectl get pods -A -o json \
  | jq -r '.items[] | select(.status.resize == "Deferred" or .status.resize == "Infeasible")
           | "\(.metadata.namespace)/\(.metadata.name)\t\(.status.resize)"'
```

Wire this into Prometheus via a kube-state-metrics 2.14+ recording rule:

```
sum by (namespace,pod) (kube_pod_status_resize{condition!="Proposed"})
```

## Expected Behaviour

| Signal | Before this hardening | After |
|---|---|---|
| Resize via `pods` update | Allowed, bypasses policies that hook only `pods` | Returns `404` — must use `pods/resize` |
| Resize beyond ceiling | Accepted, kubelet reconciles | Rejected by ValidatingAdmissionPolicy |
| Tenant resize attempt without subresource RBAC | Allowed if they have `update pods` | `403 forbidden` |
| Audit log of resize events | None or minimal | Full `RequestResponse` capture |
| ResourceQuota-overshoot window | Indeterminate | Bounded by quota controller + admission policy |
| VPA recommendation > LimitRange max | Applied | Capped at LimitRange max |
| Pod stuck `Deferred`/`Infeasible` | Not surfaced | Alert via kube-state-metrics |

Verification snippet:

```bash
# Try to resize past the ceiling — should fail.
kubectl patch pod api-7b9f --subresource=resize \
  --patch '{"spec":{"containers":[{"name":"api","resources":{"limits":{"cpu":"16"}}}]}}'
# Expected: error from server: admission webhook ... denied the request: Pod resize would exceed ...
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Subresource-aware policies | Closes the resize bypass | Every existing policy must be reviewed for matching `pods/resize` rule | Build a CI lint on policy bundles that flags `pods` rules without `pods/resize` companions |
| `RestartContainer` memory policy | Avoids OOM on shrink | Resize causes a brief restart | Use only for memory; use `NotRequired` for CPU |
| `InPlaceOrRecreate` VPA mode | Less disruption than `Auto` | New code path — fewer war stories | Roll out per namespace; keep `Initial` mode as fallback |
| Audit-log RequestResponse | Reconstructable history | Audit log volume increases | Filter to resize subresource only; ship to cold storage |
| Hard ResourceQuota | Prevents tenant escape | Workloads with bursty needs are blocked | Pair with priority classes and a small reserve quota |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Policy hooks `pods`, not `pods/resize` | Resize bypasses validation | Audit log shows resize past stated ceiling | Add matching policy rule for `pods/resize`; replay audit |
| `resizePolicy` defaults to `NotRequired` for memory on a JVM workload | Live memory-limit shrink OOM-kills container | OOMKill events with no deploy correlation | Set `RestartContainer` for memory on stateful workloads |
| RBAC grants `pods/*` to tenant | Tenant can resize | `kubectl auth can-i update pods/resize -n tenant-a --as=...` returns yes | Replace with `pods` + explicit subresource grants |
| VPA recommends past LimitRange | LimitRange holds; recommendation is dropped | VPA event "recommendation dropped" | Tune VPA targetCPU/memory; raise LimitRange if intentional |
| Resize stuck `Infeasible` | Pod runs at old size; user thinks they got more | `status.resize` field; alert on metric | Either descheduler reschedules or user reverts |
| Quota controller lag | Brief over-quota | quota-overshoot Prometheus rule | Tighten admission policy below quota; treat quota as a backstop |
| Resize during rolling upgrade of kubelet | Kubelet ignores until new version up | Resize events queue | Drain node before upgrade; rerun resize after |

## When to Consider a Managed Alternative

- **GKE Autopilot** abstracts node-level resize entirely; you specify Pod requests and Google manages the scaling. If your workload pattern fits Autopilot's restrictions, it sidesteps most of this article.
- **AWS Karpenter** can be paired with VPA + in-place resize but currently does not hook the resize subresource for its consolidation logic; rolling-restart-style consolidation is more predictable than mixing.
- **Azure AKS Vertical Pod Autoscaling (managed)** preview in 1.33 clusters bundles many of these guardrails out of the box.

## Related Articles

- [Kubernetes admission control deep dive](/articles/kubernetes/kubernetes-admission-control/)
- [Validating Admission Policy with CEL](/articles/kubernetes/validating-admission-policy-cel/)
- [Resource quotas and LimitRanges](/articles/kubernetes/resource-quotas-limitranges/)
- [Pod security context](/articles/kubernetes/pod-security-context/)
- [Multi-tenancy hardening on Kubernetes](/articles/kubernetes/multi-tenancy-hardening/)
