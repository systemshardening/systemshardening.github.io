---
title: "Kubernetes Dynamic Resource Allocation (DRA) Security Hardening"
description: "Securing the GA DRA API in Kubernetes 1.32+: ResourceClaim RBAC, driver trust boundaries, GPU/TPU isolation, and multi-tenant DRA threat model."
slug: "kubernetes-dra-security"
date: 2026-05-08
lastmod: 2026-05-08
category: "kubernetes"
tags: ["kubernetes", "dra", "resourceclaim", "gpu", "device-driver", "rbac"]
personas: ["platform-engineer", "security-engineer", "ml-engineer"]
article_number: 650
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/kubernetes/kubernetes-dra-security/index.html"
---

# Kubernetes Dynamic Resource Allocation (DRA) Security Hardening

## Problem

Dynamic Resource Allocation (DRA) graduated to GA in Kubernetes 1.32 and is now the recommended mechanism for scheduling specialised hardware: GPUs, TPUs, FPGAs, NICs with SR-IOV, and similar. It replaces the older device-plugin API for advanced workloads with a structured-parameters model where workloads request hardware via `ResourceClaim` objects that the scheduler matches against `ResourceSlice`-published inventory exposed by per-node DRA drivers.

The security story is materially different from device plugins. Device plugins were opaque kubelet sidecars with a narrow gRPC contract; DRA drivers are full Kubernetes citizens that:

1. Run a controller component with cluster-wide read/write on `ResourceClaim`, `ResourceSlice`, and `DeviceClass` objects.
2. Run a kubelet plugin component with host access (typically `hostPath` to `/var/lib/kubelet/plugins_registry/`, often `privileged: true`, almost always `hostPID`).
3. Mediate access to hardware that, in the GPU/TPU case, can read VRAM left over from a prior tenant unless the driver is careful.

Three structural risks follow. First, RBAC for DRA objects is *new* — most platform teams have not yet authored `Role`s for `resourceclaims` or `resourceclaimtemplates`, so cluster-admin-bound service accounts are the default. Second, DRA drivers from third-party vendors (NVIDIA, Intel, AMD, plus an emerging set of cloud-specific ones) ship as Helm charts with `clusterAdmin`-level defaults; few teams audit these at install time. Third, the `parameters` field on a `ResourceClaim` is driver-defined opaque JSON, opening a parser-attack surface that does not exist in the simpler device-plugin model.

Workloads have been observed exploiting privileged DRA drivers to escape pods, read GPU memory from co-tenant inference jobs, and abuse claim-template controllers to mint resources that bypass `ResourceQuota`. The DRA API surface also changes the `Pod`-spec admission story: a `Pod` referencing a `ResourceClaim` carries an indirect attack vector that ValidatingAdmissionPolicies written before 1.32 do not inspect.

Target systems: Kubernetes 1.32+ (DRA GA), 1.33 (DRA `AdminAccess` and prioritised allocation), with NVIDIA GPU Operator ≥ 24.9, Intel Device Plugins ≥ 0.31, or equivalent third-party DRA drivers.

## Threat Model

1. **Co-tenant pod attempting GPU memory disclosure.** Goal: read VRAM left by the prior tenant's inference run. Surface: DRA driver's reset/zeroing logic; misconfigured `DeviceClass.config`.
2. **Tenant exhausting cluster GPUs via forged ResourceClaims.** Goal: deny service to other tenants. Surface: missing `ResourceQuota` rules on `count/resourceclaims.resource.k8s.io` and weak admission policy.
3. **Compromised DRA driver controller.** Goal: read all `ResourceClaim` objects (containing tenant identifiers, model paths, sometimes secrets) and pivot to other namespaces. Surface: cluster-wide RBAC granted at install.
4. **Pod escape via privileged kubelet-plugin sidecar.** Goal: hostPath-mount a UNIX socket, talk to the driver, request privileged operations. Surface: containers that share `/var/lib/kubelet/plugins/<driver>/` with the kubelet plugin.

Blast radius without hardening: a single compromised tenant pod can exfiltrate GPU memory across the fleet. With hardening (driver scoping, claim-template admission, mandatory zeroing) the same compromise is contained to the tenant's own claims, with audit evidence.

## Configuration / Implementation

### Step 1 — Enable DRA-aware admission

```yaml
# apiserver-config.yaml fragment
apiServer:
  featureGates:
    DynamicResourceAllocation: true
    DRAResourceClaimDeviceStatus: true
    DRAAdminAccess: true       # 1.33+; gates the high-privilege `adminAccess` field
  admissionControl:
    - ValidatingAdmissionPolicy
    - ResourceQuota
```

Confirm:

```bash
kubectl api-resources --api-group=resource.k8s.io
# resourceclaims         resource.k8s.io/v1   true   ResourceClaim
# resourceclaimtemplates resource.k8s.io/v1   true   ResourceClaimTemplate
# resourceslices         resource.k8s.io/v1   false  ResourceSlice
# deviceclasses          resource.k8s.io/v1   false  DeviceClass
```

### Step 2 — Author RBAC for DRA

Default cluster roles do not grant tenants permission to create `ResourceClaim`s. Define a tenant-scoped role:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: dra-tenant
  namespace: tenant-a
rules:
- apiGroups: ["resource.k8s.io"]
  resources: ["resourceclaims", "resourceclaimtemplates"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["resource.k8s.io"]
  resources: ["deviceclasses"]
  verbs: ["get", "list"]   # read-only
```

Cluster-scoped `DeviceClass` and `ResourceSlice` must be read-only for tenants — these describe hardware inventory and a write would let a tenant fake capabilities.

### Step 3 — Lock down the DRA driver install

DRA drivers ship as Helm charts that frequently include `ClusterRoleBinding` to `cluster-admin`. Replace with a least-privilege role:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: nvidia-dra-driver-controller
rules:
- apiGroups: ["resource.k8s.io"]
  resources: ["resourceclaims", "resourceslices"]
  verbs: ["get", "list", "watch", "update", "patch"]
- apiGroups: ["resource.k8s.io"]
  resources: ["resourceclaims/status", "resourceslices/status"]
  verbs: ["update", "patch"]
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["events"]
  verbs: ["create", "patch"]
# Explicitly NOT: secrets, configmaps cluster-wide, pods/exec, namespaces.
```

The kubelet plugin component must not run as `privileged: true`. Use an explicit capability set:

```yaml
securityContext:
  privileged: false
  capabilities:
    drop: ["ALL"]
    add: ["SYS_ADMIN"]   # only if the driver does mount(2); justify
  readOnlyRootFilesystem: true
  seccompProfile:
    type: RuntimeDefault
```

### Step 4 — Force device zeroing in DeviceClass

For GPU/TPU classes, the `DeviceClass.spec.config` controls reset behaviour. Make zeroing mandatory:

```yaml
apiVersion: resource.k8s.io/v1
kind: DeviceClass
metadata:
  name: nvidia-gpu-shared
spec:
  selectors:
  - cel:
      expression: "device.driver == 'gpu.nvidia.com'"
  config:
  - opaque:
      driver: gpu.nvidia.com
      parameters:
        resetPolicy: "ZeroVRAMOnRelease"
        sharingStrategy: "TimeSlicing"
        sharingTimeSliceMs: 100
```

Validate at admission time that no namespace can create a `ResourceClaim` referencing a class without zeroing — the driver-specific field name varies, so pin via VAP rather than relying on driver defaults.

### Step 5 — ValidatingAdmissionPolicy for ResourceClaim

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: dra-claim-policy
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
    - apiGroups: ["resource.k8s.io"]
      apiVersions: ["v1"]
      operations: ["CREATE", "UPDATE"]
      resources: ["resourceclaims", "resourceclaimtemplates"]
  validations:
  - expression: |
      object.spec.devices.requests.all(r,
        r.deviceClassName in ['nvidia-gpu-shared', 'nvidia-gpu-exclusive', 'tpu-v5e']
      )
    message: "ResourceClaim must reference an approved DeviceClass."
  - expression: |
      !has(object.spec.devices.requests[0].adminAccess) ||
      object.spec.devices.requests[0].adminAccess == false
    message: "adminAccess is reserved for cluster admins; use a ResourceClaimTemplate from the platform team."
  - expression: "size(object.spec.devices.requests) <= 8"
    message: "ResourceClaim cannot request more than 8 devices; use multiple claims for larger jobs."
```

### Step 6 — Quota the new resources

DRA introduces quotable counts:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: dra-quota
  namespace: tenant-a
spec:
  hard:
    count/resourceclaims.resource.k8s.io: "20"
    count/resourceclaimtemplates.resource.k8s.io: "5"
```

Without these, a malicious or buggy operator can mint thousands of claims and pin scheduler memory.

### Step 7 — Audit policy

```yaml
# audit-policy.yaml
- level: Metadata
  resources:
  - group: "resource.k8s.io"
    resources: ["resourceclaims", "resourceslices", "deviceclasses"]
- level: RequestResponse
  resources:
  - group: "resource.k8s.io"
    resources: ["resourceclaims"]
  verbs: ["create", "delete", "patch"]
  namespaces: ["tenant-*"]
```

Stream to your SIEM; alert on any `adminAccess: true` create, any `ResourceClaim` whose `parameters` blob exceeds 16KB (likely a parser-attack probe), and any `DeviceClass` mutation.

## Expected Behaviour

| Signal | Before hardening | After hardening |
|--------|------------------|-----------------|
| Tenant creates `adminAccess: true` claim | Allowed; admin-mode access to device | VAP rejects with explanatory message |
| GPU memory remnant after pod release | VRAM may persist | Zeroed by driver before next allocation |
| Cluster-admin scope of DRA driver | Read everything | Limited to `resource.k8s.io` group |
| Audit trail of claim mutations | Mixed in with general API logs | Separate stream with `RequestResponse` body |
| `ResourceQuota` on claims | Not enforced | 20-claim limit per tenant |

```bash
# Verify zeroing is in DeviceClass.
kubectl get deviceclass nvidia-gpu-shared -o jsonpath='{.spec.config[0].opaque.parameters.resetPolicy}'
# ZeroVRAMOnRelease

# Verify VAP is binding.
kubectl get validatingadmissionpolicybinding | grep dra
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Zeroing on release | Closes cross-tenant memory leak | 1–4s per device release; hurts rapid-cycle batch jobs | Use exclusive (non-shared) claims for trusted single-tenant pipelines |
| Restricted driver RBAC | Smaller blast radius | Vendor charts may break minor upgrades | Pin chart versions; track upstream RBAC diffs in CI |
| VAP enforcement | Catches misconfigured workloads at submit time | CEL expressions add submit-time latency | Cache VAP compilation (default in 1.32+); keep expressions <50 ops |
| Quota on claims | Prevents flood DoS | Legitimate large-batch jobs need exception | Per-tenant override namespace; review quarterly |
| Banning `privileged: true` for kubelet plugin | Removes host-takeover path | Some drivers (e.g., older NVIDIA builds) refuse to start | Require vendor SBOM + capability justification before approval |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Driver controller crashloops post-RBAC trim | Pods stuck `Pending` with `WaitingForResourceAllocation` | `kubectl describe pod` + driver logs `forbidden: cannot list secrets` | Re-add specific verb identified in error; never restore wildcard |
| VAP regex over-matches and blocks ops claims | Platform jobs cannot submit DRA claims | VAP audit log shows reject of platform namespace | Add `namespaceSelector` to exclude `kube-system` and `platform-*` |
| Zeroing parameter ignored by driver | Inter-tenant memory disclosure still possible | Periodic VRAM-canary test pod | File issue with vendor; in interim, require exclusive claims for sensitive workloads |
| ResourceQuota race with templates | Templated workload failures during burst | Events: `exceeded quota: dra-quota` | Increase template-derived claim count carefully; consider HPA back-off |
| Audit log volume spikes | Backpressure on audit pipeline | Webhook receiver latency >5s | Drop `Metadata` level on resourceslices (high-frequency); keep RequestResponse on claims |

## When to Consider a Managed Alternative

- GKE Autopilot, EKS Auto Mode, and AKS managed GPU pools centrally apply DRA hardening and zeroing defaults; sensible if you do not have a platform team to author and maintain VAP+RBAC.
- For sovereign / regulated workloads with strict tenant isolation, confidential GPU offerings (NVIDIA H100 in CC-mode on Azure, AWS) eliminate cross-tenant VRAM leakage at the hardware level.

## Related Articles

- [GPU Isolation Patterns](/articles/kubernetes/gpu-isolation/)
- [Validating Admission Policy with CEL](/articles/kubernetes/validating-admission-policy-cel/)
- [Multi-tenancy Hardening](/articles/kubernetes/multi-tenancy-hardening/)
- [Resource Quotas and LimitRanges](/articles/kubernetes/resource-quotas-limitranges/)
- [GPU Cost and Security Monitoring](/articles/kubernetes/gpu-cost-security-monitoring/)
