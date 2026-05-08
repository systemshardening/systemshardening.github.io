---
title: "CSI Driver Security: Volume-Mount Hardening, Privileged Drivers, and Inline Ephemeral Volumes"
description: "CSI drivers run with broad privileges by design. Their security posture often goes unaudited — until one is the exfil path or the privilege-escalation step."
slug: "csi-driver-security"
date: 2026-04-29
lastmod: 2026-04-29
category: "kubernetes"
tags: ["csi", "kubernetes", "storage", "volumes", "privileged"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 224
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/kubernetes/csi-driver-security/index.html"
---

# CSI Driver Security: Volume-Mount Hardening, Privileged Drivers, and Inline Ephemeral Volumes

## Problem

The Container Storage Interface (CSI) is the standard mechanism for attaching storage to Kubernetes pods. Any storage backend — AWS EBS, GCE Persistent Disk, Azure Disk, NFS, GlusterFS, vSphere CNS, custom in-house drivers — implements CSI and runs as one or more privileged Pods on every node.

CSI drivers have an awkward security shape:

- **Privileged by design.** Mounting filesystems requires `CAP_SYS_ADMIN`; the driver typically runs with `privileged: true` to perform mounts.
- **Trusted by Kubernetes.** The kubelet asks the driver to mount a volume; the driver returns a path; kubelet bind-mounts that path into the workload Pod. No further validation.
- **Persistent.** CSI drivers run as DaemonSets — one Pod per node, always running, always privileged.
- **Multi-tenant attack surface.** A driver that handles storage for many namespaces can become a cross-tenant attack vector if it mishandles credentials or paths.
- **Inline ephemeral volumes.** CSI inline ephemeral volumes (CSI-EV) let a Pod request volume directly, with parameters in the Pod spec — interesting attack surface if parameters aren't validated.

By 2026 most production clusters run multiple CSI drivers (a cloud-storage driver, secrets-store CSI, in-house drivers). Few teams audit them.

The specific gaps in default CSI deployments:

- Drivers run with full host privileges (privileged container, host PID/network, hostPath mounts to `/var/lib/kubelet`).
- Driver Pods often have ServiceAccounts with cluster-wide read of secrets / configmaps.
- Inline ephemeral volume parameters can be used to mount arbitrary host paths if the driver's parameter validation is weak.
- CSI sidecar containers (external-attacher, external-provisioner, etc.) run with broad RBAC.
- Driver upgrade flows often skip security review; "it's just storage."

This article covers CSI driver threat-model basics, the security posture audit you should run on every CSI driver, hardening for in-house drivers, restricting inline ephemeral volume usage, and the patterns for the secrets-store CSI driver specifically.

**Target systems:** Kubernetes 1.28+, CSI spec v1.10+; common drivers: AWS EBS CSI, GCP PD CSI, Azure Disk CSI, OpenEBS, Longhorn, Rook/Ceph, secrets-store CSI driver, NFS CSI driver.

## Threat Model

- **Adversary 1 — Compromised CSI driver Pod:** an attacker has code execution in a driver Pod. Because of `privileged: true`, the attacker has effective root on the node.
- **Adversary 2 — Malicious Pod abusing inline ephemeral volume parameters:** a tenant's Pod uses CSI-EV; if the driver doesn't validate parameters, the tenant requests a volume with attacker-chosen path / parameters.
- **Adversary 3 — Cross-tenant storage access:** a CSI driver providing per-tenant volumes returns the wrong tenant's data due to parameter confusion.
- **Adversary 4 — Driver supply-chain compromise:** a CSI driver image is replaced upstream; the new version exfiltrates volume contents.
- **Adversary 5 — RBAC abuse via driver ServiceAccount:** the driver's ServiceAccount has broad cluster permissions; attacker uses driver-pod compromise to read all Secrets across the cluster.
- **Access level:** Adversary 1 has Pod compromise. Adversary 2 has Pod-create permissions. Adversary 3 has Pod-create with CSI-EV. Adversary 4 has driver-image distribution access. Adversary 5 has driver-Pod compromise + cluster-wide RBAC.
- **Objective:** Read or modify any volume on any node; escape to host; exfiltrate cluster secrets; pivot through the storage layer.
- **Blast radius:** A compromised privileged CSI driver = node-level root + cross-tenant volume access + Secret-store API access. Without hardening, this is one of the largest blast radii in a Kubernetes cluster.

## Configuration

### Step 1: Audit Existing CSI Drivers

```bash
# List all CSI drivers in the cluster.
kubectl get csidriver
# NAME                    ATTACH_REQUIRED  POD_INFO_ON_MOUNT  REQUIRES_REPUBLISH  MODES        AGE
# ebs.csi.aws.com         true             false              false               Persistent   23d
# secrets-store.csi.k8s.io  false          true               true                Ephemeral    14d
# efs.csi.aws.com         false            false              false               Persistent   23d

# For each driver, find its Pod spec.
for d in $(kubectl get csidriver -o jsonpath='{.items[*].metadata.name}'); do
    NS=$(kubectl get pods -A --selector "app=${d%%.*}-csi" -o jsonpath='{.items[0].metadata.namespace}')
    echo "=== $d ($NS) ==="
    kubectl get daemonset -n "$NS" -o yaml | yq '.spec.template.spec.containers[] | {name, securityContext, volumeMounts}'
done
```

Common red flags:

- `privileged: true` (necessary for mount operations but blast radius is large).
- `hostPID: true` or `hostNetwork: true` (rarely necessary for CSI).
- `hostPath` mounts of broad host paths (entire `/`, `/var`, `/etc`).
- ServiceAccount with `cluster-admin` or unscoped permissions.

### Step 2: Restrict CSI Driver ServiceAccount Permissions

Default driver charts often install with broad RBAC. Audit and tighten.

```yaml
# Example: minimum ClusterRole for AWS EBS CSI driver.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ebs-csi-controller-bound
rules:
  # Persistent volume management — required.
  - apiGroups: [""]
    resources: ["persistentvolumes"]
    verbs: ["get", "list", "watch", "create", "patch", "update"]
  - apiGroups: [""]
    resources: ["persistentvolumeclaims"]
    verbs: ["get", "list", "watch", "update"]
  - apiGroups: [""]
    resources: ["persistentvolumeclaims/status"]
    verbs: ["patch"]
  # Volume attachments — required.
  - apiGroups: ["storage.k8s.io"]
    resources: ["volumeattachments"]
    verbs: ["get", "list", "watch", "create", "patch", "delete"]
  - apiGroups: ["storage.k8s.io"]
    resources: ["volumeattachments/status"]
    verbs: ["patch"]
  # Storage class metadata — read only.
  - apiGroups: ["storage.k8s.io"]
    resources: ["storageclasses"]
    verbs: ["get", "list", "watch"]
  # Events for status reporting.
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["create", "patch"]
  # NOT included: secrets, configmaps, pods/exec, broad cluster reads.
```

The key omission: `secrets`. If your CSI driver doesn't need to read application secrets (most don't — they have their own credential mechanism via IRSA/Workload Identity), don't grant secret-read.

For drivers that legitimately need to read CSI-related secrets (e.g., the secrets-store CSI driver), scope:

```yaml
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["my-driver-config"]   # specific secret only
  verbs: ["get"]
```

### Step 3: Run CSI Drivers in a Dedicated Namespace

Isolate the blast radius:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: csi-drivers
  labels:
    pod-security.kubernetes.io/enforce: privileged
    pod-security.kubernetes.io/warn: privileged
    pod-security.kubernetes.io/audit: privileged
```

Privileged is honest — drivers genuinely need it. Keep them in this namespace, away from your workloads. Audit which workloads have permission to interact with this namespace; should be: nothing except cluster-admin and the driver Helm chart.

### Step 4: Restrict Inline Ephemeral Volume Usage

CSI inline ephemeral volumes (`CSIVolumeSource`) let Pods request volumes directly:

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      volumeMounts:
        - name: secrets-store
          mountPath: /etc/secrets
  volumes:
    - name: secrets-store
      csi:
        driver: secrets-store.csi.k8s.io
        readOnly: true
        volumeAttributes:
          secretProviderClass: my-provider
```

Useful for one-off mounts; risky if drivers don't validate `volumeAttributes`. A malicious tenant could craft attributes that traverse paths or escape namespaces.

Restrict at admission time:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: restrict-inline-csi
spec:
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
  validations:
    - expression: >
        !has(object.spec.volumes) ||
        object.spec.volumes.all(v,
          !has(v.csi) ||
          v.csi.driver in ["secrets-store.csi.k8s.io"])
      messageExpression: >
        "Inline CSI volumes are restricted; only secrets-store-csi-driver is allowed"
      reason: Forbidden
```

Allow only specific known-safe drivers as inline; require PVC-based access for everything else. PVCs go through the normal volume-management path with RBAC.

### Step 5: Secret-Store CSI Driver Specifics

The secrets-store-csi-driver is widely deployed; treat it specifically.

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: payments-secrets
  namespace: payments
spec:
  provider: aws
  parameters:
    objects: |
      - objectName: payments-db-password
        objectType: secretsmanager
        objectAlias: db-password
  secretObjects:
    - data:
        - key: password
          objectName: db-password
      secretName: payments-db-password
      type: Opaque
```

Hardening:

- **Limit who can create SecretProviderClass.** It's effectively a "fetch this secret from AWS" instruction.
- **Audit the IRSA / workload identity** on the driver. The secrets-store driver uses cluster credentials (or workload identity per Pod, depending on configuration) to fetch from the cloud secret store. Scope minimally.
- **Don't sync to Kubernetes Secrets** unless required — the `secretObjects` block creates a K8s Secret that's visible to anyone with `secrets:get`. Use the file-based mount (`/mnt/secrets-store/...`) instead.

```yaml
spec:
  parameters:
    objects: |
      - objectName: payments-db-password
        ...
  # Do NOT define secretObjects. Use the file mount only.
```

The file-based mount (FUSE-style) is per-Pod; only that Pod can read it. Sync to Secret is a convenience that broadens the access surface.

### Step 6: Audit Driver Image Provenance

CSI driver images come from cloud providers' registries. Verify signatures.

```yaml
# Kyverno policy: CSI drivers must have valid cosign signatures.
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: csi-image-signed
spec:
  validationFailureAction: Enforce
  rules:
    - name: csi-image-signed
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [csi-drivers, kube-system]
      verifyImages:
        - imageReferences:
            - "registry.k8s.io/sig-storage/*"
            - "amazon/aws-ebs-csi-driver:*"
            - "gcr.io/csi-secrets-store/*"
          attestors:
            - entries:
                - keys:
                    publicKeys: |-
                      -----BEGIN PUBLIC KEY-----
                      ...
                      -----END PUBLIC KEY-----
```

Register the public keys for each upstream CSI provider; reject unsigned versions. For in-house drivers, sign with your cosign workflow.

### Step 7: Per-Driver Telemetry

Monitor each CSI driver as you would any privileged workload:

```
csi_driver_volume_operations_total{driver, op, result}
csi_driver_secret_lookups_total{driver}
csi_driver_volume_attach_duration_seconds{driver}
csi_driver_volume_detach_duration_seconds{driver}
csi_driver_inline_volume_creates_total{driver, namespace}
```

Alert on:

- Sustained high error rate from a specific driver.
- Inline volume creates from unauthorized namespaces.
- Secret-lookup volume from a driver that shouldn't need them.

### Step 8: Driver Update Discipline

CSI drivers have privileged access. Treat updates as security-relevant:

- **Stage in non-prod first** — let driver run for 1 week before promoting.
- **Read changelogs** for security-relevant changes; CVE notes.
- **Verify signatures** before deploy.
- **Roll forward gradually** — node-by-node, with health checks between.

For Helm-managed drivers, pin chart versions in a GitOps repo:

```yaml
# helm-release.yaml
chart: aws-ebs-csi-driver
version: 2.36.0   # pinned; explicit upgrade via PR
```

## Expected Behaviour

| Signal | Default CSI deploy | Hardened |
|--------|----------------------|------------|
| Driver ServiceAccount permissions | Often cluster-admin or broad | Minimum-necessary; no secrets unless driver needs |
| Driver namespace | Mixed with other infrastructure | Dedicated `csi-drivers` namespace |
| Inline ephemeral volumes | Any driver | Allowlisted (typically only secrets-store-csi) |
| Image signature verification | Optional | Required via Kyverno |
| Driver Pod privileged | Yes (necessary) | Yes; understood and audited |
| Cross-driver isolation | None | Per-driver namespace; per-driver SA |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Tightened ServiceAccount | Smaller blast radius | Driver releases sometimes need new permissions | Read changelogs; scope by least-privilege; periodic audit. |
| Dedicated namespace | Bounded admin scope | More namespaces to manage | One-time setup; standardized on `csi-drivers`. |
| Inline volume allowlist | Prevents arbitrary parameter abuse | Some operators want flexibility | PVC-based access for general use; inline only for known-safe drivers. |
| Secret-store CSI: file-only | Per-Pod isolation | Some apps expect K8s Secrets format | Use file mount; app reads from disk. |
| Image signature verification | Tamper detection | Trust-root maintenance | Pin to upstream CSI providers' published keys. |
| Update staging | Reduced regression risk | Slower rollout | Parallel staging cluster; same chart versions promoted. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Driver permissions too restrictive | Driver fails to provision new volumes | Driver logs show RBAC errors | Add the specific permission needed, after review of why it's needed. |
| Inline volume policy blocks legitimate use | Pod creation fails with policy denial | VAP audit log | Allowlist the additional driver after security review. |
| Driver compromise | Privileged code on every node | Anomalous node-level activity from driver Pod | Quarantine the Pod (delete and prevent re-schedule); investigate; rotate any credentials accessible from driver. |
| ServiceAccount drift after upgrade | Driver works but RBAC has expanded | Periodic audit | Re-tighten; pin chart version. |
| Cross-tenant volume access via parameter abuse | Tenant A reads Tenant B's volume | Audit logs of volume mounts | Disable inline ephemeral for the affected driver; investigate driver code; report upstream. |
| Image signature missing for new driver release | Cluster cannot upgrade | Kyverno blocks Pod creation | Verify the upstream actually signs; if so, re-fetch keys. If not, escalate to upstream maintainer. |

## Related Articles

- [User Namespaces for Pods](/articles/kubernetes/user-namespaces-pods/)
- [Confidential Containers on Kubernetes](/articles/kubernetes/confidential-containers/)
- [Pod Security Context Hardening](/articles/kubernetes/pod-security-context/)
- [External Secrets Operator](/articles/kubernetes/external-secrets-operator/)
- [Kubernetes Admission Control](/articles/kubernetes/kubernetes-admission-control/)
