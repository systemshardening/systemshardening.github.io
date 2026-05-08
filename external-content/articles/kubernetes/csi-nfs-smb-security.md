---
title: "Kubernetes CSI NFS and SMB Driver Security"
description: "Harden Kubernetes CSI drivers for NFS and SMB against CVE-2026-3864/3865 subDir path traversal, malicious volume provisioning, and silent fixes in the fast-moving CSI driver ecosystem."
slug: csi-nfs-smb-security
date: 2026-05-02
lastmod: 2026-05-02
category: kubernetes
tags: ["csi", "nfs", "smb", "cve-2026-3864", "cve-2026-3865", "path-traversal", "storage-security"]
personas: ["platform-engineer", "sre", "security-engineer"]
article_number: 368
difficulty: advanced
estimated_reading_time: 15
published: true
layout: article.njk
permalink: "/articles/kubernetes/csi-nfs-smb-security/index.html"
---

# Kubernetes CSI NFS and SMB Driver Security

## Problem

The official `csi-driver-nfs` and `csi-driver-smb` drivers, maintained by the Kubernetes SIG Storage team, enable pods to mount NFS shares and Windows SMB/CIFS shares as PersistentVolumes. They are widely deployed in on-premises Kubernetes clusters and hybrid cloud environments where centralised NAS or SAN storage is shared across multiple workloads and teams. Both drivers are installed as Helm charts, run as DaemonSets on every node, and are responsible for translating PersistentVolume specifications into actual mount operations against remote file servers.

**CVE-2026-3864** (CSI NFS Driver, March–April 2026, CVSS 6.5) exposed a path traversal vulnerability in how the NFS driver handles the `subDir` parameter in PersistentVolume specifications. The `subDir` parameter is a convenience feature: it allows a PV to mount a sub-directory within a larger NFS share rather than the share root, so multiple PVs can coexist within a single export. The flaw was that the driver did not sanitise `subDir` values for directory traversal sequences. An attacker with PersistentVolume creation rights could set `subDir: ../../critical-data` and cause the driver to mount or operate on a path that sits outside the intended base directory on the NFS server. Critically, the traversal also affected the cleanup path executed when a PV is deleted with `reclaimPolicy: Delete` — the driver would delete the traversed-to directory on the NFS server, causing permanent data loss. The vulnerability was patched in csi-driver-nfs v4.13.1.

**CVE-2026-3865** (CSI SMB Driver, April 2026, CVSS 6.5) represents the same class of path traversal in the SMB driver's `subDir` parameter handling. The two drivers share a substantial amount of code — the sub-directory provisioning logic was originally written once and adapted into both. An attacker with PersistentVolume write access could traverse outside the intended SMB share path, again with data-destruction consequences during deletion. The patch for csi-driver-smb followed the NFS fix by a short interval after a parallel review of the shared codebase.

The broader CSI driver security surface makes these vulnerabilities especially significant. CSI node plugins run as DaemonSets with elevated privileges on every node — mounting filesystems typically requires `CAP_SYS_ADMIN` or a fully privileged container. The drivers process PersistentVolume specifications that can contain user-controlled parameters; any parameter that is passed to a mount command, network RPC, or filesystem operation without validation is a potential injection or traversal vector. In a multi-tenant cluster, a single exploited storage parameter can cross tenant boundaries on the underlying NFS or SMB server, which typically has no awareness of Kubernetes namespace isolation.

The open source context of these CVEs adds an operational dimension that platform teams must account for. CVE-2026-3864 was disclosed through the standard Kubernetes security process — filed to `security@kubernetes.io`, coordinated with the SIG Storage maintainers, and published with a GitHub security advisory and a simultaneous post to `discuss.kubernetes.io`. However, the fix commit to `csi-driver-nfs` — a change to `pkg/nfs/nfs.go` with the message "fix subdir path validation" — was merged to the public `master` branch several days before the advisory was published. An operator watching `https://github.com/kubernetes-csi/csi-driver-nfs/commits/master` would have seen the change before the official announcement. This is not unusual for open-source Kubernetes components, and the gap creates a window during which attackers who monitor commit history could act before defenders who wait for official announcements.

The code-sharing pattern between csi-driver-nfs and csi-driver-smb means that a researcher who reads the NFS fix diff can immediately check whether the same vulnerable code exists in the SMB driver. The SMB advisory was filed and patched quickly, but the gap between the two — even a few days — represents a patch-gap window that sophisticated attackers actively exploit. Platform teams should monitor both repositories together, not just the driver they believe is more critical.

Target systems: csi-driver-nfs < v4.13.1, csi-driver-smb < patched version, Kubernetes 1.28+.

## Threat Model

1. **Developer with PVC creation access exploiting subDir traversal.** A developer with `create` rights on PersistentVolumeClaims in their namespace uses a StorageClass that exposes the `subDir` parameter as a user-controllable field. They craft a PV (or trigger dynamic provisioning) with `subDir: ../../production-backups` and gain mount access to a critical NFS directory outside their allowed subtree. From within their pod, they can read, modify, or exfiltrate data belonging to other teams.

2. **Volume deletion triggering unintended data destruction.** A PV with a malicious `subDir` value is created and then deleted — either deliberately by the attacker or as part of normal PVC lifecycle management. With `reclaimPolicy: Delete`, the CSI driver's cleanup code traverses to the unintended path on the NFS or SMB server and removes the directory and all its contents. The destruction is immediate and, without a separate backup, permanent.

3. **Patch-gap attacker targeting SMB after NFS fix is published.** A threat actor reads the published CVE-2026-3864 advisory and the associated NFS driver fix diff. They observe that the identical `subDir` validation code exists in csi-driver-smb (before the SMB patch is released) and immediately scan or probe Kubernetes clusters running SMB-backed PVs, targeting environments where the SMB driver has not yet been patched. The window between the NFS advisory and the SMB advisory is the critical exposure period.

4. **NFS server credential theft via node plugin pod compromise.** The csi-driver-nfs node plugin DaemonSet has access to NFS mount credentials stored on the node — including Kerberos keytabs for sec=krb5 mounts and `auth_sys` UID mappings. A container escape from any pod on the node to the node plugin pod (which runs with elevated privileges) yields these credentials. The attacker then authenticates directly to the NFS server from outside the cluster, bypassing all Kubernetes RBAC and network policies.

The blast radius of a successful exploitation scales with how broadly the NFS or SMB share is used. If a single NFS export backs PVs for dozens of namespaces, a traversal attack from any one of those namespaces can reach data belonging to all of them. The NFS server itself has no Kubernetes namespace concept — it sees only UID/GID and path. Restricting who can create PersistentVolumes (cluster-scoped) rather than only PersistentVolumeClaims (namespace-scoped) is the primary architectural control that limits the blast radius.

## Configuration / Implementation

### Upgrading CSI Drivers

The immediate remediation is to upgrade both drivers to their patched versions. Check the currently deployed version before upgrading:

```bash
# Check csi-driver-nfs version
kubectl get daemonset -n kube-system csi-nfs-node \
  -o jsonpath='{.spec.template.spec.containers[0].image}'

# Check csi-driver-smb version
kubectl get daemonset -n kube-system csi-smb-node \
  -o jsonpath='{.spec.template.spec.containers[0].image}'
```

Upgrade using Helm:

```bash
# Add or update the Helm repo
helm repo add csi-driver-nfs https://raw.githubusercontent.com/kubernetes-csi/csi-driver-nfs/master/charts
helm repo add csi-driver-smb https://raw.githubusercontent.com/kubernetes-csi/csi-driver-smb/master/charts
helm repo update

# Upgrade csi-driver-nfs to the patched version
helm upgrade csi-driver-nfs csi-driver-nfs/csi-driver-nfs \
  --version v4.13.1 \
  --namespace kube-system \
  --reuse-values

# Upgrade csi-driver-smb to the patched version (check release notes for exact version)
helm upgrade csi-driver-smb csi-driver-smb/csi-driver-smb \
  --namespace kube-system \
  --reuse-values
```

DaemonSet upgrades perform a rolling restart across nodes. If pods are running with PVs mounted from these drivers, the rolling restart may briefly interrupt IO on those nodes. Verify the rollout completes:

```bash
kubectl rollout status daemonset/csi-nfs-node -n kube-system
kubectl rollout status daemonset/csi-smb-node -n kube-system
```

### Restricting PersistentVolume Creation via RBAC

PersistentVolume creation is a cluster-scoped operation. Developers should only be able to create PersistentVolumeClaims (namespace-scoped), not PersistentVolumes directly. Auditing who currently has PV creation rights is the first step:

```bash
# Find ClusterRoleBindings that grant PV creation
kubectl get clusterrolebinding -o json | jq -r '
  .items[] |
  select(.roleRef.kind == "ClusterRole") |
  . as $crb |
  (.subjects // [])[] |
  {
    binding: $crb.metadata.name,
    role: $crb.roleRef.name,
    subject_kind: .kind,
    subject_name: .name,
    subject_namespace: (.namespace // "cluster-scoped")
  }
' | jq -s 'map(select(.role | test("storage|pv|cluster-admin"; "i")))'

# Check which ClusterRoles allow PV creation
kubectl get clusterrole -o json | jq -r '
  .items[] |
  select(.rules[]? |
    (.resources[]? | test("persistentvolumes")) and
    (.verbs[]? | test("create|\\*"))
  ) | .metadata.name
'
```

Create a restricted ClusterRole that grants only PVC (not PV) operations for developer namespaces:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: storage-user
rules:
  - apiGroups: [""]
    resources: ["persistentvolumeclaims"]
    verbs: ["get", "list", "watch", "create", "update", "delete"]
  # Explicitly no access to persistentvolumes (cluster-scoped)
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: storage-admin
rules:
  - apiGroups: [""]
    resources: ["persistentvolumes"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: [""]
    resources: ["persistentvolumeclaims"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["storage.k8s.io"]
    resources: ["storageclasses"]
    verbs: ["get", "list", "watch"]
```

### Kyverno Policy: Blocking subDir Path Traversal

Even with the patched drivers, a defence-in-depth admission control layer prevents malicious PV specs from reaching the driver at all. The following Kyverno ClusterPolicy rejects any PersistentVolume using the NFS or SMB CSI drivers where the `subDir` volume attribute contains `..` or begins with `/`:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: block-csi-subdir-traversal
  annotations:
    policies.kyverno.io/title: Block CSI subDir Path Traversal
    policies.kyverno.io/category: Storage Security
    policies.kyverno.io/description: >-
      Rejects PersistentVolumes using NFS or SMB CSI drivers where the
      subDir volume attribute contains path traversal sequences.
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: validate-nfs-subdir
      match:
        any:
          - resources:
              kinds: ["PersistentVolume"]
      preconditions:
        all:
          - key: "{{ request.object.spec.csi.driver }}"
            operator: AnyIn
            value:
              - "nfs.csi.k8s.io"
              - "smb.csi.k8s.io"
          - key: "{{ request.object.spec.csi.volumeAttributes.subDir | length(@) }}"
            operator: GreaterThan
            value: "0"
      validate:
        message: >-
          PersistentVolume subDir must not contain '..' or begin with '/'.
          Found: {{ request.object.spec.csi.volumeAttributes.subDir }}
        deny:
          conditions:
            any:
              - key: "{{ request.object.spec.csi.volumeAttributes.subDir }}"
                operator: Contains
                value: ".."
              - key: "{{ request.object.spec.csi.volumeAttributes.subDir | starts_with(@, '/') }}"
                operator: Equals
                value: true
```

As an alternative using Kubernetes ValidatingAdmissionPolicy (GA in 1.30+), the equivalent CEL expression is:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: block-csi-subdir-traversal
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["persistentvolumes"]
  validations:
    - expression: >-
        !(has(object.spec.csi) &&
          (object.spec.csi.driver == "nfs.csi.k8s.io" ||
           object.spec.csi.driver == "smb.csi.k8s.io") &&
          has(object.spec.csi.volumeAttributes) &&
          has(object.spec.csi.volumeAttributes.subDir) &&
          (object.spec.csi.volumeAttributes.subDir.contains("..") ||
           object.spec.csi.volumeAttributes.subDir.startsWith("/")))
      message: "CSI subDir must not contain '..' or begin with '/'"
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: block-csi-subdir-traversal-binding
spec:
  policyName: block-csi-subdir-traversal
  validationActions: [Deny]
```

### StorageClass Parameter Allowlisting

The most effective approach is to design StorageClasses so that the `subDir` value is never directly user-controlled. The NFS CSI driver supports a template pattern where `subDir` is computed from PVC metadata:

```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: nfs-platform-standard
provisioner: nfs.csi.k8s.io
parameters:
  server: "nfs.internal.example.com"
  share: "/exports/kubernetes"
  # subDir is computed from PVC metadata — users cannot override it
  subDir: "${pvc.metadata.namespace}/${pvc.metadata.name}"
  onDeletePolicy: "delete"
reclaimPolicy: Delete
volumeBindingMode: Immediate
allowVolumeExpansion: true
```

With this pattern, the `subDir` is always `<namespace>/<pvc-name>` — a safe, predictable value that the driver evaluates at provisioning time. Users never supply the `subDir` value. Enforce that developers can only request PVCs against pre-approved StorageClasses using a Kyverno policy:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-approved-storageclass
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: check-storageclass
      match:
        any:
          - resources:
              kinds: ["PersistentVolumeClaim"]
              namespaces:
                # Apply to all non-system namespaces
                - "!kube-system"
                - "!kube-public"
                - "!kube-node-lease"
      validate:
        message: >-
          StorageClass must be one of the platform-approved classes:
          nfs-platform-standard, smb-platform-standard, local-path.
        pattern:
          spec:
            storageClassName: "nfs-platform-standard | smb-platform-standard | local-path"
```

### CSI Driver Pod Security

Review the security context of the CSI node plugin DaemonSet. Some operations genuinely require elevated privileges; document what is required and why:

```bash
# Inspect the security context of the NFS node plugin
kubectl get daemonset -n kube-system csi-nfs-node -o json | \
  jq '.spec.template.spec.containers[] | {name: .name, securityContext: .securityContext}'
```

Apply a NetworkPolicy restricting the CSI DaemonSet's egress to only the NFS/SMB server IP ranges:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: csi-nfs-node-egress
  namespace: kube-system
spec:
  podSelector:
    matchLabels:
      app: csi-nfs-node
  policyTypes:
    - Egress
  egress:
    # Allow NFS traffic only to the authorised server range
    - to:
        - ipBlock:
            cidr: "10.100.50.0/24"   # NFS server subnet — adjust as needed
      ports:
        - protocol: TCP
          port: 2049
        - protocol: UDP
          port: 2049
    # Allow DNS
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
```

### Monitoring CSI Driver Security Fixes

The commit-before-advisory pattern observed with CVE-2026-3864 means that watching commit history is more timely than waiting for official announcements. Use the GitHub API to scan recent commits to both driver repositories for security-relevant changes:

```bash
# Scan csi-driver-nfs commits for security-relevant messages
gh api "repos/kubernetes-csi/csi-driver-nfs/commits?per_page=50" \
  --jq '.[] | select(.commit.message | test("path|subdir|traversal|security|valid|sanitiz"; "i")) |
    {sha: .sha[0:8], message: .commit.message, date: .commit.author.date}'

# Same for csi-driver-smb
gh api "repos/kubernetes-csi/csi-driver-smb/commits?per_page=50" \
  --jq '.[] | select(.commit.message | test("path|subdir|traversal|security|valid|sanitiz"; "i")) |
    {sha: .sha[0:8], message: .commit.message, date: .commit.author.date}'
```

Configure Renovate to track CSI driver Helm chart versions and open PRs automatically when new versions are available. In your `renovate.json`:

```json
{
  "helmValues": [
    {
      "fileMatch": ["helm/values.*\\.yaml$"]
    }
  ],
  "packageRules": [
    {
      "matchPackageNames": ["csi-driver-nfs", "csi-driver-smb"],
      "matchUpdateTypes": ["patch", "minor"],
      "automerge": false,
      "labels": ["security", "storage"],
      "reviewers": ["platform-team"]
    }
  ]
}
```

Subscribe to these sources for authoritative notifications:
- `https://discuss.kubernetes.io/c/announcements/security-advisories`
- `https://github.com/kubernetes-csi/csi-driver-nfs/security/advisories`
- `https://github.com/kubernetes-csi/csi-driver-smb/security/advisories`

## Expected Behaviour

| Signal | Unpatched CSI Driver | Patched + Admission Controls |
|--------|---------------------|------------------------------|
| PV spec submitted with `subDir: ../../secret-dir` | Driver accepts the value; mounts or deletes the traversed path on the NFS/SMB server | Kyverno/ValidatingAdmissionPolicy rejects the PV at admission; driver never processes the request |
| PV with malicious `subDir` deleted with `reclaimPolicy: Delete` | Driver's cleanup code follows the traversal path and permanently deletes the unintended directory on the NFS server | PV was blocked at creation; deletion event never reaches the driver for a malicious path |
| Developer in `dev` namespace attempts to create a PersistentVolume directly | PV is created if the developer's ClusterRole permits it; traversal attack becomes possible | RBAC denies PV creation; only StorageClass-driven dynamic provisioning is available to the developer |
| Attacker attempts csi-driver-smb traversal after CVE-2026-3864 (NFS) advisory is published but before SMB patch | SMB driver accepts malicious `subDir`; traversal attack succeeds against SMB-backed PVs | Kyverno policy blocking `..` in `subDir` covers both drivers independently of the patch status; attack is blocked |
| Platform team audits PV creation rights | `kubectl get clusterrolebinding` reveals developer service accounts with PV create rights | RBAC audit shows only `storage-admin` ClusterRole bound to platform team members; no developer subjects found |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| RBAC restriction on PV creation | Eliminates direct PV creation as an attack vector; developers cannot craft arbitrary PV parameters | Developers cannot self-service storage outside of StorageClass templates; support burden on platform team increases | Invest in well-designed StorageClass templates that cover the common cases; provide a self-service PVC workflow via GitOps |
| StorageClass parameter locking (computed `subDir`) | Users never control the `subDir` value; traversal is structurally impossible for dynamically provisioned PVs | Reduces flexibility for teams that need custom sub-directory layouts on a shared NFS share | Offer multiple StorageClasses with different `subDir` templates (per-namespace, per-team, per-application) as a controlled menu |
| Kyverno `subDir` validation policy | Defence-in-depth against traversal even on patched drivers; catches misconfiguration as well as attacks | The `..` check may reject paths that legitimately contain consecutive dots in directory names (rare but possible in some naming conventions) | Use the most specific check possible — block `/../` and leading `/` rather than any occurrence of `..`; add exemptions for verified safe patterns |
| CSI driver DaemonSet upgrade | Applies the patch that fixes CVE-2026-3864 and CVE-2026-3865 at the driver level | Rolling DaemonSet update restarts the node plugin on each node sequentially; pods with mounted NFS/SMB PVs may experience brief IO interruption during node plugin restart | Schedule upgrades during maintenance windows; use pod disruption budgets on critical workloads; test in a non-production cluster first |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Kyverno policy rejects a valid `subDir` that contains a legitimate double-dot in a directory name (e.g. a version string `v1..2`) | PVC-backed workload fails to start; PV creation is denied with a Kyverno policy error message in events | `kubectl describe pv <name>` shows admission webhook rejection; check Kyverno policy logs with `kubectl logs -n kyverno -l app=kyverno` | Refine the Kyverno policy rule to use a more targeted regex — block `/../` sequences rather than any `..` occurrence; add a policy exception for the specific path pattern after security review |
| CSI driver upgrade breaks existing PV mounts (node plugin version mismatch with controller plugin) | Pods on upgraded nodes fail to mount volumes; `kubectl describe pod` shows `MountVolume.SetUp failed` errors | Monitor `kubectl get events --field-selector reason=FailedMount -A` during the rolling update; check driver logs with `kubectl logs -n kube-system -l app=csi-nfs-node` | Roll back the Helm release: `helm rollback csi-driver-nfs -n kube-system`; ensure the controller and node plugin versions match before re-upgrading |
| RBAC tightening removes PV creation rights from the storage admin during an emergency | Storage admin cannot create a replacement PV for a failed volume; workload remains down | Admin receives a 403 Forbidden error on `kubectl apply -f pv.yaml`; check with `kubectl auth can-i create persistentvolumes --as=<storage-admin-user>` | Bind the `storage-admin` ClusterRole to the storage admin user or service account immediately; review how the binding was inadvertently removed and add it to a GitOps-managed manifest to prevent recurrence |
| csi-driver-smb is not patched after the NFS CVE advisory (parallel vulnerability missed) | SMB-backed PVs remain vulnerable to `subDir` traversal; if Kyverno admission policy is not deployed, attacks can succeed silently | Run `kubectl get daemonset -n kube-system csi-smb-node -o jsonpath='{.spec.template.spec.containers[0].image}'` and compare against patched version; check GitHub advisory page for csi-driver-smb | Apply the csi-driver-smb patch immediately; ensure Kyverno policy covering both `nfs.csi.k8s.io` and `smb.csi.k8s.io` is active as an interim control; audit existing PVs for malicious `subDir` values with `kubectl get pv -o json | jq '.items[] | select(.spec.csi.driver == "smb.csi.k8s.io") | {name: .metadata.name, subDir: .spec.csi.volumeAttributes.subDir}'` |

## Related Articles

- [CSI Driver Security: Volume-Mount Hardening, Privileged Drivers, and Inline Ephemeral Volumes](/articles/kubernetes/csi-driver-security/)
- [Pod Security Context Hardening](/articles/kubernetes/pod-security-context/)
- [RBAC Design Patterns for Multi-Tenant Kubernetes](/articles/kubernetes/rbac-design-patterns/)
- [Velero Backup Security](/articles/kubernetes/velero-backup-security/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
