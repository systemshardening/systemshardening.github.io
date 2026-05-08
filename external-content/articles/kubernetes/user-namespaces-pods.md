---
title: "User Namespaces for Pods: UID Remapping, Container Escape Defense, and the GA Path in Kubernetes 1.30+"
description: "userns: true remaps Pod UIDs into a per-Pod range. A container running as root sees uid 0 inside; the host sees an unprivileged user. Big hardening win, easy to enable."
slug: "user-namespaces-pods"
date: 2026-04-27
lastmod: 2026-04-27
category: "kubernetes"
tags: ["kubernetes", "user-namespaces", "userns", "container-escape", "isolation"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 192
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/kubernetes/user-namespaces-pods/index.html"
---

# User Namespaces for Pods: UID Remapping, Container Escape Defense, and the GA Path in Kubernetes 1.30+

## Problem

Container security has long had an awkward asymmetry. A Pod's container that runs as root (`uid=0`) inside the container is, from the kernel's perspective, also `uid=0` on the host. Linux capabilities, seccomp, and SELinux/AppArmor are the things that keep that root-on-the-host from doing host-level damage — but a kernel exploit, a CVE in the runtime, or a slip in the security context config means the host sees a real `uid=0` process attempting privileged operations.

User namespaces remap UIDs and GIDs between the container and the host. With user namespaces enabled, a container's `uid=0` is the host's `uid=1000000` (or whatever range the runtime assigned). A kernel exploit that confuses runtime-level controls but ends up granting host-level access still ends up as an unprivileged user — which means filesystem access governed by host-side permissions, no `CAP_*` granted, no privileged syscalls.

User namespaces are old (Linux 3.8, 2013), but production Kubernetes adoption has been gated on multiple constraints:

- **Filesystem images.** UIDs in the image have to be shifted by the runtime; older runtimes did this by chmod'ing every file (slow, expensive). The kernel's `idmap` mounts (5.12+) made it free.
- **Volume support.** Persistent volumes have to participate in the UID mapping. CSI drivers needed updates.
- **Runtime support.** containerd 1.7+ and CRI-O 1.25+ added the integration.
- **Kubernetes feature stability.** Alpha in 1.25, beta in 1.28, GA in 1.30 (April 2024).

By 2026, every supported Kubernetes minor version has user namespaces available; the major cloud-managed offerings (GKE 1.30+, EKS 1.30+, AKS 1.30+) support the feature. The hardening win is substantial: most documented container escapes (CVE-2019-5736, CVE-2022-0847 "Dirty Pipe," CVE-2024-21626) require host-uid privilege after the escape to do real damage. With user namespaces, that privilege is absent.

The specific gaps in a 1.30+ cluster without user namespaces:

- Pods running as root container an actual host-uid-0 process.
- Container-escape exploits land as host-uid-0; capability drops apply but kernel-exploit primitives that bypass capabilities still grant root.
- Volume mounts use container-side UIDs verbatim; a malicious image can write files owned by uid 0 onto host-side persistent volumes.
- Cross-pod attacks via shared volumes or hostPath are bounded only by host-side permissions, which assume the kernel is correct.

This article covers enabling user namespaces in Pod specs, the runtime and CSI prerequisites, what protections it adds vs. Pod Security Admission's `restricted` profile, and the operational caveats.

**Target systems:** Kubernetes 1.30+ with `UserNamespacesSupport` feature gate enabled (default-on); containerd 1.7+ or CRI-O 1.25+; Linux kernel 6.3+ for full idmap-mount coverage; CSI drivers that support idmap mounts.

## Threat Model

- **Adversary 1 — Container-escape via runtime CVE:** an attacker exploits a `runc` / containerd / CRI-O CVE that lets a container break out and run code on the host with the container's effective host UID.
- **Adversary 2 — Container-escape via kernel CVE:** a kernel vulnerability in a syscall that the container can invoke (file ops, networking, namespace creation) that bypasses Pod Security Admission and lands as host UID 0.
- **Adversary 3 — Volume-mediated cross-pod attack:** attacker writes carefully-permissioned files to a shared volume; another Pod consuming the volume reads or executes them with elevated trust.
- **Adversary 4 — `hostPath` mount abuse:** a privileged Pod with `hostPath` accidentally writes to host paths with host-uid-0 ownership.
- **Access level:** Adversary 1 has code execution inside a container running as root. Adversary 2 has any code execution that can reach the vulnerable syscall. Adversary 3 has writeable access to a shared volume. Adversary 4 has a Pod spec with `hostPath`.
- **Objective:** Privileged host-level activity — read host secrets, modify host files, install persistence, pivot to other Pods or the kubelet.
- **Blast radius:** Without user namespaces, container-escape often equals host-root. With user namespaces, container-escape lands as a per-Pod unprivileged UID; subsequent host-side exploitation requires *additional* privilege escalation, and ordinary host file permissions limit what the unprivileged ID can read.

## Configuration

### Step 1: Verify the Cluster Supports It

```bash
# Feature gate.
kubectl get nodes -o jsonpath='{.items[0].status.nodeInfo.kubeletVersion}'
# v1.30.x or higher

# Confirm the feature gate is on (default in 1.30+).
kubectl get --raw /metrics | grep kubernetes_feature_enabled.*UserNamespacesSupport

# Container runtime.
ssh worker-1 'crictl version'
# RuntimeName: containerd, Version 1.7.x+

# Kernel.
ssh worker-1 'uname -r'
# 6.3+ for full idmap-mount support; 5.19+ works with older idmap modes.
```

### Step 2: Enable User Namespaces in a Pod

Single field in the Pod spec:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: payments
spec:
  hostUsers: false              # The flag. Setting false enables user namespaces.
  containers:
    - name: app
      image: ghcr.io/myorg/app:1.0
      securityContext:
        runAsNonRoot: false     # Pod can run as uid 0 inside; container-uid 0 is mapped
        runAsUser: 0            # to a host-side per-Pod range like 1000000.
      ports:
        - containerPort: 8080
```

After applying, observe the host-side UID:

```bash
# From the worker node:
ssh worker-1
sudo crictl ps --name app -q | xargs -I{} sudo crictl inspect {} | \
  jq '.info.runtimeSpec.linux.uidMappings'
# [
#   {"containerID": 0, "hostID": 65536, "size": 65536}
# ]

# Or check the actual process:
ps -eo pid,uid,cmd | grep myapp
# 12345  65536  /usr/local/bin/myapp
```

Inside the container, processes still see `uid=0`; on the host they're `uid=65536` or similar. `kubectl exec` works normally.

### Step 3: Enforce Cluster-Wide via Admission Policy

For real protection, require user namespaces by default. With `ValidatingAdmissionPolicy`:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: require-user-namespaces
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
        has(object.spec.hostUsers) && object.spec.hostUsers == false
      message: "Pods must set spec.hostUsers: false (user namespaces required)."
      reason: Forbidden
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: require-user-namespaces-binding
spec:
  policyName: require-user-namespaces
  validationActions: [Deny, Audit]
  matchResources:
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: NotIn
          values: ["kube-system", "kube-public", "kube-node-lease"]
        - key: pod-security.kubernetes.io/enforce
          operator: NotIn
          values: ["privileged"]
```

The system namespaces and explicitly-privileged namespaces are exempt; everything else must opt-in to user namespaces.

### Step 4: Volume Compatibility

User namespaces shift the apparent UID of files in mounts. CSI drivers that support idmap mounts handle this transparently; older drivers may show files owned by `uid_in_namespace + offset`.

Compatible: hostPath (in some configurations), emptyDir, persistentVolumeClaim with idmap-aware CSI drivers (CSI spec v1.10+ added the negotiation), configMap, secret.

For older CSI drivers, you may need to set `fsGroup` and `fsGroupChangePolicy` to remap on attach. Or, for highest compatibility, use a sidecar that fixes ownership on first mount.

### Step 5: Per-Pod UID Range Configuration

The container runtime allocates the per-Pod UID range. containerd's default range is `0:65536:65536` (allocate 65536 UIDs starting at 65536 host-side per pod). Confirm in containerd's config:

```toml
# /etc/containerd/config.toml
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
  IoUid = 0
  IoGid = 0
```

For very high pod-density nodes, plan for sufficient host UID space. A node with 110 pods × 65536 UIDs/pod needs ~7 million host UIDs available — ample within a 32-bit UID space.

### Step 6: Telemetry

Track adoption rate. Most clusters cannot flip `hostUsers: false` everywhere overnight; measure progress:

```yaml
# Prometheus metric expression for percent of Pods using userns.
sum(kube_pod_info * on(pod, namespace) group_left(host_users)
    label_replace(
        kube_pod_spec{...},
        ...
    )) by (namespace)
```

Actual implementation depends on your kube-state-metrics version; the kube-state-metrics project added `hostUsers` exposure in 2.13. Once available:

```promql
sum by (namespace) (
  kube_pod_spec_host_users == 0
)
/
sum by (namespace) (kube_pod_spec_host_users)
```

Alert on namespaces where adoption regresses unexpectedly.

## Expected Behaviour

| Signal | Without `hostUsers: false` | With `hostUsers: false` |
|--------|------------------------------|---------------------------|
| Process ownership on host | Container `uid=0` = host `uid=0` | Container `uid=0` = host `uid=65536` (or per-pod range) |
| Filesystem ownership of container-created files | Owned by host `uid=0` | Owned by mapped host UID |
| Privileged operations from container-root after escape | Succeed (host root) | Fail (host non-root permissions apply) |
| `runc` / containerd CVE exploitation | Lands as host-root | Lands as unprivileged host UID |
| Cross-namespace volume reuse | Possible if both pods are uid 0 | Each pod sees its own UID range; shared filesystem ownership becomes explicit |
| `kubectl exec` UX | Normal | Normal (in-container `uid=0` still works) |
| Performance | Baseline | Negligible (idmap mount avoids per-file chown) |

Verify the protection holds:

```bash
# Inside the container.
id
# uid=0(root) gid=0(root)

# From the host worker node.
ps -ef | grep <container-process-name>
# uid=65536, not uid=0

# Negative test: simulate a CVE-2019-5736 style escape trying to write /etc/shadow on host.
# The container-side write attempt as uid 0 maps to host attempt as uid 65536.
# Host /etc/shadow is owned by uid 0, mode 0640 — write fails with EACCES.
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Container-root → unprivileged host UID | Major mitigation for runtime / kernel CVEs | Some workloads break under UID remapping | Run an adoption pilot per app team; identify and fix incompatible workloads. |
| idmap mounts avoid per-file chown | No startup penalty | Requires kernel 5.19+ for stable behavior | Set worker-node minimum kernel as part of cluster baseline. |
| CSI driver requirements | Strong volume integration | Older drivers may need updates | Newer cloud-managed clusters (GKE/EKS/AKS 1.30+) ship supported drivers; for self-managed CSI, check the driver's release notes. |
| Per-Pod UID space | Strong isolation between Pods | UID-space exhaustion possible on extreme densities | Default containerd allocations easily fit 200+ Pods per node; tune only at unusual densities. |
| Admission-time enforcement | Steady-state security stays even as Pods are created | Onboarding new namespaces requires explicit opt-in | Document the requirement in your platform team's onboarding flow. |
| Network namespace + user namespace combination | Network operations also affected | Some networking utilities behave unexpectedly | Test network plugins in user-namespaced Pods explicitly. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| CSI driver does not support idmap mounts | Pod fails to start with volume permission error | `kubectl describe pod` shows mount-permission errors | Upgrade CSI driver; or fall back to `fsGroup` ownership change on the volume; or accept the workload runs without user namespaces while you upgrade. |
| Application checks for "real" UID via `/proc/self/status` | Application errors when uid in namespace doesn't match expected | Application logs show UID-mismatch errors | Application bug; the in-container UID is uid 0 as expected. The host UID outside the namespace is irrelevant to the container. Patch the application's check. |
| Host-side file permissions break expectations | Files written by Pod end up owned by host `uid=65536` not `uid=0` | Operations team complains about file ownership in shared persistent storage | Either accept the new ownership model and update operations runbooks, or use `fsGroup` to assign a known group ID for shared access. |
| `setcap` inside container affects host | A capability set inside container does NOT affect host | Operator confusion: "I gave the container CAP_NET_ADMIN, why isn't it working?" | Actually, this is the desired behavior. Capabilities apply within the user namespace. Container can do its own privileged actions inside, but cannot affect host. |
| Kernel UID-namespace exploit | Attacker bypasses user-namespace isolation | Host kernel logs show unusual capability claims | Keep kernels patched; user namespaces themselves have had CVEs (CVE-2023-32233, etc.). The mitigation: subscribe to your distro's security advisory feed. |
| `--privileged` containers ignore the policy | Pods that demand privilege escape the protection | Audit logs show pods with `securityContext.privileged: true` | Pair user-namespace requirement with PSA `restricted` enforcement. Truly privileged workloads belong in a dedicated, gated namespace. |

## Related Articles

- [Pod Security Context Hardening](/articles/kubernetes/pod-security-context/)
- [Kubernetes Admission Control: PodSecurity, OPA/Kyverno](/articles/kubernetes/kubernetes-admission-control/)
- [ValidatingAdmissionPolicy with CEL](/articles/kubernetes/validating-admission-policy-cel/)
- [seccomp Profiles for Kubernetes Workloads](/articles/kubernetes/seccomp-profiles/)
- [Falco Runtime Security for Container Anomaly Detection](/articles/kubernetes/falco-runtime-security/)
