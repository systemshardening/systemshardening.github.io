---
title: "OCI Image Volume Security in Kubernetes"
description: "Secure OCI image volumes (KEP-4639) in Kubernetes 1.31+ by hardening image pull credentials, mount path validation, and admission controls—and tracking silent fixes in evolving implementations."
slug: oci-image-volume-security
date: 2026-05-02
lastmod: 2026-05-02
category: kubernetes
tags: ["oci", "image-volumes", "kep-4639", "supply-chain", "admission-control", "kubernetes"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 344
difficulty: advanced
estimated_reading_time: 15
published: true
layout: article.njk
permalink: "/articles/kubernetes/oci-image-volume-security/index.html"
---

# OCI Image Volume Security in Kubernetes

## Problem

OCI image volumes, introduced under [KEP-4639](https://github.com/kubernetes/enhancements/issues/4639), allow a Kubernetes pod to mount an OCI container image directly as a read-only volume without running that image as a container. The image's filesystem is extracted and mounted at the path you specify in `volumeMounts`. The feature reached alpha in Kubernetes 1.31 and graduated to beta in 1.32. The driving use cases are sensible: sharing large ML model weights between an init container and a serving container without embedding them in both images, distributing static web assets, or injecting tool binaries (like a custom `kubectl` plugin) into application containers from a separate image. The alternative — duplicating hundreds of megabytes of model weights in every container image — wastes bandwidth, registry storage, and node disk.

The security surface, however, expands in several non-obvious directions the moment the feature is enabled. The first dimension is image pull credentials. When a pod spec references a private registry image in a `volumes[].image.reference` field, the kubelet must pull that image before mounting it. Unlike container images in `spec.containers[].image`, which respect `spec.imagePullSecrets` at the pod level, early implementations of OCI image volumes resolved credentials through the node's credential provider chain — potentially using node-level registry credentials that are broader in scope than what the pod should be allowed to use. A pod running in a namespace with no access to a private registry could, in some versions, trigger a successful pull of an image from that registry via the image volume mechanism.

The second dimension is mount path injection. OCI image volumes mount read-only at the path specified in `volumeMounts.mountPath`. If that path is derived from user input — a Helm value, a CRD field, or a ConfigMap that a tenant controls — an attacker can point the mount at `/etc/`, `/usr/local/bin/`, or any other sensitive path in the container's filesystem. Because the image volume is mounted over the existing directory, files from the OCI image silently shadow or replace the original content. This is a write-equivalent operation against a "read-only" volume. An attacker who controls the image in the registry and the mount path controls what binaries or configs the container sees.

The third dimension is admission policy coverage. The `ImagePolicyWebhook` admission plugin was designed to intercept image references in pod specs and enforce allow/deny policy on them. In the initial 1.31 implementation, image volume references were not consistently passed to the webhook — a gap that allows an image that would be blocked as a container image to be mounted as a volume without triggering the policy. This is not a hypothetical: the Kubernetes sig-storage team merged a fix addressing webhook coverage for image volumes in a subsequent release, but the PR carried no CVE assignment and was described in terms of feature completeness rather than security.

This brings us to the most operationally important point: KEP-4639 is an actively evolving feature, and the Kubernetes sig-storage and sig-node teams have merged a series of fixes between 1.31 and 1.33 that are security-relevant but not labeled as security issues. A commit titled "fix image volume pull not respecting node image pull credentials correctly" changed credential lookup precedence in a way that directly affects which registry a kubelet is willing to authenticate against for an image volume pull. That is a security boundary change. It was filed as a feature fix. Another PR corrected the `ImagePolicyWebhook` integration without receiving a CVE or appearing in the security advisory feed. If you upgrade from 1.31.x to 1.32.y without reading the full changelog for image volume entries, you may not realize the credential behavior changed.

To track these silent fixes: bookmark `https://github.com/kubernetes/kubernetes/pulls?q=image+volume` and the KEP-4639 issue thread. Subscribe to `kubernetes-security-announce@googlegroups.com`. Before any minor version upgrade (1.31 → 1.32, 1.32 → 1.33), `grep -i "image volume"` the Kubernetes changelog and audit any commits that touch `pkg/kubelet/images` or `plugin/pkg/admission/imagepolicy`. Watch the `area/image-volumes` label on the Kubernetes GitHub. The changelog often buries these in a "Bug Fixes" subsection with no security flag.

The feature gate implication compounds this. Because OCI image volumes are behind the `ImageVolume` feature gate, enabling them in production means running code paths with less production mileage than stable features. Alpha and beta features in Kubernetes accumulate field experience as adoption widens, which means the period immediately after graduation — when cluster operators start enabling the feature in anger — is when previously undiscovered edge cases surface as bugs or behavioral changes. Operators who enable `ImageVolume=true` speculatively, without a concrete workload requirement, are accepting unknown risk in exchange for no benefit.

Target systems: Kubernetes 1.31+ (alpha), 1.32+ (beta), containerd 1.7+.

## Threat Model

1. **Mount path injection into a shared pod.** A developer (or compromised CI pipeline) creates a pod spec that mounts an attacker-controlled OCI image at `/usr/local/bin/` or `/etc/cron.d/` inside a sidecar container. The image volume is read-only, but it shadows legitimate binaries. When the main container calls `curl` or `bash`, it executes the version from the mounted image. Because the malicious image reference is in `volumes[].image.reference` rather than `containers[].image`, some admission webhooks that only inspect container images miss it entirely.

2. **Patch-gap credential exposure.** Kubernetes 1.32.0 ships with a bug in image volume credential handling: a pod in namespace `tenant-a` can trigger a pull of a private image from `registry.company.internal/team-b/model-weights` using node credentials, bypassing the intended per-pod credential scope. The fix is committed to the public `kubernetes/kubernetes` repository three days later, and the patch release ships three weeks after that. During those three weeks, any operator watching the public PR can see the exact behavior and craft a pod spec that exploits it before the patch is applied. This is the definition of an n-day vulnerability with no CVE to trigger automated scanner alerts.

3. **TOCTOU image substitution.** Admission control checks the image reference string in the pod spec at admission time. The actual image pull for a volume mount happens when the kubelet schedules the pod to a node. An attacker who controls the registry — or who can execute a timing attack against a registry without immutable tags — substitutes a malicious image in the interval between admission and pull. This is a supply chain TOCTOU. Using digest-pinned references (`registry.internal/myimage@sha256:abc123…`) eliminates this window; using mutable tags does not.

4. **Privilege escalation via shared privileged image.** A privileged image (an image that was built by the platform team and contains sensitive configuration, internal CA bundles, or administrative binaries) is accessible from the registry. An unprivileged pod uses an image volume mount to access the filesystem of that privileged image at a path the platform team did not expect to be externally readable. If the OCI image contains a file at `/config/admin-token` that was not world-readable inside a running container (because the container process dropped privileges), it is still readable as a mounted volume by whatever UID the consuming container runs as.

The blast radius for any of these scenarios is bounded by your pod admission controls and registry access policies. Without explicit admission rules for `volumes[].image`, the blast radius is the entire cluster: any pod scheduled anywhere can reference any image in any registry the node's credential chain can reach. With registry allowlists and mount path restrictions in place, an attacker needs to compromise a trusted registry or bypass the admission controller itself to proceed. Defense in depth still applies: admission control limits the blast radius; immutable image digests prevent TOCTOU; monitoring detects anomalous image volume pulls at runtime.

## Configuration / Implementation

### Enabling and Scoping the Feature Gate

The `ImageVolume` feature gate must be enabled on both the API server and the kubelet. It is enabled by default in beta (1.32+) but not in alpha (1.31).

```yaml
# kube-apiserver configuration (e.g., kubeadm ClusterConfiguration)
apiServer:
  extraArgs:
    feature-gates: "ImageVolume=true"

# kubelet configuration (KubeletConfiguration)
featureGates:
  ImageVolume: true
```

For clusters where no workload has a concrete requirement for OCI image volumes, leave the feature gate disabled. The decision matrix:

| Condition | Recommendation |
|---|---|
| Cluster runs ML workloads sharing large model weights | Enable; apply strict admission controls |
| Multi-tenant cluster with untrusted workloads | Disable; revisit when feature is GA |
| Single-tenant cluster, all workloads internal | Enable only with registry allowlist policy |
| No identified use case | Disable |

To audit whether the gate is active: `kubectl get --raw /healthz/ready` will not surface this; instead check node feature flags via `kubectl get nodes -o json | jq '.items[].metadata.annotations'` or inspect the kubelet config directly on a node.

### Admission Control for Image Volumes

#### Kyverno ClusterPolicy — Registry Allowlist

This policy denies any pod that specifies an image volume referencing a registry outside the allowed prefix list.

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-image-volume-registry
  annotations:
    policies.kyverno.io/title: Restrict OCI Image Volume Registry
    policies.kyverno.io/description: >
      Deny image volumes that reference images outside the approved
      internal registry. Prevents unauthorized registry access via
      the image volume pull credential path.
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: deny-unauthorized-image-volume-registry
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: >
          OCI image volumes must reference images from registry.internal/ only.
          Got: {{ request.object.spec.volumes[].image.reference }}.
        foreach:
          - list: "request.object.spec.volumes[]"
            preconditions:
              any:
                - key: "{{ element.image }}"
                  operator: NotEquals
                  value: null
            deny:
              conditions:
                any:
                  - key: "{{ element.image.reference }}"
                    operator: AnyNotIn
                    value:
                      - "registry.internal/*"
```

#### ValidatingAdmissionPolicy (CEL) — Registry Allowlist

For clusters running Kubernetes 1.30+ with the `ValidatingAdmissionPolicy` feature available, the equivalent CEL expression avoids the Kyverno dependency:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: restrict-image-volume-registry
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
        !object.spec.volumes.exists(v,
          v.?image.orValue(null) != null &&
          !v.image.reference.startsWith("registry.internal/")
        )
      message: >
        OCI image volumes must reference images from registry.internal/ only.
```

### Mount Path Validation

Deny image-type volumes that are mounted at sensitive filesystem paths.

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-image-volume-mount-paths
  annotations:
    policies.kyverno.io/title: Restrict OCI Image Volume Mount Paths
    policies.kyverno.io/description: >
      Deny volumeMounts for OCI image volumes targeting sensitive
      paths. Prevents shadowing of system binaries or configuration.
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: deny-sensitive-image-volume-mountpath
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: >
          OCI image volumes may not be mounted at /etc, /usr, /bin,
          /sbin, or /lib. Use a path under /mnt or /opt instead.
        deny:
          conditions:
            any:
              - key: "{{ request.object.spec.containers[].volumeMounts[] | [?(@.mountPath starts_with '/etc') || (@.mountPath starts_with '/usr') || (@.mountPath starts_with '/bin') || (@.mountPath starts_with '/sbin') || (@.mountPath starts_with '/lib')] | length(@) }}"
                operator: GreaterThan
                value: "0"
```

The equivalent CEL expression for VAP:

```yaml
  validations:
    - expression: >
        !object.spec.containers.exists(c,
          c.volumeMounts.exists(vm,
            vm.mountPath.startsWith("/etc") ||
            vm.mountPath.startsWith("/usr") ||
            vm.mountPath.startsWith("/bin") ||
            vm.mountPath.startsWith("/sbin") ||
            vm.mountPath.startsWith("/lib")
          )
        )
      message: "Image volume mount paths must not target system directories."
```

Note: this policy applies to all `volumeMounts`, not only those backed by image volumes. Correlating a `volumeMount` to its volume type requires joining across `spec.volumes` and `spec.containers[].volumeMounts` by volume name. The full correlation logic in CEL:

```yaml
  validations:
    - expression: >
        !object.spec.containers.exists(c,
          c.volumeMounts.exists(vm,
            object.spec.volumes.exists(v,
              v.name == vm.name &&
              v.?image.orValue(null) != null
            ) &&
            (vm.mountPath.startsWith("/etc") ||
             vm.mountPath.startsWith("/usr") ||
             vm.mountPath.startsWith("/bin") ||
             vm.mountPath.startsWith("/sbin") ||
             vm.mountPath.startsWith("/lib"))
          )
        )
      message: "OCI image volumes must not be mounted at system paths."
```

### Image Pull Credential Hardening

The correct behavior — pod `imagePullSecrets` taking precedence over node credentials for image volume pulls — was not consistently implemented in early versions. Verify the behavior on your version before trusting it.

Check which pods are currently using image volumes:

```bash
kubectl get pods --all-namespaces -o json \
  | jq -r '.items[] | select(.spec.volumes != null) |
      .metadata.namespace + "/" + .metadata.name + ": " +
      (.spec.volumes[] | select(.image != null) | .image.reference)'
```

Verify that pods specifying `imagePullSecrets` have those secrets used for image volume pulls by enabling kubelet debug logging briefly and filtering for credential resolution logs:

```bash
# On a node, with kubelet at verbosity 4:
journalctl -u kubelet -f | grep -i "image volume\|imagevolume\|pull.*credential"
```

Review containerd's credential helper configuration. Overly broad credential helpers (e.g., a helper that returns credentials for all registries based on node IAM role) mean any pod can pull from any registry the node has access to, regardless of pod-level `imagePullSecrets`:

```bash
# Inspect containerd config on a node
cat /etc/containerd/config.toml | grep -A5 "credential\|registry"
```

If your containerd config uses a catch-all credential helper (`registry.host = ""`), scope it to specific registry hosts where possible.

### ImagePolicyWebhook Coverage Verification

Do not assume your existing `ImagePolicyWebhook` covers image volumes. Test it explicitly.

1. Create a pod spec that references an image in your webhook's blocklist as a volume (not as a container image).
2. Attempt to create the pod: `kubectl create -f test-blocked-image-volume.yaml`
3. If the pod is admitted, your webhook is not intercepting image volume references.

```yaml
# test-blocked-image-volume.yaml — image should be in your webhook blocklist
apiVersion: v1
kind: Pod
metadata:
  name: webhook-coverage-test
  namespace: default
spec:
  containers:
    - name: main
      image: registry.internal/baseline:latest
      volumeMounts:
        - name: test-vol
          mountPath: /mnt/test
  volumes:
    - name: test-vol
      image:
        reference: registry.external/blocked-image:latest
        pullPolicy: IfNotPresent
  restartPolicy: Never
```

If the pod is admitted despite the blocked reference, update your webhook configuration to include a handler for the `volumes[].image.reference` path. Check the Kubernetes changelog for your version to determine whether `ImagePolicyWebhook` integration for image volumes is documented as fixed.

### Monitoring Upstream for Fixes

Use the GitHub CLI to watch for new PRs and issues touching image volume implementation:

```bash
# List open and recently merged PRs related to image volumes
gh api "repos/kubernetes/kubernetes/pulls?state=all&per_page=50" \
  --jq '.[] | select(.title | test("image.volume|ImageVolume"; "i")) |
    {number: .number, title: .title, state: .state, merged_at: .merged_at}'

# Watch the area/image-volumes label
gh api "repos/kubernetes/kubernetes/issues?labels=area%2Fimage-volumes&state=all" \
  --jq '.[] | {number: .number, title: .title, state: .state}'
```

Set up a GitHub notification watch on `kubernetes/kubernetes` for the `area/image-volumes` label. Before each minor version upgrade, run:

```bash
# Check changelog for image volume entries
curl -s "https://raw.githubusercontent.com/kubernetes/kubernetes/master/CHANGELOG/CHANGELOG-1.33.md" \
  | grep -i -A3 "image volume\|imagevolume"
```

Subscribe to `kubernetes-security-announce@googlegroups.com` for CVE-level announcements, but do not rely on it exclusively — as the credential and webhook fixes demonstrate, security-relevant changes often arrive without a CVE.

## Expected Behaviour

| Signal | Without Controls | With Admission Controls |
|---|---|---|
| Pod mounts image volume at `/etc/cron.d/` | Mount succeeds; image files shadow cron configuration silently | Admission denied with message: "OCI image volumes must not be mounted at system paths" |
| Pod references image from `registry.external/` as a volume | Pull proceeds using node credentials if available; pod scheduled | Admission denied: "OCI image volumes must reference images from registry.internal/ only" |
| Image not in `ImagePolicyWebhook` allowlist used as volume | Admitted and mounted if webhook does not inspect volume image refs | Denied (after webhook coverage fix applied and verified) or admitted (if gap still present — surface via coverage test) |
| Upstream fix changes credential lookup precedence post-upgrade | Pull behavior changes silently; pods may gain or lose access to registries | Changelog review and credential audit surfaced the change before upgrade; imagePullSecrets scope verified in staging |
| Mutable image tag substituted between admission and pull | Malicious image mounted in pod; no alert | Digest-pinned reference in policy; tag-only references denied |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Feature gate (alpha/beta) | Enables legitimate ML weight sharing, tool injection use cases | Running less-tested code paths; behavior may change between patch releases | Enable only for clusters with concrete use cases; maintain staging environment on same version |
| Registry allowlist admission policy | Prevents unauthorized registry access via image volume credential path | Every new internal image registry requires policy update | Manage allowlist in GitOps; auto-PR when new registry is onboarded |
| Mount path validation | Prevents shadowing of system binaries and configuration | Legitimate use cases that want to inject configs under `/etc/` are blocked | Use `/mnt/` or `/opt/` mount paths by convention; document the constraint in platform runbooks |
| ImagePolicyWebhook coverage gap | Webhook provides unified policy point for all image references | Coverage of image volumes depends on implementation version; gap exists in 1.31 | Verify coverage explicitly after every minor upgrade; use Kyverno/VAP as defense-in-depth |
| Digest pinning for image volumes | Eliminates TOCTOU window between admission and pull | Digest must be updated on every image release; automation required | Use image promotion pipelines that output digest-pinned references automatically |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Image pull fails due to missing or incorrect credentials for image volume | Pod stuck in `ContainerCreating`; event: `Failed to pull image ... unauthorized` | `kubectl describe pod <name>`; kubelet logs on scheduled node | Add `imagePullSecrets` referencing correct registry credentials to pod spec; verify credential helper scope in containerd config |
| Admission policy rejects legitimate image volume reference | Pod creation returns `admission webhook denied` or VAP validation failure | Developer error at `kubectl apply` time; CI pipeline failure | Review admission policy allowlist; add registry prefix if valid; audit whether the image should be in the internal registry |
| Feature gate disabled after workloads have been deployed that depend on it | Pods fail to schedule or existing pods restart into `CrashLoopBackOff` if node config changes; new pods fail admission with unknown volume type | `kubectl get events --field-selector reason=FailedScheduling`; pod events showing unrecognised volume type | Re-enable feature gate (coordinated kubelet and API server restart); do not disable the gate without first migrating dependent workloads to initContainer-based sharing |
| Upstream patch changes credential lookup behavior, breaking existing volumes | Image volume pulls begin failing or succeeding where they previously did not after a version upgrade | Regression in staging post-upgrade; `kubectl get events` across namespaces filtered for pull errors | Rollback upgrade if in staging; in production, scope `imagePullSecrets` to explicit pod level and remove reliance on node-level credentials; pin to specific patch version until behavior is understood |
| TOCTOU: malicious image pulled after admission check | Pod runs with unexpected content at the image volume mount path; runtime anomaly detection may surface unexpected binaries | Falco rule on unexpected file execution paths; image digest mismatch between admission time and runtime | Enforce digest-pinned image volume references in admission policy; retrospectively audit all pods using mutable image volume tags |

## Related Articles

- [Image Policy Enforcement in Kubernetes](/articles/kubernetes/image-policy-enforcement/)
- [Pod Security Context Hardening](/articles/kubernetes/pod-security-context/)
- [CSI Driver Security](/articles/kubernetes/csi-driver-security/)
- [Container Registry Security](/articles/cicd/container-registry-security/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
