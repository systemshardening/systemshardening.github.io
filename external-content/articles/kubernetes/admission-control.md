---
title: "Kubernetes Admission Control: From PodSecurity Standards to Custom OPA/Kyverno Policies"
description: "Without admission control, any user with deployment permissions can run privileged containers, mount the host filesystem, use the host network, run..."
slug: "kubernetes-admission-control"
date: 2026-03-10
lastmod: 2026-03-10
category: "kubernetes"
tags: ["kubernetes", "admission-control", "kyverno", "opa", "gatekeeper", "pod-security"]
personas: ["platform-engineer", "security-engineer"]
article_number: 20
difficulty: "intermediate"
estimated_reading_time: 22
provider_bridges:
  - name: "Styra"
    id: 52
    category: "policy"
  - name: "Nirmata"
    id: 53
    category: "policy"
  - name: "Snyk"
    id: 48
    category: "container-security"
premium_pack: "opa-kyverno-policy-library"
published: true
layout: article.njk
permalink: "/articles/kubernetes/kubernetes-admission-control/index.html"
---

# [Kubernetes](https://kubernetes.io) Admission Control: From PodSecurity Standards to Custom [OPA](https://www.openpolicyagent.org)/[Kyverno](https://kyverno.io) Policies

## Problem

Without admission control, any user with deployment permissions can run privileged containers, mount the host filesystem, use the host network, run as root, and bypass every security boundary Kubernetes provides. Pod Security Standards (built-in since v1.25) provide a baseline, but production enforcement needs custom policies that go beyond what PSS covers: blocking the `latest` tag, requiring resource limits, enforcing specific image registries, mandating team labels, and verifying image signatures.

The landscape is fragmented: Pod Security Standards, OPA [Gatekeeper](https://open-policy-agent.github.io/gatekeeper/), and Kyverno each solve the problem differently. Teams waste time evaluating tools instead of writing policies.

**Target systems:** Kubernetes 1.29+. Covers Pod Security Standards (built-in), Kyverno 1.12+, and OPA Gatekeeper 3.16+.

## Threat Model

- **Adversary:** Malicious or negligent developer deploying insecure workloads (privileged container, host path mount, running as root), or supply chain attacker injecting a malicious container image from an unauthorized registry.
- **Blast radius:** A single privileged container can compromise the entire node and all pods on it. A host path mount can read any file on the node, including kubelet credentials and other pods' secrets.

## Configuration

### Pod Security Standards (Built-In Baseline)

PSS is built into Kubernetes, no installation needed. Three profiles: `privileged` (unrestricted), `baseline` (prevents known privilege escalations), `restricted` (best practice for hardened workloads).

```bash
# Enforce 'restricted' on all application namespaces:
kubectl label namespace production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted

# Use 'baseline' for kube-system (some system components need elevated privileges):
kubectl label namespace kube-system \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted
```

**What PSS `restricted` blocks:**
- Privileged containers
- Host namespaces (hostNetwork, hostPID, hostIPC)
- Host path mounts
- Running as root
- Privilege escalation
- Non-default seccomp profiles (must use RuntimeDefault or Localhost)
- Capabilities beyond a small allowlist

**What PSS does NOT cover** (need Kyverno or Gatekeeper):
- Image registry allowlisting
- `latest` tag blocking
- Resource limit requirements
- Label requirements
- Image signature verification
- Custom organisation-specific policies

### Choosing Kyverno vs OPA Gatekeeper

| Feature | Kyverno | OPA Gatekeeper |
|---------|---------|---------------|
| Policy language | YAML (familiar to K8s users) | [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) (dedicated policy language, learning curve) |
| Generate resources | Yes (can create NetworkPolicies, ConfigMaps from policies) | No |
| Mutate resources | Yes (auto-add labels, defaults) | No (admission only) |
| Resource overhead | ~200MB per replica (3 replicas recommended) | ~150MB per replica (3 replicas recommended) |
| Multi-cluster distribution | [Nirmata](https://nirmata.com) Enterprise | [Styra](https://www.styra.com) DAS |
| Dry-run/audit mode | `audit` mode (log violations without blocking) | `dryrun` enforcement action |
| Image verification | Built-in `verifyImages` with [cosign](https://docs.sigstore.dev/cosign/) | Requires external data provider |
| Community | Growing rapidly; CNCF project | Mature; CNCF graduated |

**Recommendation:** Kyverno for teams that want YAML policies and need generate/mutate capabilities. Gatekeeper for teams with existing Rego expertise or complex cross-resource policies. Both are production-ready.

### Kyverno: Essential Policies

Install Kyverno:

```bash
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update

helm install kyverno kyverno/kyverno \
  --namespace kyverno --create-namespace \
  --set replicaCount=3 \
  --set resources.requests.memory=256Mi \
  --set resources.limits.memory=512Mi
```

**Block `latest` tag:**

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-latest-tag
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: validate-image-tag
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: "Using the 'latest' tag is not allowed. Specify a version tag."
        pattern:
          spec:
            containers:
              - image: "!*:latest & *:*"
            =(initContainers):
              - image: "!*:latest & *:*"
```

**Require resource limits:**

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-resource-limits
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: validate-resources
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: "CPU and memory limits are required for all containers."
        pattern:
          spec:
            containers:
              - resources:
                  limits:
                    memory: "?*"
                    cpu: "?*"
```

**Restrict image registries:**

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-image-registries
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: validate-registries
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: >-
          Images must be from approved registries:
          registry.example.com, ghcr.io/your-org, docker.io/library.
        pattern:
          spec:
            containers:
              - image: "registry.example.com/* | ghcr.io/your-org/* | docker.io/library/*"
            =(initContainers):
              - image: "registry.example.com/* | ghcr.io/your-org/* | docker.io/library/*"
```

**Require team labels:**

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-labels
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: require-team-label
      match:
        any:
          - resources:
              kinds:
                - Deployment
                - StatefulSet
                - DaemonSet
      validate:
        message: "The label 'team' is required on all workloads."
        pattern:
          metadata:
            labels:
              team: "?*"
```

**Verify image signatures (cosign):**

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signatures
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: verify-cosign-signature
      match:
        any:
          - resources:
              kinds:
                - Pod
      verifyImages:
        - imageReferences:
            - "registry.example.com/*"
          attestors:
            - count: 1
              entries:
                - keyless:
                    issuer: "https://token.actions.githubusercontent.com"
                    subject: "https://github.com/your-org/*"
                    rekor:
                      url: "https://rekor.sigstore.dev"
```

### Safe Rollout Strategy

Never switch from `audit` to `enforce` without a review period:

```bash
# Step 1: Deploy policies in audit mode (log violations, don't block)
# Set validationFailureAction: Audit in all policies

# Step 2: Monitor violations for 1-2 weeks
kubectl get policyreport -A
kubectl get clusterpolicyreport

# Step 3: Review and fix all violating workloads
# Fix manifests to comply with policies

# Step 4: Switch to enforce mode
# Change validationFailureAction: Enforce in each policy

# Step 5: Monitor for blocked deployments
kubectl get events --field-selector reason=PolicyViolation -A
```

### Handling Exceptions

For emergency deployments or legitimate exceptions:

```yaml
# Exception for a specific namespace (e.g., monitoring needs host network)
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-image-registries
spec:
  validationFailureAction: Enforce
  rules:
    - name: validate-registries
      match:
        any:
          - resources:
              kinds:
                - Pod
      exclude:
        any:
          - resources:
              namespaces:
                - monitoring  # Prometheus needs some non-standard images
      validate:
        message: "Images must be from approved registries."
        pattern:
          spec:
            containers:
              - image: "registry.example.com/* | ghcr.io/your-org/*"
```

## Expected Behaviour

- `kubectl run test --image=ubuntu:latest` returns admission error (latest tag blocked)
- Deployments without resource limits are rejected
- Images from non-allowlisted registries are blocked
- Unsigned images (when signature verification is enabled) are blocked
- Violations logged in PolicyReport resources during audit mode
- All existing workloads pass validation after remediation
- `kubectl get policyreport -A` shows zero violations after full rollout

## Trade-offs

| Tool/Control | Impact | Risk | Mitigation |
|-------------|--------|------|------------|
| PSS `restricted` | Blocks privileged containers, host mounts, running as root | Many [Helm](https://helm.sh) charts need modification to comply | Start with `warn` mode. Fix charts before `enforce`. |
| Kyverno (3 replicas) | ~600MB total memory; adds 10-50ms to admission latency | Webhook unavailability blocks all pod creation if `failurePolicy=Fail` | Set `failurePolicy: Ignore` for non-critical policies. Use 3 replicas for HA. |
| `latest` tag blocking | Forces explicit versioning | Developers must update tags for every deployment | Integrate automated image tagging in CI pipeline. |
| Registry allowlisting | Blocks public images not in the allowlist | Breaks charts that use images from other registries (bitnami, quay.io) | Add legitimate registries to the allowlist. Review quarterly. |
| Image signature verification | Adds 100-500ms to admission (signature verification) | Signing infrastructure outage blocks all deployments | Break-glass: Kyverno policy exception for emergency namespace. Time-limited, auto-expiring. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Kyverno webhook down | All pod creation hangs or fails (if failurePolicy=Fail) | Pod creation timeout; Kyverno pod not running | Restart Kyverno pods. If unrecoverable: `kubectl delete validatingwebhookconfigurations kyverno-resource-validating-webhook-cfg` (disables enforcement. emergency only). |
| Policy blocks system component | kube-system pod fails to reschedule after node drain | Control plane components show scheduling errors | Exclude kube-system from all custom policies. PSS should be `baseline` (not `restricted`) for kube-system. |
| Audit mode shows 500+ violations | Too many violations to fix before switching to enforce | PolicyReport shows violation count; prioritisation needed | Fix violations by severity: privileged containers first, then registry compliance, then labels. |
| Cosign verification fails for valid image | Signed image rejected due to expired signature or unreachable Rekor | Admission error mentions signature verification failure | Check Rekor availability. Verify the image signature manually with `cosign verify`. If Rekor is down: temporarily switch policy to audit mode. |

## When to Consider a Managed Alternative

**Transition point:** Policy libraries grow past 50 rules within months. Testing policies against all workloads before enforcement requires a staging cluster. Multi-cluster policy consistency requires centralized distribution that Kyverno/Gatekeeper OSS do not provide.

- **[Styra](https://www.styra.com) DAS:** Enterprise OPA management with policy bundles, decision logging, impact analysis, and multi-cluster distribution.
- **[Nirmata](https://nirmata.com):** Kyverno Enterprise with policy lifecycle management, multi-cluster policy distribution, compliance reporting, and policy-as-code CI integration.
- **[Snyk](https://snyk.io) IaC:** Scans Kubernetes manifests in CI for policy violations before deployment, complementing runtime admission control.

**Premium content pack:** OPA/Kyverno policy library. 50+ tested policies covering: image security (registry allowlist, tag validation, signature verification), workload security (resource limits, security context, labels), network security (require network policies per namespace), and compliance (CIS Kubernetes Benchmark controls as admission policies).


## Related Articles

- [Kubernetes Image Policy Enforcement: Cosign, Notation, and Admission Webhooks](/articles/kubernetes/image-policy-enforcement/)
- [Pod Security Context Deep Dive: runAsNonRoot, readOnlyRootFilesystem, and Capabilities](/articles/kubernetes/pod-security-context/)
- [Kubernetes Network Policies That Actually Work: From Default Deny to Microsegmentation](/articles/kubernetes/kubernetes-network-policies/)
- [Seccomp Profiles for Production Workloads: Writing, Testing, and Deploying Custom Profiles](/articles/kubernetes/seccomp-profiles/)
- [Kubernetes RBAC Design Patterns: Least Privilege Without Paralysing Developers](/articles/kubernetes/rbac-design-patterns/)
