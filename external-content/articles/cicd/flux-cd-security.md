---
title: "Flux CD Security: GitRepository Authentication, Kustomization Trust, and RBAC"
description: "Flux continuously reconciles Kubernetes cluster state with Git repositories. Its service accounts need Kubernetes write access; its Git credentials need repository read access. Scoping both correctly, verifying source authenticity, and auditing reconciliation events prevents Flux from becoming a privileged attack vector."
slug: "flux-cd-security"
date: 2026-05-01
lastmod: 2026-05-01
category: "cicd"
tags: ["flux", "gitops", "kubernetes", "rbac", "git-authentication", "supply-chain"]
personas: ["platform-engineer", "security-engineer"]
article_number: 314
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/cicd/flux-cd-security/index.html"
---

# Flux CD Security: GitRepository Authentication, Kustomization Trust, and RBAC

## Problem

Flux CD is a GitOps operator: it watches Git repositories and continuously applies their contents to Kubernetes clusters. This gives Flux two powerful capabilities that together create significant attack surface: read access to Git repositories (which contain deployment manifests, Helm values, and often encrypted secrets) and write access to Kubernetes cluster resources (to apply what it reads from Git).

Common security weaknesses:

- **Flux service accounts with cluster-admin.** Flux needs to create and update Kubernetes resources. Many deployments bind the Flux service account to `cluster-admin`, giving it — and any attacker who compromises the Git repository — complete cluster control.
- **Unverified Git commits.** Flux applies whatever is in the Git repository. Without commit signature verification, a developer with push access (or an attacker who compromises a developer's credential) can push a malicious manifest that Flux immediately applies to production.
- **Git credentials stored insecurely.** Flux uses deploy keys or tokens to authenticate to Git repositories. These are stored as Kubernetes Secrets in the `flux-system` namespace. Anyone with read access to that namespace's secrets can clone all tracked repositories.
- **No Kustomization reconciliation scope.** A Flux `Kustomization` that applies to the root of a cluster can deploy any resource type — including `ClusterRoleBindings` that grant attacker-controlled service accounts cluster-admin.
- **Shared Flux instance across environments.** A single Flux instance reconciles both staging and production clusters. A manifest pushed to the staging branch — which has less scrutiny — is one merge away from being applied to production.
- **No alert on reconciliation failure.** Flux fails to apply a Kustomization; the failure is logged but no alert fires. The cluster diverges from the Git state for days without anyone noticing.

**Target systems:** Flux 2.x (fluxcd.io/v2beta2 API); flux-system namespace; GitRepository, HelmRepository, Kustomization, HelmRelease CRDs; Flux bootstrap on EKS/GKE/AKS; image automation controllers.

## Threat Model

- **Adversary 1 — Malicious commit applied by Flux:** An attacker compromises a developer's GitHub credential with push access to the production manifests repository. They push a commit containing a `ClusterRoleBinding` granting their pod cluster-admin. Flux applies it within the reconciliation interval.
- **Adversary 2 — Git deploy key exfiltration:** An attacker who gains read access to the `flux-system` namespace extracts the Kubernetes Secret containing the Git deploy key. They use the key to clone the manifests repository, discovering the full cluster configuration and any embedded sensitive values.
- **Adversary 3 — Kustomization resource type escalation:** A developer creates a Kustomization that manages their application namespace. The Kustomization has `spec.force: true` (applies all resources regardless of conflicts). The developer adds a `ClusterRoleBinding` to their application directory; Flux applies it, granting cluster-wide privilege.
- **Adversary 4 — HelmRelease values injection:** A Helm chart has values that control resource limits, replica counts, and security contexts. A developer with write access to the values file sets `securityContext.privileged: true`. Flux applies the updated HelmRelease; the chart deploys a privileged container.
- **Adversary 5 — Image automation overwrite:** Flux's image update automation writes updated image tags to the manifests repository. An attacker who compromises the image registry pushes a malicious image tag matching the automation pattern. Flux updates the manifest; the controller applies the malicious image.
- **Access level:** Adversaries 1 and 4 need repository write access. Adversary 2 needs Kubernetes namespace read access. Adversary 3 needs Kustomization management access. Adversary 5 needs registry write access.
- **Objective:** Deploy malicious workloads, extract secrets, escalate cluster privileges via the GitOps path.
- **Blast radius:** Flux with cluster-admin and no commit verification is a privileged GitOps backdoor — a repository push becomes a cluster operation.

## Configuration

### Step 1: Least-Privilege Flux RBAC

Replace the default cluster-admin binding with namespace-scoped roles:

```yaml
# flux-system/rbac.yaml — scoped service accounts per Kustomization.

# Instead of one cluster-admin Flux SA, create per-team SAs.
apiVersion: v1
kind: ServiceAccount
metadata:
  name: payments-flux-sa
  namespace: flux-system

---
# Role for the payments team's Flux Kustomization.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: payments-reconciler
  namespace: payments
rules:
  # Manage deployments, services, configmaps in the payments namespace only.
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: [""]
    resources: ["services", "configmaps"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  # NOT: ClusterRoleBindings, Secrets, other namespaces.

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: payments-reconciler-binding
  namespace: payments
subjects:
  - kind: ServiceAccount
    name: payments-flux-sa
    namespace: flux-system
roleRef:
  kind: Role
  name: payments-reconciler
  apiGroup: rbac.authorization.k8s.io
```

```yaml
# Kustomization using the scoped service account.
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: payments-app
  namespace: flux-system
spec:
  interval: 5m
  path: "./clusters/production/payments"
  prune: true
  sourceRef:
    kind: GitRepository
    name: payments-manifests
  serviceAccountName: payments-flux-sa   # Scoped SA, not flux SA.
  targetNamespace: payments              # Restrict to this namespace.
  # Restrict resource types this Kustomization may manage.
  patches:
    - patch: |-
        - op: add
          path: /spec/allowed
          value:
            apiGroups: ["apps", ""]
            resources: ["deployments", "services", "configmaps"]
```

### Step 2: Commit Signature Verification

Require GPG-signed commits before Flux applies them:

```yaml
# GitRepository with commit signature verification.
apiVersion: source.toolkit.fluxcd.io/v1
kind: GitRepository
metadata:
  name: payments-manifests
  namespace: flux-system
spec:
  interval: 1m
  url: ssh://git@github.com/example/payments-manifests.git

  # Require commits to be signed by one of these GPG keys.
  verify:
    mode: HEAD       # Verify the HEAD commit before applying.
    secretRef:
      name: allowed-gpg-keys   # Secret containing trusted public keys.

  secretRef:
    name: payments-git-credentials   # SSH deploy key.
```

```bash
# Create the GPG key verification secret.
# Export trusted public keys.
gpg --export --armour alice@example.com > alice.pub
gpg --export --armour bob@example.com >> alice.pub   # Multiple keys in one file.

kubectl create secret generic allowed-gpg-keys \
  --namespace flux-system \
  --from-file=allowed-signing-keys.pub=alice.pub

# Any commit not signed by one of these keys will be rejected by Flux.
```

### Step 3: Git Credential Security

```yaml
# Use SSH deploy keys over HTTPS tokens.
# SSH keys are scoped to a specific repository; tokens often have broader access.

# Generate a dedicated deploy key per repository.
ssh-keygen -t ed25519 -f /tmp/flux-payments-deploy -N "" \
  -C "flux-payments-deploy@example.com"

# Add the public key as a read-only deploy key on GitHub.
# Never give Flux write access to the repository.

# Create the Kubernetes Secret.
kubectl create secret generic payments-git-credentials \
  --namespace flux-system \
  --from-file=identity=/tmp/flux-payments-deploy \
  --from-file=identity.pub=/tmp/flux-payments-deploy.pub \
  --from-literal=known_hosts="$(ssh-keyscan github.com 2>/dev/null)"

# Store the private key in Vault; sync to the cluster via External Secrets.
```

```yaml
# Restrict access to Git credential secrets.
# Only Flux source controller needs these secrets.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: flux-system-isolation
  namespace: flux-system
spec:
  podSelector:
    matchLabels:
      app: source-controller
  policyTypes:
    - Egress
  egress:
    # Only to GitHub (or your Git server).
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 10.0.0.0/8
              - 172.16.0.0/12
              - 192.168.0.0/16
      ports:
        - port: 22   # SSH.
        - port: 443  # HTTPS.
```

### Step 4: Kustomization Trust Boundaries

```yaml
# Separate Kustomizations for platform (high trust) vs. team (lower trust).

# Platform Kustomization: cluster-level resources; managed by platform team.
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: platform-cluster-config
  namespace: flux-system
spec:
  path: "./clusters/production/platform"
  serviceAccountName: platform-flux-sa   # Has ClusterRole for cluster-level resources.
  # Only platform team can push to this path; branch protection enforces this.

---
# Application Kustomization: namespace-level resources only.
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: payments-app
  namespace: flux-system
spec:
  path: "./clusters/production/payments"
  serviceAccountName: payments-flux-sa   # Namespace-scoped only.
  targetNamespace: payments
  # Deny cluster-level resources via Kyverno:
  # Any ClusterRoleBinding in this path is rejected.
```

```yaml
# Kyverno policy: prevent application Kustomizations from deploying cluster resources.
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-flux-cluster-resources
spec:
  validationFailureAction: Enforce
  rules:
    - name: deny-cluster-role-binding-from-app-kustomization
      match:
        any:
          - resources:
              kinds: ["ClusterRoleBinding", "ClusterRole"]
      preconditions:
        all:
          - key: "{{ request.userInfo.username }}"
            operator: Equals
            value: "system:serviceaccount:flux-system:payments-flux-sa"
      deny:
        conditions:
          - key: "true"
            operator: Equals
            value: "true"
        message: "Application Kustomizations may not deploy cluster-level resources."
```

### Step 5: HelmRelease Security

```yaml
apiVersion: helm.toolkit.fluxcd.io/v2beta2
kind: HelmRelease
metadata:
  name: payments-api
  namespace: payments
spec:
  chart:
    spec:
      chart: payments-api
      version: ">=1.0.0 <2.0.0"  # Version range pinning.
      sourceRef:
        kind: HelmRepository
        name: internal-charts

  # Verify chart signatures (if the chart registry supports OCI signing).
  chartRef:
    kind: OCIRepository
    name: payments-api-chart
  # For OCI: Flux verifies the image signature before applying the chart.

  values:
    # Security contexts enforced in values.
    securityContext:
      runAsNonRoot: true
      runAsUser: 65534
    containerSecurityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
    # NOT: privileged: true, hostNetwork: true.

  # Rollback on failed upgrades.
  rollback:
    enable: true
    cleanupOnFail: true

  # Test after upgrade.
  test:
    enable: true
```

### Step 6: Reconciliation Monitoring

```yaml
# Prometheus rules for Flux reconciliation health.
groups:
  - name: flux-security
    rules:
      - alert: FluxKustomizationFailed
        expr: |
          gotk_reconcile_condition{type="Ready", status="False", kind="Kustomization"} > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Flux Kustomization {{ $labels.name }} is not Ready"
          description: "Cluster state may have diverged from Git. Investigate immediately."

      - alert: FluxSourceNotReady
        expr: |
          gotk_reconcile_condition{type="Ready", status="False", kind="GitRepository"} > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Flux cannot fetch from Git repository {{ $labels.name }}"

      - alert: FluxCommitVerificationFailed
        expr: |
          increase(gotk_reconcile_condition{type="SourceVerified", status="False"}[5m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Flux commit signature verification FAILED for {{ $labels.name }}"
          description: "A commit without a valid signature was pushed to the manifests repository."
```

### Step 7: Image Automation Security

```yaml
# ImagePolicy: restrict automation to approved image registries only.
apiVersion: image.toolkit.fluxcd.io/v1beta2
kind: ImagePolicy
metadata:
  name: payments-api-policy
  namespace: flux-system
spec:
  imageRepositoryRef:
    name: payments-api-repo
  policy:
    semver:
      range: ">=1.0.0 <2.0.0"   # Only 1.x releases; no pre-releases.
  # filterTags: exclude pre-release and debug tags.
  filterTags:
    pattern: "^v[0-9]+\\.[0-9]+\\.[0-9]+$"   # Only vX.Y.Z tags.
    extract: "$timestamp"
```

```yaml
# ImageRepository: only from internal registry.
apiVersion: image.toolkit.fluxcd.io/v1beta2
kind: ImageRepository
metadata:
  name: payments-api-repo
  namespace: flux-system
spec:
  image: registry.internal.example.com/payments-api
  # NOT: docker.io, ghcr.io without verification.
  secretRef:
    name: registry-credentials
  # Verify image signatures before allowing image update automation.
  certSecretRef:
    name: registry-ca
```

### Step 8: Telemetry

```
gotk_reconcile_duration_seconds{kind, name, namespace}           histogram
gotk_reconcile_condition{kind, name, namespace, type, status}    gauge
gotk_resource_info{kind, name, namespace, ready}                 gauge
flux_git_fetch_success_total{name}                               counter
flux_git_fetch_failure_total{name, reason}                       counter
flux_commit_verification_failures_total{name}                    counter
```

Alert on:

- `flux_commit_verification_failures_total` non-zero — an unsigned commit was pushed to the manifests repository; critical security event.
- `gotk_reconcile_condition{type="Ready",status="False"}` for more than 10 minutes — cluster is diverging from desired state.
- `flux_git_fetch_failure_total` — Git credentials may be invalid or the repository is inaccessible.
- Flux service account used for an operation outside its allowed resource types — Kyverno rejects it; alert on repeated denials.

## Expected Behaviour

| Signal | Default Flux | Hardened Flux |
|--------|-------------|---------------|
| Malicious commit applied | Applied within reconciliation interval | Commit signature verification rejects unsigned commit |
| Developer pushes ClusterRoleBinding | Applied if in Kustomization path | Kyverno denies cluster-level resource from app Kustomization |
| Git credential exfiltration | Full repo access from cluster secret | Deploy key scoped to specific repo; External Secrets manage rotation |
| Flux SA used for privilege escalation | cluster-admin SA available | Namespace-scoped SA; escalation path blocked |
| Reconciliation failure undetected | Cluster diverges silently | Alert fires within 10 minutes of first failure |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| GPG commit verification | Supply chain integrity | All committers must GPG-sign commits | Automate via pre-commit hooks; document in onboarding |
| Per-team service accounts | Namespace blast radius isolation | More SAs and RoleBindings to manage | Automate via Helm chart or Kustomize overlay |
| Namespace-scoped Kustomization | Limits what Flux can deploy | Platform resources need separate privileged Kustomization | Two-tier: platform (high trust) and team (lower trust) Kustomizations |
| Image policy semver restriction | Prevents tag floating | Major version changes require policy update | Acceptable friction; major updates should be intentional |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| GPG key expired | All commits rejected by Flux | Commit verification failure alert | Renew GPG key; update allowed-gpg-keys Secret |
| RBAC too restrictive | Kustomization fails to apply resources | Reconciliation failure alert; forbidden API call in logs | Add specific permission; review what resource type was denied |
| Deploy key revoked | Source controller cannot fetch | Git fetch failure alert | Generate new deploy key; update Git credential Secret |
| Image automation writes bad tag | Invalid image tag deployed | Pod crash loop; health check fails | Revert image tag commit; update ImagePolicy filter |

## Related Articles

- [GitOps Security](/articles/cicd/gitops-security/)
- [Argo CD Security Hardening](/articles/cicd/argocd-security-hardening/)
- [Sigstore Keyless Signing](/articles/cicd/sigstore-keyless-signing/)
- [Kubernetes RBAC Design Patterns](/articles/kubernetes/rbac-design-patterns/)
- [External Secrets Operator](/articles/kubernetes/external-secrets-operator/)
