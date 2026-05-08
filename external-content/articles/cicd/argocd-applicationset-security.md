---
title: "Argo CD ApplicationSet and Cluster Generator Security"
description: "Harden Argo CD ApplicationSet controllers against cluster generator privilege escalation, Git generator path traversal, and the recurring pattern of security fixes shipped without advance advisory."
slug: argocd-applicationset-security
date: 2026-05-02
lastmod: 2026-05-02
category: cicd
tags: ["argocd", "applicationset", "gitops", "cluster-generator", "cve", "privilege-escalation", "supply-chain"]
personas: ["platform-engineer", "sre", "security-engineer"]
article_number: 362
difficulty: advanced
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/cicd/argocd-applicationset-security/index.html"
---

# Argo CD ApplicationSet and Cluster Generator Security

## Problem

Argo CD ApplicationSets are a controller that generates multiple Argo CD `Application` resources from a single template using pluggable generators. The Cluster generator creates one `Application` per registered cluster, the Git generator creates `Application` resources from directories or files in a Git repository, and the Matrix generator combines the output of two generators — for example, pairing every cluster with every application directory. This makes ApplicationSets a powerful force multiplier for multi-cluster GitOps workflows: a single ApplicationSet manifest can manage hundreds of `Application` resources across dozens of clusters simultaneously. That centralized power also centralizes significant privilege.

The ApplicationSet controller became part of the core Argo CD distribution in version 2.3 and was enabled by default from version 2.5 onward. As of Argo CD 2.8, it runs as a separate controller with its own service account inside the `argocd` namespace. That service account must be able to list and read cluster secrets (the mechanism Argo CD uses to store registered cluster credentials), read Git repository configuration, and create, update, and delete `Application` resources across all namespaces it manages. This is a privileged position: an attacker who can influence what the ApplicationSet controller generates — through a malicious `ApplicationSet` manifest or by injecting content into a watched Git repository — gains a path to deploying arbitrary workloads to every cluster in the fleet.

There are three primary attack surfaces. The first is the **Cluster generator**. The ApplicationSet controller must enumerate registered clusters — stored as Kubernetes secrets in the `argocd` namespace with the label `argocd.argoproj.io/secret-type: cluster` — and create `Application` resources targeting those clusters. A developer who gains the ability to create an `ApplicationSet` in any namespace can, if the controller is not scoped, generate Applications targeting clusters they are not authorized to access. Without explicit `clusters` selector constraints, the Cluster generator defaults to targeting all registered clusters: development, staging, and production alike.

The second surface is the **Git generator**. The `directory` variant of the Git generator reads every subdirectory matching a path pattern in a Git repository and creates an `Application` for each one. If the path pattern is broad (e.g., `apps/*`) and the Git repository accepts contributions from engineers who are not platform-team members, an attacker with write access to any branch that the generator watches can add a directory containing a valid Argo CD `Application` spec. When that branch is merged — or if the generator watches a branch without merge protection — the controller will synthesize a new `Application` pointing to the attacker's chosen destination cluster and namespace.

The third surface is **template injection**. ApplicationSet templates use `{{variable}}` interpolation to substitute generator outputs into the Application template. Cluster generators expose cluster metadata — name, server URL, and all cluster labels and annotations — as template variables. If an ApplicationSet template interpolates a cluster label value directly into a field that accepts Kubernetes manifest data, such as `spec.source.helm.values` or `spec.source.kustomize.patches`, an attacker who can modify cluster labels (via `kubectl label cluster` with the appropriate Kubernetes RBAC) can inject content that alters the generated Application spec in ways the ApplicationSet author did not intend.

Argo CD has one of the higher CVE counts among CNCF projects, and the ApplicationSet controller has contributed to that record. The broader pattern across Argo CD's CVE history is instructive. CVE-2022-29165 allowed bypass of cluster secret validation. CVE-2023-22482 was a JWT bypass enabling privilege escalation. CVE-2023-40025 was an auth bypass via cache poisoning. CVE-2024-21662 enabled denial of service. CVE-2024-40634 introduced path traversal in the ApplicationSet Git generator. In 2024, an ApplicationSet privilege escalation bug allowed a malicious `ApplicationSet` to create `Application` resources in namespaces the controller should not have had write access to; the fix was shipped in a patch release of Argo CD 2.10. The fix commit appeared in the public `argoproj/argo-cd` repository under a message reading "fix namespace validation in applicationset controller" approximately five days before the accompanying GHSA was published. Operators monitoring `https://github.com/argoproj/argo-cd/commits/main` for commits touching the `applicationset/` directory could identify the change before a formal advisory existed — and so could attackers scanning for fresh patch commits to reverse-engineer exploits. This pre-advisory window is a structural characteristic of open-source security, not an Argo CD-specific failure, but it increases the operational urgency of fast patch cycles for infrastructure as privileged as the ApplicationSet controller.

Target systems: Argo CD 2.8–2.14 (ApplicationSet controller enabled by default since 2.5), Kubernetes 1.28+.

## Threat Model

1. **Developer-to-fleet escalation via ApplicationSet create.** A developer with Argo CD `Application` write access in their team's namespace learns that the cluster also has `applicationsets.argoproj.io` resources available. They create an `ApplicationSet` using the Cluster generator with no `selector` constraint and a template that deploys a `DaemonSet` running a privileged container. The ApplicationSet controller — unaware that this developer should only have access to the `team-dev` namespace — generates one `Application` per registered cluster, including the production clusters. The deployment succeeds because the controller's service account has cluster-wide `Application` create authority. The developer has escalated from dev-namespace access to cluster-admin effective control across the fleet.

2. **Git generator path traversal.** An attacker with write access to a feature branch of the source Git repository adds a directory at `apps/internal-tooling/malicious-deployment/` containing a minimal `Application` spec pointing to the production cluster with `destination.namespace: kube-system`. The ApplicationSet's `directory` generator pattern is `apps/*/*`, which matches the new path. The team's branch protection requires one reviewer, but the pull request description says "add monitoring tooling" and the new directory's `Application` YAML looks like a standard app deployment. After approval and merge, the Git generator picks up the new directory and creates the `Application`. Because the ApplicationSet template passes the Git path through to the destination namespace field, the production cluster receives a new Application deploying to `kube-system`.

3. **Patch-gap attacker.** An attacker monitors the Argo CD commit feed and identifies a commit to `applicationset/utils/utils.go` that changes how the controller validates `destination.namespace` values in generated Applications. They reverse-engineer the pre-patch behaviour, confirm that clusters running Argo CD 2.10.3 (the version before the fix) are vulnerable, and scan for exposed Argo CD UIs. They identify an organization running 2.10.3 and, during the five-day window before the GHSA is published and operators receive automated alerts, they create an ApplicationSet through a leaked API token that exploits the namespace validation gap to deploy a cryptominer to 14 clusters.

4. **Template injection via cluster label.** An ApplicationSet template includes `{{metadata.labels.team}}` in the `spec.source.helm.values` field to customize a Helm chart per cluster. An attacker with `kubectl label` access to the cluster objects (granted as part of a cluster onboarding runbook) sets the `team` label on the production cluster to `\npodAnnotations:\n  kubectl.kubernetes.io/last-applied-configuration: "..."`. The injected YAML key is valid Helm values syntax and causes the generated Application to override Helm values the platform team expected to be fixed.

The blast radius of ApplicationSet controller compromise is proportional to the number of registered clusters and the absence of `ApplicationSet` creation controls. In a fleet of 50 clusters with no `selector` constraints and no RBAC restriction on `applicationsets` create, a single malicious `ApplicationSet` can target all 50 clusters in under 30 seconds — the default ApplicationSet reconciliation interval.

## Configuration / Implementation

### Restricting ApplicationSet Creation

The first control is limiting who can create `ApplicationSet` resources at all. In most organizations, `ApplicationSet` creation should be restricted to the platform team. Developers get the ability to create individual `Application` resources within their namespaces but not `ApplicationSet` resources.

```yaml
# platform-team-applicationset-role.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: platform-applicationset-admin
rules:
  - apiGroups: ["argoproj.io"]
    resources: ["applicationsets"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["argoproj.io"]
    resources: ["applications"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
---
# developer-application-only-role.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: developer-application-user
rules:
  - apiGroups: ["argoproj.io"]
    resources: ["applications"]
    verbs: ["get", "list", "watch", "create", "update", "patch"]
  # Explicitly no applicationsets resource here
```

Argo CD 2.6 introduced namespaced ApplicationSets, which allow the ApplicationSet controller to be scoped to specific namespaces rather than operating cluster-wide. Enable namespaced mode by passing `--namespaced` to the controller and configuring `argocd-applicationset-controller` with the `ARGOCD_APPLICATIONSET_CONTROLLER_NAMESPACES` environment variable:

```yaml
# argocd-applicationset-controller deployment patch
spec:
  template:
    spec:
      containers:
        - name: argocd-applicationset-controller
          args:
            - /usr/local/bin/argocd-applicationset-controller
            - --namespaced
          env:
            - name: ARGOCD_APPLICATIONSET_CONTROLLER_NAMESPACES
              value: "platform,team-alpha,team-beta"
```

In namespaced mode, ApplicationSets in `team-alpha` can only create Applications targeting the namespaces that the ApplicationSet controller is authorized to manage for that namespace — preventing cross-namespace escalation by design.

### Cluster Generator Scoping

The Cluster generator's default behaviour — `selector: {}`, matching all registered clusters — is the most common configuration error. Every ApplicationSet using the Cluster generator should include an explicit label selector:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: team-alpha-apps
  namespace: platform
spec:
  generators:
    - clusters:
        selector:
          matchLabels:
            env: production
            argocd-managed: "true"
            team: alpha
  template:
    metadata:
      name: "{{name}}-alpha-app"
    spec:
      project: team-alpha
      source:
        repoURL: https://github.com/org/team-alpha-apps
        targetRevision: main
        path: "apps/{{name}}"
      destination:
        server: "{{server}}"
        namespace: team-alpha
      syncPolicy:
        automated:
          prune: true
          selfHeal: true
```

Audit all existing ApplicationSets for missing selectors:

```bash
kubectl get applicationset -A -o json | \
  jq '.items[] | select(.spec.generators[].clusters.selector == null) | .metadata.name'
```

To see a complete view of generator types and target namespaces across all ApplicationSets:

```bash
kubectl get applicationset -A -o json | jq '.items[] | {
  name: .metadata.name,
  namespace: .metadata.namespace,
  generators: [.spec.generators[] | keys[0]],
  templateDestinationNamespace: .spec.template.spec.destination.namespace,
  templateDestinationServer: .spec.template.spec.destination.server
}'
```

Label all registered clusters consistently so selectors are meaningful:

```bash
# Label a cluster for use with the cluster generator selector
kubectl label secret -n argocd \
  $(kubectl get secret -n argocd -l argocd.argoproj.io/secret-type=cluster \
    -o jsonpath='{.items[?(@.metadata.annotations.server=="https://prod-cluster.example.com")].metadata.name}') \
  env=production \
  argocd-managed=true \
  team=platform
```

### Git Generator Path Validation

Restrict which Git repositories the ApplicationSet controller will read from. Argo CD's `repositories` configuration (in `argocd-cm`) acts as the authoritative allowlist. Any Git URL not in this list will be rejected:

```yaml
# argocd-cm ConfigMap — restrict permitted repositories
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-cm
  namespace: argocd
data:
  repositories: |
    - url: https://github.com/org/platform-apps
      type: git
    - url: https://github.com/org/team-alpha-apps
      type: git
```

For Git generator `directory` patterns, use `exclude` directives to prevent the generator from watching paths that should not produce Applications:

```yaml
spec:
  generators:
    - git:
        repoURL: https://github.com/org/platform-apps
        revision: main
        directories:
          - path: apps/*
            exclude: false
          - path: apps/experimental/*
            exclude: true
          - path: apps/legacy-*
            exclude: true
  requeueAfterSeconds: 180
```

The `requeueAfterSeconds` field controls how frequently the controller re-reads the repository. Setting it to 180 seconds (rather than the default 30) reduces the window in which an injected directory becomes an active Application, giving monitoring systems more time to detect anomalous ApplicationSet creation events.

Ensure the source Git repository has branch protection rules that require at least two platform-team reviewers for any change to paths watched by the Git generator. GitHub branch protection example:

```bash
gh api repos/org/platform-apps/branches/main/protection \
  --method PUT \
  --field required_pull_request_reviews[required_approving_review_count]=2 \
  --field required_pull_request_reviews[dismiss_stale_reviews]=true \
  --field restrictions[teams][]="platform-team" \
  --field enforce_admins=true
```

### Template Injection Prevention

Template injection risk is highest when cluster metadata — labels, annotations, cluster name — is interpolated into fields that Argo CD passes through to Kubernetes or Helm without further validation. Safe and unsafe patterns:

```yaml
# UNSAFE: cluster label interpolated into Helm values
spec:
  template:
    spec:
      source:
        helm:
          values: |
            environment: "{{metadata.labels.env}}"
            team: "{{metadata.labels.team}}"
            # An attacker who controls cluster labels can inject
            # arbitrary YAML keys here

# SAFE: only interpolate into fields with constrained value spaces
spec:
  template:
    spec:
      source:
        targetRevision: "{{metadata.labels.gitRevision}}"
        # targetRevision is validated as a git ref — limited injection surface
      destination:
        namespace: "{{metadata.labels.teamNamespace}}"
        # scope this with an Argo CD project destinationNamespaces allowlist
```

For `spec.source.helm.values` and `spec.source.kustomize.patches`, do not use cluster label interpolation at all. Instead, store per-cluster configuration as files in the Git repository (checked by the Git generator) or as Argo CD `ConfigManagementPlugin` inputs. If you must interpolate cluster labels, validate them using an admission webhook (e.g., OPA Gatekeeper) that enforces a strict allowlist of valid label values before the label is applied to the cluster secret.

Use Argo CD AppProject `destinationNamespaces` to constrain where generated Applications can deploy, even if template injection succeeds:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: AppProject
metadata:
  name: team-alpha
  namespace: argocd
spec:
  destinations:
    - server: "https://prod-cluster.example.com"
      namespace: team-alpha
    - server: "https://staging-cluster.example.com"
      namespace: team-alpha-staging
  # Deny any destination not explicitly listed above
  sourceRepos:
    - "https://github.com/org/team-alpha-apps"
  clusterResourceWhitelist: []
  namespaceResourceWhitelist:
    - group: "apps"
      kind: "Deployment"
    - group: ""
      kind: "Service"
    - group: ""
      kind: "ConfigMap"
```

### ApplicationSet Controller RBAC Hardening

The ApplicationSet controller service account requires read access to cluster secrets in the `argocd` namespace. Scope this as narrowly as possible:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: applicationset-controller-role
  namespace: argocd
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch"]
    # Restrict to cluster secrets only via label selector (enforced in controller code)
  - apiGroups: ["argoproj.io"]
    resources: ["applicationsets", "applicationsets/status", "applicationsets/finalizers"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["argoproj.io"]
    resources: ["applications", "applications/status"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["create", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: applicationset-controller-rolebinding
  namespace: argocd
subjects:
  - kind: ServiceAccount
    name: argocd-applicationset-controller
    namespace: argocd
roleRef:
  kind: Role
  name: applicationset-controller-role
  apiGroup: rbac.authorization.k8s.io
```

Note that the ApplicationSet controller also needs a `ClusterRole` to create `Application` resources in target namespaces when operating in non-namespaced mode. Audit what this ClusterRole currently grants:

```bash
kubectl get clusterrolebinding -o json | \
  jq '.items[] | select(.subjects[]?.name == "argocd-applicationset-controller") | {
    name: .metadata.name,
    roleRef: .roleRef.name
  }'

kubectl get clusterrole argocd-applicationset-controller -o yaml
```

Replace any `cluster-admin` or wildcard verb grants with a scoped role that permits only `applications` create/update/delete in the specific namespaces the ApplicationSet controller manages.

### Monitoring Argo CD for Silent Security Fixes

Subscribe to Argo CD security advisories via GitHub's watch mechanism:

```bash
# Watch the Argo CD repository for security advisories
gh api user/subscriptions -X PUT repos/argoproj/argo-cd
```

Monitor commits to the ApplicationSet controller for security-relevant changes. This query runs against the GitHub API and can be scheduled as a daily CI job:

```bash
gh api "repos/argoproj/argo-cd/commits?path=applicationset&per_page=20" \
  --jq '.[] | select(
    .commit.message | test(
      "applicationset|generator|template|security|privilege|path.*valid|namespace.*valid|CVE|fix.*escape|sanitize";
      "i"
    )
  ) | {
    sha: .sha[0:8],
    date: .commit.author.date,
    message: (.commit.message | split("\n")[0])
  }'
```

Add Renovate or Dependabot configuration for the Argo CD Helm chart to receive automatic pull requests when new patch versions are released:

```yaml
# renovate.json
{
  "helmvals": [
    {
      "fileMatch": ["charts/argo-cd/values.yaml"],
      "packageRules": [
        {
          "matchPackageNames": ["argoproj/argo-cd"],
          "automerge": false,
          "reviewers": ["platform-team"]
        }
      ]
    }
  ]
}
```

Before each Argo CD upgrade, review the CHANGELOG for entries under `applicationset/`:

```bash
# Check CHANGELOG entries for the ApplicationSet controller since your current version
gh api "repos/argoproj/argo-cd/contents/CHANGELOG.md" \
  --jq '.content' | base64 -d | \
  grep -A 3 -i "applicationset\|cluster generator\|git generator" | \
  head -60
```

## Expected Behaviour

| Signal | Default ApplicationSet config | Hardened config |
|---|---|---|
| Developer creates ApplicationSet with Cluster generator, no selector | ApplicationSet controller creates Applications targeting all registered clusters, including production | RBAC denies `applicationsets` create for developer role; request rejected at admission |
| Git generator directory match includes attacker-added path | New Application created immediately on next reconcile (default: 30 s); Application deploys to destination cluster | `requeueAfterSeconds: 180` delays pickup; branch protection prevents merge without two platform-team reviewers; Argo CD AppProject `destinationNamespaces` rejects deploy to unauthorized namespace |
| Cluster label set to YAML-injecting value; template interpolates label into `helm.values` | Injected YAML key overrides Helm values in generated Application | No cluster label interpolation in `helm.values` or `kustomize.patches` fields; OPA Gatekeeper admission webhook rejects invalid label values |
| Patch-gap attacker exploits namespace validation gap (pre-fix Argo CD version) | Malicious ApplicationSet creates Applications in `kube-system` namespace on all clusters | Renovate PR for Argo CD patch version merged within 24 h; AppProject namespace allowlist limits impact even on un-patched version |
| Non-platform-team user attempts `kubectl create applicationset` | ApplicationSet created; controller reconciles immediately | `ClusterRole` for developer role excludes `applicationsets` resource; Kubernetes API returns 403 Forbidden |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Namespaced ApplicationSets | ApplicationSet controller privilege scoped per namespace; cross-namespace escalation prevented by design | Each namespace requires separate controller configuration; Helm chart values become more complex; per-namespace RBAC management overhead | Document namespace scoping in platform runbook; use Helm umbrella chart to manage per-namespace controller instances |
| Cluster selector requirement | Prevents accidental or malicious targeting of unintended clusters; makes ApplicationSet scope explicit and auditable | Requires consistent cluster labelling discipline; new clusters not automatically picked up by existing ApplicationSets until labelled | Automate cluster labelling in the cluster provisioning pipeline (Terraform/Crossplane); add label presence check to cluster onboarding gate |
| Git repository allowlist in `argocd-cm` | Blocks ApplicationSets from sourcing from attacker-controlled or unofficial repositories | Blocks legitimate cross-organization module sharing (e.g., community Helm chart repos); requires allowlist maintenance as repos are added | Use a proxy registry (Gitea, GitLab mirror) to import external repos into the org allowlist; update allowlist via PR with platform-team review |
| Strict template field restrictions (no label interpolation in `helm.values`) | Eliminates template injection path for cluster-label-controlled data | Breaks dynamic per-cluster Helm value customization patterns that developers already depend on | Move per-cluster config to versioned files in the Git repository; use ApplicationSet `goTemplate` mode with `helm.values` rendered from Git files rather than cluster labels |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Cluster selector too narrow after label change | New cluster added to fleet is not picked up by any ApplicationSet; cluster runs no managed workloads | `kubectl get applicationset -A -o json` shows zero Applications generated for new cluster; Argo CD UI shows no apps for cluster; alert on cluster age > 30 min with zero Argo CD Applications | Add required labels to cluster secret: `kubectl label secret -n argocd <cluster-secret> env=production argocd-managed=true`; ApplicationSet reconciles within `requeueAfterSeconds` |
| Git generator `exclude` pattern too broad | Legitimate application directories skipped; Applications not created for services that should be deployed | Developers report their app is not in Argo CD UI; `kubectl get applicationset <name> -o yaml` shows `exclude: true` matches intended paths | Narrow the exclude glob in the ApplicationSet spec; test patterns locally with `argocd app generate` before applying |
| RBAC tightening breaks existing ApplicationSet reconciliation | ApplicationSet controller logs show `403 Forbidden` on `secrets` list or `applications` create; Applications fall out of sync | Controller pod logs: `kubectl logs -n argocd deploy/argocd-applicationset-controller | grep -i "forbidden\|403\|permission"`; Argo CD health status turns Unknown | Temporarily restore prior RBAC permissions; audit what verbs the controller requires using `kubectl auth can-i --list --as=system:serviceaccount:argocd:argocd-applicationset-controller`; restore minimal required permissions |
| Argo CD upgrade changes generator behaviour | Existing ApplicationSets stop generating expected Applications or generate unexpected ones after upgrade | Argo CD upgrade changelog not reviewed before apply; Applications appear or disappear in Argo CD UI; diff between pre- and post-upgrade `argocd app list` shows unexpected changes | Pin Argo CD chart version in Renovate; run `argocd app diff --local` in staging after upgrade before promoting to production; keep previous Helm release values for rollback |

## Related Articles

- [Argo CD Security Hardening: RBAC, SSO, and Repository Access Controls](/articles/cicd/argocd-security-hardening/)
- [GitOps Security](/articles/cicd/gitops-security/)
- [Kubernetes RBAC Design Patterns](/articles/kubernetes/rbac-design-patterns/)
- [Securing GitHub Actions](/articles/cicd/securing-github-actions/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
