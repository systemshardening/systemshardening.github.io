---
title: "Argo CD Secret Extraction via Read-Only Access: CVE-2026-42880"
description: "CVE-2026-42880 (CVSS 9.6) lets any read-only Argo CD user extract plaintext Kubernetes Secrets via the Server-Side Diffs API when IncludeMutationWebhook=true is annotated. Patch to v3.3.9, audit annotations, and harden Argo CD RBAC."
slug: argocd-secret-extraction-readonly
date: 2026-05-07
lastmod: 2026-05-07
category: kubernetes
tags:
  - argocd
  - secrets
  - cve
  - rbac
  - gitops
personas:
  - platform-engineer
  - security-engineer
article_number: 448
difficulty: Intermediate
estimated_reading_time: 10
published: true
layout: article.njk
permalink: /articles/kubernetes/argocd-secret-extraction-readonly/
---

# Argo CD Secret Extraction via Read-Only Access: CVE-2026-42880

## The Problem

CVE-2026-42880 (CVSS 9.6 Critical, disclosed April 2026, fixed in Argo CD v3.3.9) allows any Argo CD user with read-only access to an application to retrieve the plaintext values of every Kubernetes Secret in that application's namespace. The attack requires no special tooling, no privilege escalation within Kubernetes, and no interaction from an administrator — a single API call is sufficient.

The vulnerability is rooted in Argo CD's Server-Side Diffs feature. Server-Side Diffs computes what would change in the cluster when an application is synced by sending resource manifests to the Kubernetes API server's dry-run endpoint and returning the result to the caller. The `IncludeMutationWebhook=true` compare option — set via the annotation `argocd.argoproj.io/compare-options: IncludeMutationWebhook=true` on an application's tracked resources — extends this calculation to include resources that would be modified by Kubernetes mutation admission webhooks, such as Istio's sidecar-injecting webhook. When this option is active, the Server-Side Diffs code path fetches the full resource spec from the cluster and includes it verbatim in the diff API response.

Kubernetes Secrets are normally masked in Argo CD's API responses: the UI shows `***` in place of `data` fields, and the standard resource API endpoints strip or redact secret content. The Server-Side Diffs code path did not apply the same masking. It returned the resource as retrieved from the Kubernetes API — `data` fields intact, Base64-encoded values included. Base64 is not encryption; decoding the values recovers the plaintext credentials.

Any user holding the `applications, get` permission in Argo CD's RBAC model can call `GET /api/v1/applications/{name}/resource-tree/diff`. In Argo CD's default RBAC policy, the built-in `readonly` role is granted exactly this permission. Developers, auditors, and external observers routinely hold the `readonly` role. The upgrade path from "read application state" to "read every credential managed in the application namespace" required only that at least one resource in the application had the `IncludeMutationWebhook=true` annotation present — a condition that is common in clusters using Istio or other mutation-heavy admission controllers.

## Threat Model

**Read-only developer extracting production credentials.** A developer assigned the Argo CD `readonly` role to give them visibility into deployment state calls the diffs API for a production application. The application's namespace contains database passwords, API keys, and TLS private keys stored as Kubernetes Secrets. Any resource in the application carrying `argocd.argoproj.io/compare-options: IncludeMutationWebhook=true` — present by default in clusters using Istio sidecar injection — causes all Secrets in the namespace to appear in the API response. The developer receives the full credential set without ever having Kubernetes API access.

**CI/CD service account with Argo CD read access pivoting to production secrets.** Many pipelines authenticate to Argo CD with a service account that holds `readonly` or `applications, get` to check deployment status, wait for sync completion, or query application health. A compromised pipeline — through a supply chain attack, a poisoned build script, or a compromised GitHub Actions runner — uses the Argo CD API token present in the pipeline environment to call the diffs endpoint and exfiltrate every Secret in every application namespace the service account can read. The attack happens entirely within the CI/CD system and leaves no Kubernetes API audit trail, because no Kubernetes API calls are made by the attacker directly.

**Multi-tenant Argo CD: lateral movement across applications.** In a multi-tenant Argo CD installation, a user with read access to their own application namespace can extract Secrets from any application in any namespace they can read. If the RBAC policy assigns `readonly` at the Argo CD project level rather than per-application, the attacker's accessible surface is every application in the project, which may span multiple product namespaces. The blast radius scales with the breadth of the RBAC grant, not with any Kubernetes-level isolation between namespaces.

**Default RBAC coverage.** Argo CD ships with a `readonly` role defined in the `argocd-rbac-cm` ConfigMap that includes `p, role:readonly, applications, get, */*, allow`. Every user or group assigned this role is affected by CVE-2026-42880 on any Argo CD version prior to v3.3.9. Installations that have not customised their RBAC policy are vulnerable by default as long as at least one application contains a resource with the affected annotation.

## Hardening Configuration

### 1. Patch to Argo CD v3.3.9

The only complete fix for CVE-2026-42880 is upgrading to v3.3.9 or later. The patch adds Secret masking to the Server-Side Diffs code path, applying the same redaction logic used in all other Argo CD API responses regardless of which compare options are active.

Check the running version before planning the upgrade window:

```bash
kubectl -n argocd get deployment argocd-server \
  -o jsonpath='{.spec.template.spec.containers[0].image}'
```

Upgrade the argocd-server deployment image directly:

```bash
kubectl -n argocd set image deployment/argocd-server \
  argocd-server=quay.io/argoproj/argocd:v3.3.9
```

The same image must be applied to all Argo CD components. Running mixed versions leaves some code paths unpatched:

```bash
kubectl -n argocd set image deployment/argocd-repo-server \
  argocd-repo-server=quay.io/argoproj/argocd:v3.3.9

kubectl -n argocd set image deployment/argocd-application-controller \
  argocd-application-controller=quay.io/argoproj/argocd:v3.3.9
```

For Helm-managed installations:

```bash
helm repo update

helm upgrade argocd argo/argo-cd \
  --namespace argocd \
  --version 7.3.9 \
  --reuse-values
```

Verify that all deployments are running the updated image after the rollout completes:

```bash
kubectl rollout status deployment/argocd-server -n argocd

kubectl -n argocd get deployment argocd-server \
  -o jsonpath='{.spec.template.spec.containers[0].image}'
```

The output should show `v3.3.9`.

### 2. Audit and Remove `IncludeMutationWebhook=true` Annotations

The vulnerability is only reachable when at least one resource in an application carries `argocd.argoproj.io/compare-options: IncludeMutationWebhook=true`. Removing this annotation from all manifests eliminates the trigger condition on any Argo CD version, patched or unpatched.

Scan all manifests in your GitOps repositories:

```bash
grep -r "IncludeMutationWebhook=true" --include="*.yaml" .
```

This identifies the files that need remediation. For each match, review whether the annotation is providing genuine operational value (see trade-offs below). In most cases, the annotation was added to improve diff accuracy for mutation-webhook-processed resources such as Istio-injected sidecars and can be removed without functional impact; Argo CD will continue to sync and display diffs, just without the mutation webhook's transformations applied in the diff preview.

Remove the annotation from each affected manifest:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: example-app
  annotations:
    argocd.argoproj.io/compare-options: ServerSideDiff=true
```

If `IncludeMutationWebhook=true` was the only compare option set, remove the annotation key entirely rather than leaving an empty value.

After updating manifests and merging to Git, verify that Argo CD has synced the changes and the annotation is no longer present on live resources:

```bash
kubectl get deployment example-app -n production \
  -o jsonpath='{.metadata.annotations.argocd\.argoproj\.io/compare-options}'
```

An empty output confirms the annotation has been removed from the live resource.

### 3. Restrict the Server-Side Diffs API with Custom RBAC

Argo CD's RBAC model does not provide a built-in way to allow `applications, get` while blocking access specifically to the diffs endpoint. The most effective control is narrowing which users hold the `applications, get` permission at all. For environments where developers need application visibility but do not need diff functionality, create a custom role that explicitly limits their access.

Edit the `argocd-rbac-cm` ConfigMap in the `argocd` namespace:

```bash
kubectl -n argocd edit configmap argocd-rbac-cm
```

Add a custom `developer` role that restricts application actions to listing and reading application metadata, without granting the broader `get` verb that enables the diffs API:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-rbac-cm
  namespace: argocd
data:
  policy.default: role:readonly
  policy.csv: |
    p, role:developer, applications, list, */*, allow
    p, role:developer, applications, get, */*, deny
    p, role:developer, applications, sync, */*, deny
    g, <your-developer-group>, role:developer
```

If removing `applications, get` entirely is too disruptive — for example, if developers rely on the Argo CD UI to review resource state — create a scope-limited readonly role that retains get but documents the accepted risk, and pair it with the annotation removal in step 2 so the diff endpoint returns no secret data even when called.

Apply the updated ConfigMap and verify the policy was loaded by Argo CD:

```bash
kubectl -n argocd rollout restart deployment/argocd-server

argocd account can-i get applications '*' --server argocd.example.com \
  --auth-token <developer-token>
```

### 4. Audit Current RBAC Assignments

Before applying the RBAC changes above, enumerate which users and service accounts currently hold `readonly` or `applications, get` access. Unexpected grants are common in installations that have grown organically.

List all Argo CD accounts and their roles:

```bash
argocd account list --server argocd.example.com
```

Inspect the full RBAC policy currently active:

```bash
kubectl -n argocd get configmap argocd-rbac-cm -o yaml
```

Pay attention to:

- Group bindings that assign `role:readonly` or `role:admin` to broad identity provider groups
- Service account tokens created for CI/CD pipelines with `readonly` access
- The `policy.default` field — if it is set to `role:readonly`, every authenticated user has `applications, get` access by default, even without an explicit binding

For each service account token used in CI pipelines, confirm that the token is scoped to only the applications the pipeline actually needs to access:

```bash
argocd proj role list <project-name> --server argocd.example.com

argocd proj role get <project-name> <role-name> --server argocd.example.com
```

Remove or scope down any grants that are broader than operationally required.

### 5. Verify Secret Masking After Patching

After upgrading to v3.3.9, confirm that the diff API no longer returns plaintext Secret data. This requires an application that contains a Kubernetes Secret and has the `IncludeMutationWebhook=true` annotation present on at least one resource.

Call the diff endpoint directly using a read-only token and inspect the response:

```bash
ARGOCD_TOKEN=<readonly-user-token>
ARGOCD_SERVER=argocd.example.com
APP_NAME=example-app

curl -s -H "Authorization: Bearer ${ARGOCD_TOKEN}" \
  "https://${ARGOCD_SERVER}/api/v1/applications/${APP_NAME}/resource-tree/diff" \
  | jq '.items[] | select(.kind == "Secret") | .normalizedLiveState'
```

On a correctly patched server, the `data` fields of any Secret in the response will be replaced with `***` or omitted entirely. If you see Base64-encoded values in the output, the patch did not apply correctly — check that all Argo CD component deployments are running v3.3.9.

Using the Argo CD CLI:

```bash
argocd app diff ${APP_NAME} --server ${ARGOCD_SERVER} \
  --auth-token ${ARGOCD_TOKEN}
```

A patched server returns diff output that redacts Secret data fields. Verify that no `data:` stanza with real values appears in the output for any Secret resource.

## Expected Behaviour After Hardening

After patching to v3.3.9: calling `GET /api/v1/applications/{name}/resource-tree/diff` for an application that contains Kubernetes Secrets returns those Secrets with their `data` fields replaced by `***`, regardless of whether `IncludeMutationWebhook=true` is present. The exploit path is closed at the API layer.

After the annotation audit: no manifests in the GitOps repository carry `argocd.argoproj.io/compare-options: IncludeMutationWebhook=true`. The diff API for those applications does not include mutation-webhook-processed resource specs in its response. The vulnerability trigger condition is absent from the application inventory.

Both controls together provide defence in depth: the patch closes the vulnerability in the code, and the annotation removal eliminates the condition that was required to reach the vulnerable code path.

## Trade-offs and Operational Considerations

Removing `IncludeMutationWebhook=true` reduces diff accuracy for resources processed by Kubernetes mutation admission webhooks. In clusters using Istio, this means the diff preview in the Argo CD UI will show the manifest as written in Git rather than the manifest as it would appear after sidecar injection. For operators who rely on the diff preview to validate that sidecars will be injected correctly, this is a visible regression in tooling. The mitigation is to move diff validation to Git-level tooling: use `helm template` or `kustomize build` combined with your admission webhook simulator to preview the fully-rendered manifest before committing, rather than relying on Argo CD's live diff preview.

Restricting the diffs endpoint for read-only users reduces developer visibility into pending changes. Developers who previously used the Argo CD UI to review what a sync would change before approving it will need to use `git diff` at the repository level or a separate pre-sync review step instead. For teams that have invested in Argo CD as the canonical view of pending changes, this requires a workflow adjustment. Evaluate whether the annotation removal alone (which preserves the diff endpoint but removes the Secret-bearing code path) is a sufficient control for your threat model, versus the additional reduction in surface area that comes from removing `applications, get` entirely.

## Failure Modes

**Argo CD server updated but repo server or application controller not updated.** The Server-Side Diffs code path runs in part through the repo server component. If `argocd-repo-server` is running an older image than `argocd-server`, the masking applied in the server may not cover all code paths that touch Secret data in the diff calculation. Always update all Argo CD component deployments to the same version in a single operation.

**Annotation removed from GitOps manifests but still present on live cluster resources.** Removing the annotation from manifests in Git does not immediately remove it from the live Kubernetes resources. Argo CD will show the application as `OutOfSync` until a sync removes the annotation from the cluster. An attacker who acts between the Git commit and the next sync can still call the diffs API and hit the `OutOfSync` state, which includes the annotation-bearing live resources. Trigger a sync immediately after merging the annotation removal:

```bash
argocd app sync ${APP_NAME} --server ${ARGOCD_SERVER}
```

Verify the annotation is gone from the live resource after sync completes using the `kubectl get` command from step 2.

**RBAC policy change applied but `policy.default` still grants `readonly` to all users.** A custom RBAC policy that restricts a specific group from `applications, get` has no effect if `policy.default: role:readonly` remains active, because every authenticated user — including those not in any explicitly bound group — inherits the default role. The default role grants `applications, get`. Review the `policy.default` field in `argocd-rbac-cm` and change it to `role:''` (no permissions by default) if your installation uses SSO group mappings for all access control, so that only explicitly granted roles are active.

## Related Articles

- [Argo CD Security Hardening](/articles/cicd/argocd-security-hardening/)
- [GitOps Security](/articles/cicd/gitops-security/)
- [Kubernetes Secrets Management](/articles/kubernetes/secrets-management/)
- [Kubernetes RBAC Design Patterns](/articles/kubernetes/rbac-design-patterns/)
- [External Secrets Operator](/articles/kubernetes/external-secrets-operator/)
