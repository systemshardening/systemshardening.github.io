---
title: "ingress-nginx Annotation Injection Hardening"
description: "Harden ingress-nginx against annotation-based configuration injection attacks—CVE-2026-3288 class—with admission controls, annotation allowlisting, and upstream release monitoring."
slug: ingress-nginx-injection-hardening
date: 2026-05-02
lastmod: 2026-05-02
category: kubernetes
tags: ["ingress-nginx", "annotation-injection", "cve-2026-3288", "kubernetes", "admission-control", "rce"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 352
difficulty: advanced
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/kubernetes/ingress-nginx-injection-hardening/index.html"
---

# ingress-nginx Annotation Injection Hardening

## Problem

[ingress-nginx](https://github.com/kubernetes/ingress-nginx) is the most widely deployed Kubernetes ingress controller. It translates Kubernetes `Ingress` resources into nginx configuration, terminates TLS, routes HTTP traffic to upstream services, and exposes dozens of behavioural knobs through Kubernetes annotations. The majority of self-managed Kubernetes clusters — on-premise, EKS with self-managed controllers, GKE standard clusters — run ingress-nginx, which makes vulnerabilities in it effectively platform-level vulnerabilities.

The fundamental design of ingress-nginx is that it reads annotations on `Ingress` objects and embeds their values directly into a Go template that generates the nginx configuration file (`nginx.conf`). Annotations such as `nginx.ingress.kubernetes.io/rewrite-target`, `nginx.ingress.kubernetes.io/configuration-snippet`, and `nginx.ingress.kubernetes.io/server-snippet` allow operators to customise nginx behaviour per ingress without touching the controller deployment. The template engine writes annotation values into nginx configuration blocks with minimal sanitisation. If an annotation value contains characters that have syntactic meaning in nginx configuration — quotes, semicolons, braces, newlines — the injected characters can terminate the current nginx directive and introduce attacker-controlled directives.

**CVE-2026-3288** (published March 9, 2026, CVSS 8.8) is the most recent exploitation of this pattern. The vulnerability is in the `nginx.ingress.kubernetes.io/rewrite-target` annotation. When ingress-nginx constructs the nginx `rewrite` directive, it embeds the annotation value into a double-quoted string in the configuration template without escaping double-quote characters (`"`) in the annotation value. An attacker who can create or modify `Ingress` objects in any namespace can break out of the quoted string and inject arbitrary nginx directives. In clusters where the nginx lua module is loaded (the default in ingress-nginx), this includes `access_by_lua_block` directives that execute arbitrary Lua code inside the nginx worker process. In practice, this means reading the Kubernetes service account token mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token`, injecting `proxy_pass` redirects that route requests through an attacker-controlled host to harvest credentials, or logging the `$http_authorization` header. The fix — proper escaping of `"` characters before template embedding — was shipped in ingress-nginx v1.13.8, v1.14.4, and v1.15.0.

This is not a new vulnerability class. It is a recurring pattern with a multi-year history. CVE-2021-25742 (September 2021) allowed injection via the `custom-http-errors` annotation. The "IngressNightmare" cluster of CVEs published in March 2025 — CVE-2025-1097, CVE-2025-1098, CVE-2025-24514, and CVE-2025-1974 — demonstrated that `configuration-snippet`, `server-snippet`, `auth-url`, and other annotations were all injection vectors, with CVE-2025-1974 being a critical (CVSS 9.8) unauthenticated remote code execution via the admission webhook itself. CVE-2026-3288 confirms that the pattern persists: each fix addresses specific characters or specific annotations, but the root cause — a template engine that treats annotation values as trusted configuration fragments — has not been eliminated. The pattern recurs because fully removing annotation-based customisation would break a large fraction of production ingress-nginx deployments.

The open-source development model of ingress-nginx creates a compounding disclosure problem. The project is maintained by a small Kubernetes SIG (sig-network) team with limited dedicated security engineering resources. For CVE-2026-3288, the fix was committed simultaneously to the `main` branch and the `release-1.13` and `release-1.14` branches before any advisory was distributed via `kubernetes-security-announce@googlegroups.com`. The commit messages and PR descriptions referenced the specific annotation (`rewrite-target`) and the specific fix (escaping). Sysdig published a detection guide the same day the patched releases appeared. Security researchers monitoring changes to `internal/ingress/annotations/` and `rootfs/etc/nginx/template/nginx.tmpl` in the ingress-nginx repository could read the nature of the fix — and therefore the nature of the vulnerability — hours before cluster operators received notification through official channels. GitHub issue `kubernetes/kubernetes#137560` was filed publicly. This creates a patch-gap window: the vulnerability is known to researchers before it is known to operators, and ingress-nginx versions are trivially discoverable via the Kubernetes API.

The correct long-term posture is not to rely on annotation-level fixes alone. Admission controls that validate annotation values against safe patterns, RBAC that restricts who can write `Ingress` objects, and aggressive monitoring of the ingress-nginx release stream reduce both the probability of exploitation and the patch-gap window during which clusters are exposed. The remainder of this article covers the specific controls required.

**Target systems:** ingress-nginx ≤ v1.13.7 / ≤ v1.14.3 (vulnerable to CVE-2026-3288). Kubernetes 1.28+.

## Threat Model

1. **Developer with namespace Ingress write access**: A developer with `create`/`update` permissions on `Ingress` resources in their application namespace adds a `rewrite-target` annotation containing a double-quote followed by nginx directives. Because `Ingress` objects are namespace-scoped and many organisations grant developers namespace-level write access, this is a low-privilege starting point. The injected directive establishes a `proxy_pass` to an attacker-controlled host, routing all incoming traffic — including `Authorization` headers and session cookies from internal services — through the exfiltration endpoint.

2. **Compromised CI/CD pipeline with chart automation**: Many teams use Renovate, Flux image automation, or custom scripts to automatically apply Helm chart updates. If the Helm chart's `ingress.annotations` values are sourced from an external repository, a package registry, or an attacker-controlled values file, the pipeline applies a chart update containing a malicious annotation value without human review. The pipeline has Kubernetes API credentials with `Ingress` write access — exactly the permissions required for CVE-2026-3288 exploitation. The annotation injection happens at chart apply time, not at cluster compromise time.

3. **Patch-gap attacker scanning for unpatched controllers**: On March 9, 2026, the CVE-2026-3288 fix appears in the ingress-nginx repository. An attacker monitoring GitHub for annotation-related commits to `nginx.tmpl` identifies the vulnerability before the advisory is published. They scan Kubernetes API servers with exposed unauthenticated or lightly authenticated endpoints, enumerate ingress-nginx controller versions via the `app.kubernetes.io/version` label on the controller `Deployment`, identify clusters running v1.13.7 or earlier, and attempt to create `Ingress` objects via misconfigured RBAC or stolen credentials. Clusters that applied the patch within 24 hours are exposed during this window; clusters that apply it within a week are exposed longer.

4. **Legitimate developer using an untrusted Ingress template**: A developer copies an Ingress manifest from a public blog post or a third-party Helm chart. The template includes a `configuration-snippet` annotation — perhaps to add a custom header — sourced from a template that has been backdoored or contains a subtle nginx directive injection (e.g., `add_header X-Debug $http_authorization` that logs the `Authorization` header to the nginx access log). The developer does not review the annotation value in detail. There is no malicious intent; the damage comes from the absence of policy enforcement on annotation content.

The blast radius of a successful annotation injection attack extends beyond the compromised ingress. If the injected `access_by_lua_block` directive reads `/var/run/secrets/kubernetes.io/serviceaccount/token`, the attacker obtains the service account token of the ingress-nginx pod. In default installations, the ingress-nginx service account has `get`/`list`/`watch` permissions on `Secrets` cluster-wide — a permission required so it can fetch TLS certificates. This means annotation injection can lead directly to full cluster secret exfiltration.

## Configuration / Implementation

### Immediate: Upgrade ingress-nginx

The first action is upgrading to a patched release. The patched versions for CVE-2026-3288 are v1.13.8, v1.14.4, and v1.15.0.

```bash
# Upgrade using the ingress-nginx Helm chart
helm repo update
helm upgrade ingress-nginx ingress-nginx/ingress-nginx \
  --namespace ingress-nginx \
  --version 1.14.4 \
  --reuse-values
```

Verify that the running pod is using the patched image:

```bash
# Check the container image digest
kubectl get pods -n ingress-nginx \
  -o jsonpath='{.items[0].spec.containers[0].image}'

# Check the version label on the Deployment
kubectl get deploy -n ingress-nginx \
  -o jsonpath='{.items[0].metadata.labels.app\.kubernetes\.io/version}'
```

The output of the second command should be `1.14.4` (or `1.13.8` / `1.15.0` depending on your upgrade path). If the version label is absent, fall back to inspecting the image tag in the pod spec.

### Disabling Dangerous Annotations Cluster-Wide

The `configuration-snippet` and `server-snippet` annotations allow arbitrary nginx configuration injection by design — they exist specifically to give operators a mechanism to add nginx directives that the controller does not natively support. Disabling them cluster-wide trades customisation capability for a significantly reduced attack surface.

Set the following Helm values when installing or upgrading the chart:

```yaml
# values.yaml
controller:
  allowSnippetAnnotations: false
  config:
    annotations-risk-level: "Critical"
```

Apply via Helm:

```bash
helm upgrade ingress-nginx ingress-nginx/ingress-nginx \
  --namespace ingress-nginx \
  --version 1.14.4 \
  --values values.yaml
```

The `allowSnippetAnnotations: false` value disables `nginx.ingress.kubernetes.io/configuration-snippet` and `nginx.ingress.kubernetes.io/server-snippet`. Ingress objects that contain these annotations will have them silently ignored (the annotation is present on the object but the controller does not act on it). Setting `annotations-risk-level: Critical` additionally blocks other high-risk annotations that the ingress-nginx team has classified as capable of configuration injection.

Verify the ConfigMap reflects the setting:

```bash
kubectl get configmap -n ingress-nginx ingress-nginx-controller \
  -o yaml | grep allow-snippet
# Expected output:
# allow-snippet-annotations: "false"
```

### Admission Control for Ingress Annotations

Disabling snippet annotations does not prevent injection via `rewrite-target` (the CVE-2026-3288 vector) or other non-snippet annotations. The defence-in-depth layer is an admission controller that validates annotation values against a safe character set before the `Ingress` object is persisted.

**Kyverno ClusterPolicy:**

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: validate-ingress-annotations
  annotations:
    policies.kyverno.io/title: Validate ingress-nginx Annotation Values
    policies.kyverno.io/description: >-
      Rejects Ingress objects whose nginx annotation values contain characters
      that can be used for nginx configuration injection (CVE-2026-3288 class).
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: validate-rewrite-target
      match:
        any:
          - resources:
              kinds:
                - Ingress
      validate:
        message: >-
          The nginx.ingress.kubernetes.io/rewrite-target annotation value
          must match ^[a-zA-Z0-9/${}._-]+$ — characters including quotes,
          semicolons, braces, and newlines are not permitted.
        deny:
          conditions:
            any:
              - key: "{{ request.object.metadata.annotations.\"nginx.ingress.kubernetes.io/rewrite-target\" || '' }}"
                operator: Matches
                value: '.*[";{}\n].*'
    - name: validate-all-nginx-annotations
      match:
        any:
          - resources:
              kinds:
                - Ingress
      validate:
        message: >-
          nginx.ingress.kubernetes.io annotation values must not contain
          injection-capable characters: double-quotes, semicolons, braces,
          or newlines.
        foreach:
          - list: "request.object.metadata.annotations | to_entries(@)"
            deny:
              conditions:
                any:
                  - key: "{{ element.key }}"
                    operator: StartsWith
                    value: "nginx.ingress.kubernetes.io/"
                  - key: "{{ element.value || '' }}"
                    operator: Matches
                    value: '.*[";{}\n].*'
```

**ValidatingAdmissionPolicy (CEL) — Kubernetes 1.28+ built-in, no Kyverno required:**

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: ingress-annotation-injection-guard
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: ["networking.k8s.io"]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["ingresses"]
  validations:
    - expression: >-
        !object.metadata.annotations.exists(k,
          k.startsWith("nginx.ingress.kubernetes.io/") &&
          object.metadata.annotations[k].matches('[";{}\\n]')
        )
      message: >-
        nginx.ingress.kubernetes.io annotation values must not contain
        characters used for nginx configuration injection: ", ;, {, }, newline.
      reason: Invalid
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: ingress-annotation-injection-guard-binding
spec:
  policyName: ingress-annotation-injection-guard
  validationActions: [Deny]
  matchResources:
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: NotIn
          values:
            - kube-system
            - ingress-nginx
```

The VAP approach has no external dependency — it is built into the Kubernetes API server from v1.28. The Kyverno approach provides richer policy reporting and is easier to audit against a policyreport. Use both in defence-in-depth: VAP as the hard enforcement layer and Kyverno for audit reporting.

### RBAC to Limit Ingress Write Access

Restricting who can write `Ingress` objects removes the precondition for annotation injection. Developers should not need direct `Ingress` write access if all ingress changes are managed through GitOps.

```yaml
# ClusterRole for ingress administration — bound to a small ingress-admin group
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ingress-admin
rules:
  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses"]
    verbs: ["create", "update", "patch", "delete", "get", "list", "watch"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses/status"]
    verbs: ["get", "list", "watch"]
---
# ClusterRole for developers — read-only Ingress access
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ingress-reader
rules:
  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses"]
    verbs: ["get", "list", "watch"]
---
# Bind the ingress-admin role to the GitOps service account only
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ingress-admin-binding
subjects:
  - kind: ServiceAccount
    name: argocd-application-controller
    namespace: argocd
roleRef:
  kind: ClusterRole
  name: ingress-admin
  apiGroup: rbac.authorization.k8s.io
```

With this structure, `Ingress` create and update operations only succeed when initiated by the ArgoCD (or Flux) service account, which applies changes from a Git repository subject to PR review. Developers who attempt `kubectl apply` on an `Ingress` manifest directly will receive a 403. This forces annotation changes through the GitOps pipeline where they are subject to diff review before application.

Verify developer RBAC is read-only:

```bash
kubectl auth can-i create ingress --as=developer-user -n production
# Expected: no
kubectl auth can-i create ingress --as=system:serviceaccount:argocd:argocd-application-controller
# Expected: yes
```

### Monitoring ingress-nginx for New Annotation Vulnerabilities

Because the patch-gap window is a primary risk, proactive monitoring of the ingress-nginx repository shortens the time between a fix commit and operator awareness.

**Watch for security-relevant commits to the annotation and template packages:**

```bash
gh api repos/kubernetes/ingress-nginx/commits \
  --jq '.[] | select(.commit.message | test("sanitiz|escape|inject|annotation|template"; "i")) | {sha: .sha[0:8], message: .commit.message}'
```

Run this query against the `main` branch and the active release branches (`release-1.13`, `release-1.14`) on a daily schedule. A commit touching `internal/ingress/annotations/` or `rootfs/etc/nginx/template/nginx.tmpl` that contains words like "escape", "sanitize", or "inject" in the commit message is a strong signal that a security fix is in flight.

**Watch the GitHub releases feed:**

```
https://github.com/kubernetes/ingress-nginx/releases.atom
```

Add this URL to your RSS reader or feed monitoring tooling. New releases appear within minutes of the tag being pushed.

**Subscribe to the security announce list:**

```
kubernetes-security-announce@googlegroups.com
```

This list receives official CVE announcements, though for ingress-nginx these have historically appeared after patches are already public.

**Automate version monitoring with Renovate or Dependabot:**

In your Helm values repository, add a Renovate configuration that tracks the ingress-nginx Helm chart version:

```json
{
  "regexManagers": [
    {
      "fileMatch": ["helmfile\\.yaml$", "values.*\\.yaml$"],
      "matchStrings": [
        "version: (?<currentValue>[\\d.]+)\\s+# ingress-nginx"
      ],
      "depNameTemplate": "ingress-nginx",
      "datasourceTemplate": "helm",
      "registryUrlTemplate": "https://kubernetes.github.io/ingress-nginx"
    }
  ]
}
```

This raises a PR automatically when a new ingress-nginx chart version is published, reducing the patch gap to the time between the PR being raised and being merged.

### Network-Level Mitigation

If annotation injection cannot be immediately blocked through admission control (e.g., during a phased rollout of Kyverno policies or a break-glass situation), a WAF in front of ingress-nginx can detect some exploitation patterns.

Configure WAF rules to alert on HTTP responses that contain nginx configuration directive strings that should never appear in application output: `proxy_pass`, `access_by_lua`, `rewrite ^`. These patterns in a response body indicate that the nginx configuration has been manipulated to expose configuration directives to downstream clients — a reliable indicator of active exploitation.

Note that WAF-based detection is a detective control, not a preventive one. It does not block the injection; it identifies that injection has occurred and can be used to trigger incident response. Do not rely on it as a substitute for patching and admission control.

## Expected Behaviour

| Signal | Unpatched ingress-nginx (≤ v1.13.7) | Patched + Admission Controls (v1.14.4+) |
|---|---|---|
| `rewrite-target` annotation containing `"` character | Nginx config template renders with unescaped quote; injected directives execute on next nginx reload | Annotation rejected at admission with 403 from VAP/Kyverno before persisting to etcd |
| `configuration-snippet` annotation with `proxy_pass` redirect | Directive injected into server block; all traffic proxied to attacker-controlled host | Rejected if `allowSnippetAnnotations: false`; additionally rejected by annotation character validation |
| Patch-gap attacker scanning Kubernetes API for ingress-nginx version label | `app.kubernetes.io/version: 1.13.7` label on controller Deployment visible; cluster identified as vulnerable | Same label visible — version discovery is not preventable — but Renovate PR already merged; cluster on v1.14.4 |
| Kyverno annotation regex validation rejects Ingress | Policy not present; malicious Ingress accepted and applied | `ClusterPolicy validate-ingress-annotations` returns admission error with policy name and message |
| Developer attempts direct `kubectl apply` of Ingress with write RBAC | Succeeds if developer has namespace-level Ingress write permission | Rejected with 403 — developer RBAC is read-only; write is restricted to GitOps service account |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| `allowSnippetAnnotations: false` | Eliminates the highest-risk annotation injection vectors (`configuration-snippet`, `server-snippet`) without requiring admission controller changes | Breaks any existing Ingress that uses snippet annotations for legitimate nginx customisation (custom headers, auth sub-requests, rate limiting logic) | Audit all Ingress objects for snippet annotations before disabling: `kubectl get ingress -A -o json \| jq '.items[] \| select(.metadata.annotations \| has("nginx.ingress.kubernetes.io/configuration-snippet"))'`; migrate to controller-level config where possible |
| Strict annotation character regex (`^[a-zA-Z0-9/${}._-]+$`) | Blocks injection via quote, semicolon, newline characters across all nginx annotations | Rejects some valid rewrite-target patterns that use regex capture groups requiring characters like `(`, `)`, `|`, or `+` | Expand the regex allowlist to include specific regex meta-characters that are safe in the nginx context: `^[a-zA-Z0-9/${}._|()+*?^-]+$`; validate expanded pattern against known-good rewrite rules before deploying |
| RBAC Ingress write restriction to GitOps SA only | Removes the direct Kubernetes API path for annotation injection; all changes go through PR review | Slows developer self-service — updating an Ingress annotation requires a Git commit, PR, review, and GitOps sync | Set short ArgoCD sync intervals (2–5 minutes) and enable ArgoCD `--auto-prune` so approved changes apply quickly; provide developers read access so they can inspect the live state without write access |
| GitOps-only Ingress changes | Creates audit trail; annotations reviewed in PR diffs before application | Deployment velocity impact for Ingress changes during incidents; cannot hotfix an Ingress annotation without a Git push | Maintain a break-glass ClusterRoleBinding for the `ingress-admin` role bound to a named SRE account, gated behind approval in PagerDuty or equivalent; rotate binding after incident |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Annotation regex too strict — rejects valid Ingress with legitimate rewrite pattern | Application returns 404 or traffic not rewritten correctly; Ingress exists but nginx config lacks rewrite directive; developers report app unreachable | Kyverno PolicyReport shows the Ingress as violating `validate-ingress-annotations`; `kubectl describe ingress <name>` shows annotation is present but `kubectl get events` shows admission rejection | Identify the specific character(s) triggering the rejection; update the Kyverno regex to permit those characters if they are safe in nginx context; switch policy to `Audit` during the fix window to restore traffic |
| ingress-nginx upgrade from v1.13.7 to v1.14.4 breaks existing snippet-dependent apps | HTTP 502 or unexpected responses from apps that relied on snippet-injected nginx behaviour; may not be immediately apparent if snippets added custom headers rather than routing logic | Compare nginx.conf before and after upgrade: `kubectl exec -n ingress-nginx deploy/ingress-nginx-controller -- nginx -T \| grep -A5 location`; check for missing directives | Identify affected Ingress objects using the audit command above; migrate snippet logic to supported annotations or nginx ConfigMap `http-snippet`/`server-snippet` at the controller level (which is controlled and reviewed) |
| Kyverno policy mis-scoped — ValidatingAdmissionPolicyBinding applies to wrong namespace, or ClusterPolicy `exclude` block omits a namespace | Admission policy does not apply to the target namespace; malicious annotations in that namespace are accepted; or policy blocks Ingress objects in a namespace it should not cover | `kubectl get clusterpolicies -o yaml` and verify `match`/`exclude` selectors; `kubectl auth can-i create ingress --as=...` to confirm enforcement; `kubectl get policyreport -A` shows which namespaces have violations reported | Correct the namespace selector in the policy spec; re-apply; run `kubectl get ingress -A` and re-validate all Ingress objects against the corrected policy using `kyverno apply` CLI |
| CVE-2026-3288 re-introduced in a fork or custom build of ingress-nginx | Clusters using a forked or internally patched ingress-nginx image remain vulnerable after the official v1.14.4 release; annotation injection succeeds despite operators believing they are patched | Check the actual image digest, not just the tag: `kubectl get pods -n ingress-nginx -o jsonpath='{.items[0].spec.containers[0].imageID}'`; compare against the published digest for the official v1.14.4 image at `registry.k8s.io/ingress-nginx/controller` | Switch to the official upstream image; if a fork is required, cherry-pick the specific sanitisation commit from ingress-nginx `main` and verify the template diff matches the upstream fix; enforce the image registry in admission policy to prevent non-official builds |

## Related Articles

- [ingress Controller Comparison: ingress-nginx vs Contour vs Traefik vs Gateway API](/articles/kubernetes/ingress-controller-comparison/)
- [Kubernetes Admission Control: From PodSecurity Standards to Custom OPA/Kyverno Policies](/articles/kubernetes/kubernetes-admission-control/)
- [Gateway API Security: Migrating from Ingress to HTTPRoute with AuthPolicy](/articles/kubernetes/gateway-api-security/)
- [ValidatingAdmissionPolicy and CEL: Replacing Webhooks with Built-In Kubernetes Policy](/articles/kubernetes/validating-admission-policy-cel/)
- [Vulnerability Management Program: From CVE Intake to SLA Enforcement](/articles/cross-cutting/vulnerability-management-program/)
