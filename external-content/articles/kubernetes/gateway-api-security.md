---
title: "Gateway API Security Patterns: Multi-Team Routing, ReferenceGrant, and Delegated Trust on Kubernetes"
description: "Gateway API replaces Ingress with a multi-role model that separates infrastructure, cluster operator, and application developer concerns. New surface, new threat model."
slug: "gateway-api-security"
date: 2026-04-24
lastmod: 2026-04-24
category: "kubernetes"
tags: ["kubernetes", "gateway-api", "ingress", "network-security", "multi-tenancy"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 164
difficulty: "intermediate"
estimated_reading_time: 17
published: true
layout: article.njk
permalink: "/articles/kubernetes/gateway-api-security/index.html"
---

# Gateway API Security Patterns: Multi-Team Routing, ReferenceGrant, and Delegated Trust on Kubernetes

## Problem

Kubernetes Ingress has a single resource type and a single implicit trust model: whoever creates the `Ingress` owns the routing rule. In a multi-team cluster this is a blunt instrument. Any namespace admin with `ingresses.create` can declare routes for any host, including those owned by other teams.

Gateway API ([v1.0 GA in 2023](https://gateway-api.sigs.k8s.io/)) splits Ingress into three resources aligned with three roles:

- `GatewayClass` — the implementation (NGINX, Envoy, Cilium, Istio, Google Cloud, AWS ALB). Owned by the infrastructure provider.
- `Gateway` — a listener (port, protocol, TLS). Owned by the cluster operator.
- `HTTPRoute` / `GRPCRoute` / `TLSRoute` / `TCPRoute` — the routing rules. Owned by the application team.

That role separation is the security model. Done right, it means a compromised or careless application namespace can only bind routes under its own hostname, to its own backend Services, across namespace boundaries it has been explicitly granted. Done wrong, it is Ingress with extra CRDs.

The specific gaps in a default Gateway API installation:

- `Gateway` listeners can accept routes from `AllowedRoutes: namespaces: from: All`, giving every namespace in the cluster equal access.
- `HTTPRoute` can forward to a `Service` in any namespace unless `ReferenceGrant` is enforced.
- `HTTPRoute` can claim any hostname on a listener unless hostname ownership is bound to namespaces via policy.
- TLS termination at the Gateway leaves backend traffic in cleartext unless `BackendTLSPolicy` is configured.
- Filters (header manipulation, URL rewriting, redirects) run in the data plane and can be used to spoof client identity to backends.

This article covers listener isolation, cross-namespace reference control via `ReferenceGrant`, hostname ownership, backend TLS enforcement, and RBAC patterns for the three Gateway API roles.

**Target systems:** Kubernetes 1.28+ with Gateway API v1.0 CRDs installed. Works with Envoy Gateway, Istio 1.20+, Cilium 1.14+, NGINX Gateway Fabric, and Kuma.

## Threat Model

- **Adversary:** Two distinct adversaries. (1) A malicious or compromised application namespace admin attempting to hijack traffic destined for other teams. (2) An external attacker who has compromised an internal Service and is using its network position to reach the control plane via the Gateway.
- **Access level:** Namespace-scoped `edit` role or ServiceAccount with `httproutes.create`.
- **Objective:** Intercept traffic intended for another team's service (credential theft, request manipulation), redirect external users to an attacker-controlled backend, expose an internal-only Service to the public Gateway.
- **Blast radius:** Without hostname binding, any namespace can claim `api.company.com` and receive its traffic. Without `ReferenceGrant`, any namespace can forward traffic to any Service in any namespace, bypassing `NetworkPolicy`. Without `BackendTLSPolicy`, sniffed east-west traffic reveals full request bodies after Gateway termination.

## Configuration

### Step 1: Listener Isolation via AllowedRoutes

Every `Gateway` listener declares which namespaces may attach routes. Default to restricted:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: public-gateway
  namespace: gateway-system
spec:
  gatewayClassName: envoy
  listeners:
    - name: https-public
      port: 443
      protocol: HTTPS
      hostname: "*.public.example.com"
      tls:
        mode: Terminate
        certificateRefs:
          - name: public-example-com-tls
      # Only namespaces labeled gateway-tier=public can attach routes.
      allowedRoutes:
        namespaces:
          from: Selector
          selector:
            matchLabels:
              gateway-tier: public
        kinds:
          - kind: HTTPRoute
    - name: https-internal
      port: 443
      protocol: HTTPS
      hostname: "*.internal.example.com"
      tls:
        mode: Terminate
        certificateRefs:
          - name: internal-example-com-tls
      allowedRoutes:
        namespaces:
          from: Selector
          selector:
            matchLabels:
              gateway-tier: internal
        kinds:
          - kind: HTTPRoute
```

Label application namespaces:

```bash
kubectl label namespace team-web gateway-tier=public
kubectl label namespace team-admin gateway-tier=internal
kubectl label namespace team-batch gateway-tier=internal
```

Namespaces without the `gateway-tier` label cannot attach routes to either listener. Reserve `from: All` for development clusters only.

### Step 2: Hostname Ownership Binding

Listener hostname wildcards (`*.public.example.com`) are necessary but not sufficient. Without further constraint, any namespace matching the label selector can claim `payments.public.example.com` if `team-web` already uses `app.public.example.com`.

Enforce hostname ownership through policy. With Kyverno:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: enforce-route-hostname-ownership
spec:
  validationFailureAction: Enforce
  rules:
    - name: namespace-owns-hostname
      match:
        resources:
          kinds:
            - HTTPRoute
      validate:
        message: "HTTPRoute hostname must match the namespace's assigned prefix."
        deny:
          conditions:
            all:
              - key: "{{ request.object.spec.hostnames[] }}"
                operator: AnyNotIn
                value: "{{ request.namespace }}.public.example.com"
```

For stricter control, maintain an explicit hostname→namespace mapping in a ConfigMap and validate against it:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: hostname-ownership
  namespace: gateway-system
data:
  ownership.yaml: |
    team-web:
      - app.public.example.com
      - www.public.example.com
    team-payments:
      - pay.public.example.com
```

A validating webhook or OPA Gatekeeper policy reads the ConfigMap and rejects HTTPRoutes whose `hostnames` are not listed for the submitting namespace.

### Step 3: Cross-Namespace References via ReferenceGrant

By default, an `HTTPRoute` in namespace `team-web` cannot forward traffic to a `Service` in namespace `team-shared`. Allow it only for specific resources via `ReferenceGrant`:

```yaml
# In the namespace that owns the target Service.
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-web-to-shared-api
  namespace: team-shared
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      namespace: team-web
  to:
    - group: ""
      kind: Service
      name: shared-api
```

Then in `team-web`:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: app-route
  namespace: team-web
spec:
  parentRefs:
    - name: public-gateway
      namespace: gateway-system
      sectionName: https-public
  hostnames: ["app.public.example.com"]
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /shared
      backendRefs:
        - group: ""
          kind: Service
          name: shared-api
          namespace: team-shared   # Cross-namespace reference.
          port: 8080
```

Without the `ReferenceGrant`, the HTTPRoute shows `status.parents[].conditions[type=ResolvedRefs, status=False, reason=RefNotPermitted]`. The traffic is not forwarded.

### Step 4: Backend TLS via BackendTLSPolicy

Terminating TLS at the Gateway leaves backend traffic in cleartext. For services that require end-to-end encryption (PCI, healthcare, zero-trust networks), re-encrypt with `BackendTLSPolicy`:

```yaml
apiVersion: gateway.networking.k8s.io/v1alpha3
kind: BackendTLSPolicy
metadata:
  name: backend-tls-shared-api
  namespace: team-shared
spec:
  targetRefs:
    - group: ""
      kind: Service
      name: shared-api
  validation:
    caCertificateRefs:
      - group: ""
        kind: ConfigMap
        name: internal-ca-bundle
    hostname: shared-api.team-shared.svc.cluster.local
    subjectAltNames:
      - type: Hostname
        hostname: shared-api.team-shared.svc.cluster.local
```

The Gateway now establishes a TLS connection to the backend, validating its certificate against the listed CA, requiring the backend hostname to match the SAN. For mutual TLS, use the provider-specific extension (Envoy Gateway supports `ClientCertificateRef`).

### Step 5: RBAC for the Three Roles

Align Kubernetes RBAC with the three Gateway API roles.

```yaml
# Infrastructure provider: manages GatewayClass and CRDs.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: gateway-infrastructure-provider
rules:
  - apiGroups: ["gateway.networking.k8s.io"]
    resources: ["gatewayclasses"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
---
# Cluster operator: manages Gateway resources.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: gateway-cluster-operator
rules:
  - apiGroups: ["gateway.networking.k8s.io"]
    resources: ["gateways"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["gateway.networking.k8s.io"]
    resources: ["gatewayclasses"]
    verbs: ["get", "list", "watch"]
---
# Application developer: namespace-scoped, creates Routes only.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: gateway-app-developer
  namespace: team-web
rules:
  - apiGroups: ["gateway.networking.k8s.io"]
    resources: ["httproutes", "grpcroutes"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["gateway.networking.k8s.io"]
    resources: ["gateways"]
    verbs: ["get", "list", "watch"]   # Read-only on Gateways they attach to.
```

Explicitly do not grant application developers `gateway.networking.k8s.io/gateways` write access. A compromised developer credential cannot redirect cluster traffic by modifying a listener.

## Expected Behaviour

| Signal | Without Controls | With Controls |
|--------|------------------|---------------|
| Cross-namespace Service reference | Any HTTPRoute forwards to any Service | Only Services covered by a ReferenceGrant accept traffic |
| Route attachment to listener | Any namespace attaches routes | Only namespaces matching the listener's selector |
| Hostname squatting | Any namespace claims any hostname | Policy rejects mismatched hostnames |
| Backend TLS | Cleartext between Gateway and Pod | TLS verified against internal CA |
| Route visibility | `kubectl describe httproute -A` shows all | Same; observability is intentional |
| Gateway modification by app team | Possible with cluster-admin spill | Blocked by RBAC (app role cannot modify Gateways) |

Verify a correctly configured setup:

```bash
# A ReferenceGrant-covered route resolves cleanly.
kubectl get httproute -n team-web app-route \
  -o jsonpath='{.status.parents[].conditions[?(@.type=="ResolvedRefs")].status}'
# True

# A route to a Service without ReferenceGrant fails.
kubectl get httproute -n team-web bad-route \
  -o jsonpath='{.status.parents[].conditions[?(@.type=="ResolvedRefs")].reason}'
# RefNotPermitted

# Listener selector rejects routes from unlabeled namespaces.
kubectl get gateway -n gateway-system public-gateway \
  -o jsonpath='{.status.listeners[?(@.name=="https-public")].attachedRoutes}'
# Matches expected count; unapproved namespaces do not increment it.
```

## Trade-offs

| Control | Security Benefit | Operational Cost | Mitigation |
|---------|-----------------|------------------|------------|
| Listener AllowedRoutes selectors | Hard boundary for route attachment | Namespaces need labels before they can publish routes | Add namespace labeling to provisioning automation (Terraform, Crossplane, Backstage scaffolder). |
| ReferenceGrant enforcement | Blocks lateral traffic forwarding | Every legitimate cross-namespace reference needs a corresponding Grant | Standardize shared services with a documented set of Grants in a central repo; review in PR like any other IAM change. |
| Hostname ownership policy | Prevents team-vs-team traffic hijack | Policy maintenance; false positives break deploys | Start with `Audit` mode in Kyverno/Gatekeeper for 2 weeks, only switch to `Enforce` after reviewing violations. |
| BackendTLSPolicy | End-to-end encryption, satisfies PCI/HIPAA | Certificate management at the pod level | Integrate with cert-manager's Certificate resources and inject via a mutating webhook rather than hand-rolling secrets. |
| Role-based RBAC split | Blast radius of a compromised app credential is bounded to routes | Onboarding friction: new teams need two RoleBindings (app role + any ReferenceGrants) | Codify the three roles as ClusterRoles and automate binding creation when namespaces are provisioned. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Missing ReferenceGrant | Route status shows `RefNotPermitted`; backend returns 503 | `kubectl get httproute -o yaml` in the owning namespace | Add ReferenceGrant in the target namespace. Verify direction: Grants live in the namespace that owns the referenced object. |
| Listener selector too restrictive | New team namespace cannot publish any routes | `attachedRoutes: 0` on a listener that should be receiving them | Check the namespace has the correct `gateway-tier` label. Do not relax the selector; fix the missing label. |
| Hostname policy blocks legitimate route | Developer PR cannot deploy; policy violation in admission webhook | Kyverno/Gatekeeper violation logs | Update the hostname ownership ConfigMap, not the policy. Keep policy logic generic. |
| BackendTLSPolicy CA rotation missed | Gateway fails backend handshake; 503s to users | Gateway logs show `certificate verify failed`; Pod logs show incoming cleartext (if not using BackendTLSPolicy on Pod side) | Rotate CA via cert-manager's `Issuer` resource. Verify `BackendTLSPolicy` references the new CA ConfigMap before removing the old. |
| App developer escalates via `kubectl edit gateway` | Unexpected listener added; unauthorized route attaches | Audit log entry `verb=update resource=gateways user=<team-sa>` | Review RBAC: the app developer role should not have `gateways.update`. Check for inherited permissions from ClusterRoleBindings. |
| Gateway implementation bug leaks headers | Client identity header present on backend request from unrelated route | Backend audit logs show `X-Forwarded-User` from an unexpected hostname | Upgrade Gateway implementation. File CVE with the provider. Temporarily strip the header via `HTTPRoute.filters`. |

## When to Consider a Managed Alternative

Managing Gateway API on self-hosted clusters requires CRD installation, implementation upgrades, TLS certificate lifecycle, and policy enforcement on every route change (4-10 hours/month for a 50-namespace cluster).

- **Google Cloud Gateway Controller:** Manages the Gateway implementation for GKE. Handles control-plane availability, upgrades, and region-level redundancy. You retain application-team RBAC responsibility.
- **AWS Gateway API Controller for VPC Lattice:** Provisions AWS VPC Lattice services from Gateway API resources. Offloads the data plane entirely. Does not cover all Gateway API features (TLS passthrough, advanced filters).
- **Envoy Gateway managed by Tetrate, Solo.io, or Kuma / Kong Gateway Enterprise:** Keeps the implementation in-cluster but offloads upgrades and CVE patching.

## Related Articles

- [Kubernetes Ingress Controller Comparison: NGINX, Traefik, Envoy, Contour](/articles/kubernetes/ingress-controller-comparison/)
- [Kubernetes Admission Control: From PodSecurity Standards to Custom OPA/Kyverno Policies](/articles/kubernetes/kubernetes-admission-control/)
- [Network Policies for Zero-Trust Kubernetes Networking](/articles/kubernetes/kubernetes-network-policies/)
- [mTLS in Service Mesh: Zero-Trust Networking Between Services](/articles/network/mtls-service-mesh/)
- [RBAC Design Patterns for Multi-Team Kubernetes Clusters](/articles/kubernetes/rbac-design-patterns/)
