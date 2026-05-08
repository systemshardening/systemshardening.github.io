---
title: "Service Mesh Egress Gateway Patterns: Bounded Outbound Traffic in Istio Clusters"
description: "Pod egress in a service mesh is a per-Pod decision; egress gateways centralize, audit, and bound it. The pattern that finally makes 'where can my workload reach' answerable."
slug: "istio-egress-gateway"
date: 2026-04-29
lastmod: 2026-04-29
category: "network"
tags: ["istio", "egress", "service-mesh", "kubernetes", "network-policy"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 228
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/network/istio-egress-gateway/index.html"
---

# Service Mesh Egress Gateway Patterns: Bounded Outbound Traffic in Istio Clusters

## Problem

Outbound traffic from a Kubernetes cluster is a tangled topic. By default Istio's sidecar proxies forward outbound calls directly through the workload Pod's network — egress is whatever the Pod can reach via the cluster's CNI / network policy.

Three problems compound:

- **Per-Pod egress decisions** mean operators can't centrally answer "where can production cluster talk to" without enumerating every NetworkPolicy + ServiceEntry.
- **TLS origination at the Pod** means each app is responsible for proper certificate handling for outbound HTTPS to third parties.
- **Audit per Pod** is partial — Istio's per-Pod telemetry shows the Pod made an outbound call, but cross-Pod patterns (multiple Pods to the same destination) are reconstructed by query, not seen at a single point.

Egress gateways consolidate these. All outbound traffic from the mesh routes through a designated set of `egressgateway` Pods. Those Pods do the TLS origination, apply egress-specific policy, log the egress at one point, and become the central observability surface.

By 2026 the pattern is mature in Istio (since 1.x), Linkerd 2.x (with the egress-gateway beta), and Kuma. Enterprise deployments often deploy egress gateways for compliance — every external API call is auditable, attributable, and rate-limitable from one place.

The specific gaps in default Istio without egress gateway:

- Each Pod's sidecar handles its own outbound TLS; certificate trust roots configured per-Pod or cluster-wide.
- NetworkPolicy is per-namespace; no central record of approved external destinations.
- Outbound DNS goes through the cluster's resolver; egress depends on what that resolver answers.
- Enterprise compliance (PCI-DSS, HIPAA) often requires "all egress observable from a single point" — each Pod's egress doesn't satisfy.
- Failure mode: a compromised Pod's sidecar doesn't restrict where it can reach; the Pod's own egress path is the only enforcement.

This article covers the egress-gateway architecture, ServiceEntry + Sidecar configuration, traffic-routing patterns, TLS origination, mTLS to the gateway, and the audit/policy benefits. Examples are Istio-specific; Linkerd / Kuma have analogous concepts.

**Target systems:** Istio 1.22+, Kubernetes 1.28+, with optional `egress-gateway` Pod replicas. Concepts apply to other meshes; vendor-specific syntax differs.

## Threat Model

- **Adversary 1 — Compromised application Pod:** an attacker has code execution in a workload Pod. Wants to exfiltrate data or pivot to external services beyond the workload's intended reach.
- **Adversary 2 — Misconfigured NetworkPolicy:** a Pod has more egress than intended due to overly-broad policy.
- **Adversary 3 — DNS-based attack (DNS rebinding):** Pod resolves an external hostname; the resolver returns an internal IP.
- **Adversary 4 — Compliance auditor:** regulator wants a single source of truth for "every external API call this cluster makes."
- **Adversary 5 — Cross-tenant egress observation:** in a multi-tenant cluster, Tenant A wants to know what Tenant B is calling externally.
- **Access level:** Adversary 1 has Pod execution. Adversary 2 has cluster-config-modify rights. Adversary 3 controls upstream DNS. Adversary 4 has audit access. Adversary 5 has only Tenant-A-level cluster access.
- **Objective:** Reach external services beyond intended scope; exfiltrate; satisfy or avoid compliance requirements.
- **Blast radius:** without egress gateway, a compromised Pod's egress is bounded only by NetworkPolicy and the Pod's own DNS; with egress gateway, egress is bounded centrally and observable from one point.

## Configuration

### Step 1: Deploy Egress Gateway

Istio's egress-gateway is a separate set of Envoy Pods, typically in `istio-system` or a dedicated namespace.

```yaml
# istio-egress-gateway.yaml
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
spec:
  components:
    egressGateways:
      - name: istio-egressgateway
        enabled: true
        k8s:
          replicaCount: 3
          resources:
            requests: {cpu: 100m, memory: 128Mi}
            limits: {cpu: 1, memory: 1Gi}
          hpaSpec:
            minReplicas: 3
            maxReplicas: 10
```

The gateway Pods receive traffic from sidecars destined for "outside the mesh." Configuration determines which traffic routes through them.

### Step 2: ServiceEntry for External Destinations

For every external destination the mesh should reach, create a `ServiceEntry`:

```yaml
apiVersion: networking.istio.io/v1
kind: ServiceEntry
metadata:
  name: stripe-api
  namespace: payments
spec:
  hosts:
    - api.stripe.com
  ports:
    - number: 443
      name: https
      protocol: HTTPS
  resolution: DNS
  location: MESH_EXTERNAL
```

`MESH_EXTERNAL` declares that this is an outside-mesh endpoint. Without ServiceEntry, the mesh sidecar treats the destination as unknown; egress depends on `outboundTrafficPolicy`.

Set the cluster-wide outboundTrafficPolicy to `REGISTRY_ONLY`:

```yaml
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
spec:
  meshConfig:
    outboundTrafficPolicy:
      mode: REGISTRY_ONLY
```

Now traffic to any host *not* declared in a ServiceEntry is rejected. The cluster's egress is exactly the set of declared ServiceEntries — auditable, reviewable, version-controlled.

### Step 3: Route Through Egress Gateway

Add a `Gateway` and `VirtualService` to route ServiceEntry-defined external traffic through the egress gateway:

```yaml
apiVersion: networking.istio.io/v1
kind: Gateway
metadata:
  name: istio-egressgateway-stripe
  namespace: istio-system
spec:
  selector:
    istio: egressgateway
  servers:
    - port: {number: 443, name: tls, protocol: TLS}
      hosts: [api.stripe.com]
      tls: {mode: PASSTHROUGH}

---
apiVersion: networking.istio.io/v1
kind: VirtualService
metadata:
  name: route-stripe-via-egressgateway
  namespace: payments
spec:
  hosts: [api.stripe.com]
  tls:
    - match:
        - port: 443
          sniHosts: [api.stripe.com]
      route:
        - destination:
            host: istio-egressgateway.istio-system.svc.cluster.local
            port: {number: 443}
            subset: stripe
          weight: 100

---
apiVersion: networking.istio.io/v1
kind: DestinationRule
metadata:
  name: egressgateway-stripe
  namespace: istio-system
spec:
  host: istio-egressgateway.istio-system.svc.cluster.local
  subsets:
    - name: stripe
      trafficPolicy:
        portLevelSettings:
          - port: {number: 443}
            tls: {mode: ISTIO_MUTUAL, sni: api.stripe.com}
```

Application Pods make HTTPS calls to `api.stripe.com`; the sidecar tunnels them through the egress gateway via mTLS; the gateway terminates inside-mesh mTLS, originates outbound TLS to the real Stripe API.

### Step 4: TLS Origination at the Gateway

The egress gateway can take cleartext from inside the mesh and originate TLS outbound. Useful when application code expects "HTTP" but needs HTTPS to the actual external service:

```yaml
apiVersion: networking.istio.io/v1
kind: ServiceEntry
metadata:
  name: external-api
spec:
  hosts: [external-api.example.com]
  ports:
    - number: 80
      name: http
      protocol: HTTP
    - number: 443
      name: https
      protocol: HTTPS
  resolution: DNS
  location: MESH_EXTERNAL

---
apiVersion: networking.istio.io/v1
kind: DestinationRule
metadata:
  name: egress-tls-origination
spec:
  host: external-api.example.com
  trafficPolicy:
    portLevelSettings:
      - port: {number: 443}
        tls:
          mode: SIMPLE
          credentialName: external-api-cert   # optional client cert
          sni: external-api.example.com
```

Application Pods can call `http://external-api.example.com` (no TLS needed in the application code); the gateway adds TLS at the perimeter. Useful for legacy applications or for services calling APIs that don't natively support modern TLS.

### Step 5: Egress Observability

Every outbound call routes through the gateway; the gateway is your central observation point.

```bash
# Inspect Envoy access logs at the egress gateway.
kubectl logs -n istio-system -l istio=egressgateway --tail 50
# 1.2.3.4 - "GET /v1/charges HTTP/1.1" 200 stripe.com

# Standard Istio metrics show per-destination counts.
istio_request_total{destination_service_namespace="external-stripe", source_workload="payments-api"}
```

Centralize:

- Set up Prometheus scraping at the egress-gateway specifically.
- Stream Envoy access logs to a SIEM with the `EGRESS_GATEWAY` label.
- Alert on unexpected destinations (anything not in the ServiceEntry registry).

### Step 6: Per-Tenant / Per-Namespace Restrictions

Limit which namespaces can use which ServiceEntries via `Sidecar` resources:

```yaml
apiVersion: networking.istio.io/v1
kind: Sidecar
metadata:
  name: payments-egress
  namespace: payments
spec:
  egress:
    - hosts:
        - "./*"   # all in same namespace
        - "istio-system/*"   # control plane
        - "external/api.stripe.com"   # specifically allow stripe
        # Other ServiceEntries NOT listed are blocked from this namespace.
```

The Sidecar resource constrains the sidecar's outbound configuration to a specific subset. Even though `api.openai.com` may have a cluster-wide ServiceEntry, the payments namespace's sidecar can't reach it unless explicitly allowed.

### Step 7: AuthorizationPolicy at the Egress Gateway

For finer control, apply an `AuthorizationPolicy` at the egress gateway:

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: egress-stripe-allowed-callers
  namespace: istio-system
spec:
  selector:
    matchLabels:
      istio: egressgateway
  action: ALLOW
  rules:
    - from:
        - source:
            namespaces: [payments]
      to:
        - operation:
            hosts: [api.stripe.com]
    - from:
        - source:
            namespaces: [auth]
      to:
        - operation:
            hosts: [auth0.com]
```

Only the payments namespace can use the gateway to reach `api.stripe.com`. The auth namespace can reach `auth0.com`. Cross-cluster lateral movement is blocked at the egress boundary.

### Step 8: Egress Rate Limiting

Bound per-namespace outbound rate:

```yaml
apiVersion: networking.istio.io/v1
kind: EnvoyFilter
metadata:
  name: egress-rate-limit-payments
  namespace: istio-system
spec:
  workloadSelector:
    labels:
      istio: egressgateway
  configPatches:
    - applyTo: HTTP_FILTER
      match:
        listener:
          filterChain:
            filter:
              name: envoy.filters.network.http_connection_manager
      patch:
        operation: INSERT_BEFORE
        value:
          name: envoy.filters.http.local_ratelimit
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit
            stat_prefix: egress_rate_limit
            token_bucket:
              max_tokens: 1000
              tokens_per_fill: 1000
              fill_interval: 1s
            response_headers_to_add:
              - append: false
                header:
                  key: X-RateLimit-Reason
                  value: "egress-rate-limit"
```

Caps per-namespace outbound to 1000 req/s. A compromised Pod cannot saturate the gateway's downstream capacity.

### Step 9: Telemetry SLOs

```
istio_egress_requests_total{destination, source_namespace, response_code}
istio_egress_bytes_total{destination, source_namespace, direction}
istio_egress_request_duration_milliseconds{destination}
istio_egress_authz_denied_total{source_namespace, destination}
istio_egress_tls_handshake_failures_total{destination}
```

Alert on:

- `istio_egress_authz_denied_total` rising — likely an attacker probing or misconfigured workload.
- Egress bytes from one namespace disproportionate — possible exfil.
- TLS handshake failures to a specific destination — cert chain issue.

### Step 10: Compliance Reporting

For audits ("show me every external API call from this cluster"):

```bash
# Last 30 days, group by destination + namespace.
prometheus_query '
  sum by (destination_service, source_workload_namespace) (
    increase(istio_request_total{
      reporter="source",
      destination_service_namespace="external"
    }[30d])
  )
'
```

Output is a complete table: which namespace called which external service how many times. Auditor's question answered from one query.

## Expected Behaviour

| Signal | Without egress gateway | With egress gateway |
|--------|-------------------------|----------------------|
| Egress destinations declarable | Per-namespace NetworkPolicy | Per-cluster ServiceEntry registry |
| Audit "where does cluster reach" | Manual enumeration | Single Prometheus query |
| TLS origination | Per-app | Centralized at gateway |
| Per-tenant egress isolation | NetworkPolicy + ServiceEntry | Sidecar + AuthorizationPolicy |
| Outbound rate limit | None | Per-namespace token bucket |
| Cross-tenant observability | Each tenant sees own logs | Central gateway sees all |
| Compliance reporting | Hard | Standard query |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Centralized egress | Audit + policy in one place | Single point of failure | Run gateway in HA (3+ replicas); HPA scaling. |
| `REGISTRY_ONLY` mode | No egress without explicit declaration | All current external endpoints must be declared | Audit current egress; declare; enforce after registration. |
| Per-namespace Sidecar | Strong namespace isolation | Configuration per namespace | Use Helm / Kustomize to standardize per-namespace patterns. |
| TLS origination at gateway | Centralized cert handling | Apps see plaintext to gateway | Acceptable in mesh-internal context; gateway-to-app uses mTLS. |
| Egress AuthorizationPolicy | Fine-grained access | Per-pair config | Standardize patterns; use Kustomize / Helm. |
| Rate limiting | Bounds abuse | False positives during legitimate bursts | Tune per-namespace; alert before block. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Gateway unavailable | All egress fails | Health probe / app errors | HA replicas; HPA scaling. Have a documented break-glass for catastrophic outage (allow direct egress with explicit alert). |
| ServiceEntry missing for a needed destination | App fails with connection error | App logs; egress-gateway authz denied | Add ServiceEntry; for emergency, use REGISTRY_ONLY temporary disable. |
| Stale TLS root | All HTTPS to a destination fails | Gateway logs show cert verify failure | Update CA bundle on the gateway; rotate via cert-manager. |
| AuthorizationPolicy too narrow | Legitimate cross-namespace blocked | Policy violation logs | Loosen policy after review. |
| Rate limit set too low | Legitimate burst rejected | App errors | Profile typical bursts; raise limit. |
| Compromised gateway Pod | Attacker can pivot inside mesh and read all external traffic | Anomalous activity from gateway Pod | Quarantine; rotate the gateway's certificates; investigate compromise vector. |
| DNS resolution drift | ServiceEntry hostname resolves to unexpected IP | Egress destination changes silently | Use IP-allowlist policy at the gateway; audit DNS resolution changes. |

## Related Articles

- [mTLS in Service Mesh: Zero-Trust Networking Between Services](/articles/network/mtls-service-mesh/)
- [Network Policies for Zero-Trust Kubernetes Networking](/articles/kubernetes/kubernetes-network-policies/)
- [Gateway API Security Patterns](/articles/kubernetes/gateway-api-security/)
- [TLS 1.3 on NGINX and Envoy](/articles/network/tls-nginx-envoy/)
- [WireGuard Mesh for Internal Zero-Trust Networking](/articles/network/wireguard-mesh/)
