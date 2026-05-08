---
title: "Linkerd Service Mesh Security Hardening"
description: "Harden Linkerd's automatic mTLS, Server and HTTPRoute authorisation policies, MeshTLSAuthentication, egress control, and multi-cluster federation — the security-first alternative to Istio."
slug: linkerd-service-mesh-security
date: 2026-05-07
lastmod: 2026-05-07
category: network
tags:
  - linkerd
  - service-mesh
  - mtls
  - zero-trust
  - kubernetes
personas:
  - security-engineer
  - platform-engineer
article_number: 506
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/network/linkerd-service-mesh-security/
---

# Linkerd Service Mesh Security Hardening

## The Problem

Every Kubernetes cluster has a large, mostly invisible attack surface: east-west traffic between pods. A single compromised workload — through a vulnerable dependency, a container escape, or a supply-chain incident — can immediately begin sniffing plaintext traffic crossing the pod network. Without mutual authentication, that same workload can impersonate any other service on the cluster. Without authorisation policies, it can reach every open port, including the database and the secret store.

Service meshes solve this by injecting a sidecar proxy into every pod. The proxy intercepts inbound and outbound TCP, performs mTLS handshakes, and enforces access control before traffic reaches application code. The principle is sound. The implementation choices matter enormously for security teams.

Istio is the dominant mesh, but its architecture introduces its own risk surface. Istio bundles Envoy, a 1.2 million-line C++ proxy with a long CVE history: credential-exfiltrating Lua sandbox escapes (CVE-2026-22771), multivalue header RBAC bypasses (CVE-2026-26308), path normalisation bypasses (CVE-2021-39156), header manipulation bypasses (CVE-2022-39278). Every Istio release ships a pinned Envoy build, and patch-gap attacks are a documented pattern — the Envoy fix lands publicly on GitHub days before the Istio advisory, leaving defenders blind while attackers scan. Istio's control plane consumes 1–2 GB of memory at scale, and its CRD surface is enormous: `VirtualService`, `DestinationRule`, `PeerAuthentication`, `AuthorizationPolicy`, `EnvoyFilter`, `ServiceEntry`, `Sidecar`. Misconfiguration risk grows with surface area.

Linkerd takes a fundamentally different approach. The data-plane proxy (`linkerd2-proxy`) is written in Rust, with a memory-safe foundation that eliminates an entire class of vulnerability. The proxy is purpose-built and small — around 10 MB binary, 10–20 MB RSS per pod. Linkerd's CVE history is substantially shorter than Envoy's. mTLS is automatic and on by default: any two meshed pods mutually authenticate without a single line of configuration. The trust model is SPIFFE-compatible and certificate management is built in.

The trade-off is feature scope. Linkerd does not support advanced traffic management (fault injection, traffic mirroring, weighted routing beyond HTTP retries). For teams whose primary requirement is cryptographic identity, automatic mTLS, and fine-grained authorisation, Linkerd's narrower scope is a feature, not a limitation.

**Target systems:** Linkerd 2.14+, Kubernetes 1.28+, cert-manager 1.14+ for externally managed certificates.

## Threat Model

- **Adversary 1 — Compromised pod:** code execution in a workload pod via a vulnerable application dependency. The attacker can sniff pod-network traffic on the local node, forge requests to internal services, and attempt lateral movement to higher-value targets (databases, secrets stores, identity providers).
- **Adversary 2 — Identity spoofing via header injection:** a workload attempts to impersonate another service by injecting a `X-Forwarded-Client-Cert` or similar trust-related header into an HTTP request, hoping the receiving service trusts the header rather than the mTLS certificate chain.
- **Adversary 3 — Unauthorised egress:** a compromised pod initiates outbound connections to external attacker-controlled infrastructure to exfiltrate data or download second-stage payloads.
- **Adversary 4 — Control-plane certificate compromise:** the Linkerd trust anchor (root CA) private key is leaked. An attacker can issue valid workload certificates and impersonate any service in the mesh.
- **Adversary 5 — Cross-cluster lateral movement:** in a multi-cluster setup, a compromised pod in cluster A attempts to reach services in cluster B via the service mirror.
- **Blast radius without hardening:** the entire east-west traffic plane is exposed. Lateral movement is unconstrained by identity. Egress is bounded only by NetworkPolicy, which is easily misconfigured.
- **Blast radius with full Linkerd hardening:** a compromised pod's access is bounded by the `MeshTLSAuthentication` and `AuthorizationPolicy` resources attached to each `Server`. Egress outside the mesh requires traversing a controlled exit point. Cross-cluster traffic requires a valid certificate issued by the remote trust anchor.

## Configuration / Implementation

### Why Linkerd's Rust Proxy Reduces Attack Surface

Before deploying, it is worth understanding the architectural security properties that distinguish Linkerd from Envoy-based meshes.

Linkerd2-proxy is written in Rust and uses the Tokio async runtime with `rustls` for TLS. The memory safety guarantees of Rust eliminate buffer overflows, use-after-free, and out-of-bounds reads — the vulnerability classes responsible for most Envoy CVEs. There is no Lua scripting interface, no WASM extension sandbox to escape, and no dynamically loaded C++ filter chain. The proxy's feature set is deliberately constrained to what a security-focused mesh needs: mTLS termination, HTTP/1.1 and HTTP/2 protocol handling, load balancing, retries, and policy enforcement.

Comparing control-plane resource consumption matters for attack surface too. Istiod maintains a full xDS API server that translates mesh configuration into Envoy configuration for thousands of proxies simultaneously. That complexity — and the memory required to hold configuration for a large cluster — has been a source of bugs. Linkerd's control-plane components (`destination`, `identity`, `proxy-injector`) are each a focused Go binary with a narrow function. The `identity` component issues certificates; `destination` handles service discovery and policy distribution; `proxy-injector` handles sidecar injection via webhook. Each can be audited independently.

### Installing Linkerd with Externally Managed Certificates

The default Linkerd installation generates a self-signed trust anchor in-cluster. For production, the trust anchor should be managed externally so it can be backed by a hardware security module and rotated without disrupting the mesh. cert-manager is the standard approach.

Install cert-manager if not already present:

```bash
helm repo add jetstack https://charts.jetstack.io
helm repo update
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --set installCRDs=true \
  --version v1.14.5
```

Create the trust anchor (root CA). This certificate should have a long validity period because rotating the trust anchor requires re-establishing trust across all meshed pods simultaneously:

```yaml
# linkerd-trust-anchor.yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: linkerd-trust-anchor
  namespace: cert-manager
spec:
  isCA: true
  commonName: root.linkerd.cluster.local
  secretName: linkerd-trust-anchor
  duration: 87600h      # 10 years
  renewBefore: 8760h    # renew 1 year before expiry
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: selfsigned-issuer
    kind: ClusterIssuer
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: selfsigned-issuer
spec:
  selfSigned: {}
```

```bash
kubectl apply -f linkerd-trust-anchor.yaml
```

Create the intermediate CA that Linkerd's `identity` component will use to issue per-workload certificates. Intermediates are rotated more frequently than the trust anchor:

```yaml
# linkerd-identity-issuer.yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: linkerd-identity-issuer
  namespace: linkerd
spec:
  isCA: true
  commonName: identity.linkerd.cluster.local
  secretName: linkerd-identity-issuer
  duration: 8760h       # 1 year
  renewBefore: 720h     # renew 30 days before expiry
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: linkerd-trust-anchor-issuer
    kind: Issuer
---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: linkerd-trust-anchor-issuer
  namespace: linkerd
spec:
  ca:
    secretName: linkerd-trust-anchor
```

```bash
kubectl create namespace linkerd
kubectl apply -f linkerd-identity-issuer.yaml
```

Install the Linkerd CLI and deploy the control plane using the external certificates:

```bash
# Install the CLI (verify checksum before use in production)
curl --proto '=https' --tlsv1.2 -sSfL https://run.linkerd.io/install | sh

# Validate cluster prerequisites
linkerd check --pre

# Extract the trust anchor PEM for the Helm values
TRUST_ANCHOR=$(kubectl get secret linkerd-trust-anchor \
  -n cert-manager -o jsonpath='{.data.tls\.crt}' | base64 -d)

# Install the CRDs
linkerd install --crds | kubectl apply -f -

# Install the control plane with external certificate management
linkerd install \
  --identity-trust-anchors-pem="$TRUST_ANCHOR" \
  --identity-issuer-certificate-file=<(kubectl get secret linkerd-identity-issuer \
      -n linkerd -o jsonpath='{.data.tls\.crt}' | base64 -d) \
  --identity-issuer-key-file=<(kubectl get secret linkerd-identity-issuer \
      -n linkerd -o jsonpath='{.data.tls\.key}' | base64 -d) \
  | kubectl apply -f -

linkerd check
```

Verify the identity certificates are correctly chained:

```bash
# Show the full certificate chain for the identity component
linkerd check --proxy

# Inspect the issuer certificate currently in use
kubectl get secret linkerd-identity-issuer -n linkerd \
  -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -text
```

### Enabling Automatic mTLS

Linkerd enables mTLS by default for all meshed pods. Enable sidecar injection per namespace using an annotation:

```bash
kubectl annotate namespace payments linkerd.io/inject=enabled
kubectl annotate namespace api linkerd.io/inject=enabled

# Restart existing deployments to trigger injection
kubectl rollout restart deployment -n payments
kubectl rollout restart deployment -n api
```

Verify mTLS is active on all edges:

```bash
# Show secured/unsecured edges between deployments
linkerd viz edges deployment -n payments

# Expected output:
# SRC           DST           SRC_NS    DST_NS    SECURED
# frontend      checkout      payments  payments  true
# checkout      inventory     payments  payments  true

# Confirm no plaintext edges exist
linkerd viz edges deployment -n payments | grep -v SECURED | grep false
# Should return no output
```

Linkerd's default policy for a meshed namespace without explicit `Server` resources is `all-unauthenticated`: meshed pods accept traffic from both meshed and unmeshed sources. This is the correct default for gradual migration but must be tightened for a security-hardened deployment. Set the default policy to `cluster-authenticated` at the Linkerd install level to reject any traffic that does not carry a valid mTLS certificate from the cluster's trust anchor:

```bash
# Re-install with deny-unauthenticated default policy
linkerd install \
  --set proxy.defaultInboundPolicy=cluster-authenticated \
  | kubectl apply -f -
```

With `cluster-authenticated`, pods that are not meshed (no sidecar) cannot reach meshed pods at all. Use this setting in production namespaces once all workloads have been injected.

### Server and HTTPRoute Authorisation Policies

Linkerd's authorisation model operates at two granularities: `Server` (a port on a pod selector) and `HTTPRoute` (per-route policy within a Server). The combination enables the same per-path identity-based access control that Istio's `AuthorizationPolicy` provides, with a simpler resource model.

Define a `Server` for each exposed port. Without a `Server` resource, Linkerd applies the default policy:

```yaml
# payments-server.yaml
apiVersion: policy.linkerd.io/v1beta3
kind: Server
metadata:
  name: payments-api-http
  namespace: payments
spec:
  podSelector:
    matchLabels:
      app: payments-api
  port: 8080
  proxyProtocol: HTTP/2
```

With a `Server` resource present, Linkerd switches to a deny-by-default posture for that port: all inbound requests are rejected unless an `AuthorizationPolicy` explicitly allows them. This is the critical hardening step — creating a `Server` resource is what flips a workload's inbound policy from permissive to deny-by-default.

Create a `MeshTLSAuthentication` that identifies the allowed callers by their SPIFFE identity (Kubernetes service account):

```yaml
# frontend-identity.yaml
apiVersion: policy.linkerd.io/v1alpha1
kind: MeshTLSAuthentication
metadata:
  name: frontend-mtls
  namespace: payments
spec:
  identities:
    - "frontend.api.serviceaccount.identity.linkerd.cluster.local"
    - "monitoring.observability.serviceaccount.identity.linkerd.cluster.local"
```

The identity string format is `<service-account>.<namespace>.serviceaccount.identity.linkerd.cluster.local`. Use `linkerd viz edges` or inspect the proxy certificate to confirm identity strings before writing policy.

Attach an `AuthorizationPolicy` to the `Server`:

```yaml
# payments-authz.yaml
apiVersion: policy.linkerd.io/v1alpha1
kind: AuthorizationPolicy
metadata:
  name: payments-api-allow-frontend
  namespace: payments
spec:
  targetRef:
    group: policy.linkerd.io
    kind: Server
    name: payments-api-http
  requiredAuthenticationRefs:
    - name: frontend-mtls
      kind: MeshTLSAuthentication
      group: policy.linkerd.io
```

For per-route granularity, combine `Server` with an `HTTPRoute`. This allows different service accounts to reach `/health` (for monitoring) versus `/api/v1/payments` (for the frontend):

```yaml
# payments-routes.yaml
apiVersion: gateway.networking.k8s.io/v1beta1
kind: HTTPRoute
metadata:
  name: payments-api-routes
  namespace: payments
spec:
  parentRefs:
    - name: payments-api-http
      kind: Server
      group: policy.linkerd.io
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /health
    - matches:
        - path:
            type: PathPrefix
            value: /api/v1/payments
---
# Allow health checks from monitoring only
apiVersion: policy.linkerd.io/v1alpha1
kind: AuthorizationPolicy
metadata:
  name: payments-health-allow-monitoring
  namespace: payments
spec:
  targetRef:
    group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: payments-api-routes
  requiredAuthenticationRefs:
    - name: monitoring-mtls
      kind: MeshTLSAuthentication
      group: policy.linkerd.io
---
apiVersion: policy.linkerd.io/v1alpha1
kind: MeshTLSAuthentication
metadata:
  name: monitoring-mtls
  namespace: payments
spec:
  identities:
    - "prometheus.observability.serviceaccount.identity.linkerd.cluster.local"
```

Apply and verify:

```bash
kubectl apply -f payments-server.yaml -f frontend-identity.yaml \
  -f payments-authz.yaml -f payments-routes.yaml

# Test that the frontend can reach the payments API
kubectl exec -n api deploy/frontend -- \
  curl -s -o /dev/null -w "%{http_code}" \
  http://payments-api.payments.svc.cluster.local:8080/api/v1/payments
# Expected: 200

# Test that an unauthorised pod cannot reach the payments API
kubectl run unauth-test --image=curlimages/curl --rm -it \
  --restart=Never -n default \
  -- curl -s -o /dev/null -w "%{http_code}" \
  http://payments-api.payments.svc.cluster.local:8080/api/v1/payments
# Expected: connection refused or empty reply (proxy drops unauthenticated traffic)
```

### NetworkAuthentication: Combining CIDRs with mTLS Identity

For hybrid environments where some clients are not meshed — on-premises systems, legacy VMs, external load balancers — Linkerd provides `NetworkAuthentication` to allow traffic from specific CIDRs without requiring mTLS. This should be the exception, not the rule, and must always be paired with a restrictive CIDR:

```yaml
# corp-network-auth.yaml
apiVersion: policy.linkerd.io/v1alpha1
kind: NetworkAuthentication
metadata:
  name: corp-network
  namespace: payments
spec:
  networks:
    - cidr: 10.100.0.0/16   # corporate network CIDR only
```

Combine `NetworkAuthentication` with `MeshTLSAuthentication` in a single `AuthorizationPolicy` using multiple refs — Linkerd evaluates them as OR (either authentication satisfies the policy):

```yaml
apiVersion: policy.linkerd.io/v1alpha1
kind: AuthorizationPolicy
metadata:
  name: payments-admin-allow
  namespace: payments
spec:
  targetRef:
    group: policy.linkerd.io
    kind: Server
    name: payments-admin-http
  requiredAuthenticationRefs:
    - name: corp-network
      kind: NetworkAuthentication
      group: policy.linkerd.io
    - name: ops-mtls
      kind: MeshTLSAuthentication
      group: policy.linkerd.io
```

Do not use `NetworkAuthentication` for east-west traffic within the cluster. Pod CIDRs are shared and dynamic; a compromised pod on the same node shares the same source IP range. `MeshTLSAuthentication` is the only authentication mechanism that provides cryptographically bound workload identity.

### Egress Control

Linkerd does not have a purpose-built egress gateway in the same way Istio does, but it provides two mechanisms for controlling and observing outbound traffic.

By default, traffic from a meshed pod to an external (non-meshed) endpoint exits the sidecar proxy in plaintext. The proxy is still on the request path and records the outbound connection in telemetry, but it cannot enforce identity-based policies on the external endpoint.

For strict egress control, combine Linkerd with Kubernetes `NetworkPolicy` to whitelist permitted external destinations. This creates a two-layer control: Linkerd handles east-west identity and encryption; NetworkPolicy handles north-south egress:

```yaml
# payments-egress-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: payments-api-egress
  namespace: payments
spec:
  podSelector:
    matchLabels:
      app: payments-api
  policyTypes:
    - Egress
  egress:
    # Allow DNS resolution
    - ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
    # Allow intra-cluster traffic (to other meshed services)
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: api
    # Allow outbound to payment processor (specific CIDR and port)
    - to:
        - ipBlock:
            cidr: 203.0.113.0/24
      ports:
        - port: 443
          protocol: TCP
```

For workloads that require HTTP-level egress policy enforcement (rather than just IP/port), Linkerd 2.15+ introduced experimental egress support that proxies outbound HTTP traffic and applies `HTTPRoute`-based policies to external calls. Enable it per pod using the `config.linkerd.io/proxy-egress-networks` annotation:

```bash
# Enable egress proxy for a specific deployment
kubectl annotate deployment payments-api -n payments \
  config.linkerd.io/proxy-egress-networks="0.0.0.0/0"
```

With egress proxying enabled, outbound connections from the pod flow through the sidecar, which records the destination hostname, response code, and latency in Linkerd's standard telemetry. This makes it possible to detect anomalous external calls — sudden traffic to a new external hostname is visible in `linkerd viz top` without deploying any additional tooling.

### Linkerd Viz for Security Monitoring

Install the viz extension to get traffic metrics, live request tapping, and the dashboard:

```bash
linkerd viz install | kubectl apply -f -
linkerd viz check
linkerd viz dashboard &
```

Use `linkerd viz top` to monitor real-time traffic rates and success rates per route. A drop in success rate on an internal service is often an early signal of a misconfigured policy or a workload under attack:

```bash
# Live top-N request table for the payments namespace
linkerd viz top deploy/payments-api -n payments

# Per-route breakdown
linkerd viz top deploy/payments-api -n payments --to deploy/checkout
```

Use `linkerd viz tap` to inspect live requests and confirm mTLS is in effect. The `tls=true` field in tap output is authoritative:

```bash
# Tap all inbound requests to the payments-api deployment
linkerd viz tap deploy/payments-api -n payments

# Expected output includes:
# req id=0:1 proxy=in src=10.0.4.12:52381 dst=10.0.3.7:8080 \
#   tls=true :method=POST :authority=payments-api :path=/api/v1/payments

# Filter to only show plaintext connections (should be empty in a hardened namespace)
linkerd viz tap deploy/payments-api -n payments | grep "tls=false"
```

Configure Prometheus and Alertmanager rules to alert on unexpected plaintext or elevated 403 rates:

```yaml
# linkerd-alerts.yaml
groups:
  - name: linkerd-security
    rules:
      - alert: LinkerdPlaintextTraffic
        expr: |
          sum(
            rate(response_total{
              namespace="payments",
              tls="false"
            }[5m])
          ) > 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Plaintext traffic detected in payments namespace"
          description: "Linkerd is observing non-mTLS traffic in a namespace that should be fully meshed."

      - alert: LinkerdHighUnauthorisedRate
        expr: |
          sum(
            rate(response_total{
              namespace="payments",
              status_code="403"
            }[5m])
          ) by (deployment) > 0.05
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High 403 rate in {{ $labels.deployment }}"
          description: "More than 5% of requests are being rejected by authorisation policy. May indicate a misconfiguration or an attempted access from an unauthorised workload."
```

### Multi-Cluster Federation

Linkerd's multi-cluster extension uses a service mirroring model. A `Link` resource in cluster A causes Linkerd to mirror selected services from cluster B as local Kubernetes services. Traffic to the mirrored service is forwarded over a gateway in cluster B, with mTLS enforced between the two gateways using each cluster's trust anchor.

Install the multi-cluster extension in both clusters:

```bash
linkerd multicluster install | kubectl apply -f -
linkerd multicluster check
```

Link cluster A to cluster B by creating a `Link` resource using the target cluster's kubeconfig credentials:

```bash
# Run from cluster A's context
linkerd multicluster link \
  --cluster-name cluster-b \
  --kubeconfig /path/to/cluster-b-kubeconfig \
  | kubectl apply -f -
```

The `Link` resource controls which services are mirrored. Only services in cluster B that carry the `mirror.linkerd.io/exported=true` label are made available in cluster A:

```bash
# In cluster B: export the inventory service
kubectl label service inventory -n inventory \
  mirror.linkerd.io/exported=true
```

Verify the cross-cluster mTLS link:

```bash
# From cluster A, check the multi-cluster link status
linkerd multicluster check

# Verify the mirrored service is present in cluster A
kubectl get service inventory-cluster-b -n inventory

# Confirm mTLS is in use across the cluster boundary
linkerd viz edges deployment -n payments | grep cluster-b
```

For hardened multi-cluster deployments, each cluster's trust anchor must be distinct. Cross-cluster mTLS is enforced between the gateway pods, not end-to-end between workload pods. The cross-cluster `Gateway` pod in cluster B is the termination point for mTLS from cluster A. Apply `Server` and `AuthorizationPolicy` resources to the services in cluster B that restrict which cluster A service accounts can reach them. The identity principal for a cross-cluster call is in the form `<sa>.<ns>.serviceaccount.identity.linkerd.<cluster-name>`.

## Linkerd vs Istio Security Comparison

Understanding the security trade-offs between the two meshes guides platform decisions.

**Default security posture.** Linkerd's default is automatic mTLS on all meshed traffic with no opt-in required. Istio enables mTLS in `PERMISSIVE` mode by default (accepting both plaintext and mTLS), which must be explicitly tightened to `STRICT`. An Istio cluster that has never had its PeerAuthentication configured is silently accepting plaintext from any source.

**Data-plane CVE history.** Linkerd2-proxy has had a substantially smaller number of security advisories than Envoy. Envoy's C++ codebase has accumulated CVEs related to HTTP/2 frame handling, Lua sandbox escapes, header normalisation bypasses, and memory corruption. Rust's ownership model prevents an entire class of memory corruption vulnerability. This is not a hypothetical advantage: Istio's security advisory page lists multiple high-severity proxy vulnerabilities per year; Linkerd's is significantly quieter.

**Configuration complexity and misconfiguration risk.** Istio's `AuthorizationPolicy` is powerful and subtle. The multivalue header bypass class (CVE-2026-26308) is directly caused by the interaction between expressive header matching and edge cases in how Envoy's `HeaderMap` handles repeated headers. Linkerd's policy model is more constrained — you can express "this mTLS identity can reach this Server on this HTTPRoute" but you cannot write arbitrary header-matching conditions. That constraint reduces the surface for policy logic errors.

**Control-plane attack surface.** Istiod's xDS API server is a large, complex Go binary that must maintain consistency across a cluster's entire proxy fleet. Linkerd's control-plane components are smaller and more focused. The `identity` component's sole function is to issue short-lived workload certificates; compromising it gives an attacker the ability to issue certificates, but the blast radius is bounded by the fact that those certificates are only valid within the mesh's trust domain and only for as long as the intermediate CA itself remains trusted.

**Operational visibility.** Both meshes provide Prometheus metrics and request telemetry. Linkerd's `linkerd viz tap` provides near-real-time request inspection without any additional tooling. Istio's equivalent requires Kiali or manual `istioctl proxy-config` inspection. For security investigations — "did this pod make any requests with `tls=false`?" — Linkerd's tap is faster to use under pressure.

**Where Istio wins.** Complex traffic management (fault injection, traffic mirroring, A/B routing), WebAssembly extension points, JWT authentication built into the mesh, and ecosystem maturity. Teams that need L7 traffic management capabilities alongside security should evaluate whether those capabilities justify Istio's larger attack surface.

| Dimension | Linkerd | Istio |
|---|---|---|
| Default mTLS posture | On, automatic, no configuration | PERMISSIVE by default, must be tightened |
| Data-plane language | Rust (memory safe) | C++ (Envoy, memory unsafe) |
| Data-plane CVE frequency | Low | Moderate to high |
| Control-plane memory | 200–500 MB | 1–2 GB |
| Policy model | Server + HTTPRoute + MeshTLSAuthentication | AuthorizationPolicy + PeerAuthentication + header matching |
| Misconfiguration surface | Narrow | Wide |
| Traffic management | Basic (retries, timeouts) | Full (routing, fault injection, mirroring) |
| JWT authentication | Via HTTPRoute filter (2.14+) | Native, PeerAuthentication + RequestAuthentication |
| WASM extensions | Not supported | Supported via EnvoyFilter |
| Multi-cluster | Service mirroring, mTLS gateways | Istio federation, shared trust roots |

## Expected Behaviour

After applying the hardening steps in this article:

| Check | Command | Expected Result |
|---|---|---|
| All meshed edges are mTLS secured | `linkerd viz edges deployment -n payments` | All rows show `SECURED: true` |
| Unauthorised pod cannot reach meshed service | `kubectl run test --image=curlimages/curl --rm -it --restart=Never -n default -- curl payments-api.payments:8080` | Connection refused or empty reply |
| Tap shows `tls=true` on all inbound requests | `linkerd viz tap deploy/payments-api -n payments \| grep "tls=false"` | No output |
| Identity component is using external certificate | `kubectl get secret linkerd-identity-issuer -n linkerd` | Secret present with cert issued by trust anchor |
| Multi-cluster link is healthy | `linkerd multicluster check` | All checks pass |
| Prometheus alert fires on plaintext | Inject a non-meshed pod and send traffic | `LinkerdPlaintextTraffic` alert fires within 1 minute |

## Trade-offs

| Decision | Benefit | Cost | Mitigation |
|---|---|---|---|
| `cluster-authenticated` default policy | Rejects all non-meshed inbound traffic; enforces mTLS as the baseline | Non-meshed pods (monitoring agents, legacy workloads) cannot reach meshed services until injected | Migrate all workloads to meshed before enabling; use `all-authenticated` during migration |
| External trust anchor (cert-manager) | Trust anchor private key is not stored in-cluster; can be backed by HSM | More complex initial setup; trust anchor rotation requires coordinated update across all meshed pods | Use a long-lived trust anchor (10 years) with a shorter-lived intermediate (1 year); rotate intermediate on schedule |
| `Server` resources with deny-by-default | Every inbound path must be explicitly authorised; reduces blast radius of compromised workload | Operational overhead: every new service-to-service connection requires a policy update | Maintain a service communication matrix; add policy validation to CI via `kubectl --dry-run=server` |
| `MeshTLSAuthentication` over `NetworkAuthentication` | Cryptographically bound workload identity; cannot be spoofed via IP source | Requires all callers to be meshed; excludes unmeshed legacy systems | Use `NetworkAuthentication` only for explicitly identified legacy systems; track and eliminate all `NetworkAuthentication` entries as legacy workloads are migrated |
| Linkerd vs Istio | Smaller attack surface, Rust proxy, simpler policy model | No WASM extensions, less expressive traffic management, smaller ecosystem | Evaluate against requirements; most security-primary use cases are satisfied by Linkerd's feature set |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Identity issuer certificate expires | New pods fail to start; existing pods lose ability to renew their workload certificates; mTLS handshakes begin failing as workload certs expire | `linkerd check` reports certificate expiry; Linkerd's `identity` component logs renewal failures | Apply renewed certificate to `linkerd-identity-issuer` secret; cert-manager should handle this automatically if configured correctly |
| `Server` resource missing for a port | Port falls back to default policy instead of deny-by-default; unexpected traffic may be accepted | `linkerd viz top` shows traffic from unexpected sources; `linkerd viz edges` shows unauthenticated connections | Create the `Server` resource for the port; verify no unauthenticated edges remain |
| Sidecar injection not enabled on namespace | Pod communicates in plaintext; `cluster-authenticated` policy causes connection refusals when attempting to reach meshed services | Pod missing `linkerd-proxy` container; `linkerd viz edges` shows missing pod | Annotate namespace and rollout restart affected deployments |
| Multi-cluster link certificate mismatch | Cross-cluster requests fail with TLS errors; `linkerd multicluster check` reports gateway errors | `linkerd multicluster check` output; Linkerd gateway pod logs showing certificate validation failure | Verify trust anchor certificates are consistent; re-run `linkerd multicluster link` to refresh the Link resource |
| `AuthorizationPolicy` missing for a `Server` | All traffic to the port is denied (deny-by-default with no allow rule) | HTTP 403 or connection refused on a previously working service-to-service path; `linkerd viz top` shows zero success rate | Create the appropriate `AuthorizationPolicy` with `MeshTLSAuthentication` refs; test with `linkerd viz tap` to confirm requests are now reaching the service |

## Related Articles

- [mTLS and Service Mesh Security](/articles/network/mtls-service-mesh/)
- [Istio RBAC and Header Policy Security](/articles/network/istio-rbac-header-security/)
- [Service Mesh Egress Gateway Patterns](/articles/network/istio-egress-gateway/)
- [Cilium L7 Policy Security](/articles/network/cilium-l7-policy-security/)
- [Network Segmentation Patterns](/articles/network/network-segmentation-patterns/)
- [Zero Trust Network Access](/articles/network/zero-trust-network-access/)
