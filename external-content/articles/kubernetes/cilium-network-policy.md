---
title: "Cilium Network Policy: FQDN Filtering, L7 Policies, and Hubble Observability"
description: "Cilium's CiliumNetworkPolicy extends standard Kubernetes NetworkPolicy with DNS-based egress control, HTTP/gRPC L7 rules, and cryptographic identity. Hubble provides flow-level visibility without packet capture."
slug: "cilium-network-policy"
date: 2026-04-30
lastmod: 2026-04-30
category: "kubernetes"
tags: ["cilium", "network-policy", "fqdn", "ebpf", "hubble"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 256
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/kubernetes/cilium-network-policy/index.html"
---

# Cilium Network Policy: FQDN Filtering, L7 Policies, and Hubble Observability

## Problem

Standard Kubernetes `NetworkPolicy` operates at L3/L4: it can restrict which pods can communicate based on label selectors, namespaces, and port numbers. It cannot:

- Restrict egress to specific external DNS names (only to IP addresses, which change).
- Enforce HTTP path or method restrictions at the proxy layer without a sidecar.
- Identify traffic by workload cryptographic identity rather than IP address.
- Provide visibility into allowed or denied traffic flows without a separate monitoring solution.

Cilium addresses all four. It replaces kube-proxy with eBPF programs and exposes `CiliumNetworkPolicy` (CNP), a superset of `NetworkPolicy` that adds:

- **FQDN-based egress:** Allow `payments.stripe.com:443` rather than managing IP allowlists that become stale within hours.
- **L7 HTTP/gRPC policies:** Allow `GET /api/public` but block `DELETE /api/admin` at the network layer without a sidecar.
- **Cryptographic identity:** Cilium assigns each pod a numeric identity derived from its labels; policies reference identities, not IPs. IP reuse (pod restart) doesn't create policy gaps.
- **Hubble:** An eBPF-based observability layer that records every network flow at L3–L7 and exposes them via CLI and UI — without packet capture or performance overhead.

Specific gaps in clusters using only standard `NetworkPolicy`:

- Egress policies reference IP ranges; third-party API IPs change and allowlists go stale silently.
- No L7 enforcement; a compromised pod can call any HTTP path on an allowed service.
- Network flow visibility requires deploying a network tap or a service mesh sidecar.
- IP-based identity is fragile across pod restarts and cluster rebalancing.

**Target systems:** Cilium 1.15+; Kubernetes 1.28+; Hubble 1.15+; Cilium CLI 0.16+.

## Threat Model

- **Adversary 1 — Stale IP allowlist bypass:** A pod is allowed to reach `api.payment-provider.com` via an IP range. The provider's IP changes; the old IP is allocated to an attacker's service. The pod can now reach the attacker's service through the "allowed" rule. FQDN-based policy resolves this — the rule follows the DNS name, not the IP.
- **Adversary 2 — HTTP path escalation:** An attacker compromises a pod that is allowed to reach the internal admin API on port 8080. Standard NetworkPolicy allows all paths on 8080; the attacker calls `DELETE /api/users` or `POST /api/admin/exec`. L7 HTTP policy restricts to `GET /api/status` only.
- **Adversary 3 — Lateral movement after pod compromise:** A compromised frontend pod attempts to reach the database pod. Without network policy, the connection succeeds. Without FQDN filtering, egress to C2 infrastructure succeeds. Cilium's default-deny with explicit allows blocks both.
- **Adversary 4 — Identity spoofing via IP reuse:** A pod is terminated; its IP is reused by a new, different pod. An IP-based allowlist inadvertently allows the new pod. Cilium's cryptographic identity (derived from labels, verified by the CNI) prevents this — a pod with different labels gets a different identity.
- **Access level:** Adversaries 1 and 2 have pod-level execution. Adversary 3 has network access within the cluster. Adversary 4 exploits IP reuse timing.
- **Objective:** Exfiltrate data via allowed egress paths, pivot to restricted services, call unauthorized API endpoints.
- **Blast radius:** Without L7 policies, allowed network paths are fully exploitable at the application layer. With Cilium L7: network-layer enforcement of HTTP method and path, independent of the application.

## Configuration

### Step 1: Install Cilium with Required Features

```bash
# Install Cilium with Hubble and L7 proxy enabled.
helm repo add cilium https://helm.cilium.io/
helm install cilium cilium/cilium \
  --version 1.15.5 \
  --namespace kube-system \
  --set kubeProxyReplacement=true \
  --set hubble.relay.enabled=true \
  --set hubble.ui.enabled=true \
  --set hubble.enabled=true \
  --set hubble.metrics.enabled="{dns,drop,tcp,flow,icmp,http}" \
  --set l7Proxy=true \
  --set policyEnforcementMode=default   # or "always" for strict default-deny

# Verify Cilium is running.
cilium status --wait

# Verify Hubble is available.
hubble status
```

Enable default-deny cluster-wide:

```bash
# Set policyEnforcementMode=always: pods with no policy are denied all traffic.
helm upgrade cilium cilium/cilium \
  --reuse-values \
  --set policyEnforcementMode=always
```

With `always` mode, every pod needs explicit ingress and egress policies. Start in `default` mode (only pods with at least one policy are restricted) during migration.

### Step 2: Standard NetworkPolicy Replacement

Cilium is fully compatible with standard `NetworkPolicy`. Existing policies continue to work:

```yaml
# Standard NetworkPolicy — works unchanged with Cilium.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: payments-ingress
  namespace: payments
spec:
  podSelector:
    matchLabels:
      app: payments
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: api-gateway
      ports:
        - port: 8080
  policyTypes: [Ingress, Egress]
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: postgres
      ports:
        - port: 5432
```

### Step 3: FQDN-Based Egress Policies

Replace IP-range egress rules with DNS name rules:

```yaml
# CiliumNetworkPolicy with FQDN-based egress.
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: payments-egress-stripe
  namespace: payments
spec:
  endpointSelector:
    matchLabels:
      app: payments
  egress:
    # Allow DNS resolution (required for FQDN policies to work).
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: kube-system
            k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: UDP
          rules:
            dns:
              - matchPattern: "*.stripe.com"   # Only resolve Stripe domains via DNS.

    # Allow HTTPS to Stripe using the resolved FQDN.
    - toFQDNs:
        - matchName: "api.stripe.com"
        - matchName: "hooks.stripe.com"
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP

    # Allow HTTPS to internal services by label, not IP.
    - toEndpoints:
        - matchLabels:
            app: vault
            io.kubernetes.pod.namespace: vault
      toPorts:
        - ports:
            - port: "8200"
              protocol: TCP

    # Block all other egress (implicit when using CiliumNetworkPolicy with egress rules).
```

Cilium's DNS proxy intercepts DNS queries, notes the resolved IPs, and dynamically updates the eBPF policy map. When `api.stripe.com` resolves to a new IP, the policy updates automatically — no manual IP list maintenance.

### Step 4: L7 HTTP Policy

Restrict which HTTP methods and paths are allowed, not just which ports:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: api-l7-ingress
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: internal-api
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: frontend
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
          rules:
            http:
              # Frontend can only read public endpoints.
              - method: "GET"
                path: "^/api/v1/products"
              - method: "GET"
                path: "^/api/v1/status"
              # Explicitly excluded: /api/admin/*, DELETE, PUT, POST
    - fromEndpoints:
        - matchLabels:
            app: admin-service
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
          rules:
            http:
              # Admin service gets broader access.
              - method: "GET"
                path: "^/api/"
              - method: "POST"
                path: "^/api/v1/products"
              - method: "DELETE"
                path: "^/api/v1/products/[0-9]+"
```

For gRPC services:

```yaml
toPorts:
  - ports:
      - port: "9090"
        protocol: TCP
    rules:
      http:
        # gRPC method names match as HTTP/2 paths.
        - method: "POST"
          path: "^/payments.PaymentService/CreatePayment"
        # Block all other gRPC methods on this service.
```

### Step 5: Cryptographic Identity Policies

Cilium assigns numeric identities to pods based on their labels. Policies referencing label selectors are identity-based, not IP-based:

```yaml
# Policy referencing the "payments" identity — survives pod restarts.
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: db-ingress
  namespace: data
spec:
  endpointSelector:
    matchLabels:
      app: postgres
  ingress:
    - fromEndpoints:
        # Pods with these labels can connect; identity derived from labels.
        - matchLabels:
            app: payments
            environment: production
      toPorts:
        - ports:
            - port: "5432"
```

Verify the identity assigned to a pod:

```bash
# Show the Cilium identity for the payments pods.
cilium identity get -l app=payments,environment=production
# Output: identity 12345: {app: payments, environment: production}

# Show which identities a policy applies to.
cilium policy get
```

### Step 6: Hubble Flow Observability

Hubble records every network flow with L3–L7 context. Use it to audit policy enforcement and investigate incidents:

```bash
# Install the Hubble CLI.
HUBBLE_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/hubble/master/stable.txt)
curl -LO "https://github.com/cilium/hubble/releases/download/$HUBBLE_VERSION/hubble-linux-amd64.tar.gz"
tar xzf hubble-linux-amd64.tar.gz && mv hubble /usr/local/bin/

# Port-forward to the Hubble relay.
cilium hubble port-forward &

# Watch live traffic flows.
hubble observe --follow

# Filter: show only denied flows in the payments namespace.
hubble observe \
  --namespace payments \
  --verdict DROPPED \
  --follow

# Show L7 HTTP flows to the internal API.
hubble observe \
  --to-pod production/internal-api \
  --protocol http \
  --follow \
  | jq '{src: .source.pod_name, method: .l7.http.method, path: .l7.http.url, verdict: .verdict}'

# Show FQDN policy resolution events.
hubble observe \
  --type policy-verdict \
  --namespace payments
```

Hubble UI (port-forward to `hubble-ui` service) shows a service dependency graph with traffic volumes and drop rates in real time.

Export flows to your SIEM:

```bash
# Hubble exports flows as JSON via the relay API.
# Use hubble-otel-exporter or configure Cilium's Hubble metrics for Prometheus.
hubble observe --output json | \
  jq 'select(.verdict == "DROPPED")' | \
  send_to_siem
```

### Step 7: DNS Policy for Egress Visibility

Cilium's DNS proxy logs every DNS query made by pods:

```yaml
# Enable DNS visibility for all egress traffic.
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: dns-visibility
  namespace: production
spec:
  endpointSelector: {}   # Apply to all pods in this namespace.
  egress:
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: kube-system
            k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: UDP
          rules:
            dns:
              - matchPattern: "*"   # Log all DNS queries; enforce in separate policy.
```

View DNS queries via Hubble:

```bash
hubble observe --protocol dns --namespace production --follow
# Shows: pod -> DNS query -> response (including resolved IPs)
```

### Step 8: Telemetry

```
cilium_drop_count_total{direction, reason, namespace}        counter
cilium_forward_count_total{direction, namespace}             counter
cilium_policy_count                                          gauge
cilium_policy_endpoint_enforcement_status{namespace, status} gauge
hubble_flows_processed_total{verdict, type, protocol}        counter
hubble_drop_total{namespace, direction, reason}              counter
cilium_identity_count                                        gauge
```

Alert on:

- `hubble_drop_total` spike in production namespaces — unexpected policy denials; check for misconfigured policy or lateral movement attempt.
- `cilium_drop_count_total{reason="Policy denied"}` from unexpected source identities — pod with unexpected labels trying to reach a restricted service.
- DNS queries to unexpected FQDNs from pods with FQDN policies — indicates a new external service being called that isn't yet in the policy.

## Expected Behaviour

| Signal | Standard NetworkPolicy | Cilium CNP |
|--------|----------------------|------------|
| Egress to third-party API | IP range (stale after provider change) | FQDN (follows DNS; auto-updates) |
| HTTP path enforcement | Not possible at network layer | L7 rule; `DELETE /api/admin` denied at eBPF |
| Pod restart IP change | Old IP policy may gap briefly | Identity-based; new pod gets same identity instantly |
| Network flow visibility | None without additional tooling | Hubble: every flow with L7 context, in real time |
| DNS query visibility | None | DNS proxy logs every query with source pod |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| FQDN policies | Survive third-party IP changes | DNS proxy adds ~0.5ms latency to DNS resolution | Negligible for most workloads; DNS is cached after first resolution. |
| L7 HTTP enforcement | Network-layer path/method control | L7 parsing overhead (~5µs per request) | Acceptable for API traffic; disable for high-throughput non-HTTP paths. |
| `policyEnforcementMode=always` | All pods have explicit deny by default | Every pod needs a CNP; initial migration effort | Roll out namespace by namespace; use audit mode first. |
| Hubble flow recording | Complete network audit trail | Memory and CPU overhead for flow storage | Configure flow retention TTL; use Hubble metrics for aggregated visibility rather than raw flows. |
| Identity-based policy | Robust to IP reuse | Requires Cilium as CNI; can't mix with other CNIs | Cilium is the CNI; all nodes must run it. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| FQDN not in DNS policy | Pod can't resolve allowed FQDN; outbound TLS fails | Hubble shows DNS DROP for the FQDN | Add the FQDN to the `dns: matchPattern` or `matchName` rule. |
| L7 proxy not enabled | L7 rules silently ignored; all HTTP paths allowed | `cilium status` shows L7Proxy=disabled | Re-install Cilium with `--set l7Proxy=true`. |
| Missing DNS egress rule | FQDN policy never activates (no DNS responses) | All FQDN egress drops; pods can't connect | Add the DNS rule to kube-dns in the egress policy. |
| policyEnforcementMode=always breaks un-policies pod | Pod has no CNP; all traffic dropped | Pod fails health checks; Hubble shows all drops | Add a permissive CNP for the pod while building the correct policy. |
| Hubble relay unavailable | `hubble observe` fails | `cilium status` shows Hubble relay down | `kubectl rollout restart deployment/hubble-relay -n kube-system`. |
| Identity conflict after label change | Pod's identity changes; existing policies no longer match | Connectivity breaks after label update | Review CNP selectors when changing pod labels; test in staging. |

## Related Articles

- [Kubernetes Network Policies](/articles/kubernetes/kubernetes-network-policies/)
- [mTLS Service Mesh Hardening](/articles/network/mtls-service-mesh/)
- [Istio Egress Gateway and Egress Control](/articles/network/istio-egress-gateway/)
- [eBPF and Tetragon Runtime Detection](/articles/observability/ebpf-tetragon/)
- [Kubernetes API Server Hardening](/articles/kubernetes/api-server-hardening/)
