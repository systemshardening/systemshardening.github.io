---
title: "Zero Trust Networking: Identity-Based Access Beyond Perimeter Security"
description: "Perimeter security assumes the internal network is safe. It is not. A single compromised pod, a stolen VPN credential, or a malicious insider gives..."
slug: "zero-trust-networking"
date: 2026-01-27
lastmod: 2026-01-27
category: "cross-cutting"
tags: ["zero-trust", "spiffe", "spire", "mtls", "istio", "identity", "service-mesh"]
personas: ["security-engineer", "platform-engineer"]
article_number: 88
difficulty: "advanced"
estimated_reading_time: 16
provider_bridges:
  - name: "Isovalent"
    id: 54
    category: "cni-networking"
  - name: "Buoyant"
    id: 55
    category: "service-mesh"
  - name: "Tailscale"
    id: 40
    category: "vpn-networking"
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
premium_pack: "zero-trust-policy-templates"
published: true
layout: article.njk
permalink: "/articles/cross-cutting/zero-trust-networking/index.html"
---

# Zero Trust Networking: Identity-Based Access Beyond Perimeter Security

## Problem

Perimeter security assumes the internal network is safe. It is not. A single compromised pod, a stolen VPN credential, or a malicious insider gives the attacker a trusted network position. From there, every internal service is reachable because the network was designed to trust anything inside the boundary.

The traditional model: firewall at the edge, flat network inside, services communicate freely. This worked when the perimeter was a physical building with a handful of servers. In a [Kubernetes](https://kubernetes.io) cluster with 200 services across multiple namespaces, "inside the perimeter" includes every pod, every sidecar, every init container, and every node. The attack surface is not the edge. It is the entire internal network.

Zero trust eliminates implicit trust based on network location. Every request is authenticated (who is calling?), authorised (are they allowed to call this endpoint?), and encrypted (can anyone else read this traffic?). This applies to service-to-service communication, not just user-to-service. Implementing it properly requires workload identity, mutual TLS, and per-request authorisation policies.

**Target systems:** Kubernetes clusters with multiple services. Service mesh ([Istio](https://istio.io), [Linkerd](https://linkerd.io)) or [Cilium](https://cilium.io) for network enforcement. SPIFFE/SPIRE for workload identity. Any architecture where services communicate over a network.

## Threat Model

- **Adversary:** Attacker with a foothold inside the network. This could be a compromised service, a container escape, a stolen service account token, or a malicious insider.
- **Objective:** Lateral movement. Access services that the compromised workload should never communicate with. Exfiltrate data from databases, secret stores, or other services by exploiting the flat network.
- **Blast radius:** Without zero trust, a compromised pod in any namespace can reach every other pod, every database, and every internal API. With zero trust, the compromised pod can only reach services it is explicitly authorised to call, and only with a valid identity certificate.

## Configuration

### Workload Identity with SPIFFE/SPIRE

SPIFFE (Secure Production Identity Framework For Everyone) provides a standard for workload identity. SPIRE is the reference implementation. Each workload receives an X.509 certificate (SVID) that proves its identity without relying on network location, IP addresses, or Kubernetes service accounts.

```yaml
# spire-server.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: spire-server
  namespace: spire
spec:
  replicas: 3
  selector:
    matchLabels:
      app: spire-server
  template:
    metadata:
      labels:
        app: spire-server
    spec:
      serviceAccountName: spire-server
      containers:
        - name: spire-server
          image: ghcr.io/spiffe/spire-server:1.11.0
          args:
            - -config
            - /run/spire/config/server.conf
          ports:
            - containerPort: 8081
              name: grpc
          volumeMounts:
            - name: spire-config
              mountPath: /run/spire/config
              readOnly: true
            - name: spire-data
              mountPath: /run/spire/data
      volumes:
        - name: spire-config
          configMap:
            name: spire-server-config
  volumeClaimTemplates:
    - metadata:
        name: spire-data
      spec:
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: 1Gi
```

```hcl
# spire-server.conf
server {
  bind_address = "0.0.0.0"
  bind_port = "8081"
  trust_domain = "example.com"
  data_dir = "/run/spire/data"
  log_level = "INFO"

  ca_ttl = "24h"
  default_x509_svid_ttl = "1h"

  # Automatic registration based on Kubernetes metadata
  plugins {
    DataStore "sql" {
      plugin_data {
        database_type = "sqlite3"
        connection_string = "/run/spire/data/datastore.sqlite3"
      }
    }
    NodeAttestor "k8s_psat" {
      plugin_data {
        clusters = {
          "production" = {
            service_account_allow_list = ["spire:spire-agent"]
          }
        }
      }
    }
    KeyManager "disk" {
      plugin_data {
        keys_path = "/run/spire/data/keys.json"
      }
    }
  }
}
```

### Registration Entries

Define which workloads receive which SPIFFE identities.

```bash
# Register workloads by Kubernetes labels
# Each service gets a unique SPIFFE ID based on namespace and service name

# API gateway
spire-server entry create \
  -spiffeID spiffe://example.com/ns/production/sa/api-gateway \
  -parentID spiffe://example.com/agent \
  -selector k8s:ns:production \
  -selector k8s:sa:api-gateway

# Payment service
spire-server entry create \
  -spiffeID spiffe://example.com/ns/production/sa/payment-service \
  -parentID spiffe://example.com/agent \
  -selector k8s:ns:production \
  -selector k8s:sa:payment-service

# Database proxy
spire-server entry create \
  -spiffeID spiffe://example.com/ns/data/sa/postgres-proxy \
  -parentID spiffe://example.com/agent \
  -selector k8s:ns:data \
  -selector k8s:sa:postgres-proxy
```

### mTLS Everywhere with Istio Strict Mode

```yaml
# istio-peer-authentication.yaml
# Require mTLS for all service-to-service communication
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system  # Mesh-wide policy
spec:
  mtls:
    mode: STRICT
    # STRICT means: reject any connection without a valid client certificate.
    # No plaintext, no permissive fallback.
```

### Per-Request Authorisation Policies

mTLS authenticates identity. Authorisation policies control what each identity can access.

```yaml
# authz-payment-service.yaml
# Only the API gateway can call the payment service
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: payment-service-access
  namespace: production
spec:
  selector:
    matchLabels:
      app: payment-service
  action: ALLOW
  rules:
    - from:
        - source:
            principals:
              - "cluster.local/ns/production/sa/api-gateway"
      to:
        - operation:
            methods: ["POST"]
            paths: ["/api/v1/payments", "/api/v1/refunds"]
---
# Default deny for payment service (explicit)
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: payment-service-deny-all
  namespace: production
spec:
  selector:
    matchLabels:
      app: payment-service
  action: DENY
  rules:
    - from:
        - source:
            notPrincipals:
              - "cluster.local/ns/production/sa/api-gateway"
```

```yaml
# authz-database-access.yaml
# Only the payment service and user service can access the database proxy
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: database-access
  namespace: data
spec:
  selector:
    matchLabels:
      app: postgres-proxy
  action: ALLOW
  rules:
    - from:
        - source:
            principals:
              - "cluster.local/ns/production/sa/payment-service"
              - "cluster.local/ns/production/sa/user-service"
      to:
        - operation:
            ports: ["5432"]
```

### Monitoring for Lateral Movement

```yaml
# prometheus-zero-trust-alerts.yaml
groups:
  - name: zero-trust-violations
    rules:
      - alert: AuthzPolicyDenied
        expr: >
          sum by (source_workload, destination_workload) (
            rate(istio_requests_total{response_code="403"}[5m])
          ) > 0
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Authorisation denied: {{ $labels.source_workload }} to {{ $labels.destination_workload }}"
          description: "A service is attempting to reach a destination it is not authorised for. This may indicate lateral movement."

      - alert: MTLSHandshakeFailure
        expr: >
          sum by (source_workload) (
            rate(envoy_ssl_connection_error_total[5m])
          ) > 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "mTLS handshake failure from {{ $labels.source_workload }}"
          description: "A workload is failing mTLS handshakes. This may indicate an attacker without valid credentials attempting to connect."
```

### Migration Path

Migrating from flat network to zero trust in production without downtime:

```yaml
# Step 1: Deploy Istio with PERMISSIVE mode (accepts both mTLS and plaintext)
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system
spec:
  mtls:
    mode: PERMISSIVE
---
# Step 2: Monitor which services are already using mTLS
# Query: istio_requests_total grouped by connection_security_policy
# "mutual_tls" = mTLS, "none" = plaintext

# Step 3: Switch to STRICT per-namespace, starting with the most sensitive
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: strict-data
  namespace: data
spec:
  mtls:
    mode: STRICT
---
# Step 4: After all namespaces are on STRICT, enforce mesh-wide
# Step 5: Add AuthorizationPolicies per service, starting with the most sensitive
# Step 6: Set default-deny mesh-wide (most restrictive, do last)
```

## Expected Behaviour

- Every service has a SPIFFE identity issued by SPIRE
- All service-to-service communication uses mTLS (no plaintext)
- AuthorizationPolicies restrict which services can communicate
- Any request without a valid identity certificate is rejected
- Lateral movement attempts generate immediate alerts (403 responses, mTLS failures)
- Certificate rotation happens automatically (1-hour SVID TTL, no manual intervention)

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| SPIRE for identity | Standard-based (SPIFFE), portable across platforms | Additional infrastructure to operate (SPIRE server cluster) | Run 3 SPIRE server replicas. Use managed service mesh if operational overhead is too high. |
| Istio strict mTLS | Encrypts and authenticates all traffic | Adds 1-3ms latency per request (TLS handshake, amortised with connection reuse) | Connection pooling reduces handshake overhead. Profile latency impact in staging before production rollout. |
| Per-service AuthorizationPolicies | Least-privilege network access | Each new service requires policy updates; missing policy blocks legitimate traffic | Start with allow-all, log denied requests, then progressively tighten. Automate policy generation from observed traffic patterns. |
| 1-hour certificate TTL | Compromised certificate is valid for at most 1 hour | Higher certificate issuance load on SPIRE server | SPIRE handles thousands of certificate issuances per second. Monitor SPIRE server resource usage. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| SPIRE server unavailable | Workloads cannot renew certificates; new pods cannot get identity | Certificate expiry alerts; SPIRE health check fails | SPIRE HA (3 replicas). Existing certificates remain valid until TTL expires (1 hour grace period). |
| mTLS strict mode breaks non-mesh service | External service (monitoring agent, legacy app) cannot connect | Connection refused errors; service health check failures | Temporarily add PeerAuthentication PERMISSIVE for the specific port/service. Migrate the external service into the mesh. |
| AuthorizationPolicy too restrictive | Legitimate service calls blocked (403) | Application errors; istio_requests_total with response_code 403 | Add the missing ALLOW rule. Review service dependency map for completeness. |
| Certificate rotation failure | Service continues with expired certificate; connections rejected | mTLS handshake errors; SPIRE agent logs show renewal failure | Restart the SPIRE agent on the affected node. If persistent, check SPIRE server connectivity and registration entries. |

## When to Consider a Managed Alternative

[Isovalent](https://isovalent.com) Cilium Enterprise for network-level identity and encryption without a sidecar proxy (lower latency, lower resource overhead). [Buoyant](https://buoyant.io) Linkerd Enterprise for a simpler service mesh with automatic mTLS and less configuration than Istio. [Tailscale](https://tailscale.com) for zero-trust network access at the infrastructure level (VPN replacement with identity-based access). [Sysdig](https://sysdig.com) for monitoring zero-trust policy violations across clusters.

**Premium content pack:** Zero trust policy templates. SPIRE deployment manifests, Istio PeerAuthentication and AuthorizationPolicy templates for common architectures, migration runbook from permissive to strict, and [Prometheus](https://prometheus.io) alert rules for zero-trust violations.


## Related Articles

- [mTLS for Service-to-Service Communication: Istio, Linkerd, and DIY with cert-manager](/articles/network/mtls-service-mesh/)
- [Hardening a Complete Kubernetes Platform: From Cluster Bootstrap to Production-Ready](/articles/cross-cutting/complete-kubernetes-hardening/)
- [Security Hardening for Small Teams: Prioritising Controls When You Cannot Do Everything](/articles/cross-cutting/hardening-small-teams/)
- [Compliance-as-Code: Mapping CIS Benchmarks to Automated Checks with InSpec and Kube-bench](/articles/cross-cutting/compliance-as-code/)
- [The Hardening Scorecard: Measuring and Tracking Security Posture](/articles/cross-cutting/hardening-scorecard/)
