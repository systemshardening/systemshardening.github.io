---
title: "Envoy Proxy Security Hardening: Filter Chains, ext_authz, and Access Log Integrity"
description: "Envoy's defaults expose admin APIs, pass headers unsanitized, and log nothing useful for security. A hardened Envoy configuration changes all three."
slug: "envoy-security-hardening"
date: 2026-04-29
lastmod: 2026-04-29
category: "network"
tags: ["envoy", "proxy", "ext-authz", "filter-chain", "security"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 233
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/network/envoy-security-hardening/index.html"
---

# Envoy Proxy Security Hardening: Filter Chains, ext_authz, and Access Log Integrity

## Problem

Envoy Proxy is the data-plane component behind Istio, Contour, Gloo Edge, and numerous custom deployments. It handles enormous volumes of traffic, sits at the boundary between internal and external systems, and holds TLS certificates and routing rules that make it a high-value target.

Default Envoy deployments leave several security gaps:

- **Admin interface exposed on all interfaces.** The Envoy admin endpoint (`/clusters`, `/config_dump`, `/stats`, `/listeners`) is bound to `0.0.0.0:9901` by default. Anyone with network access can read the full Envoy configuration, drain the listener, or modify runtime values without authentication.
- **No request header sanitization.** Downstream (client) requests can inject `x-forwarded-for`, `x-real-ip`, or custom headers that Envoy blindly forwards upstream, enabling auth bypass in services that trust these headers.
- **Permissive RBAC.** Envoy's HTTP RBAC filter is not enabled in most custom deployments. All traffic matching a route is allowed by default.
- **No external authorization.** Traffic passes through without a dedicated policy decision point; authorization logic is pushed entirely to upstream services (inconsistently applied).
- **Access logs are disabled or contain no security-relevant fields.** Tracing request path, upstream cluster, response code, and TLS properties is rarely configured in default xDS configurations.
- **TLS configuration allows weak ciphers.** Default TLS context allows negotiation of ciphers below current security baselines.

The result: a high-throughput proxy with full visibility into your service mesh that is configured for availability but not for security.

**Target systems:** Envoy 1.30+ (proxy_protocol v2, RBAC filter, ext_authz stable); Istio 1.22+ (uses Envoy 1.30 as sidecar); Gloo Edge 1.17+.

## Threat Model

- **Adversary 1 — Admin API reconnaissance:** An attacker with internal network access calls `http://envoy:9901/config_dump` and obtains the full Envoy configuration: TLS certificates, upstream cluster addresses, route configurations, secret names. Uses this to plan lateral movement.
- **Adversary 2 — Header injection for auth bypass:** A client sets `X-Authenticated-User: admin` in an HTTP request. The upstream service trusts this header, grants admin access. Envoy forwarded it without stripping.
- **Adversary 3 — RBAC bypass:** A compromised internal service sends a direct request to another service's Envoy listener on a path that should be restricted. Without RBAC, Envoy routes it upstream without question.
- **Adversary 4 — ext_authz bypass:** ext_authz is configured but with a `DENY_ON_FAILURE` policy of `false` (allow on failure). When the auth service is momentarily unavailable, Envoy allows all requests through.
- **Adversary 5 — Log tampering for persistence:** An attacker modifies access log output or exploits a missing log field to hide their activity from SIEM correlation.
- **Access level:** Adversary 1 has internal network access (pod or VM in the cluster). Adversaries 2 and 3 have HTTP client access to Envoy's listener. Adversary 4 requires control over the ext_authz service or can cause it to fail. Adversary 5 needs access to the log pipeline.
- **Objective:** Exfiltrate configuration, bypass authentication/authorization, move laterally to restricted services, cover tracks.
- **Blast radius:** A misconfigured Envoy can make your entire service mesh authorization model ineffective; an exposed admin endpoint leaks the topology of your internal network.

## Configuration

### Step 1: Restrict the Admin Interface

Bind the admin interface to localhost only, and if remote access is needed, expose it via a dedicated authenticated ingress.

```yaml
# envoy.yaml (static config)
admin:
  address:
    socket_address:
      address: 127.0.0.1   # Never 0.0.0.0.
      port_value: 9901
  access_log:
    - name: envoy.access_loggers.file
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
        path: /dev/stdout
        log_format:
          json_format:
            timestamp: "%START_TIME%"
            method: "%REQ(:METHOD)%"
            path: "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%"
            response_code: "%RESPONSE_CODE%"
            admin_access: true
```

For Kubernetes deployments, expose the admin port only within the pod:

```yaml
# Do NOT expose admin in the service manifest.
# A dedicated NetworkPolicy blocks external access.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: envoy-admin-lockdown
spec:
  podSelector:
    matchLabels:
      app: envoy
  ingress:
    - ports:
        - port: 9901   # Blocked for all sources except localhost.
      from: []         # Empty = deny all.
```

### Step 2: Sanitize Downstream Headers

Strip headers that Envoy should set (not forward from clients). Envoy's `set_current_client_cert_details` and `request_headers_to_remove` handle this.

```yaml
http_filters:
  - name: envoy.filters.http.header_mutation
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.header_mutation.v3.HeaderMutation
      mutations:
        request_mutations:
          - remove: "x-forwarded-client-cert"
          - remove: "x-authenticated-user"
          - remove: "x-forwarded-for"    # Re-set by Envoy below.
          - remove: "x-real-ip"
          - remove: "x-envoy-internal"
          - remove: "x-request-id"       # Envoy generates a fresh one.
```

Configure Envoy to re-set `x-forwarded-for` correctly:

```yaml
route_config:
  virtual_hosts:
    - name: backend
      domains: ["*"]
      routes:
        - match: { prefix: "/" }
          route:
            cluster: backend-service
  request_headers_to_add:
    - header:
        key: "x-forwarded-for"
        value: "%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%"
      keep_empty_value: false
      append_action: OVERWRITE_IF_EXISTS_OR_ADD
```

### Step 3: Configure HTTP RBAC

Envoy's HTTP RBAC filter applies access control at the proxy layer — before the upstream service sees the request:

```yaml
http_filters:
  - name: envoy.filters.http.rbac
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC
      rules:
        action: ALLOW
        policies:
          "payments-service-access":
            permissions:
              - and_rules:
                  rules:
                    - header:
                        name: ":path"
                        prefix_match: "/api/v1/payments"
                    - header:
                        name: ":method"
                        exact_match: "POST"
            principals:
              - and_ids:
                  ids:
                    - authenticated:   # Requires mTLS client cert.
                        principal_name:
                          exact: "spiffe://cluster.local/ns/frontend/sa/payments-client"
          "health-check-access":
            permissions:
              - header:
                  name: ":path"
                  exact_match: "/health"
            principals:
              - any: true   # Health checks from any source.
```

With `action: ALLOW` and explicit policies, any request not matching a policy is denied by default.

In Istio, the equivalent is an `AuthorizationPolicy`:

```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: payments-authz
  namespace: payments
spec:
  selector:
    matchLabels:
      app: payments
  action: ALLOW
  rules:
    - from:
        - source:
            principals: ["cluster.local/ns/frontend/sa/payments-client"]
      to:
        - operation:
            methods: ["POST"]
            paths: ["/api/v1/payments"]
    - to:
        - operation:
            paths: ["/health"]
```

### Step 4: Wire ext_authz with Fail-Closed Policy

External authorization delegates every request to a policy decision point (OPA, OpenFGA, a custom gRPC service). Configure with `failure_mode_allow: false` so Envoy denies requests when the auth service is unreachable.

```yaml
http_filters:
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      grpc_service:
        envoy_grpc:
          cluster_name: ext-authz-cluster
        timeout: 2s    # Hard timeout; requests waiting beyond this fail closed.
      failure_mode_allow: false   # CRITICAL: deny on failure, not allow.
      transport_api_version: V3
      with_request_body:
        max_request_bytes: 8192
        allow_partial_message: true
      clear_route_cache: true    # Re-evaluate routes after authz response.
      allowed_headers:
        patterns:
          - exact: "authorization"
          - exact: "x-request-id"
```

The ext_authz gRPC service receives the full request context (headers, path, method, body up to the limit) and returns `CheckResponse` with `OK` or `DENIED`.

When the auth service is unavailable, `failure_mode_allow: false` means Envoy returns HTTP 403. This is safe-fail behavior.

OPA as the ext_authz backend:

```bash
# Deploy OPA with the Envoy plugin.
helm install opa opa/opa \
  --set 'plugins.envoy_ext_authz_grpc.addr=:9191' \
  --set 'plugins.envoy_ext_authz_grpc.path=envoy/authz/allow'
```

```rego
# policy.rego
package envoy.authz

import input.attributes.request.http as http_request

default allow = false

allow {
  http_request.method == "GET"
  startswith(http_request.path, "/public/")
}

allow {
  http_request.headers["authorization"] == concat("Bearer ", [valid_token])
  valid_token  # validated via JWKS lookup
}
```

### Step 5: Harden TLS Configuration

Configure Envoy's downstream TLS context to enforce modern cipher suites and minimum TLS version:

```yaml
filter_chains:
  - filter_chain_match:
      server_names: ["api.example.com"]
    transport_socket:
      name: envoy.transport_sockets.tls
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
        common_tls_context:
          tls_minimum_protocol_version: TLSv1_3   # Drop TLS 1.2 for external-facing.
          cipher_suites:
            - TLS_AES_256_GCM_SHA384
            - TLS_CHACHA20_POLY1305_SHA256
            - TLS_AES_128_GCM_SHA256
          tls_certificates:
            - certificate_chain:
                filename: /etc/envoy/certs/tls.crt
              private_key:
                filename: /etc/envoy/certs/tls.key
          validation_context:
            trusted_ca:
              filename: /etc/envoy/certs/ca.crt
        require_client_certificate: true   # Enforce mTLS on internal listeners.
```

For internal service-to-service listeners, keep `require_client_certificate: true`. For external-facing listeners handling web browser clients, drop the client cert requirement but keep TLS 1.2 as minimum (TLS 1.3 is not yet universal for browsers):

```yaml
tls_minimum_protocol_version: TLSv1_2
tls_maximum_protocol_version: TLSv1_3
cipher_suites:
  # TLS 1.3 suites (auto-negotiated, no explicit config needed in TLS 1.3).
  # TLS 1.2 suites — exclude RC4, 3DES, CBC suites.
  - ECDHE-ECDSA-AES256-GCM-SHA384
  - ECDHE-RSA-AES256-GCM-SHA384
  - ECDHE-ECDSA-AES128-GCM-SHA256
  - ECDHE-RSA-AES128-GCM-SHA256
```

### Step 6: Structured Security Access Logging

Configure access logs with security-relevant fields:

```yaml
access_log:
  - name: envoy.access_loggers.file
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
      path: /dev/stdout
      log_format:
        json_format:
          timestamp: "%START_TIME%"
          request_id: "%REQ(X-REQUEST-ID)%"
          method: "%REQ(:METHOD)%"
          path: "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%"
          protocol: "%PROTOCOL%"
          response_code: "%RESPONSE_CODE%"
          response_flags: "%RESPONSE_FLAGS%"
          bytes_received: "%BYTES_RECEIVED%"
          bytes_sent: "%BYTES_SENT%"
          duration_ms: "%DURATION%"
          upstream_cluster: "%UPSTREAM_CLUSTER%"
          upstream_host: "%UPSTREAM_HOST%"
          downstream_remote_address: "%DOWNSTREAM_REMOTE_ADDRESS%"
          downstream_local_address: "%DOWNSTREAM_LOCAL_ADDRESS%"
          tls_version: "%DOWNSTREAM_TLS_VERSION%"
          tls_cipher: "%DOWNSTREAM_TLS_CIPHER%"
          tls_session_id: "%DOWNSTREAM_TLS_SESSION_ID%"
          peer_certificate_subject: "%DOWNSTREAM_PEER_SUBJECT%"
          peer_certificate_issuer: "%DOWNSTREAM_PEER_ISSUER%"
          peer_certificate_san_uri: "%DOWNSTREAM_PEER_URI_SAN%"
          user_agent: "%REQ(USER-AGENT)%"
          authority: "%REQ(:AUTHORITY)%"
          x_forwarded_for: "%REQ(X-FORWARDED-FOR)%"
          grpc_status: "%GRPC_STATUS%"
          ext_authz_denied: "%DYNAMIC_METADATA(envoy.filters.http.ext_authz:denied)%"
```

Key security fields:

- `response_flags`: includes `UF` (upstream failure), `URX` (upstream retry), `UAEX` (upstream auth error), `RLSE` (rate limit service error), `NFCF` (no cluster found — often from RBAC deny).
- `peer_certificate_san_uri`: the SPIFFE URI of the calling service's TLS client certificate.
- `ext_authz_denied`: populated when ext_authz denies a request; useful for SIEM correlation.

### Step 7: Rate Limiting via Ratelimit Service

Configure per-IP and per-user rate limits via the external rate limit service:

```yaml
http_filters:
  - name: envoy.filters.http.ratelimit
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ratelimit.v3.RateLimit
      domain: envoy-ratelimit
      failure_mode_deny: true   # Deny if rate limit service is unavailable.
      rate_limit_service:
        grpc_service:
          envoy_grpc:
            cluster_name: ratelimit-cluster
        transport_api_version: V3
```

```yaml
# virtual_host rate limit action.
rate_limits:
  - actions:
      - remote_address: {}    # Per IP.
  - actions:
      - header_value_match:
          descriptor_value: "api-key"
          headers:
            - name: "x-api-key"
              present_match: true
      - request_headers:
          header_name: "x-api-key"
          descriptor_key: "api_key_value"
```

Rate limit configuration (Lyft ratelimit service):

```yaml
domain: envoy-ratelimit
descriptors:
  - key: remote_address
    rate_limit:
      unit: MINUTE
      requests_per_unit: 100
  - key: api_key_value
    rate_limit:
      unit: MINUTE
      requests_per_unit: 1000
```

### Step 8: Telemetry

```
envoy_http_downstream_rq_total{envoy_http_conn_manager_prefix}
envoy_http_downstream_rq_4xx{envoy_http_conn_manager_prefix}
envoy_http_downstream_rq_5xx{envoy_http_conn_manager_prefix}
envoy_http_downstream_rq_time_bucket
envoy_cluster_upstream_rq_total{envoy_cluster_name}
envoy_cluster_upstream_rq_timeout{envoy_cluster_name}
envoy_http_rbac_denied{envoy_http_conn_manager_prefix}
envoy_http_ext_authz_denied{envoy_http_conn_manager_prefix}
envoy_http_ext_authz_error{envoy_http_conn_manager_prefix}
envoy_listener_ssl_handshake{envoy_listener_address}
envoy_listener_ssl_fail_verify_cert_hash{envoy_listener_address}
```

Alert on:

- `envoy_http_ext_authz_error` non-zero — ext_authz service failing; requests denied (fail-closed).
- `envoy_http_rbac_denied` spike — unusual authorization failures, possible probing.
- `envoy_listener_ssl_fail_verify_cert_hash` — mTLS client cert verification failures; possible compromised or misconfigured client.
- Admin interface accessed from non-localhost — network policy or audit log alert.

## Expected Behaviour

| Signal | Default Envoy | Hardened Envoy |
|--------|--------------|----------------|
| Admin API access | Any network address | Localhost only; NetworkPolicy blocks pod-external access |
| Client-injected headers | Forwarded to upstream | Stripped and re-set by Envoy |
| Unauthenticated request to RBAC-protected route | Forwarded to upstream | HTTP 403 at proxy layer |
| ext_authz service unavailable | Requests pass through | HTTP 403 (fail-closed) |
| TLS 1.1 negotiation | Allowed | Rejected; TLS 1.2 minimum |
| mTLS client cert logged | Not logged | `peer_certificate_san_uri` in every access log line |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| ext_authz fail-closed | No auth bypass on authz service downtime | Outage of auth service = service unavailability | Run auth service in HA; monitor `ext_authz_error` metric; set appropriate timeout (2s). |
| Admin on localhost only | No admin API reconnaissance | Harder to debug in production | Use kubectl port-forward for admin access when needed; or a separate authenticated internal ingress. |
| Header stripping | Prevents auth bypass via injected headers | Breaks services that expect custom headers to pass through | Allowlist legitimate forwarded headers explicitly in the mutation filter. |
| RBAC default-deny | All unauthorized paths blocked at proxy | Initial setup must enumerate all legitimate access patterns | Use Envoy shadow mode (`shadow_rules`) to log would-be denials before enforcing. |
| TLS 1.3 only for internal | Forward-secrecy, stronger algorithms | Very old clients may not support TLS 1.3 | Internal services all support TLS 1.3; external-facing keeps TLS 1.2 minimum. |
| Rate limiting fail-closed | No bypass when rate limit service is down | Brief rate limit service restart causes 429 for all requests | Rate limit service should be highly available; consider local token bucket fallback. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| ext_authz gRPC connection failure | All requests return 403 | `envoy_http_ext_authz_error` spike; service alerts; `UAEX` in response flags | Restore ext_authz service; Envoy reconnects automatically. |
| RBAC policy too restrictive | Legitimate requests denied | 403 responses; application errors; `RBAC_DENY` response flag | Add the missing principal or permission; test with shadow rules first. |
| Header mutation breaks upstream | Upstream service fails because expected header missing | Application 400/500 errors for specific endpoints | Identify which header was stripped; add it to the allowlist in the mutation filter. |
| Admin API leaked via NodePort | Admin endpoint accessible from outside cluster | `envoy_http_conn_manager_prefix{manager="admin"}` shows unexpected traffic | Immediately remove the NodePort; audit NetworkPolicies; rotate any exfiltrated config. |
| TLS cipher mismatch | Old clients fail TLS handshake | `ssl_fail_verify_cert_hash` or TLS alert errors in access log | Add the required cipher back; plan client upgrades. |
| Rate limit service unavailable | All requests 429 (fail-closed) | `envoy_http_ratelimit_error` metric; widespread 429 responses | Restore rate limit service; Envoy reconnects automatically. |

## Related Articles

- [TLS Hardening for nginx and Envoy](/articles/network/tls-nginx-envoy/)
- [mTLS Service Mesh Hardening](/articles/network/mtls-service-mesh/)
- [Istio Egress Gateway and Egress Control](/articles/network/istio-egress-gateway/)
- [Rate Limiting at Ingress Scale](/articles/network/rate-limiting-ingress/)
- [OPA and Gatekeeper Policy Enforcement](/articles/kubernetes/kubernetes-admission-control/)
