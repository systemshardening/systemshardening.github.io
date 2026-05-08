---
title: "gRPC API Gateway Patterns: Authentication, Rate Limiting, and Request Validation at the Edge"
description: "gRPC services exposed through API gateways face unique security challenges: gRPC-Web transcoding introduces injection surfaces, metadata headers can carry internal routing information past the edge, and per-method rate limiting requires gRPC-aware configuration."
slug: "grpc-api-gateway-patterns"
date: 2026-04-12
lastmod: 2026-04-12
category: "network"
tags: ["grpc", "api-gateway", "envoy", "rate-limiting", "grpc-web", "authentication"]
personas: ["platform-engineer", "devops-engineer"]
article_number: 148
difficulty: "intermediate"
estimated_reading_time: 20
published: true
layout: article.njk
permalink: "/articles/network/grpc-api-gateway-patterns/index.html"
---

# gRPC API Gateway Patterns: Authentication, Rate Limiting, and Request Validation at the Edge

## Problem

Exposing gRPC services through an API gateway introduces security problems that do not exist with pure internal gRPC communication:

- **gRPC-Web transcoding trusts client-supplied JSON blindly.** The [Envoy](https://www.envoyproxy.io) `grpc_json_transcoder` filter converts HTTP/JSON requests into gRPC calls. If the transcoder does not validate the JSON against the proto schema, malformed or oversized payloads pass through to the backend service unfiltered.
- **No per-method rate limiting.** Standard HTTP rate limiting applies uniformly to all endpoints. gRPC multiplexes many methods over one path prefix, so a rate limiter that counts requests to `/` does not distinguish between a cheap `GetUser` call and an expensive `RunReport` call. The expensive method remains unprotected.
- **Internal metadata leaks past the edge.** gRPC metadata (HTTP/2 headers) carries internal routing hints, trace IDs, and service identity information. If the gateway does not strip internal headers before forwarding external requests, an attacker can inject metadata like `x-internal-service: admin` and bypass downstream authorization checks.
- **No proto schema validation at the edge.** Breaking changes to protobuf schemas (removing required fields, changing field types) are deployed without detection. Clients receive cryptic deserialization errors instead of clear validation failures.
- **Authentication is done in every service instead of once at the edge.** Each gRPC service implements its own token validation interceptor. Inconsistent implementations mean some services accept expired tokens or skip audience validation.

**Target systems:** gRPC services exposed to external clients through Envoy, Kong, or a custom API gateway. Includes gRPC-Web frontends (browser clients), mobile clients using gRPC directly, and partner integrations using gRPC or transcoded REST.

## Threat Model

- **Adversary:** External attacker with access to the public API gateway endpoint. Malicious or compromised client application. Partner with valid credentials attempting to access unauthorized methods.
- **Access level:** Authenticated access to the API gateway with a valid token. May have credentials scoped to one service but attempting to call methods on another.
- **Objective:** Bypass rate limiting on expensive RPCs to cause resource exhaustion. Inject internal metadata headers to escalate privileges or alter routing. Submit malformed protobuf messages that crash or confuse backend services. Call methods that should not be exposed externally by guessing service/method paths.
- **Blast radius:** Rate limiting bypass can exhaust backend resources for all clients. Metadata injection can affect any downstream service that trusts forwarded headers. A single broken proto change can break all clients simultaneously.

## Configuration

### gRPC-Web Transcoding with Envoy

The `grpc_json_transcoder` filter converts RESTful HTTP/JSON requests into gRPC. You must configure it with the compiled proto descriptor to enforce schema validation:

```bash
# Compile the proto descriptor binary for Envoy
protoc \
  --include_imports \
  --include_source_info \
  --descriptor_set_out=api_descriptor.pb \
  --proto_path=./proto \
  proto/payments/v1/payments.proto
```

```yaml
# envoy-grpc-gateway.yaml - gRPC-Web transcoding with security controls
static_resources:
  listeners:
    - name: grpc_gateway
      address:
        socket_address:
          address: 0.0.0.0
          port_value: 443
      filter_chains:
        - transport_socket:
            name: envoy.transport_sockets.tls
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
              common_tls_context:
                tls_params:
                  tls_minimum_protocol_version: TLSv1_3
                tls_certificates:
                  - certificate_chain:
                      filename: /etc/envoy/certs/server.crt
                    private_key:
                      filename: /etc/envoy/certs/server.key
          filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: grpc_gateway
                codec_type: AUTO

                route_config:
                  name: gateway_routes
                  virtual_hosts:
                    - name: api
                      domains: ["api.company.com"]
                      routes:
                        # gRPC-Web transcoded routes (JSON to gRPC)
                        - match:
                            prefix: "/v1/payments"
                          route:
                            cluster: payments_service
                            timeout: 10s
                        # Native gRPC routes
                        - match:
                            prefix: "/payments.v1.PaymentService/"
                            grpc: {}
                          route:
                            cluster: payments_service
                            timeout: 10s
                        # Block all other paths
                        - match:
                            prefix: "/"
                          direct_response:
                            status: 404

                http_filters:
                  # 1. External auth - validate tokens at the edge
                  - name: envoy.filters.http.ext_authz
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
                      grpc_service:
                        envoy_grpc:
                          cluster_name: auth_service
                        timeout: 2s
                      failure_mode_allow: false
                      with_request_body:
                        max_request_bytes: 1048576
                        allow_partial_message: false
                        pack_as_bytes: true
                      clear_route_cache: false
                      transport_api_version: V3
                      # Only send safe headers to auth service
                      allowed_headers:
                        patterns:
                          - exact: "authorization"
                          - exact: "x-request-id"

                  # 2. gRPC-JSON transcoder
                  - name: envoy.filters.http.grpc_json_transcoder
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.grpc_json_transcoder.v3.GrpcJsonTranscoder
                      proto_descriptor: "/etc/envoy/api_descriptor.pb"
                      services:
                        - "payments.v1.PaymentService"
                      print_options:
                        add_whitespace: false
                        always_print_primitive_fields: true
                      # Reject unknown fields - prevents injection of
                      # fields not in the proto schema
                      request_validation_options:
                        reject_unknown_method: true
                        reject_unknown_query_parameters: true
                      # Reject requests with unknown fields in the JSON body
                      convert_grpc_status: true
                      # Limit body size to prevent oversized payloads
                      max_request_body_size: 1048576

                  # 3. Rate limiting
                  - name: envoy.filters.http.ratelimit
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.ratelimit.v3.RateLimit
                      domain: grpc_gateway
                      failure_mode_deny: true
                      rate_limit_service:
                        grpc_service:
                          envoy_grpc:
                            cluster_name: ratelimit_service
                        transport_api_version: V3

                  # 4. Header sanitisation - strip internal headers
                  - name: envoy.filters.http.lua
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua
                      inline_code: |
                        function envoy_on_request(handle)
                          -- Remove internal-only metadata that external
                          -- clients should never set
                          handle:headers():remove("x-internal-service")
                          handle:headers():remove("x-internal-caller-id")
                          handle:headers():remove("x-forwarded-user-role")
                          handle:headers():remove("x-debug-mode")
                          handle:headers():remove("grpc-previous-rpc-attempts")
                        end

                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
```

### Envoy ext_authz for gRPC Authentication

The external authorization service validates tokens and returns authorization context:

```go
// authz-server.go - External authorization service for Envoy
package main

import (
    "context"
    "log"
    "strings"

    core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
    auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
    envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
    "google.golang.org/genproto/googleapis/rpc/status"
    "google.golang.org/grpc/codes"
)

type AuthzServer struct{}

func (s *AuthzServer) Check(
    ctx context.Context,
    req *auth.CheckRequest,
) (*auth.CheckResponse, error) {
    headers := req.Attributes.Request.Http.Headers
    authHeader := headers["authorization"]

    if authHeader == "" {
        return denied(codes.Unauthenticated, "missing authorization header"), nil
    }

    token := strings.TrimPrefix(authHeader, "Bearer ")
    claims, err := validateToken(token)
    if err != nil {
        return denied(codes.Unauthenticated, "invalid token"), nil
    }

    // Check method-level authorization
    grpcMethod := headers[":path"]
    if !isMethodAllowed(claims.Subject, claims.Scopes, grpcMethod) {
        return denied(codes.PermissionDenied, "method not allowed"), nil
    }

    // Pass validated identity downstream as trusted headers
    return &auth.CheckResponse{
        Status: &status.Status{Code: int32(codes.OK)},
        HttpResponse: &auth.CheckResponse_OkResponse{
            OkResponse: &auth.OkHttpResponse{
                Headers: []*core.HeaderValueOption{
                    {
                        Header: &core.HeaderValue{
                            Key:   "x-authenticated-user",
                            Value: claims.Subject,
                        },
                        AppendAction: core.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
                    },
                    {
                        Header: &core.HeaderValue{
                            Key:   "x-authenticated-scopes",
                            Value: strings.Join(claims.Scopes, ","),
                        },
                        AppendAction: core.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
                    },
                },
            },
        },
    }, nil
}

func denied(code codes.Code, msg string) *auth.CheckResponse {
    return &auth.CheckResponse{
        Status: &status.Status{Code: int32(code)},
        HttpResponse: &auth.CheckResponse_DeniedResponse{
            DeniedResponse: &auth.DeniedHttpResponse{
                Status: &envoy_type.HttpStatus{
                    Code: envoy_type.StatusCode_Forbidden,
                },
                Body: msg,
            },
        },
    }
}
```

### Per-Method Rate Limiting with Descriptors

Configure rate limit descriptors so each gRPC method gets its own budget:

```yaml
# ratelimit-config.yaml - Per-method rate limits for gRPC
domain: grpc_gateway
descriptors:
  # Cheap read operations: 1000 req/min per client
  - key: method
    value: "/payments.v1.PaymentService/GetPayment"
    rate_limit:
      unit: minute
      requests_per_unit: 1000

  - key: method
    value: "/payments.v1.PaymentService/ListPayments"
    rate_limit:
      unit: minute
      requests_per_unit: 500

  # Expensive write operations: 50 req/min per client
  - key: method
    value: "/payments.v1.PaymentService/CreatePayment"
    rate_limit:
      unit: minute
      requests_per_unit: 50

  - key: method
    value: "/payments.v1.PaymentService/RefundPayment"
    rate_limit:
      unit: minute
      requests_per_unit: 20

  # Report generation: 5 req/min per client
  - key: method
    value: "/payments.v1.PaymentService/GenerateReport"
    rate_limit:
      unit: minute
      requests_per_unit: 5

  # Default: catch-all for unlisted methods
  - key: method
    rate_limit:
      unit: minute
      requests_per_unit: 100
```

To make Envoy send method-based descriptors, add rate limit actions to each route:

```yaml
# Add to each route in envoy config
routes:
  - match:
      prefix: "/payments.v1.PaymentService/"
      grpc: {}
    route:
      cluster: payments_service
      rate_limits:
        - actions:
            - header_value_match:
                descriptor_key: "method"
                descriptor_value: ""
                headers:
                  - name: ":path"
                    string_match:
                      prefix: "/payments.v1.PaymentService/"
            - request_headers:
                header_name: ":path"
                descriptor_key: "method"
```

### Proto Schema Validation with Buf

Detect breaking changes before they reach production:

```yaml
# buf.yaml - Schema configuration
version: v2
modules:
  - path: proto
lint:
  use:
    - STANDARD
  except:
    - FIELD_NOT_REQUIRED
breaking:
  use:
    - WIRE_JSON
    # Prevents: removing fields, changing field types,
    # renaming services/methods, changing field numbers
```

```yaml
# .github/workflows/proto-validation.yml
name: Proto Schema Validation
on:
  pull_request:
    paths:
      - "proto/**"

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - uses: bufbuild/buf-setup-action@v1
        with:
          version: "1.32.0"

      - name: Lint protos
        run: buf lint

      - name: Check for breaking changes
        run: buf breaking --against "https://github.com/${{ github.repository }}.git#branch=main"

      - name: Regenerate descriptor for Envoy
        run: |
          protoc \
            --include_imports \
            --descriptor_set_out=api_descriptor.pb \
            --proto_path=./proto \
            proto/payments/v1/payments.proto

          # Verify the descriptor matches what is deployed
          sha256sum api_descriptor.pb > descriptor.sha256
          echo "Descriptor hash: $(cat descriptor.sha256)"
```

### Kong gRPC Gateway Plugin

For teams using [Kong](https://konghq.com) instead of Envoy:

```yaml
# kong-grpc-gateway.yaml - Kong declarative config for gRPC
_format_version: "3.0"

services:
  - name: payments-grpc
    url: grpc://payments-service.production.svc.cluster.local:8443
    protocol: grpc
    routes:
      - name: payments-grpc-route
        protocols:
          - grpcs
        paths:
          - /payments.v1.PaymentService
    plugins:
      # Authentication at the edge
      - name: jwt
        config:
          claims_to_verify:
            - exp
          key_claim_name: iss
          secret_is_base64: false
          header_names:
            - authorization

      # Per-method rate limiting
      - name: rate-limiting
        config:
          minute: 100
          policy: redis
          redis:
            host: redis.infrastructure.svc.cluster.local
            port: 6379
            password: ${REDIS_PASSWORD}
            ssl: true

      # Request size limiting
      - name: request-size-limiting
        config:
          allowed_payload_size: 1  # 1 MB
          size_unit: megabytes

      # gRPC-Web transcoding
      - name: grpc-web
        config:
          proto: /etc/kong/proto/payments.proto
          pass_stripped_path: true

      # Strip internal headers
      - name: request-transformer
        config:
          remove:
            headers:
              - x-internal-service
              - x-internal-caller-id
              - x-forwarded-user-role
              - x-debug-mode
```

### Metadata Sanitisation Checklist

Headers that must be stripped from external requests at the gateway:

```yaml
# metadata-strip-list.yaml - Headers to remove from external requests
# Apply via Envoy Lua filter, Kong request-transformer, or gateway middleware

internal_headers_to_strip:
  # Service identity headers (set by internal services only)
  - "x-internal-service"
  - "x-internal-caller-id"
  - "x-service-version"

  # Authorization context (set by auth middleware, not clients)
  - "x-forwarded-user-role"
  - "x-authenticated-user"
  - "x-authenticated-scopes"

  # Debug and tracing (should not be client-controlled in production)
  - "x-debug-mode"
  - "x-force-trace"

  # gRPC internal metadata
  - "grpc-previous-rpc-attempts"
  - "grpc-retry-pushback-ms"
  - "grpc-tags-bin"

  # Envoy internal headers
  - "x-envoy-upstream-service-time"
  - "x-envoy-expected-rq-timeout-ms"
  - "x-envoy-original-path"
```

## Expected Behaviour

After applying the gateway configuration:

```bash
# Verify gRPC-Web transcoding rejects unknown fields
curl -X POST https://api.company.com/v1/payments \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"amount": 100, "currency": "USD", "unknown_field": "inject"}'
# Expected: 400 Bad Request - unknown field rejected by transcoder

# Verify per-method rate limiting
for i in $(seq 1 25); do
  grpcurl \
    -cacert /etc/certs/ca.crt \
    -H "authorization: Bearer $TOKEN" \
    -d '{"payment_id": "pay_123"}' \
    api.company.com:443 payments.v1.PaymentService/RefundPayment
done
# Expected: First 20 succeed, remaining 5 return RESOURCE_EXHAUSTED

# Verify internal header stripping
grpcurl \
  -cacert /etc/certs/ca.crt \
  -H "authorization: Bearer $TOKEN" \
  -H "x-internal-service: admin" \
  -H "x-forwarded-user-role: superadmin" \
  api.company.com:443 payments.v1.PaymentService/GetPayment
# Expected: Request succeeds but x-internal-service and
# x-forwarded-user-role are NOT visible to the backend service

# Verify unauthenticated requests are rejected
grpcurl -cacert /etc/certs/ca.crt \
  api.company.com:443 payments.v1.PaymentService/GetPayment
# Expected: UNAUTHENTICATED - "missing authorization header"

# Verify breaking proto changes are caught
cd proto/ && buf breaking --against "https://github.com/company/api.git#branch=main"
# Expected: Error if a field was removed or type changed
```

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| ext_authz at gateway | All requests validated before reaching backends; consistent auth | Auth service is a single point of failure; adds 1-5ms latency | Run auth service with 3+ replicas; set `failure_mode_allow: false` to deny on auth failure |
| Per-method rate limiting | Expensive RPCs are protected from abuse | Rate limit configuration must be updated when adding new methods | Default rate limit catches unlisted methods; review rate limits during method addition |
| gRPC-JSON transcoder with reject_unknown | Prevents field injection through transcoded requests | Legitimate clients using newer proto versions may be rejected | Version the API (v1, v2) and maintain separate descriptors per version |
| Header stripping via Lua filter | Prevents metadata injection from external clients | Lua filter errors can block all traffic | Test Lua filters in staging; use `pcall` for error handling in Lua scripts |
| Buf breaking change detection | Catches incompatible proto changes before deployment | False positives for intentional breaking changes (API migrations) | Use `buf breaking` exemptions for planned migrations; document in PR |
| Kong gRPC-Web plugin | Simpler configuration than raw Envoy for teams already using Kong | Kong adds a proxy hop; gRPC performance overhead compared to native | Benchmark throughput; use native gRPC for high-performance internal paths |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| ext_authz service down | All requests rejected (failure_mode_allow: false) | 100% error rate on gateway; auth service health check failures | Scale up auth service; if extended outage, temporarily switch to JWT validation in Envoy (not ext_authz) |
| Stale proto descriptor on Envoy | Transcoded requests fail with "unknown method" or field mapping errors | Client error rate increases after proto update; Envoy logs show transcoding failures | Rebuild and redeploy the descriptor file; automate descriptor generation in CI |
| Rate limit service unreachable | All requests rejected (failure_mode_deny: true) | Spike in RESOURCE_EXHAUSTED errors without corresponding traffic increase | Ensure rate limit service is highly available; consider switching to local rate limiting as fallback |
| Lua filter syntax error | Envoy rejects configuration; no traffic served | Envoy fails to start; configuration validation errors in logs | Validate Lua syntax in CI; use Envoy configuration validation before deployment |
| Header stripping incomplete | Internal headers pass through to backends; potential privilege escalation | Security audit finds internal headers in backend access logs from external requests | Maintain a tested allowlist of permitted headers rather than a denylist of stripped headers |

## When to Consider a Managed Alternative

**Transition point:** When maintaining custom Envoy configuration for gRPC transcoding, rate limiting, and authentication across multiple API surfaces becomes operationally expensive, or when you need features like API versioning, developer portals, and usage analytics that go beyond proxy configuration.

**What managed alternatives handle:**

- **API management platforms ([Apigee](https://cloud.google.com/apigee), [AWS API Gateway](https://aws.amazon.com/api-gateway/)):** Managed gRPC transcoding, rate limiting with developer-specific quotas, API key management, and analytics dashboards. Apigee supports gRPC proxying with built-in threat protection. AWS API Gateway supports gRPC routes with IAM-based authorization.

- **Managed service mesh ([GCP Traffic Director](https://cloud.google.com/traffic-director), [AWS App Mesh](https://aws.amazon.com/app-mesh/)):** xDS-based configuration management for gRPC load balancing and routing without managing your own Envoy control plane.

**What you still control:** Proto schema design and evolution policy, business-specific rate limit thresholds, method-level authorization rules (which scopes can call which RPCs), and the decision of which internal services to expose externally.

## Related Articles

- [gRPC Security in Production: TLS, Authentication, and Interceptor-Based Access Control](/articles/network/grpc-security/)
- [gRPC Load Balancing Security: Client-Side, Proxy, and Service Mesh Patterns](/articles/network/grpc-load-balancing-security/)
- [API Gateway Security: Authentication, Rate Limiting, and Input Validation](/articles/network/api-gateway-security/)
- [Rate Limiting at the Ingress Layer: Token Buckets, Sliding Windows, and Distributed Counters](/articles/network/rate-limiting-ingress/)
- [HTTP Security Headers: Content-Security-Policy, HSTS, and Beyond](/articles/network/http-security-headers/)
- [Request Smuggling Prevention: HTTP Desync Attacks and Proxy Chain Hardening](/articles/network/request-smuggling-prevention/)
