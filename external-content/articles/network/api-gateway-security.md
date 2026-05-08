---
title: "API Gateway Security: Authentication, Authorization, and Request Validation"
description: "Without a centralized API gateway, authentication and authorization logic is duplicated in every backend service. This creates several problems:"
slug: "api-gateway-security"
date: 2026-03-30
lastmod: 2026-03-30
category: "network"
tags: ["api-gateway", "jwt", "oauth2", "kong", "apisix", "envoy", "request-validation", "authentication"]
personas: ["platform-engineer", "security-engineer"]
article_number: 40
difficulty: "intermediate"
estimated_reading_time: 22
provider_bridges:
  - name: "Kong"
    id: 86
    category: "api-gateway"
  - name: "APISIX"
    id: 89
    category: "api-gateway"
  - name: "Cloudflare"
    id: 29
    category: "cdn-edge"
premium_pack: "api-gateway-configs"
published: true
layout: article.njk
permalink: "/articles/network/api-gateway-security/index.html"
---

# API Gateway Security: Authentication, Authorization, and Request Validation

## Problem

Without a centralized API gateway, authentication and authorization logic is duplicated in every backend service. Each service independently validates JWTs, checks API keys, enforces rate limits, and validates request schemas. This creates several problems:

- **Inconsistent enforcement.** Service A validates JWTs correctly. Service B has a bug that accepts expired tokens. Service C skips validation entirely for "internal" endpoints that are actually reachable from the internet.
- **Duplicated security logic.** Every service implements its own token validation, and each implementation has subtly different behaviour around edge cases (clock skew tolerance, algorithm verification, audience checks).
- **No centralized audit trail.** Authentication and authorization decisions are scattered across service logs in different formats, making incident response slow and incomplete.
- **Schema validation is absent.** Without request validation at the gateway, malformed payloads reach backend services, which must each implement their own input validation or risk injection attacks.
- **API key management is ad hoc.** Keys are issued manually, stored in environment variables, never rotated, and have no scoping (a key with read access can also write).

An API gateway centralizes these concerns: one place to validate tokens, enforce authorization policies, validate request schemas, manage API keys, and log all access decisions.

The trade-off is operational complexity. The gateway becomes a critical path component. If it goes down, every API goes down. It requires high availability, TLS termination, and plugin maintenance.

**Target systems:** Kong 3.5+, Apache APISIX 3.8+, KrakenD 2.5+, and [Envoy](https://www.envoyproxy.io) Gateway 1.0+.

## Threat Model

- **Adversary:** External attacker with network access to API endpoints. May possess leaked or stolen API keys. May attempt to bypass authentication through malformed tokens, algorithm confusion attacks, or direct requests to backend services that bypass the gateway.
- **Access level:** Unauthenticated network access to the gateway. Potentially authenticated with a low-privilege or stolen credential.
- **Objective:** Access resources beyond their authorization level (horizontal or vertical privilege escalation). Exfiltrate data through API endpoints. Inject malicious payloads through unvalidated request bodies. Abuse API endpoints through credential stuffing or token manipulation.
- **Blast radius:** Without gateway-level authentication, every backend service is independently responsible for security. A single misconfigured service exposes its entire dataset. With a properly configured gateway, an attacker must first bypass centralized authentication.

## Configuration

### Kong: JWT Validation

Kong validates JWTs at the gateway layer before requests reach your backend services.

**Enable the JWT plugin on a service:**

```bash
# Create a service and route in Kong.
curl -s -X POST http://localhost:8001/services \
  -d name=api-service \
  -d url=http://api-backend:8080

curl -s -X POST http://localhost:8001/services/api-service/routes \
  -d name=api-route \
  -d 'paths[]=/api/v1'

# Enable JWT validation on the service.
curl -s -X POST http://localhost:8001/services/api-service/plugins \
  -d name=jwt \
  -d config.claims_to_verify=exp \
  -d config.key_claim_name=iss \
  -d config.secret_is_base64=false
```

**Create a JWT consumer and credential:**

```bash
# Create a consumer (represents an API client).
curl -s -X POST http://localhost:8001/consumers \
  -d username=mobile-app

# Create a JWT credential for the consumer.
# Kong will use this to validate incoming tokens.
curl -s -X POST http://localhost:8001/consumers/mobile-app/jwt \
  -d algorithm=RS256 \
  -d rsa_public_key="$(cat public-key.pem)" \
  -d key="https://auth.yourapp.com"
```

**Kong declarative configuration (recommended for production):**

```yaml
# kong.yaml - Declarative configuration
_format_version: "3.0"

services:
  - name: api-service
    url: http://api-backend:8080
    routes:
      - name: api-route
        paths:
          - /api/v1
        strip_path: false
    plugins:
      - name: jwt
        config:
          claims_to_verify:
            - exp
          key_claim_name: iss
          secret_is_base64: false
          run_on_preflight: true

      - name: acl
        config:
          allow:
            - admin-group
            - user-group
          hide_groups_header: true

      - name: request-size-limiting
        config:
          allowed_payload_size: 1
          size_unit: megabytes
          require_content_length: true

consumers:
  - username: mobile-app
    groups:
      - user-group
    jwt_secrets:
      - algorithm: RS256
        key: "https://auth.yourapp.com"
        rsa_public_key: |
          -----BEGIN PUBLIC KEY-----
          YOUR_RSA_PUBLIC_KEY_HERE
          -----END PUBLIC KEY-----
```

### APISIX: JWT and OAuth2 Token Introspection

APISIX supports JWT validation and OAuth2 token introspection for validating opaque tokens against an authorization server.

**JWT validation:**

```yaml
# apisix-routes.yaml
routes:
  - uri: /api/v1/*
    upstream:
      type: roundrobin
      nodes:
        "api-backend:8080": 1
    plugins:
      jwt-auth:
        header: Authorization
        query: token
        cookie: jwt
      consumer-restriction:
        whitelist:
          - mobile-app
          - web-app

consumers:
  - username: mobile-app
    plugins:
      jwt-auth:
        key: "mobile-app-key"
        algorithm: RS256
        public_key: |
          -----BEGIN PUBLIC KEY-----
          YOUR_RSA_PUBLIC_KEY_HERE
          -----END PUBLIC KEY-----
```

**OAuth2 token introspection (for opaque tokens):**

```yaml
# apisix-oauth2-route.yaml
routes:
  - uri: /api/v1/*
    upstream:
      type: roundrobin
      nodes:
        "api-backend:8080": 1
    plugins:
      openid-connect:
        client_id: "apisix-gateway"
        client_secret: "your-client-secret"
        discovery: "https://auth.yourapp.com/.well-known/openid-configuration"
        bearer_only: true
        realm: "api"
        introspection_endpoint: "https://auth.yourapp.com/oauth2/introspect"
        introspection_endpoint_auth_method: "client_secret_basic"
        token_signing_alg_values_expected:
          - RS256
        set_userinfo_header: true
```

### Envoy Gateway: JWT Authentication with OIDC

```yaml
# envoy-gateway-jwt.yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: SecurityPolicy
metadata:
  name: jwt-auth
  namespace: production
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: api-route
  jwt:
    providers:
      - name: auth-provider
        issuer: "https://auth.yourapp.com"
        audiences:
          - "api.yourapp.com"
        remoteJWKS:
          uri: "https://auth.yourapp.com/.well-known/jwks.json"
          cacheDuration: 300s
        claimToHeaders:
          - claim: sub
            header: X-User-Id
          - claim: role
            header: X-User-Role
```

### Request Schema Validation

Validate incoming request bodies against an OpenAPI specification at the gateway layer. This blocks malformed payloads before they reach your backend.

**Kong request-validator plugin:**

```yaml
# kong.yaml - Request validation plugin
plugins:
  - name: request-validator
    service: api-service
    config:
      body_schema: |
        {
          "type": "object",
          "required": ["name", "email"],
          "properties": {
            "name": {
              "type": "string",
              "minLength": 1,
              "maxLength": 100
            },
            "email": {
              "type": "string",
              "format": "email",
              "maxLength": 254
            },
            "role": {
              "type": "string",
              "enum": ["user", "admin", "viewer"]
            }
          },
          "additionalProperties": false
        }
      allowed_content_types:
        - application/json
      verbose_response: false
```

**APISIX request validation:**

```yaml
# apisix-request-validation.yaml
routes:
  - uri: /api/v1/users
    methods: ["POST", "PUT"]
    upstream:
      type: roundrobin
      nodes:
        "api-backend:8080": 1
    plugins:
      request-validation:
        body_schema:
          type: object
          required:
            - name
            - email
          properties:
            name:
              type: string
              minLength: 1
              maxLength: 100
            email:
              type: string
              pattern: "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
              maxLength: 254
            role:
              type: string
              enum:
                - user
                - admin
                - viewer
          additionalProperties: false
```

### API Key Management

**Kong key-auth plugin with scoped access:**

```yaml
# kong.yaml - API key authentication with ACL
services:
  - name: read-api
    url: http://api-backend:8080
    routes:
      - name: read-route
        paths:
          - /api/v1
        methods:
          - GET
          - HEAD
    plugins:
      - name: key-auth
        config:
          key_names:
            - X-API-Key
            - apikey
          hide_credentials: true
      - name: acl
        config:
          allow:
            - read-access
            - full-access

  - name: write-api
    url: http://api-backend:8080
    routes:
      - name: write-route
        paths:
          - /api/v1
        methods:
          - POST
          - PUT
          - DELETE
    plugins:
      - name: key-auth
        config:
          key_names:
            - X-API-Key
          hide_credentials: true
      - name: acl
        config:
          allow:
            - full-access

consumers:
  - username: read-only-partner
    keyauth_credentials:
      - key: "partner-read-key-rotated-2026-04"
    acls:
      - group: read-access

  - username: internal-service
    keyauth_credentials:
      - key: "internal-svc-key-rotated-2026-04"
    acls:
      - group: full-access
```

### Payload Size Limits

```yaml
# Kong: request size limiting
plugins:
  - name: request-size-limiting
    service: api-service
    config:
      allowed_payload_size: 1
      size_unit: megabytes
      require_content_length: true
```

```yaml
# APISIX: client max body size
routes:
  - uri: /api/v1/*
    plugins:
      client-control:
        max_body_size: 1048576  # 1 MB in bytes
```

## Expected Behaviour

```bash
# Test JWT authentication (Kong).
# Request without token: rejected.
curl -s -o /dev/null -w "%{http_code}" https://api.yourapp.com/api/v1/users
# Expected: 401

# Request with valid token: accepted.
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  https://api.yourapp.com/api/v1/users
# Expected: 200

# Request with expired token: rejected.
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs...expired..." \
  https://api.yourapp.com/api/v1/users
# Expected: 401

# Test API key authentication.
curl -s -o /dev/null -w "%{http_code}" \
  -H "X-API-Key: partner-read-key-rotated-2026-04" \
  https://api.yourapp.com/api/v1/users
# Expected: 200

# Test API key with insufficient permissions (read key on write endpoint).
curl -s -o /dev/null -w "%{http_code}" \
  -H "X-API-Key: partner-read-key-rotated-2026-04" \
  -X POST -d '{"name":"test"}' \
  https://api.yourapp.com/api/v1/users
# Expected: 403

# Test request schema validation (invalid body).
curl -s -w "\n%{http_code}" \
  -H "Authorization: Bearer valid-token" \
  -H "Content-Type: application/json" \
  -X POST -d '{"invalid_field": "value"}' \
  https://api.yourapp.com/api/v1/users
# Expected: 400

# Test oversized payload.
dd if=/dev/zero bs=1M count=2 | curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer valid-token" \
  -X POST -d @- https://api.yourapp.com/api/v1/upload
# Expected: 413
```

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Gateway-level JWT validation | Centralizes token validation; backends receive pre-validated identity | Gateway becomes single point of failure for auth; JWKS endpoint downtime blocks all auth | Cache JWKS keys with long TTL; deploy gateway in HA (3+ replicas) |
| OAuth2 token introspection | Supports opaque tokens; can revoke tokens instantly | Every request triggers a call to the authorization server; adds 5-20ms latency | Cache introspection results for short TTL (30-60 seconds); use JWT for most endpoints |
| Request schema validation | Blocks malformed payloads before they reach backends | Schema must be updated when API changes; stale schema blocks valid requests | Version schemas alongside API deployments; use CI/CD to sync OpenAPI specs to gateway |
| API key at gateway | Centralizes key management; hides keys from backends (`hide_credentials`) | Key compromise requires gateway-level rotation; all keys in one system | Scope keys with ACL groups; rotate keys regularly; use short-lived tokens for high-security endpoints |
| `additionalProperties: false` | Rejects unexpected fields (prevents parameter pollution) | Clients sending extra fields get 400 errors; breaks forward compatibility | Only enforce on endpoints where strict validation matters; allow extra fields on others |
| Payload size limits | Prevents memory exhaustion from oversized requests | Legitimate large payloads (file uploads) rejected | Configure per-route limits; exempt upload endpoints |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| JWKS endpoint unreachable | All JWT-authenticated requests return 401; cached keys eventually expire | Gateway logs show JWKS fetch failures; 401 rate spikes across all services | Verify JWKS endpoint health; increase cache TTL as a buffer; consider embedding public keys as fallback |
| Gateway down (all replicas) | All API traffic returns 502 or connection refused | Load balancer health checks fail; uptime monitoring alerts | Deploy 3+ gateway replicas across availability zones; configure health checks with short intervals |
| Token validation too permissive | Expired or malformed tokens accepted; unauthorized access | Security audit reveals accepted tokens that should be rejected | Verify `claims_to_verify` includes `exp`; verify `algorithm` is pinned (not `none`) |
| Schema validation blocks valid requests | Clients receive 400 for requests that the backend would accept | 400 error rate increases after gateway or schema update | Review schema against actual API contract; relax schema or update it to match current API behaviour |
| API key leaked | Unauthorized access using the compromised key | Unusual traffic patterns from the key (geographic anomaly, request volume spike) | Revoke the key immediately in the gateway; issue a new key to the legitimate consumer |
| Clock skew causes JWT rejection | Valid tokens rejected because gateway clock is ahead of the issuer | Intermittent 401 errors; tokens work on some gateway replicas but not others | Sync clocks with NTP; configure clock skew tolerance in JWT validation (e.g., `clock_skew_seconds: 30`) |

## When to Consider a Managed Alternative

**Transition point:** When maintaining a self-hosted API gateway (HA deployment, plugin updates, certificate rotation, configuration management) across multiple environments consumes more than 8-16 hours per month. Or when you need features beyond basic auth: bot detection, API analytics, developer portal, or automatic OpenAPI schema discovery.

**What managed providers handle:**

- **[Kong](https://konghq.com) Enterprise:** Managed control plane (Konnect) with free tier for up to 3 services. Includes a developer portal, API analytics, automated credential rotation, and Vault integration for secrets. The data plane runs in your infrastructure; the control plane is managed.

- **[Cloudflare](https://www.cloudflare.com) API Shield:** Validates API requests at the edge using uploaded OpenAPI schemas. Rejects non-conforming requests before they reach your origin. Includes mTLS client certificate validation, JWT validation, and automatic API discovery that maps your actual API surface.

- **[APISIX](https://apisix.apache.org):** Open-source with no enterprise paywall for core security features (JWT, key-auth, request validation). API7.ai offers a managed control plane for multi-cluster APISIX deployments.

**What you still control:** Authorization policies (who can access what) are always your responsibility. The gateway provider handles the infrastructure and plugin execution; you define the security policies, token issuers, API key scoping, and request schemas. No provider can auto-generate your authorization model.


## Related Articles

- [Rate Limiting at the Ingress Layer: NGINX, Envoy, and Cloud Load Balancers Compared](/articles/network/rate-limiting-ingress/)
- [Hardening WebSocket Connections: Authentication, Rate Limiting, and Origin Validation](/articles/network/websocket-hardening/)
- [gRPC Security in Production: TLS, Authentication, and Interceptor-Based Access Control](/articles/network/grpc-security/)
- [TLS 1.3 Configuration for NGINX and Envoy: Ciphers, Certificates, and OCSP Stapling](/articles/network/tls-nginx-envoy/)
- [Preventing HTTP Request Smuggling: Configuration for NGINX, HAProxy, and Envoy](/articles/network/request-smuggling-prevention/)
