---
title: "Traefik ForwardAuth Authentication Bypass: CVE-2026-35051"
description: "CVE-2026-35051 allows authentication bypass in Traefik's ForwardAuth middleware when trustForwardHeader=false but Traefik sits behind a trusted upstream proxy. Patch to v2.11.43/v3.6.14 and audit header stripping in multi-proxy deployments."
slug: traefik-forwardauth-bypass
date: 2026-05-07
lastmod: 2026-05-07
category: network
tags:
  - traefik
  - authentication-bypass
  - forwardauth
  - cve
  - proxy
personas:
  - platform-engineer
  - security-engineer
article_number: 449
difficulty: Intermediate
estimated_reading_time: 10
published: true
layout: article.njk
permalink: /articles/network/traefik-forwardauth-bypass/
---

# Traefik ForwardAuth Authentication Bypass: CVE-2026-35051

## The Problem

CVE-2026-35051 (CVSS 8.1, disclosed April 24 2026) is an authentication bypass in Traefik's ForwardAuth middleware that affects all Traefik v2 releases before v2.11.43 and all v3 releases before v3.6.14. The bypass is possible in the common deployment pattern where Traefik sits behind a cloud load balancer or another proxy, and `trustForwardHeader=false` is set with the intention of preventing clients from spoofing `X-Forwarded-*` headers.

ForwardAuth works by forwarding every incoming request to an external authentication service — Authelia, oauth2-proxy, a custom JWT validator — and allowing or denying the request based on whether that service returns 200 or 401. This is one of the most common patterns for implementing authentication at the ingress layer in Kubernetes and Docker Swarm deployments. `trustForwardHeader=false` is documented as the setting that prevents downstream clients from injecting `X-Forwarded-*` headers to influence routing or bypass checks.

The flaw: Traefik correctly applies `trustForwardHeader=false` to IP-routing decisions (it will not use a client-supplied `X-Forwarded-For` to determine whether the client is "internal"), but in the vulnerable versions the ForwardAuth middleware does not strip identity-assertion headers — specifically `X-Forwarded-User` and `X-Forwarded-Groups` — before forwarding the request to the auth service. If an `X-Forwarded-User: admin` header arrives from anywhere upstream, the auth service receives it and, depending on its configuration, may treat it as a pre-authenticated identity and return 200 without performing any credential check.

The root cause is a missing header-stripping step in the ForwardAuth middleware. The middleware is supposed to present the auth service with a clean request that contains only the information Traefik itself can vouch for. Instead, it forwards the full set of incoming headers, including identity assertions that have no business reaching the auth service unless the auth service itself set them on a previous response.

**Who is exposed.** Any deployment where:

1. Traefik is behind an upstream proxy (cloud load balancer, CDN, Nginx, HAProxy, another Traefik instance).
2. That upstream proxy adds or passes through `X-Forwarded-User`, `X-Forwarded-Groups`, `X-Auth-Request-User`, or similar headers.
3. The ForwardAuth auth service trusts those headers as identity assertions.

The third condition — the auth service trusting a pre-set header — is the default behavior in several popular auth services. oauth2-proxy, when used with `--skip-provider-button` and a reverse-proxy trust configuration, will accept an incoming `X-Forwarded-User` header as the authenticated user. Authelia with certain trusted proxy configurations exhibits similar behavior. The assumption in those services is that the proxy layer (Traefik) has already validated the header before passing it through.

## Threat Model

**Attacker who controls headers at or before the upstream proxy.** The most direct attack path is an attacker who can manipulate the upstream proxy's behavior. In a misconfigured cloud deployment — common in AWS Application Load Balancer setups — the ALB is configured to add `X-Forwarded-For` to requests but does not explicitly block client-supplied `X-Forwarded-User` headers. The ALB passes the client's `X-Forwarded-User: admin` header through to Traefik unchanged. Traefik passes it to the auth service. The auth service returns 200. Traefik allows the request.

**HTTP request smuggling to inject headers.** An attacker can use HTTP/1.1 request smuggling at the upstream proxy layer to inject arbitrary headers into a request that the upstream proxy forwards to Traefik. This is a technique for bypassing WAF and proxy controls that has been well-documented since 2019. A smuggled request with `X-Forwarded-User: admin` injected into the header block lands in Traefik with an identity assertion the auth service will trust.

**Compromised outer proxy in a multi-Traefik deployment.** When one Traefik instance (edge) proxies to another (internal), the internal Traefik may be configured to trust the edge Traefik's forwarded headers for IP purposes. An attacker who compromises the edge Traefik — or exploits a misconfiguration on it — can set `X-Forwarded-User` to any value on requests forwarded to the internal Traefik, bypassing ForwardAuth on any route behind the internal instance.

**Attacker access level required.** The attack is exploitable from the internet in deployments where the upstream cloud load balancer passes through client-supplied headers unchanged. It does not require any credentials, prior access, or knowledge of the auth service's internal implementation. The attacker needs only to know (or guess) a valid username that the auth service will accept. In many deployments that username is `admin`, `root`, or the primary service account name.

**Blast radius.** Full authentication bypass on every ForwardAuth-protected route in the affected Traefik instance. The attacker gains access as the injected user identity, which in most deployments means full application access with whatever permissions that user has.

## Hardening Configuration

### Step 1: Patch to v2.11.43+ or v3.6.14+

Verify the running Traefik version:

```bash
traefik version
```

For Kubernetes deployments using the official Traefik Helm chart, update the image tag in your values file and roll out the update:

```bash
helm upgrade traefik traefik/traefik \
  --namespace traefik \
  --reuse-values \
  --set image.tag=v3.6.14
```

Verify the rollout:

```bash
kubectl rollout status deployment/traefik -n traefik
kubectl get pods -n traefik -o jsonpath='{.items[*].spec.containers[*].image}'
```

For Docker Compose deployments, update the image tag in your compose file and recreate the container:

```yaml
services:
  traefik:
    image: traefik:v3.6.14
```

```bash
docker compose pull traefik
docker compose up -d traefik
```

After patching, the ForwardAuth middleware strips `X-Forwarded-User`, `X-Forwarded-Groups`, and similar identity headers before forwarding to the auth service. The fix in v2.11.43 and v3.6.14 adds an explicit blocklist of identity-assertion headers that are removed from the request Traefik sends to the auth service, regardless of upstream trust settings.

### Step 2: Audit ForwardAuth Middleware Configuration

Review every ForwardAuth middleware definition in your Traefik configuration. The key settings are `trustForwardHeader` and `authResponseHeaders`.

`trustForwardHeader` should be `false` in virtually all deployments. Setting it `true` tells Traefik to trust `X-Forwarded-*` headers from any upstream for IP determination — a setting that makes sense only in very specific controlled environments.

`authResponseHeaders` controls which headers the auth service's response are forwarded to backend services. This list should be explicitly enumerated and minimal. If the auth service sets `X-Forwarded-User` in its response and that header is in `authResponseHeaders`, it will be passed to the backend — this is the intended behavior. What you must prevent is the same header being passed to the auth service from an upstream source before the auth service has had a chance to set it.

Example ForwardAuth middleware configuration (Kubernetes CRD):

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: forward-auth
  namespace: default
spec:
  forwardAuth:
    address: http://authelia:9091/api/verify
    trustForwardHeader: false
    authResponseHeaders:
      - X-Forwarded-User
      - X-Forwarded-Groups
      - X-Forwarded-Email
    authRequestHeaders:
      - Accept
      - Cookie
      - Authorization
```

The `authRequestHeaders` field, available in Traefik v2.6+ and v3+, restricts which headers from the incoming request are forwarded to the auth service. If you specify `authRequestHeaders`, only the listed headers are included in the request to the auth service — all others, including any upstream-injected identity headers, are excluded. This is an effective defense-in-depth control even on patched versions:

```yaml
spec:
  forwardAuth:
    address: http://authelia:9091/api/verify
    trustForwardHeader: false
    authRequestHeaders:
      - Accept
      - Cookie
      - Authorization
      - X-Original-URL
    authResponseHeaders:
      - X-Forwarded-User
      - X-Forwarded-Groups
      - X-Forwarded-Email
      - X-Auth-Request-Access-Token
```

By enumerating `authRequestHeaders`, you ensure that `X-Forwarded-User` is never sent to the auth service as part of the request from Traefik, even if it is present in the incoming request.

### Step 3: Strip Identity Headers at the Upstream Proxy

Patch the ForwardAuth middleware, but also harden the upstream layer so injected headers never reach Traefik at all. This provides defense-in-depth and protects against similar issues in other middleware or future vulnerabilities.

For Nginx acting as an upstream proxy to Traefik:

```nginx
location / {
    proxy_set_header X-Forwarded-User "";
    proxy_set_header X-Forwarded-Groups "";
    proxy_set_header X-Forwarded-Email "";
    proxy_set_header X-Auth-Request-User "";
    proxy_set_header X-Auth-Request-Email "";
    proxy_set_header X-Auth-Request-Access-Token "";
    proxy_set_header X-Remote-User "";
    proxy_set_header X-Remote-Groups "";

    proxy_pass http://traefik:80;
}
```

Setting these headers to an empty string in `proxy_set_header` causes Nginx to send the header with an empty value, which overwrites any client-supplied value. To suppress the header entirely (not send it to the upstream at all), use a map with an empty string and the `proxy_set_header` form with a conditional:

```nginx
map $http_x_forwarded_user $stripped_x_forwarded_user {
    default "";
}

server {
    location / {
        proxy_set_header X-Forwarded-User $stripped_x_forwarded_user;
        proxy_pass http://traefik:80;
    }
}
```

For HAProxy:

```
frontend traefik_frontend
    bind *:443 ssl crt /etc/haproxy/certs/
    http-request del-header X-Forwarded-User
    http-request del-header X-Forwarded-Groups
    http-request del-header X-Forwarded-Email
    http-request del-header X-Auth-Request-User
    http-request del-header X-Auth-Request-Email
    http-request del-header X-Remote-User
    http-request del-header X-Remote-Groups
    default_backend traefik_backend
```

For AWS Application Load Balancer, header modification rules are configured via Listener Rules. In the AWS Console or via Terraform, add a header-removal rule before the forwarding action. Note that ALB does not support deleting arbitrary custom headers in all configurations — if your ALB cannot strip these headers, implement the stripping in Nginx or HAProxy sitting between the ALB and Traefik.

### Step 4: Audit ForwardAuth Deployments with Test Requests

For each ForwardAuth-protected route, verify that a request with a pre-injected `X-Forwarded-User` header is rejected — not passed through as an authenticated identity.

Test against a protected route using `curl`. The test should return 401 or redirect to the login page, not a 200 with the application response:

```bash
curl -v \
  -H "X-Forwarded-User: admin" \
  -H "X-Forwarded-Groups: admins" \
  https://your-protected-app.example.com/api/admin/users
```

On a patched and correctly configured deployment, the injected `X-Forwarded-User` header is stripped before reaching the auth service, and the request is evaluated as unauthenticated. Expected response: 401 or 302 redirect to login.

On a vulnerable deployment, the auth service receives `X-Forwarded-User: admin`, interprets it as a pre-authenticated identity, and returns 200 — Traefik then allows the request to reach the backend.

Also test that the auth flow still works correctly for legitimate authenticated requests:

```bash
curl -v \
  -b "authelia_session=<valid-session-cookie>" \
  https://your-protected-app.example.com/api/admin/users
```

This should return 200 with the application response, confirming that stripping `X-Forwarded-User` from the request to the auth service has not broken the legitimate authentication path. The session cookie is the credential, and the auth service sets `X-Forwarded-User` in its response after validating it — the header flows to the backend via `authResponseHeaders`, not from the client.

Automate this test as part of your CI/CD pipeline or post-deployment smoke tests.

### Step 5: Migrate to Signed Token-Based Identity

Header injection attacks are fundamentally possible because `X-Forwarded-User` is an unsigned string that any party in the request chain can forge. Signed JWTs cannot be forged without the signing key, which eliminates the entire class of header-injection identity bypass.

Configure oauth2-proxy to issue signed JWT tokens in the `Authorization` header instead of plain identity headers:

```yaml
# oauth2-proxy configuration
set_authorization_header: true
set_xauthrequest: false
pass_user_headers: false
jwt_key: /etc/oauth2-proxy/jwt-signing-key.pem
jwt_key_file: true
```

With `set_authorization_header: true` and `set_xauthrequest: false`, oauth2-proxy sets a signed `Authorization: Bearer <jwt>` header in the auth response instead of `X-Forwarded-User`. The backend services validate the JWT signature rather than trusting a plain string header.

Update the ForwardAuth `authResponseHeaders` to forward the `Authorization` header:

```yaml
spec:
  forwardAuth:
    address: http://oauth2-proxy:4180/oauth2/auth
    trustForwardHeader: false
    authResponseHeaders:
      - Authorization
    authRequestHeaders:
      - Cookie
      - Accept
```

Backend services then validate the JWT using the public key. An attacker cannot forge the `Authorization` header without the signing key — injecting an arbitrary `Authorization: Bearer <crafted-token>` will fail signature validation.

## Expected Behaviour After Hardening

After patching Traefik to v2.11.43+ or v3.6.14+ and configuring `authRequestHeaders` with an explicit allowlist, a request with `X-Forwarded-User: admin` injected by a client is handled as follows:

1. The upstream proxy (Nginx, HAProxy, or a configured ALB rule) strips `X-Forwarded-User` from the request before it reaches Traefik.
2. Traefik's ForwardAuth middleware, even if the header were to arrive, does not include `X-Forwarded-User` in the request it sends to the auth service (because `authRequestHeaders` does not list it, and the patched middleware strips it regardless).
3. The auth service receives a request with no identity assertion. It evaluates the session cookie or `Authorization` header. Finding neither, it returns 401.
4. Traefik returns 401 to the client. The injected identity is never trusted.

The legitimate auth flow is unaffected: a request with a valid session cookie proceeds through ForwardAuth, the auth service validates the cookie, sets `X-Forwarded-User` in its response, and that header (originating from the auth service, not the client) is forwarded to the backend via `authResponseHeaders`.

## Trade-offs and Operational Considerations

Stripping `X-Forwarded-*` headers at the upstream proxy requires auditing every service that relies on those headers being passed through from upstream. Some deployments use `X-Forwarded-For` to implement IP-based access controls or logging. Removing all `X-Forwarded-*` headers wholesale will break those flows. Strip only the identity-assertion headers (`X-Forwarded-User`, `X-Forwarded-Groups`, `X-Forwarded-Email`, `X-Auth-Request-*`, `X-Remote-User`, `X-Remote-Groups`) and preserve IP-forwarding headers (`X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`) after verifying they cannot be used for auth bypass in your auth service.

Using `authRequestHeaders` to allowlist headers sent to the auth service is a breaking change if your auth service relies on headers not in the list. Before enabling `authRequestHeaders`, check what headers your auth service reads from the incoming request. Authelia reads `X-Original-URL` to determine which resource is being accessed — that header must be in the allowlist. oauth2-proxy in some configurations reads `X-Forwarded-Host`. Audit the auth service's documentation and test in a non-production environment before rolling out.

Migrating from header-based to JWT-based identity is a larger change that requires updates to both the auth service configuration and every backend application that consumes user identity. Backend services that currently read `X-Forwarded-User` must be updated to parse and validate a JWT from the `Authorization` header. This is the right long-term direction — the migration effort is the cost of having built on an insecure foundation.

## Failure Modes

**Traefik patched but upstream load balancer still passes client-controlled identity headers.** Patching Traefik closes the gap in the ForwardAuth middleware, but if the upstream proxy passes `X-Forwarded-User` from clients through to Traefik unchanged, and the auth service trusts that header, the bypass is still possible via the auth service's own logic. Stripping at the upstream proxy is a required layer of the fix, not optional defense-in-depth.

**`authResponseHeaders` configured too broadly.** If `authResponseHeaders` includes headers that clients can also inject — because the auth service echoes request headers in its response rather than setting only headers it has verified — then the auth service becomes a reflection vector. An attacker injects `X-Forwarded-User: admin` in the request; the auth service returns it unchanged in the response (perhaps as part of a catch-all response header policy); Traefik's `authResponseHeaders` forwards it to the backend. Enumerate `authResponseHeaders` explicitly and verify each header is only ever set by the auth service from validated data.

**Audit test uses a known-bad username value that the auth service rejects.** Testing only `X-Forwarded-User: admin` may give false confidence if the auth service only trusts specific, non-obvious usernames. A thorough audit includes testing with usernames that are valid in the underlying identity provider (LDAP, OIDC, Active Directory), not just common default names. Automate enumeration of all usernames that the auth service would accept via the header injection path.

**`authRequestHeaders` allowlist incomplete, causing auth service errors.** If `authRequestHeaders` is set but the auth service requires a header not in the list, the auth service may return a non-200 response that Traefik interprets as a denial — blocking all legitimate traffic. Test the `authRequestHeaders` configuration against all protected routes before production rollout.

## Related Articles

- [Traefik Auth Middleware Security](/articles/network/traefik-auth-middleware-security/)
- [Rate Limiting Ingress](/articles/network/rate-limiting-ingress/)
- [HTTP Security Headers](/articles/network/http-security-headers/)
- [Envoy Security Hardening](/articles/network/envoy-security-hardening/)
- [Load Balancer Security](/articles/network/load-balancer-security/)
