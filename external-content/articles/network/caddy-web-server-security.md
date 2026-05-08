---
title: "Caddy Web Server Security Hardening"
description: "Harden Caddy against CVE-2026-27586 mTLS silent fail, CVE-2026-27589 admin API CSRF, CVE-2026-30851 forward_auth header bypass—and Caddy's pattern of batching security fixes into routine releases."
slug: caddy-web-server-security
date: 2026-05-03
lastmod: 2026-05-03
category: network
tags: ["caddy", "cve-2026-27586", "cve-2026-27589", "mtls", "admin-api", "forward-auth", "tls"]
personas: ["systems-engineer", "sre", "security-engineer"]
article_number: 385
difficulty: advanced
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/network/caddy-web-server-security/index.html"
---

# Caddy Web Server Security Hardening

## Problem

Caddy is an open source web server and reverse proxy written in Go. Its defining characteristic is automatic HTTPS: out of the box, Caddy provisions and renews TLS certificates from Let's Encrypt or ZeroSSL, manages ACME challenges, and enforces HTTPS redirects — all without operator intervention. Configuration can be expressed either in the concise Caddyfile syntax or in a structured JSON format delivered through a live HTTP admin API. An active plugin ecosystem extends Caddy into L7 load balancer, authentication gateway, and GitOps-managed ingress roles. These properties make Caddy the default choice for self-hosted services, containerised applications, and operators who want production-grade TLS without running a separate certificate management system. Its footprint in Kubernetes sidecars, homelab infrastructure, and small-team SaaS deployments has grown substantially as an alternative to nginx.

Caddy's automatic HTTPS has a structural consequence that is easy to miss: when TLS configuration is wrong, Caddy's default behaviour is to stay up rather than refuse to start. This preference for availability is sensible for certificate provisioning failures — a brief ACME outage should not take down your site — but it becomes dangerous when applied to security-critical configuration like mutual TLS client authentication. **CVE-2026-27586**, disclosed February 23, 2026, exposed exactly this failure mode. When the CA certificate file configured for mTLS client authentication was missing, malformed, or unreadable, Caddy did not exit or log an error. Instead it silently loaded the system CA pool as the trusted client CA pool and continued serving traffic. Any client presenting a certificate signed by any system-trusted CA — including public CAs such as Let's Encrypt, DigiCert, and Google Trust Services — was treated as authenticated.

The operational impact of CVE-2026-27586 is severe because it is invisible. Operators who deployed Caddy with `client_auth { mode require_and_verify; trusted_ca_cert_file /etc/caddy/client-ca.pem }` and then moved the CA file, rotated it, or introduced a typo in the path received no error, no warning log, and no startup failure. The service continued running. Requests appeared to succeed. Meanwhile, the mTLS boundary that was supposed to enforce service-to-service identity — permitting only services holding certificates issued by the internal private CA — was silently accepting any certificate signed by any of the hundreds of publicly trusted CAs embedded in the operating system. An attacker obtaining a free Let's Encrypt certificate for any domain could present it to the internal service and be passed through as an authenticated client.

**CVE-2026-27589**, also disclosed February 23, 2026, affects Caddy's admin API. By default, Caddy exposes a management API on `localhost:2019` that accepts JSON configuration over HTTP. This API includes a `/load` endpoint that replaces the entire running Caddy configuration atomically. The vulnerability: the admin API did not enforce Origin header validation on incoming requests, making it vulnerable to cross-site request forgery. A malicious web page visited by a developer with the admin API running could issue a cross-origin POST to `http://localhost:2019/load` containing a replacement Caddy configuration — one that proxies all traffic to an attacker-controlled host, strips TLS, or disables authentication. Because the browser follows the same-origin policy for responses but not for POST requests to `localhost` in all configurations, the attack was feasible from a malicious page visited in a standard browser.

**CVE-2026-30851**, disclosed March 7, 2026 with CVSS 8.1, affects Caddy's `forward_auth` directive. The `forward_auth` directive delegates authentication to an external auth server — Authentik, Authelia, and similar systems — by forwarding each incoming request, waiting for the auth server to accept or reject it, and then copying specified headers from the auth server's response to the backend request. The vulnerability: Caddy failed to strip client-supplied headers that matched the headers the auth server was expected to set. A client sending `X-Auth-User: admin` in their original request would have this header forwarded to the backend verbatim, alongside whatever `X-Auth-User` header the auth server returned. Backend applications that trusted `X-Auth-User` for identity — a common pattern when the auth proxy is assumed to be authoritative — would accept the attacker-controlled value. The auth server's response might have been accepted normally, but the attacker's pre-supplied identity header arrived at the backend first or was duplicated in a way that allowed header precedence exploitation.

Caddy's release process compresses security fixes into normal version releases with minimal security-specific labelling. The v2.11.1 release on February 23, 2026 fixed CVE-2026-27586, CVE-2026-27589, and CVE-2026-27590 (a FastCGI path confusion vulnerability affecting Unicode path components). The release notes described these as "security fixes" but did not include CVE numbers at time of publication — numbers were filed separately and appeared later. CVE-2026-30851 landed in v2.11.2 on March 7, 2026. This pattern — multiple CVEs batched into a point release, numbers filed after the fact, fixes visible in the public commit history before the advisory is formalised — creates a patch-gap window. Operators monitoring only the GitHub releases page without reading diffs miss the severity signal until advisories are filed. Effective coverage requires subscribing to `https://github.com/caddyserver/caddy/security/advisories` and monitoring commit activity in `modules/caddytls/` and `modules/caddyhttp/reverseproxy/` with tools like:

```bash
# Check recent releases for security keywords
gh api repos/caddyserver/caddy/releases \
  --jq '.[0:5] | .[] | select(.body | test("security|CVE|fix.*tls|fix.*auth|fix.*csrf"; "i")) | {tag: .tag_name, body: .body[:200]}'
```

Target systems: Caddy < v2.11.1 (CVE-2026-27586, CVE-2026-27589, CVE-2026-27590), Caddy < v2.11.2 (CVE-2026-30851); all deployment methods including binary, Docker, Helm chart, and package manager installs.

## Threat Model

1. **CVE-2026-27586 mTLS silent fail — public CA impersonation**: An internal API is protected by mTLS and trusts only certificates from the organisation's private CA. An operator has rotated the CA file, introducing a path misconfiguration. Caddy silently falls back to the system CA pool. An attacker who knows the internal API endpoint obtains a free Let's Encrypt certificate for any domain, presents it via `curl --cert attacker.crt --key attacker.key`, and Caddy forwards the connection to the backend marked as TLS-authenticated. The backend application treats the connection as from a trusted internal service and grants full API access.

2. **CVE-2026-27589 CSRF on admin API — configuration replacement**: A developer runs Caddy locally with the default admin API on `localhost:2019` and visits a malicious web page (phishing link, compromised documentation site). The page issues a cross-origin POST to `http://localhost:2019/load` with a JSON body containing a replacement Caddy config that proxies `example.com` to `attacker.example.com`. The admin API accepts the request, applies the new config atomically, and begins forwarding traffic. The developer's Caddy instance is now exfiltrating traffic to the attacker's endpoint with no visible error.

3. **CVE-2026-30851 forward_auth header bypass — identity injection**: An application sits behind Caddy with `forward_auth` delegating to Authentik. The application trusts the `X-Auth-User` header for identity. An attacker crafts a request with `X-Auth-User: admin` in the client request headers. Caddy forwards the request to Authentik, which authenticates the attacker as a normal user and sets `X-Auth-User: attacker@example.com`. Without the fix, Caddy may pass both the client-supplied and auth-server-supplied headers to the backend. The backend processes the first `X-Auth-User: admin` header and grants administrative access. The fix requires Caddy to strip all client-supplied instances of headers listed in `copy_headers` before forwarding to the backend.

4. **Patch-gap attacker — pre-advisory exploitation**: The attacker monitors the Caddy GitHub repository and observes the v2.11.1 release with commit messages referencing "fix mTLS client CA fallback" and "validate Origin header on admin API." They identify these as security-relevant changes before CVE numbers are published. They enumerate Caddy deployments in their target organisation (via HTTP response headers, certificate transparency logs, or internal asset inventory) and find servers still running v2.10.x. They have a window of days to weeks before the advisory formalises, during which most automated vulnerability scanners carry no signal.

The blast radius of these vulnerabilities spans the authentication perimeter. CVE-2026-27586 collapses the mTLS boundary entirely for any service relying on Caddy for client certificate enforcement — every internal API trusting that boundary is exposed. CVE-2026-30851 allows identity escalation to any privilege level representable by the identity headers the auth server sets. CVE-2026-27589 allows full configuration replacement, enabling traffic interception, TLS stripping, or service disruption. The combination of all three in deployments running pre-v2.11.1 Caddy as an authentication gateway represents a complete compromise of the authentication and transport security layers.

## Configuration / Implementation

### Upgrading Caddy

The primary remediation for all three CVE groups is upgrading to the correct Caddy version. Target v2.11.2 or later to cover all four CVEs.

**Package manager installs:**

```bash
# Debian/Ubuntu
apt-get update && apt-get install --only-upgrade caddy

# macOS
brew upgrade caddy

# Verify installed version
caddy version
# Expected: v2.11.2 or later
```

**Docker:**

```bash
# Pull the patched image
docker pull caddy:2.11.2

# Or pin to the latest stable
docker pull caddy:latest

# Verify
docker run --rm caddy:2.11.2 caddy version
```

**Kubernetes deployment:**

```bash
# Update the container image in-place
kubectl set image deployment/caddy caddy=caddy:2.11.2

# Verify rollout
kubectl rollout status deployment/caddy

# Check the running version
kubectl exec -it deploy/caddy -- caddy version
```

**Helm chart (if using the official Caddy chart):**

```bash
helm upgrade caddy caddy/caddy \
  --set image.tag=2.11.2 \
  --reuse-values
```

### mTLS Verification After Upgrade (CVE-2026-27586)

After upgrading, confirm that mTLS is actually enforcing client certificate validation against your private CA — not silently accepting public CA certificates.

**Caddyfile configuration for strict mTLS:**

```
example.internal {
  tls {
    client_auth {
      mode require_and_verify
      trusted_ca_cert_file /etc/caddy/client-ca.pem
    }
  }
  reverse_proxy localhost:8080
}
```

**Critical:** verify that `/etc/caddy/client-ca.pem` exists, is readable by the Caddy process, and contains your private CA certificate. With the patch applied, a missing or unreadable file causes Caddy to log an error and refuse to serve that site.

**Test that a valid private-CA client certificate is accepted:**

```bash
curl \
  --cert /etc/caddy/valid-client.crt \
  --key /etc/caddy/valid-client.key \
  --cacert /etc/caddy/server-ca.pem \
  https://example.internal/health
# Expected: HTTP 200
```

**Test that a public-CA or self-signed certificate is rejected:**

```bash
# Generate a throwaway self-signed cert for testing
openssl req -x509 -newkey rsa:2048 -keyout bad-client.key \
  -out bad-client.crt -days 1 -nodes \
  -subj "/CN=attacker-test"

curl \
  --cert bad-client.crt \
  --key bad-client.key \
  --cacert /etc/caddy/server-ca.pem \
  https://example.internal/health
# Expected: curl: (56) OpenSSL SSL_read: error:... (TLS handshake failure)

# Using openssl s_client for detailed output
openssl s_client \
  -connect example.internal:443 \
  -cert bad-client.crt \
  -key bad-client.key 2>&1 | grep -E "alert|verify|error"
# Expected: "alert certificate unknown" or "verify error"
```

If the second test returns HTTP 200 on a patched Caddy, the `trusted_ca_cert_file` path is still wrong and Caddy has fallen back to silent-fail behaviour — check file permissions and the Caddy process user.

### Admin API Hardening (CVE-2026-27589)

The admin API should never be accessible from arbitrary network origins. Apply the most restrictive option appropriate for your deployment.

**Option 1 — Restrict to loopback only (default, explicit):**

```
{
  admin localhost:2019
}
```

This is Caddy's default but making it explicit ensures the configuration survives future default changes.

**Option 2 — Disable entirely in production:**

```
{
  admin off
}
```

Appropriate for deployments where configuration changes go through image rebuilds or GitOps pipelines rather than the live API.

**Option 3 — Unix socket for local tooling:**

```
{
  admin unix//run/caddy/admin.sock
}
```

Restricts access to processes with filesystem permissions on the socket. Set the socket to mode `0600` owned by the Caddy user.

**Firewall enforcement (defence in depth, even with loopback binding):**

```bash
# Allow admin API from localhost only
iptables -A INPUT -p tcp --dport 2019 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 2019 -j DROP

# Persist across reboots (Debian/Ubuntu)
apt-get install -y iptables-persistent
netfilter-persistent save

# Verify
iptables -L INPUT -n --line-numbers | grep 2019
```

**Test that cross-origin POST is rejected (patched behaviour):**

```bash
# This should return 403 or be blocked after the patch
curl -X POST http://localhost:2019/load \
  -H "Content-Type: application/json" \
  -H "Origin: http://evil.example.com" \
  -d '{"apps":{}}'
# Expected on patched Caddy: HTTP 403 Forbidden
```

### forward_auth Header Stripping (CVE-2026-30851)

After upgrading to v2.11.2, Caddy strips client-supplied instances of any header listed in `copy_headers` before the request reaches the backend. Verify this is working and ensure your `copy_headers` allowlist covers all identity headers your backend trusts.

**Caddyfile `forward_auth` with explicit header allowlist:**

```
example.com {
  @authenticated {
    not path /public/*
  }

  handle @authenticated {
    forward_auth auth.internal:9091 {
      uri /api/verify
      copy_headers X-Auth-User X-Auth-Email X-Auth-Groups X-Auth-Name
    }
    reverse_proxy backend:8080
  }

  handle /public/* {
    reverse_proxy backend:8080
  }
}
```

The `copy_headers` directive specifies the exact headers to copy from the auth server's response. Only these headers are forwarded to the backend. Client-supplied values for these headers are stripped by the patched Caddy before the auth server is consulted.

**Test that client-supplied identity headers are stripped:**

```bash
# Attempt header injection — should be stripped before reaching backend
curl https://example.com/protected \
  -H "X-Auth-User: admin" \
  -H "X-Auth-Email: admin@example.com" \
  -v 2>&1

# Check backend logs — X-Auth-User should reflect the auth server's value,
# not the client-supplied "admin" value
```

**Backend-side defence (additional layer):** configure your backend application to only trust identity headers when the request comes from the Caddy proxy's IP address. This limits the blast radius if Caddy's header stripping is ever bypassed.

### FastCGI Path Security (CVE-2026-27590)

If running PHP or other FastCGI applications via Caddy's `php_fastcgi` or `fastcgi` directive, upgrading to v2.11.1+ fixes a Unicode-aware path confusion issue where non-ASCII path components could be used to bypass extension matching.

**Verification:**

```bash
# Test with URL-encoded Unicode path component that should NOT match PHP
curl -v "https://example.com/uploads/image%E2%80%8E.jpg.php"
# Expected: 404 or static file response, NOT PHP execution

# Verify standard PHP execution still works
curl -v "https://example.com/index.php"
# Expected: HTTP 200 from PHP
```

### Monitoring Caddy Releases

Caddy's pattern of batching security fixes into point releases without pre-advisory notification requires active monitoring.

**Check recent releases for security-relevant content:**

```bash
gh api repos/caddyserver/caddy/releases \
  --jq '.[0:3] | .[] | {tag: .tag_name, date: .published_at, body: .body[:300]}'
```

**Watch for security-relevant commits in key modules:**

```bash
# Commits to TLS client auth code
gh api repos/caddyserver/caddy/commits \
  --field path=modules/caddytls/ \
  --jq '.[0:5] | .[] | {sha: .sha[:8], message: .commit.message[:100], date: .commit.author.date}'

# Commits to reverse proxy / forward_auth code
gh api repos/caddyserver/caddy/commits \
  --field path=modules/caddyhttp/reverseproxy/ \
  --jq '.[0:5] | .[] | {sha: .sha[:8], message: .commit.message[:100], date: .commit.author.date}'
```

**Subscribe to GitHub Security Advisories:** visit `https://github.com/caddyserver/caddy/security/advisories` and enable notifications. GitHub allows per-repository advisory subscriptions without watching all repository activity.

**Renovate for Docker image automation:**

```json
{
  "packageRules": [
    {
      "matchPackageNames": ["caddy"],
      "matchDatasources": ["docker"],
      "automerge": false,
      "prPriority": 10,
      "labels": ["security-review-required"]
    }
  ]
}
```

Setting `automerge: false` with a high priority and a security label ensures Caddy image updates reach the review queue promptly without bypassing human sign-off.

## Expected Behaviour

| Signal | Unpatched Caddy (< v2.11.1 / < v2.11.2) | Patched + Hardened Config |
|---|---|---|
| mTLS with missing CA cert file | Caddy starts silently; accepts any certificate signed by system-trusted CA; no error in logs | Caddy logs error on startup; refuses to serve the affected site; operator sees clear failure |
| mTLS with public-CA client certificate | Connection succeeds; backend receives request as authenticated | TLS handshake fails; client receives alert; backend never reached |
| Admin API CSRF from malicious page | POST to `/load` succeeds; Caddy config replaced silently | POST rejected with HTTP 403; Origin header mismatch logged |
| Admin API accessible from non-localhost | Reachable from any host that can route to port 2019 | Firewall drops packets; admin listener bound to loopback or socket only |
| forward_auth with injected identity header | Client `X-Auth-User: admin` reaches backend alongside auth server header | Client-supplied `X-Auth-User` stripped before auth check; backend receives only auth server value |
| Patch-gap via release diff inspection | No CVE numbers in release; diff shows security-relevant changes without public advisory | GitHub Advisory subscription delivers notification; Renovate surfaces version bump promptly |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Admin API disabled (`admin off`) | Eliminates CSRF attack surface entirely; removes network-exposed management endpoint | Loses ability to reload config without restarting Caddy; breaks CI pipelines that push config updates via API | Use GitOps with config baked into container image; trigger reload via `SIGHUP` to Caddy process rather than API; reserve API for development environments only |
| mTLS strict mode (`require_and_verify`) | Enforces mutual authentication; no unauthenticated connections reach backend | Any client CA cert rotation or expiry immediately breaks service; misconfigured file path causes startup failure (now visible post-patch) | Automate CA cert renewal checks; monitor Caddy startup logs in health checks; test cert rotation in staging before production |
| forward_auth `copy_headers` allowlist | Precisely controls which identity headers reach the backend; eliminates injection surface | Requires manual update when auth server adds new identity headers; too-narrow allowlist causes missing auth attributes at backend | Document all headers your auth server sets; alert on `copy_headers` changes in code review; test auth server header changes against the allowlist in CI |
| Caddy upgrade frequency | Caddy releases frequently; security fixes arrive quickly after discovery | High release cadence means frequent image rebuilds and rollouts; regression risk on Caddyfile syntax changes between minor versions | Pin to specific patch versions in production; run Caddyfile validation (`caddy validate --config /etc/caddy/Caddyfile`) in CI before deploying |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| mTLS breaks after CA cert rotation (wrong file path) | On patched Caddy: Caddy refuses to serve the site; upstream health checks fail; `502` or connection refused from load balancer. On pre-patch Caddy: silent fallback to public CA trust | On patched Caddy: Caddy startup logs show `failed to load client CA: open /etc/caddy/client-ca.pem: no such file or directory`; alerting on Caddy process exit or failed health check | Copy the new CA certificate to the path Caddy expects; or update `trusted_ca_cert_file` to the new path; reload with `systemctl reload caddy` or `SIGHUP` |
| Admin API disabled breaks CI deployment automation | CI pipeline step that pushes config via `curl -X POST localhost:2019/load` fails; deployment blocked | CI job failure with `curl: (7) Failed to connect to localhost port 2019`; pipeline alert | Switch CI to build a new container image with updated Caddyfile and redeploy; or use `caddy reload --config` from within the container; or temporarily re-enable admin API on a restricted socket for the deploy step |
| `copy_headers` allowlist too narrow (auth attributes missing at backend) | Backend returns 401 or renders partial user data; auth-dependent features fail silently or with application errors | Backend application logs show missing identity header; end-to-end auth tests fail in post-deploy smoke tests | Add the missing header name to `copy_headers` in the Caddyfile; reload Caddy config; maintain a test that sends a request through the full auth path and asserts all expected headers arrive at the backend |
| Caddy upgrade changes Caddyfile syntax (service fails to start) | Caddy container or service fails to start after image update; all traffic lost | Container exit code non-zero; Caddy logs show `parsing caddyfile: ...` syntax error; load balancer marks all backends unhealthy | Roll back to previous image tag; review Caddy upgrade changelog for deprecated directives; run `caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile` against the new binary before deploying |

## Related Articles

- [NGINX Hardening Beyond TLS](/articles/network/nginx-hardening-beyond-tls/)
- [Traefik Auth Middleware Security](/articles/network/traefik-auth-middleware-security/)
- [mTLS and Service Mesh Security](/articles/network/mtls-service-mesh/)
- [HTTP Security Headers](/articles/network/http-security-headers/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
