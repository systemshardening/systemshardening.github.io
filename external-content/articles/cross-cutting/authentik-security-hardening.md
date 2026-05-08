---
title: "Authentik Identity Provider Security Hardening"
description: "Harden Authentik against CVE-2026-25227 RCE via delegated property mapping execution and CVE-2026-25748 forward auth bypass with Traefik/Caddy—and monitor Authentik's public-commit-before-advisory pattern."
slug: authentik-security-hardening
date: 2026-05-03
lastmod: 2026-05-03
category: cross-cutting
tags: ["authentik", "cve-2026-25227", "cve-2026-25748", "rce", "forward-auth", "identity-provider", "oauth"]
personas: ["security-engineer", "platform-engineer", "sre"]
article_number: 381
difficulty: advanced
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/cross-cutting/authentik-security-hardening/index.html"
---

# Authentik Identity Provider Security Hardening

## Problem

Authentik is an open source identity provider written in Python and Django. It implements OAuth 2.0, OpenID Connect, SAML, LDAP, and forward authentication (proxy provider mode), and is increasingly deployed as a self-hosted alternative to Auth0, Okta, and Keycloak. Its Python-native stack and low operational overhead make it particularly popular as the SSO gateway for internal tooling: Kubernetes dashboards, developer portals, code review systems, monitoring stacks, and CI/CD pipelines all frequently sit behind an Authentik proxy provider. Because it acts as the centralised trust anchor for those downstream applications, a compromise of Authentik is effectively a compromise of every service behind it.

In April and May 2026, two high-severity vulnerabilities were disclosed that affect a broad range of deployed Authentik versions. Both vulnerabilities share a common characteristic: they exploit the intersection of Authentik's flexible, code-capable configuration model with its RBAC permission system — a combination that is central to Authentik's power as a platform but that also creates attack surface that does not exist in identity providers with simpler configuration models.

**CVE-2026-25227** (April-May 2026, High — arbitrary code execution) arises from a permission boundary failure in the Property Mapping and Expression Policy test execution endpoints. Property Mappings and Expression Policies are a core Authentik feature: they allow administrators to write Python code that is evaluated at runtime to transform user attributes, calculate group memberships, or implement custom authentication logic. Authentik exposes test execution endpoints at `/api/v3/propertymappings/*/test_user/` and `/api/v3/policies/expression/*/test_user/` that were designed to let administrators validate their code against real user data. However, Authentik's RBAC allowed users holding only the "view Property Mapping" or "view Expression Policy" permissions — not the more privileged "manage" permissions — to invoke these test execution endpoints via the API. The Python code in Property Mappings and Expression Policies runs inside Django's process with full access to the Authentik database connection and ORM. An attacker with "view Property Mapping" access who can influence the content of an existing mapping (or who finds one whose Python code reads user-controlled input) can trigger arbitrary Python execution with access to every table in the Authentik database: user passwords (hashed), OAuth tokens, refresh tokens, session data, and the LDAP bind credentials stored for LDAP sources. This vulnerability affects Authentik 2021.3.1 through versions before 2025.8.6, 2025.10.4, and 2025.12.4.

**CVE-2026-25748** (April-May 2026, authentication bypass) exploits a cookie parsing discrepancy in Authentik's forward authentication (proxy provider) mode when Traefik or Caddy is the front-end proxy. In proxy provider mode, Authentik acts as an authentication middleware: the proxy forwards every request to Authentik, Authentik checks the session cookie, and if authentication is valid it sets `X-Authentik-Username`, `X-Authentik-Groups`, and related headers before returning a 200 response that allows the proxy to forward the request to the backend application. CVE-2026-25748 involved a malformed cookie value that Authentik's session validation code accepted but that Traefik and Caddy parsed differently at the HTTP layer — the cookie was accepted as valid by Authentik's Python code, causing Authentik to set the authentication headers with a blank or default user identity and return a success response. The backend application received the authentication headers indicating a successful check, but the actual user identity was unauthenticated. This means that the application receives `X-Authentik-Username: ` (empty) or a platform default rather than a real username, but the authentication gate itself passes.

The compound risk of these two CVEs in a single identity provider is significant. Authentik is not just protecting individual applications — it is the authentication layer for an entire platform. CVE-2026-25227's RCE gives an attacker not just Authentik administrative access but full database access: every user's credentials, every issued OAuth token, every active session, and every LDAP source bind password stored in Authentik. A successful exploit can be used to issue forged tokens for downstream services, extract plaintext credentials from LDAP source configurations, and backdoor Expression Policies to fire malicious code on every subsequent authentication event. CVE-2026-25748 is lower severity in isolation but is particularly dangerous in multi-tenant platforms where the backend application uses the `X-Authentik-Username` header to determine data isolation boundaries — an empty or default username may trigger access to data belonging to a default account rather than a real user.

Authentik is maintained primarily by Jens Langhammer and a small contributing team at `github.com/goauthentik/authentik`. The project publishes CVE advisories at `https://docs.goauthentik.io/security/cves/` alongside fixes, but the project's small team size and public repository create a monitoring pattern worth understanding. Both CVE-2026-25227 and CVE-2026-25748 had their fix commits visible in the public Authentik repository before the formal advisory was published. The fix for CVE-2026-25227 added permission checks to the test execution endpoints in `authentik/policies/expression/api.py` and `authentik/core/api/propertymappings.py` — these changes were visible in the repository for approximately three to five days before the CVE identifier was formally published. Security researchers who monitor Authentik's API files for newly added permission checks can identify the vulnerability and the affected endpoint from the diff alone, before a patch announcement directs attention to it. Authentik also backports security fixes across multiple concurrent release lines — the fix appears in separate commits on the 2025.8.x, 2025.10.x, and 2025.12.x branches simultaneously — which makes the advisory footprint visible earlier for watchers of the repository's commit history across all active branches.

**Target systems:** Authentik < 2025.8.6, < 2025.10.4, < 2025.12.4 (CVE-2026-25227); Authentik < 2025.10.4, < 2025.12.4 (CVE-2026-25748) with Traefik/Caddy proxy providers.

## Threat Model

1. **CVE-2026-25227 — delegated RCE via Property Mapping test execution**: An Authentik user who holds the "view Property Mapping" permission — which organisations often grant broadly so that teams can inspect their own attribute mappings without requiring admin access — calls the test execution API (`POST /api/v3/propertymappings/<pk>/test_user/`) against a Property Mapping whose Python code reads from the Authentik database. The attacker does not need to create or modify a Property Mapping; they only need to invoke the test endpoint against an existing one that has code reading user or token tables. The result is arbitrary Python execution inside the Django process with full ORM access: all hashed user passwords, all issued OAuth and refresh tokens, LDAP source bind credentials (stored as plaintext in Authentik's database), and session signing keys are all accessible to a single successful test execution call.

2. **CVE-2026-25748 — forward auth bypass with Traefik or Caddy**: An attacker sends an HTTP request to a resource protected by an Authentik proxy provider behind Traefik, including a malformed `authentik_session` cookie crafted to pass Authentik's Python-side session validation while triggering a parsing discrepancy in Traefik's HTTP layer. Authentik returns a 200 with `X-Authentik-Username: ` and `X-Authentik-Authenticated: true`. Traefik forwards the request to the backend application with these headers intact. The application, which trusts the `X-Authentik-Username` header as proof of authenticated identity, grants access. Depending on how the application handles an empty username — defaulting to a guest account, a superuser, or throwing an unhandled exception — the effective access level varies but the authentication check is definitively bypassed.

3. **Patch-gap attacker targeting CVE-2026-25227**: A researcher monitoring the public Authentik repository observes the permission check addition to `authentik/policies/expression/api.py` and `authentik/core/api/propertymappings.py` three to five days before the CVE advisory is published. They identify the previously-missing permission check, reconstruct which API endpoint was unenforced, and begin scanning for Authentik instances exposing the `/api/v3/propertymappings/` API. Authentik installations that require manual deployment (bare Docker Compose, self-managed Kubernetes) are particularly exposed during this window because operators may not patch until the formal announcement. The gap between commit visibility and CVE publication is the highest-risk window for organisations running older Authentik versions.

4. **Property Mapping code injection as a persistent backdoor**: An attacker who gains access to create or modify an Expression Policy or Property Mapping — whether through CVE-2026-25227 itself, a compromised admin credential, or another misconfiguration — injects Python code into a mapping that fires on every authentication event. The injected code could exfiltrate the authenticating user's credentials to an external endpoint, or silently add the attacker's email to all groups at authentication time. Because Property Mappings execute inside the Django process on every login, a backdoored mapping provides persistent access that survives password resets, token revocations, and session invalidations — it fires again on every new authentication attempt.

The blast radius of any of these attack paths is amplified by Authentik's position as a centralised gateway. A successful CVE-2026-25227 exploit against a single Authentik instance can yield credentials and tokens for every user across every application behind that instance. CVE-2026-25748 bypasses are scoped to the specific application behind the vulnerable proxy provider, but if that application trusts Authentik headers for role or data-scope decisions, the bypass can grant access to data belonging to other tenants. Organisations that have placed sensitive internal tools — finance dashboards, secrets managers, administrative consoles — behind Authentik without additional authentication layers are at greatest risk from both vulnerabilities.

## Configuration / Implementation

### Upgrading Authentik

Upgrade Authentik to the patched version before applying any configuration mitigations. Both CVEs are fixed in 2025.8.6, 2025.10.4, and 2025.12.4.

**Docker Compose deployment:**

```bash
# Pull the latest image for your release line and restart
docker compose pull
docker compose up -d

# Verify the running version
curl -s https://authentik.company.com/api/v3/core/applications/ \
  -H "Authorization: Bearer <your-api-token>" | jq '.version'

# Confirm the specific build date matches the patched release
curl -s https://authentik.company.com/-/health/live/ -v 2>&1 | grep -i authentik
```

**Helm (Kubernetes) deployment:**

```bash
# Update the Helm chart repository
helm repo update

# Upgrade to the patched version
helm upgrade authentik authentik/authentik \
  --namespace authentik \
  --version 2025.12.4 \
  --reuse-values

# Check rollout status
kubectl rollout status deployment/authentik-server -n authentik
kubectl rollout status deployment/authentik-worker -n authentik

# Verify the API reports the patched version
kubectl exec -n authentik deploy/authentik-server -- \
  python -c "import authentik; print(authentik.__version__)"
```

After upgrade, verify that the CVE-2026-25227 fix is present by confirming that the test execution endpoint returns 403 for a non-superuser account:

```bash
# This should return 403 Forbidden after patching, not 200
curl -s -o /dev/null -w "%{http_code}" \
  -X POST "https://authentik.company.com/api/v3/propertymappings/<mapping-pk>/test_user/" \
  -H "Authorization: Bearer <non-admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"user": 1}'
```

### Permission Hardening for Property Mappings and Expression Policies

The CVE-2026-25227 fix adds permission checks to the test execution endpoints, but the underlying permission model remains broad. After upgrading, audit and restrict which users and groups hold the "view Property Mapping" and "view Expression Policy" permissions.

**Audit current permission assignments via the API:**

```bash
# List all users and groups with propertymappings view permission
curl -s "https://authentik.company.com/api/v3/rbac/permissions/?codename=view_propertymapping" \
  -H "Authorization: Bearer <superuser-token>" | jq '.results[] | {user: .user, role: .role}'

# List all users and groups with expression policy view permission
curl -s "https://authentik.company.com/api/v3/rbac/permissions/?codename=view_expressionevent" \
  -H "Authorization: Bearer <superuser-token>" | jq '.results[] | {user: .user, role: .role}'
```

**Restrict these permissions in Authentik Admin:**

Navigate to Admin > System > Permissions. Remove the `propertymappings.*` and `policies_expression.*` permissions from all non-admin roles. Only the `authentik Admins` group should retain these permissions. If your organisation uses self-service Property Mapping configuration, create a new dedicated role for mapping reviewers rather than granting the broad "view" permission to all staff.

The following outpost configuration YAML snippet shows how to scope an Authentik role to exclude property mapping access:

```yaml
# authentik-admin-role-patch.yaml
# Apply via: ak apply -f authentik-admin-role-patch.yaml
# or via the Authentik Admin API at /api/v3/rbac/roles/<pk>/
apiVersion: authentik.goauthentik.io/v1beta1
kind: Role
metadata:
  name: mapping-viewer-restricted
  namespace: authentik
spec:
  permissions:
    # Grant read access to flows and stages only — NOT propertymappings
    - codename: view_flow
      model: authentik_flows.flow
    - codename: view_stage
      model: authentik_stages_prompt.promptstage
    # Explicitly omit:
    # - codename: view_propertymapping
    # - codename: view_expressionevent
```

For global permission restriction, use the Authentik Admin > System > Global Permissions panel to ensure the `authentik Admins` group is the only group with `can_execute_test` effective permission on expression objects.

### Forward Auth Proxy Hardening

Upgrade to the patched Authentik version first — CVE-2026-25748 is fixed in the version bump. After upgrading, implement these additional hardening measures for proxy provider deployments.

**Verify the bypass is closed after upgrade:**

```bash
# Construct a malformed session cookie and confirm it returns 401 post-patch
# Replace <protected-hostname> with your application hostname
curl -v -H "Cookie: authentik_session=AAAA.BBBB.$(python3 -c 'print("."*200)')" \
  "https://protected.app.company.com/api/status" 2>&1 | grep "< HTTP"
# Expected after patching: HTTP/2 401 (redirect to Authentik login)
# Unpatched: HTTP/2 200 with X-Authentik-Username: (empty)
```

**Configure strict header verification in your Traefik ForwardAuth middleware:**

```yaml
# traefik-authentik-middleware.yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: authentik-forwardauth
  namespace: traefik
spec:
  forwardAuth:
    address: "https://authentik.company.com/outpost.goauthentik.io/auth/traefik"
    trustForwardHeader: false
    authResponseHeaders:
      - X-Authentik-Username
      - X-Authentik-Groups
      - X-Authentik-Email
      - X-Authentik-Name
      - X-Authentik-Uid
      - X-Authentik-Jwt
      - X-Authentik-Meta-Jwks
      - X-Authentik-Meta-Outpost
      - X-Authentik-Meta-Provider
      - X-Authentik-Meta-App
      - X-Authentik-Meta-Version
    # Strip inbound X-Authentik headers from the client to prevent spoofing
    authRequestHeaders:
      - "Cookie"
      - "Authorization"
```

**Require non-empty username in backend applications:**

Applications trusting Authentik headers should validate that `X-Authentik-Username` is non-empty and conforms to expected user format before granting access. Add this check at the application layer as defence in depth:

```python
# Example middleware for a Flask/FastAPI backend behind Authentik proxy
def require_authentik_identity(request):
    username = request.headers.get("X-Authentik-Username", "").strip()
    if not username:
        raise HTTPException(status_code=401, detail="Missing Authentik identity")
    if not re.match(r'^[a-zA-Z0-9._@-]{1,254}$', username):
        raise HTTPException(status_code=401, detail="Invalid Authentik identity format")
    return username
```

### Expression Policy and Property Mapping Code Review

Audit all existing Expression Policies and Property Mappings for dangerous Python patterns before and after the CVE-2026-25227 patch:

```bash
# Export all property mappings to JSON
curl -s "https://authentik.company.com/api/v3/propertymappings/all/" \
  -H "Authorization: Bearer <superuser-token>" > property-mappings-export.json

# Scan for dangerous code patterns
jq -r '.results[] | "\(.pk) \(.name): \(.expression)"' property-mappings-export.json \
  | grep -iE "import os|import subprocess|subprocess\.|exec\(|eval\(|__import__|open\(|socket\."

# Export expression policies and apply the same scan
curl -s "https://authentik.company.com/api/v3/policies/expression/" \
  -H "Authorization: Bearer <superuser-token>" > expression-policies-export.json

jq -r '.results[] | "\(.pk) \(.name): \(.expression)"' expression-policies-export.json \
  | grep -iE "import os|import subprocess|subprocess\.|exec\(|eval\(|__import__|open\(|socket\."
```

Enforce GitOps review for all Property Mapping changes. Export the Authentik configuration to version control and require pull request review before applying changes:

```bash
# Export the full Authentik configuration (requires authentik CLI or container exec)
docker compose exec server ak export > authentik-config-$(date +%Y%m%d).yaml

# Or from Kubernetes
kubectl exec -n authentik deploy/authentik-server -- ak export \
  > authentik-config-$(date +%Y%m%d).yaml

# Commit to version control and gate changes on PR approval
git add authentik-config-$(date +%Y%m%d).yaml
git commit -m "chore: export Authentik config snapshot $(date +%Y-%m-%d)"
```

### Network Isolation for the Authentik API

The Authentik API (`/api/v3/`) should not be reachable from the public internet without strong authentication. For Kubernetes deployments, restrict external access with a NetworkPolicy and limit the test execution endpoints to admin IP ranges at the ingress level:

```yaml
# authentik-network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: authentik-api-restriction
  namespace: authentik
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: authentik
  ingress:
    # Allow inbound from cluster workloads (for proxy provider outposts)
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: traefik
      ports:
        - protocol: TCP
          port: 9000
    # Allow inbound from admin CIDR only for the API
    - from:
        - ipBlock:
            cidr: 10.0.0.0/8  # internal admin network
      ports:
        - protocol: TCP
          port: 9000
```

For nginx-based deployments, restrict the test execution endpoints to the admin network:

```nginx
# nginx location block — restrict property mapping and policy test endpoints
location ~ ^/api/v3/(propertymappings|policies/expression)/[^/]+/test_user/ {
    # Allow only from admin CIDR
    allow 10.0.0.0/8;
    allow 192.168.0.0/16;
    deny all;

    proxy_pass http://authentik_backend;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

### Monitoring Authentik for Security Fixes

Set up continuous monitoring for Authentik CVEs and upstream fix commits. Because fixes often land in the public repository before the advisory is published, monitoring the repository directly provides earlier warning than waiting for the formal CVE announcement:

```bash
# List all published Authentik security advisories
gh api repos/goauthentik/authentik/security/advisories \
  --jq '.[].summary'

# Monitor recent commits for security-relevant changes to API permission files
gh api repos/goauthentik/authentik/commits \
  --jq '.[] | select(.commit.message | test("permission|test.*exec|CVE|security|cookie|proxy.*bypass"; "i")) | {sha: .sha[0:8], msg: .commit.message, date: .commit.author.date}'

# Watch specific high-value files for changes (check daily via cron or CI)
gh api "repos/goauthentik/authentik/commits?path=authentik/policies/expression/api.py&per_page=5" \
  --jq '.[] | {sha: .sha[0:8], msg: .commit.message[0:80], date: .commit.author.date}'

gh api "repos/goauthentik/authentik/commits?path=authentik/core/api/propertymappings.py&per_page=5" \
  --jq '.[] | {sha: .sha[0:8], msg: .commit.message[0:80], date: .commit.author.date}'

gh api "repos/goauthentik/authentik/commits?path=authentik/providers/proxy/&per_page=5" \
  --jq '.[] | {sha: .sha[0:8], msg: .commit.message[0:80], date: .commit.author.date}'
```

Subscribe to the Authentik security advisory RSS feed and configure Renovate to automatically open pull requests when the Authentik Docker image or Helm chart is updated:

```json
// renovate.json — Authentik auto-update configuration
{
  "packageRules": [
    {
      "matchPackageNames": ["ghcr.io/goauthentik/server"],
      "groupName": "authentik",
      "automerge": false,
      "minimumReleaseAge": "0 days",
      "prPriority": 10,
      "labels": ["security", "authentik"]
    },
    {
      "matchPackageNames": ["authentik/authentik"],
      "matchManagers": ["helm-values"],
      "groupName": "authentik-helm",
      "automerge": false,
      "prPriority": 10,
      "labels": ["security", "authentik"]
    }
  ]
}
```

## Expected Behaviour

| Signal | Unpatched Authentik | Patched + Permission Hardening |
|---|---|---|
| Non-admin user calls `/api/v3/propertymappings/<pk>/test_user/` | Returns 200, executes the property mapping Python code against the target user, returns attribute output | Returns 403 Forbidden — permission check enforced at the API view layer |
| Forward auth request with malformed cookie to Traefik-fronted app | Authentik returns 200 with `X-Authentik-Username: ` (empty); Traefik forwards request to backend | Authentik returns 302 redirect to login; Traefik presents the login page to the client |
| Property Mapping Python code calls `authentik.core.models.User.objects.all()` | Executes, returns full user list including password hashes in test execution output | Blocked by permission check (test execution denied to non-admins); code not reachable from non-superuser API call |
| Traefik header parsing discrepancy with crafted `authentik_session` value | Cookie format accepted by Authentik, empty identity passed downstream; `X-Authentik-Authenticated: true` with no username | Cookie rejected at Authentik session validation layer; 302 returned; no downstream headers set |
| Fix commit to `authentik/policies/expression/api.py` visible in repository | Vulnerability active, no public CVE identifier yet; 3–5 day gap between commit and advisory | Patch deployed; advisory published; Renovate PR raised for the new version within hours of image publication |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Restricting Property Mapping view permissions | Eliminates the CVE-2026-25227 attack surface for non-admin users; limits blast radius if a user account is compromised | Breaks self-service mapping configuration workflows where non-admin teams inspect or iterate on their own attribute mappings | Create a scoped "mapping-viewer" role that grants read access to only flows and stages, not raw expression objects; provide a safe sandbox environment (separate Authentik dev instance) for self-service iteration |
| Switching forward auth from cookie to token mode | Eliminates the cookie parsing discrepancy attack surface; token-based auth is not affected by CVE-2026-25748 | Requires per-application configuration change; token-based proxy mode may require application-level header consumption changes | Roll out application by application; test in staging first; document the header set that changes between cookie and token mode |
| Expression Policy code review via GitOps | Prevents backdoor injection into Expression Policies; provides audit trail for all policy changes; detects malicious code before deployment | Slows policy iteration velocity for teams that previously modified policies directly in the Authentik admin UI | Use feature branches for policy development with a fast-path approval for security-critical fixes; maintain an emergency override process documented in the runbook |
| Authentik API network restriction via NetworkPolicy | Reduces exposure of the API (including test execution endpoints) to only trusted network paths; provides defence in depth beyond the permission check | Breaks external integrations that reach the Authentik API from outside the cluster boundary (SCIM connectors, external LDAP clients, Terraform authentik provider) | Allowlist specific source CIDRs for each integration; use mTLS between the Terraform provider and Authentik API endpoint rather than open network access |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Permission restriction breaks existing self-service workflow | Users report 403 errors when attempting to view their Property Mappings in the Authentik admin UI; automated scripts calling the propertymappings API fail | Authentik audit log shows a spike in 403 responses for `propertymappings` endpoints from non-admin users; alerts on `authentik_api_requests_total{status="403",path=~"/api/v3/propertymappings.*"}` | Create a scoped viewer role with read access to flows and stages only (not raw expression objects); re-grant that scoped role to the affected groups; communicate the new self-service process |
| Forward auth upgrade changes cookie format, logging out all users | All users behind Authentik proxy providers are redirected to the login page simultaneously; support tickets spike; CI/CD pipelines that use browser sessions against proxy-protected tools break | Spike in `authentik_login_flows_total` immediately after deployment; monitoring for 302 responses from proxy-protected hostnames; user-facing health checks fail | Pre-announce the upgrade to end users; schedule during low-traffic window; verify cookie format compatibility in staging first; Authentik supports session migration — check release notes for the specific version pair |
| RestrictedPython breaks legitimate Property Mapping code | Property Mappings that use standard library imports (`import json`, `import re`) fail at execution time; attributes are not mapped for affected users; authentication succeeds but groups/roles are wrong | Authentik worker logs show `RestrictedPython: execution blocked` for affected mappings; users report missing group memberships or incorrect attribute values after the change | Review each flagged import individually; most standard library modules needed for attribute mapping (`json`, `re`, `base64`) are safe to allowlist explicitly in the RestrictedPython configuration; Python's `ast` module can be used to statically analyse mapping code before execution |
| Authentik upgrade requires database migration causing downtime | Authentik server pods fail to start after the Helm upgrade; readiness probes fail; `kubectl logs` shows Django migration errors | `kubectl rollout status` fails; `kubectl logs deploy/authentik-server` shows `django.db.utils.OperationalError` or pending migration messages | Run the migration manually before the server rollout: `kubectl exec -n authentik deploy/authentik-server -- ak db upgrade`; ensure the database backup completed before starting the upgrade; maintain a tested rollback procedure to the previous image tag |

## Related Articles

- [Keycloak and ZITADEL Token Security Hardening](/articles/cross-cutting/keycloak-token-security/)
- [OAuth2 and OIDC Hardening](/articles/cross-cutting/oauth2-oidc-hardening/)
- [Traefik Auth Middleware Security](/articles/network/traefik-auth-middleware-security/)
- [Production Access Management](/articles/cross-cutting/production-access-management/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
