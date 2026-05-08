---
title: "GitLab GraphQL CSRF: CVE-2026-4922 and Insufficient Token Validation"
description: "CVE-2026-4922 lets unauthenticated attackers trigger privileged GitLab operations via CSRF against the GraphQL API. A logged-in user visiting a malicious page can have their code, pipelines, and settings modified without interaction. Patch and enforce SameSite cookies."
slug: gitlab-graphql-csrf
date: 2026-05-07
lastmod: 2026-05-07
category: cicd
tags:
  - gitlab
  - csrf
  - graphql
  - cve
  - web-security
personas:
  - platform-engineer
  - security-engineer
article_number: 450
difficulty: Intermediate
estimated_reading_time: 10
published: true
layout: article.njk
permalink: /articles/cicd/gitlab-graphql-csrf/
---

# GitLab GraphQL CSRF: CVE-2026-4922 and Insufficient Token Validation

## The Problem

CVE-2026-4922 (CVSS 8.1) is a Cross-Site Request Forgery vulnerability in GitLab's GraphQL API endpoint, affecting GitLab CE and EE versions 17.0 through 18.9.5, 18.10.0 through 18.10.3, and 18.11.0. Disclosed on April 22 2026, the vulnerability allows an unauthenticated attacker to craft a malicious webpage that, when visited by a logged-in GitLab user, submits authenticated requests to the GitLab GraphQL API on the victim's behalf — without the victim's knowledge or consent.

CSRF attacks exploit the browser's behaviour of automatically attaching session cookies to cross-origin requests. The defence against this is a CSRF token: a value embedded in the legitimate frontend and required on mutating requests. The server validates the token's value against the session, confirming the request originated from the genuine GitLab interface. In CVE-2026-4922, GitLab's GraphQL endpoint checks for the *presence* of the `X-CSRF-Token` request header but, in certain code paths, does not validate the token's *value* against the session. Any non-empty string in the header passes the check. An attacker who sends a cross-origin request with a fabricated `X-CSRF-Token` value bypasses CSRF protection entirely.

The impact is severe because GitLab's GraphQL API is feature-rich. Mutations exist for creating commits, approving merge requests, triggering pipelines, modifying protected branch rules, changing project visibility, altering membership and permission levels, and updating CI/CD variable values. A single victim visit to the attacker's page can result in a full repository compromise: code injected, CI/CD pipelines backdoored, and the attacker promoted to project owner — all without the victim performing any action beyond loading the page.

Both GitLab.com and self-hosted GitLab instances running affected versions are vulnerable. The attack requires no GitLab account and no prior access to the target project. The only precondition is that the victim is authenticated to GitLab in the same browser session.

## Threat Model

- **Targeted maintainer phishing:** The attacker identifies a GitLab project maintainer or owner and sends a phishing link — a meeting invite, a fake security alert, a plausible-looking URL. The victim clicks the link and their browser loads a page containing JavaScript that issues a cross-origin `fetch()` or `XMLHttpRequest` to the victim's GitLab instance. The request carries the session cookie automatically and includes a fabricated `X-CSRF-Token` header. The GraphQL mutation executes: the attacker is added as project owner, or the `.gitlab-ci.yml` is modified to include a credential exfiltration step. The victim sees nothing.

- **Supply chain attack via dependency repository:** Many projects depend on internal GitLab-hosted libraries. An attacker who targets a maintainer of a widely-used internal library can use the CSRF to inject malicious code into that library. Every project that pulls from it then executes attacker-controlled code in its CI/CD pipeline or production environment.

- **Privilege escalation for limited insiders:** An attacker with developer-level access to a GitLab instance cannot by themselves promote themselves to maintainer or owner. By targeting a higher-privileged user — a maintainer who can be social-engineered into visiting a link — the attacker uses CSRF to escalate their own account's role within a project.

- **CI/CD pipeline backdoor without code access:** Even an attacker with no GitLab account can craft a CSRF payload that creates or modifies a CI/CD pipeline schedule. If the victim account has sufficient permission, the attacker can inject a scheduled pipeline that runs a malicious job on a recurring basis — persisting access long after the initial CSRF is complete.

- **Scope:** GitLab.com and all self-hosted GitLab CE/EE instances on affected versions are equally exposed. Instances behind an internal network boundary reduce external attacker reach but do not eliminate the threat — phishing emails can deliver malicious links to users on internal networks.

## Hardening Configuration

### Step 1: Patch GitLab

The definitive fix is upgrading to a patched release. Fixed versions are 18.9.6+, 18.10.4+, and 18.11.1+. For self-hosted instances:

```bash
sudo gitlab-ctl stop
sudo apt-get update && sudo apt-get install -y gitlab-ee
sudo gitlab-ctl reconfigure
sudo gitlab-ctl start
```

Or on RPM-based systems:

```bash
sudo gitlab-ctl stop
sudo yum update gitlab-ee
sudo gitlab-ctl reconfigure
sudo gitlab-ctl start
```

Verify the installed version after upgrade:

```bash
sudo gitlab-rake gitlab:env:info | grep Version
```

Expected output confirms the running version is 18.9.6, 18.10.4, 18.11.1, or later. The patch corrects the GraphQL CSRF middleware to validate the token value against the session, not merely check its presence.

For GitLab.com, Gitlab applies patches directly; no action is required for the managed service beyond confirming your instance reports a patched version via the GitLab version check endpoint.

### Step 2: Enforce `SameSite=Strict` on Session Cookies

`SameSite=Strict` is a defence-in-depth control independent of CSRF token handling. When the session cookie carries `SameSite=Strict`, the browser refuses to attach it to any cross-origin request — including the attacker's crafted CSRF request. The session cookie is only sent when the navigation originates from the same site. This makes CSRF impossible at the browser level, regardless of how well the server-side CSRF token logic works.

Configure this in `/etc/gitlab/gitlab.rb`:

```ruby
gitlab_rails['session_store_options'] = {
  same_site: 'strict'
}
```

Apply the change:

```bash
sudo gitlab-ctl reconfigure
```

Confirm the `Set-Cookie` header on authentication responses contains `SameSite=Strict`:

```bash
curl -sI https://gitlab.example.com/users/sign_in | grep -i set-cookie
```

### Step 3: Enable GitLab's Strict CSRF Mode

GitLab 17.x and later includes an opt-in strict CSRF enforcement mode that applies additional validation to GraphQL and API endpoints. Enable it in `/etc/gitlab/gitlab.rb`:

```ruby
gitlab_rails['csrf_token_verify_mode'] = 'strict'
```

Apply and restart:

```bash
sudo gitlab-ctl reconfigure
sudo gitlab-ctl restart gitlab-workhorse
sudo gitlab-ctl restart puma
```

In strict mode, the CSRF middleware validates the token's cryptographic value against the session regardless of request path. This is the server-side complement to `SameSite=Strict` — both controls should be active simultaneously.

### Step 4: Review Recent GraphQL Mutations in Audit Logs

After patching, audit the window of exposure to determine whether the vulnerability was exploited before the fix was applied. GitLab's audit log API records privileged operations including GraphQL mutations. Query for mutation events in the affected period:

```bash
curl --header "PRIVATE-TOKEN: $GITLAB_ADMIN_TOKEN" \
  "https://gitlab.example.com/api/v4/audit_events?entity_type=Project&entity_id=$PROJECT_ID&created_after=2026-04-22T00:00:00Z&created_before=2026-05-07T00:00:00Z" \
  | jq '.[] | select(.details.action | test("graphql|mutation|add_member|change_access|update_protected_branch"; "i"))'
```

Focus on the following event types, which correspond to high-impact GraphQL mutations:

```bash
curl --header "PRIVATE-TOKEN: $GITLAB_ADMIN_TOKEN" \
  "https://gitlab.example.com/api/v4/audit_events?action=member_added&created_after=2026-04-22T00:00:00Z" \
  | jq '.[] | {time: .created_at, user: .author_name, target: .entity_full_name, detail: .details}'
```

Correlate suspicious membership changes or CI/CD configuration updates against that user's login activity. A member addition that occurred without a corresponding web login from the acting user at that time is a strong indicator of CSRF exploitation.

For GitLab instances with Elasticsearch integration, use the advanced audit log search:

```bash
curl --header "PRIVATE-TOKEN: $GITLAB_ADMIN_TOKEN" \
  "https://gitlab.example.com/api/v4/audit_events?entity_type=Project&per_page=100" \
  | jq '[.[] | select(.details.change == "access_level" or .details.action == "push_repository")]'
```

If you identify suspicious changes, do not stop at logging — take immediate remediation action: remove unauthorised members, revert modified CI/CD files via a new commit on the protected branch, rotate any secrets that may have been exposed to a backdoored pipeline.

### Step 5: Browser Security Headers on Self-Hosted Instances

For self-hosted GitLab instances proxied through Nginx, enforce security headers that further reduce CSRF attack surface. `Content-Security-Policy: default-src 'self'` restricts what origins the GitLab frontend may load resources from and make requests to. `X-Frame-Options: DENY` prevents the GitLab interface from being embedded in iframes — eliminating clickjacking as a delivery vector for CSRF.

Example Nginx configuration for a GitLab reverse proxy:

```nginx
server {
    listen 443 ssl;
    server_name gitlab.example.com;

    ssl_certificate     /etc/ssl/certs/gitlab.crt;
    ssl_certificate_key /etc/ssl/private/gitlab.key;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'" always;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

The `Content-Security-Policy` header listed above is a starting point. GitLab's frontend requires `unsafe-inline` for styles and scripts in some configurations; refine using a report-only policy and GitLab's CSP violation reporting before switching to enforcement mode.

## Expected Behaviour After Hardening

After patching to a fixed version: a cross-site request to the GitLab GraphQL endpoint that includes any non-empty `X-CSRF-Token` header but an invalid token value returns `422 Unprocessable Entity`. The server now validates the token's cryptographic value against the user's session. The fabricated token the attacker provides does not match, and the mutation is rejected before execution.

After setting `SameSite=Strict` on the session cookie: the attacker's cross-origin request is issued by the victim's browser, but the browser refuses to attach the `_gitlab_session` cookie to a cross-site request. The GraphQL endpoint receives an unauthenticated request and returns `401 Unauthorized`. The attack fails at the browser level — the session cookie never reaches the server.

With both controls active simultaneously, CSRF is prevented at two independent layers: the browser does not send the credential, and even if it did, the server would reject the fabricated CSRF token. This layered defence means a misconfiguration at either layer does not reopen the vulnerability.

## Trade-offs and Operational Considerations

`SameSite=Strict` can break legitimate cross-origin authenticated workflows. GitLab integrations that rely on cross-origin requests carrying the session cookie — third-party dashboards that embed GitLab content, OAuth flows that redirect cross-origin, webhook callbacks that include session authentication — will stop working after this change. Before enabling `SameSite=Strict`, audit all integrations and redirect flows. In many cases, the correct fix is to migrate those integrations to use GitLab personal access tokens or OAuth app tokens rather than session cookies. Use `SameSite=Lax` as an intermediate step if `Strict` breaks too many workflows; `Lax` still prevents most CSRF vectors (it allows cookies on top-level GET navigations, but not on cross-origin POST or fetch requests).

GitLab's strict CSRF mode (`csrf_token_verify_mode = 'strict'`) may reject requests from API clients that construct GraphQL queries outside the browser context and do not manage CSRF tokens. Command-line tools and automation scripts that talk directly to the GraphQL endpoint using session-based authentication rather than personal access tokens may fail with `422` responses after enabling strict mode. The correct response is to migrate those clients to use personal access tokens or OAuth tokens, which are not subject to CSRF validation requirements.

The `Content-Security-Policy` header requires careful tuning for GitLab. A too-strict CSP will break the GitLab web interface (loading assets, running inline scripts for editor functionality). Deploy CSP in report-only mode first using `Content-Security-Policy-Report-Only`, observe violations in the browser console and in violation reports, then iteratively tighten the policy before enforcing it.

## Failure Modes

**GitLab upgraded but Nginx cache serves stale responses.** If a caching reverse proxy sits in front of GitLab and has cached HTML pages containing the old, invalid CSRF token format, users may receive pages with stale tokens that fail validation even after the patch. This manifests as `422` errors on legitimate form submissions after the upgrade. Clear the proxy cache immediately after upgrading: `nginx -s reload` flushes the connection pool but not object caches; purge the cache explicitly if using a proxy cache like `proxy_cache` or Varnish.

**`SameSite=Strict` set but GitLab is accessed from multiple subdomains.** If your organisation accesses GitLab at `gitlab.example.com` and your CI pipelines trigger web hooks that return to `ci.example.com`, these are different sites under the same-site definition when there is no shared registration at `example.com`. Session cookies with `SameSite=Strict` will not be sent between them, potentially breaking SSO flows or integrated tooling. Map out all cross-subdomain authentication flows before enabling `SameSite=Strict`.

**Audit log review finds suspicious mutations but no rollback is performed.** Identifying that an attacker used CVE-2026-4922 to add themselves as a project owner or modify `.gitlab-ci.yml` is only the first step. If the attacker's changes remain in place — a backdoor in the CI/CD pipeline, an unauthorised project member with owner privileges, a modified protected branch rule — the attacker retains persistent access after the vulnerability is patched. Patch remediation does not undo prior exploitation. After identifying suspicious mutations, remove unauthorised members, revert CI/CD configuration changes, rotate all secrets that passed through any pipeline job run after the backdoor was inserted, and audit downstream build artefacts produced by the compromised pipeline.

**Strict CSRF mode enabled but GitLab workhorse not restarted.** The CSRF middleware change applies at the Puma application server level, but GitLab Workhorse proxies requests in front of Puma. If Workhorse is not restarted after reconfiguration, it may continue forwarding requests with the old middleware behaviour. Always restart both `puma` and `gitlab-workhorse` after changing CSRF-related `gitlab.rb` settings.

## Related Articles

- [GitLab CI Security](/articles/cicd/gitlab-ci-security/)
- [Branch Protection Code Review](/articles/cicd/branch-protection-code-review/)
- [GitHub Advanced Security](/articles/cicd/github-advanced-security/)
- [Securing GitHub Actions](/articles/cicd/securing-github-actions/)
- [Pipeline Config Security](/articles/cicd/pipeline-config-security/)
