---
title: "Grafana Security Hardening: Authentication, RBAC, and Data Source Permissions"
description: "Grafana dashboards expose infrastructure metrics, logs, and traces — often including sensitive operational data. Hardening authentication, restricting data source access by team, disabling anonymous access, and auditing snapshot sharing prevents data exposure."
slug: "grafana-security-hardening"
date: 2026-05-01
lastmod: 2026-05-01
category: "observability"
tags: ["grafana", "authentication", "rbac", "data-source", "observability-security"]
personas: ["security-engineer", "platform-engineer", "sre"]
article_number: 283
difficulty: "intermediate"
estimated_reading_time: 12
published: true
layout: article.njk
permalink: "/articles/observability/grafana-security-hardening/index.html"
---

# Grafana Security Hardening: Authentication, RBAC, and Data Source Permissions

## Problem

Grafana provides visibility into infrastructure and application health. The same dashboards that help engineers debug production incidents also expose sensitive data: database query performance (revealing schema details), API response times (revealing business logic), infrastructure topology, secret variable values embedded in dashboard queries, and sometimes full log lines containing PII.

Default and common Grafana deployments have weak security boundaries:

- **Anonymous access enabled.** The Grafana default enables anonymous viewers in the Main org. Any unauthenticated user who can reach the Grafana URL sees all dashboards in that org.
- **Basic auth with shared credentials.** Teams share a single `admin`/`admin` credential or a team-level credential. There is no individual accountability; audit logs show the shared account name.
- **Data sources accessible to all users.** Prometheus, Loki, and Elasticsearch data sources are configured once and visible to every user in the organization. A developer who should see only their team's logs can query any data source.
- **Snapshot sharing exposes data publicly.** Grafana snapshot sharing uploads panel data to `snapshot.raintank.io` by default — an external service. Dashboard snapshots from internal metrics or logs are publicly accessible via an unguessable (but not private) URL.
- **Alert notification channels leak credentials.** Alert notification channels (Slack webhooks, PagerDuty keys) are stored as plaintext in Grafana's database and visible to any admin.
- **Plugin permissions not restricted.** Grafana plugins can access all data sources by default. A third-party plugin installed by an admin can read any data source the Grafana server can reach.
- **Dashboard variables allow injection.** Template variables in dashboards that pass user input directly to query backends enable PromQL/LogQL injection in some configurations.

**Target systems:** Grafana 10.x+ (RBAC GA, data source permissions, service accounts); Grafana Enterprise 10.x+ (data source query caching, enhanced RBAC); Grafana Cloud; SSO via OIDC, SAML, LDAP.

## Threat Model

- **Adversary 1 — Anonymous access data extraction:** An attacker reaches the Grafana URL (via misconfigured Ingress, public IP, or internal network access) and browses dashboards without authentication. They extract infrastructure topology, API latency, and error rate data.
- **Adversary 2 — Shared credential abuse:** An attacker who has obtained the shared Grafana admin credential (from a Slack message, a wiki page, or a commit) logs in as admin. All subsequent actions are attributed to the shared account, masking the attacker.
- **Adversary 3 — Data source credential extraction:** A Grafana admin (or an attacker who has compromised an admin account) navigates to the data source configuration, clicks "Test", and inspects the network request — or queries the Grafana API — to extract the Prometheus/Loki/Elasticsearch API key.
- **Adversary 4 — Snapshot exfiltration:** An engineer creates a Grafana snapshot to share a dashboard view and uploads it to `snapshot.raintank.io`. The snapshot contains sensitive metrics. An attacker discovers the snapshot URL (from a Slack message, a commit, or search engine indexing) and reads the data.
- **Adversary 5 — Dashboard variable injection:** A dashboard has a template variable `$namespace` that is passed directly to a Loki query: `{namespace="$namespace"}`. An attacker manipulates the URL parameter to inject a different label selector, querying log data from namespaces they should not access.
- **Access level:** Adversary 1 needs network access. Adversaries 2 and 3 need valid credentials. Adversary 4 exploits a design weakness in snapshot sharing. Adversary 5 needs authenticated access to a vulnerable dashboard.
- **Objective:** Extract infrastructure data, credentials, log data; gain persistent access.
- **Blast radius:** Grafana with data source access to Prometheus, Loki, and Elasticsearch effectively provides read access to all observability data — logs, metrics, traces — across all environments.

## Configuration

### Step 1: Disable Anonymous Access and Local Admin

```ini
# /etc/grafana/grafana.ini — disable anonymous and default credentials.

[auth.anonymous]
enabled = false              # Never allow unauthenticated access.

[auth]
disable_login_form = false   # Keep login form for initial setup; disable after SSO.
disable_signout_menu = false

[security]
# Change the default admin credentials immediately after installation.
admin_user = grafana-admin
admin_password = $__env{GF_SECURITY_ADMIN_PASSWORD}  # From environment; not hardcoded.

# Prevent viewers from editing or saving dashboards.
viewers_can_edit = false

# Cookie security.
cookie_secure = true
cookie_samesite = strict

# Content-Security-Policy to prevent XSS.
content_security_policy = true
content_security_policy_template = "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';"

[snapshots]
# Disable external snapshot sharing.
external_enabled = false     # No uploads to snapshot.raintank.io.
```

### Step 2: SSO via OIDC

Replace local accounts with SSO:

```ini
# /etc/grafana/grafana.ini — OIDC with Okta.

[auth.generic_oauth]
enabled = true
name = Okta
client_id = $__env{GF_AUTH_OKTA_CLIENT_ID}
client_secret = $__env{GF_AUTH_OKTA_CLIENT_SECRET}
scopes = openid profile email groups
auth_url = https://company.okta.com/oauth2/default/v1/authorize
token_url = https://company.okta.com/oauth2/default/v1/token
api_url = https://company.okta.com/oauth2/default/v1/userinfo
allowed_domains = company.com
use_pkce = true

# Map Okta groups to Grafana roles.
role_attribute_path = contains(groups[*], 'grafana-admin') && 'Admin' || contains(groups[*], 'grafana-editor') && 'Editor' || 'Viewer'
role_attribute_strict = true   # Reject login if role_attribute_path returns no match.
skip_org_role_sync = false

# Auto-assign users to the main org.
auto_login = false
allow_sign_up = true
```

```ini
# After SSO is configured and tested, disable local login.
[auth]
disable_login_form = true    # Only SSO; no local username/password.
```

### Step 3: RBAC and Data Source Permissions

Configure fine-grained access control using Grafana RBAC (requires Grafana 9+):

```bash
# Create custom roles for team-scoped access.
# Grafana RBAC via API or provisioning.

# /etc/grafana/provisioning/access-control/roles.yaml
apiVersion: 1
roles:
  - name: "Payments Team Viewer"
    description: "Read access to payments dashboards and Prometheus data source"
    global: false
    permissions:
      - action: "dashboards:read"
        scope: "folders:uid:payments"
      - action: "datasources:read"
        scope: "datasources:uid:payments-prometheus"
      - action: "datasources:query"
        scope: "datasources:uid:payments-prometheus"
      # Explicitly NOT granted: access to platform-prometheus or loki-all.

  - name: "Platform Team Editor"
    description: "Edit dashboards; query all internal data sources"
    global: false
    permissions:
      - action: "dashboards:read"
        scope: "dashboards:*"
      - action: "dashboards:write"
        scope: "folders:uid:platform"
      - action: "datasources:read"
        scope: "datasources:*"
      - action: "datasources:query"
        scope: "datasources:*"
```

```bash
# Assign roles to SSO groups via API.
curl -X POST "https://grafana.internal/api/access-control/teams/1/roles" \
  -H "Authorization: Bearer $GRAFANA_SERVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"roleUid": "payments-team-viewer"}'
```

Data source permissions — restrict which users can query each data source:

```yaml
# Grafana data source provisioning with permissions.
# /etc/grafana/provisioning/datasources/datasources.yaml
apiVersion: 1
datasources:
  - name: payments-prometheus
    type: prometheus
    uid: payments-prometheus
    url: http://prometheus-payments:9090
    access: proxy
    jsonData:
      httpMethod: POST
    # Data source permissions restrict which users/teams can query.
    # Set via API or Grafana Enterprise data source permissions UI.

  - name: platform-prometheus
    type: prometheus
    uid: platform-prometheus
    url: http://prometheus-platform:9090
    access: proxy
    jsonData:
      httpMethod: POST
```

```bash
# Set data source permissions via API (Grafana Enterprise / Grafana Cloud).
# Allow only platform team to query platform-prometheus.
curl -X POST "https://grafana.internal/api/datasources/uid/platform-prometheus/permissions" \
  -H "Authorization: Bearer $GRAFANA_SERVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "items": [
      {"teamId": 2, "permission": 2},   # 2 = Query permission; team 2 = platform.
      {"userId": 0, "permission": 0}    # Revoke all-users access.
    ]
  }'
```

### Step 4: Service Accounts for Automation

Replace shared human credentials for automation with service accounts:

```bash
# Create a service account for CI/CD dashboard provisioning.
curl -X POST "https://grafana.internal/api/serviceaccounts" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "dashboard-provisioner",
    "role": "Editor",
    "isDisabled": false
  }'

# Create a token for the service account.
curl -X POST "https://grafana.internal/api/serviceaccounts/1/tokens" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "ci-provisioner-token", "secondsToLive": 7776000}'  # 90 days.

# Service account tokens can be scoped to specific Grafana roles.
# Rotate via CI pipeline before expiry.
```

### Step 5: Audit Logging

Enable and ship Grafana audit logs:

```ini
# /etc/grafana/grafana.ini
[auditing]
enabled = true
loggers = ["file"]
log_dashboard_content = true   # Log dashboard content changes (diff).
```

```bash
# /etc/grafana/grafana.ini — ship logs to syslog for SIEM ingestion.
[log]
mode = console file syslog
level = info

[log.syslog]
tag = grafana
address = syslog.internal.example.com:514
network = udp
format = json
```

Key audit events to monitor:

```
grafana_audit_user_logged_in{user, auth_module}
grafana_audit_user_login_failed{user}
grafana_audit_datasource_accessed{user, datasource}
grafana_audit_dashboard_exported{user, dashboard}
grafana_audit_snapshot_created{user}
grafana_audit_alert_rule_modified{user}
grafana_audit_user_role_changed{user, old_role, new_role}
```

### Step 6: Network Exposure Restrictions

```yaml
# kubernetes/grafana-networkpolicy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: grafana-access
  namespace: monitoring
spec:
  podSelector:
    matchLabels:
      app: grafana
  policyTypes:
    - Ingress
  ingress:
    # Only allow from internal networks via ingress controller.
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress-nginx
      ports:
        - port: 3000
          protocol: TCP
    # Allow from monitoring namespace (Prometheus scrape).
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
      ports:
        - port: 3000
          protocol: TCP
```

```yaml
# Ingress with IP restriction for Grafana.
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: grafana
  namespace: monitoring
  annotations:
    nginx.ingress.kubernetes.io/whitelist-source-range: "10.0.0.0/8,172.16.0.0/12"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  rules:
    - host: grafana.internal.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: grafana
                port:
                  number: 3000
```

### Step 7: Dashboard Variable Sanitisation

Prevent injection via dashboard template variables:

```
# In Grafana dashboard JSON — use "Custom" variable type with allowed values
# instead of free-form text input.

# BAD: Free-text variable passed directly to query.
# Variable type: Text box
# Query: {namespace="$namespace"}   # User can inject: {namespace=~".*"}

# GOOD: Enumerated variable from data source.
# Variable type: Query
# Query: label_values(kube_pod_info, namespace)
# This restricts values to actual namespaces; injection not possible.
```

```json
{
  "templating": {
    "list": [
      {
        "name": "namespace",
        "type": "query",
        "datasource": {"uid": "prometheus"},
        "query": "label_values(kube_pod_info, namespace)",
        "refresh": 2,
        "multi": false,
        "includeAll": false   // Prevent "All" selection that queries everything.
      }
    ]
  }
}
```

### Step 8: Telemetry

```
grafana_api_user_signin_failures_total{auth_module}    counter
grafana_datasource_request_total{datasource, status}   counter
grafana_active_users{role}                             gauge
grafana_snapshot_total{}                               counter
grafana_dashboard_versions_total{}                     counter
grafana_plugin_request_total{plugin_id, status}        counter
```

Alert on:

- `grafana_api_user_signin_failures_total` spike — credential stuffing or brute-force against Grafana login.
- `grafana_snapshot_total` non-zero with `external_enabled = false` — unexpected; snapshot was created despite configuration.
- Admin login from unexpected IP or at unusual hour — may indicate compromised admin credential.
- Data source accessed by user outside the permitted team — data source permissions misconfiguration or bypass.
- Any anonymous access event — anonymous auth is disabled; this event should never occur.

## Expected Behaviour

| Signal | Default Grafana | Hardened Grafana |
|--------|----------------|-----------------|
| Unauthenticated dashboard access | Permitted (anonymous viewer) | Blocked; redirect to SSO |
| All users query all data sources | Default behaviour | Data source permissions restrict by team |
| Snapshot to raintank.io | Allowed by default | Disabled; external snapshot sharing blocked |
| Shared admin credential | Single credential; no accountability | Service accounts for automation; individual SSO for humans |
| Dashboard variable injection | Possible with text-box variables | Query variables restrict to valid values |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Disable local login | Eliminates credential sharing | SSO dependency; outage means no Grafana access | Emergency break-glass service account token in secrets manager |
| Data source permissions (Grafana Enterprise) | Team-scoped query isolation | Enterprise license required; additional configuration | Use folder-based access control and separate Grafana orgs as a free alternative |
| `viewers_can_edit = false` | Prevents dashboard pollution by viewers | Viewers cannot save their own views | Create an "Explore" data source and allow ad-hoc querying for editors |
| External snapshot disabled | Prevents data exfiltration via snapshots | Sharing dashboard state is harder | Use Grafana's built-in snapshot functionality without external upload |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| SSO provider unavailable | Nobody can log into Grafana | On-call cannot access dashboards during incident | Keep emergency service account token in 1Password/secrets manager |
| Data source permission misconfiguration | Team cannot query their own data source | "Permission denied" errors in Grafana | Review team RBAC; check data source permission assignments |
| Service account token expiry | CI dashboard provisioning fails | Provisioning job auth errors | Automate token rotation before expiry; alert at 14 days remaining |
| CSP header blocks plugin | Plugin UI fails to load; JavaScript errors | Browser console errors | Adjust CSP to allow plugin's required sources; audit before adding |
| RBAC role_attribute_path returns no match | User cannot log in (role_attribute_strict=true) | Login failure; "no role found" error | Correct Okta group membership or update role_attribute_path expression |

## Related Articles

- [Prometheus Security Metrics](/articles/observability/prometheus-security-metrics/)
- [OpenTelemetry Collector Hardening](/articles/observability/otel-collector-hardening/)
- [OAuth 2.0 and OIDC Implementation Hardening](/articles/cross-cutting/oauth2-oidc-hardening/)
- [Security Dashboards](/articles/observability/security-dashboards/)
- [Loki and OpenTelemetry PII Leakage Prevention](/articles/observability/otel-pii-leakage/)
