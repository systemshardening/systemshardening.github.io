---
title: "Grafana SQL Expressions and Plugin RCE Hardening"
description: "Harden Grafana deployments against CVE-2026-27876-class RCE via SQL expressions and Enterprise plugins by controlling feature toggles, plugin permissions, and monitoring silent Grafana security releases."
slug: grafana-sql-expressions-security
date: 2026-05-02
lastmod: 2026-05-02
category: observability
tags: ["grafana", "sql-expressions", "cve-2026-27876", "plugin-security", "rce", "feature-toggle"]
personas: ["sre", "security-engineer", "platform-engineer"]
article_number: 355
difficulty: advanced
estimated_reading_time: 15
published: true
layout: article.njk
permalink: "/articles/observability/grafana-sql-expressions-security/index.html"
---

# Grafana SQL Expressions and Plugin RCE Hardening

## Problem

Grafana has evolved from a dashboard rendering tool into a full-stack observability platform — and with that expansion comes a substantially larger attack surface. One of the most significant additions in recent Grafana releases is the SQL expressions feature: a capability, gated behind the `sqlExpressions` feature toggle, that allows dashboard panels and alerting rules to run SQL-like queries as transformation expressions on top of data returned from other data sources. This lets operators perform ad-hoc joins, filters, aggregations, and column manipulations directly inside Grafana without modifying the underlying data source schema or writing ETL pipelines. It is genuinely useful — and it introduced a critical vulnerability.

CVE-2026-27876 was disclosed on March 25, 2026, rated Critical. Discovered by Liad Eliyahu, Head of Research at Miggo Security, through Grafana's bug bounty program, it describes a chained attack: a crafted SQL expression submitted through the Grafana expression API, combined with a code path in a Grafana Enterprise plugin, allowed remote arbitrary code execution on the Grafana server process. Only instances with the `sqlExpressions` feature toggle explicitly enabled were vulnerable. Grafana released patches in version 12.4.2 the same day as disclosure, with backports delivered to 12.3.x, 12.2.x, 12.1.x, and 11.6.x. Alongside CVE-2026-27876, Grafana simultaneously disclosed CVE-2026-27880, a high-severity vulnerability found internally. Batching security fixes into a single periodic release is a documented pattern in Grafana's disclosure history — it minimises patch noise but also means a single update can carry multiple critical fixes that aren't individually prominent in the changelog.

The broader plugin attack surface deserves direct examination. Grafana plugins — both built-in and community — run as separate processes communicating with the Grafana backend over a plugin SDK protocol. These plugin processes have access to Grafana's database credentials, data source configurations (including encrypted secrets), and API tokens stored in the Grafana secret store. A vulnerable plugin is not a sandboxed escape; it is a lateral movement path through the entire Grafana instance. An attacker who achieves code execution inside a plugin process can read every stored data source password, every API key, and the Grafana admin credentials — and from there reach every backend that Grafana is permitted to query.

Grafana Enterprise plugins amplify this exposure. Enterprise-tier plugins include SQL data source connectors, PDF reporting engines, LDAP group sync engines, and caching layers — capabilities that require deeper integration with Grafana internals than most open source plugins. The SQL plugin surface is directly implicated in CVE-2026-27876: the Enterprise SQL plugin's query parsing code interacted with the `sqlExpressions` expression evaluator in a way that allowed expression injection to escape into the plugin's host environment. Open source Grafana with no Enterprise plugins was not vulnerable through this specific chain, but the `sqlExpressions` expression evaluator itself contained the primary injection point referenced in the CVE.

Grafana's security release process is more mature than many open source projects of comparable scale — they file CVEs, publish advisories at `https://grafana.com/blog/` and `https://grafana.com/security/security-advisories/` simultaneously with patch releases, and maintain a public bug bounty programme. However, the Grafana changelog is lengthy and mixes security fixes with feature releases, A/B test flags, and plugin updates in a single document. A security team scanning the changelog for `CVE` strings may catch headline vulnerabilities while missing the surrounding context about which feature toggles were implicated.

A compounding factor is how feature toggles propagate from experimental to production. Grafana exposes toggles in four stability stages: `stable`, `publicPreview`, `experimental`, and `alpha`. The `sqlExpressions` toggle was classified as `publicPreview` — suitable for testing and evaluation, not recommended for stable production deployments. In practice, operators enable `publicPreview` and `experimental` toggles during evaluation, the feature proves useful, and the toggle remains enabled indefinitely. The Grafana team does not push default-off enforcement once a toggle is enabled; it stays however the operator configured it. This creates a gap between the attack surface the Grafana team considers stable and the attack surface actually exposed in production at many organisations. Community plugins on `https://grafana.com/grafana/plugins/` have no mandatory security review; a plugin can request broad permissions including `data-source:read:*` (read all data source configurations) and `settings:write:*` (write Grafana server settings) with no human approval gate beyond the signing certificate check.

**Target systems:** Grafana OSS 11.x through 12.4.1 with `sqlExpressions` feature toggle enabled; Grafana Enterprise 11.x through 12.4.1 with Enterprise SQL plugin installed. Patched in Grafana 12.4.2 and the corresponding backport releases.

## Threat Model

1. **Authenticated viewer exploiting CVE-2026-27876.** A Grafana user with viewer role on a dashboard that uses SQL expressions submits a crafted SQL expression payload through the Grafana expression API. The expression escapes the SQL parser's sanitisation layer, reaches the Enterprise plugin's query dispatcher, and executes arbitrary commands under the Grafana server process's user account. The attacker gains access to the Grafana database (SQLite or PostgreSQL depending on deployment), all data source credentials stored in the encrypted secret store, and can pivot to any internal service that Grafana's data source configurations can reach — Prometheus, Loki, Elasticsearch, or application databases.

2. **Overpermissioned plugin exfiltrating the secret store.** A plugin granted `data-source:read:*` permission silently calls the Grafana internal API on initialisation to enumerate all data source configurations and extract their decrypted credentials. Because the plugin process receives the decryption key from the Grafana backend during startup, this requires no additional exploit — only the permission grant that many operators approve without reviewing the plugin's declared permissions in `plugin.json`. The exfiltration leaves no Grafana audit log entry because the access occurs through the plugin SDK RPC channel, not the standard HTTP API.

3. **Patch-gap attacker exploiting the disclosure window.** Grafana 12.4.2 is tagged on GitHub on March 25, 2026. Within hours, a researcher examining the diff between 12.4.1 and 12.4.2 in `pkg/expr/sql.go` identifies the injection point in the SQL expression parser: the specific input character sequence that bypassed sanitisation. They publish a proof-of-concept. Organisations running Grafana with a standard 1–2 week update lag — waiting for testing in staging before promoting to production — are exposed for that entire window. A threat actor with the PoC can scan for Grafana instances, check `/api/health` to confirm version, and target unpatched 12.4.0/12.4.1 instances before the organisation has acted on the advisory.

4. **Malicious community plugin installed from the Grafana marketplace.** A community plugin published to `https://grafana.com/grafana/plugins/` passes the Grafana signing requirement (a certificate issued to the plugin developer) but contains obfuscated network exfiltration code. Operators install it because the "Signed" badge is visible and the plugin description is plausible. The plugin's declared `permissions` in `plugin.json` include `data-source:read:*`, which operators approve during installation without reviewing what the permission grants. The plugin proceeds to exfiltrate data source credentials to an external endpoint on first use.

The blast radius from any of these paths is wide. Grafana is typically positioned to query every significant data source in an infrastructure: production databases, secret managers, cloud provider APIs, message queues, and tracing backends. Code execution or credential theft from the Grafana process is effectively a master key to the observability tier — and from there, to most of the infrastructure that the observability tier monitors.

## Configuration / Implementation

### Immediate: Disable sqlExpressions if Not Needed

If your dashboards and alerting rules do not use SQL expressions as transformation steps, disable the toggle immediately. This is the primary remediation for CVE-2026-27876 if upgrading to 12.4.2 is not yet possible.

In `grafana.ini`:

```ini
[feature_toggles]
# Remove sqlExpressions from any enable list, or set it explicitly to false.
# Do not set enable = sqlExpressions here; omission is sufficient but explicit false is clearer.
sqlExpressions = false
```

Via environment variable (container deployments):

```bash
# Remove sqlExpressions from the space-separated list in GF_FEATURE_TOGGLES_ENABLE.
# If it was previously: GF_FEATURE_TOGGLES_ENABLE="publicDashboards sqlExpressions lokiLive"
# Set it to:
GF_FEATURE_TOGGLES_ENABLE="publicDashboards lokiLive"
```

Verify the toggle is off after restarting Grafana:

```bash
# On the host
grep -i sqlExpressions /etc/grafana/grafana.ini

# In Kubernetes
kubectl get configmap grafana -n monitoring -o yaml | grep -i sqlExpressions

# Via the Grafana API (returns current runtime state)
curl -s -u admin:$GRAFANA_ADMIN_PASS http://localhost:3000/api/frontend/settings \
  | jq '.featureToggles.sqlExpressions'
# Expected output: null or false
```

### Feature Toggle Audit

Enumerate all currently enabled feature toggles and classify each by stability stage. Experimental and alpha toggles should not be enabled in production unless there is a documented, reviewed exception.

```bash
# List all toggles currently set to true at runtime
curl -s -u admin:$GRAFANA_ADMIN_PASS http://localhost:3000/api/frontend/settings \
  | jq '.featureToggles | to_entries[] | select(.value == true) | .key'
```

Cross-reference the output against the [Grafana feature toggle documentation](https://grafana.com/docs/grafana/latest/setup-grafana/configure-grafana/feature-toggles/) to identify stability stage. Any toggle listed as `experimental` or `alpha` should be reviewed for whether it is genuinely required.

In `grafana.ini`, prefer an explicit allowlist of known-stable toggles over an ad-hoc accumulation:

```ini
[feature_toggles]
# Explicit allowlist — only stable toggles permitted in production.
# publicDashboards and lokiLive are examples; adjust to your actual requirements.
enable = publicDashboards lokiLive
# All other toggles, including sqlExpressions, publicPreview, experimental,
# and alpha toggles, are off by default when not listed here.
```

Via environment variable:

```bash
# Production Kubernetes deployment — only stable toggles
GF_FEATURE_TOGGLES_ENABLE="publicDashboards lokiLive"
```

### Plugin Permission Hardening

List all installed plugins:

```bash
grafana-cli plugins ls
```

For each plugin, inspect its `plugin.json` to review declared permissions. On a standard Linux install:

```bash
# Find all plugin.json files
find /var/lib/grafana/plugins -name "plugin.json" | while read f; do
  echo "=== $f ==="
  jq '{id: .id, version: .version, permissions: .dependencies.permissions}' "$f" 2>/dev/null
done
```

Plugins requesting `data-source:read:*` or `settings:write:*` should be individually justified. A plugin that legitimately needs to read one specific data source type (e.g., a PostgreSQL visualisation plugin) should not request wildcard data source read access.

Disable non-admin plugin installation in `grafana.ini`:

```ini
[plugins]
# Prevent non-admin users from installing plugins through the UI
plugin_admin_enabled = false

# Disable automatic plugin installation at startup
# Only plugins explicitly listed here will be installed
auto_install_plugins =

# Prevent plugins from loading resources from external URLs
allow_loading_unsigned_plugins =
```

In Grafana Enterprise, you can additionally restrict which plugins are permitted via the plugin catalogue admin settings. For Kubernetes-deployed Grafana using the official Helm chart:

```yaml
# values.yaml excerpt
grafana.ini:
  plugins:
    plugin_admin_enabled: false
    auto_install_plugins: ""
    allow_loading_unsigned_plugins: ""
```

### Grafana Service Account and OS-Level Isolation

Confine the Grafana process so that RCE does not immediately translate to full host compromise.

On a Linux host, ensure Grafana runs as the `grafana` system user with no sudo access and no shell:

```bash
# Verify Grafana process user
ps aux | grep grafana-server | awk '{print $1}'

# Check that the grafana user has no login shell
getent passwd grafana
# Expected: grafana:x:UID:GID::/home/grafana:/sbin/nologin
```

In Kubernetes, enforce a restrictive security context in the Grafana deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: grafana
  namespace: monitoring
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 472        # default Grafana container UID
        fsGroup: 472
      containers:
        - name: grafana
          image: grafana/grafana:12.4.2
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
              add:
                - NET_BIND_SERVICE
          volumeMounts:
            - name: grafana-storage
              mountPath: /var/lib/grafana
            - name: grafana-tmp
              mountPath: /tmp
      volumes:
        - name: grafana-storage
          persistentVolumeClaim:
            claimName: grafana-pvc
        - name: grafana-tmp
          emptyDir: {}
```

Restrict Grafana pod egress to only known data source endpoints using a Kubernetes NetworkPolicy. This prevents an RCE attacker from pivoting to arbitrary internal services:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: grafana-egress
  namespace: monitoring
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: grafana
  policyTypes:
    - Egress
  egress:
    # Allow DNS
    - ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
    # Allow Prometheus
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
          podSelector:
            matchLabels:
              app.kubernetes.io/name: prometheus
      ports:
        - port: 9090
          protocol: TCP
    # Allow Loki
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
          podSelector:
            matchLabels:
              app.kubernetes.io/name: loki
      ports:
        - port: 3100
          protocol: TCP
    # Block all other egress — add entries for additional data sources as needed
```

### Authentication and RBAC Hardening

Ensure anonymous access is disabled and all access requires authentication:

```ini
[auth.anonymous]
enabled = false

[auth]
# Require login even for public dashboard views
login_cookie_name = grafana_session
disable_login_form = false

[security]
# Require at minimum 12-character passwords for local accounts
password_min_complexity = 3
```

Use Grafana Teams and Folder permissions to isolate data source access by team. Assign data sources to specific folders, then grant folder access only to the relevant team. Service accounts used by alerting rules should use minimal scope:

```bash
# Create a service account for alerting with minimal permissions
curl -s -X POST -u admin:$GRAFANA_ADMIN_PASS \
  -H "Content-Type: application/json" \
  -d '{"name": "alerting-sa", "role": "Viewer"}' \
  http://localhost:3000/api/serviceaccounts

# Verify the service account role is Viewer, not Editor or Admin
curl -s -u admin:$GRAFANA_ADMIN_PASS \
  http://localhost:3000/api/serviceaccounts/search \
  | jq '.serviceAccounts[] | {name: .name, role: .role}'
```

### Monitoring Grafana Security Releases

Subscribe to the Grafana security advisories feed at `https://grafana.com/security/security-advisories/`. This page is updated at the time of disclosure, before blog posts appear.

Use the GitHub API to scan recent Grafana releases for security-relevant content:

```bash
# List the 10 most recent Grafana releases that mention CVE, security, or vulnerability
gh api repos/grafana/grafana/releases \
  --jq '.[0:10] | .[] | select(.body | test("CVE|security|vuln"; "i")) | {tag: .tag_name, body: .body[:200]}'
```

Watch the `pkg/expr/` and `pkg/plugins/manager/` directories for new commits after each Grafana release — these are the directories implicated in expression evaluation and plugin lifecycle management:

```bash
# Commits to the expression evaluator since a specific tag
gh api "repos/grafana/grafana/commits?path=pkg/expr/&since=2026-03-01T00:00:00Z" \
  --jq '.[] | {sha: .sha[:8], message: .commit.message | split("\n")[0], date: .commit.author.date}'

# Commits to the plugin manager
gh api "repos/grafana/grafana/commits?path=pkg/plugins/manager/&since=2026-03-01T00:00:00Z" \
  --jq '.[] | {sha: .sha[:8], message: .commit.message | split("\n")[0], date: .commit.author.date}'
```

Configure Renovate or Dependabot to track the Grafana container image and alert within 48 hours of a new release. In a Renovate configuration:

```json
{
  "packageRules": [
    {
      "matchDatasources": ["docker"],
      "matchPackageNames": ["grafana/grafana", "grafana/grafana-enterprise"],
      "automerge": false,
      "schedule": ["at any time"],
      "labels": ["security-review-required"],
      "prPriority": 10
    }
  ]
}
```

## Expected Behaviour

| Signal | sqlExpressions enabled, default config | Disabled + hardened |
|---|---|---|
| SQL expression RCE attempt (CVE-2026-27876 pattern) | Expression is evaluated; attacker achieves code execution on Grafana server process under Grafana service account | Feature toggle is off; expression API returns 400 — `sqlExpressions` feature not available; no code path reached |
| Plugin reading all data source credentials | Plugin with `data-source:read:*` permission reads every data source configuration silently via SDK channel; no audit log entry | `plugin_admin_enabled = false` prevents new plugin installation; installed plugins reviewed and restricted; wildcard permissions not granted |
| Feature toggle exposure via frontend settings | `/api/frontend/settings` returns `sqlExpressions: true` alongside other experimental toggles; attacker maps enabled features for targeting | API returns only stable toggles; `sqlExpressions` absent; experimental toggle surface minimised |
| Patch-gap window (12.4.0/12.4.1 unpatched) | Organisation running default update cadence exposed for 1–2 weeks after disclosure; PoC available publicly | Renovate/Dependabot creates PR within hours of 12.4.2 release; SQLexpressions disabled as compensating control during patch window |
| Anonymous access to dashboard panels | Unauthenticated user reaches Grafana URL, sees all dashboard data including infrastructure topology | `auth.anonymous.enabled = false`; all requests redirect to login; no dashboard data exposed without authentication |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Disabling sqlExpressions | Eliminates the primary CVE-2026-27876 attack surface; removes expression injection risk for all future expression engine vulnerabilities | Dashboard panels and alerting rules that use SQL expressions as transformation steps stop working immediately after toggle is disabled | Audit dashboards for SQL expression usage before disabling: `curl -s .../api/search | xargs -I{} curl .../api/dashboards/uid/{}` and grep for `type: sql`; migrate transformations to Grafana's built-in transformation pipeline |
| Plugin allowlisting | Prevents malicious or overpermissioned community plugins from accessing the secret store; reduces supply chain risk | Blocks useful community plugins; requires explicit operator review and approval for each plugin; slows plugin adoption | Maintain a reviewed plugin allowlist in version control; document the security review status of each approved plugin; use Grafana's signed plugin requirement as a baseline, not a final gate |
| Strict RBAC with folder isolation | Prevents cross-team data source access; limits blast radius of compromised user account | Reduces dashboard sharing flexibility; requires upfront folder and team structure planning; increases administrative overhead for one-off sharing requests | Use Grafana service accounts for automation; use time-limited API tokens for ad-hoc sharing; document the folder structure and team mapping in a runbook |
| Feature toggle allowlist (stable-only) | Closes the experimental attack surface systematically; prevents future experimental toggles from being left enabled inadvertently | Breaks experimental features currently in use; may surprise teams who rely on publicPreview features for day-to-day work | Inventory experimental toggle usage before applying the allowlist; evaluate publicPreview features individually; create a review process for promoting experimental features to the allowlist |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| sqlExpressions disabled breaks existing dashboards | Dashboard panels that used SQL expression transformations render as empty or display "Data source error"; alerting rules using SQL expressions stop evaluating | Grafana dashboard error panel shows `feature sqlExpressions is disabled`; alert manager shows evaluation errors for affected rules | Re-enable toggle temporarily while migrating; audit affected dashboards using the Grafana API; replace SQL expression transforms with native Grafana transformation steps (join by field, filter by value, organize fields) |
| Plugin removed after allowlist change renders dashboards blank | Dashboards using the removed plugin's panel type show "Panel plugin not found"; datasource-backed panels return no data | Plugin list via `grafana-cli plugins ls` no longer includes the plugin; Grafana logs show `plugin not found: <plugin-id>` | Add the plugin back to the allowlist after completing a security review of its permissions; document the review outcome; alternatively, migrate panels to an approved plugin type |
| RBAC change locks out dashboard editors | Users with Editor role can no longer save dashboards in folders they previously had access to; alert: support ticket volume increases | Grafana audit log shows `403 Forbidden` on dashboard save events for affected users; specific folder access grants absent | Review folder permission assignments; add the affected team to the folder with Editor permission; use Grafana's permission inheritance model to grant access at the organisation level only when folder-level isolation is not required |
| Grafana upgrade changes feature toggle defaults | After upgrading from 11.x to 12.x, a previously-disabled toggle is enabled by default in the new version; dashboard behaviour changes unexpectedly | Compare `featureToggles` output from `/api/frontend/settings` before and after upgrade; check the Grafana upgrade guide for toggle default changes | Review Grafana release notes for toggle default changes before upgrading; pin feature toggle state explicitly in `grafana.ini` rather than relying on defaults; test toggle state in staging before promoting upgrade to production |

## Related Articles

- [Grafana Security Hardening: Authentication, RBAC, and Data Source Permissions](/articles/observability/grafana-security-hardening/)
- [Prometheus Security Metrics and Hardening](/articles/observability/prometheus-security-metrics/)
- [OpenTelemetry Collector Hardening](/articles/observability/otel-collector-hardening/)
- [Kubernetes RBAC Design Patterns](/articles/kubernetes/rbac-design-patterns/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
