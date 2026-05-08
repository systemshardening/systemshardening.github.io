---
title: "Grafana Datasource Auth Bypass: CVE-2026-27880 and HTTP Path Normalisation"
description: "CVE-2026-27880 lets Grafana Viewers bypass datasource access controls with a double slash in the API path. Patch to fixed versions, enforce datasource permissions, and understand the HTTP path normalisation class of auth bypass vulnerabilities."
slug: grafana-datasource-auth-bypass
date: 2026-05-04
lastmod: 2026-05-04
category: observability
tags:
  - grafana
  - cve
  - authentication-bypass
  - prometheus
  - path-traversal
personas:
  - security-engineer
  - platform-engineer
article_number: 435
difficulty: Intermediate
estimated_reading_time: 10
published: true
layout: article.njk
permalink: /articles/observability/grafana-datasource-auth-bypass/
---

## The Problem

CVE-2026-27880 exploits a path normalisation inconsistency between Grafana's HTTP router and its authorisation middleware. Grafana's router normalises double slashes in incoming URL paths before matching routes: a request for `/api//datasources/proxy/2/api/v1/query` is treated identically to `/api/datasources/proxy/2/api/v1/query`, and the correct datasource response is returned. The authorisation middleware that decides whether the requesting user may access a specific datasource runs before routing and reads the original, un-normalised path. Because it sees `/api//datasources/proxy/2/...` — a path it does not recognise as a datasource proxy path — it does not apply datasource access checks and passes the request through unchanged. The router then normalises the path, matches it to the datasource proxy handler, and returns the datasource data.

The practical consequence is that any authenticated Grafana user with the Viewer role — the lowest privilege level, the role that should provide read access only to dashboards, not to arbitrary datasource queries — can submit direct queries to any datasource the Grafana instance can reach. They do not need to be granted access to that datasource. They do not need to know the datasource credentials. They need only prepend an extra slash to the standard datasource proxy API path.

This matters in practice because of what Grafana datasources contain. Prometheus datasources expose all scraped metrics, including labels that reveal infrastructure topology, internal service names, customer-facing counts, error rates, and deployment identifiers that are not intended for broad consumption. Alertmanager datasources expose the full set of configured alert rules — which conditions the team considers abnormal, what thresholds trigger pages, and what service-level objectives look like from the inside. Loki datasources expose raw log streams. In a multi-tenant Grafana organisation where different teams are granted access to different datasources, CVE-2026-27880 allows one team's Viewer to read another team's datasource data by bypassing the access boundary that the datasource permissions were intended to enforce.

The vulnerability was disclosed on March 25, 2026 and fixed in Grafana 11.6.14, 12.1.10, 12.2.8, 12.3.6, and 12.4.2. The fix corrects the ordering and scope of path normalisation so that the authorisation middleware and the router operate on the same normalised path.

The path normalisation class of authorisation bypass is not unique to Grafana. It appears repeatedly across web frameworks and reverse proxy configurations because the components that handle routing and the components that handle authorisation are written and maintained independently, and each makes a different assumption about what form the URL path will take when they receive it. The canonical form of this class of bug is a middleware that checks the original request path against an access control list, coupled with a downstream component that normalises the path before dispatching. If the attacker can provide a path that the access control list does not match but that normalises to a protected resource, access control is bypassed. Variations include trailing slash differences (`/api/admin` versus `/api/admin/`), encoded slashes (`%2F` versus `/`), dot-segment resolution (`/api/./datasources/`), and null byte insertion in languages that handle C string semantics. The double-slash variant in CVE-2026-27880 is among the simplest and most portable forms of the class.

Understanding the class rather than just the CVE is operationally important. Patching Grafana closes this specific instance of the bypass. But if the same Grafana instance sits behind a reverse proxy that performs its own path normalisation, or if the next CVE in this class uses a different normalisation technique against a different middleware, the structural conditions for the bypass still exist. Defence in depth against path normalisation bypasses requires normalising paths consistently at the earliest possible point in the request processing chain — ideally at the reverse proxy, before the request reaches the application — so that neither the application's authorisation layer nor its routing layer ever sees a non-canonical path.

## Threat Model

The attacker in CVE-2026-27880 is an authenticated Grafana user with Viewer access. This is not a particularly constrained attacker. Viewer is the role routinely granted to developers, data analysts, and operations staff who need to see dashboards but should not be able to create or modify them. In many organisations, Viewer access is granted broadly — sometimes to entire LDAP or SSO groups — on the assumption that read access to dashboards is low risk. CVE-2026-27880 invalidates that assumption for any deployment that has not patched to a fixed version.

The bypass requires only a modified HTTP request. There is no exploit chain, no memory corruption, no race condition. An attacker who knows the datasource ID — which is visible in the Grafana UI to any user who can view a dashboard that uses that datasource, and which increments predictably from 1 — can construct the bypass request without any additional information. The modification is a single extra `/` character inserted after `/api`. The request is otherwise identical to a legitimate datasource proxy query.

Automated scanning increases the threat beyond opportunistic manual exploitation. A script that iterates over datasource IDs from 1 to 50, prepends the double slash, and exfiltrates metric names and alert rules from each one requires fewer than twenty lines of code and completes in seconds. An attacker who gains Viewer access through a phishing link, a compromised SSO session, or an invited account that was never revoked can automate full datasource enumeration immediately.

In multi-tenant Grafana deployments — where multiple teams share a single Grafana instance but are partitioned into organisations or datasource permissions — the blast radius of the bypass extends across organisational boundaries. A Viewer in the payments team's Grafana organisation can query the infrastructure team's Prometheus datasource, even if that datasource was never shared with the payments organisation. Prometheus metrics from the infrastructure datasource may include label sets that reveal internal service architecture, database hostnames, internal API endpoints, and deployment details that have security sensitivity independent of the metrics values themselves.

Alertmanager datasources are a secondary target worth specific attention. Alert rules reveal the operational assumptions of the team that wrote them — what failure modes are considered alertable, what thresholds are considered abnormal, and which silence rules are currently active. A quiet period in alerting rules (an active silence) tells an attacker that the team will not receive pages during that window.

## Hardening Configuration

### 1. Patch to Fixed Versions

The definitive remediation is upgrading to a version that contains the fix. The corrected releases are:

- Grafana 11.6.14 and later 11.6.x releases
- Grafana 12.1.10 and later 12.1.x releases
- Grafana 12.2.8 and later 12.2.x releases
- Grafana 12.3.6 and later 12.3.x releases
- Grafana 12.4.2 and later 12.4.x releases

Verify the running version on the host:

```bash
grafana-server --version
```

Verify via the Grafana API without requiring a login shell on the host:

```bash
curl -s https://grafana.example.com/api/health | jq '{version: .version, commit: .commit}'
```

In a Kubernetes deployment, verify the image tag on the running pod:

```bash
kubectl get pods -n monitoring -l app=grafana \
  -o jsonpath='{.items[0].spec.containers[0].image}'
```

After upgrading, confirm the bypass is no longer effective by repeating the test request described in the Expected Behaviour section. A version string alone is not a sufficient post-upgrade check; confirm that the patched behaviour is present in the running instance.

### 2. Enable Datasource Permissions

Patching closes the specific normalisation bypass in CVE-2026-27880. Enabling datasource-level permissions provides a separate authorisation layer that enforces access control at the Grafana application level, reducing the exposure window during the period between future vulnerability disclosures and patch deployment.

Grafana Enterprise and Grafana Cloud support per-datasource access control. Enable datasource permissions and restrict each datasource to only the teams or service accounts that require query access:

```bash
curl -X POST "https://grafana.example.com/api/datasources/uid/prometheus-infra/permissions" \
  -H "Authorization: Bearer ${GRAFANA_ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "items": [
      {"teamId": 3, "permission": 2},
      {"builtInRole": "Viewer", "permission": 0}
    ]
  }'
```

In this example, team 3 receives query permission (`2`) on the `prometheus-infra` datasource, and the built-in Viewer role has its access revoked (`0`). Viewers who are not members of team 3 cannot query this datasource through the normal path — and with the patch applied, the double-slash bypass path is also closed.

For open-source Grafana, per-datasource permissions are not available. The closest equivalent is using separate Grafana organisations per team, where each organisation has access only to the datasources that team needs. This is administratively heavier — users must switch between organisations rather than between dashboards — but it enforces the same data boundary that datasource permissions provide in the Enterprise tier.

Provision datasource access restrictions via configuration management rather than the UI:

```yaml
apiVersion: 1
datasources:
  - name: prometheus-infra
    type: prometheus
    uid: prometheus-infra
    url: http://prometheus-infra:9090
    access: proxy
    jsonData:
      httpMethod: POST
```

```bash
curl -X PUT "https://grafana.example.com/api/datasources/uid/prometheus-infra" \
  -H "Authorization: Bearer ${GRAFANA_ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"readOnly": true}'
```

### 3. Audit Access Logs for Exploitation During the Vulnerable Window

If your Grafana instance was running a vulnerable version and is now patched, check whether the bypass was used. Requests exploiting CVE-2026-27880 leave a distinctive mark in Grafana's access logs: the double slash in the URL path is preserved in log entries because the log is written before path normalisation occurs in the routing layer.

```bash
grep -E 'GET /api//datasources/proxy|POST /api//datasources/proxy' \
  /var/log/grafana/grafana.log
```

In a containerised deployment, search the collected log output from the relevant time period:

```bash
kubectl logs -n monitoring deployment/grafana --since=720h \
  | grep -E '/api//datasources'
```

A match on the double-slash pattern indicates a request that used the bypass path. To determine whether the request returned data rather than an error, check the HTTP status code in the same log line. A `200` response means the bypass succeeded and data was returned. Correlate the requesting user identity and the datasource ID in the log entry to determine the scope of any data that was accessed.

Do not dismiss double-slash patterns as crawler noise without verifying the response status. Legitimate crawlers and web scanners frequently generate 404 responses on malformed paths; a `200` response on a double-slash datasource proxy path during the vulnerability window is not noise.

### 4. Normalise Paths at the Reverse Proxy

Placing Grafana behind a reverse proxy that normalises double slashes before forwarding requests eliminates the bypass for all currently unpatched Grafana versions and provides defence in depth against future path normalisation vulnerabilities of the same class.

Nginx normalises double slashes by default via the `merge_slashes` directive. Verify it is enabled in your Nginx configuration and has not been explicitly disabled:

```nginx
server {
    listen 443 ssl;
    server_name grafana.example.com;

    merge_slashes on;

    location / {
        proxy_pass http://grafana:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

`merge_slashes on` is the Nginx default. If you find `merge_slashes off` in your configuration, understand why it was set before changing it: some deployments disable it to preserve encoded slashes in URL paths that are meaningful to the application. Grafana has no documented requirement for double slashes in its API paths, so enabling `merge_slashes on` is safe for Grafana.

Verify the Nginx configuration and confirm the directive is active:

```bash
nginx -T | grep merge_slashes
```

An Envoy-based ingress can be configured to normalise paths via the `normalize_path` option in the `HttpConnectionManager` filter:

```yaml
http_filters:
  - name: envoy.filters.http.router
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
normalize_path: true
merge_slashes: true
```

With either proxy, test that normalisation is active by sending a request with a double slash and confirming the Grafana access log records the normalised single-slash path:

```bash
curl -v -u viewer:password \
  "https://grafana.example.com/api//datasources/proxy/1/api/v1/query?query=up" 2>&1 \
  | grep "< HTTP"
```

### 5. Least-Privilege Datasource Access

CVE-2026-27880 is exploitable because Viewers can reach datasource proxy endpoints at all. The structural hardening that reduces the impact of any future bypass in this area is ensuring that each Grafana user can only query the datasources they have a documented business reason to access.

Audit current datasource access. In Grafana Enterprise or Grafana Cloud, retrieve per-datasource permission assignments for each datasource and review them against team membership:

```bash
for uid in $(curl -s -H "Authorization: Bearer ${GRAFANA_ADMIN_TOKEN}" \
    "https://grafana.example.com/api/datasources" \
    | jq -r '.[].uid'); do
  echo "=== Datasource: ${uid} ==="
  curl -s -H "Authorization: Bearer ${GRAFANA_ADMIN_TOKEN}" \
    "https://grafana.example.com/api/datasources/uid/${uid}/permissions" \
    | jq '.items[] | {role: .builtInRole, teamId: .teamId, permission: .permission}'
done
```

Any datasource where `builtInRole: "Viewer"` has `permission: 2` (query access) is accessible to all authenticated Grafana users in the organisation. These are the datasources with the largest exposure surface; they should either have their broad access revoked and replaced with team-scoped permissions, or their data should be validated as genuinely safe for all authenticated users to query.

## Expected Behaviour After Hardening

After patching to a fixed version, the double-slash bypass request returns a 403 response:

```bash
curl -u viewer:password \
  "https://grafana.example.com/api//datasources/proxy/2/api/v1/query?query=up"
```

The response body contains a Grafana authorisation error rather than Prometheus data. The authorisation middleware now reads the same normalised path as the router, correctly identifies the request as a datasource proxy request for datasource ID 2, evaluates the requesting user's permissions against datasource 2, and returns 403 if the user does not have query access.

After configuring Nginx with `merge_slashes on`, the double-slash request is normalised before it reaches Grafana. The Grafana access log records the request path as `/api/datasources/proxy/2/api/v1/query` — without the double slash — meaning the bypass attempt is indistinguishable from a legitimate request that the authorisation middleware evaluates normally. The mitigation is invisible to the attacker and requires no changes to Grafana's own configuration.

After revoking broad Viewer access to sensitive datasources, a Viewer who is not a member of the permitted team receives a 403 for the normalised path as well. The patch and the datasource permission configuration together ensure that both the bypass path and the direct path are covered by authorisation checks.

## Trade-offs and Operational Considerations

Grafana Enterprise datasource permissions require a Grafana Enterprise licence. Organisations running open-source Grafana cannot enable per-datasource permissions and must use separate Grafana organisations as a workaround. Managing multiple Grafana organisations — each with its own set of datasources, dashboards, and users — increases administrative overhead significantly. User-facing UX is also affected: switching between Grafana organisations requires an explicit action in the Grafana UI, and there is no cross-organisation dashboard browsing. This is a meaningful operational trade-off, but it is the only structural alternative available in the open-source tier.

Nginx `merge_slashes on` is enabled by default, but it may be explicitly disabled in configurations where the application behind Nginx uses double slashes as meaningful path components — some content management systems and file storage APIs do this. Before relying on `merge_slashes on` as a compensating control, verify that no other application behind the same Nginx instance requires double-slash preservation. If they do, use a dedicated Nginx server block for Grafana with `merge_slashes on` rather than setting it globally.

The log audit for exploitation indicators requires access to Grafana logs from the vulnerable period. If logs are rotated aggressively or are not shipped to a centralised log system, the historical evidence may not be available. A missing audit is not evidence that the bypass was not used; it is evidence that the question cannot be answered. If you cannot reconstruct whether CVE-2026-27880 was exploited in your environment during the vulnerable window, treat it as potentially exploited for incident response purposes: inventory which datasources were accessible to all Viewer-role users, assume all of them were queried, and assess the sensitivity of the data they contain.

## Failure Modes

Grafana is patched but the deployment is accessible both through a properly configured reverse proxy and directly via the Grafana pod's service port within the cluster. Kubernetes workloads running in the same namespace — or any workload with network access to the Grafana service — can reach the direct Grafana port and use the bypass regardless of what the reverse proxy does. The patch closes this vector, but if the cluster has any pods running a vulnerable pre-patch Grafana version alongside the patched version (common during a rolling update), those pods remain exploitable from inside the cluster. Apply `NetworkPolicy` to restrict access to the Grafana service port to only the ingress controller and authorised internal clients:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: grafana-restrict-ingress
  namespace: monitoring
spec:
  podSelector:
    matchLabels:
      app: grafana
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress-nginx
      ports:
        - port: 3000
          protocol: TCP
```

Datasource permissions are configured correctly, but the Grafana instance has a datasource named "Default" or a datasource that was provisioned without an explicit permission set. Grafana's default behaviour when no datasource permissions are configured for a datasource is to allow all authenticated users to query it. A single unconfigured datasource undermines the access boundary for the entire set of datasources. After configuring permissions, verify that every datasource has an explicit permission set and that no datasource relies on the default open-access behaviour.

Log analysis finds double-slash patterns in the Grafana access logs but the reviewing engineer concludes they are web crawlers or scanner noise and closes the investigation. The distinguishing factor is the HTTP response status code: crawlers and automated scanners hitting a malformed path almost universally receive 404 or 400 responses. A 200 response on `/api//datasources/proxy/N/...` during the vulnerable window means the bypass succeeded and the Grafana instance returned datasource data to that request. Filter for status 200 specifically:

```bash
grep -E '/api//datasources/proxy' /var/log/grafana/grafana.log \
  | grep '"status_code":200'
```

Any match warrants full incident investigation, not dismissal.

## Related Articles
- [Grafana Security Hardening](/articles/observability/grafana-security-hardening/)
- [Grafana Plugin Trust and RCE](/articles/observability/grafana-plugin-trust-rce/)
- [Prometheus Security Metrics](/articles/observability/prometheus-security-metrics/)
- [Prometheus Remote Write Security](/articles/observability/prometheus-remote-write-security/)
- [OTel Collector Hardening](/articles/observability/otel-collector-hardening/)
