---
title: "Synthetic Monitoring as a Security Tool: Blackbox Exporter, Certificate Probes, and Tamper Detection"
description: "Prometheus Blackbox Exporter probes external endpoints continuously — making it a powerful early-warning system for TLS certificate expiry, TLS downgrade attacks, content tampering, DNS hijacking, and missing security headers, weeks before users are affected."
slug: synthetic-monitoring-security
date: 2026-05-07
lastmod: 2026-05-07
category: observability
tags:
  - synthetic-monitoring
  - blackbox-exporter
  - certificate-monitoring
  - availability-monitoring
  - security-monitoring
personas:
  - security-engineer
  - platform-engineer
article_number: 556
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/observability/synthetic-monitoring-security/
---

# Synthetic Monitoring as a Security Tool: Blackbox Exporter, Certificate Probes, and Tamper Detection

## Problem

Synthetic monitoring is usually framed as an uptime problem: "is the site reachable?" But the Prometheus [Blackbox Exporter](https://github.com/prometheus/blackbox_exporter) does much more than ping a URL. Each probe carries security signal that most teams ignore:

- **Certificate expiry** is a hard cutover from working HTTPS to total failure. The expiry date is visible weeks in advance. Most teams still get surprised.
- **TLS downgrade** happens when a server that should only accept TLS 1.3 silently accepts TLS 1.0 connections. No alert fires because the connection still succeeds.
- **Content tampering** — defacement, injected skimming scripts, poisoned API responses — does not affect uptime. Standard uptime checks return HTTP 200 and declare everything healthy.
- **DNS hijacking** returns a different IP for your domain. Standard HTTP probes follow the redirect and pass. The user is on an attacker-controlled server.
- **Security header regression** — a deploy removes the `Content-Security-Policy` header. Metrics confirm the endpoint is up. The XSS protection is gone.

These are all detectable by Blackbox Exporter probes configured with security in mind. They are not detected by probes configured with only uptime in mind.

**Target systems:** [Prometheus](https://prometheus.io) 2.45+; Blackbox Exporter 0.24+; [Alertmanager](https://prometheus.io/docs/alerting/latest/alertmanager/) 0.26+; [Grafana](https://grafana.com) 10+.

## Threat Model

- **Adversary 1 — Certificate expiry via renewal failure:** cert-manager fails silently 30 days before expiry. No engineer notices. On day 0 the cert expires, HTTPS fails for all users. Blackbox Exporter would have been firing a warning alert for 28 days.
- **Adversary 2 — BGP hijack or DNS compromise redirects traffic:** An attacker redirects `payments.example.com` to a server they control. The server presents a valid Let's Encrypt certificate for a different domain. Standard uptime checks pass. A probe checking the expected certificate subject and issuer would have fired immediately.
- **Adversary 3 — Web skimmer injection:** An attacker compromises a CDN configuration and injects a `<script src="https://evil.example/skim.js">` tag into every page response. HTTP 200. No change in latency. A probe matching page content against a known-safe pattern fires immediately.
- **Adversary 4 — Security header stripped by misconfigured reverse proxy:** A reverse proxy update removes `Strict-Transport-Security` and `X-Frame-Options`. The application is now vulnerable to SSL stripping and clickjacking. No error. No alert without explicit header probing.
- **Adversary 5 — TLS downgrade via misconfigured load balancer:** A load balancer configuration is updated and accidentally re-enables TLS 1.0. Applications continue to work. PCI-DSS requires TLS 1.2+. A probe that asserts the minimum TLS version would fire.
- **Access level:** Adversaries 1, 3, 4, 5 are reachable via the public internet with no authentication. Adversary 2 requires BGP or DNS control, which is within reach of nation-state and sophisticated criminal actors.
- **Objective:** Harvest credentials, intercept payments, serve malware, perform SSL-stripping man-in-the-middle.
- **Blast radius:** Every user of a public-facing endpoint. For payment flows, every transaction in the window between compromise and detection.

## Configuration

### Step 1: Blackbox Exporter Baseline Setup

Deploy Blackbox Exporter and configure a core set of security-focused modules. The module configuration lives in `blackbox.yml`, not in `prometheus.yml`.

```yaml
# blackbox.yml — core security-focused probe modules.
modules:

  # Standard HTTPS check: verifies TLS, follows redirects, expects 2xx.
  https_2xx:
    prober: http
    timeout: 10s
    http:
      valid_http_versions: ["HTTP/1.1", "HTTP/2.0"]
      valid_status_codes: []          # defaults to 2xx
      method: GET
      follow_redirects: true
      fail_if_ssl: false
      fail_if_not_ssl: true           # MUST be HTTPS — fail if HTTP is served
      tls_config:
        insecure_skip_verify: false   # never skip — defeat the purpose of TLS checks

  # Strict TLS 1.2+ check: used for PCI-DSS scope endpoints.
  https_tls12_strict:
    prober: http
    timeout: 10s
    http:
      fail_if_not_ssl: true
      tls_config:
        insecure_skip_verify: false
        min_version: TLS12            # probe fails if server does not support TLS 1.2+

  # TCP with TLS — for non-HTTP services: SMTP, LDAPS, database ports.
  tcp_tls:
    prober: tcp
    timeout: 10s
    tcp:
      tls: true
      tls_config:
        insecure_skip_verify: false

  # DNS resolution check — asserts a specific IP is returned.
  dns_expected:
    prober: dns
    timeout: 5s
    dns:
      query_name: "payments.example.com"
      query_type: "A"
      valid_rcodes:
        - NOERROR
      validate_answer_rrs:
        fail_if_not_matches_regexp:
          - "payments\\.example\\.com\\.\\s+\\d+\\s+IN\\s+A\\s+203\\.0\\.113\\."
        # Fires if the returned A record is NOT in the 203.0.113.0/24 range.
        # Adjust to match your actual production IP range.
```

### Step 2: TLS Certificate Validity Probing

The `probe_ssl_earliest_cert_expiry` metric is the most valuable security metric Blackbox Exporter emits. It is a Unix timestamp of the soonest-expiring certificate in the chain returned by the probe. Combined with recording rules and alerts, it provides structured early warning.

```yaml
# prometheus.yml — scrape config for certificate expiry monitoring.
scrape_configs:
  - job_name: "blackbox_tls"
    metrics_path: /probe
    params:
      module: [https_2xx]
    static_configs:
      - targets:
          - https://www.example.com
          - https://api.example.com
          - https://payments.example.com
          - https://auth.example.com
    relabel_configs:
      # Move the target URL into the 'instance' label and pass it as the probe target.
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: blackbox-exporter:9115
```

The key metric returned per probe:

```
probe_ssl_earliest_cert_expiry{instance="https://payments.example.com"} 1.7832e+09
probe_tls_version_info{instance="https://payments.example.com", version="TLS 1.3"} 1
probe_http_ssl{instance="https://payments.example.com"} 1
probe_success{instance="https://payments.example.com"} 1
```

### Step 3: Content Integrity Checking

Use `fail_if_body_matches_regexp` to detect injected content and `fail_if_body_not_matches_regexp` to detect content removal. These two directions cover different attack scenarios.

```yaml
# blackbox.yml — content integrity modules.
modules:

  # Defacement / injection detection: probe fails if these patterns appear in the body.
  https_no_injection:
    prober: http
    timeout: 15s
    http:
      fail_if_not_ssl: true
      tls_config:
        insecure_skip_verify: false
      fail_if_body_matches_regexp:
        # Skimmer script patterns: adjust these to known-bad CDN domains.
        - "src=[\"']https?://(?!cdn\\.example\\.com|trusted-cdn\\.com)[^\"']*\\.js[\"']"
        # Generic eval-based obfuscation common in skimmers.
        - "eval\\(atob\\("
        # Iframe injection.
        - "<iframe[^>]+src=[\"']https?://(?!www\\.example\\.com)"

  # Content presence check: probe fails if expected content is MISSING.
  # Use this to detect complete replacement of page content (full defacement).
  https_content_present:
    prober: http
    timeout: 15s
    http:
      fail_if_not_ssl: true
      tls_config:
        insecure_skip_verify: false
      fail_if_body_not_matches_regexp:
        # A string that MUST be in every response — e.g., your canonical brand name.
        - "Example Corp"
        # Or a meta tag, a specific footer string, a copyright notice.
        - "© 2026 Example Corp"
```

Content integrity probes are most useful against static pages, marketing sites, and login pages — the surfaces attackers prefer for credential harvesting.

### Step 4: HTTP Security Header Monitoring

HTTP probers can assert that specific headers are present and contain expected values. This catches security header regressions introduced by deploys or proxy changes.

```yaml
# blackbox.yml — security header validation module.
modules:
  https_security_headers:
    prober: http
    timeout: 10s
    http:
      fail_if_not_ssl: true
      tls_config:
        insecure_skip_verify: false
      # fail_if_header_not_matches requires Blackbox Exporter 0.23+.
      fail_if_header_not_matches:
        - header: Strict-Transport-Security
          regexp: "max-age=([6-9][0-9]{6}|[1-9][0-9]{7,})"
          # Asserts HSTS max-age >= 6 months (15768000 seconds).
          # Fires if HSTS is absent or max-age is too short.
        - header: X-Frame-Options
          regexp: "(?i)(DENY|SAMEORIGIN)"
        - header: X-Content-Type-Options
          regexp: "(?i)nosniff"
      fail_if_header_matches:
        - header: Server
          regexp: "(?i)(Apache/[12]|nginx/[01]\\.|IIS/[0-9])"
          # Fires if the Server header reveals a known-old version.
          # Adjust regex to match versions you consider unacceptably old.
```

Run this module against your primary web properties on the same scrape interval as your uptime checks — every 60 seconds. A deploy that removes HSTS will appear in your dashboards within a minute.

Note: `Content-Security-Policy` is too variable to check with a simple regexp. Use a dedicated CSP evaluation tool for deep CSP analysis. The header probe is best for binary presence/absence and simple value assertions.

### Step 5: DNS Hijack Detection

DNS hijacking changes the A or AAAA records for your domains to point to an attacker-controlled server. The attack is especially effective against high-value targets like payment endpoints and login pages. Blackbox Exporter's DNS prober can validate the returned answers against expected IP ranges.

```yaml
# blackbox.yml — DNS hijack detection modules.
modules:
  dns_payments_a_record:
    prober: dns
    timeout: 5s
    dns:
      preferred_ip_protocol: "ip4"
      query_name: "payments.example.com"
      query_type: "A"
      valid_rcodes:
        - NOERROR
      validate_answer_rrs:
        fail_if_not_matches_regexp:
          # Expected IP range. Update to match your load balancer IPs or CDN range.
          - "payments\\.example\\.com\\.\\s+\\d+\\s+IN\\s+A\\s+(203\\.0\\.113\\.1|203\\.0\\.113\\.2)$"
        fail_if_matches_regexp:
          # Explicit deny: any RFC1918 / loopback address in the response is suspicious.
          - "payments\\.example\\.com\\.\\s+\\d+\\s+IN\\s+A\\s+(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|127\\.)"
```

```yaml
# prometheus.yml — scrape config for DNS hijack probes.
  - job_name: "blackbox_dns_hijack"
    metrics_path: /probe
    params:
      module: [dns_payments_a_record]
    static_configs:
      - targets:
          # Probe from multiple resolvers to detect resolver-specific hijacking.
          - 8.8.8.8          # Google Public DNS
          - 1.1.1.1          # Cloudflare
          - 208.67.222.222   # OpenDNS
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: blackbox-exporter:9115
```

Probing multiple resolvers catches hijacks that only affect specific resolver paths — which is the case for BGP prefix hijacks and compromised DNS resolvers at the ISP level.

### Step 6: Alertmanager Rules for Certificate Expiry

```yaml
# prometheus-rules.yml — certificate expiry and probe security alerts.
groups:
  - name: synthetic_security
    interval: 60s
    rules:

      # Certificate expiry: critical page at 14 days, warning at 28 days.
      - alert: CertificateExpiryCritical
        expr: |
          (probe_ssl_earliest_cert_expiry - time()) / 86400 < 14
        for: 5m
        labels:
          severity: critical
          team: platform
        annotations:
          summary: "Certificate expiring in less than 14 days: {{ $labels.instance }}"
          description: |
            The TLS certificate for {{ $labels.instance }} expires in
            {{ $value | printf "%.0f" }} days. Renewal must happen before day 0.
          runbook: "https://runbooks.example.com/cert-expiry"

      - alert: CertificateExpiryWarning
        expr: |
          (probe_ssl_earliest_cert_expiry - time()) / 86400 < 28
        for: 5m
        labels:
          severity: warning
          team: platform
        annotations:
          summary: "Certificate expiring in less than 28 days: {{ $labels.instance }}"
          description: |
            The TLS certificate for {{ $labels.instance }} expires in
            {{ $value | printf "%.0f" }} days.

      # TLS version regression: probe succeeds but TLS < 1.2 is in use.
      - alert: TLSVersionInsecure
        expr: |
          probe_tls_version_info{version=~"TLS 1\\.0|TLS 1\\.1|SSL.*"} == 1
        for: 5m
        labels:
          severity: critical
          team: security
        annotations:
          summary: "Insecure TLS version in use: {{ $labels.instance }}"
          description: |
            {{ $labels.instance }} accepted a connection using {{ $labels.version }}.
            PCI-DSS requires TLS 1.2+. Disable legacy TLS on the load balancer.

      # Content integrity or header probe failure.
      - alert: SecurityProbeFailure
        expr: |
          probe_success{job=~"blackbox_security_headers|blackbox_content_integrity"} == 0
        for: 2m
        labels:
          severity: critical
          team: security
        annotations:
          summary: "Security probe failure: {{ $labels.instance }}"
          description: |
            The security probe for {{ $labels.instance }} is failing.
            This may indicate a missing security header, injected content,
            or a content integrity violation. Investigate immediately.

      # DNS hijack detection.
      - alert: DNSHijackDetected
        expr: |
          probe_success{job="blackbox_dns_hijack"} == 0
        for: 1m
        labels:
          severity: critical
          team: security
        annotations:
          summary: "DNS answer validation failed: possible hijack on {{ $labels.instance }}"
          description: |
            The DNS probe for payments.example.com via resolver {{ $labels.instance }}
            returned an unexpected answer. Verify DNS records immediately.
```

### Step 7: Prometheus Recording Rules for Synthetic SLOs

Synthetic probes provide clean inputs for availability SLOs tracked over burn windows.

```yaml
# prometheus-rules.yml — synthetic SLO recording rules.
groups:
  - name: synthetic_slo_recording
    interval: 30s
    rules:

      # 5-minute probe success rate per target.
      - record: job_instance:probe_success:rate5m
        expr: |
          avg_over_time(probe_success[5m])

      # Certificate days remaining — pre-computed for dashboards.
      - record: instance:cert_days_remaining:gauge
        expr: |
          (probe_ssl_earliest_cert_expiry - time()) / 86400

      # 30-day synthetic availability per job.
      - record: job:probe_success:availability30d
        expr: |
          avg_over_time(probe_success[30d])

      # Probe duration p99 over 1 hour — latency SLO signal.
      - record: job_instance:probe_duration_seconds:p99_1h
        expr: |
          histogram_quantile(0.99,
            rate(probe_duration_seconds_bucket[1h])
          )
```

### Step 8: Securing Blackbox Exporter Itself

Blackbox Exporter has a significant SSRF vulnerability surface that is frequently overlooked. The `/probe` endpoint accepts a `target` query parameter — and by default it probes whatever URL you pass it.

**The SSRF risk:**

```
# An attacker who can reach blackbox-exporter:9115 can probe internal targets:
GET /probe?target=http://169.254.169.254/latest/meta-data/&module=http_2xx
GET /probe?target=http://internal-redis:6379&module=tcp_connect
GET /probe?target=http://kubernetes.default.svc.cluster.local/api/v1/secrets&module=http_2xx
```

If Blackbox Exporter is reachable from within the cluster and the Kubernetes service account has any permissions, this becomes a credentials-via-probe path.

**Mitigation 1: Use a static target list in Prometheus, never accept free-form targets.**

The scrape configs in Step 2 and Step 5 use `static_configs` with `relabel_configs` to pass the target as a parameter. This is correct. The risk materialises when engineers add a debug endpoint or expose the service externally. Lock this down at the network layer.

```yaml
# kubernetes NetworkPolicy: restrict who can reach blackbox-exporter.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: blackbox-exporter-ingress
  namespace: monitoring
spec:
  podSelector:
    matchLabels:
      app: blackbox-exporter
  policyTypes:
    - Ingress
  ingress:
    # Only allow traffic from Prometheus pods in the monitoring namespace.
    - from:
        - podSelector:
            matchLabels:
              app: prometheus
          namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
      ports:
        - port: 9115
          protocol: TCP
    # No ingress from any other source — no developer tooling, no debugging.
```

**Mitigation 2: Disable the `/probe` endpoint's free-form target parameter at the proxy layer.**

If you run Blackbox Exporter behind a reverse proxy (NGINX, Envoy, Traefik), add a rule that only allows probe requests with targets from an approved allowlist:

```nginx
# nginx snippet: only allow known targets to the probe endpoint.
location /probe {
    # Reject requests that do not come from the Prometheus server.
    allow 10.0.1.15;   # Prometheus pod IP (or use a CIDR for the monitoring namespace).
    deny all;
}
```

**Mitigation 3: Run Blackbox Exporter without host network access.**

```yaml
# blackbox-exporter Deployment: no privileged access, no host network.
spec:
  template:
    spec:
      hostNetwork: false
      hostPID: false
      hostIPC: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534        # nobody
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: blackbox-exporter
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
```

**Mitigation 4: Enable Blackbox Exporter's built-in web TLS and basic auth.**

```yaml
# web-config.yml for blackbox-exporter — TLS + basic auth.
tls_server_config:
  cert_file: /tls/tls.crt
  key_file: /tls/tls.key
  min_version: TLS12

basic_auth_users:
  # bcrypt hash of the Prometheus scrape password.
  prometheus: $2y$12$abc...
```

Pass this config with `--web.config.file=/etc/blackbox/web-config.yml`. Prometheus scrape configs must then include the matching `basic_auth` or `tls_config` stanza.

### Step 9: Real User Monitoring with Grafana Faro

Synthetic probes test from a fixed vantage point. [Grafana Faro](https://grafana.com/oss/faro/) instruments the browser and reports real user experience — including security-relevant signals that synthetic probes cannot see:

- **Mixed content warnings:** A page served over HTTPS loading a resource over HTTP. Faro captures these as browser console errors.
- **CSP violations:** If your CSP is configured in report-only mode, browsers report violations to Faro's collector.
- **Third-party script failures:** A skimmer that loads from a CDN not in your script-src will produce a CSP violation if your policy is correct — and Faro will capture it.

```javascript
// faro-init.js — initialise Grafana Faro in your frontend.
import { initializeFaro, getWebInstrumentations } from '@grafana/faro-web-sdk';

initializeFaro({
  url: 'https://faro-collector.example.com/collect',
  app: {
    name: 'web-frontend',
    version: '1.0.0',
    environment: 'production',
  },
  instrumentations: [
    ...getWebInstrumentations({
      captureConsole: true,     // captures mixed content and CSP warnings
      captureConsoleDisabledLevels: [],
    }),
  ],
});
```

Route Faro's CSP violation events to an Alertmanager webhook receiver to get real-time notification when a CSP violation is detected in a production browser session.

## Verification

After deploying the configuration:

1. Confirm probes are appearing in Prometheus: `probe_success{job="blackbox_tls"}` should return 1 for each configured target.
2. Check certificate expiry metrics: `instance:cert_days_remaining:gauge` should show values greater than 14 for all targets.
3. Test content integrity probes: temporarily add a known-bad string to a test page and confirm `probe_success` drops to 0 within one scrape interval.
4. Validate DNS probes: query `probe_success{job="blackbox_dns_hijack"}` — all resolvers should return 1.
5. Test SSRF mitigation: from a pod other than Prometheus, attempt `curl http://blackbox-exporter:9115/probe?target=http://kubernetes.default.svc.cluster.local/&module=http_2xx` — the NetworkPolicy should drop the connection.
6. Review Alertmanager routing: confirm that `severity: critical` alerts for `SecurityProbeFailure` and `DNSHijackDetected` route to your on-call channel, not only to email.

## Summary

Blackbox Exporter is already deployed in most Prometheus environments for uptime monitoring. The security uplift requires no new tooling — only additional modules in `blackbox.yml`, targeted scrape jobs in `prometheus.yml`, and alert rules that treat probe failures as security events rather than availability events.

The highest-impact additions in order:

1. `probe_ssl_earliest_cert_expiry` alerts at 28 days and 14 days — eliminates the most common cause of self-inflicted HTTPS outages.
2. `fail_if_body_matches_regexp` for known injection patterns — catches web skimmers and defacement within one scrape interval.
3. DNS answer validation against expected IP ranges — catches BGP hijacks and DNS compromises before users land on the attacker's server.
4. `fail_if_header_not_matches` for HSTS and X-Frame-Options — catches security header regressions introduced by deploys.
5. NetworkPolicy restricting `/probe` access to Prometheus only — removes the SSRF vector before someone exploits it.

None of these require application changes. They operate entirely at the probe layer, making them retrofittable onto existing services without coordination with application teams.
