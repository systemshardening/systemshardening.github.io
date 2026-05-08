---
title: "Certificate Expiry Monitoring: Automated Detection Across TLS, mTLS, and Signing Certificates"
description: "Certificate expiry is the most common cause of preventable production outages. When a TLS certificate expires, HTTPS connections fail, mTLS..."
slug: "certificate-expiry-monitoring"
date: 2026-01-19
lastmod: 2026-01-19
category: "observability"
tags: ["certificates", "tls", "monitoring", "prometheus", "cert-manager", "expiry"]
personas: ["sre", "platform-engineer"]
article_number: 70
difficulty: "intermediate"
estimated_reading_time: 15
provider_bridges:
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
  - name: "Cloudflare"
    id: 29
    category: "cdn-waf"
  - name: "DNSimple"
    id: 77
    category: "dns"
premium_pack: "certificate-monitoring-dashboard"
published: true
layout: article.njk
permalink: "/articles/observability/certificate-expiry-monitoring/index.html"
---

# Certificate Expiry Monitoring: Automated Detection Across TLS, mTLS, and Signing Certificates

## Problem

Certificate expiry is the most common cause of preventable production outages. When a TLS certificate expires, HTTPS connections fail, mTLS handshakes are rejected, and webhook calls between services return cryptic errors. The outage is immediate, total, and embarrassing because it was entirely predictable.

The specific challenges:

- **[cert-manager](https://cert-manager.io) handles [Kubernetes](https://kubernetes.io), nothing else.** cert-manager automates certificate renewal for Kubernetes Ingress and internal services. But your infrastructure also has load balancer certificates, database TLS certs, SMTP certs, code signing certs, CA intermediates, and SSH host certificates. cert-manager does not see any of these.
- **Certificate inventory is unknown.** Most teams cannot answer the question "how many certificates do we have and when do they expire?" Certificates are provisioned by different teams through different tools (cert-manager, [Terraform](https://www.terraform.io), AWS ACM, manual openssl commands) with no central registry.
- **Renewal failures are silent.** cert-manager attempts renewal 30 days before expiry. If renewal fails (DNS challenge fails, rate limit hit, CA unreachable), the only signal is a cert-manager event log that nobody is watching. The certificate expires anyway.
- **External endpoints are blind spots.** Your TLS cert is fine, but the third-party API you depend on has an expiring cert. When their cert expires, your service fails because HTTPS verification rejects the connection.

This article builds monitoring for all certificate types: cert-manager managed certs, external endpoint certs, host-level certs, and internal CA certificates.

**Target systems:** Kubernetes with cert-manager. [Prometheus](https://prometheus.io) + Alertmanager. Blackbox exporter for external endpoint monitoring. Any Linux host with TLS certificates.

## Threat Model

- **Adversary:** Certificate expiry is not an adversary-driven threat. It is an operational failure with security consequences. An expired certificate disables TLS, mTLS, or code signing verification. If the team "fixes" the outage by disabling certificate verification (`--insecure`, `verify=False`), they create a real security vulnerability that may persist long after the certificate is renewed.
- **Blast radius:** A single expired certificate can cascade to every service that depends on it. An expired Kubernetes webhook CA certificate can prevent all pod scheduling. An expired mTLS root CA can break every service-to-service call in the mesh.

## Configuration

### cert-manager Prometheus Metrics

cert-manager exposes metrics for certificate status. Enable the ServiceMonitor:

```yaml
# cert-manager Helm values: enable Prometheus metrics.
prometheus:
  enabled: true
  servicemonitor:
    enabled: true
    interval: 60s
    labels:
      release: kube-prometheus-stack
```

Alert on certificates approaching expiry:

```yaml
# Prometheus alerting rules for cert-manager certificates.
groups:
  - name: certificate-expiry
    rules:
      # Warning: certificate expires within 30 days.
      - alert: CertificateExpiringSoon
        expr: >
          (certmanager_certificate_expiration_timestamp_seconds - time())
          < 30 * 24 * 3600
          and
          (certmanager_certificate_expiration_timestamp_seconds - time()) > 0
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: >
            Certificate {{ $labels.name }} in {{ $labels.namespace }}
            expires in {{ $value | humanizeDuration }}
          runbook_url: "https://systemshardening.com/runbooks/certificate-expiry"

      # Critical: certificate expires within 7 days.
      - alert: CertificateExpiryCritical
        expr: >
          (certmanager_certificate_expiration_timestamp_seconds - time())
          < 7 * 24 * 3600
          and
          (certmanager_certificate_expiration_timestamp_seconds - time()) > 0
        for: 10m
        labels:
          severity: critical
        annotations:
          summary: >
            CRITICAL: Certificate {{ $labels.name }} in {{ $labels.namespace }}
            expires in {{ $value | humanizeDuration }}

      # cert-manager renewal failure: certificate not ready.
      - alert: CertificateRenewalFailed
        expr: >
          certmanager_certificate_ready_status{condition="True"} == 0
        for: 30m
        labels:
          severity: warning
        annotations:
          summary: >
            Certificate {{ $labels.name }} in {{ $labels.namespace }}
            is not in Ready state (renewal may have failed)
          description: |
            Check cert-manager logs:
            kubectl describe certificate {{ $labels.name }} -n {{ $labels.namespace }}
            kubectl logs -n cert-manager deploy/cert-manager --since=1h
```

### Blackbox Exporter for External Endpoints

Monitor TLS certificate expiry on any HTTPS endpoint, including third-party services:

```yaml
# blackbox-exporter configuration for TLS probing.
modules:
  tls_probe:
    prober: http
    timeout: 10s
    http:
      method: GET
      preferred_ip_protocol: ip4
      tls_config:
        insecure_skip_verify: false

---
# Prometheus scrape config: probe external endpoints.
scrape_configs:
  - job_name: "blackbox-tls"
    metrics_path: /probe
    params:
      module: [tls_probe]
    static_configs:
      - targets:
          # Your own externally-facing endpoints.
          - https://api.example.com
          - https://dashboard.example.com
          # Third-party services you depend on.
          - https://api.stripe.com
          - https://hooks.slack.com
          - https://registry.npmjs.org
        labels:
          probe_type: tls_expiry
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: blackbox-exporter:9115
```

```yaml
# Alert on external certificate expiry.
- alert: ExternalCertExpiringSoon
  expr: >
    (probe_ssl_earliest_cert_expiry - time()) < 30 * 24 * 3600
    and
    (probe_ssl_earliest_cert_expiry - time()) > 0
  for: 1h
  labels:
    severity: warning
  annotations:
    summary: >
      External cert for {{ $labels.instance }} expires in
      {{ $value | humanizeDuration }}
    description: |
      This is a certificate on a remote endpoint. If it is a third-party
      service, you cannot renew it, but you should prepare for potential
      connection failures and contact the provider.

- alert: TLSProbeFailure
  expr: probe_success{job="blackbox-tls"} == 0
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "TLS probe failed for {{ $labels.instance }}"
    description: |
      The endpoint is not responding or the certificate is already invalid.
      Check: is the service down, or has the certificate expired?
```

### Host-Level Certificate Discovery

For certificates outside Kubernetes (load balancers, databases, SMTP servers), scan the filesystem:

```bash
#!/bin/bash
# /usr/local/bin/cert-inventory.sh
# Scan common certificate locations and export expiry as Prometheus metrics.
# Run via cron every 6 hours. Output to node_exporter textfile collector.

METRIC_FILE="/var/lib/node_exporter/textfile_collector/cert_expiry.prom"
SEARCH_PATHS="/etc/ssl /etc/pki /etc/letsencrypt /opt/certs"

echo "# HELP host_certificate_expiry_seconds Certificate expiry timestamp" > "$METRIC_FILE"
echo "# TYPE host_certificate_expiry_seconds gauge" >> "$METRIC_FILE"

for dir in $SEARCH_PATHS; do
    [ -d "$dir" ] || continue
    find "$dir" -name "*.pem" -o -name "*.crt" -o -name "*.cert" | while read -r cert; do
        # Extract expiry date from the certificate.
        expiry=$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | cut -d= -f2)
        [ -z "$expiry" ] && continue

        # Convert to Unix timestamp.
        expiry_ts=$(date -d "$expiry" +%s 2>/dev/null)
        [ -z "$expiry_ts" ] && continue

        # Extract subject CN for labeling.
        cn=$(openssl x509 -in "$cert" -noout -subject 2>/dev/null | sed 's/.*CN *= *//')

        echo "host_certificate_expiry_seconds{path=\"$cert\",cn=\"$cn\"} $expiry_ts" >> "$METRIC_FILE"
    done
done
```

```yaml
# Alert on host-level certificate expiry.
- alert: HostCertExpiringSoon
  expr: >
    (host_certificate_expiry_seconds - time()) < 30 * 24 * 3600
    and
    (host_certificate_expiry_seconds - time()) > 0
  for: 1h
  labels:
    severity: warning
  annotations:
    summary: >
      Host cert {{ $labels.cn }} at {{ $labels.path }}
      expires in {{ $value | humanizeDuration }}
```

### Post-Renewal Verification

Renewal is not enough. Verify the new certificate is actually serving traffic:

```yaml
# Prometheus rule: detect when a certificate was recently renewed
# but the probe still shows the old expiry (new cert not deployed).
- alert: CertRenewedButNotDeployed
  expr: >
    certmanager_certificate_expiration_timestamp_seconds
    > (probe_ssl_earliest_cert_expiry + 86400)
  for: 2h
  labels:
    severity: warning
  annotations:
    summary: >
      Certificate {{ $labels.name }} was renewed in cert-manager but
      the endpoint is still serving the old certificate
    description: |
      cert-manager shows a newer expiry than what the blackbox probe sees.
      The new certificate may not have been picked up by the ingress
      controller or load balancer. Check:
      - kubectl describe certificate {{ $labels.name }}
      - kubectl rollout restart deployment/<ingress-controller>
```

### Dashboard Design

```promql
# Grafana dashboard panels for certificate monitoring.

# Panel 1: Days until expiry for all cert-manager certificates.
(certmanager_certificate_expiration_timestamp_seconds - time()) / 86400

# Panel 2: Days until expiry for external endpoints.
(probe_ssl_earliest_cert_expiry - time()) / 86400

# Panel 3: Days until expiry for host-level certificates.
(host_certificate_expiry_seconds - time()) / 86400

# Panel 4: Certificates in failed renewal state.
certmanager_certificate_ready_status{condition="True"} == 0

# Panel 5: Table view sorted by soonest expiry (all sources).
sort(
  (certmanager_certificate_expiration_timestamp_seconds - time()) / 86400
)
```

## Expected Behaviour

- All cert-manager certificates monitored with 30/7-day warning thresholds
- External endpoint certificates probed every 60 seconds with expiry tracking
- Host-level certificates discovered and monitored via filesystem scan every 6 hours
- Renewal failures detected within 30 minutes (cert-manager Ready status)
- Post-renewal verification confirms the new certificate is actually serving traffic
- Single Grafana dashboard shows days-until-expiry for every certificate across all sources
- Zero certificate expiry outages after implementation

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| 30-day warning threshold | Early notice for manual certificates | Alert fatigue if many certificates renew in the same window | Use label-based routing: auto-renewed certs (cert-manager) alert at 7 days; manual certs alert at 30 days. |
| Blackbox probe for external endpoints | Detects third-party cert expiry you cannot control | Probe failures may be network issues, not cert issues | Separate `probe_success` alert from cert expiry alert. Probe from multiple locations if possible. |
| Filesystem scan every 6 hours | Discovers certificates not managed by any automation | Misses certificates in non-standard locations | Add custom paths to SEARCH_PATHS. Use `locate *.pem` for broader discovery if available. |
| Post-renewal verification (2h delay) | Catches the gap between renewal and deployment | 2-hour delay means the old cert serves for 2 hours after renewal | Reduce to 30 minutes for production-critical certs. Trigger ingress reload on cert-manager renewal event. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| cert-manager metrics endpoint down | No cert-manager alerts fire; certificates expire silently | `absent(certmanager_certificate_expiration_timestamp_seconds)` | Restart cert-manager. Verify ServiceMonitor is scraping correctly. |
| Blackbox exporter down | External cert monitoring stops | `up{job="blackbox-tls"} == 0` | Restart blackbox exporter. Check network egress from monitoring namespace. |
| Let's Encrypt rate limit hit | Renewal fails; cert-manager retries until expiry | CertificateRenewalFailed alert fires | Wait for rate limit reset (1 hour for most limits). Use staging CA for testing. Consolidate certificates to reduce issuance count. |
| Ingress controller does not reload new cert | New cert exists in Secret but old cert is served | CertRenewedButNotDeployed alert fires | Restart ingress controller: `kubectl rollout restart deployment/ingress-nginx`. Check if the Secret name matches the Ingress TLS config. |
| Host scan misses certificate | Certificate in non-standard location expires without alert | Outage caused by expired cert not in monitoring | Post-incident: add the certificate path to SEARCH_PATHS. Audit all TLS configurations for certificate file paths. |

## When to Consider a Managed Alternative

Self-managed certificate monitoring requires cert-manager configuration, blackbox exporter deployment, host-level scanning, and dashboard maintenance (2-3 hours/month).

- **[Cloudflare](https://www.cloudflare.com):** Managed TLS for edge certificates eliminates the expiry problem entirely. Cloudflare handles issuance, renewal, and deployment for domains proxied through their network.
- **[Grafana Cloud](https://grafana.com/cloud):** Centralized Prometheus metrics for cert-manager and blackbox exporter. Pre-built certificate monitoring dashboards. Managed alerting without self-hosted Alertmanager.
- **[DNSimple](https://dnsimple.com):** Integrated Let's Encrypt certificate management with automated DNS validation and renewal for domains managed through DNSimple.

**Premium content pack:** Certificate monitoring Grafana dashboard. Pre-built dashboard with panels for cert-manager, external endpoints, and host-level certificates. Includes alerting rules, blackbox exporter configuration, and host scanning script.


## Related Articles

- [Security-Relevant Prometheus Metrics: What to Collect, How to Alert, When to Page](/articles/observability/prometheus-security-metrics/)
- [Building Detection Rules That Don't Cry Wolf: Alert Design for Security Events](/articles/observability/detection-rules/)
- [TLS 1.3 Configuration for NGINX and Envoy: Ciphers, Certificates, and OCSP Stapling](/articles/network/tls-nginx-envoy/)
- [Crypto Mining Detection: CPU Patterns, Network Signatures, and Automated Response](/articles/observability/crypto-mining-detection/)
- [Building a Security Audit Log Pipeline That Scales: auditd to Elasticsearch](/articles/observability/audit-log-pipeline/)
