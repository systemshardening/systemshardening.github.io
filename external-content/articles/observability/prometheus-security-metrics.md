---
title: "Security-Relevant Prometheus Metrics: What to Collect, How to Alert, When to Page"
description: "Prometheus is deployed in most Kubernetes environments for infrastructure monitoring (CPU, memory, disk, request latency."
slug: "prometheus-security-metrics"
date: 2026-03-05
lastmod: 2026-03-05
category: "observability"
tags: ["prometheus", "alerting", "security-metrics", "grafana", "sli", "monitoring"]
personas: ["sre", "security-engineer"]
article_number: 64
difficulty: "intermediate"
estimated_reading_time: 18
provider_bridges:
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
  - name: "Chronosphere"
    id: 116
    category: "observability"
premium_pack: "security-alert-rules"
published: true
layout: article.njk
permalink: "/articles/observability/prometheus-security-metrics/index.html"
---

# Security-Relevant [Prometheus](https://prometheus.io) Metrics: What to Collect, How to Alert, When to Page

## Problem

Prometheus is deployed in most [Kubernetes](https://kubernetes.io) environments for infrastructure monitoring (CPU, memory, disk, request latency. But security teams rarely use it for detection. Authentication failures, RBAC denials, certificate expiry, network policy drops, and syscall violations all produce Prometheus metrics. Nobody writes alert rules for them. The gap between "infrastructure observability" and "security monitoring" is not a tooling gap) it is an alert rules gap.

## Threat Model

- **Adversary:** Any attacker. Security metrics detect brute force (auth failure spikes), privilege escalation (RBAC deny spikes), lateral movement (network policy drops), resource exhaustion (OOM kills from crypto miners), and misconfiguration (certificate expiry).
- **Without security metrics:** Attacks are detected by their EFFECTS (outage, data breach, cost spike), often days or weeks later. With security metrics: attacks are detected by their CAUSES (auth failure spike, unusual RBAC denials), within minutes.

## Configuration

### Authentication Failure Monitoring

```yaml
# PrometheusRule for authentication failures
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: security-auth-alerts
  namespace: monitoring
spec:
  groups:
    - name: authentication
      interval: 30s
      rules:
        # Recording rule: auth failure rate per source
        - record: security:auth_failures:rate5m
          expr: sum by (source_ip, service) (rate(auth_failures_total{result="failure"}[5m]))

        # Alert: brute force detection
        - alert: BruteForceDetected
          expr: security:auth_failures:rate5m > 0.5  # >30 failures per minute
          for: 2m
          labels:
            severity: warning
          annotations:
            summary: "Possible brute force against {{ $labels.service }} from {{ $labels.source_ip }}"
            runbook_url: "https://systemshardening.com/runbooks/brute-force"
            description: "{{ $value | humanize }} auth failures/sec from {{ $labels.source_ip }}"

        # Alert: credential stuffing (many IPs, same pattern)
        - alert: CredentialStuffing
          expr: count by (service) (security:auth_failures:rate5m > 0.1) > 10
          for: 5m
          labels:
            severity: critical
          annotations:
            summary: "Possible credential stuffing against {{ $labels.service }}, {{ $value }} source IPs"
```

### Kubernetes RBAC Denial Monitoring

```yaml
        # RBAC denials from the API server
        - alert: RBACDenialSpike
          expr: >
            rate(apiserver_authorization_decisions_total{decision="forbid"}[5m])
            > 3 * avg_over_time(rate(apiserver_authorization_decisions_total{decision="forbid"}[5m])[7d:5m])
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "RBAC denial rate is 3x above 7-day average"
            runbook_url: "https://systemshardening.com/runbooks/rbac-denial"
            description: |
              Current rate: {{ $value | humanize }}/sec.
              Investigate: is a service account misconfigured, or is someone probing for permissions?

        # Specific: cluster-admin usage
        - alert: ClusterAdminUsage
          expr: >
            increase(apiserver_request_total{
              verb=~"create|update|patch|delete",
              userAgent!~".*kube-controller-manager.*|.*kube-scheduler.*"
            }[5m]) > 0
            and on() (apiserver_authorization_decisions_total{decision="allow"} > 0)
          labels:
            severity: info
          annotations:
            summary: "Mutation API call detected, review for unauthorized changes"
```

### Certificate Expiry Monitoring

```yaml
    - name: certificates
      interval: 1m
      rules:
        # cert-manager certificate expiry
        - alert: CertificateExpiringSoon
          expr: certmanager_certificate_expiration_timestamp_seconds - time() < 7 * 24 * 3600
          labels:
            severity: warning
          annotations:
            summary: "Certificate {{ $labels.name }} in {{ $labels.namespace }} expires in {{ $value | humanizeDuration }}"

        - alert: CertificateExpiryCritical
          expr: certmanager_certificate_expiration_timestamp_seconds - time() < 24 * 3600
          labels:
            severity: critical
          annotations:
            summary: "Certificate {{ $labels.name }} expires in {{ $value | humanizeDuration }}. IMMEDIATE ACTION REQUIRED"

        # cert-manager renewal failures
        - alert: CertificateRenewalFailed
          expr: certmanager_certificate_ready_status{condition="False"} == 1
          for: 1h
          labels:
            severity: critical
          annotations:
            summary: "Certificate {{ $labels.name }} renewal has failed for over 1 hour"
```

### Network Policy Drop Monitoring

```yaml
    - name: network-security
      interval: 30s
      rules:
        # Cilium network policy drops
        - alert: NetworkPolicyDrop
          expr: rate(cilium_drop_count_total{reason="POLICY_DENIED"}[5m]) > 0
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "Network policy dropping traffic in {{ $labels.namespace }}"
            description: "{{ $value | humanize }} packets/sec dropped. Check if a new service needs a policy update or if this is suspicious traffic."

        # New destination detection (lateral movement indicator)
        - alert: NewNetworkDestination
          expr: >
            count by (source_workload) (
              rate(hubble_flows_processed_total{verdict="FORWARDED"}[1h]) > 0
            )
            unless
            count by (source_workload) (
              rate(hubble_flows_processed_total{verdict="FORWARDED"}[7d]) > 0
            )
          labels:
            severity: info
          annotations:
            summary: "{{ $labels.source_workload }} connected to a destination not seen in the past 7 days"
```

### Resource Exhaustion (Security-Relevant)

```yaml
    - name: resource-security
      interval: 30s
      rules:
        # OOM kills - could indicate crypto mining or resource exhaustion attack
        - alert: OOMKillDetected
          expr: increase(kube_pod_container_status_last_terminated_reason{reason="OOMKilled"}[5m]) > 0
          labels:
            severity: warning
          annotations:
            summary: "Container {{ $labels.container }} in {{ $labels.namespace }}/{{ $labels.pod }} was OOMKilled"

        # Unexpected high CPU - crypto mining indicator
        - alert: UnexpectedHighCPU
          expr: >
            (rate(container_cpu_usage_seconds_total[5m])
            / on(namespace, pod) kube_pod_container_resource_limits{resource="cpu"})
            > 0.95
          for: 15m
          labels:
            severity: warning
          annotations:
            summary: "Container {{ $labels.container }} at >95% CPU limit for 15 minutes"
            description: "Sustained high CPU could indicate crypto mining. Investigate the process."
```

### Complete PrometheusRule Deployment

```bash
# Save all rules to a single file and apply:
kubectl apply -f security-prometheus-rules.yaml

# Verify rules are loaded:
kubectl get prometheusrules -n monitoring
# Expected: security-auth-alerts listed

# Check rules in Prometheus UI:
# Navigate to http://prometheus:9090/rules
# Look for the 'authentication', 'certificates', 'network-security', 'resource-security' groups
```

### Alert Routing

```yaml
# Alertmanager configuration for security alerts
# Route security alerts to the security team channel, not the general on-call.

route:
  receiver: default
  routes:
    - match:
        severity: critical
      receiver: security-pager
      continue: true
    - match_re:
        alertname: "BruteForce.*|CredentialStuffing|RBACDenial.*|CertificateExpiry.*"
      receiver: security-slack
      group_wait: 30s
      group_interval: 5m

receivers:
  - name: security-slack
    slack_configs:
      - channel: '#security-alerts'
        send_resolved: true
        title: '{{ .GroupLabels.alertname }}'
        text: '{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'

  - name: security-pager
    pagerduty_configs:
      - service_key: "${PAGERDUTY_KEY}"
```

## Expected Behaviour

- Security alerts fire within 1-2 minutes of threshold breach
- Brute force detection triggers on >30 auth failures per minute from a single source
- Certificate expiry alerts at 30, 7, and 1 day before expiry
- Network policy drops generate informational alerts (not pages, too noisy for paging)
- RBAC denial spikes alert when rate exceeds 3x the 7-day average
- All alerts include runbook URLs and actionable context (which service, which source, what to investigate)
- False positive rate below 2 per day after 2-week tuning period

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Auth failure alerting | Detects brute force within minutes | Legitimate login failures (wrong password) generate noise | Set threshold high enough to exclude individual failures (>30/min, not >1/min). |
| RBAC denial alerting | Catches permission escalation attempts | CI/CD pipelines with wrong permissions trigger false positives | Exclude known CI service accounts from the alert. |
| Network policy drop alerting | Detects lateral movement attempts | New deployments generate drops until policies are updated | Use `info` severity (not `warning` or `critical`). Suppress during deployment windows. |
| 30-second scrape interval | Near-real-time detection | Slightly higher Prometheus resource usage | Default 30s is fine. Only reduce to 15s if detection latency is critical. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Prometheus scrape target down | Missing metrics for a service; security gap | `up == 0` alert fires for the missing target | Fix ServiceMonitor/PodMonitor. Check network policy allows Prometheus to scrape the target. |
| Alert threshold too sensitive | 10+ false positive pages per day | On-call fatigue; team starts ignoring security alerts | Increase thresholds. Add deployment-window suppression. Move high-noise alerts to `info` severity (Slack, not pager). |
| Metric cardinality explosion | Prometheus OOM or slow queries | Prometheus memory spike; query latency increase | Drop high-cardinality labels (per-IP auth metrics → aggregate to per-service). Use recording rules for pre-aggregation. |
| Alertmanager routing misconfigured | Security alerts go to the wrong channel or nobody | Test alerts not received; real incidents missed | Test alert routing monthly (send a test alert, verify delivery). Include alerting in security drill. |

## When to Consider a Managed Alternative

Self-managed Prometheus storage exceeds 500GB within 6 months for a 20-node cluster. HA Prometheus (Thanos/Cortex) adds significant operational complexity. Cross-cluster metric aggregation requires federation or remote write infrastructure.

- **[Grafana Cloud](https://grafana.com/cloud):** Prometheus-compatible remote write, managed storage, unified alerting across metrics and logs. Start free (10K metrics). The most natural migration path from self-hosted Prometheus.
- **[Chronosphere](https://chronosphere.io):** Handles high-cardinality metrics (per-IP, per-user) without cost explosion. Built on M3. For teams where cardinality is the primary scaling challenge.
- **[VictoriaMetrics](https://victoriametrics.com):** Self-hosted but lower resource usage than Prometheus. Extends the free stage before needing managed.

**Premium content pack:** Complete PrometheusRule YAML for all security metrics (auth, RBAC, certs, network, resource), Alertmanager routing configuration, and [Grafana](https://grafana.com) dashboard JSON for security monitoring. See [Security Dashboards That Engineers Actually Use: Grafana Designs for Hardening Verification](/articles/observability/security-dashboards/)(/articles/observability/security-dashboards/) for the dashboard design guide.


## Related Articles

- [Building Detection Rules That Don't Cry Wolf: Alert Design for Security Events](/articles/observability/detection-rules/)
- [Certificate Expiry Monitoring: Automated Detection Across TLS, mTLS, and Signing Certificates](/articles/observability/certificate-expiry-monitoring/)
- [Security Dashboards That Engineers Actually Use: Grafana Designs for Hardening Verification](/articles/observability/security-dashboards/)
- [Incident Response Runbooks: Structured Procedures for Common Security Events](/articles/observability/incident-response-runbooks/)
- [Crypto Mining Detection: CPU Patterns, Network Signatures, and Automated Response](/articles/observability/crypto-mining-detection/)
