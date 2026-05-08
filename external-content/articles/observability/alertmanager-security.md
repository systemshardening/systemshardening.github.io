---
title: "Prometheus Alertmanager Security: Receiver Credentials, Silencing Controls, and Inhibition Rules"
description: "Alertmanager routes security alerts to PagerDuty, Slack, and email. Exposed receiver credentials, unauthenticated silence APIs, and overly broad inhibition rules can suppress legitimate security alerts — exactly what an attacker wants. Hardening Alertmanager protects the alerting pipeline itself."
slug: "alertmanager-security"
date: 2026-05-01
lastmod: 2026-05-01
category: "observability"
tags: ["alertmanager", "prometheus", "alerting", "security", "silence", "receiver"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 299
difficulty: "intermediate"
estimated_reading_time: 12
published: true
layout: article.njk
permalink: "/articles/observability/alertmanager-security/index.html"
---

# Prometheus Alertmanager Security: Receiver Credentials, Silencing Controls, and Inhibition Rules

## Problem

Alertmanager is the routing and notification layer for Prometheus alerts. It receives firing alerts, matches them to routing rules, and delivers notifications via receivers — Slack webhooks, PagerDuty integration keys, email SMTP credentials, and OpsGenie API keys. These credentials are stored in the Alertmanager configuration file and are accessible to anyone who can read it.

The security implications of a compromised Alertmanager go beyond credential theft: an attacker who can modify Alertmanager configuration can silence all security alerts indefinitely. This is not hypothetical — attacker tooling explicitly targets monitoring and alerting infrastructure to create a blind spot for subsequent activity.

Common weaknesses:

- **Receiver credentials in plaintext configuration.** Alertmanager's `alertmanager.yml` contains Slack webhook URLs, PagerDuty routing keys, SMTP passwords, and OpsGenie API keys in plaintext. Any process or user with read access to the file or the Kubernetes Secret containing it has all notification credentials.
- **Unauthenticated silence API.** Alertmanager's HTTP API (`/api/v2/silences`) accepts POST requests to create silences without authentication in default deployments. An attacker who can reach the Alertmanager endpoint can silence all alerts indefinitely with a single API call.
- **Overly broad inhibition rules.** Inhibition rules suppress child alerts when a parent alert fires. A poorly designed inhibition rule that fires on a broad condition can suppress security alerts when infrastructure is under load — precisely the correlation an attacker exploiting a high-load condition would want.
- **No alerting on alerting system health.** Nobody monitors the monitor. If Alertmanager fails, stops processing, or its receivers are unreachable, security alerts are silently dropped. Without health monitoring for the alerting pipeline itself, failures go undetected.
- **Shared Alertmanager across environments.** Development and production alerts route through the same Alertmanager instance. A noisy development environment generates alert storms that desensitise on-call engineers to production alerts.

**Target systems:** Alertmanager 0.27+ (kube-prometheus-stack, standalone); Kubernetes Secret-based credential management; Alertmanager HA with gossip protocol; webhook receivers.

## Threat Model

- **Adversary 1 — Receiver credential exfiltration:** An attacker reads the Alertmanager configuration (from a ConfigMap, Secret, or configuration file) and extracts PagerDuty routing keys, Slack webhook URLs, and email credentials. They use these to send fake alerts or to understand the on-call rotation.
- **Adversary 2 — Silence API abuse:** An attacker who reaches the Alertmanager HTTP API creates a silence matching `alertname=~".+"` (all alerts) for 30 days. All security alerts are silently suppressed while the attacker operates.
- **Adversary 3 — Inhibition rule exploitation:** An attacker triggers a high-load condition (resource exhaustion, synthetic DDoS) that fires an inhibition parent alert. The inhibition rule suppresses security-relevant child alerts — intrusion detection, unusual login, lateral movement — while the attacker operates.
- **Adversary 4 — Webhook receiver SSRF:** An Alertmanager webhook receiver is configured to POST alert data to an internal URL. An attacker who can modify the receiver URL (via configuration access) points it to an internal service endpoint, using Alertmanager as an SSRF proxy.
- **Adversary 5 — HA gossip poisoning:** In a multi-instance Alertmanager HA deployment, instances share silence and notification state via a gossip protocol. An attacker who can reach the gossip port injects a silence entry that propagates to all instances.
- **Access level:** Adversaries 1 needs read access to configuration. Adversary 2 needs network access to the Alertmanager HTTP API. Adversaries 3 and 5 require network or API access. Adversary 4 needs configuration write access.
- **Objective:** Silence security alerts; steal notification credentials; blind the security operations team.
- **Blast radius:** Successful Alertmanager silence of security alerts means the entire Prometheus-based alerting pipeline is dark. Attacks can proceed undetected for the silence duration.

## Configuration

### Step 1: Secrets Management for Receiver Credentials

Never store receiver credentials in the Alertmanager config file:

```yaml
# BAD: plaintext credentials in alertmanager.yml.
receivers:
  - name: pagerduty-production
    pagerduty_configs:
      - routing_key: "abc123def456..."  # Plaintext secret.

  - name: slack-security
    slack_configs:
      - api_url: "https://hooks.slack.com/services/T.../B.../..."  # Plaintext webhook.
```

```yaml
# GOOD: reference environment variables (Alertmanager 0.24+).
receivers:
  - name: pagerduty-production
    pagerduty_configs:
      - routing_key: "$PAGERDUTY_ROUTING_KEY"   # Loaded from env variable at startup.

  - name: slack-security
    slack_configs:
      - api_url: "$SLACK_WEBHOOK_URL"
```

```yaml
# Kubernetes deployment: inject secrets as environment variables.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: alertmanager
  namespace: monitoring
spec:
  template:
    spec:
      containers:
        - name: alertmanager
          env:
            - name: PAGERDUTY_ROUTING_KEY
              valueFrom:
                secretKeyRef:
                  name: alertmanager-credentials
                  key: pagerduty-routing-key
            - name: SLACK_WEBHOOK_URL
              valueFrom:
                secretKeyRef:
                  name: alertmanager-credentials
                  key: slack-webhook-url
          # Mount config without credentials (uses env variable references).
          volumeMounts:
            - name: config
              mountPath: /etc/alertmanager
```

```bash
# Store credentials in Vault; sync to Kubernetes Secret via External Secrets Operator.
vault kv put secret/alertmanager/receivers \
  pagerduty-routing-key="$PAGERDUTY_KEY" \
  slack-webhook-url="$SLACK_WEBHOOK"
```

### Step 2: Authenticate the Alertmanager API

Alertmanager has no built-in authentication. Enforce it at the ingress layer:

```yaml
# Kubernetes Ingress with basic auth or OAuth2 Proxy.
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: alertmanager
  namespace: monitoring
  annotations:
    nginx.ingress.kubernetes.io/auth-type: basic
    nginx.ingress.kubernetes.io/auth-secret: alertmanager-basic-auth
    nginx.ingress.kubernetes.io/auth-realm: "Alertmanager"
    # Or: use OAuth2 Proxy for SSO.
    # nginx.ingress.kubernetes.io/auth-url: "https://oauth2.internal/oauth2/auth"
    nginx.ingress.kubernetes.io/whitelist-source-range: "10.0.0.0/8"
spec:
  rules:
    - host: alertmanager.internal.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: alertmanager
                port:
                  number: 9093
```

```bash
# Create basic auth credentials for Alertmanager UI/API access.
htpasswd -c /tmp/htpasswd alertmanager-admin
kubectl create secret generic alertmanager-basic-auth \
  --from-file=auth=/tmp/htpasswd \
  --namespace monitoring
```

Restrict network access to Alertmanager:

```yaml
# NetworkPolicy: Alertmanager only reachable from Prometheus and ingress.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: alertmanager-access
  namespace: monitoring
spec:
  podSelector:
    matchLabels:
      app: alertmanager
  policyTypes:
    - Ingress
  ingress:
    # Prometheus pushes alerts.
    - from:
        - podSelector:
            matchLabels:
              app: prometheus
      ports:
        - port: 9093
    # Ingress controller for authenticated UI/API access.
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress-nginx
      ports:
        - port: 9093
    # HA gossip between Alertmanager instances.
    - from:
        - podSelector:
            matchLabels:
              app: alertmanager
      ports:
        - port: 9094
          protocol: UDP
        - port: 9094
          protocol: TCP
    # NO: direct pod access to Alertmanager.
```

### Step 3: Silence Governance

Implement controls around silence creation:

```yaml
# alertmanager.yml — restrict silence duration.
# Alertmanager does not natively limit silence duration, but you can:
# 1. Use the API with custom tooling that enforces limits.
# 2. Alert on long-duration silences.

# Prometheus rule: alert on long-duration silences.
groups:
  - name: alertmanager-governance
    rules:
      - alert: AlertmanagerSilenceTooLong
        expr: |
          (alertmanager_silences{state="active"} > 0)
          and on()
          # Check if any silence extends more than 4 hours.
          # (alertmanager_silence_expires_at - time()) > 14400
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "Alertmanager silence exceeds 4-hour limit"
          description: "A silence has been created for more than 4 hours. Review required."

      - alert: AlertmanagerAllAlertsSilenced
        expr: |
          count(alertmanager_silences{state="active"}) > 0
          and absent(ALERTS{alertstate="firing"})
          and count(up{job="prometheus"}) > 0
        for: 5m
        labels:
          severity: critical
          team: security
        annotations:
          summary: "ALL alerts appear silenced — possible attacker silence"
          description: "No alerts are firing despite Prometheus being healthy. Verify Alertmanager silences."
```

```python
# silence_auditor.py — audit all active silences.
import requests
from datetime import datetime, timezone

def audit_silences(alertmanager_url: str, auth: tuple) -> list:
    """Returns silences that warrant review."""
    resp = requests.get(
        f"{alertmanager_url}/api/v2/silences",
        auth=auth,
        verify=True,
    )
    silences = resp.json()
    
    suspicious = []
    for silence in silences:
        if silence["status"]["state"] != "active":
            continue
        
        ends_at = datetime.fromisoformat(silence["endsAt"].replace("Z", "+00:00"))
        duration_hours = (ends_at - datetime.now(timezone.utc)).total_seconds() / 3600
        
        # Flag: silence longer than 4 hours.
        if duration_hours > 4:
            suspicious.append({
                "id": silence["id"],
                "created_by": silence["createdBy"],
                "comment": silence["comment"],
                "hours_remaining": duration_hours,
                "matchers": silence["matchers"],
            })
        
        # Flag: silence matching all alerts.
        if any(m["name"] == "alertname" and m["isRegex"] and m["value"] == ".+"
               for m in silence["matchers"]):
            suspicious.append({"reason": "matches all alerts", **silence})
    
    return suspicious
```

### Step 4: Inhibition Rule Hardening

Review inhibition rules to prevent them from suppressing security alerts:

```yaml
# alertmanager.yml — safe inhibition configuration.

inhibit_rules:
  # GOOD: Inhibit disk-full warning when disk-full critical fires.
  # Both must match the same instance. Security alerts are NOT inhibited.
  - source_match:
      alertname: DiskFull
      severity: critical
    target_match:
      alertname: DiskFull
      severity: warning
    equal: [instance]

  # GOOD: Inhibit dependent service alerts when the root cause fires.
  - source_match:
      alertname: DatabaseDown
    target_match:
      alertname: ApplicationHighErrorRate
    equal: [environment]

  # BAD — do NOT use:
  # This inhibits ALL alerts when any node is down — including security alerts.
  # - source_match:
  #     alertname: NodeDown
  #   target_match_re:
  #     severity: ".*"    # Suppresses everything.

  # NEVER inhibit security-labelled alerts.
  # Add team=security label to all security alerts.
  # Ensure no inhibition rule targets team=security.
```

Add explicit security alert labels to prevent inhibition:

```yaml
# Prometheus alerting rules — label security alerts explicitly.
groups:
  - name: security
    rules:
      - alert: UnauthorisedAPIAccess
        expr: sum(rate(http_requests_total{status=~"401|403"}[5m])) > 10
        labels:
          severity: high
          team: security
          inhibit_protected: "true"   # Custom label to prevent inhibition.
        annotations:
          summary: "Elevated authentication failures"
```

### Step 5: Receiver Endpoint Validation

Prevent SSRF via webhook receivers:

```yaml
# alertmanager.yml — restrict webhook URLs to approved destinations.
# Alertmanager does not natively validate URLs, but you can enforce via:
# 1. Policy-as-code review of alertmanager.yml changes.
# 2. Egress NetworkPolicy on the Alertmanager pod.

receivers:
  - name: slack-security
    slack_configs:
      - api_url: "$SLACK_WEBHOOK_URL"   # Must be hooks.slack.com.
        # Never allow: internal URLs, 10.x.x.x, 172.x.x.x, 192.168.x.x.
```

```yaml
# NetworkPolicy: Alertmanager egress restricted to approved notification endpoints.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: alertmanager-egress
  namespace: monitoring
spec:
  podSelector:
    matchLabels:
      app: alertmanager
  policyTypes:
    - Egress
  egress:
    # PagerDuty API.
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 10.0.0.0/8
              - 172.16.0.0/12
              - 192.168.0.0/16
      ports:
        - port: 443
    # DNS.
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - port: 53
          protocol: UDP
```

### Step 6: Alert on Alertmanager Health

```yaml
# Prometheus rules: monitor the monitoring system itself.
groups:
  - name: alertmanager-health
    rules:
      - alert: AlertmanagerDown
        expr: absent(up{job="alertmanager"} == 1)
        for: 2m
        labels:
          severity: critical
          team: platform
        annotations:
          summary: "Alertmanager is down — alerts not being delivered"

      - alert: AlertmanagerReceiverFailure
        expr: rate(alertmanager_notifications_failed_total[5m]) > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Alertmanager receiver failing — alerts being dropped"
          description: "Receiver {{ $labels.receiver }} is failing. Check credentials."

      - alert: AlertmanagerNoActiveAlerts
        expr: |
          count(ALERTS{alertstate="firing", team="security"}) == 0
          and
          count(up{job="prometheus"}) > 0
          and
          count(alertmanager_silences{state="active"}) > 0
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "No security alerts firing with active silences — verify"
```

### Step 7: HA Deployment Security

```yaml
# Alertmanager HA: restrict gossip port.
# Deploy 3 instances; mesh via gossip on port 9094.
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: alertmanager
  namespace: monitoring
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: alertmanager
          args:
            - --config.file=/etc/alertmanager/alertmanager.yml
            - --storage.path=/alertmanager
            - --cluster.peer=alertmanager-0.alertmanager:9094
            - --cluster.peer=alertmanager-1.alertmanager:9094
            - --cluster.peer=alertmanager-2.alertmanager:9094
            - --cluster.listen-address=0.0.0.0:9094
            # TLS for gossip (Alertmanager 0.25+).
            - --cluster.tls-config.cert=/etc/alertmanager/tls/tls.crt
            - --cluster.tls-config.key=/etc/alertmanager/tls/tls.key
            - --cluster.tls-config.client-ca=/etc/alertmanager/tls/ca.crt
```

### Step 8: Telemetry

```
alertmanager_alerts_received_total{receiver, status}           counter
alertmanager_notifications_total{receiver, integration}        counter
alertmanager_notifications_failed_total{receiver, integration} counter
alertmanager_silences{state}                                   gauge
alertmanager_inhibitions_muted_alerts_total{}                  counter
alertmanager_receivers{name}                                   gauge
alertmanager_config_hash{}                                     gauge
```

Alert on:

- `alertmanager_notifications_failed_total` non-zero — receiver failing; alerts being dropped; investigate credentials.
- `alertmanager_silences{state="active"}` > expected — unexpected silences active; possible attacker intervention.
- `alertmanager_config_hash` changes unexpectedly — configuration was modified outside of change management.
- No `alertmanager_alerts_received_total` increment despite known firing alert — Prometheus → Alertmanager pipeline broken.
- `alertmanager_inhibitions_muted_alerts_total` spike — many alerts being inhibited; review inhibition rules for overly broad match.

## Expected Behaviour

| Signal | Default Alertmanager | Hardened Alertmanager |
|--------|---------------------|----------------------|
| Receiver credential exposure | Plaintext in config file | Environment variable injection from Kubernetes Secret |
| Unauthenticated silence API | Any pod can silence all alerts | API authentication required; NetworkPolicy blocks direct pod access |
| Broad inhibition silences security alerts | Security alerts suppressed during infra incident | Security alerts labelled; excluded from inhibition rules |
| Alertmanager receiver failure | Alerts silently dropped | `AlertmanagerReceiverFailure` fires to backup channel |
| Webhook SSRF via receiver URL | Internal URL reachable | NetworkPolicy blocks internal destinations from Alertmanager egress |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Env variable credentials | No plaintext in config | Requires Secret injection in deployment | External Secrets Operator automates credential sync from Vault |
| Ingress-level authentication | Protects silence API | Ingress dependency for Alertmanager access | Internal Ingress within cluster; separate from external ingress |
| Egress NetworkPolicy | Prevents SSRF and exfiltration | Notification endpoints must be allowlisted by IP | Use DNS-based egress policy (Cilium FQDN policies) for dynamic IPs |
| 3-replica HA | Reliability | More resource consumption | Required for production; use anti-affinity to spread across nodes |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Credential rotation breaks receiver | Notifications fail silently | `alertmanager_notifications_failed_total` | Update Kubernetes Secret; Alertmanager hot-reloads config |
| Authentication misconfiguration | Prometheus cannot reach Alertmanager API | Prometheus shows "alertmanager not available" | Verify NetworkPolicy and ingress auth bypass for Prometheus |
| Gossip TLS cert expired | HA instances cannot sync; duplicate alerts | Gossip port errors in logs | cert-manager auto-renewal; manual renewal as fallback |
| Config error after hot-reload | Alertmanager reverts to previous config | Config hash doesn't update; config load error log | Validate config with `amtool check-config` before applying |

## Related Articles

- [Prometheus Security Metrics](/articles/observability/prometheus-security-metrics/)
- [Grafana Security Hardening](/articles/observability/grafana-security-hardening/)
- [Loki Security Hardening](/articles/observability/loki-security-hardening/)
- [Security SLOs](/articles/observability/security-slos/)
- [Alert Correlation](/articles/observability/alert-correlation/)
