---
title: "Alertmanager Receiver Security: SSRF, API Hardening, and Alert Pipeline Integrity"
description: "Alertmanager webhook receivers can be weaponised for SSRF if an attacker modifies the configuration. Harden the admin API with authentication, restrict receiver URLs to an allowlist, and protect the alert pipeline from pre-attack blind spot creation."
slug: alertmanager-receiver-security
date: 2026-05-07
lastmod: 2026-05-07
category: observability
tags:
  - alertmanager
  - prometheus
  - ssrf
  - api-security
  - observability
personas:
  - security-engineer
  - platform-engineer
article_number: 451
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/observability/alertmanager-receiver-security/
---

# Alertmanager Receiver Security: SSRF, API Hardening, and Alert Pipeline Integrity

## The Problem

Alertmanager is the routing and notification component of the Prometheus ecosystem — it receives firing alerts from Prometheus servers and routes them to configured receivers: PagerDuty, Slack, email, OpsGenie, and generic webhooks. Webhook receivers work by making outbound HTTP POST requests to a configured URL whenever a matching alert fires. That mechanism is the attack surface.

Consider what an attacker with write access to the Alertmanager configuration can do. They add a new webhook receiver with `url: http://169.254.169.254/latest/meta-data/iam/security-credentials/` — the AWS Instance Metadata Service endpoint. The next time any alert fires, Alertmanager makes a POST to that URL. The response body contains temporary IAM credentials: access key ID, secret access key, session token. The attacker has turned Alertmanager's normal notification mechanism into an SSRF pivot to the cloud credentials service, without ever touching the application workloads. The same technique works against Kubernetes service endpoints (`http://kubernetes.default.svc.cluster.local`), internal APIs, and external exfiltration endpoints — any URL reachable from the Alertmanager pod.

The second problem is the admin API. Alertmanager exposes an HTTP API on port 9093 that, in the default deployment, requires no authentication. The API surface includes:

- `POST /-/reload` — reload the configuration file
- `DELETE /-/quit` — shut down the process
- `POST /api/v2/silences` — create a silence that suppresses matching alerts
- `DELETE /api/v2/silences/{id}` — delete a silence
- `POST /api/v2/alerts` — inject synthetic alert entries

An attacker who can reach port 9093 from any pod in the cluster — or from outside if the port is exposed — can silence all security alerts with a single API call. They do not need any prior access to application systems; network reachability to the monitoring namespace is sufficient.

In 2026, threat actors treat observability infrastructure as a first-phase target rather than an incidental compromise. The pre-attack blind spot pattern is now a documented tactic: identify and silence alerting and intrusion detection systems before launching the primary attack. The sequence is deliberate: (1) reach the Alertmanager API; (2) enumerate active alert routes to identify security-relevant receiver names (the names are often descriptive — `security-oncall`, `siem-webhook`); (3) create a silence with matcher `alertname=~".+"` covering all alerts for 24–72 hours; (4) wait for on-call rotation awareness to fade; (5) execute the primary operation. The Alertmanager silence log records who created the silence and when — but only if someone reviews it, which requires an active monitoring capability that has just been disabled.

The configuration attack surface is broader than the admin API alone. In Kubernetes environments, Alertmanager configuration typically lives in a ConfigMap that is mounted into the pod or managed by the Prometheus Operator's `AlertmanagerConfig` CRD. A GitOps pipeline that automatically applies changes to this ConfigMap creates a path where a compromised developer credential or a pull request without required security review can introduce a malicious webhook receiver. The receiver takes effect at the next `/-/reload` — either triggered explicitly or at pod restart.

## Threat Model

**Attacker modifies Alertmanager configuration to add a malicious webhook receiver.** The modification path may be direct API access (if `/-/reload` and the config file are writable), a Kubernetes ConfigMap write (`kubectl edit configmap alertmanager-config`), modification of a GitOps repository without adequate review gates, or via the Prometheus Operator `AlertmanagerConfig` CRD if RBAC allows it. Once the receiver is in place, every subsequent alert firing triggers an outbound HTTP POST to the attacker-controlled or SSRF-targeted URL. Alert payloads include label sets, annotations, and generator URLs — these contain hostnames, IP addresses, service names, and sometimes application error messages. A malicious receiver collecting alert payloads builds an internal asset map from normal alerting traffic.

**Unauthenticated network access to port 9093 used for pre-attack silence.** An attacker who can reach the Alertmanager endpoint creates a silence with a broad matcher. All security alerts — intrusion detection, unusual authentication, lateral movement indicators — are suppressed for the silence duration. The platform team sees no firing alerts and interprets it as a healthy system. The attacker executes the primary campaign during this window.

**Configuration reload API used to push a modified configuration.** An attacker with temporary access to the Alertmanager pod filesystem or the config volume modifies `alertmanager.yml` and triggers `POST /-/reload` to activate the changes, replacing legitimate security receivers with receivers pointing to a null endpoint (silently dropping alerts) or a malicious collection endpoint.

**Information exfiltration via alert payloads.** Alertmanager webhook `POST` bodies include the full alert payload: labels (including `instance`, `job`, `namespace`, `pod`), annotations (often containing description text with internal IP addresses or stack traces), and the `generatorURL` pointing to the Prometheus query that fired the alert — which reveals internal Prometheus hostnames and PromQL expressions. A receiver collecting these payloads passively extracts internal infrastructure topology.

**Supply chain via GitOps pipeline compromise.** An Alertmanager configuration file managed in a Git repository is a single commit away from introducing a new receiver. If the pipeline auto-applies without a required security team review, a compromised developer account or a social engineering attack on a pull request reviewer delivers the malicious receiver at the next reconciliation cycle without touching the Kubernetes cluster directly.

**Blast radius.** Successful silence of the entire alert pipeline removes the organisation's primary automated detection capability. Attacks that would normally generate alerts — brute force, privilege escalation, data exfiltration volume spikes, lateral movement between services — proceed without notification to on-call engineers. Recovery requires detecting the silence through an out-of-band channel: log review, anomaly in ticket volume, or manual Alertmanager UI inspection — all of which depend on someone noticing the absence of expected alerts.

## Hardening Configuration

### 1. Enable Alertmanager Web Authentication

Alertmanager 0.26+ supports native HTTP basic authentication via a `web.yml` configuration file, similar to the mechanism used by the Prometheus Node Exporter. This authenticates all requests to the Alertmanager HTTP API, including the admin endpoints, the silence API, and the UI.

Generate a bcrypt-hashed password:

```bash
htpasswd -nBC 12 alertmanager-admin
```

Create the `web.yml` configuration:

```yaml
tls_server_config: {}

basic_auth_users:
  alertmanager-admin: "$2y$12$hashed_password_output_here"
```

Pass the configuration file to Alertmanager at startup:

```bash
alertmanager \
  --config.file=/etc/alertmanager/alertmanager.yml \
  --web.config.file=/etc/alertmanager/web.yml \
  --storage.path=/alertmanager
```

In a Kubernetes deployment using the Prometheus Operator, set this via the `Alertmanager` custom resource:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata:
  name: main
  namespace: monitoring
spec:
  replicas: 3
  webConfig:
    basicAuthUsers:
      - name: alertmanager-web-auth
        key: auth
  configSecret: alertmanager-generated
```

For stronger authentication, place Alertmanager behind an Nginx reverse proxy enforcing mTLS or OAuth2. The proxy terminates authentication before requests reach the Alertmanager process, which means even if the Alertmanager `web.yml` is misconfigured, the proxy layer still requires a valid client certificate or token:

```nginx
server {
    listen 9093 ssl;
    ssl_certificate     /etc/nginx/certs/server.crt;
    ssl_certificate_key /etc/nginx/certs/server.key;
    ssl_client_certificate /etc/nginx/certs/ca.crt;
    ssl_verify_client on;

    location / {
        proxy_pass http://alertmanager-backend:9093;
        proxy_set_header Authorization "";
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location ~ ^/(/-/reload|/-/quit) {
        allow 10.0.0.0/8;
        deny all;
        proxy_pass http://alertmanager-backend:9093;
    }
}
```

Update the Prometheus `alerting` configuration to include credentials after enabling authentication, or Prometheus will fail to push alerts:

```yaml
alerting:
  alertmanagers:
    - static_configs:
        - targets:
            - alertmanager:9093
      basic_auth:
        username: alertmanager-admin
        password_file: /etc/prometheus/alertmanager-password
```

### 2. Restrict Receiver Webhook URLs to an Allowlist

Alertmanager does not validate webhook URLs against an allowlist before making requests. Enforce this at the point of configuration change using a Kyverno `ClusterPolicy` that validates the `receivers[].webhook_configs[].url` field whenever the Alertmanager `ConfigMap` is created or updated.

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: alertmanager-webhook-allowlist
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: restrict-webhook-receiver-urls
      match:
        any:
          - resources:
              kinds:
                - ConfigMap
              namespaces:
                - monitoring
              names:
                - alertmanager-config
      validate:
        message: >
          Alertmanager webhook receiver URLs must match an approved domain.
          Internal IP ranges and unapproved domains are prohibited.
        foreach:
          - list: "request.object.data.\"alertmanager.yml\" | parse_yaml(@) | receivers[]"
            foreach:
              - list: "element.webhook_configs || `[]`"
                deny:
                  conditions:
                    any:
                      - key: "{{ element.url }}"
                        operator: Matches
                        value: "^https?://(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|169\\.254\\.)"
                      - key: "{{ element.url }}"
                        operator: NotMatches
                        value: "^https://(hooks\\.slack\\.com|events\\.pagerduty\\.com|app\\.opsgenie\\.com)/"
```

Apply equivalent validation to `AlertmanagerConfig` CRD resources using a separate rule targeting that resource kind, since the Prometheus Operator may manage configuration via the CRD rather than a ConfigMap directly.

### 3. Network Egress Restriction for Alertmanager Pods

A Kubernetes `NetworkPolicy` that blocks egress to RFC 1918 addresses and link-local addresses from the Alertmanager pod prevents SSRF requests from reaching their target, regardless of what the configuration contains. This is a defence-in-depth layer that acts even if the Kyverno admission check is bypassed (for example, via a configuration file mounted from a local volume rather than a ConfigMap).

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: alertmanager-egress-restriction
  namespace: monitoring
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: alertmanager
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 10.0.0.0/8
              - 172.16.0.0/12
              - 192.168.0.0/16
              - 169.254.0.0/16
              - 100.64.0.0/10
      ports:
        - port: 443
          protocol: TCP
        - port: 80
          protocol: TCP
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
        - podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
    - to:
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: alertmanager
      ports:
        - port: 9094
          protocol: TCP
        - port: 9094
          protocol: UDP
```

This policy allows DNS resolution, egress to external HTTPS endpoints (PagerDuty, Slack, OpsGenie), and Alertmanager gossip traffic between HA replicas, while blocking all access to internal cluster IP ranges and the AWS IMDS link-local address `169.254.169.254`. Note that notification providers with dynamic IP ranges — Slack CDN, for example — require a DNS-based egress proxy (Cilium FQDN egress policy, or a Squid proxy with domain-based allowlist) to remain maintainable as those IP ranges change.

### 4. Protect Alertmanager Configuration via GitOps with Review Gates

A GitOps pipeline that auto-applies Alertmanager configuration changes without review is a single-step injection path for malicious receivers. Implement branch protection rules requiring at minimum one review from a member of the security or platform team for any pull request that modifies files under the path containing `alertmanager.yml` or `AlertmanagerConfig` resources.

Use a CODEOWNERS file to require automatic review requests:

```bash
/kubernetes/monitoring/alertmanager.yml         @security-team @platform-team
/kubernetes/monitoring/alertmanager-config/     @security-team @platform-team
```

Add a CI pipeline step that validates the Alertmanager configuration for suspicious receiver URLs before merge. `amtool` can validate configuration syntax; a custom check validates the receiver URL allowlist:

```bash
amtool check-config /kubernetes/monitoring/alertmanager.yml

python3 - <<'PYEOF'
import yaml, sys, re

ALLOWED_WEBHOOK_PATTERN = re.compile(
    r'^https://(hooks\.slack\.com|events\.pagerduty\.com|app\.opsgenie\.com)/'
)
BLOCKED_PATTERN = re.compile(
    r'^https?://(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.)'
)

with open(sys.argv[1]) as f:
    config = yaml.safe_load(f)

violations = []
for receiver in config.get('receivers', []):
    for wh in receiver.get('webhook_configs', []):
        url = wh.get('url', '')
        if BLOCKED_PATTERN.match(url):
            violations.append(f"BLOCKED internal URL in {receiver['name']}: {url}")
        elif not ALLOWED_WEBHOOK_PATTERN.match(url):
            violations.append(f"UNAPPROVED webhook URL in {receiver['name']}: {url}")

if violations:
    for v in violations:
        print(f"ERROR: {v}", file=sys.stderr)
    sys.exit(1)

print("Webhook URL validation passed.")
PYEOF
```

### 5. Monitor for Unexpected Silence Operations

Log all Alertmanager API calls via an access log or a sidecar that tails the Alertmanager stdout. Use Prometheus to track silence count changes and alert when the pattern indicates possible attacker activity — large-scope silences, silences created outside business hours, or a sudden drop to zero active alerts while Prometheus remains healthy.

```yaml
groups:
  - name: alertmanager-silence-governance
    interval: 1m
    rules:
      - alert: AlertmanagerSilenceCountIncrease
        expr: |
          increase(alertmanager_silences{state="active"}[5m]) > 0
        for: 0m
        labels:
          severity: warning
          team: security
        annotations:
          summary: "New Alertmanager silence created — review required"
          description: >
            The number of active Alertmanager silences increased. Verify that
            the silence was created through an approved change process.

      - alert: AlertmanagerBroadSilenceActive
        expr: |
          alertmanager_silences{state="active"} >= 1
          and on()
          absent(ALERTS{alertstate="firing",severity="critical"})
          and on()
          count(up{job=~"prometheus.*"} == 1) > 0
        for: 5m
        labels:
          severity: critical
          team: security
        annotations:
          summary: "No critical alerts firing despite active Prometheus — possible broad silence"
          description: >
            Active silences exist and no critical alerts are firing, but Prometheus
            is healthy. A broad silence matcher may be suppressing all alerts.

      - alert: AlertmanagerConfigHashChanged
        expr: |
          changes(alertmanager_config_hash[10m]) > 0
        for: 0m
        labels:
          severity: info
          team: platform
        annotations:
          summary: "Alertmanager configuration reloaded"
          description: "The Alertmanager configuration changed. Verify the change is authorised."
```

The `alertmanager_config_hash` metric changes whenever the configuration is successfully reloaded — either via `/-/reload` or at pod startup. An unexpected change to this metric outside of a scheduled deployment window indicates unauthorised configuration modification. Route this alert to a separate out-of-band channel (email, PagerDuty) that is not subject to Alertmanager silences.

## Expected Behaviour After Hardening

After enabling `web.yml` authentication: a request to `http://alertmanager:9093/-/reload` without credentials returns HTTP `401 Unauthorized`. Prometheus continues to deliver alerts because the `alerting.alertmanagers` configuration includes credentials. The Alertmanager UI prompts for login.

After applying the egress `NetworkPolicy`: an Alertmanager pod attempting to connect to `169.254.169.254:80` has the connection dropped at the network layer. The webhook fires, Alertmanager logs a connection timeout for the receiver, and the `alertmanager_notifications_failed_total` counter increments — which triggers the existing receiver failure alert. The SSRF attempt produces a visible signal rather than silently returning cloud credentials.

After enforcing the Kyverno `ClusterPolicy`: a `kubectl apply` or GitOps reconciliation that attempts to update the Alertmanager ConfigMap with a webhook URL pointing to `http://10.96.0.1/api/v1/secrets` is rejected at admission with the policy violation message. The ConfigMap is not updated. The rejection event is recorded in the Kubernetes audit log and visible in Kyverno policy reports.

## Trade-offs and Operational Considerations

**Authentication breaks existing unauthenticated integrations.** Enabling Alertmanager `web.yml` basic authentication immediately breaks any Prometheus instance that pushes alerts without credentials and any tooling (dashboards, scripts) that calls the Alertmanager API without authentication. Audit all consumers of the Alertmanager API before enabling authentication — typically Prometheus, `amtool`, Grafana datasource for Alertmanager, and any custom silence management scripts. Update each to include credentials. Deploy the credential as a Kubernetes Secret and reference it via `password_file` rather than embedding it in the Prometheus configuration.

**NetworkPolicy egress maintenance overhead.** PagerDuty, Slack, and OpsGenie publish API endpoints via hostnames backed by CDN infrastructure with IP ranges that can change without notice. A strict `ipBlock` allowlist based on current IP addresses will break notifications when providers rotate IP ranges. The sustainable approach is a DNS-based egress proxy: deploy a Squid or Envoy instance with an FQDN allowlist (`events.pagerduty.com`, `hooks.slack.com`, `app.opsgenie.com`), route Alertmanager egress through it, and apply the `NetworkPolicy` to allow egress only to the proxy pod. Cilium users can use `CiliumNetworkPolicy` with `toFQDNs` rules directly.

**GitOps review gate adds latency to alerting configuration updates.** During an incident, an engineer may need to add a temporary silence or update a receiver URL immediately. Requiring a pull request review adds minutes to hours of latency. Document and test an emergency bypass process: a designated break-glass account with direct `kubectl` access to the monitoring namespace that can apply changes without the GitOps pipeline, with the requirement that every bypass is logged and reviewed post-incident within 24 hours. The emergency bypass should itself generate an audit event.

## Failure Modes

**Alertmanager metrics disappear after authentication is enabled.** The Prometheus `ServiceMonitor` or scrape configuration for the `alertmanager` job does not include the basic auth credentials for the `/metrics` endpoint. Prometheus begins returning scrape errors for Alertmanager targets. The `alertmanager_*` metrics disappear from dashboards. The health alerts based on `alertmanager_notifications_failed_total` stop working because the time series has gone stale. Mitigation: update the `ServiceMonitor` to reference the same credentials secret, or add a separate unauthenticated `/metrics` path at the proxy layer while keeping the API endpoints protected.

**Kyverno policy validates ConfigMap but a sidecar bypasses it.** The Alertmanager deployment uses a sidecar container that fetches configuration from an external source (Vault, a configuration service, an S3 bucket) and writes it directly to the shared volume at `/etc/alertmanager/alertmanager.yml`, then triggers `/-/reload`. The Kyverno admission policy validates the ConfigMap at admission time, but the ConfigMap is not actually the source of the running configuration — the sidecar's fetch is not subject to Kubernetes admission control. Mitigation: audit all pods in the monitoring namespace for sidecar containers that write to config volumes; prohibit this pattern via a Kyverno policy on Pod specs.

**Silence monitoring alert evades detection via edit rather than create.** The `AlertmanagerSilenceCountIncrease` alert triggers on a net increase in the `alertmanager_silences{state="active"}` count. An attacker who creates a narrow silence (matching a single non-security alert to avoid detection), then edits it to extend the matcher to cover all alerts, does not increase the count — only the scope changes. The count remains stable. Mitigation: supplement count-based monitoring with API access log analysis; any silence with a `regex` matcher on `alertname` matching `.*` or `.+` should generate an alert regardless of whether the count changed.

## Related Articles

- [Alertmanager Security](/articles/observability/alertmanager-security/)
- [Prometheus Security Metrics](/articles/observability/prometheus-security-metrics/)
- [Prometheus Remote Write Security](/articles/observability/prometheus-remote-write-security/)
- [OTel Collector Remote Config Security](/articles/observability/otel-collector-remote-config-security/)
- [Grafana Security Hardening](/articles/observability/grafana-security-hardening/)
