---
title: "OTel Collector Remote Configuration Security: Hardening the OpAMP Trust Boundary"
description: "OpAMP lets a central server push arbitrary pipeline configs to OTel Collectors. An attacker with OpAMP server access can redirect all telemetry to their endpoint or disable security alert pipelines. Harden the OpAMP trust boundary with mTLS, config signing, and change alerting."
slug: otel-collector-remote-config-security
date: 2026-05-04
lastmod: 2026-05-04
category: observability
tags:
  - opentelemetry
  - otel-collector
  - opamp
  - configuration-security
  - observability
personas:
  - security-engineer
  - platform-engineer
article_number: 443
difficulty: Advanced
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/observability/otel-collector-remote-config-security/
---

# OTel Collector Remote Configuration Security: Hardening the OpAMP Trust Boundary

## The Problem

Whoever controls the OpAMP server controls every pipeline configuration across your entire OTel Collector fleet. OpAMP (Open Agent Management Protocol) is an IETF-standardised protocol, adopted and extended by the OpenTelemetry project, that allows a central management server to push new pipeline configurations to running Collector instances without a restart. As of OTel Collector 0.99+ (generally available in early 2026), OpAMP-based fleet management has moved from experimental to production-ready. Adoption has accelerated: platforms such as Odigos, Chronosphere's management plane, and custom internal implementations are now commonly used to manage fleets of dozens to hundreds of Collectors. The protocol's security model has not kept pace with its deployment rate.

The OpAMP supervisor is a sidecar process (or built-in component) that runs alongside each Collector instance, maintains a persistent WebSocket connection to the OpAMP management server, and applies configuration updates as they arrive. A pipeline configuration tells the Collector which receivers to run (what data to accept and from where), which processors to apply (what transformations, filtering, and enrichment to perform), and which exporters to use (where to send the resulting telemetry). Controlling the pipeline configuration is equivalent to controlling the data plane of your entire observability infrastructure.

The attacker model is direct. An adversary who gains access to the OpAMP management server — through a compromised admin credential, a vulnerability in the server's API, or an insider action — can push a new configuration to every connected Collector within seconds. Specifically, they can:

- **Redirect all telemetry.** Push a new exporter definition pointing to `https://attacker.example.com/ingest`. Every trace, metric, and log from the entire fleet is now delivered to an attacker-controlled endpoint alongside (or instead of) the legitimate backend. The data stream includes request payloads, service topology, authentication event records, and any other attributes the application attaches to spans or log lines.
- **Suppress security-relevant telemetry before it reaches the SIEM.** Add a `filter` processor that drops all spans tagged with `security.tool: true`, all log lines matching `audit|auth|login|privilege`, or all metrics from a specific namespace. The SIEM continues to receive data — it simply no longer receives the subset that would trigger alerts.
- **Remove receivers for alert-generating log sources.** Delete the `filelog` receiver reading `/var/log/audit/audit.log`. The Collector stops ingesting audit events entirely. The SIEM sees no new audit data and (if monitoring data freshness) may or may not raise a staleness alert — a much weaker signal than an active alert on a specific suspicious event.
- **Crash the Collector to create a blind spot.** Push an invalid configuration that causes the Collector to exit. In a Kubernetes deployment, the pod restarts; during the gap, all telemetry is lost. Time this to coincide with lateral movement or privilege escalation and the attack proceeds without observability.

The management plane attack is particularly dangerous for observability infrastructure because the tools you rely on to detect an ongoing attack are themselves the target. A compromised SIEM query is suspicious; a compromised Collector pipeline is invisible until someone audits the pipeline configuration itself — an operation most teams perform infrequently if at all.

The protocol weakness is not a single CVE. OpAMP is a well-designed protocol: it supports TLS, it includes configuration checksums, and the specification documents the intended security properties. The gap is in how deployments configure and operate OpAMP, not in the protocol itself. Default configurations frequently omit mTLS, do not validate configuration against an allowlist before applying it, and do not alert on configuration changes. The supervisor applies what the server sends.

## Threat Model

**Compromised OpAMP management server.** An attacker gains access to the OpAMP server (Odigos control plane, a custom management API, or a self-hosted OpAMP server implementation) through credential theft, API vulnerability exploitation, or supply chain compromise of the server software. They push a malicious pipeline configuration to all connected Collectors. Because the connection is persistent and configurations are applied without human approval, propagation to the entire fleet is measured in seconds, not minutes.

**DNS poisoning or MITM routing collectors to a rogue server.** Without certificate pinning or mutual TLS, a Collector that cannot reach its configured OpAMP server endpoint may be susceptible to DNS-based redirection to an attacker-controlled server that presents a valid (Let's Encrypt) certificate for the spoofed hostname. The Collector's TLS handshake succeeds; it has no way to verify it is talking to the legitimate server rather than an attacker's replica. The rogue server pushes a malicious configuration.

**Insider threat: privileged platform engineer.** A platform engineer with write access to the OpAMP management server modifies Collector configurations to add a secondary exporter. Because OpAMP config pushes are a normal operational action, the change may not be reviewed. Telemetry exfiltration begins immediately and continues until the engineer's access is revoked or the pipeline config is audited.

**Blind spot attack: disable alert pipelines before the main attack.** The most operationally sophisticated threat. An attacker who knows which alert pipelines are running (discoverable by reading existing Collector configs via the OpAMP server, or by observing SIEM alert patterns) pushes a config change that silences specific alert pipelines — removes the `filelog` receiver for audit logs, or adds a filter dropping all alerting-relevant spans. They then execute their primary attack (lateral movement, data exfiltration, privilege escalation) during the window where the observability infrastructure is effectively blind. The silence may go undetected if the SIEM does not monitor for the absence of expected alert categories.

**Supply chain: compromised Collector container image.** A modified Collector image ships with an OpAMP supervisor pre-configured to connect to an attacker-controlled server in addition to the legitimate one. Both connections are maintained simultaneously. The attacker's server receives a copy of all accepted configurations and can push its own configs in parallel with the legitimate server. Image digest pinning in the deployment manifest is the primary defence; this threat model highlights the importance of container image verification in the OpAMP deployment chain.

## Hardening Configuration

### 1. Mutual TLS for OpAMP Connections

The OpAMP supervisor in the OTel Collector supports TLS configuration for its WebSocket connection to the management server. Enabling only server-side TLS (standard HTTPS) authenticates the server to the Collector but does not authenticate the Collector to the server — and critically does not prevent a rogue server presenting a certificate from a public CA from intercepting the connection. Mutual TLS adds a client certificate to the handshake: the OpAMP server verifies the Collector's identity, and the Collector verifies the server against a private CA that only the legitimate server's certificate is signed by. A rogue server cannot obtain a certificate signed by your private CA.

Create a private CA, issue server and client certificates from it, and configure the supervisor:

```yaml
extensions:
  opamp:
    server:
      ws:
        endpoint: wss://opamp.internal.example.com/v1/opamp
        tls:
          ca_file: /etc/otel/pki/ca.crt
          cert_file: /etc/otel/pki/collector-client.crt
          key_file: /etc/otel/pki/collector-client.key
          insecure_skip_verify: false
    agent_description:
      identifying_attributes:
        service.name: otel-collector
        host.name: ${env:K8S_NODE_NAME}
```

Mount the PKI files as a Kubernetes Secret projected volume, not as environment variables. Automate certificate rotation using cert-manager with a `Certificate` resource targeting the private CA `ClusterIssuer`:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: opamp-collector-client
  namespace: observability
spec:
  secretName: opamp-collector-client-tls
  duration: 720h
  renewBefore: 168h
  privateKey:
    algorithm: ECDSA
    size: 256
  usages:
    - client auth
  issuerRef:
    name: internal-ca
    kind: ClusterIssuer
```

The `renewBefore: 168h` (7 days) setting ensures cert-manager rotates certificates well before expiry without manual intervention. The Collector's supervisor reloads the certificate on rotation if the file path remains constant and the volume is a projected secret — verify this behaviour for your supervisor version.

### 2. Config Change Alerting

A configuration push from the OpAMP server is a privileged operation. It must generate an out-of-band alert that cannot be suppressed by a subsequent malicious config push. The key constraint: the alert pipeline must not be routed through the same OpAMP-managed Collector that is receiving the configuration change.

The OTel Collector supervisor logs configuration change events to its standard output. In a Kubernetes DaemonSet deployment, these logs are written to the node's container log path. A separate, OpAMP-independent Collector instance (see item 4 below) running a `filelog` receiver can ingest these logs and route config-change events to the SIEM.

On the managed Collector, configure the supervisor's log level to ensure config-change events are emitted:

```yaml
service:
  telemetry:
    logs:
      level: info
      encoding: json
```

With JSON-encoded logs, config-change events from the OpAMP supervisor appear with a structured field such as `"msg": "Config received from server"` or `"msg": "Applying remote config"` (exact message depends on supervisor version — validate against your deployed version). On the independent security-alert Collector, configure a `filelog` receiver targeting the managed Collector's log path and route matching lines to an alert pipeline:

```yaml
receivers:
  filelog/opamp-audit:
    include:
      - /var/log/containers/otel-collector-*.log
    operators:
      - type: json_parser
        parse_from: body
      - type: filter
        expr: 'body["msg"] matches "(?i)(remote config|config received|applying.*config)"'

exporters:
  otlphttp/siem:
    endpoint: https://siem.internal.example.com/otlp
    tls:
      ca_file: /etc/otel/pki/ca.crt

service:
  pipelines:
    logs/opamp-change-alerts:
      receivers: [filelog/opamp-audit]
      exporters: [otlphttp/siem]
```

This pipeline is not managed by OpAMP. Its configuration lives in a Kubernetes `ConfigMap` that is only writable by cluster administrators via the Kubernetes API (enforced by RBAC), not through the OpAMP server. A malicious OpAMP config push to the managed fleet cannot disable this pipeline.

### 3. Config Allowlist and Schema Validation

Before a pushed configuration is applied, validate it against an allowlist of permitted exporter endpoints. The OTel Collector's supervisor does not natively support pre-apply validation hooks as of 0.99, but the pattern can be implemented using the `confmap` providers or a wrapper script that intercepts the supervisor's configuration write path.

A practical approach for Kubernetes deployments: run an admission webhook (or a separate validation step in the OpAMP server itself) that rejects configurations containing exporter endpoints not present in an approved list. If your OpAMP server is a custom implementation or Odigos, the validation belongs at the server before the config is pushed to the fleet. If you are running a self-hosted OpAMP server, implement a middleware layer:

```yaml
allowed_exporter_endpoints:
  - https://tempo.internal.example.com
  - https://prometheus.internal.example.com/api/v1/write
  - https://loki.internal.example.com/loki/api/v1/push
  - https://siem.internal.example.com/otlp
```

Any pushed configuration containing an exporter `endpoint` value not present in this list is rejected before it reaches the Collector. The rejection itself is logged and triggers an alert — an attempted push of a non-allowlisted exporter is a high-confidence indicator of a compromise or insider threat.

Maintain the allowlist in version control with a change approval process (pull request review). New legitimate exporter destinations require an approved PR before they are added. This makes the allowlist itself an auditable record of where telemetry is permitted to flow.

### 4. Separate Security-Alert Pipelines from OpAMP-Managed Fleet

The single most effective architectural control: run a dedicated OTel Collector instance for security-critical alert pipelines that has no OpAMP supervisor. This instance is not reachable by the OpAMP management server and cannot receive configuration pushes from it.

Deploy this collector as a separate `Deployment` (not a `DaemonSet`) with a distinct container image digest pinned in the manifest:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: otel-collector-security
  namespace: observability
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: collector
          image: otel/opentelemetry-collector-contrib@sha256:<pinned-digest>
          args:
            - --config=/etc/otel/config.yaml
          volumeMounts:
            - name: config
              mountPath: /etc/otel
              readOnly: true
      volumes:
        - name: config
          configMap:
            name: otel-collector-security-config
```

The `ConfigMap` `otel-collector-security-config` is protected by Kubernetes RBAC: only the `cluster-admin` group can write to it. No OpAMP-related extensions are present in the Collector's configuration. The security-critical pipelines — audit log ingestion, authentication event processing, alert forwarding to the SIEM — run exclusively in this instance. An attacker who fully compromises the OpAMP management server and pushes malicious configs to the entire managed fleet cannot affect this instance.

### 5. Audit OpAMP Server Access

Treat the OpAMP management server as a privileged control plane component equivalent to a Kubernetes API server or a secrets management system. Apply the same controls:

- **RBAC on config push operations.** Separate read access (viewing current configs) from write access (pushing new configs). Only a small number of named service accounts used by CI/CD systems should have write access. Human operators should require approval workflows for direct config pushes outside automated deployment pipelines.
- **Immutable audit log of config pushes.** Every config push to the OpAMP server must be logged with: the identity of the pusher (service account or human), the timestamp, the diff of the configuration change (previous vs. new), and the list of Collectors the change was applied to. Store these logs in a backend that is not itself managed by the OpAMP server.
- **Alert on config pushes outside change windows.** If your organisation uses change windows, alert immediately on any config push that occurs outside them. A config push at 02:00 on a Saturday that was not pre-approved is a high-priority incident to investigate.
- **Rotate OpAMP server credentials on any suspected compromise.** Because a compromised OpAMP server has immediate fleet-wide impact, the response to any suspected server compromise must include immediate credential rotation and a review of all config changes applied in the preceding 24 hours.

## Expected Behaviour After Hardening

After mTLS is configured with a private CA, a rogue OpAMP server presenting a certificate from a public CA fails the TLS handshake immediately. The Collector logs a TLS verification error, the connection is refused, and the Collector continues running its last-known-good configuration. No malicious config is applied. The TLS error is itself a signal: an unexpected connection refusal to the OpAMP server endpoint warrants investigation.

After config change alerting is in place via the independent security Collector, a malicious config push generates a log event on the managed Collector within milliseconds. The independent Collector ingests that log, matches it against the filter expression, and forwards the alert to the SIEM. End-to-end latency from config push to SIEM alert is typically under 60 seconds — well within a window where a security team can intervene before the exfiltration pipeline begins delivering meaningful data volume to the attacker's endpoint.

After the separate security-alert Collector is deployed, an attacker who compromises the OpAMP management server and pushes a config that removes audit log receivers from the managed fleet finds that the SIEM continues to receive audit events. The managed fleet's audit ingestion is silent, but the independent security Collector's audit pipeline (which was never connected to OpAMP) is unaffected. The SIEM may even detect the anomaly: two Collectors were previously contributing audit events; now only one is.

## Trade-offs and Operational Considerations

The separate security-alert Collector adds a deployment to manage. Its configuration is updated via GitOps pull requests to the `ConfigMap`, not via the OpAMP server's push interface — which means it does not benefit from the operational convenience that motivated adopting OpAMP in the first place. When the alert pipeline configuration genuinely needs to change (new log source, updated SIEM endpoint), the change requires a Kubernetes rollout rather than an OpAMP push. This is the intended trade-off: the security-critical pipeline is deliberately harder to change.

The config allowlist requires active maintenance. Every legitimate new exporter destination — a new Grafana Cloud account, a new regional SIEM endpoint, a DR-site replica — must be added to the allowlist via an approved PR before the corresponding OpAMP config push will succeed. In organisations with frequent infrastructure changes, the allowlist can become a source of friction if the approval process is not streamlined. The friction is also the point.

mTLS certificate rotation for a large Collector fleet is operationally non-trivial. A fleet of 200 Collector instances each holding a client certificate with a 30-day expiry requires cert-manager (or an equivalent) to be functioning correctly at all times. A cert-manager misconfiguration that causes certificate renewal to fail silently will result in mass Collector disconnections from the OpAMP server when certificates expire simultaneously. Monitor cert-manager's certificate renewal events as a first-class operational signal, separate from the Collectors themselves.

## Failure Modes

**mTLS configured with a CA certificate stored on the OpAMP server.** If the private CA's certificate and key material are co-located with the OpAMP server, an attacker who compromises the server can issue new client certificates for a rogue Collector or a new server certificate for a rogue OpAMP endpoint. The mTLS control is defeated. The CA must be stored and operated independently of the OpAMP server — in an offline CA, a hardware security module, or a secrets manager that requires separate authentication.

**Config change alert pipeline routed through the OpAMP-managed fleet.** If the config-change alert pipeline runs on a Collector instance that is itself managed by OpAMP, an attacker can push a config to that instance that disables or modifies the alert pipeline before pushing a malicious config to the rest of the fleet. The alert mechanism is silenced before the attack it is meant to detect. The independence of the security-alert Collector from the OpAMP management plane is not optional — it is the control that makes the alerting meaningful.

**Allowlist blocks the malicious exporter domain, but the attacker uses an allowlisted internal endpoint they have already compromised.** If an attacker has compromised an internal service that is on the allowlist (for example, an internal metrics aggregation service that is a legitimate exporter destination), they can push a config that adds a duplicate exporter pointing to that service. The allowlist does not block it. This is a limitation of endpoint-based allowlisting: it assumes that all allowlisted endpoints remain trustworthy. Defence in depth at the network layer (egress NetworkPolicy restricting Collector outbound connections to known endpoints) provides a complementary control that the allowlist alone does not.

## Related Articles

- [OTel Collector Hardening](/articles/observability/otel-collector-hardening/)
- [OTel Collector Pipelines](/articles/observability/otel-collector-pipelines/)
- [OTel SDK Security](/articles/observability/otel-sdk-security/)
- [Audit Log Pipeline](/articles/observability/audit-log-pipeline/)
- [Detection Rules](/articles/observability/detection-rules/)
