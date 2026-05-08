---
title: "Lateral Movement Detection: Network Patterns, Authentication Anomalies, and Alert Correlation"
description: "East-west traffic inside a Kubernetes cluster is a blind spot for most security teams."
slug: "lateral-movement-detection"
date: 2026-03-13
lastmod: 2026-03-13
category: "observability"
tags: ["lateral-movement", "cilium", "hubble", "network-monitoring", "detection", "kubernetes"]
personas: ["security-engineer", "sre"]
article_number: 63
difficulty: "advanced"
estimated_reading_time: 18
provider_bridges:
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
  - name: "Isovalent"
    id: 54
    category: "networking"
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
premium_pack: "lateral-movement-detection-rules"
published: true
layout: article.njk
permalink: "/articles/observability/lateral-movement-detection/index.html"
---

# Lateral Movement Detection: Network Patterns, Authentication Anomalies, and Alert Correlation

## Problem

East-west traffic inside a [Kubernetes](https://kubernetes.io) cluster is a blind spot for most security teams. Once an attacker compromises a single pod, they pivot to other services using internal network paths that look identical to normal inter-service communication. Without baseline-aware monitoring of network flows and authentication events, lateral movement is invisible until the attacker reaches a high-value target like a database or secrets store.

The specific challenges:

- **Internal traffic is trusted by default.** Kubernetes flat networking means every pod can reach every other pod unless network policies restrict it. A compromised frontend pod can probe the entire cluster.
- **Service meshes add encryption but not visibility.** mTLS between sidecars encrypts east-west traffic, preventing network-level inspection. You need flow-level metadata (source, destination, port, protocol) rather than payload inspection.
- **Authentication logs are scattered.** Each service logs its own auth events. Correlating a failed login attempt on service A with a successful login on service B from the same source requires centralized log aggregation and join logic.
- **Static allowlists break at scale.** Manually maintaining a list of "allowed" communication paths between 200 microservices is impractical. You need automatic baseline generation from observed traffic.

This article covers baseline establishment with [Cilium](https://cilium.io) and [Hubble](https://docs.cilium.io/en/stable/observability/hubble/), anomaly detection rules for new or unexpected network flows, authentication correlation across services, and automated response for confirmed lateral movement.

**Target systems:** Kubernetes clusters running Cilium CNI with Hubble enabled. [Prometheus](https://prometheus.io) for metrics. [Falco](https://falco.org) or [Tetragon](https://tetragon.io) for runtime detection.

## Threat Model

- **Adversary:** An attacker who has compromised a single pod through an application vulnerability (SSRF, RCE, dependency exploit). Their goal is to move laterally to higher-value targets: databases, secrets management, CI/CD systems, or cluster control plane components.
- **Blast radius:** Without lateral movement detection, the attacker can map the entire internal network, enumerate services, and pivot freely. Average dwell time for undetected lateral movement is 21 days. With flow-level monitoring and baseline alerting, initial pivot attempts generate alerts within minutes.

## Configuration

### Hubble Flow Monitoring

Enable Hubble to capture structured flow logs for all east-west traffic:

```yaml
# cilium-config ConfigMap (or Helm values)
# Enable Hubble with L7 visibility for HTTP flows.
hubble:
  enabled: true
  metrics:
    enabled:
      - dns
      - drop
      - tcp
      - flow
      - icmp
      - http
    serviceMonitor:
      enabled: true
  relay:
    enabled: true
  ui:
    enabled: true
```

### Baseline Traffic Pattern Recording

Capture 30 days of normal traffic patterns as Prometheus recording rules:

```yaml
# Prometheus recording rules: build a baseline of normal communication pairs.
groups:
  - name: lateral-movement-baselines
    interval: 5m
    rules:
      # Count unique source-destination pairs observed over 7 days.
      - record: hubble:flow_pairs:count_7d
        expr: >
          count by (source_workload, destination_workload, destination_port) (
            rate(hubble_flows_processed_total{verdict="FORWARDED"}[7d]) > 0
          )

      # Average flow rate between known service pairs (bytes/sec).
      - record: hubble:flow_rate:avg_7d
        expr: >
          avg_over_time(
            rate(hubble_tcp_bytes_total[5m])[7d:5m]
          )

      # Auth failure rate per source workload across all destinations.
      - record: security:lateral_auth_failures:rate5m_7d
        expr: >
          avg_over_time(
            sum by (source_workload) (
              rate(auth_failures_total{result="failure"}[5m])
            )[7d:5m]
          )
```

### Anomaly Detection Rules

#### New Network Destination (Never Seen Before)

```yaml
# Alert: a workload is communicating with a destination not seen in the
# 30-day baseline. This is the highest-signal lateral movement indicator.
- alert: NewNetworkDestination
  expr: >
    (
      count by (source_workload, destination_workload, destination_port) (
        rate(hubble_flows_processed_total{verdict="FORWARDED"}[5m]) > 0
      )
    )
    unless
    (hubble:flow_pairs:count_7d > 0)
  for: 3m
  labels:
    severity: warning
    detection_type: lateral_movement
  annotations:
    summary: >
      New flow: {{ $labels.source_workload }} ->
      {{ $labels.destination_workload }}:{{ $labels.destination_port }}
    runbook_url: "https://systemshardening.com/runbooks/lateral-movement"
    false_positive_notes: |
      Common FP sources: new deployments, canary rollouts, feature flags
      enabling new service calls. Check if a deployment occurred in the
      last 30 minutes before escalating.
```

#### Port Scanning Detection

```yaml
# Alert: a single source contacts more than 10 unique destination ports
# within a 5-minute window. Normal services contact 1-3 ports.
- alert: PortScanDetected
  expr: >
    count by (source_workload) (
      count by (source_workload, destination_port) (
        rate(hubble_flows_processed_total{verdict="FORWARDED"}[5m]) > 0
      )
    ) > 10
  for: 2m
  labels:
    severity: critical
    detection_type: lateral_movement
  annotations:
    summary: "Port scan: {{ $labels.source_workload }} contacted {{ $value }} unique ports"
    runbook_url: "https://systemshardening.com/runbooks/port-scan"
```

#### Authentication Anomaly Correlation

```yaml
# Alert: a workload has auth failures against 3+ distinct services
# within 10 minutes. Normal services authenticate to 1-2 backends.
- alert: LateralAuthSweep
  expr: >
    count by (source_workload) (
      sum by (source_workload, destination_service) (
        rate(auth_failures_total{result="failure"}[10m])
      ) > 0
    ) > 3
  for: 5m
  labels:
    severity: critical
    detection_type: lateral_movement
  annotations:
    summary: >
      Auth sweep: {{ $labels.source_workload }} failed auth against
      {{ $value }} services in 10 minutes
    runbook_url: "https://systemshardening.com/runbooks/credential-sweep"
```

### Correlated Multi-Signal Alert

Single anomalies are noisy. Combine network and auth signals for high-confidence detection:

```yaml
# High-confidence lateral movement: new network destination AND auth
# failures from the same source workload.
- alert: ConfirmedLateralMovement
  expr: >
    (count by (source_workload) (
      ALERTS{alertname="NewNetworkDestination", alertstate="firing"}
    ) > 0)
    and on (source_workload)
    (count by (source_workload) (
      ALERTS{alertname="LateralAuthSweep", alertstate="firing"}
    ) > 0)
  labels:
    severity: critical
    detection_type: correlated_lateral_movement
  annotations:
    summary: >
      CORRELATED LATERAL MOVEMENT: {{ $labels.source_workload }}
      has new destinations AND auth failures
    description: |
      HIGH CONFIDENCE. This workload exhibits:
      1. Communication to destinations never seen in 30-day baseline
      2. Authentication failures against multiple services
      IMMEDIATE ACTION: Isolate the workload. Begin investigation.
    runbook_url: "https://systemshardening.com/runbooks/lateral-movement-confirmed"
```

### Automated Response with Cilium Network Policy

When a correlated lateral movement alert fires, apply an isolation policy:

```yaml
# CiliumNetworkPolicy: quarantine a compromised workload.
# Applied automatically via Alertmanager webhook or Falcosidekick.
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: quarantine-compromised
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      security.quarantine: "true"
  egressDeny:
    - toEntities:
        - cluster
        - world
  ingressDeny:
    - fromEntities:
        - cluster
        - world
```

The response webhook labels the suspected pod with `security.quarantine: "true"`, and Cilium immediately drops all traffic to and from that pod.

## Expected Behaviour

- New service-to-service communication paths generate alerts within 5 minutes
- Port scanning from a single source triggers a critical alert within 2 minutes
- Authentication sweep across 3+ services triggers a critical alert within 5 minutes
- Correlated alerts (network + auth) reduce false positive rate by 70-80% compared to single-signal detection
- Automated quarantine isolates confirmed threats within 30 seconds of correlated alert
- False positive rate below 3 per day after 30-day baseline period

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| 30-day baseline learning period | Accurate traffic map; fewer false positives | No anomaly detection for new workloads during learning | Use strict Cilium network policies (deny by default) for new workloads instead of behavioural detection. |
| Hubble L7 metrics enabled | HTTP-level visibility (paths, methods) | 15-25% increase in Hubble relay memory usage | Limit L7 visibility to security-critical namespaces. Use L3/L4 for everything else. |
| Automated quarantine on correlated alert | Fast containment (seconds vs minutes) | False positive quarantine disrupts legitimate traffic | Require two correlated signals before auto-quarantine. Single-signal alerts page but do not isolate. |
| `unless` baseline matching | Zero alerts for known traffic pairs | Baseline includes attacker traffic if compromise occurred before monitoring | Re-baseline periodically. Audit baseline entries against expected architecture. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Hubble relay down | No flow data; all network alerts stop firing | Absent metric alert: `absent(hubble_flows_processed_total)` | Restart Hubble relay. Check Cilium agent health on each node. |
| Baseline too broad | Attacker traffic matches existing patterns; no alert fires | Post-incident review shows lateral movement within baseline | Review baseline entries quarterly. Remove overly broad pairs. Tighten destination port specificity. |
| Deployment triggers flood of NewNetworkDestination alerts | 20+ alerts during a rollout; on-call ignores real alerts | Deployment suppression rule not configured | Add inhibit rule: suppress `lateral_movement` alerts when `DeploymentInProgress` is firing in the same namespace. |
| Auto-quarantine false positive | Production service isolated; downstream failures | Service health checks fail; dependent services report errors | Quarantine policy has a 5-minute TTL. Require manual confirmation to extend. Automated rollback if health checks fail within 60 seconds. |
| Prometheus recording rules lagging | Baseline calculations stale; false positives increase | Recording rule evaluation duration exceeds interval | Reduce baseline calculation frequency (5m to 15m). Increase Prometheus resources. |

## When to Consider a Managed Alternative

Self-managed lateral movement detection requires Cilium + Hubble operation, Prometheus recording rules, and ongoing baseline maintenance (4-6 hours/month for tuning).

- **[Sysdig](https://sysdig.com):** Network security monitoring with automatic baseline generation. ML-powered lateral movement detection across multi-cluster environments. Managed Falco rules updated for emerging techniques.
- **[Isovalent](https://isovalent.com):** Cilium Enterprise with built-in network flow analytics, automatic policy recommendation, and threat detection. Native Hubble integration without self-managed relay scaling.
- **[Grafana Cloud](https://grafana.com/cloud):** Centralized Hubble metric storage with managed Prometheus. Pre-built dashboards for network flow analysis. Alert correlation across metrics and logs.

**Premium content pack:** Lateral movement detection rule library. 15+ Prometheus alert rules, Cilium network policies for automated quarantine, Alertmanager webhook configurations, and [Grafana](https://grafana.com) dashboards for flow visualization.


## Related Articles

- [eBPF-Based Security Monitoring: Tetragon for Process, Network, and File Observability](/articles/observability/ebpf-tetragon/)
- [Crypto Mining Detection: CPU Patterns, Network Signatures, and Automated Response](/articles/observability/crypto-mining-detection/)
- [Kubernetes Audit Log Pipeline Design: From API Server to SIEM](/articles/observability/k8s-audit-log-design/)
- [Building Detection Rules That Don't Cry Wolf: Alert Design for Security Events](/articles/observability/detection-rules/)
- [Container Escape Detection: Runtime Signals, Kernel Indicators, and Response Automation](/articles/observability/container-escape-detection/)
