---
title: "Crypto Mining Detection: CPU Patterns, Network Signatures, and Automated Response"
description: "Cryptojacking is the most common post-compromise activity in Kubernetes environments."
slug: "crypto-mining-detection"
date: 2026-01-23
lastmod: 2026-01-23
category: "observability"
tags: ["cryptojacking", "detection", "falco", "prometheus", "kubernetes", "runtime-security"]
personas: ["security-engineer", "sre"]
article_number: 73
difficulty: "intermediate"
estimated_reading_time: 15
provider_bridges:
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
premium_pack: "crypto-mining-detection-rules"
published: true
layout: article.njk
permalink: "/articles/observability/crypto-mining-detection/index.html"
---

# Crypto Mining Detection: CPU Patterns, Network Signatures, and Automated Response

## Problem

Cryptojacking is the most common post-compromise activity in [Kubernetes](https://kubernetes.io) environments. It is profitable for attackers, low-risk (mining is not as legally severe as data theft), and often goes undetected for weeks because CPU usage increases gradually. By the time someone notices the cloud bill spike, the attacker has been mining for a month.

The specific challenges:

- **CPU usage alone is not conclusive.** Legitimate workloads (data processing, ML training, CI builds) also sustain high CPU. A detection rule that alerts on "high CPU" generates constant false positives.
- **Miners are obfuscated.** Attackers rename `xmrig` to `worker`, `httpd`, or random strings. Process name matching catches only unsophisticated attacks.
- **Mining pools use standard ports.** While the Stratum protocol commonly runs on ports 3333, 4444, and 8333, miners can be configured to use port 443 or 80 to blend with normal HTTPS traffic.
- **Gradual ramp-up avoids spike detection.** Sophisticated miners start at low CPU usage and increase gradually over days, avoiding sudden-change alerts.
- **Compromised images in public registries.** Attackers publish [Docker](https://www.docker.com) images with miners baked in. The miner starts on container launch, looking like normal application behaviour.

This article combines CPU pattern analysis, process execution detection, DNS and network monitoring, and automated response to detect and terminate crypto mining operations.

**Target systems:** Kubernetes clusters with [Prometheus](https://prometheus.io) for metrics, [Falco](https://falco.org) for runtime detection, and [CoreDNS](https://coredns.io) for DNS monitoring.

## Threat Model

- **Adversary:** An opportunistic attacker who exploits exposed services (misconfigured dashboards, known CVEs, leaked credentials) to deploy mining workloads. Their goal is sustained computation, not data theft or disruption.
- **Blast radius:** Crypto mining consumes CPU and electricity, inflating cloud costs by 2-10x. Performance of legitimate workloads degrades as mining competes for CPU. In Kubernetes, resource limits may prevent impact on co-located pods, but nodes without limits are fully consumed. The attacker also maintains persistent access (the same vector used for mining can be used for more damaging attacks later).

## Configuration

### CPU Anomaly Detection

Static CPU thresholds are useless. Use baseline-relative detection:

```yaml
# Prometheus recording rules: establish CPU baselines per workload.
groups:
  - name: crypto-mining-baselines
    interval: 5m
    rules:
      # Average CPU usage per pod over 7 days.
      - record: workload:cpu_usage:avg_7d
        expr: >
          avg_over_time(
            rate(container_cpu_usage_seconds_total[5m])[7d:5m]
          )

      # P95 CPU usage per pod over 7 days (captures normal spikes).
      - record: workload:cpu_usage:p95_7d
        expr: >
          quantile_over_time(0.95,
            rate(container_cpu_usage_seconds_total[5m])[7d:5m]
          )
```

```yaml
# Alert: sustained CPU usage 3x above the 7-day P95 baseline.
# "Sustained" means 30 minutes, which filters out normal batch jobs.
groups:
  - name: crypto-mining-detection
    rules:
      - alert: SustainedHighCPU
        expr: >
          rate(container_cpu_usage_seconds_total[5m])
          > 3 * workload:cpu_usage:p95_7d
          and rate(container_cpu_usage_seconds_total[5m]) > 0.5
        for: 30m
        labels:
          severity: warning
          detection_type: crypto_mining
        annotations:
          summary: >
            Sustained high CPU: {{ $labels.pod }} at
            {{ $value | humanize }} cores (3x above P95 baseline)
          runbook_url: "https://systemshardening.com/runbooks/crypto-mining"
          false_positive_notes: |
            Common FP sources: CI/CD build pods, ML training jobs,
            batch data processing, Java GC compaction.
            Check if the pod belongs to a known compute-heavy workload.

      # Detect CPU usage that is both high AND constant.
      # Mining produces very stable CPU patterns (low coefficient of variation).
      - alert: FlatlineCPUPattern
        expr: >
          stddev_over_time(
            rate(container_cpu_usage_seconds_total[5m])[1h:5m]
          )
          /
          avg_over_time(
            rate(container_cpu_usage_seconds_total[5m])[1h:5m]
          )
          < 0.05
          and
          rate(container_cpu_usage_seconds_total[5m]) > 0.8
        for: 1h
        labels:
          severity: warning
          detection_type: crypto_mining
        annotations:
          summary: >
            Flatline CPU: {{ $labels.pod }} running at {{ $value | humanize }}
            cores with <5% variation for 1+ hour
          description: |
            Crypto miners produce very stable CPU usage (low variance).
            Normal workloads have variable CPU patterns.
            Investigate the processes running in this pod.
```

### Process Execution Detection with Falco

```yaml
# Falco rules for known mining process names and behaviours.

# Rule 1: known miner binary names (catches unsophisticated attacks).
- rule: Known Crypto Miner Execution
  desc: >
    A known cryptocurrency mining binary was executed inside a container.
  condition: >
    spawned_process
    and container
    and (proc.name in (xmrig, cpuminer, minerd, minergate, xmr-stak,
                       ccminer, ethminer, nbminer, t-rex, gminer,
                       lolminer, phoenixminer, nanominer, bfgminer,
                       cgminer, srbminer))
  output: >
    Known crypto miner executed
    (binary=%proc.name command=%proc.cmdline container=%container.name
     image=%container.image.repository namespace=%k8s.ns.name
     pod=%k8s.pod.name)
  priority: CRITICAL
  tags: [crypto-mining, known-binary]

# Rule 2: Stratum protocol arguments in any process.
# Even renamed miners are typically invoked with stratum:// URLs.
- rule: Stratum Protocol Arguments
  desc: >
    A process was started with Stratum mining protocol arguments.
    This catches renamed miners that still use standard mining pool URLs.
  condition: >
    spawned_process
    and container
    and (proc.cmdline contains "stratum+tcp://"
         or proc.cmdline contains "stratum+ssl://"
         or proc.cmdline contains "stratum2+tcp://"
         or proc.cmdline contains "--coin"
         or proc.cmdline contains "--algo=random"
         or proc.cmdline contains "--donate-level")
  output: >
    Stratum protocol in process arguments
    (command=%proc.cmdline container=%container.name
     image=%container.image.repository namespace=%k8s.ns.name
     pod=%k8s.pod.name)
  priority: CRITICAL
  tags: [crypto-mining, stratum]

# Rule 3: process reading CPU model information.
# Miners read /proc/cpuinfo to optimize for the CPU architecture.
# This is unusual for typical application workloads.
- rule: CPU Info Read in Container
  desc: >
    A container process read /proc/cpuinfo, which miners do to detect
    CPU features for hash algorithm optimization.
  condition: >
    open_read
    and container
    and fd.name = /proc/cpuinfo
    and not (proc.name in (node, python, java, dotnet))
  output: >
    CPU info read in container
    (binary=%proc.name container=%container.name
     namespace=%k8s.ns.name pod=%k8s.pod.name)
  priority: NOTICE
  tags: [crypto-mining, cpuinfo]
```

### DNS and Network Monitoring

```yaml
# Prometheus alerting rules for mining pool DNS resolution and network traffic.
groups:
  - name: crypto-mining-network
    rules:
      # Alert: DNS resolution of known mining pool domains.
      - alert: MiningPoolDNSQuery
        expr: >
          sum by (source_pod) (
            rate(coredns_dns_requests_total{
              domain=~".*(pool|mine|mining|xmr|monero|nicehash|2miners|f2pool|nanopool|ethermine|hiveon|hashvault|supportxmr).*"
            }[5m])
          ) > 0
        for: 1m
        labels:
          severity: critical
          detection_type: crypto_mining
        annotations:
          summary: >
            Mining pool DNS: {{ $labels.source_pod }} resolved
            mining pool domain

      # Alert: connections to known Stratum protocol ports.
      - alert: StratumPortConnection
        expr: >
          sum by (source_pod, destination_port) (
            rate(hubble_flows_processed_total{
              verdict="FORWARDED",
              destination_port=~"3333|4444|5555|7777|8333|9999|14444"
            }[5m])
          ) > 0
        for: 2m
        labels:
          severity: critical
          detection_type: crypto_mining
        annotations:
          summary: >
            Stratum port: {{ $labels.source_pod }} connecting to
            port {{ $labels.destination_port }}

      # Alert: sustained outbound connections to a single external IP.
      # Miners maintain persistent TCP connections to pool servers.
      - alert: PersistentExternalConnection
        expr: >
          count by (source_pod) (
            hubble_tcp_flags_total{
              destination_is_external="true",
              flag="SYN"
            }
          ) == 1
          and
          sum by (source_pod) (
            rate(hubble_tcp_bytes_total{destination_is_external="true"}[1h])
          ) > 1024
        for: 2h
        labels:
          severity: warning
          detection_type: crypto_mining
        annotations:
          summary: >
            {{ $labels.source_pod }} has a persistent connection to
            a single external IP for 2+ hours
```

### Correlated Multi-Signal Detection

```yaml
# High-confidence mining detection: CPU anomaly AND network indicator.
- alert: ConfirmedCryptoMining
  expr: >
    (count by (pod, namespace) (
      ALERTS{alertname=~"SustainedHighCPU|FlatlineCPUPattern", alertstate="firing"}
    ) > 0)
    and on (pod, namespace)
    (count by (pod, namespace) (
      ALERTS{alertname=~"MiningPoolDNSQuery|StratumPortConnection", alertstate="firing"}
    ) > 0)
  labels:
    severity: critical
    detection_type: confirmed_crypto_mining
  annotations:
    summary: >
      CONFIRMED MINING: {{ $labels.pod }} in {{ $labels.namespace }}
      has CPU anomaly AND mining network activity
    description: |
      HIGH CONFIDENCE. This pod exhibits:
      1. Sustained high or flatline CPU usage above baseline
      2. DNS queries to mining pools OR connections on Stratum ports
      IMMEDIATE ACTION: Terminate the pod. Investigate the attack vector.
```

### Automated Response

```yaml
# Falcosidekick response for confirmed mining detection.
config:
  webhook:
    address: "http://response-automation:8080/falco"
    minimumpriority: "critical"

---
# Response handler actions for crypto mining:
actions:
  crypto_mining:
    rules:
      - "Known Crypto Miner Execution"
      - "Stratum Protocol Arguments"
    steps:
      # Step 1: kill the pod immediately (no grace period).
      - type: kubectl
        command: "delete pod {{ .pod }} -n {{ .namespace }} --grace-period=0 --force"
      # Step 2: scale down the deployment to prevent restart.
      - type: kubectl
        command: >
          scale deployment
          $(kubectl get pod {{ .pod }} -n {{ .namespace }}
            -o jsonpath='{.metadata.ownerReferences[0].name}')
          -n {{ .namespace }} --replicas=0
      # Step 3: alert the security team with forensic context.
      - type: alert
        severity: critical
        channel: "#security-incidents"
        message: |
          Crypto mining terminated.
          Pod: {{ .pod }}
          Namespace: {{ .namespace }}
          Image: {{ .image }}
          Binary: {{ .proc_name }}
          Command: {{ .proc_cmdline }}
          Action taken: pod killed, deployment scaled to 0.
          Next: investigate attack vector and image provenance.
```

## Expected Behaviour

- Known mining binaries (xmrig, cpuminer, etc.) detected and killed within seconds
- Stratum protocol arguments in any process detected regardless of binary name
- Mining pool DNS queries detected within 1 minute
- Sustained high CPU (3x above baseline for 30+ minutes) triggers investigation alert
- Flatline CPU pattern (high usage, low variance for 1+ hour) triggers investigation alert
- Correlated detection (CPU + network) produces high-confidence alert
- Automated response kills mining pods and scales deployment to zero
- Mean time from mining start to termination: under 35 minutes for obfuscated miners, under 1 minute for known binaries

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| 30-minute `for` duration on CPU alerts | Filters out batch jobs and short compute bursts | Miner runs for 30 minutes before detection | Use Falco process detection (instant) for known binaries. CPU alerts catch only obfuscated miners. |
| Auto-kill on known binary detection | Immediate termination of confirmed mining | False positive if a legitimate tool shares a name with a miner | The binary list is specific (xmrig, cpuminer, etc.). No legitimate tool uses these names. Review list quarterly. |
| DNS domain pattern matching for mining pools | Catches miners using known pools | New or private mining pools with unrecognized domains | Combine with Stratum port detection. Private pools still use standard Stratum ports. Update domain patterns monthly. |
| Flatline CPU detection (coefficient of variation < 0.05) | Catches obfuscated miners by behaviour, not name | Legitimate steady-state workloads (databases, caches) also have low variance | Exclude known steady-state workloads by label. Apply only to application workloads. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Miner uses port 443 to pool | Stratum port alert does not fire; only CPU anomaly triggers | Post-incident: network logs show persistent connection to unknown IP on 443 | Add TLS fingerprint detection (JA3/JA4 hash). Mining Stratum over TLS has a distinct fingerprint from HTTPS. |
| Miner throttles to 50% CPU | CPU stays within 3x baseline; alert does not fire | Cloud bill audit reveals elevated compute costs | Lower the multiplier to 2x for non-compute workloads. Use flatline detection as a secondary signal. |
| Falco rule exception too broad | Known miner runs in an excluded namespace | Post-incident review shows mining in excluded namespace | Never exclude user-facing namespaces. Only exclude kube-system and monitoring. Audit exclusions quarterly. |
| Auto-response kills pod but attacker redeploys | Mining restarts repeatedly; pod kill/restart loop | Deployment restart count increasing; same image redeploying | Scale deployment to 0 (not just pod delete). Investigate the deployment source (compromised CI, stolen credentials, vulnerable admission path). |
| New mining algorithm with unknown binary | No Falco rule matches; CPU pattern is the only signal | Sustained high CPU alert fires after 30 minutes | Investigate all SustainedHighCPU alerts that do not correlate with known batch jobs. Add new binary names to Falco rules as they are discovered. |

## When to Consider a Managed Alternative

Self-managed crypto mining detection requires Falco DaemonSet operation, Prometheus baseline rules, DNS monitoring, and rule updates for new mining tools (3-5 hours/month).

- **[Sysdig](https://sysdig.com):** Integrated crypto mining detection with ML-powered process classification. Automatic rule updates for new mining tools and obfuscation techniques. Drift detection catches miners introduced via image modification. Multi-cluster detection and response from a single console.

**Premium content pack:** Crypto mining detection rule library. Falco rules for 30+ known mining binaries, Stratum protocol detection, CPU anomaly Prometheus rules, DNS blocklist patterns, and automated response configurations. Includes a testing framework with safe mining process simulators for validating detection.


## Related Articles

- [Building Detection Rules That Don't Cry Wolf: Alert Design for Security Events](/articles/observability/detection-rules/)
- [Lateral Movement Detection: Network Patterns, Authentication Anomalies, and Alert Correlation](/articles/observability/lateral-movement-detection/)
- [Container Escape Detection: Runtime Signals, Kernel Indicators, and Response Automation](/articles/observability/container-escape-detection/)
- [eBPF-Based Security Monitoring: Tetragon for Process, Network, and File Observability](/articles/observability/ebpf-tetragon/)
- [Kubernetes Audit Log Pipeline Design: From API Server to SIEM](/articles/observability/k8s-audit-log-design/)
