---
title: "Detecting AI-Generated Attacks: Moving from Signatures to Behavioural Baselines"
description: "Signature-based detection (WAF CRS rules, static Falco rules, antivirus signatures) matches \"known bad.\" AI-generated attacks are polymorphic, every..."
slug: "detecting-ai-attacks"
date: 2026-02-23
lastmod: 2026-02-23
category: "ai-landscape"
tags: ["ai-security", "behavioural-detection", "falco", "tetragon", "ebpf", "anomaly-detection"]
personas: ["security-engineer", "sre"]
article_number: 105
difficulty: "advanced"
estimated_reading_time: 18
provider_bridges:
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
  - name: "Panther"
    id: 127
    category: "runtime-security"
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
premium_pack: "behavioural-detection-rules"
published: true
layout: article.njk
permalink: "/articles/ai-landscape/detecting-ai-attacks/index.html"
---

# Detecting AI-Generated Attacks: Moving from Signatures to Behavioural Baselines

## Problem

Signature-based detection (WAF CRS rules, static [Falco](https://falco.org) rules, antivirus signatures) matches "known bad." AI-generated attacks are polymorphic, every payload variant is unique, every exploit uses different code paths, every phishing email is original. Signatures catch zero AI-generated variants because there is no signature to match.

The defensive shift: detect "different from known good" instead of "matches known bad." This requires behavioural baselines, understanding what normal looks like for each workload, and alerting when behaviour deviates.

## Threat Model

- **Adversary:** AI-augmented attacker using polymorphic payloads, adaptive C2, and novel exploitation techniques.
- **Key shift:** Signatures are now detection debt. Every signature you wrote for a specific attack pattern has zero value against the AI-generated variant.

## Configuration

### Process Execution Baselines with [Tetragon](https://tetragon.io)

Tetragon (CNCF/[Cilium](https://cilium.io)) monitors process execution, network connections, and file access at the eBPF level.

```yaml
# tetragon-process-monitoring.yaml
# TracingPolicy: monitor which binaries each container image runs.
# After 30-day baseline, alert on any binary not in the expected set.
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: process-execution-monitor
spec:
  kprobes:
    - call: "sys_execve"
      syscall: true
      args:
        - index: 0
          type: "string"
      selectors:
        - matchNamespaces:
            - namespace: production
              operator: In
```

```yaml
# Prometheus recording rule: track unique binaries per container image
groups:
  - name: process-baselines
    interval: 5m
    rules:
      - record: security:process_executions:by_image_binary
        expr: >
          count by (container_image, binary_name) (
            tetragon_process_exec_total
          )
```

### Network Flow Baselines with Cilium [Hubble](https://docs.cilium.io/en/stable/observability/hubble/)

```yaml
# Prometheus recording rule: track network destinations per service
groups:
  - name: network-baselines
    interval: 5m
    rules:
      # Unique destinations per source workload in the last 24 hours
      - record: security:network_destinations:count_24h
        expr: >
          count by (source_workload, destination_workload) (
            rate(hubble_flows_processed_total{verdict="FORWARDED"}[24h]) > 0
          )

      # Alert on new destinations not seen in the past 7 days
      - alert: NewNetworkDestination
        expr: >
          security:network_destinations:count_24h
          unless on (source_workload, destination_workload)
          (count by (source_workload, destination_workload) (
            rate(hubble_flows_processed_total{verdict="FORWARDED"}[7d]) > 0
          ))
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "{{ $labels.source_workload }} connected to new destination: {{ $labels.destination_workload }}"
          runbook: "Verify this is expected. New deployments and scaling create new connections. Investigate if no deployment occurred."
```

### Falco Behavioural Rules (Not Signatures)

```yaml
# Rules based on IDENTITY (which container image) not PATTERN (which binary name).

# Traditional signature rule (catches known attacks only):
# - rule: Detect xmrig
#   condition: proc.name = xmrig
#   priority: CRITICAL
# This misses any renamed or custom-compiled miner.

# Behavioural rule (catches any anomaly regardless of technique):
- rule: Unexpected Binary in NGINX
  desc: A process was executed that is not expected in NGINX containers.
  condition: >
    spawned_process
    and container
    and container.image.repository endswith "nginx"
    and not proc.name in (nginx, sh, envsubst, sed, grep, cat, ls)
    and not proc.pname = nginx
  output: >
    Unexpected binary in NGINX container
    (binary=%proc.name parent=%proc.pname
     container=%container.name image=%container.image.repository
     namespace=%k8s.ns.name pod=%k8s.pod.name)
  priority: WARNING
  tags: [behavioural]

- rule: Unexpected Binary in PostgreSQL
  desc: A process was executed that is not expected in PostgreSQL containers.
  condition: >
    spawned_process
    and container
    and container.image.repository endswith "postgres"
    and not proc.name in (postgres, pg_isready, pg_ctl, pg_dump, pg_restore, sh, bash, locale, ldconfig)
    and not proc.pname in (postgres, pg_ctl)
  output: >
    Unexpected binary in PostgreSQL container
    (binary=%proc.name parent=%proc.pname
     container=%container.name namespace=%k8s.ns.name pod=%k8s.pod.name)
  priority: WARNING
  tags: [behavioural]
```

### Anomaly Scoring and Correlation

Single anomalies are low-confidence. Multiple correlated anomalies from the same source are high-confidence:

```yaml
# Prometheus alert: correlated anomaly (multi-signal)
groups:
  - name: correlated-detection
    rules:
      # High-confidence: process anomaly AND network anomaly from the same pod
      # within a 10-minute window.
      - alert: CorrelatedAnomalyHighConfidence
        expr: >
          (
            count by (k8s_pod_name) (
              ALERTS{alertname=~"Unexpected.*Binary.*", alertstate="firing"}
            ) > 0
          )
          and on (k8s_pod_name)
          (
            count by (k8s_pod_name) (
              ALERTS{alertname="NewNetworkDestination", alertstate="firing"}
            ) > 0
          )
        labels:
          severity: critical
        annotations:
          summary: "CORRELATED: {{ $labels.k8s_pod_name }} has both process AND network anomalies"
          runbook: |
            HIGH CONFIDENCE DETECTION. This pod has:
            1. Executed an unexpected binary
            2. Connected to a new network destination
            Both within the alerting window.
            IMMEDIATE ACTION: Quarantine the pod. Investigate.
```

### Deployment Window Suppression

```yaml
# Detect ArgoCD sync events and suppress behavioural alerts during deployments.
groups:
  - name: deployment-suppression
    rules:
      - record: deployment:in_progress
        expr: >
          changes(argocd_app_sync_total[15m]) > 0

      # Inhibition rule in Alertmanager:
      # inhibit_rules:
      #   - source_match:
      #       alertname: DeploymentInProgress
      #     target_match_re:
      #       alertname: "Unexpected.*Binary.*|NewNetworkDestination"
      #     equal: ['namespace']
```

## Expected Behaviour

- Behavioural baselines established within 30-90 days of deployment
- Anomaly alerts fire within 1 minute of deviation from baseline
- Correlated alerts (multi-signal) trigger with high confidence
- False positive rate below 5/day after 30-day tuning period
- Deployment-window suppression eliminates 90% of deployment-related false positives
- Detection works regardless of specific attack technique (polymorphic-proof)

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| 30-90 day baseline period | No behavioural detection for new workloads | Attackers may target new workloads during learning | Use strict allowlists (not baselines) for new workloads. |
| Per-image behavioural rules | Must write rules for each container image type | Maintenance burden grows with unique image count | Start with the top 5-10 images. Cover ~80% of workloads. |
| Deployment suppression | Reduced detection during deployments (15-min window) | Attacker times attack to deployment window | Keep suppression window minimal (15 min). Alert on deployments that weren't expected (manual deploy outside CI). |
| Tetragon eBPF monitoring | 1-2% CPU overhead per node | Measurable on small nodes | Profile CPU impact. Tune TracingPolicy scope. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Baseline too narrow | Every deployment triggers 10+ alerts | Alert volume 5-10x during deployments | Widen baseline to include deployment-time behaviour. Add suppression. |
| Baseline too broad | Real attack doesn't trigger anomaly | Missed detection; discovered post-incident | Narrow baseline per-image. Add more granular behavioural rules. |
| Tetragon TracingPolicy error | No process monitoring on affected nodes | Tetragon pod errors; gap in process metrics | Fix TracingPolicy CRD. Redeploy Tetragon DaemonSet. |
| Correlation window too wide | Composite alert fires late (after damage) | Detection delay exceeds SLA | Reduce correlation window. Accept higher false positive rate for faster detection. |

## When to Consider a Managed Alternative

Behavioural detection at scale (1000+ events/second, 30-90 days stored history, ML anomaly analysis) exceeds what self-managed Falco and Prometheus can handle.

- **[Sysdig](https://sysdig.com):** ML-powered behavioural detection built on Falco. Managed rules updated for emerging AI-generated attack techniques. Multi-cluster baseline aggregation.
- **[Panther](https://panther.com):** Detection-as-code SIEM with Python-based behavioural rules. Cross-signal correlation.
- **[Grafana Cloud](https://grafana.com/cloud):** Long-term metric storage for baselines. ML-powered anomaly alerting.
- **[Elastic Security](https://www.elastic.co/security):** ML anomaly detection across logs and metrics.

**Premium content pack:** Behavioural detection rule pack. Falco rules per container image type, Tetragon TracingPolicies, Prometheus recording rules for baseline-deviation alerting, and correlation alert configurations.


## Related Articles

- [How AI Is Compressing the Attacker Timeline: What Defenders Need to Change Now](/articles/ai-landscape/ai-compressing-attacker-timeline/)
- [The Threat Model Has Changed: Rewriting Security Assumptions for an AI-Augmented World](/articles/ai-landscape/threat-model-ai-augmented/)
- [Using AI to Harden Systems: Automated Configuration Review and Remediation](/articles/ai-landscape/ai-assisted-hardening/)
- [AI-Powered Vulnerability Discovery: What Automated Code Analysis Means for Your Patch Cycle](/articles/ai-landscape/ai-vulnerability-discovery/)
- [Sandboxing AI Agent Tool Use: Filesystem, Network, and Process Isolation for Autonomous Actions](/articles/ai-landscape/agent-tool-use-sandboxing/)
