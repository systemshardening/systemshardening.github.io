---
title: "Kubernetes Audit Log Pipeline Design: From API Server to SIEM"
description: "Kubernetes audit logging at the RequestResponse level captures everything: every API call, every request body, every response payload."
slug: "k8s-audit-log-design"
date: 2026-01-27
lastmod: 2026-01-27
category: "observability"
tags: ["kubernetes", "audit-logging", "siem", "api-server", "security-monitoring"]
personas: ["platform-engineer", "security-engineer"]
article_number: 66
difficulty: "advanced"
estimated_reading_time: 16
provider_bridges:
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
  - name: "Axiom"
    id: 112
    category: "observability"
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
premium_pack: "k8s-audit-policy-templates"
published: true
layout: article.njk
permalink: "/articles/observability/k8s-audit-log-design/index.html"
---

# [Kubernetes](https://kubernetes.io) Audit Log Pipeline Design: From API Server to SIEM

## Problem

Kubernetes audit logging at the `RequestResponse` level captures everything: every API call, every request body, every response payload. On an active cluster this generates terabytes per week. At the `None` level, you have zero visibility into who did what. The challenge is designing an audit policy that captures security-relevant events at the right level of detail while keeping storage costs manageable.

The specific problems:

- **Default audit logging is off.** Most Kubernetes distributions ship with no audit policy. You have no record of who created a privileged pod, who read a secret, or who modified RBAC bindings.
- **RequestResponse for everything is unaffordable.** Full request and response bodies for every API call generate 500MB-2GB per node per day. At 50 nodes, that is 25-100GB per day before indexing overhead.
- **Secrets appear in audit logs.** Without field redaction, Secret values are logged in plaintext when someone creates or updates a Secret with `RequestResponse` level. This turns your audit log into a credential store.
- **Managed Kubernetes restricts access.** EKS, GKE, and AKS each expose audit logs differently. EKS sends them to CloudWatch (expensive to query). GKE sends them to Cloud Logging (different schema). AKS requires a diagnostic setting. You cannot simply configure the audit policy file.
- **Volume estimation is guesswork.** Without understanding how policy levels map to log volume for your specific workload, capacity planning is impossible.

This article provides a production audit policy, volume estimation approach, field redaction, and pipeline design from API server to SIEM.

**Target systems:** Self-managed Kubernetes (kubeadm, k3s, RKE2) with direct audit policy control. Guidance for EKS, GKE, AKS log access patterns.

## Threat Model

- **Adversary:** An insider or external attacker with valid cluster credentials (stolen kubeconfig, compromised service account). They read secrets, escalate RBAC privileges, create privileged pods, or delete workloads.
- **Blast radius:** Without audit logs, post-incident investigation is impossible. You cannot determine what the attacker accessed, what they modified, or how they escalated privileges. With properly designed audit logging, every security-relevant API call is recorded with the actor identity, resource, and timestamp.

## Configuration

### Audit Policy Design

The policy applies the most verbose level only to security-critical resources:

```yaml
# /etc/kubernetes/audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
# Omit stages that are not useful for security analysis.
omitStages:
  - "RequestReceived"

rules:
  # --- HIGH PRIORITY: RequestResponse for security-critical resources ---

  # Secrets: log full request and response to track who created/read/updated.
  # WARNING: enable redaction (see below) to avoid logging secret values.
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets"]
    verbs: ["create", "update", "patch", "delete"]

  # Secret reads: Metadata only (response body contains the secret value).
  - level: Metadata
    resources:
      - group: ""
        resources: ["secrets"]
    verbs: ["get", "list", "watch"]

  # RBAC: full request/response for all mutations.
  - level: RequestResponse
    resources:
      - group: "rbac.authorization.k8s.io"
        resources: ["clusterroles", "clusterrolebindings", "roles", "rolebindings"]

  # ServiceAccounts: track creation and token requests.
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["serviceaccounts"]
      - group: "authentication.k8s.io"
        resources: ["tokenreviews", "tokenrequests"]

  # --- MEDIUM PRIORITY: Request level for workload mutations ---

  # Pod/Deployment/DaemonSet mutations: log the request body.
  - level: Request
    resources:
      - group: ""
        resources: ["pods", "pods/exec", "pods/portforward"]
      - group: "apps"
        resources: ["deployments", "daemonsets", "statefulsets", "replicasets"]
    verbs: ["create", "update", "patch", "delete"]

  # Pod exec and port-forward deserve special attention.
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["pods/exec", "pods/portforward"]

  # --- LOW PRIORITY: Metadata for reads ---

  # All other resource reads: just metadata (who, what, when).
  - level: Metadata
    resources:
      - group: ""
        resources: ["configmaps", "services", "endpoints", "persistentvolumeclaims"]
    verbs: ["get", "list", "watch"]

  # --- EXCLUDED: None for noisy, low-value endpoints ---

  # Health checks and metrics: no security value, extreme volume.
  - level: None
    nonResourceURLs:
      - "/healthz*"
      - "/readyz*"
      - "/livez*"
      - "/metrics"
      - "/openapi/*"

  # System components: kube-proxy, kubelet, and node updates.
  - level: None
    users:
      - "system:kube-proxy"
      - "system:kube-scheduler"
      - "system:kube-controller-manager"
    resources:
      - group: ""
        resources: ["endpoints", "services", "services/status"]

  # Catch-all: Metadata for everything else.
  - level: Metadata
    omitStages:
      - "RequestReceived"
```

### API Server Configuration

```yaml
# kube-apiserver flags (in the static pod manifest or systemd unit)
spec:
  containers:
    - command:
        - kube-apiserver
        - --audit-policy-file=/etc/kubernetes/audit-policy.yaml
        - --audit-log-path=/var/log/kubernetes/audit/audit.log
        - --audit-log-maxage=7
        - --audit-log-maxbackup=3
        - --audit-log-maxsize=200
        # Webhook backend for real-time streaming (alternative to file).
        # - --audit-webhook-config-file=/etc/kubernetes/audit-webhook.yaml
        # - --audit-webhook-batch-max-wait=5s
      volumeMounts:
        - mountPath: /etc/kubernetes/audit-policy.yaml
          name: audit-policy
          readOnly: true
        - mountPath: /var/log/kubernetes/audit
          name: audit-log
  volumes:
    - name: audit-policy
      hostPath:
        path: /etc/kubernetes/audit-policy.yaml
        type: File
    - name: audit-log
      hostPath:
        path: /var/log/kubernetes/audit
        type: DirectoryOrCreate
```

### Log Shipping with [Vector](https://vector.dev)

```yaml
# vector.yaml: ship audit logs to your SIEM backend.
sources:
  k8s_audit:
    type: file
    include:
      - /var/log/kubernetes/audit/audit.log
    read_from: beginning

transforms:
  parse_audit:
    type: remap
    inputs: ["k8s_audit"]
    source: |
      . = parse_json!(.message)

      # Redact secret values from request/response objects.
      if .objectRef.resource == "secrets" {
        del(.requestObject.data)
        del(.responseObject.data)
        del(.requestObject.stringData)
      }

      # Normalize fields for SIEM ingestion.
      .actor = .user.username
      .groups = .user.groups
      .resource = join!([
        .objectRef.resource,
        "/",
        .objectRef.namespace // "cluster",
        "/",
        .objectRef.name // "unknown"
      ])
      .action = .verb
      .timestamp = .requestReceivedTimestamp

  filter_noise:
    type: filter
    inputs: ["parse_audit"]
    condition: |
      # Drop events already excluded by policy that slip through.
      .verb != "watch" || .objectRef.resource == "secrets"

sinks:
  elasticsearch:
    type: elasticsearch
    inputs: ["filter_noise"]
    endpoints:
      - "https://elasticsearch.internal:9200"
    bulk:
      index: "k8s-audit-%Y.%m.%d"
    auth:
      strategy: basic
      user: "${ES_USER}"
      password: "${ES_PASSWORD}"
    tls:
      verify_certificate: true
```

### Volume Estimation

Use this formula to estimate daily audit log volume before enabling the policy:

```
Daily volume = (API requests/day) x (average event size) x (policy multiplier)

Policy multipliers (approximate):
  None:              0 bytes
  Metadata:          ~500 bytes per event
  Request:           ~2 KB per event
  RequestResponse:   ~5-10 KB per event

Example (50-node cluster, moderate activity):
  Total API calls/day:     2,000,000
  Breakdown by policy:
    None (health/metrics):   800,000 x 0       = 0
    Metadata (reads):        900,000 x 500B    = 450 MB
    Request (mutations):     250,000 x 2 KB    = 500 MB
    RequestResponse (RBAC):   50,000 x 5 KB    = 250 MB
  Total:                                        ~1.2 GB/day
```

### Managed Kubernetes Differences

```bash
# EKS: enable audit logs via cluster logging configuration.
aws eks update-cluster-config \
  --name production \
  --logging '{"clusterLogging":[{"types":["audit"],"enabled":true}]}'
# Logs go to CloudWatch Log Group: /aws/eks/production/cluster
# Cost: $0.50/GB ingested + $0.03/GB stored/month

# GKE: audit logs are enabled by default in Cloud Audit Logs.
# Admin Activity logs: free, always on.
# Data Access logs: must be enabled, billed at Cloud Logging rates.
gcloud projects get-iam-policy PROJECT_ID \
  --format=json | jq '.auditConfigs'

# AKS: enable via diagnostic settings.
az monitor diagnostic-settings create \
  --name aks-audit \
  --resource "/subscriptions/.../managedClusters/production" \
  --logs '[{"category":"kube-audit-admin","enabled":true}]' \
  --workspace "/subscriptions/.../workspaces/security-logs"
```

## Expected Behaviour

- Security-critical resources (secrets, RBAC, service accounts) logged at RequestResponse level
- Pod exec and port-forward commands logged with full request and response
- Health checks and system component activity excluded (80% volume reduction)
- Secret values redacted from all log entries before shipping
- Daily log volume between 1-3 GB for a 50-node cluster (vs 25-100 GB at full RequestResponse)
- Audit events available in SIEM within 60 seconds of API call

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| Metadata-only for secret reads | Avoids logging secret values on read operations | Cannot see which specific secret version was read | Combine with Vault audit logs if detailed secret access tracking is needed. |
| None for health checks and system components | 80% volume reduction | Misses attacks that abuse health check endpoints | Monitor health check endpoint response codes separately with [Prometheus](https://prometheus.io). |
| File-based audit backend (not webhook) | Simpler setup; survives backend outages | Log delay if shipping agent falls behind | Monitor file size growth rate. Alert if audit log file exceeds 100MB (shipping lag). |
| 7-day local retention (maxage=7) | Limits disk usage on control plane nodes | Local logs lost after 7 days if shipping fails | Central SIEM is the primary store. Local retention is backup only. Alert on shipping failures. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Audit policy file missing or malformed | API server refuses to start or starts without audit | API server logs show policy parse error; no audit events in SIEM | Validate policy with `kubectl apply --dry-run` equivalent. Keep a known-good policy as fallback. |
| Audit log volume exceeds disk capacity | Control plane node disk full; API server crashes | Disk usage alert on control plane nodes | Reduce maxsize and maxbackup. Add None rules for additional high-volume, low-value resources. |
| Vector shipping lag | Audit events delayed by minutes or hours | Lag metric in Vector dashboard; SIEM freshness alert | Scale Vector resources. Increase batch size. Check network throughput to SIEM backend. |
| Secret values not redacted | Secrets visible in SIEM to anyone with log access | Periodic audit: search SIEM for `objectRef.resource:secrets AND requestObject.data:*` | Fix Vector transform. Re-index affected time range with redaction. Rotate exposed secrets. |
| Managed K8s cost explosion | CloudWatch or Cloud Logging bill spikes unexpectedly | Billing alerts on logging cost | Add subscription-level log filters in CloudWatch/Cloud Logging to drop non-security events before storage. |

## When to Consider a Managed Alternative

Self-managed Kubernetes audit logging requires API server configuration, log shipping infrastructure, storage capacity planning, and ongoing policy tuning (2-4 hours/month).

- **[Grafana Cloud](https://grafana.com/cloud):** Managed [Loki](https://grafana.com/oss/loki/) backend for audit log storage. Pre-built dashboards for K8s audit analysis. No [Elasticsearch](https://www.elastic.co/elasticsearch) cluster management.
- **[Axiom](https://axiom.co):** Schemaless ingestion handles audit log format changes across K8s versions. Cost-effective storage with fast query performance. No index management.
- **[Sysdig](https://sysdig.com):** K8s-native audit analysis with pre-built detection rules. Automatic correlation of audit events with runtime security events.

**Premium content pack:** Kubernetes audit policy templates. Policies tuned for CIS Benchmark, SOC 2, and PCI-DSS compliance requirements. Includes Vector transforms, Elasticsearch index templates, and [Grafana](https://grafana.com) dashboards.


## Related Articles

- [Building a Security Audit Log Pipeline That Scales: auditd to Elasticsearch](/articles/observability/audit-log-pipeline/)
- [Lateral Movement Detection: Network Patterns, Authentication Anomalies, and Alert Correlation](/articles/observability/lateral-movement-detection/)
- [OpenTelemetry for Security: Distributed Tracing of Authentication and Authorization Flows](/articles/observability/otel-security-tracing/)
- [Kubernetes Audit Log Analysis: What to Log, How to Query, and What to Alert On](/articles/kubernetes/audit-log-analysis/)
- [Container Escape Detection: Runtime Signals, Kernel Indicators, and Response Automation](/articles/observability/container-escape-detection/)
