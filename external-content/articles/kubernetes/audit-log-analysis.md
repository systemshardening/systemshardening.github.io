---
title: "Kubernetes Audit Log Analysis: What to Log, How to Query, and What to Alert On"
description: "Kubernetes audit logs record every request to the API server: who made the request, what they asked for, and whether it succeeded."
slug: "audit-log-analysis"
date: 2026-01-17
lastmod: 2026-01-17
category: "kubernetes"
tags: ["kubernetes", "audit-logs", "security-monitoring", "siem", "detection", "compliance"]
personas: ["security-engineer", "platform-engineer"]
article_number: 34
difficulty: "intermediate"
estimated_reading_time: 22
provider_bridges:
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
  - name: "Axiom"
    id: 112
    category: "log-management"
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
published: true
layout: article.njk
permalink: "/articles/kubernetes/audit-log-analysis/index.html"
---

# [Kubernetes](https://kubernetes.io) Audit Log Analysis: What to Log, How to Query, and What to Alert On

## Problem

Kubernetes audit logs record every request to the API server: who made the request, what they asked for, and whether it succeeded. In an active cluster, this generates 1-10 GB per day at the Metadata level and 5-50 GB per day at the RequestResponse level. Without filtering, storage costs are prohibitive. Without analysis, security-relevant events are buried in millions of routine API calls.

The core challenges are:

- **Logging everything is too expensive.** The `RequestResponse` level records the full request and response body for every API call. For a cluster with frequent pod scheduling, configmap reads, and health checks, this produces terabytes of data per month. Most of it is noise.
- **Logging nothing is blind.** The `None` level disables all audit logging. You have no record of who created a privileged pod, who read a secret, or who modified RBAC. Incident response becomes guesswork.
- **The useful signal is in the middle.** Secret access, RBAC changes, exec into pods, service account token creation, and node status changes are high-value events. Health checks, metrics scraping, and leader election updates are noise. The audit policy must distinguish between the two.
- **Shipping and querying at scale requires infrastructure.** Audit logs must be forwarded to a SIEM or log aggregation system, parsed, indexed, and queryable. The Kubernetes API server writes logs to files or webhooks; getting them into [Loki](https://grafana.com/oss/loki/), [Elasticsearch](https://www.elastic.co/elasticsearch), or a managed backend requires additional configuration.

This article covers audit policy design, per-resource filtering, sensitive field redaction, log shipping, and the top 10 suspicious patterns to alert on.

**Target systems:** Kubernetes 1.29+ (self-managed). Managed providers expose audit logs through their own interfaces (CloudWatch for EKS, Cloud Logging for GKE, Azure Monitor for AKS).

## Threat Model

- **Adversary:** Insider with legitimate cluster access attempting privilege escalation, or an external attacker who has compromised a ServiceAccount or user credential.
- **Access level:** Valid Kubernetes API credentials (user certificate, ServiceAccount token, or OIDC token) with some level of RBAC permissions.
- **Objective:** Escalate privileges (create ClusterRoleBindings), access sensitive data (list secrets), establish persistence (create new ServiceAccounts, modify webhooks), or cover tracks (delete audit-relevant resources).
- **Blast radius:** Without audit logging, these actions leave no trace. With proper audit logging and alerting, each suspicious action triggers a detection, enabling incident response within minutes instead of days or weeks.

## Configuration

### Step 1: Audit Policy Design

The audit policy defines four logging levels per resource type:

| Level | What is logged | Storage impact |
|-------|---------------|----------------|
| `None` | Nothing | Zero |
| `Metadata` | Request metadata (user, verb, resource, timestamp) | Low (200-500 bytes per event) |
| `Request` | Metadata + request body | Medium (1-5 KB per event) |
| `RequestResponse` | Metadata + request body + response body | High (5-50 KB per event) |

```yaml
# /etc/kubernetes/audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # ============================================
  # Level 1: Skip noise (None)
  # ============================================

  # Skip all requests to health check and readiness endpoints
  - level: None
    nonResourceURLs:
      - /healthz*
      - /readyz*
      - /livez*
      - /metrics

  # Skip API discovery requests (constant, high-volume)
  - level: None
    resources:
      - group: ""
        resources: ["endpoints", "events"]
    verbs: ["get", "list", "watch"]

  # Skip watch requests (long-running, generate massive volume)
  - level: None
    verbs: ["watch"]

  # Skip system:nodes and system:kube-scheduler reads
  # (constant heartbeats and lease updates)
  - level: None
    users:
      - "system:kube-scheduler"
      - "system:kube-controller-manager"
    verbs: ["get", "list"]
    resources:
      - group: "coordination.k8s.io"
        resources: ["leases"]

  # ============================================
  # Level 2: High-value targets (RequestResponse)
  # ============================================

  # Log full request and response for secrets
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets"]
    omitStages:
      - RequestReceived

  # Log full RBAC changes
  - level: RequestResponse
    resources:
      - group: "rbac.authorization.k8s.io"
        resources: ["clusterroles", "clusterrolebindings", "roles", "rolebindings"]
    omitStages:
      - RequestReceived

  # Log full request for service account token creation
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["serviceaccounts/token"]
    omitStages:
      - RequestReceived

  # ============================================
  # Level 3: Mutation tracking (Request)
  # ============================================

  # Log request body for pod, deployment, and daemonset mutations
  - level: Request
    resources:
      - group: ""
        resources: ["pods", "pods/exec", "pods/portforward"]
      - group: "apps"
        resources: ["deployments", "daemonsets", "statefulsets"]
    verbs: ["create", "update", "patch", "delete"]
    omitStages:
      - RequestReceived

  # Log webhook configuration changes (persistence vector)
  - level: Request
    resources:
      - group: "admissionregistration.k8s.io"
        resources: ["mutatingwebhookconfigurations", "validatingwebhookconfigurations"]
    omitStages:
      - RequestReceived

  # Log namespace lifecycle
  - level: Request
    resources:
      - group: ""
        resources: ["namespaces"]
    verbs: ["create", "delete"]
    omitStages:
      - RequestReceived

  # ============================================
  # Level 4: Everything else (Metadata)
  # ============================================

  # Default: log metadata for all other requests
  - level: Metadata
    omitStages:
      - RequestReceived
```

### Step 2: Enable Audit Logging on the API Server

**For kubeadm clusters:**

```yaml
# /etc/kubernetes/manifests/kube-apiserver.yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
    - name: kube-apiserver
      command:
        - kube-apiserver
        - --audit-policy-file=/etc/kubernetes/audit-policy.yaml
        - --audit-log-path=/var/log/kubernetes/audit/audit.log
        - --audit-log-maxage=30
        - --audit-log-maxbackup=10
        - --audit-log-maxsize=100
        # ... other existing flags ...
      volumeMounts:
        - name: audit-policy
          mountPath: /etc/kubernetes/audit-policy.yaml
          readOnly: true
        - name: audit-log
          mountPath: /var/log/kubernetes/audit
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

**For k3s:**

```bash
# Create the audit policy
sudo mkdir -p /var/lib/rancher/k3s/server/
sudo cp audit-policy.yaml /var/lib/rancher/k3s/server/audit-policy.yaml

# Add to k3s server configuration
# /etc/rancher/k3s/config.yaml
# kube-apiserver-arg:
#   - "audit-policy-file=/var/lib/rancher/k3s/server/audit-policy.yaml"
#   - "audit-log-path=/var/log/kubernetes/audit/audit.log"
#   - "audit-log-maxage=30"
#   - "audit-log-maxbackup=10"
#   - "audit-log-maxsize=100"

sudo systemctl restart k3s
```

### Step 3: Sensitive Field Redaction

Prevent passwords and tokens from appearing in audit logs, even at the RequestResponse level:

```yaml
# Add to the audit policy (top-level field alongside rules)
apiVersion: audit.k8s.io/v1
kind: Policy
omitManagedFields: true
rules:
  # Log secrets at RequestResponse but redact the data field
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets"]
    omitStages:
      - RequestReceived
  # Note: Kubernetes 1.30+ supports the omitResponseBody field
  # For older versions, use a webhook backend that strips sensitive
  # fields before forwarding to the SIEM
  # ... rest of the policy ...
```

For pre-1.30 clusters, use a log pipeline to strip sensitive fields:

```yaml
# Fluent Bit filter to redact secret data from audit logs
# fluent-bit-config.yaml
[FILTER]
    Name    lua
    Match   kube-audit.*
    Script  /fluent-bit/scripts/redact-secrets.lua
    Call    redact_secrets
```

```lua
-- /fluent-bit/scripts/redact-secrets.lua
function redact_secrets(tag, timestamp, record)
    if record["objectRef"] and record["objectRef"]["resource"] == "secrets" then
        if record["requestObject"] and record["requestObject"]["data"] then
            record["requestObject"]["data"] = "[REDACTED]"
        end
        if record["responseObject"] and record["responseObject"]["data"] then
            record["responseObject"]["data"] = "[REDACTED]"
        end
    end
    return 1, timestamp, record
end
```

### Step 4: Ship Audit Logs to a SIEM

**Option A: Fluent Bit to Loki**

```yaml
# fluent-bit-daemonset.yaml (audit log shipper on control plane nodes)
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: audit-log-shipper
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: audit-log-shipper
  template:
    metadata:
      labels:
        app: audit-log-shipper
    spec:
      nodeSelector:
        node-role.kubernetes.io/control-plane: ""
      tolerations:
        - key: node-role.kubernetes.io/control-plane
          effect: NoSchedule
      containers:
        - name: fluent-bit
          image: fluent/fluent-bit:3.1
          volumeMounts:
            - name: audit-log
              mountPath: /var/log/kubernetes/audit
              readOnly: true
            - name: config
              mountPath: /fluent-bit/etc
          env:
            - name: LOKI_URL
              value: "http://loki.monitoring.svc.cluster.local:3100/loki/api/v1/push"
      volumes:
        - name: audit-log
          hostPath:
            path: /var/log/kubernetes/audit
            type: Directory
        - name: config
          configMap:
            name: fluent-bit-audit-config
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluent-bit-audit-config
  namespace: monitoring
data:
  fluent-bit.conf: |
    [SERVICE]
        Flush        5
        Log_Level    info

    [INPUT]
        Name         tail
        Path         /var/log/kubernetes/audit/audit.log
        Parser       json
        Tag          kube-audit
        Refresh_Interval 5

    [OUTPUT]
        Name         loki
        Match        kube-audit
        Host         loki.monitoring.svc.cluster.local
        Port         3100
        Labels       job=kube-audit
        Auto_Kubernetes_Labels off
```

**Option B: Webhook backend (direct streaming)**

```yaml
# /etc/kubernetes/audit-webhook.yaml
apiVersion: v1
kind: Config
clusters:
  - name: audit-backend
    cluster:
      server: https://siem.internal.example.com:9200/_bulk
      certificate-authority: /etc/kubernetes/pki/siem-ca.crt
contexts:
  - name: audit
    context:
      cluster: audit-backend
current-context: audit
```

```yaml
# Add to kube-apiserver flags:
# --audit-webhook-config-file=/etc/kubernetes/audit-webhook.yaml
# --audit-webhook-batch-max-wait=5s
# --audit-webhook-batch-max-size=100
```

### Step 5: Top 10 Suspicious Patterns to Alert On

These are the highest-signal audit log patterns that indicate potential security incidents:

| # | Pattern | LogQL Query (Loki) | Severity |
|---|---------|-------------------|----------|
| 1 | Secret list across namespaces | `{job="kube-audit"} \| json \| objectRef_resource="secrets" and verb="list" and objectRef_namespace=""` | Critical |
| 2 | ClusterRoleBinding creation | `{job="kube-audit"} \| json \| objectRef_resource="clusterrolebindings" and verb="create"` | Critical |
| 3 | Exec into pod | `{job="kube-audit"} \| json \| objectRef_subresource="exec" and verb="create"` | High |
| 4 | ServiceAccount token request | `{job="kube-audit"} \| json \| objectRef_resource="serviceaccounts" and objectRef_subresource="token" and verb="create"` | High |
| 5 | Webhook configuration change | `{job="kube-audit"} \| json \| objectRef_resource=~"mutatingwebhookconfigurations\|validatingwebhookconfigurations"` | Critical |
| 6 | Privileged pod creation | `{job="kube-audit"} \| json \| objectRef_resource="pods" and verb="create" \| line_format "{{.requestObject}}" \| regexp "privileged.*true"` | Critical |
| 7 | Namespace deletion | `{job="kube-audit"} \| json \| objectRef_resource="namespaces" and verb="delete"` | High |
| 8 | Anonymous or unauthenticated requests | `{job="kube-audit"} \| json \| user_username="system:anonymous"` | Critical |
| 9 | RBAC escalation (bind/escalate verbs) | `{job="kube-audit"} \| json \| verb=~"bind\|escalate"` | Critical |
| 10 | Node status patch from unexpected source | `{job="kube-audit"} \| json \| objectRef_resource="nodes" and verb="patch" and user_username!~"system:node:.*"` | High |

**Example [Prometheus](https://prometheus.io) alerting rules (from audit log metrics):**

```yaml
# audit-alerts.yaml (PrometheusRule)
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: kubernetes-audit-alerts
  namespace: monitoring
spec:
  groups:
    - name: kubernetes-audit
      interval: 30s
      rules:
        - alert: SecretListAllNamespaces
          expr: |
            count by (user_username) (
              count_over_time(
                {job="kube-audit"} | json
                | objectRef_resource="secrets"
                | verb="list"
                | objectRef_namespace=""
                [5m]
              )
            ) > 0
          for: 0m
          labels:
            severity: critical
          annotations:
            summary: "User {{ $labels.user_username }} listed secrets across all namespaces"
            description: "Listing secrets without a namespace filter is a common reconnaissance technique."

        - alert: ClusterRoleBindingCreated
          expr: |
            count by (user_username) (
              count_over_time(
                {job="kube-audit"} | json
                | objectRef_resource="clusterrolebindings"
                | verb="create"
                [5m]
              )
            ) > 0
          for: 0m
          labels:
            severity: critical
          annotations:
            summary: "User {{ $labels.user_username }} created a ClusterRoleBinding"
            description: "ClusterRoleBinding creation grants cluster-wide permissions. Verify this was authorized."

        - alert: ExecIntoPod
          expr: |
            count by (user_username, objectRef_namespace) (
              count_over_time(
                {job="kube-audit"} | json
                | objectRef_subresource="exec"
                | verb="create"
                [5m]
              )
            ) > 3
          for: 0m
          labels:
            severity: high
          annotations:
            summary: "User {{ $labels.user_username }} exec'd into pods in {{ $labels.objectRef_namespace }} more than 3 times in 5 minutes"
```

### Step 6: Storage Estimation

Use this formula to estimate audit log storage requirements:

| Cluster Activity | Metadata Only | Request (mutations) | RequestResponse (secrets + RBAC) |
|-----------------|--------------|--------------------|---------------------------------|
| Small (50 pods, 5 deploys/day) | 500 MB/day | 1 GB/day | 2 GB/day |
| Medium (200 pods, 20 deploys/day) | 2 GB/day | 5 GB/day | 10 GB/day |
| Large (1000 pods, 100 deploys/day) | 10 GB/day | 25 GB/day | 50 GB/day |

With the tiered policy from Step 1 (None for noise, Metadata for reads, Request for mutations, RequestResponse for secrets and RBAC), expect 40-60% reduction compared to a flat RequestResponse policy.

## Expected Behaviour

After implementing audit logging and analysis:

- Health checks, metrics endpoints, and watch requests produce no audit log entries (filtered to None)
- Secret access and RBAC changes produce full RequestResponse entries for forensic analysis
- Pod mutations, exec operations, and webhook changes produce Request-level entries
- All other API calls produce Metadata-level entries (who, what, when, result)
- Audit logs ship to the SIEM within 5-10 seconds of the API call
- Alerts fire within 30-60 seconds of a suspicious pattern match
- Secret data fields are redacted in the log pipeline, preventing credential exposure in the SIEM

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| RequestResponse for secrets | Full request/response bodies for secret operations (5-50 KB per event) | Storage cost increase; secret data in audit logs creates a secondary exposure risk | Redact secret data in the log pipeline. Set retention limits (30 days for RequestResponse, 90 days for Metadata) |
| None for health checks | No audit trail for health check endpoints | If an attacker discovers an unauthenticated health endpoint that leaks information, there is no log | Monitor health endpoints separately. Ensure health endpoints do not expose sensitive data |
| Webhook backend | API server depends on SIEM availability for audit delivery | If the webhook backend is unavailable, audit events are lost (unless buffered) | Use file-based logging as primary, webhook as secondary. Configure batch settings to buffer during short outages |
| Aggressive filtering | Reduced log volume and cost | Filtered events are invisible; new attack patterns targeting filtered resources will not be detected | Review and update the audit policy quarterly. Compare against updated threat models |
| Alert rules for top 10 patterns | Early detection of common attack techniques | Alert fatigue if patterns trigger on legitimate operations (e.g., platform engineers exec into pods regularly) | Exclude known-good identities from alerts. Use escalating severity (first occurrence: info; repeated: critical) |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Audit policy syntax error | API server fails to start; static pod enters CrashLoopBackOff | API server container logs show "failed to load audit policy"; `kubectl` commands fail | Fix the policy YAML syntax. On kubeadm, the kubelet restarts the static pod automatically after the file is corrected |
| Audit log disk full | API server stops writing audit logs; if `--audit-log-path` is on the same partition as etcd, etcd may also fail | Disk usage alerts on control plane nodes; audit log file stops growing | Increase disk size. Reduce `--audit-log-maxbackup` and `--audit-log-maxsize`. Archive old logs to object storage |
| Fluent Bit shipper OOM | Audit logs accumulate on disk but are not forwarded to the SIEM | Fluent Bit pod in OOM/CrashLoopBackOff; gap in SIEM audit data | Increase Fluent Bit memory limits. Reduce batch size. Check for log parsing errors causing memory leaks |
| SIEM backend unreachable | Webhook-based shipping drops events; file-based shipping continues locally | Webhook mode: API server logs show webhook delivery errors. File mode: no symptoms on API server side, but SIEM shows data gap | Restore SIEM connectivity. For webhook mode, consider switching to file-based shipping with a separate shipper for reliability |
| Alert rule too broad | Constant alerts for legitimate operations (e.g., CI/CD service accounts exec into pods) | Alert fatigue; team starts ignoring audit alerts | Add exclusions for known service accounts. Use separate alert rules for human users vs service accounts |

## When to Consider a Managed Alternative

**Transition point:** Building an audit log pipeline (policy design, log shipping, SIEM integration, alert rules, storage management) requires 20-40 hours of initial setup and ongoing maintenance. The audit policy needs updates as your cluster evolves. The SIEM needs capacity planning. The alert rules need tuning to reduce noise. For teams without a dedicated security engineer, this is a significant and permanent operational commitment.

**Recommended providers:**

- **[Grafana Cloud](https://grafana.com/cloud):** Managed Loki for audit log storage with built-in LogQL querying. Eliminates the need to run Loki infrastructure. Includes alerting via [Grafana](https://grafana.com) Alerting with no additional tooling.
- **[Axiom](https://axiom.co):** Managed log aggregation with zero-configuration ingestion. Supports direct webhook ingestion from the Kubernetes API server, eliminating the need for a separate log shipper.
- **[Sysdig](https://sysdig.com):** Kubernetes-native security platform that includes audit log analysis with pre-built detection rules. Provides the top 10 alert patterns from this article as out-of-the-box detections.

**What you still control:** The audit policy (what to log at which level) remains your configuration regardless of where logs are stored. The SIEM provider handles storage, indexing, and querying infrastructure. You define the alert rules and response procedures.

**Premium content pack:** Alert rule pack for Kubernetes audit events, including Prometheus alerting rules, Grafana dashboard for audit log visualization, and LogQL queries for the top 10 suspicious patterns. Includes a Fluent Bit configuration for shipping audit logs to Loki, Elasticsearch, and S3.


## Related Articles

- [AI Data Leakage Prevention: Input Filtering, Output Scanning, and Audit Trails](/articles/kubernetes/ai-data-leakage-prevention/)
- [Runtime Security with Falco on Kubernetes: Rules, Tuning, and Response Automation](/articles/kubernetes/falco-runtime-security/)
- [Kubernetes Network Policies That Actually Work: From Default Deny to Microsegmentation](/articles/kubernetes/kubernetes-network-policies/)
- [Seccomp Profiles for Production Workloads: Writing, Testing, and Deploying Custom Profiles](/articles/kubernetes/seccomp-profiles/)
- [Kubernetes RBAC Design Patterns: Least Privilege Without Paralysing Developers](/articles/kubernetes/rbac-design-patterns/)
