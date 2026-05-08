---
title: "Kubernetes Events for Security: Detecting Threats Beyond the Audit Log"
description: "Kubernetes events surface OOMKilled pods, image pull failures, CrashLoopBackOff cycles, and node pressure before an attacker's activity reaches audit logs — here's how to collect, ship, and alert on them."
slug: kubernetes-events-security
date: 2026-05-07
lastmod: 2026-05-07
category: observability
tags:
  - kubernetes
  - events-monitoring
  - cluster-security
  - admission-control
  - threat-detection
personas:
  - security-engineer
  - platform-engineer
article_number: 564
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/observability/kubernetes-events-security/
---

# Kubernetes Events for Security: Detecting Threats Beyond the Audit Log

## Problem

Most Kubernetes security monitoring starts and ends with the audit log. The API server audit trail is essential, but it records what actors did to the API — who created a pod, who read a secret, who patched a role binding. It does not tell you what happened to the resulting workloads after they were created.

[Kubernetes events](https://kubernetes.io/docs/reference/kubernetes-api/cluster-resources/event-v1/) fill that gap. An Event is a Kubernetes object written by the kubelet, the scheduler, the controller manager, and admission webhooks whenever something noteworthy happens to a cluster resource. Events are stored in etcd (by default for one hour) and emitted at the cluster object level — they carry a `Reason`, a `Message`, an `InvolvedObject`, and a `Type` (`Normal` or `Warning`).

The security-relevant signal buried in those events is significant:

- **OOMKilled pods** are the first indicator of a crypto miner exceeding its memory allocation or of a DoS condition being achieved.
- **CrashLoopBackOff on security-critical pods** (admission webhooks, policy controllers, certificate managers) signals a potential control plane availability attack.
- **Image pull failures** with unexpected registry addresses indicate supply chain interference or image substitution attempts.
- **Node pressure and eviction events** expose resource exhaustion that an attacker may be deliberately inducing.
- **Admission webhook denials** reveal privilege escalation attempts that were blocked but not logged anywhere else by default.

The challenge: events are ephemeral (gone after one hour by default), scattered across namespaces, and not shipped anywhere unless you build the pipeline yourself.

**Target systems:** Kubernetes clusters (self-managed or managed EKS/GKE/AKS). [Prometheus](https://prometheus.io) with kube-state-metrics. [Elasticsearch](https://www.elastic.co/elasticsearch) or [Loki](https://grafana.com/oss/loki/) as the events backend.

## Threat Model

- **Adversary:** An attacker who has deployed a workload to the cluster (through a compromised image, a misused service account, or a misconfigured admission policy) and is now operating inside it. Their activity generates Events that the audit log does not capture: resource exhaustion, container restarts, failed network communication, and admission control blocks.
- **Blast radius:** Without event collection, security teams lose visibility into post-deployment attacker behaviour. An OOMKilled crypto miner restarts and keeps mining. A CrashLoopBackOff on a security webhook means all subsequent admission decisions fail open. Image substitution goes unnoticed because the pull failure reason is only in the Event object, not in any API audit record.

## Events vs Audit Logs: What Each Covers

| Signal | Kubernetes Events | Audit Log |
|--------|------------------|-----------|
| API call actor and verb | No | Yes |
| Pod OOMKilled | Yes (kubelet emits `OOMKilling`) | No |
| Container restart count | Via CrashLoopBackOff event | No |
| Image pull failure with registry URL | Yes (`Failed` / `ErrImagePull`) | Partially (only the create call) |
| Node memory/disk pressure | Yes (NodeCondition events) | No |
| Admission webhook denial | Yes (webhook emits Warning event) | Yes (only the rejected request) |
| Scheduler placement decisions | Yes (`FailedScheduling`) | No |
| Liveness/readiness probe failures | Yes (`Unhealthy`) | No |

The two sources are complementary, not redundant. Disable either and you have blind spots.

## Configuration

### Deploying Kubernetes Event Exporter

The [kubernetes-event-exporter](https://github.com/resmoio/kubernetes-event-exporter) watches the Kubernetes Events API and ships events to external backends. It runs as a single Deployment and requires only read access to Events across all namespaces.

```yaml
# event-exporter-rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: event-exporter
  namespace: monitoring
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: event-exporter
rules:
  - apiGroups: [""]
    resources: ["events", "namespaces", "pods", "nodes"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: event-exporter
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: event-exporter
subjects:
  - kind: ServiceAccount
    name: event-exporter
    namespace: monitoring
```

```yaml
# event-exporter-config.yaml
# Ship Warning events and all events from security namespaces to Elasticsearch.
logLevel: warn
logFormat: json
route:
  routes:
    # High-priority: all Warning events go to the security index.
    - match:
        - type: Warning
      outputs:
        - security-es

    # All events from the policy-system namespace regardless of type.
    - match:
        - namespace: policy-system
        - namespace: cert-manager
        - namespace: kube-system
      outputs:
        - security-es

outputs:
  - name: security-es
    elasticsearch:
      hosts:
        - https://elasticsearch.internal:9200
      index: k8s-events-{namespace}-{.yyyy.MM.dd}
      username: "${ES_USER}"
      password: "${ES_PASSWORD}"
      tls:
        insecureSkipVerify: false
      # Enrich every event with cluster identity.
      fields:
        cluster: production
        datacenter: eu-west-1
```

```yaml
# event-exporter-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: event-exporter
  namespace: monitoring
spec:
  replicas: 1
  selector:
    matchLabels:
      app: event-exporter
  template:
    metadata:
      labels:
        app: event-exporter
    spec:
      serviceAccountName: event-exporter
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: event-exporter
          image: ghcr.io/resmoio/kubernetes-event-exporter:v1.7
          args:
            - -conf=/data/config.yaml
          resources:
            requests:
              cpu: 10m
              memory: 64Mi
            limits:
              cpu: 100m
              memory: 128Mi
          env:
            - name: ES_USER
              valueFrom:
                secretKeyRef:
                  name: event-exporter-creds
                  key: username
            - name: ES_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: event-exporter-creds
                  key: password
          volumeMounts:
            - name: config
              mountPath: /data
              readOnly: true
      volumes:
        - name: config
          configMap:
            name: event-exporter-config
```

### Shipping Events to Loki

If your observability stack uses [Grafana](https://grafana.com) with [Loki](https://grafana.com/oss/loki/) instead of Elasticsearch, the event exporter supports a Loki output directly:

```yaml
outputs:
  - name: loki-backend
    loki:
      streamLabels:
        cluster: production
        type: "{{ .Type }}"
        reason: "{{ .Reason }}"
        namespace: "{{ .Namespace }}"
      url: http://loki.monitoring:3100
      # Route only Warning events to reduce Loki ingest costs.
```

### Detecting Security-Relevant Events by Reason

The `Reason` field on a Kubernetes Event is the primary classification key. These are the reasons with security relevance:

| Reason | Source | Security Signal |
|--------|--------|-----------------|
| `OOMKilling` | kubelet | Pod exceeding memory limits — possible crypto miner or DoS |
| `BackOff` / `CrashLoopBackOff` | kubelet | Repeated container crashes — possible attack on security-critical controllers |
| `Failed` / `ErrImagePull` / `ImagePullBackOff` | kubelet | Image unavailable or substituted — supply chain anomaly |
| `Evicted` | kubelet | Pod evicted for resource pressure — possible resource exhaustion attack |
| `Unhealthy` | kubelet | Liveness or readiness probe failing — availability attack or compromised application |
| `FailedScheduling` | scheduler | Pod cannot be placed — resource starvation |
| `NodeNotReady` | node controller | Node degraded — infrastructure-level attack surface |
| `FailedCreate` | replication controller | Cannot create pods — admission control blocking or quota exceeded |
| `PolicyViolation` | OPA/Gatekeeper, Kyverno | Admission policy denied — privilege escalation attempt |

### Prometheus Alerting on Kubernetes Warning Events

[kube-state-metrics](https://github.com/kubernetes/kube-state-metrics) exposes the `kube_event_*` metrics family, which lets Prometheus query Warning events without requiring a separate event exporter for alerting purposes:

```yaml
# prometheus-k8s-event-alerts.yaml
groups:
  - name: kubernetes-security-events
    rules:

      # OOMKilled pods: potential crypto mining or memory-based DoS.
      - alert: PodOOMKilledSecurity
        expr: >
          sum by (namespace, pod, container) (
            kube_pod_container_status_last_terminated_reason{reason="OOMKilled"}
              * on(namespace, pod) group_left()
              kube_pod_labels
          ) > 0
        for: 2m
        labels:
          severity: warning
          detection_type: resource_exhaustion
        annotations:
          summary: >
            Pod {{ $labels.namespace }}/{{ $labels.pod }} container
            {{ $labels.container }} OOMKilled — investigate for crypto
            mining or memory exhaustion attack.

      # CrashLoopBackOff on admission webhook pods: policy enforcement failing.
      - alert: AdmissionWebhookCrashLoop
        expr: >
          kube_pod_container_status_waiting_reason{
            reason="CrashLoopBackOff",
            namespace=~"policy-system|opa-system|kyverno|cert-manager"
          } == 1
        for: 3m
        labels:
          severity: critical
          detection_type: control_plane_availability
        annotations:
          summary: >
            Admission webhook pod {{ $labels.namespace }}/{{ $labels.pod }}
            is in CrashLoopBackOff — policy enforcement may be degraded.
            Investigate for targeted disruption.

      # Image pull failures outside expected registries.
      - alert: UnexpectedImagePullFailure
        expr: >
          sum by (namespace, pod) (
            kube_pod_init_container_status_waiting_reason{reason="ImagePullBackOff"}
            or
            kube_pod_container_status_waiting_reason{reason="ImagePullBackOff"}
          ) > 0
        for: 5m
        labels:
          severity: warning
          detection_type: supply_chain
        annotations:
          summary: >
            ImagePullBackOff in {{ $labels.namespace }}/{{ $labels.pod }} —
            verify image registry matches approved sources and image digest
            has not been substituted.

      # Node memory pressure: early indicator of resource exhaustion attack.
      - alert: NodeMemoryPressureSecurity
        expr: >
          kube_node_status_condition{condition="MemoryPressure", status="true"} == 1
        for: 5m
        labels:
          severity: warning
          detection_type: resource_exhaustion
        annotations:
          summary: >
            Node {{ $labels.node }} is under memory pressure — check for
            runaway workloads, crypto miners, or fork bombs.

      # Admission policy violations: privilege escalation attempts blocked.
      - alert: AdmissionPolicyViolation
        expr: >
          sum by (namespace) (
            increase(
              apiserver_admission_webhook_rejection_count[10m]
            )
          ) > 5
        for: 1m
        labels:
          severity: warning
          detection_type: privilege_escalation
        annotations:
          summary: >
            {{ $value | humanize }} admission rejections in namespace
            {{ $labels.namespace }} in the last 10 minutes — possible
            privilege escalation probe.
```

### Detecting Image Changes via Events and Admission Webhooks

Running container image digest verification at two points catches both pre-deployment substitution and runtime tampering:

**Point 1: At admission time (Kyverno policy)**

```yaml
# kyverno-image-digest-policy.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-image-digest
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: check-image-digest
      match:
        any:
          - resources:
              kinds: ["Pod"]
              namespaces: ["production", "staging"]
      validate:
        message: >
          Images must be pinned by digest (sha256:...). Tag-only references
          allow silent image substitution without changing the manifest.
        pattern:
          spec:
            containers:
              - image: "*@sha256:*"
```

**Point 2: Post-deployment via kube-state-metrics image label comparison**

```promql
# Detect pods running images without a digest pin in non-dev namespaces.
# kube-state-metrics exposes the image reference as a label.
kube_pod_container_info{
  namespace!~"dev|sandbox",
  image!~".*@sha256:.*"
}
```

When this query returns results, a pod in a sensitive namespace is running a mutable tag reference. Any event with `Reason=Pulled` and a different image ID than the previous pull indicates the tag was silently updated (or replaced).

### kube-state-metrics Security Queries

Beyond event counting, kube-state-metrics exposes cluster state that reveals security misconfigurations and anomalies:

```promql
# Services exposed as LoadBalancer in unexpected namespaces.
# Attackers create LoadBalancer services to exfiltrate data or establish C2.
kube_service_spec_type{
  type="LoadBalancer",
  namespace!~"ingress-nginx|istio-system|load-balancer"
}

# Pods running as root (UID 0) in production.
kube_pod_container_info * on(pod, namespace) group_left()
  kube_pod_spec_containers_securitycontext_runasuser{
    run_as_user="0",
    namespace=~"production|staging"
  }

# Pods with host network access enabled.
kube_pod_spec_volumes_persistentvolumeclaims_readonly{} unless
kube_pod_info{host_network="false"}
```

```yaml
# Alert on unexpected LoadBalancer services (C2 channel or data exfiltration).
- alert: UnexpectedLoadBalancerService
  expr: >
    kube_service_spec_type{
      type="LoadBalancer",
      namespace!~"ingress-nginx|istio-system|gateway-system"
    } == 1
  for: 5m
  labels:
    severity: high
    detection_type: data_exfiltration
  annotations:
    summary: >
      LoadBalancer service {{ $labels.namespace }}/{{ $labels.service }}
      appeared outside approved namespaces — verify this is intentional
      and not an attacker-controlled egress channel.
```

### EKS: EventBridge for GuardDuty Security Findings

On EKS, [Amazon GuardDuty](https://aws.amazon.com/guardduty/) emits EKS-specific findings (runtime monitoring, audit log findings) as [EventBridge](https://aws.amazon.com/eventbridge/) events. Route these to your SIEM alongside Kubernetes Events:

```json
{
  "EventBusName": "default",
  "EventPattern": {
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "type": [
        { "prefix": "Kubernetes.Backdoor" },
        { "prefix": "Kubernetes.Execution" },
        { "prefix": "Kubernetes.PrivilegeEscalation" },
        { "prefix": "Kubernetes.Impact" },
        { "prefix": "Runtime.Kubernetes" }
      ]
    }
  }
}
```

```hcl
# Terraform: EventBridge rule routing EKS GuardDuty findings to Kinesis Firehose.
resource "aws_cloudwatch_event_rule" "guardduty_eks" {
  name           = "guardduty-eks-security-findings"
  event_bus_name = "default"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Kubernetes." },
        { prefix = "Runtime.Kubernetes" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "to_firehose" {
  rule      = aws_cloudwatch_event_rule.guardduty_eks.name
  target_id = "SendToFirehose"
  arn       = aws_kinesis_firehose_delivery_stream.security_events.arn
  role_arn  = aws_iam_role.eventbridge_firehose.arn
}
```

Key EKS GuardDuty finding types to prioritise:

| Finding Type | Security Signal |
|---|---|
| `Kubernetes.PrivilegeEscalation:Kubernetes/PrivilegedContainer` | Privileged pod created |
| `Kubernetes.Execution:Kubernetes/ExecInKubeSystemPod` | Exec into kube-system pod |
| `Kubernetes.Impact:Kubernetes/MaliciousIPCaller` | API calls from threat intel IPs |
| `Runtime.Kubernetes/CryptoCurrencyMiningActivity` | Mining process detected at runtime |
| `Kubernetes.Backdoor:Kubernetes/ChangeDefaultServiceAccount` | Default service account modified |

### Privilege Escalation via Pod Security Admission Events

[Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/) (PSA), which replaced PodSecurityPolicy, emits audit annotations and Warning events when a pod violates the configured level. Collect these to detect privilege escalation probes:

```yaml
# Namespace annotation to enforce the restricted policy level.
# PSA emits a Warning event and an audit annotation on any violation.
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    # Warn and audit at baseline so you see violation attempts before enforce.
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
```

PSA violations appear in two places: the API server audit log (as an annotation on the create request) and as Warning Events on the namespace. The Event-based signal is more accessible for real-time alerting without parsing the full audit log:

```bash
# Query for PSA violation events in the last hour.
kubectl get events \
  --all-namespaces \
  --field-selector type=Warning \
  -o json | \
  jq '.items[] | select(
    .reason == "FailedCreate" and
    (.message | test("violates PodSecurity"))
  ) | {
    namespace: .involvedObject.namespace,
    message: .message,
    timestamp: .lastTimestamp
  }'
```

Pair this with a Prometheus alert on admission webhook rejection rates (shown in the previous section) to catch systematic escalation probing.

## Expected Behaviour

- All `Warning` Kubernetes events shipped to Elasticsearch or Loki within 60 seconds of emission
- OOMKilled containers in production namespaces generate a `warning` severity alert within 2 minutes
- CrashLoopBackOff on admission webhook pods triggers a `critical` alert within 3 minutes
- ImagePullBackOff persisting beyond 5 minutes creates a `warning` alert with the pod reference
- Unexpected `LoadBalancer` services generate a `high` severity alert within 5 minutes
- EKS GuardDuty EKS findings routed to SIEM within 30 seconds via EventBridge and Firehose
- Pod Security Admission violation events queryable in central log store within 60 seconds

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| Ship only Warning events by default | Reduces event exporter load and storage costs by 60-80% | Normal events may contain relevant context for an incident (e.g., successful image pulls preceding a pull failure) | Add Normal events for namespaces in scope (cert-manager, policy-system). Retain Normal events for 24 hours locally via a separate lower-priority pipeline. |
| 1-hour default event TTL in etcd | Kubernetes events disappear before you can investigate manually | Gap between event emission and alert response may exceed 1 hour | Event exporter persists events to external storage immediately. The 1-hour limit only affects the Kubernetes API (`kubectl get events`). |
| kube-state-metrics for alerting (not a dedicated event consumer) | Simpler stack — one fewer component | kube-state-metrics does not expose all Event fields (Reason, Message). It exposes derived metrics from object state. | Use event exporter for full Event content in SIEM. Use kube-state-metrics for Prometheus alerting where metric labels are sufficient. |
| Enforcing image digest pinning at admission | Prevents tag-based image substitution entirely | Breaks workflows that use mutable tags (dev environments, CI) | Apply the digest requirement only to production and staging namespaces. Exclude `dev` and `sandbox` namespaces from the Kyverno policy scope. |
| EventBridge + Firehose for EKS findings | Managed, low-latency delivery path | Firehose delivery adds up to 60s buffering by default | Set Firehose buffer interval to 60 seconds (minimum). For lower latency, route through EventBridge directly to Lambda and forward to SIEM. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Event exporter pod crashloops | Events stop arriving in SIEM; alerts stop firing | Alert on `absent(kube_pod_container_status_running{pod=~"event-exporter.*"})` | Check RBAC permissions (ClusterRole must include Events watch). Check Elasticsearch/Loki connectivity from the pod. |
| etcd event TTL expires before exporter processes | Events missing in SIEM for a time window | Gap in event timestamps in SIEM; compare to kube-apiserver uptime | Increase event exporter resource limits. Ensure exporter keeps up with event rate (watch lag metric in exporter logs). |
| kube-state-metrics not scraping all namespaces | Alert coverage gaps for certain namespaces | Cross-check namespaces in Prometheus with `kubectl get ns` | Check kube-state-metrics namespace selector configuration. Default is all namespaces; a restrictive selector silently drops data. |
| PSA in warn-only mode silently passes violations | Escalation attempts are logged but not blocked | PSA violation events still emitted; check for recurring violations from the same workload | Promote namespace from `warn` to `enforce` for the violated policy. Track violation trends — repeated identical violations indicate a persistent misconfigured workload that needs remediation. |
| GuardDuty EKS runtime monitoring not enabled | No `Runtime.Kubernetes.*` findings even when miners are active | GuardDuty console shows `Runtime Monitoring` as disabled | Enable EKS runtime monitoring in GuardDuty and deploy the security agent DaemonSet via an EKS add-on. This is separate from audit log monitoring. |

## When to Consider a Managed Alternative

Self-managed Kubernetes event collection requires event exporter deployment, RBAC configuration, external storage provisioning, and alert rule maintenance (2-3 hours/month).

- **[Sysdig](https://sysdig.com):** Kubernetes event analysis integrated with runtime security findings. Correlates OOMKills with process execution events to distinguish crypto mining from legitimate memory pressure. Pre-built dashboards for Event-based security monitoring.
- **[Datadog](https://www.datadoghq.com):** Kubernetes Event collection built into the cluster agent. No separate event exporter required. Event search integrated with traces and metrics for cross-signal correlation.
- **[Grafana Cloud](https://grafana.com/cloud):** Managed Loki backend for event storage. Pre-built Grafana dashboards for Kubernetes Warning Event analysis. Integrates with Alertmanager for Prometheus-based alerting on kube-state-metrics.

## Related Articles

- [Kubernetes Audit Log Pipeline Design: From API Server to SIEM](/articles/observability/k8s-audit-log-design/)
- [Crypto Mining Detection: CPU Patterns, Network Signatures, and Automated Response](/articles/observability/crypto-mining-detection/)
- [Container Escape Detection: Runtime Signals, Kernel Indicators, and Response Automation](/articles/observability/container-escape-detection/)
- [Falco Security Rules: Writing and Tuning Runtime Detection for Containers](/articles/observability/falco-security-rules/)
- [kube-bench: CIS Kubernetes Benchmark Automation](/articles/kubernetes/kube-bench-cis-benchmark/)
