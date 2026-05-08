---
title: "Securing the OpenTelemetry Collector: Deployment Patterns, TLS, and Access Control"
description: "The OpenTelemetry Collector processes every trace, metric, and log in your infrastructure. A compromised Collector leaks all observability data."
slug: "otel-collector-hardening"
date: 2026-04-15
lastmod: 2026-04-15
category: "observability"
tags: ["opentelemetry", "otel-collector", "tls", "deployment", "kubernetes", "security"]
personas: ["sre", "platform-engineer", "security-engineer"]
article_number: 141
difficulty: "intermediate"
estimated_reading_time: 18
provider_bridges:
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
  - name: "Axiom"
    id: 112
    category: "observability"
published: true
layout: article.njk
permalink: "/articles/observability/otel-collector-hardening/index.html"
---

# Securing the [OpenTelemetry](https://opentelemetry.io) Collector: Deployment Patterns, TLS, and Access Control

## Problem

The OpenTelemetry Collector sits at the center of every modern observability pipeline. Every trace, metric, and log passes through it. If an attacker compromises the Collector, they gain access to all observability data in your infrastructure, including request payloads, user identifiers, internal service names, database query patterns, and authentication flow details. A Collector with default configuration accepts data from any source, runs as root, exposes health endpoints on the same network as data ingestion, and stores secrets in plaintext config files.

The specific gaps in a default deployment:

- **No transport encryption.** The default OTLP receiver listens on plaintext gRPC (port 4317) and HTTP (port 4318). Any process on the network can intercept observability data in transit, including span attributes that may contain PII, authentication tokens, or internal service topology.
- **No sender authentication.** Without mTLS, the Collector accepts data from any client that can reach it. An attacker with network access can inject false telemetry, poison metrics, or flood the pipeline to cause resource exhaustion.
- **Overprivileged container.** Default Helm chart deployments often run the Collector as root with a writable filesystem. A container escape or RCE vulnerability in the Collector binary gives the attacker root access to the node.
- **Flat network exposure.** Without NetworkPolicy, every pod in the cluster (and potentially external traffic) can send data to the Collector. The health check and zpages debug endpoints are reachable on the same interface as the data pipeline.
- **No resource limits.** A burst of telemetry data (malicious or accidental) causes the Collector to consume unbounded memory, eventually OOM-killing the pod and dropping all observability data.

This article covers deployment pattern selection, TLS and mTLS configuration, Kubernetes security hardening, network isolation, and resource limiting for the OpenTelemetry Collector.

**Target systems:** [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/) v0.96+ deployed on Kubernetes 1.28+. Applies to both the core and contrib distributions.

## Threat Model

- **Adversary:** An attacker who has gained initial access to a workload in the cluster (compromised pod, supply chain attack on a dependency) or has network-level access to the Collector's ingestion ports. They aim to exfiltrate observability data, inject false telemetry to mask an ongoing attack, or pivot through the Collector to other infrastructure.
- **Blast radius:** Without hardening, the Collector exposes the complete topology of your services, request patterns, error rates, and any sensitive attributes attached to spans or logs. An attacker can read this data passively by sniffing unencrypted OTLP traffic or actively by querying debug endpoints. With the hardening in this article, the Collector only accepts authenticated TLS connections from known application namespaces, runs with minimal privileges, and isolates management endpoints from the data plane.

## Configuration

### Deployment Pattern Selection

Three deployment patterns exist for the OpenTelemetry Collector on Kubernetes. Each carries different security trade-offs.

**Sidecar** (one Collector per pod): The Collector shares the pod network namespace with the application. Traffic between the app SDK and Collector stays on localhost, eliminating network exposure. The downside is resource overhead (every pod runs a Collector container) and configuration sprawl across many sidecar definitions.

**DaemonSet** (one Collector per node): The Collector runs once per node and receives data from all pods on that node. This reduces resource overhead compared to sidecars but means OTLP traffic crosses the pod network. Requires TLS to protect data in transit between application pods and the DaemonSet Collector.

**Gateway** (centralized Collector deployment): A standalone Deployment (typically 2-3 replicas) receives data from all nodes. This centralizes configuration and enables advanced processing (tail sampling, routing) but creates a single aggregation point. All OTLP traffic crosses the cluster network. TLS and mTLS are mandatory.

For most production deployments, use a **two-tier architecture**: DaemonSet Collectors on each node for ingestion and batching, forwarding to a Gateway Collector for tail sampling and export. This isolates the ingestion layer from the export layer.

### TLS on OTLP Receivers

Configure TLS on both gRPC and HTTP receivers. This config enables server-side TLS with mTLS for client authentication:

```yaml
# otel-collector-config.yaml
# Collector configuration with TLS on all receivers.
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
        tls:
          cert_file: /etc/otel/certs/tls.crt
          key_file: /etc/otel/certs/tls.key
          client_ca_file: /etc/otel/certs/ca.crt
          # Require client certificates (mTLS).
          require_client_cert: true
          min_version: "1.3"
      http:
        endpoint: 0.0.0.0:4318
        tls:
          cert_file: /etc/otel/certs/tls.crt
          key_file: /etc/otel/certs/tls.key
          client_ca_file: /etc/otel/certs/ca.crt
          require_client_cert: true
          min_version: "1.3"

processors:
  # Limit memory consumption to prevent OOM.
  memory_limiter:
    check_interval: 1s
    limit_mib: 512
    spike_limit_mib: 128

  batch:
    send_batch_size: 8192
    timeout: 5s

exporters:
  otlphttp:
    endpoint: https://tempo.observability.svc.cluster.local:4318
    tls:
      cert_file: /etc/otel/certs/tls.crt
      key_file: /etc/otel/certs/tls.key
      ca_file: /etc/otel/certs/ca.crt

extensions:
  # Health check on a separate port, not exposed externally.
  health_check:
    endpoint: 127.0.0.1:13133

service:
  extensions: [health_check]
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [otlphttp]
    metrics:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [otlphttp]
    logs:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [otlphttp]
```

The `min_version: "1.3"` setting enforces TLS 1.3, which removes support for older cipher suites with known weaknesses. The `require_client_cert: true` setting enables mTLS, meaning application SDKs must present a valid client certificate signed by the CA specified in `client_ca_file`.

### mTLS Between Application SDKs and the Collector

Configure the OTel SDK in your application to present a client certificate when connecting to the Collector:

```yaml
# Environment variables for the OTel SDK (set in the application's Deployment).
# These configure the SDK's OTLP exporter to use mTLS.
env:
  - name: OTEL_EXPORTER_OTLP_ENDPOINT
    value: "https://otel-collector.observability.svc.cluster.local:4317"
  - name: OTEL_EXPORTER_OTLP_CERTIFICATE
    value: "/etc/otel/certs/ca.crt"
  - name: OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE
    value: "/etc/otel/certs/tls.crt"
  - name: OTEL_EXPORTER_OTLP_CLIENT_KEY
    value: "/etc/otel/certs/tls.key"
```

Use [cert-manager](https://cert-manager.io) to automate certificate issuance and rotation.

### Kubernetes Deployment with Security Context

```yaml
# otel-collector-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: otel-collector
  namespace: observability
  labels:
    app: otel-collector
spec:
  replicas: 2
  selector:
    matchLabels:
      app: otel-collector
  template:
    metadata:
      labels:
        app: otel-collector
    spec:
      serviceAccountName: otel-collector
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        runAsGroup: 65534
        fsGroup: 65534
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: otel-collector
          image: otel/opentelemetry-collector-contrib:0.96.0
          args: ["--config=/etc/otel/config.yaml"]
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          ports:
            - containerPort: 4317
              name: otlp-grpc
              protocol: TCP
            - containerPort: 4318
              name: otlp-http
              protocol: TCP
            # Health check port is NOT listed here.
            # It binds to 127.0.0.1 only, so no containerPort needed.
          resources:
            requests:
              cpu: 250m
              memory: 512Mi
            limits:
              cpu: "1"
              memory: 1Gi
          volumeMounts:
            - name: config
              mountPath: /etc/otel
              readOnly: true
            - name: certs
              mountPath: /etc/otel/certs
              readOnly: true
            - name: tmp
              mountPath: /tmp
          livenessProbe:
            httpGet:
              path: /
              port: 13133
              host: 127.0.0.1
            initialDelaySeconds: 10
            periodSeconds: 15
          readinessProbe:
            httpGet:
              path: /
              port: 13133
              host: 127.0.0.1
            initialDelaySeconds: 5
            periodSeconds: 10
      volumes:
        - name: config
          configMap:
            name: otel-collector-config
        - name: certs
          secret:
            secretName: otel-collector-tls
        - name: tmp
          emptyDir:
            sizeLimit: 50Mi
```

Key hardening decisions in this manifest:

- **`runAsNonRoot: true` and `runAsUser: 65534`** run the Collector as the `nobody` user. If an attacker exploits an RCE in the Collector, they land as an unprivileged user.
- **`readOnlyRootFilesystem: true`** prevents the attacker from writing binaries, scripts, or persistence mechanisms to the container filesystem. The `/tmp` emptyDir provides writable space where needed.
- **`capabilities.drop: [ALL]`** removes all Linux capabilities. The Collector does not need `NET_BIND_SERVICE` because it listens on ports above 1024.
- **`automountServiceAccountToken: false`** prevents the Collector from accessing the Kubernetes API. Unless your Collector uses the `k8sattributes` processor, it has no reason to talk to the API server.
- **`seccompProfile: RuntimeDefault`** applies the container runtime's default seccomp profile, blocking dangerous syscalls.

### NetworkPolicy for Ingestion Isolation

Restrict which namespaces can send OTLP data to the Collector. This policy allows traffic only from namespaces labeled `otel-send: "true"`:

```yaml
# otel-collector-networkpolicy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: otel-collector-ingress
  namespace: observability
spec:
  podSelector:
    matchLabels:
      app: otel-collector
  policyTypes:
    - Ingress
  ingress:
    # Allow OTLP traffic only from labeled namespaces.
    - from:
        - namespaceSelector:
            matchLabels:
              otel-send: "true"
      ports:
        - port: 4317
          protocol: TCP
        - port: 4318
          protocol: TCP
    # Allow egress probes from the Collector's own pod (localhost health check).
    # No rule needed here because localhost traffic bypasses NetworkPolicy.
```

Label each application namespace that should be allowed to send telemetry:

```bash
kubectl label namespace app-frontend otel-send=true
kubectl label namespace app-backend otel-send=true
kubectl label namespace payment-service otel-send=true
```

This prevents pods in namespaces you have not explicitly approved (including `default`, `kube-system`, or any attacker-controlled namespace) from reaching the Collector.

### Health Check Endpoint Isolation

The Collector's health check extension (`health_check`) and debug extensions (`zpages`, `pprof`) must not be reachable from outside the pod. In the Collector config above, the health check binds to `127.0.0.1:13133`. This means only processes inside the same pod can reach it. Do not create a Kubernetes Service for this port.

```yaml
# otel-collector-service.yaml
# Only expose OTLP ports. Do NOT expose 13133.
apiVersion: v1
kind: Service
metadata:
  name: otel-collector
  namespace: observability
spec:
  selector:
    app: otel-collector
  ports:
    - name: otlp-grpc
      port: 4317
      targetPort: 4317
      protocol: TCP
    - name: otlp-http
      port: 4318
      targetPort: 4318
      protocol: TCP
```

### Configuration File Permissions and Secrets Handling

The Collector configuration file may reference secrets (API keys for SaaS backends, bearer tokens). Never embed secrets directly in the ConfigMap. Instead, use environment variable substitution:

```yaml
# In the Collector config, reference secrets via env vars.
exporters:
  otlphttp:
    endpoint: https://api.observability-vendor.example.com
    headers:
      Authorization: "Bearer ${env:OTEL_EXPORTER_API_KEY}"
```

```yaml
# In the Deployment, inject the secret as an environment variable.
env:
  - name: OTEL_EXPORTER_API_KEY
    valueFrom:
      secretKeyRef:
        name: otel-collector-secrets
        key: api-key
```

Mount the ConfigMap and Secrets as read-only volumes (already done in the Deployment manifest above). For GitOps workflows, encrypt secrets with [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets) or [SOPS](https://github.com/getsops/sops) before committing.

## Expected Behaviour

After applying these configurations:

| Signal | Before Hardening | After Hardening |
|--------|------------------|-----------------|
| OTLP traffic encryption | Plaintext gRPC/HTTP | TLS 1.3 with mTLS on all receivers |
| Sender authentication | Any client accepted | Only clients with valid certificates from the trusted CA |
| Container privileges | Root user, writable filesystem, all capabilities | nobody user (65534), read-only root filesystem, all capabilities dropped |
| Network access | All pods and external traffic can reach Collector | Only namespaces with `otel-send=true` label on ports 4317/4318 |
| Health endpoints | Reachable from cluster network | Bound to 127.0.0.1, not exposed via Service |
| Memory limits | Unbounded | 512 MiB soft limit (memory_limiter), 1 Gi hard limit (Kubernetes) |
| Secrets in config | Plaintext in ConfigMap | Environment variable substitution from Kubernetes Secrets |

## Trade-offs

| Hardening Measure | Security Benefit | Operational Cost | Mitigation |
|-------------------|-----------------|------------------|------------|
| mTLS on receivers | Prevents unauthorized data injection and eavesdropping | Certificate management overhead; every application needs a client cert | Use cert-manager with auto-rotation. Set certificate lifetimes to 24-72 hours for automated workloads. |
| `readOnlyRootFilesystem` | Prevents attacker persistence and binary drops | Some Collector extensions (filelog receiver, file_storage) need writable paths | Mount specific emptyDir volumes at required paths. Avoid the filelog receiver on the Gateway Collector. |
| NetworkPolicy restrictions | Limits blast radius to approved namespaces only | New namespaces must be explicitly labeled before they can send telemetry | Add `otel-send=true` labeling to your namespace provisioning automation. |
| `memory_limiter` processor | Prevents OOM from telemetry floods | Drops data when limits are hit; you lose observability during spikes | Set `spike_limit_mib` to absorb bursts. Use the `batch` processor after `memory_limiter` to smooth throughput. Monitor `otelcol_processor_refused_spans` metric. |
| Sidecar deployment pattern | No network exposure for OTLP traffic (localhost only) | Higher resource consumption; config changes require pod restarts | Use the sidecar pattern only for the most sensitive workloads (payment, auth). Use DaemonSet for general workloads. |
| Health check on localhost | Prevents information disclosure about Collector internals | Kubernetes liveness/readiness probes must use `host: 127.0.0.1` | Kubelet runs probes from the node, which can reach 127.0.0.1 inside the pod via the pod's network namespace. This works by default. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| TLS certificate expired | All application SDKs fail to connect; no telemetry flows | `otelcol_receiver_refused_spans` spikes; application logs show TLS handshake errors | Use cert-manager with automatic renewal at 2/3 of certificate lifetime. Set alerts on certificate expiry at 7 days and 24 hours. |
| mTLS CA mismatch | New application namespace cannot send telemetry; Collector rejects client certs | Application logs show "certificate signed by unknown authority" | Ensure all client certificates are signed by the same CA referenced in `client_ca_file`. Distribute the CA cert through a shared Secret or ConfigMap. |
| memory_limiter triggers data drop | Gaps in traces and metrics during high-throughput periods | `otelcol_processor_dropped_spans` and `otelcol_processor_dropped_metric_points` increase | Increase `limit_mib` and pod memory limits together. Add horizontal pod autoscaling to the Gateway Collector. |
| NetworkPolicy blocks legitimate traffic | New service deployed in unlabeled namespace; no telemetry from that service | Missing data in dashboards; `otelcol_receiver_accepted_spans` does not increase when new service generates traffic | Add namespace labeling to your provisioning pipeline. Create an alert on namespaces missing the `otel-send` label. |
| readOnlyRootFilesystem breaks Collector | Collector crashes on startup with "permission denied" writing to a path | Pod in CrashLoopBackOff; container logs show filesystem write errors | Identify the path the Collector needs to write to. Add an emptyDir volume mount at that specific path. Do not disable readOnlyRootFilesystem. |
| Collector ServiceAccount has excess permissions | Attacker uses Collector pod to query Kubernetes API for cluster reconnaissance | Audit logs show API requests from the `otel-collector` ServiceAccount for resources it should not access | Set `automountServiceAccountToken: false`. If the `k8sattributes` processor is needed, create a Role with only pods/namespaces read access, not a ClusterRole. |

## When to Consider a Managed Alternative

Self-managed Collector hardening requires TLS certificate infrastructure, NetworkPolicy maintenance, security context tuning, and ongoing monitoring of Collector health and resource usage (4-8 hours/month for a multi-cluster deployment).

- **[Grafana Cloud](https://grafana.com/cloud):** Managed OTel-compatible ingestion endpoints. Your applications send OTLP directly to Grafana Cloud over TLS with API key authentication. Eliminates the need to run and secure your own Collector for the export layer. You may still run a local Collector for preprocessing, but the security surface area is significantly reduced.
- **[Axiom](https://axiom.co):** Native OTLP ingestion over HTTPS with API token authentication. No Collector required for basic pipelines. For advanced processing (filtering, sampling), Axiom provides a managed Collector option that handles TLS termination and access control.

## Related Articles

- [OpenTelemetry for Security: Distributed Tracing of Authentication and Authorization Flows](/articles/observability/otel-security-tracing/)
- [Prometheus Security Metrics: Instrumenting Your Hardening Progress](/articles/observability/prometheus-security-metrics/)
- [Building a Security Audit Log Pipeline That Scales: auditd to Elasticsearch](/articles/observability/audit-log-pipeline/)
- [Centralized Logging Architecture for Security: Fluentd, Vector, and Loki Compared](/articles/observability/centralized-logging/)
- [mTLS in Service Mesh: Zero-Trust Networking Between Services](/articles/network/mtls-service-mesh/)
