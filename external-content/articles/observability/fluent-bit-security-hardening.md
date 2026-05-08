---
title: "Fluent Bit Security Hardening: Securing Log Collection Pipelines in Kubernetes"
description: "Fluent Bit runs as a privileged DaemonSet that reads every pod log on every node. A misconfigured Fluent Bit deployment leaks PII, ships logs to the wrong destination, and provides an exfiltration vector. Harden RBAC, mTLS output, PII scrubbing, and routing controls before attackers reach your log pipeline."
slug: fluent-bit-security-hardening
date: 2026-05-07
lastmod: 2026-05-07
category: observability
tags:
  - fluent-bit
  - log-collection
  - pipeline-security
  - tls
  - kubernetes-logging
personas:
  - security-engineer
  - platform-engineer
article_number: 542
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/observability/fluent-bit-security-hardening/
---

# Fluent Bit Security Hardening: Securing Log Collection Pipelines in Kubernetes

## Problem

Fluent Bit is the dominant lightweight log collector in Kubernetes environments. Its low memory footprint — typically under 10 MB resident — and native Kubernetes metadata enrichment make it the default DaemonSet choice for shipping container logs to Elasticsearch, Loki, OpenSearch, and cloud-managed logging services. That ubiquity, combined with the privileges it requires to do its job, makes Fluent Bit one of the most consequential components in a Kubernetes security posture.

A default Fluent Bit DaemonSet deployment presents several specific risks:

- **Reads every container log on the node.** Fluent Bit mounts `/var/log/containers` and `/var/log/pods` from the host. Any log line emitted by any container — including application logs that accidentally contain passwords, JWT tokens, API keys, or PII — passes through the Fluent Bit process. A compromised or misconfigured Fluent Bit instance is a comprehensive data exfiltration point.
- **Ships logs over plaintext by default.** Without explicit TLS configuration in the output plugin, log data travels unencrypted from the node to the backend. On-path attackers — a rogue pod exploiting a CNI vulnerability, a compromised switch, or a cloud VPC misconfiguration — can intercept the entire log stream.
- **Exposes a management HTTP server.** Fluent Bit's built-in HTTP server (default port 2020) exposes `/api/v1/metrics`, `/api/v1/reload`, and health endpoints. Without binding restrictions, this interface is reachable from within the cluster and can be used to inspect or reload Fluent Bit's configuration remotely.
- **Runs with excessive RBAC permissions.** Helm chart defaults often grant the Fluent Bit ServiceAccount broad read access to the Kubernetes API, including access to Secrets and ConfigMaps, which are not required for log collection.
- **Forwards PII and sensitive fields without scrubbing.** Fluent Bit collects raw log lines. Without explicit filter configuration, structured logs containing email addresses, credit card numbers, session tokens, and internal identifiers are forwarded verbatim to backends that may be less tightly controlled than the production cluster.
- **Has no CPU or memory limits.** A log volume spike — from a crashing application emitting thousands of error lines per second, or from a deliberate log-flood attack — causes an unlimited Fluent Bit pod to consume node resources, potentially interfering with workloads on the same node.

**Target systems:** Fluent Bit 3.x, Kubernetes DaemonSet deployment, outputs to Elasticsearch, Loki, OpenSearch, and cloud logging services.

## Threat Model

1. **Exfiltration via log plaintext transit:** An attacker with access to the cluster network intercepts unencrypted Fluent Bit output traffic. The log stream contains credentials, tokens, and user data logged by poorly instrumented applications.

2. **PII leakage to less-secure log destinations:** A Fluent Bit multi-output pipeline forwards all logs — including payment processing logs with PAN data and authentication logs with email addresses — to a development Elasticsearch cluster with relaxed access control, violating data residency and compliance requirements.

3. **RBAC over-permission exploitation:** A compromised pod leverages the Fluent Bit ServiceAccount token to read Kubernetes Secrets from the API, accessing database credentials and TLS private keys that have nothing to do with log collection.

4. **HTTP server config reload abuse:** An attacker with network access to Fluent Bit's port 2020 calls `/api/v1/reload` after modifying the ConfigMap, forcing Fluent Bit to load a new configuration that redirects the log stream to an attacker-controlled endpoint. In environments where the HTTP server is not bound to loopback, this requires only cluster-internal network access.

5. **Resource exhaustion DoS:** A misconfigured or deliberately crashing application floods stdout with 100,000+ lines per second. An unbounded Fluent Bit pod on the same node exhausts memory and CPU, causing the kubelet to evict production workloads.

6. **Config change exfiltration:** A malicious insider modifies the Fluent Bit ConfigMap to add a second output block shipping logs to an external endpoint. Without alerting on ConfigMap changes, this modification goes undetected for days or weeks.

## Configuration / Implementation

### Minimal ServiceAccount RBAC

The Fluent Bit Kubernetes filter needs to enrich log records with pod metadata — namespace, pod name, container name, labels. This requires read access to the Kubernetes API for pods. It does not require access to Secrets, ConfigMaps, Deployments, or any cluster-scoped resources beyond what is listed below.

Create a minimal ServiceAccount with a namespaced Role or a ClusterRole scoped to exactly the resources the Kubernetes filter needs:

```yaml
# serviceaccount.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: fluent-bit
  namespace: logging
automountServiceAccountToken: false  # prevent automatic mounting; use projected volume below
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: fluent-bit-read
rules:
  - apiGroups: [""]
    resources:
      - namespaces
      - pods
    verbs: ["get", "list", "watch"]
  # Do NOT add: secrets, configmaps, nodes/proxy, or any other resource
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: fluent-bit-read
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: fluent-bit-read
subjects:
  - kind: ServiceAccount
    name: fluent-bit
    namespace: logging
```

Audit your existing RBAC with `kubectl auth can-i --list --as=system:serviceaccount:logging:fluent-bit` before tightening. Remove any rules that grant access to Secrets, ConfigMaps, or cluster-scoped resources like ClusterRoles that were added by Helm chart defaults.

### Running Fluent Bit as Non-Root

The primary reason Fluent Bit runs as root in default deployments is access to the host `/var/log/containers` directory. On most Linux distributions the log files in this path are owned by root and readable only by root. Two approaches allow non-root operation:

**Option 1 — Change log file group ownership on the node (preferred for long-term deployments).** Configure containerd or the CRI to write log files with a supplemental group readable by a non-root GID. Then grant Fluent Bit that GID via `securityContext.runAsGroup` and `securityContext.supplementalGroups`.

**Option 2 — Use the `supplementalGroups` approach without changing the CRI.** Where log files are group-owned by `root` (GID 0), you cannot avoid root group. However, you can still drop all Linux capabilities and prevent privilege escalation:

```yaml
# DaemonSet securityContext
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 0          # required for /var/log access on default nodes
        fsGroup: 0
      containers:
        - name: fluent-bit
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
```

Even where `runAsGroup: 0` is necessary for log file access, dropping all capabilities and setting `allowPrivilegeEscalation: false` materially reduces the impact of a container breakout. The pod cannot acquire new privileges or use kernel capabilities to pivot to the host.

Always mount a writable `emptyDir` for Fluent Bit's state directory (position tracking files) when using `readOnlyRootFilesystem: true`:

```yaml
volumeMounts:
  - name: fluent-bit-state
    mountPath: /var/fluent-bit/state
volumes:
  - name: fluent-bit-state
    emptyDir: {}
```

### mTLS for Log Shipping

Configure TLS on every Fluent Bit output. For outputs to Elasticsearch, OpenSearch, and Loki, the output plugin supports a `tls.*` parameter block.

```ini
[OUTPUT]
    Name              es
    Match             *
    Host              elasticsearch.logging.svc.cluster.local
    Port              9200
    Index             cluster-logs
    tls               On
    tls.verify        On
    tls.ca_file       /etc/fluent-bit/tls/ca.crt
    tls.crt_file      /etc/fluent-bit/tls/tls.crt
    tls.key_file      /etc/fluent-bit/tls/tls.key
    tls.vhost         elasticsearch.logging.svc.cluster.local
```

For mTLS (mutual TLS, where the output also authenticates Fluent Bit as a client), set `tls.crt_file` and `tls.key_file` to a certificate issued to the Fluent Bit service identity. Use cert-manager to provision and rotate these certificates automatically:

```yaml
# Certificate for Fluent Bit client identity
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: fluent-bit-client-tls
  namespace: logging
spec:
  secretName: fluent-bit-client-tls
  duration: 720h   # 30 days
  renewBefore: 168h
  subject:
    organizations: ["logging"]
  commonName: fluent-bit.logging.svc.cluster.local
  usages:
    - client auth
  issuerRef:
    name: cluster-ca
    kind: ClusterIssuer
```

Mount the resulting Secret into the Fluent Bit DaemonSet and never disable `tls.verify`. Setting `tls.verify Off` removes the server identity check, making TLS transport-only and vulnerable to MITM attacks.

### Protecting the HTTP Server

Fluent Bit's HTTP server on port 2020 provides metrics, health checks, and — critically — a `/api/v1/reload` endpoint that reloads configuration at runtime. If this endpoint is reachable from within the cluster without authentication, any pod that can send an HTTP request to Fluent Bit's pod IP can force a configuration reload.

The safest option is to disable the HTTP server entirely if you collect metrics through another path (for example, Prometheus scraping Fluent Bit's built-in metrics via the Prometheus input plugin instead):

```ini
[SERVICE]
    HTTP_Server  Off
```

If you need the HTTP server for health probes or Prometheus scraping, bind it to loopback only:

```ini
[SERVICE]
    HTTP_Server   On
    HTTP_Listen   127.0.0.1
    HTTP_Port     2020
```

Binding to `127.0.0.1` means the endpoint is only reachable from within the same pod's network namespace — usable by Kubernetes liveness and readiness probes (which run in the container's namespace) but not from other pods.

Add a Kubernetes NetworkPolicy to deny inbound traffic to port 2020 from all sources except the Prometheus scrape namespace if you cannot bind to loopback:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: fluent-bit-restrict-http
  namespace: logging
spec:
  podSelector:
    matchLabels:
      app: fluent-bit
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
      ports:
        - port: 2020
          protocol: TCP
  policyTypes:
    - Ingress
```

### PII Scrubbing with Record Modifier and Lua Filters

Fluent Bit processes log records before they are shipped. Use the `record_modifier` filter to drop known sensitive fields entirely, and Lua filters for pattern-based redaction of sensitive values embedded in log strings.

**Drop sensitive structured fields:**

```ini
[FILTER]
    Name    record_modifier
    Match   app.*
    Remove_key  password
    Remove_key  passwd
    Remove_key  secret
    Remove_key  token
    Remove_key  api_key
    Remove_key  authorization
    Remove_key  x-api-key
    Remove_key  credit_card
    Remove_key  ssn
```

**Pattern-based redaction with a Lua filter:**

```ini
[FILTER]
    Name    lua
    Match   app.*
    script  /etc/fluent-bit/scripts/redact.lua
    call    redact_pii
```

```lua
-- /etc/fluent-bit/scripts/redact.lua
function redact_pii(tag, timestamp, record)
    local modified = false

    -- Redact email addresses
    if record["log"] then
        local redacted = record["log"]:gsub(
            "[a-zA-Z0-9._%+%-]+@[a-zA-Z0-9%.%-]+%.[a-zA-Z]{2,}",
            "[EMAIL REDACTED]"
        )
        if redacted ~= record["log"] then
            record["log"] = redacted
            modified = true
        end
    end

    -- Redact 16-digit card numbers (basic Luhn-pattern match)
    if record["log"] then
        local redacted = record["log"]:gsub(
            "%d%d%d%d[%- ]?%d%d%d%d[%- ]?%d%d%d%d[%- ]?%d%d%d%d",
            "[CARD REDACTED]"
        )
        if redacted ~= record["log"] then
            record["log"] = redacted
            modified = true
        end
    end

    -- Redact Bearer tokens in log strings
    if record["log"] then
        local redacted = record["log"]:gsub(
            "Bearer%s+[A-Za-z0-9%._%-]+",
            "Bearer [TOKEN REDACTED]"
        )
        if redacted ~= record["log"] then
            record["log"] = redacted
            modified = true
        end
    end

    if modified then
        return 1, timestamp, record
    end
    return 0, timestamp, record
end
```

Mount the Lua script from a ConfigMap rather than baking it into the image. This allows you to update redaction patterns without rebuilding containers, and makes the redaction logic subject to the same review process as other configuration changes.

Test redaction coverage before deploying to production. Run Fluent Bit locally against a sample log corpus containing synthetic PII and verify the output. Redaction failures are silent — a pattern that misses a variation of a token format will forward that token without any error.

### Secure Log Routing with Tag-Based Multi-Output

Fluent Bit's tag and routing model allows you to separate log streams before they reach output plugins, directing sensitive log sources only to appropriately secured destinations.

Use the `rewrite_tag` filter to assign distinct tags based on Kubernetes namespace or pod labels:

```ini
[FILTER]
    Name          rewrite_tag
    Match         kube.*
    Rule          $kubernetes['namespace_name']  ^(payments|auth|pii-workloads)$  secure.$TAG  false
    Emitter_Name  re_emitted

[OUTPUT]
    Name              es
    Match             secure.*
    Host              elasticsearch-secure.logging.svc.cluster.local
    Port              9200
    tls               On
    tls.verify        On
    tls.ca_file       /etc/fluent-bit/tls/ca.crt
    tls.crt_file      /etc/fluent-bit/tls/tls.crt
    tls.key_file      /etc/fluent-bit/tls/tls.key
    # Additional access controls, audit logging, and retention policies
    # enforced by the elasticsearch-secure instance

[OUTPUT]
    Name              loki
    Match             kube.*
    Host              loki.monitoring.svc.cluster.local
    Port              3100
    tls               On
    tls.verify        On
    tls.ca_file       /etc/fluent-bit/tls/ca.crt
    # General application logs — does NOT match secure.* because Loki
    # match is kube.*, and secure.* tags have already been consumed
    # by the Elasticsearch output above
```

The key invariant: `secure.*` tagged records go only to the hardened Elasticsearch instance. The general Loki output matches `kube.*`, which does not match `secure.*` because the rewrite_tag filter changed the tag. Verify this routing logic by checking Fluent Bit's internal tag routing at startup with `--log-level=debug` in a staging environment.

Explicitly test the negative case: emit a log line from the `payments` namespace and confirm it does not appear in the general Loki instance.

### ServiceAccount Token Projection for Cloud Service Authentication

When Fluent Bit ships to cloud-managed log services (Google Cloud Logging, AWS CloudWatch, Azure Monitor), avoid long-lived credentials in environment variables or ConfigMaps. Use Kubernetes ServiceAccount token projection with workload identity federation instead.

For AWS CloudWatch with IRSA (IAM Roles for Service Accounts):

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: fluent-bit
  namespace: logging
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/FluentBitCloudWatchRole
```

The projected token mounts automatically at `/var/run/secrets/eks.amazonaws.com/serviceaccount/token` and is rotated by the kubelet. The AWS SDK that Fluent Bit's CloudWatch plugin uses will pick it up via standard credential chain resolution. No static AWS credentials are stored anywhere in the cluster.

For GCP Workload Identity:

```yaml
metadata:
  annotations:
    iam.gke.io/gcp-service-account: fluent-bit@your-project.iam.gserviceaccount.com
```

The pattern is the same: token projection from the cloud provider's mutating admission webhook, rotated automatically, with the log shipper accessing only the IAM role it needs (e.g., `roles/logging.logWriter`).

### Resource Limits to Prevent Resource Exhaustion

Set explicit CPU and memory requests and limits on the Fluent Bit DaemonSet container. Without limits, a log flood from a misbehaving application can exhaust node memory and cause the kubelet to evict unrelated workloads.

```yaml
resources:
  requests:
    cpu: 50m
    memory: 64Mi
  limits:
    cpu: 500m
    memory: 256Mi
```

Tune these values based on your actual log volume. A cluster with high-throughput microservices may need higher limits. The important property is that a limit exists — an evicted Fluent Bit pod is a recoverable incident; a log-flood-induced node OOM that evicts critical workloads is an outage.

In addition to pod-level limits, configure Fluent Bit's internal buffer limits to prevent unbounded in-memory queue growth:

```ini
[SERVICE]
    Flush           5
    Mem_Buf_Limit   50MB

[INPUT]
    Name              tail
    Path              /var/log/containers/*.log
    Mem_Buf_Limit     30MB
    Skip_Long_Lines   On
    Refresh_Interval  10
```

`Mem_Buf_Limit` on the tail input causes Fluent Bit to pause reading from the log file when the internal buffer fills, applying backpressure rather than consuming unbounded memory. `Skip_Long_Lines` prevents a single enormously long log line from blocking the buffer indefinitely.

### Auditing and Alerting on Config Changes

Fluent Bit's configuration lives in a Kubernetes ConfigMap. Any change to that ConfigMap is a change to the log collection pipeline — potentially redirecting logs, disabling filters, or adding new outputs. Audit and alert on these changes.

**Enable Kubernetes audit logging for ConfigMap mutations in the logging namespace.** Create an audit policy rule targeting the logging namespace:

```yaml
# audit-policy.yaml (excerpt)
- level: RequestResponse
  resources:
    - group: ""
      resources: ["configmaps"]
  namespaces: ["logging"]
  verbs: ["create", "update", "patch", "delete"]
```

This captures the full before/after content of every ConfigMap change in the logging namespace, including the Fluent Bit config.

**Alert on the audit log event in your SIEM.** A Sigma rule targeting Kubernetes audit logs:

```yaml
title: Fluent Bit ConfigMap Modified
status: stable
logsource:
  product: kubernetes
  service: audit
detection:
  selection:
    objectRef.resource: configmaps
    objectRef.namespace: logging
    objectRef.name|contains: fluent-bit
    verb:
      - update
      - patch
      - delete
  condition: selection
falsepositives:
  - Planned configuration updates by platform engineering team
level: high
tags:
  - attack.defense-evasion
  - attack.t1562.001
```

For GitOps environments (Flux, Argo CD), the ConfigMap should be reconciled from a Git repository. Any out-of-band change that does not match the Git state will be flagged by the GitOps controller as drift. Configure an alert on drift detection for the Fluent Bit ConfigMap in your GitOps controller:

```yaml
# Flux Kustomization alert for drift
apiVersion: notification.toolkit.fluxcd.io/v1beta3
kind: Alert
metadata:
  name: fluent-bit-config-drift
  namespace: logging
spec:
  summary: "Fluent Bit configuration drift detected"
  providerRef:
    name: slack-security-channel
  eventSeverity: error
  eventSources:
    - kind: Kustomization
      name: fluent-bit
      namespace: logging
```

## Verification

After applying hardening controls, verify each control independently:

**RBAC:** `kubectl auth can-i get secrets --as=system:serviceaccount:logging:fluent-bit` should return `no`. `kubectl auth can-i list pods --as=system:serviceaccount:logging:fluent-bit` should return `yes`.

**TLS output:** Capture traffic on the Fluent Bit pod's egress with `kubectl exec` and `tcpdump` or use a network policy trace. Verify no plaintext log data appears on the wire. Alternatively, temporarily break the CA certificate and confirm Fluent Bit logs TLS verification errors and stops forwarding.

**HTTP server binding:** From another pod in the cluster, attempt `curl http://<fluent-bit-pod-ip>:2020/api/v1/metrics`. If the server is bound to loopback, this should time out or be refused. Do not test from within the Fluent Bit pod itself.

**PII redaction:** Deploy a test pod that logs a known synthetic email address and credit card number. Confirm the log record in the downstream backend contains `[EMAIL REDACTED]` and `[CARD REDACTED]`, not the original values.

**Routing isolation:** Deploy a pod in the `payments` namespace that logs a known marker string. Confirm the marker appears in the secure Elasticsearch index and does not appear in the general Loki instance.

**Resource limits:** Confirm limits are enforced with `kubectl describe pod -l app=fluent-bit -n logging | grep -A4 Limits`.

## Summary

Fluent Bit's position as a privileged DaemonSet that reads all container logs makes it a high-value target and a significant source of data exposure risk. The controls in this article — minimal RBAC, non-root pod security, mTLS output, loopback HTTP binding, PII scrubbing filters, tag-based log routing to appropriately secured backends, projected ServiceAccount tokens for cloud destinations, resource limits, and alerting on config changes — address the specific attack surface that Fluent Bit's architecture creates.

The highest-priority controls to apply first: enable TLS on all outputs (immediate protection against in-transit interception), restrict the ServiceAccount to pod and namespace read-only access (prevents credential escalation via the Kubernetes API), and bind the HTTP server to loopback or disable it (closes the unauthenticated config reload endpoint). PII scrubbing and routing controls require more planning but are essential before Fluent Bit forwards data to any destination that is not subject to the same data handling requirements as the source.
