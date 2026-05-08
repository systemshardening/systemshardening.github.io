---
title: "Continuous Profiling Security with Parca and Pyroscope"
description: "Protect sensitive call-stack and memory data collected by eBPF-based continuous profilers (Parca, Pyroscope) with access control, PII scrubbing, and retention limits."
slug: continuous-profiling-security
date: 2026-05-01
lastmod: 2026-05-01
category: observability
tags: ["profiling", "parca", "pyroscope", "ebpf", "pii", "observability", "access-control"]
personas: ["sre", "security-engineer", "platform-engineer"]
article_number: 323
difficulty: intermediate
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/observability/continuous-profiling-security/index.html"
---

# Continuous Profiling Security with Parca and Pyroscope

## Problem

Continuous profiling has graduated from a niche SRE tool to a standard Kubernetes observability component. Tools such as Parca and Grafana Pyroscope use eBPF to collect CPU flame graphs, heap allocation profiles, goroutine states, and mutex contention data from every containerised process on a node — always-on, with roughly 1% CPU overhead, and without any application code changes. That combination makes them compelling. It also makes them a security problem that very few teams have addressed.

The data that a continuous profiler collects is more sensitive than it first appears. A CPU flame graph is not just a list of hot functions: it is a complete call stack sampled at 100–200 Hz. Every frame in every sample is a named symbol — `crypto/tls.(*Conn).Handshake`, `golang.org/x/crypto/bcrypt.GenerateFromPassword`, `database/sql.(*DB).QueryContext` — with line number and binary path when compiled with debug symbols enabled. An attacker reading your profiling data can reconstruct which cryptographic primitives you use, where password hashing occurs relative to request handling, which internal services call which other services, and whether sensitive code paths (key derivation, token validation) execute during normal traffic. That is a service dependency map and a vulnerability surface map in one.

Heap profiles add a further dimension. The pprof heap format records allocation sites with the call stack at the point of allocation and, when debug symbols are present, can contain the names of struct fields and function arguments compiled into the binary. Goroutine profiles expose which goroutines are blocked and on what — including lock names and file descriptors. Even without debug symbols the call-graph topology is enough for an attacker performing reconnaissance to understand your authentication boundary and data flow.

The operational trend compounds the risk. Grafana Pyroscope is now a first-class Grafana Cloud product. Teams that adopt the managed offering route profiling data through Grafana's infrastructure, outside the Kubernetes cluster and potentially outside the data residency boundary required by GDPR or HIPAA. Even self-hosted Pyroscope configured with S3 remote storage writes flame graphs to object storage that may have overly permissive bucket policies or no server-side encryption.

Parca requires elevated Linux capabilities to function. The Parca agent DaemonSet must run with `CAP_BPF` and `CAP_PERFMON` (or the older `CAP_SYS_ADMIN` on kernels before 5.8). These capabilities allow a process to load and run eBPF programs in the kernel, read perf event rings, and walk kernel data structures. If the Parca agent pod is compromised, the attacker inherits those capabilities — a significant privilege escalation path on a shared Kubernetes node.

Despite all of this, the typical Parca or Pyroscope deployment has no RBAC on the query API (any developer with `kubectl port-forward` can query any service's profiles), no data retention limit (profiles accumulate indefinitely), no filtering of which namespaces are profiled (the payments namespace is sampled alongside the logging namespace), and no symbol scrubbing (debug builds ship to production because stripping symbols is not part of the CI pipeline). This article addresses all four gaps.

**Target systems:** Parca v0.20+, Grafana Pyroscope 1.x, Grafana Alloy 1.x, Kubernetes 1.28+.

## Threat Model

1. **Developer with `kubectl` access querying cross-team profiles.** A developer with permission to `kubectl port-forward svc/parca 7070:7070` in the monitoring namespace can query CPU profiles for any service in the cluster — including the payments service, the auth service, and any workload containing secrets in hot code paths. The Parca query API has no built-in notion of which principal may query which service's profiles. A single port-forward becomes a cluster-wide flame-graph browser.

2. **Insider exfiltrating service topology via call-graph analysis.** A malicious insider (or a compromised developer laptop) with read access to Grafana can use the Pyroscope datasource to enumerate every service that reports profiles, map caller/callee relationships between services, and identify which services handle the most sensitive data flows — all without touching application logs or traces. Call graphs are a topology oracle.

3. **Attacker with Grafana read access pivoting to profiling data containing crypto call paths.** An attacker who obtains a Grafana viewer credential (leaked API key, credential stuffing against the Grafana login) can query the Pyroscope datasource if it is configured without additional authentication. CPU profiles for services using TLS termination or JWT validation will reveal exactly which OpenSSL or Go crypto functions are called, their relative depth, and — if debug symbols are present — variable names and file paths that narrow the attack surface for vulnerability research.

4. **Supply chain attacker with Pyroscope push access injecting fake profiles.** Pyroscope's push-based ingestion model (agents send profiles to a central server) means that any process with network access to the Pyroscope ingestion endpoint and knowledge of the tenant/application label format can inject synthetic profiles. Injected profiles can hide malicious call stacks from flame-graph review or pollute retention-based alerting that triggers on CPU regressions.

The blast radius of a profiling data breach spans multiple security domains: it leaks application architecture (useful for targeted exploitation), exposes cryptographic implementation details (useful for algorithm-specific attacks), and may contain strings that are PII under GDPR if function argument names include customer identifiers compiled into debug binaries. A profiling breach is not a low-severity finding.

## Configuration / Implementation

### Parca RBAC and Authentication

Parca server supports bearer token authentication on its gRPC/HTTP API. Generate a token per consumer role and pass it via a mounted Secret.

```bash
# Generate a random bearer token for SRE read access
kubectl -n monitoring create secret generic parca-sre-token \
  --from-literal=token="$(openssl rand -hex 32)"

# Generate a separate token for the Parca agent (write/push)
kubectl -n monitoring create secret generic parca-agent-token \
  --from-literal=token="$(openssl rand -hex 32)"
```

Mount the token file into the Parca server deployment and pass it as a flag:

```yaml
# parca-server-deployment-patch.yaml
spec:
  template:
    spec:
      containers:
        - name: parca
          args:
            - "--bearer-token-file=/etc/parca/auth/token"
            - "--storage-active-memory=536870912"   # 512 MiB cap
            - "--storage-path=/var/lib/parca"
          volumeMounts:
            - name: auth-token
              mountPath: /etc/parca/auth
              readOnly: true
      volumes:
        - name: auth-token
          secret:
            secretName: parca-sre-token
            items:
              - key: token
                path: token
```

Kubernetes RBAC cannot gate Parca's own HTTP API, but it can limit who can perform `kubectl port-forward` to the Parca service — which is the primary access vector in most clusters:

```yaml
# rbac-parca-portforward-deny.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: parca-viewer
  namespace: monitoring
rules:
  - apiGroups: [""]
    resources: ["pods/portforward"]
    resourceNames: []
    verbs: []   # no port-forward allowed by default
---
# Grant only a specific group the ability to port-forward to Parca pods
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: parca-sre-portforward
  namespace: monitoring
subjects:
  - kind: Group
    name: sre-team
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: parca-portforward-allowed   # custom ClusterRole granting pods/portforward
  apiGroup: rbac.authorization.k8s.io
```

### Pyroscope Multi-Tenancy

Grafana Pyroscope 1.x supports multi-tenancy with per-tenant data isolation. Enable it in the Helm values and issue per-tenant API keys:

```yaml
# pyroscope-values.yaml
pyroscope:
  extraArgs:
    - "-auth.multitenancy-enabled=true"

  # Require X-Scope-OrgID header on all requests
  components:
    querier:
      extraArgs:
        - "-auth.multitenancy-enabled=true"
    distributor:
      extraArgs:
        - "-auth.multitenancy-enabled=true"
    compactor:
      extraArgs:
        - "-auth.multitenancy-enabled=true"
        - "-compactor.blocks-retention-period=168h"  # 7-day retention

  storage:
    backend: s3
    s3:
      bucket_name: my-pyroscope-profiles
      endpoint: s3.us-east-1.amazonaws.com
      # Use IAM role — avoid static credentials
      access_key_id: ""
      secret_access_key: ""
```

Configure each Grafana datasource to inject the tenant header, ensuring Grafana viewers only access their own tenant's data:

```yaml
# grafana-datasource-team-payments.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: grafana-datasource-pyroscope-payments
  namespace: monitoring
  labels:
    grafana_datasource: "1"
data:
  datasource.yaml: |
    apiVersion: 1
    datasources:
      - name: Pyroscope-Payments
        type: grafana-pyroscope-datasource
        url: http://pyroscope.monitoring.svc.cluster.local:4040
        jsonData:
          httpHeaderName1: "X-Scope-OrgID"
          httpHeaderName2: "Authorization"
        secureJsonData:
          httpHeaderValue1: "payments"
          httpHeaderValue2: "Bearer ${PYROSCOPE_PAYMENTS_TOKEN}"
```

### Restricting eBPF Probe Scope

By default, the Parca agent profiles every pod on the node. Use label selectors and namespace exclusions to restrict this to non-sensitive workloads:

```yaml
# parca-agent-daemonset-patch.yaml
spec:
  template:
    spec:
      containers:
        - name: parca-agent
          args:
            - "--kubernetes-node=$(NODE_NAME)"
            - "--pod-label-selector=profiling=enabled"
            - "--exclude-namespaces=payments,auth,secrets-store"
            - "--bearer-token-file=/etc/parca-agent/auth/token"
          env:
            - name: NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
```

Label workloads that should be profiled rather than opting out sensitive ones — opt-in is safer:

```bash
# Opt specific deployments into profiling
kubectl label deployment api-gateway profiling=enabled -n platform
kubectl label deployment metrics-aggregator profiling=enabled -n platform

# Explicitly verify payments namespace pods have no profiling label
kubectl get pods -n payments --show-labels | grep profiling
```

### PII Scrubbing in Symbol Names

The most reliable way to prevent sensitive symbol names from appearing in profiles is to strip debug information at build time. For Go services:

```dockerfile
# Dockerfile — production build stage
FROM golang:1.22 AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOARCH=amd64 GOOS=linux \
    go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /app/server \
    ./cmd/server

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /app/server /server
ENTRYPOINT ["/server"]
```

The `-trimpath` flag removes all local file system paths from compiled binaries. The `-ldflags="-s -w"` flags strip the symbol table (`-s`) and DWARF debug information (`-w`). Together they reduce the binary size by 20–40% and eliminate the function argument names and file paths that would otherwise appear in heap profiles.

For the Parca agent itself, the `--strip-debug-symbols` flag instructs the agent not to symbolise raw addresses using local debug files:

```bash
parca-agent \
  --strip-debug-symbols \
  --kubernetes-node="${NODE_NAME}" \
  --bearer-token-file=/etc/parca-agent/auth/token
```

Validate that a production binary contains no DWARF sections before deploying:

```bash
# Should return no output if debug info is stripped
objdump -h ./server | grep -E '\.debug_|\.zdebug_'

# Check Go binary specifically
go tool buildid ./server   # should print a build ID without file paths
strings ./server | grep '/home/' | head  # should return nothing
```

### Retention and Storage Limits

Cap in-memory storage to prevent Parca from consuming unbounded node memory when profiling high-cardinality services:

```yaml
# parca-server-args
args:
  - "--storage-active-memory=1073741824"    # 1 GiB max in-memory store
  - "--storage-path=/var/lib/parca"
  - "--storage-enable-wal=true"
  - "--storage-wal-truncate-frequency=2h"   # flush to disk and truncate every 2 h
```

For Pyroscope with S3 backend, configure the compactor retention and add an S3 lifecycle rule to enforce hard deletion:

```yaml
# pyroscope-compactor-retention.yaml
# In pyroscope-values.yaml under pyroscope.extraArgs:
- "-compactor.blocks-retention-period=168h"    # 7 days
- "-querier.max-query-lookback=168h"
- "-querier.max-query-length=24h"              # limit single query window
```

```json
// s3-lifecycle-rule.json — apply with: aws s3api put-bucket-lifecycle-configuration
{
  "Rules": [
    {
      "ID": "pyroscope-profile-expiry",
      "Status": "Enabled",
      "Filter": { "Prefix": "pyroscope/" },
      "Expiration": { "Days": 10 },
      "NoncurrentVersionExpiration": { "NoncurrentDays": 1 }
    }
  ]
}
```

```bash
aws s3api put-bucket-lifecycle-configuration \
  --bucket my-pyroscope-profiles \
  --lifecycle-configuration file://s3-lifecycle-rule.json
```

### TLS for Parca and Pyroscope APIs

Use cert-manager to issue TLS certificates for Parca's gRPC/HTTP endpoint:

```yaml
# parca-certificate.yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: parca-tls
  namespace: monitoring
spec:
  secretName: parca-tls-secret
  duration: 2160h    # 90 days
  renewBefore: 360h  # renew 15 days early
  dnsNames:
    - parca.monitoring.svc.cluster.local
    - parca.monitoring.svc
  issuerRef:
    name: cluster-ca-issuer
    kind: ClusterIssuer
---
# Mount in Parca deployment
# args:
#   - "--tls-cert-file=/etc/parca/tls/tls.crt"
#   - "--tls-key-file=/etc/parca/tls/tls.key"
```

Configure the Parca agent to use mutual TLS when pushing profiles to the server:

```yaml
# parca-agent-daemonset-tls-patch.yaml
spec:
  template:
    spec:
      containers:
        - name: parca-agent
          args:
            - "--remote-store-address=parca.monitoring.svc.cluster.local:7070"
            - "--remote-store-bearer-token-file=/etc/parca-agent/auth/token"
            - "--remote-store-insecure=false"
            - "--remote-store-insecure-skip-verify=false"
          volumeMounts:
            - name: cluster-ca
              mountPath: /etc/ssl/certs/cluster-ca.crt
              subPath: ca.crt
              readOnly: true
      volumes:
        - name: cluster-ca
          configMap:
            name: kube-root-ca.crt
```

### Network Isolation

Restrict which pods can reach the Parca server and the Pyroscope distributor using NetworkPolicy:

```yaml
# networkpolicy-parca-server.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: parca-server-ingress
  namespace: monitoring
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: parca
  policyTypes:
    - Ingress
  ingress:
    # Allow Parca agents from any namespace (DaemonSet pods)
    - from:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              app.kubernetes.io/name: parca-agent
      ports:
        - protocol: TCP
          port: 7070
    # Allow Grafana in monitoring namespace to query Parca
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
          podSelector:
            matchLabels:
              app.kubernetes.io/name: grafana
      ports:
        - protocol: TCP
          port: 7070
---
# networkpolicy-pyroscope-distributor.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: pyroscope-distributor-ingress
  namespace: monitoring
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/component: distributor
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              app.kubernetes.io/name: alloy
      ports:
        - protocol: TCP
          port: 4040
```

## Expected Behaviour

After applying the controls above, the following observable changes indicate the configuration is working correctly.

| Signal | Before | After |
|---|---|---|
| Unauthorized profile query via `kubectl port-forward` | Any authenticated Kubernetes user can retrieve flame graphs for any service with no API-level check | Parca API requires bearer token; users without the `parca-sre-token` secret receive `401 Unauthorized` on every profile query |
| Debug symbols in heap profile | Heap allocation profiles include full file paths (`/home/ci/build/src/...`), struct field names, and function argument variable names from DWARF data | Profiles contain only symbolised function names with no file paths or argument metadata; `objdump` confirms absence of `.debug_info` sections |
| Cross-tenant data access in Pyroscope | A Grafana viewer with access to one team's datasource can modify the `X-Scope-OrgID` header to read another tenant's profiles | Multi-tenancy enabled; the Grafana datasource injects the tenant header from `secureJsonData` — viewers cannot override it; Pyroscope rejects requests without a valid tenant header |
| Profiling of sensitive namespace | Parca agent samples all pods including those in the `payments` namespace | `--exclude-namespaces=payments,auth` causes agent to skip those namespaces; no profiles appear in Parca for those workloads |
| Unbounded profile retention | Profiles accumulate for months, consuming 40+ GiB of disk | S3 lifecycle rule expires objects after 10 days; compactor enforces 168-hour query window; `aws s3 ls --recursive s3://my-pyroscope-profiles \| wc -l` decreases over time |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| eBPF privilege requirement (`CAP_BPF`, `CAP_PERFMON`) | Enables kernel-level profiling without instrumentation; accurate CPU and memory data | DaemonSet pods hold elevated capabilities; compromise of the agent container is a node-level privilege escalation | Run agent as a dedicated non-root user; apply a tight Seccomp profile (`RuntimeDefault`); use read-only root filesystem; pin the agent image by digest |
| Symbol stripping (`-s -w`, `-trimpath`) | Eliminates file paths and argument names from profiles; reduces binary size by 20–40% | Debugging production issues becomes harder; panic stack traces lose file/line information; pprof output shows only function names | Retain unstripped binaries in a secure artifact store (e.g., S3 with restricted access) indexed by build ID; use debuginfod or Parca's symbol upload API to serve symbols on demand to authorised engineers only |
| Pyroscope multi-tenancy | Isolates profiling data per team or service group; prevents cross-team data leakage | Adds per-request header validation overhead; requires Helm re-configuration and Grafana datasource per tenant | Enable multi-tenancy from day one before teams onboard; use Grafana's team-scoped datasource permissions to automate tenant assignment |
| Short retention (7 days) | Limits the window of sensitive data available to an attacker who compromises storage | Post-incident investigations requiring profiles older than 7 days are blocked | Keep a cold-storage copy of profiles for production incidents with stricter access control and an approval workflow for retrieval; document the access procedure in runbooks |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| `CAP_BPF` denied — kernel too old or seccomp blocking | Parca agent pods crash-loop with `operation not permitted` or `failed to load eBPF program`; no profiles appear in Parca for the affected node | Alert on `parca_agent_up == 0` per node; check agent logs with `kubectl logs -n monitoring ds/parca-agent --previous` | Upgrade kernel to 5.8+ for granular capabilities; on older kernels use `CAP_SYS_ADMIN` (broader, less preferred); if seccomp is blocking, add `bpf` and `perf_event_open` syscalls to the allowed list |
| Parca OOM from too many label series | Parca server pod is OOM-killed; Kubernetes restarts it; recent profiles are lost; `--storage-active-memory` limit was not set | Alert on `container_oom_events_total{container="parca"} > 0`; monitor `parca_memory_alloc_bytes` metric | Set `--storage-active-memory` to no more than 50% of the pod's memory limit; increase pod memory request if needed; reduce cardinality by dropping low-value label dimensions in agent configuration |
| TLS certificate expiry breaks agent push | Parca agent logs `certificate expired` or `tls: failed to verify certificate`; profiles stop arriving at server; Parca dashboards go stale | Alert on cert-manager `Certificate` condition `Ready=False`; alert on `parca_profiles_received_total` rate dropping to zero | cert-manager auto-renews certificates if `renewBefore` is set; verify with `kubectl get certificate -n monitoring parca-tls`; manual rotation: delete the TLS secret and allow cert-manager to reissue |
| Retention policy deletes profiles needed for incident investigation | Post-incident review finds no profiles available for the time window of the incident; compactor has already expired the data | Alert when incident timeline exceeds retention window (compare `incident_start_time` against retention boundary in runbook); track retention policy version in change log | Establish an emergency retention override: before closing an incident, use the Pyroscope admin API or S3 object lock to preserve the relevant time window; document this in the incident response runbook |

## Related Articles

- [OpenTelemetry PII Leakage](/articles/observability/otel-pii-leakage/)
- [eBPF Security with Tetragon](/articles/observability/ebpf-tetragon/)
- [Application Security Logging](/articles/observability/application-security-logging/)
- [Kubernetes RBAC Design Patterns](/articles/kubernetes/rbac-design-patterns/)
- [Data Loss Prevention in Platform Engineering](/articles/cross-cutting/data-loss-prevention/)
