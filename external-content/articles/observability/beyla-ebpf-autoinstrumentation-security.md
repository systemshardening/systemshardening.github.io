---
title: "Grafana Beyla eBPF Auto-Instrumentation Security"
description: "Harden Grafana Beyla deployments by scoping eBPF privileges, restricting process visibility, preventing telemetry data leakage, and controlling network-level instrumentation scope."
slug: beyla-ebpf-autoinstrumentation-security
date: 2026-05-02
lastmod: 2026-05-02
category: observability
tags: ["beyla", "ebpf", "auto-instrumentation", "observability", "cap-bpf", "opentelemetry", "pii"]
personas: ["sre", "security-engineer", "platform-engineer"]
article_number: 331
difficulty: advanced
estimated_reading_time: 15
published: true
layout: article.njk
permalink: "/articles/observability/beyla-ebpf-autoinstrumentation-security/index.html"
---

# Grafana Beyla eBPF Auto-Instrumentation Security

## Problem

Grafana Beyla is an eBPF-based automatic instrumentation agent that produces distributed traces and metrics for HTTP, gRPC, SQL, Redis, and other protocols without requiring any code changes to the instrumented application. It achieves this by attaching eBPF programs to uprobes (user-space function entry and return hooks) and socket-level traffic control hooks, capturing request and response metadata directly from kernel data structures. Because Beyla operates at the kernel interface, it can observe traffic across any process on the node without a sidecar, a language runtime agent, or any cooperation from the application itself.

This zero-code model is operationally attractive, but it rests on a substantial privilege grant. Beyla requires `CAP_BPF` to load and manage eBPF programs, `CAP_PERFMON` to open perf event buffers and attach kprobes or uprobes, and `CAP_SYS_PTRACE` to read process memory for symbol resolution. Many production deployments run Beyla with `privileged: true` in the DaemonSet pod spec because it is the path of least resistance; this grants every Linux capability and disables all seccomp filtering. The result is a process that can read arbitrary kernel structures, load unrestricted eBPF programs, and attach to any process anywhere on the node.

The first category of security risk is data capture scope. Beyla captures full HTTP request paths, query strings, and response codes at the kernel level. Any personally identifiable information present in a URL — user IDs, session tokens, search terms, healthcare record identifiers — flows into Beyla's trace output. gRPC method names and metadata headers follow the same path. For SQL and Redis instrumentation, Beyla captures the statement or command text, which may contain literal values including passwords, credit card numbers, or other sensitive data interpolated by an application that does not use parameterized queries.

The second category is tenant isolation. A Beyla DaemonSet that runs on every node in a multi-tenant cluster can observe every process on those nodes. There is no per-namespace or per-team boundary enforced by the eBPF attachment mechanism itself. A team operating in the `payments` namespace and a team operating in the `analytics` namespace share a node, and Beyla can instrument both without either team's knowledge or consent. This violates the isolation guarantees that namespace-based tenancy is expected to provide.

The third category is credential exposure in the observability pipeline. HTTP instrumentation captures request headers at the point of the kernel socket, before TLS termination is stripped. Authorization headers carrying Bearer tokens, Basic credentials, or API keys flow into span attributes. These attributes are then exported to an OTEL Collector, stored in Tempo, and made queryable in Grafana. Any analyst with access to Grafana's trace explorer can query for HTTP spans and read the captured Authorization header values, recovering live credentials from production traffic.

The fourth category is the attack surface of the Beyla pod itself. A privileged container with `CAP_BPF` and `CAP_SYS_PTRACE` is one of the highest-value targets in any Kubernetes cluster. An attacker who achieves code execution inside the Beyla pod — through a vulnerability in Beyla's own Go binary, its dependency chain, or its configuration management — can use the existing eBPF privilege to load arbitrary programs, read kernel memory, or mount a container escape. The DaemonSet topology means this risk is replicated to every node.

Target systems: Grafana Beyla 1.7+ (GA), Kubernetes 1.28+, Linux kernel >= 5.8.

## Threat Model

1. **Attacker escalating from Beyla pod to node kernel.** A vulnerability in Beyla's HTTP or gRPC parsing code, or in a dependency such as a YAML configuration parser, allows remote code execution inside the Beyla container. The attacker uses the already-loaded `CAP_BPF` grants to load a custom eBPF program that reads kernel memory, bypasses LSM hooks, or exfiltrates secrets from other processes. Because the pod runs with `hostPID: true`, the attacker can also signal or ptrace arbitrary processes on the node, completing a full host escape.

2. **Insider harvesting credentials via Grafana trace explorer.** A developer or analyst with legitimate read access to Grafana queries Tempo for HTTP traces from the `payments` service. Because Beyla captured the raw `Authorization` header on each request, the analyst reads live production API keys from the span attribute panel. Credentials are harvested silently with no alert, because the access path is a normal Grafana query that does not trigger any SIEM rule.

3. **Rogue or misconfigured Beyla instance observing all tenants.** An operator deploys an additional Beyla DaemonSet in a namespace where it does not belong, or a misconfigured `BEYLA_SYSTEM_WIDE=true` setting causes a scoped Beyla to attach to processes in all namespaces. Traffic and process memory from every tenant on affected nodes becomes visible to this instance. The rogue Beyla exports traces to an attacker-controlled OTEL Collector endpoint, where the captured headers and SQL statements are stored for offline analysis.

4. **Supply chain attacker injecting malicious eBPF via Beyla extension.** A future or third-party Beyla plugin mechanism, a compromised Beyla container image, or a malicious update to the official image delivers a modified eBPF object file alongside the legitimate Beyla binary. When Beyla loads its programs at startup, the injected program attaches to sensitive kernel functions and begins exfiltrating data through a covert DNS channel, exploiting the pre-approved `CAP_BPF` grant to operate without triggering capability-level alerts.

The blast radius of any of these scenarios extends to the entire node. Because Beyla runs as a DaemonSet, a single successful exploit or misconfiguration affects all workloads scheduled on that node simultaneously. In a cluster where Beyla targets all namespaces, the blast radius is the entire cluster's runtime traffic. Effective hardening therefore focuses on minimizing what Beyla can see, minimizing the privilege required to do so, and eliminating credential-class data from the observability pipeline before it reaches storage.

## Configuration / Implementation

### Minimal capability set

Replace `privileged: true` with the minimum set of Linux capabilities Beyla actually requires. For kernel 5.8+ with eBPF uprobe and tc eBPF support, this is `CAP_BPF`, `CAP_PERFMON`, and `CAP_NET_ADMIN` (the last is required for tc eBPF socket-level hooks). Drop every other capability and apply `allowPrivilegeEscalation: false` and a read-only root filesystem.

```yaml
# beyla-daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: beyla
  namespace: beyla-system
spec:
  selector:
    matchLabels:
      app: beyla
  template:
    metadata:
      labels:
        app: beyla
    spec:
      serviceAccountName: beyla
      hostPID: true          # Required for uprobe symbol resolution; see HostPID section
      hostNetwork: false     # Do not grant host network namespace
      containers:
        - name: beyla
          image: grafana/beyla:1.7.0
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
              add:
                - BPF
                - PERFMON
                - NET_ADMIN
          env:
            - name: BEYLA_SYSTEM_WIDE
              value: "false"
            - name: BEYLA_OPEN_PORT
              value: "8080"
          volumeMounts:
            - name: beyla-config
              mountPath: /etc/beyla
              readOnly: true
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: beyla-config
          configMap:
            name: beyla-config
        - name: tmp
          emptyDir: {}
```

On kernels older than 5.8, or when `CAP_PERFMON` is not split from `CAP_SYS_ADMIN`, you may need `CAP_SYS_ADMIN` instead of `CAP_PERFMON`. Test with `bpftool prog list` after startup to confirm programs load before removing capabilities in production.

### Process and namespace scoping

`BEYLA_SYSTEM_WIDE=true` causes Beyla to attach to every executable on the node. Set it to `false` and provide a narrowing filter using either the executable name or the open port pattern. This restricts instrumentation to the intended service without requiring any change to the application.

```bash
# Target a specific process by executable name
BEYLA_SYSTEM_WIDE=false
BEYLA_EXECUTABLE_NAME=myapp

# Or target by the port the process listens on (preferred in Kubernetes)
BEYLA_SYSTEM_WIDE=false
BEYLA_OPEN_PORT=8080

# Combine both for tighter scoping
BEYLA_EXECUTABLE_NAME=myapp
BEYLA_OPEN_PORT=8080
```

For multi-service nodes, use the pod label selector feature introduced in Beyla 1.6 to confine instrumentation to pods carrying specific labels. This approach uses the Kubernetes API watch to determine which processes correspond to pods in the target set.

```yaml
# beyla-config ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: beyla-config
  namespace: beyla-system
data:
  beyla.yaml: |
    discovery:
      services:
        - name: payments-api
          open_ports: 8080
          k8s_pod_labels:
            app: payments-api
            beyla.io/instrument: "true"
    # Exclude kube-system and monitoring namespaces from instrumentation
    attributes:
      kubernetes:
        enable: true
```

Apply a label to pods that should be instrumented and omit it from sensitive or infrastructure pods:

```bash
kubectl label pod <pod-name> beyla.io/instrument=true
```

### PII scrubbing in captured data

Beyla captures raw HTTP attribute data before any application-layer sanitization. Configure the OTEL Collector to strip sensitive attributes before traces reach the storage backend.

First, configure Beyla itself to suppress query-string capture and unmatched route recording:

```yaml
# In beyla.yaml ConfigMap
routes:
  unmatched: drop           # Do not record spans for routes Beyla cannot classify

attributes:
  select:
    # Drop HTTP query parameters entirely — they commonly carry PII
    http.url.query: drop
    # Drop authorization and cookie headers
    http.request.header.authorization: drop
    http.request.header.cookie: drop
    http.response.header.set-cookie: drop
    # Drop raw DB statements — use parameterized query names only
    db.statement: drop
```

Then apply an OTEL Collector `filter` processor to enforce the same rules at the pipeline boundary, providing defense in depth in case Beyla configuration drifts:

```yaml
# otel-collector-config.yaml (relevant sections)
processors:
  attributes/strip-sensitive:
    actions:
      - key: http.request.header.authorization
        action: delete
      - key: http.request.header.cookie
        action: delete
      - key: http.response.header.set-cookie
        action: delete
      - key: db.statement
        action: delete
      - key: url.query
        action: delete
      - key: http.url
        action: update
        # Replace full URL with path only by hashing query component
        from_attribute: http.target

  filter/drop-sensitive-routes:
    traces:
      span:
        # Drop spans for health-check endpoints that produce noisy low-value data
        - 'attributes["http.route"] == "/healthz"'
        - 'attributes["http.route"] == "/readyz"'
        - 'attributes["http.route"] == "/metrics"'

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [attributes/strip-sensitive, filter/drop-sensitive-routes, batch]
      exporters: [otlp/tempo]
```

For SQL instrumentation, if you need to retain query structure for performance analysis without retaining literal values, configure Beyla to capture only the normalized statement form (available in Beyla 1.7+ via `db.query.summary`).

### RBAC and NetworkPolicy for Beyla

Beyla's ServiceAccount requires no cluster-wide resource read permissions for its core instrumentation function. RBAC should be limited to what is strictly necessary for Kubernetes metadata enrichment.

```yaml
# beyla-rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: beyla
  namespace: beyla-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: beyla
rules:
  # Metadata enrichment only — no secrets, no configmaps cluster-wide
  - apiGroups: [""]
    resources: ["pods", "nodes", "services", "namespaces"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: beyla
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: beyla
subjects:
  - kind: ServiceAccount
    name: beyla
    namespace: beyla-system
```

Restrict network egress for Beyla pods to only the OTEL Collector endpoint. Deny all other egress to prevent a compromised Beyla pod from exfiltrating data to an attacker-controlled endpoint.

```yaml
# beyla-networkpolicy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: beyla-egress
  namespace: beyla-system
spec:
  podSelector:
    matchLabels:
      app: beyla
  policyTypes:
    - Egress
    - Ingress
  ingress: []          # Beyla does not receive inbound connections
  egress:
    # Allow DNS resolution
    - ports:
        - protocol: UDP
          port: 53
    # Allow OTEL Collector gRPC export on port 4317
    - to:
        - namespaceSelector:
            matchLabels:
              name: monitoring
          podSelector:
            matchLabels:
              app: otel-collector
      ports:
        - protocol: TCP
          port: 4317
    # Allow Kubernetes API for pod metadata enrichment
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 10.0.0.0/8
              - 172.16.0.0/12
              - 192.168.0.0/16
      ports:
        - protocol: TCP
          port: 443
```

Restrict ConfigMap write access for the Beyla namespace to the platform team only, using namespace-scoped RBAC so that application team service accounts cannot modify Beyla's configuration:

```yaml
# Only platform-team ClusterRole should have update/patch on configmaps in beyla-system
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: beyla-config-manager
  namespace: beyla-system
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "update", "patch"]
```

### HostPID and HostNetwork restrictions

Beyla requires `hostPID: true` to resolve user-space symbols for uprobe attachment. This grants the Beyla process visibility into every PID on the node and the ability to ptrace any of them using the `CAP_SYS_PTRACE` grant. There is no current workaround that preserves uprobe-based instrumentation for compiled languages (Go, Rust, C++) while eliminating `hostPID`.

Use PodSecurity admission to confine this exception to the Beyla namespace only. Apply the `privileged` policy exclusively to the `beyla-system` namespace and enforce `restricted` everywhere else:

```bash
# Label the Beyla namespace to permit the required host-access capabilities
kubectl label namespace beyla-system \
  pod-security.kubernetes.io/enforce=privileged \
  pod-security.kubernetes.io/warn=privileged \
  pod-security.kubernetes.io/audit=privileged

# All other application namespaces should carry restricted enforcement
kubectl label namespace payments \
  pod-security.kubernetes.io/enforce=restricted
```

For interpreted runtimes (Python, Node.js, Ruby) that Beyla instruments via socket hooks rather than uprobes, you can omit `hostPID: true`. Maintain two Beyla DaemonSet variants if your cluster serves both compiled and interpreted workloads, applying `hostPID: true` only to the instance targeting compiled services.

`hostNetwork: false` is safe and recommended. Beyla's eBPF tc hooks operate at the virtual ethernet level within each pod's network namespace without requiring the Beyla process itself to share the host network namespace.

### Audit and integrity

Verify at startup that only the expected eBPF programs are loaded by Beyla. An adversary who achieves write access to the Beyla image or configuration might inject additional programs.

```bash
# List all loaded eBPF programs on the node, filtering by type
bpftool prog list

# Expected output for Beyla: uprobe, tracepoint, and sk_skb type programs
# Unexpected: kprobe/kretprobe programs not associated with Beyla, raw_tracepoint, socket_filter
# Store baseline at deployment and compare on each node reconciliation cycle
bpftool prog list --json | jq '[.[] | {id, type, name, tag}]' > /var/lib/beyla/prog-baseline.json
```

Monitor for unexpected eBPF syscall usage from non-Beyla processes using bpftrace:

```bash
# Alert on any process other than beyla invoking the bpf() syscall
bpftrace -e '
tracepoint:syscalls:sys_enter_bpf {
  if (comm != "beyla") {
    printf("UNEXPECTED BPF SYSCALL: pid=%d comm=%s cmd=%d\n",
           pid, comm, args->cmd);
  }
}'
```

Apply a Falco rule to generate alerts when the `bpf` syscall is invoked by a process outside the Beyla DaemonSet:

```yaml
# falco-beyla-rule.yaml
- rule: Unexpected BPF Syscall
  desc: A process other than beyla has invoked the bpf() syscall
  condition: >
    syscall.type = bpf and
    not proc.name = beyla and
    not proc.name in (known_bpf_tools)
  output: >
    Unexpected bpf() syscall (pid=%proc.pid comm=%proc.name
    container=%container.name image=%container.image.repository)
  priority: WARNING
  tags: [ebpf, container, integrity]

- list: known_bpf_tools
  items: [bpftool, bpftrace, perf, cilium-agent]
```

### Grafana data source access control

Even after PII scrubbing at the Collector, restrict Grafana data source access so that only authorized teams can query raw traces:

```yaml
# Grafana provisioning — data source with restricted access
apiVersion: 1
datasources:
  - name: Tempo
    type: tempo
    access: proxy
    url: http://tempo.monitoring:3100
    jsonData:
      httpMethod: GET
      tracesToLogs:
        datasourceUid: loki
    # Restrict to platform-team org only — do not expose to default org
    orgId: 2
```

In Grafana 10+, use role-based access control to limit trace query permissions to the `platform-engineer` and `security-engineer` roles. Grant `metrics:read` but not `traces:read` to lower-privilege viewer roles.

For Tempo itself, configure per-tenant query isolation if running Tempo in multi-tenant mode, and use the `X-Scope-OrgID` header to prevent cross-tenant trace queries:

```yaml
# tempo-config.yaml (relevant section)
multitenancy_enabled: true
auth_enabled: true
```

## Expected Behaviour

| Signal | Without hardening | With hardening |
|---|---|---|
| `http.request.header.authorization` in trace spans | Bearer token visible in plain text to any Grafana user | Attribute deleted by OTEL Collector `attributes` processor before export to Tempo; field absent from all spans |
| Container escape via `CAP_BPF` from Beyla pod | Full kernel memory read and arbitrary eBPF program load possible; `privileged: true` removes all Linux capability restrictions | Capabilities scoped to `BPF`, `PERFMON`, `NET_ADMIN` only; seccomp profile applied; escape requires chaining additional kernel vulnerability |
| Cross-tenant process visibility | `BEYLA_SYSTEM_WIDE=true` attaches Beyla to all processes on node; all tenants' traffic captured in single trace stream | `BEYLA_SYSTEM_WIDE=false` with `k8s_pod_labels` selector; only pods carrying `beyla.io/instrument=true` label are instrumented; other namespaces produce no spans |
| Sensitive SQL query text in database spans | Full SQL statement including literal values (`SELECT * FROM users WHERE password='abc'`) stored in `db.statement` attribute | `db.statement` attribute deleted at Beyla config layer; only normalized query type retained via `db.operation` and `db.name` |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Process scoping via `BEYLA_EXECUTABLE_NAME` / `BEYLA_OPEN_PORT` | Eliminates cross-tenant instrumentation; reduces Beyla's observable footprint on the node | Services that share a port or executable name with unintended processes may be included or excluded incorrectly; new services added without the `beyla.io/instrument` label produce no traces | Enforce label-based discovery as the canonical selector; use admission webhooks to auto-apply the label during deployment |
| PII scrubbing via OTEL attribute deletion | Prevents credential and personal data exposure in trace storage | Strips attributes that engineers use during incident response to understand request context; debugging authentication failures requires correlating with application logs instead | Retain a short-lived (1-hour TTL) raw trace buffer in the Collector that is accessible only to on-call engineers via break-glass access; document the procedure |
| Dropping `hostPID: true` for interpreted-runtime services | Eliminates the broadest host-access privilege; significantly reduces blast radius of a Beyla compromise | eBPF uprobe attachment for compiled languages (Go, Rust) fails without `hostPID`; Beyla falls back to socket-level instrumentation only, which does not capture some language-specific spans | Maintain two Beyla DaemonSets: one with `hostPID: false` for interpreted-runtime services (socket-level hooks sufficient), one with `hostPID: true` for compiled-language services, deployed with stricter node affinity |
| OTEL Collector `filter` and `attributes` processors | Defense-in-depth layer independent of Beyla configuration; survives Beyla config drift or upgrade | Each processor adds CPU overhead in the Collector pipeline; attribute iteration on high-throughput clusters can increase Collector pod resource usage by 10–20% | Profile Collector CPU at baseline; adjust processor batch sizes and use sampling upstream (tail-based sampling before filter processors) to reduce volume |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| `CAP_BPF` denied by admission controller (e.g., OPA Gatekeeper or Kyverno policy) | Beyla DaemonSet pods fail to start; pod status shows `CreateContainerConfigError`; Beyla logs contain `operation not permitted` on eBPF map creation | `kubectl describe pod -n beyla-system`; OPA/Kyverno audit log entries for the Beyla namespace; Prometheus alert on DaemonSet unavailable replicas | Create a Kyverno/Gatekeeper policy exception for the `beyla-system` namespace; apply the exception before redeploying; validate with `kubectl auth can-i --as system:serviceaccount:beyla-system:beyla` |
| Kernel too old for required eBPF program type | Beyla starts but emits zero spans; logs show `failed to load eBPF object: program type not supported`; kernel version below 5.8 confirmed | `uname -r` on affected nodes; Beyla startup log `level=error` lines; compare against Beyla compatibility matrix for the deployed version | Upgrade node kernel to 5.8+; as interim, restrict Beyla DaemonSet to nodes with a matching kernel version using `nodeSelector: kubernetes.io/kernel-version: ">=5.8"` (requires Node Feature Discovery) |
| Process filter too restrictive (zero spans exported) | Services are running and receiving traffic but Beyla produces no spans; OTEL Collector receives no inbound data from Beyla; Grafana shows empty trace views | Check `BEYLA_EXECUTABLE_NAME` and `BEYLA_OPEN_PORT` against actual process names with `kubectl exec -n beyla-system <pod> -- cat /proc/*/comm`; Beyla debug log `discovered 0 processes` | Relax the executable name filter or add the missing port; add `beyla.io/instrument=true` label to the target pod; restart Beyla pod to trigger fresh process discovery |
| OTEL Collector `attributes` processor drops legitimate trace data | Engineers report that spans are missing context attributes needed for debugging; correlation between traces and logs breaks because `trace.id` attribute was inadvertently deleted | Query Tempo for affected service spans; compare present attributes against the expected schema; Collector logs for `attribute deleted` events; diff Collector config against last known-good version | Restore the accidentally deleted attribute name from the `attributes/strip-sensitive` processor action list; re-deploy Collector; use Collector's `debug` exporter temporarily to inspect pipeline output before routing to Tempo |

## Related Articles

- [eBPF Security with Tetragon](/articles/observability/ebpf-tetragon/)
- [Continuous Profiling Security](/articles/observability/continuous-profiling-security/)
- [OTEL Collector Hardening](/articles/observability/otel-collector-hardening/)
- [eBPF LSM Security](/articles/linux/ebpf-lsm/)
- [Kubernetes RBAC Design Patterns](/articles/kubernetes/rbac-design-patterns/)
