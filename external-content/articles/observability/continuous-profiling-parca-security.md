---
title: "Security Considerations for Continuous Profiling with Parca and Pyroscope"
description: "Understand the kernel attack surface, privilege model, and data sensitivity risks of eBPF-based continuous profiling with Parca and Grafana Pyroscope, and harden deployments against each threat."
slug: continuous-profiling-parca-security
date: 2026-05-07
lastmod: 2026-05-07
category: observability
tags:
  - continuous-profiling
  - parca
  - pyroscope
  - ebpf-profiling
  - performance-security
personas:
  - security-engineer
  - platform-engineer
article_number: 561
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/observability/continuous-profiling-parca-security/
---

# Security Considerations for Continuous Profiling with Parca and Pyroscope

## Problem

Continuous profiling with Parca and Grafana Pyroscope sits at an unusual intersection: the feature that makes these tools valuable — always-on, zero-instrumentation, system-wide visibility into CPU time, memory allocation, and blocking I/O — also makes them among the highest-privilege, highest-sensitivity components in a Kubernetes cluster. Most teams that adopt continuous profiling focus on the flame-graph UX and the storage backend, and defer the security architecture until something goes wrong. This article addresses that gap by examining the specific risks that arise from the profiling agent's privilege model, the kernel attack surface it exposes, the sensitivity of the data it produces, and the access control gaps that are almost universally present in default deployments.

The two primary agents in this space operate on fundamentally different privilege models that are worth distinguishing. Parca Agent uses eBPF CO-RE (Compile Once, Run Everywhere) programs loaded through the `bpf()` syscall. Because it relies entirely on the eBPF verifier rather than a kernel module, it offers a meaningful safety boundary: any program that the verifier accepts cannot corrupt kernel memory or create infinite loops. This is a genuine architectural advantage over older `perf`-record-based profilers that relied on raw `perf_event_open` interfaces, and it is categorically safer than a kernel module. Pyroscope's eBPF-based agent (Grafana Alloy with the `pyroscope.ebpf` component) follows the same model.

However, "safer than a kernel module" is not the same as "safe to run without thought." Both agents must call `bpf()` with `BPF_PROG_LOAD` and `BPF_MAP_CREATE` commands, attach programs to perf events via `perf_event_open`, and — for compiled languages such as Go and Rust — read the memory of every process on the node to unwind call stacks. Each of these operations requires specific Linux capabilities, and each represents an attack surface that a determined adversary can leverage.

On kernels 5.8 and later, the minimum capability set for eBPF-based profiling is `CAP_BPF` (load programs, create and manage eBPF maps) and `CAP_PERFMON` (open perf events, use `perf_event_open`). On kernels before 5.8, these capabilities did not exist as separate grants; all eBPF and perf operations required `CAP_SYS_ADMIN`, which is an enormously broad capability that also permits mounting filesystems, modifying kernel parameters, and bypassing DAC restrictions. Many production clusters — particularly those running AWS EKS with older AMIs or GKE node images — are still on kernel versions that require `CAP_SYS_ADMIN` for a fully functional profiling agent. Even on 5.8+ kernels, stack unwinding for compiled languages often requires either `CAP_SYS_PTRACE` (to read `/proc/<pid>/mem` for frame pointer unwinding) or the use of DWARF-based unwinding via debug frame sections read from the process's mapped binaries. This is process memory access. A compromised profiling agent with these capabilities can read arbitrary memory from any process on the node.

The second security problem is the data the agents produce. A CPU flame graph is not a summary statistic. It is a sampled call stack — typically 100 to 200 samples per second per CPU core — where each sample is an ordered list of function names from the instruction pointer down to the entry point. When a service is built with debug symbols or without `-trimpath`, those function names include package paths (`github.com/myorg/payments/internal/crypto/tokenize.(*Handler).IssueJWT`), file paths, and in DWARF-enriched heap profiles, variable names. A sufficiently detailed flame graph is a map of the authentication boundary, the cryptographic implementation, and the data flow of the profiled service. It is reconnaissance output delivered to the observability platform.

Profile storage adds a third dimension. Parca's default storage is in-memory with optional WAL persistence. Pyroscope's recommended production storage backend is S3-compatible object storage. Neither enforces per-service access control on the stored profiles at the storage layer. The access control question — who may read profiles for the `payments` service — is an application-layer concern, and it is not answered by default in either project.

**Target systems:** Parca v0.20+, Grafana Pyroscope 1.x, Grafana Alloy 1.x, Kubernetes 1.28+, Linux kernel 5.8+.

## Threat Model

1. **Profiling agent compromise leading to node-wide process memory read.** A vulnerability in the Parca Agent or Alloy binary (dependency chain CVE, configuration parsing, gRPC server), combined with the agent's pre-existing `CAP_BPF` and `CAP_PERFMON` grants, allows an attacker to load a custom eBPF program or use the existing perf event interface to read kernel ring buffers. Because the agent already holds open file descriptors to perf event rings for every process it profiles, an attacker with code execution in the agent container does not need to request additional capabilities — the scaffolding is already in place. On clusters where `CAP_SYS_ADMIN` was granted because the kernel predates 5.8, the blast radius extends to mounting the host filesystem, modifying network interfaces, and bypassing namespace isolation.

2. **Developer querying cross-service profiles via unauthenticated Parca API.** The Parca server's query API is unauthenticated in its default configuration. A developer with permission to run `kubectl port-forward svc/parca 7070:7070 -n monitoring` can point the Parca Web UI at `localhost:7070` and query CPU profiles for every service in the cluster. There is no API-level notion of which principals may query which service's profiles. The flame graph for the `payments-api` service, complete with stack frames showing which functions handle card tokenization, is a single label selector query away from any authenticated Kubernetes user.

3. **Profile data exfiltration via Pyroscope push endpoint.** Grafana Pyroscope's ingestion model is push-based: profiling agents send profiles to a central distributor over HTTP with a tenant identifier in the `X-Scope-OrgID` header. In deployments where multi-tenancy is enabled but the ingestion endpoint is not separately authenticated, any process in the cluster with network access to the Pyroscope distributor on port 4040 can inject profiles under an arbitrary tenant identifier, read other tenants' profiles if the query endpoint is not access-controlled, or flood the distributor with high-cardinality label sets to exhaust memory and cause denial of service.

4. **Sensitive frame data leakage through symbol resolution.** The Parca Agent performs symbol resolution for profiled processes by reading ELF symbol tables and DWARF debug frames from the process's mapped memory segments. If a service is deployed with debug symbols — either deliberately (for better flame graph fidelity) or accidentally (because the CI pipeline does not strip symbols on production builds) — the resolved frame names include package-internal function names, struct field names embedded in type information, and file paths on the build host. These details are stored as-is in the Parca profile database and are queryable by anyone with read access to the API.

5. **perf_event_paranoid misconfiguration enabling unprivileged kernel profiling.** The kernel sysctl `kernel.perf_event_paranoid` controls what `perf_event_open` can do without elevated capabilities. A value of `-1` (permissive mode, sometimes set by platform teams to allow developer perf tooling without `sudo`) allows any process to open system-wide perf events and read kernel call stacks. In a Kubernetes cluster where node-level sysctl is shared across all pods, `perf_event_paranoid=-1` means that any process in any container on the node — including those running as non-root in restricted namespaces — can collect kernel profiling data. This is not a profiling agent vulnerability but a kernel configuration that interacts dangerously with the profiling agent's assumed privilege model.

## Configuration / Implementation

### Parca Agent: Minimal Capabilities on Kernel 5.8+

The single most important hardening step is replacing `CAP_SYS_ADMIN` with the minimum capability set on kernels that support it. Verify the node kernel version before applying:

```bash
# Check all nodes for kernel version
kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.nodeInfo.kernelVersion}{"\n"}{end}'

# Kernel 5.8+ supports CAP_BPF and CAP_PERFMON as separate capabilities
# Kernels before 5.8 require CAP_SYS_ADMIN for the same operations
```

For kernel 5.8+, the Parca Agent DaemonSet security context:

```yaml
# parca-agent-daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: parca-agent
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: parca-agent
  template:
    metadata:
      labels:
        app.kubernetes.io/name: parca-agent
    spec:
      serviceAccountName: parca-agent
      # hostPID required for /proc/<pid>/maps access during stack unwinding
      # Scope this exception to the monitoring namespace only via PodSecurity
      hostPID: true
      containers:
        - name: parca-agent
          image: ghcr.io/parca-dev/parca-agent:v0.31.0
          args:
            - "--kubernetes-node=$(NODE_NAME)"
            - "--pod-label-selector=profiling=enabled"
            - "--exclude-namespaces=payments,auth,kube-system"
            - "--bearer-token-file=/etc/parca-agent/auth/token"
            - "--remote-store-address=parca.monitoring.svc.cluster.local:7070"
            - "--remote-store-insecure=false"
          env:
            - name: NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: false    # Agent needs uid 0 for /proc access; see note below
            seccompProfile:
              type: RuntimeDefault  # Restricts syscalls while permitting bpf() and perf_event_open()
            capabilities:
              drop:
                - ALL
              add:
                - BPF          # Load/manage eBPF programs and maps (kernel 5.8+)
                - PERFMON      # perf_event_open, attach to perf events (kernel 5.8+)
                # SYS_PTRACE is required for /proc/<pid>/mem frame pointer unwinding
                # If you use DWARF-only unwinding and can accept narrower language support,
                # omit SYS_PTRACE and set --dwarf-unwinding-only in agent args
                - SYS_PTRACE
          volumeMounts:
            - name: auth-token
              mountPath: /etc/parca-agent/auth
              readOnly: true
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: auth-token
          secret:
            secretName: parca-agent-token
            items:
              - key: token
                path: token
        - name: tmp
          emptyDir: {}
```

The `RuntimeDefault` seccomp profile is compatible with `CAP_BPF` and `CAP_PERFMON` usage. It restricts the full syscall table to a safe subset while still permitting `bpf()`, `perf_event_open()`, `ptrace()`, and the `io_uring` operations Parca Agent uses internally. Verify this after deployment:

```bash
# Confirm eBPF programs are loaded and the agent is running
kubectl logs -n monitoring ds/parca-agent | grep -E 'loaded|program|capability'

# On the node, verify only expected eBPF programs exist
bpftool prog list --json | jq '[.[] | select(.name | startswith("parca")) | {id, type, name}]'
```

### PodSecurity: Isolating the Profiling Namespace

`hostPID: true` grants visibility into every process ID on the node. Scope the exception to only the monitoring namespace:

```bash
# Permit elevated capabilities only in the monitoring namespace
kubectl label namespace monitoring \
  pod-security.kubernetes.io/enforce=privileged \
  pod-security.kubernetes.io/warn=privileged \
  pod-security.kubernetes.io/audit=privileged

# Enforce restricted policy everywhere else — this blocks hostPID
kubectl label namespace payments \
  pod-security.kubernetes.io/enforce=restricted
kubectl label namespace auth \
  pod-security.kubernetes.io/enforce=restricted
```

Use a Kyverno policy to prevent other workloads in the monitoring namespace from accidentally inheriting the same capabilities:

```yaml
# kyverno-cap-bpf-audit.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: audit-cap-bpf-usage
spec:
  validationFailureAction: Audit
  background: true
  rules:
    - name: alert-on-cap-bpf-outside-monitoring
      match:
        any:
          - resources:
              kinds: ["Pod"]
      exclude:
        any:
          - resources:
              namespaces: ["monitoring"]
      validate:
        message: "CAP_BPF and CAP_PERFMON are restricted to the monitoring namespace"
        pattern:
          spec:
            containers:
              - securityContext:
                  capabilities:
                    add:
                      X(BPF|PERFMON|SYS_ADMIN): "!BPF & !PERFMON & !SYS_ADMIN"
```

### perf_event_paranoid Hardening

Check and correct the `perf_event_paranoid` sysctl on every node. The default value of `2` (kernel 4.6+) restricts `perf_event_open` to processes with `CAP_PERFMON`. A value of `-1` removes all restrictions:

```bash
# Check current value on all nodes via a privileged DaemonSet job
# Or check directly on a node via SSH/debug container:
sysctl kernel.perf_event_paranoid

# Correct value: 2 (restrict perf_event_open to CAP_PERFMON holders)
# Value 1: allow CPU events to unprivileged users (less safe)
# Value 0: allow kernel profiling to unprivileged users (unsafe)
# Value -1: no restriction (do not use in production)
```

Enforce the correct value via a node configuration tool. With Kubernetes node feature settings or a custom DaemonSet:

```yaml
# sysctl-hardening-daemonset.yaml (runs once per node boot)
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: sysctl-hardening
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: sysctl-hardening
  template:
    spec:
      hostPID: true
      hostNetwork: true
      initContainers:
        - name: set-perf-paranoid
          image: busybox:1.36
          securityContext:
            privileged: true
          command:
            - /bin/sh
            - -c
            - |
              sysctl -w kernel.perf_event_paranoid=2
              sysctl -w kernel.perf_event_max_sample_rate=1000
      containers:
        - name: pause
          image: gcr.io/google_containers/pause:3.9
```

Alternatively, use `kubelet` node configuration or node init scripts to set the sysctl at boot rather than via a privileged DaemonSet.

### eBPF CO-RE Verifier Safety and Program Integrity

Parca Agent's use of CO-RE means its eBPF programs are verified by the kernel's eBPF verifier on every load. The verifier enforces memory safety, termination, and type correctness. This is a meaningful safety guarantee — a Parca Agent that loads its programs successfully has not bypassed the verifier. However, verifier safety only applies to the programs that Parca loads. It does not prevent a compromised agent from loading *additional* malicious programs using the same capabilities.

Monitor the eBPF program inventory on every node to detect unexpected additions:

```bash
# Establish a baseline of expected Parca eBPF programs on a freshly deployed node
bpftool prog list --json | \
  jq -r '.[] | "\(.id) \(.type) \(.name)"' | \
  sort > /var/lib/parca-agent/prog-baseline.txt

# Run this comparison on a schedule (or via a monitoring DaemonSet)
bpftool prog list --json | \
  jq -r '.[] | "\(.id) \(.type) \(.name)"' | \
  sort > /tmp/prog-current.txt

# Unexpected programs indicate a potential compromise
diff /var/lib/parca-agent/prog-baseline.txt /tmp/prog-current.txt
```

Pin the Parca Agent container image by digest to prevent silent image substitution:

```yaml
# Use a digest pin rather than a mutable tag
image: ghcr.io/parca-dev/parca-agent@sha256:a3f1c2d4e5b6...
```

### Parca Server: Authentication and Network Isolation

Enable bearer token authentication on the Parca server to require credentials on all API calls:

```bash
# Create the server authentication token
kubectl -n monitoring create secret generic parca-api-token \
  --from-literal=token="$(openssl rand -hex 32)"

# Create a separate token for the Parca Agent (write/push only)
kubectl -n monitoring create secret generic parca-agent-push-token \
  --from-literal=token="$(openssl rand -hex 32)"
```

Mount the token in the Parca server deployment:

```yaml
# parca-server-deployment.yaml (relevant section)
spec:
  template:
    spec:
      containers:
        - name: parca
          args:
            - "--bearer-token-file=/etc/parca/auth/token"
            - "--tls-cert-file=/etc/parca/tls/tls.crt"
            - "--tls-key-file=/etc/parca/tls/tls.key"
            - "--storage-active-memory=536870912"
            - "--storage-path=/var/lib/parca"
          volumeMounts:
            - name: auth-token
              mountPath: /etc/parca/auth
              readOnly: true
            - name: parca-tls
              mountPath: /etc/parca/tls
              readOnly: true
      volumes:
        - name: auth-token
          secret:
            secretName: parca-api-token
        - name: parca-tls
          secret:
            secretName: parca-tls-secret
```

Restrict network access to the Parca server using NetworkPolicy. The agent (all nodes) should be allowed to push profiles; only the Grafana pod and SRE tooling should be able to query:

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
    - Egress
  ingress:
    - from:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              app.kubernetes.io/name: parca-agent
      ports:
        - protocol: TCP
          port: 7070
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
  egress:
    - ports:
        - protocol: TCP
          port: 443    # cert-manager OCSP, object storage
        - protocol: UDP
          port: 53     # DNS
```

Also gate `kubectl port-forward` access at the Kubernetes RBAC level. The primary way developers reach the Parca API in most clusters is port-forwarding directly to the pod or service — this bypasses any external ingress authentication:

```yaml
# rbac-parca-portforward.yaml
# Only the sre-team group may port-forward to Parca
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: parca-portforward
  namespace: monitoring
rules:
  - apiGroups: [""]
    resources: ["pods/portforward", "services/portforward"]
    resourceNames: []
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: parca-portforward-sre
  namespace: monitoring
subjects:
  - kind: Group
    name: sre-team
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: parca-portforward
  apiGroup: rbac.authorization.k8s.io
```

### Pyroscope: Multi-Tenancy and API Key Management

Enable Pyroscope multi-tenancy from the initial deployment — retrofitting it after data has accumulated requires re-labelling existing blocks:

```yaml
# pyroscope-values.yaml (Helm)
pyroscope:
  extraArgs:
    - "-auth.multitenancy-enabled=true"
  components:
    distributor:
      extraArgs:
        - "-auth.multitenancy-enabled=true"
    querier:
      extraArgs:
        - "-auth.multitenancy-enabled=true"
    compactor:
      extraArgs:
        - "-auth.multitenancy-enabled=true"
        - "-compactor.blocks-retention-period=168h"

  storage:
    backend: s3
    s3:
      bucket_name: org-pyroscope-profiles
      endpoint: s3.us-east-1.amazonaws.com
      # Use IRSA / Workload Identity — never static credentials
      access_key_id: ""
      secret_access_key: ""
```

Issue per-tenant Grafana data sources with the tenant header injected as a secure value. This prevents users from switching tenant identifiers by modifying the request:

```yaml
# grafana-datasource-payments-team.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: pyroscope-datasource-payments
  namespace: monitoring
  labels:
    grafana_datasource: "1"
data:
  datasource.yaml: |
    apiVersion: 1
    datasources:
      - name: Pyroscope-Payments
        type: grafana-pyroscope-datasource
        url: http://pyroscope-query-frontend.monitoring.svc.cluster.local:4040
        jsonData:
          httpHeaderName1: "X-Scope-OrgID"
        secureJsonData:
          httpHeaderValue1: "payments"
```

For Alloy-based profiling agents pushing to Pyroscope, configure per-team API keys and restrict the push endpoint. Alloy's `pyroscope.write` component accepts a `basic_auth` or `bearer_token` stanza:

```hcl
# alloy-pyroscope-push.alloy
pyroscope.write "payments_remote" {
  endpoint {
    url = "http://pyroscope-distributor.monitoring.svc.cluster.local:4040"
    headers = {
      "X-Scope-OrgID" = "payments",
    }
    basic_auth {
      username = "alloy-payments"
      password = env("PYROSCOPE_API_KEY")
    }
  }
  external_labels = {
    cluster = "prod-us-east-1",
    team    = "payments",
  }
}
```

Store the API key in a Kubernetes Secret and project it into the Alloy pod as an environment variable through `envFrom`, not as a mounted file at a path that appears in Alloy's own profiling frames.

### Profiling Scope: Opt-In Only

Switch from the default opt-out model (profile everything, exclude sensitive namespaces) to an explicit opt-in model (profile nothing unless labelled). This prevents accidentally profiling a newly deployed sensitive service that was not added to the exclusion list:

```yaml
# parca-agent args — opt-in selector
args:
  - "--pod-label-selector=profiling=enabled"
  # Do not use --exclude-namespaces as the primary control;
  # use it as a defence-in-depth backstop only
  - "--exclude-namespaces=payments,auth,secrets-operator"
```

Enforce this at the admission layer with a Kyverno policy that validates the `profiling=enabled` label is only applied to deployments in permitted namespaces:

```yaml
# kyverno-profiling-label-restriction.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-profiling-label
spec:
  validationFailureAction: Enforce
  rules:
    - name: block-profiling-label-in-sensitive-namespaces
      match:
        any:
          - resources:
              kinds: ["Pod", "Deployment", "StatefulSet"]
              namespaces: ["payments", "auth", "secrets-operator"]
      validate:
        message: "The profiling=enabled label is not permitted in this namespace"
        pattern:
          metadata:
            labels:
              =(profiling): "!enabled"
```

### Symbol Stripping to Limit Profile Data Sensitivity

Build production Go binaries without debug symbols and with path trimming. This reduces the information density of profiles stored in Parca without eliminating the profiling capability — function names are preserved; file paths, struct field names, and compiler-internal metadata are removed:

```dockerfile
# Dockerfile — production build
FROM golang:1.22 AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /app/server \
    ./cmd/server

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /app/server /server
ENTRYPOINT ["/server"]
```

Validate that production binaries have no debug sections before they reach the container registry:

```bash
# Run in CI after the build stage, before the push stage
objdump -h ./server | grep -E '\.debug_info|\.debug_line|\.debug_frame'
# Should produce no output

# Check for embedded build host paths (from -trimpath omission)
strings ./server | grep -E '^/home/|^/root/|^/Users/' | head -5
# Should produce no output
```

For Java and JVM-based services, configure the Pyroscope JVM agent to exclude sensitive stack frames from symbol resolution using the `profilingExcludeAgents` and `profilingAlloc` settings, and to avoid capturing `sun.security.*` and `javax.crypto.*` frame details by filtering in the agent configuration:

```yaml
# alloy-pyroscope-java.alloy
pyroscope.java "payments_jvm" {
  profiling_config {
    cpu    = true
    alloc  = false    # Heap allocation profiles carry higher data sensitivity
    lock   = false
    sample_rate = 100
  }
}
```

## Expected Behaviour

| Signal | Without hardening | With hardening |
|---|---|---|
| Capability grant for Parca Agent DaemonSet | `CAP_SYS_ADMIN` or `privileged: true`; grants all kernel capabilities including filesystem mount, network device control, and DAC bypass | `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_PTRACE` only; verifiable with `kubectl get pod -n monitoring -o json \| jq '.spec.containers[].securityContext.capabilities'` |
| Developer access to cross-team profiles | Any Kubernetes user with `kubectl port-forward` access to the monitoring namespace can query any service's flame graphs with no additional authentication | Parca bearer token required; Kubernetes RBAC restricts `pods/portforward` to `sre-team`; unauthorized queries return `401 Unauthorized` |
| `kernel.perf_event_paranoid` value on nodes | `-1` or `0` set by platform team for developer convenience; any pod can call `perf_event_open` without elevated capabilities | Value `2` enforced at node boot; only processes with `CAP_PERFMON` can open perf events; non-privileged pods receive `EACCES` on `perf_event_open` |
| Debug symbols in stored profiles | Full file paths (`/home/ci/src/github.com/org/payments/...`), struct field names, and build host metadata visible in Parca query UI | `-trimpath -ldflags="-s -w"` removes paths and DWARF sections; profiles show function names only; confirmed by `objdump` finding no `.debug_info` sections |
| Pyroscope cross-tenant profile access | `X-Scope-OrgID` header set client-side; any Grafana user can modify the header in a forked request to query another team's profiles | Multi-tenancy enabled; Grafana datasource injects tenant header from `secureJsonData`; end-users cannot override it; Pyroscope rejects requests with no valid tenant |
| Newly deployed sensitive service accidentally profiled | Exclusion list must be kept current; any service added to `payments` namespace without updating the list is profiled until someone notices | Opt-in label required; new services in all namespaces are not profiled until explicitly labelled `profiling=enabled`; Kyverno blocks labelling in restricted namespaces |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| `CAP_BPF` + `CAP_PERFMON` over `CAP_SYS_ADMIN` | Eliminates the broadest kernel capability grant; limits what a compromised agent can do with its existing privileges | Requires kernel 5.8+; EKS, GKE, and AKS may run older AMIs that predate the capability split; capability availability must be verified per node pool before deployment | Pin node pool OS images to versions shipping kernel 5.8+; use `kubectl get nodes -o wide` to audit kernel versions before applying the narrowed security context |
| eBPF CO-RE verifier safety | Parca's eBPF programs cannot corrupt kernel memory or loop indefinitely; verifier acceptance is a meaningful safety guarantee absent from kernel modules | Verifier safety applies only to programs Parca loads, not to additional programs an attacker might load using the same `CAP_BPF` grant; the capability is a persistent attack surface | Monitor the eBPF program inventory at a scheduled interval; alert on any program not in the baseline; pin the agent image by digest to prevent supply chain substitution |
| Symbol stripping (`-trimpath -ldflags="-s -w"`) | Eliminates file paths, struct field names, and build host metadata from profile data; reduces binary size by 20–40% | Post-incident debugging loses line number information; panic stack traces show only function names; pprof heap profiles become less useful for memory leak investigation | Store unstripped debug binaries in a secured artifact registry indexed by build ID; use debuginfod or Parca's symbol server API to serve symbols to authorised engineers on demand; do not store symbols alongside production binaries |
| Opt-in profiling (`profiling=enabled` label) | Prevents inadvertent profiling of new or sensitive services; security boundary does not degrade as the cluster grows | Developers must explicitly label services before profiles appear; flame graphs absent during performance investigations until the label is applied | Automate label application via a deployment template in the team's scaffolding; document the label in onboarding runbooks; build a Grafana panel showing services that are not profiled as a discoverability aid |
| Pyroscope multi-tenancy | Per-tenant data isolation; cross-team profile access is structurally impossible within the same Pyroscope deployment | Requires Helm reconfiguration and a separate Grafana datasource per tenant; operational overhead scales with team count; must be enabled before initial data ingestion | Implement from day one; use Grafana team-scoped data source permissions to automate tenant-to-datasource mapping; script datasource provisioning per team from a shared template |
| `hostPID: true` on profiling agent pods | Required for `/proc/<pid>/maps` access during stack unwinding for compiled languages; without it, Go and Rust profiles show unresolved frames | Grants the profiling agent visibility into every process ID on the node; a compromised agent can read memory maps of any process without additional privilege escalation | Confine the exception to the monitoring namespace via PodSecurity `privileged` policy; enforce `restricted` on all other namespaces; monitor for `hostPID: true` usage outside the monitoring namespace with Kyverno or OPA Gatekeeper |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| `CAP_BPF` unavailable on pre-5.8 kernel | Parca Agent fails to load eBPF programs; agent pod crash-loops with `operation not permitted`; no profiles appear in Parca for affected nodes | Alert on `parca_agent_up == 0` per node label; `kubectl logs -n monitoring ds/parca-agent --previous` shows eBPF load errors; `uname -r` on affected nodes returns version < 5.8 | Fall back to `CAP_SYS_ADMIN` as a temporary measure while kernel upgrade is planned; document the fallback in the change log and set a remediation deadline; update node pool AMI to a version shipping kernel 5.8+ |
| `perf_event_paranoid` reset to `-1` by node restart or competing automation | Unprivileged profiling re-enabled; non-profiling pods can read kernel events; sysctl hardening DaemonSet did not run after node restart | Monitor `node_sysctl_kernel_perf_event_paranoid` metric via the node-exporter `sysctl` collector; alert on value < 2; audit with `kubectl debug node/<name> -it --image=busybox -- sysctl kernel.perf_event_paranoid` | Run the sysctl hardening DaemonSet on each node reboot using a Kubernetes Job with `restartPolicy: OnFailure` triggered by node-ready events; alternatively encode the sysctl in the node OS image via cloud-init or Ignition |
| `hostPID: true` blocked by admission policy on monitoring namespace | Parca Agent DaemonSet pods fail admission; pods never enter Running state; all profiles absent | `kubectl describe daemonset parca-agent -n monitoring` shows 0 desired/current pods; admission webhook logs show policy violation for `hostPID: true` | Apply PodSecurity `privileged` label to the monitoring namespace; if using OPA Gatekeeper or Kyverno, add an explicit namespace exception for the profiling DaemonSet; re-apply the DaemonSet after the exception is in place |
| Pyroscope multi-tenancy enabled mid-deployment with existing single-tenant data | Existing profiles (written without a tenant label) become inaccessible; services report zero historical profiles; teams see empty flame graphs for the pre-migration period | Pyroscope query logs show `tenant header required` for old blocks; `--querier.query-store-after` setting determines whether old blocks are queried at all | Re-index existing blocks with a tenant identifier using the Pyroscope admin compaction API; alternatively, accept the data loss for the pre-multi-tenancy period and document it in the retention runbook; enable multi-tenancy on all future deployments from initial cluster bootstrapping |
| Symbol stripping breaks production panic symbolisation | On-call engineers see unsymbolised panic stack traces with only hex addresses; incident mean time to identify root cause increases | Grafana alerts fire; `kubectl logs` shows hex addresses instead of function names; build pipeline objdump check confirms no debug sections | Access unstripped binary from the artifact registry by looking up the build ID from the binary's `.note.go.buildid` section; use `go tool addr2line` with the unstripped binary to resolve addresses; update the runbook to document the break-glass symbol resolution procedure |

## Related Articles

- [Continuous Profiling Security with Parca and Pyroscope](/articles/observability/continuous-profiling-security/)
- [Grafana Beyla eBPF Auto-Instrumentation Security](/articles/observability/beyla-ebpf-autoinstrumentation-security/)
- [eBPF Security with Tetragon](/articles/observability/ebpf-tetragon/)
- [OpenTelemetry PII Leakage](/articles/observability/otel-pii-leakage/)
- [Kubernetes RBAC Design Patterns](/articles/kubernetes/rbac-design-patterns/)
