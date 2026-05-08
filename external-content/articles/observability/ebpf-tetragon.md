---
title: "eBPF-Based Security Monitoring: Tetragon for Process, Network, and File Observability"
description: "Falco monitors syscalls for runtime detection. Tetragon (CNCF/Cilium) goes deeper: it monitors process execution, network connections, and file..."
slug: "ebpf-tetragon"
date: 2026-02-22
lastmod: 2026-02-22
category: "observability"
tags: ["ebpf", "tetragon", "cilium", "runtime-security", "process-monitoring", "falco"]
personas: ["security-engineer", "platform-engineer"]
article_number: 75
difficulty: "advanced"
estimated_reading_time: 18
provider_bridges:
  - name: "Isovalent"
    id: 54
    category: "service-mesh"
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
premium_pack: "tetragon-tracing-policies"
published: true
layout: article.njk
permalink: "/articles/observability/ebpf-tetragon/index.html"
---

# eBPF-Based Security Monitoring: [Tetragon](https://tetragon.io) for Process, Network, and File Observability

## Problem

[Falco](https://falco.org) monitors syscalls for runtime detection. Tetragon (CNCF/[Cilium](https://cilium.io)) goes deeper: it monitors process execution, network connections, and file access at the eBPF level with enforcement capability, it can block actions in real time, not just detect them. Most engineers do not know Tetragon exists or how it complements Falco.

Key differences:
- **Falco:** Detection-only (alert on suspicious activity). Kernel module or eBPF driver. Rule-based matching against syscall events.
- **Tetragon:** Detection AND enforcement (alert and/or block). eBPF-only (no kernel module). TracingPolicy CRDs for [Kubernetes](https://kubernetes.io)-native configuration. Can SIGKILL a process that violates policy.

Use both: Falco for broad behavioural detection rules, Tetragon for targeted enforcement on specific high-risk actions.

**Target systems:** Kubernetes 1.29+ with kernel 5.8+ (eBPF requirement). Tetragon 1.2+.

## Threat Model

- **Adversary:** Attacker with code execution inside a container, attempting: reverse shell, credential theft, container escape, crypto mining, or data exfiltration.
- **Key advantage of Tetragon over detection-only:** Tetragon can kill the malicious process before the attack completes, not just alert after it succeeds.

## Configuration

### Deployment

```bash
helm repo add cilium https://helm.cilium.io
helm repo update

helm install tetragon cilium/tetragon \
  --namespace kube-system \
  --set tetragon.grpc.enabled=true \
  --set tetragon.exportFilename=/var/run/cilium/tetragon/tetragon.log \
  --set tetragon.resources.requests.cpu=100m \
  --set tetragon.resources.requests.memory=256Mi \
  --set tetragon.resources.limits.cpu=1000m \
  --set tetragon.resources.limits.memory=512Mi
```

```bash
# Install the tetra CLI for event viewing
GOOS=$(go env GOOS)
GOARCH=$(go env GOARCH)
curl -L "https://github.com/cilium/tetragon/releases/latest/download/tetra-${GOOS}-${GOARCH}.tar.gz" | tar -xz
sudo mv tetra /usr/local/bin/

# Verify Tetragon is running:
kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon
# Expected: one pod per node, Running

# View live events:
kubectl exec -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact
```

### TracingPolicy: Process Execution Monitoring

```yaml
# process-monitor.yaml
# Monitor all process executions in production namespaces.
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: monitor-process-execution
spec:
  kprobes:
    - call: "sys_execve"
      syscall: true
      return: false
      args:
        - index: 0
          type: "string"  # filename (binary path)
      selectors:
        - matchNamespaces:
            - namespace: production
              operator: In
```

```bash
# View process execution events:
kubectl exec -n kube-system ds/tetragon -c tetragon -- \
  tetra getevents -o compact --namespaces production

# Example output:
# 🚀 process production/nginx-7d8f9b/nginx  /usr/sbin/nginx
# 🚀 process production/nginx-7d8f9b/nginx  /bin/sh -c "echo test"  ← SUSPICIOUS
```

### TracingPolicy: Block Specific Binaries (Enforcement)

```yaml
# block-crypto-miners.yaml
# Kill any known crypto mining binary immediately.
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: block-crypto-miners
spec:
  kprobes:
    - call: "sys_execve"
      syscall: true
      args:
        - index: 0
          type: "string"
      selectors:
        - matchArgs:
            - index: 0
              operator: "In"
              values:
                - "/usr/bin/xmrig"
                - "/tmp/xmrig"
                - "/usr/local/bin/minerd"
                - "/tmp/minerd"
                - "/usr/bin/cpuminer"
          matchActions:
            - action: Sigkill  # Kill the process immediately
```

**Warning:** Enforcement (Sigkill) has no undo. If the policy matches a legitimate process, it is killed instantly. Test enforcement policies in monitoring-only mode first (remove `matchActions`), verify zero false positives for 7 days, then enable Sigkill.

### TracingPolicy: Network Connection Monitoring

```yaml
# network-monitor.yaml
# Monitor outbound TCP connections from production pods.
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: monitor-outbound-connections
spec:
  kprobes:
    - call: "tcp_connect"
      syscall: false
      args:
        - index: 0
          type: "sock"
      selectors:
        - matchNamespaces:
            - namespace: production
              operator: In
```

### TracingPolicy: Sensitive File Access

```yaml
# file-access-monitor.yaml
# Monitor access to sensitive files in containers.
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: monitor-sensitive-files
spec:
  kprobes:
    - call: "fd_install"
      syscall: false
      args:
        - index: 0
          type: "int"
        - index: 1
          type: "file"
      selectors:
        - matchArgs:
            - index: 1
              operator: "Prefix"
              values:
                - "/etc/shadow"
                - "/etc/passwd"
                - "/run/secrets/kubernetes.io/serviceaccount/token"
                - "/proc/1/environ"
          matchNamespaces:
            - namespace: production
              operator: In
```

### Event Export to [Grafana](https://grafana.com) Cloud

```yaml
# vector-tetragon.yaml - ship Tetragon events to centralized logging
sources:
  tetragon_events:
    type: file
    include:
      - /var/run/cilium/tetragon/tetragon.log

transforms:
  parse_tetragon:
    type: remap
    inputs: [tetragon_events]
    source: |
      . = parse_json!(.message)
      .source = "tetragon"

sinks:
  grafana_cloud:
    type: loki
    inputs: [parse_tetragon]
    endpoint: "https://logs-prod-us-central1.grafana.net"
    auth:
      strategy: basic
      user: "${LOKI_USER}"
      password: "${LOKI_API_KEY}"
    labels:
      source: tetragon
      event_type: "{{ process_exec.process.binary }}"
      namespace: "{{ process_exec.process.pod.namespace }}"
```

### Tetragon vs Falco: When to Use Each

| Scenario | Tool | Reason |
|----------|------|--------|
| Broad behavioural detection (unexpected processes) | Falco | Falco's rule language is more expressive for behavioural patterns |
| Enforce: kill crypto mining binaries | Tetragon | Enforcement capability (Sigkill) |
| Network flow baselines and anomaly detection | Tetragon + [Hubble](https://docs.cilium.io/en/stable/observability/hubble/) | Native integration with Cilium networking |
| Sensitive file access monitoring | Tetragon | Lower overhead per-file monitoring |
| Container escape detection | Both | Falco for broad patterns, Tetragon for specific enforcement |
| Multi-cluster rule management | Falco + [Sysdig](https://sysdig.com) | Better managed rule distribution ecosystem |

**Recommendation:** Deploy both. Falco for broad detection and alert routing (via [Falcosidekick](https://github.com/falcosecurity/falcosidekick)). Tetragon for targeted enforcement on known-dangerous actions and deep file/network visibility.

## Expected Behaviour

- Tetragon DaemonSet running on all nodes (pod count = node count)
- Process execution events visible in `tetra getevents`
- Enforcement policies kill targeted binaries within milliseconds
- Sensitive file access events exported to [Grafana Cloud](https://grafana.com/cloud)
- Network connection events correlated with Hubble flow data
- CPU overhead below 2% per node

```bash
# Verify enforcement:
kubectl exec -n production deploy/test -- /tmp/test-binary
# If the binary matches a block policy: process is killed immediately
# tetra events show: 💀 exit production/test/test /tmp/test-binary SIGKILL
```

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Enforcement (Sigkill) | Instant process termination | Kills legitimate processes if policy is too broad | Monitor-only for 7 days before enabling enforcement. Use precise path matching. |
| Process monitoring (all execve) | Complete visibility into all process execution | High event volume on busy nodes (1000+ events/sec) | Filter by namespace. Export only security-relevant events. |
| File access monitoring | Detect credential access, config modification | I/O overhead for high-throughput file access | Monitor specific paths only (not all file access). |
| eBPF requirement (kernel 5.8+) | No kernel module needed | Some older cloud provider images have kernel <5.8 | Check node kernel version before deployment. Upgrade node image if needed. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| TracingPolicy syntax error | Policy not applied; no events generated | `kubectl get tracingpolicies` shows error status; `kubectl describe` shows validation error | Fix YAML syntax. Reapply. Tetragon validates policies at admission. |
| Enforcement kills legitimate process | Application service disrupted | Service monitoring detects pod crash; Tetragon event log shows Sigkill | Remove or narrow the enforcement policy. Restart the affected pod. Test policy in monitor-only mode for longer. |
| Tetragon OOM on busy node | Tetragon pod crashloops; monitoring gap | Pod restart count increases; DaemonSet availability drops | Increase memory limits. Reduce TracingPolicy scope (fewer monitored namespaces or paths). |
| Event export pipeline fails | Events generated but not shipped to centralized storage | Tetragon events visible locally but not in Grafana Cloud; [Vector](https://vector.dev) delivery metrics show failures | Fix Vector pipeline. Events are buffered locally and ship when the pipeline recovers. |

## When to Consider a Managed Alternative

Tetragon event volume at scale requires managed storage. TracingPolicy lifecycle management across clusters requires centralized distribution.

- **[Isovalent](https://isovalent.com) Cilium Enterprise:** Managed Tetragon with policy lifecycle management, UI for TracingPolicy creation, and multi-cluster policy distribution.
- **[Sysdig](https://sysdig.com):** eBPF-based monitoring with managed platform. Not Tetragon-native but provides similar eBPF process/network/file monitoring.
- **[Grafana Cloud](https://grafana.com/cloud):** For Tetragon event storage and dashboarding.

**Premium content pack:** Tetragon TracingPolicy collection. policies for process execution monitoring (per container image), crypto miner enforcement (block + kill), sensitive file access detection, network connection monitoring, and Grafana dashboards for Tetragon events.


## Related Articles

- [Lateral Movement Detection: Network Patterns, Authentication Anomalies, and Alert Correlation](/articles/observability/lateral-movement-detection/)
- [Container Escape Detection: Runtime Signals, Kernel Indicators, and Response Automation](/articles/observability/container-escape-detection/)
- [Crypto Mining Detection: CPU Patterns, Network Signatures, and Automated Response](/articles/observability/crypto-mining-detection/)
- [Building Detection Rules That Don't Cry Wolf: Alert Design for Security Events](/articles/observability/detection-rules/)
- [Kubernetes Audit Log Pipeline Design: From API Server to SIEM](/articles/observability/k8s-audit-log-design/)
