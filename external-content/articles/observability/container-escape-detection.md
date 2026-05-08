---
title: "Container Escape Detection: Runtime Signals, Kernel Indicators, and Response Automation"
description: "Container escapes are the highest-impact attack in Kubernetes. A single compromised pod that escapes its container gains access to the underlying..."
slug: "container-escape-detection"
date: 2026-02-07
lastmod: 2026-02-07
category: "observability"
tags: ["container-security", "falco", "tetragon", "runtime-detection", "container-escape", "kubernetes"]
personas: ["security-engineer", "platform-engineer"]
article_number: 71
difficulty: "advanced"
estimated_reading_time: 18
provider_bridges:
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
  - name: "Aqua"
    id: 123
    category: "runtime-security"
premium_pack: "container-escape-falco-rules"
published: true
layout: article.njk
permalink: "/articles/observability/container-escape-detection/index.html"
---

# Container Escape Detection: Runtime Signals, Kernel Indicators, and Response Automation

## Problem

Container escapes are the highest-impact attack in [Kubernetes](https://kubernetes.io). A single compromised pod that escapes its container gains access to the underlying node, and from there to every other pod on that node, the kubelet credentials, and potentially the entire cluster. Detection must catch the escape attempt before it succeeds, because once the attacker has node-level access, they can disable the monitoring that would detect them.

The specific challenges:

- **Escape techniques are kernel-level.** Container escapes exploit namespace manipulation (`nsenter`, `unshare`), cgroup breakouts, `/proc` filesystem abuse, and mounted host paths. Detecting these requires kernel-level instrumentation, not application-level logging.
- **Legitimate admin operations look like escapes.** `nsenter` into a container namespace is a normal debugging tool. Mounting host paths is required for log collection and storage. Detection rules must distinguish between authorized admin actions and attack techniques.
- **New escape techniques appear regularly.** CVE-2024-21626 (runc `WORKDIR` escape), CVE-2022-0185 (file system context escape), and Leaky Vessels (2024) each introduced new escape vectors. Static detection rules that check for known techniques miss novel exploits.
- **Privileged containers bypass all protections.** Containers running with `privileged: true` or with specific dangerous capabilities (`SYS_ADMIN`, `SYS_PTRACE`) can escape trivially. Detection for privileged containers is a different problem than detection for standard containers.

This article covers [Falco](https://falco.org) rules for known escape techniques, [Tetragon](https://tetragon.io) TracingPolicies for kernel-level detection and blocking, Kubernetes audit log patterns, and automated response.

**Target systems:** Kubernetes clusters with Falco or Tetragon deployed as DaemonSets. [Prometheus](https://prometheus.io) + Alertmanager. [Cilium](https://cilium.io) for network-level response.

## Threat Model

- **Adversary:** An attacker who has gained code execution inside a container (through application vulnerability, supply chain compromise, or compromised image). They attempt to break out of the container namespace to reach the host node.
- **Blast radius:** A successful container escape gives the attacker root on the node. From there: access to kubelet credentials (can impersonate the node in the cluster), access to all pods on the node (including secrets mounted as volumes), ability to pivot to other nodes via the cluster network, and potential access to the cloud provider metadata service for further privilege escalation.

## Configuration

### Falco Rules for Known Escape Techniques

```yaml
# falco-rules-container-escape.yaml
# Rules detecting common container escape techniques.

# Rule 1: nsenter or unshare execution inside a container.
# nsenter allows entering another namespace (escape to host namespace).
# unshare creates new namespaces (can be used to gain capabilities).
- rule: Namespace Manipulation in Container
  desc: >
    Detected nsenter or unshare execution inside a container.
    This is a strong indicator of a container escape attempt.
  condition: >
    spawned_process
    and container
    and (proc.name in (nsenter, unshare))
    and not (k8s.ns.name in (kube-system, monitoring))
  output: >
    Namespace manipulation in container
    (command=%proc.cmdline container=%container.name
     image=%container.image.repository namespace=%k8s.ns.name
     pod=%k8s.pod.name user=%user.name)
  priority: CRITICAL
  tags: [container-escape, namespace]

# Rule 2: mount syscall from a non-init process in a container.
# Mounting filesystems inside a container is unusual and may indicate
# an attempt to mount the host filesystem.
- rule: Unexpected Mount in Container
  desc: >
    A process inside a container executed a mount syscall.
    This may indicate an attempt to mount host filesystems.
  condition: >
    evt.type = mount
    and container
    and proc.pid != 1
    and not (proc.pname in (mount, umount, systemd))
    and not (k8s.ns.name in (kube-system))
  output: >
    Mount syscall in container
    (command=%proc.cmdline container=%container.name
     image=%container.image.repository namespace=%k8s.ns.name)
  priority: CRITICAL
  tags: [container-escape, mount]

# Rule 3: write to sensitive /proc paths.
# /proc/sysrq-trigger can reboot the host.
# /proc/*/mem can read/write other process memory.
- rule: Write to Sensitive Proc Path
  desc: >
    A container process wrote to a sensitive /proc path that could
    affect the host or other processes.
  condition: >
    open_write
    and container
    and (fd.name startswith /proc/sysrq-trigger
         or fd.name startswith /proc/self/mem
         or fd.name startswith /host/proc)
  output: >
    Write to sensitive /proc path
    (file=%fd.name command=%proc.cmdline container=%container.name
     namespace=%k8s.ns.name pod=%k8s.pod.name)
  priority: CRITICAL
  tags: [container-escape, proc]

# Rule 4: access to Docker socket or containerd socket.
# Direct socket access allows creating new privileged containers.
- rule: Container Runtime Socket Access
  desc: >
    A process inside a container accessed the container runtime socket.
    This allows creating new containers with arbitrary privileges.
  condition: >
    (open_read or open_write)
    and container
    and (fd.name in (/var/run/docker.sock, /run/containerd/containerd.sock,
                     /var/run/crio/crio.sock))
  output: >
    Container runtime socket access
    (socket=%fd.name command=%proc.cmdline container=%container.name
     namespace=%k8s.ns.name pod=%k8s.pod.name)
  priority: CRITICAL
  tags: [container-escape, runtime-socket]

# Rule 5: cgroup escape attempt (notify_on_release).
# Classic cgroup v1 escape: write to notify_on_release and release_agent.
- rule: Cgroup Escape Attempt
  desc: >
    A container process wrote to cgroup notify_on_release or release_agent,
    which is the classic cgroup v1 container escape technique.
  condition: >
    open_write
    and container
    and (fd.name contains notify_on_release or fd.name contains release_agent)
  output: >
    Cgroup escape attempt
    (file=%fd.name command=%proc.cmdline container=%container.name
     namespace=%k8s.ns.name pod=%k8s.pod.name)
  priority: CRITICAL
  tags: [container-escape, cgroup]

# Rule 6: access to host filesystem via mounted paths.
# Pods with hostPath mounts may access sensitive host files.
- rule: Sensitive Host Path Access
  desc: >
    A container accessed sensitive files through a host path mount.
  condition: >
    (open_read or open_write)
    and container
    and (fd.name startswith /host/etc/shadow
         or fd.name startswith /host/etc/kubernetes
         or fd.name startswith /host/root/.ssh
         or fd.name startswith /host/var/lib/kubelet)
  output: >
    Sensitive host path access
    (file=%fd.name command=%proc.cmdline container=%container.name
     namespace=%k8s.ns.name pod=%k8s.pod.name)
  priority: CRITICAL
  tags: [container-escape, host-path]
```

### Tetragon TracingPolicies for Real-Time Blocking

Tetragon can block escape attempts at the kernel level, not just detect them:

```yaml
# tetragon-escape-policy.yaml
# TracingPolicy that kills the process attempting a container escape.
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: container-escape-prevention
spec:
  kprobes:
    # Block nsenter/unshare in non-system namespaces.
    - call: "__x64_sys_setns"
      syscall: true
      selectors:
        - matchNamespaces:
            - namespace: Pid
              operator: NotIn
              values:
                - "host_ns"
          matchActions:
            - action: Sigkill
              argError: -1
      args:
        - index: 0
          type: int
        - index: 1
          type: int

    # Block mount syscall from containers (non-init processes).
    - call: "__x64_sys_mount"
      syscall: true
      selectors:
        - matchPIDs:
            - operator: NotIn
              followForks: true
              values:
                - 1
          matchNamespaces:
            - namespace: Mnt
              operator: NotIn
              values:
                - "host_ns"
          matchActions:
            - action: Sigkill

    # Block writes to cgroup escape paths.
    - call: "security_file_open"
      selectors:
        - matchArgs:
            - index: 0
              operator: Postfix
              values:
                - "notify_on_release"
                - "release_agent"
          matchActions:
            - action: Sigkill
```

### Kubernetes Audit Log Patterns

Detect escape-adjacent activity through the API server:

```yaml
# Prometheus alerting rules based on Kubernetes audit log events.
groups:
  - name: container-escape-audit
    rules:
      # Alert: exec into a pod with suspicious commands.
      - alert: SuspiciousPodExec
        expr: >
          sum by (user, namespace, pod) (
            rate(apiserver_audit_event_total{
              verb="create",
              resource="pods/exec",
              request_uri=~".*command=(nsenter|chroot|mount|unshare).*"
            }[5m])
          ) > 0
        for: 1m
        labels:
          severity: critical
          detection_type: container_escape
        annotations:
          summary: >
            Suspicious exec: {{ $labels.user }} ran escape-related
            command in {{ $labels.namespace }}/{{ $labels.pod }}

      # Alert: pod created with privileged security context.
      - alert: PrivilegedPodCreated
        expr: >
          sum by (user, namespace) (
            rate(apiserver_audit_event_total{
              verb="create",
              resource="pods",
              request_object=~".*privileged.*true.*"
            }[5m])
          ) > 0
        for: 1m
        labels:
          severity: warning
          detection_type: privilege_escalation
        annotations:
          summary: >
            Privileged pod created by {{ $labels.user }}
            in {{ $labels.namespace }}
```

### Automated Response

```yaml
# Falcosidekick configuration: auto-respond to container escape events.
config:
  kubernetesPolicyReport:
    enabled: true
    minimumpriority: "critical"

  webhook:
    address: "http://response-automation:8080/falco"
    minimumpriority: "critical"

# Response actions for container escape:
# 1. Kill the offending pod immediately.
# 2. Apply network quarantine to prevent lateral movement.
# 3. Cordon the node (prevent new pods from scheduling).
# 4. Page the security team with forensic context.

---
# response-actions.yaml (webhook handler configuration)
actions:
  container_escape:
    rules:
      - "Namespace Manipulation in Container"
      - "Cgroup Escape Attempt"
      - "Container Runtime Socket Access"
    steps:
      - type: kubectl
        command: "delete pod {{ .pod }} -n {{ .namespace }} --grace-period=0"
      - type: kubectl
        command: "label pod {{ .pod }} -n {{ .namespace }} security.quarantine=true"
      - type: kubectl
        command: "cordon {{ .node }}"
      - type: alert
        severity: critical
        channel: "#security-incidents"
```

## Expected Behaviour

- `nsenter`, `unshare`, and `mount` execution inside containers triggers a CRITICAL alert within seconds
- Writes to `/proc/sysrq-trigger`, cgroup escape paths, and container runtime sockets are detected and blocked
- Tetragon kills escape processes at the kernel level before the escape completes
- Suspicious `kubectl exec` commands are flagged through Kubernetes audit log monitoring
- Privileged pod creation generates a WARNING alert
- Automated response kills the pod, quarantines the workload, and cordons the node within 30 seconds
- False positive rate below 1 per week after excluding `kube-system` and monitoring namespaces

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| Tetragon Sigkill on escape attempt | Blocks escape in real time, before completion | False positive kills a legitimate process | Exclude kube-system, monitoring, and other trusted namespaces. Test rules in audit mode (action: Post) before enabling Sigkill. |
| Auto-cordon node on escape detection | Prevents attacker from scheduling new pods on compromised node | Reduces cluster capacity; may cause scheduling pressure | Auto-uncordon after security team clears the node (within SLA). Ensure sufficient capacity to absorb one cordoned node. |
| Falco + Tetragon (both deployed) | Falco for visibility and alerting; Tetragon for blocking | Two DaemonSets add resource overhead (100-200MB RAM per node) | Use Falco for detection/alerting only. Use Tetragon for enforcement. Do not duplicate rules between them. |
| Excluding kube-system from rules | Reduces false positives from system components | Attacker could deploy malicious workload in kube-system | Restrict kube-system namespace with RBAC and admission control. Alert on any non-system workload deployed to kube-system. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Falco DaemonSet not running on a node | No escape detection on that node | `absent(falco_events_total{node="X"})` or DaemonSet pod count mismatch | Check node taints/tolerations. Ensure Falco DaemonSet has appropriate tolerations for all nodes. |
| Tetragon policy not loaded | Escape attempts detected by Falco but not blocked | Tetragon logs show policy parse error; escape process is not killed | Validate TracingPolicy with `kubectl describe tracingpolicy`. Check Tetragon agent logs for BPF program load errors. |
| Escape technique uses unknown vector | No rule matches; escape succeeds undetected | Post-incident investigation reveals new technique | Subscribe to container security advisories. Update rules within 48 hours of new CVE disclosure. Add generic behavioural rules (unexpected capability usage). |
| Auto-response kills legitimate pod | Service disruption; pod restarts in a loop | Pod restart count increases; service health checks fail | Review the triggering event. Add an exception for the specific workload if it legitimately needs the detected behaviour. |
| Node cordoned but not uncordoned | Cluster capacity shrinks over time as nodes accumulate cordons | Node count in schedulable state decreasing | Set a TTL on cordon actions (auto-uncordon after 4 hours unless security team extends). Alert on nodes cordoned for more than 2 hours. |

## When to Consider a Managed Alternative

Self-managed container escape detection requires Falco and/or Tetragon DaemonSet operation, rule maintenance for new CVEs, automated response infrastructure, and regular rule tuning (6-8 hours/month).

- **[Sysdig](https://sysdig.com):** Managed Falco rules with automatic updates for new escape techniques. Drift detection that identifies unexpected changes inside containers. Multi-cluster rule management from a single console.
- **[Aqua](https://www.aquasec.com):** Runtime protection with container escape prevention built in. Enforcement mode blocks escape attempts without custom rule writing. Integrates vulnerability scanning with runtime detection.

**Premium content pack:** Container escape Falco rule pack. 20+ rules covering nsenter, unshare, mount, cgroup breakout, proc filesystem abuse, runtime socket access, and host path exploitation. Includes Tetragon TracingPolicies, automated response configurations, and a testing framework for validating detection rules.


## Related Articles

- [Crypto Mining Detection: CPU Patterns, Network Signatures, and Automated Response](/articles/observability/crypto-mining-detection/)
- [eBPF-Based Security Monitoring: Tetragon for Process, Network, and File Observability](/articles/observability/ebpf-tetragon/)
- [Lateral Movement Detection: Network Patterns, Authentication Anomalies, and Alert Correlation](/articles/observability/lateral-movement-detection/)
- [Kubernetes Audit Log Pipeline Design: From API Server to SIEM](/articles/observability/k8s-audit-log-design/)
- [Building Detection Rules That Don't Cry Wolf: Alert Design for Security Events](/articles/observability/detection-rules/)
