---
title: "Sandboxing AI Agent Tool Use: Filesystem, Network, and Process Isolation for Autonomous Actions"
description: "AI agents execute tool calls on real infrastructure: writing files, running shell commands, making HTTP requests, modifying databases."
slug: "agent-tool-use-sandboxing"
date: 2026-01-26
lastmod: 2026-01-26
category: "ai-landscape"
tags: ["ai-agents", "sandboxing", "gvisor", "firecracker", "isolation", "filesystem-security"]
personas: ["platform-engineer", "security-engineer", "ai-ml-engineer"]
article_number: 112
difficulty: "advanced"
estimated_reading_time: 18
provider_bridges:
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
  - name: "Vault"
    id: 65
    category: "secrets"
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
premium_pack: "agent-sandboxing-pack"
published: true
layout: article.njk
permalink: "/articles/ai-landscape/agent-tool-use-sandboxing/index.html"
---

# Sandboxing AI Agent Tool Use: Filesystem, Network, and Process Isolation for Autonomous Actions

## Problem

AI agents execute tool calls on real infrastructure: writing files, running shell commands, making HTTP requests, modifying databases. When an agent hallucinates a command, misinterprets context, or gets manipulated through prompt injection, it executes with the full permissions of the host process. A single `rm -rf /` passed through a shell tool destroys the host. A `curl` to an attacker-controlled URL exfiltrates environment variables. The agent does not understand the consequences of what it executes. It runs commands the same way it generates text: confidently and without hesitation. Every tool call is a potential blast radius event, and the only defense is to ensure the execution environment limits what damage any single action can cause.

## Threat Model

- **Adversary:** (1) Agent executing hallucinated or incorrect commands at machine speed. (2) Prompt injection causing the agent to run attacker-crafted commands. (3) Supply chain compromise in tool implementations that the agent invokes.
- **Blast radius:** Without sandboxing: the full host filesystem, network, and all processes running under the same user. With sandboxing: limited to the sandbox boundary (a container, a microVM, or a chroot with restricted permissions).

## Configuration

### [gVisor](https://gvisor.dev) Sandbox for Agent Execution

gVisor interposes a user-space kernel between the agent process and the host kernel. Syscalls from the agent never reach the host kernel directly. This limits kernel exploit surface and prevents container escapes.

```yaml
# gvisor-runtime-class.yaml
# Install gVisor (runsc) on nodes, then create a RuntimeClass.
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
```

```yaml
# agent-sandbox-pod.yaml
# Agent runs inside a gVisor sandbox with strict resource limits.
apiVersion: v1
kind: Pod
metadata:
  name: agent-sandbox
  namespace: ai-agents
  labels:
    app: agent-sandbox
    sandbox-type: gvisor
spec:
  runtimeClassName: gvisor
  serviceAccountName: agent-sandbox-sa
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
    runAsGroup: 65534
    fsGroup: 65534
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: agent
      image: registry.example.com/agent-runner:v2.1.0
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      resources:
        requests:
          cpu: 500m
          memory: 512Mi
        limits:
          cpu: 2000m
          memory: 2Gi
      volumeMounts:
        - name: workspace
          mountPath: /workspace
        - name: tmp
          mountPath: /tmp
      env:
        - name: AGENT_WORKSPACE
          value: "/workspace"
        - name: AGENT_TIMEOUT_SECONDS
          value: "300"
  volumes:
    - name: workspace
      emptyDir:
        sizeLimit: 500Mi
    - name: tmp
      emptyDir:
        sizeLimit: 100Mi
  terminationGracePeriodSeconds: 10
```

### [Firecracker](https://firecracker-microvm.github.io) MicroVM for Stronger Isolation

For high-risk tool calls (shell execution, code interpretation), Firecracker microVMs provide hardware-level isolation. Each agent action runs in a fresh microVM that boots in under 200ms and is destroyed after execution.

```json
{
  "boot-source": {
    "kernel_image_path": "/opt/firecracker/vmlinux",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
  },
  "drives": [
    {
      "drive_id": "rootfs",
      "path_on_host": "/opt/firecracker/rootfs/agent-rootfs.ext4",
      "is_root_device": true,
      "is_read_only": true
    },
    {
      "drive_id": "workspace",
      "path_on_host": "/tmp/agent-workspace-${SESSION_ID}.ext4",
      "is_root_device": false,
      "is_read_only": false
    }
  ],
  "machine-config": {
    "vcpu_count": 2,
    "mem_size_mib": 1024
  },
  "network-interfaces": []
}
```

The root filesystem is read-only. The workspace drive is an ephemeral disk created for this session and destroyed after. Network interfaces are omitted entirely, meaning the microVM has no network access unless explicitly configured.

### Filesystem Read/Write Scoping

Restrict agent file access to a designated workspace directory. Use bind mounts with read-only flags for reference data.

```yaml
# agent-filesystem-policy.yaml
# OPA policy: validate that agent pods only mount allowed paths.
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sagentfilesystempolicy
spec:
  crd:
    spec:
      names:
        kind: K8sAgentFilesystemPolicy
      validation:
        openAPIV3Schema:
          type: object
          properties:
            allowedMountPaths:
              type: array
              items:
                type: string
            maxVolumeSizeMi:
              type: integer
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sagentfilesystempolicy
        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          mount := container.volumeMounts[_]
          not path_allowed(mount.mountPath)
          msg := sprintf(
            "Agent container mount path '%v' is not in allowed list",
            [mount.mountPath]
          )
        }
        path_allowed(path) {
          allowed := input.parameters.allowedMountPaths[_]
          startswith(path, allowed)
        }
```

```yaml
# Apply the constraint
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAgentFilesystemPolicy
metadata:
  name: agent-fs-restriction
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces: ["ai-agents"]
  parameters:
    allowedMountPaths:
      - "/workspace"
      - "/tmp"
    maxVolumeSizeMi: 500
```

### Network Egress Restrictions

Agents should have no network access by default. Allow specific egress only when a tool requires it.

```yaml
# agent-network-deny-all.yaml
# Default deny: agent pods cannot make any network connections.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: agent-default-deny
  namespace: ai-agents
spec:
  podSelector:
    matchLabels:
      app: agent-sandbox
  policyTypes:
    - Egress
    - Ingress
  ingress: []
  egress: []
---
# Selective allow: agents that need API access get a specific policy.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: agent-api-egress
  namespace: ai-agents
spec:
  podSelector:
    matchLabels:
      app: agent-sandbox
      network-profile: api-access
  policyTypes:
    - Egress
  egress:
    # DNS resolution
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
    # Internal API only
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: internal-api
      ports:
        - protocol: TCP
          port: 443
```

### Timeout Enforcement

Every agent action must have a hard timeout. An agent stuck in a loop or waiting on a hung process must be terminated.

```python
# timeout_executor.py
# Wraps every tool call in a timeout. Kills the process if it exceeds the limit.

import signal
import subprocess
import sys

class TimeoutError(Exception):
    pass

def execute_with_timeout(
    command: list[str],
    timeout_seconds: int = 60,
    working_dir: str = "/workspace"
) -> dict:
    """Execute a command with a hard timeout. Returns stdout, stderr, exit code."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            cwd=working_dir,
            env={
                "PATH": "/usr/bin:/bin",
                "HOME": "/workspace",
                "LANG": "C.UTF-8",
            },
        )
        return {
            "stdout": result.stdout[:10000],  # Truncate output
            "stderr": result.stderr[:5000],
            "exit_code": result.returncode,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": f"Command timed out after {timeout_seconds} seconds",
            "exit_code": -1,
            "timed_out": True,
        }
```

### Rollback Mechanisms for Failed Actions

For file operations, snapshot the workspace before each action. If the action fails or produces unexpected results, restore the snapshot.

```bash
#!/bin/bash
# agent-action-wrapper.sh
# Wraps each agent action with snapshot/rollback capability.
# Usage: agent-action-wrapper.sh <timeout_seconds> <command> [args...]

set -euo pipefail

WORKSPACE="/workspace"
SNAPSHOT_DIR="/tmp/snapshots"
TIMEOUT="${1:?Timeout required}"
shift
COMMAND=("$@")

# Create snapshot
SNAPSHOT_ID=$(date +%s)-$$
mkdir -p "$SNAPSHOT_DIR"
tar cf "$SNAPSHOT_DIR/$SNAPSHOT_ID.tar" -C "$WORKSPACE" . 2>/dev/null || true

echo "[agent-wrapper] Snapshot $SNAPSHOT_ID created"
echo "[agent-wrapper] Executing: ${COMMAND[*]}"
echo "[agent-wrapper] Timeout: ${TIMEOUT}s"

# Execute with timeout
EXIT_CODE=0
timeout "$TIMEOUT" "${COMMAND[@]}" || EXIT_CODE=$?

if [ "$EXIT_CODE" -ne 0 ]; then
    echo "[agent-wrapper] Command failed with exit code $EXIT_CODE"
    echo "[agent-wrapper] Rolling back workspace to snapshot $SNAPSHOT_ID"
    rm -rf "$WORKSPACE"/*
    tar xf "$SNAPSHOT_DIR/$SNAPSHOT_ID.tar" -C "$WORKSPACE" 2>/dev/null || true
    echo "[agent-wrapper] Rollback complete"
fi

# Clean up old snapshots (keep last 10)
ls -t "$SNAPSHOT_DIR"/*.tar 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null || true

exit "$EXIT_CODE"
```

### Runtime Monitoring

```yaml
# Prometheus alerts for sandbox violations
groups:
  - name: agent-sandbox-monitoring
    rules:
      - alert: AgentSandboxOOMKilled
        expr: >
          kube_pod_container_status_last_terminated_reason{
            namespace="ai-agents",
            reason="OOMKilled"
          } > 0
        labels:
          severity: warning
        annotations:
          summary: "Agent container {{ $labels.container }} OOM killed in pod {{ $labels.pod }}"
          runbook: "Review agent memory usage. Increase limits or investigate memory leak in tool execution."

      - alert: AgentSandboxTimeout
        expr: >
          increase(agent_tool_execution_timeouts_total{namespace="ai-agents"}[5m]) > 3
        labels:
          severity: warning
        annotations:
          summary: "Agent {{ $labels.pod }} exceeded timeout 3+ times in 5 minutes"
          runbook: "Agent may be stuck in a loop. Check tool call audit logs."

      - alert: AgentNetworkPolicyViolation
        expr: >
          increase(cilium_drop_count_total{
            reason="POLICY_DENIED",
            namespace="ai-agents"
          }[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "Agent pod attempted blocked network connection"
          runbook: "Agent attempted egress outside its allowed destinations. Investigate tool call that triggered the request."
```

## Expected Behaviour

- Agent tool calls execute inside gVisor sandboxes (or Firecracker microVMs for high-risk operations)
- Agent filesystem access is limited to /workspace (read-write, 500Mi max) and /tmp (100Mi max)
- Root filesystem is read-only; no privilege escalation possible
- Network access denied by default; specific egress allowed only for tools that need API access
- Every tool call has a hard timeout (default 60 seconds, configurable per tool)
- Failed actions automatically roll back the workspace to the pre-action snapshot
- OOM kills, timeouts, and network policy violations generate alerts

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| gVisor runtime | 5-15% syscall overhead compared to native runc | Performance-sensitive agent tasks run slower | Use gVisor for untrusted tool calls. Run trusted, performance-critical tools with runc in a separate pod with stricter RBAC. |
| Firecracker microVMs | 150-200ms boot overhead per action | Latency adds up for agents making many sequential tool calls | Batch related actions. Keep a pool of warm microVMs for low-latency execution. |
| Read-only root filesystem | Agent cannot install packages or modify system files at runtime | Some tools expect writable system paths | Mount /tmp as writable. Pre-install all required tools in the container image. |
| Default deny networking | Agent tools that need external APIs fail silently | Agents fail without clear error messages about blocked network | Return explicit error messages when network is blocked. Document which tools require network access. |
| Workspace snapshots | Disk I/O overhead for creating tar snapshots before each action | Slow for large workspaces | Use filesystem-level snapshots (btrfs/zfs) instead of tar for workspaces over 100Mi. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| gVisor runtime not installed on node | Pod stuck in Pending state | `kubectl describe pod` shows RuntimeClass not found | Install gVisor on agent nodes. Use node affinity to schedule agent pods only on gVisor-ready nodes. |
| Snapshot rollback fails | Workspace left in corrupted state after failed action | Agent reports file errors on subsequent actions | Destroy and recreate the workspace volume. Agent re-initializes from scratch. |
| Timeout too short for legitimate operations | Agent actions killed before completion | High rate of timeout failures in audit logs | Tune per-tool timeouts based on observed execution times. Set generous limits for known slow operations. |
| Network policy not enforced | Agent makes unrestricted egress connections | [Cilium](https://cilium.io)/[Calico](https://www.tigera.io/project-calico/) logs show no policy drops; external connections succeed | Verify CNI plugin supports NetworkPolicy. Test with a curl from an agent pod to confirm policy enforcement. |

## When to Consider a Managed Alternative

Building agent sandboxing infrastructure requires gVisor or Firecracker setup, [Gatekeeper](https://open-policy-agent.github.io/gatekeeper/) policies, network policies, and monitoring.

- **[Sysdig](https://sysdig.com):** Runtime container security with drift detection, syscall monitoring, and automated response for sandboxed agent pods.
- **[Grafana Cloud](https://grafana.com/cloud):** Centralized monitoring dashboards for sandbox health, timeout rates, and resource consumption.
- **HCP [Vault](https://www.vaultproject.io):** Dynamic credentials for agent pods so that sandbox compromise does not expose long-lived secrets.

**Premium content pack:** Agent sandboxing pack. gVisor RuntimeClass configs, Firecracker microVM templates, Gatekeeper filesystem policies, NetworkPolicy templates, timeout wrapper scripts, and Prometheus alert rules for sandboxed agent deployments.


## Related Articles

- [Agent-to-Agent Trust: Authentication, Delegation, and Capability Boundaries in Multi-Agent Systems](/articles/ai-landscape/agent-to-agent-trust/)
- [AI Credential Delegation: Short-Lived Tokens, Scope Narrowing, and Audit Trails for Agent Access](/articles/ai-landscape/ai-credential-delegation/)
- [Securing AI Agents in Production: Tool-Use Boundaries, Credential Scoping, and Output Verification](/articles/ai-landscape/securing-ai-agents/)
- [Hardening the AI Control Plane: Kill Switches, Rate Limits, and Human-in-the-Loop Gates](/articles/ai-landscape/ai-control-plane/)
- [Verifying AI Agent Output: Deterministic Checks, Human-in-the-Loop Gates, and Rollback Safety](/articles/ai-landscape/ai-agent-output-verification/)
