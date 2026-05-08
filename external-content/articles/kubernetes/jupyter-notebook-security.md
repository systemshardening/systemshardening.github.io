---
title: "Jupyter Notebook Security: Authentication, Isolation, and Data Protection"
description: "JupyterHub is a code execution platform. Every notebook cell is arbitrary code running with whatever permissions the notebook server process has."
slug: "jupyter-notebook-security"
date: 2026-03-06
lastmod: 2026-03-06
category: "kubernetes"
tags: ["ai", "jupyter", "jupyterhub", "isolation", "authentication", "notebooks"]
personas: ["ai-ml-engineer", "platform-engineer"]
article_number: 84
difficulty: "intermediate"
estimated_reading_time: 14
provider_bridges:
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
premium_pack: "jupyterhub-hardened-helm-values"
published: true
layout: article.njk
permalink: "/articles/kubernetes/jupyter-notebook-security/index.html"
---

# Jupyter Notebook Security: Authentication, Isolation, and Data Protection

## Problem

JupyterHub is a code execution platform. Every notebook cell is arbitrary code running with whatever permissions the notebook server process has. In a shared JupyterHub deployment, each user gets a kernel that can read files, make network requests, and access any credential available in the environment.

Most JupyterHub deployments start as a convenience tool for data scientists and end up as a production-adjacent system with access to training data, model artifacts, and cloud credentials. The default configuration runs notebook servers as root, shares a single namespace, has no network restrictions, and exposes the full Python environment including shell commands.

A single compromised or careless user can access another user's data, exfiltrate the training dataset, install persistent backdoors, or pivot to production infrastructure through shared credentials.

**Target systems:** JupyterHub on [Kubernetes](https://kubernetes.io) (Zero to JupyterHub [Helm](https://helm.sh) chart). Shared data science environments. Any notebook environment with access to sensitive data or infrastructure credentials.

## Threat Model

- **Adversary:** Malicious insider (disgruntled employee, compromised account) or external attacker who gains access to a single user's notebook through credential theft or session hijacking.
- **Objective:** Access another user's data and notebooks, exfiltrate training data, escalate privileges from notebook execution to cluster-level access, or establish persistence.
- **Blast radius:** Without isolation, a single compromised notebook can read any other user's files (shared filesystem), access any network service (no network policy), and use any credential available on the node. With proper isolation, blast radius is limited to the compromised user's own pod and explicitly shared data.

## Configuration

### OIDC Authentication

Replace the default token-based authentication with OIDC through your identity provider.

```yaml
# jupyterhub-config.yaml (Helm values)
hub:
  config:
    JupyterHub:
      authenticator_class: generic-oauth
    GenericOAuthenticator:
      client_id: "jupyterhub"
      client_secret:
        valueFrom:
          secretKeyRef:
            name: jupyterhub-oauth
            key: client-secret
      oauth_callback_url: "https://notebooks.example.com/hub/oauth_callback"
      authorize_url: "https://auth.example.com/authorize"
      token_url: "https://auth.example.com/oauth/token"
      userdata_url: "https://auth.example.com/userinfo"
      scope:
        - openid
        - profile
        - email
      username_claim: "email"
      # Restrict to specific groups
      allowed_groups:
        - "data-science"
        - "ml-engineering"
      admin_groups:
        - "ml-platform-admin"
    Authenticator:
      auto_login: true
      enable_auth_state: true
```

### Per-User Pod Isolation

Each user gets their own pod with resource limits, running as a non-root user.

```yaml
# jupyterhub-singleuser-config.yaml (Helm values)
singleuser:
  # Run as non-root
  uid: 1000
  fsGid: 100

  # Resource limits per user
  cpu:
    limit: 4
    guarantee: 0.5
  memory:
    limit: 8G
    guarantee: 1G
  # GPU limits (if applicable)
  extraResource:
    limits:
      nvidia.com/gpu: "1"

  # Security context
  extraPodConfig:
    securityContext:
      runAsNonRoot: true
      fsGroup: 100
      seccompProfile:
        type: RuntimeDefault

  extraContainerConfig:
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
          - ALL
      readOnlyRootFilesystem: false  # Notebooks need to write to home

  # User storage: each user gets their own PVC
  storage:
    type: dynamic
    capacity: 10Gi
    dynamic:
      storageClass: standard
      pvcNameTemplate: "claim-{username}"
      volumeNameTemplate: "vol-{username}"

  # Profile list: different resource profiles for different workloads
  profileList:
    - display_name: "Standard (4 CPU, 8GB RAM)"
      description: "For data exploration and small models"
      default: true
    - display_name: "GPU (4 CPU, 16GB RAM, 1 GPU)"
      description: "For model training and inference"
      kubespawner_override:
        extra_resource_limits:
          nvidia.com/gpu: "1"
        mem_limit: "16G"
        cpu_limit: 4
        node_selector:
          node-role: gpu-training
        tolerations:
          - key: workload-type
            value: training
            effect: NoSchedule
```

### Network Policy for Notebook Pods

Restrict notebook pods to approved data sources only.

```yaml
# notebook-network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: notebook-default-deny
  namespace: jupyterhub
spec:
  podSelector:
    matchLabels:
      component: singleuser-server
  policyTypes:
    - Ingress
    - Egress
  ingress:
    # Allow traffic from the JupyterHub proxy only
    - from:
        - podSelector:
            matchLabels:
              component: proxy
      ports:
        - protocol: TCP
          port: 8888
  egress:
    # DNS
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    # Internal data sources (e.g., database, object storage)
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: data-platform
      ports:
        - protocol: TCP
          port: 5432  # PostgreSQL
        - protocol: TCP
          port: 9000  # MinIO
    # HTTPS for package installation (restrict to approved registries)
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
      ports:
        - protocol: TCP
          port: 443
```

### Disabling Dangerous IPython Features

```python
# jupyter_notebook_config.py
# Deployed as a ConfigMap mounted into singleuser pods

c = get_config()

# Disable shell access via ! and %system magics
# This prevents: !curl, !wget, %system commands
c.IPKernelApp.exec_lines = [
    "from IPython.core.magic import register_line_magic",
    "import IPython",
    """
def _block_shell(*args, **kwargs):
    raise PermissionError("Shell commands are disabled in this environment. Use Python libraries instead.")

ip = IPython.get_ipython()
if ip:
    ip.system = _block_shell
""",
]

# Disable terminal access
c.NotebookApp.terminals_enabled = False

# Session timeout: idle notebooks shut down after 1 hour
c.MappingKernelManager.cull_idle_timeout = 3600
c.MappingKernelManager.cull_interval = 300
c.MappingKernelManager.cull_connected = False

# Disable file download for sensitive environments
# (users can still view data in notebooks but cannot download raw files)
# c.ContentsManager.allow_hidden = False
```

### Audit Logging

```yaml
# jupyterhub-audit-config.yaml (Helm values)
hub:
  extraConfig:
    audit-log: |
      import logging
      import json
      from datetime import datetime

      audit_logger = logging.getLogger("jupyterhub.audit")
      audit_handler = logging.FileHandler("/var/log/jupyterhub/audit.json")
      audit_logger.addHandler(audit_handler)
      audit_logger.setLevel(logging.INFO)

      from jupyterhub import orm

      def audit_event(event_type, username, details=None):
          audit_logger.info(json.dumps({
              "timestamp": datetime.utcnow().isoformat(),
              "event": event_type,
              "user": username,
              "details": details or {}
          }))

      c.JupyterHub.load_roles = [
          {
              "name": "user",
              "scopes": ["self"],
          }
      ]

  extraVolumeMounts:
    - name: audit-log
      mountPath: /var/log/jupyterhub

  extraVolumes:
    - name: audit-log
      emptyDir: {}
```

For shipping audit logs to a central backend:

```yaml
# fluentbit-sidecar for jupyterhub audit logs
hub:
  extraContainers:
    - name: log-shipper
      image: fluent/fluent-bit:3.0
      volumeMounts:
        - name: audit-log
          mountPath: /var/log/jupyterhub
          readOnly: true
        - name: fluent-bit-config
          mountPath: /fluent-bit/etc/
      resources:
        limits:
          memory: 64Mi
          cpu: 100m
```

## Expected Behaviour

- Users authenticate through OIDC and are restricted to approved groups
- Each user runs in an isolated pod with dedicated storage and resource limits
- Notebook pods cannot reach production services or other users' pods
- Shell command execution is blocked inside notebooks
- Idle notebooks are terminated after 1 hour
- All login events, server starts, and notebook executions are logged to a central audit backend
- Users select resource profiles based on their workload needs; GPU access requires the GPU profile

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| Per-user pods | Strong isolation; each user is a separate Kubernetes pod | Higher resource overhead (each pod has base memory/CPU cost) | Set low resource guarantees (0.5 CPU, 1GB). Idle culling reduces wasted resources. |
| Disabled shell magics | Prevents shell-based exfiltration and lateral movement | Blocks legitimate shell commands (git, pip install) | Pre-install common packages in the base image. Provide a curated list of pre-approved packages. Allow pip via Python subprocess for package installation only. |
| Network policy restricting egress | Prevents data exfiltration to external endpoints | Blocks package installation from PyPI over HTTPS | Allow HTTPS egress to approved registries (pypi.org, conda). Consider running an internal package mirror for sensitive environments. |
| Idle culling (1 hour) | Frees resources from unused notebooks | Users lose unsaved work | Auto-save every 60 seconds (JupyterHub default). Persistent storage preserves saved notebooks. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| OIDC provider unavailable | Users cannot log in to JupyterHub | Login page shows authentication error; OIDC health check fails | Configure OIDC timeout and retry. If prolonged outage, fall back to temporary token auth (with incident logging). |
| Per-user PVC exhausted | User cannot save notebooks | Kernel reports "No space left on device" | Increase PVC size or help user clean up unused files. Set quota alerts at 80% capacity. |
| Network policy blocks required data source | Notebook cannot connect to a new database | User reports connection timeout; network policy deny logs | Add the new data source to the egress allow list. Review and approve the access request first. |
| Shell restriction bypassed | User finds alternative code execution path (subprocess, os.system) | Audit logs show unexpected process execution; [Falco](https://falco.org) detects shell spawn in notebook pod | Harden further: use seccomp profiles to block execve for non-Python processes. Accept that Python-native network/file operations are the actual boundary. |

## When to Consider a Managed Alternative

Managed Kubernetes providers simplify the infrastructure layer for JupyterHub. [Grafana Cloud](https://grafana.com/cloud) for centralised audit log storage and dashboarding. For teams that need managed notebook environments without operating JupyterHub, cloud-native notebook services (SageMaker, Vertex AI Workbench) provide built-in isolation and access control at the cost of vendor lock-in.

**Premium content pack:** JupyterHub hardened Helm values and RBAC templates. Complete values.yaml with OIDC configuration, per-user isolation, network policies, audit logging, and [Fluent Bit](https://fluentbit.io) sidecar configuration.


## Related Articles

- [Hardening Model Inference Endpoints: Authentication, Rate Limiting, and Input Validation](/articles/kubernetes/inference-endpoint-hardening/)
- [GPU Workload Isolation: MIG, MPS, and vGPU Security Boundaries](/articles/kubernetes/gpu-isolation/)
- [Observability for LLM Applications: Token Usage, Latency Anomalies, and Output Classification](/articles/kubernetes/llm-observability/)
- [AI Data Leakage Prevention: Input Filtering, Output Scanning, and Audit Trails](/articles/kubernetes/ai-data-leakage-prevention/)
- [Kubernetes API Server Hardening: Flags, Authentication, and Audit Logging](/articles/kubernetes/api-server-hardening/)
