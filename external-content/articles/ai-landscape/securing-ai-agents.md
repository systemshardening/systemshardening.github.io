---
title: "Securing AI Agents in Production: Tool-Use Boundaries, Credential Scoping, and Output Verification"
description: "AI agents are being deployed with production tool access: shell execution, kubectl, terraform apply, database queries, API calls."
slug: "securing-ai-agents"
date: 2026-04-11
lastmod: 2026-04-11
category: "ai-landscape"
tags: ["ai-agents", "security", "rbac", "vault", "credential-scoping", "guardrails"]
personas: ["ai-ml-engineer", "security-engineer", "platform-engineer"]
article_number: 102
difficulty: "advanced"
estimated_reading_time: 20
provider_bridges:
  - name: "Vault"
    id: 65
    category: "secrets"
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
  - name: "Lakera"
    id: 142
    category: "llm-security"
premium_pack: "ai-agent-security-pack"
published: true
layout: article.njk
permalink: "/articles/ai-landscape/securing-ai-agents/index.html"
---

# Securing AI Agents in Production: Tool-Use Boundaries, Credential Scoping, and Output Verification

## Problem

AI agents are being deployed with production tool access: shell execution, kubectl, terraform apply, database queries, API calls. An agent with cluster-admin credentials can cause catastrophic damage in under 60 seconds. An agent manipulated through prompt injection can exfiltrate credentials through its output. There are no established security patterns for controlling agent infrastructure access, and teams are deploying agents with the same credentials they would give a senior engineer, but without the judgement that senior engineer has.

## Threat Model

- **Adversary:** Two threat vectors: (1) Well-intentioned agent making incorrect decisions at machine speed (hallucinated commands, wrong context, cascading errors). (2) Attacker manipulating agent behaviour through prompt injection (crafted input that causes the agent to execute unintended actions or leak information through its output).
- **Blast radius:** Everything the agent's credentials can reach. An agent with `kubectl` and cluster-admin can delete all deployments, read all secrets, and create backdoor service accounts, in seconds.

## Configuration

### Credential Scoping with Vault

Never give agents static, long-lived credentials. Use [Vault](https://www.vaultproject.io) for dynamic, short-lived credentials that expire automatically.

```hcl
# vault-policy-agent.hcl - Vault policy for AI agent credentials
# Only allows reading secrets in the agent's designated path.
# Cannot access other teams' secrets, cannot write secrets, cannot manage Vault itself.

path "secret/data/agents/web-hardening/*" {
  capabilities = ["read"]
}

path "kubernetes/creds/agent-deployer" {
  capabilities = ["read"]
}

# Explicitly deny everything else
path "*" {
  capabilities = ["deny"]
}
```

```bash
# Create a Kubernetes auth role for the agent
vault write auth/kubernetes/role/ai-agent \
  bound_service_account_names=ai-agent-sa \
  bound_service_account_namespaces=ai-agents \
  policies=agent-policy \
  ttl=1h \
  max_ttl=4h

# The agent's pod authenticates to Vault using its service account token.
# Vault returns credentials that expire in 1 hour (max 4 hours).
# No credential files on disk. No environment variables with long-lived tokens.
```

### Execution Sandboxing

```yaml
# ai-agent-deployment.yaml
# The agent runs in a sandboxed pod with minimal permissions.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ai-agent
  namespace: ai-agents
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ai-agent
  template:
    metadata:
      labels:
        app: ai-agent
    spec:
      serviceAccountName: ai-agent-sa
      automountServiceAccountToken: false  # Use Vault instead
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        fsGroup: 65534
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: agent
          image: registry.example.com/ai-agent:v1.2.3
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
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: tmp
          emptyDir:
            sizeLimit: 100Mi
```

```yaml
# Network policy: agent can only reach its target namespace and Vault.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: agent-egress
  namespace: ai-agents
spec:
  podSelector:
    matchLabels:
      app: ai-agent
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: vault
      ports:
        - protocol: TCP
          port: 8200
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: production
      ports:
        - protocol: TCP
          port: 443
```

### RBAC for Agent Service Account

```yaml
# agent-rbac.yaml
# Namespace-scoped role - agent can only operate in 'production' namespace.
# Can view and update deployments. Cannot delete. Cannot access secrets directly.
# Cannot modify RBAC. Cannot access other namespaces.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ai-agent-role
  namespace: production
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "update", "patch"]
  - apiGroups: [""]
    resources: ["pods", "services", "configmaps"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["pods/log"]
    verbs: ["get"]
  # Explicitly: no secrets, no exec, no delete, no RBAC modification
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ai-agent-binding
  namespace: production
subjects:
  - kind: ServiceAccount
    name: ai-agent-sa
    namespace: ai-agents
roleRef:
  kind: Role
  name: ai-agent-role
  apiGroup: rbac.authorization.k8s.io
```

### Human-in-the-Loop Approval Gates

Define "destructive operations" that always require human approval:

```yaml
# OPA/Gatekeeper constraint: block agent service account from destructive operations
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sBlockAgentDestructive
metadata:
  name: block-agent-deletes
spec:
  match:
    kinds:
      - apiGroups: ["*"]
        kinds: ["*"]
  parameters:
    agentServiceAccounts:
      - "system:serviceaccount:ai-agents:ai-agent-sa"
    blockedVerbs:
      - "delete"
      - "deletecollection"
```

For operations that need approval: the agent generates the change, sends it to a Slack channel for review, and a human applies it:

```python
# Agent workflow (pseudocode):
# 1. Agent generates kubectl patch command
# 2. Agent runs: kubectl apply --dry-run=server -o yaml
# 3. Agent sends dry-run output to approval channel
# 4. Human reviews and approves
# 5. Agent applies the change (or human applies manually)
```

### Action Audit Logging

```yaml
# OTel instrumentation for agent actions
# Every tool call is logged before execution.
spans:
  - name: "agent.tool_call"
    attributes:
      agent.id: "web-hardening-agent-01"
      agent.action: "kubectl_apply"
      agent.input_context: "User requested NGINX config update"
      agent.target_resource: "deployment/nginx"
      agent.target_namespace: "production"
      agent.dry_run: true
      agent.approval_required: false
      agent.timestamp: "2026-04-22T10:30:00Z"
```

Ship to immutable storage:

```yaml
# Vector config: ship agent audit logs to Axiom (#112)
sinks:
  agent_audit:
    type: axiom
    inputs:
      - agent_logs
    dataset: "agent-audit"
    token: "${AXIOM_API_TOKEN}"
```

### Kill Switch

```bash
#!/bin/bash
# kill-agent.sh - Emergency kill switch for AI agent.
# Revokes all agent access within 10 seconds.

echo "EMERGENCY: Revoking all AI agent access..."

# 1. Delete the agent's Kubernetes service account token
kubectl delete serviceaccount ai-agent-sa -n ai-agents

# 2. Block all agent network egress immediately
kubectl apply -f - <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: agent-kill-switch
  namespace: ai-agents
spec:
  podSelector:
    matchLabels:
      app: ai-agent
  policyTypes:
    - Egress
  egress: []  # Block ALL egress
EOF

# 3. Revoke Vault leases for the agent
vault lease revoke -prefix secret/data/agents/

# 4. Scale agent deployment to zero
kubectl scale deployment ai-agent -n ai-agents --replicas=0

# 5. Create incident
echo "Agent access revoked. Creating incident..."
# Integration with Incident.io (#175) or your incident management tool

echo "DONE. All agent access revoked."
```

## Expected Behaviour

- Agent operates with Vault-issued credentials that expire within 1 hour
- Agent can only access resources in its designated namespace
- All destructive operations blocked by OPA policy
- Every agent action logged to immutable storage before execution
- Kill switch revokes all agent access within 10 seconds
- Agent cannot access secrets, modify RBAC, or reach other namespaces

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| 1-hour credential TTL | Agent must re-authenticate hourly | Long-running agent tasks interrupted by credential expiry | Set TTL to match the longest expected task duration. Use Vault lease renewal for tasks that may exceed TTL. |
| Human-in-the-loop for deletes | Agent cannot perform automated cleanup | Approval bottleneck for routine operations | Define a clear "safe to auto-approve" list (e.g., scaling within limits, config updates). Only require approval for deletes and permission changes. |
| Namespace isolation | Agent cannot manage cross-namespace workflows | Multi-namespace operations require multiple agents or human intervention | Deploy one agent per target namespace. Or use a coordinator agent with broader access and stricter oversight. |
| Full action logging | 10-100x more audit data than human operators | Storage cost; query complexity | Use [Axiom](https://axiom.co) free tier (500GB/month). Agent audit data is high-value and worth the storage cost. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Agent credential too broad | Agent modifies resources outside intended scope | Audit log shows actions on unexpected resources | Activate kill switch. Tighten Vault policy and RBAC. Redeploy agent with scoped credentials. |
| Kill switch too slow | Damage occurs in the 10-second revocation window | Post-incident: audit log shows actions between detection and kill | Add network-level kill (block pod egress immediately via network policy, faster than service account deletion). |
| Prompt injection bypasses guardrails | Agent executes attacker-crafted instructions | Output monitoring detects unexpected action patterns; audit log shows anomalous commands | Activate kill switch. Investigate the input chain. Add [Lakera](https://www.lakera.ai) for real-time injection detection. |
| Vault lease expired mid-task | Agent loses access during a multi-step operation | Agent logs show 403 from Vault; task fails midway | Implement lease renewal. Set Vault TTL > expected task duration. Handle lease expiry gracefully in agent code. |

## When to Consider a Managed Alternative

Agent security infrastructure requires [Vault](https://www.vaultproject.io) for credentials, OPA for policy enforcement, and a logging backend for audit. For teams deploying 3+ agents:

- **HCP [Vault](https://www.vaultproject.io):** Managed Vault eliminates seal/unseal management and HA setup.
- **[Sysdig](https://sysdig.com):** Runtime monitoring of agent containers with automated response.
- **[Lakera](https://www.lakera.ai):** Managed prompt injection detection API for agent inputs.
- **[Grafana Cloud](https://grafana.com/cloud):** Centralized agent audit logs with dashboards and alerting.
- **[Incident.io](https://incident.io):** Automated incident creation when kill switch activates.

**Premium content pack:** AI agent security policy pack. Vault policies, Kubernetes RBAC templates, OPA constraints, network policies, [Prometheus](https://prometheus.io) alert rules, and kill switch scripts for AI agent deployments.


## Related Articles

- [AI Credential Delegation: Short-Lived Tokens, Scope Narrowing, and Audit Trails for Agent Access](/articles/ai-landscape/ai-credential-delegation/)
- [Hardening the AI Control Plane: Kill Switches, Rate Limits, and Human-in-the-Loop Gates](/articles/ai-landscape/ai-control-plane/)
- [Sandboxing AI Agent Tool Use: Filesystem, Network, and Process Isolation for Autonomous Actions](/articles/ai-landscape/agent-tool-use-sandboxing/)
- [Agent-to-Agent Trust: Authentication, Delegation, and Capability Boundaries in Multi-Agent Systems](/articles/ai-landscape/agent-to-agent-trust/)
- [Securing MCP Servers: Authentication, Tool Sandboxing, and Input Validation for Model Context Protocol](/articles/ai-landscape/mcp-server-security/)
