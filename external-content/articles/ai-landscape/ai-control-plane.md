---
title: "Hardening the AI Control Plane: Kill Switches, Rate Limits, and Human-in-the-Loop Gates"
description: "AI agents with write access to production systems can execute 100+ infrastructure changes per minute."
slug: "ai-control-plane"
date: 2026-02-01
lastmod: 2026-02-01
category: "ai-landscape"
tags: ["ai-agents", "control-plane", "kill-switch", "rate-limiting", "safety"]
personas: ["platform-engineer", "ai-ml-engineer", "sre"]
article_number: 108
difficulty: "advanced"
estimated_reading_time: 16
provider_bridges:
  - name: "Vault"
    id: 65
    category: "secrets"
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
  - name: "Incident.io"
    id: 175
    category: "incident-response"
premium_pack: "ai-control-plane-pack"
published: true
layout: article.njk
permalink: "/articles/ai-landscape/ai-control-plane/index.html"
---

# Hardening the AI Control Plane: Kill Switches, Rate Limits, and Human-in-the-Loop Gates

## Problem

AI agents with write access to production systems can execute 100+ infrastructure changes per minute. A malfunctioning agent (bad prompt, hallucinated action, context confusion, or prompt injection) causes more damage in 5 minutes than a human attacker in an hour. The control plane around AI agents is a critical security boundary that most organisations have not built.

## Threat Model

- **Adversary:** Malfunctioning agent (incorrect decisions at machine speed) or attacker manipulating the agent through prompt injection.
- **Blast radius:** Everything the agent's credentials can reach, at machine speed. Without rate limits: hundreds of changes per minute. Without a kill switch: minutes of damage before anyone can intervene.

## Configuration

### Kill Switch Implementation

Target: revoke all agent access within 10 seconds.

```bash
#!/bin/bash
# kill-all-agents.sh - Emergency kill for ALL AI agents.
# Execute this when any agent exhibits unexpected behaviour.

set -e
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "[$TIMESTAMP] KILL SWITCH ACTIVATED by $(whoami)"

# 1. Network kill (fastest - blocks agent immediately)
echo "Blocking agent network egress..."
kubectl apply -f - <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: emergency-agent-kill
  namespace: ai-agents
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress: []
EOF

# 2. Scale to zero (stops agent processes)
echo "Scaling agent deployments to zero..."
kubectl scale deployment --all -n ai-agents --replicas=0

# 3. Revoke all Vault leases (invalidates all agent credentials)
echo "Revoking Vault agent credentials..."
vault lease revoke -prefix auth/kubernetes/login/ 2>/dev/null || true
vault lease revoke -prefix secret/data/agents/ 2>/dev/null || true

# 4. Delete agent service accounts (prevents re-authentication)
echo "Removing agent service accounts..."
kubectl delete serviceaccount --all -n ai-agents --ignore-not-found

# 5. Create incident
echo "Creating incident..."
curl -X POST "https://api.incident.io/v2/incidents" \
  -H "Authorization: Bearer ${INCIDENT_IO_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"AI Agent Kill Switch Activated\",
    \"summary\": \"Kill switch activated at $TIMESTAMP by $(whoami). All agent access revoked.\",
    \"severity\": {\"id\": \"critical\"}
  }" 2>/dev/null || echo "Incident creation failed, create manually."

# 6. Preserve audit logs
echo "Agent audit logs preserved in Axiom dataset 'agent-audit'."
echo "Investigation query: source='agent' AND timestamp > '$TIMESTAMP' - 30m"

echo ""
echo "=== KILL SWITCH COMPLETE ==="
echo "All agent access revoked. Agent pods terminated."
echo "Manual intervention required to restore agent access."
```

### Rate Limiting Agent Actions

```yaml
# OPA/Gatekeeper constraint: limit mutations per service account per minute
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sagentmutationratelimit
spec:
  crd:
    spec:
      names:
        kind: K8sAgentMutationRateLimit
      validation:
        openAPIV3Schema:
          type: object
          properties:
            maxMutationsPerMinute:
              type: integer
            agentServiceAccounts:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sagentmutationratelimit
        violation[{"msg": msg}] {
          input.review.userInfo.username == input.parameters.agentServiceAccounts[_]
          input.review.operation == "CREATE"  # or UPDATE, DELETE
          # Rate limiting via external cache (Redis) or admission counter
          msg := sprintf("Agent %v exceeded mutation rate limit", [input.review.userInfo.username])
        }
```

**[Prometheus](https://prometheus.io)-based rate monitoring:**

```yaml
# Alert when agent mutation rate exceeds threshold
groups:
  - name: agent-rate-limiting
    rules:
      - alert: AgentMutationRateHigh
        expr: >
          sum by (user) (
            rate(apiserver_request_total{
              verb=~"create|update|patch|delete",
              user=~"system:serviceaccount:ai-agents:.*"
            }[5m])
          ) > 1  # More than 1 mutation per second sustained over 5 minutes
        labels:
          severity: warning
        annotations:
          summary: "Agent {{ $labels.user }} making {{ $value | humanize }}/sec mutations"
          runbook: "Investigate agent behaviour. Consider activating kill switch if unexpected."
```

### Human-in-the-Loop Approval Gates

```yaml
# Kyverno policy: block destructive operations from agent service accounts.
# Agents can create and update but not delete.
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: agent-block-destructive
spec:
  validationFailureAction: Enforce
  rules:
    - name: block-agent-deletes
      match:
        any:
          - resources:
              kinds: ["*"]
            subjects:
              - kind: ServiceAccount
                name: ai-agent-*
                namespace: ai-agents
      validate:
        message: "AI agents cannot delete resources. Request human approval."
        deny:
          conditions:
            all:
              - key: "{{ request.operation }}"
                operator: In
                value: ["DELETE"]
```

### Blast Radius Containment

```yaml
# Agent namespace isolation - agents can only operate in their designated target.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: agent-containment
  namespace: ai-agents
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/component: agent
  policyTypes:
    - Egress
  egress:
    # DNS only
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
    # Target namespace only
    - to:
        - namespaceSelector:
            matchLabels:
              agent-target: "true"
      ports:
        - protocol: TCP
          port: 443
    # Vault for credentials
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: vault
      ports:
        - protocol: TCP
          port: 8200
```

### Behavioural Drift Monitoring

```yaml
# Alert when agent behaviour deviates from its baseline pattern.
groups:
  - name: agent-behaviour
    rules:
      # Alert if an agent starts accessing resource types it hasn't touched before
      - alert: AgentNewResourceType
        expr: >
          count by (user, resource) (
            rate(apiserver_request_total{
              user=~"system:serviceaccount:ai-agents:.*"
            }[1h]) > 0
          )
          unless
          count by (user, resource) (
            rate(apiserver_request_total{
              user=~"system:serviceaccount:ai-agents:.*"
            }[7d]) > 0
          )
        labels:
          severity: warning
        annotations:
          summary: "Agent {{ $labels.user }} accessing new resource type: {{ $labels.resource }}"
```

## Expected Behaviour

- Kill switch revokes all agent access within 10 seconds
- Rate limit alerts fire when agent exceeds 1 mutation/second sustained
- DELETE operations by agents are blocked by Kyverno policy
- Agent network egress limited to DNS, Vault, and target namespace only
- Behavioural drift alerts fire when agent accesses new resource types
- Incident automatically created when kill switch activates

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Rate limiting (1 mutation/sec) | Slows agent for legitimate batch operations | Legitimate batch tasks blocked | Per-task rate override mechanism. Document expected rates per agent type. |
| Block all deletes | Agent cannot perform cleanup operations | Manual cleanup needed for agent-managed resources | Human performs deletes. Or: allow deletes on specific resource types (e.g., completed Jobs) with explicit policy exception. |
| Namespace containment | Agent cannot manage cross-namespace workflows | Multi-namespace operations need multiple agents | Deploy one scoped agent per target namespace. |
| Kill switch (nuclear option) | ALL agents stop immediately | Legitimate agent work in progress is interrupted | Kill switch should be the last resort. Rate limiting and containment handle most issues without full shutdown. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Kill switch script fails | Agent continues operating after activation | Manual check: agent pods still running; API calls still succeeding | Fallback: manually delete the ai-agents namespace: `kubectl delete namespace ai-agents`. Nuclear option but guaranteed to work. |
| Rate limit bypass | Agent makes mutations faster than detected | Prometheus scrape interval (30s) creates a detection gap | Add admission webhook for real-time rate limiting (not just monitoring). |
| Kyverno policy not enforcing | Agent performs a delete that should be blocked | Audit log shows DELETE by agent service account | Check Kyverno webhook registration. Verify policy is in Enforce mode. |
| Behavioural drift false positive | Alert fires on legitimate new agent capability | Agent team deploys new feature; drift alert triggers | Document expected agent capabilities. Update baseline when new features are deployed. |

## When to Consider a Managed Alternative

Building AI agent control plane infrastructure requires [Vault](https://www.vaultproject.io) for credentials, admission webhooks for rate limiting, and monitoring for drift detection.

- **HCP [Vault](https://www.vaultproject.io):** Managed Vault for dynamic agent credential lifecycle.
- **[Sysdig](https://sysdig.com):** Runtime monitoring of agent containers with automated response and ML anomaly detection.
- **[Grafana Cloud](https://grafana.com/cloud) + [Grafana OnCall (OSS)](https://github.com/grafana/oncall):** Alerting and escalation when agent behaviour deviates.
- **[Incident.io](https://incident.io):** Automated incident creation on kill switch activation.

**Premium content pack:** AI control plane policy pack. Vault policies, Kyverno constraints, network policies, Prometheus alert rules, kill switch scripts, and behavioural drift monitoring for AI agent deployments.


## Related Articles

- [Securing AI Agents in Production: Tool-Use Boundaries, Credential Scoping, and Output Verification](/articles/ai-landscape/securing-ai-agents/)
- [Sandboxing AI Agent Tool Use: Filesystem, Network, and Process Isolation for Autonomous Actions](/articles/ai-landscape/agent-tool-use-sandboxing/)
- [Agent-to-Agent Trust: Authentication, Delegation, and Capability Boundaries in Multi-Agent Systems](/articles/ai-landscape/agent-to-agent-trust/)
- [AI Credential Delegation: Short-Lived Tokens, Scope Narrowing, and Audit Trails for Agent Access](/articles/ai-landscape/ai-credential-delegation/)
- [Verifying AI Agent Output: Deterministic Checks, Human-in-the-Loop Gates, and Rollback Safety](/articles/ai-landscape/ai-agent-output-verification/)
