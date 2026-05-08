---
title: "Agent-to-Agent Trust: Authentication, Delegation, and Capability Boundaries in Multi-Agent Systems"
description: "Multi-agent systems are moving from research demos to production deployments. A coordinator agent delegates tasks to specialist agents: one handles..."
slug: "agent-to-agent-trust"
date: 2026-02-18
lastmod: 2026-02-18
category: "ai-landscape"
tags: ["ai-agents", "multi-agent", "trust", "delegation", "capability-tokens", "zero-trust"]
personas: ["security-engineer", "platform-engineer", "ai-ml-engineer"]
article_number: 113
difficulty: "advanced"
estimated_reading_time: 18
provider_bridges:
  - name: "Vault"
    id: 65
    category: "secrets"
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
premium_pack: "multi-agent-trust-pack"
published: true
layout: article.njk
permalink: "/articles/ai-landscape/agent-to-agent-trust/index.html"
---

# Agent-to-Agent Trust: Authentication, Delegation, and Capability Boundaries in Multi-Agent Systems

## Problem

Multi-agent systems are moving from research demos to production deployments. A coordinator agent delegates tasks to specialist agents: one handles database queries, another manages deployments, a third writes code. Each agent has its own credentials, tools, and execution context. The security question that teams skip: how does Agent B verify that Agent A is who it claims to be, that A is authorized to make this request, and that A has not been compromised by prompt injection? Without identity verification between agents, a compromised agent can impersonate the coordinator and escalate privileges across the entire swarm. Without delegation boundaries, a low-privilege agent can ask a high-privilege agent to perform actions on its behalf, creating a privilege escalation chain. There are no established patterns for agent-to-agent authentication, and most multi-agent frameworks treat inter-agent communication as trusted by default.

## Threat Model

- **Adversary:** (1) Compromised agent (via prompt injection or supply chain attack) that attempts to manipulate other agents. (2) Attacker who gains access to the inter-agent communication channel and injects messages. (3) Legitimate agent that malfunctions and sends incorrect delegation requests at machine speed.
- **Blast radius:** The union of all capabilities across all agents in the swarm. A compromised coordinator can weaponize every specialist agent. A compromised specialist with unrestricted delegation can request any action from any other agent.

## Configuration

### Agent Identity with mTLS

Every agent gets a unique identity backed by a TLS certificate. Inter-agent communication uses mutual TLS. No agent can communicate without presenting a valid certificate.

```yaml
# agent-identity-cert.yaml
# cert-manager Certificate for agent identity.
# Each agent gets a unique certificate with its identity in the CN and SAN.
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: agent-deployer-identity
  namespace: ai-agents
spec:
  secretName: agent-deployer-tls
  duration: 24h
  renewBefore: 8h
  subject:
    organizations:
      - "ai-agents"
  commonName: "agent-deployer"
  dnsNames:
    - "agent-deployer.ai-agents.svc.cluster.local"
  usages:
    - client auth
    - server auth
  issuerRef:
    name: agent-ca-issuer
    kind: ClusterIssuer
---
# CA issuer for agent certificates
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: agent-ca-issuer
spec:
  ca:
    secretName: agent-ca-keypair
```

### Capability Tokens with Scope Limits

When Agent A delegates a task to Agent B, it issues a capability token that describes exactly what Agent B is allowed to do. The token is scoped, time-limited, and non-transferable.

```python
# capability_token.py
# Issues and validates scoped capability tokens for agent-to-agent delegation.

import json
import time
import hmac
import hashlib
import base64

SECRET_KEY = b""  # Loaded from Vault at startup

def issue_capability_token(
    issuer_agent_id: str,
    target_agent_id: str,
    capabilities: list[str],
    resources: list[str],
    max_uses: int = 1,
    ttl_seconds: int = 300,
) -> str:
    """Issue a scoped capability token for delegation."""
    payload = {
        "iss": issuer_agent_id,
        "sub": target_agent_id,
        "cap": capabilities,       # e.g. ["read_file", "query_database"]
        "res": resources,           # e.g. ["/data/reports/*"]
        "max_uses": max_uses,
        "iat": int(time.time()),
        "exp": int(time.time()) + ttl_seconds,
        "delegatable": False,       # Cannot be passed to another agent
    }
    payload_bytes = json.dumps(payload, sort_keys=True).encode()
    signature = hmac.new(SECRET_KEY, payload_bytes, hashlib.sha256).hexdigest()
    token_data = base64.urlsafe_b64encode(payload_bytes).decode()
    return f"{token_data}.{signature}"


def validate_capability_token(
    token: str,
    presenting_agent_id: str,
    requested_capability: str,
    requested_resource: str,
) -> dict:
    """Validate a capability token. Returns payload if valid, raises on failure."""
    parts = token.split(".")
    if len(parts) != 2:
        raise ValueError("Malformed token")

    payload_bytes = base64.urlsafe_b64decode(parts[0])
    expected_sig = hmac.new(SECRET_KEY, payload_bytes, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(parts[1], expected_sig):
        raise ValueError("Invalid token signature")

    payload = json.loads(payload_bytes)

    # Check expiration
    if time.time() > payload["exp"]:
        raise ValueError("Token expired")

    # Check that the presenting agent matches the token subject
    if payload["sub"] != presenting_agent_id:
        raise ValueError(
            f"Token issued to {payload['sub']}, presented by {presenting_agent_id}"
        )

    # Check capability
    if requested_capability not in payload["cap"]:
        raise ValueError(
            f"Capability {requested_capability} not in token scope {payload['cap']}"
        )

    # Check resource (simple prefix matching)
    resource_allowed = False
    for allowed_res in payload["res"]:
        if allowed_res.endswith("*"):
            if requested_resource.startswith(allowed_res[:-1]):
                resource_allowed = True
        elif requested_resource == allowed_res:
            resource_allowed = True
    if not resource_allowed:
        raise ValueError(f"Resource {requested_resource} not in token scope")

    return payload
```

### Delegation Chains with Depth Limits

When a coordinator delegates to Agent B, and Agent B needs to sub-delegate to Agent C, the delegation chain must be tracked and bounded.

```python
# delegation_chain.py
# Tracks and enforces delegation chain depth and scope narrowing.

from dataclasses import dataclass

@dataclass
class DelegationContext:
    chain: list[str]          # [coordinator, agent-b, agent-c]
    original_capabilities: list[str]
    current_capabilities: list[str]
    max_depth: int
    depth: int

    def can_delegate(self) -> bool:
        return self.depth < self.max_depth

    def delegate(
        self,
        from_agent: str,
        to_agent: str,
        narrowed_capabilities: list[str]
    ) -> "DelegationContext":
        """Create a new delegation context with narrowed scope."""
        if not self.can_delegate():
            raise ValueError(
                f"Delegation depth limit reached ({self.max_depth}). "
                f"Chain: {' -> '.join(self.chain)}"
            )

        # Capabilities can only be narrowed, never expanded
        for cap in narrowed_capabilities:
            if cap not in self.current_capabilities:
                raise ValueError(
                    f"Cannot delegate capability '{cap}' - "
                    f"not in current scope: {self.current_capabilities}"
                )

        return DelegationContext(
            chain=self.chain + [to_agent],
            original_capabilities=self.original_capabilities,
            current_capabilities=narrowed_capabilities,
            max_depth=self.max_depth,
            depth=self.depth + 1,
        )
```

```yaml
# delegation-policy.yaml
# ConfigMap defining delegation rules for the agent swarm.
apiVersion: v1
kind: ConfigMap
metadata:
  name: agent-delegation-policy
  namespace: ai-agents
data:
  policy.json: |
    {
      "max_delegation_depth": 2,
      "delegation_rules": {
        "agent-coordinator": {
          "can_delegate_to": ["agent-deployer", "agent-analyst", "agent-writer"],
          "max_capability_set": ["read_file", "write_file", "query_database", "kubectl_get", "kubectl_apply"]
        },
        "agent-deployer": {
          "can_delegate_to": ["agent-validator"],
          "max_capability_set": ["kubectl_get", "kubectl_apply"]
        },
        "agent-analyst": {
          "can_delegate_to": [],
          "max_capability_set": ["read_file", "query_database"]
        }
      }
    }
```

### Trust Propagation Limits

Define which agents can communicate directly. Agents outside the trust boundary cannot send messages to each other, even with valid certificates.

```yaml
# agent-mesh-policy.yaml
# Istio AuthorizationPolicy: restrict which agents can call which.
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: agent-communication-policy
  namespace: ai-agents
spec:
  rules:
    # Coordinator can call any agent
    - from:
        - source:
            principals: ["cluster.local/ns/ai-agents/sa/agent-coordinator-sa"]
      to:
        - operation:
            methods: ["POST"]
            paths: ["/v1/delegate"]
    # Deployer can call validator only
    - from:
        - source:
            principals: ["cluster.local/ns/ai-agents/sa/agent-deployer-sa"]
      to:
        - operation:
            methods: ["POST"]
            paths: ["/v1/delegate"]
      when:
        - key: destination.labels[app]
          values: ["agent-validator"]
    # Analyst cannot delegate to anyone (no rule = deny)
```

### Detecting Compromised Agents

Monitor for behavioural anomalies that indicate an agent has been compromised or manipulated.

```yaml
# Prometheus alerts for compromised agent detection
groups:
  - name: agent-trust-monitoring
    rules:
      - alert: AgentDelegationDepthExceeded
        expr: >
          agent_delegation_depth_current > 2
        labels:
          severity: critical
        annotations:
          summary: "Agent delegation chain exceeded maximum depth"
          runbook: "Possible delegation chain attack. Revoke all tokens. Inspect the full chain."

      - alert: AgentCapabilityEscalation
        expr: >
          increase(agent_capability_escalation_attempts_total[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "Agent {{ $labels.agent_id }} attempted capability escalation"
          runbook: "Agent requested capabilities beyond its scope. Likely compromised. Activate kill switch for this agent."

      - alert: AgentUnauthorizedCommunication
        expr: >
          increase(istio_requests_total{
            source_workload=~"agent-.*",
            response_code="403",
            destination_workload=~"agent-.*"
          }[5m]) > 3
        labels:
          severity: warning
        annotations:
          summary: "Agent {{ $labels.source_workload }} making unauthorized calls to {{ $labels.destination_workload }}"

      - alert: AgentTokenReplayDetected
        expr: >
          increase(agent_token_reuse_attempts_total[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "Capability token replay detected for agent {{ $labels.agent_id }}"
          runbook: "A capability token was used more times than allowed. Token may have been stolen. Revoke all tokens for this agent."
```

### Audit Logging for Inter-Agent Communication

```python
# agent_comm_audit.py
# Logs every inter-agent message with full delegation context.

import json
import time

def log_agent_message(
    from_agent: str,
    to_agent: str,
    message_type: str,     # "delegate", "response", "capability_request"
    delegation_chain: list[str],
    capabilities_used: list[str],
    token_id: str,
    result: str,           # "accepted", "denied", "error"
):
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": "agent.communication",
        "from_agent": from_agent,
        "to_agent": to_agent,
        "message_type": message_type,
        "delegation_chain": delegation_chain,
        "delegation_depth": len(delegation_chain),
        "capabilities_used": capabilities_used,
        "token_id": token_id,
        "result": result,
    }
    print(json.dumps(entry), flush=True)
```

## Expected Behaviour

- Every agent has a unique mTLS identity issued by cert-manager, rotated every 24 hours
- Delegation between agents requires a scoped capability token with a maximum TTL of 5 minutes
- Capability tokens are non-transferable and single-use by default
- Delegation depth is limited to 2 hops (coordinator to specialist to validator)
- Capabilities can only be narrowed during delegation, never expanded
- Istio AuthorizationPolicy restricts which agents can communicate with each other
- Capability escalation attempts and token replay trigger critical alerts

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| mTLS between agents | 2-5ms latency per inter-agent call for TLS handshake | Latency overhead in chatty multi-agent workflows | Use connection pooling. Keep-alive connections between frequently communicating agents. |
| Single-use capability tokens | Each delegation requires a new token issuance | Token issuance becomes a bottleneck in high-throughput swarms | Batch token issuance for known task patterns. Allow multi-use tokens (max 5) for trusted pairs. |
| Delegation depth limit of 2 | Complex multi-step tasks cannot fan out deeply | Tasks requiring 3+ agent hops fail | Redesign agent topology to flatten delegation. Or increase depth limit with stricter monitoring. |
| Non-transferable tokens | Agent cannot pass received work to a sub-agent | Limits flexibility of agent composition | Issue separate tokens from the coordinator for each hop. Coordinator maintains visibility. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Agent certificate expired | Inter-agent calls fail with TLS errors | cert-manager certificate status shows expired; agent logs show TLS handshake failure | cert-manager auto-renews. If renewal fails: check ClusterIssuer, CA secret, and cert-manager logs. |
| Capability token key compromised | Attacker forges valid delegation tokens | Impossible to detect directly. Look for unexpected capability usage patterns. | Rotate the HMAC signing key in Vault. All existing tokens become invalid. Re-issue tokens to legitimate agents. |
| Compromised agent in delegation chain | Agent executes unexpected actions under delegated authority | Audit logs show actions inconsistent with the task context; behavioural drift alerts fire | Revoke all tokens issued to and by the compromised agent. Activate kill switch for that agent. Audit all actions taken during the compromise window. |
| Delegation policy too restrictive | Legitimate multi-agent workflows fail | Agents report "delegation denied" errors; tasks stall | Review delegation policy against actual workflow requirements. Add specific rules for needed communication paths. |

## When to Consider a Managed Alternative

Multi-agent trust infrastructure requires cert-manager for identity, a service mesh for communication policy, and a token issuance system for delegation.

- **HCP [Vault](https://www.vaultproject.io):** Managed PKI for agent certificate issuance and HMAC key storage for capability tokens.
- **[Sysdig](https://sysdig.com):** Runtime monitoring of agent containers with ML-based anomaly detection for compromised agent behaviour.
- **[Grafana Cloud](https://grafana.com/cloud):** Centralized dashboards for delegation chains, token usage, and inter-agent communication patterns.

**Premium content pack:** Multi-agent trust pack. cert-manager Certificate templates, Istio AuthorizationPolicy configs, capability token library, delegation chain tracking, and Prometheus alert rules for multi-agent deployments.


## Related Articles

- [Sandboxing AI Agent Tool Use: Filesystem, Network, and Process Isolation for Autonomous Actions](/articles/ai-landscape/agent-tool-use-sandboxing/)
- [AI Credential Delegation: Short-Lived Tokens, Scope Narrowing, and Audit Trails for Agent Access](/articles/ai-landscape/ai-credential-delegation/)
- [Securing AI Agents in Production: Tool-Use Boundaries, Credential Scoping, and Output Verification](/articles/ai-landscape/securing-ai-agents/)
- [Hardening the AI Control Plane: Kill Switches, Rate Limits, and Human-in-the-Loop Gates](/articles/ai-landscape/ai-control-plane/)
- [Verifying AI Agent Output: Deterministic Checks, Human-in-the-Loop Gates, and Rollback Safety](/articles/ai-landscape/ai-agent-output-verification/)
