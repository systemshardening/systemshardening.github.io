---
title: "AI Credential Delegation: Short-Lived Tokens, Scope Narrowing, and Audit Trails for Agent Access"
description: "AI agents need credentials to do useful work: database passwords, API keys, Kubernetes service account tokens, cloud IAM roles."
slug: "ai-credential-delegation"
date: 2026-01-18
lastmod: 2026-01-18
category: "ai-landscape"
tags: ["ai-agents", "credentials", "vault", "short-lived-tokens", "audit", "just-in-time-access"]
personas: ["security-engineer", "platform-engineer", "ai-ml-engineer"]
article_number: 114
difficulty: "advanced"
estimated_reading_time: 18
provider_bridges:
  - name: "Vault"
    id: 65
    category: "secrets"
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
premium_pack: "ai-credential-delegation-pack"
published: true
layout: article.njk
permalink: "/articles/ai-landscape/ai-credential-delegation/index.html"
---

# AI Credential Delegation: Short-Lived Tokens, Scope Narrowing, and Audit Trails for Agent Access

## Problem

AI agents need credentials to do useful work: database passwords, API keys, [Kubernetes](https://kubernetes.io) service account tokens, cloud IAM roles. Teams are solving this by copying their own credentials into agent configs, setting environment variables with long-lived API keys, or giving agents the same IAM role as the CI pipeline. The result is agents running with permanent, broad credentials that never expire and are never rotated. When an agent is compromised through prompt injection or a tool vulnerability, those credentials give the attacker persistent access to everything the agent could reach. A leaked `.env` file with an agent's AWS access key is indistinguishable from an engineer's leaked credentials, except the agent's key has been active 24/7 for months with no rotation. Every credential given to an agent must be short-lived, narrowly scoped, and fully audited. There is no other way to maintain a defensible security posture.

## Threat Model

- **Adversary:** (1) Attacker who compromises an agent and extracts its credentials from environment variables or mounted secrets. (2) Prompt injection that causes the agent to leak credentials through its output. (3) Insider who accesses agent credential stores. (4) Supply chain attack on agent tooling that harvests credentials at runtime.
- **Blast radius:** Everything the credential can access, for the entire duration the credential is valid. A static AWS key with AdministratorAccess gives indefinite access to the entire AWS account. A Vault token with no TTL gives permanent access to every secret path the policy allows.

## Configuration

### Dynamic Credential Issuance with Vault

Never store static credentials in agent configurations. Use [Vault](https://www.vaultproject.io) to issue dynamic, short-lived credentials on demand.

```hcl
# vault-agent-db-role.hcl
# Vault database secrets engine role for AI agents.
# Issues credentials that expire in 15 minutes.
# Agent must re-authenticate to get new credentials.

resource "vault_database_secret_backend_role" "agent_readonly" {
  backend = "database"
  name    = "agent-readonly"
  db_name = "production-postgres"

  creation_statements = [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
    "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";",
  ]

  revocation_statements = [
    "DROP ROLE IF EXISTS \"{{name}}\";",
  ]

  default_ttl = "15m"
  max_ttl     = "1h"
}
```

```hcl
# vault-agent-policy.hcl
# Vault policy for AI agent: can only read from specific paths.
# Cannot manage Vault itself, cannot access other teams' secrets.

path "database/creds/agent-readonly" {
  capabilities = ["read"]
}

path "secret/data/agents/config/*" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

# Deny everything else
path "*" {
  capabilities = ["deny"]
}
```

### Kubernetes-Native Credential Binding

Use Vault's Kubernetes auth method so agents authenticate using their pod's service account. No static tokens in environment variables.

```yaml
# agent-vault-auth.yaml
# Vault Agent sidecar injects credentials into the agent pod.
# Credentials are written to a shared volume, not environment variables.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ai-agent-credentialed
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
      annotations:
        vault.hashicorp.com/agent-inject: "true"
        vault.hashicorp.com/role: "ai-agent-role"
        vault.hashicorp.com/agent-inject-secret-db-creds: "database/creds/agent-readonly"
        vault.hashicorp.com/agent-inject-template-db-creds: |
          {{- with secret "database/creds/agent-readonly" -}}
          {
            "username": "{{ .Data.username }}",
            "password": "{{ .Data.password }}",
            "ttl_seconds": {{ .Data.lease_duration }}
          }
          {{- end -}}
    spec:
      serviceAccountName: ai-agent-sa
      containers:
        - name: agent
          image: registry.example.com/ai-agent:v2.3.0
          volumeMounts:
            - name: vault-secrets
              mountPath: /vault/secrets
              readOnly: true
          env:
            - name: DB_CREDS_PATH
              value: "/vault/secrets/db-creds"
```

### Just-in-Time Access for High-Risk Operations

For operations that need elevated permissions (production database writes, infrastructure changes), the agent requests access through an approval workflow. Credentials are issued only after approval and expire immediately after the task.

```python
# jit_access.py
# Just-in-time credential request for AI agents.
# Agent requests elevated access, waits for approval, gets time-bounded credentials.

import requests
import time
import json

VAULT_ADDR = "https://vault.internal:8200"

def request_jit_access(
    agent_id: str,
    vault_token: str,
    operation: str,
    target_resource: str,
    justification: str,
    max_duration_minutes: int = 15,
) -> dict:
    """Request just-in-time elevated credentials through Vault."""

    # Step 1: Create the access request (logged for audit)
    access_request = {
        "agent_id": agent_id,
        "operation": operation,
        "target_resource": target_resource,
        "justification": justification,
        "requested_duration_minutes": max_duration_minutes,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    # Step 2: Submit to approval queue
    response = requests.post(
        f"{VAULT_ADDR}/v1/sys/control-group/request",
        headers={"X-Vault-Token": vault_token},
        json=access_request,
    )

    if response.status_code != 200:
        raise RuntimeError(f"JIT request failed: {response.text}")

    request_id = response.json()["request_id"]

    # Step 3: Poll for approval (human reviews in Slack/PagerDuty)
    for _ in range(60):  # 5 minute timeout (5s intervals)
        status = requests.get(
            f"{VAULT_ADDR}/v1/sys/control-group/request/{request_id}",
            headers={"X-Vault-Token": vault_token},
        )
        if status.json().get("approved"):
            break
        time.sleep(5)
    else:
        raise TimeoutError("JIT access request was not approved within 5 minutes")

    # Step 4: Fetch the time-bounded credentials
    creds = requests.get(
        f"{VAULT_ADDR}/v1/database/creds/agent-readwrite",
        headers={"X-Vault-Token": vault_token},
    )
    return creds.json()["data"]
```

### Credential Rotation During Long-Running Tasks

Agents running multi-step tasks that exceed credential TTL must handle rotation gracefully. The Vault Agent sidecar handles this automatically by refreshing credentials before they expire.

```python
# credential_manager.py
# Watches the credential file for changes and reloads connections.
# Works with Vault Agent sidecar that refreshes credentials on disk.

import json
import os
import time
from pathlib import Path

class CredentialManager:
    def __init__(self, creds_path: str):
        self.creds_path = Path(creds_path)
        self._last_mtime = 0.0
        self._current_creds: dict = {}
        self._reload()

    def _reload(self):
        mtime = self.creds_path.stat().st_mtime
        if mtime > self._last_mtime:
            with open(self.creds_path) as f:
                self._current_creds = json.load(f)
            self._last_mtime = mtime
            return True
        return False

    def get_credentials(self) -> dict:
        """Get current credentials, reloading if the file has changed."""
        self._reload()
        return self._current_creds

    def get_connection_string(self) -> str:
        """Build a database connection string from current credentials."""
        creds = self.get_credentials()
        return (
            f"postgresql://{creds['username']}:{creds['password']}"
            f"@db.internal:5432/production"
        )

    def is_expiring_soon(self, threshold_seconds: int = 60) -> bool:
        """Check if credentials will expire within threshold."""
        creds = self.get_credentials()
        ttl = creds.get("ttl_seconds", 0)
        return ttl < threshold_seconds
```

### Full Audit Trail

Every credential issuance, usage, renewal, and revocation must be logged.

```yaml
# vault-audit-backend.hcl - Enable Vault audit logging
# Logs every credential operation with full context.
resource "vault_audit" "agent_audit" {
  type = "file"
  options = {
    file_path = "/var/log/vault/agent-audit.log"
    format    = "json"
  }
}
```

Correlate credential usage with agent actions using a shared trace ID:

```python
# credential_audit.py
# Links credential issuance to the actions taken with those credentials.

import json
import time
import uuid

def log_credential_event(
    event_type: str,          # "issued", "used", "renewed", "revoked", "expired"
    agent_id: str,
    credential_type: str,     # "database", "kubernetes", "aws", "api_key"
    credential_scope: str,    # "SELECT on public.*", "namespace:production"
    ttl_seconds: int,
    trace_id: str,
    action_context: str = "",
):
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": f"agent.credential.{event_type}",
        "agent_id": agent_id,
        "credential_type": credential_type,
        "credential_scope": credential_scope,
        "ttl_seconds": ttl_seconds,
        "trace_id": trace_id,
        "action_context": action_context,
    }
    print(json.dumps(entry), flush=True)


# Usage in agent workflow:
# trace_id = str(uuid.uuid4())
# log_credential_event("issued", "agent-deployer", "database", "SELECT on public.*", 900, trace_id)
# ... agent performs database queries ...
# log_credential_event("used", "agent-deployer", "database", "SELECT on public.*", 850, trace_id, "queried user_metrics table")
# ... task completes ...
# log_credential_event("revoked", "agent-deployer", "database", "SELECT on public.*", 0, trace_id, "task completed")
```

### [Prometheus](https://prometheus.io) Monitoring for Credential Health

```yaml
# credential-monitoring.yaml
groups:
  - name: agent-credential-health
    rules:
      - alert: AgentCredentialNotRotated
        expr: >
          time() - vault_token_creation_time{
            role=~"ai-agent.*"
          } > 3600
        labels:
          severity: warning
        annotations:
          summary: "Agent credential for role {{ $labels.role }} has not been rotated in over 1 hour"

      - alert: AgentCredentialLeaseExpiringSoon
        expr: >
          vault_token_ttl{role=~"ai-agent.*"} < 120
        labels:
          severity: warning
        annotations:
          summary: "Agent credential TTL under 2 minutes for {{ $labels.role }}"
          runbook: "Vault Agent sidecar should auto-renew. If this fires, check sidecar health."

      - alert: AgentCredentialDenied
        expr: >
          increase(vault_audit_log_request_failure{
            auth_entity_id=~"ai-agent.*"
          }[5m]) > 5
        labels:
          severity: critical
        annotations:
          summary: "Agent {{ $labels.auth_entity_id }} denied credentials 5+ times in 5 minutes"
          runbook: "Agent may be requesting out-of-scope credentials. Check for prompt injection or misconfiguration."
```

## Expected Behaviour

- Agent credentials are issued dynamically by Vault with a maximum TTL of 15 minutes for database access
- No static credentials exist in agent configurations, environment variables, or mounted secrets
- Vault Agent sidecar handles credential rotation automatically before expiry
- High-risk operations require human approval through JIT access workflow
- Every credential issuance, use, renewal, and revocation is logged with a trace ID
- Credentials are scoped to the minimum permissions needed (SELECT-only for read tasks)
- Alert fires when credentials are not rotated within expected windows

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| 15-minute credential TTL | Agent must renew credentials every 15 minutes | Credential renewal failure interrupts long-running tasks | Vault Agent sidecar handles renewal automatically. Set renewal window to 5 minutes before expiry. |
| JIT approval for writes | Agent cannot perform write operations without human approval | Approval latency blocks time-sensitive operations | Define pre-approved write operations for low-risk targets. Only require JIT for production databases and infrastructure. |
| No environment variable credentials | Agent code must read credentials from file path | Incompatible with libraries that expect credentials in environment variables | Write a wrapper that reads from file and sets env vars at startup. Re-read on credential rotation. |
| Full audit logging | High volume of credential events in audit log | Storage costs; query performance | Index by agent_id and trace_id. Retain for 90 days in hot storage, archive to cold after. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Vault Agent sidecar crash | Credentials on disk expire and are not renewed | Agent logs show authentication failures; Vault sidecar container in CrashLoopBackOff | Restart the sidecar. If persistent: check Vault connectivity and Kubernetes auth role configuration. |
| Credential scope too narrow | Agent cannot perform required operations | Agent logs show permission denied from target service | Review and expand the Vault role's creation statements. Test credentials manually before deploying. |
| JIT approval timeout | Agent task stalls waiting for human approval | Task duration exceeds SLA; agent logs show approval timeout | Set up PagerDuty escalation for JIT requests. Consider auto-approval for pre-defined low-risk operations. |
| Credential leaked through agent output | Attacker gains short-lived access to target resource | Vault audit log shows credential used from unexpected IP; output monitoring detects credential patterns | Revoke the leaked credential immediately. Vault's short TTL limits exposure. Add output scanning for credential patterns. |

## When to Consider a Managed Alternative

Building credential delegation infrastructure requires Vault for dynamic secrets, a sidecar for rotation, and a logging pipeline for audit.

- **HCP [Vault](https://www.vaultproject.io):** Managed Vault eliminates the operational burden of running Vault in production (unsealing, HA, upgrades).
- **[Grafana Cloud](https://grafana.com/cloud):** Centralized credential audit dashboards with alerting on anomalous credential usage patterns.
- **[Sysdig](https://sysdig.com):** Runtime detection of credential access patterns in agent containers.

**Premium content pack:** AI credential delegation pack. Vault policies, database secrets engine roles, Kubernetes auth configuration, JIT approval workflow, credential audit pipeline, and Prometheus alert rules for agent credential management.


## Related Articles

- [Securing AI Agents in Production: Tool-Use Boundaries, Credential Scoping, and Output Verification](/articles/ai-landscape/securing-ai-agents/)
- [Sandboxing AI Agent Tool Use: Filesystem, Network, and Process Isolation for Autonomous Actions](/articles/ai-landscape/agent-tool-use-sandboxing/)
- [Agent-to-Agent Trust: Authentication, Delegation, and Capability Boundaries in Multi-Agent Systems](/articles/ai-landscape/agent-to-agent-trust/)
- [Hardening the AI Control Plane: Kill Switches, Rate Limits, and Human-in-the-Loop Gates](/articles/ai-landscape/ai-control-plane/)
- [Verifying AI Agent Output: Deterministic Checks, Human-in-the-Loop Gates, and Rollback Safety](/articles/ai-landscape/ai-agent-output-verification/)
