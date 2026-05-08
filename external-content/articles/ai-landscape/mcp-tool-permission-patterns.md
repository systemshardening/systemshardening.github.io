---
title: "MCP Tool Permission Patterns: Least Privilege, Approval Workflows, and Scope Boundaries"
description: "MCP servers expose tools that agents invoke. Without fine-grained permissions, every connected agent can call every tool. This article covers least privilege patterns, per-client allowlists, human approval gates, audit logging, multi-tenant isolation, and capability tokens."
slug: "mcp-tool-permission-patterns"
date: 2026-04-01
lastmod: 2026-04-01
category: "ai-landscape"
tags: ["mcp", "model-context-protocol", "tool-permissions", "least-privilege", "approval-workflow", "audit-logging", "capability-tokens"]
personas: ["security-engineer", "platform-engineer", "ai-ml-engineer"]
article_number: 144
difficulty: "advanced"
estimated_reading_time: 19
provider_bridges:
  - name: "Vault"
    id: 65
    category: "secrets"
  - name: "OPA"
    id: 77
    category: "policy"
  - name: "Temporal"
    id: 130
    category: "workflow"
premium_pack: "mcp-security-pack"
published: true
layout: article.njk
permalink: "/articles/ai-landscape/mcp-tool-permission-patterns/index.html"
---

# MCP Tool Permission Patterns: Least Privilege, Approval Workflows, and Scope Boundaries

## Problem

An MCP server exposes a set of tools. A connected agent can invoke any of them. Out of the box, there is no distinction between a read-only analytics agent and an operations agent with deployment authority. Both see the same tool list, both can call `kubectl_apply`, both can execute `shell_exec`. The default MCP permission model is "all tools available to all clients." This violates least privilege at the most fundamental level.

The real-world consequences are direct. A compromised agent, a prompt injection that triggers unintended tool calls, or a misconfigured client identity can invoke destructive tools: deleting files, applying Kubernetes manifests, dropping database tables, or calling external APIs with production credentials. Without human approval gates, these actions execute instantly and silently. Without audit logging, you cannot reconstruct what happened. Without multi-tenant isolation, one tenant's agent can invoke another tenant's tools. Without capability token expiration, a leaked token grants permanent access.

Tool permissions must be enforced at the MCP server layer, not at the agent layer. Agents are probabilistic. Their behaviour is shaped by prompts, context, and model weights. Permissions must be deterministic. The server must deny unauthorized tool calls regardless of what the agent requests.

## Threat Model

- **Adversary:** (1) Prompt injection payload that causes an agent to invoke destructive tools (file deletion, database writes, infrastructure changes). (2) Compromised MCP client identity that attempts to escalate privileges by calling tools outside its allowed scope. (3) Insider with access to one tenant's agent who attempts to invoke tools belonging to another tenant. (4) Stolen or leaked capability token used to call tools after the token should have expired.
- **Blast radius:** Without tool permissions, the blast radius is the union of all tools the MCP server exposes. A single unauthorized `kubectl_apply` can deploy malicious workloads. A single `shell_exec` can exfiltrate data. With proper scoping, the blast radius is limited to the specific tools allowed for the compromised identity, and destructive tools require human approval before execution.

## Configuration

### Fine-Grained Tool Permissions: Read-Only vs Read-Write

Classify every tool by its side-effect profile. Read-only tools query state without modifying it. Read-write tools change state. Destructive tools delete or overwrite data irreversibly.

```json
{
  "tool_classifications": {
    "read_only": [
      "read_file",
      "list_directory",
      "query_database_readonly",
      "kubectl_get",
      "describe_resource",
      "list_buckets"
    ],
    "read_write": [
      "write_file",
      "create_resource",
      "kubectl_apply",
      "update_record",
      "send_notification"
    ],
    "destructive": [
      "delete_file",
      "drop_table",
      "kubectl_delete",
      "purge_bucket",
      "revoke_credentials"
    ]
  }
}
```

### Per-Client Tool Allowlists

Assign each client identity an explicit set of allowed tools. The default policy denies everything.

```yaml
# tool-permissions.yaml
# Per-client tool permissions with classification-based defaults.

clients:
  agent-analyst:
    description: "Read-only analytics agent"
    allowed_classifications:
      - "read_only"
    allowed_tools: []      # No additional tools beyond classification
    denied_tools: []       # Classification already restricts scope
    max_calls_per_minute: 30
    require_approval: []   # No approval needed for read-only tools

  agent-deployer:
    description: "Deployment agent with restricted write access"
    allowed_classifications:
      - "read_only"
    allowed_tools:
      - "kubectl_apply"
      - "write_file"
    denied_tools:
      - "shell_exec"
    max_calls_per_minute: 20
    require_approval:
      - "kubectl_apply"   # Human must approve before execution

  agent-ops:
    description: "Operations agent with destructive capabilities"
    allowed_classifications:
      - "read_only"
      - "read_write"
    allowed_tools:
      - "delete_file"
      - "kubectl_delete"
    denied_tools:
      - "drop_table"
      - "purge_bucket"
      - "revoke_credentials"
    max_calls_per_minute: 15
    require_approval:
      - "kubectl_delete"
      - "delete_file"
      - "kubectl_apply"

  default:
    description: "Default policy: deny all"
    allowed_classifications: []
    allowed_tools: []
    denied_tools: ["*"]
    max_calls_per_minute: 0
    require_approval: []
```

Implement the permission check as server middleware:

```python
# tool_permission_engine.py
# Evaluates tool permissions based on client identity, tool classification,
# and explicit allow/deny lists. Runs before every tool invocation.

import yaml
from pathlib import Path

class ToolPermissionEngine:
    def __init__(self, config_path: str, classifications_path: str):
        with open(config_path) as f:
            self.config = yaml.safe_load(f)
        with open(classifications_path) as f:
            self.classifications = yaml.safe_load(f)

        # Build reverse map: tool_name -> classification
        self.tool_class_map: dict[str, str] = {}
        for classification, tools in self.classifications["tool_classifications"].items():
            for tool in tools:
                self.tool_class_map[tool] = classification

    def is_allowed(self, client_id: str, tool_name: str) -> tuple[bool, str]:
        """Check if client_id is allowed to call tool_name.

        Returns (allowed, reason).
        """
        client_config = self.config["clients"].get(
            client_id,
            self.config["clients"].get("default", {})
        )

        # Check explicit deny
        denied = client_config.get("denied_tools", [])
        if "*" in denied:
            return False, "default_deny_all"
        if tool_name in denied:
            return False, f"explicitly_denied: {tool_name}"

        # Check explicit allow
        allowed_tools = client_config.get("allowed_tools", [])
        if tool_name in allowed_tools:
            return True, "explicitly_allowed"

        # Check classification-based allow
        tool_class = self.tool_class_map.get(tool_name)
        allowed_classes = client_config.get("allowed_classifications", [])
        if tool_class and tool_class in allowed_classes:
            return True, f"classification_allowed: {tool_class}"

        return False, "not_in_allowlist"

    def requires_approval(self, client_id: str, tool_name: str) -> bool:
        """Check if tool_name requires human approval for this client."""
        client_config = self.config["clients"].get(
            client_id,
            self.config["clients"].get("default", {})
        )
        return tool_name in client_config.get("require_approval", [])
```

### Human Approval Gates for Destructive Tools

Destructive tools must not execute without human review. Implement an approval workflow that pauses execution, notifies a human, and waits for explicit approval before proceeding.

```python
# approval_gate.py
# Human-in-the-loop approval workflow for destructive MCP tool calls.
# Uses a webhook to notify reviewers and waits for approval response.

import time
import uuid
import json
import hashlib
import requests
from dataclasses import dataclass
from enum import Enum

class ApprovalStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"

@dataclass
class ApprovalRequest:
    request_id: str
    client_id: str
    tool_name: str
    tool_input: dict
    input_hash: str
    status: ApprovalStatus
    created_at: float
    ttl_seconds: int = 300  # 5 minute approval window
    reviewer: str | None = None

# In production, use Redis or a database. This is for illustration.
pending_approvals: dict[str, ApprovalRequest] = {}

def request_approval(
    client_id: str,
    tool_name: str,
    tool_input: dict,
    webhook_url: str,
    ttl_seconds: int = 300,
) -> ApprovalRequest:
    """Create an approval request and notify reviewers."""
    request_id = str(uuid.uuid4())
    input_hash = hashlib.sha256(
        json.dumps(tool_input, sort_keys=True).encode()
    ).hexdigest()[:16]

    approval = ApprovalRequest(
        request_id=request_id,
        client_id=client_id,
        tool_name=tool_name,
        tool_input=tool_input,
        input_hash=input_hash,
        status=ApprovalStatus.PENDING,
        created_at=time.time(),
        ttl_seconds=ttl_seconds,
    )
    pending_approvals[request_id] = approval

    # Notify reviewers via webhook (Slack, PagerDuty, custom UI)
    requests.post(webhook_url, json={
        "type": "mcp_approval_request",
        "request_id": request_id,
        "client_id": client_id,
        "tool_name": tool_name,
        "input_preview": json.dumps(tool_input)[:512],
        "input_hash": input_hash,
        "expires_at": approval.created_at + ttl_seconds,
        "approve_url": f"https://mcp-admin.example.com/approve/{request_id}",
        "deny_url": f"https://mcp-admin.example.com/deny/{request_id}",
    }, timeout=10)

    return approval

def check_approval(request_id: str) -> ApprovalStatus:
    """Check the status of an approval request."""
    approval = pending_approvals.get(request_id)
    if not approval:
        return ApprovalStatus.DENIED

    # Check expiration
    if time.time() - approval.created_at > approval.ttl_seconds:
        approval.status = ApprovalStatus.EXPIRED
        return ApprovalStatus.EXPIRED

    return approval.status

def process_approval_response(request_id: str, approved: bool, reviewer: str):
    """Process a human reviewer's approval or denial."""
    approval = pending_approvals.get(request_id)
    if not approval or approval.status != ApprovalStatus.PENDING:
        return

    # Check expiration before accepting the response
    if time.time() - approval.created_at > approval.ttl_seconds:
        approval.status = ApprovalStatus.EXPIRED
        return

    approval.status = ApprovalStatus.APPROVED if approved else ApprovalStatus.DENIED
    approval.reviewer = reviewer
```

### Audit Logging of Every Tool Invocation

Log every tool call with the client identity, tool name, input, permission decision, approval status, and result. These logs are the forensic record for incident investigation.

```python
# tool_audit_logger.py
# Structured audit logger for MCP tool invocations.
# Captures the full lifecycle: permission check, approval, execution, result.

import json
import time
import hashlib
from dataclasses import dataclass, asdict

@dataclass
class ToolAuditEntry:
    timestamp: str
    event_type: str  # "permission_check", "approval_requested", "tool_executed", "tool_denied"
    client_id: str
    tool_name: str
    input_hash: str
    input_preview: str
    permission_result: str    # "allowed", "denied", "requires_approval"
    permission_reason: str
    approval_id: str | None
    approval_status: str | None
    approval_reviewer: str | None
    execution_result: str | None  # "success", "error"
    duration_ms: float | None
    error_message: str | None

def log_tool_event(
    event_type: str,
    client_id: str,
    tool_name: str,
    tool_input: dict,
    permission_result: str,
    permission_reason: str,
    approval_id: str | None = None,
    approval_status: str | None = None,
    approval_reviewer: str | None = None,
    execution_result: str | None = None,
    duration_ms: float | None = None,
    error_message: str | None = None,
):
    """Log a tool event to stdout in JSON format for log collection."""
    input_json = json.dumps(tool_input, sort_keys=True)
    entry = ToolAuditEntry(
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        event_type=event_type,
        client_id=client_id,
        tool_name=tool_name,
        input_hash=hashlib.sha256(input_json.encode()).hexdigest()[:16],
        input_preview=input_json[:512],
        permission_result=permission_result,
        permission_reason=permission_reason,
        approval_id=approval_id,
        approval_status=approval_status,
        approval_reviewer=approval_reviewer,
        execution_result=execution_result,
        duration_ms=duration_ms,
        error_message=error_message,
    )
    print(json.dumps(asdict(entry)), flush=True)
```

### Multi-Tenant Tool Isolation

In multi-tenant MCP deployments, each tenant's tools must be isolated. A tenant's agent must not see or invoke another tenant's tools.

```python
# tenant_isolation.py
# Multi-tenant tool isolation for MCP servers.
# Each tenant has its own tool namespace and permission boundary.

from dataclasses import dataclass, field

@dataclass
class TenantToolConfig:
    tenant_id: str
    tool_prefix: str  # Tools are namespaced: "tenant_a.read_file"
    allowed_tools: list[str] = field(default_factory=list)
    shared_tools: list[str] = field(default_factory=list)  # Cross-tenant tools (read-only)

class TenantIsolation:
    def __init__(self):
        self.tenants: dict[str, TenantToolConfig] = {}
        self.client_tenant_map: dict[str, str] = {}  # client_id -> tenant_id

    def register_tenant(self, config: TenantToolConfig):
        self.tenants[config.tenant_id] = config

    def map_client_to_tenant(self, client_id: str, tenant_id: str):
        self.client_tenant_map[client_id] = tenant_id

    def get_visible_tools(self, client_id: str) -> list[str]:
        """Return the list of tools visible to this client."""
        tenant_id = self.client_tenant_map.get(client_id)
        if not tenant_id:
            return []

        tenant = self.tenants.get(tenant_id)
        if not tenant:
            return []

        # Tenant sees its own namespaced tools plus shared tools
        namespaced = [f"{tenant.tool_prefix}.{t}" for t in tenant.allowed_tools]
        return namespaced + tenant.shared_tools

    def can_invoke(self, client_id: str, tool_name: str) -> tuple[bool, str]:
        """Check if client can invoke the specified tool."""
        visible = self.get_visible_tools(client_id)
        if tool_name in visible:
            return True, "tenant_allowed"
        return False, "tool_not_in_tenant_scope"
```

Override the MCP `tools/list` handler to filter the tool list per client:

```python
# filtered_tool_list.py
# MCP tools/list handler that returns only the tools visible to the
# authenticated client. Prevents tool enumeration across tenants.

def handle_tools_list(client_id: str, isolation: "TenantIsolation", all_tools: list[dict]) -> list[dict]:
    """Filter the tool list to show only tools the client can access."""
    visible_tool_names = set(isolation.get_visible_tools(client_id))

    filtered = []
    for tool in all_tools:
        if tool["name"] in visible_tool_names:
            filtered.append(tool)

    return filtered
```

### Capability Tokens with TTL

Issue short-lived capability tokens that grant access to specific tools for a limited duration. When the token expires, the client must re-authenticate.

```python
# capability_tokens.py
# Issue and validate capability tokens for MCP tool access.
# Tokens encode allowed tools, TTL, and client identity.

import time
import hmac
import hashlib
import json
import base64
from dataclasses import dataclass

SECRET_KEY = b""  # Load from Vault or environment. Never hardcode.

@dataclass
class CapabilityToken:
    client_id: str
    allowed_tools: list[str]
    issued_at: float
    expires_at: float
    tenant_id: str | None = None

def issue_token(
    client_id: str,
    allowed_tools: list[str],
    ttl_seconds: int = 3600,
    tenant_id: str | None = None,
    secret_key: bytes = SECRET_KEY,
) -> str:
    """Issue a capability token with embedded permissions and TTL."""
    now = time.time()
    payload = {
        "client_id": client_id,
        "allowed_tools": allowed_tools,
        "issued_at": now,
        "expires_at": now + ttl_seconds,
        "tenant_id": tenant_id,
    }
    payload_bytes = json.dumps(payload, sort_keys=True).encode()
    signature = hmac.new(secret_key, payload_bytes, hashlib.sha256).hexdigest()

    token_data = {
        "payload": base64.b64encode(payload_bytes).decode(),
        "signature": signature,
    }
    return base64.b64encode(json.dumps(token_data).encode()).decode()

def validate_token(token: str, secret_key: bytes = SECRET_KEY) -> CapabilityToken | None:
    """Validate a capability token. Returns None if invalid or expired."""
    try:
        token_data = json.loads(base64.b64decode(token))
        payload_bytes = base64.b64decode(token_data["payload"])
        expected_sig = hmac.new(secret_key, payload_bytes, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(token_data["signature"], expected_sig):
            return None

        payload = json.loads(payload_bytes)

        if time.time() > payload["expires_at"]:
            return None

        return CapabilityToken(
            client_id=payload["client_id"],
            allowed_tools=payload["allowed_tools"],
            issued_at=payload["issued_at"],
            expires_at=payload["expires_at"],
            tenant_id=payload.get("tenant_id"),
        )
    except (json.JSONDecodeError, KeyError, ValueError):
        return None
```

## Expected Behaviour

- Every tool is classified as read-only, read-write, or destructive
- Each client identity has an explicit tool allowlist; the default policy denies all tools
- Destructive tools require human approval before execution, with a configurable TTL (default 5 minutes) after which the approval request expires
- Every tool invocation is logged with client identity, permission decision, approval status, and execution result
- Multi-tenant deployments filter the `tools/list` response to show only tools within the client's tenant scope
- Capability tokens encode allowed tools and expire after a configurable TTL (default 1 hour)
- Expired or invalid capability tokens are rejected before the permission check runs
- Rate limits are enforced per client identity, not per connection

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Per-client tool allowlists | Agents can only use explicitly permitted tools | New tools require permission updates before agents can use them | Automate permission updates through CI. Include permission changes in MCP server deployment reviews. |
| Human approval gates for destructive tools | Prevents automated execution of dangerous operations | Introduces latency; agent blocks until a human responds or the request expires | Set appropriate TTLs. Provide clear approval UIs. Use Slack/PagerDuty integration for fast response. |
| Classification-based permissions | Simplifies permission management for large tool sets | Misclassified tools grant unintended access (e.g., a write tool classified as read-only) | Review tool classifications in CI. Test classification accuracy with integration tests. |
| Capability tokens with TTL | Limits the window of exposure for leaked tokens | Short TTLs cause frequent re-authentication; long TTLs increase exposure | Use 1-hour TTL for interactive sessions. Use 15-minute TTL for automated pipelines. |
| Multi-tenant tool isolation | Prevents cross-tenant tool access | Shared tools (cross-tenant) create a permission boundary that must be carefully managed | Limit shared tools to truly read-only, low-risk operations. Audit shared tool usage separately. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Default policy set to allow-all instead of deny-all | Unknown clients can invoke any tool | Audit log shows tool calls from unrecognized client_id values | Fix default policy to deny-all. Audit all tool calls from unrecognized clients. Rotate credentials. |
| Approval webhook delivery fails | Approval requests never reach reviewers; agents block indefinitely | Monitoring detects approval requests stuck in "pending" state beyond TTL | Implement webhook retry with exponential backoff. Add a dead-letter queue. Default to deny on approval timeout. |
| Tool classification out of date | Newly added write tool inherits read-only classification | Security review catches classification mismatch; or audit log shows unexpected write operations | Require classification as part of tool registration. CI check that verifies every tool has a classification. |
| Capability token secret key leaked | Attacker forges tokens with arbitrary tool permissions | Anomalous tool call patterns from unknown sources; token validation succeeds but client_id does not match known clients | Rotate the signing key immediately. Invalidate all outstanding tokens. Investigate the leak source. |
| Tenant isolation bypass via unnamespaced tool | Agent invokes a tool that was registered without a tenant prefix | Audit log shows cross-tenant tool invocation; tenant isolation check returns "tenant_allowed" for a tool the tenant should not see | Enforce tool namespacing at registration time. Reject tools without a tenant prefix in multi-tenant deployments. |

## When to Consider a Managed Alternative

Building tool permission engines, approval workflows, audit logging, tenant isolation, and capability token systems is significant engineering work.

- **[OPA](https://www.openpolicyagent.org) (Open Policy Agent):** Define tool permissions as Rego policies. Evaluate permissions externally. Decouple policy from MCP server code.
- **HCP [Vault](https://www.vaultproject.io):** Issue short-lived capability tokens backed by Vault's token lifecycle management. Automatic revocation on lease expiry.
- **[Temporal](https://temporal.io):** Model approval workflows as Temporal workflows with human-in-the-loop activities. Built-in retry, timeout, and audit trail.
- **[Grafana Cloud](https://grafana.com/cloud):** Centralized dashboards for MCP tool audit logs with alerting on anomalous permission patterns.

**Premium content pack:** MCP security pack. OPA Rego policies for tool permissions, approval workflow templates, audit log Vector pipeline configs, and Prometheus alert rules for MCP permission monitoring.

## Related Articles

- [Securing MCP Servers: Authentication, Tool Sandboxing, and Input Validation for Model Context Protocol](/articles/ai-landscape/mcp-server-security/)
- [MCP Transport Security: Securing stdio, SSE, and HTTP Channels for Model Context Protocol](/articles/ai-landscape/mcp-transport-security/)
- [Securing AI Agents in Production: Tool-Use Boundaries, Credential Scoping, and Output Verification](/articles/ai-landscape/securing-ai-agents/)
- [Hardening the AI Control Plane: Kill Switches, Rate Limits, and Human-in-the-Loop Gates](/articles/ai-landscape/ai-control-plane/)
- [AI Credential Delegation: Short-Lived Tokens, Scope Narrowing, and Audit Trails for Agent Access](/articles/ai-landscape/ai-credential-delegation/)
- [Auditing AI Actions: Structured Logging, Provenance Chains, and Tamper-Evident Records](/articles/ai-landscape/auditing-ai-actions/)
