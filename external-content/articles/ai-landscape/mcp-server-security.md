---
title: "Securing MCP Servers: Authentication, Tool Sandboxing, and Input Validation for Model Context Protocol"
description: "The Model Context Protocol (MCP) gives AI agents structured access to tools: filesystem operations, database queries, API calls, shell commands."
slug: "mcp-server-security"
date: 2026-03-17
lastmod: 2026-03-17
category: "ai-landscape"
tags: ["mcp", "model-context-protocol", "tool-sandboxing", "input-validation", "prompt-injection"]
personas: ["ai-ml-engineer", "security-engineer", "platform-engineer"]
article_number: 111
difficulty: "advanced"
estimated_reading_time: 18
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
premium_pack: "mcp-security-pack"
published: true
layout: article.njk
permalink: "/articles/ai-landscape/mcp-server-security/index.html"
---

# Securing MCP Servers: Authentication, Tool Sandboxing, and Input Validation for Model Context Protocol

## Problem

The Model Context Protocol (MCP) gives AI agents structured access to tools: filesystem operations, database queries, API calls, shell commands. An MCP server is a tool execution layer that accepts requests from language models and runs actions on real infrastructure. A misconfigured MCP server is an unauthenticated remote code execution endpoint. Most MCP servers ship with no authentication, no input validation, and no limits on what tools a connected client can invoke. A prompt injection that reaches an MCP tool call can read files, write data, or call external APIs with the server's full permissions. The attack surface is the union of every tool the server exposes, and by default that surface is wide open.

## Threat Model

- **Adversary:** (1) Attacker who gains access to the MCP transport layer (network-exposed SSE endpoint, compromised stdio pipe). (2) Prompt injection payload embedded in user content or retrieved documents that triggers unintended tool calls. (3) Malicious or compromised MCP client connecting to a shared server.
- **Blast radius:** Everything the MCP server process can access. If the server runs as root or with broad IAM permissions, a single tool call can read secrets, modify infrastructure, or exfiltrate data. With SSE transport, the server is a network service, so the blast radius extends to anyone who can reach the endpoint.

## Configuration

### Transport Security: stdio vs SSE

stdio transport runs the MCP server as a child process of the client. The communication channel is the process's stdin/stdout. This is inherently scoped to the local machine and the invoking user's permissions. SSE transport exposes the server over HTTP, making it a network service that requires authentication and TLS.

```yaml
# MCP server configuration - SSE transport with TLS and auth
# mcp-server-config.yaml
server:
  transport: "sse"
  host: "127.0.0.1"  # Bind to localhost only. Never bind to 0.0.0.0.
  port: 8443
  tls:
    enabled: true
    cert_file: "/etc/mcp/tls/server.crt"
    key_file: "/etc/mcp/tls/server.key"
    min_version: "TLS1.3"
  auth:
    type: "bearer"
    token_validation:
      issuer: "https://auth.example.com"
      audience: "mcp-server"
      jwks_uri: "https://auth.example.com/.well-known/jwks.json"
```

For [Kubernetes](https://kubernetes.io) deployments, keep SSE servers behind a service mesh or restrict access via NetworkPolicy:

```yaml
# NetworkPolicy: only allow connections from the ai-agents namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: mcp-server-ingress
  namespace: mcp-servers
spec:
  podSelector:
    matchLabels:
      app: mcp-server
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ai-agents
      ports:
        - protocol: TCP
          port: 8443
```

### Tool Permission Scoping

Define explicit tool allowlists per client identity. Never expose all tools to all clients.

```json
{
  "tool_permissions": {
    "agent-deployer": {
      "allowed_tools": ["read_file", "list_directory", "kubectl_get"],
      "denied_tools": ["*"],
      "max_calls_per_minute": 30
    },
    "agent-analyst": {
      "allowed_tools": ["query_database", "read_file"],
      "denied_tools": ["write_file", "shell_exec", "kubectl_apply"],
      "max_calls_per_minute": 20
    },
    "default": {
      "allowed_tools": [],
      "denied_tools": ["*"],
      "max_calls_per_minute": 0
    }
  }
}
```

Enforce this at the server level with middleware that checks the client identity against the permission map before dispatching any tool call:

```python
# mcp_auth_middleware.py
# Runs before every tool invocation. Checks client identity and tool permissions.

import time
from collections import defaultdict

call_counts: dict[str, list[float]] = defaultdict(list)

def authorize_tool_call(client_id: str, tool_name: str, permissions: dict) -> bool:
    """Check if client_id is allowed to call tool_name."""
    client_perms = permissions.get(client_id, permissions.get("default", {}))

    allowed = client_perms.get("allowed_tools", [])
    denied = client_perms.get("denied_tools", [])

    # Deny takes precedence
    if "*" in denied and tool_name not in allowed:
        return False
    if tool_name in denied:
        return False
    if "*" not in allowed and tool_name not in allowed:
        return False

    # Rate limiting
    max_rpm = client_perms.get("max_calls_per_minute", 0)
    now = time.time()
    window = [t for t in call_counts[client_id] if now - t < 60]
    if len(window) >= max_rpm:
        return False
    call_counts[client_id] = window + [now]

    return True
```

### Input Schema Validation

Every MCP tool must declare a strict JSON Schema for its inputs. Reject any call that does not match the schema before execution begins.

```json
{
  "tools": [
    {
      "name": "read_file",
      "description": "Read contents of a file within the allowed directory.",
      "input_schema": {
        "type": "object",
        "properties": {
          "path": {
            "type": "string",
            "pattern": "^/data/workspace/[a-zA-Z0-9_/.-]+$",
            "maxLength": 256
          },
          "encoding": {
            "type": "string",
            "enum": ["utf-8", "ascii", "latin-1"]
          }
        },
        "required": ["path"],
        "additionalProperties": false
      }
    },
    {
      "name": "query_database",
      "description": "Run a read-only SQL query against the analytics database.",
      "input_schema": {
        "type": "object",
        "properties": {
          "query": {
            "type": "string",
            "maxLength": 2048,
            "pattern": "^SELECT\\s"
          },
          "timeout_seconds": {
            "type": "integer",
            "minimum": 1,
            "maximum": 30
          }
        },
        "required": ["query"],
        "additionalProperties": false
      }
    }
  ]
}
```

The `pattern` field on the path restricts traversal attacks. The query pattern enforces SELECT-only access at the schema level. These are not foolproof (regex is not a SQL parser), but they add a layer of defense before the tool executes.

### Rate Limiting Tool Calls

```python
# rate_limiter.py
# Token bucket rate limiter for MCP tool calls.
# Prevents a compromised or runaway agent from flooding the server.

import time
from dataclasses import dataclass, field

@dataclass
class TokenBucket:
    capacity: int
    refill_rate: float  # tokens per second
    tokens: float = field(init=False)
    last_refill: float = field(init=False)

    def __post_init__(self):
        self.tokens = float(self.capacity)
        self.last_refill = time.monotonic()

    def consume(self, count: int = 1) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

        if self.tokens >= count:
            self.tokens -= count
            return True
        return False

# Per-client buckets: 30 calls per minute, refill at 0.5/sec
client_buckets: dict[str, TokenBucket] = {}

def check_rate_limit(client_id: str) -> bool:
    if client_id not in client_buckets:
        client_buckets[client_id] = TokenBucket(capacity=30, refill_rate=0.5)
    return client_buckets[client_id].consume()
```

### Audit Logging of Tool Invocations

Every tool call must be logged before execution, with the full input, client identity, and result status.

```python
# audit_logger.py
# Structured audit logging for MCP tool invocations.
# Logs are written to stdout in JSON format for collection by Vector/Fluentd.

import json
import time
import hashlib

def log_tool_invocation(
    client_id: str,
    tool_name: str,
    tool_input: dict,
    result_status: str,
    duration_ms: float,
    error: str | None = None
):
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": "mcp.tool_invocation",
        "client_id": client_id,
        "tool_name": tool_name,
        "input_hash": hashlib.sha256(
            json.dumps(tool_input, sort_keys=True).encode()
        ).hexdigest()[:16],
        "input_preview": json.dumps(tool_input)[:512],
        "result_status": result_status,  # "success", "denied", "error", "rate_limited"
        "duration_ms": duration_ms,
        "error": error,
    }
    # Write to stdout for log collection pipeline
    print(json.dumps(entry), flush=True)
```

Ship these logs to immutable storage:

```yaml
# vector-mcp-audit.yaml
# Vector config to ship MCP audit logs to S3 with immutable retention
sources:
  mcp_audit:
    type: file
    include:
      - "/var/log/mcp-server/*.log"
sinks:
  s3_audit:
    type: aws_s3
    inputs:
      - mcp_audit
    bucket: "mcp-audit-logs"
    key_prefix: "mcp/{{ '{{' }} timestamp {{ '}}' }}/"
    encoding:
      codec: json
    compression: gzip
```

### Preventing Prompt Injection Through Tool Responses

Tool responses flow back into the model's context. A response containing crafted instructions can hijack the agent's next action. Sanitize all tool outputs before returning them to the model.

```python
# output_sanitizer.py
# Strips known prompt injection patterns from tool responses
# before they re-enter the model context.

import re

INJECTION_PATTERNS = [
    r"(?i)ignore\s+(all\s+)?previous\s+instructions",
    r"(?i)you\s+are\s+now\s+",
    r"(?i)system\s*:\s*",
    r"(?i)<\s*/?system\s*>",
    r"(?i)IMPORTANT:\s*override",
    r"(?i)new\s+instructions?\s*:",
]

def sanitize_tool_output(output: str, max_length: int = 10000) -> str:
    """Sanitize tool output before returning to model context."""
    # Truncate to prevent context stuffing
    output = output[:max_length]

    # Flag (do not silently remove - log for investigation)
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, output):
            return (
                "[TOOL OUTPUT FLAGGED: potential prompt injection detected. "
                "Raw output withheld. Check audit log for details.]"
            )

    return output
```

## Expected Behaviour

- SSE transport endpoints require TLS 1.3 and bearer token authentication
- Each client identity has an explicit tool allowlist; default policy denies all tools
- Every tool input is validated against a JSON Schema before execution
- Tool calls are rate-limited to 30 per minute per client (configurable)
- Every tool invocation is logged with client identity, input hash, and result status
- Tool responses are scanned for prompt injection patterns before returning to model context
- MCP server pods accept connections only from the ai-agents namespace

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Strict input schema validation | Rejects tool calls with unexpected parameters | Legitimate tool calls blocked by overly strict patterns | Test schemas against real agent usage patterns. Log rejected calls to tune schemas. |
| Per-client tool allowlists | Agents can only use explicitly permitted tools | New tools require permission updates before agents can use them | Automate permission updates through CI. Review tool additions as part of MCP server deployment. |
| Output sanitization | Blocks prompt injection through tool responses | False positives on legitimate content containing flagged phrases | Flag and log rather than silently strip. Review flagged outputs. Tune patterns based on false positive rate. |
| Rate limiting (30 calls/min) | Prevents runaway agents from flooding the server | Legitimate batch operations throttled | Per-task rate overrides. Different limits per client role. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| SSE endpoint exposed without auth | Unauthorized clients connect and invoke tools | Network scan detects open port; audit log shows unknown client_id | Terminate exposed endpoint. Apply NetworkPolicy. Rotate any credentials the server had access to. |
| Schema validation bypass | Agent sends malformed input that passes validation | Audit log shows unexpected input patterns; tool errors on malformed data | Tighten JSON Schema patterns. Add server-side input sanitization inside the tool implementation. |
| Rate limiter state lost on restart | Rate limits reset to zero after pod restart | Spike in tool calls immediately after pod restart | Use [Redis](https://redis.io) or shared state for rate limit counters. Accept the risk of a brief burst on restart. |
| Prompt injection through tool response | Agent executes attacker-crafted instructions from tool output | Output monitoring detects anomalous agent actions after a tool call | Activate kill switch. Investigate the data source that returned the injected content. Add [Lakera](https://www.lakera.ai) for real-time detection. |

## When to Consider a Managed Alternative

Securing MCP servers requires building authentication middleware, input validation, rate limiting, and audit logging around every server deployment.

- **HCP [Vault](https://www.vaultproject.io):** Issue short-lived bearer tokens for MCP client authentication instead of static API keys.
- **[Sysdig](https://sysdig.com):** Runtime monitoring of MCP server containers for unexpected syscalls or network connections.
- **[Lakera](https://www.lakera.ai):** Managed prompt injection detection for scanning tool outputs before they return to the model context.
- **[Grafana Cloud](https://grafana.com/cloud):** Centralized MCP audit log dashboards with alerting on anomalous tool call patterns.

**Premium content pack:** MCP server security pack. JSON Schema templates for common tools, authentication middleware, rate limiting configuration, Vector pipeline configs, and [Prometheus](https://prometheus.io) alert rules for MCP server deployments.


## Related Articles

- [Securing AI Agents in Production: Tool-Use Boundaries, Credential Scoping, and Output Verification](/articles/ai-landscape/securing-ai-agents/)
- [Hardening the AI Control Plane: Kill Switches, Rate Limits, and Human-in-the-Loop Gates](/articles/ai-landscape/ai-control-plane/)
- [Sandboxing AI Agent Tool Use: Filesystem, Network, and Process Isolation for Autonomous Actions](/articles/ai-landscape/agent-tool-use-sandboxing/)
- [Agent-to-Agent Trust: Authentication, Delegation, and Capability Boundaries in Multi-Agent Systems](/articles/ai-landscape/agent-to-agent-trust/)
- [AI Credential Delegation: Short-Lived Tokens, Scope Narrowing, and Audit Trails for Agent Access](/articles/ai-landscape/ai-credential-delegation/)
