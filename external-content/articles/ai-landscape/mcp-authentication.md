---
title: "MCP Authentication Patterns: OAuth 2.1, Capability Tokens, and Per-Tool Authorization"
description: "MCP servers expose tool surfaces to LLM agents. The auth model decides what an agent can do — and most deployments leave it underspecified."
slug: "mcp-authentication"
date: 2026-04-27
lastmod: 2026-04-27
category: "ai-landscape"
tags: ["mcp", "authentication", "oauth", "agents", "ai-security"]
personas: ["security-engineer", "ml-engineer", "platform-engineer"]
article_number: 193
difficulty: "intermediate"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/ai-landscape/mcp-authentication/index.html"
---

# MCP Authentication Patterns: OAuth 2.1, Capability Tokens, and Per-Tool Authorization

## Problem

Model Context Protocol (MCP) servers expose tools, resources, and prompts to LLM clients. An agent backed by Claude, ChatGPT, Gemini, or any MCP-aware model can connect to a server, enumerate its capabilities, and invoke tools on the user's behalf. By 2026, MCP servers exist for filesystems, databases, ticketing systems, GitHub, Slack, Google Workspace, Jira, internal APIs, and dozens more.

The authentication and authorization story is structurally underspecified. The MCP specification covers transport-layer authentication via OAuth 2.1 (added in the 2025-06-18 spec revision) and bearer tokens, but most production deployments treat auth as "the bearer token grants everything." The specific gaps:

- **Coarse tokens.** A single token authorizes the entire MCP server; a user who gave the agent a token for "the internal-tools MCP" gave it access to every tool the server exposes.
- **No per-tool authorization.** Tools that read public data and tools that perform privileged writes share the same token. An LLM that reads a phishing-style instruction in retrieved data can invoke any tool.
- **Long-lived tokens.** Access tokens often live for hours or days, with no proof-of-possession binding. A leaked token = full impersonation.
- **No audit trail of agent actions.** Standard server logs show "tool X invoked at time T" without identifying which user session caused it.
- **No capability tokens.** Each tool call uses the same broad authority instead of a fresh, narrowly-scoped capability token.
- **OAuth flows that confuse end users.** When the MCP server is itself an OAuth client to a downstream API (Google Workspace, Salesforce), users see a chain of consent prompts they don't fully parse — and approve.

This article covers OAuth 2.1 + PKCE for MCP authentication, capability-token patterns for per-tool authorization, proof-of-possession (DPoP) tokens to bind tokens to a session, audit logging keyed to user-agent-tool triples, and the policy decisions for production MCP deployments.

**Target systems:** MCP specification 2025-06-18+, MCP SDKs in Python (`mcp` 1.4+), TypeScript (`@modelcontextprotocol/sdk` 1.4+), Rust (`mcp-rs` 0.5+). OAuth 2.1 + PKCE per RFC 9700; DPoP per RFC 9449.

## Threat Model

- **Adversary 1 — Stolen MCP token:** an attacker has a leaked access token from a developer's `.env`, a CI runner log, or a compromised laptop. Wants to impersonate the user against the MCP server.
- **Adversary 2 — Confused-deputy via prompt injection:** end-user content reaches the LLM (a webpage, an email, a document the agent reads). Injected instructions try to drive tool calls the user did not intend.
- **Adversary 3 — Malicious or compromised MCP server:** the agent connects to a server that is either intentionally hostile or has been compromised. Wants to harvest tokens, steal data, or pivot through the agent's other connections.
- **Adversary 4 — Network-on-path observer:** intercepts MCP traffic between agent and server.
- **Access level:** Adversary 1 has a leaked token. Adversary 2 has only content the LLM reads. Adversary 3 controls the MCP server. Adversary 4 has network interception.
- **Objective:** Drive tool calls outside the user's intent; harvest credentials; observe sensitive data flowing through MCP.
- **Blast radius:** Without per-tool authorization, a compromised token or successful prompt injection authorizes every tool on the server. With proper segmentation, even a perfectly-replicated token grants only the specific capabilities it was minted for.

## Configuration

### Step 1: OAuth 2.1 + PKCE for the Initial Authorization

MCP's recommended auth flow is OAuth 2.1 with PKCE (the only safe public-client flow). The MCP client (an LLM agent application) is the OAuth client; the MCP server is the protected resource.

Server-side metadata at `/.well-known/oauth-authorization-server`:

```json
{
  "issuer": "https://mcp.internal.example.com",
  "authorization_endpoint": "https://auth.internal.example.com/oauth2/authorize",
  "token_endpoint": "https://auth.internal.example.com/oauth2/token",
  "jwks_uri": "https://auth.internal.example.com/.well-known/jwks.json",
  "scopes_supported": [
    "mcp:tools:list",
    "mcp:tools:call:read",
    "mcp:tools:call:write",
    "mcp:tools:call:admin",
    "mcp:resources:read"
  ],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none"],
  "dpop_signing_alg_values_supported": ["ES256", "EdDSA"]
}
```

The agent client implements the standard PKCE flow: generate `code_verifier`, derive `code_challenge`, redirect user to authorization endpoint, exchange authorization code at token endpoint with the verifier. Server returns access token and refresh token.

### Step 2: Scope Tokens to Specific Capabilities

Scopes split tool authority. The model: each MCP tool requires a specific scope; tokens are minted with the smallest scope set the agent needs.

In the MCP server (Python example):

```python
# server.py
from mcp.server import Server
from mcp.server.auth import RequireScope

app = Server("internal-tools")

@app.list_tools()
async def list_tools():
    return [
        Tool(name="search_kb", description="Search internal knowledge base",
             scope_required="mcp:tools:call:read"),
        Tool(name="create_ticket", description="Create a Jira ticket",
             scope_required="mcp:tools:call:write"),
        Tool(name="delete_ticket", description="Delete a Jira ticket",
             scope_required="mcp:tools:call:admin"),
    ]

@app.call_tool()
@RequireScope("mcp:tools:call:read")
async def search_kb(query: str) -> list[TextContent]:
    return await kb.search(query)

@app.call_tool()
@RequireScope("mcp:tools:call:write")
async def create_ticket(title: str, body: str) -> TextContent:
    return await jira.create(title, body)
```

A token issued with only `mcp:tools:call:read` cannot invoke `create_ticket`. The MCP server returns a clean `403 insufficient_scope` and the agent surfaces the limitation to the user.

### Step 3: Proof-of-Possession with DPoP

Bearer tokens are stealable. DPoP (RFC 9449) binds a token to a public key: the holder of the matching private key is the only one who can present it. DPoP is mandatory for high-privilege tokens.

```python
# DPoP middleware on the server.
from mcp.server.dpop import DPoPValidator

dpop = DPoPValidator(
    accepted_algs=["ES256", "EdDSA"],
    nonce_required=True,
    nonce_ttl=300,
)

@app.before_request
async def verify_dpop(request):
    if request.scope_required.startswith("mcp:tools:call:write") or \
       request.scope_required.startswith("mcp:tools:call:admin"):
        await dpop.validate(request)
```

On the client, every request carries a `DPoP` header — a signed JWT containing the request method, URL, and a server-issued nonce. Stealing the access token without the private key gives the attacker nothing.

### Step 4: Capability Tokens for Tool Calls

For the highest-privilege operations, issue per-call capability tokens that authorize a single tool call rather than re-using the broad access token.

The flow:

1. Agent attempts `delete_ticket` with the broad access token.
2. Server returns `400` with a `capability_request_uri` — a URL where the user is prompted to approve this specific call.
3. Agent redirects the user (out-of-band, via the agent UI's confirmation flow) to the capability endpoint.
4. User reviews the specific action ("Delete ticket PROD-1234?") and confirms.
5. Server issues a capability token good for one invocation of `delete_ticket(id=PROD-1234)` and only that.
6. Agent retries with the capability token.

```python
# Server-side capability flow.
@app.tool_call_handler("delete_ticket")
async def delete_ticket(token: AccessToken, ticket_id: str):
    cap = await capabilities.find(token=token, tool="delete_ticket", args={"ticket_id": ticket_id})
    if not cap:
        return CapabilityRequired(
            tool="delete_ticket",
            args={"ticket_id": ticket_id},
            confirmation_url=f"https://mcp.internal.example.com/cap/confirm?token={token.id}&tool=delete_ticket&ticket_id={ticket_id}"
        )
    if cap.consumed:
        raise UnauthorizedError("Capability token already used")
    cap.consume()
    return await jira.delete(ticket_id)
```

The user sees the destructive action explicitly and confirms before it happens. A successful prompt injection cannot self-approve a capability token; the human-in-the-loop is structural.

### Step 5: Audit Logging Keyed to User-Agent-Tool Triples

Every MCP call logs the user, the agent client, the tool, the arguments (redacted as needed), and the resolved outcome.

```python
import structlog
log = structlog.get_logger()

@app.tool_call_handler()
async def audit(token, tool, args, result):
    log.info(
        "mcp_tool_call",
        user_id=token.subject,
        client_id=token.audience,
        tool=tool,
        args_hash=hashlib.sha256(json.dumps(args).encode()).hexdigest()[:16],
        scope=token.scope,
        capability_used=token.capability_id if hasattr(token, 'capability_id') else None,
        outcome=result.outcome,
        duration_ms=result.duration_ms,
        request_id=token.request_id,
    )
```

Audit logs feed your SIEM. Detection rules look for:
- High-privilege tool invocations from unexpected clients.
- Bursts of tool calls on the same access token (suggests automation gone wild or compromise).
- Rejected calls (`outcome=insufficient_scope`) at unusual rates per user (suggests probing).

### Step 6: Token Rotation and Session Lifecycle

Access tokens should be short-lived (5-30 minutes); refresh tokens longer but bound. Rotate refresh tokens on every use:

```python
@app.token_endpoint
async def issue_token(grant):
    if grant.type == "refresh_token":
        old = await tokens.find(grant.refresh_token)
        if old.consumed:
            # Refresh token reuse: the original holder may have been compromised.
            await tokens.revoke_all_for_user(old.user_id)
            raise InvalidGrant("Refresh token reuse detected")
        old.consume()
    new_access = AccessToken(ttl_seconds=600, ...)
    new_refresh = RefreshToken(ttl_seconds=86400, ...)
    return TokenResponse(access=new_access, refresh=new_refresh)
```

Refresh-token reuse detection (RFC 6819 §4.4.2) catches the case where an attacker stole a refresh token and used it after the legitimate client also used it.

## Expected Behaviour

| Signal | Default MCP deployment | Hardened |
|--------|-------------------------|----------|
| Token scope | All tools authorized | Scoped per-tool capability |
| Token lifetime | Hours / days | Minutes; refresh tokens rotated |
| Token theft impact | Full impersonation until revoked | Limited by DPoP key binding; capability tokens single-use |
| Prompt-injection driven privileged action | Authorized | Blocked at capability-confirmation step |
| Audit trail per agent action | Server-side only, often missing user attribution | User + client + tool + arg hash + outcome per invocation |
| Token leak in CI / log | Exploitable | Useless without DPoP private key |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| OAuth 2.1 + PKCE | Standard, well-tooled | Initial onboarding requires user consent flow | Use a hosted identity provider (Auth0, Okta, Keycloak) so you don't implement the OAuth server. |
| Per-tool scopes | Fine-grained authorization | More scopes to manage | Group by privilege class (read / write / admin). Resist scope explosion. |
| DPoP | Mitigates token theft | Client must manage private key; some SDKs don't support DPoP yet | Require DPoP only for write/admin-class tokens; read-only tokens use plain bearer. |
| Capability tokens for destructive ops | Human-in-the-loop for risk | UX friction on every privileged call | Limit to truly destructive operations; confirm at session-level for repeated calls within a window. |
| Audit logging per invocation | Strong forensics | Log volume scales with agent activity | Centralize logs to a write-only audit store; redact arg values at ingest, keep only hashes. |
| Refresh-token rotation | Catches reuse / theft | Complex client-side handling | Use OAuth client SDKs that handle rotation natively. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Scope check missing on a tool | Privileged tool callable with read-only token | Audit log shows successful invocation despite scope mismatch | Code review; add scope decorator. Test by invoking with a read-only token. |
| DPoP nonce reuse | Replayed request appears valid | Server detects nonce already consumed and rejects | Working as intended; investigate where the replay came from. |
| Capability confirmation bypassed | Destructive operation completes without user confirmation | Audit log shows operation without preceding capability-confirm event | Bug in the capability flow; fix the server-side enforcement. The flow must be a hard requirement, not a recommendation. |
| Refresh-token reuse on legitimate client | False positive token revocation | User session interrupted; re-authentication required | Race condition on the client side. Implement strict mutex around refresh-token use; cache the new access token before the old refresh is consumed. |
| Token in browser localStorage | XSS exfiltrates token | Browser-side console flagged in security scan | Use BFF (backend-for-frontend) pattern; tokens never reach browser JS. |
| Confused-deputy from prompt injection | Agent invokes destructive tool based on injected instruction | Audit log shows tool call with arguments resembling the injection | Capability tokens prevent this for write-class tools; for read-class tools, harden the agent's prompt to mark retrieved content as untrusted. |

## When to Consider a Managed Alternative

Self-hosting MCP authentication requires OAuth server, scope catalog, DPoP middleware, audit pipeline, and capability-flow UX (8-15 hours/month for an enterprise MCP deployment).

- **Auth0 or Okta with custom MCP scopes:** offload OAuth, integrate via JWT claims to your MCP server.
- **AWS Cognito or GCP Identity Platform:** managed identity with OAuth; integrates with cloud-side audit.
- **Cloudflare Access:** zero-trust gateway in front of MCP servers; integrates with your existing IdP.

## Related Articles

- [MCP Server Security: Threat Model for Model Context Protocol Deployments](/articles/ai-landscape/mcp-server-security/)
- [MCP Tool Permission Patterns](/articles/ai-landscape/mcp-tool-permission-patterns/)
- [MCP Transport Security](/articles/ai-landscape/mcp-transport-security/)
- [Agent Memory Poisoning Defence](/articles/ai-landscape/agent-memory-poisoning/)
- [Agent Tool-Use Sandboxing](/articles/ai-landscape/agent-tool-use-sandboxing/)
