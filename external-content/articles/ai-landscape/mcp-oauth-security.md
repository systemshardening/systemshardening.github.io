---
title: "MCP OAuth 2.1 Authorization Security"
description: "Implement and harden OAuth 2.1 authorization for Model Context Protocol servers, covering PKCE flows, dynamic client registration, token scoping, and open source MCP SDK security gaps."
slug: mcp-oauth-security
date: 2026-05-02
lastmod: 2026-05-02
category: ai-landscape
tags: ["mcp", "oauth", "authorization", "llm", "ai-agents", "pkce", "dynamic-client-registration"]
personas: ["security-engineer", "ml-engineer", "platform-engineer"]
article_number: 340
difficulty: advanced
estimated_reading_time: 17
published: true
layout: article.njk
permalink: "/articles/ai-landscape/mcp-oauth-security/index.html"
---

# MCP OAuth 2.1 Authorization Security

## Problem

Model Context Protocol (MCP) is an open protocol introduced by Anthropic in late 2024 for connecting LLM agents to external tools and data sources via standardized server interfaces. An MCP server exposes a catalogue of callable tools — filesystem access, database queries, API integrations, shell execution — and any MCP-compatible client, such as Claude Desktop or a custom agent framework, can discover and invoke those tools over a well-defined JSON-RPC transport. The protocol abstracts away the specifics of each integration so that a single agent runtime can work across hundreds of tool providers.

The original MCP specification shipped with no authentication mechanism. Any client that could reach an MCP server's transport endpoint could connect, enumerate tools, and invoke them. For local development workflows — a developer running an MCP server on localhost, accessible only to a Claude Desktop instance on the same machine — this was an acceptable trade-off. The attack surface was bounded by the machine's network controls. But as teams began deploying MCP servers remotely, exposing them over HTTPS to agent runtimes running in cloud infrastructure, the absence of authentication became a structural vulnerability. An unauthenticated HTTP endpoint that executes shell commands, queries databases, or exfiltrates files is not a development convenience; it is an externally exploitable service with no access control.

The November 2024 MCP specification update (spec version 2024-11-05) introduced OAuth 2.1 as the required authorization mechanism for remote MCP servers. Under this model, MCP clients must obtain an OAuth access token from an authorization server before invoking any tools. MCP servers act as OAuth resource servers: they validate the presented bearer token on every inbound request and reject calls that carry no token or an invalid one. The authorization server — which may be Keycloak, Auth0, a cloud identity provider, or a custom implementation — issues, validates, and revokes tokens. The MCP server itself does not issue tokens; it only verifies them.

The OAuth 2.1 flow selected for MCP is the authorization code flow with Proof Key for Code Exchange (PKCE), mandatory for public clients. PKCE was originally designed to protect mobile and single-page-app OAuth flows from authorization code interception attacks, and MCP clients are architecturally similar: they run in environments where a client secret cannot be kept confidential. The PKCE mechanism — a one-time `code_verifier` / `code_challenge` pair bound to each authorization request — ensures that only the client that initiated the flow can exchange the authorization code for a token. MCP also incorporates dynamic client registration (RFC 7591), because MCP clients often have no pre-configured credentials with a given MCP server's authorization server. Dynamic registration lets a client register itself at runtime and receive a `client_id` and optional `client_secret` before beginning the authorization flow.

Beyond the core flow, production MCP OAuth deployments must manage token scoping per tool or per tool group, refresh token rotation, and short access token lifetimes. These requirements interact: a 15-minute access token lifetime means frequent silent refreshes using a rotating refresh token, which requires the client to correctly implement the rotation protocol and the server to invalidate used refresh tokens. Scope granularity creates management overhead — a server with 20 tools may define 10–20 distinct OAuth scopes, each of which must be maintained, documented, and validated in server-side middleware.

The MCP SDK implementations that most teams use in practice are the TypeScript SDK (`@modelcontextprotocol/sdk`) and the Python SDK (`mcp`). Both moved quickly to implement OAuth support following the November 2024 spec update. Several security issues surfaced in public GitHub pull requests and commits and were resolved before receiving broad attention or formal CVE identifiers. The TypeScript SDK initially had a CSRF vulnerability in its OAuth callback handler: the `state` parameter returned by the authorization server was not validated against the session state stored during the authorization request, allowing an attacker who could intercept or predict the callback URL to complete an OAuth flow on behalf of another user and bind their authorization code to the victim's session. The fix landed in a public GitHub pull request several days before a corrected npm package version was published. No CVE was filed. During the gap, any MCP deployment using the affected TypeScript SDK version and exposing its OAuth callback to the internet was exploitable.

The Python MCP SDK had a separate issue: access tokens obtained during the OAuth flow were written to a local file cache with world-readable permissions (mode `0o644`). Any process running under a different user on the same system could read the cached access token and use it to impersonate the MCP client. The fix was committed with the message "fix token file permissions" and set the file mode to `0o600`. No security advisory was published on PyPI or in the repository's security tab. Separately, several MCP server implementations that implemented dynamic client registration accepted arbitrary `redirect_uri` values during registration without validating them against an allowlist, enabling open redirect attacks where an attacker could register a client pointing to an attacker-controlled redirect URI. These fixes were committed silently across multiple repositories.

The practical implication is that the MCP ecosystem's security posture depends heavily on tracking upstream SDK commits, not just released package versions. Teams should watch `https://github.com/modelcontextprotocol/python-sdk/commits/main` and the equivalent TypeScript SDK repository for commits touching paths that include `auth`, `oauth`, or `token`. Subscribe to the MCP specification repository for spec changes that imply security fixes — a spec clarification about state parameter handling or redirect URI validation is a signal that an attack was identified. Check npm and PyPI for new MCP SDK releases immediately on publication and read the full changelog before upgrading or deciding to hold.

Target systems: MCP spec 2024-11-05+, `@modelcontextprotocol/sdk` 1.x, `mcp` Python package 1.x.

## Threat Model

1. **Unauthenticated tool invocation.** An attacker discovers an internet-exposed MCP server running without OAuth enforcement — either pre-2024-11-05 spec, a development deployment promoted to production, or a server where the OAuth middleware was misconfigured and fails open. The attacker sends a valid JSON-RPC `tools/call` request and executes any available tool, including those with write access or shell execution capability. No credentials are required.

2. **CSRF on the OAuth callback.** A legitimate user initiates an MCP OAuth authorization flow. Before the user completes authorization, an attacker crafts a callback URL containing the attacker's authorization code and the victim's session cookie (obtained via a prior XSS or session fixation). If the MCP client's callback handler does not validate the `state` parameter against the session, it accepts the attacker's code and exchanges it for a token bound to the victim's session. The attacker can now invoke MCP tools as the victim, accessing the victim's connected resources. This is the class of vulnerability that existed in the TypeScript MCP SDK before the CSRF fix.

3. **Patch-gap exploitation.** An attacker monitors `https://github.com/modelcontextprotocol/python-sdk/commits/main` and identifies a commit that fixes an OIDC token validation bypass — for example, a missing `iss` or `aud` claim check in JWT validation. The fix is merged but a new PyPI package version has not yet been released. The attacker identifies MCP servers in the wild that report the current (unfixed) package version via error messages or misconfigured debug endpoints, and exploits the validation bypass to present a forged token that the server accepts as valid. The window between merge and published package release has historically been days to over a week.

4. **Token scope confusion.** An MCP client requests and obtains an access token scoped to `mcp:files:read`. The MCP server's tool dispatch middleware validates token presence but does not check the specific scope against the invoked tool. The client sends a `tools/call` request for `shell_execute` — a tool that requires `mcp:shell:execute` scope. The server dispatches the call and executes the shell command. The client obtained a narrowly scoped token but gained broad execution access due to absent server-side scope enforcement.

The blast radius of any of these failures scales with the tools the MCP server exposes. A read-only documentation MCP server carries low risk. An MCP server that provides filesystem access, database write capability, API key retrieval, or shell execution on a cloud instance is a complete compromise vector. The combination of OAuth's perceived complexity — teams often ship "good enough" implementations — and the fast-moving MCP SDK release cadence creates a persistent gap between specification intent and deployed reality.

## Configuration / Implementation

### OAuth 2.1 Flow for MCP Servers

The authorization code flow with PKCE for an MCP client proceeds in the following sequence:

```
MCP Client                    Authorization Server         MCP Server (Resource Server)
     |                               |                              |
     |-- Generate code_verifier -----+                              |
     |   code_challenge = BASE64URL(SHA256(code_verifier))         |
     |                               |                              |
     |-- GET /authorize?             |                              |
     |   response_type=code          |                              |
     |   client_id=<id>              |                              |
     |   redirect_uri=<uri>          |                              |
     |   code_challenge=<hash>       |                              |
     |   code_challenge_method=S256  |                              |
     |   state=<random>              |                              |
     |   scope=mcp:files:read ------>|                              |
     |                               |                              |
     |<-- Redirect with code + state-|                              |
     |                               |                              |
     |-- Validate state matches -----+                              |
     |   session state               |                              |
     |                               |                              |
     |-- POST /token?                |                              |
     |   grant_type=authorization_code                              |
     |   code=<auth_code>            |                              |
     |   code_verifier=<verifier> -->|                              |
     |                               |                              |
     |<-- access_token + refresh_token                              |
     |                               |                              |
     |-- tools/call request          |                              |
     |   Authorization: Bearer <token> --------------------------->|
     |                               |                              |
     |                               |<-- introspect or JWT verify -|
     |                               |-- active, scope, sub ------->|
     |                               |                              |
     |<-- tool result ------------------------------------------------
```

The `code_challenge_method` must be `S256`. Plain challenge method is prohibited in OAuth 2.1. The `state` parameter must be a cryptographically random value generated per authorization request and stored server-side.

### Implementing OAuth in a Python MCP Server

The `mcp` Python library provides an `OAuthProvider` abstraction for integrating an external authorization server. The following example uses token introspection — the MCP server calls the authorization server's introspection endpoint (`POST /introspect`) on each request rather than validating JWTs locally, which avoids the class of JWT validation bugs present in the Python SDK's early releases.

```python
import os
import httpx
from functools import wraps
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.types import Tool, TextContent

INTROSPECTION_ENDPOINT = os.environ["OAUTH_INTROSPECTION_URL"]
INTROSPECTION_CLIENT_ID = os.environ["OAUTH_CLIENT_ID"]
INTROSPECTION_CLIENT_SECRET = os.environ["OAUTH_CLIENT_SECRET"]

server = Server("secure-mcp-server")


async def introspect_token(token: str) -> dict:
    """Call the authorization server introspection endpoint."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            INTROSPECTION_ENDPOINT,
            data={"token": token},
            auth=(INTROSPECTION_CLIENT_ID, INTROSPECTION_CLIENT_SECRET),
            timeout=5.0,
        )
        response.raise_for_status()
        return response.json()


def require_scope(required_scope: str):
    """Decorator that enforces a specific OAuth scope for an MCP tool handler."""
    def decorator(func):
        @wraps(func)
        async def wrapper(token: str, *args, **kwargs):
            token_data = await introspect_token(token)
            if not token_data.get("active", False):
                raise PermissionError("Token is not active")
            granted_scopes = token_data.get("scope", "").split()
            if required_scope not in granted_scopes:
                raise PermissionError(
                    f"Insufficient scope: required {required_scope}, "
                    f"granted {granted_scopes}"
                )
            return await func(token_data, *args, **kwargs)
        return wrapper
    return decorator


@server.call_tool()
@require_scope("mcp:files:read")
async def handle_read_file(token_data: dict, name: str, arguments: dict):
    if name == "read_file":
        path = arguments.get("path", "")
        # Enforce path restrictions based on token subject
        subject = token_data.get("sub", "unknown")
        allowed_prefix = f"/data/users/{subject}/"
        if not path.startswith(allowed_prefix):
            raise PermissionError(f"Path {path} not permitted for subject {subject}")
        with open(path) as f:
            return [TextContent(type="text", text=f.read())]


@server.call_tool()
@require_scope("mcp:shell:execute")
async def handle_shell(token_data: dict, name: str, arguments: dict):
    # Shell tool requires explicit high-privilege scope
    if name == "shell_execute":
        import subprocess
        cmd = arguments.get("command", "")
        result = subprocess.run(
            cmd, shell=False, capture_output=True, text=True,
            args=cmd.split(), timeout=30
        )
        return [TextContent(type="text", text=result.stdout)]
```

For Keycloak, set `OAUTH_INTROSPECTION_URL=https://keycloak.internal/realms/mcp/protocol/openid-connect/token/introspect`. For Auth0, set it to `https://<tenant>.auth0.com/oauth/introspect`.

### Dynamic Client Registration Hardening

If your MCP authorization server implements dynamic client registration (RFC 7591), harden it against abuse:

```python
import secrets
import re
from datetime import datetime, timedelta

ALLOWED_GRANT_TYPES = {"authorization_code", "refresh_token"}
ALLOWED_REDIRECT_URI_PATTERN = re.compile(
    r"^https://([a-z0-9-]+\.)*yourdomain\.com/mcp/callback$"
)
REGISTRATION_TOKEN_STORE = {}  # replace with persistent store


def validate_registration_request(request: dict, initial_access_token: str) -> None:
    """Validate a dynamic client registration request."""
    # Require a pre-issued initial access token
    if initial_access_token not in REGISTRATION_TOKEN_STORE:
        raise ValueError("Invalid or expired initial_access_token")
    if REGISTRATION_TOKEN_STORE[initial_access_token] < datetime.utcnow():
        raise ValueError("initial_access_token has expired")

    # Validate grant types
    requested_grants = set(request.get("grant_types", []))
    if not requested_grants.issubset(ALLOWED_GRANT_TYPES):
        raise ValueError(f"Disallowed grant types: {requested_grants - ALLOWED_GRANT_TYPES}")

    # Validate redirect URIs against allowlist pattern
    for uri in request.get("redirect_uris", []):
        if not ALLOWED_REDIRECT_URI_PATTERN.match(uri):
            raise ValueError(f"redirect_uri not permitted: {uri}")

    # Consume the initial access token (single use)
    del REGISTRATION_TOKEN_STORE[initial_access_token]


def issue_initial_access_token(expires_in_minutes: int = 60) -> str:
    """Issue a single-use initial access token for dynamic registration."""
    token = secrets.token_urlsafe(32)
    expiry = datetime.utcnow() + timedelta(minutes=expires_in_minutes)
    REGISTRATION_TOKEN_STORE[token] = expiry
    return token
```

Registered clients should be stored in a database with an expiry timestamp. Purge unconfirmed registrations that have not completed an authorization flow within 24 hours.

### Token Scoping per Tool

Define OAuth scopes at the tool-group level, not per individual tool, to keep scope count manageable:

```
mcp:files:read          — read_file, list_directory, stat_file
mcp:files:write         — write_file, delete_file, move_file
mcp:database:read       — query_database, describe_schema
mcp:database:write      — execute_dml, run_migration
mcp:shell:execute       — shell_execute, run_script
mcp:secrets:read        — get_secret, list_secrets
```

In the server's tool dispatch middleware, map each tool name to its required scope and return `403` with a `WWW-Authenticate` header on mismatch:

```python
TOOL_SCOPE_MAP = {
    "read_file": "mcp:files:read",
    "write_file": "mcp:files:write",
    "query_database": "mcp:database:read",
    "shell_execute": "mcp:shell:execute",
    "get_secret": "mcp:secrets:read",
}

async def dispatch_tool_with_scope_check(
    tool_name: str, arguments: dict, bearer_token: str
) -> dict:
    required_scope = TOOL_SCOPE_MAP.get(tool_name)
    if required_scope is None:
        raise ValueError(f"Unknown tool: {tool_name}")

    token_data = await introspect_token(bearer_token)
    if not token_data.get("active"):
        # Return 401-equivalent in JSON-RPC
        return {
            "error": "unauthorized",
            "www_authenticate": 'Bearer error="invalid_token"'
        }

    granted = set(token_data.get("scope", "").split())
    if required_scope not in granted:
        return {
            "error": "forbidden",
            "www_authenticate": (
                f'Bearer error="insufficient_scope", '
                f'scope="{required_scope}"'
            )
        }

    return await invoke_tool(tool_name, arguments, token_data)
```

### State Parameter and CSRF Protection

Generate the `state` parameter using `secrets.token_urlsafe(32)` — 32 bytes provides 256 bits of entropy, sufficient to resist brute force. Store the `state` value server-side, keyed to the user's session identifier. Do not rely on a cookie alone to carry state, as cookie-based state can be bypassed in certain browser configurations. Validate that the `state` returned in the callback matches the stored value before exchanging the authorization code:

```python
import secrets
from typing import Optional

# Use a server-side session store (Redis, database, etc.)
STATE_STORE: dict[str, str] = {}  # session_id -> state


def begin_authorization(session_id: str) -> tuple[str, str]:
    """Generate PKCE code_verifier, code_challenge, and state."""
    import base64, hashlib

    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    state = secrets.token_urlsafe(32)

    STATE_STORE[session_id] = state
    return code_verifier, code_challenge, state


def validate_callback(session_id: str, returned_state: str) -> bool:
    """Validate the state parameter from the OAuth callback."""
    expected = STATE_STORE.pop(session_id, None)
    if expected is None:
        return False
    return secrets.compare_digest(expected, returned_state)
```

Use `secrets.compare_digest` rather than `==` to avoid timing side-channels in state comparison.

### Monitoring MCP SDK for Silent Security Fixes

Run this command on a schedule (daily via cron or a CI pipeline) to surface security-relevant commits in the Python MCP SDK:

```bash
gh api repos/modelcontextprotocol/python-sdk/commits \
  --jq '.[] | select(
    .commit.message | test("auth|oauth|token|csrf|redirect|scope|permission|secret|vuln|fix|security"; "i")
  ) | {sha: .sha[0:8], message: .commit.message, date: .commit.author.date}'
```

Do the same for the TypeScript SDK:

```bash
gh api repos/modelcontextprotocol/typescript-sdk/commits \
  --jq '.[] | select(
    .commit.message | test("auth|oauth|token|csrf|redirect|scope|permission|secret|vuln|fix|security"; "i")
  ) | {sha: .sha[0:8], message: .commit.message, date: .commit.author.date}'
```

Subscribe to npm release notifications for `@modelcontextprotocol/sdk` and PyPI release notifications for `mcp`. When a new version publishes, retrieve the full changelog before deciding whether to hold or upgrade. A GitHub Actions workflow can automate this check and open a Dependabot-style PR with the diff between the currently pinned version and the new release, allowing security review before deployment.

### Token Rotation and Revocation

Configure short access token lifetimes — 15 minutes for MCP tool calls is appropriate. Long-lived tokens increase the blast radius of a token leak, since a leaked access token from an MCP client log or a memory dump can be used by an attacker for the token's full remaining lifetime. Use refresh tokens with rotation enabled: each use of a refresh token must issue a new refresh token and invalidate the previous one. If a refresh token is replayed — presented a second time after rotation — treat it as a compromise signal and revoke the entire token family for that user.

```python
async def revoke_all_user_tokens(
    user_subject: str,
    revocation_endpoint: str,
    client_id: str,
    client_secret: str
) -> None:
    """Revoke all tokens for a user on session termination."""
    # Retrieve all active refresh tokens for the user from your token store
    tokens = await get_user_refresh_tokens(user_subject)
    async with httpx.AsyncClient() as client:
        for token in tokens:
            await client.post(
                revocation_endpoint,
                data={"token": token, "token_type_hint": "refresh_token"},
                auth=(client_id, client_secret),
            )
    await clear_user_token_store(user_subject)
```

Call this function on user logout, on detected compromise, and on account suspension.

## Expected Behaviour

| Signal | Without OAuth | With OAuth 2.1 + Hardening |
|---|---|---|
| Unauthenticated tool invocation | Tool executes; attacker gains full access to all exposed tools | Request rejected with `401 Unauthorized`; no tool dispatch occurs |
| CSRF attack on OAuth callback | Attacker's authorization code accepted; victim's session bound to attacker-controlled token | `state` parameter mismatch detected; callback rejected; no token issued; event logged |
| Scope escalation attempt | `shell_execute` invoked with read-only token; server dispatches the call | Server checks `mcp:shell:execute` scope against token; returns `403` with `WWW-Authenticate: Bearer error="insufficient_scope"` |
| SDK patch-gap exploitation window | Forged or replayed token accepted due to missing validation; attacker accesses resources | Token introspection calls authorization server on every request; local JWT validation not used; patch-gap in SDK JWT code has no effect |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| OAuth token validation per request | Every tool call is authorized against a live token state; revoked tokens are immediately rejected | Adds 10–50 ms of latency per request for introspection round-trip to authorization server | Cache introspection responses for the token's remaining lifetime using the `exp` claim; use JWT validation for low-sensitivity tools to avoid the network call |
| Dynamic client registration | MCP clients can self-register without pre-provisioned credentials; reduces operational friction for new deployments | Increases attack surface; malicious clients can attempt to register with crafted parameters; requires robust registration endpoint validation | Require initial access tokens for all registrations; enforce strict allowlists on `redirect_uri` and `grant_types`; expire unconfirmed registrations |
| Short access token lifetime (15 min) | Limits the exploitation window for leaked tokens; forces frequent re-validation | MCP clients must implement silent refresh correctly; failed refresh causes tool invocation failures visible to end users | Implement proactive refresh (refresh when 70% of lifetime elapsed); return clear error codes that prompt retry so agents can recover gracefully |
| Fine-grained scope per tool group | Limits blast radius of a compromised token to the scopes it carries; enables least-privilege tool access | More scopes to define, document, and maintain; MCP clients must request correct scopes upfront; scope mismatch errors degrade agent reliability | Define scopes at tool-group granularity (not per individual tool); document the scope catalogue in the MCP server's well-known metadata endpoint |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Authorization server unavailable | All MCP tool invocations fail; introspection calls time out; MCP server returns `503` or generic errors to clients | Authorization server health check alert fires; MCP error rate metric exceeds threshold; client-side tool invocation failure rate spikes | Fail closed — reject all tool calls when the authorization server is unreachable; do not cache previous introspection results past expiry; restore authorization server; alerts should page on-call within 2 minutes of downtime |
| Token introspection endpoint rate limited | Sporadic `429` responses from authorization server; intermittent tool invocation failures under load | Authorization server client metrics show `429` rate; MCP server error logs show introspection failures | Implement introspection response caching keyed on token hash with TTL set to the token's `exp` minus current time; reduce introspection call volume; coordinate rate limit increase with authorization server operator |
| PKCE code verifier mismatch | Authorization flow loops; client presents code verifier that does not match the challenge sent in the authorization request; authorization server returns `invalid_grant` | Client logs show repeated authorization code exchange failures; user-visible auth loop that never completes | Verify `code_verifier` is stored in durable session storage before redirect, not in memory; ensure session state is not reset between the authorization redirect and the callback; regenerate `code_verifier` and restart the flow |
| Scope definition mismatch between client and server | Client requests `mcp:files:read`; server expects `files:read`; all tool calls for that group return `403`; agent cannot complete tasks requiring file access | `403` errors on specific tool categories visible in server logs; agent task completion rate drops for affected tool groups | Publish the server's scope catalogue at `/.well-known/oauth-authorization-server` in the `scopes_supported` field; update client to request scopes exactly as defined; test scope round-trips in CI before deploying server changes |

## Related Articles

- [MCP Authentication Patterns](/articles/ai-landscape/mcp-authentication/)
- [MCP Server Security](/articles/ai-landscape/mcp-server-security/)
- [MCP Transport Security](/articles/ai-landscape/mcp-transport-security/)
- [OAuth 2.0 and OIDC Hardening](/articles/cross-cutting/oauth2-oidc-hardening/)
- [Securing AI Agents](/articles/ai-landscape/securing-ai-agents/)
