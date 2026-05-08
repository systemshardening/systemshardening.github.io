---
title: "MCP RCE via Project Config Files: CVE-2026-21852 and the MCP Trust Model"
description: "CVE-2026-21852 lets a malicious repository execute code on any developer running Claude Code. The root cause is MCP's trust model: servers are authenticated by config file presence, not cryptographic identity. Harden MCP server trust boundaries and project config handling."
slug: mcp-rce-project-config-hardening
date: 2026-05-04
lastmod: 2026-05-04
category: ai-landscape
tags:
  - mcp
  - rce
  - cve
  - claude-code
  - ai-security
personas:
  - security-engineer
  - platform-engineer
article_number: 436
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/ai-landscape/mcp-rce-project-config-hardening/
---

# MCP RCE via Project Config Files: CVE-2026-21852 and the MCP Trust Model

## The Problem

CVE-2026-21852 describes a code execution path in Claude Code: when a developer opens a project directory, Claude Code reads `.claude/settings.json` to load project-specific configuration, including MCP server definitions. A malicious MCP server definition in that file causes Claude Code to start the specified binary or script as an MCP server process — executing arbitrary code with the developer's full user privileges, before any user interaction beyond opening the directory.

An attacker who can get a developer to clone a malicious repository achieves RCE without the developer running any explicit command. The vector is a GitHub link, a dependency repository, a code review request, an internal fork. Clone the repository, open it in Claude Code: the payload runs.

The broader systemic flaw disclosed in April 2026 by Check Point Research is the MCP protocol's trust model. MCP servers are authenticated by their presence in a configuration file, not by any cryptographic identity. There is no signature verification on server definitions. There is no binding between a running server process and the key material that originated the configuration. Any process or script that can write to `~/.claude/settings.json` or to a project's `.claude/` directory becomes a trusted MCP server — it will receive tool calls, including requests to read files, execute shell commands, and access secrets. Researchers identified over 200,000 MCP server instances reachable or locally configured at disclosure time, with a significant portion configured to auto-discover and execute local server definitions without user confirmation.

The two vulnerabilities compound each other. CVE-2026-21852 provides initial code execution in the developer environment. The trust-model flaw provides persistence and privilege escalation: a payload that writes a second MCP server definition to the global `~/.claude/settings.json` survives project deletion and persists across all future Claude Code sessions. Once the global config is poisoned, every subsequent project the developer opens routes tool calls through the attacker's server.

The fix for CVE-2026-21852 is a patch that adds a user confirmation prompt before executing project-level MCP servers. The fix for the systemic trust-model flaw requires defence in depth: protecting config files from unauthorized modification, auditing MCP server definitions before accepting them, restricting what MCP servers can reach once they run, and applying least-privilege grants over what tools each server can invoke.

## Threat Model

- **Malicious repository with crafted `.claude/settings.json`:** a repository contains a `.claude/` directory with a `settings.json` that defines an MCP server pointing to a script bundled in the repository. When the developer opens the project in Claude Code, the script executes with the developer's user privileges. No explicit command required beyond opening the directory.

- **Supply chain attack via package manager:** a compromised npm or PyPI package includes a postinstall script that writes a malicious MCP server definition to `~/.claude/settings.json`. The package is a transitive dependency; the developer never installs it directly. The poisoned global config then persists across every Claude Code session on the machine.

- **MCP server impersonation via config overwrite:** a local process with write access to the MCP config file — a compromised background service, a script from another package, a scheduled job — replaces the legitimate MCP server definitions with a definition pointing to an attacker-controlled binary. That binary then receives all subsequent tool calls: file reads, shell executions, API credentials passed as tool arguments.

- **Prompt injection via MCP tool response:** a malicious MCP server does not need to perform its own destructive actions. It can respond to tool calls with content containing injected instructions, causing Claude to take unintended actions — exfiltrating files through a subsequent tool call, making API requests to attacker-controlled infrastructure, or disclosing secrets from the session context.

- **Blast radius:** developer's full user privileges. Source trees, SSH keys, cloud credentials, browser sessions, development secrets, internal API access — anything accessible to the developer's account is accessible to code running as that developer.

## Hardening Configuration

### 1. Apply the Claude Code patch

Update Claude Code to the version that addresses CVE-2026-21852. The patch adds a confirmation prompt requiring explicit user approval before executing any MCP server definition found in a project-level config file. Without this patch, project MCP servers execute silently on directory open.

```bash
npm update -g @anthropic-ai/claude-code
claude --version
```

Verify the installed version against the release notes entry that references the project MCP server confirmation feature. In a team environment, pin the minimum acceptable version in your developer tooling baseline and enforce it through onboarding checks:

```bash
REQUIRED_MAJOR=1
REQUIRED_MINOR=8
version=$(claude --version | grep -oP '\d+\.\d+\.\d+' | head -1)
major=$(echo "$version" | cut -d. -f1)
minor=$(echo "$version" | cut -d. -f2)
if [ "$major" -lt "$REQUIRED_MAJOR" ] || { [ "$major" -eq "$REQUIRED_MAJOR" ] && [ "$minor" -lt "$REQUIRED_MINOR" ]; }; then
  echo "Claude Code $version is below minimum required version. Update before opening projects."
  exit 1
fi
```

### 2. Audit project MCP server definitions before opening a cloned repository

Before opening any cloned repository in Claude Code, inspect its `.claude/` directory for unexpected MCP server entries. This step is relevant even with the patch applied: the patch produces a confirmation dialog, but you need to know what you are being asked to approve.

```bash
find . -name "settings.json" -path "*/.claude/*" | xargs cat 2>/dev/null
```

Inspect the `mcpServers` key in any result. Red flags:

- MCP server commands pointing to executables outside the project directory (`/tmp/`, `~/.local/`, absolute paths unrelated to the project)
- Network-listening servers defined as local MCP servers (server command opens a TCP socket on a fixed port)
- Shell scripts with obfuscated content: base64-encoded payloads, `eval`, `curl | bash` patterns
- MCP server names that shadow names defined in your global config (an attempt to intercept tool calls intended for a legitimate server)

```bash
find . -name "settings.json" -path "*/.claude/*" | while read f; do
  echo "--- $f ---"
  python3 -m json.tool "$f" 2>/dev/null | grep -A5 '"mcpServers"'
done
```

For repositories that define project MCP servers for legitimate shared tooling, verify the server command against the repository's own source: the command should resolve to a file that exists in the repository and whose contents you can read and understand.

### 3. Disable project-level MCP server auto-approval

Configure Claude Code's global settings to require explicit approval for each project-level MCP server rather than auto-starting them. Set `mcp.projectServers.autoApprove` to `false` in `~/.claude/settings.json`:

```json
{
  "mcp": {
    "projectServers": {
      "autoApprove": false
    },
    "globalServers": {
      "autoApprove": false
    }
  }
}
```

With this configuration, any MCP server encountered in a project config — including servers you have approved before in a different project — requires an explicit approval decision before Claude Code starts it. This converts a silent execution into a visible prompt. The prompt names the server, the command, and the arguments; inspect all three before approving.

### 4. Protect `~/.claude/settings.json` from modification

Apply the Linux immutable flag to prevent any process running as your user from modifying the global MCP config:

```bash
chattr +i ~/.claude/settings.json
```

After this, any attempt by another process to write to the file — a postinstall script, a malicious package, a supply chain payload — receives `Operation not permitted`, regardless of whether the process runs as your user. The immutable flag is enforced by the filesystem layer, not the permission bits, so user-level processes cannot remove it.

To add a new MCP server to the global config intentionally:

```bash
chattr -i ~/.claude/settings.json
# edit the file
chattr +i ~/.claude/settings.json
```

Establish this as an explicit workflow step. If you use a dotfiles manager or any tool that regenerates `~/.claude/settings.json` automatically, configure it to remove the immutable flag before writing and re-apply it after. Automate the re-application so it is not accidentally skipped.

Verify the flag is set after each intentional modification:

```bash
lsattr ~/.claude/settings.json
```

The output should show `----i-----------` in the attribute field.

### 5. Restrict network egress for MCP server processes

MCP servers that do not need network access should not have it. A malicious MCP server's primary exit path is network exfiltration: writing captured data to an attacker-controlled endpoint. Confining the server in a network namespace eliminates that path.

Run an MCP server in an isolated network namespace using `unshare`:

```bash
unshare --net claude
```

This starts Claude Code (and thus any MCP servers it spawns) inside a new network namespace with no interfaces except loopback. Network connections from MCP servers to external hosts fail. The Claude Code client itself can still communicate through the namespace boundary if you configure the appropriate interface; the goal is specifically to isolate MCP server child processes.

For a more targeted approach that isolates only the MCP server child process without affecting Claude Code itself, wrap the server command in a namespace-isolated launcher. Add this as a wrapper script alongside the real MCP server binary:

```bash
#!/usr/bin/env bash
exec unshare --net -- /usr/local/bin/my-real-mcp-server "$@"
```

Then reference the wrapper script in the MCP server definition instead of the binary directly. The server loses network access; legitimate local IPC (stdio, Unix socket) continues to work.

Apply this selectively. MCP servers that legitimately need internet access — web search integrations, API connectors — cannot function under network isolation. Isolate local-only tools: filesystem servers, local database servers, code analysis tools.

### 6. Apply least-privilege tool grants per MCP server

Review which tools each MCP server is granted access to invoke. A file-reading MCP server does not need shell execution tools. A search MCP server does not need write access. Limit each server to the tool categories its function requires.

In `~/.claude/settings.json`, scope tool grants per server:

```json
{
  "mcpServers": {
    "filesystem-reader": {
      "command": "/usr/local/bin/mcp-fs-server",
      "args": ["--root", "/home/user/projects"],
      "toolGrants": {
        "allowedCategories": ["read"],
        "deniedTools": ["write_file", "delete_file", "shell_exec", "run_command"]
      }
    },
    "code-analysis": {
      "command": "/usr/local/bin/mcp-analysis-server",
      "toolGrants": {
        "allowedCategories": ["read", "analyze"],
        "deniedTools": ["shell_exec", "run_command", "write_file"]
      }
    }
  }
}
```

The principle: define the minimum set of tools each server needs, deny everything else explicitly. When a new tool is added to the MCP server, the grant does not expand automatically — the administrator must make a deliberate decision to add it.

For servers shared across a team, codify the tool grant policy in a repository alongside the server definition. Treat changes to tool grants as security-relevant changes requiring review.

## Expected Behaviour After Hardening

After applying the CVE-2026-21852 patch: opening a project directory that contains a `.claude/settings.json` with MCP server definitions produces a confirmation dialog listing each server by name and command. The developer must explicitly approve each server before Claude Code starts it. A malicious repository cannot execute code silently.

After setting `autoApprove: false` in the global config: previously approved project MCP servers require re-approval when encountered in a new project context. There is no silent inheritance of prior approvals.

After applying `chattr +i` to `~/.claude/settings.json`: a supply chain payload that attempts to write to the file logs a filesystem error (`Operation not permitted`) and fails. The global MCP configuration remains as the developer left it.

After network namespace isolation: a malicious MCP server that attempts to establish a connection to an attacker-controlled host (`curl`, raw socket, DNS lookup) receives connection errors or `Network is unreachable`. Data the server captures does not leave the machine via network.

After scoping tool grants: a malicious MCP server registered with the `filesystem-reader` identity cannot invoke `shell_exec` even if it constructs a valid tool-call request. The grant check denies the call before dispatch.

## Trade-offs and Operational Considerations

`chattr +i` on the global settings file creates friction for any legitimate workflow that updates Claude Code settings programmatically — dotfile managers, provisioning scripts, configuration management tools. Establish an explicit documented procedure for the remove/edit/re-apply cycle, and consider adding the re-application step to your shell profile or as a cron job that verifies the flag is set:

```bash
test -e ~/.claude/settings.json && lsattr ~/.claude/settings.json | grep -q '\-i\-' || \
  echo "WARNING: ~/.claude/settings.json immutable flag is not set"
```

Network isolation for MCP servers breaks servers that legitimately need internet access: web search tools, API integrators, remote database connectors. The isolation must be applied selectively per server, not globally. Maintain a documented list of which servers are isolated and which are allowed network access, and review that list when adding new servers.

Project MCP server confirmation adds friction for teams that intentionally use project-level MCP configs to share tooling — a common pattern for monorepos where a shared `mcp-analysis` server is defined in the project and every developer uses it. In this case, the confirmation is still correct security behaviour: developers should read and understand what they are approving. Document the expected MCP servers for your projects so developers know what is legitimate and what is not when the prompt appears.

Scoping tool grants requires upfront knowledge of which tools each server needs. If a server's legitimate tool requirements are not well understood, the grant will be either too narrow (blocking legitimate operations) or effectively unbounded (granting everything). Audit existing MCP servers by running them in a logging mode that records every tool call they make before setting restrictive grants.

## Failure Modes

**Patch applied but user clicks "Allow" on every MCP server confirmation without reading it.** The confirmation becomes a click-through. This is the most likely failure mode in practice. Mitigate by training developers to read the server command before approving — specifically, to verify the command resolves to a file inside the project directory and to open that file and read it if unfamiliar. Consider adding a pre-clone check step that inspects `.claude/` directories before developers open unfamiliar repositories.

**`chattr +i` applied to `~/.claude/settings.json` but not to `~/.claude/` directory.** An attacker payload that cannot write to the file can instead rename the directory and create a new one with a fresh `settings.json`. Apply the immutable flag to the directory as well:

```bash
chattr +i ~/.claude/
chattr +i ~/.claude/settings.json
```

Be aware that making `~/.claude/` itself immutable may prevent Claude Code from creating other files in that directory (session state, cache, logs). Test this before applying; selectively immuting `settings.json` while leaving the directory writable is often the better trade-off, combined with monitoring the directory for unexpected new files.

**Network isolation applied to local MCP servers but not to those sourced from remote registries or auto-discovered.** If Claude Code fetches and registers MCP servers from a remote registry and those servers are not covered by the network isolation wrapper, they run with unrestricted network access. Verify that the network isolation wrapper is referenced in the server definition for every server that should be isolated, not just a subset.

**Supply chain attack uses a package that runs before `chattr +i` is applied.** If the immutable flag is not applied at machine provisioning time — only applied later — there is a window during initial setup where the config file is writable. Apply the immutable flag as part of the provisioning step immediately after the initial Claude Code configuration is written. On a fresh machine, this means: install Claude Code, configure `~/.claude/settings.json`, apply `chattr +i`, then install other development dependencies.

## Related Articles

- [MCP Server Security](/articles/ai-landscape/mcp-server-security/)
- [MCP Authentication](/articles/ai-landscape/mcp-authentication/)
- [MCP Tool Permission Patterns](/articles/ai-landscape/mcp-tool-permission-patterns/)
- [AI Agent Kill Switches](/articles/ai-landscape/ai-agent-kill-switches/)
- [LLM Supply Chain Incident Response](/articles/ai-landscape/llm-supply-chain-incident-response/)
