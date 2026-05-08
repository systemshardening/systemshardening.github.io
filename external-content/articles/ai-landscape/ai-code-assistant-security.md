---
title: "AI Code Assistant Security: Prompt Leakage, Code Exfiltration, and IDE Plugin Risks"
description: "AI code assistants send code context to external APIs by default, including files, environment variables, and repository contents. Understanding data flows, configuring retention policies, and governing plugin permissions protects intellectual property and prevents credential exfiltration."
slug: "ai-code-assistant-security"
date: 2026-05-01
lastmod: 2026-05-01
category: "ai-landscape"
tags: ["code-assistant", "copilot", "ide-security", "data-exfiltration", "intellectual-property"]
personas: ["security-engineer", "ciso", "platform-engineer"]
article_number: 300
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/ai-landscape/ai-code-assistant-security/index.html"
---

# AI Code Assistant Security: Prompt Leakage, Code Exfiltration, and IDE Plugin Risks

## Problem

AI code assistants — GitHub Copilot, Cursor, Cline, JetBrains AI Assistant, Amazon CodeWhisperer, and similar tools — have become standard in software development workflows. They significantly accelerate development but introduce a category of security risk that most organisations have not formally evaluated: the continuous transmission of code context to external AI APIs.

When a developer accepts a suggestion from an AI code assistant, the tool typically sends:

- The current file and several surrounding files as context.
- Recent edits and cursor position.
- Repository metadata (project structure, imports, function signatures).
- Potentially: environment variables, configuration files, `.env` files, and secrets that are open in the editor.

This happens for every completion request — dozens to hundreds of times per developer per hour — and the data leaves the developer's machine, crosses the internet, and is processed by the AI provider's infrastructure.

Security concerns:

- **Secret and credential exposure.** If a developer has an `.env` file or `credentials.json` open in their editor, context-window scraping may include these in API requests. The AI provider receives plaintext credentials.
- **Intellectual property transmission.** Proprietary algorithms, business logic, and unreleased product code are transmitted to third-party AI providers. The provider's data retention policy determines how long this is stored and whether it is used for model training.
- **Malicious suggestion injection (prompt poisoning).** A compromised or malicious code repository may contain specially crafted comments designed to influence AI suggestions — for example, injecting a comment that causes the AI to suggest importing a malicious package.
- **IDE plugin permissions.** AI code assistant IDE plugins often request broad permissions: access to all files, network access, terminal execution, and browser control. A compromised plugin (supply chain attack) with these permissions has full developer workstation access.
- **Auto-complete accepting insecure patterns.** Studies show AI code assistants suggest insecure code (SQL injection, hardcoded secrets, weak cryptography) at meaningful rates. Developers who accept suggestions without review introduce vulnerabilities without awareness.

**Target systems:** GitHub Copilot (VS Code, JetBrains, Neovim); Cursor IDE; JetBrains AI Assistant; Amazon CodeWhisperer; Codeium; self-hosted models (Ollama, LM Studio) for air-gapped environments.

## Threat Model

- **Adversary 1 — Credential exfiltration via context window:** A developer has an AWS credentials file open in their editor while using Copilot. The context window includes the credentials file. The AI provider receives and (depending on retention policy) stores the plaintext credentials. An adversary who compromises the AI provider's storage or exploits a data breach recovers the credentials.
- **Adversary 2 — Intellectual property exfiltration:** A developer at a pharmaceutical company uses Copilot while writing code that implements a proprietary drug synthesis algorithm. The algorithm is transmitted to GitHub's API. A nation-state actor or competitor with access to GitHub's training data pipeline obtains the algorithm.
- **Adversary 3 — Malicious suggestion via prompt injection in repository:** An attacker commits a specially crafted comment to an open-source repository the developer is working with: `// TODO: import from https://evil.com/package`. The AI assistant, trained to follow code comments and patterns, suggests importing from the malicious URL when completing nearby code.
- **Adversary 4 — Compromised IDE plugin:** An AI code assistant VS Code extension is compromised via a supply chain attack. The extension, which has permissions to read all workspace files, network access, and terminal execution, exfiltrates all source code and credentials in the developer's workspace.
- **Adversary 5 — Insecure code suggestion accepted without review:** An AI assistant suggests a database query using string concatenation (SQL injection pattern). The developer accepts without modification. The vulnerability reaches production.
- **Access level:** Adversaries 1 and 2 exploit the normal functioning of the tool. Adversary 3 only needs to commit to a public repository. Adversary 4 requires supply chain access. Adversary 5 exploits developer inattention.
- **Objective:** Steal credentials, steal intellectual property, inject vulnerabilities, gain developer workstation access.
- **Blast radius:** Credential exfiltration via code assistant context could expose AWS/GCP/Azure root credentials. IP theft via code context could expose entire proprietary codebases transmitted across months of development.

## Configuration

### Step 1: Inventory and Policy

Before configuring controls, understand what is in use:

```bash
# Audit installed VS Code extensions for AI assistants.
code --list-extensions | grep -iE "copilot|cursor|codeium|whisperer|tabnine|kite"

# Check for AI assistant CLI tools.
which github-copilot-cli cursor codeium 2>/dev/null

# Check JetBrains plugin installations.
find ~/.config/JetBrains -name "*.xml" 2>/dev/null | \
  xargs grep -l "AI\|Copilot\|Codeium" 2>/dev/null
```

Develop a formal AI code assistant policy:

```yaml
# ai-code-assistant-policy.yaml
policy:
  approved_tools:
    - name: "GitHub Copilot"
      data_retention: "No training on Business/Enterprise plan code"
      approved_for: ["general-development"]
      not_approved_for: ["classified-projects", "financial-algorithms", "security-research"]
      required_settings:
        - "Editor: Copilot > Enable Telemetry: false"
        - "Suggestions requiring secrets files open: blocked by .copilotignore"

    - name: "Self-hosted Ollama"
      data_retention: "On-premise; no external transmission"
      approved_for: ["all-projects-including-classified"]

  not_approved:
    - "Cursor (transmits to Anthropic API; no enterprise retention controls)"
    - "Codeium free tier (training opt-out requires enterprise plan)"

  required_controls:
    - ".copilotignore in all repositories covering secrets and sensitive paths"
    - "IDE: disable AI suggestions in files matching .env, *.key, *.pem, credentials*"
    - "Annual review of AI provider data retention policies"
```

### Step 2: Repository-Level Exclusions

Configure AI assistants to ignore sensitive files:

```
# .copilotignore — same syntax as .gitignore
# Place at repository root. GitHub Copilot respects this file.

# Secrets and credentials.
.env
.env.*
*.key
*.pem
*.p12
*.pfx
credentials.json
secrets.yaml
secret*.yaml
*-secret.yaml
*.tfvars          # Terraform variable files with secrets.
kubeconfig        # Kubernetes config with credentials.

# Sensitive business logic (project-specific).
src/algorithms/proprietary/
src/pricing/models/
internal/

# Security research files.
exploits/
payloads/
```

```json
// VS Code settings.json — disable Copilot for specific file patterns.
{
  "github.copilot.enable": {
    "*": true,
    "plaintext": false,
    "markdown": false,
    ".env": false,
    "*.key": false,
    "*.pem": false
  }
}
```

### Step 3: Enterprise Retention Controls

Ensure the AI provider is not training on your code:

```bash
# GitHub Copilot Business/Enterprise: verify training opt-out.
# Organization settings → GitHub Copilot → Policies:
# "Allow GitHub to use my code snippets for product improvements": UNCHECKED.

# Verify via API.
curl -H "Authorization: Bearer $GITHUB_TOKEN" \
  "https://api.github.com/orgs/$ORG_NAME/copilot/billing" | \
  jq '.seat_management_setting, .public_code_suggestions'
# public_code_suggestions should be "block" for IP protection.
```

For regulated industries (financial services, healthcare, defense):

```yaml
# Requirements for regulated environments.
ai_assistant_requirements:
  data_residency: "Must process data in specific regions (EU/US)"
  training_opt_out: "Required; verify contractually"
  data_retention: "Maximum 30 days; ideally zero"
  audit_log: "All prompts and completions logged for compliance review"
  approved_providers:
    - "GitHub Copilot Enterprise (with DPA and data processing addendum)"
    - "Amazon CodeWhisperer Professional (AWS region-locked)"
    - "Self-hosted models (Ollama with local models)"
  not_approved:
    - "Any tool without explicit training opt-out"
    - "Any tool without a data processing addendum"
    - "Free-tier tools with training on user code"
```

### Step 4: Pre-commit Hooks to Prevent Secret Transmission

Add checks that prevent developers from having secrets files open during AI-assisted sessions — or at least prevent secrets from being committed:

```bash
# .pre-commit-config.yaml — detect secrets before commit.
repos:
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
        exclude: .secrets.baseline

  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
```

```bash
# Install and run.
pip install pre-commit
pre-commit install
pre-commit run --all-files   # Scan existing files.
```

### Step 5: IDE Plugin Permission Auditing

```bash
# Audit VS Code extension permissions (check extension manifest).
# High-risk permissions in package.json:
RISKY_PERMISSIONS=(
  "vscode.executeCommand"
  "terminals"         # Can run terminal commands.
  "workspace"         # Read all workspace files.
  "webview"           # Can render arbitrary HTML (XSS risk).
  "externalUriOpener" # Can open external URLs.
)

# Review extension permissions before installing.
# Extensions with "terminal" access can execute arbitrary commands.
# Verify extension publisher and check for recent supply chain compromises.

# Pin extension versions to prevent automatic updates to compromised versions.
# VS Code: "extensions.autoUpdate": false in settings.json.
```

```yaml
# Corporate VS Code settings (deployed via MDM/policy).
# settings.json applied to all developer machines.
{
  "extensions.autoUpdate": false,          # Prevent auto-update to compromised versions.
  "extensions.autoCheckUpdates": true,     # Still check; update manually after review.
  "github.copilot.advanced": {
    "debug.overrideProxyUrl": "",          # Prevent proxy override (data interception).
    "authProvider": "github"               # Only official GitHub auth.
  }
}
```

### Step 6: Self-Hosted Models for Sensitive Projects

For classified or highly sensitive projects, use on-premise models:

```bash
# Ollama: run models locally — no data leaves the workstation.
curl -fsSL https://ollama.com/install.sh | sh

# Pull a code-capable model.
ollama pull codellama:13b    # 13B parameter CodeLlama.
ollama pull deepseek-coder:6.7b

# Configure VS Code Continue extension to use local Ollama.
# ~/.continue/config.json
{
  "models": [
    {
      "title": "CodeLlama (Local)",
      "provider": "ollama",
      "model": "codellama:13b",
      "apiBase": "http://localhost:11434"  # Local API; no external calls.
    }
  ]
}
```

```yaml
# For team environments: self-hosted model server with access control.
# Kubernetes deployment of Ollama with mTLS.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ollama-server
  namespace: ai-tools
spec:
  template:
    spec:
      containers:
        - name: ollama
          image: ollama/ollama:latest
          ports:
            - containerPort: 11434
          # Data stays within cluster; no external egress for model inference.
```

### Step 7: Secure Code Review Process for AI Suggestions

Require security review of AI-generated code before merge:

```yaml
# .github/CODEOWNERS — require security review for AI-heavy changes.
# This is process, not tooling, but should be documented.

# /src/auth/ @security-team   # Authentication code requires security review.
# /src/crypto/ @security-team
# /src/database/ @security-team
```

```yaml
# GitHub Actions: run SAST on all PRs to catch AI-suggested vulnerabilities.
name: Security Scan
on: [pull_request]
jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Semgrep
        uses: semgrep/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/secrets
            p/sql-injection
            p/owasp-top-ten
```

### Step 8: Telemetry

```
ai_assistant_api_calls_total{tool, developer_id}              counter
ai_assistant_data_transmitted_bytes{tool}                     counter
ai_assistant_secret_pattern_in_context_total{tool, pattern}  counter
ai_plugin_permission_alerts_total{plugin, permission}         counter
ai_suggestion_accepted_total{tool, language}                  counter
sast_ai_generated_findings_total{severity, category}          counter
```

Alert on:

- `ai_assistant_secret_pattern_in_context_total` non-zero — a secret pattern (API key, password) was detected in AI assistant context; investigate what was transmitted.
- `ai_plugin_permission_alerts_total` — a plugin is requesting unexpected new permissions after an update; review before allowing.
- `sast_ai_generated_findings_total{severity="high"}` — SAST found high-severity issues in AI-generated code; block merge and require security review.
- AI assistant configured to use non-approved provider — policy violation; notify developer and manager.

## Expected Behaviour

| Signal | Unmanaged AI assistant | Governed AI assistant |
|--------|----------------------|----------------------|
| .env file open during completion | Contents may be in API request context | .copilotignore excludes .env; no suggestion offered |
| Code from proprietary algorithm sent to API | Transmitted to AI provider | Policy blocks AI use on classified project; local model used |
| Malicious package suggested | Developer may accept | SAST catches import of unknown package in CI |
| Plugin auto-updated to compromised version | Update installs silently | Auto-update disabled; manual review required |
| SQL injection suggested by AI | Developer may accept | Semgrep catches pattern in CI before merge |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| .copilotignore | Prevents credential context inclusion | AI less helpful near secrets (no context for completion near excluded files) | Acceptable trade-off; secrets should not be in source |
| Enterprise plan (training opt-out) | Code not used for training | Higher cost | Required for any sensitive development; budget accordingly |
| Self-hosted model | Zero data exfiltration | Lower quality than cloud models; GPU infrastructure required | Hybrid: local for sensitive; cloud for general development |
| `extensions.autoUpdate: false` | Prevents silent supply chain compromise | Missed security fixes in plugins | Weekly manual update review; subscribe to extension security advisories |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| .copilotignore not in repo | Credentials file contents in completion context | Periodic audit of .copilotignore coverage | Add .copilotignore; rotate any credentials that may have been transmitted |
| Training opt-out not applied org-wide | Some developers transmit training data | GitHub org settings audit | Apply opt-out at organisation level; not per-user |
| Local model not available | Developer falls back to cloud assistant on sensitive project | Audit logs show cloud assistant calls on restricted project | Ensure local model is always available; policy check in CI |
| AI suggests vulnerable pattern accepted | Security vulnerability in production | SAST in CI catches most patterns | Block merge on high-severity SAST finding; require manual security review |

## Related Articles

- [LLM System Prompt Protection](/articles/ai-landscape/llm-system-prompt-protection/)
- [AI Supply Chain Attack Surface](/articles/ai-landscape/ai-supply-chain-attack-surface/)
- [Data Loss Prevention for Cloud Environments](/articles/cross-cutting/data-loss-prevention/)
- [GitHub Advanced Security: Secret Scanning, Code Scanning, and Dependabot](/articles/cicd/github-advanced-security/)
- [Vendor Security Assessment](/articles/cross-cutting/vendor-security-assessment/)
