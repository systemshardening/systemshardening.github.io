---
title: "AI Framework Security Disclosure: Reporting Vulnerabilities in LLM Servers, ML Frameworks, and Model Weights"
description: "vLLM, Ollama, LangChain, and Hugging Face Transformers are accumulating CVEs rapidly — but the AI security disclosure ecosystem is immature. Model weights can contain embedded exploits, inference servers have unauthenticated APIs by default, and LLM framework vulnerabilities often involve novel attack classes with no established CVSS scoring guidance. This guide covers the AI security disclosure landscape, how to report AI infrastructure vulnerabilities, and how to track and respond to them."
slug: ai-framework-security-disclosure
date: 2026-05-08
lastmod: 2026-05-08
category: ai-landscape
tags:
  - ai-security
  - responsible-disclosure
  - vllm
  - langchain
  - open-source-security
personas:
  - security-engineer
  - ml-engineer
article_number: 654
difficulty: Intermediate
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/ai-landscape/ai-framework-security-disclosure/
---

# AI Framework Security Disclosure: Reporting Vulnerabilities in LLM Servers, ML Frameworks, and Model Weights

## Problem

The AI security disclosure ecosystem is roughly where the web application security ecosystem was in 2003: the vulnerabilities are real, the impact can be severe, but the frameworks for finding, reporting, scoring, and patching them haven't caught up to the threat.

vLLM shipped its first public release in June 2023. Within 18 months it had accumulated multiple CVEs, including remote code execution issues in its multimodal input processing pipeline. Ollama reached widespread adoption in 2024 with an unauthenticated API bound to `0.0.0.0:11434` by default — a design choice rather than a bug, which means it doesn't fit neatly into any CVE. LangChain's rapid iteration velocity means its dependency tree changes weekly, and SSRF vulnerabilities via agent tool use have appeared repeatedly. Hugging Face Transformers has accumulated advisories around pickle deserialization in model files since before most organisations knew they were loading pickle files at all.

None of these frameworks have mature security processes by the standards applied to, say, OpenSSL or the Linux kernel. Many lack a SECURITY.md file altogether. Some have security policies that redirect researchers to open GitHub issues — the opposite of responsible disclosure. Volunteer maintainers working at startup speed rarely have bandwidth for coordinated disclosure processes, 90-day embargo timelines, or CVSS scoring of novel vulnerability classes that no one has seen before.

The problem is compounded by the novelty of AI-specific vulnerability classes. Prompt injection, model weight poisoning, and SSRF via agentic tool use don't fit cleanly into existing CVE taxonomy. The Common Vulnerability Scoring System was designed around traditional software flaws: network-reachable services, authentication bypasses, privilege escalation. A prompt injection vulnerability that enables data exfiltration from a multi-tenant RAG system doesn't have a clean CVSS attack vector. Is it network-adjacent? Local? Does confidentiality impact apply if the exfiltrated data is probabilistic rather than deterministic? These questions are unresolved, and different scorers give wildly different CVSS values for the same AI vulnerability.

Meanwhile, the speed of release means CVEs accumulate faster than most organisations can track them. A team running vLLM in production that updates on a quarterly patching cycle is almost certainly running software with known vulnerabilities. The same is true for LangChain, which has had months where minor version releases shipped multiple times per week.

Model weight security adds a supply chain dimension with no traditional analogue. A `.pkl` file containing model weights is executable Python. When a user runs `torch.load("model.pkl")`, Python's pickle module deserialises arbitrary objects — including objects whose `__reduce__` methods execute shell commands. A malicious model uploaded to Hugging Face Hub can achieve remote code execution on any machine that loads it, with no CVE, no package version, and no obvious indicator of compromise. The attack surface is the entire model distribution ecosystem, and the mitigations require changes to both producer and consumer behaviour.

## Threat Model

**Ollama's unauthenticated API** is the most immediately exposed surface in the AI ecosystem. Ollama binds to `0.0.0.0:11434` by default on Linux systems, making the API reachable from any network interface. Any client with network access can call `/api/generate` to trigger generation, `/api/pull` to pull new models (consuming storage and bandwidth), and `/api/delete` to remove models from the server. There is no authentication mechanism in Ollama's core — this is an explicit design decision to prioritise ease of use. Organisations running Ollama on developer workstations connected to corporate networks, or on cloud VMs without restrictive security groups, are exposing a fully functional model serving API to the internal network or the internet.

**vLLM RCE via multimodal input processing** reflects a pattern common to complex software: a high-level framework builds on lower-level libraries for format parsing, and vulnerabilities in those libraries become exploitable through the framework's API. vLLM's multimodal capabilities pass image data to underlying libraries (Pillow, OpenCV, or model-specific processors) for preprocessing. Image parsing is a historically vulnerability-dense surface — heap overflows, out-of-bounds reads, and integer overflows in JPEG, PNG, and WEBP decoders have produced exploitable conditions in every major library. When vLLM exposes a multimodal completion endpoint that accepts user-supplied images, vulnerabilities in the underlying parsing stack become reachable from the network.

**LangChain SSRF via tool use** is a structural consequence of how agent frameworks work. An agent equipped with an HTTP request tool — `requests.get`, a web scraping tool, or a webhook notifier — will make HTTP requests to URLs derived from its context. If that context includes user-supplied content (a document, a chat message, a retrieved chunk), and the model resolves that content into a URL argument for the tool, an attacker can craft inputs that cause the agent to make HTTP requests to internal services. In cloud environments, this means requests to the instance metadata service at `169.254.169.254`, returning IAM credentials. LangChain's tool execution model provides no built-in URL allowlisting or SSRF protection.

**Hugging Face model weight with embedded pickle exploit** is the supply chain attack with the lowest barrier to entry. An attacker uploads a model to Hugging Face Hub — it can be a legitimate, functioning model — with a malicious serialisation payload in a `.bin` or `.pkl` file. Any user who downloads and loads that file executes the payload. The attack requires no vulnerability in Hugging Face's platform code; it exploits the design of Python's pickle protocol. The attacker needs only a Hub account to publish the malicious model.

## Configuration / Implementation

### The AI CVE Landscape

The AI framework CVE landscape has developed rapidly since 2023. Key examples from vLLM include CVE-2024-42368 (RCE via malformed multimodal request inputs hitting vulnerable image processing), and several advisories around the OpenAI-compatible API layer's handling of untrusted request parameters. Ollama's exposure is less about traditional CVEs and more about the documented default of binding its API without authentication — a posture that has been described in advisories and security research even though it doesn't map to a standard CVE format. LangChain has accumulated CVEs around SSRF (CVE-2023-38896 and related issues) and arbitrary code execution via the Python REPL tool (CVE-2023-36188). Hugging Face Transformers carries persistent advisories around `torch.load` with `pickle` and the risks of loading arbitrary checkpoint files.

**Searching osv.dev for AI framework coverage** gives a practical starting point for understanding the CVE history of any AI package. The Open Source Vulnerabilities database aggregates advisories from PyPI, GitHub, and other sources. Run:

```bash
# Query osv.dev API for a specific package
curl "https://api.osv.dev/v1/query" \
  -H "Content-Type: application/json" \
  -d '{"package": {"name": "vllm", "ecosystem": "PyPI"}}'

curl "https://api.osv.dev/v1/query" \
  -H "Content-Type: application/json" \
  -d '{"package": {"name": "langchain", "ecosystem": "PyPI"}}'

curl "https://api.osv.dev/v1/query" \
  -H "Content-Type: application/json" \
  -d '{"package": {"name": "transformers", "ecosystem": "PyPI"}}'
```

The results reveal both the volume of advisories and their severity distribution. For LangChain and Transformers, the list is longer than most security teams expect.

**Why CVSS scoring doesn't cleanly map to AI vulnerabilities** is a practical problem for anyone trying to communicate severity to a security operations team. The CVSS 3.1 framework has no attack vector for "model input" — the closest options are Network (for API-delivered attacks) or Local (for model file loading). Prompt injection doesn't fit the "user interaction required" field well, because interaction is a property of the LLM deployment architecture, not a user choice. Model poisoning has no analogue in confidentiality/integrity/availability scoring because the "impact" is probabilistic model behaviour change rather than data disclosure or service disruption. Several AI security researchers have proposed AI-specific scoring frameworks, but none have achieved consensus adoption as of 2025.

### Reporting Vulnerabilities in AI Frameworks

**vLLM security disclosure** uses GitHub's private security advisory mechanism. Navigate to `github.com/vllm-project/vllm`, click "Security", and use "Report a vulnerability" to open a private advisory visible only to maintainers. vLLM's security team has improved its response cadence significantly since 2024, with a stated goal of acknowledging reports within 7 days. When filing a vLLM report, include:

- The vLLM version and Python version
- Whether multimodal processing, the OpenAI API compatibility layer, or a specific backend (CUDA, ROCm, CPU) is involved
- A minimal reproduction case that doesn't require a full model weight — most vLLM vulnerabilities can be reproduced with a tiny test model or mocked inputs
- Network accessibility of the test environment (was the API exposed externally?)

vLLM's CVE pattern clusters around two areas: multimodal input processing (image and video preprocessing pipelines) and the API compatibility layer's trust model for request parameters. If your report touches either area, flag it explicitly.

**Ollama security disclosure** also uses GitHub private advisories at `github.com/ollama/ollama`. The unauthenticated API is the dominant security concern with Ollama, and it requires careful framing in any disclosure. The lack of authentication is not a bug — it's a documented design choice optimised for local development use. When documenting an Ollama security concern:

- Distinguish between a design-choice exposure (unauthenticated API accessible from the network) and a code-level vulnerability (a bug in the API's request handling or model loading)
- Design-choice exposures are better reported as security advisories with configuration guidance, or as documentation issues, rather than CVEs
- Code-level vulnerabilities in Ollama's model pulling, API parsing, or GGUF file loading should be reported as private advisories

The community discussion around Ollama's authentication posture has produced a well-documented recommendation: bind to `127.0.0.1` rather than `0.0.0.0`, and place an authenticated reverse proxy (nginx with `auth_basic`, or Caddy with forward auth) in front of any network-accessible Ollama deployment.

**LangChain and LangGraph** have a dedicated security contact at `security@langchain.dev`. LangChain's vulnerability patterns break into three categories:

1. **SSRF via tool execution**: any tool that makes HTTP requests without URL validation is a SSRF vector when agent inputs include user-controlled content. Reports should include the specific tool involved, the LangChain version, and a demonstration of the internal service reached (the metadata service test case at `169.254.169.254/latest/meta-data/` is standard).

2. **Prompt injection enabling tool misuse**: when an LLM agent can be manipulated via injected instructions to call tools with attacker-specified arguments, the resulting capability (arbitrary HTTP requests, filesystem access, shell execution) defines the severity. Reports should clearly separate the injection mechanism from the downstream tool capability.

3. **Arbitrary code execution via Python REPL tools**: LangChain's `PythonREPLTool` executes arbitrary Python code. This is by design — but when combined with prompt injection or untrusted input, it becomes an RCE primitive. Reports in this category often generate debate about whether the tool is being used as documented.

LangChain's line between "feature" and "vulnerability" is blurry for agent tool use. The framework is designed to give LLMs access to powerful capabilities. When those capabilities are misused through adversarial inputs, the question of whether the framework is "vulnerable" or the deployment is "misconfigured" doesn't have a universal answer. In practice, the LangChain security team has been receptive to reports that demonstrate concrete, reproducible harm — data exfiltration, credential access, or persistent system modification — even when the underlying mechanism is documented tool behaviour.

**Hugging Face Transformers** security reporting goes to `security@huggingface.co`. Transformers security issues divide between framework-level vulnerabilities (bugs in the library code itself) and ecosystem-level issues (malicious models on the Hub).

For framework-level issues: include the Transformers version, the specific model architecture or tokenizer involved, and whether the issue is in model loading (`from_pretrained`), tokenizer behaviour, or the model's forward pass.

For malicious models on the Hub: Hugging Face provides a "Report this model" button on each model page, which routes to a PSIRT (Product Security Incident Response Team) triage process. When reporting a malicious model:

- Note the repository name and version (commit hash)
- Include the specific file containing the malicious payload (usually a `.bin`, `.pkl`, or `model.safetensors`-adjacent file)
- If you can, include the pickle opcode sequence or the shell command embedded in the payload — this accelerates triage
- Do not publicly disclose the model repository name until Hugging Face has removed or quarantined it; doing so amplifies the attack surface

The core mitigation for model weight safety is the safetensors format. Safetensors is a simple serialisation format that stores only tensor data — no Python objects, no executable code. When loading models:

```python
# Unsafe: arbitrary code execution possible
model = torch.load("model.bin")  # pickle-based, dangerous

# Safe: no code execution
from safetensors.torch import load_file
tensors = load_file("model.safetensors")
```

The `transformers` library added `trust_remote_code=False` as a default in recent versions, but model loading still defaults to pickle-based `.bin` files when safetensors equivalents aren't available. **ModelScan** (`pip install modelscan`) scans model files for malicious pickle payloads before loading:

```bash
modelscan -p ./model_directory/
# Reports any pickle opcodes that could execute code
```

### Prompt Injection as a Disclosure Class

The question of whether prompt injection constitutes a CVE has been debated extensively. The current emerging consensus: prompt injection is CVE-worthy when it enables concrete, demonstrable harm in a specific deployment configuration.

A prompt injection that causes a chatbot to produce rude responses is a product quality issue. A prompt injection that causes an agent with tool access to exfiltrate data from a corporate knowledge base to an external webhook is a security vulnerability. The distinction is the concrete harm, not the injection mechanism itself.

To write a prompt injection vulnerability report that will be taken seriously:

1. **Identify the attack surface**: which input field or data source contains the injected content? (User message, retrieved document, tool output, memory store?)
2. **Document the injection payload**: the exact string that triggers the behaviour
3. **Demonstrate concrete harm**: what does the injected payload cause the agent to do? Be specific — "the agent calls the `send_email` tool with the content of the system prompt as the body, sending it to the attacker's address"
4. **Specify the affected configuration**: which tools are equipped, what trust level does the agent operate at, what data sources are in scope?
5. **Distinguish from intended behaviour**: if the framework documents the attack surface (e.g., "tool inputs are derived from model outputs"), explain why this specific combination constitutes a vulnerability rather than a misconfiguration

CVSS scoring for prompt injection: use Attack Vector: Network (if delivered via API), Attack Complexity: Low (if the injection is reliable), Privileges Required: None (no account needed), User Interaction: None (if the agent processes inputs automatically), and set Confidentiality/Integrity/Availability impact based on what the agent can access and modify.

### Responding as a Consumer

**Tracking AI framework CVEs** requires integrating AI packages into your existing vulnerability management tooling. The most direct path:

```bash
# Install osv-scanner
go install github.com/google/osv-scanner/cmd/osv-scanner@latest

# Scan your Python environment's lockfile
osv-scanner --lockfile requirements.txt

# Or scan the full installed environment
pip freeze > /tmp/current-requirements.txt
osv-scanner --lockfile /tmp/current-requirements.txt
```

Enable Dependabot for Python repositories that include `vllm`, `langchain`, `transformers`, or `ollama` in `requirements.txt` or `pyproject.toml`. In `.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: pip
    directory: "/"
    schedule:
      interval: daily
    open-pull-requests-limit: 10
```

AI framework dependencies change frequently enough that weekly scanning is insufficient. Daily Dependabot checks, combined with weekly `osv-scanner` runs against production lockfiles, provides reasonable coverage.

**Emergency mitigation for vLLM CVEs**: when a critical vLLM CVE is published and a patched version isn't immediately deployable, the fastest mitigations are:

- Block the vLLM API port at the firewall or security group level; if only internal services need access, restrict to specific source IPs or CIDRs
- Disable multimodal endpoints if only text completion is needed (`--disable-frontend-multiprocessing` and removing multimodal model configurations)
- Place an authenticating proxy (nginx with `auth_request`, Envoy with JWT validation) in front of the API immediately

**Emergency mitigation for Ollama exposure**: Ollama's unauthenticated API can be isolated in under five minutes:

```bash
# Immediately block external access with iptables
sudo iptables -I INPUT -p tcp --dport 11434 ! -s 127.0.0.1 -j DROP

# Or with ufw
sudo ufw deny in on any to any port 11434
sudo ufw allow in from 127.0.0.1 to any port 11434

# Longer term: configure Ollama to bind only to localhost
# In /etc/systemd/system/ollama.service.d/override.conf:
# [Service]
# Environment="OLLAMA_HOST=127.0.0.1"
```

## Expected Behaviour

The following table maps AI vulnerability classes to reporting channels, CVSS applicability, and the consumer response:

| Vulnerability Class | Reporting Channel | CVSS Applicable? | Consumer Response |
|---|---|---|---|
| vLLM multimodal RCE | GitHub private advisory (vllm-project/vllm) | Yes — standard software CVE | Update immediately; disable multimodal if unpatched |
| Ollama unauthenticated API | GitHub advisory or documentation issue | No — design choice, not a bug | Firewall port 11434; bind to 127.0.0.1 |
| LangChain SSRF via tool use | security@langchain.dev | Partial — CVSS scores vary widely | Implement URL allowlisting; audit tool configurations |
| Prompt injection (agent with tools) | Framework security contact | Partial — no standard scoring | Add input validation; restrict tool permissions |
| HuggingFace pickle exploit in model | security@huggingface.co + Hub report button | No standard CVE format | Use safetensors only; run modelscan before loading |
| LangChain Python REPL RCE | security@langchain.dev | Yes — if triggered by untrusted input | Disable PythonREPLTool; sandbox execution |
| Transitive library CVE (Pillow via vLLM) | Upstream library (Pillow project) | Yes — standard CVE | Update dependency; verify transitive dependency versions |

## Trade-offs

**CVE vs advisory for novel AI vulnerability classes**: pursuing a CVE for a prompt injection vulnerability or a default-insecure Ollama configuration forces the issue into a framework designed for traditional software flaws. The CVSS score will be contested. The NVD description will be imprecise. The CVE ID becomes the canonical reference even if its severity rating is wrong. The alternative — publishing a security advisory without a CVE, either through the framework's GitHub security advisories or through independent research publication — gives more flexibility in describing the vulnerability accurately, at the cost of lower discoverability. For most AI-specific vulnerability classes, the advisory path produces more useful documentation than the CVE path.

**Embargo length for fast-moving AI frameworks**: the standard 90-day disclosure embargo was designed for established software projects with predictable release cadences. AI frameworks ship multiple releases per week. A 90-day embargo on a LangChain SSRF is often unnecessary — a patch can typically be shipped within days of a confirmed report. On the other hand, some AI infrastructure projects (particularly those with enterprise deployments) need longer windows to coordinate patch rollout. Agree on embargo length with the framework's security team early in the disclosure process rather than applying a default assumption.

**Model weight format migration cost**: migrating from pickle-based `.bin` files to safetensors requires both model producers (who must re-export and re-upload models) and consumers (who must update their loading code and model references). For organisations with proprietary fine-tuned models stored in `.bin` format, this migration may involve reprocessing large files and updating model serving infrastructure. The security benefit — eliminating arbitrary code execution from model loading — is significant, but the operational cost isn't trivial. A practical path: convert all newly acquired models to safetensors before storage, scan existing `.bin` files with modelscan, and migrate high-risk models (those loaded from external sources or with broad access) first.

## Failure Modes

**Prompt injection reported as a GitHub issue**: a researcher discovers a prompt injection in LangChain that enables SSRF via the HTTP request tool. They open a public GitHub issue titled "Bug: agent makes unexpected HTTP requests". The issue is indexed by search engines within hours. Attackers with LangChain deployments in their target environments now have a working attack technique before any patch exists. This is the disclosure failure mode that the AI ecosystem encounters repeatedly, because researchers accustomed to the "open source, open issues" model don't know that security advisories should be private. Mitigation: frameworks need visible, clearly labelled security reporting instructions; researchers need to check for SECURITY.md before filing issues.

**vLLM CVE missed because it's in a transitive ML library**: a critical CVE is published for Pillow (the Python imaging library). vLLM depends on Pillow for multimodal image preprocessing, but vLLM doesn't appear in the CVE description. An organisation scanning their `requirements.txt` with `pip-audit` finds the Pillow CVE — but concludes it's not exploitable because they "don't use Pillow directly". In fact, their vLLM deployment exposes Pillow's image parsing to network-supplied inputs via the multimodal API. The CVE is exploitable remotely, through vLLM. Mitigation: scan full dependency trees including transitive dependencies; map which network-exposed services invoke vulnerable code paths.

**Pickle exploit in model weights loaded despite safetensors being available**: an organisation has a policy of using safetensors for all models. A new team member downloads a model from Hugging Face Hub that offers both `.bin` and `.safetensors` files. They use the transformers `from_pretrained` convenience function without specifying `use_safetensors=True`. The library loads the `.bin` file by default because it appears first in the model's file listing. The `.bin` file contains a pickle payload. Mitigation: enforce `use_safetensors=True` in all `from_pretrained` calls through code review or a linting rule; use modelscan in CI to catch any pickle-based files before they reach production.

## The Responsible Disclosure Challenge for AI

AI security researchers sometimes bypass coordinated disclosure entirely — not out of bad faith, but because the disclosure ecosystem hasn't given them a reasonable alternative. A framework with no SECURITY.md, no security contact, and maintainers who close security-related issues as "not a bug" leaves researchers with a binary choice: publish publicly or say nothing.

The constructive path for AI project maintainers is to establish minimum viable security infrastructure before the CVEs arrive:

```markdown
# SECURITY.md template for ML projects

## Reporting Security Vulnerabilities

Please do not report security vulnerabilities through public GitHub issues.

**Email**: security@[project].dev
**GitHub private advisories**: Use the "Report a vulnerability" button on our Security tab

We will acknowledge your report within 7 days and aim to release a fix
within 30 days for confirmed vulnerabilities.

### Scope

The following are in scope:
- Code execution via model loading (pickle exploits)
- SSRF via agent tool use
- Authentication bypasses in the API server
- Prompt injection enabling data exfiltration or unauthorised tool use
- RCE via input processing

The following are out of scope:
- Prompt injection that only affects model output content (no tool access)
- Default configuration choices documented as security trade-offs
- Vulnerabilities requiring physical access to the deployment host

### CVE Policy

We will request CVEs for vulnerabilities that meet the threshold of
concrete, reproducible harm in a realistic deployment configuration.
Novel AI vulnerability classes (prompt injection, model poisoning) will
be published as GitHub Security Advisories regardless of CVE status.
```

The AI framework security ecosystem is maturing quickly, driven by the accumulation of real CVEs and the growing number of organisations deploying AI infrastructure in production. The gap between the speed at which AI frameworks ship and the speed at which security processes formalise remains large — but closing that gap requires both framework maintainers establishing disclosure processes and security practitioners learning the specific vulnerability classes that AI infrastructure introduces.
