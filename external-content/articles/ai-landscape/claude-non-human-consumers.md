---
title: "Claude, Mythos, and the Non-Human Infrastructure Consumer: Writing Hardening Guides for AI Agents"
description: "AI models are no longer just tools that engineers use to write code. They are becoming direct infrastructure consumers:"
slug: "claude-non-human-consumers"
date: 2026-03-04
lastmod: 2026-03-04
category: "ai-landscape"
tags: ["ai-agents", "claude", "documentation", "structured-content", "infrastructure-as-code", "llm"]
personas: ["ai-ml-engineer", "platform-engineer", "ai-agent"]
article_number: 103
difficulty: "intermediate"
estimated_reading_time: 18
provider_bridges:
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
premium_pack: "machine-parseable-configs"
published: true
layout: article.njk
permalink: "/articles/ai-landscape/claude-non-human-consumers/index.html"
---

# [Claude](https://claude.ai), Mythos, and the Non-Human Infrastructure Consumer: Writing Hardening Guides for AI Agents

## Problem

AI models are no longer just tools that engineers use to write code. They are becoming direct infrastructure consumers:

- **[Claude Code](https://claude.ai/code)** reads documentation and generates hardening configurations from it.
- **AI coding assistants** produce [Terraform](https://www.terraform.io) modules, [Kubernetes](https://kubernetes.io) manifests, and [Ansible](https://www.ansible.com) playbooks based on security guides they ingest.
- **Autonomous AI agents** with tool access read guides, generate configs, and apply them to production systems, sometimes without human review of the intermediate steps.

The documentation these agents consume was written for human readers. Humans can infer context from surrounding paragraphs, recognise when a guide is outdated, mentally merge partial instructions, and exercise judgement when instructions are ambiguous. AI agents cannot reliably do any of these things.

The consequences are different:

- An ambiguous guide consumed by a human produces a confused engineer who asks a colleague or searches for clarification.
- An ambiguous guide consumed by an AI agent produces a misconfigured production system deployed at machine speed.

This is not a model safety problem. The models are doing exactly what they are told. **This is a documentation security problem.** The input (the documentation) is the failure point.

The security community has not yet addressed this question: how should hardening content be structured so that both human engineers and AI agents produce correct, safe outputs from it?

This article answers that question. It also explains why every article on systemshardening.com follows the format it does.

## Threat Model

- **Adversary:** This is not an adversary-driven threat model. The threat is well-intentioned AI agents consuming poorly-structured documentation and producing incorrect or insecure configurations.
- **Access level:** AI agent has write access to infrastructure: `kubectl apply`, `terraform apply`, `ansible-playbook`, shell execution. The level of access depends on the agent's credential scoping (see [Securing AI Agents in Production: Tool-Use Boundaries, Credential Scoping, and Output Verification](/articles/ai-landscape/securing-ai-agents/): Securing AI Agents](/articles/ai-landscape/securing-ai-agents/)).
- **Objective (unintended):** Agent applies a hardening configuration that is incomplete (missing a critical setting because the guide used ellipses), outdated (guide was for Kubernetes 1.24, cluster is 1.30), internally contradictory (guide merged recommendations from two incompatible sources), or overly aggressive (guide recommended `lockdown=confidentiality` without documenting that it blocks NVIDIA drivers).
- **Blast radius:** Depends on the agent's credential scope. An agent with cluster-admin applying a misconfigured network policy can isolate every service in the cluster. An agent applying incorrect sysctl settings can crash a node. An agent generating a broken `pg_hba.conf` can lock every application out of the database.

## Configuration

This article does not have a traditional "Configuration" section with commands and config files. Instead, it defines the principles and patterns for writing documentation that AI agents can safely consume. These principles are the configuration; they determine whether the output of every agent interaction is correct or dangerous.

### What AI Models Do Well with Documentation

AI models excel at following explicit, step-by-step instructions with clear preconditions and postconditions. Given a well-structured guide, a model will:

- Execute commands in the correct order
- Apply configuration blocks exactly as written
- Run verification commands and compare output to expected results
- Follow conditional logic ("if X, then do Y; otherwise do Z") when the conditions are precisely defined
- Detect when its target system does not match the guide's stated preconditions and stop or ask for clarification

### What AI Models Do Poorly with Documentation

AI models struggle with (and sometimes fail silently at) the following:

**Inferring context from surrounding discussion.** A guide that says "adjust the buffer size based on your workload" provides no usable instruction to a model. The model will either pick an arbitrary value, use a value from a different context in its training data, or ask the user, but if the agent is operating autonomously, there is no user to ask.

**Detecting outdated instructions.** A guide written for Ubuntu 20.04 does not announce that it is outdated when an agent reads it in 2026. The agent will apply the instructions to Ubuntu 24.04 without modification. If the configuration format, file paths, or default values have changed between versions, the result is silent misconfiguration.

**Recognising incompatible merges.** When an agent is asked to "harden [NGINX](https://nginx.org)," it may draw on multiple sources in its training data or context. Guide A recommends `client_body_buffer_size 16k`. Guide B recommends `client_body_buffer_size 128k`. The agent may merge these into a single configuration, choosing one value without understanding the trade-off. Or worse, it may include both directives (the last one wins, silently).

**Handling ellipses and pseudocode.** A config block that contains `...` to indicate "other settings go here" is invisible to a human who knows to fill in the gap. To an AI agent, `...` is either literal text (syntax error) or a signal that the block is incomplete (the agent may try to generate the missing content, potentially incorrectly).

### The Six Principles for AI-Safe Documentation

These principles govern every article on systemshardening.com. They are the reason the site exists, no other hardening resource follows all six.

#### Principle 1: Explicit Preconditions

Every article states the exact operating system, software version, and current configuration state required before any instruction can be applied.

**Bad (human-only):**
```
This guide covers NGINX hardening.
```

**Good (human + AI):**
```
This guide covers NGINX hardening for NGINX 1.24+ (stable) and 1.26+
(mainline) running as a reverse proxy on Ubuntu 24.04 LTS, Debian 12,
or RHEL 9. All commands assume NGINX was installed via the distribution
package manager (apt or dnf), not compiled from source. The configuration
file is located at /etc/nginx/nginx.conf.
```

An AI agent reading the good version can verify: "Am I on NGINX 1.24+? Is this Ubuntu/Debian/RHEL? Was NGINX installed via apt/dnf? Is the config at /etc/nginx/nginx.conf?" If any answer is no, the agent knows the guide does not apply.

#### Principle 2: Deterministic Instructions

Every command produces the same result on every qualifying system. No "adjust to your environment" without specifying the variables and their valid ranges.

**Bad:**
```
Set an appropriate buffer size for your workload.
```

**Good:**
```
Set client_body_buffer_size to 16k. This handles request bodies up to 16KB
in memory. For API endpoints receiving JSON payloads, 16k is sufficient for
99% of requests. For file upload endpoints, override this per-location block
to match your maximum upload size (e.g., client_max_body_size 50m for a
50MB upload endpoint).
```

The good version gives a specific default value, explains when it is appropriate, and specifies exactly when and how to override it.

#### Principle 3: Complete Configuration Blocks

Every code block is syntactically valid, copy-pasteable, and includes all required context (enclosing blocks, file paths, prerequisite commands).

**Bad:**
```nginx
# Add these settings to your NGINX config:
server_tokens off;
client_max_body_size 1m;
...
```

**Good:**
```nginx
# /etc/nginx/nginx.conf
# Add to the http {} block. This is the complete set of hardening
# directives for the http block. See the full nginx.conf template
# at the end of this article for the complete file.

http {
    server_tokens off;
    client_max_body_size 1m;
    client_body_buffer_size 16k;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 8k;
    # ... (remaining settings listed individually below)
}
```

The good version specifies the file path, the enclosing block, and provides the complete directive set. The ellipsis in the good version is annotated, it tells the reader (human or AI) that individual settings follow, not that content is omitted.

#### Principle 4: Explicit Versioning

Every guide specifies which software versions it covers. Agents should not apply v1.24 guidance to v1.30.

```yaml
# Frontmatter on every article:
---
target_systems:
  - os: "Ubuntu 24.04 LTS"
    kernel: "6.8+"
  - os: "RHEL 9 / Rocky Linux 9"
    kernel: "5.14+"
software:
  - name: "NGINX"
    versions: ["1.24+", "1.26+"]
  - name: "Kubernetes"
    versions: ["1.29+"]
last_verified: "2026-04-21"
---
```

An AI agent can compare these versions against the target system and determine whether the guide applies before executing any instructions.

#### Principle 5: Verification After Every Change

Every configuration change includes a verification command with expected output. The agent runs the verification after applying the change and confirms the output matches before proceeding.

**Bad:**
```bash
# Apply sysctl settings
sudo sysctl --system
```

**Good:**
```bash
# Apply sysctl settings
sudo sysctl --system

# Verify the critical settings are active:
sysctl net.ipv4.conf.all.rp_filter
# Expected output: net.ipv4.conf.all.rp_filter = 1

sysctl kernel.kptr_restrict
# Expected output: kernel.kptr_restrict = 2

# If any value does not match: check /etc/sysctl.d/ for conflicting
# files that may override the setting. Files are applied in
# lexicographic order; the last value wins.
```

The agent can now verify its work. If the output does not match, the agent can follow the troubleshooting instruction (check for conflicting files) or stop and report the discrepancy.

#### Principle 6: Rollback Instructions for Every Change

Every change includes the exact command to undo it. Agents can execute rollback automatically if verification fails.

**Bad:**
```
If this doesn't work, revert the change.
```

**Good:**
```bash
# To rollback: restore the original sysctl configuration
sudo rm /etc/sysctl.d/60-net-hardening.conf
sudo sysctl --system

# Verify rollback:
sysctl net.ipv4.conf.all.rp_filter
# Expected output: net.ipv4.conf.all.rp_filter = 0
# (default value on most distributions)
```

### How systemshardening.com Implements These Principles

The Writing Format Standard (Problem → Threat Model → Configuration → Expected Behaviour → Trade-offs → Failure Modes) is not arbitrary. Each section serves a specific purpose for AI agent consumption:

| Section | Human Purpose | AI Agent Purpose |
|---------|--------------|-----------------|
| **Problem** | Understand why this matters | Assess relevance: does the target system have this problem? |
| **Threat Model** | Understand the risk | Match the threat model to the target environment's risk profile |
| **Configuration** | Follow the steps | Execute deterministic commands in order |
| **Expected Behaviour** | Verify it worked | Run verification commands; compare output to expected values |
| **Trade-offs** | Make informed decisions | Evaluate whether the trade-offs are acceptable for the target environment; if not, skip the control |
| **Failure Modes** | Know what can go wrong | Match observed failures to known patterns; execute recovery procedures automatically |

The "When to Consider a Managed Alternative" section at the end of every article serves an additional purpose for AI agents: it defines the boundary of the article's applicability. If the agent is operating on a managed Kubernetes cluster, and the article's managed alternative section says "managed providers handle this for you," the agent knows not to apply the configuration.

### Designing Infrastructure for Non-Human Consumers

Beyond documentation, the infrastructure itself should be designed for safe AI agent interaction:

**Idempotent operations.** Applying the same configuration twice should have no side effect. `kubectl apply` is idempotent. `sysctl --system` is idempotent. `echo "setting=value" >> /etc/sysctl.conf` is NOT idempotent (it appends a duplicate line). Prefer operations that are safe to re-run.

**Dry-run modes.** Before an agent applies a change, it should preview the effect:

```bash
# Kubernetes: dry-run before apply
kubectl apply -f manifest.yaml --dry-run=server

# Terraform: plan before apply
terraform plan -out=tfplan

# NGINX: test before reload
nginx -t
```

**Confirmation gates.** Destructive or irreversible operations should require explicit confirmation. For AI agents, this means: the agent generates the change, a human reviews the dry-run output, and the human approves execution. See [Securing AI Agents in Production: Tool-Use Boundaries, Credential Scoping, and Output Verification](/articles/ai-landscape/securing-ai-agents/): Securing AI Agents](/articles/ai-landscape/securing-ai-agents/) for implementation patterns.

**Structured output formats.** When agents query infrastructure state, they need structured output, not human-formatted tables:

```bash
# Bad for AI agents:
kubectl get pods

# Good for AI agents:
kubectl get pods -o json
```

## Expected Behaviour

After adopting the documentation and infrastructure patterns in this article:

- An AI agent reading a systemshardening.com article produces a correct, complete configuration for the stated target system without requiring human intervention to fill in gaps
- The agent verifies its own work using the Expected Behaviour section after every change
- The agent identifies when an article does not apply to its target system (wrong OS, wrong version, managed vs self-managed) from the preconditions and stops or asks for clarification
- The agent executes rollback if verification fails, using the documented rollback commands
- The agent never needs to "fill in the blanks", every value is explicit or has a documented decision framework with clear variable ranges
- Infrastructure operations are idempotent, dry-runnable, and produce structured output that agents can parse

## Trade-offs

| Decision | Human Impact | AI Impact | Assessment |
|----------|-------------|-----------|------------|
| Explicit preconditions on every article | Adds 3-5 lines to the top of each article; repetitive for experienced readers | Critical for agent accuracy; prevents applying wrong-version guidance | Worth it. Human readers skip the preconditions they already know. |
| No ellipses or pseudocode in configs | Config blocks are longer and more verbose | Eliminates ambiguity; agents produce correct configs | Worth it. Verbose but correct beats concise but ambiguous. |
| Verification commands after every change | Adds 2-3 lines per config block; human readers may skip them | Enables self-checking; agents catch their own errors | Worth it. The verification commands also serve as documentation of expected state. |
| Rollback instructions for every change | Adds rollback section to each config block | Enables automated recovery; agents can undo failed changes | Worth it. Rollback documentation is valuable for humans too, especially during incidents. |
| Version pinning on every article | Requires updating the article when new versions are released | Prevents agents from applying outdated guidance to new systems | Worth it, but requires maintenance commitment. Stale version pins are dangerous. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Agent applies guide to wrong OS version | Commands fail or produce different results than documented | Verification section commands return unexpected output; agent detects mismatch | Agent stops; reports precondition mismatch to operator. Operator selects correct guide version. |
| Agent merges configs from multiple sources | Contradictory settings applied (last write wins, silently) | Verification reveals incorrect values; `nginx -t` or `sysctl` shows unexpected settings | Agent rolls back to pre-change state. Apply articles sequentially, not merged. Each article's config is self-contained. |
| Agent applies outdated guide to current system | Deprecated API versions used; removed features referenced; file paths changed | API returns 404 or deprecation warning; command returns "not found" | Article versioning in frontmatter prevents this if the agent checks preconditions. Update the article's `last_verified` date and version constraints. |
| Agent proceeds despite ambiguous instruction | Incorrect value chosen for a setting that the guide left undefined | Verification section reveals incorrect behaviour; unexpected performance or connectivity impact | Eliminate ambiguity from the guide. Every "it depends" must have a decision framework: "if X, use value A; if Y, use value B." |
| Guide's version pin is stale | Agent correctly checks version but the guide hasn't been updated for the current version | Agent refuses to apply the guide (precondition mismatch); operator sees "guide not applicable to this version" | Update the guide: test on the new version, update preconditions and any changed defaults, update `last_verified` date. |

## When to Consider a Managed Alternative

This article does not have a traditional "managed alternative" bridge. Instead, it validates the entire site as a resource.

**The site IS the managed alternative to unstructured documentation.** Every article on systemshardening.com follows the six principles described in this article. This makes the entire corpus a premium resource for AI agent consumption that no other hardening resource provides.

Other hardening guides (CIS Benchmarks, vendor documentation, blog posts) are written for human readers only. They contain ellipses, pseudocode, implicit version assumptions, and "adjust to your environment" instructions that AI agents cannot safely interpret. systemshardening.com is the only hardening resource designed from the ground up for both human and AI consumption.

**Premium opportunity:** Machine-parseable configuration packs. YAML/JSON files with JSON Schema validation that AI agents consume directly without parsing documentation. Free content is the guide that teaches you what to configure and why. Premium content is the pre-validated, schema-checked configuration file that the agent applies directly, with built-in precondition checks and rollback.

**Monitoring AI-applied changes:** When AI agents apply configurations from this site, monitor the results using the verification commands in each article. For centralised monitoring of AI-applied changes across your infrastructure, [Grafana Cloud](https://grafana.com/cloud) provides dashboards that track configuration drift, verification pass/fail rates, and agent activity patterns. See [Auditing AI Actions at Scale: Building Tamper-Proof Logs for Non-Human Actors](/articles/ai-landscape/auditing-ai-actions/): Auditing AI Actions at Scale](/articles/ai-landscape/auditing-ai-actions/) for the full audit logging architecture.
