---
title: "LLM-Assisted Supply Chain Incident Response: Accelerating the Axios Blast Radius Analysis"
description: "The Axios compromise required scanning hundreds of repos, generating remediation runbooks, and rotating credentials under time pressure. LLMs accelerate IOC parsing, lockfile scanning, and runbook generation — with clear boundaries on what humans must decide."
slug: llm-supply-chain-incident-response
date: 2026-05-04
lastmod: 2026-05-04
category: ai-landscape
tags:
  - supply-chain
  - npm
  - llm
  - incident-response
  - automation
personas:
  - security-engineer
  - platform-engineer
article_number: 428
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/ai-landscape/llm-supply-chain-incident-response/
---

# LLM-Assisted Supply Chain Incident Response: Accelerating the Axios Blast Radius Analysis

## The Problem

The Axios compromise disclosure on March 31 2026 gave security teams a specific, time-bounded task: determine blast radius and remediate before the remote access trojan could cause further damage. The inputs were concrete and immediate: an IOC report from Microsoft and Google Threat Intelligence containing affected package names (`axios@1.14.1`), the malicious dependency (`plain-crypto-js@4.2.1`), SHA-512 file hashes, and a list of C2 IP addresses; hundreds of Git repositories containing `package-lock.json` files that needed to be scanned for the affected version; a list of Kubernetes deployments to check for running pods built with the affected lockfile; and a set of credentials — npm publish tokens, API keys, database credentials — potentially exfiltrated during the attack window.

In a large organisation with 400 repositories and a dozen platform teams, the manual version of this process takes 8–24 hours. Someone has to read the IOC report and extract the exact affected versions. Someone has to write the `grep` and `jq` commands. Someone has to run them across every repository. Someone has to look up which services each affected repository backs, find the service owner, and draft a remediation ticket with the right update commands. Someone has to write an executive summary from the technical findings before the end-of-day board call.

An LLM-assisted process — using the LLM to parse, query, draft, and summarise while humans make containment decisions — can compress this timeline to 2–4 hours. The key design principle underpins every pattern in this article: LLMs generate queries, commands, and runbooks that humans review and execute. LLMs do not execute commands autonomously or make containment decisions.

This is not a capability limitation. It is a deliberate safety boundary. LLM-generated shell commands can contain subtle bugs. LLM-parsed IOC lists can have missed entries or incorrect version ranges. An autonomous agent that acts on either without human review introduces new failure modes into an already stressful incident. The goal is acceleration, not autonomy.

## Threat Model

This section covers the IR scenarios where LLM assistance is most valuable, rather than an adversary threat model.

**Unstructured IOC report that needs to be parsed into machine-readable queries.** Microsoft and Google Threat Intelligence publish IOC reports as prose documents or semi-structured PDFs. Extracting affected package names, version ranges, file hashes, and C2 addresses for use in automated scanning requires either manual effort or a tool that can parse natural-language threat reports. LLMs handle unstructured-to-structured extraction well.

**Hundreds of repositories that need to be scanned for affected lockfile entries.** `package-lock.json` files record the exact resolved version of every transitive dependency. Scanning them for a specific package version across hundreds of repositories requires a script. Writing that script correctly under time pressure is error-prone. The LLM can generate the script; a human validates it before it runs.

**Service-specific remediation runbooks that need to be drafted under time pressure.** Once affected repositories are identified, each service owner needs a remediation runbook tailored to their specific `package.json`, deployment platform, and credential types. Writing twelve variants of the same runbook manually is slow. LLMs can generate them from a template plus per-service context.

**Executive communication that needs to summarise technical blast radius in non-technical terms.** The CISO needs to know: how many services were affected, whether any production systems made C2 contact, what is the remediation status, and what is the business risk. Translating technical findings into executive language is a task LLMs handle well and humans often deprioritise during a high-pressure incident.

**Credential rotation coordination across multiple service owners with different tech stacks.** Different services use different secret management systems: AWS Secrets Manager, HashiCorp Vault, Kubernetes Secrets, GitHub Actions secrets. The rotation runbook for each varies. LLMs can generate the correct rotation commands for each platform given the service context.

## Hardening Configuration

### 1. IOC Parsing: Structured Extraction from Threat Reports

The first step after the IOC report is published is extraction. The report contains the information needed to drive every downstream step — lockfile scanning queries, Kubernetes label selectors, network block rules — but it arrives as unstructured prose. Feeding it to an LLM with a structured-output prompt produces the machine-readable form in minutes.

The system prompt establishes the extraction task and output schema. The user message is the raw IOC report text, pasted in full.

```python
import anthropic
import json

client = anthropic.Anthropic()

SYSTEM_PROMPT = """You are a security analyst assistant specialising in supply chain incident response.
You will be given a raw threat intelligence report describing a software supply chain compromise.
Extract the following fields and return them as a JSON object matching this schema exactly:

{
  "incident_name": "string",
  "disclosure_date": "ISO 8601 date string",
  "affected_packages": [
    {
      "ecosystem": "npm | pypi | maven | rubygems",
      "name": "string",
      "affected_versions": ["string"],
      "safe_versions": ["string"],
      "malicious_file_hashes": {
        "sha512": ["string"],
        "sha256": ["string"]
      }
    }
  ],
  "malicious_dependencies": [
    {
      "ecosystem": "string",
      "name": "string",
      "versions": ["string"]
    }
  ],
  "c2_indicators": {
    "ip_addresses": ["string"],
    "domains": ["string"],
    "ports": [integer]
  },
  "persistence_indicators": ["string"],
  "attack_window": {
    "start": "ISO 8601 datetime or null",
    "end": "ISO 8601 datetime or null"
  }
}

If a field is not mentioned in the report, use null or an empty list as appropriate.
Do not infer information not present in the report. Return only valid JSON."""

def extract_iocs_from_report(raw_report_text: str) -> dict:
    response = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=2048,
        system=SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": f"Extract the IOCs from this threat report:\n\n{raw_report_text}"
            }
        ]
    )
    return json.loads(response.content[0].text)
```

The output for the Axios compromise would look like this:

```json
{
  "incident_name": "Axios npm Supply Chain Compromise (Sapphire Sleet)",
  "disclosure_date": "2026-03-31",
  "affected_packages": [
    {
      "ecosystem": "npm",
      "name": "axios",
      "affected_versions": ["1.14.1"],
      "safe_versions": ["1.13.9", "1.14.2"],
      "malicious_file_hashes": {
        "sha512": [
          "a3f8c2d1e9b04567890abcdef1234567890abcdef1234567890abcdef12345678"
        ],
        "sha256": [
          "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678"
        ]
      }
    }
  ],
  "malicious_dependencies": [
    {
      "ecosystem": "npm",
      "name": "plain-crypto-js",
      "versions": ["4.2.1"]
    }
  ],
  "c2_indicators": {
    "ip_addresses": ["198.51.100.47", "203.0.113.12"],
    "domains": ["telemetry-cdn.net", "update-sync.io"],
    "ports": [443, 8443]
  },
  "persistence_indicators": [
    "postinstall script writing cron entry to /tmp/.npm_cache_sync",
    "base64-encoded payload decoded to ~/.config/.npm/.session"
  ],
  "attack_window": {
    "start": "2026-03-28T14:00:00Z",
    "end": "2026-03-31T18:00:00Z"
  }
}
```

**Mandatory human verification step.** Before using this JSON as the input to any automated scan, a human reviewer must compare the extracted IOCs against the original report. LLMs occasionally truncate version lists, misparse version ranges (interpreting `>= 1.14.0 < 1.14.2` as `1.14.0` only), or miss C2 entries buried in footnotes. The extraction step saves time; it does not replace reading the source document.

### 2. Lockfile Scanning Query Generation

With verified IOC JSON in hand, the next step is generating the scanning script. Rather than writing the `jq` and `bash` pipeline under time pressure, prompt the LLM with the structured IOC list and ask it to generate a script that a human can review and run.

```python
SCAN_GENERATION_PROMPT = """You are a security engineer. You will be given a JSON object containing
verified IOC data from a supply chain compromise. Generate a bash script that:

1. Accepts a root directory as its first argument (defaulting to the current directory)
2. Recursively finds all package-lock.json files under that directory
3. For each lockfile, checks whether any of the affected packages at the affected versions
   are present in the "packages" or "dependencies" section
4. Also checks for the presence of the malicious dependencies by name
5. Outputs a tab-separated report: REPO_PATH, AFFECTED_PACKAGE, AFFECTED_VERSION, LOCKFILE_PATH
6. Exits with code 1 if any affected packages are found, 0 if clean

The script must handle:
- npm lockfile versions 2 and 3 (which use the "packages" key)
- npm lockfile version 1 (which uses the "dependencies" key)
- Repositories with multiple package-lock.json files (monorepos)

Use jq for JSON parsing. The script must not modify any files."""

def generate_lockfile_scanner(verified_ioc_json: dict) -> str:
    response = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=3000,
        messages=[
            {
                "role": "user",
                "content": f"{SCAN_GENERATION_PROMPT}\n\nIOC data:\n{json.dumps(verified_ioc_json, indent=2)}"
            }
        ]
    )
    return response.content[0].text
```

The LLM will produce a script similar to this:

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${1:-.}"
AFFECTED=0

PACKAGES='["axios"]'
VERSIONS='["1.14.1"]'
MALICIOUS_DEPS='["plain-crypto-js"]'

find "$ROOT_DIR" -name "package-lock.json" -not -path "*/node_modules/*" | while read -r lockfile; do
    repo_dir="$(dirname "$lockfile")"

    lockfile_version=$(jq -r '.lockfileVersion // 1' "$lockfile")

    if [[ "$lockfile_version" -ge 2 ]]; then
        jq -r --argjson pkgs "$PACKAGES" --argjson vers "$VERSIONS" '
          .packages // {} |
          to_entries[] |
          select(
            (.key | ltrimstr("node_modules/") | split("/") | last) as $name |
            ($pkgs | index($name)) != null and
            (($vers | index(.value.version)) != null)
          ) |
          [.key, .value.version]
        ' "$lockfile" | while IFS=$'\t' read -r pkg ver; do
            printf '%s\t%s\t%s\t%s\n' "$repo_dir" "$pkg" "$ver" "$lockfile"
            AFFECTED=1
        done

        jq -r --argjson deps "$MALICIOUS_DEPS" '
          .packages // {} |
          to_entries[] |
          select(
            (.key | ltrimstr("node_modules/") | split("/") | last) as $name |
            ($deps | index($name)) != null
          ) |
          [.key, .value.version]
        ' "$lockfile" | while IFS=$'\t' read -r pkg ver; do
            printf '%s\tMALICIOUS:%s\t%s\t%s\n' "$repo_dir" "$pkg" "$ver" "$lockfile"
            AFFECTED=1
        done
    else
        jq -r --argjson pkgs "$PACKAGES" --argjson vers "$VERSIONS" '
          .dependencies // {} |
          to_entries[] |
          select(
            ($pkgs | index(.key)) != null and
            ($vers | index(.value.version)) != null
          ) |
          [.key, .value.version]
        ' "$lockfile" | while IFS=$'\t' read -r pkg ver; do
            printf '%s\t%s\t%s\t%s\n' "$repo_dir" "$pkg" "$ver" "$lockfile"
            AFFECTED=1
        done
    fi
done

exit $AFFECTED
```

**Why human review before execution is mandatory.** LLM-generated shell commands have a class of subtle bugs that are not visible to a quick read but cause silent failures: a `jq` filter that silently returns empty output when the lockfile schema differs from the assumed format, a `find` path exclusion that accidentally skips a directory containing affected services, a variable scoping issue in a subshell that means `AFFECTED` is never set to `1` in the outer process. Any of these causes false negatives — the script reports "clean" for repositories that are actually affected. Before running the script, a reviewer should verify: the `find` exclusion list is correct for your directory layout; the `jq` filters produce expected output against a known-affected lockfile (use the IOC package version as a test case); the exit code logic is correct. This review takes 5–10 minutes and is not optional.

### 3. Service-Specific Remediation Runbook Generation

The lockfile scan produces a list of affected repositories. For each one, a service owner needs a runbook: the exact `npm update` command for their affected package, the steps to update their deployment, and the credential rotation steps specific to their service. Generating a generic runbook and telling service owners to adapt it adds friction during an incident. Generating a service-specific runbook from the service's own `package.json` and context is faster.

```python
RUNBOOK_TEMPLATE = """You are a senior platform engineer writing a remediation runbook
for a supply chain security incident. You will be given:
1. The name and description of the affected service
2. The service's package.json
3. A list of affected packages found in the lockfile scan
4. The deployment platform (kubernetes, ecs, lambda, etc.)
5. The types of credentials the service uses

Generate a numbered remediation runbook with the following sections:
- Immediate actions (what to do in the next 30 minutes)
- Dependency remediation (exact npm commands to run)
- Deployment update (how to redeploy after fixing the lockfile)
- Credential rotation (which credentials to rotate and how, given the platforms listed)
- Verification (how to confirm the service is no longer using the affected version)

Be specific: use the actual package names, actual update commands, and actual platform commands.
Do not include generic advice. Every step must be immediately actionable by the service owner."""

def generate_service_runbook(
    service_name: str,
    service_description: str,
    package_json: dict,
    affected_packages: list[dict],
    deployment_platform: str,
    credential_types: list[str]
) -> str:
    context = {
        "service_name": service_name,
        "service_description": service_description,
        "package_json": package_json,
        "affected_packages": affected_packages,
        "deployment_platform": deployment_platform,
        "credential_types": credential_types
    }
    response = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=3000,
        messages=[
            {
                "role": "user",
                "content": f"{RUNBOOK_TEMPLATE}\n\nService context:\n{json.dumps(context, indent=2)}"
            }
        ]
    )
    return response.content[0].text
```

The generated runbook for a payment service using Kubernetes and HashiCorp Vault would include the exact `npm update axios@1.14.2` command, the `kubectl rollout restart deployment/payment-service -n production` command, and the specific Vault path rotation commands for that service's credentials — not a generic placeholder. Providing the service's actual `package.json` and deployment platform is what makes this possible. A thin prompt produces a generic runbook that is no faster to act on than a template.

### 4. Blast Radius Summary for Executive Communication

Technical findings need to reach decision-makers in a form they can act on. The CISO needs containment status, business impact, and next steps — not `jq` filter output. Generating this summary during an incident competes with the work of containment itself. An LLM can draft it in under a minute given the structured technical findings.

```python
EXECUTIVE_SUMMARY_PROMPT = """You are a security communications specialist. Write a one-page
executive summary of a supply chain security incident for a CISO audience.

The summary must cover:
1. What happened (one paragraph, non-technical)
2. Blast radius (affected services, any confirmed C2 contact, credential exposure)
3. Containment status (what has been done, what is in progress)
4. Business risk (operational impact, data exposure risk, regulatory considerations)
5. Next steps and timeline

Tone: factual, measured, no alarm language. Acknowledge uncertainty where it exists.
Do not use technical jargon (no "lockfile", "npm", "SHA hash"). Length: 300-400 words."""

def generate_executive_summary(technical_findings: dict) -> str:
    response = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=1000,
        messages=[
            {
                "role": "user",
                "content": f"{EXECUTIVE_SUMMARY_PROMPT}\n\nTechnical findings:\n{json.dumps(technical_findings, indent=2)}"
            }
        ]
    )
    return response.content[0].text
```

An example `technical_findings` dict for the Axios incident might include: 12 affected services identified, 3 services with confirmed deployment during the attack window, 0 confirmed C2 egress connections (based on firewall log review), 47 credentials flagged for rotation, 11 of 12 service runbooks distributed to owners, estimated remediation completion 6 hours from disclosure.

### 5. Boundaries: What LLMs Must Not Do Autonomously

The patterns above are effective precisely because they keep the LLM in the role of drafter and the human in the role of executor. When that boundary is removed, the risk calculus changes.

**No autonomous command execution.** The scanning script generated in step 2 must be reviewed and run by a human. An agentic tool that generates and immediately executes shell commands against production repositories removes the review step that catches bugs causing false negatives. In a supply chain IR, a false negative (missed affected service) is a worse outcome than a false positive (unnecessary remediation of an unaffected service).

**No autonomous containment decisions.** Decisions to isolate a Kubernetes pod, revoke an npm publish token, or block a C2 IP at the network perimeter have blast radius of their own. Revoking the wrong token breaks a CI pipeline. Blocking the wrong IP disrupts a legitimate CDN. These decisions require a human who understands the service topology and can weigh the operational risk of the containment action against the security risk of delay.

**No autonomous credential rotation.** Credential rotation in production requires coordination with service owners and must target the correct environment. An agentic tool that rotates credentials without human approval can rotate the wrong credential, target the staging environment's secret path instead of production, or rotate a shared credential used by multiple services without notifying all owners.

**No external communications without human approval.** LLM-generated incident communications — Slack messages to affected service owners, breach notification drafts, regulatory disclosure drafts — must be reviewed before sending. Legal and compliance communications in particular require legal review, not just security review. An LLM can draft; it cannot send.

**No treatment of LLM output as ground truth.** The lockfile scan result is not authoritative until a human has verified that the script ran against all repositories, not a subset. The IOC extraction is not authoritative until a human has compared it to the source report. Every LLM output in an IR workflow is a first draft, not a final answer.

These guardrails are not limitations to work around. They are the safety margin that makes LLM-assisted IR a net positive rather than a net risk.

## Expected Behaviour After Hardening

With this LLM-assisted IR workflow in place, the timeline for a compromise comparable to the Axios incident compresses significantly. Within 30 minutes of the IOC report being published, the LLM has parsed it into structured JSON and generated the lockfile scanning script. The security team has reviewed the script and is running it across all 400 repositories. Within 90 minutes, the scan is complete and the blast radius is known: 12 affected services, 3 of which were deployed during the attack window. Within 2 hours, service-specific runbooks have been drafted and distributed to all 12 service owners. The executive summary draft is ready within 15 minutes of the scan completing. The total IR timeline is 4 hours instead of 24.

The productivity gain comes from eliminating the drafting and scripting work, not from removing human judgment. Every decision point — which services to isolate, which credentials to rotate, when to send external communications — still has a human in the loop. The LLM has handled the work that scales with the number of affected services (runbook generation) and the complexity of the threat report (IOC extraction), while humans handle the work that requires organisational context and risk judgment.

## Trade-offs and Operational Considerations

**LLM-generated shell commands must be reviewed before execution.** The time saved by LLM generation must not be absorbed by inadequate review. Train the IR team on what to look for in generated scripts: verify the `find` exclusions match your directory layout, verify the `jq` filters against a known-affected test case, check exit code logic for subshell scoping issues. A 10-minute review is the correct investment; skipping it negates the safety margin.

**IOC extraction accuracy is not guaranteed.** LLMs occasionally miss version ranges buried in footnotes, misparse semver operators (`~` versus `^` versus `>=`), or truncate long lists of affected hashes. The extraction step saves the mechanical work of structured formatting; it does not replace reading the source document. Always cross-reference the extracted IOCs against the original report before using them as scan inputs. Any discrepancy between the extracted JSON and the source document must be resolved in favour of the source document.

**Runbook quality depends on the context provided.** A runbook generated from a sparse prompt — service name and affected package only — will be generic and slow to act on. A runbook generated with the service's actual `package.json`, deployment platform, and credential types will be specific and immediately actionable. The investment in providing richer context pays back in the time service owners spend adapting the runbook. For organisations that want to use this pattern at scale, maintaining a service inventory with deployment platform and credential type metadata enables automated context assembly at incident time.

**LLM API availability during an incident.** If your LLM integration depends on an external API (Anthropic, OpenAI, Azure OpenAI), verify that API availability is not in scope of your incident. A supply chain attack that targets developer tooling could, in theory, affect the availability or integrity of tooling your IR team depends on. Consider whether a cached or on-premises model is appropriate for the most critical IR steps.

## Failure Modes

**Security team uses LLM-generated lockfile scan script without review.** The script contains a `jq` filter that silently returns empty output for lockfile version 3 format — the format used by 60% of repositories. The script reports "no affected packages found" across the entire repository estate. The team proceeds to credential rotation and closes the incident. Three weeks later, a post-incident review identifies that 8 of 12 affected services were not caught by the scan.

**LLM used to generate external breach notification communications without legal review.** The LLM draft contains phrasing that implies confirmed data exfiltration when the forensic evidence is inconclusive. The communication is sent to affected customers before legal review. The organisation is now committed to a position that its forensic investigation has not established.

**Agentic IR tool given execution permissions.** The tool autonomously rotates the `AXIOS_API_KEY` credential across all affected services. One of those services uses the same credential name for a different key that backs a completely separate integration. Rotating it causes an outage in an unrelated service. The incident response has now caused its own incident.

**LLM output treated as ground truth.** The IOC extraction report shows three affected packages. The lockfile scan reports zero affected repositories. The team closes the incident. The IOC extraction had missed a fourth affected package — `axios-retry@3.1.0`, which pinned `axios@1.14.1` as a peer dependency — because it appeared in an appendix table the LLM did not fully parse. Repositories using `axios-retry` were not scanned for the direct `axios` dependency at the affected version, and remained compromised.

## Related Articles

- [AI OT Security Operations](/articles/ai-landscape/ai-ot-security-operations/)
- [AI Incident Reporting](/articles/ai-landscape/ai-incident-reporting/)
- [SBOM Supply Chain Compromise Detection](/articles/observability/sbom-supply-chain-compromise-detection/)
- [npm Supply Chain Runtime Detection](/articles/observability/npm-supply-chain-runtime-detection/)
- [Kubernetes Supply Chain Incident Response](/articles/kubernetes/kubernetes-supply-chain-incident-response/)
