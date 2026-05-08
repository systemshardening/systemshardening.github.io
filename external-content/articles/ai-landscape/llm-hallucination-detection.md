---
title: "LLM Hallucination Detection for Security-Critical Decisions"
description: "LLMs confidently generate false CVE details, incorrect tool syntax, and fabricated IP addresses when used in security automation. Grounding, confidence scoring, and human-in-the-loop triggers detect and contain these errors."
slug: "llm-hallucination-detection"
date: 2026-04-30
lastmod: 2026-04-30
category: "ai-landscape"
tags: ["hallucination", "llm", "security-automation", "rag", "grounding"]
personas: ["security-engineer", "ml-engineer", "platform-engineer"]
article_number: 260
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/ai-landscape/llm-hallucination-detection/index.html"
---

# LLM Hallucination Detection for Security-Critical Decisions

## Problem

Language models are increasingly deployed in security workflows: triaging vulnerability reports, generating remediation playbooks, assessing code for security issues, summarising incident timelines, and recommending firewall rules. These applications rely on the LLM producing accurate factual claims about the real world — specific CVE identifiers, correct tool flags, valid IP ranges, accurate package names.

LLMs hallucinate. The hallucination rate varies by model, task, and domain, but all current models confidently generate plausible-sounding falsehoods, particularly for:

- **CVE details:** A model asked to summarise CVE-2024-1234 may describe the wrong software, wrong CVSS score, or wrong mitigation — or describe a CVE that doesn't exist at all.
- **Tool syntax:** A model generating a Kubernetes remediation command may produce subtly wrong flags that silently do nothing or cause damage when executed.
- **Package versions:** A model recommending "upgrade to patched version X.Y.Z" may cite a version that doesn't exist in the registry.
- **Network addresses:** A model asked to parse threat intelligence may fabricate IP addresses or ASNs not present in the source data.
- **Code vulnerabilities:** A model claiming "line 47 contains an SQL injection" may be wrong about the line, the vulnerability type, or both.

In security automation, acting on a hallucinated CVE summary could mean patching the wrong system, leaving the actual vulnerability unaddressed, or triggering a false incident response. The stakes are higher than consumer applications where hallucinations are merely annoying.

**Target systems:** Any LLM-assisted security workflow — Claude-based security tools, GPT-4o for code review, Gemini for threat intelligence — regardless of model. Grounding techniques work across all models.

## Threat Model

- **Adversary 1 — Hallucination-induced misconfiguration:** A DevSecOps pipeline uses an LLM to generate firewall rules from a threat intelligence feed. The LLM hallucinates an IP range; the generated rule blocks legitimate traffic or permits an attacker's IP.
- **Adversary 2 — False CVE summary causing missed patch:** A vulnerability management tool uses an LLM to summarise CVEs. The LLM describes the wrong affected component; the team patches the wrong package and the real vulnerability remains exploitable.
- **Adversary 3 — Fabricated remediation step:** An LLM-generated incident response playbook includes a remediation step that doesn't work (wrong kubectl flag, wrong API call) or causes additional damage when executed under pressure.
- **Adversary 4 — Prompt injection via threat intelligence:** An attacker embeds instructions in a threat intelligence feed that the LLM processes. The LLM's output includes the injected instruction, causing the security tool to take incorrect action. (Distinct from adversarial manipulation — this is prompt injection via untrusted input.)
- **Adversary 5 — Confidence masking:** The LLM produces a high-confidence-sounding response ("CVE-2024-99999 affects OpenSSL 3.2 with CVSS 9.8") for a hallucinated CVE. The human reviewer, seeing confident output, doesn't verify.
- **Access level:** Adversaries 1–3 arise from the model itself (no external adversary). Adversary 4 has write access to input data sources. Adversary 5 exploits the human's overreliance on LLM output.
- **Objective:** Cause incorrect security decisions that leave vulnerabilities unaddressed, misconfigure defences, or exhaust response capacity on false positives.
- **Blast radius:** An undetected hallucination in a vulnerability management pipeline could leave a critical vulnerability exploitable for weeks. A hallucination in an automated firewall rule generation tool could cause an outage.

## Configuration

### Step 1: Grounding with Authoritative Sources

The most effective mitigation: force the LLM to cite specific claims from provided source documents rather than from training data.

```python
import anthropic
import httpx

client = anthropic.Anthropic()

def get_cve_details_grounded(cve_id: str) -> dict:
    # Step 1: Fetch authoritative CVE data.
    nvd_response = httpx.get(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
        timeout=10,
    )
    if nvd_response.status_code != 200 or not nvd_response.json().get("vulnerabilities"):
        return {"error": f"CVE {cve_id} not found in NVD"}

    cve_data = nvd_response.json()["vulnerabilities"][0]["cve"]
    description = cve_data["descriptions"][0]["value"]
    cvss = cve_data.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
    references = [r["url"] for r in cve_data.get("references", [])[:5]]

    # Step 2: Ask the LLM to summarise ONLY from the provided data.
    prompt = f"""You are summarising a CVE for a security team.

Use ONLY the following authoritative data. Do not add any information from your training.
If a field is missing from the data, say "not available" — do not infer or guess.

CVE ID: {cve_id}
Description: {description}
CVSS Score: {cvss.get('baseScore', 'not available')}
CVSS Vector: {cvss.get('vectorString', 'not available')}
References: {references}

Provide:
1. Affected software and versions (from description only)
2. Vulnerability type (from description only)
3. CVSS score and severity
4. Recommended action (from references only; if references don't specify, say "consult vendor advisory")

Do not cite any CVE, vulnerability, or remediation step not present in the data above."""

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=500,
        messages=[{"role": "user", "content": prompt}]
    )

    return {
        "cve_id": cve_id,
        "summary": response.content[0].text,
        "source": "NVD",
        "raw_cvss": cvss,
        "grounded": True,
    }
```

For tool-generated outputs (firewall rules, kubectl commands), include the exact tool documentation:

```python
def generate_k8s_remediation_grounded(finding: dict) -> str:
    # Fetch the actual kubectl documentation for the relevant command.
    docs_snippet = load_kubectl_docs(finding["resource_type"])

    prompt = f"""Generate a kubectl command to remediate this finding.

Finding: {finding['description']}
Resource: {finding['resource']}
Namespace: {finding['namespace']}

Use ONLY the following kubectl syntax reference. Do not invent flags or options
not present in this reference.

<kubectl_reference>
{docs_snippet}
</kubectl_reference>

Output ONLY the exact kubectl command, nothing else. If the remediation cannot
be expressed as a single kubectl command from the reference above, respond with:
MANUAL_REVIEW_REQUIRED: <reason>"""

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=200,
        messages=[{"role": "user", "content": prompt}]
    )
    return response.content[0].text
```

### Step 2: Structured Output with Verification Fields

Request outputs that include explicit uncertainty markers:

```python
import json

def analyse_code_for_vulnerabilities_with_confidence(code: str, filename: str) -> dict:
    prompt = f"""Analyse this code for security vulnerabilities.

For each finding, you MUST provide:
- A specific line number from the code
- The exact code snippet at that line
- Your confidence level (high/medium/low)
- Why you are uncertain (if confidence is not high)

If you cannot point to a specific line, do NOT report the finding.
If you are not certain the pattern is exploitable, set confidence to low or medium.

Return a JSON object with this structure:
{{
  "findings": [
    {{
      "line_number": <integer>,
      "code_snippet": "<exact text from the provided code>",
      "vulnerability_type": "<CWE name>",
      "cwe_id": "<CWE-XXX>",
      "confidence": "high|medium|low",
      "confidence_reason": "<why you are uncertain, or 'verified against source'>"
    }}
  ]
}}

Code ({filename}):
```
{code}
```"""

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1000,
        messages=[{"role": "user", "content": prompt}]
    )

    try:
        result = json.loads(response.content[0].text)
    except json.JSONDecodeError:
        return {"error": "Model did not return valid JSON", "raw": response.content[0].text}

    # Post-hoc verification: confirm the cited line number and snippet actually exist.
    code_lines = code.splitlines()
    verified_findings = []
    for finding in result.get("findings", []):
        line_num = finding.get("line_number", 0)
        snippet = finding.get("code_snippet", "")
        if 1 <= line_num <= len(code_lines) and snippet.strip() in code_lines[line_num - 1]:
            finding["verified"] = True
        else:
            finding["verified"] = False
            finding["confidence"] = "low"
            finding["confidence_reason"] = f"Line {line_num} does not match cited snippet — possible hallucination"
        verified_findings.append(finding)

    result["findings"] = verified_findings
    return result
```

### Step 3: Cross-Model Verification for High-Stakes Decisions

For decisions above a risk threshold, use a second model to verify the first:

```python
def verify_security_claim(claim: str, source_data: str, verifier_model: str = "claude-haiku-4-5-20251001") -> dict:
    """Ask a second, faster model to verify a specific claim against source data."""
    prompt = f"""A security tool made the following claim:

CLAIM: {claim}

Verify this claim against the following source data ONLY.
Answer only YES (claim is fully supported by source), NO (claim is contradicted or unsupported by source),
or PARTIAL (claim is partially supported but contains unverifiable elements).

Source data:
{source_data}

Your response must be JSON: {{"verdict": "YES|NO|PARTIAL", "reason": "<one sentence>"}}"""

    response = client.messages.create(
        model=verifier_model,
        max_tokens=100,
        messages=[{"role": "user", "content": prompt}]
    )

    try:
        return json.loads(response.content[0].text)
    except json.JSONDecodeError:
        return {"verdict": "UNKNOWN", "reason": "Verification failed to parse"}

# Usage:
cve_summary = get_cve_details_grounded("CVE-2024-1234")
key_claim = "CVE-2024-1234 affects OpenSSL versions before 3.2.1"
verification = verify_security_claim(key_claim, cve_summary["raw_cvss"]["vectorString"])
if verification["verdict"] != "YES":
    flag_for_human_review(cve_summary, verification)
```

### Step 4: Human-in-the-Loop Triggers

Define clear thresholds that route LLM outputs to human review:

```python
from enum import Enum
from dataclasses import dataclass

class ReviewTrigger(Enum):
    CONFIDENCE_LOW = "confidence_below_threshold"
    VERIFICATION_FAILED = "cross_model_verification_failed"
    HIGH_BLAST_RADIUS = "action_affects_production"
    NOVEL_CVE = "cve_not_in_authoritative_db"
    UNGROUNDED_CLAIM = "claim_cites_no_source"

@dataclass
class SecurityDecision:
    action: str
    confidence: float
    triggers: list[ReviewTrigger]
    requires_human_review: bool

def evaluate_decision(llm_output: dict, action_context: dict) -> SecurityDecision:
    triggers = []

    # Low confidence in the LLM output.
    confidence = llm_output.get("confidence_score", 1.0)
    if confidence < 0.7:
        triggers.append(ReviewTrigger.CONFIDENCE_LOW)

    # Cross-model verification failed.
    if llm_output.get("verification", {}).get("verdict") != "YES":
        triggers.append(ReviewTrigger.VERIFICATION_FAILED)

    # The action affects production systems.
    if action_context.get("environment") == "production":
        triggers.append(ReviewTrigger.HIGH_BLAST_RADIUS)

    # CVE was not found in NVD (possible hallucinated CVE ID).
    if llm_output.get("cve_not_in_nvd"):
        triggers.append(ReviewTrigger.NOVEL_CVE)

    # The LLM cited no sources.
    if not llm_output.get("sources"):
        triggers.append(ReviewTrigger.UNGROUNDED_CLAIM)

    requires_review = bool(triggers)
    return SecurityDecision(
        action=llm_output["recommended_action"],
        confidence=confidence,
        triggers=triggers,
        requires_human_review=requires_review,
    )
```

### Step 5: Hallucination Testing in CI

Test your security automation prompts for hallucination before deploying:

```python
import pytest

# Test: model should refuse to describe a non-existent CVE.
def test_nonexistent_cve_handling():
    result = get_cve_details_grounded("CVE-1900-99999")
    assert result.get("error") is not None
    assert "not found" in result["error"].lower()
    # The model must not hallucinate details about a CVE that doesn't exist.

# Test: model output cites only provided source data.
def test_grounded_summary_cites_source():
    result = get_cve_details_grounded("CVE-2021-44228")   # Log4Shell — well-documented.
    summary = result["summary"]
    # The model should mention Log4j / log4j2; this is in the NVD description.
    assert "log4j" in summary.lower() or "log4shell" in summary.lower()
    # The model should NOT mention technologies not in the CVE description.
    # (This requires a negative list check specific to the CVE.)

# Test: code analysis citations are verifiable.
def test_code_analysis_verifiable_lines():
    code = """
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"  # Line 3: SQL injection
    return db.execute(query)
"""
    result = analyse_code_for_vulnerabilities_with_confidence(code, "test.py")
    for finding in result.get("findings", []):
        assert finding["verified"], f"Unverified finding: {finding}"
```

### Step 6: Telemetry

```
llm_hallucination_detected_total{task_type, trigger}          counter
llm_human_review_triggered_total{task_type, trigger}          counter
llm_grounding_source_used_total{source}                       counter
llm_verification_verdict_total{verdict, model}                counter
llm_output_confidence_score{task_type}                        histogram
llm_cve_not_in_nvd_total                                      counter
```

Alert on:

- `llm_hallucination_detected_total` spike — prompts or models are producing more unverifiable output; review recently changed prompts.
- `llm_cve_not_in_nvd_total` non-zero — a security tool is citing CVEs that don't exist; block the output and review the prompt.
- `llm_human_review_triggered_total` rate rising — possible increase in low-confidence outputs; may indicate a model change or prompt drift.

## Expected Behaviour

| Signal | Unmitigated LLM output | Grounded + verified output |
|--------|------------------------|--------------------------|
| CVE not in NVD | Plausible-sounding fabrication | Error returned; human review triggered |
| Wrong line number in code finding | Reported confidently | `verified: false` flag; confidence downgraded to `low` |
| Remediation step uses non-existent flag | Included in playbook | Flagged as not in docs reference; MANUAL_REVIEW_REQUIRED |
| High-confidence hallucination | Sent to execution pipeline | Cross-model verification fails; human review triggered |
| Novel CVE with no NVD entry | Described in detail | Routed to human; not actioned automatically |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Grounding with source documents | Dramatically reduces factual errors | Requires fetching authoritative data per request | Cache NVD data; refresh daily; latency impact is small (< 500ms). |
| Cross-model verification | Independent check catches primary model errors | 2× API cost; additional latency | Use a smaller/faster model (Haiku) for verification; reserve for high-stakes decisions. |
| Structured output with confidence | Enables programmatic filtering | Some models struggle with strict JSON format | Use a pydantic/schema validator; retry once on parse failure. |
| Human-in-the-loop for uncertain outputs | Catches errors before they cause damage | Increases review workload | Tune thresholds to keep human review rate < 10%; automate only high-confidence outputs. |
| Hallucination tests in CI | Catches prompt regressions | Requires maintaining test cases | 5–10 test cases per workflow; update when model or prompt changes. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Grounding source unavailable (NVD API down) | CVE lookup returns error; workflow stalls | `llm_grounding_source_used_total` drops; errors rise | Cache last-known NVD data; fall back to human review for all CVE tasks during outage. |
| Model update changes hallucination rate | More unverified outputs; review queue grows | `llm_human_review_triggered_total` spikes after model update | Run hallucination test suite after any model version change. |
| Verifier model hallucinates agreement | Cross-model check passes a hallucinated claim | Both models agree on wrong answer (correlated errors) | Use models from different families for primary and verifier to reduce correlation. |
| Threshold too low | All outputs require human review | Review rate near 100%; automation provides no value | Raise confidence threshold; improve prompts to produce more confident grounded output. |
| Prompt injection via threat intel feed | LLM follows injected instruction in feed data | Anomalous action triggered; output doesn't match input intent | Apply prompt injection detection to all untrusted input before passing to LLM. |
| Missing CVE causes false "not found" | Real CVE that NVD hasn't indexed yet | Legitimate CVE treated as hallucination | Add a secondary source (MITRE CVE list, GitHub Advisory); log "not in primary source" not "hallucination". |

## Related Articles

- [LLM Prompt Security Patterns](/articles/ai-landscape/llm-prompt-security-patterns/)
- [AI Agent Output Verification](/articles/ai-landscape/ai-agent-output-verification/)
- [Claude for Security Detection](/articles/ai-landscape/claude-security-detection/)
- [AI-Powered Security Assessments](/articles/ai-landscape/ai-powered-security-assessments/)
- [Multi-Modal Model Attack Surfaces](/articles/ai-landscape/multimodal-attack-surfaces/)
