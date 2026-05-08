---
title: "AI-Assisted Code Scanning: Copilot Autofix, DeepCode AI, and Evaluating Fix Quality"
description: "GitHub Copilot Autofix, Snyk DeepCode AI, and Amazon CodeGuru generate automated fixes for security findings — but AI-generated patches can introduce new vulnerabilities, incomplete fixes, or contextually wrong remediations. This guide evaluates AI autofix tools for security, covers fix quality assessment, safe review workflows, and the risks of blindly merging AI-suggested security patches."
slug: ai-code-scanning-autofix
date: 2026-05-08
lastmod: 2026-05-08
category: ai-landscape
tags:
  - ai-code-scanning
  - copilot-autofix
  - sast
  - ai-security
  - secure-coding
personas:
  - security-engineer
  - platform-engineer
article_number: 646
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/ai-landscape/ai-code-scanning-autofix/
---

# AI-Assisted Code Scanning: Copilot Autofix, DeepCode AI, and Evaluating Fix Quality

## Problem

Static analysis tools have always identified more vulnerabilities than developer teams can remediate. The bottleneck is not detection — it is the human effort required to understand a finding, locate the right fix, apply it consistently across all affected call sites, and validate that the change does not break functionality or introduce a regression. AI autofix tools promise to close this gap by generating code patches automatically. GitHub Copilot Autofix, Snyk DeepCode AI, and Amazon CodeGuru Security each attach a suggested code change directly to a security finding, collapsing remediation time from hours to minutes.

The promise is real. In controlled evaluations, AI autofix tools reduce mean time to remediation for well-understood vulnerability classes — SQL injection, XSS, path traversal — by a significant margin. Development teams under pressure to clear security backlogs find the tooling compelling. The risk is equally real: AI-generated security patches are suggestions from a model trained on public code. That model has learned from repositories that contain insecure patterns, does not know your specific threat model, cannot reason about downstream security controls, and generates fixes that are plausible rather than correct.

The critical failure mode is not that AI-generated fixes are always wrong. It is that they look right. An AI fix for a SQL injection finding that adds input sanitisation instead of a parameterised query will pass code review by a tired developer, pass functional tests, and satisfy the SAST scanner — while remaining exploitable under certain inputs. A fix for a credential comparison that introduces string normalisation before the comparison may inadvertently create a timing side channel. An auto-merge workflow that treats a positive AI suggestion as equivalent to a security engineer's review amplifies this risk across the entire codebase.

### The Trust Boundary

AI autofix models are trained on publicly available code. This creates a specific class of problem: the model has seen vast amounts of code that attempts to fix the same categories of vulnerability, including code that implements incomplete or incorrect fixes. When the model generates a suggestion, it is pattern-matching against this training distribution — producing fixes that are statistically likely rather than provably correct. The model does not have access to your application's trust boundaries, your deployment environment, what sanitisation has already happened upstream, or which inputs are attacker-controlled. Every AI-generated security fix must be evaluated with this constraint in mind.

## Threat Model

**Auto-merged insufficient fix.** A developer receives a Copilot Autofix suggestion for a SQL injection finding. The suggested fix wraps the user input in an escaping function rather than converting the query to use a parameterised statement. The fix passes the SAST scanner because the rule fires on unescaped input reaching a query, and the escaping function satisfies that check. The fix is merged. The application remains vulnerable to SQL injection via second-order attacks, encoding bypasses, or character set mismatches. The false confidence introduced by the "fixed" finding is more dangerous than the original open finding.

**Timing side channel introduction.** An AI fix for a hardcoded credential or insecure credential comparison replaces a direct string comparison with a normalisation step — for example, lowercasing both values before comparing. The fix is functionally correct for case-insensitive matching. It introduces a timing side channel: the normalisation operation takes variable time depending on input length and content, allowing an attacker to infer information about the secret through repeated requests. A constant-time comparison function was required; the AI did not suggest it because the training data associated "fix credential comparison" with "normalise inputs", not with "use hmac.compare_digest or a constant-time equivalence function".

**Security control bypass through restructuring.** An AI fix reorganises code to address a path traversal finding by validating the filename early in the function. The restructuring also moves the validation before an existing permission check, or changes the code path in a way that bypasses a downstream authorisation control that was not visible to the AI in its context window. The SAST finding is resolved. The authorisation bypass is not detected.

## Configuration and Implementation

### GitHub Copilot Autofix

GitHub Copilot Autofix is integrated directly into GitHub Advanced Security (GHAS) and activates on code scanning alerts in pull requests. When a SAST rule fires on a PR, Autofix generates a suggested patch, a description of the change, and — in many cases — a test case demonstrating that the fix addresses the finding.

Autofix is triggered automatically when a code scanning alert is created on a PR and when developers request a fix from the alert view. The suggested patch is presented as a diff that the developer can apply with a single click or dismiss. There is no mandatory review gate: a developer can apply an Autofix suggestion without any security team involvement.

**Configuring Autofix in your organisation:**

```yaml
# .github/workflows/codeql.yml
name: CodeQL Analysis
on:
  pull_request:
    branches: [main, develop]

jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
      pull-requests: write   # Required for Autofix to post suggestions
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: javascript, python
      - uses: github/codeql-action/autobuild@v3
      - uses: github/codeql-action/analyze@v3
        with:
          category: /language:javascript
```

To require security champion review before Autofix patches are merged, add a branch protection rule requiring review from a `security-champions` team for any PR that modifies files matched by a CODEOWNERS pattern covering security-sensitive paths.

**Security engineer checklist for reviewing Autofix suggestions:**

Before accepting any Autofix suggestion, work through the following questions:

1. **Root cause or symptom?** Does the fix address why the vulnerability exists, or does it apply a surface-level filter? A parameterised query addresses root cause. An escaping wrapper addresses the symptom and may be bypassable.
2. **Secure API or sanitisation function?** For injection vulnerabilities, the fix should use a structured API that separates code from data. Sanitisation functions that modify input are weaker: they depend on completeness (covering all attack vectors) and correctness (handling encoding, character sets, null bytes).
3. **All call sites fixed?** SAST tools often flag a single instance of a pattern. The AI may fix only the flagged instance. Check whether the same vulnerable pattern appears elsewhere in the codebase using the "find all references" or a grep for the same call pattern.
4. **Functionality preserved?** Does the fix change observable behaviour in non-security edge cases? Run the full test suite. Check whether the fix handles null inputs, empty strings, and non-ASCII characters.
5. **New security issues introduced?** Read the diff as an attacker. Does the fix add new imports from third-party libraries? Does it change the control flow in a way that affects other security properties? Does it introduce any form of deserialization, eval, or dynamic code execution?

**Workflow with Autofix:**

```
Autofix suggestion created on PR
         ↓
Assigned to security champion (via CODEOWNERS + required review)
         ↓
Security champion applies five-point checklist
         ↓
    ┌────┴────┐
    │         │
Adequate    Inadequate
    │         │
  Merge    Request human implementation
             (Autofix suggestion dismissed with explanation)
```

### Snyk DeepCode AI

Snyk DeepCode AI is available in the Snyk VS Code extension, JetBrains plugin, and Snyk CI/CD integrations. DeepCode's distinguishing architecture is interprocedural data flow analysis: rather than flagging a single statement, DeepCode traces the data flow from source (user-controlled input) through all transformations to the sink (dangerous function call), and generates a fix suggestion that addresses the source of the taint rather than adding sanitisation at intermediate points.

In the Snyk VS Code extension, DeepCode AI fix suggestions appear inline alongside the finding. In CI/CD pipelines, suggestions are available via the Snyk API and can be surfaced in PR comments.

**Evaluating DeepCode suggestion quality by vulnerability type:**

For SQL injection, DeepCode typically suggests converting string-concatenated queries to parameterised statements and adds the import for the parameterised query API if it is not already present. This is generally adequate. Verify that the suggested parameterisation covers all parameters in the query, not just the flagged one.

For XSS in JavaScript/TypeScript, DeepCode suggestions vary in quality. Context-aware output encoding — encoding differently for HTML body, HTML attribute, JavaScript context, and URL context — is the correct fix. Suggestions that add a single HTML-escaping function are adequate only for HTML body context and inadequate for the others. Always check which output context the flagged code writes into.

For path traversal, DeepCode often suggests resolving the path to its canonical form and checking that it starts with the expected base directory. This is generally correct, but verify that the check uses a strict prefix match (with a trailing separator) rather than a substring check. `path.startswith('/allowed/dir')` incorrectly allows `/allowed/dir.malicious/`.

**DeepCode configuration in CI pipeline:**

```yaml
# snyk-security.yml (GitHub Actions)
- name: Snyk Code Analysis
  uses: snyk/actions/node@master
  env:
    SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
  with:
    args: --severity-threshold=high --sarif-file-output=snyk-code.sarif

- name: Upload SARIF to GitHub
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: snyk-code.sarif
```

### Amazon CodeGuru Security

Amazon CodeGuru Security provides automated remediation suggestions integrated into AWS CodePipeline, CodeCommit PRs, and the AWS console. It focuses on Java and Python codebases and is tuned for AWS-hosted applications.

CodeGuru's fix suggestions follow AWS SDK best practices: for hardcoded credentials, it suggests replacing the literal with a call to AWS Secrets Manager or Parameter Store. For SSRF vulnerabilities, it suggests adding URL validation against an explicit allowlist. Suggestions are available in the CodeGuru console and via the CodeGuru API for programmatic integration.

Fix quality for Java findings is generally higher than for Python, reflecting the composition of CodeGuru's training data. For Python, evaluate suggestions against the same checklist used for Copilot Autofix, with particular attention to whether the suggested fix uses the most idiomatic secure library for the Python ecosystem (e.g., `sqlalchemy` parameterised queries rather than manual escaping).

## Fix Quality Evaluation Framework

The following table summarises expected AI fix patterns by vulnerability type and provides guidance on adequacy and review focus.

| Vulnerability | Typical AI Fix Approach | Adequate? | Review Focus |
|---|---|---|---|
| SQL injection | Parameterised query (Copilot, DeepCode) or input escaping (weaker tools) | Parameterised: yes. Escaping: no. | Check all query parameters are bound, not just the flagged one. Verify ORM usage doesn't fall back to raw interpolation. |
| XSS | HTML entity encoding function | Context-dependent | Verify output context: HTML body, attribute, JS, URL each require different encoding. Generic HTML escape is insufficient for JS context. |
| Path traversal | Canonical path + prefix check | Yes, if prefix check is strict | Ensure trailing separator in prefix check. Validate on the OS-resolved path, not the raw input string. |
| Hardcoded credentials | Environment variable reference | Partial | Environment variable reference removes the hardcoded value but does not implement rotation, auditing, or least-privilege access. Vault integration is the complete fix. |
| SSRF | URL scheme allowlist check | No | Scheme check (`http://`, `https://`) is insufficient. Full SSRF mitigation requires allowlisting specific hosts and blocking internal IP ranges. AI suggestions rarely implement IMDS blocking. |
| Insecure deserialization | Switch to safe deserializer | Yes | Verify the replacement deserializer has no unsafe modes that can be re-enabled via configuration. |
| Weak cryptography | Algorithm substitution | Yes, with caveats | Verify key length, mode of operation (ECB vs GCM), and IV handling are also corrected, not just the algorithm name. |

## Testing AI-Generated Fixes

Accepting an AI fix and running the existing test suite is insufficient to validate security adequacy. The test suite was written to verify functional behaviour, not to test adversarial inputs.

**Adversarial test cases for AI fixes:**

After applying an AI fix for an injection vulnerability, add test cases that exercise known bypass techniques for the fix type:

```python
# Example: testing a SQL injection fix that used escaping (inadequate)
# These should all be handled safely — if escaping was used, some may not be

@pytest.mark.parametrize("payload", [
    "'; DROP TABLE users; --",           # Classic injection
    "\\'; DROP TABLE users; --",         # Escaped quote bypass attempt
    "%27; DROP TABLE users; --",         # URL-encoded quote
    "1 OR 1=1",                          # Boolean injection
    "1; WAITFOR DELAY '0:0:5'--",        # Time-based blind injection
    "\x00' OR '1'='1",                   # Null byte injection
])
def test_sql_injection_fix_resists_payloads(payload):
    # Should raise an exception or return no results, not execute injected SQL
    result = get_user_by_name(payload)
    assert result is None or isinstance(result, list) and len(result) == 0
```

**Post-fix SAST scan:** Re-run the SAST scanner on the modified code immediately after applying the fix. Confirm that the original finding is resolved (not just suppressed) and that no new findings have been introduced by the change. Autofix suggestions that resolve a finding by suppressing the alert rather than changing the code are a red flag.

**Peer review of AI diff:** Treat the AI-generated diff as code authored by an unfamiliar developer. Review the diff in its entirety, not just the flagged lines. Security-relevant changes often have ripple effects that only become visible when reading the full function.

## Measuring AI Autofix Programme Effectiveness

Track the following metrics to assess whether your AI autofix programme is genuinely improving security posture or creating false confidence:

- **Autofix suggestion rate:** The percentage of SAST findings for which an AI tool generates a fix suggestion. Low rates indicate the tool is not providing value for your codebase's language or pattern mix.
- **Security champion acceptance rate:** The percentage of suggestions that pass the review checklist and are accepted as-is. Declining rates may indicate suggestion quality is degrading or reviewers are becoming more rigorous.
- **Fix adequacy rate:** The percentage of accepted fixes for which no regression (reopened finding, related incident, penetration test finding) is observed within 30 days. This is the most important quality signal.
- **Time-to-remediate delta:** Mean time to close a security finding with AI autofix assistance compared to without. Meaningful acceleration (>30% reduction) suggests the tool is delivering value. Acceleration with declining adequacy rates indicates speed is being prioritised over security.
- **Regression detection:** Track findings that are closed via AI autofix and later reopened or identified as incompletely fixed. Build this as an automated query against your security findings database.

## When Not to Use AI Autofix

AI autofix is appropriate for well-understood, high-volume, syntactically localised vulnerability classes — SQL injection, basic XSS, path traversal — where the correct fix pattern is mechanical and does not require knowledge of your application's specific threat model.

Do not use AI autofix as the sole remediation path for:

**Authentication and authorisation code.** The correct fix for an authorisation vulnerability is rarely adding a check at a single code location. It typically requires understanding the full request lifecycle, the session model, and the trust boundaries between components. AI does not have this context. A fix that adds an authorisation check in the wrong location, or that is conditional on state the AI did not observe, can create a false sense of security while leaving the underlying bypass available.

**Cryptographic implementations.** AI models associate "fix weak cryptography" with "change the algorithm name". Correct cryptographic implementation requires correct key management, correct IV/nonce handling, correct mode of operation, correct padding, and correct output encoding. AI-suggested cryptographic fixes frequently correct one of these properties while leaving others vulnerable. Cryptographic code should be reviewed by a developer with specific expertise, not fixed by autofix.

**Business logic security vulnerabilities.** Race conditions in financial transaction processing, order-of-operations vulnerabilities in multi-step workflows, and trust boundary violations in multi-tenant systems require understanding of your specific data model and business rules. No AI tool trained on public code has this context. Fixes for these findings must come from engineers who understand the full system.

**Critical infrastructure and safety-relevant code.** The risk of a subtle AI-introduced bug in code that controls infrastructure, handles failover, or implements safety interlocks is not worth the remediation speed gain. Human review is mandatory.

## Expected Behaviour by Vulnerability Class

| Vulnerability class | AI tool | Fix pattern | Adequate? | Review time saved |
|---|---|---|---|---|
| SQL injection (simple) | Copilot Autofix, DeepCode | Parameterised query conversion | Yes | High (~70%) |
| SQL injection (ORM) | Copilot Autofix | ORM parameterised binding | Yes, usually | Medium (~50%) |
| Reflected XSS (HTML body) | Copilot Autofix, DeepCode | HTML entity encoding | Yes | High (~70%) |
| Stored XSS (JS context) | All tools | Generic HTML escape | No | Low (~10%) |
| Path traversal | DeepCode, CodeGuru | Canonical path + prefix | Usually | Medium (~50%) |
| Hardcoded secret | Copilot Autofix, CodeGuru | Env var reference | Partial | Medium (~40%) |
| SSRF | All tools | URL scheme check | No | Very low (~5%) |
| Insecure deserialization | DeepCode | Safe deserializer swap | Usually | Medium (~50%) |
| Timing side channel | All tools | Not reliably detected | N/A | N/A |
| Authorisation bypass | All tools | Highly variable | Rarely | Very low (~5%) |

## Trade-offs

**Review time saved versus risk of inadequate fixes.** For SQL injection with parameterised query conversion, AI autofix genuinely accelerates remediation with acceptable adequacy rates. For SSRF and authorisation issues, the suggestion quality is too low to provide meaningful time savings after accounting for the review effort required to identify inadequacy. Calibrate your team's use of AI autofix to vulnerability classes where it demonstrably performs well in your codebase.

**Developer over-reliance on AI suggestions.** The most significant long-term risk of AI autofix is not any individual inadequate fix — it is the erosion of security engineering skill within development teams. When developers consistently accept AI-generated fixes without reasoning through the root cause, they lose the ability to identify when a fix is wrong. Security champions and security engineers must actively maintain and reinforce security engineering knowledge rather than deferring entirely to AI.

**Coverage gaps for complex vulnerabilities.** AI autofix tools have high suggestion rates for syntactically local vulnerability patterns and very low rates for vulnerabilities that require interprocedural or cross-service reasoning. This creates a coverage illusion: teams see high fix rates in their dashboards while the most significant vulnerabilities — logic flaws, authorisation bypasses, trust boundary violations — remain unaddressed because no AI suggestion was generated for them.

## Failure Modes

**Functionally correct, security-inadequate auto-merge.** The highest-frequency failure mode. The fix resolves the immediate SAST finding, passes tests, and is merged with minimal review. The vulnerability class remains exploitable through vectors the AI did not consider. Detectable only through adversarial testing or penetration testing after the fact.

**Fix introduces new vulnerability.** Occurs when the AI restructures code to address a finding and the restructuring creates a new vulnerability — a missing authorisation check, an exploitable race condition, an import of a vulnerable library. Most likely when the AI is operating on complex, poorly-structured code where the relationship between security controls is not visible in the local context window.

**Fix breaks edge-case tests in production.** The AI fix handles the common input path correctly but fails on inputs outside the standard ASCII range, on empty inputs, or under concurrent access. Functional tests pass. Production incidents occur. This failure mode is distinct from security inadequacy but has security consequences when it occurs in authentication or access control code.

**Suppression masquerading as remediation.** Some AI fix suggestions resolve a finding by adding a SAST suppression comment rather than changing the code. This is indistinguishable from a genuine fix in dashboard metrics. Review your accepted fix diff list periodically for suppression-based "fixes".

The correct posture is to use AI autofix as a tool for generating fix candidates, not as an automated remediation system. Every suggestion requires review by someone who understands the vulnerability class, the fix pattern, and the application's specific security requirements. The review should be structured — not a casual glance at the diff — and should be enforced by workflow controls that prevent auto-merge of security-related AI suggestions. Used with that discipline, AI autofix tools provide genuine value. Used without it, they create a remediation theatre that makes security posture appear to improve while leaving applications exploitable.
