---
title: "Detection-as-Code with Sigma: Versioned, Tested, Vendor-Neutral SIEM Rules"
description: "Detection logic scattered across SIEM consoles and shell scripts does not scale. Sigma rules in Git, tested in CI, converted to any backend on deploy, do."
slug: "detection-as-code-sigma"
date: 2026-04-24
lastmod: 2026-04-24
category: "observability"
tags: ["detection", "sigma", "siem", "detection-as-code", "splunk", "elastic"]
personas: ["security-engineer", "sre", "soc-analyst"]
article_number: 169
difficulty: "intermediate"
estimated_reading_time: 15
published: true
layout: article.njk
permalink: "/articles/observability/detection-as-code-sigma/index.html"
---

# Detection-as-Code with Sigma: Versioned, Tested, Vendor-Neutral SIEM Rules

## Problem

Most security teams maintain detection logic in three incompatible places: the SIEM's rule editor (Splunk SPL, Elastic KQL, Sentinel KQL, Chronicle YARA-L), a folder of shell and Python scripts that grep through logs, and tribal knowledge — what the on-call analyst remembers to check during an incident. Each of these has structural problems:

- **Console-edited rules are not versioned.** When a rule changes, there is no record of what it used to be, who changed it, or why.
- **Rules are vendor-locked.** The SPL that catches a specific attack pattern in Splunk does not translate to the KQL in Sentinel. Switching SIEMs or sending the same events to multiple backends duplicates the maintenance.
- **Rules are not tested.** Nobody knows if the rule still fires on the attack it was built for, or if it silently broke when the log schema changed.
- **New rules land without review.** There is no pull-request flow, no CODEOWNERS, no diff for the SOC lead to approve before the rule goes live.
- **False positives are invisible.** A rule that fires 10,000 times a day gets muted at the analyst level and nobody upstream knows.

Detection-as-code solves this by treating detection rules like any other software artifact: stored in Git, written in a vendor-neutral DSL, tested in CI against known-good and known-bad log samples, and deployed automatically to the SIEM via API.

[Sigma](https://sigmahq.io/) is the open-source generic signature format for SIEM content. A Sigma rule is a YAML document describing a detection pattern; `sigma-cli` converts it to any backend query language (SPL, KQL, Lucene, Kusto, YARA-L, Panther, Sumo Logic). The same rule file produces the correct query for every SIEM you run.

This article covers the Sigma rule format, repository structure, CI testing patterns, conversion to backend queries, and deployment automation.

**Target systems:** Sigma specification v2.0+, `sigma-cli` (Python), `pySigma` library. Works with Splunk, Elastic SIEM, Microsoft Sentinel, Chronicle, Sumo Logic, QRadar, LogRhythm, Panther, Wazuh, CrowdStrike Logscale.

## Threat Model

The detection ruleset itself is an attack surface.

- **Adversary 1 — Detection evasion:** attacker with knowledge of your ruleset (leaked, inferred through probing, or from a former employee) crafts activity that stays just outside the rule's conditions.
- **Adversary 2 — Detection tampering:** insider or attacker with SIEM console access disables a rule, muting alerts for their ongoing activity.
- **Adversary 3 — Alert fatigue exploitation:** attacker generates legitimate-looking activity that triggers poorly-tuned rules, burying real alerts in noise so analysts miss the actual compromise.
- **Access level:** Adversary 1 requires visibility into rules (often via a former-employee leak or published commercial ruleset). Adversary 2 requires SIEM admin credentials. Adversary 3 requires no special access.
- **Objective:** Operate inside your monitoring blind spots, mute detection of ongoing actions, or exhaust SOC capacity so real incidents are missed.
- **Blast radius:** Missed detection of post-compromise activity (lateral movement, data exfiltration, privilege escalation), leading to extended dwell time and larger eventual incident scope.

## Configuration

### Step 1: Repository Structure

```
detections/
├── rules/
│   ├── windows/
│   │   ├── process-creation/
│   │   │   ├── mimikatz-command-line.yml
│   │   │   ├── psexec-remote-execution.yml
│   │   │   └── powershell-base64-encoded.yml
│   │   └── authentication/
│   │       └── kerberoasting-detection.yml
│   ├── linux/
│   │   ├── auditd/
│   │   │   ├── suspicious-cron-modification.yml
│   │   │   └── sudo-to-root.yml
│   │   └── process-creation/
│   │       └── reverse-shell-one-liners.yml
│   └── cloud/
│       ├── aws/
│       │   ├── iam-privilege-escalation.yml
│       │   └── cloudtrail-logging-disabled.yml
│       └── gcp/
│           └── service-account-key-creation.yml
├── tests/
│   ├── fixtures/
│   │   └── windows/
│   │       └── mimikatz-logon-passwords.json   # known-malicious log
│   └── benign/
│       └── windows/
│           └── admin-process-creation.json     # known-benign logs
├── pipelines/
│   └── backend-configs/
│       ├── splunk.yml
│       ├── elasticsearch.yml
│       └── sentinel.yml
├── .github/workflows/
│   ├── test.yml       # validate and test on PR
│   └── deploy.yml     # deploy to SIEM on merge to main
└── CODEOWNERS
```

Every rule lives in a category-oriented path. Every rule has matching test fixtures. Backend-specific configuration lives separately — the rules themselves are vendor-neutral.

### Step 2: Writing a Sigma Rule

```yaml
# rules/windows/process-creation/mimikatz-command-line.yml
title: Mimikatz Command Line Artifacts
id: 06d71506-7beb-4f22-8888-e2e5e2ca7fd8
status: stable
description: >
  Detects process creation events containing command-line patterns
  characteristic of Mimikatz, even when the binary is renamed.
references:
  - https://github.com/gentilkiwi/mimikatz/wiki
  - https://attack.mitre.org/techniques/T1003/001/
author: security-team
date: 2026-04-24
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  category: process_creation
  product: windows
detection:
  mimikatz_cli:
    CommandLine|contains:
      - 'sekurlsa::logonpasswords'
      - 'sekurlsa::wdigest'
      - 'kerberos::ptt'
      - 'lsadump::sam'
      - 'crypto::certificates'
  condition: mimikatz_cli
falsepositives:
  - Penetration testing activity
  - Red-team engagements
level: critical
fields:
  - CommandLine
  - ParentImage
  - Image
  - User
  - ProcessId
```

The `id` is a UUID that stays constant across refactors. The `level` maps to SIEM severity. The `falsepositives` array forces the author to document known benign triggers at the time of writing.

### Step 3: Lint and Validate on PR

```yaml
# .github/workflows/test.yml
name: Test Sigma rules
on:
  pull_request:
    paths:
      - 'rules/**'
      - 'tests/**'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: |
          pip install sigma-cli pysigma pysigma-backend-splunk \
                      pysigma-backend-elasticsearch

      # Syntax and schema validation.
      - name: Validate Sigma rules
        run: sigma check rules/

      # Ensure every rule has a matching test fixture.
      - name: Ensure test coverage
        run: |
          python scripts/check_test_coverage.py

      # Convert rules to each backend, catch conversion failures early.
      - name: Convert to Splunk
        run: sigma convert -t splunk -p splunk-windows rules/ -o /tmp/splunk.spl
      - name: Convert to Elasticsearch
        run: sigma convert -t esql -p ecs_windows rules/ -o /tmp/esql.txt

      # Run detection against fixtures.
      - name: Test detection against known-malicious fixtures
        run: python scripts/test_detections.py --fixtures tests/fixtures/
      - name: Test against benign fixtures (no false positives)
        run: python scripts/test_detections.py --benign tests/benign/ --expect-no-match
```

The coverage check:

```python
# scripts/check_test_coverage.py
# Every rule must have a matching .json fixture in tests/fixtures/ or tests/benign/.
import sys, pathlib, yaml

rules = list(pathlib.Path("rules").rglob("*.yml"))
missing = []
for r in rules:
    data = yaml.safe_load(r.read_text())
    rule_id = data.get("id")
    fixture_paths = list(pathlib.Path("tests").rglob(f"*{rule_id}*"))
    if not fixture_paths:
        missing.append(str(r))
if missing:
    print("Rules without fixtures:", *missing, sep="\n  ")
    sys.exit(1)
```

Fixture example:

```json
{
  "_meta": {
    "rule_id": "06d71506-7beb-4f22-8888-e2e5e2ca7fd8",
    "expected": "match",
    "description": "Mimikatz logonpasswords invocation captured from Sysmon event 1"
  },
  "events": [
    {
      "EventID": 1,
      "Image": "C:\\temp\\not-mimikatz.exe",
      "CommandLine": "not-mimikatz.exe \"sekurlsa::logonpasswords\" exit",
      "User": "CORP\\admin",
      "ParentImage": "C:\\Windows\\System32\\cmd.exe",
      "ProcessId": 4321
    }
  ]
}
```

The fixture test converts the rule to its native form, replays events through a stub evaluator, and asserts a match (or non-match, for benign fixtures).

### Step 4: Backend Pipelines for Log-Schema Translation

Raw log events have different field names per platform. Sysmon calls the command line `CommandLine`; a SIEM's normalized schema might call it `process.command_line`. [`pySigma`](https://github.com/SigmaHQ/pySigma) uses pipelines to translate.

```yaml
# pipelines/backend-configs/splunk.yml
name: splunk-windows
priority: 20
transformations:
  - id: sysmon_source
    type: add_condition
    conditions:
      source: 'WinEventLog:Microsoft-Windows-Sysmon/Operational'
    rule_conditions:
      - type: logsource
        product: windows
        category: process_creation
  - id: field_rename_commandline
    type: field_name_mapping
    mapping:
      CommandLine: CommandLine
      Image: Image
    rule_conditions:
      - type: logsource
        product: windows
```

The same Sigma rule now generates a Splunk query that targets the Sysmon source and uses the correct field names. For Elastic, a different pipeline maps `CommandLine` to `process.command_line`.

### Step 5: Deploy to SIEM Backends

```yaml
# .github/workflows/deploy.yml
name: Deploy rules to SIEM
on:
  push:
    branches: [main]
    paths:
      - 'rules/**'
      - 'pipelines/**'

jobs:
  splunk:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install sigma-cli pysigma-backend-splunk

      - name: Convert rules
        run: |
          sigma convert -t splunk -p splunk-windows \
                       -f savedsearches \
                       rules/ -o splunk-savedsearches.conf

      - name: Push to Splunk via REST
        env:
          SPLUNK_TOKEN: ${{ secrets.SPLUNK_HEC_TOKEN }}
        run: |
          python scripts/sync_splunk.py splunk-savedsearches.conf

  elastic:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
      - run: pip install sigma-cli pysigma-backend-elasticsearch

      - name: Convert rules to Elastic Detection format
        run: |
          sigma convert -t esql -p ecs_windows \
                       -f kibana-ndjson \
                       rules/ -o elastic-rules.ndjson

      - name: Push to Elastic via API
        env:
          KIBANA_URL: ${{ vars.KIBANA_URL }}
          KIBANA_API_KEY: ${{ secrets.KIBANA_API_KEY }}
        run: |
          curl -X POST "$KIBANA_URL/api/detection_engine/rules/_import" \
               -H "Authorization: ApiKey $KIBANA_API_KEY" \
               -H "kbn-xsrf: true" \
               -F file=@elastic-rules.ndjson
```

The deploy step is idempotent — re-running it produces the same set of rules. Rules removed from the repo are also removed from the SIEM (after a safety check that flags large-scale deletions).

## Expected Behaviour

| Signal | Console-Managed | Detection-as-Code |
|--------|-----------------|-------------------|
| Rule history | Unknown | Full Git log, per-rule |
| Vendor lock-in | One SIEM gets the rule, others duplicate | One rule generates queries for every SIEM |
| Rule review | Analyst clicks "Save" | Pull request with CODEOWNERS approval |
| Test coverage | Informal | Every rule has known-malicious and known-benign fixtures |
| False-positive baseline | Discovered in production | Measured in CI against benign fixtures |
| Rollback | Manual revert in console; lost metadata | `git revert` + auto-deploy |
| Multi-SIEM sync | Manual per platform | Single commit deploys everywhere |

Instrument the deploy pipeline:

```
sigma_rules_total                     gauge
sigma_rules_deployed_total{backend}   counter
sigma_rules_failed_to_convert_total   counter
sigma_rule_test_pass_ratio            gauge
```

## Trade-offs

| Control | Security Benefit | Cost | Mitigation |
|---------|------------------|------|------------|
| Version control | Full history, PR review, blame | PRs add latency to urgent detection updates | Provide a fast-track workflow for P1 incidents: direct commit to `hotfix/` branch with post-hoc review. |
| Multi-backend conversion | Same rule in Splunk + Elastic + Sentinel | `pySigma` conversion has edge cases; complex rules may not convert cleanly to every backend | Write rules against the common denominator of supported features; fall back to backend-native queries for rules that cannot be expressed in Sigma. Flag them explicitly. |
| Test fixtures | Detects silent regressions when log schema changes | Every new rule requires creating fixtures | Auto-extract fixtures from production logs (with appropriate redaction) when the rule first fires. |
| Automated deploy | No console drift | Deploy requires API credentials to each SIEM; compromise would allow rule manipulation | Scope tokens to minimum — rule create/update/delete only. Rotate quarterly. Audit-log every deploy. |
| CODEOWNERS on rules dir | Prevents accidental merge of risky rules | Slows down contributions from outside the SOC | Invite SOC engineers as reviewers on detection PRs; autoapprove cosmetic changes via a bot. |
| Benign-fixture regression tests | Catches false-positive-prone rules before prod | Benign fixtures require ongoing curation | Extract benign fixtures from production logs weekly; rotate them into the test set automatically. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Rule does not convert to a backend | CI fails on `sigma convert` step | GitHub Actions status red | Simplify the rule to avoid backend-unsupported features, or mark the rule `backend: splunk-only` in frontmatter and skip other conversions. |
| Log schema change breaks field mapping | Rule does not fire on new events; fixture tests still pass | Backend queries return zero results for events that should match; real incidents missed | Keep fixtures in sync with production log shape. Add a fixture-refresh job that samples production logs and re-generates the test set weekly. |
| Rule deploys with typo, breaks SIEM | SIEM rejects the imported rule; deploy fails mid-batch | CI deploy step fails with SIEM-specific error | Deploy idempotently; failed rules do not affect succeeded ones. Fix typo, re-deploy. For Splunk, use `savedsearches.conf` with atomic replace to avoid partial state. |
| Large rule deletion disables monitoring | `rules/windows/` removed in a bad rebase; SIEM rules disappear | Detection coverage drops; alert-volume metric drops sharply | Add a pre-deploy safety check: if deleted rules > 10% of total, require a `allow-large-delete: true` label on the PR before the deploy job runs. |
| Secret leakage via rule content | Rule contains a hardcoded password or API key as a detection string | Git history retains the value; pre-receive hooks catch on next push | Scan rules for secret patterns in CI. Revoke any credential that appeared in a rule; do not use real production values as detection strings. |
| Backend API credential compromise | Attacker uses the deploy token to disable or modify rules | Audit log on the SIEM shows rule changes outside normal deploy windows | Require the deploy pipeline to run from a specific IP range; rotate credentials quarterly; alert on rule changes that do not correlate to a Git deploy. |

## When to Consider a Managed Alternative

Running detection-as-code at scale requires CI infrastructure, backend-specific pipelines, schema maintenance, fixture curation, and multi-SIEM deploy automation (6-14 hours/month for a medium SOC).

- **[Panther](https://panther.com/):** detection-as-code built-in. Rules written in Python, testing and deploy integrated.
- **[Sumo Logic Cloud SIEM](https://www.sumologic.com/solutions/cloud-siem-enterprise):** rule lifecycle managed by the vendor; supports Sigma-format imports.
- **[Chronicle Security Operations (Google)](https://cloud.google.com/security/products/security-operations):** YARA-L rules with native version control integration.
- **[SigmaHQ community rules](https://github.com/SigmaHQ/sigma):** 2,500+ open-source Sigma rules; pull directly into your repo as a starting baseline.

## Related Articles

- [Writing Detection Rules That Catch Real Attacks](/articles/observability/detection-rules/)
- [Building a Security Audit Log Pipeline That Scales](/articles/observability/audit-log-pipeline/)
- [Centralized Logging Architecture for Security](/articles/observability/centralized-logging/)
- [eBPF Runtime Security with Tetragon](/articles/observability/ebpf-tetragon/)
- [Lateral Movement Detection](/articles/observability/lateral-movement-detection/)
