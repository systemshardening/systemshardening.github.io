---
title: "Building a Security Policy for Your Open Source Project: SECURITY.md, CVE Workflow, and Community Trust"
description: "An open source project without a security policy forces researchers to choose between silent disclosure and public exploitation — neither helps your users. A SECURITY.md, private reporting channel, CVE workflow, and clear disclosure timeline turns security reports into trust-building opportunities. This guide builds a complete security programme for open source project maintainers, from first report to post-disclosure retrospective."
slug: oss-security-policy
date: 2026-05-08
lastmod: 2026-05-08
category: cross-cutting
tags:
  - open-source-security
  - security-policy
  - responsible-disclosure
  - cve
  - community-security
personas:
  - security-engineer
  - platform-engineer
article_number: 655
difficulty: Intermediate
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/cross-cutting/oss-security-policy/
---

# Building a Security Policy for Your Open Source Project: SECURITY.md, CVE Workflow, and Community Trust

## Problem

Most open source projects have no documented security policy. GitHub's own research has found that the majority of popular repositories lack a `SECURITY.md` file. The practical consequence is a trilemma for every security researcher who finds a vulnerability: open a public issue (potentially arming attackers before a fix exists), email a maintainer address that may not be monitored, or wait indefinitely with no idea whether anyone has noticed. None of these outcomes help users.

For maintainers, the gap is symmetrical. Without a structured intake channel, a critical vulnerability might sit in a maintainer's spam folder, get filed as a generic bug and triaged at low priority, or appear in a public tweet before a patch exists. The absence of a security policy doesn't prevent vulnerabilities — it prevents the coordinated response that limits their impact.

The stakes extend beyond responsible disclosure ethics. Projects without a `SECURITY.md` score lower on the [OpenSSF Scorecard](https://securityscorecards.dev/), which evaluates open source projects across ten security criteria. The "Security-Policy" check is binary: either a security policy exists and is findable, or the project loses that point. Google's `deps.dev` surfaces OpenSSF Scorecard data alongside dependency information, meaning enterprises evaluating your project as a dependency will see that gap. Enterprise procurement teams increasingly require demonstrable security policies before adopting open source software — projects without them are deprioritised or rejected outright.

The spectrum of open source security maturity runs from complete absence to full coordinated disclosure practice. At the low end: no `SECURITY.md`, no private reporting channel, vulnerabilities reported as public issues. At the high end: a formal `SECURITY.md`, private advisory intake, embargo coordination with downstream distributors, CVE assignment through a CNA, signed release artifacts, and post-disclosure retrospectives. Most projects should aim for the middle of this spectrum. A formal CVE workflow with distros coordination is appropriate for projects used in critical infrastructure; a clear `SECURITY.md` with GitHub private reporting is sufficient and achievable for the vast majority.

## Threat Model

**Security researcher finding a critical vulnerability with no private channel.** A researcher discovers a remote code execution vulnerability in your project. They look for a `SECURITY.md`. None exists. They check for a security email. Nothing. They open a GitHub issue because they have no other option — or they wait 90 days (the informal industry standard established by Google Project Zero) and then publish regardless, because public disclosure after a reasonable period is the ethical backstop that keeps vendors from ignoring reports indefinitely. In both cases, your users are exposed before a patch exists.

**Malicious actor exploiting disclosure process absence.** A well-funded attacker actively monitors projects for high-value vulnerabilities. They know that projects without coordinated disclosure processes often have long lag times between vulnerability introduction and public awareness. Without a CVE and advisory, your users have no mechanism to know they need to update. An attacker can exploit a known-but-undisclosed vulnerability in production deployments for months.

**Enterprise procurement rejection.** An engineering team wants to adopt your project. Their procurement checklist includes: does the project have a documented security policy? Is there evidence of vulnerability handling (CVEs, advisories)? What is the project's OpenSSF Scorecard? Without a `SECURITY.md` and at least some advisory history, the project fails the checklist. This isn't hypothetical — the US government's CISA guidance on software security now explicitly references OpenSSF criteria.

## Configuration

### Writing SECURITY.md

The `SECURITY.md` file is the foundation. Place it in two locations: the repository root and `.github/SECURITY.md`. GitHub reads `.github/SECURITY.md` and surfaces it on the repository's Security tab; the root copy is visible to anyone reading the repository directly or via package mirrors.

```markdown
# Security Policy

## Supported Versions

We provide security fixes for the following versions.
Older versions are end-of-life and will not receive patches.

| Version | Supported          |
|---------|--------------------|
| 2.x     | Yes (current)      |
| 1.x     | Yes (LTS, until 2027-06-01) |
| < 1.0   | No                 |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

To report a vulnerability privately, use one of the following:

- **GitHub private advisory** (preferred): https://github.com/yourorg/yourproject/security/advisories/new
- **Security email**: security@yourproject.dev
- **PGP-encrypted email**: Fingerprint `ABCD 1234 ...` — key at https://yourproject.dev/security.asc

## Response Timeline

We commit to the following response SLA:

| Milestone                        | Target time   |
|----------------------------------|---------------|
| Acknowledgement of report        | 48 hours      |
| Initial assessment and severity  | 7 days        |
| Fix development underway         | 30 days       |
| Fix released                     | 90 days       |

If we need more time due to complexity, we will notify you and negotiate an extension.
We will never request an extension longer than 60 additional days without your agreement.

## Disclosure Policy

We follow coordinated disclosure with a 90-day embargo.

- Once you report a vulnerability, we ask that you keep the details private until we release a fix or 90 days elapse, whichever comes first.
- If 90 days elapse without a fix, you may disclose at your discretion. We will always prefer to coordinate timing with you.
- After release, we publish a GitHub Security Advisory and request a CVE.

## Scope

The following are in scope:

- Authentication and authorisation bypass
- Remote code execution
- Injection vulnerabilities (SQL, command, template)
- Cryptographic failures
- Sensitive data exposure in logs or API responses

The following are **not** in scope:

- Vulnerabilities requiring physical access to the server
- Social engineering of project maintainers
- Missing security headers on the project documentation site
- Issues in dependencies not introduced by this project

## Credits

We publicly acknowledge reporters in our security advisories unless you request anonymity.
We do not offer a financial reward — this project has no bounty programme.
```

This template covers every field a researcher needs. The supported versions table sets expectations immediately: if you're running a version not listed, security fixes won't reach you. The explicit "do not open a public GitHub issue" instruction prevents the most common failure mode. The SLA table creates accountability — maintainers who miss the 48-hour acknowledgement target are visibly failing a public commitment.

### Setting Up Private Reporting Infrastructure

**GitHub private vulnerability reporting** is the lowest-friction option for GitHub-hosted projects. Enable it under repository Settings → Security → Private vulnerability reporting. Once enabled, GitHub provides a private intake form at `/security/advisories/new`. Reports go to maintainers only; GitHub holds the advisory in draft state until you choose to publish. GitHub also tracks draft advisories in your security tab, so reports don't get lost in email.

**Security email alias.** Set up `security@yourproject.dev` as a Google Group or equivalent with all active maintainers as members. A personal email address creates a single point of failure — maintainer burnout, life events, or domain expiry will cause reports to bounce. Routing to a group ensures multiple people receive every report and can cover for each other.

**PGP key for sensitive reports.** Generate a project keypair rather than using a personal key:

```bash
gpg --full-generate-key
# Choose: RSA and RSA, 4096 bits, 2 years expiry
# Name: YourProject Security Team
# Email: security@yourproject.dev

gpg --armor --export security@yourproject.dev > security.asc
```

Publish `security.asc` at a stable URL and include the fingerprint in `SECURITY.md`. Rotate the key before expiry and update `SECURITY.md` proactively. A bounced security email or an expired PGP key signals abandonment to researchers and eliminates the private channel entirely.

### CVE Assignment Workflow

For GitHub-hosted projects, GitHub acts as a CNA (CVE Numbering Authority) through the GitHub Security Advisory system. This is the simplest path to CVE assignment for most projects:

1. Create a draft GitHub Security Advisory from the repository's Security tab.
2. Fill in the affected package, affected versions, CVSS score, CWE identifiers, and description.
3. Request a CVE from GitHub using the advisory interface — GitHub submits to MITRE on your behalf.
4. Develop and merge the fix while the advisory remains in draft.
5. Publish the advisory simultaneously with the release. The CVE is assigned and becomes publicly searchable within hours.

For projects not hosted on GitHub, request a CVE directly at [cveform.mitre.org](https://cveform.mitre.org/). MITRE assigns CVEs directly for projects that don't have a CNA in their ecosystem.

**What makes a good CVE description:**

```
In ExampleLib before 2.3.1, the YAML parser does not limit
entity expansion depth, allowing an attacker who controls
YAML input to cause exponential memory consumption (a "billion
laughs" attack) and crash the server process. This affects
all deployments that parse YAML from untrusted input.

CVSS v3.1: 7.5 (High) — AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H

Fix: upgrade to 2.3.1. Workaround: validate YAML input length
before parsing.

Credit: Researcher Name (Twitter: @handle)
```

A good description answers: what component is affected, what versions, what does an attacker need, what happens if they succeed, and where is the fix. Vague CVE descriptions ("a vulnerability exists in ExampleLib") provide no actionable information to users.

**CVSS scoring guidance:**

Use the [CVSS v3.1 Calculator](https://www.first.org/cvss/calculator/3.1). Key distinctions:

- **Critical (9.0–10.0):** Network-reachable, no authentication, full system compromise. Reserve this for RCE over the internet with no prerequisites.
- **High (7.0–8.9):** Network-reachable but requires authentication, or significant impact without full system compromise.
- **Medium (4.0–6.9):** Requires specific conditions, limited impact, or local access.
- **Low (0.1–3.9):** Minimal impact or highly constrained attack vector.

Err toward accuracy rather than minimisation. Under-scoring a High vulnerability as Medium erodes trust; over-scoring a Medium as Critical creates unnecessary alarm. When in doubt, document your scoring rationale in the internal advisory notes.

### Embargo and Downstream Coordination

The 90-day embargo standard originates with Google Project Zero's 2014 policy. The logic: 90 days is sufficient time to develop and ship a fix for most vulnerabilities; beyond that, researcher patience is exhausted and the vulnerability is likely being exploited anyway. The embargo is a commitment from both parties — the researcher does not disclose, and the maintainer ships a fix.

**Notifying downstream packagers.** If your project is distributed through Linux distribution package repositories, package maintainers need advance notice so they can prepare updated packages for simultaneous release. The coordination channel is `distros@openwall.com` — a private list for Linux distribution security teams. Send notification at least 7 days before your planned release, including:

- The CVE identifier (even if not yet published)
- Affected versions
- A draft patch or branch reference
- Your planned release date

For language ecosystem packages, contact security teams directly:
- npm: `security@npmjs.com`
- PyPI: `security@python.org`
- Maven Central: contact the project's repository manager

**Private fix development.** Develop the security fix in a private fork or a private branch. A commit like "fix: prevent YAML entity expansion" pushed to a public branch leaks the nature of the vulnerability before you're ready to disclose. GitHub allows creating a private fork directly from a draft Security Advisory, which is the cleanest approach. Only merge to the main branch at release time.

### Release and Disclosure

Coordinated release means simultaneous actions on release day:

1. Merge the private fix branch to main.
2. Tag the release with a GPG-signed tag: `git tag -s v2.3.1 -m "Release 2.3.1"`.
3. Build and publish release artifacts. Sign archives with the project GPG key if applicable.
4. Publish the GitHub Security Advisory (this also publishes the CVE).
5. Publish the release on all distribution channels (npm, PyPI, Docker Hub, etc.).
6. Post disclosure announcement.

**Changelog entry format:**

```markdown
## 2.3.1 — 2026-05-08

### Security

- **CVE-2026-12345 (High, CVSS 7.5):** Fixed YAML entity expansion
  vulnerability that could cause denial of service. Reported by
  Researcher Name. Upgrade immediately if you parse YAML from
  untrusted input. See [security advisory](https://github.com/...).
```

The changelog entry must include the CVE identifier, severity, a one-sentence plain English description, and the advisory link. Without this, users who don't monitor advisories may miss the update.

**Announcement to the security community.** Post to `oss-security@openwall.com` — the primary open mailing list for open source security disclosures. The format is a brief post with: project name and version, CVE, one-paragraph description, CVSS, fix version, and a link to the advisory. Posts to oss-security are indexed by security news services and notify researchers who track the ecosystem.

Also post to your project's own channels: GitHub Discussions, the project mailing list, Slack/Discord, and social accounts. Not all users monitor CVE databases — direct communication reaches them where they are.

### OpenSSF Scorecard and Security Tooling

The OpenSSF Scorecard evaluates repositories automatically via a GitHub Action or direct API. The security-relevant checks:

| Check | What it evaluates | SECURITY.md impact |
|---|---|---|
| Security-Policy | Presence and content of SECURITY.md | Direct: file must exist |
| Vulnerabilities | Open vulnerabilities in OSV database | CVE workflow reduces score risk |
| Binary-Artifacts | Signed release artifacts | Signing process affects this |
| Signed-Releases | GPG-signed tags and artifacts | Directly improved by signing |

Add the Scorecard Action to your repository to get continuous scoring:

```yaml
# .github/workflows/scorecard.yml
name: Scorecard
on:
  branch_protection_rule:
  schedule:
    - cron: '20 3 * * 1'
  push:
    branches: [main]

jobs:
  analysis:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      id-token: write
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: ossf/scorecard-action@v2
        with:
          results_file: results.sarif
          results_format: sarif
          publish_results: true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

The OSSF Best Practices badge (CII Best Practices, now OpenSSF Best Practices) requires a security policy as a passing criterion. Projects at the "passing" level need to describe how to report vulnerabilities privately; "silver" and "gold" levels require documented response timelines and evidence of following them.

### Handling the First Security Report

When your first security report arrives, the instinct may be to treat it as a crisis. Reframe it: a security researcher chose to report to you privately rather than publish, which means the coordinated disclosure system is working as intended. Your response in the first 48 hours establishes whether researchers will report to you again.

**Response to the initial report:**

```
Hi [Name],

Thank you for reporting this. We've received your report and will
provide an initial assessment within 7 days. In the meantime,
please treat the details as confidential per our disclosure policy.

We'll keep you updated at each stage. If you have additional
information that would help us reproduce the issue, please share it.

[Your name]
[Project] Security Team
```

This response is professional regardless of whether the issue turns out to be valid. A researcher who reports an invalid finding still deserves acknowledgement — they spent time and reported in good faith.

**Severity thresholds for escalation:**

- **Low/Medium:** Handle within the regular maintainer group.
- **High:** Loop in all active maintainers; begin embargo coordination immediately.
- **Critical (CVSS 9.0+):** Consider engaging the CNCF Security TAG (for CNCF projects) or the broader project governance committee. Some critical vulnerabilities affecting widely-deployed software warrant a shorter embargo and direct outreach to major users.

**When the reported issue is invalid.** Close the advisory draft and inform the reporter clearly:

```
Thank you for investigating this. After review, we've determined
this behaviour is intentional — [brief explanation]. We appreciate
you reporting privately before publishing.
```

Never be dismissive. Invalid reports are part of the process.

## Expected Behaviour

| Maturity Level | SECURITY.md | CVE Capability | Disclosure Process | OpenSSF Score Impact |
|---|---|---|---|---|
| None | Absent | None | Public issue or no channel | -1 on Security-Policy check |
| Basic | Present, email only | Via MITRE form ad hoc | Informal, no embargo commitment | Passes Security-Policy check |
| Standard | Present, GitHub private reporting | GitHub CNA, systematic | 90-day embargo, coordinated release | Strong Security-Policy, improved Vulnerabilities |
| Advanced | Present, PGP + multiple channels | GitHub CNA + distros coordination | 90-day embargo, signed releases, oss-security post | High scores across Security-Policy, Signed-Releases, Binary-Artifacts |
| Full | All of above + OSSF badge | Full CNA membership or ecosystem CNA | Embargo lists, post-mortems, documented response history | Maximum available score on all related checks |

## Trade-offs

**Embargo length versus user exposure time.** A 90-day embargo gives maintainers time to develop and test a fix. During those 90 days, users running vulnerable versions have no way to know they're at risk. For vulnerabilities being actively exploited (zero-days), a shorter embargo — sometimes just days — may be appropriate. The trade-off is that a shorter embargo may not allow time for downstream distributors to prepare packages. The right answer depends on whether you have evidence of active exploitation; if you do, speed matters more than coordination completeness.

**Full CVE process overhead for small projects.** Requesting a CVE, coordinating with distros, posting to oss-security, and signing releases takes real time. For a small project with a handful of users, an informal approach — private email, patched release, clear changelog entry — may be more practical than a full formal process. Calibrate the process to the risk profile of your project. If enterprises use your project in production, the full process is warranted. If it's a personal project with a few dozen users, a clear SECURITY.md with a working email is sufficient.

**distros@openwall.com coordination burden.** Sending advance notice to Linux distribution security teams is the right thing for widely-deployed projects. The coordination burden is real: you must manage a private communication with multiple parties, track acknowledgements, and coordinate release timing across distributions that operate on different schedules. For projects that are not packaged by Linux distributions (pure npm or PyPI libraries, for instance), this step is unnecessary.

**Maintaining the security@domain email address.** A security email on a custom domain is more professional than a personal email, but it introduces operational risk. If the domain lapses, the email address bounces silently. Use a domain you control for the long term, or use GitHub private advisory as the primary channel with email as a backup. Check the security email address quarterly to confirm it is still receiving mail.

## Failure Modes

**SECURITY.md security email bouncing.** The maintainer listed in SECURITY.md leaves the project, or the domain hosting the security email lapses. Researchers send reports to a dead address with no bounce notification. The vulnerability is never received. Mitigation: route security email to a group alias with multiple members, and test the address quarterly.

**CVE assigned but not coordinated with release.** A maintainer requests a CVE while still developing the fix. The CVE is assigned and published by MITRE before the fix is released — because MITRE publishes CVEs on their own timeline unless you coordinate the timing explicitly. This publicly announces the vulnerability without a fix being available. Mitigation: use GitHub Security Advisory, which lets you control CVE publication timing. Do not request a MITRE CVE until you are ready to release.

**Embargo broken by accidental public commit.** During private fix development, a maintainer accidentally pushes the security fix branch to the public repository, or references the private advisory in a public commit message. The vulnerability is effectively disclosed. Mitigation: develop fixes in a private fork (GitHub's security advisory feature creates one automatically). Never reference an unpublished advisory in public commits.

**Downstream distributions not notified in time.** You notify distros@openwall.com with 2 days' notice before a coordinated release. Distribution packagers cannot build, test, and release updated packages in 2 days. Users on Debian, Ubuntu, Fedora, and similar systems are running vulnerable versions for weeks after your release, because updated packages aren't available. Mitigation: notify distros@openwall.com at least 7 days before release. If you need to release sooner due to active exploitation, notify distros immediately and accept that distribution packages will lag.

**Researcher loses patience and discloses early.** You acknowledge a report but miss every subsequent SLA milestone. The researcher, having given you 90 days with no progress, publishes. The public disclosure is a surprise. Mitigation: honour the response SLA table in your SECURITY.md. If you cannot make progress due to maintainer availability, communicate that to the researcher and negotiate. A researcher who understands the project is resource-constrained will usually extend; one who hears nothing will not.

A security policy is not bureaucracy. It is the infrastructure that allows the security research community to help your users — by routing sensitive information through a channel where it can be acted on before it causes harm. A `SECURITY.md` that takes 30 minutes to write and a GitHub private advisory channel that takes 5 minutes to enable are the minimum viable security policy. Start there, and grow the process as your project's risk profile demands.
