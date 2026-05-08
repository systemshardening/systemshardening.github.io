---
title: "Open Source Security Release Process: CVE Assignment, Coordinated Disclosure, and Patching Linux Tools"
description: "Maintaining an open source Linux tool means handling security vulnerabilities responsibly — assigning CVEs, coordinating disclosure with downstream distributions, building patched releases, and communicating clearly to users. Poorly handled security disclosures damage trust and leave users exposed. This guide covers the end-to-end security release process for Linux daemon and tool maintainers."
slug: oss-security-release-process
date: 2026-05-08
lastmod: 2026-05-08
category: linux
tags:
  - open-source-security
  - cve-assignment
  - responsible-disclosure
  - security-release
  - vulnerability-management
personas:
  - security-engineer
  - platform-engineer
article_number: 681
difficulty: Intermediate
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/linux/oss-security-release-process/
---

# Open Source Security Release Process: CVE Assignment, Coordinated Disclosure, and Patching Linux Tools

## Problem

Most open source Linux projects are maintained by small teams — sometimes a single person — shipping features and fixing bugs in public. When a security vulnerability surfaces, that casual, open workflow becomes a liability. A bug report filed as a public GitHub issue exposes the vulnerability before anyone has time to build a fix. A researcher who can't find a private contact goes to Twitter. A downstream distribution discovers the CVE on the day of release and scrambles to package it before users start asking why they're still exposed.

Without a defined security process, several things go wrong simultaneously:

- **No private reporting channel.** Reporters who find the process don't know how to file a confidential report. The options are: open a public issue (bad), email a generic address that nobody reads (bad), or do a full public disclosure (bad). Many researchers default to public disclosure when they can't find a private path.
- **No CVE before disclosure.** CVE IDs anchor downstream packaging and user communication. If you publish a patched release without a CVE, distributions have no identifier to attach to their advisories, and users have no way to correlate the vulnerability against their scanner output.
- **Downstream distributions left scrambling.** Debian, Ubuntu, Red Hat, and Alpine all maintain their own packaging of popular Linux tools. They need advance notice — usually 7–14 days before a coordinated release — to prepare packages and test them. Notifying them the same day you release is not coordination; it's an announcement.
- **Users don't know whether to upgrade.** Without a clear changelog entry that names the CVE, severity, and affected versions, users running automated scanners will get noisy alerts they can't act on, and users not running scanners may not know they're exposed at all.

The cost of a poorly handled disclosure compounds: a critical vulnerability exploited in the wild while a fix was already available — but not communicated — destroys maintainer credibility in a way that takes years to rebuild.

**What users and distributors expect:**
- A `SECURITY.md` file in the repository root that describes how to report a vulnerability privately
- A CVE ID assigned before or concurrent with the patched release
- Advance notice to downstream distributors before public disclosure
- A patched release signed with the maintainer's GPG key
- A changelog entry that includes the CVE ID, severity, affected versions, and credit to the reporter

## Threat Model

Three actors define the security release process requirements:

**Security researcher with a critical finding.** A researcher discovers a privilege escalation or remote code execution vulnerability in your daemon. They want to report it responsibly — but if your project has no `SECURITY.md`, no private issue tracker, and no PGP key published, they have nowhere to go. After a week of silence, many researchers treat the project as unresponsive and publish full details. A well-defined reporting path converts a potential public zero-day into a coordinated fix.

**Downstream Linux distributor.** Debian stable might ship your tool to hundreds of thousands of systems. When a CVE is fixed, Debian's security team needs time to: receive advance notice, pull the patch, verify it applies cleanly to the version in stable (which may be two major versions behind), build and test a package, and publish their own advisory. If the distributor finds out about the vulnerability when the general public does, their users remain unpatched for days after your release. The `distros@openwall.com` embargo list exists precisely to solve this coordination problem.

**End user under active exploitation.** A user discovers traffic patterns consistent with exploitation of a vulnerability. They need to quickly answer three questions: Am I running an affected version? Is a patched version available? What's the CVE ID so I can track this in my vulnerability management system? Without a CVE, a clear changelog, and patched packages in distribution repositories, each of those questions requires manual investigation.

## Setting Up Private Vulnerability Reporting

### SECURITY.md

Every project should have a `SECURITY.md` in the repository root. GitHub surfaces this file automatically when someone opens an issue, and it is indexed by security researchers as the canonical contact point. A complete `SECURITY.md` contains:

```markdown
# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | Yes       |
| 1.x     | Security fixes only |
| < 1.0   | No        |

## Reporting a Vulnerability

Report security vulnerabilities via GitHub's private vulnerability reporting:
https://github.com/yourorg/yourproject/security/advisories/new

Alternatively, email security@yourproject.example.com — PGP key available at
https://yourproject.example.com/security.asc (fingerprint: AABB CCDD ...).

**Do not open a public issue for security vulnerabilities.**

## Response Timeline

- **Initial acknowledgment:** within 2 business days
- **Triage and severity assessment:** within 5 business days
- **Fix development and coordinated release:** within 90 days (sooner for critical issues)

## Disclosure Policy

We follow a 90-day coordinated disclosure policy. After 90 days, or when a fix is
available (whichever comes first), details will be published publicly. We will
credit reporters in the CVE description and release notes unless anonymity is requested.
```

### GitHub Private Vulnerability Reporting

For GitHub-hosted projects, enable private vulnerability reporting under **Settings → Security → Private vulnerability reporting → Enable**. This creates a private channel where reporters can submit structured vulnerability reports. The report is visible only to repository maintainers, and GitHub can assign a CVE ID directly from this interface.

When a report arrives, GitHub opens a private advisory draft. You work on the fix in a private fork associated with the advisory, keeping the vulnerability confidential until you are ready to publish.

### PGP-Encrypted Email

Projects not on GitHub, or those that prefer email, should publish a PGP public key linked from `SECURITY.md`. Keep the private key offline or on a hardware token. Set a clear contact email — `security@` is conventional — and ensure at least two maintainers have the private key decryption capability to prevent reports going unread during vacations.

**Security contact rotation:** Define in your project governance who is responsible for monitoring the security reporting channel. If the primary maintainer is unavailable, a designated backup should have access. A report sitting unacknowledged for two weeks looks like abandonment and encourages public disclosure.

## CVE Assignment

### GitHub as a CNA

GitHub is a CVE Numbering Authority (CNA). For projects hosted on GitHub, request a CVE ID directly from the Security Advisory UI. In your private advisory draft, click **Request CVE ID**. GitHub's CNA team assigns a CVE ID typically within a few days, and the ID is reserved (unpublished) until you choose to publish the advisory.

This is the lowest-friction path for most projects. The CVE ID appears in the advisory, in the release notes, and in GitHub's security database, which is consumed by package scanners and distribution security teams automatically.

### MITRE Direct Request

For projects not hosted on GitHub, file a CVE request directly with MITRE at https://cveform.mitre.org/. The form asks for a project description, vulnerability details, affected versions, and references. MITRE assigns a CVE ID, which you then use in your release communications.

### CVSS Severity Scoring

Every CVE requires a CVSS v3.1 base score. For Linux tool vulnerabilities, four vectors dominate the score:

| Vector | Options | Impact on score |
|--------|---------|----------------|
| **Attack Vector** | Network / Adjacent / Local / Physical | Network-exploitable vulnerabilities score higher |
| **Privileges Required** | None / Low / High | No-auth vulnerabilities score higher |
| **Scope** | Unchanged / Changed | Privilege escalation that breaks out of a sandbox scores higher |
| **Confidentiality / Integrity / Availability Impact** | None / Low / High | RCE or data exfil scores highest |

A local privilege escalation with no required authentication (common in SUID binaries or daemon socket vulnerabilities) typically scores 7.8 (High). A network-exploitable RCE with no authentication scores 9.8 (Critical). Use the NVD CVSS calculator at https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator to compute your score before writing the CVE description.

### Writing the CVE Description

A good CVE description answers five questions in two sentences:

1. What is the software and affected versions?
2. What is the attack vector?
3. What is the impact?
4. Is there a fix available?
5. Who gets credit?

Example:

> `yourproject` before version 2.3.1 allows a local attacker to escalate privileges to root via a race condition in the Unix domain socket handler (CVE-2026-XXXXX). The vulnerability is fixed in version 2.3.1; users should upgrade. Credit: Jane Researcher (independent).

Avoid vague language like "could allow an attacker to..." — describe what actually happens when the vulnerability is exploited.

## Embargo Period and Coordination

### The 90-Day Window

The 90-day embargo, established by Google Project Zero, is the de facto industry standard. The clock starts when the vulnerability is reported to you. During those 90 days:

- **Days 1–5:** Acknowledge, triage, assess severity, assign CVE
- **Days 5–30:** Develop the fix in a private branch or fork
- **Days 30–60:** Test the fix, backport to supported stable branches, notify `distros@openwall.com`
- **Days 60–75:** Coordinate with downstream distributors, confirm they have packaged the fix
- **Days 75–90:** Finalize patched release, schedule coordinated disclosure date
- **Day 90 (or earlier):** Simultaneous public release, CVE publication, `oss-security@openwall.com` announcement

For critical vulnerabilities being actively exploited in the wild, shorten the timeline. A CVSS 9.8 issue with a known exploit circulating does not benefit from a 90-day embargo that keeps users unpatched.

### Notifying Downstream Distributors

The `distros@openwall.com` mailing list coordinates security notifications to major Linux distributions under embargo. Membership is restricted to distribution security teams (Debian, Ubuntu, Red Hat, SUSE, Arch, Alpine, Gentoo, and others). To notify them:

1. Email `distros@openwall.com` with the CVE ID, a description of the vulnerability, the patch, and the planned disclosure date.
2. Attach or link to the patch (not the full exploit details in the first message).
3. Request confirmation of receipt from each distribution team.
4. Allow at minimum 7 days — ideally 14 — between notification and the public release date.

After public disclosure, post the same information to `oss-security@openwall.com`, which is a public archive. This is the canonical public record of coordinated disclosures for the Linux security community.

### Coordinating with Dependent Projects

If your vulnerability also affects upstream or downstream projects — for example, a shared library function that is vulnerable, or a vulnerability in a protocol implementation that other daemons also use — notify those projects under the same embargo. Add them to a private coordination thread and agree on a unified disclosure date so that users don't face partial information.

## Preparing the Patched Release

### Minimal Patch Principle

The security fix should be the smallest possible change that addresses the vulnerability. A minimal patch:

- Is easier for downstream distributions to backport to older stable versions
- Is easier for independent auditors to verify it actually fixes the vulnerability
- Does not introduce unrelated changes that could cause regressions

Resist the temptation to bundle feature changes or cleanup into a security release. Ship the fix alone. Unrelated changes can delay backporting and make it harder for users to evaluate the risk.

### Backporting to Stable Branches

Many users — especially those running distribution-packaged versions — will be on a version that is one or two majors behind your current development branch. If your project maintains stable branches (e.g., `v1.x-stable`, `v2.x-stable`), backport the security fix to each supported branch and tag a release from each.

Check whether the fix applies cleanly with `git cherry-pick`. If it doesn't, write the backport manually and document why it differs from the main fix. Reference the same CVE ID in all backport commit messages.

### Tagging and Signing the Release

Sign the release tag with your GPG key:

```bash
git tag -s v2.3.1 -m "Security fix for CVE-2026-XXXXX (CVSS 7.8 High)"
git push origin v2.3.1
```

Users and distribution packagers verify the tag signature to confirm the release comes from the legitimate maintainer and has not been tampered with. Publish your GPG public key at a stable URL referenced in `SECURITY.md` and on major keyservers.

### Release Checksums

Generate SHA-256 checksums for all release tarballs and sign the checksum file:

```bash
sha256sum yourproject-2.3.1.tar.gz > SHA256SUMS
gpg --armor --detach-sign SHA256SUMS
```

Publish `SHA256SUMS` and `SHA256SUMS.asc` alongside the release assets. Distribution packagers use these to verify download integrity. Attach them to the GitHub release and to the tarball download page.

## Public Disclosure

### Coordinated Release Day

On the agreed disclosure date, publish all artifacts simultaneously:

1. **Patched release tags and binaries** pushed to GitHub Releases
2. **GitHub Security Advisory** set to public status (this also publishes the CVE to the NVD feed)
3. **Announcement to `oss-security@openwall.com`**
4. **Project blog or mailing list post** for users who follow the project directly

Simultaneous release is critical. If the CVE becomes public before the patched release is available, users are exposed with no recourse. If the patched release is available before the CVE is public, users don't know they need to upgrade.

### Changelog Entry

The `CHANGELOG.md` or release notes entry for a security release must include:

- The CVE ID
- CVSS severity rating (e.g., High, 7.8)
- Affected version range
- Fixed version
- A one-sentence description of the vulnerability (without exploit details)
- Credit to the reporter

Example:

```
## 2.3.1 (2026-05-08) — Security Release

### Security

- **CVE-2026-XXXXX** (High, CVSS 7.8): Fixed a race condition in the Unix domain
  socket handler that allowed a local attacker to escalate privileges to root.
  Affected versions: 2.0.0–2.3.0. Fixed in 2.3.1.
  Credit: Jane Researcher (independent).
```

### oss-security Announcement Format

Post to `oss-security@openwall.com` using the conventional format:

```
Subject: [ANNOUNCE] yourproject 2.3.1 — security fix for CVE-2026-XXXXX

CVE: CVE-2026-XXXXX
Severity: High (CVSS 7.8)
Affected: yourproject 2.0.0 through 2.3.0
Fixed: yourproject 2.3.1

Description:
A race condition in the Unix domain socket handler allows a local attacker
to escalate privileges to root.

References:
  https://github.com/yourorg/yourproject/security/advisories/GHSA-XXXX
  https://yourproject.example.com/releases/2.3.1

Patch:
  https://github.com/yourorg/yourproject/commit/abc123

Credit:
  Jane Researcher
```

## Expected Behaviour

| Disclosure Phase | Action | Timeline | Output Artifact |
|-----------------|--------|----------|----------------|
| Report received | Acknowledge reporter, open private advisory | Day 0–2 | Email acknowledgment, private advisory draft |
| Triage | Reproduce, assess severity, CVSS score | Day 2–5 | CVSS score, CVE ID requested |
| Fix development | Minimal patch, private branch or fork | Day 5–30 | Patch commit(s) |
| Backporting | Apply fix to all supported stable branches | Day 20–40 | Backport commits per branch |
| Distributor notification | Email `distros@openwall.com` with patch | Day 40–60 | Embargo thread with distros |
| Pre-release testing | Build, test, generate checksums | Day 60–80 | Signed tarballs, SHA256SUMS |
| Coordinated release | Tag, sign, publish release, publish advisory | Day 90 | Signed tag, public advisory, CVE published |
| Announcement | Post to `oss-security@openwall.com` | Day 90 | Public archive entry |
| Post-disclosure | Follow up with slow distributors, handle backport requests | Day 90–120 | Distro advisory links |

## Trade-offs

**Embargo length vs. user exposure.** A 90-day embargo gives distributors and maintainers time to prepare, but it also means that users are running vulnerable software for up to three months. For CVSS 9.x vulnerabilities — especially those with public proof-of-concept exploits — the standard embargo period is actively harmful. Shorten the embargo when the vulnerability is being actively exploited or when a functional exploit is already public. The 90-day timeline is a ceiling, not a target.

**Public disclosure before patch vs. delayed fixes.** Some researchers or competing discoverers will publish vulnerability details before the embargo ends. When this happens, the calculus flips: a vulnerability that is now fully public but unpatched is worse than releasing an incomplete or minimally tested fix. Have a break-glass procedure for accelerating release when embargo breaks. This means keeping a build environment current so you can cut a release in hours, not days.

**Backporting burden vs. security coverage for older versions.** Maintaining security fixes for multiple stable branches is expensive. Each backport requires understanding the code at that version, testing the fix in a potentially quite different codebase, and managing a separate release. Projects with small teams often cannot sustain this. Be explicit in `SECURITY.md` about which versions receive security backports. Unsupported versions should be clearly marked so users know they need to upgrade, not wait for a patch.

**CVE severity inflation.** There is pressure — sometimes from reporters seeking recognition, sometimes from vendors seeking urgency — to inflate CVSS scores. A local vulnerability that requires root already (Privileges Required: High) is not a High severity issue, but it may be filed as one. Compute CVSS scores methodically from the specification vectors, not from intuition or impact narrative. Inflated severity erodes trust in your advisories over time.

## Failure Modes

**Reporter goes public before embargo ends.** This is the most common failure mode. Mitigate it by: acknowledging reports promptly (silence looks like inaction), providing a realistic timeline, and issuing a patch as quickly as possible. If an early disclosure occurs, release the patched version immediately — do not wait for the original disclosure date. Notify distributors that the embargo has broken and request expedited packaging.

**CVE not assigned before disclosure.** Releasing a patched version without a CVE leaves users and distributors without an identifier to track. If your CVE request is pending when the release date arrives, either delay the release (if the CVE will arrive within days) or release with a note that the CVE ID is pending and update the advisory when it arrives. Do not use placeholder language like "CVE-TBD" in production advisories — use the actual reserved ID or explicitly state it is pending assignment.

**Downstream distributors not notified.** If you skip the `distros@openwall.com` step, distribution users remain unpatched for days or weeks after your release. Debian stable users may be running a version with a known, public CVE while Debian's security team is learning about it for the first time. Always notify distributors under embargo, at minimum 7 days before the public release.

**Patched release with regressions.** A security fix that breaks existing functionality is a different kind of emergency. Implement a minimal test suite that covers the code path touched by the fix. Run it against the patched release before publication. If a regression is discovered after release, issue a follow-up patch release quickly — and do not re-use the same CVE ID for the regression fix unless the regression is itself a security issue.

**Duplicate CVE IDs.** If a researcher reports a vulnerability that was already reported separately, or if MITRE assigns a duplicate ID, coordinate with the CNA to reject one ID and reference the authoritative one in all advisories. Duplicate CVEs cause scanner false positives and confuse distribution packagers. Check existing CVE databases and `oss-security` archives before requesting a new CVE ID.

## Post-Disclosure

After the patched release and public announcement, the process continues:

**Follow up with distributions.** Not every distribution will package the fix immediately. Check distribution security trackers (Debian Security Tracker, Red Hat CVE Database, Ubuntu CVE Tracker) 1–2 weeks after disclosure. If a major distribution has not yet published a patched package, reach out directly to their security team to check for blockers.

**Handle backport requests.** Users on versions outside your official support window may request security backports. Decide in advance whether you will accept such requests and document the policy in `SECURITY.md`. If you do not, point users to the upstream fix and encourage them to upgrade.

**Post-mortem.** For every significant security incident, hold a post-mortem focused on process improvement, not blame. Common findings: the vulnerable code pattern appears elsewhere in the codebase (audit for similar issues), the vulnerability class was introduced by a dependency (evaluate dependency update policies), or the test suite didn't cover the affected code path (add regression tests). The post-mortem output is a set of concrete actions that reduce the likelihood of the same class of vulnerability appearing again.

A well-run security release process is not just about fixing one vulnerability — it is infrastructure for building and maintaining trust with every user, reporter, and distributor who depends on your project.
